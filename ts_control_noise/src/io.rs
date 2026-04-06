use core::{
    pin::Pin,
    task::{Context, Poll},
};
use std::io::{self, ErrorKind};

use bytes::Buf;
use noise_protocol::CipherState;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use ts_hexdump::{AsHexExt, Case};
use ts_packet::old::PacketMut;
use zerocopy::{IntoBytes, TryFromBytes};

use crate::{
    cipher::ChaCha20Poly1305BigEndian,
    messages::{ControlMessageHeader, ControlMessageType, RecordMessage},
};

pin_project_lite::pin_project! {
    /// Wrapper that transparently performs Noise encryption and decryption over an
    /// underlying I/O connection at relatively low overhead. Assumes we're speaking the
    /// Tailscale control server protocol with a Noise connection which has already been
    /// handshaken out-of-band.
    ///
    /// Does not perform any internarl buffering for I/O optimization -- apply buffering
    /// above or below instead.
    pub struct NoiseIo<Conn> {
        #[pin]
        conn: Conn,

        rx: CipherState<ChaCha20Poly1305BigEndian>,
        rx_state: AsyncReadState,

        tx: CipherState<ChaCha20Poly1305BigEndian>,
        tx_state: AsyncWriteState,
    }
}

impl<Conn> NoiseIo<Conn> {
    /// Construct a new Noise connection wrapping the underlying connection with the given
    /// cipher states.
    ///
    /// The cipher states are expected to have been negotiated out-of-band, e.g. by
    /// [`Handshake`][crate::Handshake].
    pub const fn new(
        conn: Conn,
        rx: CipherState<ChaCha20Poly1305BigEndian>,
        tx: CipherState<ChaCha20Poly1305BigEndian>,
    ) -> Self {
        Self {
            conn,
            rx,
            rx_state: AsyncReadState::ReadHeader {
                bytes_read: 0,
                bytes: [0u8; 3],
            },
            tx,
            tx_state: AsyncWriteState::Idle,
        }
    }
}

enum AsyncReadState {
    ReadHeader {
        bytes_read: usize,
        bytes: [u8; 3],
    },
    ReadBody {
        ty: ControlMessageType,
        len: usize,
        body: PacketMut,
    },
    ReturnToCaller {
        body: PacketMut,
    },
}

enum AsyncWriteState {
    Idle,
    WritingPacket(PacketMut),
}

impl<Conn: AsyncRead> AsyncRead for NoiseIo<Conn> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut pin_self = self.project();

        loop {
            match &mut pin_self.rx_state {
                AsyncReadState::ReadHeader { bytes_read, bytes } => {
                    let mut rb = ReadBuf::new(bytes.as_mut_slice());
                    core::task::ready!(pin_self.conn.as_mut().poll_read(cx, &mut rb)?);

                    *bytes_read += rb.filled().len();
                    // Per the docs for `AsyncRead::poll_read`, a return value of 0 indicates we've
                    // reached EOF, or the ReadBuf had a capacity of 0 - in either case, forward
                    // the result to the caller to handle.
                    if *bytes_read == 0 {
                        tracing::warn!("poll_read: ReadHeader: got EOF when reading packet header");
                        return Poll::Ready(Ok(()));
                    }

                    // We've only read 1-2 bytes of the 3-byte header, stay in this state.
                    if *bytes_read < 3 {
                        continue;
                    }
                    assert_eq!(*bytes_read, 3);
                    let hdr = ControlMessageHeader::try_ref_from_bytes(bytes)
                        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e.to_string()))?;
                    tracing::trace!("poll_read: ReadHeader: read {hdr:?}, moving to ReadBody");
                    *pin_self.rx_state = AsyncReadState::ReadBody {
                        ty: hdr.typ,
                        len: hdr.len(),
                        body: PacketMut::new(hdr.len()),
                    };
                }
                AsyncReadState::ReadBody { ty, len, body } => {
                    let ty = *ty;
                    let len = *len;
                    let mut rb = ReadBuf::new(body.as_mut());
                    core::task::ready!(pin_self.conn.as_mut().poll_read(cx, &mut rb)?);

                    let bytes_read = rb.filled_mut().len();
                    // Per the docs for `AsyncRead::poll_read`, a return value of 0 indicates we've
                    // reached EOF, or the ReadBuf had a capacity of 0 - in either case, forward
                    // the result to the caller to handle.
                    if bytes_read == 0 {
                        tracing::warn!(
                            "poll_read: ReadBody({ty:?}): got EOF when reading packet body"
                        );
                        return Poll::Ready(Ok(()));
                    }

                    if body.len() < len {
                        tracing::trace!(
                            "poll_read: ReadBody({ty:?}): read {bytes_read} bytes, have {}/{len} bytes of body",
                            body.len()
                        );
                        continue;
                    }

                    tracing::trace!("poll_read: ReadBody({ty:?}): have full message body, parsing");
                    match ty {
                        ControlMessageType::Record => {
                            if body.len() != len {
                                let err = io::Error::new(
                                    ErrorKind::InvalidData,
                                    format!(
                                        "header length ({len} bytes) does not match actual length ({} bytes)",
                                        body.len()
                                    ),
                                );
                                Err(err)?;
                            }
                            let body = match pin_self.rx.decrypt_in_place(body.as_mut(), len) {
                                Ok(plaintext_len) => {
                                    let packet = body.split_to(plaintext_len);
                                    tracing::trace!(
                                        bytes_received = plaintext_len,
                                        "poll_read: ReadBody({ty:?}): received packet:\n{}",
                                        packet
                                            .iter()
                                            .hexdump(Case::Lower)
                                            .flatten()
                                            .collect::<String>()
                                    );
                                    packet
                                }
                                Err(e) => {
                                    tracing::trace!(
                                        "poll_read: ReadBody({ty:?}): error decrypting Record message from control: {e:?}"
                                    );
                                    *pin_self.rx_state = AsyncReadState::ReadHeader {
                                        bytes_read: 0,
                                        bytes: [0u8; 3],
                                    };
                                    return Poll::Ready(Err(io::Error::other(
                                        "noise decryption failed",
                                    )));
                                }
                            };
                            tracing::trace!(
                                "poll_read: ReadBody({ty:?}): full message parsed, moving to ReturnToCaller"
                            );
                            *pin_self.rx_state = AsyncReadState::ReturnToCaller { body };
                        }
                        ControlMessageType::Error => {
                            let msg = core::str::from_utf8(body.as_ref())
                                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
                            let err = io::Error::other(msg);
                            tracing::trace!(
                                "poll_read: ReadBody({ty:?}): control returned an Error message: {msg}"
                            );
                            tracing::trace!("poll_read: ReadBody({ty:?}): moving to ReadHeader");
                            *pin_self.rx_state = AsyncReadState::ReadHeader {
                                bytes_read: 0,
                                bytes: [0u8; 3],
                            };
                            return Poll::Ready(Err(err));
                        }
                        _ => {
                            tracing::trace!(
                                "poll_read: ReadBody({ty:?}): unexpected message type from control, moving to ReadHeader"
                            );
                            *pin_self.rx_state = AsyncReadState::ReadHeader {
                                bytes_read: 0,
                                bytes: [0u8; 3],
                            };
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::InvalidData,
                                format!("unexpected message type {:?}", ty),
                            )));
                        }
                    }
                }
                AsyncReadState::ReturnToCaller { body } => {
                    assert!(!body.is_empty());

                    let remaining = body.len().min(buf.remaining());
                    let rest = body.split_off(remaining);
                    tracing::trace!(
                        "poll_read: ReturnToCaller: returning {remaining}/{} bytes to caller",
                        body.len()
                    );
                    buf.put_slice(body.as_ref());

                    if rest.is_empty() {
                        tracing::trace!(
                            "poll_read: ReturnToCaller: returned full message, moving to ReadHeader"
                        );
                        *pin_self.rx_state = AsyncReadState::ReadHeader {
                            bytes_read: 0,
                            bytes: [0u8; 3],
                        };
                    } else {
                        *pin_self.rx_state = AsyncReadState::ReturnToCaller { body: rest };
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<T: AsyncWrite> AsyncWrite for NoiseIo<T> {
    #[tracing::instrument(skip_all)]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let mut pin_self = self.project();
        let plaintext_len = buf.len();
        let buf = &mut buf;

        loop {
            match &mut pin_self.tx_state {
                AsyncWriteState::Idle => {
                    if buf.is_empty() {
                        return Poll::Ready(Ok(plaintext_len));
                    }

                    tracing::trace!(
                        plaintext_len,
                        "Idle -> WritingPacket: encrypting plaintext payload:\n{}",
                        buf.iter()
                            .hexdump(Case::Lower)
                            .flatten()
                            .collect::<String>()
                    );
                    // TOOD (dylan): wat? make constant
                    let auth_data_len = 16;
                    // TOOD (dylan): wat? make constant
                    let payload_len = plaintext_len.min(4096);

                    let mut slice = buf.take(payload_len);
                    let chunk = slice.chunk();
                    let chunk_len = chunk.len();
                    let packet_len = size_of::<ControlMessageHeader>() + chunk_len + auth_data_len;
                    let mut packet = PacketMut::new(packet_len);
                    let record = RecordMessage::new_in(packet.as_mut(), chunk_len + auth_data_len)?;
                    chunk
                        .write_to_prefix(&mut record.data)
                        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e.to_string()))?;
                    pin_self.tx.encrypt_in_place(&mut record.data, chunk_len);
                    let encrypted_len = packet.len();
                    tracing::trace!(
                        encrypted_len,
                        "Idle -> WritingPacket: writing encrypted payload:\n{}",
                        packet
                            .iter()
                            .hexdump(Case::Lower)
                            .flatten()
                            .collect::<String>()
                    );
                    slice.advance(chunk_len);
                    tracing::trace!(
                        plaintext_len,
                        encrypted_len,
                        final_len = buf.len(),
                        "Idle -> WritingPacket: encrypted payload written"
                    );

                    *pin_self.tx_state = AsyncWriteState::WritingPacket(packet);
                }
                AsyncWriteState::WritingPacket(packet) => {
                    match pin_self.conn.as_mut().poll_write(cx, packet.as_ref()) {
                        // Per the docs for `AsyncWrite::poll_write`, a return value of 0 typically
                        // indicates EOF - whatever we're writing to isn't accepting bytes anymore
                        // and probably won't accept them in the future. Take the minimally-
                        // opinionated approach here and forward the return value up to the caller;
                        // if the caller decides to poll us again, we'll resume from the current
                        // state (not dropping the data in the buffer).
                        Poll::Ready(Ok(0)) => {
                            tracing::warn!(
                                "WritingPacket[Ready(Ok(0))]: got EOF when writing packet"
                            );
                            return Poll::Ready(Ok(0));
                        }
                        Poll::Ready(Ok(bytes_written)) => {
                            packet.truncate_front(bytes_written);
                            if packet.is_empty() {
                                tracing::trace!(
                                    "WritingPacket[Ready(Ok)] -> Idle: packet written fully, moving to Idle state"
                                );
                                *pin_self.tx_state = AsyncWriteState::Idle;
                            } else {
                                tracing::trace!(
                                    bytes_remaining = packet.len(),
                                    bytes_written,
                                    "WritingPacket[Ready(Ok)]: packet partially written, remaining to write:\n{}",
                                    packet
                                        .iter()
                                        .hexdump(Case::Lower)
                                        .flatten()
                                        .collect::<String>()
                                );
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            tracing::trace!(
                                "WritingPacket[Ready(Err)] -> Err: error writing packet: {e}"
                            );
                            return Poll::Ready(Err(e));
                        }
                        Poll::Pending => {
                            tracing::trace!(
                                bytes_remaining = packet.len(),
                                "WritingPacket[Pending]: waiting to write packet:\n{}",
                                packet
                                    .iter()
                                    .hexdump(Case::Lower)
                                    .flatten()
                                    .collect::<String>()
                            );
                            if buf.len() == plaintext_len {
                                tracing::trace!(
                                    "WritingPacket[Pending] -> WritingPacket[Pending]: still waiting"
                                );
                                return Poll::Pending;
                            } else {
                                let bytes_written = plaintext_len - buf.len();
                                tracing::trace!(
                                    bytes_written,
                                    "WritingPacket[Pending] -> WritingPacket[Ready(Ok)]: wrote bytes, moving to Ready(Ok)"
                                );
                                return Poll::Ready(Ok(bytes_written));
                            }
                        }
                    }
                }
            }
        }
    }

    #[tracing::instrument(skip_all)]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let mut pin_self = self.project();

        loop {
            match &mut pin_self.tx_state {
                AsyncWriteState::Idle => {
                    tracing::trace!("Idle: internal poll_flush");
                    return pin_self.conn.as_mut().poll_flush(cx);
                }
                AsyncWriteState::WritingPacket(packet) => {
                    tracing::trace!(
                        "WritingPacket: packet is {} bytes:\n{}",
                        packet.len(),
                        packet
                            .iter()
                            .hexdump(Case::Lower)
                            .flatten()
                            .collect::<String>()
                    );
                    match pin_self.conn.as_mut().poll_write(cx, packet.as_ref()) {
                        Poll::Ready(Ok(bytes_written)) => {
                            tracing::trace!(
                                "poll_flush: WritingPacket: Ready(Ok({bytes_written})): packet is {} bytes:\n{}",
                                packet.len(),
                                packet
                                    .iter()
                                    .hexdump(Case::Lower)
                                    .flatten()
                                    .collect::<String>()
                            );
                            packet.truncate_front(bytes_written);
                            tracing::trace!(
                                "poll_flush: WritingPacket: packet truncated to {} bytes",
                                packet.len()
                            );

                            // Per the docs for `AsyncWrite::poll_write`, writing 0 bytes indicates
                            // the underlying connection is EOF or otherwise not accepting bytes,
                            // and isn't expected to accept bytes again in the future. To complete
                            // the flush, move to the Idle state. We'll likely lose the bytes that
                            // we read from the packet, since we can't write them to the `conn`,
                            // but if we don't move to Idle we'll likely end up stuck in the
                            // Poll::Ready(Ok) state trying to write to a `conn` that won't ever
                            // start accepting bytes again.
                            if packet.is_empty() || bytes_written == 0 {
                                tracing::trace!(
                                    "poll_flush: WritingPacket: Ready(Ok({bytes_written})) -> Idle"
                                );
                                *pin_self.tx_state = AsyncWriteState::Idle;
                            }
                        }
                        Poll::Ready(Err(e)) => {
                            tracing::trace!("poll_flush: WritingPacket: Ready(Err({e})) -> Err");
                            return Poll::Ready(Err(e));
                        }
                        Poll::Pending => {
                            tracing::trace!(
                                "poll_flush: WritingPacket: Pending: packet is {} bytes:\n{}",
                                packet.len(),
                                packet
                                    .iter()
                                    .hexdump(Case::Lower)
                                    .flatten()
                                    .collect::<String>()
                            );
                            tracing::trace!("poll_flush: WritingPacket: Pending -> Pending");
                            return Poll::Pending;
                        }
                    }
                }
            }
        }
    }

    #[tracing::instrument(skip_all)]
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        tracing::trace!("flushing");
        core::task::ready!(AsyncWrite::poll_flush(self.as_mut(), cx)?);
        tracing::trace!("conn.poll_shutdown");
        self.project().conn.as_mut().poll_shutdown(cx)
    }
}
