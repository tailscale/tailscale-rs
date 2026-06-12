use core::{
    borrow::Borrow,
    pin::Pin,
    task::{Context, Poll},
};
use std::{io::Read, os::fd::AsRawFd};

use futures_util::Stream;
use libc::{PF_ROUTE, SO_USELOOPBACK, SOL_SOCKET};
use nom::Parser;
use socket2::{Domain, Socket, Type};
use tokio::io::{Interest, unix::AsyncFd};
use zerocopy::IntoBytes;

use crate::bsd::net_table;

/// A socket handling [`PF_ROUTE`] messages to/from a BSD kernel.
pub struct RouteSocket {
    fd: AsyncFd<Socket>,
}

impl RouteSocket {
    pub fn new() -> std::io::Result<Self> {
        let sock = Socket::new(Domain::from(PF_ROUTE), Type::RAW, None)?;
        sock.set_nonblocking(true)?;

        // SAFETY: this usage of the `setsockopt` API is correct.
        unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                SOL_SOCKET,
                SO_USELOOPBACK,
                &0u8 as *const u8 as *const _,
                1,
            );
        }

        let fd = AsyncFd::new(sock)?;
        Ok(Self { fd })
    }

    /// Produce a stream of raw messages as [`bytes::BytesMut`].
    ///
    /// The contents are not interpreted or guaranteed to be valid, the messages are simply deframed
    /// according to the initial length word.
    pub fn raw_msg_stream(&self) -> MsgStream<&Self> {
        MsgStream {
            rtsock: self,
            buf: bytes::BytesMut::new(),
        }
    }

    /// Send a message over the route socket.
    pub async fn send_raw(&self, msg: &[u8]) -> std::io::Result<usize> {
        self.fd
            .async_io(Interest::WRITABLE, |sock| sock.send(msg))
            .await
    }
}

/// A stream of raw messages from a [`RouteSocket`].
pub struct MsgStream<RS> {
    /// The socket from which we're streaming packets.
    rtsock: RS,

    /// Working buffer which holds undecoded state.
    ///
    /// We receive from the socket into this buffer and then yield messages out of it one-at-a-time
    /// until it empties (then repeat).
    ///
    /// This is stored as a field rather than as a local var on [`MsgStream`] to avoid thrashing
    /// allocations where possible; it's likely that we'll end up with a bigger chunk of memory than
    /// we need and will be able to skip allocating in some cases.
    buf: bytes::BytesMut,
}

impl<RS> MsgStream<RS> {
    pub fn new(rs: RS) -> MsgStream<RS> {
        Self {
            rtsock: rs,
            buf: bytes::BytesMut::new(),
        }
    }
}

impl<RS> MsgStream<RS> {
    /// Nominal buffer size for receiving from a `PF_ROUTE` socket.
    const BUF_SIZE: usize = 8192;
}

impl<RS> Stream for MsgStream<RS>
where
    RS: Borrow<RouteSocket> + Unpin,
{
    type Item = std::io::Result<bytes::BytesMut>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut slf = self.as_mut();

        loop {
            while !slf.buf.is_empty() {
                let msg_len = match net_table::msg_chunk().parse(slf.buf.as_bytes()) {
                    Ok((rest, _msg)) => {
                        let full_msg_len = slf.buf.len() - rest.len();
                        debug_assert_eq!(_msg.len(), full_msg_len);

                        tracing::trace!(rest_len = rest.len(), full_msg_len, msg_len = _msg.len());

                        Some(full_msg_len)
                    }

                    // Chunk was truncated in the input.
                    //
                    // We don't buffer partial results (or impl AsyncRead) because PF_ROUTE messages
                    // are delivered like UDP datagrams: anything that overflows our buffer is
                    // truncated and discarded by the kernel.
                    Err(nom::Err::Incomplete(_n)) => {
                        tracing::error!("incomplete PF_ROUTE message (dropped)");
                        None
                    }

                    // Fine to bail here, the error condition here is that the message didn't start
                    // with a valid length u16, i.e. the rest of the input wasn't long enough. This
                    // should actually just produce an Incomplete, but in case something changes,
                    // cover this error case separately.
                    Err(nom::Err::Failure(e) | nom::Err::Error(e)) => {
                        tracing::error!(error = ?e, "malformed PF_ROUTE message");
                        None
                    }
                };

                tracing::trace!(?msg_len);

                let Some(msg_len) = msg_len else {
                    slf.buf.clear();
                    continue;
                };

                // Re-split the message; this is fine because net_table::msg_chunk() doesn't discard
                // data, it's actual-size.
                let msg = slf.buf.split_to(msg_len);
                return Poll::Ready(Some(Ok(msg)));
            }

            loop {
                let Self { rtsock, buf } = &mut *slf;
                let rtsock: &RouteSocket = (*rtsock).borrow();

                let mut rdy = core::task::ready!(rtsock.fd.poll_read_ready(cx))?;
                buf.resize(Self::BUF_SIZE, 0);

                let n = match rdy.try_io(|sock| {
                    let mut sock = sock.get_ref();
                    sock.read(buf.as_mut())
                }) {
                    Err(_) => {
                        buf.clear();
                        continue;
                    }
                    Ok(n) => n?,
                };

                buf.truncate(n);
                break;
            }
        }
    }
}
