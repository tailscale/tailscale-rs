use std::{io::ErrorKind, marker::PhantomData};

use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use tokio_util::codec::{Decoder, Encoder};
use ts_noise::core::{Role, Session};
use zerocopy::{IntoBytes, TryCastError, TryFromBytes, network_endian::U16};

use crate::messages::{Header, MessageType};

/// The maximum wire size of a message to control over noise.
pub const MAX_MESSAGE_SIZE: usize = 4096;

/// Overhead required by the AEAD's authentication tag.
const AEAD_OVERHEAD: usize = 16;

/// Maximum size of a data chunk, without the per-message overhead.
const MAX_CHUNK_SIZE: usize = MAX_MESSAGE_SIZE - size_of::<Header>() - AEAD_OVERHEAD;

/// Marker type to indicate that a [`Codec`] instance can only be used for receiving, not sending.
pub enum Rx {}

/// Marker type to indicate that a [`Codec`] instance can only be used for sending, not receiving.
pub enum Tx {}

/// Control noise codec that uses a different cipher state for the up and down directions.
///
/// Just a wrapper containing two [`Codec`]s, one of which provides [`Encoder`] and the
/// other [`Decoder`].
pub struct BiCodec {
    /// The transmit codec, used for encoding messages to control.
    tx: Codec<Tx>,
    /// The receive codec, used for decoding messages from control.
    rx: Codec<Rx>,
}

impl<B> Encoder<B> for BiCodec
where
    B: AsRef<[u8]>,
{
    type Error = <Codec<Tx> as Encoder<B>>::Error;

    fn encode(&mut self, item: B, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.tx.encode(item, dst)
    }
}

impl Decoder for BiCodec {
    type Item = <Codec<Rx> as Decoder>::Item;
    type Error = <Codec<Rx> as Decoder>::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.rx.decode(src)
    }
}

impl From<Session> for BiCodec {
    fn from(session: Session) -> Self {
        match session.role {
            Role::Initiator => Self {
                tx: Codec::<Tx>::from(session.initiator_to_responder),
                rx: Codec::<Rx>::from(session.responder_to_initiator),
            },
            Role::Responder => Self {
                tx: Codec::<Tx>::from(session.responder_to_initiator),
                rx: Codec::<Rx>::from(session.initiator_to_responder),
            },
        }
    }
}

/// Codec supporting encrypting and decrypting data according to the control noise protocol
/// using the specified cipher state.
///
/// In accordance with Noise session semantics, a particular Codec instance can only be used for
/// sending or receiving, never both. The type parameter should be [`Tx`] for sending sessions and
/// [`Rx`] for receiving sessions.
pub struct Codec<D> {
    cipher: ChaCha20Poly1305,
    next_nonce: u64,
    _phantom: PhantomData<D>,
}

impl<D> Codec<D> {
    fn new(key: Key, nonce: u64) -> Self {
        Codec {
            cipher: ChaCha20Poly1305::new(&key),
            next_nonce: nonce,
            _phantom: PhantomData,
        }
    }

    fn next_nonce(&mut self) -> Nonce {
        assert_ne!(self.next_nonce, u64::MAX);
        let mut ret = [0; 12];
        ret[4..].copy_from_slice(&self.next_nonce.to_be_bytes());
        self.next_nonce += 1;
        ret.into()
    }
}

impl<D> From<Key> for Codec<D> {
    fn from(key: Key) -> Self {
        Codec::new(key, 0)
    }
}

impl<B> Encoder<B> for Codec<Tx>
where
    B: AsRef<[u8]>,
{
    type Error = std::io::Error;

    fn encode(&mut self, b: B, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let b = b.as_ref();

        for chunk in b.chunks(MAX_CHUNK_SIZE) {
            let hdr = Header {
                typ: MessageType::Record,
                len: U16::new(chunk.len() as u16 + AEAD_OVERHEAD as u16),
            };

            dst.put(hdr.as_bytes());

            let data_start = dst.len();
            dst.put(chunk);

            let nonce = self.next_nonce();
            let tag = self
                .cipher
                .encrypt_in_place_detached(&nonce, &[], &mut dst[data_start..])
                .unwrap();
            dst.put(tag.as_ref());
        }

        Ok(())
    }
}

impl Decoder for Codec<Rx> {
    type Item = BytesMut;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (header, rest_len) = match Header::try_ref_from_prefix(src) {
            Ok((hdr, rest)) => (*hdr, rest.len()),
            Err(TryCastError::Size(_)) => return Ok(None),
            Err(e) => {
                tracing::error!(error = %e, "parsing control message header");
                return Err(ErrorKind::InvalidData.into());
            }
        };
        let len = header.len.get() as usize;

        if rest_len < len {
            return Ok(None);
        }

        src.advance(size_of::<Header>());
        let mut body = src.split_to(len);

        match header.typ {
            MessageType::Record => {
                let nonce = self.next_nonce();
                let tag = body.split_off(body.len() - AEAD_OVERHEAD);
                if self
                    .cipher
                    .decrypt_in_place_detached(&nonce, &[], body.as_mut(), tag.as_ref().into())
                    .is_err()
                {
                    tracing::error!("decryption failed");
                    return Err(ErrorKind::InvalidData.into());
                }

                Ok(Some(body))
            }
            MessageType::Error => {
                let error_message =
                    core::str::from_utf8(&body).unwrap_or("<invalid utf-8 in error body>");

                tracing::error!(
                    error_message,
                    error_body_len = body.len(),
                    "error received from control"
                );
                Ok(None)
            }
            typ => {
                tracing::error!(message_type = ?typ, "unexpected message type from control");
                Err(ErrorKind::InvalidData.into())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use proptest::{collection::vec, prelude::*};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::codec::Framed;

    use super::*;

    fn init_codec_pair(key: [u8; 32], nonce: u64) -> (Codec<Tx>, Codec<Rx>) {
        (Codec::new(key.into(), nonce), Codec::new(key.into(), nonce))
    }

    fn rand_codec_pair() -> (Codec<Tx>, Codec<Rx>) {
        init_codec_pair(rand::random(), rand::random())
    }

    const TEST_PAYLOAD: &[u8] = b"hello";

    #[test]
    fn roundtrip() {
        let (mut encrypt_codec, mut decrypt_codec) = rand_codec_pair();
        let mut buf = BytesMut::new();

        encrypt_codec.encode(TEST_PAYLOAD, &mut buf).unwrap();
        assert_ne!(buf.as_ref(), TEST_PAYLOAD);
        assert_eq!(buf.len(), TEST_PAYLOAD.len() + 16 + size_of::<Header>());

        let decoded = decrypt_codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.as_ref(), TEST_PAYLOAD);
    }

    #[test]
    fn roundtrip_partial() {
        let (mut encrypt_codec, mut decrypt_codec) = rand_codec_pair();
        let mut buf = BytesMut::new();

        encrypt_codec.encode(TEST_PAYLOAD, &mut buf).unwrap();
        assert_ne!(buf.as_ref(), TEST_PAYLOAD);
        assert_eq!(buf.len(), TEST_PAYLOAD.len() + 16 + size_of::<Header>());

        for i in 0..TEST_PAYLOAD.len() - 1 {
            let mut test_payload = buf.clone().split_to(i);
            assert_eq!(
                decrypt_codec.decode(&mut test_payload).unwrap(),
                None,
                "i={i}"
            );
            assert_eq!(test_payload.len(), i);
        }

        let decoded = decrypt_codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.as_ref(), TEST_PAYLOAD);
    }

    static RUNTIME: LazyLock<tokio::runtime::Runtime> =
        LazyLock::new(|| tokio::runtime::Runtime::new().unwrap());

    #[test]
    fn read_write() {
        let (encrypt_codec, decrypt_codec) = rand_codec_pair();

        let (rx, tx) = tokio::io::simplex(32);

        let mut framed_encrypt =
            crate::framed_io::FramedIo::<_, BytesMut>::new(Framed::new(tx, encrypt_codec));
        let mut framed_decrypt =
            crate::framed_io::FramedIo::<_, BytesMut>::new(Framed::new(rx, decrypt_codec));

        let (_, read_payload) = RUNTIME.block_on(async move {
            tokio::try_join![
                async move {
                    framed_encrypt.write_all(TEST_PAYLOAD).await?;
                    framed_encrypt.flush().await
                },
                async move {
                    let mut read_payload = BytesMut::zeroed(TEST_PAYLOAD.len());
                    framed_decrypt.read_exact(&mut read_payload).await?;
                    Ok(read_payload)
                }
            ]
            .unwrap()
        });

        assert_eq!(read_payload, TEST_PAYLOAD);
    }

    proptest::proptest! {
        #[test]
        fn roundtrip_prop(payload in vec(any::<u8>(), 1..=MAX_MESSAGE_SIZE - size_of::<Header>() - 16), key: [u8; 32], nonce: u64) {
            let (mut encrypt_codec, mut decrypt_codec) = init_codec_pair(key, nonce);

            let mut buf = BytesMut::new();
            encrypt_codec.encode(&payload, &mut buf).unwrap();
            let decoded = decrypt_codec.decode(&mut buf).unwrap().unwrap();
            assert_eq!(decoded.as_ref(), payload.as_slice());
        }

        #[test]
        fn read_write_prop(payload in vec(any::<u8>(), 1..=MAX_MESSAGE_SIZE * 4), key: [u8; 32], nonce: u64) {
            let (encrypt_codec, decrypt_codec) = init_codec_pair(key, nonce);

            let (rx, tx) = tokio::io::simplex(32);

            let mut framed_encrypt = crate::framed_io::FramedIo::<_, BytesMut>::new(Framed::new(tx, encrypt_codec));
            let mut framed_decrypt = crate::framed_io::FramedIo::<_, BytesMut>::new(Framed::new(rx, decrypt_codec));

            let write_payload = payload.clone();
            let mut read_payload = BytesMut::zeroed(payload.len());

            let (_, read_payload) = RUNTIME.block_on(async move {
                tokio::try_join![
                    async move {
                        framed_encrypt.write_all(&write_payload).await?;
                        framed_encrypt.flush().await
                    },
                    async move {
                        framed_decrypt.read_exact(&mut read_payload).await?;
                        Ok(read_payload)
                    }
                ]
                .unwrap()
            });

            assert_eq!(read_payload, payload);
        }
    }
}
