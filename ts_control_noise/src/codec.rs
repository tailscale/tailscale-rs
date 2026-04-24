use std::io::ErrorKind;

use bytes::{Buf, BufMut, BytesMut};
use noise_protocol::{Cipher, CipherState};
use tokio_util::codec::{Decoder, Encoder};
use zerocopy::{IntoBytes, TryCastError, TryFromBytes, U16};

use crate::messages::{Header, MessageType};

/// The maximum wire size of a message to control over noise.
pub const MAX_MESSAGE_SIZE: usize = 4096;

/// Control noise codec that uses a different cipher state for the up and down directions.
///
/// Just a wrapper containing two [`Codec`]s, one of which provides [`Encoder`] and the
/// other [`Decoder`].
pub struct BiCodec<Tx, Rx>
where
    Tx: Cipher,
    Rx: Cipher,
{
    /// The transmit codec, used for encoding messages to control.
    pub tx: Codec<Tx>,
    /// The receive codec, used for decoding messages from control.
    pub rx: Codec<Rx>,
}

impl<B, Tx, Rx> Encoder<B> for BiCodec<Tx, Rx>
where
    B: AsRef<[u8]>,
    Tx: Cipher,
    Rx: Cipher,
{
    type Error = <Codec<Tx> as Encoder<B>>::Error;

    fn encode(&mut self, item: B, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.tx.encode(item, dst)
    }
}

impl<Tx, Rx> Decoder for BiCodec<Tx, Rx>
where
    Tx: Cipher,
    Rx: Cipher,
{
    type Item = <Codec<Rx> as Decoder>::Item;
    type Error = <Codec<Rx> as Decoder>::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.rx.decode(src)
    }
}

/// Codec supporting encrypting and decrypting data according to the control noise protocol
/// using the specified cipher state.
pub struct Codec<C>
where
    C: Cipher,
{
    /// The cipher state to use to encode and decode message payloads.
    pub cipher_state: CipherState<C>,
}

impl<C> From<CipherState<C>> for Codec<C>
where
    C: Cipher,
{
    fn from(value: CipherState<C>) -> Self {
        Codec {
            cipher_state: value,
        }
    }
}

impl<B, C> Encoder<B> for Codec<C>
where
    C: Cipher,
    B: AsRef<[u8]>,
{
    type Error = std::io::Error;

    fn encode(&mut self, b: B, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let b = b.as_ref();
        let max_data_chunk = MAX_MESSAGE_SIZE - (3 + C::tag_len()); // 3 = header len

        for chunk in b.chunks(max_data_chunk) {
            let hdr = Header {
                typ: MessageType::Record,
                len: U16::new(chunk.len() as u16 + C::tag_len() as u16),
            };

            dst.put(hdr.as_bytes());

            let data_start = dst.len();

            dst.put(chunk);
            dst.put_bytes(0, C::tag_len());

            self.cipher_state
                .encrypt_in_place(&mut dst[data_start..], chunk.len());
        }

        Ok(())
    }
}

impl<C> Decoder for Codec<C>
where
    C: Cipher,
{
    type Error = std::io::Error;
    type Item = BytesMut;

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

        src.advance(3);
        let mut body = src.split_to(len);

        match header.typ {
            MessageType::Record => {
                match self.cipher_state.decrypt_in_place(&mut body, len) {
                    Ok(n) => body.truncate(n),
                    Err(()) => {
                        tracing::error!("decryption failed");
                        return Err(ErrorKind::InvalidData.into());
                    }
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
