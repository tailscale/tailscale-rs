use bytes::{Buf, BufMut, BytesMut};
use ts_hexdump::{AsHexExt, Case};
use zerocopy::{FromBytes, IntoBytes};

use crate::frame::{Header, RawFrame, RawHeader};

/// Implements [`tokio_util::codec::Encoder`] and [`tokio_util::codec::Decoder`] for
/// the derp protocol.
pub struct Codec;

impl<'a, 'b> tokio_util::codec::Encoder<(RawFrame<'a>, &'b [u8])> for Codec {
    type Error = std::io::Error;

    #[tracing::instrument(skip_all, fields(frame_hdr = ?frame.header, frame_body_len = frame.raw_body.len(), extra_payload_len = extra_payload.len()), err, level = "trace")]
    fn encode(
        &mut self,
        (frame, extra_payload): (RawFrame<'a>, &'b [u8]),
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let header: RawHeader = frame.header.into();

        debug_assert_eq!(header.len(), { frame.raw_body.len() + extra_payload.len() });

        tracing::trace!(raw_header = ?header);

        dst.put_slice(header.as_bytes());
        dst.put_slice(frame.raw_body);
        dst.put_slice(extra_payload);

        tracing::trace!(
            len = dst.len(),
            "dst:\n{}",
            dst.iter().hexdump_string(Case::Lower)
        );

        Ok(())
    }
}

impl<'a> tokio_util::codec::Encoder<RawFrame<'a>> for Codec {
    type Error = std::io::Error;

    #[tracing::instrument(skip_all, fields(frame_hdr = ?frame.header, frame_body_len = frame.raw_body.len()), err, level = "trace")]
    fn encode(&mut self, frame: RawFrame<'a>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        <Self as tokio_util::codec::Encoder<(RawFrame<'a>, &'static [u8])>>::encode(
            self,
            (frame, &[]),
            dst,
        )
    }
}

impl tokio_util::codec::Decoder for Codec {
    type Item = yoke::Yoke<RawFrame<'static>, Vec<u8>>;
    type Error = std::io::Error;

    #[tracing::instrument(skip_all, fields(src_len = src.len(), src_cap = src.capacity()), err, level = "trace")]
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < Header::LEN_BYTES {
            return Ok(None);
        }

        let (header, post_header_len) = {
            let (header, rest) = RawHeader::ref_from_prefix(src).map_err(|e| {
                tracing::error!(err = %e);
                std::io::Error::other("invalid raw header")
            })?;

            let header: Header = header.try_into().map_err(std::io::Error::other)?;
            (header, rest.len())
        };

        let header_len = src.len() - post_header_len;
        let full_packet_len = header_len + header.len() as usize;

        tracing::trace!(
            header_len,
            post_header_len,
            full_packet_len,
            orig_len = src.len(),
            ?header
        );

        if full_packet_len > src.len() {
            tracing::trace!("incomplete packet, bail out");
            return Ok(None);
        }

        src.advance(header_len);
        let payload = src.split_to(header.len() as _);

        let ret = yoke::Yoke::attach_to_cart(payload.to_vec(), move |raw_body| RawFrame {
            header,
            raw_body,
        });

        Ok(Some(ret))
    }
}
