use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::frame::{Body, Error, Header, RawHeader};

/// A raw DERP frame.
#[derive(Debug, Copy, Clone, PartialEq, Eq, yoke::Yokeable)]
pub struct RawFrame<'a> {
    /// This frame's header.
    pub header: Header,

    /// This frame's raw body bytes.
    ///
    /// If the frame was parsed with [`RawFrame::parse`], this field contains both the frame
    /// body and additional subsequent data.
    pub raw_body: &'a [u8],
}

impl<'a> RawFrame<'a> {
    /// Parse a frame from the specified byte slice.
    ///
    /// # Returns
    ///
    /// A [`RawFrame`] and the rest of the bytes (that were not consumed) as a tuple, if
    /// there was no error.
    ///
    /// A successfully parsed frame always has a [`RawFrame::raw_body`] with a length
    /// exactly equal to its [`Header::len`].
    pub fn parse(b: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let (raw_header, rest) = RawHeader::ref_from_prefix(b)?;
        let header: Header = raw_header.try_into()?;

        let (this_frame, rest) = rest
            .split_at_checked(header.len() as _)
            .ok_or(Error::IncompleteFrame)?;

        Ok((
            RawFrame {
                header,
                raw_body: this_frame,
            },
            rest,
        ))
    }

    /// Attempt to interpret the frame body as a `T`.
    ///
    /// Consults `T`'s [`Body`] implementation to check the expected frame type against the
    /// header.
    ///
    /// # Returns
    ///
    /// If the frame type matches, the body type `T` with a trailing byte slice carrying an
    /// additional payload. This additional payload contains the data payload in
    /// [`SendPacket`][crate::frame::SendPacket], for instance.
    pub fn as_type<T>(&self) -> Option<(&T, &[u8])>
    where
        T: Body + FromBytes + Immutable + KnownLayout,
    {
        if self.header.typ != T::FRAME_TYPE {
            return None;
        }

        T::ref_from_prefix(self.raw_body).ok()
    }

    /// Construct a new [`RawFrame`] from a [`Body`] and a specified additional
    /// `payload_len`.
    ///
    /// NB: this constructs a [`RawFrame`] that does _not_ contain the full payload
    /// in the `raw_body`. This is to accommodate outgoing messages which can't put the
    /// additional payload in the same buffer as the primary payload. See the
    /// [`Codec`][crate::frame::Codec] source for a usage example.
    pub fn from_body<T>(t: &'a T, payload_len: usize) -> Result<Self, Error>
    where
        T: Body + IntoBytes + Immutable,
    {
        let bytes = t.as_bytes();

        Ok(Self {
            header: Header::new(T::FRAME_TYPE, (bytes.len() + payload_len) as _)?,
            raw_body: bytes,
        })
    }
}
