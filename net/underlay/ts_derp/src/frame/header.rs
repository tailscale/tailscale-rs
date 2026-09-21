use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, network_endian::U32};

use crate::frame;

/// The TLV header for the derp protocol as it appears on the wire.
///
/// Convert into [`Header`] for easier manipulation.
#[derive(Debug, Copy, Clone, KnownLayout, Immutable, IntoBytes, FromBytes)]
#[repr(C)]
pub struct RawHeader {
    typ: u8,
    len: U32,
}

impl RawHeader {
    /// Interpret the type field as a well-known [`frame::FrameType`].
    pub fn typ(&self) -> Result<frame::FrameType, frame::Error> {
        self.typ.try_into()
    }

    /// Report the length of this frame (excluding the 5-byte header length).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len.get() as usize
    }
}

/// Header for the derp protocol.
///
/// Convert to [`RawHeader`] for the wire format.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Header {
    /// The frame type.
    pub typ: frame::FrameType,
    len: u32,
}

impl Header {
    /// The length of a header in bytes on the wire.
    pub const LEN_BYTES: usize = 5;

    /// Construct a new frame of the specified type and length.
    ///
    /// May fail if the `len` exceeds `frame::MAX_PACKET_SIZE`.
    pub const fn new(typ: frame::FrameType, len: u32) -> Result<Self, frame::Error> {
        if len as usize > frame::MAX_PACKET_SIZE {
            return Err(frame::Error::InvalidPacketLength(len as _));
        }

        Ok(Self { typ, len })
    }

    /// Report the length of the associated frame (excluding the 5-byte header length).
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Set the len to `new_len`.
    pub const fn set_len(&mut self, new_len: u32) -> Result<(), frame::Error> {
        if new_len as usize > frame::MAX_PACKET_SIZE {
            return Err(frame::Error::InvalidPacketLength(new_len as _));
        }

        self.len = new_len;
        Ok(())
    }
}

impl TryFrom<&RawHeader> for Header {
    type Error = frame::Error;

    fn try_from(&RawHeader { typ, len }: &RawHeader) -> Result<Self, Self::Error> {
        let len = len.get();
        if len as usize > frame::MAX_PACKET_SIZE {
            return Err(frame::Error::InvalidPacketLength(len as _));
        }

        Ok(Self {
            typ: typ.try_into()?,
            len,
        })
    }
}

impl From<Header> for RawHeader {
    fn from(Header { typ, len }: Header) -> Self {
        Self {
            typ: typ as _,
            len: U32::new(len),
        }
    }
}
