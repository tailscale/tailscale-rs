use core::convert::Infallible;
use std::string::ToString;

use zerocopy::{AlignmentError, CastError, ConvertError, KnownLayout, SizeError};

use crate::frame;

/// Errors that can occur when trying to parse a DERP frame from a packet.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Packet too short.
    #[error("cannot parse {0}-byte packet; valid frames are at least 5 bytes")]
    InvalidPacketLength(usize),
    /// Could not parse frame header.
    #[error("cannot parse frame header from packet: {0}")]
    InvalidFrameHeader(String),
    /// Unknown frame type.
    #[error("invalid frame type {0:02X}")]
    InvalidFrameType(u8),
    /// Invalid frame length for frame type.
    #[error("frame type {0} has max length of {2} bytes; header length is {1}")]
    InvalidFrameLengthForType(frame::FrameType, usize, usize),
    /// Invalid body length for frame type.
    #[error("frame type {0} has min length of {2} bytes; body length is {1}")]
    InvalidBodyLengthForType(frame::FrameType, usize, usize),
    /// Error parsing frame body.
    #[error("cannot parse {0} frame body from packet: {1}")]
    InvalidFrameBody(frame::FrameType, String),
    /// Frame unexpectedly had a payload.
    #[error("frame type {0} cannot have a payload, but {1} bytes remained in packet")]
    InvalidFrameStructure(frame::FrameType, usize),
    /// Invalid magic bytes.
    #[error("invalid magic byte sequence in ServerKey frame")]
    InvalidMagic,
    /// Unknown peer gone reason.
    #[error("invalid peer gone reason: {0}")]
    InvalidPeerGoneReason(u8),
    /// Incomplete frame.
    #[error("incomplete frame")]
    IncompleteFrame,
    /// Decryption failed.
    #[error("could not decrypt frame payload")]
    DecryptionFailed(String),
    /// Encryption failed.
    #[error("could not encrypt frame payload")]
    EncryptionFailed,
    /// Invalid public key.
    #[error("could not parse public key from string")]
    InvalidKey,
}

impl From<CastError<&[u8], frame::RawHeader>> for Error {
    fn from(value: CastError<&[u8], frame::RawHeader>) -> Self {
        Error::InvalidFrameHeader(value.to_string())
    }
}

impl<B: frame::Body + KnownLayout>
    From<ConvertError<AlignmentError<&[u8], B>, SizeError<&[u8], B>, Infallible>> for Error
{
    fn from(
        value: ConvertError<AlignmentError<&[u8], B>, SizeError<&[u8], B>, Infallible>,
    ) -> Self {
        Error::InvalidFrameBody(B::FRAME_TYPE, value.to_string())
    }
}
