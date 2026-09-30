use ts_keys::NodePublicKey;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::frame::{Body, FrameType};

/// An incoming packet from the derp server.
///
/// The data payload follows this message immediately.
#[derive(
    Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes, Unaligned,
)]
#[repr(C, packed)]
pub struct RecvPacket {
    /// The sender's public key.
    pub src: NodePublicKey,
}

impl Body for RecvPacket {
    const FRAME_TYPE: FrameType = FrameType::RecvPacket;
}
