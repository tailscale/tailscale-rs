use ts_keys::NodePublicKey;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::frame::{Body, FrameType};

/// Mesh message to closes the provided peer's connection.
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
#[repr(C)]
pub struct ClosePeer {
    /// The peer whose connection should be closed.
    pub key: NodePublicKey,
}

impl Body for ClosePeer {
    const FRAME_TYPE: FrameType = FrameType::ClosePeer;
}
