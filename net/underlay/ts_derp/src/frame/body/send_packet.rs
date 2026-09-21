use ts_keys::NodePublicKey;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::frame::{Body, FrameType};

/// Send a packet to the peer with the specified key.
///
/// The data payload follows this message immediately.
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
#[repr(C)]
pub struct SendPacket {
    /// The peer to send the data to.
    pub dest: NodePublicKey,
}

impl Body for SendPacket {
    const FRAME_TYPE: FrameType = FrameType::SendPacket;
}
