use ts_keys::{NodeKey, Public};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::frame::{Body, FrameType};

/// Like [`SendPacket`][crate::frame::SendPacket], but on behalf of another peer.
///
/// Data payload follows immediately.
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
#[repr(C)]
pub struct ForwardPacket {
    /// Sender on behalf of which we're forwarding the packet.
    pub src: Public<NodeKey>,
    /// The peer to which the packet should be sent.
    pub dest: Public<NodeKey>,
}

impl Body for ForwardPacket {
    const FRAME_TYPE: FrameType = FrameType::ForwardPacket;
}
