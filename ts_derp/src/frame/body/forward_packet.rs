use ts_keys::{Node, PublicKey};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::frame::{Body, FrameType};

/// Like [`SendPacket`][crate::frame::SendPacket], but on behalf of another peer.
///
/// Data payload follows immediately.
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
#[repr(C)]
pub struct ForwardPacket {
    /// Sender on behalf of which we're forwarding the packet.
    pub src: PublicKey<Node>,
    /// The peer to which the packet should be sent.
    pub dest: PublicKey<Node>,
}

impl Body for ForwardPacket {
    const FRAME_TYPE: FrameType = FrameType::ForwardPacket;
}
