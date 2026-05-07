use ts_keys::NodePublicKey;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, network_endian::U16};

use crate::frame::{Body, FrameType, Ip};

/// DERP mesh message indicating that the node with the given key has connected.
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
#[repr(C)]
pub struct PeerPresent {
    /// The connected peer's public key.
    pub key: NodePublicKey,
    /// The IP of the connected peer.
    pub ip: Ip,
    /// The port on which the peer connected.
    pub port: U16,
}

impl Body for PeerPresent {
    const FRAME_TYPE: FrameType = FrameType::PeerPresent;
}
