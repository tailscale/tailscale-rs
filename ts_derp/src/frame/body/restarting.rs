use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, network_endian::U32};

use crate::frame::{Body, FrameType};

/// Sent from server to client to indicate that the server is restarting.
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
#[repr(C)]
pub struct Restarting {
    /// How long to wait before reconnecting (milliseconds).
    pub reconnect: U32,
    /// How long to try to reconnect overall (milliseconds).
    pub total: U32,
}

impl Body for Restarting {
    const FRAME_TYPE: FrameType = FrameType::Restarting;
}
