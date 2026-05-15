use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::frame::{Body, FrameType};

/// Message from the server to verify connectivity.
///
/// Clients should respond with [`Pong`][crate::frame::Pong].
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
#[repr(C)]
pub struct Ping {
    /// Data to send to the peer.
    ///
    /// Should be echoed back exactly in the corresponding [`Pong`][crate::frame::Pong].
    pub payload: [u8; 8],
}

impl Body for Ping {
    const FRAME_TYPE: FrameType = FrameType::Ping;
}

impl From<Ping> for crate::frame::Pong {
    fn from(value: Ping) -> Self {
        Self {
            payload: value.payload,
        }
    }
}
