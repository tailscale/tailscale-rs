use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::frame::{Body, FrameType};

/// Response to a server [`Ping`][crate::frame::Ping] containing the same payload.
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
#[repr(C)]
pub struct Pong {
    /// The payload to echo back to the server.
    ///
    /// Should be the same data contained in the originating [`Ping`][crate::frame::Ping].
    pub payload: [u8; 8],
}

impl Body for Pong {
    const FRAME_TYPE: FrameType = FrameType::Pong;
}
