use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::frame::{Body, FrameType};

/// Indicate that this derp server is the client's preferred node.
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
#[repr(C)]
pub struct NotePreferred {
    /// Whether this is the client's home region (`0x1`) or not (`0x0`).
    pub is_home: u8,
}

impl Body for NotePreferred {
    const FRAME_TYPE: FrameType = FrameType::NotePreferred;
}
