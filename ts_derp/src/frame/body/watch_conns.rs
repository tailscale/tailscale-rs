use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::frame::{Body, FrameType};

/// How one derp node in a regional mesh subscribes to others in the region.
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
#[repr(C)]
pub struct WatchConns;

impl Body for WatchConns {
    const FRAME_TYPE: FrameType = FrameType::WatchConns;
}
