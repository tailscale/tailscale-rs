use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::frame::{Body, FrameType};

/// Empty message to keep the connection alive.
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
#[repr(C)]
#[deprecated = "use Ping/Pong instead"]
pub struct KeepAlive;

#[allow(deprecated)]
impl Body for KeepAlive {
    const FRAME_TYPE: FrameType = FrameType::KeepAlive;
}
