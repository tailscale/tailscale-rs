use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::frame::{Body, FrameType};

/// Indication that the client-server connection is unhealthy.
///
/// A UTF-8 string follows in the additional payload section which should be
/// interpreted as error text. An empty additional payload clears the error state.
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
#[repr(C)]
pub struct Health;

impl Body for Health {
    const FRAME_TYPE: FrameType = FrameType::Health;
}
