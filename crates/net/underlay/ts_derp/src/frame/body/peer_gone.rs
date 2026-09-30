use core::fmt;

use ts_keys::NodePublicKey;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::frame;

/// Indication from the server that a previous sender has disconnected.
#[derive(
    Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes, Unaligned,
)]
#[repr(C, packed)]
pub struct PeerGone {
    /// The server that disconnected.
    pub key: NodePublicKey,
    /// The reason code for the peer disconnection.
    pub raw_reason: u8,
}

impl PeerGone {
    /// Interpret the raw reason field as a [`PeerGoneReason`].
    pub fn reason(&self) -> Result<PeerGoneReason, frame::Error> {
        self.raw_reason.try_into()
    }
}

impl frame::Body for PeerGone {
    const FRAME_TYPE: frame::FrameType = frame::FrameType::PeerGone;
}

/// Code indicating why a DERP server can't find a path to a particular peer.
#[derive(Debug, Copy, Clone, KnownLayout, Immutable, IntoBytes)]
#[repr(u8)]
pub enum PeerGoneReason {
    /// The peer was connected to this DERP server, but has disconnected.
    Disconnected = 0x0,
    /// The DERP server doesn't know about this peer, meaning the peer has not connected to this
    /// DERP server for a long time, or has never connected to this DERP server. This is
    /// unexpected in normal ops.
    NotHere = 0x1,
}

impl fmt::Display for PeerGoneReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl TryFrom<u8> for PeerGoneReason {
    type Error = frame::Error;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Ok(match v {
            0x0 => PeerGoneReason::Disconnected,
            0x1 => PeerGoneReason::NotHere,
            _ => return Err(frame::Error::InvalidPeerGoneReason(v)),
        })
    }
}

impl From<PeerGoneReason> for u8 {
    fn from(v: PeerGoneReason) -> Self {
        v as u8
    }
}
