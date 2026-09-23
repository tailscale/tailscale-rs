//! Derp framing implementation.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

mod body;
mod codec;
mod error;
mod frame_type;
mod header;
mod magic;
mod raw;

#[allow(deprecated)]
pub use body::KeepAlive;
pub use body::{
    Body, ClientInfo, ClientInfoPayload, ClosePeer, ForwardPacket, Health, NotePreferred, PeerGone,
    PeerGoneReason, PeerPresent, Ping, Pong, RecvPacket, Restarting, SendPacket, ServerInfo,
    ServerInfoPayload, ServerKey, WatchConns,
};
pub use codec::Codec;
pub use error::Error;
pub use frame_type::FrameType;
pub use header::{Header, RawHeader};
pub use magic::Magic;
pub use raw::RawFrame;

/// Maximum size (in bytes) of a packet sent via DERP, not including any on-wire framing overhead.
/// Equivalent to the max payload size of a [SendPacket], [ForwardPacket], or [RecvPacket] frame.
pub const MAX_PACKET_SIZE: usize = 64 << 10;

/// Maximum length (in bytes) of a [ClientInfo] or [ServerInfo] frame's payload, excluding the
/// key and nonce fields, and any on-wire framing overhead.
pub const MAX_INFO_LEN: usize = 1 << 20;

/// Minimum frequency (in seconds) at which the DERP server sends [`KeepAlive`] frames to each DERP
/// client. The server adds some jitter, so this timing is not exact, but 2x this value can be
/// considered a missed keep-alive.
pub const KEEP_ALIVE: usize = 60;

/// Current version of the DERP protocol; must be bumped whenever there's a wire-incompatible
/// change.
/// - Version 1 (zero on wire): consistent box headers, in use by employee dev nodes a bit
/// - Version 2: received packets have src addrs in [RecvPacket] frames at beginning
pub const PROTOCOL_VERSION: usize = 2;

/// IP address.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
pub struct Ip([u8; 16]);
