use std::fmt;

use crate::frame::error::Error;

/// Indicates the type of message contained in a DERP frame.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Payload contains the server public key.
    ServerKey = 0x01,

    /// The client's connection info and public key.
    ClientInfo = 0x02,
    /// The server's connection info.
    ServerInfo = 0x03,
    /// Send a packet to a specified peer.
    SendPacket = 0x04,
    /// Send a packet on behalf of another peer.
    ForwardPacket = 0x0a,
    /// A packet sent from the server on behalf of another peer.
    RecvPacket = 0x05,

    /// Empty-payload message meant to keep the connection alive.
    #[deprecated = "use Ping/Pong instead"]
    KeepAlive = 0x06,

    /// Indicate whether this server is the client's preferred derp server.
    NotePreferred = 0x07,

    /// Signals to the client that a previous sender is no longer connected.
    ///
    /// That is, if `A` sent to `B`, and `A` disconnects, the server sends this frame type
    /// to `B` so that `B` can forget the reverse path to `A`. It is also sent to `A` if
    /// `A` tries to send a `CallMeMaybe` to `B` and the server has no record of `B`
    /// (currently, this would only happen if there is a bug).
    PeerGone = 0x08,

    /// Like [`FrameType::PeerGone`], but between meshed members of a derp region.
    PeerPresent = 0x09,

    /// How one DERP node in a regional mesh subscribes to the others in the region.
    WatchConns = 0x10,

    /// Privileged frame that closes the provided peer's connection, used for cluster load
    /// balancing.
    ClosePeer = 0x11,

    /// To be echoed back by a [`FrameType::Pong`].
    Ping = 0x12,
    /// Response to a [`FrameType::Ping`].
    Pong = 0x13,

    /// Sent from the server to the client to tell the client that the connection is
    /// unhealthy somehow.
    ///
    /// Currently, the only unhealthy state is if the connection is detected as a duplicate.
    Health = 0x14,

    /// Sent from the server to client for the server to declare that it's restarting.
    Restarting = 0x15,
}

/// The entity that originates a frame.
pub enum Originator {
    Server,
    Client,
}

impl FrameType {
    /// Report the originator of this message kind.
    pub const fn originator(&self) -> Originator {
        #[allow(deprecated)]
        match self {
            FrameType::Health
            | FrameType::ServerKey
            | FrameType::ServerInfo
            | FrameType::PeerPresent
            | FrameType::Restarting
            | FrameType::RecvPacket
            | FrameType::WatchConns
            | FrameType::KeepAlive
            | FrameType::Ping => Originator::Server,
            _ => Originator::Client,
        }
    }

    /// Report whether this frame type is privileged (requires the mesh key).
    pub const fn is_privileged(&self) -> bool {
        matches!(
            self,
            FrameType::PeerPresent | FrameType::ClosePeer | FrameType::WatchConns
        )
    }
}

impl TryFrom<u8> for FrameType {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Ok(match v {
            0x01 => FrameType::ServerKey,
            0x02 => FrameType::ClientInfo,
            0x03 => FrameType::ServerInfo,
            0x04 => FrameType::SendPacket,
            0x0a => FrameType::ForwardPacket,
            0x05 => FrameType::RecvPacket,
            #[allow(deprecated)]
            0x06 => FrameType::KeepAlive,
            0x07 => FrameType::NotePreferred,
            0x08 => FrameType::PeerGone,
            0x09 => FrameType::PeerPresent,
            0x10 => FrameType::WatchConns,
            0x11 => FrameType::ClosePeer,
            0x12 => FrameType::Ping,
            0x13 => FrameType::Pong,
            0x14 => FrameType::Health,
            0x15 => FrameType::Restarting,
            _ => return Err(Error::InvalidFrameType(v)),
        })
    }
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<FrameType> for u8 {
    fn from(v: FrameType) -> Self {
        v as u8
    }
}
