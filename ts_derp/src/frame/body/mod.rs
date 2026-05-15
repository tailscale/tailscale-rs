use crate::frame::FrameType;

mod client_info;
mod close_peer;
mod forward_packet;
mod health;
mod keep_alive;
mod note_preferred;
mod peer_gone;
mod peer_present;
mod ping;
mod pong;
mod recv_packet;
mod restarting;
mod send_packet;
mod server_info;
mod server_key;
mod watch_conns;

pub use client_info::{ClientInfo, ClientInfoPayload};
pub use close_peer::ClosePeer;
pub use forward_packet::ForwardPacket;
pub use health::Health;
#[allow(deprecated)]
pub use keep_alive::KeepAlive;
pub use note_preferred::NotePreferred;
pub use peer_gone::{PeerGone, PeerGoneReason};
pub use peer_present::PeerPresent;
pub use ping::Ping;
pub use pong::Pong;
pub use recv_packet::RecvPacket;
pub use restarting::Restarting;
pub use send_packet::SendPacket;
pub use server_info::{ServerInfo, ServerInfoPayload};
pub use server_key::ServerKey;
pub use watch_conns::WatchConns;

/// Represents a derp frame body.
pub trait Body {
    /// Frame type for this frame body.
    const FRAME_TYPE: FrameType;
}
