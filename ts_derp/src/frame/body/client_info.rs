use ts_keys::NodePublicKey;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{
    Nonce,
    frame::{Body, FrameType},
};

/// Sent from client to server as part of the initial handshake, containing the client's
/// public key and capabilities.
///
/// An encrypted JSON-formatted [`ClientInfoPayload`] follows this message immediately.
#[derive(Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes)]
#[repr(C)]
pub struct ClientInfo {
    /// The client's public key.
    pub key: NodePublicKey,
    /// A nonce to decrypt the payload.
    pub nonce: Nonce,
}

impl Body for ClientInfo {
    const FRAME_TYPE: FrameType = FrameType::ClientInfo;
}

/// Payload associated with [`ClientInfo`].
#[derive(serde::Serialize)]
pub struct ClientInfoPayload {
    /// Whether this client can ack pings.
    pub can_ack_pings: bool,
    /// If this client is a prober.
    pub is_prober: bool,
    /// Mesh key. Only used for server-to-server conns.
    pub mesh_key: String,
    /// Protocol version the client is using.
    pub version: i32,
}
