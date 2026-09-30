use ts_keys::NodePublicKey;

/// A handle for a wireguard peer.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub u32);

/// A wireguard symmetric pre-shared key.
pub type Psk = ts_noise::core::Psk;

/// The cryptographic configuration for a wireguard peer.
pub struct PeerConfig {
    /// The ID used to refer to this peer in [`crate::Endpoint`] APIs.
    pub id: PeerId,
    /// The peer's public key.
    pub key: NodePublicKey,
    /// The pre-shared key to use for the peer, for post-quantum resistance.
    pub psk: Psk,
}

impl PeerConfig {
    /// Return a [`PeerConfig`] with the given configuration.
    pub fn new(id: PeerId, key: NodePublicKey, psk: Psk) -> Self {
        Self { id, key, psk }
    }
}
