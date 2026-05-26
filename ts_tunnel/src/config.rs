use ts_keys::NodePublicKey;

/// A handle for a wireguard peer.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub u32);

/// A wireguard symmetric pre-shared key.
pub type Psk = ts_noise::core::Psk;

/// The cryptographic configuration for a wireguard peer.
pub struct PeerConfig {
    /// The peer's public key.
    pub key: NodePublicKey,
    /// The pre-shared key to use for the peer, for post-quantum resistance.
    pub psk: Psk,
}
