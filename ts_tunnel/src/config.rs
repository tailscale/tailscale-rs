use rand::{
    Rng, RngExt,
    distr::{Distribution, StandardUniform},
};
use ts_keys::NodePublicKey;

/// A handle for a wireguard peer.
#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub u32);

/// A wireguard symmetric pre-shared key.
#[derive(Copy, Clone)]
pub struct Psk([u8; 32]);

impl From<[u8; 32]> for Psk {
    fn from(bytes: [u8; 32]) -> Self {
        Psk(bytes)
    }
}

impl AsRef<[u8]> for Psk {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Psk {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl Distribution<Psk> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Psk {
        Psk(rng.random())
    }
}

/// The cryptographic configuration for a wireguard peer.
pub struct PeerConfig {
    /// The peer's public key.
    pub key: NodePublicKey,
    /// The pre-shared key to use for the peer, for post-quantum resistance.
    pub psk: Psk,
}
