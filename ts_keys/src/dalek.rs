//! Utility type for working with the x25519_dalek crate.

/// An x25519_dalek private key, and its associated public key.
///
/// This exists because the x25519_dalek crate doesn't have a pair type, which results in
/// awkward APIs and pubkey recomputations when we have a strongly typed keypair of our own that
/// we want to convert cheaply for crypto ops.
#[derive(Clone)]
pub struct X25519KeyPair {
    /// The keypair's public key.
    pub public: ::x25519_dalek::PublicKey,
    /// The keypair's private key.
    pub private: ::x25519_dalek::StaticSecret,
}

impl X25519KeyPair {
    /// Return a new random keypair.
    pub fn random() -> Self {
        let private = ::x25519_dalek::StaticSecret::random();
        let public = ::x25519_dalek::PublicKey::from(&private);
        Self { public, private }
    }
}
