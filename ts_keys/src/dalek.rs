//! Utility type for working with the x25519_dalek crate.

use crate::{KeyPair, X25519Private};

/// An x25519_dalek keypair.
///
/// This type exists because x25519_dalek does not provide a pair type, but we often find it
/// useful to handle both public and private halves in x25519_dalek form in crypto code. Having
/// this type avoids clunkier APIs or having to recalculate the public key repeatedly.
///
/// You should only use this type when low-level cryptography code requires it. For general code,
/// use [`KeyPair`] instead and convert to a [`DalekKeyPair`] at the interface with
/// crypto code.
#[derive(Clone)]
pub struct DalekKeyPair {
    /// The public half of the keypair.
    pub public: x25519_dalek::PublicKey,
    /// The private half of the keypair.
    pub private: x25519_dalek::StaticSecret,
}

impl DalekKeyPair {
    /// Create a new random keypair.
    pub fn random() -> Self {
        let private = x25519_dalek::StaticSecret::random();
        let public = x25519_dalek::PublicKey::from(&private);
        Self { private, public }
    }
}

impl<T: X25519Private> From<KeyPair<T>> for DalekKeyPair {
    fn from(v: KeyPair<T>) -> Self {
        Self::from(&v)
    }
}

impl<T: X25519Private> From<&KeyPair<T>> for DalekKeyPair {
    fn from(v: &KeyPair<T>) -> Self {
        Self {
            public: v.into(),
            private: v.into(),
        }
    }
}
