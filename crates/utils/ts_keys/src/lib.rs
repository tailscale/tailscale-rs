#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

pub mod dalek;
mod keystate;
mod macros;
mod util;

use alloc::string::ToString;
use core::{
    fmt,
    fmt::{Debug, Display, Formatter},
    str::FromStr,
};

pub use dalek::X25519KeyPair;
#[doc(inline)]
pub use keystate::{NodeState, PersistState};
use macros::{
    create_x25519_keypair_types, create_x25519_private_key_type, create_x25519_public_key_type,
};
#[cfg(feature = "serde")]
use serde::de::Error;

use crate::util::write_hex;

mod private {
    use core::{fmt::Debug, str::FromStr};

    use crate::util::ParseError;

    pub trait SealedExportable: Clone + Debug + FromStr<Err = ParseError> {
        const KEY_PREFIX: &'static str;

        fn as_bytes(&self) -> &[u8; 32];

        fn from_bytes(bytes: [u8; 32]) -> Self;
    }
}

/// A key that can be exported for serialization.
pub trait ExportableKey: private::SealedExportable {
    /// Convert the key to its serializable form.
    fn export(&self) -> Export<Self>;
}

impl<T: private::SealedExportable> ExportableKey for T {
    fn export(&self) -> Export<Self> {
        Export(self.clone())
    }
}

/// A wrapped key that can be serialized, but not used for cryptographic operations.
///
/// This type exists as a guard against accidentally serializing private keys: the regular
/// key type can be used for cryptographic operations, but cannot be serialized. Conversely,
/// this wrapper can be serialized, but not used for cryptography without first converting it
/// back to the underlying key type using [`Export::import`].
///
/// Keys should be converted to exportable form as close as possible to the point of
/// serialization, to make it harder to accidentally serialize the key at an unexpected point.
#[derive(Clone)]
pub struct Export<T: ExportableKey>(T);

impl<T: ExportableKey> Export<T> {
    /// Remove the export wrapper, returning the underlying key that can be used for
    /// cryptographic operations.
    pub fn import(&self) -> T {
        self.0.clone()
    }

    /// Create a key from its raw byte representation.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(T::from_bytes(bytes))
    }

    /// Return the raw byte representation of the key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl<T: ExportableKey> Debug for Export<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // The debug impl is redacted even for exportable keys. It's never correct to dump a private
        // key into logs.
        Debug::fmt(&self.0, f)
    }
}

impl<T: ExportableKey> Display for Export<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write_hex(self.0.as_bytes(), T::KEY_PREFIX, f)
    }
}

impl<T: ExportableKey> FromStr for Export<T> {
    type Err = <T as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        <T as FromStr>::from_str(s).map(Export)
    }
}

#[cfg(feature = "serde")]
impl<'de, T: ExportableKey> serde::Deserialize<'de> for Export<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        let s = <&str>::deserialize(deserializer)?;
        T::from_str(s).map_err(D::Error::custom).map(Self)
    }
}

#[cfg(feature = "serde")]
impl<T: ExportableKey> ::serde::Serialize for Export<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ::serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// The client never handles challenge private keys, so we only create a public key type rather than
// public/private/keypair types.
create_x25519_public_key_type!(
    /// The X25519 public key of a challenge issued by control to a Tailnet node during registration.
    ChallengePublicKey,
    "chalpub"
);

create_x25519_public_key_type!(
    /// The X25519 public key of a DERP server.
    DerpServerPublicKey,
    "derp"
);

create_x25519_keypair_types!(
    /// The X25519 public key a Tailscale node uses for the Disco protocol.
    DiscoPublicKey,
    "discokey",
    /// The X25519 private key a Tailscale node uses for the Disco protocol.
    DiscoPrivateKey,
    "privkey",
    /// The X25519 public/private key pair a Tailscale node uses for the Disco protocol.
    DiscoKeyPair
);

create_x25519_keypair_types!(
    /// The X25519 public key of a unique piece of hardware running one or more Tailscale nodes.
    /// Also the key type sent from a control server to a Tailscale node during the initial control
    /// handshake.
    MachinePublicKey,
    "mkey",
    /// The X25519 private key of a unique piece of hardware running one or more Tailscale nodes.
    MachinePrivateKey,
    "privkey",
    /// The X25519 public/private key pair of a unique piece of hardware running one or more
    /// Tailscale nodes.
    MachineKeyPair
);

create_x25519_keypair_types!(
    /// The X25519 public key of a Tailscale node for use with Tailnet Lock.
    NetworkLockPublicKey,
    "nlpub",
    /// The X25519 private key of a Tailscale node for use with Tailnet Lock.
    NetworkLockPrivateKey,
    "nlpriv",
    /// The X25519 public/private key pair of a Tailscale node for use with Tailnet Lock.
    NetworkLockKeyPair
);

create_x25519_keypair_types!(
    /// The X25519 public key of a Tailscale node.
    NodePublicKey,
    "nodekey",
    /// The X25519 private key of a Tailscale node.
    NodePrivateKey,
    "privkey",
    /// The X25519 public/private key pair of a Tailscale node.
    NodeKeyPair
);

#[cfg(test)]
mod tests {
    use zeroize::ZeroizeOnDrop;

    use super::*;

    #[test]
    fn test_zeroize() {
        fn assert_implements<T: ZeroizeOnDrop>() {}

        assert_implements::<DiscoPrivateKey>();
        assert_implements::<MachinePrivateKey>();
        assert_implements::<NetworkLockPrivateKey>();
        assert_implements::<NodePrivateKey>();
    }
}
