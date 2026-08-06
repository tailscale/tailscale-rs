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
    fmt::{Display, Formatter},
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

mod private {
    use core::{fmt, fmt::Formatter, str::FromStr};

    use crate::util::ParseError;

    pub trait SealedExportable: Clone + FromStr<Err = ParseError> {
        fn write_hex(&self, out: &mut Formatter) -> fmt::Result;
    }
}

pub trait ExportableKey: private::SealedExportable {
    fn export(self) -> Export<Self>;
}

#[derive(Clone, Debug)]
pub struct Export<T: ExportableKey>(T);

impl<T: ExportableKey> Export<T> {
    pub fn import(&self) -> T {
        self.0.clone()
    }
}

impl<T: ExportableKey> Display for Export<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.0.write_hex(f)
    }
}

#[cfg(feature = "serde")]
impl<'de, T: ExportableKey> serde::Deserialize<'de> for Export<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        let s = <&str>::deserialize(deserializer)?;
        T::from_str(&s).map_err(D::Error::custom).map(Self)
    }
}

#[cfg(feature = "serde")]
impl<T: ExportableKey> ::serde::Serialize for Export<T> {
    fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
    where
        S: ::serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<T: ExportableKey> From<T> for Export<T> {
    fn from(k: T) -> Self {
        Self(k)
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
