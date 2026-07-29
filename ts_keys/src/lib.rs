#![doc = include_str!("../README.md")]
#![no_std]

use crate::alloc::string::ToString;
extern crate alloc;

pub mod dalek;
mod keystate;
mod parse;

use alloc::{string::String, vec::Vec};
use core::{
    fmt,
    fmt::{Debug, Display, Formatter},
    marker::PhantomData,
    str::FromStr,
};

pub use keystate::{NodeState, PersistState};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
use zeroize::ZeroizeOnDrop;

use crate::parse::{KeyVisitor, ParseError, parse_hex, write_hex};

/// A public key that can perform X25519 operations.
pub trait X25519Public {
    /// The descriptive prefix of the key when serialized to a string.
    const PUBLIC_KEY_PREFIX: &'static str;

    /// The length of the key in its serialized form.
    const PUBLIC_KEY_HEX_STR_LEN: usize = Self::PUBLIC_KEY_PREFIX.len() + 1 + X25519_LEN_HEX_STR;
}

/// A private key that can perform X25519 operations.
pub trait X25519Private: X25519Public {
    /// The descriptive prefix of the key when serialized to a string.
    const PRIVATE_KEY_PREFIX: &'static str;

    /// The length of the key in its serialized form.
    const PRIVATE_KEY_HEX_STR_LEN: usize = Self::PRIVATE_KEY_PREFIX.len() + 1 + X25519_LEN_HEX_STR;
}

const X25519_LEN_BYTES: usize = 32;
const X25519_LEN_HEX_STR: usize = X25519_LEN_BYTES * 2;

/// The public half of an asymmetric keypair.
#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Default,
    Hash,
    PartialOrd,
    Ord,
    FromBytes,
    IntoBytes,
    Immutable,
    KnownLayout,
    Unaligned,
)]
#[repr(C)]
pub struct PublicKey<T: X25519Public> {
    key: [u8; 32],
    _marker: PhantomData<T>,
}

impl<T: X25519Public> PublicKey<T> {
    /// Create a new random key.
    ///
    /// The key is derived from a randomly generated private key that is immediately thrown
    /// away, so although the key has all the right mathematical structure of a public key,
    /// it's useless in practice since the private half is unavailable.
    ///
    /// This is intended to facilitate tests in which some public key is needed to e.g. fill
    /// a data structure, but not to perform any cryptography.
    pub fn random() -> Self {
        let key = x25519_dalek::EphemeralSecret::random();
        Self {
            key: x25519_dalek::PublicKey::from(&key).to_bytes(),
            _marker: PhantomData,
        }
    }

    /// Return the public key as an untyped byte array.
    ///
    /// Avoid using this outside of serializing a key for transmission. Untyped keys introduce the
    /// risk of using the wrong key in a cryptographic operation, which can have dire security
    /// consequences.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.key
    }
}

impl<T: X25519Public> FromStr for PublicKey<T> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key = parse_hex(s, T::PUBLIC_KEY_PREFIX)?;
        Ok(PublicKey {
            key,
            _marker: PhantomData,
        })
    }
}

impl<T: X25519Public> Debug for PublicKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write_hex(self.key, T::PUBLIC_KEY_PREFIX, f)
    }
}

impl<T: X25519Public> Display for PublicKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        <Self as Debug>::fmt(self, f)
    }
}

impl<T: X25519Public> From<PublicKey<T>> for ::x25519_dalek::PublicKey {
    fn from(v: PublicKey<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Public> From<&PublicKey<T>> for ::x25519_dalek::PublicKey {
    fn from(v: &PublicKey<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Public> From<PublicKey<T>> for ::crypto_box::PublicKey {
    fn from(v: PublicKey<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Public> From<&PublicKey<T>> for ::crypto_box::PublicKey {
    fn from(v: &PublicKey<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Public> From<::x25519_dalek::PublicKey> for PublicKey<T> {
    fn from(v: ::x25519_dalek::PublicKey) -> Self {
        let key = v.to_bytes();
        Self {
            key,
            _marker: PhantomData,
        }
    }
}

impl<T: X25519Public> From<&::x25519_dalek::PublicKey> for PublicKey<T> {
    fn from(v: &::x25519_dalek::PublicKey) -> Self {
        let key = v.to_bytes();
        Self {
            key,
            _marker: PhantomData,
        }
    }
}

impl<T: X25519Public> From<[u8; 32]> for PublicKey<T> {
    fn from(key: [u8; 32]) -> Self {
        Self {
            key,
            _marker: PhantomData,
        }
    }
}

/// A serde parser for hex-encoded keys.
#[cfg(feature = "serde")]
impl<T: X25519Public> ::serde::Serialize for PublicKey<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ::serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}

/// The private half of an asymetric keypair.
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey<T: X25519Private> {
    key: [u8; 32],
    _marker: PhantomData<T>,
}

impl<T: X25519Private> PrivateKey<T> {
    /// Create a new private key from raw untyped bytes.
    ///
    /// This is an internal helper that's deliberately not exported, to make it harder to
    /// accidentally cast between key types.
    fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            _marker: PhantomData,
        }
    }

    /// Create a new random key.
    pub fn random() -> Self {
        let key = ::x25519_dalek::StaticSecret::random().to_bytes();
        Self {
            key,
            _marker: PhantomData,
        }
    }

    /// Calculate and return the public key that matches this private key.
    ///
    /// This method recalculates the public key on every call. Consider instead using [`KeyPair`] to
    /// hold both halves of the keypair long-term.
    pub fn public_key(&self) -> PublicKey<T> {
        let key = ::crypto_box::SecretKey::from(self.key)
            .public_key()
            .to_bytes();
        PublicKey {
            key,
            _marker: PhantomData,
        }
    }

    /// Package up the key for serialization.
    ///
    /// To avoid accidental disclosure of private key material, [`PrivateKey`] does not implement
    /// any methods that allow access to or serialization of the private key. Code that needs to
    /// do so (e.g. to persist keys to disk) must explicitly convert the key to an [`ExportableKey`] at
    /// the point where serialization is required.
    pub fn export(self) -> ExportableKey<T> {
        ExportableKey(self)
    }
}

impl<T: X25519Private> Default for PrivateKey<T> {
    fn default() -> Self {
        Self::random()
    }
}

impl<T: X25519Private> FromStr for PrivateKey<T> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key = parse_hex(s, T::PRIVATE_KEY_PREFIX)?;
        Ok(PrivateKey::new(key))
    }
}

impl<T: X25519Private> From<PrivateKey<T>> for PublicKey<T> {
    fn from(v: PrivateKey<T>) -> Self {
        v.public_key()
    }
}

impl<T: X25519Private> From<PrivateKey<T>> for ::x25519_dalek::StaticSecret {
    fn from(v: PrivateKey<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Private> From<&PrivateKey<T>> for ::x25519_dalek::StaticSecret {
    fn from(v: &PrivateKey<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Private> From<PrivateKey<T>> for ::crypto_box::SecretKey {
    fn from(v: PrivateKey<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Private> From<&PrivateKey<T>> for ::crypto_box::SecretKey {
    fn from(v: &PrivateKey<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Private> Debug for PrivateKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[redacted]", T::PRIVATE_KEY_PREFIX)
    }
}

impl<T: X25519Private> Display for PrivateKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        <Self as Debug>::fmt(self, f)
    }
}

/// The serializable form of the private half of an asymmetric keypair.
///
/// Serializable private keys should be created as close as possible to the point of serialization
/// by calling [`PrivateKey::export`], and held only for the duration of the serialization operation.
///
/// To discourage holding onto serializable values for extended time, [`ExportableKey`] does not offer
/// easy access to cryptographic operations. The serializable key must be converted to its
/// non-serializable form first, via [`ExportableKey::import`] or an [`Into`] impl.
#[derive(Clone, Debug, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct ExportableKey<T: X25519Private>(PrivateKey<T>);

impl<T: X25519Private> ExportableKey<T> {
    /// Create a new random key.
    pub fn random() -> Self {
        Self(PrivateKey::random())
    }

    /// Return the private key as an untyped byte array.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.key
    }

    /// Return the key in its non-serializable form, which allows cryptographic use.
    pub fn import(&self) -> PrivateKey<T> {
        self.into()
    }

    /// Return the key as an untyped [`Vec`] of bytes.
    ///
    /// Unless you specifically need a Vec, prefer using [`ExportableKey::as_bytes`] to get an exact
    /// size array.
    pub fn as_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl<T: X25519Private> From<ExportableKey<T>> for PrivateKey<T> {
    fn from(v: ExportableKey<T>) -> Self {
        v.0
    }
}

impl<T: X25519Private> From<&ExportableKey<T>> for PrivateKey<T> {
    fn from(v: &ExportableKey<T>) -> Self {
        PrivateKey::new(v.0.key)
    }
}

impl<T: X25519Private> From<ExportableKey<T>> for KeyPair<T> {
    fn from(v: ExportableKey<T>) -> Self {
        PrivateKey::from(v).into()
    }
}

impl<T: X25519Private> From<&ExportableKey<T>> for KeyPair<T> {
    fn from(v: &ExportableKey<T>) -> Self {
        PrivateKey::from(v).into()
    }
}

impl<T: X25519Private> From<[u8; 32]> for ExportableKey<T> {
    fn from(key: [u8; 32]) -> Self {
        Self(PrivateKey::new(key))
    }
}

impl<T: X25519Private> TryFrom<Vec<u8>> for ExportableKey<T> {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl<T: X25519Private> TryFrom<&Vec<u8>> for ExportableKey<T> {
    type Error = ();

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let array: [u8; 32] = value.as_slice().try_into().map_err(|_| ())?;
        Ok(array.into())
    }
}

impl<T: X25519Private> FromStr for ExportableKey<T> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key = parse_hex(s, T::PRIVATE_KEY_PREFIX)?;
        Ok(Self(PrivateKey::new(key)))
    }
}

#[cfg(feature = "serde")]
impl<T: X25519Private> ::serde::Serialize for ExportableKey<T> {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = String::with_capacity(T::PRIVATE_KEY_HEX_STR_LEN);
        write_hex(self.0.key, T::PRIVATE_KEY_PREFIX, &mut s).unwrap();
        ser.serialize_str(s.as_ref())
    }
}

#[cfg(feature = "serde")]
impl<'de, T: X25519Private> ::serde::Deserialize<'de> for ExportableKey<T> {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        d.deserialize_str(KeyVisitor::new(T::PRIVATE_KEY_PREFIX))
            .map(PrivateKey::new)
            .map(ExportableKey)
    }
}

/// An asymmetric keypair.
#[derive(Clone)]
pub struct KeyPair<T: X25519Private> {
    /// The public half of the pair.
    pub public: PublicKey<T>,
    /// The private half of the pair.
    pub private: PrivateKey<T>,
}

impl<T: X25519Private> KeyPair<T> {
    /// Create a new random keypair.
    pub fn random() -> Self {
        let private = PrivateKey::random();
        let public = private.public_key();
        Self { public, private }
    }

    /// Package up the private key part of the keypair for serialization.
    ///
    /// To avoid accidental disclosure of private key material, [`KeyPair`] does not implement
    /// any methods that allow access to or serialization of the private key. Code that needs to
    /// do so (e.g. to persist keys to disk) must explicitly convert the pair to an [`ExportableKey`] at
    /// the point where serialization is required.
    pub fn export(self) -> ExportableKey<T> {
        self.private.export()
    }
}

impl<T: X25519Private> Debug for KeyPair<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        ::core::fmt::Debug::fmt(&self.public, f)
    }
}

impl<T: X25519Private> Default for KeyPair<T> {
    fn default() -> Self {
        Self::random()
    }
}

impl<T: X25519Private> From<PrivateKey<T>> for KeyPair<T> {
    fn from(private: PrivateKey<T>) -> Self {
        let public = private.public_key();
        Self { private, public }
    }
}

impl<T: X25519Private> From<KeyPair<T>> for ::x25519_dalek::StaticSecret {
    fn from(v: KeyPair<T>) -> Self {
        v.private.into()
    }
}

impl<T: X25519Private> From<&KeyPair<T>> for ::x25519_dalek::StaticSecret {
    fn from(v: &KeyPair<T>) -> Self {
        v.private.key.into()
    }
}

impl<T: X25519Private> From<KeyPair<T>> for ::crypto_box::SecretKey {
    fn from(v: KeyPair<T>) -> Self {
        v.private.into()
    }
}

impl<T: X25519Private> From<&KeyPair<T>> for ::crypto_box::SecretKey {
    fn from(v: &KeyPair<T>) -> Self {
        v.private.key.into()
    }
}

impl<T: X25519Private> From<KeyPair<T>> for ::x25519_dalek::PublicKey {
    fn from(v: KeyPair<T>) -> Self {
        v.public.into()
    }
}

impl<T: X25519Private> From<&KeyPair<T>> for ::x25519_dalek::PublicKey {
    fn from(v: &KeyPair<T>) -> Self {
        v.public.key.into()
    }
}

impl<T: X25519Private> From<KeyPair<T>> for ::crypto_box::PublicKey {
    fn from(v: KeyPair<T>) -> Self {
        v.public.into()
    }
}

impl<T: X25519Private> From<&KeyPair<T>> for ::crypto_box::PublicKey {
    fn from(v: &KeyPair<T>) -> Self {
        v.public.key.into()
    }
}

impl<T: X25519Private> AsRef<PrivateKey<T>> for KeyPair<T> {
    fn as_ref(&self) -> &PrivateKey<T> {
        &self.private
    }
}

impl<T: X25519Private> AsRef<PublicKey<T>> for KeyPair<T> {
    fn as_ref(&self) -> &PublicKey<T> {
        &self.public
    }
}

impl<T: X25519Private> FromStr for KeyPair<T> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(PrivateKey::from_str(s)?.into())
    }
}

#[cfg(feature = "serde")]
impl<'de, T: X25519Private> ::serde::Deserialize<'de> for KeyPair<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        ExportableKey::<T>::deserialize(deserializer).map(KeyPair::from)
    }
}

macro_rules! x25519_public {
    ($(#[$attr:meta])* $marker_type:ident, $public_prefix:literal) => {
        $(#[$attr])*
        #[derive(Copy, Clone, Eq, PartialEq, Default, Hash, PartialOrd, Ord)]
        pub struct $marker_type;

        impl X25519Public for $marker_type {
            const PUBLIC_KEY_PREFIX: &'static str = $public_prefix;
        }
    };
}

macro_rules! x25519_pair {
    (
        $(#[$attr:meta])*
        $marker_type:ident,
        $public_prefix:literal,
        $private_prefix:literal,
    ) => {
        $(#[$attr])*
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Default, Hash, PartialOrd, Ord)]
        pub struct $marker_type;

        impl X25519Public for $marker_type {
            const PUBLIC_KEY_PREFIX: &'static str = $public_prefix;
        }

        impl X25519Private for $marker_type {
            const PRIVATE_KEY_PREFIX: &'static str = $private_prefix;
        }
    };
}

x25519_public!(
    /// Challenge key issued by control during registration.
    Challenge,
    "chalpub"
);

x25519_public!(
    /// Key of a DERP server.
    DerpServer,
    "derp"
);

x25519_pair!(
    /// A key used in the disco protocol.
    Disco,
    "discokey",
    "privkey",
);

x25519_pair!(
    /// A device's machine key.
    Machine,
    "mkey",
    "privkey",
);

x25519_pair!(
    /// A Tailnet Lock key.
    NetworkLock,
    "nlpub",
    "nlpriv",
);

x25519_pair!(
    /// A device's node key.
    Node,
    "nodekey",
    "privkey",
);

#[cfg(test)]
mod tests {
    use zeroize::ZeroizeOnDrop;

    use super::*;

    #[test]
    fn test_zeroize() {
        fn assert_implements<T: ZeroizeOnDrop>() {}

        assert_implements::<PrivateKey<Disco>>();
        assert_implements::<PrivateKey<Node>>();
        assert_implements::<PrivateKey<NetworkLock>>();
        assert_implements::<PrivateKey<Machine>>();
    }
}
