#![doc = include_str!("../README.md")]
#![no_std]

use crate::alloc::string::ToString;
extern crate alloc;

mod keystate;
mod macros;

use alloc::{string::String, vec::Vec};
use core::{
    fmt,
    fmt::{Debug, Display, Formatter, Write},
    marker::PhantomData,
    str::FromStr,
};

pub use keystate::{NodeState, PersistState};
use macros::{x25519_pair, x25519_public};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer, de, de::Visitor};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
use zeroize::ZeroizeOnDrop;

/// Errors that may occur when parsing a string into a key type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Key string was formatted incorrectly.
    #[error("key string was formatted incorrectly")]
    InvalidFormat,

    /// Key was the wrong length.
    #[error("key was the wrong length")]
    WrongLength,

    /// Parsed prefix did not match the key type.
    #[error("parsed prefix did not match the key type")]
    BadPrefix,
}

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

fn parse_hex(s: &str, want_prefix: &'static str) -> Result<[u8; 32], ParseError> {
    let total_len = want_prefix.len() + 1 + X25519_LEN_HEX_STR;
    if s.len() != total_len {
        return Err(ParseError::WrongLength);
    }

    let mut parts = s.split(':');
    let Some(prefix) = parts.next() else {
        return Err(ParseError::InvalidFormat);
    };
    if prefix != want_prefix {
        return Err(ParseError::BadPrefix);
    }

    let Some(hex_str) = parts.next() else {
        return Err(ParseError::WrongLength);
    };
    if hex_str.len() != X25519_LEN_HEX_STR {
        return Err(ParseError::WrongLength);
    }

    // s.split(':') should only return 2 parts: the prefix and the hex string. If
    // the string contained additional colons, it's malformed and not a valid key
    // string.
    if parts.next().is_some() {
        return Err(ParseError::InvalidFormat);
    }

    let mut key = [0u8; X25519_LEN_BYTES];
    for i in (0..X25519_LEN_HEX_STR).step_by(2) {
        let slice = hex_str.get(i..i + 2).unwrap();
        let keyidx = i / 2;
        let x = u8::from_str_radix(slice, 16).map_err(|_| ParseError::InvalidFormat)?;
        key[keyidx] = x;
    }
    Ok(key)
}

fn write_hex(key: [u8; 32], prefix: &'static str, out: &mut impl Write) -> fmt::Result {
    write!(out, "{}:", prefix)?;
    for b in key.iter() {
        write!(out, "{b:02x}")?;
    }
    Ok(())
}

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
pub struct Public<T: X25519Public> {
    key: [u8; 32],
    _marker: PhantomData<T>,
}

impl<T: X25519Public> Public<T> {
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

impl<T: X25519Public> FromStr for Public<T> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key = parse_hex(s, T::PUBLIC_KEY_PREFIX)?;
        Ok(Public {
            key,
            _marker: PhantomData,
        })
    }
}

impl<T: X25519Public> Debug for Public<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write_hex(self.key, T::PUBLIC_KEY_PREFIX, f)
    }
}

impl<T: X25519Public> Display for Public<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        <Self as Debug>::fmt(self, f)
    }
}

impl<T: X25519Public> From<Public<T>> for ::x25519_dalek::PublicKey {
    fn from(v: Public<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Public> From<&Public<T>> for ::x25519_dalek::PublicKey {
    fn from(v: &Public<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Public> From<Public<T>> for ::crypto_box::PublicKey {
    fn from(v: Public<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Public> From<&Public<T>> for ::crypto_box::PublicKey {
    fn from(v: &Public<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Public> From<::x25519_dalek::PublicKey> for Public<T> {
    fn from(v: ::x25519_dalek::PublicKey) -> Self {
        let key = v.to_bytes();
        Self {
            key,
            _marker: PhantomData,
        }
    }
}

impl<T: X25519Public> From<&::x25519_dalek::PublicKey> for Public<T> {
    fn from(v: &::x25519_dalek::PublicKey) -> Self {
        let key = v.to_bytes();
        Self {
            key,
            _marker: PhantomData,
        }
    }
}

impl<T: X25519Public> From<[u8; 32]> for Public<T> {
    fn from(key: [u8; 32]) -> Self {
        Self {
            key,
            _marker: PhantomData,
        }
    }
}

/// A serde parser for hex-encoded keys.
#[cfg(feature = "serde")]
struct KeyVisitor(&'static str);

#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for KeyVisitor {
    type Value = [u8; 32];

    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "a string with the prefix '{}:' followed by {} hex characters",
            self.0, X25519_LEN_HEX_STR
        )
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        parse_hex(v, self.0).map_err(|e| ::serde::de::Error::custom(e))
    }
}

#[cfg(feature = "serde")]
impl<'de, T: X25519Public> ::serde::Deserialize<'de> for Public<T> {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(KeyVisitor(T::PUBLIC_KEY_PREFIX))
            .map(|key| Public {
                key,
                _marker: PhantomData,
            })
    }
}

#[cfg(feature = "serde")]
impl<T: X25519Public> ::serde::Serialize for Public<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ::serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}

/// The private half of an asymetric keypair.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Private<T: X25519Private> {
    key: [u8; 32],
    _marker: PhantomData<T>,
}

impl<T: X25519Private> Private<T> {
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
    /// This method recalculates the public key on every call. Consider instead using [`Pair`] to
    /// hold both halves of the keypair long-term.
    pub fn public_key(&self) -> Public<T> {
        let key = ::crypto_box::SecretKey::from(self.key)
            .public_key()
            .to_bytes();
        Public {
            key,
            _marker: PhantomData,
        }
    }

    /// Package up the key for serialization.
    ///
    /// To avoid accidental disclosure of private key material, [`Private`] does not implement
    /// any methods that allow access to or serialization of the private key. Code that needs to
    /// do so (e.g. to persist keys to disk) must explicitly convert the key to an [`Export`] at
    /// the point where serialization is required.
    pub fn export(self) -> Export<T> {
        Export {
            key: self.key,
            _marker: PhantomData,
        }
    }
}

impl<T: X25519Private> Default for Private<T> {
    fn default() -> Self {
        Self::random()
    }
}

impl<T: X25519Private> FromStr for Private<T> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key = parse_hex(s, T::PRIVATE_KEY_PREFIX)?;
        Ok(Private {
            key,
            _marker: PhantomData,
        })
    }
}

impl<T: X25519Private> From<Private<T>> for Public<T> {
    fn from(v: Private<T>) -> Self {
        v.public_key()
    }
}

impl<T: X25519Private> From<Private<T>> for ::x25519_dalek::StaticSecret {
    fn from(v: Private<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Private> From<&Private<T>> for ::x25519_dalek::StaticSecret {
    fn from(v: &Private<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Private> From<Private<T>> for ::crypto_box::SecretKey {
    fn from(v: Private<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Private> From<&Private<T>> for ::crypto_box::SecretKey {
    fn from(v: &Private<T>) -> Self {
        v.key.into()
    }
}

impl<T: X25519Private> Debug for Private<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:[redacted]", T::PRIVATE_KEY_PREFIX)
    }
}

impl<T: X25519Private> Display for Private<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        <Self as Debug>::fmt(self, f)
    }
}

/// The serializable form of the private half of an asymmetric keypair.
///
/// Serializable private keys should be created as close as possible to the point of serialization
/// by calling [`Private::export`], and held only for the duration of the serialization operation.
///
/// To discourage holding onto serializable values for extended time, [`Export`] does not offer
/// easy access to cryptographic operations. The serializable key must be converted to its
/// non-serializable form first, via [`Export::import`] or an [`Into`] impl.
#[derive(Clone, Debug, IntoBytes, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct Export<T: X25519Private> {
    key: [u8; 32],
    _marker: PhantomData<T>,
}

impl<T: X25519Private> Export<T> {
    /// Create a new random key.
    pub fn random() -> Self {
        let key = ::x25519_dalek::StaticSecret::random().to_bytes();
        Self {
            key,
            _marker: PhantomData,
        }
    }

    /// Return the private key as an untyped byte array.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.key
    }

    /// Return the key in its non-serializable form, which allows cryptographic use.
    pub fn import(&self) -> Private<T> {
        self.into()
    }

    /// Return the key as an untyped [`Vec`] of bytes.
    ///
    /// Unless you specifically need a Vec, prefer using [`Export::as_bytes`] to get an exact
    /// size array.
    pub fn as_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl<T: X25519Private> From<Export<T>> for Private<T> {
    fn from(v: Export<T>) -> Self {
        Private {
            key: v.key,
            _marker: PhantomData,
        }
    }
}

impl<T: X25519Private> From<&Export<T>> for Private<T> {
    fn from(v: &Export<T>) -> Self {
        Private {
            key: v.key,
            _marker: PhantomData,
        }
    }
}

impl<T: X25519Private> From<Export<T>> for Pair<T> {
    fn from(v: Export<T>) -> Self {
        Private::from(v).into()
    }
}

impl<T: X25519Private> From<&Export<T>> for Pair<T> {
    fn from(v: &Export<T>) -> Self {
        Private::from(v).into()
    }
}

impl<T: X25519Private> From<[u8; 32]> for Export<T> {
    fn from(key: [u8; 32]) -> Self {
        Self {
            key,
            _marker: PhantomData,
        }
    }
}

impl<T: X25519Private> TryFrom<Vec<u8>> for Export<T> {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl<T: X25519Private> TryFrom<&Vec<u8>> for Export<T> {
    type Error = ();

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let array: [u8; 32] = value.as_slice().try_into().map_err(|_| ())?;
        Ok(array.into())
    }
}

impl<T: X25519Private> FromStr for Export<T> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key = parse_hex(s, T::PRIVATE_KEY_PREFIX)?;
        Ok(Export {
            key,
            _marker: PhantomData,
        })
    }
}

#[cfg(feature = "serde")]
impl<T: X25519Private> ::serde::Serialize for Export<T> {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = String::with_capacity(T::PRIVATE_KEY_HEX_STR_LEN);
        write_hex(self.key, T::PRIVATE_KEY_PREFIX, &mut s).unwrap();
        ser.serialize_str(s.as_ref())
    }
}

#[cfg(feature = "serde")]
impl<'de, T: X25519Private> ::serde::Deserialize<'de> for Export<T> {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        d.deserialize_str(KeyVisitor(T::PRIVATE_KEY_PREFIX))
            .map(|key| Export {
                key,
                _marker: PhantomData,
            })
    }
}

/// An asymmetric keypair.
#[derive(Clone)]
pub struct Pair<T: X25519Private> {
    /// The public half of the pair.
    pub public: Public<T>,
    /// The private half of the pair.
    pub private: Private<T>,
}

impl<T: X25519Private> Pair<T> {
    /// Create a new random keypair.
    pub fn random() -> Self {
        let private = Private::random();
        let public = private.public_key();
        Self { public, private }
    }

    /// Package up the keypair for serialization.
    ///
    /// To avoid accidental disclosure of private key material, [`Pair`] does not implement
    /// any methods that allow access to or serialization of the private key. Code that needs to
    /// do so (e.g. to persist keys to disk) must explicitly convert the pair to an [`Export`] at
    /// the point where serialization is required.
    pub fn export(self) -> Export<T> {
        self.private.export()
    }
}

impl<T: X25519Private> Debug for Pair<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        ::core::fmt::Debug::fmt(&self.public, f)
    }
}

impl<T: X25519Private> Default for Pair<T> {
    fn default() -> Self {
        Self::random()
    }
}

impl<T: X25519Private> From<Private<T>> for Pair<T> {
    fn from(private: Private<T>) -> Self {
        let public = private.public_key();
        Self { private, public }
    }
}

impl<T: X25519Private> From<Pair<T>> for ::x25519_dalek::StaticSecret {
    fn from(v: Pair<T>) -> Self {
        v.private.into()
    }
}

impl<T: X25519Private> From<&Pair<T>> for ::x25519_dalek::StaticSecret {
    fn from(v: &Pair<T>) -> Self {
        v.private.key.into()
    }
}

impl<T: X25519Private> From<Pair<T>> for ::crypto_box::SecretKey {
    fn from(v: Pair<T>) -> Self {
        v.private.into()
    }
}

impl<T: X25519Private> From<&Pair<T>> for ::crypto_box::SecretKey {
    fn from(v: &Pair<T>) -> Self {
        v.private.key.into()
    }
}

impl<T: X25519Private> From<Pair<T>> for ::x25519_dalek::PublicKey {
    fn from(v: Pair<T>) -> Self {
        v.public.into()
    }
}

impl<T: X25519Private> From<&Pair<T>> for ::x25519_dalek::PublicKey {
    fn from(v: &Pair<T>) -> Self {
        v.public.key.into()
    }
}

impl<T: X25519Private> From<Pair<T>> for ::crypto_box::PublicKey {
    fn from(v: Pair<T>) -> Self {
        v.public.into()
    }
}

impl<T: X25519Private> From<&Pair<T>> for ::crypto_box::PublicKey {
    fn from(v: &Pair<T>) -> Self {
        v.public.key.into()
    }
}

impl<T: X25519Private> AsRef<Private<T>> for Pair<T> {
    fn as_ref(&self) -> &Private<T> {
        &self.private
    }
}

impl<T: X25519Private> AsRef<Public<T>> for Pair<T> {
    fn as_ref(&self) -> &Public<T> {
        &self.public
    }
}

impl<T: X25519Private> FromStr for Pair<T> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Private::from_str(s)?.into())
    }
}

/// An x25519_dalek keypair.
///
/// This type exists because x25519_dalek does not provide a pair type, but we often find it
/// useful to handle both public and private halves in x25519_dalek form in crypto code. Having
/// this type avoids clunkier APIs or having to recalculate the public key repeatedly.
///
/// You should only use this type when low-level cryptography code requires it. For general code,
/// use [`Pair`] instead and convert to a [`DalekPair`] at the interface with crypto code.
#[derive(Clone)]
pub struct DalekPair {
    /// The public half of the keypair.
    pub public: x25519_dalek::PublicKey,
    /// The private half of the keypair.
    pub private: x25519_dalek::StaticSecret,
}

impl DalekPair {
    /// Create a new random keypair.
    pub fn random() -> Self {
        let private = x25519_dalek::StaticSecret::random();
        let public = x25519_dalek::PublicKey::from(&private);
        Self { private, public }
    }
}

impl<T: X25519Private> From<Pair<T>> for DalekPair {
    fn from(v: Pair<T>) -> Self {
        Self::from(&v)
    }
}

impl<T: X25519Private> From<&Pair<T>> for DalekPair {
    fn from(v: &Pair<T>) -> Self {
        Self {
            public: v.into(),
            private: v.into(),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, T: X25519Private> ::serde::Deserialize<'de> for Pair<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Export::<T>::deserialize(deserializer).map(Pair::from)
    }
}

x25519_public!(
    /// Challenge key issued by control during registration.
    ChallengeKey,
    "chalpub"
);

x25519_public!(
    /// Key of a DERP server.
    DerpServerKey,
    "derp"
);

x25519_pair!(
    /// A key used in the disco protocol.
    DiscoKey,
    "discokey",
    "privkey",
);

x25519_pair!(
    /// A device's machine key.
    MachineKey,
    "mkey",
    "privkey",
);

x25519_pair!(
    /// A Tailnet Lock key.
    NetworkLockKey,
    "nlpub",
    "nlpriv",
);

x25519_pair!(
    /// A device's node key.
    NodeKey,
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

        assert_implements::<Private<DiscoKey>>();
        assert_implements::<Private<NodeKey>>();
        assert_implements::<Private<NetworkLockKey>>();
        assert_implements::<Private<MachineKey>>();
    }
}
