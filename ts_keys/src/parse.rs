use core::{
    fmt,
    fmt::{Formatter, Write},
    marker::PhantomData,
};

use serde::{de, de::Visitor};

use crate::{PublicKey, X25519_LEN_BYTES, X25519_LEN_HEX_STR, X25519Public};

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

/// Parse a hex-formatted key into an untyped byte array.
///
/// Keys are in the format `<identifying prefix>:<64 hex digits>`. The key string's
/// prefix must match the provided `want_prefix`.
pub fn parse_hex(s: &str, want_prefix: &'static str) -> Result<[u8; 32], ParseError> {
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

/// Write an untyped byte array representing a key to `out`, in tailscale's conventional hex
/// encoding.
///
/// Keys are in the format `<prefix>:<64 hex digits>`.
pub fn write_hex(key: [u8; 32], prefix: &'static str, out: &mut impl Write) -> fmt::Result {
    write!(out, "{}:", prefix)?;
    for b in key.iter() {
        write!(out, "{b:02x}")?;
    }
    Ok(())
}

/// A serde::de::Visitor that parses a hex-formatted key with the given identifying prefix
/// into an untyped 32-byte array.
#[cfg(feature = "serde")]
pub struct KeyVisitor(&'static str);

impl KeyVisitor {
    pub fn new(prefix: &'static str) -> Self {
        Self(prefix)
    }
}

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
impl<'de, T: X25519Public> ::serde::Deserialize<'de> for PublicKey<T> {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(KeyVisitor(T::PUBLIC_KEY_PREFIX))
            .map(|key| PublicKey {
                key,
                _marker: PhantomData,
            })
    }
}
