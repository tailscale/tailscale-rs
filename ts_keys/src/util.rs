use alloc::string::String;
use core::{fmt, fmt::Write};

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

//const X25519_LEN_BYTES: usize = 32;
const X25519_LEN_HEX_STR: usize = 64;

pub const fn key_hex_str_len(prefix: &'static str) -> usize {
    prefix.len() + 1 + X25519_LEN_HEX_STR
}

/// Parse a hex-formatted key into an untyped byte array.
///
/// Keys are in the format `<identifying prefix>:<64 hex digits>`. The key string's
/// prefix must match the provided `want_prefix`.
pub fn parse_hex(s: &str, want_prefix: &'static str) -> Result<[u8; 32], ParseError> {
    if s.len() != key_hex_str_len(want_prefix) {
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

    let mut key = [0u8; 32];
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

pub fn to_hex_string(key: [u8; 32], prefix: &'static str) -> String {
    let mut ret = String::with_capacity(key_hex_str_len(prefix));
    write_hex(key, prefix, &mut ret).unwrap();
    ret
}

pub fn random_x25519_private() -> [u8; 32] {
    x25519_dalek::StaticSecret::random().to_bytes()
}

pub fn random_x25519_public() -> [u8; 32] {
    let private = x25519_dalek::StaticSecret::random();
    x25519_dalek::PublicKey::from(&private).to_bytes()
}

pub fn x25519_public_from_private(k: impl Into<x25519_dalek::StaticSecret>) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&k.into()).to_bytes()
}
