//! Wire message types for Noise handshakes.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::core::AeadTag;

/// A type that implements all the zerocopy traits for unconditional conversion
/// to/from bytes.
///
/// This is the trait bound for handshake payloads.
pub trait Pod: FromBytes + IntoBytes + Immutable + KnownLayout + Unaligned {}

impl<T: FromBytes + IntoBytes + Immutable + KnownLayout + Unaligned> Pod for T {}

/// A Noise handshake initiation message.
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct Init<P: Pod> {
    /// The initiator's ephemeral public key.
    pub ephemeral_pub: [u8; 32],
    /// The initiator's static public key.
    ///
    /// Encrypted on the wire by the handshake-derived AEAD.
    pub static_pub: [u8; 32],
    /// The AEAD authenticator tag for the static public key.
    pub static_pub_tag: AeadTag,
    /// The handshake initiation payload. This is a freeform field that
    /// higher level protocols (e.g. WireGuard) can use to exchange further
    /// information during the handshake without requiring additional round
    /// trips.
    ///
    /// The security guarantees for this payload are weaker than the security
    /// guarantees provided by a fully established session (i.e. after handshake
    /// completion):
    ///  - No forward secrecy protection: if an attacker compromises the responder's
    ///    static private key, they can decrypt all past handshake initiation payloads
    ///    that they've recorded.
    ///  - There is no replay protection, the handshake (including its payload) can
    ///    be replayed by an attacker at a later date. If replay protection is desired,
    ///    the higher level protocol must provide that property (and may use the payload
    ///    field as a component of that).
    ///  - The initiation as a whole is vulnerable to key compromise impersonation: an
    ///    attacker who compromises the responder's static private key can forge handshake
    ///    initiations from any other peer identity. This is normally not a significant
    ///    concern because once a static private key is compromised it's broadly considered
    ///    to be "game over" in our specific threat model, but it does mean that you have
    ///    to be careful to not allow forged payload data to e.g. execute arbitrary code or
    ///    grant out-of-protocol capabilities.
    ///
    /// Encrypted on the wire by the handshake-derived AEAD.
    pub payload: P,
    /// The AEAD authenticator tag for the payload.
    pub payload_tag: AeadTag,
}

/// A Noise handshake response message.
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct Resp {
    /// The responder's ephemeral public key.
    pub ephemeral_pub: [u8; 32],
    /// The AEAD authenticator tag for the response.
    ///
    /// Technically this is the authenticator for the response payload (see the [`Init`] message
    /// for details), but in the protocols we need to implement the response payload is empty,
    /// so the payload tag acts purely as an overall authenticator for the entire handshake.
    pub auth_tag: AeadTag,
}
