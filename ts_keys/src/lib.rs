#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

mod keystate;
mod macros;

#[doc(inline)]
pub use keystate::NodeState;
use macros::{
    _create_x25519_base_key_type, create_x25519_keypair_types, create_x25519_private_key_type,
    create_x25519_public_key_type,
};

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

// The client never handles challenge private keys, so we only create a public key type rather than
// public/private/keypair types.
create_x25519_public_key_type!(
    /// The X25519 public key of a challenge issued by control to a Tailnet node during registration.
    ChallengePublicKey,
    "chalpub"
);

// The client never handles DERP server private keys, so we only create a public key type rather
// than public/private/keypair types.
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
