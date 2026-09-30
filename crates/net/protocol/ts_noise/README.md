# ts_noise

Noise protocol implementations for tailscale.

This is not a general purpose Noise protocol library. It only implements the two specific
handshake patterns that Tailscale requires (Noise IK for the control protocol, and Noise IKpsk2
for wireguard).

## Architecture

The `core` module provides handshake state types that expose the primitive operations that Noise
handshake patterns are built from. It tries to limit some incorrect combinations of the primitives
through the type system. For example, performing an encryption/decryption of part of the handshake
is represented as a separate type that can only be obtained by first performing a handshake step that
derives a single-use AEAD key.

the `ik` and `ikpsk2` modules build on `core` and provide strongly typed implementations of the
corresponding handshake patterns.

This crate's responsibility ends when a handshake successfully concludes and produces a pair of
session keys. It's up to the caller to use those keys appropriately for the duration of the session,
in accordance with the upper level protocol being implemented. See the `ts_control_noise` and
`ts_tunnel` crates for the two uses in this codebase.