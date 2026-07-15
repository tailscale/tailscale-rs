//! Supporting machinery for executing Noise handshakes.
//!
//! This is not a general-purpose Noise protocol library. The provided functionality is
//! sufficient to execute the two protocols that Tailscale cares about (IK and IKpsk2).
//!
//! This module only provides the primitive operations found in Noise handshakes. It is
//! the caller's responsibility to chain the primitives together correctly to produce the
//! desired handshake pattern.
//!
//! This module uses typestates to make some invalid sequences of operations compile-time
//! errors, in an effort to make protocol construction errors more obvious. This does not
//! cover all possible invalid sequences, it is still the caller's responsibility to ensure
//! that their sequence correctly reflects the desired handshake pattern.

use aead::AeadInPlace;
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hkdf::SimpleHkdf;
use zerocopy::IntoBytes;
use zeroize::ZeroizeOnDrop;

/// Initialize a ChaCha20Poly1305 cipher with the given key.
fn must_cipher(key: [u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(&key.into())
}

/// Use HKDF to derive N 32-byte values.
///
/// # Panics
///
/// If you request more bytes than the KDF can provide. Never panics for N <= 3.
fn must_hkdf<const N: usize>(chaining_key: &[u8; 32], key: &[u8]) -> [[u8; 32]; N] {
    let kdf = SimpleHkdf::<Blake2s256>::new(Some(chaining_key), key);
    let mut ret = [[0; 32]; N];
    kdf.expand(&[], ret.as_flattened_mut()).unwrap();
    ret
}

/// A symmetric session.
pub struct Session {
    /// The key to send data.
    pub initiator_to_responder: chacha20poly1305::Key,
    /// The key to receive data.
    pub responder_to_initiator: chacha20poly1305::Key,
    /// Local endpoint's role in the handshake.
    pub role: Role,
}

/// Base Noise handshake state.
#[derive(Clone, ZeroizeOnDrop)]
pub struct State {
    hash: [u8; 32],
    chaining_key: [u8; 32],
}

/// The role of the local peer in the handshake.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Role {
    /// Local peer initiated the handshake.
    Initiator,
    /// Remote peer initiated the handshake.
    Responder,
}

impl State {
    /// Initialize a new Noise handshake.
    ///
    /// `protocol_name` is the Noise protocol name as specified
    /// in <https://noiseprotocol.org/noise.html#protocol-names-and-modifiers>.
    pub fn new(protocol_name: &[u8]) -> State {
        let init = Blake2s256::digest(protocol_name);
        State {
            hash: init.into(),
            chaining_key: init.into(),
        }
    }

    /// Mix data into the handshake state.
    ///
    /// This is the MixHash() operation in the Noise spec.
    #[inline]
    pub fn mix_hash(self, data: &[u8]) -> Self {
        self.mix_hash_gather(&[data])
    }

    /// Like mix_hash, but the data can be provided in multiple non-contiguous pieces.
    pub fn mix_hash_gather(mut self, data: &[&[u8]]) -> Self {
        let mut h = Blake2s256::new_with_prefix(self.hash);
        for d in data {
            h.update(d);
        }
        h.finalize_into(self.hash.as_mut_bytes().into());
        self
    }

    /// Mix a public key into the handshake state.
    ///
    /// This should only be used to mix in the ephemeral public key in psk handshake variants,
    /// in accordance with sections 9.2 and 9.3 of the Noise spec. Use [`State::mix_dh`] if
    /// you're looking to MixKey the result of an X25519 operation.
    ///
    /// This is the MixHash(ephemeral)+MixKey(ephemeral) operations in the Noise spec.
    pub fn mix_hash_and_key(mut self, public: &x25519_dalek::PublicKey) -> State {
        self = self.mix_hash(public.as_ref());
        let [ck] = must_hkdf(&self.chaining_key, public.as_ref());
        State {
            hash: self.hash,
            chaining_key: ck,
        }
    }

    /// Perform an X25519 operation, and mix the result into the handshake state.
    ///
    /// This is the MixKey(DH(private, public)) operation in the Noise spec.
    pub fn mix_dh(
        self,
        private: &x25519_dalek::StaticSecret,
        public: &x25519_dalek::PublicKey,
    ) -> StateWithAead {
        let shared = private.diffie_hellman(public);
        let [ck, k] = must_hkdf(&self.chaining_key, shared.as_ref());
        StateWithAead {
            state: State {
                hash: self.hash,
                chaining_key: ck,
            },
            aead: must_cipher(k),
        }
    }

    /// Finalize the handshake.
    ///
    /// This is the Split() operation in the Noise spec.
    pub fn finish(self, role: Role) -> Session {
        let [initiator_to_responder, responder_to_initiator] = must_hkdf(&self.chaining_key, &[]);
        Session {
            initiator_to_responder: initiator_to_responder.into(),
            responder_to_initiator: responder_to_initiator.into(),
            role,
        }
    }
}

/// A pre-shared symmetric key.
pub type Psk = [u8; 32];

/// The authentication tag of an AEAD ciphertext.
pub type AeadTag = [u8; 16];

/// Noise handshake state when AEAD operations are available.
///
/// For the supported handshake patterns, when the handshake is in this state there are
/// only two valid ways to continue:
///
/// - Perform an AEAD operation ([`StateWithAead::seal`] or [`StateWithAead::open`]), which
///   consumes the AEAD and returns a plain [`State`].
/// - Mix additional key material into the handshake ([`StateWithAead::mix_dh`] or
///   [`StateWithAead::mix_psk`], which returns an updated [`StateWithAead`].
pub struct StateWithAead {
    // Note: StateWithAead doesn't derive ZeroizeOnDrop, because doing so forces a bunch of
    // unnecessary clones in its impl. All its fields are themselves ZeroizeOnDrop, so the
    // default drop implementation still zeroizes in practice, while also letting us move
    // individual fields out of the struct when needed.
    //
    // If you are adding a new field here, you MUST think through whether that field needs
    // to be zeroized, and make it ZeroizeOnDrop.
    state: State,
    aead: ChaCha20Poly1305,
}

impl StateWithAead {
    /// Perform an X25519 operation, and mix the result into the handshake state.
    ///
    /// This is the MixKey(DH(private, public)) operation in the Noise spec.
    pub fn mix_dh(
        self,
        private: &x25519_dalek::StaticSecret,
        public: &x25519_dalek::PublicKey,
    ) -> StateWithAead {
        self.state.mix_dh(private, public)
    }

    /// Mix a pre-shared symmetric key into the handshake state.
    ///
    /// This is the MixKeyAndHash() operation in the Noise spec.
    pub fn mix_psk(self, psk: &Psk) -> StateWithAead {
        let [ck, h, k] = must_hkdf(&self.state.chaining_key, psk);
        StateWithAead {
            state: State {
                hash: self.state.hash,
                chaining_key: ck,
            }
            .mix_hash(&h),
            aead: must_cipher(k),
        }
    }

    /// Seal `cleartext` in place.
    ///
    /// `cleartext` is overwritten with ciphertext, and the authentication tag is written to `tag`.
    ///
    /// This is the EncryptAndHash() operation in the Noise spec.
    pub fn seal(self, cleartext: &mut [u8], tag: &mut AeadTag) -> State {
        let nonce = [0; 12];
        let res = self
            .aead
            .encrypt_in_place_detached(&nonce.into(), &self.state.hash, cleartext)
            .unwrap();
        res.write_to(tag).unwrap();

        self.state.mix_hash_gather(&[cleartext, tag])
    }

    /// Decrypt `ciphertext` in place, authenticating with `tag`.
    ///
    /// If successful, `ciphertext` is overwritten with cleartext. Returns `None` if decryption
    /// fails, implicitly terminating the handshake.
    ///
    /// This is the DecryptAndHash() operation in the Noise spec.
    pub fn open(self, ciphertext: &mut [u8], tag: &AeadTag) -> Option<State> {
        // On successful decryption, we have to mix the ciphertext into the handshake state.
        // This pairs awkwardly with the in place crypto we're doing, where a successful decryption
        // overwrites the ciphertext.
        // Instead, update the handshake hash before the decryption attempt. This is okay because
        // we discard the handshake state entirely on decryption failure.
        let hash = self.state.hash;
        let state = self.state.mix_hash_gather(&[ciphertext, tag]);

        let nonce = [0; 12];
        self.aead
            .decrypt_in_place_detached(&nonce.into(), &hash, ciphertext, tag.into())
            .ok()?;

        Some(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroize() {
        // This is a regression test which checks that the crypto primitives we use zeroize
        // their key material properly.
        //
        // As of 2026-06, the rustcrypto chacha20poly1305 crate (version 0.10.0) implements zeroize
        // unconditionally. The upcoming 0.11.0 release makes zeroization conditional on a new
        // crate feature, so if we're not careful at dependency update time we could silently
        // disable zeroization of Noise session keys and weaken the forward secrecy properties
        // of ts_tunnel and ts_control_noise.
        //
        // This regression test was motivated by that problem: it will fail to compile if our
        // x25519 and chacha20poly1305 primitives don't implement zeroize as we expect. If you're
        // here because you updated our dependencies and this test no longer compiles, you may need
        // to turn on the `zeroize` feature on the chacha20poly1305 crate.
        fn assert_implements<T: ZeroizeOnDrop>() {}

        // Crypto primitives
        assert_implements::<x25519_dalek::StaticSecret>();
        assert_implements::<ChaCha20Poly1305>();

        // Handshake state
        assert_implements::<State>();
        // StateWithAead is not ZeroizeOnDrop even though all its fields are, see comment in its
        // definition.
    }
}
