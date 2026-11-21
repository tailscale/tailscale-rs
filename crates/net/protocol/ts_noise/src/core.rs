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
use ml_kem::{
    B32, Decapsulate, Encapsulate,
    ml_kem_768::{DecapsulationKey, EncapsulationKey},
};
use zerocopy::IntoBytes;
use zeroize::ZeroizeOnDrop;

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

/// An AEAD cipher and its nonce counter.
///
/// Each Aead instance can only be used to perform two cryptographic operations, consuming
/// nonce values 0 and 1.
#[derive(Clone, ZeroizeOnDrop)]
struct Aead {
    cipher: ChaCha20Poly1305,
    nonce: u8,
}

impl Aead {
    fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&key.into()),
            nonce: 0,
        }
    }

    /// Return the next nonce to use for encryption or decryption.
    ///
    /// # Panics
    ///
    /// If this Aead has already produced 2 nonces. This is an additional sanity check, because
    /// the handshake patterns we implement never require more than 2 nonces per Aead, so trying
    /// to consume more indicates an implementation mistake.
    fn next_nonce(&mut self) -> [u8; 12] {
        if self.nonce >= 2 {
            panic!("Aead used more than twice");
        }
        let mut ret = [0; 12];
        ret[0] = self.nonce;
        self.nonce += 1;
        ret
    }
}

/// Base Noise handshake state.
#[derive(Clone, ZeroizeOnDrop)]
pub struct State {
    hash: [u8; 32],
    chaining_key: [u8; 32],
    cipher: Option<Aead>,
}

/// The role of the local peer in the handshake.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Role {
    /// Local peer initiated the handshake.
    Initiator,
    /// Remote peer initiated the handshake.
    Responder,
}

/// A pre-shared symmetric key.
pub type Psk = [u8; 32];

/// The authentication tag of an AEAD ciphertext.
pub type AeadTag = [u8; 16];

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
            cipher: None,
        }
    }

    /// Mix data into the handshake state.
    ///
    /// This is the MixHash() operation in the Noise spec.
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

    /// Mix a key into the key derivation state.
    ///
    /// This is the MixKey() operation in the Noise spec.
    fn mix_key(mut self, key: &[u8]) -> State {
        let [ck, k] = must_hkdf(&self.chaining_key, key);
        self.chaining_key = ck;
        self.cipher = Some(Aead::new(k));
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
        self.mix_key(public.as_ref())
    }

    /// Perform an X25519 operation, and mix the result into the handshake state.
    ///
    /// This is the MixKey(DH(private, public)) operation in the Noise spec.
    pub fn mix_dh(
        self,
        private: &x25519_dalek::StaticSecret,
        public: &x25519_dalek::PublicKey,
    ) -> State {
        let shared = private.diffie_hellman(public);
        self.mix_key(shared.as_ref())
    }

    /// Mix a pre-shared symmetric key into the handshake state.
    ///
    /// This is the MixKeyAndHash() operation in the Noise spec.
    pub fn mix_psk(mut self, psk: &Psk) -> State {
        let [ck, h, k] = must_hkdf(&self.chaining_key, psk);
        self.chaining_key = ck;
        self.cipher = Some(Aead::new(k));
        self.mix_hash(&h)
    }

    /// Encapsulate a shared secret to the given KEM key.
    ///
    /// Fails if the key is not a valid ML-KEM encapsulation key.
    ///
    /// `m` is the random bits that ML-KEM will use to produce the shared secret and ciphertext.
    /// It MUST be `None` outside of tests that are checking against known vectors.
    ///
    /// # Panics
    ///
    /// If an encryption key is not available in the current handshake state. This indicates that
    /// the caller's handshake implementation is incorrect.
    ///
    /// If `m` is not `None`, outside `#[cfg(test)]`.
    pub fn encaps_kem(
        self,
        key: EncapsulationKey,
        m: Option<B32>,
        ciphertext: &mut [u8; 1088],
        tag: &mut AeadTag,
    ) -> State {
        let (ct, s) = match m {
            #[cfg(test)]
            Some(m) => key.encapsulate_deterministic(&m),
            #[cfg(not(test))]
            Some(_) => panic!("cannot provide random bits for KEM encapsulation outside of tests"),
            None => key.encapsulate(),
        };
        ciphertext.copy_from_slice(ct.as_ref());
        self.seal(ciphertext, tag).mix_key(s.as_ref())
    }

    /// Decapsulate a shared secret with the given KEM key.
    ///
    /// # Panics
    ///
    /// If a decryption key is not available in the current handshake state. This indicates that
    /// the caller's handshake implementation is incorrect.
    pub fn decaps_kem(
        self,
        key: &DecapsulationKey,
        ciphertext: &mut [u8; 1088],
        tag: &AeadTag,
    ) -> Option<State> {
        let ret = self.open(ciphertext, tag)?;
        let s = key.decapsulate_slice(ciphertext).ok()?;
        Some(ret.mix_key(s.as_ref()))
    }

    /// Seal `cleartext` in place.
    ///
    /// `cleartext` is overwritten with ciphertext, and the authentication tag is written to `tag`.
    ///
    /// This is the EncryptAndHash() operation in the Noise spec.
    ///
    /// # Panics
    ///
    /// If an encryption key is not available in the current handshake state. This indicates that
    /// the caller's handshake implementation is incorrect.
    pub fn seal(mut self, cleartext: &mut [u8], tag: &mut AeadTag) -> State {
        let cipher = self.cipher.as_mut().unwrap();
        let nonce = cipher.next_nonce();
        let res = cipher
            .cipher
            .encrypt_in_place_detached(&nonce.into(), &self.hash, cleartext)
            .unwrap();
        res.write_to(tag).unwrap();

        self.mix_hash_gather(&[cleartext, tag])
    }

    /// Decrypt `ciphertext` in place, authenticating with `tag`.
    ///
    /// If successful, `ciphertext` is overwritten with cleartext. Returns `None` if decryption
    /// fails, implicitly terminating the handshake.
    ///
    /// This is the DecryptAndHash() operation in the Noise spec.
    ///
    /// # Panics
    ///
    /// If a decryption key is not available in the current handshake state. This indicates that
    /// the caller's handshake implementation is incorrect.
    pub fn open(self, ciphertext: &mut [u8], tag: &AeadTag) -> Option<State> {
        // On successful decryption, we have to mix the ciphertext into the handshake state.
        // This pairs awkwardly with the in place crypto we're doing, where a successful decryption
        // overwrites the ciphertext.
        // Instead, update the handshake hash before the decryption attempt. This is okay because
        // we discard the handshake state entirely on decryption failure.
        let hash = self.hash;
        let mut state = self.mix_hash_gather(&[ciphertext, tag]);

        let cipher = state.cipher.as_mut().unwrap();
        let nonce = cipher.next_nonce();
        cipher
            .cipher
            .decrypt_in_place_detached(&nonce.into(), &hash, ciphertext, tag.into())
            .ok()?;

        Some(state)
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
    }
}
