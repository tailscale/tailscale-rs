use std::time::Instant;

use aead::AeadInPlace;
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hkdf::SimpleHkdf;
use ts_keys::{NodeKeyPair, NodePrivateKey, NodePublicKey};
use ts_packet::old::PacketMut;
use ts_time::Handle;
use zerocopy::{FromZeros, IntoBytes};

use crate::{
    config::Psk,
    endpoint::Event,
    macs::{MACReceiver, MACSender, Mac},
    messages::*,
    session::{ReceiveSession, TransmitSession},
    time::TAI64N,
};

/// The symmetric session keys produced by a WireGuard handshake.
struct SessionKeys {
    initiator_to_responder: chacha20poly1305::Key,
    responder_to_initiator: chacha20poly1305::Key,
}

/// The state of a partially processed handshake.
///
/// Has to be cloneable because we may have to attempt finalization of the handshake
/// as the initiator multiple times, if rogue invalid responses are received. It's
/// deliberately not Copy, because cloning and allowing potential reuse of the cipher
/// state is risky and needs to be a deliberate act.
#[derive(Clone)]
struct Handshake {
    hash: [u8; 32],
    chaining_key: [u8; 32],
    cipher: Option<ChaCha20Poly1305>,
}

/// Initialize a ChaCha20Poly1305 cipher with the given key.
///
/// # Panics
/// Panics if the key isn't exactly 32 bytes.
fn must_cipher(key: &[u8]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new_from_slice(key).expect("ChaCha20Poly1305 key should be 32 bytes")
}

/// Use HKDF to derive two 32-byte values.
fn must_hkdf2(chaining_key: &[u8; 32], key: &[u8]) -> ([u8; 32], [u8; 32]) {
    let kdf = SimpleHkdf::<Blake2s256>::new(Some(chaining_key), key);
    let mut expanded = [0; 64];
    kdf.expand(&[], &mut expanded)
        .expect("64 should be a valid HKDF output length");
    // Unwrap is fine, the inputs are statically the right size.
    (
        expanded[..32].try_into().unwrap(),
        expanded[32..].try_into().unwrap(),
    )
}

/// Use HKDF to derive three 32-byte values.
fn must_hkdf3(chaining_key: &[u8; 32], key: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let kdf = SimpleHkdf::<Blake2s256>::new(Some(chaining_key), key);
    let mut expanded = [0; 96];
    kdf.expand(&[], &mut expanded)
        .expect("96 should be a valid HKDF output length");
    // Unwrap is fine, the inputs are statically the right size.
    (
        expanded[..32].try_into().unwrap(),
        expanded[32..64].try_into().unwrap(),
        expanded[64..].try_into().unwrap(),
    )
}

impl Handshake {
    fn new(responder_static: NodePublicKey) -> Handshake {
        // TODO: precompute initial hash and chaining key, unless the compiler
        // is clever enough to figure it out by itself?
        let init = Blake2s256::digest("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
        Handshake {
            hash: init.into(),
            chaining_key: init.into(),
            cipher: None,
        }
        .mix_hash(b"WireGuard v1 zx2c4 Jason@zx2c4.com")
        .mix_hash(responder_static.as_bytes())
    }

    /// Mix data into the handshake state.
    ///
    /// This is the MixHash() operation in the Noise spec.
    fn mix_hash(mut self, data: &[u8]) -> Self {
        let mut h = Blake2s256::new_with_prefix(self.hash);
        h.update(data);
        h.finalize_into(self.hash.as_mut_bytes().into());
        self
    }

    /// Mix a symmetric key into the handshake state, producing a single-use AEAD
    /// cipher able to encrypt/decrypt the next portion of the handshake.
    ///
    /// This is the MixKey() operation in the Noise spec.
    fn mix_key(self, key: &[u8; 32]) -> Handshake {
        let (ck, k) = must_hkdf2(&self.chaining_key, key);
        Handshake {
            hash: self.hash,
            chaining_key: ck,
            cipher: Some(must_cipher(&k)),
        }
    }

    /// Derive a one-time AEAD from the pre-shared symmetric key.
    ///
    /// This is the `psk` handshake step.
    fn mix_psk(self, psk: &Psk) -> Handshake {
        let (ck, h, k) = must_hkdf3(&self.chaining_key, psk.as_ref());
        Handshake {
            hash: self.hash,
            chaining_key: ck,
            cipher: Some(must_cipher(&k)),
        }
        .mix_hash(&h)
    }

    /// Finalize the handshake and return a pair of symmetric session keys.
    ///
    /// This is the Split() operation in the Noise spec.
    fn finish(self) -> SessionKeys {
        let (k1, k2) = must_hkdf2(&self.chaining_key, &[]);
        SessionKeys {
            initiator_to_responder: chacha20poly1305::Key::from(k1),
            responder_to_initiator: chacha20poly1305::Key::from(k2),
        }
    }

    /// Encrypt cleartext into dst.
    ///
    /// dst must be 16 bytes longer than cleartext, and is overwritten.
    ///
    /// This is the EncryptAndHash() operation in the Noise spec.
    ///
    /// # Panics
    /// Panics if dst is not exactly 16 bytes longer than cleartext, or if called at an
    /// incorrect stage of the handshake where encryption is forbidden.
    fn encrypt(mut self, cleartext: &[u8], dst: &mut [u8]) -> Handshake {
        assert_eq!(
            dst.len(),
            cleartext.len() + 16,
            "output slice provided to encrypt should be 16 bytes longer than the input"
        );
        let cipher = self
            .cipher
            .take()
            .expect("encrypt should only be called at points in the handshake where an AEAD key is available");
        // The cipher API here is awkward: we can either encrypt into a fresh Vec (causing an alloc), or we
        // can encrypt in place. The operation we want, encrypting into a provided slice of the right size,
        // isn't available.
        //
        // So, we do a little dance of copying the cleartext to the destination slice, then encrypt in place
        // and add the authentication tag to the end. This is unwieldy, but being able to pass in a destination
        // slice plays much nicer with zerocopy's transmutations.
        cleartext.write_to_prefix(dst).unwrap(); // destination size verified by assert above
        let nonce = [0; 12];
        let tag = cipher
            .encrypt_in_place_detached(&nonce.into(), &self.hash, &mut dst[..cleartext.len()])
            .expect("ChaCha20Poly1305 encryption should not fail");
        tag.write_to_suffix(dst).unwrap(); // destination size verified by assert above
        self.mix_hash(dst)
    }

    /// Decrypt ciphertext and return the cleartext.
    ///
    /// This is the DecryptAndHash() operation in the Noise spec.
    ///
    /// # Panics
    /// Panics if ciphertext is not exactly 16 bytes longer than dst, or if called at an
    /// incorrect stage of the handshake where decryption is forbidden.
    fn decrypt(mut self, ciphertext: &[u8], dst: &mut [u8]) -> Option<Handshake> {
        assert_eq!(
            dst.len(),
            ciphertext.len() - 16,
            "output slice provided to decrypt should be 16 bytes shorter than the input"
        );
        let cipher = self
            .cipher
            .take()
            .expect("decrypt should only be called at points in the handshake where an AEAD key is available");
        // Awkward API, see the longer comment in encrypt() for details.
        ciphertext[..dst.len()].write_to(dst).unwrap(); // destination size verified by assert above
        let nonce = [0; 12];
        cipher
            .decrypt_in_place_detached(
                &nonce.into(),
                &self.hash,
                dst,
                ciphertext[dst.len()..].into(),
            )
            .inspect_err(|e| {
                tracing::warn!(error = %e, "decryption failed");
            })
            .ok()?;
        Some(self.mix_hash(ciphertext))
    }
}

/// A partially completed incoming handshake.
pub struct ReceivedHandshake {
    send_id: SessionId,

    // Info decrypted from the HandshakeInitiation
    peer_ephemeral: x25519_dalek::PublicKey,
    peer_static: NodePublicKey,
    pub timestamp: TAI64N,

    // State needed to complete the handshake
    handshake: Handshake,
}

impl ReceivedHandshake {
    /// Process a peer's handshake initiation message.
    pub fn new(
        pkt: &HandshakeInitiation,
        my_static: &NodeKeyPair,
        macs: &MACReceiver,
    ) -> Option<ReceivedHandshake> {
        if !macs.verify_macs(pkt.as_bytes()) {
            return None;
        };

        // TODO: cookie DoS protection. Deferring implementation until more of the surrounding code is in place,
        // because the right place to do cookie enforcement might be outside of the core Noise handshake logic.
        let peer_ephemeral = x25519_dalek::PublicKey::from(pkt.ephemeral_pub);
        let my_static_dalek = x25519_dalek::StaticSecret::from(my_static.private);
        let mut peer_static_bytes = [0; 32];
        let mut timestamp = TAI64N::new_zeroed();
        let handshake = Handshake::new(my_static.public)
            .mix_hash(&pkt.ephemeral_pub) // e
            .mix_key(&pkt.ephemeral_pub) // e (extra mixing required by psk variant)
            .mix_key(my_static_dalek.diffie_hellman(&peer_ephemeral).as_bytes()) // es (reversed because this is the responder)
            .decrypt(&pkt.static_pub_sealed, &mut peer_static_bytes)? // s
            .mix_key(
                my_static_dalek
                    .diffie_hellman(&x25519_dalek::PublicKey::from(peer_static_bytes))
                    .as_bytes(),
            ) // ss
            .decrypt(&pkt.timestamp_sealed, timestamp.as_mut_bytes())?; // payload

        Some(ReceivedHandshake {
            handshake,
            timestamp,
            peer_static: NodePublicKey::from(peer_static_bytes),
            peer_ephemeral: x25519_dalek::PublicKey::from(pkt.ephemeral_pub),
            send_id: pkt.sender_id,
        })
    }

    /// Finalize the handshake, producing a HandshakeResponse.
    pub fn respond(
        self,
        session_id: SessionId,
        psk: &Psk,
        macs: &MACSender,
        now: Instant,
    ) -> (SessionPair, PacketMut) {
        let my_ephemeral = x25519_dalek::ReusableSecret::random();
        let my_ephemeral_pub = x25519_dalek::PublicKey::from(&my_ephemeral);
        let mut response = HandshakeResponse {
            sender_id: session_id,
            receiver_id: self.send_id,
            ephemeral_pub: my_ephemeral_pub.to_bytes(),
            ..Default::default()
        };

        let session_keys = self
            .handshake
            .mix_hash(&my_ephemeral_pub.to_bytes()) // e
            .mix_key(&my_ephemeral_pub.to_bytes()) // e (extra mixing required by psk variant)
            .mix_key(my_ephemeral.diffie_hellman(&self.peer_ephemeral).as_bytes()) // ee
            .mix_key(
                my_ephemeral
                    .diffie_hellman(&self.peer_static.into())
                    .as_bytes(),
            ) // se (reversed because this is the responder)
            .mix_psk(psk) // psk
            .encrypt(&[], &mut response.auth_tag) // payload (empty, but must encrypt to generate an auth tag)
            .finish();

        let send = TransmitSession::new(session_keys.responder_to_initiator, self.send_id, now);
        let recv = ReceiveSession::new(session_keys.initiator_to_responder, session_id, now);
        let mut pkt = PacketMut::new(size_of::<HandshakeResponse>());
        response
            .write_to(pkt.as_mut())
            .expect("ret is wrong size for a handshake response");
        macs.write_macs(pkt.as_mut());
        (SessionPair { send, recv }, pkt)
    }

    pub fn peer_static(&self) -> NodePublicKey {
        self.peer_static
    }
}

/// Generate a handshake initiation message for a peer.
pub fn initiate_handshake(
    endpoint_static: NodePrivateKey,
    peer_static: NodePublicKey,
    session_id: SessionId,
    timestamp: TAI64N,
) -> (SentHandshake, HandshakeInitiation) {
    let ephemeral = x25519_dalek::ReusableSecret::random();
    let ephemeral_pub = x25519_dalek::PublicKey::from(&ephemeral);
    let endpoint_static_pub = NodePublicKey::from(endpoint_static);

    let mut pkt = HandshakeInitiation {
        sender_id: session_id,
        ephemeral_pub: ephemeral_pub.to_bytes(),
        ..Default::default()
    };

    let handshake = Handshake::new(peer_static)
        .mix_hash(ephemeral_pub.as_bytes()) // e
        .mix_key(ephemeral_pub.as_bytes()) // e (extra mixing required by psk variant)
        .mix_key(ephemeral.diffie_hellman(&peer_static.into()).as_bytes()) // es
        .encrypt(endpoint_static_pub.as_bytes(), &mut pkt.static_pub_sealed) // s
        .mix_key(
            x25519_dalek::StaticSecret::from(endpoint_static)
                .diffie_hellman(&peer_static.into())
                .as_bytes(),
        ) // ss
        .encrypt(timestamp.as_bytes(), &mut pkt.timestamp_sealed); // payload

    let ret = SentHandshake {
        id: session_id,
        my_ephemeral: ephemeral,
        my_static: endpoint_static,
        handshake,
    };

    (ret, pkt)
}

/// A partially completed sent handshake.
pub struct SentHandshake {
    pub id: SessionId,
    my_ephemeral: x25519_dalek::ReusableSecret,
    my_static: NodePrivateKey,
    handshake: Handshake,
}

pub struct SessionPair {
    pub send: TransmitSession,
    pub recv: ReceiveSession,
}

/// State of a handshake with a peer.
pub(crate) enum HandshakeState {
    /// No handshake in progress.
    None,
    /// We are the initiator, awaiting a response.
    ///
    /// Second field is the timeout for the handshake.
    Initiated(SentHandshake, Handle<Event>, Mac),
    /// We are the responder, awaiting an initial transport
    /// message to confirm the new session.
    Responded(Box<SessionPair>),
}

impl HandshakeState {
    pub(crate) fn is_active(&self) -> bool {
        !matches!(self, HandshakeState::None)
    }

    /// Return the session id of the handshake, if any.
    pub(crate) fn session_id(&self) -> Option<SessionId> {
        match self {
            HandshakeState::Initiated(handshake, ..) => Some(handshake.id),
            HandshakeState::Responded(tentative) => Some(tentative.recv.id()),
            HandshakeState::None => None,
        }
    }

    /// Respond to a peer's handshake initiation, and switch to the responder state to await
    /// session confirmation.
    ///
    /// Responding replaces any other handshake state unconditionally.
    pub(crate) fn respond(
        &mut self,
        session_id: SessionId,
        handshake: ReceivedHandshake,
        psk: &Psk,
        cookie_sender: &MACSender,
        now: Instant,
    ) -> PacketMut {
        // TODO: tie-breaker for simultaneous initiation.
        // When both peers initiate simultaneously, it's possible to get into a sticky situation
        // where each peer completes their own initiation based on the other's response, and in
        // so doing end up on completely different session keys that will never be confirmed.
        // We need to resolve the conflict one way or another to avoid this race.
        //
        // However, in practice the race is vanishingly rare unless you somehow externally
        // synchronize the peers to start handshaking at exactly the same time. So, the code is
        // usable without this race avoidance logic.
        //
        // We may also be able to resolve this race with a 4th handshake state wherein we are
        // simultaneously initiator and responder, and temporarily exist in quantum superposition
        // until confirmation packets collapse the state again.
        let (session, packet) = handshake.respond(session_id, psk, cookie_sender, now);
        *self = HandshakeState::Responded(Box::new(session));
        packet
    }

    /// Finish a handshake as the initiator, returning the newly established sessions.
    ///
    /// The handshake state is unchanged if the handshake cannot complete, either because
    /// it's not in an appropriate state or because the handshake response isn't a valid
    /// completion of the handshake.
    pub(crate) fn finish(
        &mut self,
        packet: &HandshakeResponse,
        psk: &Psk,
        cookies: &MACReceiver,
        now: Instant,
    ) -> Option<SessionPair> {
        let HandshakeState::Initiated(sent_handshake, ..) = self else {
            return None;
        };

        if !cookies.verify_macs(packet.as_bytes()) {
            return None;
        };

        let peer_ephemeral = x25519_dalek::PublicKey::from(packet.ephemeral_pub);
        let handshake = sent_handshake.handshake.clone();
        let session_keys = handshake
            .mix_hash(&packet.ephemeral_pub) // e
            .mix_key(&packet.ephemeral_pub) // e (extra mixing required by psk variant)
            .mix_key(
                sent_handshake
                    .my_ephemeral
                    .diffie_hellman(&peer_ephemeral)
                    .as_bytes(),
            ) // ee
            .mix_key(
                x25519_dalek::StaticSecret::from(sent_handshake.my_static)
                    .diffie_hellman(&peer_ephemeral)
                    .as_bytes(),
            ) // se
            .mix_psk(psk) // psk
            .decrypt(&packet.auth_tag, &mut Vec::new()) // payload (empty, but must decrypt to verify auth tag)
            .map(|handshake| handshake.finish())?;

        let send = TransmitSession::new(session_keys.initiator_to_responder, packet.sender_id, now);
        let recv = ReceiveSession::new(session_keys.responder_to_initiator, sent_handshake.id, now);

        let HandshakeState::Initiated(_, timeout, _) =
            std::mem::replace(self, HandshakeState::None)
        else {
            unreachable!();
        };
        timeout.cancel();

        Some(SessionPair { send, recv })
    }

    /// Confirm a handshake as responder, using the provided ciphertext packets.
    ///
    /// A tentative session becomes confirmed when it successfully decrypts its first packet.
    ///
    /// The handshake state is unchanged if the handshake cannot be confirmed, either because it's
    /// not in an appropriate state or because no packet successfully decrypted.
    ///
    /// Upon successful confirmation, returns the newly established sessions as well as the one
    /// or more packets that decrypted successfully
    pub(crate) fn confirm(
        &mut self,
        session_id: SessionId,
        mut packets: Vec<PacketMut>,
    ) -> Option<(SessionPair, Vec<PacketMut>)> {
        let HandshakeState::Responded(tentative) = self else {
            return None;
        };

        if tentative.recv.id() != session_id {
            return None;
        };

        packets = tentative.recv.decrypt(packets);
        if packets.is_empty() {
            return None;
        }

        let HandshakeState::Responded(tentative) = std::mem::replace(self, HandshakeState::None)
        else {
            unreachable!();
        };

        Some((*tentative, packets))
    }
}

#[cfg(test)]
mod tests {
    use ts_keys::NodeKeyPair;
    use ts_time::Scheduler;
    use zerocopy::TryFromBytes;

    use super::*;

    #[test]
    fn test_handshake() {
        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let psk = rand::random();

        // Peer A sends a handshake initiation...
        let a_mac_send = MACSender::new(&b_static.public);
        let a_mac_recv = MACReceiver::new(&a_static.public);
        let a_session = SessionId::random(); // A wants to receive at this ID
        let a_init_time = TAI64N::now();
        let (a_handshake, init_pkt) =
            initiate_handshake(a_static.private, b_static.public, a_session, a_init_time);

        let mut init_pkt = PacketMut::from(init_pkt.as_bytes());
        let handshake_mac = a_mac_send.write_macs(init_pkt.as_mut());

        let mut scheduler = Scheduler::default();
        let timeout = scheduler.add(
            ts_time::TimeRange::new_around(Instant::now(), std::time::Duration::from_secs(1000)),
            crate::Event::HandshakeTimeout(crate::config::PeerId(0)),
        );
        let mut a_handshake = HandshakeState::Initiated(a_handshake, timeout, handshake_mac);

        // Peer B receives it and responds
        let init_pkt = HandshakeInitiation::try_ref_from_bytes(init_pkt.as_ref())
            .expect("init_pkt is a valid handshake initiation message");
        let b_mac_send = MACSender::new(&a_static.public);
        let b_mac_recv = MACReceiver::new(&b_static.public);
        let b_handshake = ReceivedHandshake::new(init_pkt, &b_static, &b_mac_recv)
            .expect("peer B can successfully process A's handshake initiation");
        assert_eq!(b_handshake.peer_static, a_static.public);
        assert_eq!(b_handshake.timestamp, a_init_time);
        let b_session = SessionId::random(); // B wants to receive at this ID
        let (b_session, response_pkt) =
            b_handshake.respond(b_session, &psk, &b_mac_send, Instant::now());

        // Peer A receives response
        let response_pkt = HandshakeResponse::try_ref_from_bytes(response_pkt.as_ref())
            .expect("response_pkt is a valid handshake response message");
        let Some(a_session) = a_handshake.finish(response_pkt, &psk, &a_mac_recv, Instant::now())
        else {
            panic!("failed to process handshake response from peer B");
        };

        // They can now communicate
        let a_plaintext = vec![PacketMut::from("xyzzy".as_bytes())];
        let mut packets = a_plaintext.clone();
        a_session.send.encrypt(packets.iter_mut());
        let b_received = b_session.recv.decrypt(packets);
        assert_eq!(b_received, a_plaintext);

        let b_plaintext = vec![PacketMut::from("plover".as_bytes())];
        packets = b_plaintext.clone();
        b_session.send.encrypt(&mut packets);
        let a_received = a_session.recv.decrypt(packets);
        assert_eq!(a_received, b_plaintext);
    }
}
