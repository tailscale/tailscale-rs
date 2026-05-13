//! Implementation of the Noise IKpsk2 handshake pattern.

use std::marker::PhantomData;

use zerocopy::FromBytes;

use crate::{
    core::{Psk, Session, State},
    messages::{Init, Pod, Resp},
};

const PROTOCOL: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// A partially completed handshake, where the peer is the handshake's initiator.
pub struct ReceivedHandshake {
    state: State,
    peer_ephemeral_pub: x25519_dalek::PublicKey,
    /// The peer's static identity.
    pub peer_static_pub: x25519_dalek::PublicKey,
}

impl ReceivedHandshake {
    /// Size of the packet expected by [`ReceivedHandshake::finish`].
    pub const RESP_SIZE: usize = size_of::<Resp>();

    /// Process an incoming handshake initiation packet.
    ///
    /// Returns a [`ReceivedHandshake`] and the decrypted handshake payload, or None
    /// if the handshake message is invalid in some way.
    pub fn new<'packet, P: Pod>(
        packet: &'packet mut [u8],
        prologue: &[u8],
        my_static: x25519_dalek::StaticSecret,
    ) -> Option<(Self, &'packet mut P)> {
        let packet: &mut Init<P> = Init::mut_from_bytes(packet).ok()?;

        let peer_ephemeral_pub = x25519_dalek::PublicKey::from(packet.ephemeral_pub);
        let my_static_pub = x25519_dalek::PublicKey::from(&my_static);

        let handshake = State::new(PROTOCOL)
            .mix_hash(prologue) // prologue
            .mix_hash(my_static_pub.as_ref()) // <- s ...
            .mix_hash_and_key(&peer_ephemeral_pub) // -> e
            .mix_dh(&my_static, &peer_ephemeral_pub) // es
            .open(&mut packet.static_pub, &packet.static_pub_tag)? // s
            .mix_dh(&my_static, &packet.static_pub.into()) // ss
            .open(packet.payload.as_mut_bytes(), &packet.payload_tag)?; // payload

        Some((
            ReceivedHandshake {
                state: handshake,
                peer_ephemeral_pub,
                peer_static_pub: packet.static_pub.into(),
            },
            &mut packet.payload,
        ))
    }

    /// Finalize the handshake and generate a response.
    ///
    /// The response is written to `packet`, which must be exactly
    /// [`ReceivedHandshake::RESP_SIZE`] bytes.
    ///
    /// # Panics
    ///
    /// If `packet` is the wrong size.
    #[inline]
    pub fn finish(self, psk: &Psk, out: &mut [u8]) -> Session {
        let ephemeral = x25519_dalek::StaticSecret::random();
        self.finish_with_ephemeral(psk, ephemeral, out)
    }

    fn finish_with_ephemeral(
        self,
        psk: &Psk,
        my_ephemeral: x25519_dalek::StaticSecret,
        out: &mut [u8],
    ) -> Session {
        assert_eq!(out.len(), Self::RESP_SIZE);
        let response = Resp::mut_from_bytes(out).unwrap();

        let my_ephemeral_pub = x25519_dalek::PublicKey::from(&my_ephemeral);
        response.ephemeral_pub = my_ephemeral_pub.to_bytes();

        self.state
            .mix_hash_and_key(&my_ephemeral_pub) // <- e
            .mix_dh(&my_ephemeral, &self.peer_ephemeral_pub) // ee
            .mix_dh(&my_ephemeral, &self.peer_static_pub) // se
            .mix_psk(psk) // psk
            .seal(&mut [], &mut response.auth_tag) // payload
            .finish_as_responder()
    }
}

/// A partially completed handshake, where the peer is the handshake's responder.
pub struct SentHandshake<P: Pod> {
    state: State,
    my_ephemeral: x25519_dalek::StaticSecret,
    _phantom: PhantomData<P>,
}

impl<P: Pod> SentHandshake<P> {
    /// Size of the output packet to be provided to [`SentHandshake::new`].
    pub const INIT_SIZE: usize = size_of::<Init<P>>();

    /// Generate an outgoing handshake initiation for the given peer identity.
    ///
    /// # Panics
    ///
    /// If `packet` is not [`SentHandshake::INIT_SIZE`] bytes.
    #[inline]
    pub fn new(
        my_static: x25519_dalek::StaticSecret,
        peer_static: x25519_dalek::PublicKey,
        prologue: &[u8],
        payload: P,
        out: &mut [u8],
    ) -> Self {
        let ephemeral = x25519_dalek::StaticSecret::random();
        Self::new_with_ephemeral(my_static, ephemeral, peer_static, prologue, payload, out)
    }

    fn new_with_ephemeral(
        my_static: x25519_dalek::StaticSecret,
        my_ephemeral: x25519_dalek::StaticSecret,
        peer_static: x25519_dalek::PublicKey,
        prologue: &[u8],
        payload: P,
        out: &mut [u8],
    ) -> Self {
        assert_eq!(out.len(), Self::INIT_SIZE);
        let out: &mut Init<P> = Init::mut_from_bytes(out).unwrap();

        let ephemeral_pub = x25519_dalek::PublicKey::from(&my_ephemeral);

        out.ephemeral_pub = ephemeral_pub.to_bytes();
        out.static_pub = x25519_dalek::PublicKey::from(&my_static).to_bytes();
        out.payload = payload;

        let state = State::new(PROTOCOL)
            .mix_hash(prologue) // prologue
            .mix_hash(peer_static.as_ref()) // <- s
            .mix_hash_and_key(&ephemeral_pub) // -> e
            .mix_dh(&my_ephemeral, &peer_static) // es
            .seal(&mut out.static_pub, &mut out.static_pub_tag) // s
            .mix_dh(&my_static, &peer_static) // ss
            .seal(out.payload.as_mut_bytes(), &mut out.payload_tag); // payload

        SentHandshake {
            state,
            my_ephemeral,
            _phantom: PhantomData,
        }
    }

    /// Try to finalize the handshake and generate a response.
    ///
    /// If successful, consumes `self` and returns keys for the new session.
    /// If the response is invalid, returns `Err(self)` to allow for another finalization
    /// attempt later.
    pub fn try_finish(
        self,
        packet: &mut [u8],
        my_static: x25519_dalek::StaticSecret,
        psk: &Psk,
    ) -> Result<Session, Self> {
        let Ok(packet) = Resp::mut_from_bytes(packet) else {
            return Err(self);
        };

        let peer_ephemeral_pub = x25519_dalek::PublicKey::from(packet.ephemeral_pub);
        let state = self.state.clone();

        let ret = state
            .mix_hash_and_key(&peer_ephemeral_pub) // e
            .mix_dh(&self.my_ephemeral, &peer_ephemeral_pub) // ee
            .mix_dh(&my_static, &peer_ephemeral_pub) // se
            .mix_psk(psk) // psk
            .open(&mut [], &packet.auth_tag)
            .ok_or(self)?
            .finish_as_initiator();

        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use itertools::Itertools;

    use super::*;

    fn test_key(r: Range<u8>) -> (x25519_dalek::StaticSecret, x25519_dalek::PublicKey) {
        assert_eq!(r.len(), 32);
        let private = x25519_dalek::StaticSecret::from(r.collect_array().unwrap());
        let public = x25519_dalek::PublicKey::from(&private);
        (private, public)
    }

    #[test]
    fn test_handshake() {
        let (init_static, init_static_pub) = test_key(0..32);
        let (init_ephemeral, _) = test_key(32..64);

        let (resp_static, resp_static_pub) = test_key(64..96);
        let (resp_ephemeral, _) = test_key(96..128);

        let psk: Psk = (128..160).collect_array().unwrap();

        const PROLOGUE: &[u8] = b"TEST HANDSHAKE";
        const PAYLOAD: &[u8; 12] = b"TEST PAYLOAD";

        // These values were verified by hand to be identical to the packets produced by the
        // third-party noise-protocol crate.
        let expected_init_packet = hex::decode("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662544df99f4e2d9c658302e247ec71c206e70c31df074049bd3d8ab636b27d8a20c512e4beeec758c4b2bee13e5d6c4a6abfe18cb917c010702e44515036af229780d44f50cf68cf7cdaabd81372").unwrap();
        let expected_resp_packet = hex::decode("675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f1d31e903c203fe7ca9187d9ef4059b09").unwrap();

        let mut init_packet = [0; SentHandshake::<[u8; 12]>::INIT_SIZE];
        let init_sent = SentHandshake::<[u8; 12]>::new_with_ephemeral(
            init_static.clone(),
            init_ephemeral,
            resp_static_pub,
            PROLOGUE,
            *PAYLOAD,
            &mut init_packet,
        );
        assert_eq!(init_packet, expected_init_packet.as_ref());

        let (resp_recv, resp_payload) =
            ReceivedHandshake::new::<[u8; 12]>(&mut init_packet, PROLOGUE, resp_static).unwrap();
        assert_eq!(resp_recv.peer_static_pub, init_static_pub);
        assert_eq!(resp_payload, PAYLOAD);

        let mut resp_packet = [0; ReceivedHandshake::RESP_SIZE];
        let resp_session = resp_recv.finish_with_ephemeral(&psk, resp_ephemeral, &mut resp_packet);
        assert_eq!(resp_packet, expected_resp_packet.as_ref());

        let Ok(init_session) = init_sent.try_finish(&mut resp_packet, init_static, &psk) else {
            panic!("initiator failed to finalize handshake");
        };

        assert_eq!(init_session.send, resp_session.recv);
        assert_eq!(init_session.recv, resp_session.send);
    }
}
