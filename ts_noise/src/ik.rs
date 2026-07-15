//! Implementation of the Noise IK handshake pattern.

use ts_keys::X25519KeyPair;
use zerocopy::FromBytes;

use crate::{
    core::{
        Role::{Initiator, Responder},
        Session, State,
    },
    messages::{Init, Resp},
};

const PROTOCOL: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";

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
    /// Returns a [`ReceivedHandshake`] with information about the peer on success, or
    /// None if the handshake message is invalid in some way.
    pub fn new(packet: &mut [u8], prologue: &[u8], my_static: &X25519KeyPair) -> Option<Self> {
        let packet: &mut Init<()> = Init::mut_from_bytes(packet).ok()?;

        let peer_ephemeral_pub = x25519_dalek::PublicKey::from(packet.ephemeral_pub);

        let handshake = State::new(PROTOCOL)
            .mix_hash(prologue) // prologue
            .mix_hash(my_static.public.as_ref()) // <- s ...
            .mix_hash(&packet.ephemeral_pub) // -> e
            .mix_dh(&my_static.private, &peer_ephemeral_pub) // es
            .open(&mut packet.static_pub, &packet.static_pub_tag)? // s
            .mix_dh(&my_static.private, &packet.static_pub.into()) // ss
            .open(&mut [], &packet.payload_tag)?; // payload

        Some(ReceivedHandshake {
            state: handshake,
            peer_ephemeral_pub,
            peer_static_pub: packet.static_pub.into(),
        })
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
    pub fn finish(self, packet: &mut [u8]) -> Session {
        let ephemeral = X25519KeyPair::random();
        self.finish_with_ephemeral(packet, ephemeral)
    }

    fn finish_with_ephemeral(self, packet: &mut [u8], my_ephemeral: X25519KeyPair) -> Session {
        assert_eq!(packet.len(), Self::RESP_SIZE);
        let response = Resp::mut_from_bytes(packet).unwrap();

        response.ephemeral_pub = my_ephemeral.public.to_bytes();

        self.state
            .mix_hash(my_ephemeral.public.as_ref()) // <- e
            .mix_dh(&my_ephemeral.private, &self.peer_ephemeral_pub) // ee
            .mix_dh(&my_ephemeral.private, &self.peer_static_pub) // se
            .seal(&mut [], &mut response.auth_tag) // payload
            .finish(Responder)
    }
}

/// A partially completed handshake, where the peer is the handshake's responder.
pub struct SentHandshake {
    state: State,
    my_ephemeral: x25519_dalek::StaticSecret,
}

impl SentHandshake {
    /// Size of the output packet to be provided to [`SentHandshake::new`].
    pub const INIT_SIZE: usize = size_of::<Init<()>>();

    /// Generate an outgoing handshake initiation for the given peer identity.
    ///
    /// # Panics
    ///
    /// If `packet` is not [`SentHandshake::INIT_SIZE`] bytes.
    #[inline]
    pub fn new(
        my_static: X25519KeyPair,
        peer_static: x25519_dalek::PublicKey,
        prologue: &[u8],
        out: &mut [u8],
    ) -> Self {
        let ephemeral = X25519KeyPair::random();
        SentHandshake::new_with_ephemeral(my_static, ephemeral, peer_static, prologue, out)
    }

    fn new_with_ephemeral(
        my_static: X25519KeyPair,
        my_ephemeral: X25519KeyPair,
        peer_static: x25519_dalek::PublicKey,
        prologue: &[u8],
        out: &mut [u8],
    ) -> Self {
        assert_eq!(out.len(), Self::INIT_SIZE);
        let out: &mut Init<()> = Init::mut_from_bytes(out).unwrap();

        out.ephemeral_pub = my_ephemeral.public.to_bytes();
        out.static_pub = my_static.public.to_bytes();

        let state = State::new(PROTOCOL)
            .mix_hash(prologue) // prologue
            .mix_hash(peer_static.as_ref()) // <- s
            .mix_hash(&out.ephemeral_pub) // -> e
            .mix_dh(&my_ephemeral.private, &peer_static) // es
            .seal(&mut out.static_pub, &mut out.static_pub_tag) // s
            .mix_dh(&my_static.private, &peer_static) // ss
            .seal(&mut [], &mut out.payload_tag); // payload

        SentHandshake {
            state,
            my_ephemeral: my_ephemeral.private,
        }
    }

    /// Try to finalize the handshake and generate a response.
    ///
    /// If successful, consumes `self` and returns keys for the new session.
    /// If the response is invalid, returns `Err(self)` to allow for another finalization
    /// attempt later.
    pub fn try_finish(self, packet: &mut [u8], my_static: X25519KeyPair) -> Result<Session, Self> {
        let Ok(packet) = Resp::mut_from_bytes(packet) else {
            return Err(self);
        };

        let peer_ephemeral_pub = x25519_dalek::PublicKey::from(packet.ephemeral_pub);
        let state = self.state.clone();

        let ret = state
            .mix_hash(&packet.ephemeral_pub) // e
            .mix_dh(&self.my_ephemeral, &peer_ephemeral_pub) // ee
            .mix_dh(&my_static.private, &peer_ephemeral_pub) // se
            .open(&mut [], &packet.auth_tag)
            .ok_or(self)? // payload
            .finish(Initiator);

        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use itertools::Itertools;

    use super::*;

    fn test_key(r: Range<u8>) -> X25519KeyPair {
        assert_eq!(r.len(), 32);
        let private = x25519_dalek::StaticSecret::from(r.collect_array().unwrap());
        let public = x25519_dalek::PublicKey::from(&private);
        X25519KeyPair { private, public }
    }

    #[test]
    fn test_handshake() {
        let init_static = test_key(0..32);
        let init_ephemeral = test_key(32..64);

        let resp_static = test_key(64..96);
        let resp_ephemeral = test_key(96..128);

        const PROLOGUE: &[u8] = b"TEST HANDSHAKE";

        // These values were verified by hand to be identical to the packets produced by the
        // third-party noise-protocol crate.
        let expected_init_packet = hex::decode("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254ad5b8febedeb97415be53612205e6bfab385e34cb127dd8854c4f9afb10f9b0e49075a6f14f9d5bc61412f096ae4950589aef8286944be93ca02ab76a5483b51").unwrap();
        let expected_resp_packet = hex::decode("675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f5ef5508032efff8066fc858410f411e8").unwrap();

        let mut init_packet = [0; SentHandshake::INIT_SIZE];
        let init_sent = SentHandshake::new_with_ephemeral(
            init_static.clone(),
            init_ephemeral,
            resp_static.public,
            PROLOGUE,
            &mut init_packet,
        );
        assert_eq!(init_packet, expected_init_packet.as_ref());

        let resp_recv = ReceivedHandshake::new(&mut init_packet, PROLOGUE, &resp_static).unwrap();
        assert_eq!(resp_recv.peer_static_pub, init_static.public);

        let mut resp_packet = [0; ReceivedHandshake::RESP_SIZE];
        let resp_session = resp_recv.finish_with_ephemeral(&mut resp_packet, resp_ephemeral);
        assert_eq!(resp_packet, expected_resp_packet.as_ref());

        let Ok(init_session) = init_sent.try_finish(&mut resp_packet, init_static) else {
            panic!("initiator failed to finalize handshake");
        };

        assert_eq!(
            init_session.initiator_to_responder,
            resp_session.initiator_to_responder
        );
        assert_eq!(
            init_session.responder_to_initiator,
            resp_session.responder_to_initiator
        );
        assert_eq!(init_session.role, Initiator);
        assert_eq!(resp_session.role, Responder);
    }
}
