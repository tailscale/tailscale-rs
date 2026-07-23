use std::time::Instant;

use ts_keys::{NodeKeyPair, NodePublicKey};
use ts_noise::ikpsk2;
use ts_packet::PacketMut;
use ts_time::Handle;
use zerocopy::IntoBytes;

use crate::{
    config::Psk,
    endpoint::Event,
    macs::{MACReceiver, MACSender, Mac},
    messages::*,
    session::BidiSession,
    time::TAI64N,
};

const PROLOGUE: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

/// A partially completed incoming handshake.
pub struct ReceivedHandshake {
    responder_to_initiator_id: SessionId,
    noise: ikpsk2::ReceivedHandshake,
    // Info decrypted from the HandshakeInitiation
    pub timestamp: TAI64N,
}

impl ReceivedHandshake {
    /// Process a peer's handshake initiation message.
    pub fn new(
        pkt: &mut HandshakeInitiation,
        my_static: &NodeKeyPair,
        macs: &MACReceiver,
    ) -> Option<ReceivedHandshake> {
        if !macs.verify_macs(pkt.as_bytes()) {
            return None;
        };

        let (noise, timestamp) =
            ikpsk2::ReceivedHandshake::new(&mut pkt.noise, PROLOGUE, my_static.into())?;

        Some(ReceivedHandshake {
            responder_to_initiator_id: pkt.sender_id,
            noise,
            timestamp: *timestamp,
        })
    }

    /// Finalize the handshake, producing a HandshakeResponse.
    pub fn respond(
        self,
        initiator_to_responder_id: SessionId,
        psk: &Psk,
        macs: &MACSender,
        now: Instant,
    ) -> (BidiSession, PacketMut) {
        let mut response = HandshakeResponse {
            sender_id: initiator_to_responder_id,
            receiver_id: self.responder_to_initiator_id,
            ..Default::default()
        };

        let session_keys = self.noise.finish(psk, response.noise.as_mut_bytes());

        let session = BidiSession::new(
            session_keys,
            initiator_to_responder_id,
            self.responder_to_initiator_id,
            now,
        );
        let mut pkt = PacketMut::new(size_of::<HandshakeResponse>());
        // Packet is allocated above with the correct size.
        response.write_to(pkt.as_mut()).unwrap();
        macs.write_macs(pkt.as_mut());
        (session, pkt)
    }

    pub fn peer_static(&self) -> NodePublicKey {
        self.noise.peer_static_pub.to_bytes().into()
    }
}

/// Generate a handshake initiation message for a peer.
pub fn initiate_handshake(
    endpoint_static: &NodeKeyPair,
    peer_static: &NodePublicKey,
    session_id: SessionId,
    timestamp: TAI64N,
) -> (SentHandshake, HandshakeInitiation) {
    let mut pkt = HandshakeInitiation {
        sender_id: session_id,
        ..Default::default()
    };

    let noise = ikpsk2::SentHandshake::new(
        endpoint_static.into(),
        peer_static.into(),
        PROLOGUE,
        timestamp,
        pkt.noise.as_mut_bytes(),
    );

    let ret = SentHandshake {
        responder_to_initiator_id: session_id,
        noise,
    };

    (ret, pkt)
}

/// A partially completed sent handshake.
pub struct SentHandshake {
    pub responder_to_initiator_id: SessionId,
    noise: ikpsk2::SentHandshake<TAI64N>,
}

/// A handshake with a peer.
pub(crate) enum Handshake {
    /// No handshake in progress.
    None,
    /// We are the initiator, awaiting a response.
    ///
    /// Second field is the timeout for the handshake.
    Initiated(SentHandshake, Handle<Event>, Mac),
    /// We are the responder, awaiting an initial transport
    /// message to confirm the new session.
    Responded(Box<BidiSession>),
}

impl Handshake {
    pub(crate) fn is_active(&self) -> bool {
        !matches!(self, Handshake::None)
    }

    /// Return the session id of the handshake, if any.
    pub(crate) fn session_id(&self) -> Option<SessionId> {
        match self {
            Handshake::Initiated(handshake, ..) => Some(handshake.responder_to_initiator_id),
            Handshake::Responded(tentative) => Some(tentative.recv_id()),
            Handshake::None => None,
        }
    }

    pub(crate) fn take_initiated(&mut self) -> Option<(SentHandshake, Handle<Event>, Mac)> {
        match std::mem::replace(self, Handshake::None) {
            Handshake::Initiated(sent, timeout, mac) => Some((sent, timeout, mac)),
            other => {
                *self = other;
                None
            }
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
        *self = Handshake::Responded(Box::new(session));
        packet
    }

    /// Finish a handshake as the initiator, returning the newly established sessions.
    ///
    /// The handshake state is unchanged if the handshake cannot complete, either because
    /// it's not in an appropriate state or because the handshake response isn't a valid
    /// completion of the handshake.
    pub(crate) fn finish(
        &mut self,
        packet: &mut HandshakeResponse,
        endpoint_static: &NodeKeyPair,
        psk: &Psk,
        cookies: &MACReceiver,
        now: Instant,
    ) -> Option<BidiSession> {
        let (mut sent_handshake, timeout, _) = self.take_initiated()?;

        if !cookies.verify_macs(packet.as_bytes()) {
            return None;
        };

        let session_keys =
            match sent_handshake
                .noise
                .try_finish(&mut packet.noise, endpoint_static.into(), psk)
            {
                Ok(session_keys) => session_keys,
                Err(handshake) => {
                    sent_handshake.noise = handshake;
                    return None;
                }
            };

        let session = BidiSession::new(
            session_keys,
            packet.sender_id,
            sent_handshake.responder_to_initiator_id,
            now,
        );

        timeout.cancel();

        Some(session)
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
    ) -> Option<(BidiSession, Vec<PacketMut>)> {
        let Handshake::Responded(tentative) = self else {
            return None;
        };

        if tentative.recv_id() != session_id {
            return None;
        };

        packets = tentative.decrypt(packets);
        if packets.is_empty() {
            return None;
        }

        let Handshake::Responded(tentative) = std::mem::replace(self, Handshake::None) else {
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
            initiate_handshake(&a_static, &b_static.public, a_session, a_init_time);

        let mut init_pkt = PacketMut::from(init_pkt.as_bytes());
        let handshake_mac = a_mac_send.write_macs(init_pkt.as_mut());

        let mut scheduler = Scheduler::default();
        let timeout = scheduler.add(
            ts_time::TimeRange::new_around(Instant::now(), std::time::Duration::from_secs(1000)),
            crate::Event::HandshakeTimeout(crate::config::PeerId(0)),
        );
        let mut a_handshake = Handshake::Initiated(a_handshake, timeout, handshake_mac);

        // Peer B receives it and responds
        let init_pkt = HandshakeInitiation::try_mut_from_bytes(init_pkt.as_mut())
            .expect("init_pkt should be a valid handshake initiation message");
        let b_mac_send = MACSender::new(&a_static.public);
        let b_mac_recv = MACReceiver::new(&b_static.public);
        let b_handshake = ReceivedHandshake::new(init_pkt, &b_static, &b_mac_recv)
            .expect("peer B should successfully process A's handshake initiation");
        assert_eq!(b_handshake.peer_static(), a_static.public);
        assert_eq!(b_handshake.timestamp, a_init_time);
        let b_session = SessionId::random(); // B wants to receive at this ID
        let (mut b_session, mut response_pkt) =
            b_handshake.respond(b_session, &psk, &b_mac_send, Instant::now());

        // Peer A receives response
        let response_pkt = HandshakeResponse::try_mut_from_bytes(response_pkt.as_mut())
            .expect("response_pkt should be a valid handshake response message");
        let Some(mut a_session) =
            a_handshake.finish(response_pkt, &a_static, &psk, &a_mac_recv, Instant::now())
        else {
            panic!("failed to process handshake response from peer B");
        };

        // They can now communicate
        let a_plaintext = vec![PacketMut::from("xyzzy".as_bytes())];
        let mut packets = a_plaintext.clone();
        a_session.encrypt(packets.iter_mut());
        let b_received = b_session.decrypt(packets);
        assert_eq!(b_received, a_plaintext);

        let b_plaintext = vec![PacketMut::from("plover".as_bytes())];
        packets = b_plaintext.clone();
        b_session.encrypt(&mut packets);
        let a_received = a_session.decrypt(packets);
        assert_eq!(a_received, b_plaintext);
    }
}
