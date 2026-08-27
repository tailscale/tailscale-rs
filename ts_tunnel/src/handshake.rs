use std::{
    mem::replace,
    ops::Add,
    time::{Duration, Instant},
};

use ts_keys::{NodeKeyPair, NodePublicKey};
use ts_noise::ikpsk2;
use ts_packet::PacketMut;
use ts_time::{Handle, TimeRange};
use zerocopy::IntoBytes;

use crate::{
    PeerConfig,
    endpoint::{EndpointState, Event},
    ids::SessionHandle,
    macs::{MACReceiver, MACSender, Mac},
    messages::*,
    session::BidiSession,
    time::TAI64N,
};

const PROLOGUE: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

/// A partially processed incoming handshake.
///
/// Incoming handshakes have to be decrypted in order to know who the remote peer is, before a reply
/// can be generated. [`ReceivedHandshake`] holds this half-handled incoming handshake until it's
/// dispatched to the correct peer's [`Handshake::respond`] for further processing.
pub struct ReceivedHandshake {
    /// The session ID the initiator wants us to use when sending it packets.
    responder_to_initiator_id: SessionId,
    /// The half-completed Noise handshake with the peer. It is far enough along to provide the
    /// peer's static public key.
    noise: ikpsk2::ReceivedHandshake,
    /// The packet's anti-replay timestamp.
    timestamp: TAI64N,
}

impl ReceivedHandshake {
    pub fn new(mut pkt: PacketMut, my_static: &NodeKeyPair, macs: &MACReceiver) -> Option<Self> {
        if !macs.verify_macs(pkt.as_ref()) {
            return None;
        }

        let Ok(MessageMut::HandshakeInitiation(init)) = MessageMut::try_from(pkt.as_mut()) else {
            tracing::debug!("invalid handshake initiation message");
            return None;
        };

        let (noise, timestamp) =
            ikpsk2::ReceivedHandshake::new::<TAI64N>(&mut init.noise, PROLOGUE, my_static.into())?;

        Some(Self {
            responder_to_initiator_id: init.sender_id,
            noise,
            timestamp: *timestamp,
        })
    }

    /// Return the peer's static public key.
    pub fn peer_static(&self) -> NodePublicKey {
        self.noise.peer_static_pub.to_bytes().into()
    }
}

/// A partially completed sent handshake.
struct SentHandshake {
    responder_to_initiator_handle: SessionHandle,
    noise: ikpsk2::SentHandshake<TAI64N>,
    // timeout is a handle that cancels a retransmit event when the SentHandshake is abandoned,
    // but is otherwise unused.
    #[allow(dead_code)]
    timeout: Handle<Event>,
    // The mac1 of the transmitted handshake, required to process CookieReply messages.
    mac1: Mac,
    // The final deadline for this handshake attempt, including all retries.
    deadline: Instant,
}

pub(crate) const HANDSHAKE_RETRY_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const HANDSHAKE_FAILURE_TIMEOUT: Duration = Duration::from_secs(90);

/// The state machine portion of a handshake.
#[derive(Default)]
enum State {
    /// No handshake in progress.
    #[default]
    None,
    /// We are the initiator, awaiting a response.
    Initiated(SentHandshake),
    /// We are the responder, awaiting an initial transport
    /// message to confirm the new session.
    Responded(Box<BidiSession>),
}

impl State {
    fn take_if_initiated(&mut self) -> Option<SentHandshake> {
        match replace(self, State::None) {
            State::Initiated(sent) => Some(sent),
            other => {
                *self = other;
                None
            }
        }
    }

    fn take_if_responded(&mut self) -> Option<Box<BidiSession>> {
        match replace(self, State::None) {
            State::Responded(session) => Some(session),
            other => {
                *self = other;
                None
            }
        }
    }

    fn as_initiated_mut(&mut self) -> Option<&mut SentHandshake> {
        if let State::Initiated(sent) = self {
            Some(sent)
        } else {
            None
        }
    }

    fn as_responded_mut(&mut self) -> Option<&mut BidiSession> {
        if let State::Responded(session) = self {
            Some(session.as_mut())
        } else {
            None
        }
    }
}

/// The handshake state for a peer.
///
/// Handshake state can be idle, or in-flight. As soon as a handshake completes, it yields a new
/// usable [`BidiSession`] and goes back to being idle.
pub struct Handshake {
    cookie_sender: MACSender,
    last_seen_timestamp: Option<TAI64N>,
    state: State,
}

/// Error returned from [`Handshake::timeout`].
#[derive(Copy, Clone, Debug)]
pub enum TimeoutError {
    /// Handshake is not in the initiated state. Likely this means the timeout notification raced
    /// with handshake completion. Either way, no action is required.
    WrongHandshakeState,
    /// The handshake has reached the maximum number of timeout retries, and has permanently failed.
    /// Caller should clear out any state that was waiting for a session (e.g. packet buffers) and
    /// not try another handshake initiation until [`Endpoint::send`] is called again with a new
    /// packet for the peer.
    HandshakeTimeout,
}

impl Handshake {
    pub fn new(peer_key: &NodePublicKey) -> Self {
        let cookie_sender = MACSender::new(peer_key);
        Self {
            cookie_sender,
            last_seen_timestamp: None,
            state: State::None,
        }
    }

    /// Report whether a handshake is currently in flight.
    pub fn is_active(&self) -> bool {
        !matches!(self.state, State::None)
    }

    /// Abandon any in-flight handshake, returning to the idle state.
    pub fn abandon(&mut self) {
        self.state = State::None;
    }

    /// Return the session ID of the handshake's tentative session, if one exists.
    ///
    /// Callers wishing to use [`Handshake::confirm`] can use this method to check if it's worth
    /// attempting.
    pub fn session_id(&self) -> Option<SessionId> {
        match &self.state {
            State::Responded(session) => Some(session.recv_id()),
            _ => None,
        }
    }

    /// Start a new handshake in the initiator role.
    ///
    /// Starting a new handshake abandons any other handshake that was already in flight.
    ///
    /// [`Handshake::initiate`] schedules an [`Event::HandshakeTimeout`] event. The caller must call
    /// [`Handshake::timeout`] when that event fires to continue advancing the handshake state machine.
    pub fn initiate(
        &mut self,
        endpoint: &mut EndpointState,
        peer: &PeerConfig,
        now: Instant,
    ) -> PacketMut {
        let deadline = now.add(HANDSHAKE_FAILURE_TIMEOUT);
        self.initiate_inner(endpoint, peer, now, deadline)
    }

    /// Process a handshake initiation timeout.
    ///
    /// Returns `Ok(packet)` if the handshake can continue to retry,
    /// `Err(TimeoutError::HandshakeTimeout)` if the maximum number of retries has been reached,
    /// or `Err(TimeoutError::WrongHandshakeState)` if the timeout is no longer applicable.
    pub fn timeout(
        &mut self,
        endpoint: &mut EndpointState,
        peer: &PeerConfig,
        now: Instant,
    ) -> Result<PacketMut, TimeoutError> {
        let handshake = self
            .state
            .take_if_initiated()
            .ok_or(TimeoutError::WrongHandshakeState)?;

        if now >= handshake.deadline {
            return Err(TimeoutError::HandshakeTimeout);
        }

        Ok(self.initiate_inner(endpoint, peer, now, handshake.deadline))
    }

    fn initiate_inner(
        &mut self,
        endpoint: &mut EndpointState,
        peer: &PeerConfig,
        now: Instant,
        deadline: Instant,
    ) -> PacketMut {
        let session_handle = endpoint.ids.allocate_session(peer.id);

        let mut pkt = HandshakeInitiation {
            sender_id: session_handle.id(),
            ..Default::default()
        };

        let noise = ikpsk2::SentHandshake::new(
            (&endpoint.my_key).into(),
            peer.key.into(),
            PROLOGUE,
            endpoint.timestamps.now(),
            pkt.noise.as_mut_bytes(),
        );
        let mut pkt = PacketMut::from(pkt.as_bytes());
        let mac1 = self.cookie_sender.write_macs(pkt.as_mut());

        let tr = TimeRange::new_around(now + HANDSHAKE_RETRY_TIMEOUT, Duration::from_millis(500));
        let timeout = endpoint.scheduler.add(tr, Event::HandshakeTimeout(peer.id));

        self.state = State::Initiated(SentHandshake {
            responder_to_initiator_handle: session_handle,
            noise,
            timeout,
            mac1,
            deadline,
        });

        pkt
    }

    /// Finish a handshake as the initiator, returning the newly established sessions.
    ///
    /// The handshake state is unchanged if the handshake cannot complete, either because
    /// it's not in an appropriate state or because the handshake response isn't a valid
    /// completion of the handshake.
    pub fn finish(
        &mut self,
        packet: &mut HandshakeResponse,
        endpoint: &mut EndpointState,
        peer: &PeerConfig,
        now: Instant,
    ) -> Option<BidiSession> {
        let mut sent_handshake = self.state.take_if_initiated()?;

        if !endpoint.my_cookie.verify_macs(packet.as_bytes()) {
            self.state = State::Initiated(sent_handshake);
            return None;
        };

        let session_keys = match sent_handshake.noise.try_finish(
            &mut packet.noise,
            (&endpoint.my_key).into(),
            &peer.psk,
        ) {
            Ok(session_keys) => session_keys,
            Err(handshake) => {
                sent_handshake.noise = handshake;
                self.state = State::Initiated(sent_handshake);
                return None;
            }
        };

        let session = BidiSession::new_initiator(
            endpoint,
            peer,
            session_keys,
            sent_handshake.responder_to_initiator_handle,
            packet.sender_id,
            now,
        );

        Some(session)
    }

    /// Respond to a [`ReceivedHandshake`] from the peer.
    ///
    /// The session must be confirmed before it can be used to communicate, by calling
    /// [`Handshake::confirm`] with valid data packets from the initiator.
    ///
    /// Responding abandons any other handshake that was already in flight.
    pub fn respond(
        &mut self,
        handshake: ReceivedHandshake,
        endpoint: &mut EndpointState,
        peer: &PeerConfig,
        now: Instant,
    ) -> Option<PacketMut> {
        if let Some(last_seen_timestamp) = self.last_seen_timestamp
            && handshake.timestamp < last_seen_timestamp
        {
            tracing::trace!("handshake replay detected, bailing out");
            return None;
        }

        let session_handle = endpoint.ids.allocate_session(peer.id);
        let mut response = HandshakeResponse {
            sender_id: session_handle.id(),
            receiver_id: handshake.responder_to_initiator_id,
            ..Default::default()
        };
        let session_keys = handshake
            .noise
            .finish(&peer.psk, response.noise.as_mut_bytes());
        let mut pkt = PacketMut::from(response.as_bytes());
        self.cookie_sender.write_macs(pkt.as_mut());

        let session = Box::new(BidiSession::new_responder(
            endpoint,
            peer,
            session_keys,
            session_handle,
            handshake.responder_to_initiator_id,
            now,
        ));

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
        self.state = State::Responded(session);
        Some(pkt)
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
    pub fn confirm(
        &mut self,
        mut packets: Vec<PacketMut>,
    ) -> Option<(BidiSession, Vec<PacketMut>)> {
        let tentative = self.state.as_responded_mut()?;

        packets = tentative.decrypt(packets);
        if packets.is_empty() {
            return None;
        }

        // as_responded_mut above confirmed that the handshake is in the responded state.
        let tentative = *self.state.take_if_responded().unwrap();

        Some((tentative, packets))
    }

    /// Process a cookie reply packet from the peer.
    ///
    /// If present, the handshake that caused the cookie reply is not changed: processing a cookie
    /// reply merely updates the state that will be used in future handshakes.
    pub fn cookie_reply(&mut self, packet: &CookieReply) {
        let Some(handshake) = self.state.as_initiated_mut() else {
            tracing::trace!("got cookie reply outside of handshake initiation");
            return;
        };
        self.cookie_sender.receive_cookie(packet, &handshake.mac1);
    }

    /// clean up expired responded handshake state, if any.
    pub fn cleanup_expired(&mut self, now: Instant) {
        if let State::Responded(tentative) = &self.state
            && tentative.expired(now)
        {
            tracing::trace!("pending responded handshake expired");
            self.state = State::None;
        }
    }
}

#[cfg(test)]
mod tests {
    use ts_keys::NodeKeyPair;
    use zerocopy::TryFromBytes;

    use super::*;
    use crate::PeerId;

    #[test]
    fn test_handshake() {
        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let psk = rand::random();

        // Peer A sends a handshake initiation...
        let mut a_state = EndpointState::from(a_static.clone());
        let mut a_handshake = Handshake::new(&b_static.public);
        let a_peer = PeerConfig::new(PeerId(1), b_static.public, psk);
        let init_pkt = a_handshake.initiate(&mut a_state, &a_peer, Instant::now());
        // Peer B receives it and responds
        let b_mac_recv = MACReceiver::new(&b_static.public);
        let init_pkt = ReceivedHandshake::new(init_pkt, &b_static, &b_mac_recv)
            .expect("B should parse the initiation message");

        let mut b_handshake = Handshake::new(&a_state.my_key.public);
        let mut b_state = EndpointState::from(b_static);
        let b_peer = PeerConfig::new(PeerId(2), a_static.public, psk);
        let mut response_pkt = b_handshake
            .respond(init_pkt, &mut b_state, &b_peer, Instant::now())
            .expect("B should respond to handshake");

        // Peer A receives response, sends confirmation
        let response_pkt = HandshakeResponse::try_mut_from_bytes(response_pkt.as_mut())
            .expect("response_pkt should be a valid handshake response message");
        let Some(mut a_session) =
            a_handshake.finish(response_pkt, &mut a_state, &a_peer, Instant::now())
        else {
            panic!("failed to process handshake response from peer B");
        };
        let a_plaintext = vec![PacketMut::from("xyzzy".as_bytes())];
        let mut packets = a_plaintext.clone();
        a_session.encrypt(packets.iter_mut());

        // Peer B confirms and decrypts packet
        let (b_session, mut packets) = b_handshake.confirm(packets).expect("B should confirm");
        assert_eq!(packets, a_plaintext);

        let b_plaintext = vec![PacketMut::from("plover".as_bytes())];
        packets = b_plaintext.clone();
        b_session.encrypt(&mut packets);
        let a_received = a_session.decrypt(packets);
        assert_eq!(a_received, b_plaintext);
    }

    // Regression test for https://github.com/tailscale/tailscale-rs/issues/334
    #[test]
    fn test_invalid_response_ignored() {
        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let psk = rand::random();

        // A sends a handshake
        let mut a_state = EndpointState::from(a_static.clone());
        let mut a_handshake = Handshake::new(&b_static.public);
        let a_peer = PeerConfig::new(PeerId(0), b_static.public, psk);
        let init_pkt = a_handshake.initiate(&mut a_state, &a_peer, Instant::now());

        // B receives and responds
        let b_mac_recv = MACReceiver::new(&b_static.public);
        let init_pkt = ReceivedHandshake::new(init_pkt, &b_static, &b_mac_recv)
            .expect("B should parse the initiation message");
        let mut b_handshake = Handshake::new(&a_static.public);
        let mut b_state = EndpointState::from(b_static);
        let b_peer = PeerConfig::new(PeerId(2), a_static.public, psk);

        let mut response_pkt = b_handshake
            .respond(init_pkt, &mut b_state, &b_peer, Instant::now())
            .expect("B responds to handshake");

        // A receives several invalid responses: one with bad MACs, one with a bad Noise handshake
        assert!(
            a_handshake
                .finish(
                    &mut HandshakeResponse::default(),
                    &mut a_state,
                    &a_peer,
                    Instant::now()
                )
                .is_none()
        );
        let mut corrupt_pkt = response_pkt.clone();
        let corrupt_pkt = HandshakeResponse::try_mut_from_bytes(corrupt_pkt.as_mut()).unwrap();
        corrupt_pkt.noise[3] = corrupt_pkt.noise[3].wrapping_add(1);
        assert!(
            a_handshake
                .finish(corrupt_pkt, &mut a_state, &a_peer, Instant::now())
                .is_none()
        );

        // Finally, A receives the correct response and establishes the session.
        let response_pkt = HandshakeResponse::try_mut_from_bytes(response_pkt.as_mut())
            .expect("response_pkt should be a valid handshake response message");
        assert!(
            a_handshake
                .finish(response_pkt, &mut a_state, &a_peer, Instant::now())
                .is_some()
        );
    }
}
