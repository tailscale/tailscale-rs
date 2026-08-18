use core::time::Duration;
use std::{collections::HashMap, time::Instant};

use itertools::Itertools;
use ts_keys::{NodeKeyPair, NodePublicKey};
use ts_packet::PacketMut;
use ts_time::{Handle, Scheduler, TimeRange};

use crate::{
    config::{PeerConfig, PeerId},
    handshake::{Handshake, ReceivedHandshake},
    ids::IdMap,
    macs::MACReceiver,
    messages::{HandshakeResponse, Message, MessageMut, SessionId},
    queue::Queue,
    session::Session,
    time::TAI64NClock,
};

/// If an endpoint hasn't sent any packets to a peer for `KEEPALIVE_TIMEOUT` after receiving a
/// packet from that peer, it must send an empty keepalive message so that the peer can distinguish
/// lack of activity from loss of session.
/// See: WireGuard spec, section 6.5
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

struct Peer {
    config: PeerConfig,
    session: Session,
    handshake: Handshake,
    queue: Queue,
    keepalive: Option<Handle<Event>>,
    send_another_keepalive: bool,
}

impl From<PeerConfig> for Peer {
    fn from(config: PeerConfig) -> Self {
        let handshake = Handshake::new(&config.key);
        Self {
            config,
            handshake,

            session: Default::default(),
            keepalive: None,
            queue: Default::default(),
            send_another_keepalive: false,
        }
    }
}

impl Peer {
    fn schedule_keepalive(&mut self, scheduler: &mut Scheduler<Event>, now: Instant) {
        if self.keepalive.is_some() {
            self.send_another_keepalive = true;
            return;
        }
        let tr = TimeRange::new_around(now + KEEPALIVE_TIMEOUT, Duration::from_secs(1));
        self.keepalive = Some(scheduler.add(tr, Event::MaybeSendKeepalive(self.config.id)));
    }

    // TODO: consider replacing outparam with plain SendResult that supports merging.
    fn send(
        &mut self,
        endpoint: &mut EndpointState,
        mut packets: Vec<PacketMut>,
        now: Instant,
        out: &mut SendResult,
    ) {
        self.check_invariants(now);

        match self.session.send(&mut packets, now) {
            Ok(_) => {
                tracing::trace!("enqueueing packets to peer");
                out.queue_to_peer(self.config.id, packets);
            }
            Err(_) => {
                self.queue.append(packets);
            }
        }

        if self.handshake.is_active() {
            tracing::trace!("handshake is already in-flight, bail");
            return;
        }

        if !self.session.needs_rotation(now) {
            tracing::trace!("session does not need new handshake");
            return;
        }

        self.start_handshake(endpoint, now, out);
    }

    #[tracing::instrument(skip_all, fields(?session_id, n_packets = packets.len()))]
    fn recv(
        &mut self,
        endpoint: &mut EndpointState,
        session_id: SessionId,
        mut packets: Vec<PacketMut>,
        now: Instant,
        out: &mut RecvResult,
    ) {
        self.check_invariants(now);

        let mut dropped = 0;
        packets.retain_mut(|packet| match MessageMut::try_from(packet.as_mut()) {
            Err(()) => {
                tracing::trace!("dropping invalid packet");
                dropped += 1;
                false
            }
            Ok(MessageMut::TransportDataHeader(_)) => true,
            Ok(MessageMut::HandshakeResponse(resp)) => {
                self.recv_handshake_response(endpoint, resp, now, out);
                false
            }
            Ok(MessageMut::CookieReply(resp)) => {
                self.handshake.cookie_reply(resp);
                false
            }
            Ok(MessageMut::HandshakeInitiation(_)) => {
                debug_assert!(
                    false,
                    "handshake initiations should have been filtered out prior to calling recv"
                );
                tracing::warn!("unexpected handshake init in recv");
                false
            }
        });

        if dropped > 0 {
            tracing::trace!(n_dropped = dropped, "dropped packets");
        }

        self.recv_transport_data(endpoint, session_id, packets, now, out);
    }

    fn recv_handshake_response(
        &mut self,
        endpoint: &mut EndpointState,
        packet: &mut HandshakeResponse,
        now: Instant,
        out: &mut RecvResult,
    ) {
        let Some(session) = self.handshake.finish(packet, endpoint, &self.config, now) else {
            tracing::error!("handshake failed to complete");
            return;
        };

        self.session
            .activate(endpoint, self.config.id, session, now);
        let mut packets = self.queue.drain();
        if packets.is_empty() {
            // Initiator must transmit one packet to confirm session. If there are none queued,
            // send a keepalive.
            packets.push(PacketMut::new(0));
        }
        // Session was just activated, so can always send.
        self.session.send(&mut packets, now).unwrap();
        out.queue_to_peer(self.config.id, packets);
    }

    fn recv_transport_data(
        &mut self,
        endpoint: &mut EndpointState,
        session_id: SessionId,
        packets: Vec<PacketMut>,
        now: Instant,
        out: &mut RecvResult,
    ) {
        if let Some(recv) = self.session.get_recv(session_id, now) {
            let packets = recv.decrypt(packets);
            if !packets.is_empty() {
                out.queue_to_local(self.config.id, packets);
                self.schedule_keepalive(&mut endpoint.scheduler, now);
                if self.session.needs_rotation(now) {
                    self.start_handshake(endpoint, now, out);
                }
            }
            return;
        }

        let Some(tentative_id) = self.handshake.session_id() else {
            return;
        };
        if tentative_id != session_id {
            return;
        }
        let Some((session, packets)) = self.handshake.confirm(packets) else {
            return;
        };

        out.queue_to_local(self.config.id, packets);
        self.schedule_keepalive(&mut endpoint.scheduler, now);

        self.session
            .activate(endpoint, self.config.id, session, now);
        let mut packets = self.queue.drain();
        if !packets.is_empty() {
            // Session was just activated, so can always send.
            self.session.send(&mut packets, now).unwrap();
            out.queue_to_peer(self.config.id, packets);
        }
    }

    fn respond_to_handshake(
        &mut self,
        endpoint: &mut EndpointState,
        handshake: ReceivedHandshake,
        now: Instant,
        out: &mut RecvResult,
    ) {
        let packet = self
            .handshake
            .respond(handshake, endpoint, &self.config, now);
        if let Some(packet) = packet {
            out.queue_to_peer(self.config.id, [packet]);
        }
    }

    fn handshake_timeout(
        &mut self,
        endpoint: &mut EndpointState,
        now: Instant,
        out: &mut EventResult,
    ) {
        self.check_invariants(now);

        if !self.handshake.is_active() {
            // Handshake completed prior to timeout firing.
            return;
        }

        self.start_handshake(endpoint, now, out);
    }

    fn send_keepalive(
        &mut self,
        endpoint: &mut EndpointState,
        now: Instant,
        out: &mut EventResult,
    ) {
        let Some(packet) = self.session.send_keepalive(now) else {
            tracing::trace!("send keepalive: session expired, skipping");
            return;
        };
        out.queue_to_peer(self.config.id, [packet]);

        self.keepalive = None;

        if self.send_another_keepalive {
            self.schedule_keepalive(&mut endpoint.scheduler, now);
            self.send_another_keepalive = false;
        }
    }

    fn cleanup_expired(&mut self, now: Instant) {
        self.check_invariants(now);
        self.session.cleanup_expired(now);
    }

    fn shutdown(&mut self) {
        self.session.deactivate();
        self.handshake.abandon();
        if let Some(handle) = self.keepalive.take() {
            handle.cancel();
        }
    }

    fn start_handshake(
        &mut self,
        endpoint: &mut EndpointState,
        now: Instant,
        out: &mut impl QueueToPeer,
    ) {
        let packet = self.handshake.initiate(endpoint, &self.config, now);
        out.queue_to_peer(self.config.id, [packet]);
    }

    fn check_invariants(&self, now: Instant) {
        if !cfg!(debug_assertions) {
            return;
        }
        if !self.queue.is_empty() {
            assert!(
                !self.session.is_active(now),
                "peer {:?}: packets in queue with active session",
                self.config.id
            );

            assert!(
                self.handshake.is_active(),
                "peer {:?}: packets in queue with no handshake in flight",
                self.config.id
            );
        }
    }
}

/// A WireGuard endpoint capable of communicating with multiple remote peers.
pub struct Endpoint {
    state: EndpointState,
    peers: HashMap<PeerId, Peer>,
}

pub struct EndpointState {
    pub my_key: NodeKeyPair,

    pub my_cookie: MACReceiver,
    pub ids: IdMap,
    pub timestamps: TAI64NClock,
    pub scheduler: Scheduler<Event>,
}

impl EndpointState {
    pub fn new(my_key: NodeKeyPair) -> Self {
        let my_cookie = MACReceiver::new(&my_key.public);
        Self {
            my_key,
            my_cookie,
            ids: IdMap::default(),
            timestamps: TAI64NClock::default(),
            scheduler: Scheduler::default(),
        }
    }
}

impl Endpoint {
    /// Construct a new endpoint with the given keypair.
    pub fn new(my_key: NodeKeyPair) -> Self {
        Self {
            state: EndpointState::new(my_key),
            peers: HashMap::new(),
        }
    }

    /// Insert a peer if it doesn't exist, otherwise update the peer with the given `cfg.id`
    /// with the given config.
    ///
    /// Returns the old [`PeerConfig`] if there was one.
    ///
    /// # Panics
    ///
    /// If the [`NodePublicKey`] in the new [`PeerConfig`] collides with an existing key
    /// for a different [`PeerId`].
    pub fn upsert_peer(&mut self, mut cfg: PeerConfig) -> Option<PeerConfig> {
        match self.peers.get_mut(&cfg.id) {
            Some(peer) => {
                if peer.config.key != cfg.key {
                    self.state.ids.remove_peer(&peer.config.key);
                    self.state.ids.add_peer(cfg.id, &cfg.key);
                }

                core::mem::swap(&mut peer.config, &mut cfg);
                Some(cfg)
            }
            None => {
                if !self.state.ids.add_peer(cfg.id, &cfg.key) {
                    panic!("nodekey collision");
                }

                self.peers.insert(cfg.id, Peer::from(cfg));
                None
            }
        }
    }

    /// Remove the given peer.
    ///
    /// Returns whether the peer in question existed.
    pub fn remove_peer(&mut self, peer: PeerId) -> bool {
        match self.peers.remove(&peer) {
            None => false,
            Some(mut peer) => {
                peer.shutdown();
                self.state.ids.remove_peer(&peer.config.key);
                true
            }
        }
    }

    /// Send packets to peers.
    pub fn send(
        &mut self,
        now: Instant,
        packets: impl IntoIterator<Item = (PeerId, Vec<PacketMut>)>,
    ) -> SendResult {
        let mut ret = SendResult::default();
        for (peer_id, packets) in packets {
            let Some(peer) = self.peers.get_mut(&peer_id) else {
                tracing::warn!(?peer_id, "no peer stored for id");
                continue;
            };

            tracing::debug!(
                ?peer_id,
                n_packets = packets.len(),
                "processing send packets"
            );

            peer.send(&mut self.state, packets, now, &mut ret);
        }
        ret
    }

    /// Receive packets from peers.
    pub fn recv(
        &mut self,
        now: Instant,
        packets: impl IntoIterator<Item = PacketMut>,
    ) -> RecvResult {
        let mut ret = RecvResult::default();

        let mut packets = packets.into_iter().into_group_map_by(|packet| {
            u32::from(
                Message::try_from(packet.as_ref())
                    .ok()
                    .and_then(|message| message.receiver_id())
                    .unwrap_or_default(),
            )
        });

        let handshakes = packets.remove(&0).unwrap_or_default();
        if !handshakes.is_empty() {
            tracing::trace!(n = handshakes.len(), "processing handshakes");
        }

        for packet in handshakes {
            self.process_one_handshake(packet, now, &mut ret);
        }

        tracing::trace!(n = packets.len(), "processing packets");

        for (session_id, packets) in packets {
            let session_id = session_id.into();

            let Some(peer_id) = self.state.ids.get_by_session_id(&session_id) else {
                tracing::warn!(?session_id, "session not found");
                continue;
            };
            let Some(peer) = self.peers.get_mut(&peer_id) else {
                tracing::warn!(?peer_id, "no peer found");
                continue;
            };

            peer.recv(&mut self.state, session_id, packets, now, &mut ret);
        }

        ret
    }

    fn process_one_handshake(&mut self, packet: PacketMut, now: Instant, out: &mut RecvResult) {
        let Some(handshake) =
            ReceivedHandshake::new(packet, &self.state.my_key, &self.state.my_cookie)
        else {
            tracing::error!("parsing received handshake failed");
            return;
        };

        let Some(peer_id) = self.state.ids.get_by_nodekey(&handshake.peer_static()) else {
            tracing::error!(peer_key = %handshake.peer_static(), "no peer id stored for peer's key");
            return;
        };
        let Some(peer) = self.peers.get_mut(&peer_id) else {
            tracing::error!(?peer_id, "no peer entry for peer id");
            return;
        };

        peer.respond_to_handshake(&mut self.state, handshake, now, out)
    }

    /// Dispatch time-based events that are due to occur at or before the given instant.
    ///
    /// Use [`Endpoint::next_event`] to know when to call dispatch_events. It is inefficient but
    /// harmless to call it more frequently than specified by [`Endpoint::next_event`].
    pub fn dispatch_events(&mut self, now: Instant) -> EventResult {
        let mut out = EventResult::default();
        for event in self.state.scheduler.dispatch(now) {
            match event {
                Event::HandshakeTimeout(peer_id) => {
                    let Some(peer) = self.peers.get_mut(&peer_id) else {
                        continue;
                    };
                    peer.handshake_timeout(&mut self.state, now, &mut out);
                }
                Event::MaybeSendKeepalive(peer_id) => {
                    let Some(peer) = self.peers.get_mut(&peer_id) else {
                        continue;
                    };
                    peer.send_keepalive(&mut self.state, now, &mut out);
                }
                Event::ExpireSession(peer_id) => {
                    let Some(peer) = self.peers.get_mut(&peer_id) else {
                        continue;
                    };
                    peer.cleanup_expired(now);
                }
            }
        }
        out
    }

    /// Returns the next time range in which [`Endpoint::dispatch_events`] should next be called to
    /// dispatch events.
    ///
    /// [`Endpoint::dispatch_events`] should be called at some point in the returned [`TimeRange`]
    /// to keep the wireguard state machine functioning correctly.
    ///
    /// See [`Scheduler::next_dispatch_range`] for additional details.
    pub fn next_event(&self) -> Option<TimeRange> {
        self.state.scheduler.next_dispatch_range()
    }

    /// Return the node key for the selected peer.
    pub fn peer_key(&self, id: PeerId) -> Option<NodePublicKey> {
        let peer = self.peers.get(&id)?;
        Some(peer.config.key)
    }

    /// Return the peer id that has the selected node key.
    pub fn peer_id(&self, key: NodePublicKey) -> Option<PeerId> {
        self.state.ids.get_by_nodekey(&key)
    }
}

trait QueueToPeer {
    fn queue_to_peer(&mut self, peer: PeerId, packets: impl IntoIterator<Item = PacketMut>);
}

/// The outcome of attempting to send packets to peers.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct SendResult {
    /// Packets to be sent to remote peers.
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

impl QueueToPeer for SendResult {
    fn queue_to_peer(&mut self, peer: PeerId, packets: impl IntoIterator<Item = PacketMut>) {
        self.to_peers.entry(peer).or_default().extend(packets);
    }
}

/// The outcome of processing received packets.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct RecvResult {
    /// Valid packets from peers to be delivered locally.
    pub to_local: HashMap<PeerId, Vec<PacketMut>>,
    /// Packets to be sent to remote peers.
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

impl RecvResult {
    fn queue_to_local(&mut self, peer: PeerId, packets: impl IntoIterator<Item = PacketMut>) {
        self.to_local
            .entry(peer)
            .or_default()
            .extend(packets.into_iter().filter(|p| !p.is_empty()));
    }
}

impl QueueToPeer for RecvResult {
    fn queue_to_peer(&mut self, peer: PeerId, packets: impl IntoIterator<Item = PacketMut>) {
        self.to_peers.entry(peer).or_default().extend(packets);
    }
}

/// The outcome of processing an Event.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct EventResult {
    /// Packets to be sent to remote peers.
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

impl QueueToPeer for EventResult {
    fn queue_to_peer(&mut self, peer: PeerId, packets: impl IntoIterator<Item = PacketMut>) {
        self.to_peers.entry(peer).or_default().extend(packets);
    }
}

/// An event that Endpoint needs to know about.
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Copy, Clone)]
pub enum Event {
    /// Didn't receive a response to a handshake initiation.
    HandshakeTimeout(PeerId),
    /// Send a keepalive packet, if there was no recent outgoing traffic.
    MaybeSendKeepalive(PeerId),
    /// Clean up expired session state.
    ExpireSession(PeerId),
}

#[cfg(test)]
mod tests {
    use zerocopy::TryFromBytes;

    use super::*;
    use crate::{
        config::PeerConfig,
        messages::{HandshakeInitiation, TransportDataHeader},
    };

    /// Matches different shapes of packets.
    #[derive(Clone)]
    enum PacketMatcher {
        /// Packet must be byte for byte identical to an expected packet.
        Exact(PacketMut),
        /// Packet must have the right size for a handshake initiation message.
        HandshakeInitiation,
        /// Packet must have the right size for a handshake response message.
        HandshakeResponse,
        /// Packet must be large enough to potentially be an encrypted transport data message.
        TransportData,
    }

    impl PacketMatcher {
        fn assert_matches(&self, packet: &PacketMut) {
            match self {
                PacketMatcher::Exact(want) => assert_eq!(want, packet),
                PacketMatcher::HandshakeInitiation => {
                    HandshakeInitiation::try_ref_from_bytes(packet.as_ref()).unwrap();
                }
                PacketMatcher::HandshakeResponse => {
                    HandshakeResponse::try_ref_from_bytes(packet.as_ref()).unwrap();
                }
                PacketMatcher::TransportData => {
                    TransportDataHeader::try_ref_from_prefix(packet.as_ref()).unwrap();
                }
            }
        }
    }

    impl From<PacketMut> for PacketMatcher {
        fn from(v: PacketMut) -> Self {
            PacketMatcher::Exact(v)
        }
    }

    /// Create a test packet consisting of four copies of the given byte.
    pub fn packet(v: u8) -> PacketMut {
        PacketMut::from(vec![v; 4])
    }

    /// A clock that creates instants relative to an arbitrary start point.
    struct TestClock {
        start: Instant,
    }

    impl TestClock {
        pub fn new() -> Self {
            Self {
                start: Instant::now(),
            }
        }

        /// Return an instant that is the given number of seconds after the arbitrary epoch.
        pub fn at(&self, secs: u64) -> Instant {
            self.start + Duration::from_secs(secs)
        }
    }

    /// Test helper for a pair of endpoints configured to talk to each other.
    ///
    /// As the endpoints send and receive traffic, the helper keeps track of what
    /// packets are currently "on the wire" between the peers in each direction, as well
    /// as the cleartext packets that have been delivered locally to each endpoint.
    ///
    /// Assertion helpers let tests inspect the packets on the wire that have not yet
    /// been received by the destination peer, as well as the post-decryption delivered
    /// packets.
    struct EndpointPair {
        a: Endpoint,
        b: Endpoint,

        a_to_b: Vec<PacketMut>,
        b_to_a: Vec<PacketMut>,

        received_at_a: Vec<PacketMut>,
        received_at_b: Vec<PacketMut>,
    }

    impl EndpointPair {
        pub fn new() -> Self {
            let key_a = NodeKeyPair::new();
            let key_b = NodeKeyPair::new();
            let mut a = Endpoint::new(key_a.clone());
            let mut b = Endpoint::new(key_b.clone());
            let psk = rand::random();
            assert!(
                a.upsert_peer(PeerConfig::new(PeerId(1), key_b.public, psk))
                    .is_none()
            );
            assert!(
                b.upsert_peer(PeerConfig::new(PeerId(1), key_a.public, psk))
                    .is_none()
            );
            Self {
                a,
                b,
                a_to_b: Vec::new(),
                b_to_a: Vec::new(),
                received_at_a: Vec::new(),
                received_at_b: Vec::new(),
            }
        }

        fn send(
            now: Instant,
            sender: &mut Endpoint,
            packets: impl IntoIterator<Item = PacketMut>,
            out: &mut Vec<PacketMut>,
        ) {
            let id = PeerId(1);
            let mut acts = sender.send(now, HashMap::from([(id, packets.into_iter().collect())]));
            match acts.to_peers.len() {
                0 => (),
                1 => {
                    out.extend(acts.to_peers.remove(&id).unwrap());
                }
                _ => panic!(
                    "got packets for {} peers, expected 0 or 1",
                    acts.to_peers.len()
                ),
            }
        }

        fn recv(
            now: Instant,
            receiver: &mut Endpoint,
            packets: &mut Vec<PacketMut>,
            to_local: &mut Vec<PacketMut>,
            to_peer: &mut Vec<PacketMut>,
        ) {
            let id = PeerId(1);
            let mut acts = receiver.recv(now, std::mem::take(packets));
            match acts.to_peers.len() {
                0 => (),
                1 => to_peer.extend(acts.to_peers.remove(&id).unwrap()),
                _ => panic!(
                    "got packets for {} peers, expected 1 or 0",
                    acts.to_peers.len()
                ),
            }
            match acts.to_local.len() {
                0 => (),
                1 => to_local.extend(acts.to_local.remove(&id).unwrap()),
                _ => panic!(
                    "got packets from {} peers, expected 0 or 1",
                    acts.to_local.len()
                ),
            }
        }

        fn assert_packets<T: Into<PacketMatcher>>(
            packets: &[PacketMut],
            matchers: impl IntoIterator<Item = T>,
        ) {
            let matchers = matchers.into_iter();
            assert_eq!(packets.len(), matchers.size_hint().0);
            for (packet, matcher) in packets.iter().zip(matchers) {
                matcher.into().assert_matches(packet);
            }
        }

        /// Send cleartext packets from endpoint A to endpoint B.
        ///
        /// This may result in the queuing of encrypted packets from A to B, which can be
        /// inspected with [`EndpointPair::assert_a_to_b`].
        pub fn send_from_a(&mut self, now: Instant, packets: impl IntoIterator<Item = PacketMut>) {
            EndpointPair::send(now, &mut self.a, packets, &mut self.a_to_b);
        }

        /// Send cleartext packets from endpoint B to endpoint A.
        ///
        /// This may result in the queuing of encrypted packets from B to A, which can be
        /// inspected with [`EndpointPair::assert_b_to_a`].
        pub fn send_from_b(&mut self, now: Instant, packets: impl IntoIterator<Item = PacketMut>) {
            EndpointPair::send(now, &mut self.b, packets, &mut self.b_to_a);
        }

        /// Deliver all queued packets in transit from B to A.
        ///
        /// This may result in the queuing of encrypted packets from A to B, which can be inspected
        /// with [`EndpointPair::assert_a_to_b`], as well as locally delivered cleartext which can
        /// be inspected with [`EndpointPair::assert_recieved_at_a`].
        pub fn recv_at_a(&mut self, now: Instant) {
            EndpointPair::recv(
                now,
                &mut self.a,
                &mut self.b_to_a,
                &mut self.received_at_a,
                &mut self.a_to_b,
            );
        }

        /// Deliver all queued packets in transit from A to B.
        ///
        /// This may result in the queuing of encrypted packets from B to A, which can be inspected
        /// with [`EndpointPair::assert_b_to_a`], as well as locally delivered cleartext which can
        /// be inspected with [`EndpointPair::assert_recieved_at_b`].
        pub fn recv_at_b(&mut self, now: Instant) {
            EndpointPair::recv(
                now,
                &mut self.b,
                &mut self.a_to_b,
                &mut self.received_at_b,
                &mut self.b_to_a,
            );
        }

        /// Assert that packets currently in flight from A to B match the expected packet shapes.
        ///
        /// The inspection is non-destructive, in-flight packets will be delivered by the next call
        /// to [`EndpointPair::recv_at_b`].
        pub fn assert_a_to_b<T: Into<PacketMatcher>>(&self, packets: impl IntoIterator<Item = T>) {
            EndpointPair::assert_packets(&self.a_to_b, packets);
        }

        /// Assert that packets currently in flight from B to A match the expected packet shapes.
        ///
        /// The inspection is non-destructive, in-flight packets will be delivered by the next call
        /// to [`EndpointPair::recv_at_a`].
        pub fn assert_b_to_a<T: Into<PacketMatcher>>(&self, packets: impl IntoIterator<Item = T>) {
            EndpointPair::assert_packets(&self.b_to_a, packets);
        }

        /// Assert that data packets decrypted at A match the expected packet shapes.
        ///
        /// The receive queue is cleared upon inspection.
        pub fn assert_received_at_a<T: Into<PacketMatcher>>(
            &mut self,
            packets: impl IntoIterator<Item = T>,
        ) {
            EndpointPair::assert_packets(&self.received_at_a, packets);
            self.received_at_a.clear();
        }

        /// Assert that data packets decrypted at B match the expected packet shapes.
        ///
        /// The receive queue is cleared upon inspection.
        pub fn assert_received_at_b<T: Into<PacketMatcher>>(
            &mut self,
            packets: impl IntoIterator<Item = T>,
        ) {
            EndpointPair::assert_packets(&self.received_at_b, packets);
            self.received_at_b.clear();
        }
    }

    /// Assert that the given packet slice is empty.
    pub fn assert_no_packets(packets: &[PacketMut]) {
        assert_eq!(packets.len(), 0);
    }

    #[test]
    fn test_one_peer() {
        use PacketMatcher::*;

        let mut p = EndpointPair::new();
        let t = TestClock::new();

        // A sends to B. Results in a handshake initiation being transmitted, not the
        // requested packet (which gets buffered internally by the endpoint).
        p.send_from_a(t.at(0), [packet(1), packet(2)]);
        p.assert_a_to_b([HandshakeInitiation]);

        // A sends another packet. No activity on the wire.
        p.send_from_a(t.at(1), [packet(3)]);
        p.assert_a_to_b([HandshakeInitiation]);

        // B processes the handshake and responds. No packets delivered to B.
        p.recv_at_b(t.at(2));
        p.assert_b_to_a([HandshakeResponse]);
        assert_no_packets(&p.received_at_b);

        // A processes the response, and sends its queued packets.
        p.recv_at_a(t.at(3));
        p.assert_a_to_b([TransportData, TransportData, TransportData]);
        assert_no_packets(&p.received_at_a);

        // B receives
        p.recv_at_b(t.at(4));
        p.assert_received_at_b([packet(1), packet(2), packet(3)]);
        assert_no_packets(&p.b_to_a);

        // B sends
        p.send_from_b(t.at(5), [packet(4)]);
        p.assert_b_to_a([TransportData]);

        // A receives
        p.recv_at_a(t.at(6));
        p.assert_received_at_a([packet(4)]);
        assert_no_packets(&p.a_to_b);
    }

    #[test]
    fn test_rotation_initiator() {
        use PacketMatcher::*;

        let mut p = EndpointPair::new();
        let t = TestClock::new();

        // A sends a packet to establish a session.
        p.send_from_a(t.at(0), [packet(1)]);
        p.recv_at_b(t.at(1));
        p.recv_at_a(t.at(2));
        p.recv_at_b(t.at(3));
        assert_no_packets(&p.received_at_a);
        p.assert_received_at_b([packet(1)]);
        assert_no_packets(&p.a_to_b);
        assert_no_packets(&p.b_to_a);

        // After session becomes stale, A sends a packet, causing a new handshake.
        p.send_from_a(t.at(125), [packet(2)]);
        p.assert_a_to_b([TransportData, HandshakeInitiation]);
        // B receives packet and responds to handshake.
        p.recv_at_b(t.at(126));
        p.assert_received_at_b([packet(2)]);
        p.assert_b_to_a([HandshakeResponse]);
        // A receives handshake response, sends empty confirmation packet.
        p.recv_at_a(t.at(127));
        assert_no_packets(&p.received_at_a);
        p.assert_a_to_b([TransportData]);
        // B receives confirmation, finalizes rotation.
        p.recv_at_b(t.at(128));
        assert_no_packets(&p.received_at_b);
    }

    #[test]
    fn test_rotation_responder() {
        use PacketMatcher::*;

        let mut p = EndpointPair::new();
        let t = TestClock::new();

        // A sends a packet to establish a session.
        p.send_from_a(t.at(0), [packet(1)]);
        p.recv_at_b(t.at(1));
        p.recv_at_a(t.at(2));
        p.recv_at_b(t.at(3));
        assert_no_packets(&p.received_at_a);
        p.assert_received_at_b([packet(1)]);
        assert_no_packets(&p.a_to_b);
        assert_no_packets(&p.b_to_a);

        // After session becomes stale, B sends a packet.
        p.send_from_b(t.at(125), [packet(2)]);
        p.assert_b_to_a([TransportData]);
        // A receives packet, initiates handshake.
        p.recv_at_a(t.at(126));
        p.assert_received_at_a([packet(2)]);
        p.assert_a_to_b([HandshakeInitiation]);
        // B receives handshake init, sends response.
        p.recv_at_b(t.at(127));
        assert_no_packets(&p.received_at_b);
        p.assert_b_to_a([HandshakeResponse]);
        // A receives response, sends confirmation
        p.recv_at_a(t.at(128));
        assert_no_packets(&p.received_at_a);
        p.assert_a_to_b([TransportData]);
        // B receives confirmation, finalizes rotation.
        p.recv_at_b(t.at(129));
        assert_no_packets(&p.received_at_b);
    }
}
