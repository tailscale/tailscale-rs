use core::time::Duration;
use std::{
    cmp::min,
    collections::{HashMap, VecDeque, vec_deque},
    time::Instant,
};

use itertools::Itertools;
use ts_keys::{NodeKeyPair, NodePublicKey};
use ts_packet::old::PacketMut;
use ts_time::{Handle, Scheduler, TimeRange};
use zerocopy::IntoBytes;

use crate::{
    config::{PeerConfig, PeerId},
    handshake::{HandshakeState, ReceivedHandshake, SessionPair, initiate_handshake},
    macs::{MACReceiver, MACSender},
    messages::{CookieReply, HandshakeResponse, Message, SessionId},
    session::{ReceiveSession, TransmitSession},
    time::{TAI64N, TAI64NClock},
};

const MAX_QUEUED_PER_PEER: usize = 32;

/// If an endpoint hasn't sent any packets to a peer for `KEEPALIVE_TIMEOUT` after receiving a
/// packet from that peer, it must send an empty keepalive message so that the peer can distinguish
/// lack of activity from loss of session.
/// See: WireGuard spec, section 6.5
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// A bounded packet queue that drops oldest packets when full.
#[derive(Default)]
struct Queue(VecDeque<PacketMut>);

impl Queue {
    /// Shorthand for Queue::default then Queue::append.
    fn new_with(packets: Vec<PacketMut>) -> Self {
        let mut queue = Self::default();
        queue.append(packets);
        queue
    }

    fn append(&mut self, packets: Vec<PacketMut>) {
        let new_packets = min(packets.len(), MAX_QUEUED_PER_PEER);
        let drop_incoming = packets.len() - new_packets;
        let keep_queued = MAX_QUEUED_PER_PEER - new_packets;
        let drop_queued = self.0.len().saturating_sub(keep_queued);
        self.0.drain(..drop_queued);
        packets
            .into_iter()
            .skip(drop_incoming)
            .for_each(|packet| self.0.push_back(packet));
    }
}

impl From<Queue> for Vec<PacketMut> {
    fn from(queue: Queue) -> Self {
        queue.0.into()
    }
}

impl IntoIterator for Queue {
    type Item = PacketMut;
    type IntoIter = vec_deque::IntoIter<PacketMut>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// State of a peer's session.
enum SessionState {
    /// No active session, packets may be queued for future transmission.
    None(Queue),
    /// Active session available.
    Active {
        recv: ReceiveSession,
        recv_prev: Option<ReceiveSession>,
        send: TransmitSession,
    },
}

impl SessionState {
    /// Take the session state, leaving SessionState::None in its place.
    fn take(&mut self) -> SessionState {
        std::mem::replace(self, SessionState::None(Queue::default()))
    }

    /// Activate the session using the provided send/receive sessions.
    ///
    /// Existing sessions are rotated appropriately. Returns encrypted packets to send to the
    /// peer, if any were queued.
    fn activate(&mut self, endpoint: &mut EndpointState, next: SessionPair) -> Vec<PacketMut> {
        tracing::trace!(recv_id = ?next.recv.id(), "activating new session");

        match self.take() {
            SessionState::None(queue) => {
                let mut ret = queue.into();
                next.send.encrypt(&mut ret);
                *self = SessionState::Active {
                    send: next.send,
                    recv: next.recv,
                    recv_prev: None,
                };
                ret
            }
            SessionState::Active {
                recv,
                mut recv_prev,
                ..
            } => {
                recv_prev
                    .take()
                    .inspect(|recv_prev| endpoint.ids.remove_session(recv_prev.id()));
                *self = SessionState::Active {
                    send: next.send,
                    recv: next.recv,
                    recv_prev: Some(recv),
                };
                vec![]
            }
        }
    }

    /// Deactivate the session, releasing any active session IDs.
    fn deactivate(&mut self, endpoint: &mut EndpointState) {
        if let SessionState::Active {
            recv,
            mut recv_prev,
            ..
        } = self.take()
        {
            endpoint.ids.remove_session(recv.id());
            recv_prev
                .as_mut()
                .inspect(|recv_prev| endpoint.ids.remove_session(recv_prev.id()));
        }
    }

    /// Encrypt a keepalive packet for transmission.
    ///
    /// Returns None if the session cannot currently transmit.
    fn encrypt_keepalive(&mut self) -> Option<PacketMut> {
        if let SessionState::Active { send, .. } = self
            && !send.expired(Instant::now())
        {
            let mut packet = vec![PacketMut::new(0)];
            send.encrypt(&mut packet);
            packet.pop()
        } else {
            None
        }
    }

    /// Encrypt packets for transmission.
    ///
    /// Returns the encrypted packets if a session is available, otherwise queues the packets and
    /// returns None to signal that the caller needs to establish a session.
    fn encrypt_or_queue(&mut self, mut packets: Vec<PacketMut>) -> Option<Vec<PacketMut>> {
        match self {
            SessionState::None(queue) => {
                queue.append(packets);
                None
            }
            SessionState::Active { send, .. } => {
                if send.expired(Instant::now()) {
                    // Note, this also deletes both receive sessions. This is okay: due to the
                    // semantics of session rotation, if the transmit session has expired, all
                    // receive sessions have also expired.
                    *self = SessionState::None(Queue::new_with(packets));
                    return None;
                }
                send.encrypt(&mut packets);
                Some(packets)
            }
        }
    }

    /// Get the receive session matching the given ID, if any.
    fn get_recv(&self, id: SessionId) -> Option<&ReceiveSession> {
        match self {
            SessionState::None(_) => None,
            SessionState::Active {
                recv, recv_prev, ..
            } => {
                if recv.id() == id && !recv.expired(Instant::now()) {
                    Some(recv)
                } else if let Some(recv_prev) = recv_prev.as_ref()
                    && recv_prev.id() == id
                    && !recv.expired(Instant::now())
                {
                    Some(recv_prev)
                } else {
                    None
                }
            }
        }
    }

    /// Report whether the transmit side of the session is stale and in need of key rotation.
    ///
    /// Returns true if no session exists.
    fn needs_rotation(&self) -> bool {
        match self {
            SessionState::None(_) => true,
            SessionState::Active { send, .. } => send.stale(Instant::now()),
        }
    }
}

/// Tracks and allocates session IDs for peer sessions.
#[derive(Default)]
struct IdMap {
    sessions: HashMap<SessionId, PeerId>,
    // TODO: track recently abandoned session IDs, avoid reusing them for
    // one or two session lifetimes to avoid confusion with reordered packets.
    node_keys: HashMap<NodePublicKey, PeerId>,
    next_peer_id: u32,
}

impl IdMap {
    /// Return the peer handle for a node public key, if any.
    fn get_by_nodekey(&self, key: &NodePublicKey) -> Option<PeerId> {
        self.node_keys.get(key).copied()
    }

    /// Return the peer handle for a session, if any.
    fn get_by_session_id(&self, key: &SessionId) -> Option<&PeerId> {
        self.sessions.get(key)
    }

    /// Allocate a new peer handle for communicating with the given peer pubkey.
    ///
    /// Returns None if a peer already exists for the key.
    fn allocate_peer(&mut self, key: &NodePublicKey) -> Option<PeerId> {
        if self.node_keys.contains_key(key) {
            return None;
        }
        self.next_peer_id += 1;
        let ret = PeerId(self.next_peer_id);
        self.node_keys.insert(*key, ret);
        Some(ret)
    }

    /// Allocate a new session ID for communication with the given peer.
    ///
    /// Note that due to key rotation, a peer can have multiple session IDs in use at once.
    fn allocate_session(&mut self, peer: PeerId) -> SessionId {
        loop {
            let ret = SessionId::random();
            if let std::collections::hash_map::Entry::Vacant(e) = self.sessions.entry(ret) {
                e.insert(peer);
                return ret;
            }
        }
    }

    /// Abandon the given session ID.
    ///
    /// Panics if the session ID isn't currently in use.
    fn remove_session(&mut self, id: SessionId) {
        self.sessions
            .remove(&id)
            .expect("IDMap::delete should only be called for allocated IDs");
    }

    fn remove_handshake_session(&mut self, handshake: &HandshakeState) {
        if let Some(id) = handshake.session_id() {
            self.remove_session(id);
        }
    }

    /// Delete the peer handle for the given key.
    ///
    /// Panics if there is no peer currently using that key.
    fn remove_peer(&mut self, key: &NodePublicKey) {
        self.node_keys
            .remove(key)
            .expect("IDMap::remove_peer should only be called for allocated peers");
    }
}

struct Peer {
    id: PeerId,
    config: PeerConfig,
    session: SessionState,
    handshake: HandshakeState,
    last_seen_timestamp: Option<TAI64N>,
    cookie_sender: MACSender,
    keepalive: Option<Handle<Event>>,
    send_another_keepalive: bool,
}

impl Peer {
    fn new(id: PeerId, config: PeerConfig) -> Self {
        let macs = MACSender::new(&config.key);
        Self {
            id,
            config,
            session: SessionState::None(Queue::default()),
            handshake: HandshakeState::None,
            last_seen_timestamp: None,
            cookie_sender: macs,
            keepalive: None,
            send_another_keepalive: false,
        }
    }

    fn schedule_keepalive(&mut self, scheduler: &mut Scheduler<Event>) {
        if self.keepalive.is_some() {
            self.send_another_keepalive = true;
            return;
        }
        let tr = TimeRange::new_around(Instant::now() + KEEPALIVE_TIMEOUT, Duration::from_secs(1));
        self.keepalive = Some(scheduler.add(tr, Event::MaybeSendKeepalive(self.id)));
    }

    // TODO: consider replacing outparam with plain SendResult that supports merging.
    fn send(
        &mut self,
        endpoint: &mut EndpointState,
        packets: Vec<PacketMut>,
        out: &mut SendResult,
    ) {
        if let Some(mut packets) = self.session.encrypt_or_queue(packets) {
            tracing::trace!("enqueueing packets to peer");
            out.queue_to_peer(self.id).append(&mut packets);
            // Fall through to check if the session is in need of rotation.
        }

        if self.handshake.is_active() {
            tracing::trace!("handshake is already in-flight, bail");
            return;
        }

        if !self.session.needs_rotation() {
            tracing::trace!("session does not need rotation");
            return;
        }

        self.start_handshake(endpoint, out);
    }

    #[tracing::instrument(skip_all, fields(?session_id, n_packets = packets.len()))]
    fn recv(
        &mut self,
        endpoint: &mut EndpointState,
        session_id: SessionId,
        mut packets: Vec<PacketMut>,
        out: &mut RecvResult,
    ) {
        let pre_len = packets.len();

        packets.retain_mut(|packet| match Message::try_from(packet.as_ref()) {
            Err(()) => {
                tracing::trace!("dropping invalid packet");
                false
            }
            Ok(Message::TransportDataHeader(_)) => true,
            Ok(Message::HandshakeResponse(resp)) => {
                self.recv_handshake_response(endpoint, resp, out);
                false
            }
            Ok(Message::CookieReply(resp)) => {
                self.recv_cookie_reply(resp);
                false
            }
            Ok(Message::HandshakeInitiation(_)) => {
                debug_assert!(
                    false,
                    "handshake initiations should have been filtered out prior to calling recv"
                );
                tracing::warn!("unexpected handshake init in recv");
                false
            }
        });

        let post_len = packets.len();
        if post_len != pre_len {
            tracing::trace!(n_dropped = pre_len - post_len, "dropped packets");
        }

        self.recv_transport_data(endpoint, session_id, packets, out);
    }

    fn recv_cookie_reply(&mut self, packet: &CookieReply) {
        let HandshakeState::Initiated(_, _, handshake_mac1) = &mut self.handshake else {
            tracing::trace!("dropping cookie reply received outside of handshake");
            return;
        };
        self.cookie_sender.receive_cookie(packet, handshake_mac1);
    }

    fn recv_handshake_response(
        &mut self,
        endpoint: &mut EndpointState,
        packet: &HandshakeResponse,
        out: &mut RecvResult,
    ) {
        let Some(session) = self.handshake.finish(
            packet,
            &self.config.psk,
            &endpoint.my_cookie,
            Instant::now(),
        ) else {
            tracing::error!("handshake failed to complete");
            return;
        };

        let mut packets = self.session.activate(endpoint, session);
        if packets.is_empty() {
            // Upon completing a handshake, the initiator must send at least one packet to confirm
            // the session. Usually that can be a queued packet, but if we happen to complete a
            // handshake with no queued packets available, we have to send an empty packet explicitly.
            packets.push(PacketMut::new(0));
            // Session was just activated, therefore it can encrypt.
            packets = self.session.encrypt_or_queue(packets).unwrap();
        }
        out.queue_to_peer(self.id).append(&mut packets);
    }

    fn recv_transport_data(
        &mut self,
        endpoint: &mut EndpointState,
        session_id: SessionId,
        mut packets: Vec<PacketMut>,
        out: &mut RecvResult,
    ) {
        if let Some(session) = self.session.get_recv(session_id) {
            packets = session.decrypt(packets);
            if !packets.is_empty() {
                out.queue_to_local(self.id).append(&mut packets);
                self.schedule_keepalive(&mut endpoint.scheduler);
            }
            return;
        }

        let Some((session, mut packets)) = self.handshake.confirm(session_id, packets) else {
            // TODO: log
            return;
        };

        out.queue_to_local(self.id).append(&mut packets);
        self.schedule_keepalive(&mut endpoint.scheduler);

        let mut packets_for_peer = self.session.activate(endpoint, session);
        if !packets_for_peer.is_empty() {
            out.queue_to_peer(self.id).append(&mut packets_for_peer);
        }
    }

    fn respond_to_handshake(
        &mut self,
        endpoint: &mut EndpointState,
        handshake: ReceivedHandshake,
        out: &mut RecvResult,
    ) {
        if let Some(timestamp) = self.last_seen_timestamp
            && handshake.timestamp < timestamp
        {
            // Replayed handshake initiation
            // TODO: because we buffer the raw initiation packet on the sender side, we need to accept
            // initiations with an equal timestamp to the last one received. Check against reference
            // implementations and see if we should instead regenerate a fresh handshake with new timestamp
            // on retransmit.
            tracing::warn!("handshake replay detected, bailing out");
            return;
        }
        self.last_seen_timestamp = Some(handshake.timestamp);

        let session_id = endpoint.ids.allocate_session(self.id);

        let packet = self.handshake.respond(
            session_id,
            handshake,
            &self.config.psk,
            &self.cookie_sender,
            Instant::now(),
        );
        out.queue_to_peer(self.id).push(packet);
    }

    fn handshake_timeout(&mut self, endpoint: &mut EndpointState, out: &mut EventResult) {
        if !self.handshake.is_active() {
            // Handshake completed prior to timeout firing.
            return;
        }

        endpoint.ids.remove_handshake_session(&self.handshake);
        self.handshake = HandshakeState::None;

        self.start_handshake(endpoint, out);
    }

    fn send_keepalive(&mut self, scheduler: &mut Scheduler<Event>, out: &mut EventResult) {
        let Some(packet) = self.session.encrypt_keepalive() else {
            tracing::trace!("send keepalive: session expired, skipping");
            return;
        };
        out.queue_to_peer(self.id).push(packet);

        self.keepalive = None;

        if self.send_another_keepalive {
            self.schedule_keepalive(scheduler);
            self.send_another_keepalive = false;
        }
    }

    fn shutdown(&mut self, endpoint: &mut EndpointState) {
        self.session.deactivate(endpoint);

        endpoint.ids.remove_handshake_session(&self.handshake);
        self.handshake = HandshakeState::None;
    }

    /// (Soft) precondition: `self.handshake == HandshakeState::None` (previous handshake is lost, but
    /// that shouldn't cause anything terrible to happen).
    fn start_handshake(&mut self, endpoint: &mut EndpointState, out: &mut impl QueueToPeer) {
        // TODO most of this logic might be better in the `handshake` module.
        let session_id = endpoint.ids.allocate_session(self.id);
        let (handshake, packet) = initiate_handshake(
            endpoint.my_key.private,
            self.config.key,
            session_id,
            endpoint.timestamps.now(),
        );

        let mut packet = PacketMut::from(packet.as_bytes());
        let mac = self.cookie_sender.write_macs(packet.as_mut());

        tracing::debug!(peer_id = ?self.id, ?session_id, "enqueue handshake start");

        out.queue_to_peer(self.id).push(packet);
        let tr = TimeRange::new_around(
            Instant::now() + HANDSHAKE_TIMEOUT,
            Duration::from_millis(500),
        );

        let timeout = endpoint.scheduler.add(tr, Event::HandshakeTimeout(self.id));
        self.handshake = HandshakeState::Initiated(handshake, timeout, mac);
    }
}

/// A WireGuard endpoint capable of communicating with multiple remote peers.
pub struct Endpoint {
    state: EndpointState,
    peers: HashMap<PeerId, Peer>,
}

struct EndpointState {
    my_key: NodeKeyPair,

    my_cookie: MACReceiver,
    ids: IdMap,
    timestamps: TAI64NClock,
    scheduler: Scheduler<Event>,
}

impl Endpoint {
    /// Construct a new endpoint with the given keypair.
    pub fn new(my_key: NodeKeyPair) -> Self {
        Self {
            state: EndpointState {
                my_key,
                my_cookie: MACReceiver::new(&my_key.public),
                ids: Default::default(),
                timestamps: Default::default(),
                scheduler: Default::default(),
            },
            peers: HashMap::new(),
        }
    }

    /// Add a new peer.
    ///
    /// Returns a handle to the newly configured peer, or None if a peer is already configured
    /// with the given node key.
    pub fn add_peer(&mut self, cfg: PeerConfig) -> Option<PeerId> {
        let ret = self.state.ids.allocate_peer(&cfg.key)?;
        self.peers.insert(ret, Peer::new(ret, cfg));
        Some(ret)
    }

    /// Remove the given peer.
    ///
    /// Returns whether the peer in question existed.
    pub fn remove_peer(&mut self, peer: PeerId) -> bool {
        match self.peers.remove(&peer) {
            None => false,
            Some(mut peer) => {
                peer.shutdown(&mut self.state);
                self.state.ids.remove_peer(&peer.config.key);
                true
            }
        }
    }

    /// Send packets to peers.
    pub fn send(
        &mut self,
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

            peer.send(&mut self.state, packets, &mut ret);
        }
        ret
    }

    /// Receive packets from peers.
    pub fn recv(&mut self, packets: impl IntoIterator<Item = PacketMut>) -> RecvResult {
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
            self.process_one_handshake(packet, &mut ret);
        }

        tracing::trace!(n = packets.len(), "processing packets");

        for (session_id, packets) in packets {
            let session_id = session_id.into();

            let Some(peer_id) = self.state.ids.get_by_session_id(&session_id) else {
                tracing::warn!(?session_id, "session not found");
                continue;
            };
            let Some(peer) = self.peers.get_mut(peer_id) else {
                tracing::warn!(?peer_id, "no peer found");
                continue;
            };

            peer.recv(&mut self.state, session_id, packets, &mut ret);
        }

        ret
    }

    fn process_one_handshake(&mut self, packet: PacketMut, out: &mut RecvResult) {
        let Ok(Message::HandshakeInitiation(init)) = Message::try_from(packet.as_ref()) else {
            tracing::error!("message parsing failed");
            return;
        };
        let Some(handshake) =
            ReceivedHandshake::new(init, &self.state.my_key, &self.state.my_cookie)
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

        peer.respond_to_handshake(&mut self.state, handshake, out)
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
                    peer.handshake_timeout(&mut self.state, &mut out);
                }
                Event::MaybeSendKeepalive(peer_id) => {
                    let Some(peer) = self.peers.get_mut(&peer_id) else {
                        continue;
                    };
                    peer.send_keepalive(&mut self.state.scheduler, &mut out);
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
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut>;
}

/// The outcome of attempting to send packets to peers.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct SendResult {
    /// Packets to be sent to remote peers.
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

impl QueueToPeer for SendResult {
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_peers.entry(peer).or_default()
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
    fn queue_to_local(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_local.entry(peer).or_default()
    }
}

impl QueueToPeer for RecvResult {
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_peers.entry(peer).or_default()
    }
}

/// The outcome of processing an Event.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct EventResult {
    /// Packets to be sent to remote peers.
    pub to_peers: HashMap<PeerId, Vec<PacketMut>>,
}

impl QueueToPeer for EventResult {
    fn queue_to_peer(&mut self, peer: PeerId) -> &mut Vec<PacketMut> {
        self.to_peers.entry(peer).or_default()
    }
}

/// An event that Endpoint needs to know about.
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Copy, Clone)]
pub enum Event {
    /// Didn't receive a response to a handshake initiation.
    HandshakeTimeout(PeerId),
    /// Send a keepalive packet, if there was no recent outgoing traffic.
    MaybeSendKeepalive(PeerId),
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PeerConfig;

    #[test]
    fn test_onepeer() {
        let (a_static, b_static) = (NodeKeyPair::new(), NodeKeyPair::new());
        let psk = rand::random();

        let (mut a_ep, mut b_ep) = (Endpoint::new(a_static), Endpoint::new(b_static));

        let a_peer = a_ep
            .add_peer(PeerConfig {
                key: b_static.public,
                psk,
            })
            .unwrap();

        let b_peer = b_ep
            .add_peer(PeerConfig {
                key: a_static.public,
                psk,
            })
            .unwrap();

        let a_to_b_packets = [
            PacketMut::from(vec![1, 2, 3, 4]),
            PacketMut::from(vec![5, 6, 7, 8]),
        ];

        // A sends to B. Results in a handshake initiation being transmitted, not the
        // requested packet (which gets buffered internally by the endpoint).
        let to_send = HashMap::from([(a_peer, Vec::from([a_to_b_packets[0].clone()]))]);
        let a_acts = a_ep.send(to_send);
        assert_eq!(
            a_acts.to_peers.len(),
            1,
            "communicating with unexpected number of peers"
        );
        let packets = a_acts
            .to_peers
            .get(&a_peer)
            .expect("no packets for A's peer");
        assert_eq!(packets.len(), 1, "unexpected number of packets for peer");

        // A sends another packet. No further activity, but pkt2 gets queued as well.
        let to_send = HashMap::from([(a_peer, Vec::from([a_to_b_packets[1].clone()]))]);
        let a_acts2 = a_ep.send(to_send);
        assert_eq!(a_acts2, SendResult::default());

        // B processes the handshake and responds. No packets delivered to B.
        let b_acts = b_ep.recv(packets.clone());
        assert_eq!(b_acts.to_local.len(), 0, "unexpected received message");
        assert_eq!(
            b_acts.to_peers.len(),
            1,
            "unexpected number of sent messages"
        );
        let packets = b_acts
            .to_peers
            .get(&b_peer)
            .expect("no packets for B's peer");
        assert_eq!(packets.len(), 1, "unexpected packet count for B's peer");

        // A processes the response, and sends the two queued packets.
        let a_acts3 = a_ep.recv(packets.clone());
        assert_eq!(a_acts3.to_local.len(), 0, "unexpected received message");
        assert_eq!(
            a_acts3.to_peers.len(),
            1,
            "unexpected number of sent messages"
        );
        let packets = a_acts3
            .to_peers
            .get(&a_peer)
            .expect("no packets for A's peer");
        assert_eq!(packets.len(), 2, "wrong number of packets for A's peer");

        // B receives transport messages.
        let b_acts = b_ep.recv(packets.clone());
        assert_eq!(b_acts.to_local.len(), 1, "didn't receive message");
        let packets = b_acts
            .to_local
            .get(&b_peer)
            .expect("no packets from B's peer");
        assert_eq!(packets, &a_to_b_packets, "wrong packets received from A",);
        assert_eq!(b_acts.to_peers.len(), 0, "unexpected sent message");

        // B sends transport message
        let b_to_a_packet = PacketMut::from(vec![9, 10, 11, 12]);
        let to_send = HashMap::from([(b_peer, vec![b_to_a_packet.clone()])]);
        let b_acts = b_ep.send(to_send);
        assert_eq!(
            b_acts.to_peers.len(),
            1,
            "unexpected number of sent messages"
        );
        let packets = b_acts
            .to_peers
            .get(&b_peer)
            .expect("no packets for B's peer");
        assert_eq!(packets.len(), 1, "unexpected packet count for B's peer");

        // A receives
        let a_acts = a_ep.recv(packets.clone());
        assert_eq!(a_acts.to_local.len(), 1, "didn't receive message");
        let packets = a_acts
            .to_local
            .get(&a_peer)
            .expect("no packets from A's peer");
        assert_eq!(
            packets,
            &[b_to_a_packet],
            "wrong packets received from A's peer"
        );
        assert_eq!(a_acts.to_peers.len(), 0, "unexpected sent message");
    }
}
