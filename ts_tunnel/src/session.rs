use core::fmt::{Debug, Formatter};
use std::{
    cmp::min,
    collections::{VecDeque, vec_deque},
    sync::Mutex,
    time::{Duration, Instant},
};

use aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use ts_packet::PacketMut;
use ts_time::TimeRange;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned,
    little_endian::{U32, U64},
};

use crate::{
    handshake::SessionPair,
    ids::IdMap,
    messages::{SessionId, TransportDataHeader},
    replay::ReplayWindow,
};

type SessionKey = chacha20poly1305::Key;

/// A generator of monotonically increasing 64-bit nonces.
#[derive(Default)]
struct NonceGenerator {
    nonce: Mutex<u64>,
}

impl NonceGenerator {
    /// Reserve a batch of consecutive nonces.
    ///
    /// The reserved range is fully consumed even if the returned NonceIter isn't.
    fn batch(&self, num: usize) -> NonceIter {
        let mut nonce = self.nonce.lock().unwrap();
        let end = match nonce.checked_add(num as u64) {
            Some(end) => end,
            // NonceGenerator is used to produce nonces for a wireguard session.
            // A single wireguard session lives for 120s before being replaced.
            // To exhaust a u64 in that time, assuming 1500b packets, you would
            // have to be sending 27.6 zettabytes every two minutes, or 230
            // exabytes/sec.
            //
            // If you're still running this code on a computer capable of that
            // kind of data rate: hello from the past! Enjoy your panic.
            None => panic!("nonce exhausted"),
        };
        let ret = NonceIter { cur: *nonce, end };
        *nonce = end;
        ret
    }
}
struct NonceIter {
    cur: u64,
    end: u64,
}

impl Iterator for NonceIter {
    type Item = Nonce;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur == self.end {
            None
        } else {
            let ret = self.cur;
            self.cur += 1;
            Some(Nonce::from(ret))
        }
    }
}

/// A cryptographic nonce for use with ChaCha20Poly1305.
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
struct Nonce {
    _zero: U32,
    counter: U64,
}

impl From<U64> for Nonce {
    fn from(v: U64) -> Self {
        Nonce {
            counter: v,
            _zero: Default::default(),
        }
    }
}

impl From<u64> for Nonce {
    fn from(v: u64) -> Self {
        Self::from(U64::from(v))
    }
}

impl AsRef<chacha20poly1305::Nonce> for Nonce {
    fn as_ref(&self) -> &chacha20poly1305::Nonce {
        let array: &[u8] = self.as_bytes();
        array.into()
    }
}

/// How long a session lasts before becoming eligible for key rotation.
///
/// Endpoints start a new handshake to rotate onto fresh session keys once a session
/// has been alive for this long, if it's still exchanging traffic. The session can
/// continue to be used while the rotation handshake proceeds, up to [`SESSION_LIFETIME`].
pub const SESSION_FRESH_LIFETIME: Duration = Duration::from_secs(120);

/// How long a session can be used before being discarded.
///
/// Endpoints must not continue using a session older than this. If there is still traffic
/// being exchanged, a key rotation handshake should have started at the halfway point
/// (defined by [`SESSION_FRESH_LIFETIME`]) to switch to a new session. If that handshake
/// fails to establish a new session in time, or traffic is no longer being exchanged,
/// the previously established session is forcibly discarded after this much time to preserve
/// forward secrecy.
pub const SESSION_LIFETIME: Duration = Duration::from_secs(240);

/// Grace time for cleaning up a session that has exceeded [`SESSION_LIFETIME`].
///
/// Once a session has expired, we need to delete its key material to ensure forward secrecy
/// of the data exchanged in that session. To allow for wakeup coalescing, we allow an expired
/// session's state to persist for short additional time before requiring that it be deleted.
pub const SESSION_CLEANUP_GRACE: Duration = Duration::from_secs(5);

/// Established session that can only send.
pub struct TransmitSession {
    cipher: ChaCha20Poly1305,
    nonce: NonceGenerator,
    id: SessionId,
    created: Instant,
}

impl TransmitSession {
    pub fn new(key: SessionKey, id: SessionId, now: Instant) -> Self {
        TransmitSession {
            cipher: ChaCha20Poly1305::new(&key),
            nonce: Default::default(),
            id,
            created: now,
        }
    }

    /// Encrypt a batch of packets.
    pub fn encrypt<'a, Into, Iter>(&self, packets: Into)
    where
        Iter: ExactSizeIterator<Item = &'a mut PacketMut>,
        Into: IntoIterator<Item = &'a mut PacketMut, IntoIter = Iter>,
    {
        let packets = packets.into_iter();
        let nonce = self.nonce.batch(packets.len());
        for (packet, nonce) in packets.zip(nonce) {
            // Session encryption only fails if the provided packet can't grow, which ours can.
            self.cipher
                .encrypt_in_place(nonce.as_ref(), &[], packet)
                .unwrap();
            let header = TransportDataHeader {
                receiver_id: self.id,
                nonce: nonce.counter,
                ..Default::default()
            };
            packet.grow_front(size_of::<TransportDataHeader>());
            // Write only fails if the packet is too small, and we just extended it to have
            // enough space.
            header.write_to_prefix(packet.as_mut()).unwrap();
        }
    }

    pub fn stale(&self, now: Instant) -> bool {
        now.duration_since(self.created) > SESSION_FRESH_LIFETIME
    }

    pub fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.created) > SESSION_LIFETIME
    }
}

/// Established session that can only receive.
pub struct ReceiveSession {
    cipher: ChaCha20Poly1305,
    id: SessionId,
    expiry: Instant,
    window: ReplayWindow,
}

impl Debug for ReceiveSession {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiveSession")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl ReceiveSession {
    pub fn new(key: SessionKey, id: SessionId, now: Instant) -> Self {
        ReceiveSession {
            cipher: ChaCha20Poly1305::new(&key),
            id,
            expiry: now + SESSION_LIFETIME,
            window: ReplayWindow::default(),
        }
    }

    /// Decrypt wireguard transport data messages in place.
    ///
    /// Returns the packets which successfully decrypted.
    pub fn decrypt(&mut self, mut packets: Vec<PacketMut>) -> Vec<PacketMut> {
        packets.retain_mut(|packet| self.decrypt_one(packet));
        packets
    }

    /// Decrypt a wireguard transport data message in place.
    #[tracing::instrument(skip_all, fields(session_id = ?self.id))]
    #[must_use]
    fn decrypt_one(&mut self, pkt: &mut PacketMut) -> bool {
        let Ok((header, _)) = TransportDataHeader::try_ref_from_prefix(pkt.as_ref()) else {
            tracing::warn!("decode as transport packet failed");
            return false;
        };

        let _guard = tracing::trace_span!("header_parsed", ?header).entered();

        if header.receiver_id != self.id {
            // Technically an unnecessary check, because a bespoke session is created for each
            // session ID, with different AEAD keys. So, if the caller mistakenly hands the wrong
            // packet to a session, it'll always fail to decrypt below. But, comparing one u32
            // is cheaper than getting partway through AEAD decryption before finding that the
            // authenticator is wrong, so might as well take the shortcut.
            //
            // Passing the wrong packet to a session is also a programmer error, so scream a bit
            // more loudly in debug builds.
            tracing::error!(message_session_id = ?header.receiver_id, "wrong receiver id");

            debug_assert!(
                false,
                "decrypt_in_place given packet with wrong receiver ID"
            );

            return false;
        }

        let counter = header.nonce.into();
        if !self.window.check(counter) {
            tracing::trace!("reject old/replayed packet");
            return false;
        }

        let nonce = Nonce::from(header.nonce);
        pkt.truncate_front(size_of::<TransportDataHeader>());

        match self.cipher.decrypt_in_place(nonce.as_ref(), &[], pkt) {
            Ok(_) => {
                self.window.set(counter);
                true
            }
            Err(e) => {
                tracing::error!(err = %e, "decryption failed");
                false
            }
        }
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn expired(&self, now: Instant) -> bool {
        now > self.expiry
    }
}

const MAX_QUEUED_PER_PEER: usize = 32;

/// A bounded packet queue that drops oldest packets when full.
#[derive(Default)]
pub struct Queue(VecDeque<PacketMut>);

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

/// A bidirectional established session.
pub struct ActiveSession {
    recv: Box<ReceiveSession>,
    send: Box<TransmitSession>,
    recv_prev: Option<Box<ReceiveSession>>,
}

impl From<SessionPair> for ActiveSession {
    fn from(pair: SessionPair) -> Self {
        Self {
            recv: Box::new(pair.recv),
            send: Box::new(pair.send),
            recv_prev: None,
        }
    }
}

impl ActiveSession {
    /// Start using a new keypair for communication.
    ///
    /// The prior receive session is rotated into the previous slot, and will continue to accept
    /// packets until the next rotation (or the hard session expiry deadline).
    ///
    /// If a receive session was already in the previous slot, destroys it and returns its session
    /// ID for further cleanup.
    fn rotate(&mut self, next: SessionPair, ids: &mut IdMap) {
        if let Some(prev) = self.recv_prev.as_ref() {
            ids.remove_session(prev.id());
        }
        let send = Box::new(next.send);
        let recv = Box::new(next.recv);
        if self.recv.expired(Instant::now()) {
            ids.remove_session(self.recv.id());
            self.recv_prev = None;
        } else {
            self.recv_prev = Some(std::mem::replace(&mut self.recv, recv));
        }
        self.send = send;
    }

    fn cleanup_ids(&mut self, ids: &mut IdMap) {
        ids.remove_session(self.recv.id());
        if let Some(prev) = self.recv_prev.as_ref() {
            ids.remove_session(prev.id());
        }
    }

    fn soonest_expiry(&self) -> Instant {
        if let Some(prev) = self.recv_prev.as_ref() {
            prev.expiry
        } else {
            self.recv.expiry
        }
    }
}

/// A communication session to a peer.
pub enum Session {
    /// No session established yet.
    ///
    /// This session cannot receive packets. Sent packets are queued if possible, and will be
    /// transmitted if the session becomes active in the future.
    None(Queue),
    /// Active session capable of bidirectional communication.
    Active(ActiveSession),
}

impl Default for Session {
    fn default() -> Self {
        Self::None(Queue::default())
    }
}

impl Session {
    fn take(&mut self) -> Session {
        std::mem::replace(self, Self::None(Queue::default()))
    }

    /// Return a reference to the active session, if any.
    ///
    /// Incidentally performs session expiry checking and cleanup. Callers can assume that
    /// if they get a &mut ActiveSession, it contains only valid non-expired session state.
    fn as_active(&mut self, ids: &mut IdMap) -> Option<&mut ActiveSession> {
        match self {
            Self::None(_) => None,
            Self::Active(session) => {
                if session.recv.expired(Instant::now()) {
                    session.cleanup_ids(ids);
                    *self = Self::default();
                    None
                } else {
                    if let Some(prev) = session.recv_prev.as_ref()
                        && prev.expired(Instant::now())
                    {
                        ids.remove_session(prev.id());
                        session.recv_prev = None;
                    }
                    // Re-borrow session, because rustc can't see that the assignment to *self
                    // above is mutually exclusive with continued use of the borrow.
                    let Self::Active(session) = self else {
                        unreachable!();
                    };
                    Some(session)
                }
            }
        }
    }

    /// Activate the session with the given keys.
    ///
    /// If any packets were queued waiting for an active session, they are encrypted and
    /// returned.
    pub fn activate(
        &mut self,
        next: SessionPair,
        ids: &mut IdMap,
        need_keepalive: bool,
    ) -> Vec<PacketMut> {
        tracing::trace!(recv_id = ?next.recv.id(), "activating new session");

        let (active, mut packets) = match self.take() {
            Self::None(queue) => (next.into(), queue.into()),
            Self::Active(mut session) => {
                session.rotate(next, ids);
                (session, vec![])
            }
        };

        if need_keepalive && packets.is_empty() {
            packets.push(PacketMut::new(0));
        }
        active.send.encrypt(&mut packets);
        *self = Self::Active(active);
        packets
    }

    /// Discard all state for this session.
    pub fn deactivate(&mut self, ids: &mut IdMap) {
        if let Self::Active(mut session) = self.take() {
            session.cleanup_ids(ids);
        }
        *self = Self::default();
    }

    /// Encrypt a keepalive packet for the peer.
    ///
    /// Returns None if the session is inactive (and thus no keepalive is necessary).
    pub fn send_keepalive(&mut self, ids: &mut IdMap) -> Option<PacketMut> {
        let session = self.as_active(ids)?;
        let mut packet = vec![PacketMut::new(0)];
        session.send.encrypt(&mut packet);
        packet.pop()
    }

    /// Send packets to the peer.
    ///
    /// If the session is inactive, packets are queued for future transmission.
    ///
    /// Returns None to indicate that packets were queued, indicating the caller may need to
    /// initiate a handshake.
    pub fn send(&mut self, mut packets: Vec<PacketMut>, ids: &mut IdMap) -> Option<Vec<PacketMut>> {
        match self {
            Self::None(queue) => {
                queue.append(packets);
                None
            }
            Self::Active(session) => {
                if session.send.expired(Instant::now()) {
                    session.cleanup_ids(ids);
                    *self = Self::None(Queue::new_with(packets));
                    return None;
                }
                session.send.encrypt(&mut packets);
                Some(packets)
            }
        }
    }

    /// Get the ReceiveSession for the given receiving ID, if any.
    pub fn get_recv(&mut self, id: SessionId, ids: &mut IdMap) -> Option<&mut ReceiveSession> {
        let session = self.as_active(ids)?;
        if session.recv.id() == id {
            Some(session.recv.as_mut())
        } else if let Some(recv_prev) = session.recv_prev.as_mut()
            && recv_prev.id() == id
        {
            Some(recv_prev)
        } else {
            None
        }
    }

    /// Reports whether the session is in need of a fresh handshake.
    pub fn needs_handshake(&self) -> bool {
        match self {
            Self::None(_) => true,
            Self::Active(session) => session.send.stale(Instant::now()),
        }
    }

    /// Clean up expired session state, if any.
    pub fn cleanup_expired(&mut self, ids: &mut IdMap) {
        self.as_active(ids);
    }

    /// Returns the soonest time at which some session state may be expired, necessitating
    /// a call to [`Session::cleanup_expired`]
    pub fn expiry(&mut self, ids: &mut IdMap) -> Option<TimeRange> {
        let soonest = self.as_active(ids)?.soonest_expiry();
        Some(TimeRange::new(soonest, soonest + SESSION_CLEANUP_GRACE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::Message;

    #[test]
    fn test_session() {
        let k: [u8; 32] = rand::random();
        let session = SessionId::random();
        let now = Instant::now();
        let send = TransmitSession::new(k.into(), session, now);
        let mut recv = ReceiveSession::new(k.into(), session, now);

        const CLEARTEXT: &[u8] = b"foobar";
        let mut pkt = [PacketMut::from(CLEARTEXT)];

        send.encrypt(&mut pkt);
        assert_eq!(pkt[0].len(), 38);
        let Ok(Message::TransportDataHeader(msg)) = Message::try_from(pkt[0].as_ref()) else {
            panic!("packet is not a valid TransportData message");
        };
        assert_eq!(msg.receiver_id, session);
        assert_eq!(u64::from(msg.nonce), 0);

        assert!(recv.decrypt_one(&mut pkt[0]));
        assert_eq!(pkt[0].as_ref(), CLEARTEXT);

        send.encrypt(&mut pkt);
        assert_eq!(pkt[0].len(), 38);
        let Ok(Message::TransportDataHeader(msg)) = Message::try_from(pkt[0].as_ref()) else {
            panic!("packet is not a valid TransportData message");
        };
        assert_eq!(msg.receiver_id, session);
        assert_eq!(u64::from(msg.nonce), 1);

        assert!(recv.decrypt_one(&mut pkt[0]));
        assert_eq!(pkt[0].as_ref(), CLEARTEXT);
    }

    #[test]
    fn session_timers() {
        let k: [u8; 32] = rand::random();
        let session = SessionId::random();
        let now = Instant::now();
        let send = TransmitSession::new(k.into(), session, now);
        let recv = ReceiveSession::new(k.into(), session, now);
        let epsilon = Duration::from_secs(1);

        assert!(!send.stale(now));
        assert!(!send.stale(now + SESSION_FRESH_LIFETIME - epsilon));
        assert!(send.stale(now + SESSION_FRESH_LIFETIME + epsilon));
        assert!(send.stale(now + SESSION_LIFETIME + epsilon));

        assert!(!send.expired(now));
        assert!(!send.expired(now + SESSION_FRESH_LIFETIME - epsilon));
        assert!(!send.expired(now + SESSION_FRESH_LIFETIME + epsilon));
        assert!(send.expired(now + SESSION_LIFETIME + epsilon));

        assert!(!recv.expired(now));
        assert!(!recv.expired(now + SESSION_FRESH_LIFETIME - epsilon));
        assert!(!recv.expired(now + SESSION_FRESH_LIFETIME + epsilon));
        assert!(recv.expired(now + SESSION_LIFETIME + epsilon));
    }
}
