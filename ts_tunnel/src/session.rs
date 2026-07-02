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
        pkt.truncate_front(size_of_val(header));

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

    /// Return the session ID that will appear on received packets meant for this session.
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// Report whether the session is expired.
    pub fn expired(&self, now: Instant) -> bool {
        now > self.expiry
    }
}

/// Established session that can send and receive.
pub struct BidiSession {
    recv: ReceiveSession,

    send_id: SessionId,
    send_cipher: ChaCha20Poly1305,
    send_nonce: NonceGenerator,
}

pub struct BidiSessionKeys {
    pub send_key: SessionKey,
    pub send_id: SessionId,
    pub recv_key: SessionKey,
    pub recv_id: SessionId,
}

impl BidiSession {
    pub fn new(keys: BidiSessionKeys, now: Instant) -> Self {
        Self {
            recv: ReceiveSession::new(keys.recv_key, keys.recv_id, now),
            send_id: keys.send_id,
            send_cipher: ChaCha20Poly1305::new(&keys.send_key),
            send_nonce: Default::default(),
        }
    }

    /// Encrypt wireguard transport data messages in place.
    pub fn encrypt<'a, Into, Iter>(&self, packets: Into)
    where
        Iter: ExactSizeIterator<Item = &'a mut PacketMut>,
        Into: IntoIterator<Item = &'a mut PacketMut, IntoIter = Iter>,
    {
        let packets = packets.into_iter();
        let nonce = self.send_nonce.batch(packets.len());
        for (packet, nonce) in packets.zip(nonce) {
            // Session encryption only fails if the provided packet can't grow, which ours can.
            self.send_cipher
                .encrypt_in_place(nonce.as_ref(), &[], packet)
                .unwrap();
            let header = TransportDataHeader {
                receiver_id: self.send_id,
                nonce: nonce.counter,
                ..Default::default()
            };
            packet.grow_front(size_of_val(&header));
            // Write only fails if the packet is too small, and we just extended it to have
            // enough space.
            header.write_to_prefix(packet.as_mut()).unwrap();
        }
    }

    /// Decrypt wireguard transport data messages in place.
    ///
    /// Returns the packets which successfully decrypted.
    pub fn decrypt(&mut self, packets: Vec<PacketMut>) -> Vec<PacketMut> {
        self.recv.decrypt(packets)
    }

    /// Return the session ID that will appear on received packets meant for this session.
    pub fn recv_id(&self) -> SessionId {
        self.recv.id
    }

    /// Return the time at which the session expires.
    pub fn expiry(&self) -> Instant {
        self.recv.expiry
    }

    pub fn rotation_time(&self) -> Instant {
        self.recv.expiry - SESSION_LIFETIME + SESSION_FRESH_LIFETIME
    }

    /// Report whether the session is expired.
    pub fn expired(&self, now: Instant) -> bool {
        now > self.recv.expiry
    }

    pub fn stale(&self, now: Instant) -> bool {
        now > self.rotation_time()
    }
}

impl From<BidiSession> for ReceiveSession {
    fn from(session: BidiSession) -> Self {
        session.recv
    }
}

const MAX_QUEUED_PER_PEER: usize = 32;

/// A bounded packet queue that drops oldest packets when full.
#[derive(Default)]
pub struct Queue(VecDeque<PacketMut>);

impl Queue {
    fn append(&mut self, packets: Vec<PacketMut>) {
        let new_packets = min(packets.len(), MAX_QUEUED_PER_PEER);
        let drop_incoming = packets.len() - new_packets;
        let keep_queued = MAX_QUEUED_PER_PEER - new_packets;
        let drop_queued = self.0.len().saturating_sub(keep_queued);
        self.0.drain(..drop_queued);
        self.0.extend(packets.into_iter().skip(drop_incoming));
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
    cur: Box<BidiSession>,
    prev: Option<Box<ReceiveSession>>,
}

impl From<BidiSession> for ActiveSession {
    fn from(session: BidiSession) -> Self {
        Self {
            cur: Box::new(session),
            prev: None,
        }
    }
}

impl ActiveSession {
    /// Start using a new keypair for communication.
    ///
    /// The prior receive session is rotated into the previous slot, and will continue to accept
    /// packets until the next rotation (or the hard session expiry deadline).
    fn rotate(&mut self, next: BidiSession, ids: &mut IdMap, now: Instant) {
        if let Some(prev) = self.prev.as_ref() {
            ids.remove_session(prev.id());
        }
        let prev = std::mem::replace(self.cur.as_mut(), next);
        if prev.expired(now) {
            ids.remove_session(prev.recv_id());
        } else {
            self.prev = Some(Box::new(prev.into()));
        }
    }

    fn cleanup_ids(&mut self, ids: &mut IdMap) {
        ids.remove_session(self.cur.recv_id());
        if let Some(prev) = self.prev.as_ref() {
            ids.remove_session(prev.id());
        }
    }

    fn expired(&self, now: Instant) -> bool {
        self.cur.expired(now)
    }

    fn soonest_expiry(&self) -> Instant {
        if let Some(prev) = self.prev.as_ref() {
            prev.expiry
        } else {
            self.cur.expiry()
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
        std::mem::take(self)
    }

    /// Return a reference to the active session, if any.
    ///
    /// Calls [`Session::maybe_expire`], so callers can assume that the returned session
    /// consists only of unexpired state.
    fn as_active(&mut self, ids: &mut IdMap, now: Instant) -> Option<&mut ActiveSession> {
        self.cleanup_expired(ids, now);
        if let Self::Active(session) = self {
            Some(session)
        } else {
            None
        }
    }

    /// Activate the session with the given keys.
    ///
    /// If any packets were queued waiting for an active session, they are encrypted and
    /// returned.
    pub fn activate(
        &mut self,
        next: BidiSession,
        ids: &mut IdMap,
        now: Instant,
        need_keepalive: bool,
    ) -> Vec<PacketMut> {
        tracing::trace!(recv_id = ?next.recv.id(), "activating new session");

        let (active, mut packets) = match self.take() {
            Self::None(queue) => (next.into(), queue.into()),
            Self::Active(mut session) => {
                session.rotate(next, ids, now);
                (session, vec![])
            }
        };

        if need_keepalive && packets.is_empty() {
            packets.push(PacketMut::new(0));
        }
        active.cur.encrypt(&mut packets);
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
    pub fn send_keepalive(&mut self, ids: &mut IdMap, now: Instant) -> Option<PacketMut> {
        let session = self.as_active(ids, now)?;
        let mut packet = vec![PacketMut::new(0)];
        session.cur.encrypt(&mut packet);
        packet.pop()
    }

    /// Send packets to the peer.
    ///
    /// If the session is inactive, packets are queued for future transmission.
    ///
    /// Returns None to indicate that packets were queued, indicating the caller may need to
    /// initiate a handshake.
    pub fn send(
        &mut self,
        mut packets: Vec<PacketMut>,
        ids: &mut IdMap,
        now: Instant,
    ) -> Option<Vec<PacketMut>> {
        self.cleanup_expired(ids, now);
        match self {
            Self::None(queue) => {
                queue.append(packets);
                None
            }
            Self::Active(session) => {
                session.cur.encrypt(&mut packets);
                Some(packets)
            }
        }
    }

    /// Get the ReceiveSession for the given receiving ID, if any.
    pub fn get_recv(
        &mut self,
        id: SessionId,
        ids: &mut IdMap,
        now: Instant,
    ) -> Option<&mut ReceiveSession> {
        let session = self.as_active(ids, now)?;
        if session.cur.recv_id() == id {
            Some(&mut session.cur.recv)
        } else if let Some(prev) = session.prev.as_mut()
            && prev.id() == id
        {
            Some(prev)
        } else {
            None
        }
    }

    /// Reports whether the session is in need of a fresh handshake.
    pub fn needs_handshake(&self, now: Instant) -> bool {
        match self {
            Self::None(_) => true,
            Self::Active(session) => session.cur.stale(now),
        }
    }

    /// Clean up expired session state, if any.
    pub fn cleanup_expired(&mut self, ids: &mut IdMap, now: Instant) {
        if let Self::Active(session) = self {
            if session.expired(now) {
                session.cleanup_ids(ids);
                *self = Self::default();
                return;
            }
            if let Some(prev) = session.prev.as_ref()
                && prev.expired(now)
            {
                ids.remove_session(prev.id());
                session.prev = None;
            }
        }
    }

    /// Returns the soonest time at which some session state may be expired, necessitating
    /// a call to [`Session::cleanup_expired`]
    pub fn expiry(&mut self, ids: &mut IdMap, now: Instant) -> Option<TimeRange> {
        let soonest = self.as_active(ids, now)?.soonest_expiry();
        Some(TimeRange::new(soonest, soonest + SESSION_CLEANUP_GRACE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PeerId, messages::Message};

    #[test]
    fn test_session_parts() {
        let k: [u8; 32] = rand::random();
        let session = SessionId::random();
        let now = Instant::now();
        // NOTE: this would be catastrophically insecure in non-test code, because it reuses the
        // same key in both directions, which leads to catastrophic nonce reuse. It's okay here
        // because (a) it's a test and (b) we only ever transmit in one direction.
        let send = BidiSession::new(
            BidiSessionKeys {
                send_key: k.into(),
                send_id: session,
                recv_key: k.into(),
                recv_id: session,
            },
            now,
        );
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

    fn packet(payload: &str) -> Vec<PacketMut> {
        vec![PacketMut::from(payload.as_bytes())]
    }

    #[derive(Default)]
    struct PeerSession {
        ids: IdMap,
        recv_id: Option<SessionId>,
        recv_id_prev: Option<SessionId>,
        session: Session,
    }

    impl PeerSession {
        fn allocate_id(&mut self) -> SessionId {
            self.recv_id_prev = self.recv_id.take();
            let id = self.ids.allocate_session(PeerId(1));
            self.recv_id = Some(id);
            id
        }

        fn handshake_with(
            &mut self,
            other: &mut Self,
            now: Instant,
        ) -> (Vec<PacketMut>, Vec<PacketMut>) {
            let (k1, k2): ([u8; 32], [u8; 32]) = rand::random();
            let sid1 = self.allocate_id();
            let sid2 = other.allocate_id();
            let s1 = BidiSession::new(
                BidiSessionKeys {
                    send_key: k1.into(),
                    send_id: sid2,
                    recv_key: k2.into(),
                    recv_id: sid1,
                },
                now,
            );
            let s2 = BidiSession::new(
                BidiSessionKeys {
                    send_key: k2.into(),
                    send_id: sid1,
                    recv_key: k1.into(),
                    recv_id: sid2,
                },
                now,
            );
            let p1 = self.session.activate(s1, &mut self.ids, now, false);
            let p2 = other.session.activate(s2, &mut other.ids, now, false);
            (p1, p2)
        }

        fn send(&mut self, now: Instant, packets: Vec<PacketMut>) -> Option<Vec<PacketMut>> {
            self.session.send(packets, &mut self.ids, now)
        }

        fn get_recv(&mut self, now: Instant, packets: &[PacketMut]) -> Option<&mut ReceiveSession> {
            let (hdr, _) =
                TransportDataHeader::try_ref_from_prefix(packets.first()?.as_ref()).unwrap();
            self.session.get_recv(hdr.receiver_id, &mut self.ids, now)
        }

        fn recv(&mut self, now: Instant, packets: Vec<PacketMut>) -> Vec<PacketMut> {
            self.get_recv(now, &packets).unwrap().decrypt(packets)
        }

        fn unknown_recv(&mut self, now: Instant, packets: Vec<PacketMut>) -> bool {
            self.get_recv(now, &packets).is_none()
        }

        fn needs_handshake(&self, now: Instant) -> bool {
            self.session.needs_handshake(now)
        }
    }

    #[test]
    fn test_session() {
        let mut a = PeerSession::default();
        let mut b = PeerSession::default();

        let now = Instant::now();

        assert_eq!(a.send(now, packet("foobar")), None);
        assert_eq!(b.send(now, packet("qux")), None);

        assert!(a.needs_handshake(now));
        assert!(b.needs_handshake(now));

        // Establish a session between the peers. We're cheating and not doing any of the
        // handshake lifecycle.
        let (a_to_b, b_to_a) = a.handshake_with(&mut b, now);
        assert_eq!(a_to_b.len(), 1);
        assert_eq!(b_to_a.len(), 1);

        // Verify that the packets queued prior to session activation transmit correctly.
        let a_to_b = b.recv(now, a_to_b);
        assert_eq!(a_to_b, packet("foobar"));

        let b_to_a = a.recv(now, b_to_a);
        assert_eq!(b_to_a, packet("qux"));

        assert!(!a.needs_handshake(now));
        assert!(!b.needs_handshake(now));

        // Transmit with established session.
        let now = now + Duration::from_secs(60);

        let a_to_b = a.send(now, packet("frobozz")).unwrap();
        let a_to_b = b.recv(now, a_to_b);
        assert_eq!(a_to_b, packet("frobozz"));

        let b_to_a = b.send(now, packet("xyzzy")).unwrap();
        let b_to_a = a.recv(now, b_to_a);
        assert_eq!(b_to_a, packet("xyzzy"));

        assert!(!a.needs_handshake(now));
        assert!(!b.needs_handshake(now));

        // Transmit with stale session.
        let now = now + Duration::from_secs(70);

        let a_to_b = a.send(now, packet("foo")).unwrap();
        let a_to_b = b.recv(now, a_to_b);
        assert_eq!(a_to_b, packet("foo"));

        let b_to_a = b.send(now, packet("bar")).unwrap();
        let b_to_a = a.recv(now, b_to_a);
        assert_eq!(b_to_a, packet("bar"));

        assert!(a.needs_handshake(now));
        assert!(b.needs_handshake(now));

        // Transmit with expired session.
        let now = now + Duration::from_secs(120);

        let a_to_b = a.send(now, packet("no"));
        assert_eq!(a_to_b, None);

        let b_to_a = b.send(now, packet("nope"));
        assert_eq!(b_to_a, None);

        assert!(a.needs_handshake(now));
        assert!(b.needs_handshake(now));
    }

    #[test]
    fn test_rotation() {
        let mut a = PeerSession::default();
        let mut b = PeerSession::default();

        let start = Instant::now();
        let epsilon = Duration::from_secs(1);

        let now = start;
        let (a_to_b, b_to_a) = a.handshake_with(&mut b, now);
        assert!(a_to_b.is_empty());
        assert!(b_to_a.is_empty());

        let now = start + SESSION_FRESH_LIFETIME - epsilon;
        let a_to_b = a.send(now, packet("foo")).unwrap();
        let a_to_b = b.recv(now, a_to_b);
        assert_eq!(a_to_b, packet("foo"));

        let b_to_a = b.send(now, packet("bar")).unwrap();
        let b_to_a = a.recv(now, b_to_a);
        assert_eq!(b_to_a, packet("bar"));

        // Rotate session, with packets delivered across the rotation.
        let a_to_b = a.send(now, packet("before rotate A->B")).unwrap();
        let b_to_a = b.send(now, packet("before rotate B->A")).unwrap();

        let very_delayed_a_to_b = a.send(now, packet("delayed A->B")).unwrap();
        let very_delayed_b_to_a = b.send(now, packet("delayed B->A")).unwrap();

        let to_send = a.handshake_with(&mut b, now);
        assert_eq!(to_send, (vec![], vec![]));

        let a_to_b = b.recv(now, a_to_b);
        assert_eq!(a_to_b, packet("before rotate A->B"));
        let b_to_a = a.recv(now, b_to_a);
        assert_eq!(b_to_a, packet("before rotate B->A"));

        let a_to_b = a.send(now, packet("after rotate A->B")).unwrap();
        let a_to_b = b.recv(now, a_to_b);
        assert_eq!(a_to_b, packet("after rotate A->B"));

        let b_to_a = b.send(now, packet("after rotate B->A")).unwrap();
        let b_to_a = a.recv(now, b_to_a);
        assert_eq!(b_to_a, packet("after rotate B->A"));

        // Rotate again, delayed packets should not decrypt anymore.
        let now = start + SESSION_FRESH_LIFETIME + epsilon;
        let a_to_b = a.send(now, packet("before rotate2 A->B")).unwrap();
        let b_to_a = b.send(now, packet("before rotate2 B->A")).unwrap();

        let to_send = a.handshake_with(&mut b, now);
        assert_eq!(to_send, (vec![], vec![]));

        let a_to_b = b.recv(now, a_to_b);
        assert_eq!(a_to_b, packet("before rotate2 A->B"));
        let b_to_a = a.recv(now, b_to_a);
        assert_eq!(b_to_a, packet("before rotate2 B->A"));

        let a_to_b = a.send(now, packet("after rotate2 A->B")).unwrap();
        let a_to_b = b.recv(now, a_to_b);
        assert_eq!(a_to_b, packet("after rotate2 A->B"));

        let b_to_a = b.send(now, packet("after rotate2 B->A")).unwrap();
        let b_to_a = a.recv(now, b_to_a);
        assert_eq!(b_to_a, packet("after rotate2 B->A"));

        assert!(b.unknown_recv(now, very_delayed_a_to_b));
        assert!(a.unknown_recv(now, very_delayed_b_to_a));
    }

    #[test]
    fn test_expiration() {
        let mut a = PeerSession::default();
        let mut b = PeerSession::default();

        let now = Instant::now();
        let to_send = a.handshake_with(&mut b, now);
        assert_eq!(to_send, (vec![], vec![]));

        let a_to_b = a.send(now, packet("A->B")).unwrap();
        let b_to_a = b.send(now, packet("B->A")).unwrap();

        let now = now + SESSION_LIFETIME + SESSION_LIFETIME;

        assert!(b.unknown_recv(now, a_to_b));
        assert!(a.unknown_recv(now, b_to_a));

        assert_eq!(a.send(now, packet("expired A->B")), None);
        assert_eq!(b.send(now, packet("expired B->A")), None);
    }

    #[test]
    fn test_session_timers() {
        let k: [u8; 32] = rand::random();
        let id = SessionId::random();
        let now = Instant::now();
        let epsilon = Duration::from_secs(1);

        let recv = ReceiveSession::new(k.into(), id, now);
        assert!(!recv.expired(now));
        assert!(!recv.expired(now + SESSION_FRESH_LIFETIME - epsilon));
        assert!(!recv.expired(now + SESSION_FRESH_LIFETIME + epsilon));
        assert!(recv.expired(now + SESSION_LIFETIME + epsilon));

        let k2: [u8; 32] = rand::random();
        let id2 = SessionId::random();

        let bidi = BidiSession::new(
            BidiSessionKeys {
                send_key: k.into(),
                send_id: id,
                recv_key: k2.into(),
                recv_id: id2,
            },
            now,
        );
        assert!(!bidi.expired(now));
        assert!(!bidi.stale(now));

        assert!(!bidi.expired(now + SESSION_FRESH_LIFETIME - epsilon));
        assert!(!bidi.stale(now + SESSION_FRESH_LIFETIME - epsilon));

        assert!(!bidi.expired(now + SESSION_FRESH_LIFETIME + epsilon));
        assert!(bidi.stale(now + SESSION_FRESH_LIFETIME + epsilon));

        assert!(bidi.expired(now + SESSION_LIFETIME + epsilon));
        assert!(bidi.stale(now + SESSION_LIFETIME + epsilon));
    }
}
