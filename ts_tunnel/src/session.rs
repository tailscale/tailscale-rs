use core::fmt::{Debug, Formatter};
use std::{
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
    Event, PeerId,
    endpoint::EndpointState,
    ids::SessionHandle,
    messages::{SessionId, TransportDataHeader},
    replay::ReplayWindow,
};

type SessionKey = chacha20poly1305::Key;

/// A generator of monotonically increasing 64-bit nonces.
#[derive(Default)]
struct NonceGenerator {
    nonce: Mutex<u64>,
}

/// The maximum number of messages that can be processed on one session key. This maps
/// to the number of nonces that NonceGenerator is willing to produce before panicking.
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (2 << 13);

impl NonceGenerator {
    #[cfg(test)]
    fn new_with(value: u64) -> Self {
        Self {
            nonce: Mutex::new(value),
        }
    }

    /// Reserve a batch of consecutive nonces.
    ///
    /// The reserved range is fully consumed even if the returned NonceIter isn't.
    fn batch(&self, num: usize) -> NonceIter {
        let mut nonce = self.nonce.lock().unwrap();
        let end = nonce.saturating_add(num as u64);
        if end > REJECT_AFTER_MESSAGES + 1 {
            // NonceGenerator is used to produce nonces for a wireguard session.
            // A single wireguard session lives for 120s before being replaced.
            // To exhaust `REJECT_AFTER_MESSAGES` nonces in that time, assuming
            // 1500b packets, you would have to be sending 27.6 zettabytes every
            // two minutes, or 230 exabytes/sec.
            //
            // If you're still running this code on a computer capable of that
            // kind of data rate: hello from the past! Enjoy your panic.
            panic!("nonce exhausted");
        }
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
#[derive(Eq, PartialEq, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
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
/// being exchanged, a key rotation handshake should have started after `SESSION_FRESH_LIFETIME`
/// to switch to a new session. If that handshake fails to establish a new session in time, or
/// traffic is no longer being exchanged, the previously established session is forcibly discarded
/// after this much time to preserve forward secrecy.
pub const SESSION_LIFETIME: Duration = Duration::from_secs(180);

/// Grace time for cleaning up a session that has exceeded [`SESSION_LIFETIME`].
///
/// Once a session has expired, we need to delete its key material to ensure forward secrecy
/// of the data exchanged in that session. To allow for wakeup coalescing, we allow an expired
/// session's state to persist for short additional time before requiring that it be deleted.
pub const SESSION_CLEANUP_GRACE: Duration = Duration::from_secs(5);

/// Established session that can only receive.
pub struct ReceiveSession {
    cipher: ChaCha20Poly1305,
    session_handle: SessionHandle,
    expiry: Instant,
    window: ReplayWindow,
}

impl Debug for ReceiveSession {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiveSession")
            .field("id", self.session_handle.as_ref())
            .finish_non_exhaustive()
    }
}

impl ReceiveSession {
    pub fn new(key: SessionKey, session_handle: SessionHandle, now: Instant) -> Self {
        ReceiveSession {
            cipher: ChaCha20Poly1305::new(&key),
            session_handle,
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
    #[tracing::instrument(skip_all, fields(session_id = ?self.session_handle))]
    #[must_use]
    fn decrypt_one(&mut self, pkt: &mut PacketMut) -> bool {
        let Ok((header, _)) = TransportDataHeader::try_ref_from_prefix(pkt.as_ref()) else {
            tracing::warn!("decode as transport packet failed");
            return false;
        };

        let _guard = tracing::trace_span!("header_parsed", ?header).entered();

        if header.receiver_id != self.id() {
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
        self.session_handle.id()
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

    is_initiator: bool,
}

impl BidiSession {
    /// Create a new session in the initiator role.
    pub fn new_initiator(
        keys: ts_noise::core::Session,
        responder_to_initiator_handle: SessionHandle,
        initiator_to_responder_id: SessionId,
        now: Instant,
    ) -> Self {
        Self {
            recv: ReceiveSession::new(
                keys.responder_to_initiator,
                responder_to_initiator_handle,
                now,
            ),
            send_id: initiator_to_responder_id,
            send_cipher: ChaCha20Poly1305::new(&keys.initiator_to_responder),
            send_nonce: Default::default(),
            is_initiator: true,
        }
    }

    /// Create a new session in the responder role.
    pub fn new_responder(
        keys: ts_noise::core::Session,
        initiator_to_responder_handle: SessionHandle,
        responder_to_initiator_id: SessionId,
        now: Instant,
    ) -> Self {
        Self {
            recv: ReceiveSession::new(
                keys.initiator_to_responder,
                initiator_to_responder_handle,
                now,
            ),
            send_id: responder_to_initiator_id,
            send_cipher: ChaCha20Poly1305::new(&keys.responder_to_initiator),
            send_nonce: Default::default(),
            is_initiator: false,
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
        self.recv.session_handle.id()
    }

    pub fn rotation_time(&self) -> Instant {
        self.recv.expiry - SESSION_LIFETIME + SESSION_FRESH_LIFETIME
    }

    /// Report whether the session is expired.
    pub fn expired(&self, now: Instant) -> bool {
        now > self.recv.expiry
    }

    pub fn needs_rotation(&self, now: Instant) -> bool {
        self.is_initiator && now > self.rotation_time()
    }
}

impl From<BidiSession> for ReceiveSession {
    fn from(session: BidiSession) -> Self {
        session.recv
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
    fn rotate(&mut self, next: BidiSession, now: Instant) {
        let prev = std::mem::replace(self.cur.as_mut(), next);
        if !prev.expired(now) {
            self.prev = Some(Box::new(prev.into()));
        }
    }

    fn expired(&self, now: Instant) -> bool {
        self.cur.expired(now)
    }
}

/// A communication session to a peer.
#[derive(Default)]
pub struct Session(Option<ActiveSession>);

impl Session {
    pub fn is_active(&self, now: Instant) -> bool {
        match &self.0 {
            Some(session) => !session.expired(now),
            None => false,
        }
    }

    /// Activate the session with the given keys.
    pub fn activate(
        &mut self,
        endpoint: &mut EndpointState,
        peer_id: PeerId,
        next: BidiSession,
        now: Instant,
    ) {
        tracing::trace!(recv_id = ?next.recv.id(), "activating new session");

        match &mut self.0 {
            Some(session) => {
                session.rotate(next, now);
            }
            None => self.0 = Some(next.into()),
        }

        let cleanup = TimeRange::new(
            now + SESSION_LIFETIME,
            now + SESSION_LIFETIME + SESSION_CLEANUP_GRACE,
        );
        endpoint
            .scheduler
            .add(cleanup, Event::ExpireSession(peer_id));
    }

    /// Discard all state for this session.
    pub fn deactivate(&mut self) {
        *self = Self::default();
    }

    /// Encrypt a keepalive packet for the peer.
    ///
    /// Returns None if the session is inactive (and thus no keepalive is necessary).
    pub fn send_keepalive(&mut self, now: Instant) -> Option<PacketMut> {
        self.cleanup_expired(now);
        let session = self.0.as_mut()?;
        let mut packet = vec![PacketMut::new(0)];
        session.cur.encrypt(&mut packet);
        packet.pop()
    }

    /// Send packets to the peer.
    ///
    /// Returns Err to indicate that no session is available for transmission.
    pub fn send(&mut self, packets: &mut Vec<PacketMut>, now: Instant) -> Result<(), ()> {
        self.cleanup_expired(now);
        let session = self.0.as_mut().ok_or(())?;
        session.cur.encrypt(packets);
        Ok(())
    }

    /// Get the ReceiveSession for the given receiving ID, if any.
    pub fn get_recv(&mut self, id: SessionId, now: Instant) -> Option<&mut ReceiveSession> {
        self.cleanup_expired(now);
        let session = self.0.as_mut()?;
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

    /// Reports whether the session is old enough to require rotation.
    pub fn needs_rotation(&self, now: Instant) -> bool {
        match &self.0 {
            None => true,
            Some(session) => session.cur.needs_rotation(now),
        }
    }

    /// Clean up expired session state, if any.
    pub fn cleanup_expired(&mut self, now: Instant) {
        let Some(session) = self.0.as_mut() else {
            return;
        };

        if session.expired(now) {
            *self = Self::default();
            return;
        }
        if let Some(prev) = session.prev.as_ref()
            && prev.expired(now)
        {
            session.prev = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use ts_noise::core::Role;

    use super::*;
    use crate::{PeerId, ids::IdMap, messages::Message};

    #[test]
    fn test_session_parts() {
        let k: [u8; 32] = rand::random();
        let mut ids = IdMap::default();

        let initiator_session = ids.allocate_session(PeerId(1));
        let responder_session = ids.allocate_session(PeerId(2));
        let responder_session_id = responder_session.id();
        let now = Instant::now();
        // NOTE: this would be catastrophically insecure in non-test code, because it reuses the
        // same key in both directions, which leads to catastrophic nonce reuse. It's okay here
        // because (a) it's a test and (b) we only ever transmit in one direction.
        let send = BidiSession::new_initiator(
            ts_noise::core::Session {
                initiator_to_responder: k.into(),
                responder_to_initiator: k.into(),
                role: Role::Initiator,
            },
            initiator_session,
            responder_session_id,
            now,
        );
        let mut recv = ReceiveSession::new(k.into(), responder_session, now);

        const CLEARTEXT: &[u8] = b"foobar";
        let mut pkt = [PacketMut::from(CLEARTEXT)];

        send.encrypt(&mut pkt);
        assert_eq!(pkt[0].len(), 38);
        let Ok(Message::TransportDataHeader(msg)) = Message::try_from(pkt[0].as_ref()) else {
            panic!("packet is not a valid TransportData message");
        };
        assert_eq!(msg.receiver_id, responder_session_id);
        assert_eq!(u64::from(msg.nonce), 0);

        assert!(recv.decrypt_one(&mut pkt[0]));
        assert_eq!(pkt[0].as_ref(), CLEARTEXT);

        send.encrypt(&mut pkt);
        assert_eq!(pkt[0].len(), 38);
        let Ok(Message::TransportDataHeader(msg)) = Message::try_from(pkt[0].as_ref()) else {
            panic!("packet is not a valid TransportData message");
        };
        assert_eq!(msg.receiver_id, responder_session_id);
        assert_eq!(u64::from(msg.nonce), 1);

        assert!(recv.decrypt_one(&mut pkt[0]));
        assert_eq!(pkt[0].as_ref(), CLEARTEXT);
    }

    #[test]
    fn test_session_timers() {
        let k: [u8; 32] = rand::random();
        let mut ids = IdMap::default();
        let recv_session = ids.allocate_session(PeerId(1));
        let recv_session_id = recv_session.id();
        let bidi_session = ids.allocate_session(PeerId(2));
        let now = Instant::now();
        let epsilon = Duration::from_secs(1);

        let recv = ReceiveSession::new(k.into(), recv_session, now);
        assert!(!recv.expired(now));
        assert!(!recv.expired(now + SESSION_FRESH_LIFETIME - epsilon));
        assert!(!recv.expired(now + SESSION_FRESH_LIFETIME + epsilon));
        assert!(recv.expired(now + SESSION_LIFETIME + epsilon));

        let k2: [u8; 32] = rand::random();

        let bidi = BidiSession::new_initiator(
            ts_noise::core::Session {
                initiator_to_responder: k.into(),
                responder_to_initiator: k2.into(),
                role: Role::Initiator,
            },
            bidi_session,
            recv_session_id,
            now,
        );
        assert!(!bidi.expired(now));
        assert!(!bidi.needs_rotation(now));

        assert!(!bidi.expired(now + SESSION_FRESH_LIFETIME - epsilon));
        assert!(!bidi.needs_rotation(now + SESSION_FRESH_LIFETIME - epsilon));

        assert!(!bidi.expired(now + SESSION_FRESH_LIFETIME + epsilon));
        assert!(bidi.needs_rotation(now + SESSION_FRESH_LIFETIME + epsilon));

        assert!(bidi.expired(now + SESSION_LIFETIME + epsilon));
        assert!(bidi.needs_rotation(now + SESSION_LIFETIME + epsilon));
    }

    #[test]
    fn test_nonce_limit() {
        let nonces = NonceGenerator::new_with(REJECT_AFTER_MESSAGES);
        assert_eq!(
            nonces.batch(1).collect::<Vec<Nonce>>(),
            vec![Nonce::from(REJECT_AFTER_MESSAGES)]
        );
    }
    #[test]
    #[should_panic(expected = "nonce exhausted")]
    fn test_nonce_limit_exceeded() {
        let nonces = NonceGenerator::new_with(REJECT_AFTER_MESSAGES + 1);
        nonces.batch(1);
    }

    #[test]
    #[should_panic(expected = "nonce exhausted")]
    fn test_nonce_limit_exceeded_batch() {
        let nonces = NonceGenerator::new_with(REJECT_AFTER_MESSAGES - 10);
        nonces.batch(20);
    }
}
