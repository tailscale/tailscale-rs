use core::fmt::{Debug, Formatter};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use ts_packet::PacketMut;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned,
    little_endian::{U32, U64},
};

use crate::messages::{SessionId, TransportDataHeader};

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
        now.duration_since(self.created) > Duration::from_secs(120) // TODO: constants
    }

    pub fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.created) > Duration::from_secs(240) // TODO: constants
    }
}

/// Established session that can only receive.
pub struct ReceiveSession {
    cipher: ChaCha20Poly1305,
    id: SessionId,
    created: Instant,
    // TODO: nonce sliding window for replay protection
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
            created: now,
        }
    }

    /// Decrypt wireguard transport data messages in place.
    ///
    /// Returns the packets which successfully decrypted.
    pub fn decrypt(&self, mut packets: Vec<PacketMut>) -> Vec<PacketMut> {
        packets.retain_mut(|packet| self.decrypt_one(packet));
        packets
    }

    /// Decrypt a wireguard transport data message in place.
    #[tracing::instrument(skip_all, fields(session_id = ?self.id))]
    #[must_use]
    fn decrypt_one(&self, pkt: &mut PacketMut) -> bool {
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

        let nonce = Nonce::from(header.nonce);
        pkt.truncate_front(size_of::<TransportDataHeader>());

        let result = self.cipher.decrypt_in_place(nonce.as_ref(), &[], pkt);

        if let Err(e) = &result {
            tracing::error!(err = %e, "decryption failed");
        }

        result.is_ok()
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.created) > Duration::from_secs(240) // TODO: constants
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
        let recv = ReceiveSession::new(k.into(), session, now);

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

        assert!(!send.stale(now));
        assert!(!send.stale(now + Duration::from_secs(100)));
        assert!(send.stale(now + Duration::from_secs(130)));
        assert!(send.stale(now + Duration::from_secs(250)));

        assert!(!send.expired(now));
        assert!(!send.expired(now + Duration::from_secs(100)));
        assert!(!send.expired(now + Duration::from_secs(130)));
        assert!(send.expired(now + Duration::from_secs(250)));

        assert!(!recv.expired(now));
        assert!(!recv.expired(now + Duration::from_secs(100)));
        assert!(!recv.expired(now + Duration::from_secs(130)));
        assert!(recv.expired(now + Duration::from_secs(250)));
    }
}
