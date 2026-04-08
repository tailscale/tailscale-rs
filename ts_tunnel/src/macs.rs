use std::{
    ops::Add,
    time::{Duration, Instant},
};

use aead::{Aead, Payload, consts::U16};
use blake2::{Blake2s256, Blake2sMac, Digest, digest::FixedOutput};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use ts_keys::NodePublicKey;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

use crate::messages::CookieReply;

const MAC1_LABEL: &[u8] = b"mac1----";
const MAC2_LABEL: &[u8] = b"cookie--";
const COOKIE_ROTATION_TIME: Duration = Duration::from_secs(120);

type CookieMac = Blake2sMac<U16>;

pub type Mac = [u8; 16];

#[repr(C, packed)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
struct Mac1Trailer {
    mac1: Mac,
    mac2: Mac,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
struct Mac2Trailer {
    mac2: Mac,
}

fn mac1_key(key: &NodePublicKey) -> [u8; 32] {
    let mut h = Blake2s256::new_with_prefix(MAC1_LABEL);
    h.update(key.to_bytes());
    h.finalize().into()
}

fn mac2_key(key: &NodePublicKey) -> [u8; 32] {
    let mut h = Blake2s256::new_with_prefix(MAC2_LABEL);
    h.update(key.to_bytes());
    h.finalize().into()
}

#[derive(Debug)]
struct Mac2Cookie {
    key: [u8; 16],
    expiry: Instant,
}

/// Computes MACs on outbound packets.
pub struct MACSender {
    mac1_key: [u8; 32],
    mac2_key: [u8; 32],
    cookie: Option<Mac2Cookie>,
}

impl MACSender {
    /// Create a MAC sender for the given peer.
    pub fn new(peer_key: &NodePublicKey) -> Self {
        Self {
            mac1_key: mac1_key(peer_key),
            mac2_key: mac2_key(peer_key),
            cookie: None,
        }
    }

    /// Write packet MACs to the final 32 bytes of pkt.
    ///
    /// Returns the computed mac1 value.
    pub fn write_macs(&self, pkt: &mut [u8]) -> Mac {
        let (data, trailer) =
            Mac1Trailer::try_mut_from_suffix(pkt).expect("packet too small for MACs");
        let mut m: CookieMac = blake2::digest::Mac::new(&self.mac1_key.into());
        blake2::digest::Mac::update(&mut m, data);
        m.finalize_into(trailer.mac1.as_mut_bytes().into());
        let ret = trailer.mac1;

        if let Some(mac2) = &self.cookie
            && mac2.expiry > Instant::now()
        {
            let (data, trailer) =
                Mac2Trailer::try_mut_from_suffix(pkt).expect("packet too small for MACs");
            // Have to use new_from_slice, because new only accepts keys exactly 32 bytes long,
            // whereas new_from_slice accepts keys <32 bytes and pads them in the correct way
            // internally.
            let mut m: CookieMac = blake2::digest::Mac::new_from_slice(&mac2.key).unwrap();
            blake2::digest::Mac::update(&mut m, data);
            m.finalize_into(trailer.mac2.as_mut_bytes().into());
        } else {
            trailer.mac2 = Default::default();
        }

        ret
    }

    /// Process a received cookie reply message.
    pub fn receive_cookie(&mut self, cookie: &CookieReply, handshake_mac: &Mac) {
        let cipher = XChaCha20Poly1305::new(&self.mac2_key.into());
        let msg = Payload {
            msg: &cookie.cookie_sealed,
            aad: handshake_mac,
        };
        let Ok(cookie) = cipher.decrypt(&cookie.nonce.into(), msg) else {
            return;
        };
        self.cookie = Some(Mac2Cookie {
            // CookieReply has fixed sized fields of the correct size, so the conversion
            // from Vec cannot fail.
            key: cookie.try_into().unwrap(),
            expiry: Instant::now().add(COOKIE_ROTATION_TIME),
        });
    }
}

/// Verifies MACs on inbound packets.
pub struct MACReceiver {
    mac1_key: [u8; 32],
}

impl MACReceiver {
    /// Creates a MAC receiver.
    pub fn new(my_key: &NodePublicKey) -> Self {
        Self {
            mac1_key: mac1_key(my_key),
        }
    }

    /// Verifies packet MACs in the final 32 bytes of pkt.
    #[must_use]
    pub fn verify_macs(&self, pkt: &[u8]) -> bool {
        let Ok((data, trailer)) = Mac1Trailer::try_ref_from_suffix(pkt) else {
            return false;
        };
        let mut m: CookieMac = blake2::digest::Mac::new(&self.mac1_key.into());
        blake2::digest::Mac::update(&mut m, data);
        if blake2::digest::Mac::verify(m, &trailer.mac1.into()).is_err() {
            return false;
        }

        // TODO: verify non-zero mac2
        if trailer.mac2 != Mac::default() {
            return false;
        }
        true
    }
}
