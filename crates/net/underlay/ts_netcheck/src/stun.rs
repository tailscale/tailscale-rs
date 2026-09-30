//! STUN functionality.

use core::net::SocketAddr;

use bytes::BytesMut;
pub use stun_rs::TransactionId;
use stun_rs::{
    MessageClass, StunMessageBuilder,
    attributes::stun::{Fingerprint, Software, XorMappedAddress},
    methods::BINDING,
};

const SOFTWARE: &str = "tailnode";

/// Create a new STUN binding transaction with a random id.
pub fn new_txn() -> (TransactionId, BytesMut) {
    let req = StunMessageBuilder::new(BINDING, MessageClass::Request)
        .with_attribute(Software::new(SOFTWARE).unwrap())
        .with_attribute(Fingerprint::default())
        .build();

    let encoder = stun_rs::MessageEncoderBuilder::default().build();
    let mut buf = BytesMut::zeroed(128);
    let n = encoder.encode(&mut buf, &req).unwrap();
    buf.truncate(n);

    (*req.transaction_id(), buf)
}

/// Try to decode `packet` as a STUN binding response, returning its transaction ID and the
/// XOR-mapped address it contains.
pub fn try_decode(packet: &[u8]) -> Option<(TransactionId, SocketAddr)> {
    let (msg, _n) = stun_rs::MessageDecoderBuilder::default()
        .build()
        .decode(packet)
        .inspect_err(|e| {
            tracing::error!(error = %e, "stun decode");
        })
        .ok()?;

    let Some(addr) = msg.get::<XorMappedAddress>() else {
        tracing::error!("no xor mapped address");
        return None;
    };

    let addr = addr.as_xor_mapped_address().unwrap();

    Some((*msg.transaction_id(), *addr.socket_address()))
}
