use core::{
    fmt::{Debug, Formatter},
    hash::{Hash, Hasher},
};

use ts_keys::{Node, PublicKey};

use crate::{Message, MessageType};

/// A ping message from one node to another.
#[derive(
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
    zerocopy::KnownLayout,
)]
#[repr(C, packed)]
pub struct Ping {
    /// Random client-generated per-ping transaction id.
    pub tx_id: [u8; 12],

    /// Allegedly the ping sender's wireguard public key.
    ///
    /// Old clients (~1.16.0 and earlier) don't send this field.
    ///
    /// It shouldn't be trusted by itself, but can be combined with netmap data to reduce
    /// the discokey:nodekey relation from 1:N to 1:1.
    pub node_key: PublicKey<Node>,

    /// Zero bytes at the end of the message used to probe path MTU.
    pub padding: [u8],
}

impl Message for Ping {
    const TYPE: MessageType = MessageType::Ping;
}

impl Ping {
    /// The size of a ping message with `n` bytes of padding.
    pub const fn size_with_padding(n: usize) -> usize {
        12 + size_of::<PublicKey<Node>>() + n
    }
}

impl Debug for &Ping {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let mut dbg = f.debug_struct("Ping");

        dbg.field("node_key", &self.node_key).field(
            "tx_id",
            &format_args!("{:02x}", ts_hexdump::IterFmt::contiguous(&self.tx_id)),
        );

        if self.padding.iter().any(|&x| x != 0) {
            dbg.field("padding", &format_args!("<nonzero> {:x?}", &self.padding));
        } else {
            dbg.field("padding", &self.padding.len());
        };

        dbg.finish()
    }
}

impl PartialEq for &Ping {
    fn eq(&self, other: &Self) -> bool {
        self.tx_id == other.tx_id
            && self.node_key == other.node_key
            && self.padding == other.padding
    }
}

impl Eq for &Ping {}

impl Hash for &Ping {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.tx_id.hash(state);
        self.node_key.hash(state);
        self.padding.hash(state);
    }
}
