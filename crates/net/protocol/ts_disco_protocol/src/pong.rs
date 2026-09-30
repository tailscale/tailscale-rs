use crate::{Endpoint, Message, MessageType};

/// A pong message responds to a [`Ping`][crate::Ping] with the same `tx_id`.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
    zerocopy::KnownLayout,
)]
#[repr(C, packed)]
pub struct Pong {
    /// Same tx id sent in the associated ping.
    pub tx_id: [u8; 12],

    /// The sender's source IP and port from the perspective of the receiver.
    pub src: Endpoint,
}

impl Message for Pong {
    const TYPE: MessageType = MessageType::Pong;
}

impl Pong {
    /// The size of a pong message.
    pub const fn size() -> usize {
        size_of::<Self>()
    }
}
