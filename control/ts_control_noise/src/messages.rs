use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, network_endian::U16};

/// Type for messages sent to and from a Tailscale control server.
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(u8)]
pub enum MessageType {
    /// Initiation message (client to control).
    Initiation = 0x1,

    /// Response to an initiation (received from control).
    Response = 0x2,

    /// An error occurred.
    ///
    /// The body of the message is a cleartext string describing it.
    Error = 0x3,

    /// Encrypted data.
    Record = 0x4,
}

/// A message header (3 bytes).
#[derive(Copy, Clone, Debug, TryFromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct Header {
    /// The type of the message.
    pub typ: MessageType,
    /// The length of the following body (not including the header).
    pub len: U16,
}

static_assertions::const_assert_eq!(size_of::<Header>(), 3);

/// An initiation message.
///
/// Distinct from other message types in that it starts with the capability version.
#[derive(IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Initiation {
    /// The capability version of this node.
    pub capability_version: U16,
    /// The typical header.
    pub hdr: Header,
    /// The payload, consisting of the noise handshake initiation.
    pub payload: [u8; Self::PAYLOAD_LEN],
}

impl Initiation {
    /// The fixed length of an [`Initiation`] payload, in bytes.
    pub const PAYLOAD_LEN: usize = 96;

    /// Construct a new initiation message.
    pub fn new(
        capability_version: u16,
        overhead_len: u16,
        payload: [u8; Self::PAYLOAD_LEN],
    ) -> Self {
        Self {
            capability_version: capability_version.into(),
            hdr: Header {
                typ: MessageType::Initiation,
                len: overhead_len.into(),
            },
            payload,
        }
    }
}
