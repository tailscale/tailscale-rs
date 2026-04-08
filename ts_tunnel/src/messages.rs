use core::fmt::{Debug, Formatter};

use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned,
    byteorder::little_endian::{U32, U64},
};

#[repr(transparent)]
#[derive(
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Copy,
    Clone,
    FromBytes,
    IntoBytes,
    Immutable,
    KnownLayout,
    Unaligned,
    Hash,
)]
pub struct SessionId(U32);

impl SessionId {
    pub fn random() -> Self {
        let v: u32 = rand::random();
        SessionId(v.into())
    }
}

impl From<u32> for SessionId {
    fn from(v: u32) -> Self {
        SessionId(v.into())
    }
}

impl From<SessionId> for u32 {
    fn from(v: SessionId) -> Self {
        v.0.into()
    }
}

#[repr(u8)]
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned,
)]
pub enum MessageType {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    CookieReply = 3,
    TransportData = 4,
}

#[repr(C)]
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct HandshakeInitiation {
    pub msg_type: MessageType,
    pub _reserved: [u8; 3],
    pub sender_id: SessionId,
    pub ephemeral_pub: [u8; 32],
    pub static_pub_sealed: [u8; 32 + 16],
    pub timestamp_sealed: [u8; 12 + 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

impl Default for HandshakeInitiation {
    fn default() -> Self {
        Self {
            msg_type: MessageType::HandshakeInitiation,
            _reserved: Default::default(),
            sender_id: Default::default(),
            ephemeral_pub: Default::default(),
            static_pub_sealed: [0; 32 + 16], // no Default impl for such a large array
            timestamp_sealed: Default::default(),
            mac1: Default::default(),
            mac2: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct HandshakeResponse {
    pub msg_type: MessageType,
    pub _reserved: [u8; 3],
    pub sender_id: SessionId,
    pub receiver_id: SessionId,
    pub ephemeral_pub: [u8; 32],
    pub auth_tag: [u8; 16],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

impl Default for HandshakeResponse {
    fn default() -> Self {
        Self {
            msg_type: MessageType::HandshakeResponse,
            _reserved: Default::default(),
            sender_id: Default::default(),
            receiver_id: Default::default(),
            ephemeral_pub: Default::default(),
            auth_tag: Default::default(),
            mac1: Default::default(),
            mac2: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct TransportDataHeader {
    pub msg_type: MessageType,
    pub _reserved: [u8; 3],
    pub receiver_id: SessionId,
    pub nonce: U64,
}

impl Debug for TransportDataHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransportDataHeader")
            .field("msg_type", &self.msg_type)
            .field("receiver_id", &self.receiver_id)
            .field("nonce", &self.nonce)
            .finish()
    }
}

impl<'packet> TryFrom<&'packet [u8]> for &'packet TransportDataHeader {
    type Error = ();

    fn try_from(value: &'packet [u8]) -> Result<Self, Self::Error> {
        Ok(TransportDataHeader::try_ref_from_prefix(value)
            .map_err(|_| ())?
            .0)
    }
}

impl Default for TransportDataHeader {
    fn default() -> Self {
        Self {
            msg_type: MessageType::TransportData,
            _reserved: Default::default(),
            receiver_id: Default::default(),
            nonce: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct CookieReply {
    pub msg_type: MessageType,
    pub _reserved: [u8; 3],
    pub receiver_id: SessionId,
    pub nonce: [u8; 24],
    pub cookie_sealed: [u8; 16 + 16],
}
impl Default for CookieReply {
    fn default() -> Self {
        Self {
            msg_type: MessageType::TransportData,
            _reserved: Default::default(),
            receiver_id: Default::default(),
            nonce: Default::default(),
            cookie_sealed: Default::default(),
        }
    }
}

pub enum Message<'packet> {
    HandshakeInitiation(&'packet HandshakeInitiation),
    HandshakeResponse(&'packet HandshakeResponse),
    TransportDataHeader(&'packet TransportDataHeader),
    CookieReply(&'packet CookieReply),
}

impl<'packet> TryFrom<&'packet [u8]> for Message<'packet> {
    type Error = ();

    fn try_from(raw: &'packet [u8]) -> Result<Message<'packet>, Self::Error> {
        let Ok((msg_type, _)) = MessageType::try_ref_from_prefix(raw) else {
            return Err(());
        };

        match msg_type {
            MessageType::HandshakeInitiation => HandshakeInitiation::try_ref_from_bytes(raw)
                .map(Message::HandshakeInitiation)
                .map_err(|_| ()),
            MessageType::HandshakeResponse => HandshakeResponse::try_ref_from_bytes(raw)
                .map(Message::HandshakeResponse)
                .map_err(|_| ()),
            MessageType::TransportData => TransportDataHeader::try_ref_from_prefix(raw)
                .map(|(header, _)| Message::TransportDataHeader(header))
                .map_err(|_| ()),
            MessageType::CookieReply => CookieReply::try_ref_from_bytes(raw)
                .map(Message::CookieReply)
                .map_err(|_| ()),
        }
    }
}

impl Message<'_> {
    pub fn receiver_id(&self) -> Option<SessionId> {
        match self {
            Message::HandshakeInitiation(_) => None,
            Message::HandshakeResponse(resp) => Some(resp.receiver_id),
            Message::TransportDataHeader(data) => Some(data.receiver_id),
            Message::CookieReply(cookie) => Some(cookie.receiver_id),
        }
    }
}
