use num_traits::FromPrimitive;

/// Disco message types.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, num_derive::FromPrimitive)]
#[repr(u8)]
pub enum MessageType {
    /// [`Ping`][crate::Ping] message: request that the recipient send a
    /// [`Pong`][crate::Pong] back to us.
    Ping = 0x1,
    /// [`Pong`][crate::Pong] message: response to a [`Ping`][crate::Ping].
    Pong = 0x2,
    /// [`CallMeMaybe`][crate::CallMeMaybe] message: request that the recipient open a
    /// magicsock path to us.
    CallMeMaybe = 0x3,
    /// First message in a bind UDP relay handshake.
    BindUdpRelayEndpoint = 0x4,
    /// UDP relay endpoint challenge.
    BindUdpRelayEndpointChallenge = 0x5,
    /// UDP relay challenge answer.
    BindUdpRelayEndpointAnswer = 0x6,
    /// Like [`MessageType::CallMeMaybe`], but highlights that the response path travels
    /// through a relay.
    CallMeMaybeVia = 0x7,
    /// Request allocation of a relay endpoint on a UDP relay server.
    AllocateUdpRelayEndpointsRequest = 0x8,
    /// Response to a request for allocation of a relay endpoint.
    AllocateUdpRelayEndpointsResponse = 0x9,
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_u8(value).ok_or(())
    }
}
