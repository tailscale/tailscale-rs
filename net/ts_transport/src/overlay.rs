use core::error::Error;

use ts_packet::PacketMut;

/// The unique id of an overlay transport.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OverlayTransportId(pub u32);

impl From<u32> for OverlayTransportId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<OverlayTransportId> for u32 {
    fn from(value: OverlayTransportId) -> Self {
        value.0
    }
}

/// A transport that can carry packets to and from the overlay network.
pub trait OverlayTransport {
    /// The error type this transport may produce.
    type Error: Error + Send + Sync + 'static;

    /// Send packets onto the overlay transport.
    fn send<PacketIter>(
        &self,
        packets: PacketIter,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        PacketIter: IntoIterator<Item = PacketMut> + Send,
        PacketIter::IntoIter: Send;

    /// Receive packets from the overlay transport.
    fn recv(
        &self,
    ) -> impl Future<Output = impl IntoIterator<Item = Result<PacketMut, Self::Error>> + Send> + Send;
}
