use core::error::Error;

use crate::{BatchRecvIter, BatchSendIter};

/// The unique id of an underlay transport.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UnderlayTransportId(pub u32);

impl From<u32> for UnderlayTransportId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<UnderlayTransportId> for u32 {
    fn from(value: UnderlayTransportId) -> Self {
        value.0
    }
}

/// An abstract transport that can carry packets to configurable destinations.
pub trait UnderlayTransport {
    /// The error type that this transport may produce.
    type Error: Error + Send + Sync + 'static;

    /// Send packets through the transport.
    ///
    /// The return type should be interpreted as meaning essentially
    /// `HashMap<PeerId, Vec<PacketMut>>`. It is set up this way to enable the caller
    /// to use iterators to transform a collection of a slightly different shape, or e.g.
    /// look up `PeerId`s on-the-fly, without having to `.collect()` into an
    /// intermediary collection.
    fn send(
        &self,
        packet_batch: impl BatchSendIter,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Receive packets from the transport.
    ///
    /// The return type should be interpreted as meaning essentially
    /// `HashMap<PeerId, Vec<PacketMut>>`, but allows for the implementation to
    /// use iterators to map a collection of a slightly different shape, or e.g. look up
    /// `PeerId`s on-the-fly, without having to `.collect()` into an intermediary
    /// collection.
    fn recv(&self) -> impl Future<Output = impl BatchRecvIter<Error = Self::Error>> + Send;
}
