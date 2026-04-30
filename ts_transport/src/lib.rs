#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

use core::{
    error::Error,
    fmt::{Debug, Display, Formatter},
};

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

/// The unique id of a peer.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub u32);

impl Display for PeerId {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(self, f)
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
    fn send<BatchIter, PacketIter>(
        &self,
        packet_batch: BatchIter,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        BatchIter: IntoIterator<Item = (PeerId, PacketIter)> + Send,
        BatchIter::IntoIter: Send,
        PacketIter: IntoIterator<Item = PacketMut> + Send,
        PacketIter::IntoIter: Send;

    /// Receive packets from the transport.
    ///
    /// The return type should be interpreted as meaning essentially
    /// `HashMap<PeerId, Vec<PacketMut>>`, but allows for the implementation to
    /// use iterators to map a collection of a slightly different shape, or e.g. look up
    /// `PeerId`s on-the-fly, without having to `.collect()` into an intermediary
    /// collection.
    fn recv(
        &self,
    ) -> impl Future<
        Output = impl IntoIterator<
            Item = Result<(PeerId, impl IntoIterator<Item = PacketMut>), Self::Error>,
        >,
    > + Send;
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
