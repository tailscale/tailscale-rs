#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

use core::fmt::{Debug, Display, Formatter};

mod batch_iter;
mod endpoint;
mod overlay;
mod underlay;

pub use batch_iter::{BatchRecvIter, BatchSendIter};
pub use endpoint::{DerpEndpoint, DynEndpoint, DynOrd, Endpoint, EndpointStorage, UdpEndpoint};
pub use overlay::{OverlayTransport, OverlayTransportId};
pub use underlay::{UnderlayTransport, UnderlayTransportId};

pub extern crate smallbox;

/// The unique id of a peer.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub u32);

impl Display for PeerId {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(self, f)
    }
}
