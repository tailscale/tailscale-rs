#![doc = include_str!("../README.md")]

use std::net::IpAddr;

#[cfg(target_os = "macos")]
pub mod bsd;
mod family;
mod id;
#[cfg(target_os = "linux")]
pub mod linux;
mod netmon;
#[cfg(windows)]
pub mod windows;

pub use family::{Family, FamilyOrBoth};
pub use id::{InterfaceId, MonType};
pub use netmon::{BoxStream, Netmon, PlatformMon, platform_mon};

/// An event produced by the network monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The given address on the given interface has been added or modified.
    ///
    /// Modification is possible when the [`Netmon`] impl has [`Netmon::interface_unique_addrs`].
    AddrUpsert(InterfaceId, ipnet::IpNet),
    /// The given address has been removed from the given interface.
    AddrRemoved(InterfaceId, ipnet::IpNet),

    /// This network interface has been added or modified.
    InterfaceUpsert(Interface),

    /// The network interface with the given id has been removed.
    InterfaceRemoved(InterfaceId),

    /// This route has been added to or modified on the given interface.
    RouteUpsert(InterfaceId, Route),

    /// This route has been removed from the given interface.
    RouteRemoved(InterfaceId, Route),

    /// A new default route interface has been selected, or there is no default route
    /// interface anymore.
    DefaultRouteInterface(Option<InterfaceId>, Family),
}

/// Details about a network interface.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Interface {
    /// The id of the interface.
    pub id: InterfaceId,

    /// Whether the interface is up and accepting traffic.
    pub up: bool,

    /// The name of the interface.
    pub name: String,

    /// The MTU of the interface.
    pub mtu: Option<usize>,

    /// The interface's hardware address (if set).
    pub hardware_addr: Option<smallvec::SmallVec<[u8; 6]>>,
}

/// The unique/identifying part of a [`Route`] (excludes the metric field).
pub type RouteUnique = (ipnet::IpNet, smallvec::SmallVec<[IpAddr; 1]>);

/// A route definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Route {
    /// The destination subnet specified by the route.
    pub dst: ipnet::IpNet,
    /// The gateways (next-hops) to use for this route in descending order of preference.
    ///
    /// Currently, this field is only ever populated by zero (implying the route is
    /// on-link) or one addresses, but multipath implies that there could be any number of
    /// gateways for a given route.
    pub gateway: smallvec::SmallVec<[IpAddr; 1]>,
    /// The metric for this route. Lower is higher-preference.
    pub metric: usize,
}

impl Route {
    /// Report whether this is a default route.
    ///
    /// Default routes have a zero prefix length on their destination (handle all addresses)
    /// and must have a gateway (i.e. the destination prefix is not on-link).
    pub fn is_default_route(&self) -> bool {
        self.dst.prefix_len() == 0 && !self.gateway.is_empty()
    }

    /// Report the address family to which this route pertains.
    pub fn family(&self) -> Family {
        if self.dst.addr().is_ipv4() {
            Family::Ipv4
        } else {
            Family::Ipv6
        }
    }

    /// The unique identifying tuple of this [`Route`].
    pub fn unique(&self) -> RouteUnique {
        (self.dst, self.gateway.clone())
    }

    /// A reference to the fields of the unique identifying tuple of this [`Route`].
    pub const fn unique_ref(&self) -> (&ipnet::IpNet, &smallvec::SmallVec<[IpAddr; 1]>) {
        (&self.dst, &self.gateway)
    }
}
