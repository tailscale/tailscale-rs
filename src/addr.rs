//! Traits that extend [`IpAddr`](core::net::IpAddr) and [`SocketAddr`](core::net::SocketAddr) with
//! Tailnet-specific methods.

use core::net::{IpAddr, SocketAddr};

/// Helper methods to determine if an IP address is in the correct IPv4 or IPv6 range to be a
/// tailnet address.
pub trait TailnetAddr {
    /// Returns whether this IP address is in the correct range to be a tailnet address.
    ///
    /// For IPv4 addresses, returns `true` if the address is in the range `100.64.0.0/10` (the CGNAT
    /// address space). For IPv6 addresses, returns `true` if the address is in the range
    /// `FD7A:115C:A1EO::/48`. Otherwise, returns `false`.
    fn is_tailnet_addr(&self) -> bool;

    /// Returns `true` if this is an IPv4 address in the range `100.64.0.0/10` (the CGNAT address
    /// space); otherwise, returns `false`.
    fn is_tailnet_v4(&self) -> bool;

    /// Returns `true` if this is an IPv6 address in the range `FD7A:115C:A1EO::/48`; otherwise,
    /// returns `false`.
    fn is_tailnet_v6(&self) -> bool;
}

impl TailnetAddr for IpAddr {
    /// Returns whether this [IpAddr] is in the correct range to be a tailnet address.
    ///
    /// For [IpAddr::V4] addresses, returns `true` if the address is in the range `100.64.0.0/10`
    /// (the CGNAT address space). For [IpAddr::V6] addresses, returns `true` if the address is in
    /// the range `FD7A:115C:A1EO::/48`. Otherwise, returns `false`.
    fn is_tailnet_addr(&self) -> bool {
        self.is_tailnet_v4() || self.is_tailnet_v6()
    }

    /// Returns `true` if this is an [IpAddr::V4] address in the range `100.64.0.0/10` (the CGNAT
    /// address space); otherwise, returns `false`.
    fn is_tailnet_v4(&self) -> bool {
        match self {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127
            }
            _ => false,
        }
    }

    /// Returns `true` if this is an [IpAddr::V6] address in the range `FD7A:115C:A1EO::/48`;
    /// otherwise, returns `false`.
    fn is_tailnet_v6(&self) -> bool {
        match self {
            IpAddr::V6(addr) => {
                let octets = addr.octets();
                octets[0] == 0xFD
                    && octets[1] == 0x7A
                    && octets[2] == 0x11
                    && octets[3] == 0x5C
                    && octets[4] == 0xA1
                    && octets[5] == 0xE0
            }
            _ => false,
        }
    }
}

impl TailnetAddr for SocketAddr {
    /// Returns whether the IP address of this [SocketAddr] is in the correct range to be a tailnet
    /// address.
    ///
    /// For [SocketAddr::V4] addresses, returns `true` if the address is in the range
    /// `100.64.0.0/10` (the CGNAT address space). For [SocketAddr::V6] addresses, returns `true` if
    /// the address is in the range `FD7A:115C:A1EO::/48`. Otherwise, returns `false`.
    fn is_tailnet_addr(&self) -> bool {
        self.is_tailnet_v4() || self.is_tailnet_v6()
    }

    /// Returns `true` if this is a [SocketAddr::V4] address in the range `100.64.0.0/10` (the CGNAT
    /// address space); otherwise, returns `false`.
    fn is_tailnet_v4(&self) -> bool {
        self.ip().is_tailnet_v4()
    }

    /// Returns `true` if this is a [SocketAddr::V6] address in the range `FD7A:115C:A1EO::/48`;
    /// otherwise, returns `false`.
    fn is_tailnet_v6(&self) -> bool {
        self.ip().is_tailnet_v6()
    }
}
