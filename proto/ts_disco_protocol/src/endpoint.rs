use core::{
    cmp::Ordering,
    fmt::Debug,
    hash::Hash,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
};

use zerocopy::NetworkEndian;

/// An endpoint included in a [`CallMeMaybe`][crate::CallMeMaybe] message: a socket address
/// on which this node believes it's reachable.
///
/// All addresses are encoded as IPv6: IPv4 is mapped.
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    zerocopy::Immutable,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
    zerocopy::KnownLayout,
)]
#[repr(C, packed)]
pub struct Endpoint {
    addr: [zerocopy::U16<NetworkEndian>; 8],
    port: zerocopy::U16<NetworkEndian>,
}

impl Debug for Endpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.socket_addr().fmt(f)
    }
}

impl Endpoint {
    /// Report the address part of this endpoint.
    ///
    /// Does not unwrap IPv4-mapped IPv6: this is just the literal value in the endpoint.
    pub const fn addr_v6(&self) -> Ipv6Addr {
        Ipv6Addr::new(
            self.addr[0].get(),
            self.addr[1].get(),
            self.addr[2].get(),
            self.addr[3].get(),
            self.addr[4].get(),
            self.addr[5].get(),
            self.addr[6].get(),
            self.addr[7].get(),
        )
    }

    /// Report the address part of this endpoint with any IPv4-in-IPv6 mapping unwrapped.
    pub const fn addr(&self) -> IpAddr {
        let addr = self.addr_v6();

        match addr.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(addr),
        }
    }

    /// Report the port part of this endpoint.
    pub const fn port(&self) -> u16 {
        self.port.get()
    }

    /// Return this endpoint as a [`SocketAddrV6`].
    pub const fn socket_addr_v6(&self) -> SocketAddrV6 {
        SocketAddrV6::new(self.addr_v6(), self.port(), 0, 0)
    }

    /// Return this endpoint as a [`SocketAddr`] with any IPv4-in-IPv6 mapping unwrapped.
    pub const fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr(), self.port())
    }

    /// Construct a new value from a socket addr.
    ///
    /// Applies IPv4 to IPv6 mapping.
    pub const fn from_socket_addr(sa: SocketAddr) -> Self {
        let ip = match sa.ip() {
            IpAddr::V4(sa) => sa.to_ipv6_mapped(),
            IpAddr::V6(sa) => sa,
        };

        Self {
            addr: zerocopy::transmute!(ip.octets()),
            port: zerocopy::U16::new(sa.port()),
        }
    }
}

impl PartialOrd for Endpoint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Endpoint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.socket_addr().cmp(&other.socket_addr())
    }
}

impl From<Endpoint> for SocketAddrV6 {
    fn from(value: Endpoint) -> Self {
        value.socket_addr_v6()
    }
}

impl From<Endpoint> for SocketAddr {
    fn from(value: Endpoint) -> Self {
        value.socket_addr()
    }
}

impl From<SocketAddrV6> for Endpoint {
    fn from(value: SocketAddrV6) -> Self {
        Self {
            addr: zerocopy::transmute!(value.ip().octets()),
            port: value.port().into(),
        }
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(value: SocketAddr) -> Self {
        Self::from_socket_addr(value)
    }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use zerocopy::{FromBytes, IntoBytes};

    use super::*;

    #[test]
    fn convert_basic() {
        const BYTES: [u8; 18] = [
            0x26, 0x00, 0xab, 0xcd, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0xa5, 0xb5,
        ];

        let addr = Ipv6Addr::from_str("2600:abcd:ef01:0203:0405:0607:0809:0a0b").unwrap();
        let ep = Endpoint::read_from_bytes(&BYTES).unwrap();

        assert_eq!(ep.addr_v6(), addr);
        assert_eq!(ep.port(), 0xa5b5);

        let sa = ep.socket_addr();
        assert_eq!(sa.ip(), IpAddr::V6(addr));
        assert_eq!(sa.port(), 0xa5b5);

        let ep2 = Endpoint::from(sa);
        assert_eq!(ep2, ep);
        assert_eq!(ep2.as_bytes(), BYTES);
    }
}
