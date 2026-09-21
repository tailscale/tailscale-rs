use core::{
    fmt::{Debug, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// Specification of IPv4 or IPv6 or both.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum FamilyOrBoth {
    /// Both address families; `AF_UNSPEC`.
    Both,
    /// A single address family.
    Single(Family),
}

impl Debug for FamilyOrBoth {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            FamilyOrBoth::Both => write!(f, "Both"),
            FamilyOrBoth::Single(family) => family.fmt(f),
        }
    }
}

impl From<Family> for FamilyOrBoth {
    fn from(family: Family) -> Self {
        FamilyOrBoth::Single(family)
    }
}

/// Specification of either IPv4 or IPv6.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Family {
    /// The IPv4 address family.
    Ipv4,
    /// The IPv6 address family.
    Ipv6,
}

impl TryFrom<FamilyOrBoth> for Family {
    type Error = ();

    fn try_from(value: FamilyOrBoth) -> Result<Self, Self::Error> {
        match value {
            FamilyOrBoth::Both => Err(()),
            FamilyOrBoth::Single(family) => Ok(family),
        }
    }
}

impl From<IpAddr> for Family {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Family::Ipv4,
            IpAddr::V6(_) => Family::Ipv6,
        }
    }
}
impl From<Ipv4Addr> for Family {
    fn from(_: Ipv4Addr) -> Self {
        Family::Ipv4
    }
}

impl From<Ipv6Addr> for Family {
    fn from(_: Ipv6Addr) -> Self {
        Family::Ipv6
    }
}
