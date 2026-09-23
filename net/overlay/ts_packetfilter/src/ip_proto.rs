/// An IP protocol number.
///
/// Typically, these would be `u8`, but Tailscale packet filters accept arbitrary `int`
/// values beyond the `u8` range to define Tailscale-specific semantics.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpProto(i64);

impl IpProto {
    /// Protocol number for ICMP.
    pub const ICMP: Self = Self(1);
    /// Protocol number for ICMPv6.
    pub const ICMPV6: Self = Self(58);
    /// Protocol number for TCP.
    pub const TCP: Self = Self(6);
    /// Protocol number for UDP.
    pub const UDP: Self = Self(17);

    /// Construct a new [`IpProto`] of the given value.
    pub const fn new(value: i64) -> Self {
        Self(value)
    }
}

impl From<i64> for IpProto {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl From<IpProto> for i64 {
    fn from(value: IpProto) -> Self {
        value.0
    }
}
