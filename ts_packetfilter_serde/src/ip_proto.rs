use core::cmp::Ordering;

/// An IP protocol number (in 0..=255), or a Tailscale-specific traffic kind (outside the `u8` range).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct IpProto(Repr);

/// Inner repr prevents users from directly constructing instances of
/// TailscaleReserved, which must not overlap with the u8 range.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
enum Repr {
    ProtoNumber(u8),
    TailscaleReserved(isize),
}

impl Ord for IpProto {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        isize::from(*self).cmp(&isize::from(*other))
    }
}

impl PartialOrd for IpProto {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl IpProto {
    /// Protocol number for ICMP.
    pub const ICMP: Self = Self::new(1);
    /// Protocol number for ICMPv6.
    pub const ICMPV6: Self = Self::new(58);
    /// Protocol number for TCP.
    pub const TCP: Self = Self::new(6);
    /// Protocol number for UDP.
    pub const UDP: Self = Self::new(17);

    /// These are the default protocols in a
    /// [`FilterRule`][super::FilterRule] if none are given: ICMP, TCP, and UDP.
    pub const NULL_DEFAULTS: &'static [IpProto] =
        &[IpProto::ICMP, IpProto::ICMPV6, IpProto::TCP, IpProto::UDP];

    /// Report whether the slice is the default set of protocols
    /// ([`NULL_DEFAULTS`][IpProto::NULL_DEFAULTS]).
    #[inline]
    pub fn is_default_set(t: impl AsRef<[Self]>) -> bool {
        let r = t.as_ref();
        r.is_empty() || r == Self::NULL_DEFAULTS
    }

    /// Construct a new protocol with the given value.
    #[inline]
    pub const fn new(val: isize) -> Self {
        if val < 0 || val > u8::MAX as isize {
            Self(Repr::TailscaleReserved(val))
        } else {
            Self(Repr::ProtoNumber(val as u8))
        }
    }

    /// If this is an actual IP protocol number, return it as a u8.
    #[inline]
    pub const fn as_proto_number(self) -> Option<u8> {
        match self.0 {
            Repr::ProtoNumber(x) => Some(x),
            _ => None,
        }
    }

    /// If this is in the Tailscale reserved range (outside of 0..=255), return the
    /// value as an isize.
    #[inline]
    pub const fn as_reserved(self) -> Option<isize> {
        match self.0 {
            Repr::TailscaleReserved(x) => Some(x),
            _ => None,
        }
    }

    /// Deserialize a `Vec` of `IpProto` as anticipated by
    /// [`FilterRule`][crate::control::FilterRule]. If the value is empty or null, returns
    /// [`NULL_DEFAULTS`][IpProto::NULL_DEFAULTS].
    pub(crate) fn deserialize_vec<'de, D>(deser: D) -> Result<alloc::vec::Vec<Self>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::Deserialize;

        let v = Option::<alloc::vec::Vec<Self>>::deserialize(deser)?.unwrap_or_default();

        if v.is_empty() {
            Ok(Self::NULL_DEFAULTS.to_vec())
        } else {
            Ok(v)
        }
    }

    /// Serde support function to use as default if value is missing.
    #[inline]
    pub(crate) fn null_defaults() -> alloc::vec::Vec<Self> {
        Self::NULL_DEFAULTS.to_vec()
    }
}

impl<'de> serde::Deserialize<'de> for IpProto {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        isize::deserialize(deserializer).map(IpProto::new)
    }
}

impl serde::Serialize for IpProto {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        isize::from(*self).serialize(serializer)
    }
}

impl From<isize> for IpProto {
    #[inline]
    fn from(value: isize) -> Self {
        Self::new(value)
    }
}

impl From<u8> for IpProto {
    #[inline]
    fn from(value: u8) -> Self {
        IpProto(Repr::ProtoNumber(value))
    }
}

impl From<IpProto> for isize {
    #[inline]
    fn from(value: IpProto) -> Self {
        match value.0 {
            Repr::ProtoNumber(value) => value as isize,
            Repr::TailscaleReserved(value) => value,
        }
    }
}

impl TryFrom<IpProto> for u8 {
    type Error = ();

    #[inline]
    fn try_from(value: IpProto) -> Result<Self, Self::Error> {
        value.as_proto_number().ok_or(())
    }
}
