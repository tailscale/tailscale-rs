use core::{
    fmt::{Display, Formatter},
    net::IpAddr,
};

use ipnet::IpNet;
use nom::{Finish, IResult, Parser, branch::alt, bytes::tag, combinator::rest, sequence::preceded};

use crate::IpRange;

/// A traffic source for a [`FilterRule`][crate::FilterRule].
///
/// The type name is a misnomer: the source may not be an IP at all, it might be a
/// [`NodeCap`][ts_nodecapability::NodeCap]. The name is maintained as it is for conceptual
/// parity with the Go codebase, in which these values are a single string field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SrcIp<'a> {
    /// Satisfied if the incoming traffic is in the given range of IP addresses.
    IpRange(IpRange),
    /// Satisfied if the peer associated with the incoming traffic (discovered via
    /// `Node::capabilities` in the netmap) has the specified capability.
    NodeCap(ts_nodecapability::NodeCap<'a>),
}

impl<'a> SrcIp<'a> {
    /// Return a [`nom::Parser`] that can parse a `SrcIp` from a string, as it would appear
    /// in the netmap.
    pub fn parser() -> impl Parser<&'a str, Output = Self, Error = nom::error::Error<&'a str>> {
        alt((IpRange::parser().map(Self::from), parse_cap))
    }

    /// Construct a new `SrcIp` from the given capability string.
    pub const fn from_cap(cap: &'a str) -> Self {
        Self::NodeCap(cap)
    }
}

impl Display for SrcIp<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IpRange(r) => Display::fmt(r, f),
            SrcIp::NodeCap(cap) => write!(f, "cap:{cap}"),
        }
    }
}

impl From<IpRange> for SrcIp<'_> {
    fn from(value: IpRange) -> Self {
        Self::IpRange(value)
    }
}

impl From<IpAddr> for SrcIp<'_> {
    fn from(value: IpAddr) -> Self {
        IpRange::from(value).into()
    }
}

impl From<IpNet> for SrcIp<'_> {
    fn from(value: IpNet) -> Self {
        IpRange::from(value).into()
    }
}

impl<'a> TryFrom<&'a str> for SrcIp<'a> {
    type Error = nom::error::Error<&'a str>;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let (rest, val) = Self::parser().parse_complete(s).finish()?;
        debug_assert!(rest.is_empty());

        Ok(val)
    }
}

fn parse_cap(s: &str) -> IResult<&str, SrcIp<'_>> {
    preceded(tag("cap:"), rest)
        .map(SrcIp::NodeCap)
        .parse_complete(s)
}

impl serde::Serialize for SrcIp<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use alloc::string::ToString;
        self.to_string().serialize(serializer)
    }
}

impl<'de, 'a> serde::Deserialize<'de> for SrcIp<'a>
where
    'de: 'a,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use alloc::string::ToString;

        use serde::de::Error;

        <&'de str>::deserialize(deserializer)
            .and_then(|s| SrcIp::try_from(s).map_err(|e| Error::custom(e.to_string())))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn valid_cap() {
        assert_eq!(SrcIp::NodeCap("abc"), SrcIp::try_from("cap:abc").unwrap());
    }

    #[should_panic]
    #[test]
    fn invalid_src_ip() {
        SrcIp::try_from("abcdef").unwrap();
    }
}
