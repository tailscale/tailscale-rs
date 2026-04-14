use alloc::boxed::Box;
use core::{
    fmt::{Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
    str::FromStr,
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use nom::{
    Finish, IResult, Parser,
    branch::alt,
    bytes::is_not,
    character::char,
    combinator::{rest, value},
    sequence::separated_pair,
};

/// A range of IPs in the various formats in which they might appear.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpRange {
    /// Match all addresses. `*` in serialized form.
    Wildcard,
    /// A subnet defined by an address with a mask of a given length.
    Prefix(IpNet),
    /// A range of IP addresses defined by a start and end address.
    Range(RangeInclusive<IpAddr>),
}

impl IpRange {
    /// Report whether this IP range contains the given address.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Prefix(pfx) => pfx.contains(ip),
            Self::Range(range) => range.contains(ip),
        }
    }

    /// Return a [`nom::Parser`] for an `IpRange`, which can parse it from a string in
    /// the format in which it appears in a `MapResponse`.
    ///
    /// The [`Display`] impl for this type roundtrips with the parser.
    #[inline]
    pub fn parser<'a>()
    -> impl Parser<&'a str, Output = Self, Error = nom::error::Error<&'a str>> + 'static {
        alt((parse_wildcard, parse_range, parse_prefix))
    }

    /// Iterate all prefixes covered by this `IpRange`.
    ///
    /// The iterator is well-behaved even in the [`IpRange::Range`] case: it selects the
    /// largest subnets possible, so the maximum number of elements yielded is in
    /// `O(log(n))` for `n` the number of addresses in the range. (Thanks to [`ipnet`]!)
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_packetfilter_serde::IpRange;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Small ranges have a trivial prefix representation.
    /// let tiny_range = IpRange::Range("127.0.0.1".parse()?..="127.0.0.1".parse()?);
    /// let pfxs = tiny_range.iter_prefixes().collect::<Vec<_>>();
    /// assert_eq!(pfxs.len(), 1);
    /// assert_eq!(pfxs[0], "127.0.0.1/32".parse()?);
    ///
    /// // Likewise with large ranges.
    /// let big_range = IpRange::Range("0.0.0.0".parse()?..="255.255.255.255".parse()?);
    /// let pfxs = big_range.iter_prefixes().collect::<Vec<_>>();
    /// assert_eq!(pfxs.len(), 1);
    /// assert_eq!(pfxs[0], "0.0.0.0/0".parse()?);
    ///
    /// // Even a range between addresses that differ in all octets has a relatively compact
    /// // set of prefixes.
    /// let weird_range = IpRange::Range("1.2.3.4".parse()?..="2.3.4.5".parse()?);
    /// let pfxs = weird_range.iter_prefixes().collect::<Vec<_>>();
    /// assert_eq!(pfxs.len(), 24);
    /// # Ok(())
    /// # }
    /// ```
    pub fn iter_prefixes(&self) -> impl Iterator<Item = IpNet> {
        match self {
            Self::Wildcard => Box::new(
                [
                    Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 0).into(),
                    Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 1).into(),
                ]
                .into_iter(),
            ) as Box<dyn Iterator<Item = IpNet>>,
            &Self::Prefix(pfx) => Box::new(core::iter::once(pfx)),
            Self::Range(range) => Box::new(match (*range.start(), *range.end()) {
                (IpAddr::V4(start), IpAddr::V4(end)) => {
                    Box::new(ipnet::Ipv4Subnets::new(start, end, 0).map(IpNet::from))
                        as Box<dyn Iterator<Item = IpNet>>
                }
                (IpAddr::V6(start), IpAddr::V6(end)) => {
                    Box::new(ipnet::Ipv6Subnets::new(start, end, 0).map(IpNet::from))
                }
                _ => unreachable!(),
            }),
        }
    }
}

impl Display for IpRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wildcard => write!(f, "*"),
            Self::Range(range) => write!(f, "{}-{}", range.start(), range.end()),
            Self::Prefix(net) if net.prefix_len() == net.max_prefix_len() => {
                write!(f, "{}", net.addr())
            }
            Self::Prefix(net) => write!(f, "{net}"),
        }
    }
}

impl From<IpAddr> for IpRange {
    #[inline]
    fn from(value: IpAddr) -> Self {
        Self::Prefix(value.into())
    }
}

impl From<IpNet> for IpRange {
    #[inline]
    fn from(value: IpNet) -> Self {
        Self::Prefix(value.trunc())
    }
}

impl<'a> TryFrom<&'a str> for IpRange {
    type Error = nom::error::Error<&'a str>;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        let (rest, val) = Self::parser().parse_complete(s).finish()?;

        debug_assert!(rest.is_empty());

        Ok(val)
    }
}

#[inline]
fn parse_wildcard(s: &str) -> IResult<&str, IpRange> {
    value(IpRange::Wildcard, char('*')).parse_complete(s)
}

fn parse_range(s: &str) -> IResult<&str, IpRange> {
    separated_pair(
        is_not("-").map_res(IpAddr::from_str),
        char('-'),
        rest.map_res(IpAddr::from_str),
    )
    .map_opt(|(x, y)| (x.is_ipv4() == y.is_ipv4()).then_some((x, y)))
    .map(|(x, y)| IpRange::Range(RangeInclusive::new(x, y)))
    .parse_complete(s)
}

fn parse_prefix(s: &str) -> IResult<&str, IpRange> {
    alt((
        rest.map_res(IpNet::from_str),
        rest.map_res(IpAddr::from_str).map(IpNet::from),
    ))
    .map(|n| IpRange::Prefix(n.trunc()))
    .parse_complete(s)
}

impl serde::Serialize for IpRange {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use alloc::string::ToString;
        self.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for IpRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use alloc::string::ToString;

        use serde::de::Error;

        <&'de str>::deserialize(deserializer)
            .and_then(|s| IpRange::try_from(s).map_err(|e| Error::custom(e.to_string())))
    }
}

#[cfg(test)]
mod test {
    use alloc::string::ToString;
    use core::net::{Ipv4Addr, Ipv6Addr};

    use ipnet::IpNet;
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn valid_src_ip() {
        assert_eq!(
            IpRange::Prefix(IpNet::new_assert(Ipv4Addr::new(127, 0, 0, 1).into(), 32)),
            IpRange::try_from("127.0.0.1").unwrap()
        );

        assert_eq!(
            IpRange::Prefix(IpNet::new_assert(Ipv4Addr::new(1, 0, 0, 0).into(), 8)),
            IpRange::try_from("1.0.0.0/8").unwrap()
        );

        assert_eq!(IpRange::Wildcard, IpRange::try_from("*").unwrap());
    }

    #[should_panic]
    #[test]
    fn invalid_src_ip() {
        IpRange::try_from("abcdef").unwrap();
    }

    #[test]
    #[should_panic]
    fn mismatched_ip_kinds() {
        IpRange::try_from("127.0.0.1-ffef::").unwrap();
    }

    #[test]
    fn sanity_check_weird_range() {
        let weird_range = IpRange::Range("1.2.3.4".parse().unwrap()..="2.3.4.5".parse().unwrap());
        let pfxs = weird_range.iter_prefixes().collect::<alloc::vec::Vec<_>>();
        assert_eq!(pfxs.len(), 24);
        std::println!("{pfxs:#?}");
    }

    fn any_prefix() -> impl Strategy<Value = IpNet> {
        (any::<IpAddr>(), any::<u8>()).prop_map(|(addr, len)| {
            let max_prefix_len = if addr.is_ipv4() { 32 } else { 128 };
            let len = len % max_prefix_len;

            IpNet::new_assert(addr, len).trunc()
        })
    }

    fn any_range() -> impl Strategy<Value = IpRange> {
        prop_oneof![
            (any::<Ipv4Addr>(), any::<Ipv4Addr>()).prop_map(|(mut x, mut y)| {
                if x > y {
                    core::mem::swap(&mut x, &mut y);
                }

                IpRange::Range(x.into()..=y.into())
            }),
            (any::<Ipv6Addr>(), any::<Ipv6Addr>()).prop_map(|(mut x, mut y)| {
                if x > y {
                    core::mem::swap(&mut x, &mut y);
                }

                IpRange::Range(x.into()..=y.into())
            }),
        ]
    }

    fn any_iprange() -> impl Strategy<Value = IpRange> {
        prop_oneof![
            any_prefix().prop_map(IpRange::Prefix),
            any_range(),
            Just(IpRange::Wildcard),
        ]
    }

    proptest! {
        #[test]
        fn roundtrip(range in any_iprange()) {
            let formatted = range.to_string();
            let reparsed = IpRange::try_from(formatted.as_str()).unwrap();

            assert_eq!(range, reparsed);
        }
    }
}
