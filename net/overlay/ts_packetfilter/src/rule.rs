use alloc::{string::String, vec::Vec};
use core::ops::RangeInclusive;

use crate::{IpProto, PacketInfo};

/// Alias for a collection of filter [`Rule`]s, typically stored under a single key
/// in a [`Filter`](crate::Filter).
pub type Ruleset = Vec<Rule>;

/// A network packet filter rule. Permits tailnet peers to access specific IPs
/// and ports.
///
/// Conjunctive: `src` _and_ `protos` _and_ `dst` must match for this rule to accept a
/// packet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rule {
    /// Sender info this rule applies to.
    pub src: SrcMatch,
    /// The IP protocol numbers this rule applies to.
    pub protos: Vec<IpProto>,
    /// Destination info this rule applies to.
    pub dst: Vec<DstMatch>,
}

impl Rule {
    /// Report whether this rule matches the given [`PacketInfo`] and `caps`.
    ///
    /// This implementation is not optimized for speed.
    pub fn matches<'cap>(
        &self,
        info: &PacketInfo,
        caps: impl IntoIterator<Item = &'cap str>,
    ) -> bool {
        self.protos.contains(&info.ip_proto)
            && self.src.matches(info, caps)
            && self.dst.iter().any(|dst| dst.matches(info))
    }
}

/// Matcher for the source of a given packet.
///
/// Disjunctive: either `pfxs` or `caps` may match for this matcher to accept a packet.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct SrcMatch {
    /// The IP prefixes to match for this rule.
    pub pfxs: Vec<ipnet::IpNet>,

    /// The node capabilities to match for this rule.
    ///
    /// These are arbitrary strings provided out-of-band.
    pub caps: Vec<String>,
}

impl SrcMatch {
    /// Report whether this matcher matches the given [`PacketInfo`].
    ///
    /// This implementation is not optimized for speed.
    pub fn matches<'cap>(
        &self,
        info: &PacketInfo,
        caps: impl IntoIterator<Item = &'cap str>,
    ) -> bool {
        self.pfxs.iter().any(|pfx| pfx.contains(&info.src))
            || caps
                .into_iter()
                .any(|cap| self.caps.iter().any(|c| c == cap))
    }
}

/// Matcher for the destination of a given packet.
///
/// Conjunctive: _all_ of `protos`, `ports`, and `ips` must match for this matcher to
/// accept a packet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DstMatch {
    /// The range of ports this match applies to.
    pub ports: RangeInclusive<u16>,

    /// The destination IP prefixes this match applies to.
    pub ips: Vec<ipnet::IpNet>,
}

impl DstMatch {
    /// Report whether this matcher matches the given [`PacketInfo`].
    pub fn matches(&self, info: &PacketInfo) -> bool {
        self.ports.contains(&info.port) && self.ips.iter().any(|pfx| pfx.contains(&info.dst))
    }
}
