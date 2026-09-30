#![doc = include_str!("../README.md")]
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod cap_grant;
mod dst_port;
mod filter_rule;
mod ip_proto;
mod ip_range;
mod srcip;

pub use cap_grant::CapGrant;
pub use dst_port::DstPort;
pub use filter_rule::{AppRule, FilterRule, NetworkRule};
pub use ip_proto::IpProto;
pub use ip_range::IpRange;
pub use srcip::SrcIp;

/// A set of packet filtering rules that is named by a specific key.
pub type Ruleset<'a> = alloc::vec::Vec<FilterRule<'a>>;

/// A map of named rulesets, typically transmitted in a `MapResponse`.
pub type Map<'a> = alloc::collections::BTreeMap<&'a str, Option<Ruleset<'a>>>;
