use core::ops::RangeInclusive;

use crate::IpRange;

/// A range of ports allowed for one or more IPs.
///
/// The IP protocols the permission applies to are specified in
/// [`NetworkRule`][crate::NetworkRule].
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DstPort {
    /// IPs on which access to `ports` is permitted.
    #[serde(rename = "IP")]
    pub ip: IpRange,

    /// Ports that may be accessed on the given `ip`s.
    #[serde(with = "port_range")]
    pub ports: RangeInclusive<u16>,
}

mod port_range {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct PortRange {
        first: u16,
        last: u16,
    }

    pub fn serialize<S>(t: &RangeInclusive<u16>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        PortRange {
            first: *t.start(),
            last: *t.end(),
        }
        .serialize(s)
    }

    pub fn deserialize<'de, D>(de: D) -> Result<RangeInclusive<u16>, D::Error>
    where
        D: Deserializer<'de>,
    {
        PortRange::deserialize(de).map(|r| r.first..=r.last)
    }
}
