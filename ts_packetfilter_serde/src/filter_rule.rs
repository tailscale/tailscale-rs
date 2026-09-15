use alloc::vec::Vec;

use serde::de::Error;

use crate::{CapGrant, DstPort, IpProto, SrcIp};

/// A filter rule delivered in `MapResponse::packet_filters`.
///
/// The type name is somewhat of a misnomer because application-level capabilities (peer
/// caps) are shoved into this type as well, which have nothing to do with _packets_ (at
/// L3) or filtering, necessarily.
///
/// This implementation deviates from the Go codebase by categorically separating the two
/// kinds at parse time.
#[derive(Debug, Clone, PartialEq, Hash, serde::Serialize)]
#[serde(untagged)]
pub enum FilterRule<'a> {
    /// A rule that grants network access from certain IPs and node caps to a set of
    /// IPs and ports on selected IP protocol numbers.
    Network(NetworkRule<'a>),

    /// A separate kind of rule that indicates that application traffic from the specified
    /// sources should be granted an arbitrary set of user-defined capabilities (peercaps).
    /// Has no impact on layer 3 or 4 networking operation.
    #[serde(borrow)]
    Application(AppRule<'a>),
}

// Provide a custom deserialize to avoid the hard-to-predict guessing behavior from
// #[serde(untagged)]
impl<'a, 'de: 'a> serde::Deserialize<'de> for FilterRule<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct DeserFilterRule<'a> {
            // shared field:
            #[serde(rename = "SrcIPs", borrow)]
            src_ips: Vec<SrcIp<'a>>,

            // network fields:
            #[serde(rename = "IPProto", default)]
            ip_proto: Option<Vec<IpProto>>,
            #[serde(default)]
            dst_ports: Option<Vec<DstPort>>,

            // app field:
            #[serde(borrow, default)]
            cap_grant: Option<Vec<CapGrant<'a>>>,
        }

        let DeserFilterRule {
            src_ips,
            ip_proto,
            dst_ports,
            cap_grant,
        } = DeserFilterRule::deserialize(deserializer)?;

        match (cap_grant, dst_ports, ip_proto) {
            (Some(cap_grant), None, None) => {
                Ok(FilterRule::Application(AppRule { src_ips, cap_grant }))
            }

            (None, dst_ports, ip_proto) if dst_ports.is_some() || ip_proto.is_some() => {
                let mut ip_proto = ip_proto.unwrap_or_else(IpProto::null_defaults);
                if ip_proto.is_empty() {
                    ip_proto = IpProto::null_defaults();
                }

                Ok(FilterRule::Network(NetworkRule {
                    src_ips,
                    ip_proto,
                    dst_ports: dst_ports.unwrap_or_default(),
                }))
            }

            _otherwise => Err(D::Error::custom("ambiguous filter rule")),
        }
    }
}

impl<'a> From<AppRule<'a>> for FilterRule<'a> {
    fn from(value: AppRule<'a>) -> Self {
        FilterRule::Application(value)
    }
}

impl<'a> From<NetworkRule<'a>> for FilterRule<'a> {
    fn from(value: NetworkRule<'a>) -> Self {
        FilterRule::Network(value)
    }
}

/// A network packet filter rule. Permits tailnet peers to access specific IPs and ports.
#[derive(Debug, Clone, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkRule<'a> {
    /// The traffic sources which match for this rule.
    #[serde(rename = "SrcIPs", borrow)]
    pub src_ips: Vec<SrcIp<'a>>,

    /// The [`IpProto`]s that match for this rule.
    #[serde(
        rename = "IPProto",
        skip_serializing_if = "IpProto::is_default_set",
        deserialize_with = "IpProto::deserialize_vec",
        default = "IpProto::null_defaults"
    )]
    pub ip_proto: Vec<IpProto>,

    /// IP ranges and ports that match for this rule.
    pub dst_ports: Vec<DstPort>,
}

impl Default for NetworkRule<'_> {
    fn default() -> Self {
        Self {
            src_ips: Default::default(),
            ip_proto: IpProto::NULL_DEFAULTS.to_vec(),
            dst_ports: Default::default(),
        }
    }
}

/// A packet filter rule that describes application capabilities between Tailscale-aware
/// peers.
///
/// No effect at the network layer, does not affect routing or packet filtering.
#[derive(Debug, Clone, PartialEq, Hash, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AppRule<'a> {
    /// Principals to which to grant the caps in `cap_grant`.
    #[serde(rename = "SrcIPs", borrow)]
    pub src_ips: Vec<SrcIp<'a>>,

    /// Capability names and values
    #[serde(borrow)]
    pub cap_grant: Vec<CapGrant<'a>>,
}

impl<'a> FilterRule<'a> {
    /// Get a reference to the contained [`NetworkRule`] if this is one.
    pub const fn as_network(&self) -> Option<&NetworkRule<'a>> {
        match self {
            FilterRule::Network(r) => Some(r),
            _ => None,
        }
    }

    /// Convert this into a [`NetworkRule`] if it is one.
    pub fn into_network(self) -> Option<NetworkRule<'a>> {
        match self {
            FilterRule::Network(r) => Some(r),
            _ => None,
        }
    }

    /// Get a reference to the contained [`AppRule`] if this is one.
    pub const fn as_app(&self) -> Option<&AppRule<'a>> {
        match self {
            FilterRule::Application(r) => Some(r),
            _ => None,
        }
    }

    /// Convert this into an [`AppRule`] if it is one.
    pub fn into_app(self) -> Option<AppRule<'a>> {
        match self {
            FilterRule::Application(r) => Some(r),
            _ => None,
        }
    }

    /// Report whether this is a [`NetworkRule`].
    pub const fn is_network(&self) -> bool {
        matches!(self, FilterRule::Network(_))
    }

    /// Report whether this is an [`AppRule`].
    pub const fn is_app(&self) -> bool {
        matches!(self, FilterRule::Application(_))
    }
}

#[cfg(test)]
mod test {
    use core::net::IpAddr;

    use ipnet::IpNet;

    use crate::{
        CapGrant, DstPort, IpProto, IpRange, SrcIp,
        filter_rule::{AppRule, FilterRule, NetworkRule},
    };

    type BoxResult<T> = Result<T, alloc::boxed::Box<dyn core::error::Error>>;

    const TEST_EMPTY_CAPGRANT: &str = r#"{
        "SrcIPs": [],
        "CapGrant": []
    }"#;

    const TEST_EMPTY_DST_PORTS: &str = r#"{
        "SrcIPs": [],
        "DstPorts": []
    }"#;

    const TEST_CAP_GRANT: &str = r#"{
        "SrcIPs": [
            "*",
            "100.100.100.100",
            "ffff::",
            "100.0.0.0/8",
            "ffff::/16",
            "ffef::-ffff::",
            "100.100.100.100-100.100.100.101",
            "cap:tailscale.com/zzz"
        ],
        "CapGrant": [
            {
                "Dsts": [
                    "123.123.0.0/16",
                    "ffef::/24"
                ],
                "CapMap": {
                    "tailscale.com/abc": [{}, [], "abc"]
                }
            },
            {
                "Dsts": [
                    "123.123.0.0/16",
                    "ffef::/24"
                ],
                "CapMap": {
                    "tailscale.com/xyz": []
                }
            }
        ]
    }"#;

    const TEST_DST_PORTS: &str = r#"{
        "SrcIPs": [
            "*",
            "100.100.100.100",
            "ffff::",
            "100.0.0.0/8",
            "ffff::/16",
            "ffef::-ffff::",
            "100.100.100.100-100.100.100.101",
            "cap:tailscale.com/zzz"
        ],
        "IPProto": [
            1, 3, 12, 32, 128, -41239, 103845812, 0
        ],
        "DstPorts": [
            {
                "IP": "1.2.3.4",
                "Ports": {
                    "First": 32,
                    "Last": 128
                }
            },
            {
                "IP": "0.0.0.0/0",
                "Ports": {
                    "First": 80,
                    "Last": 80
                }
            },
            {
                "IP": "1::-2::",
                "Ports": {
                    "First": 1,
                    "Last": 65535
                }
            },
            {
                "IP": "*",
                "Ports": {
                    "First": 312,
                    "Last": 4000
                }
            }
        ]
    }"#;

    fn test_roundtrip<'a, 'j>(json: &'j str, expected: FilterRule<'a>) -> BoxResult<()>
    where
        'j: 'a,
    {
        let raw_json = serde_json::from_str::<serde_json::Value>(json)?;
        let parsed = serde_json::from_str::<FilterRule>(json)?;

        std::println!("parsed: {parsed:#?}");

        assert_eq!(expected, parsed);

        let reencoded = serde_json::to_value(&parsed)?;
        assert_eq!(raw_json, reencoded);

        Ok(())
    }

    #[test]
    fn empty_net_rule() -> BoxResult<()> {
        test_roundtrip(
            TEST_EMPTY_DST_PORTS,
            FilterRule::Network(NetworkRule::default()),
        )
    }

    #[test]
    fn empty_app_rule() -> BoxResult<()> {
        test_roundtrip(
            TEST_EMPTY_CAPGRANT,
            FilterRule::Application(AppRule::default()),
        )
    }

    #[test]
    #[allow(deprecated)]
    fn cap_grant() -> BoxResult<()> {
        let expected = FilterRule::Application(AppRule {
            src_ips: alloc::vec![
                IpRange::Wildcard.into(),
                SrcIp::from("100.100.100.100".parse::<IpAddr>()?),
                SrcIp::from("ffff::".parse::<IpAddr>()?),
                SrcIp::from("100.0.0.0/8".parse::<IpNet>()?),
                SrcIp::from("ffff::/16".parse::<IpNet>()?),
                IpRange::Range("ffef::".parse()?..="ffff::".parse()?).into(),
                IpRange::Range("100.100.100.100".parse()?..="100.100.100.101".parse()?).into(),
                SrcIp::NodeCap("tailscale.com/zzz"),
            ],
            cap_grant: alloc::vec![
                CapGrant {
                    dsts: alloc::vec!["123.123.0.0/16".parse()?, "ffef::/24".parse()?],
                    peer_caps: ts_peercapability::Map::from([(
                        "tailscale.com/abc".into(),
                        (&["{}", "[]", r#""abc""#]).into(),
                    )]),
                },
                CapGrant {
                    dsts: alloc::vec!["123.123.0.0/16".parse()?, "ffef::/24".parse()?],
                    peer_caps: ts_peercapability::Map::from([(
                        "tailscale.com/xyz".into(),
                        (&[]).into()
                    )]),
                },
            ],
        });

        test_roundtrip(TEST_CAP_GRANT, expected)
    }

    #[test]
    #[allow(deprecated)]
    fn dst_ports() -> BoxResult<()> {
        let expected = FilterRule::Network(NetworkRule {
            src_ips: alloc::vec![
                IpRange::Wildcard.into(),
                SrcIp::from("100.100.100.100".parse::<IpAddr>()?),
                SrcIp::from("ffff::".parse::<IpAddr>()?),
                SrcIp::from("100.0.0.0/8".parse::<IpNet>()?),
                SrcIp::from("ffff::/16".parse::<IpNet>()?),
                IpRange::Range("ffef::".parse()?..="ffff::".parse()?).into(),
                IpRange::Range("100.100.100.100".parse()?..="100.100.100.101".parse()?).into(),
                SrcIp::NodeCap("tailscale.com/zzz"),
            ],

            ip_proto: [1isize, 3, 12, 32, 128, -41239, 103845812, 0]
                .into_iter()
                .map(IpProto::from)
                .collect(),

            dst_ports: alloc::vec![
                DstPort {
                    ip: "1.2.3.4".try_into()?,
                    ports: 32..=128,
                },
                DstPort {
                    ip: "0.0.0.0/0".try_into()?,
                    ports: 80..=80,
                },
                DstPort {
                    ip: "1::-2::".try_into()?,
                    ports: 1..=65535,
                },
                DstPort {
                    ip: "*".try_into()?,
                    ports: 312..=4000,
                },
            ],
        });

        test_roundtrip(TEST_DST_PORTS, expected)
    }
}
