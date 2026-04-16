use alloc::collections::BTreeMap;
use core::{
    fmt,
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::{NonZero, NonZeroU32},
    str::FromStr,
};

use serde::{Deserializer, Serializer};

/// The default port to use to perform STUN with a DERP server.
pub const DEFAULT_STUN_PORT: u16 = 3478;

/// A unique integer ID representing a geographical DERP region. Must be positive, non-zero, and
/// guaranteed to fit in a Javascript number.
///
/// IDs in the range 900-999 are reserved for end users to run their own DERP nodes.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct RegionId(NonZero<u32>);

impl Display for RegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.get())
    }
}

impl From<NonZero<u32>> for RegionId {
    fn from(value: NonZero<u32>) -> Self {
        Self(value)
    }
}

impl From<RegionId> for NonZeroU32 {
    fn from(value: RegionId) -> Self {
        value.0
    }
}

impl From<RegionId> for u32 {
    fn from(value: RegionId) -> Self {
        value.0.get()
    }
}

/// Describes a DERP packet relay server running within a [`Region`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DerpServer<'a> {
    /// A unique server name (across all regions). It is NOT a host name. Typically of the form
    /// `<region ID><suffix>`, e.g. "1b", "2a", "3b".
    #[serde(borrow)]
    pub name: &'a str,
    /// The [`RegionId`] of the [`Region`] that this [`DerpServer`] is running in.
    #[serde(rename = "RegionID")]
    pub region_id: RegionId,
    /// The hostname of this [`DerpServer`]. This field is required to be present, but may not be
    /// unique; multiple servers may have the same [`DerpServer::hostname`] but otherwise vary in
    /// configuration.
    #[serde(rename = "HostName", borrow)]
    pub hostname: &'a str,

    /// If populated, specifies this [`DerpServer`]'s expected TLS certificate common name. When
    /// populated, a Tailscale node should use this field to validate the DERP server's TLS
    /// certificate, and only use the [`DerpServer::hostname`] field for the initial TLS
    /// `ClientHello` packet, and the initial TCP connection if the [`DerpServer::ipv4`] and
    /// [`DerpServer::ipv6`] fields are `None`.
    ///
    /// If this field starts with `"sha256-raw:"`, the remainder of the string is a hex-encoded
    /// SHA256 of the certificate to expect; this format is used for validating self-signed
    /// certificates. In this case, the [`DerpServer::hostname`] field will typically be an IPv4 or
    /// IPv6 address literal.
    ///
    /// If `None`, the Tailscale node should use [`DerpServer::hostname`] instead.
    #[serde(borrow, default)]
    pub cert_name: Option<&'a str>,

    /// How a Tailscale node should resolve this server's IPv4 address.
    #[serde(rename = "IPv4", default)]
    pub ipv4: IpUsage<Ipv4Addr>,

    /// How a Tailscale node should resolve this server's IPv6 address.
    #[serde(rename = "IPv6", default)]
    pub ipv6: IpUsage<Ipv6Addr>,

    /// The port on the [`DerpServer`] listening for STUN binding requests. If not provided,
    /// defaults to `StunPort::Port(3478)`. If `StunPort::Disabled`, STUN is disabled on the
    /// server.
    #[serde(default, rename = "STUNPort")]
    pub stun_port: StunPort,
    /// Indicates this server is only a STUN server, and not a DERP server capable of relaying
    /// packets.
    #[serde(default, rename = "STUNOnly")]
    pub stun_only: bool,
    /// Optionally provides an alternate TLS port number for the DERP HTTPS server. If zero, port
    /// 443 is used.
    #[serde(default, rename = "DERPPort")]
    pub derp_port: u16,

    /// Used by unit tests to disable TLS verification. Do NOT set this on production servers or
    /// custom/private DERP servers. It should not be set by users.
    #[serde(default)]
    pub insecure_for_tests: bool,
    /// Used in tests to override the STUN server's IP address. If empty, it's assumed to be the
    /// same IP address as the DERP server.
    #[serde(default, rename = "STUNTestIP")]
    pub stun_test_ip: Option<IpAddr>,
    /// Indicates whether this DERP node is accessible over HTTP on TCP port 80. This is used for
    /// captive portal checks.
    #[serde(default)]
    pub can_port_80: bool,
}

/// The port on the DERP server listening for STUN binding requests, or if STUN is disabled on this
/// DERP server. Defaults to [`StunPort::Port(3478)`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum StunPort {
    /// STUN is disabled on the DERP server. Do not attempt to STUN with it.
    Disabled,
    /// Port on the DERP server listening for STUN binding requests.
    Port(u16),
}

impl Default for StunPort {
    fn default() -> Self {
        StunPort::Port(DEFAULT_STUN_PORT)
    }
}

impl From<StunPort> for Option<u16> {
    fn from(value: StunPort) -> Self {
        (&value).into()
    }
}

impl From<&StunPort> for Option<u16> {
    fn from(value: &StunPort) -> Self {
        match value {
            StunPort::Disabled => None,
            StunPort::Port(x) => Some(*x),
        }
    }
}

impl<'de> serde::Deserialize<'de> for StunPort {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let p = <Option<i32>>::deserialize(deserializer)?;

        match p {
            None | Some(0) => Ok(Default::default()),
            Some(-1) => Ok(StunPort::Disabled),
            Some(x) if x > 0 && x <= u16::MAX as i32 => Ok(StunPort::Port(x as u16)),
            _ => Err(serde::de::Error::custom("invalid stun port")),
        }
    }
}

impl serde::Serialize for StunPort {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Disabled => serializer.serialize_i32(-1),
            Self::Port(DEFAULT_STUN_PORT) => serializer.serialize_i32(0),
            Self::Port(p) => serializer.serialize_i32(*p as i32),
        }
    }
}

/// IP usage mode for a [`DerpServer`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum IpUsage<T> {
    /// Do not use this IP addressing mode.
    Disable,
    /// Use DNS with the hostname field to resolve the IP for this addressing mode.
    #[default]
    UseDns,
    /// Use this IP address for this addressing mode.
    FixedAddr(T),
}

impl<'de, T> serde::Deserialize<'de> for IpUsage<T>
where
    T: FromStr,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <Option<&'de str>>::deserialize(deserializer)?;

        let s = match s {
            None | Some("") => {
                return Ok(IpUsage::UseDns);
            }
            Some(s) => s,
        };

        match s.parse::<T>() {
            Ok(ip) => Ok(IpUsage::FixedAddr(ip)),
            Err(_) => Ok(IpUsage::Disable),
        }
    }
}

impl<T> serde::Serialize for IpUsage<T>
where
    T: Display,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Disable => serializer.serialize_str("none"),
            Self::UseDns => serializer.serialize_str(""),
            Self::FixedAddr(t) => serializer.serialize_str(&alloc::format!("{t}")),
        }
    }
}

/// Contains parameters from the control server related to selecting a DERP home region (sometimes
/// referred to as the "preferred DERP").
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct HomeParams {
    /// Scales latencies of DERP regions by a given scaling factor when determining which region to
    /// use as the home ("preferred") DERP. Scores in the range `(0, 1)` will cause this region to
    /// be proportionally more preferred, and scores in the range `(1, ∞)` will penalize a region.
    ///
    /// If a region is not present in this map, it is treated as having a score of `1.0`. Scores
    /// should not be 0 or negative; such scores must be ignored. A completely empty map indicates
    /// all scores should be reset to `1.0`.
    pub region_score: BTreeMap<RegionId, f64>,
}

/// A geographic region running DERP relay node(s).
///
/// Tailscale nodes discover which region they're closest to, advertise that "home" DERP region to
/// the control server, and maintain a persistent connection to one of the DERP servers in that
/// home region as long as it's the closest.
///
/// Tailscale nodes will further connect to other regions as necessary to communicate with peer
/// nodes advertising other regions as their homes.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Region<'a> {
    /// A unique integer ID for a geographic region. Corresponds to the legacy
    /// `derpN.tailscale.com` hostnames used by older versions of Tailscale nodes. Must be
    /// positive, non-zero, and guaranteed to fit in a Javascript number.
    ///
    /// IDs in the range 900-999 are reserved for end users to run their own DERP nodes.
    #[serde(rename = "RegionID")]
    pub id: RegionId,

    /// A short name for the region. It's usually a popular city or airport code in the region:
    /// "nyc", "sf", "sin", "fra", etc.
    #[serde(rename = "RegionCode", borrow)]
    pub code: &'a str,
    /// A long English name for the region: "New York City", "San Francisco", "Singapore",
    /// "Frankfurt", etc.
    #[serde(rename = "RegionName", borrow)]
    pub name: &'a str,

    /// The geographical latitude coordinate of the DERP region's city center, in degrees. Note
    /// that this is the rough center of the city, not the datacenter.
    #[serde(default)]
    pub latitude: f64,
    /// The geographical longitude coordinate of the DERP region's city center, in degrees. Note
    /// that this is the center of the city, not the datacenter.
    #[serde(default)]
    pub longitude: f64,

    /// Deprecated. Use [`Region::no_measure_no_home`] instead.
    ///
    /// Whether or not the Tailscale node should avoid picking this [`Region`] as its home
    /// region. The region should only be used if a peer is there. Tailscale nodes already using
    /// this region as their home should migrate away to the next-best region (without
    /// [`Region::avoid`] set).
    ///
    /// Due to bugs in past implementations combined with unclear docs that caused people to think
    /// the bugs were intentional, this field is deprecated. It was never supposed to cause
    /// STUN/DERP measurement probes, but due to bugs in the Go client, it sometimes did. And then
    /// some parts of the Go client code began to rely on that property. But then this field
    /// couldn't be used for its original purpose, nor its later imagined purpose, because various
    /// parts of the Go codebase thought it meant one thing and others thought it meant another.
    /// Therefore, it was deprecated/retired in favor of [`Region::no_measure_no_home`].
    #[deprecated = "use no_measure_no_home instead"]
    #[serde(default)]
    pub avoid: bool,
    /// Indicates this [`Region`] should not be measured for its latency distance (STUN, HTTPS,
    /// etc) or availability (e.g. captive portal checks), and should never be selected as the
    /// Tailscale node's home region. However, if a peer Tailscale node declares this region as its
    /// home, then this Tailscale node is allowed to connect to it for the purpose of communicating
    /// with that peer node.
    ///
    /// This is what the deprecated [`Region::avoid`] flag was originally meant for, but had
    /// implementation bugs and documentation omissions.
    #[serde(default)]
    pub no_measure_no_home: bool,

    /// The DERP servers running in this region, sorted in priority order for this Tailscale node.
    /// TLS connections from this node should ideally only go to the first server in the list,
    /// falling back to the second server if necessary. STUN packets should go to the first server
    /// or both first and second server in the list.
    ///
    /// DERP servers within a region are meshed to each other (route packets amongst themselves),
    /// but are not meshed with servers in other regions. That said, each node in a Tailnet should
    /// get the same preferred node order, so if all Tailscale nodes in a Tailnet pick the first
    /// server (as they should, when things are healthy), the inter-cluster routing is minimal to
    /// zero.
    #[serde(default)]
    pub nodes: alloc::vec::Vec<DerpServer<'a>>,
}

/// Describes the set of DERP packet relay servers that are available, sent from the control server
/// to a Tailscale node.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct DerpMap<'a> {
    /// If populated, contains the new home parameters that this Tailscale node should use when
    /// selecting a home region (aka "preferred DERP server"). If `None`, indicates no change from
    /// the previous values, if any was provided.
    pub home_params: Option<HomeParams>,
    /// The set of geographic regions running DERP node(s), keyed by [`RegionId`]. Note that the
    /// keys may not be contiguous; do not attempt to iterate over this field's keys using integer
    /// ranges.
    #[serde(borrow)]
    pub regions: BTreeMap<RegionId, Region<'a>>,
    /// If `true`, indicates this Tailscale node should not use Tailscale's DERP servers, and only
    /// use those specified in [`DerpMap::regions`].
    ///
    /// If there aren't any non-default DERP servers in [`DerpMap::regions`], this field is
    /// ignored. This field is only meaningful if [`DerpMap::regions`] is also populated, which
    /// indicates a change in the set of DERP regions/servers.
    pub omit_default_regions: bool,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ip_usage() {
        fn d<T>(s: &str) -> IpUsage<T>
        where
            T: FromStr,
        {
            serde_json::from_str::<IpUsage<T>>(s).unwrap()
        }

        assert_eq!(d::<Ipv4Addr>(r#""""#), IpUsage::UseDns);
        assert_eq!(d::<Ipv4Addr>(r#""none""#), IpUsage::Disable);
        assert_eq!(
            d::<Ipv4Addr>(r#""1.2.3.4""#),
            IpUsage::FixedAddr(Ipv4Addr::new(1, 2, 3, 4))
        );
    }
}
