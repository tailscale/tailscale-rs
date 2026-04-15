use alloc::{collections::BTreeMap, string::ToString, vec::Vec};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserializer, Serializer};

/// DNS configuration.
#[derive(serde::Deserialize, Debug, Clone, Default)]
#[serde(default, rename_all = "PascalCase")]
pub struct Config<'a> {
    /// DNS resolvers to use, in order of preference.
    pub resolvers: Vec<Option<Resolver<'a>>>,

    /// Map of DNS name suffixes to a set of resolvers to use.
    ///
    /// It is used to implement "split DNS" and other advanced DNS routing overlays.
    ///
    /// Map keys are FQDN suffixes; they may optional contain a trailing dot but no leading
    /// dot.
    ///
    /// If the value is the empty slice, the suffix should still be handled by Tailscale's
    /// built-in resolver `100.100.100.100`, such as for the purpose of handling
    /// `extra_records`
    pub routes: BTreeMap<&'a str, Option<Vec<Option<Resolver<'a>>>>>,

    /// Like [`resolvers`][Config::resolvers], but only used if split DNS is requested
    /// in a configuration that doesn't work yet without explicit default resolvers.
    ///
    /// See: <https://github.com/tailscale/tailscale/issues/1743>
    pub fallback_resolvers: Vec<Option<Resolver<'a>>>,

    /// Search domains to use.
    ///
    /// Must be FQDNs _without_ the trailing dot.
    #[serde(borrow, rename = "Domains")]
    pub search_domains: Vec<&'a str>,

    /// Turns on MagicDNS, i.e. automatic resolution of hostnames for devices in the netmap.
    ///
    /// The legacy name in the Go codebase is `Proxied`.
    #[serde(rename = "Proxied")]
    pub magic_dns: bool,

    /// The IP addresses of the global nameservers to use.
    #[deprecated = "only used when MapRequest.version ∈ [9, 14]"]
    pub nameservers: Vec<IpAddr>,

    /// The set of DNS names for which control will assist with provisioning TLS certs.
    ///
    /// These names are FQDNs without trailing periods, and without any `_acme-challenge.`
    /// prefix.
    #[serde(borrow)]
    pub cert_domains: Vec<&'a str>,

    /// Extra DNS records to add to the MagicDNS config.
    pub extra_records: Vec<Record<'a>>,

    /// The DNS suffixes that the node, when being an exit node DNS proxy, should not
    /// answer.
    ///
    /// The entries do not contain trailing periods and are always all lowercase.
    ///
    /// If an entry starts with a period, it's a suffix match (but suffix ".a.b" doesn't
    /// match "a.b"; a prefix is required).
    ///
    /// If an entry does not start with a period, it's an exact match.
    ///
    /// Matches are case-insensitive.
    pub exit_node_filtered_set: Vec<&'a str>,
}

/// Configuration for one DNS resolver.
#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Resolver<'a> {
    /// The address of the DNS resolver, as described by [`ResolverAddr`].
    #[serde(borrow)]
    pub addr: ResolverAddr<'a>,

    /// Optional suggested resolution for a DNS-over-TLS or DNS-over-HTTPS resolver, if the
    /// URL doesn't reference an IP address directly.
    ///
    /// If empty, clients should use their local "classic" DNS resolver to look up the
    /// server IP.
    #[serde(default)]
    pub bootstrap_resolution: Vec<IpAddr>,

    /// Continue using this resolver while an exit node is in use.
    ///
    /// Normally, DNS resolution is delegated to the exit node, but there are situations
    /// where it is preferable to still use a split DNS server and/or global DNS server
    /// instead.
    #[serde(default)]
    pub use_with_exit_node: bool,
}

/// The address of a DNS resolver.
#[derive(Debug, Clone)]
pub enum ResolverAddr<'a> {
    /// Classic plaintext DNS on the given address.
    Plaintext(SocketAddr),

    /// DNS over HTTPS.
    ///
    /// As of 2022-09-08, only used for certain well-known resolvers, so bootstrapping isn't
    /// required.
    Https(&'a str),

    /// DNS over HTTP over WireGuard.
    ///
    /// Implemented in the peer API for exit nodes and app connectors.
    HttpWireguard(&'a str),

    /// DNS over TLS.
    Tls(&'a str),
}

impl serde::Serialize for ResolverAddr<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            // Default port can be serialized as the plain IP representation
            Self::Plaintext(addr) if addr.port() == 53 => {
                addr.ip().to_string().serialize(serializer)
            }
            // Otherwise Go uses `net.ParseAddrPort`, which should be equivalent
            Self::Plaintext(addr) => addr.to_string().serialize(serializer),
            Self::HttpWireguard(addr) | Self::Tls(addr) | Self::Https(addr) => {
                addr.serialize(serializer)
            }
        }
    }
}

impl<'a, 'de: 'a> serde::Deserialize<'de> for ResolverAddr<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let s = <&'a str as serde::Deserialize>::deserialize(deserializer)?;

        if s.starts_with("https://") {
            return Ok(ResolverAddr::Https(s));
        }

        if s.starts_with("http://") {
            return Ok(ResolverAddr::HttpWireguard(s));
        }

        if s.starts_with("tls://") {
            return Ok(ResolverAddr::Tls(s));
        }

        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(ResolverAddr::Plaintext(SocketAddr::new(ip, 53)));
        }

        Ok(ResolverAddr::Plaintext(
            s.parse::<SocketAddr>().map_err(D::Error::custom)?,
        ))
    }
}

/// DNS record.
#[derive(Debug, Clone)]
pub enum Record<'a> {
    /// `A` record: bind an IPv4 address to a name.
    A {
        /// The fully-qualified domain name of the record to add.
        ///
        /// The trailing dot is optional.
        name: &'a str,

        /// The IP address bound to `name`.
        value: Ipv4Addr,
    },
    /// `AAAA` record: bind an IPv6 address to a name.
    AAAA {
        /// The fully-qualified domain name of the record to add.
        ///
        /// The trailing dot is optional.
        name: &'a str,

        /// The IP address bound to `name`.
        value: Ipv6Addr,
    },
    /// Catchall for other record types.
    Other {
        /// The fully-qualified domain name of the record to add.
        ///
        /// The trailing dot is optional.
        name: &'a str,
        /// The type of the record.
        ty: &'a str,
        /// The IP address in string form.
        value: &'a str,
    },
}

impl<'a, 'de: 'a> serde::Deserialize<'de> for Record<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        #[derive(serde::Deserialize, Default)]
        #[serde(rename_all = "PascalCase", default)]
        struct GenericRecord<'a> {
            #[serde(borrow)]
            name: &'a str,
            value: &'a str,
            #[serde(rename = "Type")]
            ty: &'a str,
        }

        let rec = <GenericRecord as serde::Deserialize>::deserialize(deserializer)?;

        if rec.ty.eq_ignore_ascii_case("a") {
            return Ok(Record::A {
                name: rec.name,
                value: rec.value.parse().map_err(D::Error::custom)?,
            });
        }

        if rec.ty.eq_ignore_ascii_case("aaaa") {
            return Ok(Record::AAAA {
                name: rec.name,
                value: rec.value.parse().map_err(D::Error::custom)?,
            });
        }

        if !rec.ty.is_empty() {
            return Ok(Record::Other {
                name: rec.name,
                value: rec.value,
                ty: rec.ty,
            });
        }

        Ok(
            match rec.value.parse::<IpAddr>().map_err(D::Error::custom)? {
                IpAddr::V4(v4) => Record::A {
                    name: rec.name,
                    value: v4,
                },
                IpAddr::V6(v6) => Record::AAAA {
                    name: rec.name,
                    value: v6,
                },
            },
        )
    }
}
