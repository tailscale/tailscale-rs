use core::net::{IpAddr, SocketAddr};

use chrono::{DateTime, Utc};
use ts_keys::{DiscoPublicKey, MachinePublicKey, NodePublicKey};

/// The unique id of a node.
pub type Id = i64;

/// The stable ID of a node.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StableId(pub String);

/// A node in a tailnet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Node {
    /// The node's id.
    pub id: Id,
    /// The node's stable id.
    pub stable_id: StableId,

    /// This node's hostname.
    pub hostname: String,

    /// The tailnet this node belongs to.
    pub tailnet: Option<String>,

    /// The tags assigned to this node.
    pub tags: Vec<String>,

    /// The address of the node in the tailnet.
    pub tailnet_address: TailnetAddress,

    /// The node's [`NodePublicKey`].
    pub node_key: NodePublicKey,
    /// The node key's expiration.
    pub node_key_expiry: Option<DateTime<Utc>>,

    /// The node's [`MachinePublicKey`], if known.
    pub machine_key: Option<MachinePublicKey>,
    /// The node's [`DiscoPublicKey`], if known.
    pub disco_key: Option<DiscoPublicKey>,

    /// The routes this node accepts traffic for.
    pub accepted_routes: Vec<ipnet::IpNet>,
    /// The underlay addresses this node is reachable on (`Endpoints` in Go).
    pub underlay_addresses: Vec<SocketAddr>,

    /// The DERP region for this node, if known.
    pub derp_region: Option<ts_derp::RegionId>,
}

impl Node {
    /// The fully-qualified domain name of the node.
    ///
    /// This is a string of the form `$HOST.$TAILNET_DOMAIN.`. For tailnets controlled by
    /// Tailscale's control plane, this usually means `$HOST.tail1234.ts.net.`
    ///
    /// The `trailing_dot` parameter specifies whether to include the trailing dot in the
    /// fqdn. This is included by the definition of FQDN, and is the way the Go codebase
    /// formats this field, but the parameter is included to allow turning it off for use
    /// in contexts that expect it to be absent.
    pub fn fqdn(&self, trailing_dot: bool) -> String {
        let dot = if trailing_dot { "." } else { "" };
        match &self.tailnet {
            Some(tailnet) => format!("{}.{tailnet}{dot}", self.hostname),
            None => format!("{}{dot}", self.hostname),
        }
    }

    /// The fully-qualified domain name of the node, only returning `Some` if the tailnet
    /// component is present.
    ///
    /// See [`Node::fqdn`].
    pub fn fqdn_opt(&self, trailing_dot: bool) -> Option<String> {
        let dot = if trailing_dot { "." } else { "" };
        let tailnet = self.tailnet.as_deref()?;

        Some(format!("{}.{tailnet}{dot}", self.hostname))
    }

    /// Report whether this node matches the given `name`.
    ///
    /// `name` is checked for equality with both this node's bare hostname and its fqdn. A
    /// trailing `.` may be present.
    pub fn matches_name(&self, name: &str) -> bool {
        // This approach is taken to avoid allocating a buffer just for the sake of making this
        // comparison: try to chop `.tailnet.` off of the end of `name` and compare the
        // remainder to our hostname. If `.tailnet.` doesn't match `name`, we'll end up comparing
        // our hostname to `hostname.other_tailnet.`, which won't succeed. If `name` was just the
        // hostname, nothing will have been chopped, so the comparison will still be hostname-to-
        // hostname.

        let name = name.strip_suffix('.').unwrap_or(name);

        let name = if let Some(tailnet) = &self.tailnet {
            name.strip_suffix(tailnet.as_str())
                .and_then(|name| name.strip_suffix('.'))
                .unwrap_or(name)
        } else {
            name
        };

        name == self.hostname
    }
}

/// Addresses for a node within a tailnet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TailnetAddress {
    /// The IPv4 address of the node in the tailnet.
    pub ipv4: ipnet::Ipv4Net,
    /// The IPv6 address of the node in the tailnet.
    pub ipv6: ipnet::Ipv6Net,
}

impl TailnetAddress {
    /// Report whether `addr` matches either address in this [`TailnetAddress`].
    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(a) => self.ipv4.addr() == a,
            IpAddr::V6(a) => self.ipv6.addr() == a,
        }
    }
}

impl From<&ts_control_serde::Node<'_>> for Node {
    fn from(value: &ts_control_serde::Node) -> Self {
        let fqdn_without_trailing_dot = value.name.strip_suffix('.').unwrap_or(value.name);

        let (hostname, tailnet) = match fqdn_without_trailing_dot.split_once('.') {
            Some((hostname, tailnet)) => (hostname, Some(tailnet.to_owned())),
            None => (fqdn_without_trailing_dot, None),
        };

        Self {
            id: value.id,
            stable_id: StableId(value.stable_id.0.to_string()),

            hostname: hostname.to_owned(),
            tailnet,

            tags: value
                .tags
                .as_ref()
                .map(|x| x.iter().map(|x| x.to_string()).collect())
                .unwrap_or_default(),

            tailnet_address: TailnetAddress {
                ipv4: value.addresses.0,
                ipv6: value.addresses.1,
            },
            node_key: value.key,
            node_key_expiry: value.key_expiry,
            machine_key: value.machine,
            disco_key: value.disco_key,

            accepted_routes: value
                .allowed_ips
                .clone()
                .unwrap_or_else(|| vec![value.addresses.0.into(), value.addresses.1.into()]),
            underlay_addresses: value.endpoints.clone(),

            // legacy_derp_string is still in practical use as of 3/2026
            #[allow(deprecated)]
            derp_region: value
                .home_derp
                .or(value.legacy_derp_string)
                .or_else(|| value.host_info.net_info.as_ref()?.preferred_derp)
                .map(|x| ts_derp::RegionId(x.into())),
        }
    }
}
