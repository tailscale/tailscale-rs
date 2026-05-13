use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ts_capabilityversion::CapabilityVersion;
use ts_keys::{DiscoPublicKey, MachinePublicKey, NodePublicKey};

use crate::{DnsResolver, derp_map::RegionId, host_info::HostInfo, user::UserId};

/// A serialized (marshalled) node key signature. If valid, authorizes a specific Tailscale node to
/// join a Tailnet protected with Tailnet Lock. The Tailnet Key Authority (TKA) for a Tailnet can
/// verify if a signature is valid.
///
/// For more info, see `tka.NodeKeySignature` in the Golang codebase.
pub type MarshaledSignature<'a> = &'a [u8];

/// A unique integer ID for a Tailscale node.
///
/// It's global within a control plane URL (`tailscale up --login-server`) and is (as of
/// 2025-01-06) never re-used even after a node is deleted.
///
/// To be nice, control plane servers should not use int64s that are too large to fit in a
/// JavaScript number (see JavaScript's `Number.MAX_SAFE_INTEGER`). The Tailscale-hosted control
/// plane stopped allocating large integers in March 2023, but nodes prior to that may have node
/// IDs larger than `MAX_SAFE_INTEGER` (2^53 – 1).
///
/// [`NodeId`]s are not stable across control plane URLs. For more stable URLs, see [`StableNodeId`].
pub type NodeId = i64;

/// A string representation of a Tailscale node's [`NodeId`].
///
/// Different control plane servers should ideally have different [`StableNodeId`] suffixes for
/// different sites or regions.
///
/// Being a string, it's safer to use in JavaScript without worrying about the size of the integer,
/// as documented on [`NodeId`]. But in general, Tailscale APIs can accept either a [`NodeId`]
/// integer or a [`StableNodeId`] string when referring to a node.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct StableNodeId<'a>(#[serde(borrow)] pub &'a str);

/// A Tailscale device in a Tailnet.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Node<'a> {
    /// A unique integer ID for the Tailscale node.
    #[serde(rename = "ID")]
    pub id: NodeId,
    /// A string representation of the Tailscale node's [`Node::id`] field.
    #[serde(rename = "StableID", borrow)]
    pub stable_id: StableNodeId<'a>,

    /// The fully-qualified domain name (FQDN) of this node, as well as the MagicDNS name for the
    /// node. Ends with a trailing dot, e.g. "host.tail-scale.ts.net."
    #[serde(borrow)]
    pub name: &'a str,

    /// Unique ID of the [`User`][crate::User] who created the node.
    ///
    /// If ACL tags are in use for the node, this field doesn't reflect the ACL identity that the
    /// node is running as.
    pub user: UserId,
    /// Unique ID of the user who shared this node, if non-zero and different from [`Node::user`].
    pub sharer: UserId,

    /// If populated, the public key of the Tailscale node's [`NodeKeyPair`][ts_keys::NodeKeyPair].
    pub key: NodePublicKey,
    /// The date and time that the Tailscale node's [`NodeKeyPair`][ts_keys::NodeKeyPair] will expire.
    pub key_expiry: Option<DateTime<Utc>>,
    /// If populated, a signature of the Tailnet Key Authority (TKA) key authorizing the Tailscale
    /// node to join the Tailnet.
    #[serde(borrow)]
    pub key_signature: Option<MarshaledSignature<'a>>,
    /// If populated, the public key of the Tailscale node's [`MachineKeyPair`][ts_keys::MachineKeyPair].
    pub machine: Option<MachinePublicKey>,
    /// If populated, the public key of the Tailscale node's [`DiscoKeyPair`][ts_keys::DiscoKeyPair].
    pub disco_key: Option<DiscoPublicKey>,

    /// The IP addresses of the Tailscale node in the Tailnet. There are exactly 2 addresses, and
    /// they are always in the same order: the first is the IPv4 address, the second is the IPv6
    /// address.
    pub addresses: (ipnet::Ipv4Net, ipnet::Ipv6Net),
    /// IP ranges to route to this node.
    ///
    /// As of [`CapabilityVersion::V112`], this may be null/undefined on the wire to indicate the
    /// value is the same as [`Node::addresses`]. Once deserialized, it must always be populated,
    /// even if those values are identical to [`Node::addresses`].
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Option<Vec<ipnet::IpNet>>,
    /// IP addresses/ports that this node can be reached directly on.
    ///
    /// Examples include public IP addresses/ports discovered via disco/STUN, or LAN-local IP
    /// addresses/ports.
    pub endpoints: Vec<SocketAddr>,

    /// Deprecated. This node's home DERP region ID, but shoved into an IP:port string for legacy
    /// reasons. The IP address is always `127.3.3.40` (a loopback address (127) followed by the
    /// number keys over the letters DERP on a QWERTY keyboard (`3.3.40`)). The "port number" is
    /// the home DERP region ID.
    ///
    /// The [`Node::home_derp`] field has replaced this since capability version 111, but old
    /// servers might still send this field (see tailscale/tailscale#14636). Do not use this field
    /// in code other than to upgrade/canonicalize the value to use [`Node::home_derp`] if a
    /// `"LegacyDERPString"` field arrives on the wire.
    #[serde(rename = "DERP", with = "legacy_derp_string")]
    #[deprecated = "use Node::home_derp field instead"]
    pub legacy_derp_string: Option<RegionId>,

    /// Unique ID of this node's home DERP region.
    ///
    /// May be zero if not yet known, but will ideally always be non-zero for normal connectivity;
    /// as DERP is used to discover direct connections, a home DERP region ID of zero prevents
    /// direct connection types from being discovered until its home DERP region ID is populated.
    ///
    /// Preferred over the [`Node::legacy_derp_string`] field and supported by clients as of
    /// [`CapabilityVersion`] 111.
    #[serde(rename = "HomeDERP", deserialize_with = "crate::util::derp_region_id")]
    pub home_derp: Option<RegionId>,

    /// A summary of the host that a Tailscale node is running on. Includes information about the
    /// version of Tailscale running on the host, the operating system, running services, and
    /// various diagnostic/logging and configuration values.
    #[serde(borrow)]
    pub host_info: HostInfo<'a>,
    /// The date/time this Tailscale node was created (added to the Tailnet for the first time).
    pub created: DateTime<Utc>,
    /// The node's [`CapabilityVersion`]; old servers may not send this value across the wire.
    pub cap: CapabilityVersion,

    /// The list of ACL tags applied to this node. Tags take the form of `tag:<value>` where
    /// `<value>` starts with a letter and only contains alphanumerics and dashes (`-`).
    ///
    /// Some valid tag examples:
    /// - `tag:prod`
    /// - `tag:database`
    /// - `tag:lab-1`
    #[serde(borrow)]
    pub tags: Option<Vec<&'a str>>,

    /// The routes from [`Node::allowed_ips`] that this node is currently the primary subnet router
    /// for, as determined by the control plane. It does not include the self address values from
    /// [`Node::addresses`] that are in [`Node::allowed_ips`].
    pub primary_routes: Vec<ipnet::IpNet>,

    /// When the node was last online. Only updated when [`Node::online`] is `false`. It is
    /// `None` if the current node doesn't have permission to know, or the node has never been
    /// online.
    pub last_seen: Option<DateTime<Utc>>,

    /// Whether the node is currently connected to the control plane. A value of `None` means:
    /// 1. The online status of the node is unknown
    /// 2. The current node doesn't have permission to know whether this node is online
    /// 3. The node has never been online
    pub online: Option<bool>,

    /// Whether or not the Tailscale node is authorized to be part of the Tailnet.
    pub machine_authorized: bool,

    /// Deprecated. Capabilities of this node.
    ///
    /// They're free-form strings, but should be in the form of URLs/URIs
    /// such as:
    /// - `https://tailscale.com/cap/is-admin`
    /// - `https://tailscale.com/cap/file-sharing`
    ///
    /// Replaced by the [`Node::cap_map`] field since capability version 89; use that field instead
    /// (see [tailscale/tailscale#11508](https://github.com/tailscale/tailscale/issues/11508)).
    #[deprecated = "use Node::cap_map instead"]
    #[serde(borrow)]
    pub capabilities: Vec<ts_nodecapability::NodeCap<'a>>,

    /// Map of capabilities to their optional argument/data values.
    ///
    /// It is valid for a capability to not have any argument/data values. These type of
    /// capabilities indicate that a node has a capability, but there is no additional data
    /// associated with it. These were previously represented by the `capabilities` field,
    /// but can now be represented by an entry in [`Node::cap_map`] with an empty value.
    ///
    /// See [`NodeCap`][ts_nodecapability::NodeCap] for more information on keys.
    ///
    /// Metadata about nodes can be transmitted in 3 ways:
    /// 1. [`MapResponse::node::cap_map`][Node::cap_map] describes attributes that affect behavior
    ///    for this node, such as which features have been enabled through the admin panel and any
    ///    associated configuration details.
    /// 2. [`MapResponse::packet_filters`][crate::MapResponse::packet_filters] describes
    ///    access (both IP- and application-based) that should be granted to peers.
    /// 3. [`MapResponse::peers::cap_map`][Node::cap_map] describes attributes regarding a peer node, such as
    ///    which features the peer supports or if that peer is preferred for a particular task vs
    ///    other peers that could also be chosen.
    #[serde(borrow)]
    pub cap_map: ts_nodecapability::Map<'a>,

    /// Indicates this node is not signed nor subject to Tailnet Key Authority (TKA) restrictions.
    /// However, in exchange for that privilege, it does not get network access.It can only access
    /// this node's peerapi, which may not let it do anything. It is the Tailscale client's job to
    /// double-check the [`MapResponse::packet_filter`][crate::MapResponse::packet_filter] field to
    /// verify that its [`Node::allowed_ips`] will not be accepted by the packet filter.
    #[serde(rename = "UnsignedPeerAPIOnly")]
    pub unsigned_peer_api_only: bool,

    /// The per-node logtail ID used for data plane audit logging.
    #[serde(rename = "DataPlaneAuditLogID", borrow)]
    pub data_plane_audit_log_id: &'a str,

    /// Whether or not this node's key has expired.
    ///
    /// Control may send this; clients are only allowed to set this from `false` to `true`. On the
    /// client, this is calculated client-side based on a timestamp sent from control to avoid
    /// clock skew issues.
    pub expired: bool,

    /// The IPv4 address that this peer knows the current node as. It may be `None` if the peer
    /// knows the current node by its native IPv4 address.
    ///
    /// This field is only populated in [`MapResponse::peers`][crate::MapResponse::peers], and will not be populated for the
    /// current node. If set, it should be used to masquerade traffic originating from the current
    /// node to this peer. The masquerade address is only relevant for this peer and not for other
    /// peers. This only applies to traffic originating from the current node to the peer or any of
    /// its subnets. Traffic originating from subnet routes will not be masqueraded (e.g. in case
    /// of `--snat-subnet-routes`).
    pub self_node_v4_masq_addr_for_this_peer: Option<IpAddr>,
    /// The IPv6 address that this peer knows the current node as. It may be `None` if the peer
    /// knows the current node by its native IPv6 address.
    ///
    /// This field is only populated in [`MapResponse::peers`][crate::MapResponse::peers], and will not be populated for the
    /// current node. If set, it should be used to masquerade traffic originating from the current
    /// node to this peer. The masquerade address is only relevant for this peer and not for other
    /// peers. This only applies to traffic originating from the current node to the peer or any of
    /// its subnets. Traffic originating from subnet routes will not be masqueraded (e.g. in case
    /// of `--snat-subnet-routes`).
    pub self_node_v6_masq_addr_for_this_peer: Option<IpAddr>,

    /// Indicates that this is a non-Tailscale WireGuard peer.
    ///
    /// WireGuard-only peers are not expected to speak Disco or DERP, and must have valid values in
    /// [`Node::endpoints`] to be reachable.
    #[serde(rename = "IsWireGuardOnly")]
    pub is_wireguard_only: bool,

    /// Indicates that this node is jailed and should not be allowed initiate connections, but
    /// should be allowed to accept inbound connections.
    pub is_jailed: bool,

    /// The list of DNS servers that should be used when this node is WireGuard-only and being used
    /// as an exit node.
    #[serde(rename = "ExitNodeDNSResolvers", borrow)]
    pub exit_node_dns_resolvers: Vec<DnsResolver<'a>>,
}

pub mod legacy_derp_string {
    use core::num::NonZeroU32;

    use serde::{Deserialize, Serialize};

    use crate::DerpRegionId;

    const PREFIX: &str = "127.3.3.40:";

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DerpRegionId>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <&'de str>::deserialize(deserializer)?;
        if !s.starts_with(PREFIX) {
            return Ok(None);
        }

        let Some((_pfx, port)) = s.split_at_checked(PREFIX.len()) else {
            return Ok(None);
        };

        let port = match port.parse::<u16>() {
            Ok(port) => port,
            Err(e) => return Err(serde::de::Error::custom(e)),
        };

        let Some(region) = NonZeroU32::new(port as _) else {
            return Ok(None);
        };

        Ok(Some(DerpRegionId::from(region)))
    }

    pub fn serialize<S>(val: &Option<DerpRegionId>, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match val {
            &Some(x) => {
                let val: u32 = x.into();
                alloc::format!("{PREFIX}{val}").serialize(s)
            }
            None => "".serialize(s),
        }
    }
}
