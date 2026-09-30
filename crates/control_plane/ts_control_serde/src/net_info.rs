use alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::derp_map::RegionId;

/// Map of stringified DERP region IDs and address families to their average latency in
/// milliseconds.
pub type DerpLatencyMap<'a> = BTreeMap<&'a str, f64>;

/// Indicates the type of physical link (layer 2) connecting a Tailscale node to the network.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkType<'a> {
    /// A wired connection, such as 802.3 Ethernet or 802.4 Token Bus.
    Wired,
    /// A wireless 802.11 connection.
    Wifi,
    /// A wireless cellular data connection, such as 3G/4G/5G or the fabled EDGE.
    Mobile,
    /// A network link type that doesn't fall under the other categories.
    #[serde(untagged, borrow)]
    Other(&'a str),
}

/// Information about a Tailscale node's host networking state.
#[serde_with::apply(
    &str => #[serde(borrow)] #[serde(skip_serializing_if = "str::is_empty")],
    Option => #[serde(skip_serializing_if = "Option::is_none")],
     _ => #[serde(default)],
)]
#[derive(Clone, Debug, PartialEq, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetInfo<'a> {
    /// Indicates whether the host's NAT mappings vary based on the destination IP address.
    pub mapping_varies_by_dest_ip: Option<bool>,
    /// Indicates if the router between the Tailscale node and the internet does hairpinning. This
    /// value will be `true` even when there's no NAT involved.
    pub hair_pinning: Option<bool>,
    /// Indicates whether the Tailscale node's host has IPv6 internet connectivity.
    pub working_ipv6: Option<bool>,
    /// Indicates whether the Tailscale node's host operating system supports IPv6 at all,
    /// regardless of whether IPv6 internet connectivity is available.
    pub os_has_ipv6: Option<bool>,
    /// Indicates whether the Tailscale node's host has UDP internet connectivity.
    pub working_udp: Option<bool>,
    /// Indicates whether the Tailscale node's host has working ICMPv4. `None` indicates this wasn't
    /// checked, and is unknown.
    pub working_icmpv4: Option<bool>,
    /// Indicates whether the Tailscale node has an existing open port mapping, regardless of the
    /// mapping mechanism (e.g. UPnP, NAT-PMP, PCP, etc.).
    pub have_port_map: Option<bool>,
    /// Indicates whether UPnP is present on the Tailscale node's LAN. `None` indicates this wasn't
    /// checked, and is unknown.
    pub upnp: Option<bool>,
    /// Indicates whether NAT-PMP is present on the Tailscale node's LAN. `None` indicates this
    /// wasn't checked, and is unknown.
    pub pmp: Option<bool>,
    /// Indicates whether PCP is present on the Tailscale node's LAN. `None` indicates this wasn't
    /// checked, and is unknown.
    pub pcp: Option<bool>,
    /// The Tailscale node's preferred (home) DERP region ID. This is where the node expects to be
    /// contacted to begin a peer-to-peer connection.
    ///
    /// A Tailscale node might be temporarily connected to multiple DERP servers (to speak to
    /// Tailscale nodes located in different DERP regions); this field is the region ID that this
    /// node subscribes to traffic at. Zero means disconnected or unknown.
    #[serde(deserialize_with = "crate::util::derp_region_id")]
    pub preferred_derp: Option<RegionId>,
    /// The current type of physical link connecting the Tailscale node to the network; `None`
    /// indicates unknown.
    #[serde(borrow)]
    pub link_type: Option<LinkType<'a>>,
    /// The fastest recent time to reach various DERP STUN servers, in seconds. The map key is the
    /// "regionID-v4" or "-v6"; it was previously the DERP server's STUN host:port.
    ///
    /// This should only be updated rarely, or when there's a material change, as any change here
    /// also gets uploaded to the control plane.
    pub derp_latency: Option<DerpLatencyMap<'a>>,
    /// Encodes both which firewall mode was selected and why, to help debug iptables-vs-nftables
    /// issues. The string is of the form "{nft,ift}-REASON", like "nft-forced" or "ipt-default".
    ///
    /// As of 2023-08-19, this field is Linux-specific. Empty means either this Tailscale node is
    /// not running on Linux, or indicates a configuration in which the host firewall rules are
    /// not managed by Tailscale.
    pub firewall_mode: &'a str,
}
