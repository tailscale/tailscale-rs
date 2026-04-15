use alloc::{collections::BTreeMap, vec::Vec};
use core::net::SocketAddr;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use ts_capabilityversion::CapabilityVersion;
use ts_keys::{DiscoPublicKey, NodePublicKey};

use crate::{
    DerpRegionId, MarshaledSignature,
    client_version::ClientVersion,
    debug::Debug,
    derp_map::DerpMap,
    dial_plan::ControlDialPlan,
    host_info::HostInfo,
    node::{Node, NodeId},
    ping::PingRequest,
    tka_info::TkaInfo,
    user::UserProfile,
};

/// Sent by a Tailscale node to the control server to either update the control plane about its
/// current state, or to start a long-poll of network map updates. Includes a copy of the node's
/// current set of WireGuard endpoints and general host information.
///
/// The request is JSON-encoded and sent to the control server via an HTTP POST to
/// `https://<control-server>/machine/map`.
#[serde_with::apply(
    bool => #[serde(skip_serializing_if = "crate::util::is_default")],
    &str => #[serde(borrow)] #[serde(skip_serializing_if = "str::is_empty")],
    Option => #[serde(skip_serializing_if = "Option::is_none")],
    Vec => #[serde(skip_serializing_if = "Vec::is_empty")],
     _ => #[serde(default)],
)]
#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MapRequest<'a> {
    /// The capability version of this Tailscale node. Incremented whenever the client code
    /// (in any client, Go/Rust/etc) changes enough that we want to signal to the control server
    /// that we're capable of something different.
    ///
    /// See the [`CapabilityVersion`] enum for info the changes introduced with each version.
    pub version: CapabilityVersion,

    /// Either "zstd" to receive [`MapResponse`]s compressed with `zstd`, or "" to receive
    /// [`MapResponse`]s with no compression.
    pub compress: &'a str,
    /// Whether the control server should periodically send application-level keep-alives back to
    /// this Tailscale node.
    pub keep_alive: bool,

    /// The public key of this Tailscale node.
    pub node_key: NodePublicKey,
    /// The public key this Tailscale node will use with the Disco protocol to establish direct
    /// connections with peer nodes in the Tailnet.
    pub disco_key: DiscoPublicKey,

    /// If populated, the public key of the node's hardware-backed identity attestation key.
    pub hardware_attestation_key: Option<Vec<u8>>,
    /// If populated, the signature of "$UNIX_TIMESTAMP|$NODE_PUBLIC_KEY" as signed by the
    /// hardware attestation key.
    pub hardware_attestation_key_signature: Option<Vec<u8>>,
    /// If populated, the time at which the [`MapRequest::hardware_attestation_key_signature`] was
    /// created.
    #[serde_as(as = "serde_with::TimestampSeconds<i64>")]
    pub hardware_attestation_key_signature_timestamp: Option<DateTime<Utc>>,

    /// Whether or not this Tailscale node wants to receive multiple [`MapResponse`]s over the same
    /// HTTP connection, referred to as "long-polling" or a "map poll".
    ///
    /// If `false`, the control server will send a single [`MapResponse`] and then close the
    /// connection. If `true` and [`MapRequest::version`] >= 68, the server will treat this as a
    /// read-only request and ignore [`MapRequest::host_info`] and any other fields that might be
    /// set.
    pub stream: bool,

    /// Current information about this Tailscale node's host. Although it is always included in a
    /// [`MapRequest`], a control server may choose to ignore it when [`MapRequest::stream`] is
    /// `true` and [`MapRequest::version`] >= 68.
    #[serde(borrow)]
    pub host_info: Option<HostInfo<'a>>,

    /// If non-empty, indicates a request to reattach to a previous map session after a previous
    /// map session was interrupted for whatever reason. Its value is an opaque string.
    ///
    /// When set, the Tailscale node must also send [`MapRequest::map_session_seq`] to specify the
    /// last processed message in that prior session. The control server may choose to ignore the
    /// request for any reason and start a new map session. This is only applicable when
    /// [`MapRequest::stream`] is `true`.
    pub map_session_handle: &'a str,
    /// The sequence number in the map session (identified by [`MapRequest::map_session_handle`]
    /// that was most recently processed by this Tailscale node. It is only applicable when
    /// [`MapRequest::map_session_handle`] is specified. If the control server chooses to honor the
    /// [`MapRequest::map_session_handle`] request, only sequence numbers greater than this value
    /// will be returned.
    #[serde(skip_serializing_if = "crate::util::is_default")]
    pub map_session_seq: i64,

    /// The client's magicsock UDP ip:port endpoints (IPv4 or IPv6).
    ///
    /// These can be ignored if `stream` is true and `version` >= 68.
    #[serde(flatten, with = "endpoint_serde")]
    pub endpoints: Vec<Endpoint>,

    /// Describes the hash of the latest AUM applied to the local Tailnet Key Authority, if one is
    /// operating.
    #[serde(rename = "TKAHead")]
    pub tka_head: &'a str,

    /// Deprecated. In the past, was set by Tailscale nodes when they wanted to fetch the full
    /// [`MapResponse`] from the control server without updating their [`MapRequest::endpoints`].
    /// The intended use was for clients to discover the DERP map at start-up before their first
    /// real endpoint update.
    ///
    /// This value must always be omitted or set to `false` as of [`MapRequest::version`] >= 68.
    #[deprecated = "do not use; must always be omitted/false"]
    pub read_only: Option<bool>,

    /// Whether the Tailscale node is okay with the [`MapResponse::peers`] list being omitted in the
    /// [`MapResponse`]. If `true`, the behavior of the control server varies based on the
    /// [`MapRequest::stream`] and [`MapRequest::read_only`] flags:
    ///
    /// - If [`MapRequest::omit_peers`] is `true`, [`MapRequest::stream`] is `false`, and
    ///   [`MapRequest::read_only`] is `false`: the control server will let Tailscale nodes update
    ///   their endpoints without breaking existing long-polling connections. In this case, the
    ///   server can omit the entire response; the Tailscale node only needs to check the HTTP
    ///   response status code.
    /// - If [`MapRequest::omit_peers`] is `true`, [`MapRequest::stream`] is `false`, and
    ///   [`MapRequest::read_only`] is `true`: the control server includes all fields in the
    ///   [`MapResponse`], as if the Tailscale node is fetching data from the control server for
    ///   the first time.
    pub omit_peers: bool,

    /// A list of strings specifying debugging and development features to enable in handling this
    /// [`MapRequest`]. The values are deliberately unspecified, as they get added and removed all
    /// the time during development, and offer no compatibility promise. To roll out semantic
    /// changes, bump the [`CapabilityVersion`] instead.
    ///
    /// Current valid values are:
    /// - `"warn-ip-forwarding-off"`: node is trying to be a subnet router, but their IP forwarding
    ///   is broken.
    /// - `"warn-router-unhealthy"`: node's subnet router implementation is having problems.
    pub debug_flags: Vec<&'a str>,

    /// If non-empty, an opaque string sent by the Tailscale node that identifies this specific
    /// connection to the control server. The server may choose to use this handle to identify
    /// the connection for debugging or testing purposes. It has no semantic meaning.
    pub connection_handle_for_test: &'a str,
}

/// An endpoint (address + port) on which a peer can be reached.
#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Endpoint {
    /// The address of this endpoint.
    pub endpoint: SocketAddr,

    /// The type of this endpoint.
    pub ty: EndpointType,
}

/// Distinguishes different sources of [`MapRequest::endpoints`] values.
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, serde_repr::Serialize_repr, serde_repr::Deserialize_repr,
)]
#[repr(isize)]
pub enum EndpointType {
    /// Unknown endpoint type.
    Unknown = 0,

    /// Endpoint is a LAN address.
    Local = 1,

    /// Endpoint is a STUN address.
    Stun = 2,

    /// Endpoint is a router port-mapping.
    PortMapped = 3,

    /// Hard NAT: STUNed IPv4 with local fixed port.
    Stun4LocalPort = 4,

    /// Explicitly configured (routing to be done by client).
    ExplicitConf = 5,
}

mod endpoint_serde {
    use core::net::SocketAddr;

    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct EndpointSerde {
        pub endpoints: Vec<SocketAddr>,
        pub endpoint_types: Vec<EndpointType>,
    }

    pub fn deserialize<'de, D>(de: D) -> Result<Vec<Endpoint>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let result = EndpointSerde::deserialize(de)?;

        let eps = result
            .endpoints
            .into_iter()
            .zip(result.endpoint_types)
            .map(|(endpoint, ty)| Endpoint { endpoint, ty })
            .collect();

        Ok(eps)
    }

    pub fn serialize<S>(t: &[Endpoint], s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let tys = t.iter().map(|x| x.ty).collect();
        let addrs = t.iter().map(|x| x.endpoint).collect();

        EndpointSerde {
            endpoint_types: tys,
            endpoints: addrs,
        }
        .serialize(s)
    }
}

// TODO (dylan): MapResponse: add missing fields
/// The response to a [`MapRequest`]. It describes the state of the local Tailscale node, the peer
/// nodes in the Tailnet, the DNS configuration, the packet filter, and more. A [`MapRequest`],
/// depending on its parameters, may result in the control plane coordination server sending 0, 1,
/// or a stream of multiple [`MapResponse`] values.
///
/// When a node sends a [`MapRequest`] to the control server with the [`MapRequest::stream`] flag
/// set to `true`, the server will respond with a stream of [`MapResponse`]s. The long-lived HTTP
/// transaction delivering the stream is called a "map poll". In a map poll, the first
/// [`MapResponse`] will be complete; subsequent [`MapResponse`]s will be incremental updates with
/// only changed information.
///
/// In general, fields omitted in the [`MapResponse`] JSON (or `None` in the deserialized struct
/// instance) indicate the field's value is unchanged from the previous value. However, several
/// older slice-like fields have different semantics; this is noted in the doc comments for the
/// relevant fields. For background, see the [doc comment for `MapResponse`] in the Go client.
///
/// [doc comment for MapResponse]: <https://github.com/tailscale/tailscale/blob/e2233b794247bf20d022d0ebefa99ad39bbad591/tailcfg/tailcfg.go#L1927-L1936>
#[derive(Default, Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct MapResponse<'a> {
    /// Optionally specifies a unique opaque handle for this stateful [`MapResponse`] session.
    /// Servers may choose not to send it, and it's only sent on the first [`MapResponse`] in a
    /// stream. The client can determine whether it's reattaching to a prior stream by seeing
    /// whether this value matches the requested [`MapResponse::map_session_handle`].
    #[serde(borrow)]
    pub map_session_handle: &'a str,
    /// Sequence number within a named map session (a response where the first message contains a
    /// [`MapResponse::map_session_handle`]). The sequence number may be omitted on responses that
    /// don't change the state of the stream, such as KeepAlive or certain types of PingRequests.
    /// This is the value to be sent in [`MapRequest::map_session_seq`] to resume after this
    /// message.
    pub seq: i64,
    /// If set, represents an empty message just to keep the connection alive. When `true`, all
    /// other fields except [`MapResponse::ping_request`], [`MapResponse::control_time`], and
    /// [`MapResponse::pop_browser_url`] are ignored.
    pub keep_alive: Option<bool>,
    /// If non-`None`, a request to the client to prove it's still there by sending an HTTP
    /// request to the provided URL. No auth headers are necessary. [`MapResponse::ping_request`]
    /// may be sent on any [`MapResponse`] (ones with [`MapResponse::keep_alive`] set to either
    /// `true` or `false`).
    pub ping_request: Option<PingRequest>,
    /// If non-`None`, a URL for the client to open to complete an action. The client should
    /// debounce identical URLs and only open it once for the same URL.
    pub pop_browser_url: Option<&'a str>,

    /// Describes the Tailscale node making the map request (ie, the "self" node). Starting with
    /// capability version 18, a value of `None` means unchanged.
    pub node: Option<Node<'a>>,

    /// Describes the set of available DERP regions and servers. If `None`, the set of servers is
    /// unchanged from the last set sent from the control plane to this client.
    #[serde(rename = "DERPMap")]
    pub derp_map: Option<DerpMap<'a>>,

    /// The complete list of peer Tailscale nodes in the same Tailnet as this node. This field will
    /// always be populated in the first [`MapResponse`] in a long-polled stream sent to this node.
    /// Subsequent [`MapResponse`]s in the stream will usually provide delta-encoded updates on
    /// nodes that have been added, removed, or changed since the previous [`MapResponse`] via the
    /// [`MapResponse::peers_changed`] and [`MapResponse::peers_removed`] fields.
    ///
    /// If this field is populated, it takes precedence over the other two fields; in other words,
    /// if [`MapResponse::peers`] is populated, you must ignore both the
    /// [`MapResponse::peers_changed`] and [`MapResponse::peers_removed`] fields and use only the
    /// values in this field.
    ///
    /// This list will always be sorted by [`Node::id`] in ascending order.
    pub peers: Option<Vec<Node<'a>>>,
    /// The Tailscale nodes in the Tailnet that have changed or been added since the last
    /// [`MapResponse`] sent to this node. Do not use this field if [`MapResponse::peers`] is
    /// populated.
    ///
    /// This list will always be sorted by [`Node::id`] in ascending order.
    pub peers_changed: Option<Vec<Node<'a>>>,
    /// IDs of Tailscale nodes that are no longer in the peer list for the Tailnet.
    pub peers_removed: Option<Vec<NodeId>>,

    /// If present, the indicated nodes have changed.
    ///
    /// This is a lighter version of `peers_changed` that only supports certain types of
    /// updates.
    ///
    /// These are applied after `peers*`, but in practice, the control server should only
    /// send these on their own, without the `peers*` fields also set.
    #[serde(borrow)]
    pub peers_changed_patch: Vec<Option<PeerChange<'a>>>,

    /// How to update peers' [`last_seen`][crate::Node::last_seen] times.
    ///
    /// If the value for a peer is false, the peer is gone. If true, update `last_seen` to
    /// now.
    pub peer_seen_change: BTreeMap<NodeId, bool>,

    /// Updates to peers' [`online`][crate::Node::online] states.
    pub online_change: BTreeMap<NodeId, bool>,

    // --------------------------------------------------------------------------------------------

    // DNSConfig contains the DNS settings for the client to use.
    // A nil value means no change from an earlier non-nil value.
    //DNSConfig *DNSConfig `json:",omitempty"`

    // --------------------------------------------------------------------------------------------
    /// The name of the network that this node is in. It's either of the form:
    /// - "example.com" (for user foo@example.com, for multi-user networks)
    /// - "foo@gmail.com" (for siloed users on shared email providers)
    ///
    /// Do not depend on the exact format of this field; more forms will be added in the future. If
    /// empty, the value is unchanged.
    pub domain: &'a str,

    /// Indicates whether this node's tailnet has requested that info about services be included in
    /// [`Node::host_info`]. If `None`, the most recent non-empty MapResponse value in the HTTP
    /// response stream is used.
    pub collect_services: Option<bool>,

    /// `packet_filter` are the firewall rules.
    ///
    /// For [`MapRequest::version`] >= 6, a `None` value means the most
    /// previously streamed non-`None` [`MapResponse::packet_filter`] within
    /// the same HTTP response. A present (`Some`) but empty list always means
    /// no `packet_filter` (that is, to block everything).
    ///
    /// See [`packet_filters`][MapResponse::packet_filters] for the newer way to send
    /// `packet_filter` updates.
    #[serde(borrow)]
    pub packet_filter: Option<ts_packetfilter_serde::Ruleset<'a>>,

    /// `packet_filters` encodes incremental packet filter updates to the client
    /// without having to send the entire packet filter on any changes as
    /// required by the older `packet_filter` (singular) field above. The map keys
    /// are server-assigned arbitrary strings. The map values are the new rules
    /// for that key, or nil to delete it. The client then concatenates all the
    /// rules together to generate the final packet filter. Because the
    /// [`FilterRule`][ts_packetfilter_serde::FilterRule]s can only match or not match, the
    /// ordering of filter rules doesn't matter.
    ///
    /// If the server sends a non-nil [`packet_filter`][MapResponse::packet_filter]
    /// (above), that is equivalent to a named packet filter with the key "base". It is
    /// valid for the server to send both `packet_filter` and `packet_filters` in the same
    /// MapResponse or alternate between them within a session. `packet_filter` is applied
    /// first (if set), and then `packet_filters`.
    ///
    /// As a special case, the map key "*" with a value of `None` means to clear all
    /// prior named packet filters (including any implicit "base") before
    /// processing the other map entries.
    #[serde(borrow)]
    pub packet_filters: ts_packetfilter_serde::Map<'a>,

    // --------------------------------------------------------------------------------------------
    /// The [`UserProfile`]s associated with Tailscale nodes in the Tailnet. As of
    /// [`CapabilityVersion::V5`], contains only new or updated profiles.
    pub user_profiles: Vec<UserProfile<'a>>,

    // --------------------------------------------------------------------------------------------
    // Health, if non-nil, sets the health state of the node from the control
    // plane's perspective. A nil value means no change from the previous
    // MapResponse. A non-nil 0-length slice restores the health to good (no
    // known problems). A non-zero length slice are the list of problems that
    // the control plane sees.
    //
    // Either this will be set, or DisplayMessages will be set, but not both.
    //
    // Note that this package's type, due its use of a slice and omitempty, is
    // unable to marshal a zero-length non-nil slice. The control server needs
    // to marshal this type using a separate type. See MapResponse docs.
    //Health []string `json:",omitempty"`

    // DisplayMessages sets the health state of the node from the control
    // plane's perspective.
    //
    // Either this will be set, or Health will be set, but not both.
    //
    // The map keys are IDs that uniquely identify the type of health issue. The
    // map values are the messages. If the server sends down a map with entries,
    // the client treats it as a patch: new entries are added, keys with a value
    // of nil are deleted, existing entries with new values are updated. A nil
    // map and an empty map both mean no change has occurred since the last
    // update.
    //
    // As a special case, the map key "*" with a value of nil means to clear all
    // prior display messages before processing the other map entries.
    //DisplayMessages map[DisplayMessageID]*DisplayMessage `json:",omitempty"`

    // SSHPolicy, if non-nil, updates the SSH policy for how incoming
    // SSH connections should be handled.
    //SSHPolicy *SSHPolicy `json:",omitempty"`

    // --------------------------------------------------------------------------------------------
    /// The current timestamp according to the control server; otherwise, `None`.
    pub control_time: Option<DateTime<Utc>>,

    /// Encodes the control plane's view of Tailnet Key Authority (TKA) state.
    ///
    /// If populated for an initial [`MapResponse`] (not a delta update), the control plane
    /// believes TKA should be enabled for this node. If `None` in an initial [`MapResponse`], the
    /// control plane believes TKA should be disabled for this node.
    ///
    /// If `None` in subsequent [`MapResponse`] updates in a long-polling map stream (i.e., delta
    /// updates), there are no changes to TKA state since the previous value.
    #[serde(rename = "TKAInfo")]
    pub tka_info: Option<TkaInfo<'a>>,

    /// If populated, the per-tailnet log ID to be used when writing data plane audit logs.
    #[serde(rename = "DomainDataPlaneAuditLogID")]
    pub domain_data_plane_audit_log_id: Option<&'a str>,

    /// Deprecated. If populated, contains debug settings from the control server that this
    /// Tailscale node should set.
    #[deprecated = "use Node::capabilities or c2n requests instead"]
    pub debug: Option<Debug>,

    /// If populated, tells this Tailscale node how to connect to the control server. If `None`,
    /// the node should use DNS to look up the IP address of the control server.
    ///
    /// Used to maintain connection if the node's network state changes after the initial
    /// connection, or if the control server pushes other changes to the node (such as DNS config
    /// updates) that break connectivity.
    pub control_dial_plan: Option<ControlDialPlan<'a>>,

    /// If populated, describes the latest Tailscale version that's available for download for this
    /// node's platform and package type. If `None`, the latest version hasn't changed since the
    /// previous value.
    pub client_version: Option<ClientVersion<'a>>,

    /// The default node auto-update setting for this tailnet. The node is free to opt-in or out
    /// locally regardless of this value. This value is only used on first [`MapResponse`] from
    /// control; the auto-update setting doesn't change if the tailnet admin flips the default
    /// after the node registered.
    pub default_auto_update: Option<bool>,
}

/// An update to a node.
#[derive(Default, Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct PeerChange<'a> {
    /// The ID of the node being mutated.
    ///
    /// If not known in the current netmap, this change should be ignored.
    #[serde(rename = "NodeID")]
    pub node_id: NodeId,

    /// If present, the node's home derp region is updated to the new value.
    #[serde(
        rename = "DERPRegion",
        deserialize_with = "crate::util::derp_region_id"
    )]
    pub derp_region: Option<DerpRegionId>,

    /// If present, the node's capability version is the new value.
    pub cap: Option<CapabilityVersion>,

    /// If present, the node's capability map has changed.
    #[serde(borrow)]
    pub cap_map: Option<ts_nodecapability::Map<'a>>,

    /// If present, the node's UDP endpoints have changed to the new value.
    pub endpoints: Option<Vec<Endpoint>>,

    /// If present, the node's wireguard public key has changed.
    pub key: Option<NodePublicKey>,

    /// If present, the signature of the node's wireguard public key has changed.
    #[serde(borrow)]
    pub key_signature: Option<MarshaledSignature<'a>>,

    /// If present, the node's disco key has changed.
    pub disco_key: Option<DiscoPublicKey>,
    /// If present, the node's online status changed.
    pub online: Option<bool>,
    /// If present, the node's last seen time changed.
    pub last_seen: Option<DateTime<Utc>>,

    /// If present, the node's key expiry has changed to the new value.
    pub key_expiry: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn endpoint() {
        const TEST: &str = r#"{
            "Version": 130,
            
            "Compress": "",
            "KeepAlive": false,
            "Stream": false,
            "ReadOnly": false,
            "OmitPeers": false,
            "DebugFlags": [],
            "ConnectionHandleForTest": "",
            "NodeKey": "nodekey:0000000000000000000000000000000000000000000000000000000000000000",
            "DiscoKey": "discokey:0000000000000000000000000000000000000000000000000000000000000000",
            "MapSessionHandle": "",
            "MapSessionSeq": 0,
            "TKAHead": "",
            
            "Endpoints": [
                "1.2.3.4:80"
            ],
            "EndpointTypes": [
                1
            ]
        }"#;

        let req = serde_json::from_str::<MapRequest>(TEST).unwrap();

        assert_eq!(
            req.endpoints,
            &[Endpoint {
                endpoint: "1.2.3.4:80".parse().unwrap(),
                ty: EndpointType::Local,
            }]
        );

        let serialized = serde_json::to_string_pretty(&req).unwrap();
        std::println!("{serialized}");
    }
}
