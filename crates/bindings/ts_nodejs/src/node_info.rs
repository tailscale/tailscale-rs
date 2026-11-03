use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use zerocopy::IntoBytes;

use crate::AddressInfo;

/// Info about a tailscale node.
#[napi(object, object_from_js = false)]
pub struct NodeInfo {
    /// Node's id. A string, as it may not fit in a JS number.
    pub id: String,
    /// Stable id.
    pub stable_id: String,
    /// The node's hostname.
    pub hostname: String,
    /// The tailnet to which this node belongs.
    pub tailnet: Option<String>,
    /// This node's tags.
    pub tags: Vec<String>,
    /// The tailnet addresses this device has.
    pub tailnet_address: TailnetAddress,
    /// This node's home derp region.
    pub derp_region: Option<u32>,
    /// This node's node key.
    pub node_key: Buffer,
    /// This node's disco key.
    pub disco_key: Option<Buffer>,
    /// This node's machine key.
    pub machine_key: Option<Buffer>,
    /// The underlay addresses on which this node is reachable.
    pub underlay_addresses: Vec<AddressInfo>,
}

/// A node's tailnet IP addresses.
#[napi(object, object_from_js = false)]
pub struct TailnetAddress {
    /// IPv4 address.
    pub ipv4: String,
    /// IPv6 address.
    pub ipv6: String,
}

impl From<&tailscale::NodeInfo> for NodeInfo {
    fn from(value: &tailscale::NodeInfo) -> Self {
        Self {
            id: value.id.to_string(),
            stable_id: value.stable_id.0.clone(),
            tags: value.tags.clone(),
            node_key: value.node_key.as_bytes().into(),

            hostname: value.hostname.clone(),
            tailnet: value.tailnet.clone(),
            tailnet_address: TailnetAddress {
                ipv4: value.tailnet_address.ipv4.addr().to_string(),
                ipv6: value.tailnet_address.ipv6.addr().to_string(),
            },
            derp_region: value.derp_region.map(|x| x.0.get()),

            machine_key: value.machine_key.as_ref().map(|x| x.as_bytes().into()),
            disco_key: value.disco_key.as_ref().map(|x| x.as_bytes().into()),
            underlay_addresses: value
                .underlay_addresses
                .iter()
                .map(|addr| AddressInfo::from(*addr))
                .collect(),
        }
    }
}
