use crate::{erl_ip::ErlIp, helpers::sockaddr_to_erl};

/// Info about a Tailscale peer.
#[derive(rustler::NifStruct)]
#[module = "Tailscale.NodeInfo"]
pub struct NodeInfo {
    id: i64,
    stable_id: String,
    hostname: String,
    tailnet: Option<String>,
    tags: Vec<String>,
    tailnet_addresses: Vec<ErlIp>,
    derp_region: Option<u32>,
    node_key: String,
    disco_key: Option<String>,
    machine_key: Option<String>,
    underlay_addresses: Vec<(ErlIp, u16)>,
}

impl From<tailscale::NodeInfo> for NodeInfo {
    fn from(value: tailscale::NodeInfo) -> Self {
        Self {
            id: value.id,
            stable_id: value.stable_id.0,
            hostname: value.hostname,
            tailnet: value.tailnet,
            tags: value.tags,
            tailnet_addresses: vec![
                ErlIp::from(value.tailnet_address.ipv4.addr()),
                ErlIp::from(value.tailnet_address.ipv6.addr()),
            ],
            derp_region: value.derp_region.map(|x| x.0.get()),
            node_key: value.node_key.to_string(),
            disco_key: value.disco_key.as_ref().map(ToString::to_string),
            machine_key: value.machine_key.as_ref().map(ToString::to_string),
            underlay_addresses: value
                .underlay_addresses
                .into_iter()
                .map(sockaddr_to_erl)
                .collect(),
        }
    }
}
