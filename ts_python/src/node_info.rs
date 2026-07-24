use std::net::IpAddr;

/// Info about a tailscale node.
///
/// Turned into a `dict` on the Python side via `IntoPyObject`.
#[derive(Debug, PartialEq, Eq, pyo3::IntoPyObject)]
pub struct NodeInfo {
    /// Node's id.
    pub id: i64,
    /// Stable id.
    pub stable_id: String,
    /// The node's hostname.
    pub hostname: String,
    /// The tailnet to which this node belongs.
    pub tailnet: Option<String>,
    /// This node's tags.
    pub tags: Vec<String>,
    /// The tailnet addresses this device has.
    pub tailnet_addresses: Vec<IpAddr>,
    /// This node's home derp region.
    pub derp_region: Option<u32>,
    /// This node's node key.
    pub node_key: Vec<u8>,
    /// This node's disco key.
    pub disco_key: Option<Vec<u8>>,
    /// This node's machine key.
    pub machine_key: Option<Vec<u8>>,
    /// The underlay addresses on which this node is reachable.
    pub underlay_addresses: Vec<(IpAddr, u16)>,
}

impl From<&tailscale::NodeInfo> for NodeInfo {
    fn from(value: &tailscale::NodeInfo) -> Self {
        Self {
            id: value.id,
            stable_id: value.stable_id.0.clone(),
            tags: value.tags.clone(),
            node_key: value.node_key.as_bytes().to_vec(),

            hostname: value.hostname.clone(),
            tailnet: value.tailnet.clone(),
            tailnet_addresses: vec![
                value.tailnet_address.ipv4.addr().into(),
                value.tailnet_address.ipv6.addr().into(),
            ],
            derp_region: value.derp_region.map(|x| x.0.get()),

            machine_key: value.machine_key.as_ref().map(|x| x.as_bytes().to_vec()),
            disco_key: value.disco_key.as_ref().map(|x| x.as_bytes().to_vec()),
            underlay_addresses: value
                .underlay_addresses
                .iter()
                .map(|addr| (addr.ip(), addr.port()))
                .collect(),
        }
    }
}
