use ts_capabilityversion::CapabilityVersion;
use ts_control_serde::{HostInfo, MapRequest, NetInfo};

/// Builder type for [`MapRequest`]s; smooths over the annoying parts of creating a request.
#[derive(Debug, Clone)]
pub struct MapRequestBuilder<'a> {
    req: MapRequest<'a>,
}

impl<'a> MapRequestBuilder<'a> {
    /// Create a new [`MapRequestBuilder`]. By default:
    /// - [`MapRequest::keep_alive`] is `false`
    /// - [`MapRequest::omit_peers`] is `true`
    /// - [`MapRequest::stream`] is `false`
    /// - [`MapRequest::host_info`]:
    ///     - [`HostInfo::hostname`] is populated from [`TailnetPeerConfig::hostname`]
    ///     - [`HostInfo::net_info`] is `None`, therefore:
    ///         - [`NetInfo::derp_latency`][crate::types::NetInfo::derp_latency] is not populated
    ///         - [`NetInfo::preferred_derp`][crate::types::NetInfo::preferred_derp] is not populated
    pub fn new(key_state: &ts_keys::NodeState) -> Self {
        Self {
            req: MapRequest {
                version: CapabilityVersion::CURRENT,

                keep_alive: false,
                omit_peers: true,
                stream: false,

                node_key: key_state.node_keys.public,
                disco_key: key_state.disco_keys.public,

                host_info: Some(HostInfo::default()),
                ..Default::default()
            },
        }
    }

    /// Consumes this [`MapRequestBuilder`] and returns a [`MapRequest`] with the configured
    /// values.
    pub fn build(self) -> MapRequest<'a> {
        self.req
    }

    /// Set the [`MapRequest::keep_alive`] field.
    pub fn keep_alive(mut self, value: bool) -> Self {
        self.req.keep_alive = value;
        self
    }

    /// Set the [`MapRequest::omit_peers`] field.
    pub fn omit_peers(mut self, value: bool) -> Self {
        self.req.omit_peers = value;
        self
    }

    /// Set the [`MapRequest::stream`] field.
    pub fn stream(mut self, value: bool) -> Self {
        self.req.stream = value;
        self
    }

    /// Set the [`HostInfo::hostname`] field.
    pub fn hostname(mut self, hostname: &'a str) -> Self {
        self.host_info_mut().hostname = Some(hostname);
        self
    }

    /// Set the [`NetInfo::preferred_derp`] field (inside [`MapRequest::host_info`] ->
    /// [`HostInfo::net_info`]).
    pub fn preferred_derp(mut self, value: ts_derp::RegionId) -> Self {
        self.net_info_mut().preferred_derp = Some(value.0.into());
        self
    }

    /// Set the [`NetInfo::derp_latency`] field (inside [`MapRequest::host_info`] ->
    /// [`HostInfo::net_info`]).
    pub fn derp_latencies(mut self, value: impl IntoIterator<Item = (&'a str, f64)>) -> Self {
        self.net_info_mut().derp_latency = Some(value.into_iter().collect());

        self
    }

    fn host_info_mut(&mut self) -> &mut HostInfo<'a> {
        self.req.host_info.get_or_insert_default()
    }

    fn net_info_mut(&mut self) -> &mut NetInfo<'a> {
        self.host_info_mut().net_info.get_or_insert_default()
    }
}
