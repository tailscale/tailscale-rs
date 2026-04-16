use alloc::collections::BTreeMap;

use ts_transport_derp::TlsValidationConfig;

/// The full derp state, a map of [`ts_transport_derp::RegionId`]s to [`Region`]s.
pub type Map = BTreeMap<ts_transport_derp::RegionId, Region>;

/// Convert a derp map from the [`ts_control_serde`] representation to the [`ts_transport_derp`]
/// representation.
pub fn convert_derp_map(
    derp_map: &ts_control_serde::DerpMap<'_>,
) -> impl Iterator<Item = (ts_transport_derp::RegionId, Region)> {
    derp_map.regions.iter().map(|(id, region)| {
        let id = ts_transport_derp::RegionId((*id).into());
        let region: Region = region.into();

        (id, region)
    })
}

/// A single derp [`Region`], holding the region info and all the server info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    /// The info for this region.
    pub info: ts_transport_derp::RegionInfo,

    /// Servers in this region.
    pub servers: Vec<ts_transport_derp::ServerConnInfo>,
}

impl From<&ts_control_serde::DerpRegion<'_>> for Region {
    fn from(region: &ts_control_serde::DerpRegion<'_>) -> Self {
        let info = region_info(region);
        let servers = region.nodes.iter().map(server).collect();

        Region { info, servers }
    }
}

fn region_info(region: &ts_control_serde::DerpRegion) -> ts_transport_derp::RegionInfo {
    ts_transport_derp::RegionInfo {
        name: region.name.to_string(),
        code: region.code.to_string(),
        no_measure_no_home: region.no_measure_no_home,
    }
}

fn server(server: &ts_control_serde::DerpServer) -> ts_transport_derp::ServerConnInfo {
    const DEFAULT_TLS_PORT: u16 = 443;

    let https_port = match server.derp_port {
        0 => DEFAULT_TLS_PORT,
        port => port,
    };

    let tls_config = if server.insecure_for_tests {
        TlsValidationConfig::InsecureForTests
    } else {
        TlsValidationConfig::from_str(server.cert_name.unwrap_or_default(), server.hostname)
    };

    ts_transport_derp::ServerConnInfo {
        hostname: server.hostname.to_string(),
        https_port,
        stun_port: server.stun_port.into(),
        supports_port_80: server.can_port_80,

        ipv4: convert_ip_usage(server.ipv4),
        ipv6: convert_ip_usage(server.ipv6),

        stun_only: server.stun_only,

        tls_validation_config: tls_config,
    }
}

fn convert_ip_usage<T>(ip: ts_control_serde::DerpIpUsage<T>) -> ts_transport_derp::IpUsage<T>
where
    T: Copy,
{
    match ip {
        ts_control_serde::DerpIpUsage::Disable => ts_transport_derp::IpUsage::Disable,
        ts_control_serde::DerpIpUsage::UseDns => ts_transport_derp::IpUsage::UseDns,
        ts_control_serde::DerpIpUsage::FixedAddr(ip) => ts_transport_derp::IpUsage::FixedAddr(ip),
    }
}
