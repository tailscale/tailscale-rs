//! Common code used by multiple `ts_transport_derp` examples.

use std::{collections::BTreeMap, num::NonZeroU32};

use ts_transport_derp::{RegionId, ServerConnInfo, TlsValidationConfig};

/// ID of DERP Region #1, which is New York City.
pub const REGION_1: RegionId = RegionId(NonZeroU32::new(1).unwrap());

/// Load the DERP map from `login.tailscale.com`.
pub async fn load_derp_map() -> BTreeMap<RegionId, Vec<ServerConnInfo>> {
    const DERP_MAP_URL: &str = "https://login.tailscale.com/derpmap/default";

    let result = reqwest::get(DERP_MAP_URL).await.unwrap();
    let body = result.bytes().await.unwrap();

    let map = serde_json::from_slice::<ts_control_serde::DerpMap>(&body).unwrap();

    map.regions
        .into_iter()
        .map(|(id, region)| {
            let id = RegionId(id.into());

            let node = region
                .nodes
                .into_iter()
                .map(|server| ServerConnInfo {
                    tls_validation_config: TlsValidationConfig::from_str(
                        server.cert_name.unwrap_or_default(),
                        server.hostname,
                    ),

                    supports_port_80: server.can_port_80,
                    ipv4: convert_ip_usage(server.ipv4),
                    ipv6: convert_ip_usage(server.ipv6),
                    hostname: server.hostname.to_owned(),
                    https_port: if server.derp_port == 0 {
                        443
                    } else {
                        server.derp_port
                    },
                    stun_only: server.stun_only,
                    stun_port: server.stun_port.into(),
                })
                .collect();

            (id, node)
        })
        .collect()
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

#[allow(dead_code)]
fn main() {}
