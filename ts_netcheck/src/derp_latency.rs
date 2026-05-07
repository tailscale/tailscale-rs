//! Calculate latency to collections of derp servers.

use core::{fmt::Debug, net::SocketAddr, time::Duration};

use ts_control::DerpMap;
use ts_derp::RegionId;

/// Configuration for probing derp map latency.
#[derive(Debug, Copy, Clone)]
pub struct Config {
    /// The number of region probes that must succeed for the probe to end.
    ///
    /// After `complete_threshold` and `min_timeout` are met (or all region probes
    /// complete), the derp map measurement ends.
    pub complete_threshold: usize,

    /// The shortest duration for a derp map probe.
    ///
    /// After `complete_threshold` and `min_timeout` are met (or all region probes
    /// complete), the derp map measurement ends.
    pub min_timeout: Duration,

    /// Config for HTTP probes.
    pub https: crate::https::Config,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            complete_threshold: 3,
            min_timeout: Duration::from_millis(250),

            https: Default::default(),
        }
    }
}

/// Result of measuring latency for a particular derp region.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegionResult {
    // NOTE(npry): field order is load-bearing wrt. *Ord derives. `latency` must come first to
    // ensure results are primarily sorted by latency.
    /// The measured latency.
    pub latency: Duration,
    /// The id of the region.
    pub id: RegionId,
    /// The latency map key (in the format to be submitted to control).
    pub latency_map_key: String,
    /// The remote peer we successfully ran the measurement against.
    pub connected_remote: SocketAddr,
}

/// Measure all regions in the supplied [`DerpMap`] and return a binary heap sorted by
/// mean per-region sample time.
#[tracing::instrument(skip_all)]
pub async fn measure_derp_map(map: &DerpMap, config: &Config) -> Vec<RegionResult> {
    let mut joinset = tokio::task::JoinSet::new();

    for (&id, region) in map {
        if region.info.no_measure_no_home {
            tracing::trace!(region_id = %id, "skip! region is no_measure_no_home");
            continue;
        }

        let servers = region.servers.clone();
        let latency_map_key = format!("{id}-v4");

        let config = config.https;

        joinset.spawn(async move {
            let sample_info = crate::measure_https_latency(&servers, config)
                .await
                .map(|(dur, _info, addr)| (dur, addr));

            Result::<_, crate::https::Error>::Ok((id, latency_map_key, sample_info))
        });
    }

    let mut out = Vec::with_capacity(map.len());

    let process_joinset_result = |out: &mut Vec<_>, ret| {
        match ret {
            Ok(Ok((id, latency_map_key, Some((dur, addr))))) => {
                out.push(RegionResult {
                    latency: dur,
                    connected_remote: addr,
                    id,
                    latency_map_key,
                });
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, "measuring region failed");
            }
            Ok(Ok((id, ..))) => {
                tracing::error!(%id, "region had no reachable servers");
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to join");
            }
        };
    };

    let mut timeout = core::pin::pin![tokio::time::sleep(config.min_timeout)];

    while !(out.len() >= config.complete_threshold && timeout.is_elapsed()) {
        tokio::select! {
            ret = joinset.join_next() => {
                let Some(ret) = ret else {
                    break;
                };

                process_joinset_result(&mut out, ret);
            },
            _ = &mut timeout => {},
        }
    }

    // If there are any more ready results available without waiting, add them.
    while let Some(x) = joinset.try_join_next() {
        process_joinset_result(&mut out, x);
    }

    out.sort();

    out
}

#[cfg(test)]
mod test {
    use super::*;

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn map() {
        if !ts_test_util::run_net_tests() {
            return;
        }

        let map = load_derp_map().await;
        let result = measure_derp_map(&map, &Default::default()).await;

        tracing::info!("measured latencies:\n{result:#?}");
    }

    async fn load_derp_map() -> DerpMap {
        const DERP_MAP_URL: &str = "https://login.tailscale.com/derpmap/default";

        let result = reqwest::get(DERP_MAP_URL).await.unwrap();
        let body = result.bytes().await.unwrap();

        let map = serde_json::from_slice::<ts_control_serde::DerpMap>(&body).unwrap();

        ts_control::convert_derp_map(&map).collect()
    }
}
