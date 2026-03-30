//! Common utilities for writing command-line clients and examples with tailscale-rs.

mod config;

use std::sync::Arc;

#[doc(inline)]
pub use config::Config;
use futures_util::{Stream, StreamExt};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};
use ts_netcheck::RegionResult;
use ts_transport_derp::{RegionId, ServerConnInfo};

/// Result with a boxed [`core::error::Error`] trait object.
pub type Result<T> = core::result::Result<T, Box<dyn core::error::Error + Send + Sync + 'static>>;

#[cfg(feature = "tracy")]
#[global_allocator]
static GLOBAL_ALLOC: tracy_client::ProfiledAllocator<std::alloc::System> =
    tracy_client::ProfiledAllocator::new(std::alloc::System, 128);

/// Shared args for a tailscale cli program.
#[derive(Debug, Clone, PartialEq, Eq, clap::Parser)]
pub struct CommonArgs {
    /// The path of the config file to save to.
    #[arg(short, long, default_value = "config.json")]
    pub statefile: std::path::PathBuf,

    /// The auth key to connect with.
    ///
    /// Can be omitted if the keys in the config are already authenticated.
    #[arg(short = 'k', long)]
    pub auth_key: Option<String>,
}

impl CommonArgs {
    /// Load or init the config using the config path from the args.
    pub async fn load_or_init_config(&self) -> std::io::Result<Config> {
        Config::load_or_init(&self.statefile).await
    }

    /// Load or init the config, then connect to the configured control server.
    pub async fn connect(
        &self,
    ) -> Result<(
        Config,
        ts_control::AsyncControlClient,
        impl Stream<Item = Arc<ts_control::StateUpdate>> + Send + Sync + use<>,
    )> {
        let config = self.load_or_init_config().await?;

        let (client, stream) = ts_control::AsyncControlClient::connect(
            &config.control_config(),
            &config.key_state,
            self.auth_key.as_deref(),
        )
        .await?;
        tracing::info!("connected to control");

        Ok((config, client, stream))
    }
}

/// Init [`tracing`] with a [`tracing_subscriber::Registry`] and a set of default layers,
/// including a stdout layer and a `tracy` layer if the `tracy` feature is enabled.
///
/// The stdout layer makes use of [`tracing_subscriber::EnvFilter`]: default level is
/// `INFO`, overrideable via `env_logger`-style `RUST_LOG` env var.
pub fn init_tracing() {
    let mut layers = vec![];

    // stdout fmt layer:
    {
        let log_env = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        let fmt_layer = tracing_subscriber::fmt::layer();

        let fmt_layer = if std::env::var("TS_RS_LOG_PRETTY") == Ok("1".into()) {
            fmt_layer.pretty().boxed()
        } else {
            fmt_layer.boxed()
        };

        layers.push(fmt_layer.with_filter(log_env).boxed())
    }

    #[cfg(feature = "tracy")]
    {
        layers.push(tracing_tracy::TracyLayer::default().boxed());
    }

    tracing_subscriber::registry().with(layers).init();
}

/// Load the derp map, then measure latencies and set the closest derp region. Returns the
/// URL for the preferred derp server.
#[tracing::instrument(skip(stream), ret, err)]
pub async fn set_closest_derp(
    client: &mut ts_control::AsyncControlClient,
    stream: impl Stream<Item = Arc<ts_control::StateUpdate>>,
) -> Result<(RegionId, Vec<ServerConnInfo>)> {
    let mut netmap_stream = core::pin::pin![stream.filter_map(async |x| x.derp.clone())];

    let map = netmap_stream.next().await.ok_or("could not get derp map")?;

    let regions = ts_netcheck::measure_derp_map(&map, &Default::default()).await;

    let Some(RegionResult { id, .. }) = regions.first() else {
        return Err("no derp regions found".into());
    };

    client
        .set_home_region(
            *id,
            regions.iter().map(|result| {
                (
                    result.latency_map_key.as_str(),
                    result.latency.as_secs_f64(),
                )
            }),
        )
        .await?;

    Ok((*id, map.get(id).unwrap().servers.clone()))
}
