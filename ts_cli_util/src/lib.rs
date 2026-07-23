#![doc = include_str!("../README.md")]

use std::sync::Arc;

use futures_util::{Stream, StreamExt};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};
use ts_control::MapRequestBuilder;
use ts_derp::{RegionId, ServerConnInfo};
use ts_netcheck::RegionResult;

/// Result with a boxed [`core::error::Error`] trait object.
pub type Result<T> = core::result::Result<T, Box<dyn core::error::Error + Send + Sync + 'static>>;

#[cfg(not(all(target_os = "windows", target_env = "gnu")))]
#[cfg(feature = "tracy")]
#[global_allocator]
static GLOBAL_ALLOC: tracy_client::ProfiledAllocator<std::alloc::System> =
    tracy_client::ProfiledAllocator::new(std::alloc::System, 128);

/// Shared args for a tailscale cli program.
#[derive(Debug, Clone, PartialEq, Eq, clap::Parser)]
pub struct CommonArgs {
    /// The path of the key file to save to.
    #[arg(short = 'c', long, default_value = "tsrs_keys.json")]
    pub key_state_path: std::path::PathBuf,

    /// The auth key to connect with.
    ///
    /// Can be omitted if the keys in the config are already authenticated.
    #[arg(short = 'k', long)]
    pub auth_key: Option<String>,

    /// The hostname this node will request.
    ///
    /// If left blank, uses the hostname reported by the OS.
    #[arg(short = 'H', long)]
    pub hostname: Option<String>,

    /// URL of the control server to connect to.
    #[arg(long)]
    pub control_url: Option<url::Url>,
}

impl CommonArgs {
    /// Convert the args to a [`tailscale::Config`].
    pub async fn config(&self) -> Result<tailscale::Config> {
        let mut config = tailscale::Config::default_with_key_file(&self.key_state_path).await?;

        config.requested_hostname = self.hostname.clone();
        config.control_server_url = self
            .control_url
            .clone()
            .unwrap_or(ts_control::DEFAULT_CONTROL_SERVER.clone());

        Ok(config)
    }

    /// Load or init the config, then connect to the configured control server.
    pub async fn connect_control(
        &self,
    ) -> Result<(
        tailscale::Config,
        ts_keys::NodeState,
        ts_control::client::HttpConn,
        impl Stream<Item = Arc<ts_control::StateUpdate>> + Send + Sync + use<>,
    )> {
        let config: tailscale::Config = self.config().await?;

        let conn = ts_control::connect(
            &config.control_server_url,
            &config.key_state.machine_key.clone().into(),
        )
        .await?;

        let ctrl_conf: ts_control::Config = (&config).into();
        let key_state = config.key_state.clone().into();

        ts_control::register(
            &ctrl_conf,
            &config.control_server_url,
            self.auth_key.as_deref(),
            None,
            &key_state,
            &conn,
        )
        .await?;

        let stream = ts_control::client::start_stream(
            &ctrl_conf.server_url,
            &key_state,
            &ctrl_conf,
            conn.clone(),
        )
        .await?
        .map(Arc::new);

        tracing::info!("connected to control");

        Ok((config, key_state, conn, stream))
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
        cfg_if::cfg_if! {
            if #[cfg(not(all(target_os = "windows", target_env = "gnu")))] {
                layers.push(tracing_tracy::TracyLayer::default().boxed());
            } else {
                eprintln!("warning: ts_cli_util/tracy feature enabled but this is a noop on *-windows-gnu");
            }
        }
    }

    tracing_subscriber::registry().with(layers).init();
}

/// Load the derp map, then measure latencies and set the closest derp region. Returns the
/// URL for the preferred derp server.
#[tracing::instrument(skip(stream), ret, err)]
pub async fn set_closest_derp(
    keys: &ts_keys::NodeState,
    control_url: &url::Url,
    conn: &ts_control::client::HttpConn,
    stream: impl Stream<Item = Arc<ts_control::StateUpdate>>,
) -> Result<(RegionId, Vec<ServerConnInfo>)> {
    let mut netmap_stream = core::pin::pin![stream.filter_map(async |x| x.derp.clone())];

    let map = netmap_stream.next().await.ok_or("could not get derp map")?;

    let regions = ts_netcheck::measure_derp_map(&map, &Default::default()).await;

    let Some(RegionResult { id, .. }) = regions.first() else {
        return Err("no derp regions found".into());
    };

    let mr = MapRequestBuilder::new(keys)
        .as_request()
        .preferred_derp(*id)
        .derp_latencies(regions.iter().map(|result| {
            (
                result.latency_map_key.as_str(),
                result.latency.as_secs_f64(),
            )
        }))
        .build();

    ts_control::client::send_map_request(mr, &control_url.join("machine/map").unwrap(), conn)
        .await?;

    Ok((*id, map.get(id).unwrap().servers.clone()))
}
