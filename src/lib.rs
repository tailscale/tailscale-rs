//! Tailscale SDK.

extern crate ts_netstack_smoltcp as netstack;

use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

#[doc(inline)]
pub use netstack::netsock::{TcpListener, TcpStream, UdpSocket};
use netstack::{CreateSocket, netcore::Channel};

#[cfg(feature = "axum")]
pub mod axum;
mod config;
mod error;
pub mod statefile;

pub use config::Config;
pub use error::Error;

/// A tailscale device.
pub struct Device {
    runtime: ts_runtime::Runtime,
    channel: Channel,
}

impl Device {
    /// Spawn a device from the given [`Config`].
    ///
    /// This is a convenience wrapper around [`Device::new`].
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main]
    /// # async fn main() {
    /// let dev = tailscale::Device::from_config(&tailscale::Config {
    ///     auth_key: Some("MY_AUTH_KEY".to_string()),
    ///     statefile: "mystate.json".into(),
    ///     ..Default::default()
    /// }).await?;
    /// # }
    /// ```
    pub async fn from_config(config: &Config) -> Result<Self, Error> {
        Self::new(
            config.control_config(),
            config.auth_key.clone(),
            config
                .load_statefile()
                .await
                .inspect_err(|e| tracing::error!(error = %e, "loading statefile"))?
                .keys,
        )
        .await
    }

    /// Spawn a new device with the given config, auth key, and keys.
    pub async fn new(
        config: ts_control::Config,
        auth_key: Option<String>,
        keys: ts_keys::NodeState,
    ) -> Result<Self, Error> {
        check_magic_env()?;

        let rt = ts_runtime::Runtime::spawn(config, auth_key, keys).await?;
        let channel = rt.channel().await?;

        Ok(Self {
            runtime: rt,
            channel,
        })
    }

    /// Get this node's IPv4 tailnet address.
    pub async fn ipv4(&self) -> Result<Ipv4Addr, Error> {
        self.runtime
            .control
            .ask(ts_runtime::control_runner::Ipv4)
            .await
            .map_err(ts_runtime::Error::from)?
            .ok_or(Error::InternalFailure)
    }

    /// Get this node's IPv6 tailnet address.
    pub async fn ipv6(&self) -> Result<Ipv6Addr, Error> {
        self.runtime
            .control
            .ask(ts_runtime::control_runner::Ipv6)
            .await
            .map_err(ts_runtime::Error::from)?
            .ok_or(Error::InternalFailure)
    }

    /// Bind a UDP socket to `port` on the specified [`SocketAddr`].
    pub async fn udp_bind(&self, socket_addr: SocketAddr) -> Result<UdpSocket, Error> {
        self.channel.udp_bind(socket_addr).await.map_err(Into::into)
    }

    /// Bind a TCP listener to `port` on the specified [`SocketAddr`].
    pub async fn tcp_listen(&self, socket_addr: SocketAddr) -> Result<TcpListener, Error> {
        self.channel
            .tcp_listen(socket_addr)
            .await
            .map_err(Into::into)
    }

    /// Connect to a TCP socket at the remote address.
    pub async fn tcp_connect(&self, remote: SocketAddr) -> Result<TcpStream, Error> {
        let ip: IpAddr = match remote.is_ipv4() {
            true => self.ipv4().await?.into(),
            false => self.ipv6().await?.into(),
        };

        // TODO(npry): collision checking
        let ephemeral_port = rand::random_range(49152..=u16::MAX);

        self.channel
            .tcp_connect((ip, ephemeral_port).into(), remote)
            .await
            .map_err(Into::into)
    }

    /// Attempt to gracefully shut down this device's runtime.
    ///
    /// Reports whether the device was fully shut down before the timeout. It is still shut
    /// down if it timed out, just more violently and with potential resource leaks.
    pub async fn graceful_shutdown(self, timeout: Option<Duration>) -> bool {
        self.runtime.graceful_shutdown(timeout).await
    }
}

const ENV_MAGIC_VAR: &str = "TS_RS_EXPERIMENT";
const ENV_MAGIC_VALUE: &str = "this_is_unstable_software";

fn check_magic_env() -> Result<(), Error> {
    let Ok(ENV_MAGIC_VALUE) = std::env::var(ENV_MAGIC_VAR).as_deref() else {
        let warning = format!(
            "
check failed: set {ENV_MAGIC_VAR}={ENV_MAGIC_VALUE} to acknowledge that tailscale-rs is early-days
experimental software containing bugs, unvalidated cryptography, and no stability or compatibility 
guarantees.
            "
        );

        eprintln!("{}", warning.trim());

        return Err(Error::InternalFailure);
    };

    Ok(())
}
