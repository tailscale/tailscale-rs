//! Tailscale SDK.
//!
//! ## Example
//!
//! Example binding a UDP socket and sending periodic pings:
//!
//! ```no_run
//! # use std::{
//! #     time::Duration,
//! #     net::Ipv4Addr,
//! #     error::Error,
//! # };
//! #
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn Error>> {
//! // Open a new connection to tailscale
//! let dev = tailscale::Device::new(
//!     Default::default(), // control config
//!     Some("YOUR_AUTH_KEY_HERE".to_owned()),
//!     Default::default(), // key state: WARNING, this creates a throwaway node identity
//! ).await?;
//!
//! // Bind a UDP socket on our tailnet IP, port 1234
//! let sock = dev.udp_bind((dev.ipv4().await?, 1234).into()).await?;
//!
//! // Send a packet containing "ping" to 100.64.0.1:5678 once per second
//! loop {
//!     sock.send_to((Ipv4Addr::new(100, 64, 0, 1), 5678).into(), b"ping").await?;
//!     tokio::time::sleep(Duration::from_secs(1)).await;
//! }
//! # }
//! ```
//!
//! ## Caveats
//!
//! This software is still a work-in-progress! We are providing it in the open at this stage out of a
//! belief in open-source and to see where the community runs with it, but please be aware of a few
//! important considerations:
//!
//! - This implementation contains unaudited cryptography and hasn't undergone a comprehensive security
//!   analysis. Conservatively, assume there could be a critical security hole meaning anything you send
//!   or receive could be in the clear on the public Internet.
//! - There are no compatibility guarantees at the moment. This is early-days software &mdash; we may
//!   break dependent code in order to get things right.
//! - We currently rely on DERP relays for all communication. Direct connections via NAT holepunching
//!   will be a seamless upgrade in the future, but for now, this puts a cap on data throughput.

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
mod error;

#[doc(inline)]
pub use error::Error;

/// A tailscale device.
pub struct Device {
    runtime: ts_runtime::Runtime,
    channel: Channel,
}

impl Device {
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
    if std::env::var(ENV_MAGIC_VAR).as_deref() != Ok(ENV_MAGIC_VALUE) {
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
