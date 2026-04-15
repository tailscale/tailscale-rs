//! A work-in-progress [Tailscale](https://tailscale.com/blog/how-tailscale-works) library.
//!
//! `tailscale` allows Rust programs to connect to a tailnet and exchange traffic with peers over
//! TCP and UDP. It can communicate with other `tailscale`-based peers, `tailscaled` (the Tailscale
//! Go client), `tsnet`, and `libtailscale` via public DERP servers.
//!
//! <div class="warning">
//! `tailscale` is unstable and insecure.
//!
//! We welcome enthusiasm and interest, but please **do not** build production software using these
//! libraries or rely on it for data privacy until we have a chance to batten down some hatches and
//! complete a third-party audit.
//!
//! See the [Caveats section](#caveats) for more details.
//! </div>
//!
//! For instructions on how to run tests, lints, etc., see [CONTRIBUTING.md]. For the high-level
//! architecture and repository layout, see [ARCHITECTURE.md].
//!
//! ## Code Sample
//!
//! A simple UDP client that periodically sends messages to a tailnet peer at `100.64.0.1:5678`:
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
//! // Open a new connection to the tailnet
//! let dev = tailscale::Device::new(
//!     &tailscale::Config {
//!         key_state: tailscale::load_key_file("tsrs_key.json", Default::default()).await?,
//!         ..Default::default()
//!     },
//!     Some("YOUR_AUTH_KEY_HERE".to_owned()),
//! ).await?;
//!
//! // Bind a UDP socket on our tailnet IP, port 1234
//! let sock = dev.udp_bind((dev.ipv4_addr().await?, 1234).into()).await?;
//!
//! // Send a packet containing "hello, world!" to 100.64.0.1:5678 once per second
//! loop {
//!     sock.send_to((Ipv4Addr::new(100, 64, 0, 1), 5678).into(), b"hello, world!").await?;
//!     tokio::time::sleep(Duration::from_secs(1)).await;
//! }
//! # }
//! ```
//!
//! Additional examples of using the `tailscale` crate can be found in the [`examples/`] directory.
//!
//! ## Caveats
//!
//! This software is still a work-in-progress! We are providing it in the open at this stage out of
//! a belief in open-source and to see where the community runs with it, but please be aware of a
//! few important considerations:
//!
//! - This implementation contains unaudited cryptography and hasn't undergone a comprehensive
//!   security analysis. Conservatively, assume there could be a critical security hole meaning
//!   anything you send or receive could be in the clear on the public Internet.
//! - There are no compatibility guarantees at the moment. This is early-days software - we may
//!   break dependent code in order to get things right.
//! - We currently rely on DERP relays for all communication. Direct connections via NAT
//!   holepunching will be a seamless upgrade in the future, but for now, this puts a cap on data
//!   throughput.
//! - The `TS_RS_EXPERIMENT` environment variable is required to be set to
//!   `this_is_unstable_software` for all code linked against `tailscale-rs`; this includes Rust, C,
//!   Elixir, and Python code. We'll remove this requirement after a third-party code/cryptography
//!   audit and any necessary fixes.
//!
//! ## Feature Flags
//!
//! `tailscale` has a single feature flag at this time, but we'll be adding more flags as we add
//! more features that can be disabled.
//! - `axum`: enables the `axum` module, which enables you to run an [`axum` HTTP server] on top
//!   of a [`TcpListener`].
//!
//! ## Platform Support
//!
//! `tailscale` currently supports the following platforms:
//!
//! - Linux (`x86_64`/`ARM64`)
//! - macOS (`ARM64`)
//!
//! [ARCHITECTURE.md]: https://github.com/tailscale/tailscale-rs/blob/main/ARCHITECTURE.md
//! [CONTRIBUTING.md]: https://github.com/tailscale/tailscale-rs/blob/main/CONTRIBUTING.md
//! [`examples/`]: https://github.com/tailscale/tailscale-rs/blob/main/examples/README.md
//! [open an issue]: https://github.com/tailscale/tailscale-rs/issues
//! [`axum` HTTP server]: https://docs.rs/axum/latest/axum/

extern crate ts_netstack_smoltcp as netstack;

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

#[doc(inline)]
pub use config::{BadFormatBehavior, Config, load_key_file};
#[doc(inline)]
pub use error::Error;
#[doc(inline)]
pub use netstack::netsock::{TcpListener, TcpStream, UdpSocket};
use netstack::{CreateSocket, netcore::Channel};
#[doc(inline)]
pub use ts_control::Node as NodeInfo;
#[doc(inline)]
pub use ts_keys::NodeState;

#[cfg(feature = "axum")]
pub mod axum;
mod config;
mod error;

/// How a program connects to a tailnet and communicates with peers.
///
/// The `Device` connects to the control plane, registers itself with the tailnet, and communicates
/// with tailnet peers. Its tailnet identity is determined by the key state provided at
/// construction-time.
pub struct Device {
    runtime: ts_runtime::Runtime,
    channel: Channel,
}

impl Device {
    /// Create a device from the given [`Config`] and auth key.
    ///
    /// Internally, this will spawn multiple asynchronous actors onto a Tokio runtime.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let dev = tailscale::Device::new(
    ///     &tailscale::Config {
    ///         key_state: tailscale::load_key_file("tsrs_state.json", Default::default()).await?,
    ///         ..Default::default()
    ///     },
    ///     Some("MY_AUTH_KEY".to_string()),
    /// ).await?;
    /// # Ok(()) }
    /// ```
    pub async fn new(config: &Config, auth_key: Option<String>) -> Result<Self, Error> {
        check_magic_env()?;

        let rt =
            ts_runtime::Runtime::spawn(config.into(), auth_key, config.key_state.clone()).await?;
        let channel = rt.channel().await?;

        Ok(Self {
            runtime: rt,
            channel,
        })
    }

    /// Get this [`Device`]'s IPv4 tailnet address.
    pub async fn ipv4_addr(&self) -> Result<Ipv4Addr, Error> {
        self.runtime
            .control
            .ask(ts_runtime::control_runner::Ipv4)
            .await
            .map_err(ts_runtime::Error::from)?
            .ok_or(Error::InternalFailure)
    }

    /// Get this [`Device`]'s IPv6 tailnet address.
    pub async fn ipv6_addr(&self) -> Result<Ipv6Addr, Error> {
        self.runtime
            .control
            .ask(ts_runtime::control_runner::Ipv6)
            .await
            .map_err(ts_runtime::Error::from)?
            .ok_or(Error::InternalFailure)
    }

    /// Bind a UDP socket to the specified [`SocketAddr`].
    pub async fn udp_bind(&self, socket_addr: SocketAddr) -> Result<UdpSocket, Error> {
        self.channel.udp_bind(socket_addr).await.map_err(Into::into)
    }

    /// Bind a TCP listener to the specified [`SocketAddr`].
    pub async fn tcp_listen(&self, socket_addr: SocketAddr) -> Result<TcpListener, Error> {
        self.channel
            .tcp_listen(socket_addr)
            .await
            .map_err(Into::into)
    }

    /// Connect to a TCP socket at the remote address.
    pub async fn tcp_connect(&self, remote: SocketAddr) -> Result<TcpStream, Error> {
        let ip: IpAddr = match remote.is_ipv4() {
            true => self.ipv4_addr().await?.into(),
            false => self.ipv6_addr().await?.into(),
        };

        // TODO(npry): collision checking
        let ephemeral_port = rand::random_range(49152..=u16::MAX);

        self.channel
            .tcp_connect((ip, ephemeral_port).into(), remote)
            .await
            .map_err(Into::into)
    }

    /// Look up a peer by name.
    pub async fn peer_by_name(&self, name: &str) -> Result<Option<NodeInfo>, Error> {
        let pt = self
            .runtime
            .peer_tracker
            .upgrade()
            .ok_or(Error::RuntimeDegraded)?;

        pt.ask(ts_runtime::peer_tracker::PeerByName {
            name: name.to_string(),
        })
        .await
        .map_err(ts_runtime::Error::from)
        .map_err(Into::into)
    }

    /// Attempt to gracefully shut down this device's runtime.
    ///
    /// Reports whether the device was fully shut down before the timeout. It is still shut
    /// down if it timed out, just more violently and with potential resource leaks.
    ///
    /// If `timeout` is `None`, then shutdown will never time-out.
    pub async fn shutdown(self, timeout: Option<Duration>) -> bool {
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
