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
//! For language bindings, see the following crates:
//!
//! - C: [ts_ffi](https://docs.rs/ts_ffi)
//! - Python: [ts_python](https://docs.rs/ts_python)
//! - Elixir: [ts_elixir](https://docs.rs/ts_elixir)
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
//!     &tailscale::Config::default_with_key_file("tsrs_keys.json").await?,
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
//! ## Using `tailscale`
//!
//! To use this crate or the language bindings, you will need to set the `TS_RS_EXPERIMENT` env var
//! to `this_is_unstable_software`. We'll remove this requirement after a third-party code/cryptography
//! audit and any necessary fixes.
//!
//! Under the hood, we use Tokio for our async runtime. You must also use Tokio, any kind and most
//! configurations of Tokio runtimes should work, but there must be one available when you call any
//! async API functions. The easiest way to do this is to use `#[tokio::main]`, see the
//! [Tokio docs](https://docs.rs/tokio) for more information. In the future, we would like to limit
//! our reliance on Tokio so that there are alternatives for users of other async runtimes.
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
//!
//! ## Feature Flags
//!
//! - `axum`: enables the [`axum`] module, which enables you to run an [`axum` HTTP server] on top
//!   of a [`netstack::TcpListener`].
//!
//! ## Platform Support
//!
//! `tailscale` currently supports the following platforms:
//!
//! - Linux (x86_64 and ARM64)
//! - macOS (ARM64)
//!
//! ## Component crates
//!
//! The following crates are part of the tailscale-rs project and are dependencies of this one. For
//! many tasks, just this crate should be sufficient and these other crates are an implementation detail.
//! There are other crates too, see [ARCHITECTURE.md]
//! or the [GitHub repo](https://github.com/tailscale/tailscale-rs).
//!
//! - [ts_runtime](https://docs.rs/ts_runtime): for each API-level `Device`, the runtime uses an actor
//!   architecture to manage the lifecycle of the control client, data plane components, netstack, etc.
//!   A message bus passes updates and communications between these top-level actors.
//! - [ts_netcheck](https://docs.rs/ts_netcheck): checks network availability and reports latency to
//!   DERP servers in different regions.
//! - [ts_netstack_smoltcp](https://docs.rs/ts_netstack_smoltcp): a [smoltcp](https://docs.rs/smoltcp)-based
//!   network stack that processes Layer 3+ packets to/from the overlay network.
//! - [ts_control](https://docs.rs/ts_control): control plane client that handles registration,
//!   authorization/authentication, configuration, and streaming updates.
//! - [ts_dataplane](https://docs.rs/ts_dataplane): wires all the individual data plane functions together,
//!   flowing inbound and outbound packets through the components in the correct order.
//! - [ts_tunnel](https://docs.rs/ts_tunnel): a partial implementation of the WireGuard specification
//!   that protects all data plane traffic, and is interoperable with other WireGuard clients, including Tailscale clients.
//! - [ts_cli_util](https://docs.rs/ts_cli_util): helpers for writing command line tools and initializing
//!   logging, used in examples.
//! - [ts_disco_protocol](https://docs.rs/ts_disco_protocol): incomplete implementation of Tailscale's
//!   discovery protocol (disco).
//!
//! [ARCHITECTURE.md]: https://github.com/tailscale/tailscale-rs/blob/main/ARCHITECTURE.md
//! [CONTRIBUTING.md]: https://github.com/tailscale/tailscale-rs/blob/main/CONTRIBUTING.md
//! [`examples/`]: https://github.com/tailscale/tailscale-rs/blob/main/examples/README.md
//! [open an issue]: https://github.com/tailscale/tailscale-rs/issues
//! [`axum` HTTP server]: https://docs.rs/axum/latest/axum/

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

#[doc(inline)]
pub use config::Config;
#[doc(inline)]
pub use error::{Error, InternalErrorKind};
#[doc(inline)]
pub use ts_control::Node as NodeInfo;
use ts_netstack_smoltcp::{CreateSocket, netcore::Channel};
use ts_runtime::Spawn;

mod addr;
pub use addr::TailnetAddr;
#[cfg(feature = "axum")]
pub mod axum;
pub mod config;
mod error;
mod proxy;
pub use proxy::{TargetStream, TcpProxy};
#[cfg(feature = "ssh")]
pub mod ssh;

/// How a program connects to a tailnet and communicates with peers.
///
/// The `Device` connects to the control plane, registers itself with the tailnet, and communicates
/// with tailnet peers. Its tailnet identity is determined by the key state provided at
/// construction-time.
pub struct Device {
    runtime: ts_runtime::ActorRef<ts_runtime::Runtime>,
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
    /// # use tailscale::*;
    /// let dev = Device::new(
    ///     &Config::default_with_key_file("tsrs_keys.json").await?,
    ///     Some("MY_AUTH_KEY".to_string()),
    /// ).await?;
    /// # Ok(()) }
    /// ```
    pub async fn new(config: &Config, auth_key: Option<String>) -> Result<Self, Error> {
        check_magic_env()?;

        let keys = (&config.key_state).into();
        let rt = ts_runtime::Runtime::spawn(ts_runtime::Config {
            control_config: config.into(),
            auth_key,
            keys,
        });

        rt.wait_for_startup_result()
            .await
            .map_err(ts_runtime::Error::from)?;

        let (channel,) = rt
            .ask(ts_runtime::GetChannel)
            .await
            .map_err(ts_runtime::Error::from)?;

        Ok(Self {
            runtime: rt,
            channel,
        })
    }

    /// Get this [`Device`]'s IPv4 tailnet address.
    pub async fn ipv4_addr(&self) -> Result<Ipv4Addr, Error> {
        self.runtime
            .ask(ts_runtime::Ipv4)
            .await
            .map_err(ts_runtime::Error::from)?
            .ok_or(Error::Internal(InternalErrorKind::Actor))
    }

    /// Get this [`Device`]'s IPv6 tailnet address.
    pub async fn ipv6_addr(&self) -> Result<Ipv6Addr, Error> {
        self.runtime
            .ask(ts_runtime::Ipv6)
            .await
            .map_err(ts_runtime::Error::from)?
            .ok_or(Error::Internal(InternalErrorKind::Actor))
    }

    /// Bind a UDP socket to the specified [`SocketAddr`].
    pub async fn udp_bind(&self, socket_addr: SocketAddr) -> Result<netstack::UdpSocket, Error> {
        self.channel.udp_bind(socket_addr).await.map_err(Into::into)
    }

    /// Bind a TCP listener to the specified [`SocketAddr`].
    pub async fn tcp_listen(
        &self,
        socket_addr: SocketAddr,
    ) -> Result<netstack::TcpListener, Error> {
        self.channel
            .tcp_listen(socket_addr)
            .await
            .map_err(Into::into)
    }

    /// Connect to a TCP socket at the remote address.
    pub async fn tcp_connect(&self, remote: SocketAddr) -> Result<netstack::TcpStream, Error> {
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

    /// Proxies a remote TCP stream with a tailnet peer to a target TCP stream.
    ///
    /// # Warning
    /// `target_addr` may contain any valid IPv4/IPv6 address. If `target_addr` references anything
    /// other than a tailnet peer, data sent between the proxy and the target will no longer be
    /// encrypted, and will be sent in plaintext. This includes `target_addr`s such as localhost
    /// (127.0.0.0/8, etc.), a private IP address (10.0.0.0/8, fd00::/8, etc.), or a public IP
    /// address (1.2.3.4, etc.). Consider the risks of proxying a tailnet peer with a target remote
    /// before using this method.
    ///
    /// # Example
    /// ```rust,no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # use tailscale::*;
    /// let dev = Device::new(
    ///     &Config::default_with_key_file("tsrs_keys.json").await?,
    ///     Some("MY_AUTH_KEY".to_string()),
    /// ).await?;
    /// let listen_addr = (dev.ipv4_addr().await?, 1234).into();
    /// let target_addr = ([127, 0, 0, 1], 4567).into();
    /// dev.tcp_proxy(listen_addr, target_addr, None, None).await?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Details
    /// Listens on the given `listen_addr` for an incoming TCP connection from a remote tailnet
    /// peer. Once the remote stream is established, connects to the given `target_addr` to
    /// establish the target stream, then proxies bytes between the two streams until one stream
    /// closes, or the task is canceled. `target_addr` may be any valid TCP4/TCP6 address, such as
    /// a port on a tailnet peer, localhost, or a public/private IP address.
    ///
    /// Does not retry if the first connection attempt to the `target_addr` fails; retry loops
    /// must be built on top of this method.
    ///
    /// Each direction of the proxy (remote-to-target and target-to-remote) uses a buffer to hold
    /// bytes being proxied. The size of each of these buffers can be tuned with `remote_buf_len`
    /// and `target_buf_len`, respectively. By default, these buffers are 8KiB in size.
    pub async fn tcp_proxy(
        &self,
        listen_addr: SocketAddr,
        remote_buf_len: Option<usize>,
        target_buf_len: Option<usize>,
    ) -> Result<TcpProxy, Error> {
        let listener = self.tcp_listen(listen_addr).await?;
        Ok(TcpProxy::new(
            self.channel.clone(),
            listener,
            remote_buf_len,
            target_buf_len,
        ))
    }

    /// Get our node info.
    pub async fn self_node(&self) -> Result<NodeInfo, Error> {
        self.runtime
            .ask(ts_runtime::SelfNode)
            .await
            .map_err(ts_runtime::Error::from)?
            .ok_or(Error::Internal(InternalErrorKind::Actor))
    }

    /// Look up a peer by name.
    pub async fn peer_by_name(&self, name: &str) -> Result<Option<NodeInfo>, Error> {
        self.runtime
            .ask(ts_runtime::peer_tracker::PeerByName {
                name: name.to_string(),
            })
            .await
            .map_err(ts_runtime::Error::from)
            .map_err(Into::into)
    }

    /// Look up a peer by ip.
    pub async fn peer_by_tailnet_ip(&self, ip: IpAddr) -> Result<Option<NodeInfo>, Error> {
        self.runtime
            .ask(ts_runtime::peer_tracker::PeerByTailnetIp { ip })
            .await
            .map_err(ts_runtime::Error::from)
            .map_err(Into::into)
    }

    /// Look up the peer(s) with the most-specific route matches for `ip`.
    pub async fn peers_with_route(&self, ip: IpAddr) -> Result<Vec<NodeInfo>, Error> {
        self.runtime
            .ask(ts_runtime::peer_tracker::PeerByAcceptedRoute { ip })
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
        match timeout {
            Some(timeout) => {
                if tokio::time::timeout(timeout, async {
                    let _ = self.runtime.stop_gracefully().await;
                    self.runtime.wait_for_shutdown().await;
                })
                .await
                .is_err()
                {
                    self.runtime.kill();

                    return false;
                }

                true
            }
            None => {
                let _ = self.runtime.stop_gracefully().await;
                self.runtime.wait_for_shutdown().await;

                true
            }
        }
    }
}

/// Command-channel-driven userspace network stack.
///
/// This is an opinionated wrapper around [smoltcp](https://docs.rs/smoltcp) that provides an
/// easier-to-integrate, more-portable API.
pub mod netstack {
    #[doc(inline)]
    pub use ts_netstack_smoltcp::netcore::Error;
    #[doc(inline)]
    pub use ts_netstack_smoltcp::netcore::InternalErrorKind;
    #[doc(inline)]
    pub use ts_netstack_smoltcp::netsock::{TcpListener, TcpStream, UdpSocket};
}

/// Tailscale cryptographic key types.
pub mod keys {
    #[doc(inline)]
    pub use ts_keys::{
        DiscoKeyPair, DiscoPrivateKey, DiscoPublicKey, MachineKeyPair, MachinePrivateKey,
        MachinePublicKey, NetworkLockKeyPair, NetworkLockPrivateKey, NetworkLockPublicKey,
        NodeKeyPair, NodePrivateKey, NodePublicKey, NodeState, PersistState,
    };
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

        return Err(Error::UnstableEnvVar);
    };

    Ok(())
}
