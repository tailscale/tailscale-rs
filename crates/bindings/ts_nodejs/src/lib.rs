//! Node.js bindings for `tailscale-rs`, using [napi-rs](https://napi.rs).
//!
//! This crate is the native layer of the `tailscale-rs` npm package. Its API is not intended to be
//! used directly. The package's public API is the TypeScript wrapper in `lib/`.

use std::{sync::Once, time::Duration};

use napi::{Env, bindgen_prelude::*};
use napi_derive::napi;
use tokio_util::sync::CancellationToken;

mod closable;
mod error;
mod key_state;
mod node_info;
mod socket_address;
mod tcp;
mod udp;

pub use closable::CancelToken;
pub use key_state::{Keys, PublicKeys, generate_keys, public_keys};
pub use node_info::{NodeInfo, TailnetAddress};
pub use socket_address::{AddressInfo, SocketAddress};
pub use tcp::{TcpListener, TcpStream};
pub use udp::{Datagram, UdpSocket};

use crate::{
    closable::{Closable, spawn_cancellable},
    error::{js_arg_err, ts_err},
};

/// How long `Device.close` waits for a graceful shutdown before forcing it.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Parameters for `connect`.
#[napi(object, object_to_js = false)]
pub struct ConnectOptions {
    /// Path of the key file to load keys from (or create).
    pub key_file: Option<String>,
    /// Auth key to authenticate with.
    pub auth_key: Option<String>,
    /// URL of the control server to use instead of the default.
    pub control_server_url: Option<String>,
    /// Hostname to request for this device.
    pub hostname: Option<String>,
    /// Tags to request for this device.
    pub tags: Option<Vec<String>>,
    /// Keys to use for this device, instead of loading or generating them.
    pub keys: Option<Keys>,
    /// Whether this device should be ephemeral.
    pub ephemeral: Option<bool>,
}

/// Connect to tailscale using the specified parameters.
#[napi(ts_return_type = "Promise<Device>")]
pub fn connect<'env>(
    env: &'env Env,
    options: ConnectOptions,
    cancel: Option<&CancelToken>,
) -> Result<PromiseRaw<'env, Device>> {
    static TRACING_ONCE: Once = Once::new();
    TRACING_ONCE.call_once(|| {
        // Logging is off unless asked for.
        if std::env::var_os("RUST_LOG").is_some() {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .try_init()
                .ok();
        }
    });

    let ConnectOptions {
        key_file,
        auth_key,
        control_server_url,
        hostname,
        tags,
        keys,
        ephemeral,
    } = options;

    // Errors are reported from the future so they reject the returned promise rather than throwing.
    let key_state = keys
        .as_ref()
        .map(tailscale::keys::PersistState::try_from)
        .transpose()?;

    spawn_cancellable(env, cancel, async move {
        let mut config = if let Some(key_state) = key_state {
            key_state.into()
        } else if let Some(key_file) = key_file {
            tailscale::Config::default_with_key_file(key_file)
                .await
                .map_err(ts_err)?
        } else {
            tailscale::Config::default()
        };

        config.client_name = Some("ts_nodejs".to_owned());
        if let Some(control_server_url) = control_server_url {
            config.control_server_url = control_server_url.parse().map_err(js_arg_err)?;
        }

        if let Some(hostname) = hostname {
            config.requested_hostname = Some(hostname);
        }

        if let Some(tags) = tags {
            config.requested_tags = tags;
        }

        config.ephemeral = ephemeral.unwrap_or(false);

        let dev = tailscale::Device::new(&config, auth_key)
            .await
            .map_err(ts_err)?;

        Ok(Device {
            inner: Closable::new(dev),
            shut_down: CancellationToken::new(),
        })
    })
}

/// Tailscale client.
#[napi]
pub struct Device {
    inner: Closable<tailscale::Device>,
    /// Cancelled once `close` has finished shutting down the device.
    shut_down: CancellationToken,
}

#[napi]
impl Device {
    /// Bind a new UDP socket on the given `addr`.
    #[napi(ts_return_type = "Promise<UdpSocket>")]
    pub fn udp_bind<'env>(
        &self,
        env: &'env Env,
        addr: SocketAddress,
    ) -> Result<PromiseRaw<'env, UdpSocket>> {
        let addr = addr.try_into()?;

        self.inner.spawn(env, None, async move |dev| {
            let sock = dev.udp_bind(addr).await.map_err(ts_err)?;
            Ok(UdpSocket::new(sock))
        })
    }

    /// Bind a new TCP listen socket on the given `addr`.
    #[napi(ts_return_type = "Promise<TcpListener>")]
    pub fn tcp_listen<'env>(
        &self,
        env: &'env Env,
        addr: SocketAddress,
    ) -> Result<PromiseRaw<'env, TcpListener>> {
        let addr = addr.try_into()?;

        self.inner.spawn(env, None, async move |dev| {
            let listener = dev.tcp_listen(addr).await.map_err(ts_err)?;
            Ok(TcpListener::new(listener))
        })
    }

    /// Create a new TCP connection to the given `addr`.
    #[napi(ts_return_type = "Promise<TcpStream>")]
    pub fn tcp_connect<'env>(
        &self,
        env: &'env Env,
        addr: SocketAddress,
        cancel: Option<&CancelToken>,
    ) -> Result<PromiseRaw<'env, TcpStream>> {
        let addr = addr.try_into()?;

        self.inner.spawn(env, cancel, async move |dev| {
            let sock = dev.tcp_connect(addr).await.map_err(ts_err)?;
            Ok(TcpStream::new(sock))
        })
    }

    /// Get the device's IPv4 tailnet address.
    #[napi(ts_return_type = "Promise<string>")]
    pub fn ipv4_address<'env>(&self, env: &'env Env) -> Result<PromiseRaw<'env, String>> {
        self.inner.spawn(env, None, async move |dev| {
            let ip = dev.ipv4_addr().await.map_err(ts_err)?;
            Ok(ip.to_string())
        })
    }

    /// Get the device's IPv6 tailnet address.
    #[napi(ts_return_type = "Promise<string>")]
    pub fn ipv6_address<'env>(&self, env: &'env Env) -> Result<PromiseRaw<'env, String>> {
        self.inner.spawn(env, None, async move |dev| {
            let ip = dev.ipv6_addr().await.map_err(ts_err)?;
            Ok(ip.to_string())
        })
    }

    /// Look up a peer by name.
    ///
    /// `name` may be an unqualified hostname or a fully-qualified name.
    #[napi(ts_return_type = "Promise<NodeInfo | null>")]
    pub fn peer_by_name<'env>(
        &self,
        env: &'env Env,
        name: String,
    ) -> Result<PromiseRaw<'env, Option<NodeInfo>>> {
        self.inner.spawn(env, None, async move |dev| {
            let node = dev.peer_by_name(&name).await.map_err(ts_err)?;
            Ok(node.map(|node| NodeInfo::from(&node)))
        })
    }

    /// Get this device's node info.
    #[napi(ts_return_type = "Promise<NodeInfo>")]
    pub fn self_node<'env>(&self, env: &'env Env) -> Result<PromiseRaw<'env, NodeInfo>> {
        self.inner.spawn(env, None, async move |dev| {
            let node = dev.self_node().await.map_err(ts_err)?;
            Ok(NodeInfo::from(&node))
        })
    }

    /// Look up a peer by IP address.
    #[napi(ts_return_type = "Promise<NodeInfo | null>")]
    pub fn peer_by_tailnet_ip<'env>(
        &self,
        env: &'env Env,
        ip: String,
    ) -> Result<PromiseRaw<'env, Option<NodeInfo>>> {
        let ip = ip.parse().map_err(js_arg_err)?;

        self.inner.spawn(env, None, async move |dev| {
            let node = dev.peer_by_tailnet_ip(ip).await.map_err(ts_err)?;
            Ok(node.map(|node| NodeInfo::from(&node)))
        })
    }

    /// Look up peer(s) with the most specific route match for the given address.
    #[napi(ts_return_type = "Promise<Array<NodeInfo>>")]
    pub fn peers_with_route<'env>(
        &self,
        env: &'env Env,
        ip: String,
    ) -> Result<PromiseRaw<'env, Vec<NodeInfo>>> {
        let ip = ip.parse().map_err(js_arg_err)?;

        self.inner.spawn(env, None, async move |dev| {
            let nodes = dev.peers_with_route(ip).await.map_err(ts_err)?;
            Ok(nodes.iter().map(NodeInfo::from).collect())
        })
    }

    /// Shut down the device, rejecting any pending operations.
    ///
    /// Resolves once the device has shut down, including if it was already being closed.
    #[napi(ts_return_type = "Promise<void>")]
    pub fn close<'env>(&self, env: &'env Env) -> Result<PromiseRaw<'env, ()>> {
        let dev = self.inner.close();
        let shut_down = self.shut_down.clone();

        env.spawn_future(async move {
            match dev {
                Some(dev) => {
                    dev.shutdown(Some(SHUTDOWN_TIMEOUT)).await;
                    shut_down.cancel();
                }
                // Already closed: wait for the call which closed it to finish shutting down.
                None => shut_down.cancelled().await,
            }

            Ok(())
        })
    }
}
