#![doc = include_str!("../README.md")]

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Once},
};

use pyo3::{
    exceptions::{PyConnectionRefusedError, PyConnectionResetError, PyTimeoutError, PyValueError},
    prelude::*,
};
use pyo3_async_runtimes::tokio::future_into_py;
use tracing_subscriber::filter::LevelFilter;

use crate::ip_or_str::IpRepr;

extern crate tailscale as ts;

type PyFut<'p> = PyResult<Bound<'p, PyAny>>;

mod ip_or_str;
mod key_state;
mod node_info;
mod tcp;
mod udp;

use key_state::Keystate;
use node_info::NodeInfo;
use ts::Error;

/// Tailscale API.
#[pymodule]
pub mod _internal {
    use super::*;
    #[pymodule_export]
    use crate::{
        Device, Keystate,
        tcp::{TcpListener, TcpStream},
        udp::UdpSocket,
    };

    /// Connect to tailscale using the specified parameters.
    #[pyfunction]
    #[pyo3(signature = (key_file_path: "str | None" = None , /, auth_key: "str | None" = None, *, control_server_url: "str | None" = None, hostname: "str | None" = None, tags: "list[str] | None" = None, keys: "Keystate | None" = None) -> "Awaitable[Device]")]
    pub fn connect(
        py: Python<'_>,
        key_file_path: Option<String>,
        auth_key: Option<String>,
        control_server_url: Option<String>,
        hostname: Option<String>,
        tags: Option<Vec<String>>,
        keys: Option<Keystate>,
    ) -> PyFut<'_> {
        static TRACING_ONCE: Once = Once::new();
        TRACING_ONCE.call_once(|| {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                )
                .init();
        });

        future_into_py(py, async move {
            let mut config = if let Some(key_file_path) = key_file_path {
                ts::Config::default_with_key_file(key_file_path)
                    .await
                    .map_err(py_value_err)?
            } else {
                ts::Config::default()
            };

            config.client_name = Some("ts_python".to_owned());
            if let Some(control_server_url) = control_server_url {
                config.control_server_url = control_server_url.parse().map_err(py_value_err)?;
            }

            if let Some(hostname) = hostname {
                config.requested_hostname = Some(hostname);
            }

            if let Some(tags) = tags {
                config.requested_tags = tags;
            }

            if let Some(keys) = &keys {
                config.key_state = keys.try_into().map_err(|_| py_value_err("invalid keys"))?;
            }

            let dev = ts::Device::new(&config, auth_key)
                .await
                .map_err(py_value_err)?;

            Ok(Device { dev: Arc::new(dev) })
        })
    }
}

/// Tailscale client.
#[pyclass(frozen, module = "tailscale")]
pub struct Device {
    dev: Arc<ts::Device>,
}

#[pymethods]
impl Device {
    /// Bind a new UDP socket on the given `addr`.
    ///
    /// `addr` must be given as (host, port). Presently, `host` must be an IP.
    #[pyo3(signature = (addr: "tuple[IPv4Address | IPv6Address | str, int]") -> "Awaitable[UdpSocket]")]
    pub fn udp_bind<'p>(&self, py: Python<'p>, addr: (IpRepr, u16)) -> PyFut<'p> {
        let dev = self.dev.clone();
        let ip: Result<IpAddr, _> = addr.0.try_into();

        future_into_py(py, async move {
            let ip = ip?;

            let sock = dev
                .udp_bind((ip, addr.1).into())
                .await
                .map_err(py_value_err)?;

            Ok(udp::UdpSocket {
                sock: Arc::new(sock),
            })
        })
    }

    /// Bind a new TCP listen socket on the given `addr` and `port`.
    ///
    /// `addr` must be given as (host, port). Presently, `host` must be an IP.
    #[pyo3(signature = (addr: "tuple[IPv4Address | IPv6Address | str, int]") -> "Awaitable[TcpListener]")]
    pub fn tcp_listen<'p>(&self, py: Python<'p>, addr: (IpRepr, u16)) -> PyFut<'p> {
        let dev = self.dev.clone();
        let ip: Result<IpAddr, _> = addr.0.try_into();

        future_into_py(py, async move {
            let ip = ip?;

            let listener = dev
                .tcp_listen((ip, addr.1).into())
                .await
                .map_err(py_value_err)?;

            Ok(tcp::TcpListener {
                listener: Arc::new(listener),
            })
        })
    }

    /// Create a new TCP connection to the given `addr`.
    ///
    /// `addr` must be given as (host, port). Presently, `host` must be an IP.
    #[pyo3(signature = (addr: "tuple[IPv4Address | IPv6Address | str, int]") -> "Awaitable[TcpStream]")]
    pub fn tcp_connect<'p>(&self, py: Python<'p>, addr: (IpRepr, u16)) -> PyFut<'p> {
        let dev = self.dev.clone();
        let ip: Result<IpAddr, _> = addr.0.try_into();

        future_into_py(py, async move {
            let ip = ip?;

            let sock = dev
                .tcp_connect((ip, addr.1).into())
                .await
                .map_err(|e| PyValueError::new_err(e.to_string()))?;

            Ok(tcp::TcpStream {
                sock: Arc::new(sock),
            })
        })
    }

    // TODO (dylan): update doc comment
    /// Proxies a remote TCP stream to a target TCP stream.
    ///
    /// # Warning
    /// `target_addr` may contain any valid IPv4/IPv6 address. If `target_addr` references anything
    /// other than a tailnet peer, data sent between the proxy and the target will no longer be
    /// encrypted, and will be sent in plaintext. This includes `target_addr`s such as localhost
    /// (127.0.0.0/8, etc.), a private IP address (10.0.0.0/8, fd00::/8, etc.), or a public IP
    /// address (1.2.3.4, etc.). Consider the risks of proxying a tailnet peer with a target remote
    /// before using this method.
    ///
    /// # Details
    /// Listens on the given `listen_addr` for an incoming TCP connection from a remote tailnet
    /// peer. Once the remote stream is established, connects to the given `target_addr` to
    /// establish the target stream, then proxies bytes between the two streams until one stream
    /// closes, or the task is canceled.
    ///
    /// Each direction of the proxy (remote-to-target and target-to-remote) uses a buffer to hold
    /// bytes being proxied. The size of each of these buffers can be tuned with `remote_buf_len`
    /// and `target_buf_len`, respectively. By default, these buffers are 8KiB in size.
    #[pyo3(signature = (listen_addr: "tuple[IPv4Address | IPv6Address | str, int]", target_addr: "tuple[IPv4Address | IPv6Address | str, int]", remote_buf_len: "int | None" = None, target_buf_len: "int | None" = None) -> "Awaitable[TcpProxyServer]")]
    pub fn tcp_proxy<'p>(
        &self,
        py: Python<'p>,
        listen_addr: (IpRepr, u16),
        target_addr: (IpRepr, u16),
        remote_buf_len: Option<usize>,
        target_buf_len: Option<usize>,
    ) -> PyFut<'p> {
        let dev = self.dev.clone();
        let listen_addr = (IpAddr::try_from(listen_addr.0)?, listen_addr.1).into();
        let proxy_addr = (IpAddr::try_from(target_addr.0)?, target_addr.1).into();

        future_into_py(py, async move {
            match dev
                .tcp_proxy(listen_addr, proxy_addr, remote_buf_len, target_buf_len)
                .await
            {
                Ok(server) => Ok(tcp::TcpProxy {
                    server: Arc::new(server),
                }),
                Err(err) => {
                    let pyerr = match err {
                        Error::Timeout => PyTimeoutError::new_err(err.to_string()),
                        Error::ConnectionReset => PyConnectionResetError::new_err(err.to_string()),
                        Error::ConnectionRefused => {
                            PyConnectionRefusedError::new_err(err.to_string())
                        }
                        _ => PyValueError::new_err(err.to_string()),
                    };
                    Err(pyerr)
                }
            }
        })
    }

    /// Get the device's IPv4 tailnet address.
    #[pyo3(signature = () -> "Awaitable[IPv4Address]")]
    pub fn ipv4_addr<'p>(&self, py: Python<'p>) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let ip = dev.ipv4_addr().await.map_err(py_value_err)?;
            Ok(ip)
        })
    }

    /// Get the device's IPv6 tailnet address.
    #[pyo3(signature = () -> "Awaitable[IPv6Address]")]
    pub fn ipv6_addr<'p>(&self, py: Python<'p>) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let ip = dev.ipv6_addr().await.map_err(py_value_err)?;
            Ok(ip)
        })
    }

    /// Look up info about a peer by its name.
    ///
    /// `name` may be an unqualified hostname or a fully-qualified name.
    #[pyo3(signature = (name: "str") -> "Awaitable[dict[str, Any]]")]
    pub fn peer_by_name<'p>(&self, py: Python<'p>, name: String) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let node = dev.peer_by_name(&name).await.map_err(py_value_err)?;

            Ok(node.map(|node| NodeInfo::from(&node)))
        })
    }

    /// Get this device's node info.
    #[pyo3(signature = () -> "Awaitable[dict[str, Any]]")]
    pub fn self_node<'p>(&self, py: Python<'p>) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let node = dev.self_node().await.map_err(py_value_err)?;
            Ok(NodeInfo::from(&node))
        })
    }

    /// Look up a peer by its tailnet IP address.
    #[pyo3(signature = (ip: "IPv4Address | IPv6Address | str") -> "Awaitable[dict[str, Any]]")]
    pub fn peer_by_tailnet_ip<'p>(&self, py: Python<'p>, ip: IpRepr) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let ip = ip.try_into().map_err(py_value_err)?;
            let node = dev.peer_by_tailnet_ip(ip).await.map_err(py_value_err)?;

            Ok(node.map(|node| NodeInfo::from(&node)))
        })
    }

    /// Look up peer(s) with the most specific route match for the given address.
    ///
    /// If more than one peer has the same route covering the same address, more than one
    /// result may be returned.
    #[pyo3(signature = (ip: "IPv4Address | IPv6Address | str") -> "Awaitable[list[dict[str, Any]]]")]
    pub fn peers_with_route<'p>(&self, py: Python<'p>, ip: IpRepr) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let ip = ip.try_into().map_err(py_value_err)?;
            let nodes = dev.peers_with_route(ip).await.map_err(py_value_err)?;

            Ok(nodes
                .into_iter()
                .map(|node| NodeInfo::from(&node))
                .collect::<Vec<_>>())
        })
    }
}

fn sockaddr_as_tuple(s: SocketAddr) -> (IpAddr, u16) {
    (s.ip(), s.port())
}

fn py_value_err(e: impl ToString) -> PyErr {
    PyValueError::new_err(e.to_string())
}
