#![doc = include_str!("../README.md")]

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Once},
};

use pyo3::{exceptions::PyValueError, prelude::*};
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
    #[pyo3(signature = (key_file_path=None, /, auth_key=None, *, control_server_url=None, hostname=None, tags=None, keys=None))]
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

    /// Get the device's IPv4 tailnet address.
    pub fn ipv4_addr<'p>(&self, py: Python<'p>) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let ip = dev.ipv4_addr().await.map_err(py_value_err)?;
            Ok(ip)
        })
    }

    /// Get the device's IPv6 tailnet address.
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
    pub fn peer_by_name<'p>(&self, py: Python<'p>, name: String) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let node = dev.peer_by_name(&name).await.map_err(py_value_err)?;

            Ok(node.map(|node| NodeInfo::from(&node)))
        })
    }

    /// Get this device's node info.
    pub fn self_node<'p>(&self, py: Python<'p>) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let node = dev.self_node().await.map_err(py_value_err)?;
            Ok(NodeInfo::from(&node))
        })
    }

    /// Look up a peer by its tailnet IP address.
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
