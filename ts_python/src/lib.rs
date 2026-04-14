#![doc = include_str!("../README.md")]

use core::str::FromStr;
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Once},
};

use pyo3::{exceptions::PyValueError, prelude::*};
use pyo3_async_runtimes::tokio::future_into_py;

extern crate tailscale as ts;

type PyFut<'p> = PyResult<Bound<'p, PyAny>>;

mod tcp;
mod udp;

/// Tailscale API.
#[pymodule]
pub mod tailscale {
    use super::*;
    #[pymodule_export]
    use crate::{
        Device,
        tcp::{TcpListener, TcpStream},
        udp::UdpSocket,
    };

    /// Connect to tailscale using the specified config file and optional auth key.
    #[pyfunction]
    #[pyo3(signature = (config_path, auth_key=None))]
    pub fn connect(py: Python<'_>, config_path: String, auth_key: Option<String>) -> PyFut<'_> {
        static TRACING_ONCE: Once = Once::new();
        TRACING_ONCE.call_once(ts_cli_util::init_tracing);

        future_into_py(py, async move {
            let config = ts::Config {
                key_state: ts::load_key_file(config_path, Default::default())
                    .await
                    .map_err(py_value_err)?,
                client_name: Some("ts_python".to_owned()),
                ..Default::default()
            };

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
    pub fn udp_bind<'p>(&self, py: Python<'p>, addr: (&str, u16)) -> PyFut<'p> {
        let dev = self.dev.clone();
        let ip = IpAddr::from_str(addr.0);

        future_into_py(py, async move {
            let ip = ip.map_err(py_value_err)?;

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
    pub fn tcp_listen<'p>(&self, py: Python<'p>, addr: (&str, u16)) -> PyFut<'p> {
        let dev = self.dev.clone();
        let ip = IpAddr::from_str(addr.0);

        future_into_py(py, async move {
            let ip = ip.map_err(py_value_err)?;

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
    pub fn tcp_connect<'p>(&self, py: Python<'p>, addr: (&str, u16)) -> PyFut<'p> {
        let dev = self.dev.clone();
        let ip = IpAddr::from_str(addr.0);

        future_into_py(py, async move {
            let ip = ip.map_err(py_value_err)?;

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
            Ok(ip.to_string())
        })
    }

    /// Get the device's IPv6 tailnet address.
    pub fn ipv6_addr<'p>(&self, py: Python<'p>) -> PyFut<'p> {
        let dev = self.dev.clone();

        future_into_py(py, async move {
            let ip = dev.ipv6_addr().await.map_err(py_value_err)?;
            Ok(ip.to_string())
        })
    }
}

fn sockaddr_as_tuple(s: SocketAddr) -> (String, u16) {
    (s.ip().to_string(), s.port())
}

fn py_value_err(e: impl ToString) -> PyErr {
    PyValueError::new_err(e.to_string())
}
