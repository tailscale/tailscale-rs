#![doc = include_str!("../README.md")]

use core::str::FromStr;
use std::{
    net::SocketAddr,
    sync::{Arc, Once},
};

use pyo3::{exceptions::PyValueError, prelude::*};
use pyo3_async_runtimes::tokio::future_into_py;

extern crate tailscale as ts;

type PyFut<'p> = PyResult<Bound<'p, PyAny>>;

mod tcp;
mod udp;

// NOTE(npry): we want to declare our types inside the `tailscale` module so that printing them or
// calling python's `help` reports that their types are `tailscale.*`, rather than `builtin.*`,
// which is what they show if declared outside a `pymodule`, even if reexported from one.
//
// The module organization is awkward because proc-macro annotation on file modules is
// currently unstable: https://github.com/rust-lang/rust/issues/54727. Ideally we'd put `tailscale`
// in `tailscale.rs` and make `udp` and `tcp` submodules of it, but that currently doesn't work.

/// Tailscale API.
#[pymodule]
pub mod tailscale {
    use std::net::IpAddr;

    use super::*;

    /// Connect to tailscale using the specified config file and optional auth key.
    #[pyfunction]
    #[pyo3(signature = (config_path, auth_key=None))]
    pub fn connect(py: Python<'_>, config_path: String, auth_key: Option<String>) -> PyFut<'_> {
        static TRACING_ONCE: Once = Once::new();
        TRACING_ONCE.call_once(ts_cli_util::init_tracing);

        future_into_py(py, async move {
            let config = ts_cli_util::Config::load_or_init(config_path.as_ref()).await?;

            // TODO(npry): let clients also define an app name once the sdk-level name moves
            //  to a dedicated field
            let mut control_config = config.control_config();
            control_config.client_name = Some("ts_python".to_owned());

            let dev = ts::Device::new(control_config, auth_key, config.key_state)
                .await
                .map_err(py_value_err)?;

            Ok(Device { dev: Arc::new(dev) })
        })
    }

    /// Tailscale client.
    #[pyclass(frozen)]
    pub struct Device {
        dev: Arc<ts::Device>,
    }

    /// A TCP listen socket.
    #[pyclass(frozen)]
    pub struct TcpListener {
        pub(crate) listener: Arc<ts::TcpListener>,
    }

    /// An established TCP stream.
    #[pyclass(frozen)]
    pub struct TcpStream {
        pub(crate) sock: Arc<ts::TcpStream>,
    }

    /// A tailscale UDP socket.
    #[pyclass(frozen)]
    pub struct UdpSocket {
        pub(crate) sock: Arc<ts::UdpSocket>,
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

                Ok(UdpSocket {
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

                Ok(TcpListener {
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

                Ok(TcpStream {
                    sock: Arc::new(sock),
                })
            })
        }

        /// Get the device's IPv4 tailnet address.
        pub fn ipv4<'p>(&self, py: Python<'p>) -> PyFut<'p> {
            let dev = self.dev.clone();

            future_into_py(py, async move {
                let ip = dev.ipv4().await.map_err(py_value_err)?;
                Ok(ip.to_string())
            })
        }

        /// Get the device's IPv6 tailnet address.
        pub fn ipv6<'p>(&self, py: Python<'p>) -> PyFut<'p> {
            let dev = self.dev.clone();

            future_into_py(py, async move {
                let ip = dev.ipv6().await.map_err(py_value_err)?;
                Ok(ip.to_string())
            })
        }
    }
}

fn sockaddr_as_tuple(s: SocketAddr) -> (String, u16) {
    (s.ip().to_string(), s.port())
}

fn py_value_err(e: impl ToString) -> PyErr {
    PyValueError::new_err(e.to_string())
}
