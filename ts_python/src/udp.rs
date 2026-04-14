use core::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};
use std::sync::Arc;

use pyo3::{Python, pyclass, pymethods};
use pyo3_async_runtimes::tokio::future_into_py;

use crate::{PyFut, py_value_err, sockaddr_as_tuple};

/// A tailscale UDP socket.
#[pyclass(frozen)]
pub struct UdpSocket {
    pub(crate) sock: Arc<ts::UdpSocket>,
}

#[pymethods]
impl UdpSocket {
    /// Send a datagram to the given address.
    ///
    /// The address argument is currently expected to adopt the 2-tuple form (host, port),
    /// where host is strictly an IP address -- DNS lookup is not yet supported.
    pub fn sendto<'p>(&self, py: Python<'p>, addr: (&str, u16), msg: &[u8]) -> PyFut<'p> {
        let (ip, port) = addr;

        let addr = IpAddr::from_str(ip)?;
        let socket_addr = SocketAddr::new(addr, port);
        let msg = msg.to_vec();

        let sock = self.sock.clone();
        let none = py.None();

        future_into_py(py, async move {
            sock.send_to(socket_addr, &msg)
                .await
                .map_err(py_value_err)?;

            Ok(none)
        })
    }

    /// Receive a datagram from the socket.
    ///
    /// Returns a tuple `(bytes, address)`, e.g. `(b"hello", ("127.0.0.1", 1234))`.
    pub fn recvfrom<'p>(&self, py: Python<'p>) -> PyFut<'p> {
        let sock = self.sock.clone();

        future_into_py(py, async move {
            let (who, msg) = sock.recv_from_bytes().await.map_err(py_value_err)?;

            Ok((msg, (who.ip(), who.port())))
        })
    }

    /// Get the local endpoint this socket is bound to.
    pub fn local_endpoint_addr(&self) -> (String, u16) {
        sockaddr_as_tuple(self.sock.local_endpoint_addr())
    }

    fn __repr__(&self) -> String {
        format!("tailscale.UdpSocket({})", self.sock.local_endpoint_addr())
    }
}
