use std::sync::Arc;

use pyo3::{PyResult, Python, exceptions::PyOSError, pyclass, pymethods};
use pyo3_async_runtimes::tokio::future_into_py;

use crate::{PyFut, py_value_err, sockaddr_as_tuple};

/// A TCP listen socket.
#[pyclass(frozen, module = "tailscale")]
pub struct TcpListener {
    pub(crate) listener: Arc<ts::TcpListener>,
}

/// An established TCP stream.
#[pyclass(frozen, module = "tailscale")]
pub struct TcpStream {
    pub(crate) sock: Arc<ts::TcpStream>,
}

#[pymethods]
impl TcpListener {
    /// Accept a new incoming connection.
    ///
    /// Blocks indefinitely until a connection is ready to be accepted.
    pub fn accept<'p>(&self, py: Python<'p>) -> PyFut<'p> {
        let sock = Arc::clone(&self.listener);

        future_into_py(py, async move {
            let stream = sock.accept().await.map_err(py_value_err)?;

            Ok(TcpStream {
                sock: Arc::new(stream),
            })
        })
    }

    /// Get the local endpoint this TCP listener is listening on.
    pub fn local_endpoint_addr(&self) -> (String, u16) {
        sockaddr_as_tuple(self.listener.local_endpoint_addr())
    }

    fn __repr__(&self) -> String {
        format!(
            "tailscale.TcpListener({})",
            self.listener.local_endpoint_addr(),
        )
    }
}

#[pymethods]
impl TcpStream {
    /// Send bytes to the stream, returning the number of bytes transmitted.
    ///
    /// Always sends at least one byte if not an error.
    pub fn send<'p>(&self, py: Python<'p>, msg: &[u8]) -> PyFut<'p> {
        let sock = Arc::clone(&self.sock);
        let msg = msg.to_vec();

        future_into_py(py, async move {
            let n = sock.send(&msg).await.map_err(py_value_err)?;

            Ok(n)
        })
    }

    /// Receive bytes from the stream.
    ///
    /// Always returns at least one byte if not an error.
    pub fn recv<'p>(&self, py: Python<'p>) -> PyFut<'p> {
        let sock = Arc::clone(&self.sock);

        future_into_py(py, async move {
            let ret = sock.recv_bytes().await.map_err(py_value_err)?;

            Ok(ret)
        })
    }

    /// Get the local endpoint this socket is bound to.
    pub fn local_endpoint_addr(&self) -> (String, u16) {
        sockaddr_as_tuple(self.sock.local_endpoint_addr())
    }

    /// Get the remote endpoint this socket is connected to.
    pub fn remote_endpoint_addr(&self) -> (String, u16) {
        sockaddr_as_tuple(self.sock.remote_endpoint_addr())
    }

    fn __repr__(&self) -> String {
        format!(
            "tailscale.TcpStream({} -> {})",
            self.sock.local_endpoint_addr(),
            self.sock.remote_endpoint_addr()
        )
    }

    // I/O API:

    /// Report whether the stream is writable.
    ///
    /// Always returns `True`.
    pub fn writable(&self) -> bool {
        true
    }

    /// Report whether the stream is writable.
    ///
    /// Always returns `True`.
    pub fn readable(&self) -> bool {
        true
    }

    /// Report whether the stream is writable.
    ///
    /// Always returns `False`.
    pub fn seekable(&self) -> bool {
        false
    }

    /// Report the current position.
    ///
    /// TCP streams don't support seeking, so this always returns `0`.
    pub fn tell(&self) -> usize {
        0
    }

    /// Report whether this is a TTY.
    ///
    /// Always returns `False`.
    pub fn isatty(&self) -> bool {
        false
    }

    /// Report the file descriptor number for this TCP stream.
    ///
    /// As this is a tailscale userspace device, there is no file descriptor, so this always
    /// raises an `OsError`.
    pub fn fileno(&self) -> PyResult<i32> {
        Err(PyOSError::new_err(
            "tailscale.TcpStream does not use a file descriptor",
        ))
    }
}
