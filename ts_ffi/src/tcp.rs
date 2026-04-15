use std::ffi;

use crate::TOKIO_RUNTIME;

/// A Tailscale TCP listener handle.
pub struct tcp_listener(tailscale::TcpListener);

/// A Tailscale TCP stream handle.
pub struct tcp_stream(tailscale::TcpStream);

/// Start a TCP listener on the given `addr`.
///
/// Returns null if the listener couldn't be created.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_listen(
    dev: &crate::device,
    addr: &crate::sockaddr,
) -> Option<Box<tcp_listener>> {
    let addr = addr.try_into().ok()?;

    match TOKIO_RUNTIME.block_on(dev.0.tcp_listen(addr)) {
        Ok(sock) => Some(Box::new(tcp_listener(sock))),
        Err(e) => {
            tracing::error!(err = %e, "tcp listen");
            None
        }
    }
}

/// Accept an incoming connection on the given listener.
///
/// Returns null if there was an error.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_accept(listener: &tcp_listener) -> Option<Box<tcp_stream>> {
    match listener.0.accept_blocking() {
        Ok(sock) => Some(Box::new(tcp_stream(sock))),
        Err(e) => {
            tracing::error!(err = %e, "tcp accept");
            None
        }
    }
}

/// Get the local endpoint `listener` is listening on.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_listener_local_addr(listener: &tcp_listener) -> crate::sockaddr {
    listener.0.local_addr().into()
}

/// Close the specified socket.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_close_listener(sock: Box<tcp_listener>) {
    drop(sock)
}

/// Open a TCP connection to the specified `remote`.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_connect(
    dev: &crate::device,
    remote: &crate::sockaddr,
) -> Option<Box<tcp_stream>> {
    let addr = remote.try_into().ok()?;

    match TOKIO_RUNTIME.block_on(dev.0.tcp_connect(addr)) {
        Ok(sock) => Some(Box::new(tcp_stream(sock))),
        Err(e) => {
            tracing::error!(err = %e, "binding sock");
            None
        }
    }
}

/// Send bytes to the specified socket, blocking until at least one byte is sent.
///
/// Returns the number of bytes written, or a negative number if an error occurred. This is
/// guaranteed to be less than or equal to `len`.
///
/// # Safety
///
/// `buf` must be safe to convert into a Rust slice of length `len` (see
/// [`core::slice::from_raw_parts`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_tcp_send(
    stream: &tcp_stream,
    buf: *const u8,
    len: usize,
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    let b = unsafe { core::slice::from_raw_parts(buf, len) };

    match stream.0.send_blocking(b) {
        Err(e) => {
            tracing::error!(err = %e, "tcp accept");
            -1
        }
        Ok(n) => n as _,
    }
}

/// Receive bytes from the specified socket, blocking until at least one byte is received.
///
/// Returns the number of bytes read, or a negative number if an error occurred. This is
/// guaranteed to be less than or equal to `len`.
///
/// # Safety
///
/// `buf` must be safe to convert into a mutable Rust slice of length `len` (see
/// [`core::slice::from_raw_parts_mut`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_tcp_recv(stream: &tcp_stream, buf: *mut u8, len: usize) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    let b = unsafe { core::slice::from_raw_parts_mut(buf, len) };

    match stream.0.recv_blocking(b) {
        Err(e) => {
            tracing::error!(err = %e, "tcp accept");
            -1
        }
        Ok(read) => read as _,
    }
}

/// Get the local endpoint for this TCP stream.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_local_addr(stream: &tcp_stream) -> crate::sockaddr {
    stream.0.local_addr().into()
}

/// Get the remote endpoint this TCP stream is connected to.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_remote_addr(stream: &tcp_stream) -> crate::sockaddr {
    stream.0.remote_addr().into()
}

/// Close the specified socket.
#[unsafe(no_mangle)]
pub extern "C" fn ts_tcp_close(sock: Box<tcp_stream>) {
    drop(sock);
}
