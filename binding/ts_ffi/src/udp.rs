use std::ffi;

use crate::TOKIO_RUNTIME;

/// A Tailscale UDP socket handle.
pub struct udp_socket(tailscale::netstack::UdpSocket);

/// Bind a UDP socket on `addr`.
///
/// Returns null if an error occurred.
#[unsafe(no_mangle)]
pub extern "C" fn ts_udp_bind(
    dev: &crate::device,
    addr: &crate::sockaddr,
) -> Option<Box<udp_socket>> {
    let addr = addr.try_into().ok()?;

    match TOKIO_RUNTIME.block_on(dev.0.udp_bind(addr)) {
        Ok(sock) => Some(Box::new(udp_socket(sock))),
        Err(e) => {
            tracing::error!(error = %e, "binding udp socket");
            None
        }
    }
}

/// Close the specified UDP socket.
#[unsafe(no_mangle)]
pub extern "C" fn ts_udp_close(sock: Box<udp_socket>) {
    drop(sock);
}

/// Send data over the specified socket to the given `addr`.
///
/// Returns a negative number if an error occurred.
///
/// # Safety
///
/// `buf` must be safe to convert into a Rust slice of length `len` (see
/// [`core::slice::from_raw_parts`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_udp_sendto(
    sock: &udp_socket,
    addr: &crate::sockaddr,
    msg: *const u8,
    len: usize,
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    let msg = unsafe { core::slice::from_raw_parts(msg, len) };

    let Ok(addr) = addr.try_into() else {
        return -1;
    };

    if let Err(e) = sock.0.send_to_blocking(addr, msg) {
        tracing::error!(err = %e, "udp_send failed");
        return -1;
    }

    0
}

/// Receive a packet from the socket.
///
/// `addr` may be `None` (null) if the sender's address isn't needed.
///
/// Returns the length of the packet, or a negative number on error. This is guaranteed to
/// be less than or equal to `len`.
///
/// # Safety
///
/// `buf` must be safe to convert into a mutable Rust slice of length `len` (see
/// [`core::slice::from_raw_parts_mut`]).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_udp_recvfrom(
    sock: &udp_socket,
    addr: Option<&mut crate::sockaddr>,
    buf: *mut u8,
    len: usize,
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    let buf = unsafe { core::slice::from_raw_parts_mut(buf, len) };

    match sock.0.recv_from_blocking(buf) {
        Err(e) => {
            tracing::error!(err = %e, "udp_recv failed");
            -1
        }
        Ok((who, len)) => {
            tracing::trace!(%who);

            if let Some(addr) = addr {
                *addr = who.into();
            }

            len as _
        }
    }
}

/// Get the local endpoint to which the socket is bound.
#[unsafe(no_mangle)]
pub extern "C" fn ts_udp_local_addr(sock: &udp_socket) -> crate::sockaddr {
    sock.0.local_addr().into()
}
