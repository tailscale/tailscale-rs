#![allow(non_camel_case_types)]

//! C FFI for tailscale-rs.
//!
//! # Safety
//!
//! All resources created by this library must be treated in accordance with the Rust
//! borrowing and ownership rules. Keep in mind that this _requires_ all memory to be
//! initialized before handing it into Rust-land.
//!
//! Null-checking is the responsibility of the caller, both on function call and return. We
//! don't check for parameter nullity: all params are assumed non-null unless noted
//! otherwise. Null return values are used for error signaling and must be inspected.
//!
//! Handles provided by this library are threadsafe -- operations will be implicitly
//! synchronized and serialized by the runtime. The only caveat is that you cannot `deinit`
//! or `close` a handle concurrently with other operations: this requires external
//! synchronization.

use std::{
    ffi::{self, CStr, c_char},
    sync::{LazyLock, Once},
};

mod net_types;
mod tcp;
mod udp;

pub use net_types::{
    AF_INET, AF_INET6, in_addr_t, in6_addr_t, sa_family_t, sockaddr, sockaddr_data, sockaddr_in,
    sockaddr_in6,
};
pub use tcp::{
    tcp_listener, tcp_stream, ts_tcp_close, ts_tcp_close_listener, ts_tcp_connect, ts_tcp_listen,
    ts_tcp_listener_local_addr, ts_tcp_local_addr, ts_tcp_recv, ts_tcp_remote_addr, ts_tcp_send,
};
pub use udp::{ts_udp_bind, ts_udp_close, ts_udp_recvfrom, ts_udp_sendto, udp_socket};

static TOKIO_RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    tracing::info!("started tokio runtime");

    rt
});

type Result<T> = std::result::Result<T, Box<dyn core::error::Error + Send + Sync + 'static>>;

/// A Tailscale device, also variously called a "node" or "peer".
///
/// A device is the unit of identity in a tailnet; it has a tailnet IP and can send and
/// receive IP datagrams to other peers.
pub struct device(tailscale::Device);

/// Initialize a new Tailscale device.
///
/// `config_path` is the path to a config file on your system. It will be created if it doesn't
/// exist.
///
/// `auth_token` is an optional auth token (you may pass `NULL`) that is used to authenticate the
/// device if required. If you pass `NULL`, the credentials in `config_path` must already be
/// authorized to make a successful connection.
///
/// # Safety
///
/// `config_path` and `auth_token` must be able to be read according to [`CStr`] rules, i.e.
/// they must be NUL-terminated and valid for reading up to and including the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_init(
    config_path: *const c_char,
    auth_token: *const c_char,
) -> Option<Box<device>> {
    static TRACING_ONCE: Once = Once::new();
    TRACING_ONCE.call_once(ts_cli_util::init_tracing);

    async fn _ts_init(config_path: &CStr, auth_token: Option<&CStr>) -> Result<device> {
        let config_path = config_path.to_str()?.to_string();
        tracing::info!(config_path);

        let auth_token = auth_token
            .and_then(|x| x.to_str().ok())
            .map(ToOwned::to_owned);

        let dev = tailscale::Device::new(
            &tailscale::Config::default_with_key_file(&config_path).await?,
            auth_token,
        )
        .await?;

        Result::<_>::Ok(device(dev))
    }

    // SAFETY: ensured by function precondition
    unsafe {
        TOKIO_RUNTIME.block_on(_ts_init(
            CStr::from_ptr(config_path),
            if auth_token.is_null() {
                None
            } else {
                Some(CStr::from_ptr(auth_token))
            },
        ))
    }
    .inspect_err(|e| {
        tracing::error!(err = %e, "ts_init failed");
    })
    .ok()
    .map(Box::new)
}

/// Deinitialize and shut down a Tailscale device.
#[unsafe(no_mangle)]
pub extern "C" fn ts_deinit(dev: Box<device>) {
    drop(dev)
}

/// Get the IPv4 address of the Tailscale node, blocking until it's available.
///
/// Returns a negative number on error.
#[unsafe(no_mangle)]
pub extern "C" fn ts_ipv4_addr(dev: &device, dst: &mut in_addr_t) -> ffi::c_int {
    let addr = match TOKIO_RUNTIME.block_on(dev.0.ipv4_addr()) {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!(error = %e, "getting ipv4");
            return -1;
        }
    };

    dst.0 = addr.octets();

    0
}

/// Get the IPv6 address of the Tailscale node, blocking until it's available.
///
/// Returns a negative number on error.
#[unsafe(no_mangle)]
pub extern "C" fn ts_ipv6_addr(dev: &device, dst: &mut in6_addr_t) -> ffi::c_int {
    let addr = match TOKIO_RUNTIME.block_on(dev.0.ipv6_addr()) {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!(error = %e, "getting ipv6");
            return -1;
        }
    };

    dst.0 = addr.segments();

    0
}

/// Get the IPv4 address of a specified peer by name.
///
/// `peer_name` can be a fully-qualified name (`$HOST.tail1234.ts.net`) or an unqualified
/// hostname (`$HOST`). The first match is returned: shared-in nodes may cause ambiguity
/// when unqualified hostnames are used.
///
/// Returns a negative number if there was an error, zero if no match was found, and a
/// positive number if `addr` has been populated with the address for the requested peer.
///
/// # Safety
///
/// `peer_name` must be able to be read according to [`CStr`] rules, i.e.
/// it must be NUL-terminated and valid for reading up to and including the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_peer_ipv4_addr(
    dev: &device,
    peer_name: *const c_char,
    addr: &mut in_addr_t,
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    unsafe {
        _peer_by_addr(dev, peer_name, |n| {
            *addr = n.tailnet_address.ipv4.addr().into();
        })
    }
}

/// Get the IPv6 address of a specified peer by name.
///
/// `peer_name` can be a fully-qualified name (`$HOST.tail1234.ts.net`) or an unqualified
/// hostname (`$HOST`). The first match is returned: shared-in nodes may cause ambiguity
/// when unqualified hostnames are used.
///
/// Returns a negative number if there was an error, zero if no match was found, and a
/// positive number if `addr` has been populated with the address for the requested peer.
///
/// # Safety
///
/// `peer_name` must be able to be read according to [`CStr`] rules, i.e.
/// it must be NUL-terminated and valid for reading up to and including the NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ts_peer_ipv6_addr(
    dev: &device,
    peer_name: *const c_char,
    addr: &mut in6_addr_t,
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    unsafe {
        _peer_by_addr(dev, peer_name, |n| {
            *addr = n.tailnet_address.ipv6.addr().into();
        })
    }
}

/// # Safety
///
/// `peer_name` must be able to be read according to [`CStr`] rules, i.e.
/// it must be NUL-terminated and valid for reading up to and including the NUL.
unsafe fn _peer_by_addr(
    dev: &device,
    peer_name: *const c_char,
    on_node_info: impl FnOnce(&tailscale::NodeInfo),
) -> ffi::c_int {
    // SAFETY: ensured by function precondition
    let name = unsafe { CStr::from_ptr(peer_name) };

    let Ok(name) = name.to_str() else {
        tracing::error!("peer name: invalid utf-8");
        return -1;
    };

    match TOKIO_RUNTIME.block_on(dev.0.peer_by_name(name)) {
        Ok(Some(node)) => {
            on_node_info(&node);
            1
        }

        Ok(None) => 0,

        Err(e) => {
            tracing::error!(error = %e, "looking up peer");
            -1
        }
    }
}
