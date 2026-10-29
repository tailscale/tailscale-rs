use std::net::SocketAddr;

use napi::{
    Env,
    bindgen_prelude::{Buffer, PromiseRaw, Result, Uint8Array},
};
use napi_derive::napi;

use crate::{
    AddressInfo, SocketAddress,
    closable::{CancelToken, Closable},
    error::netstack_err,
};

/// A UDP socket.
#[napi]
pub struct UdpSocket {
    pub(crate) sock: Closable<tailscale::netstack::UdpSocket>,
    pub(crate) local_addr: SocketAddr,
}

/// A datagram received from a `UdpSocket`.
#[napi(object, object_from_js = false)]
pub struct Datagram {
    /// The datagram's payload.
    pub data: Buffer,
    /// The address the datagram was sent from.
    pub from: AddressInfo,
}

impl UdpSocket {
    pub(crate) fn new(sock: tailscale::netstack::UdpSocket) -> Self {
        Self {
            local_addr: sock.local_addr(),
            sock: Closable::new(sock),
        }
    }
}

#[napi]
impl UdpSocket {
    /// Send a datagram to the given address.
    #[napi(ts_return_type = "Promise<void>")]
    pub fn send_to<'env>(
        &self,
        env: &'env Env,
        addr: SocketAddress,
        msg: Uint8Array,
    ) -> Result<PromiseRaw<'env, ()>> {
        let addr: SocketAddr = addr.try_into()?;
        let msg = msg.to_vec();

        self.sock.spawn(env, None, async move |sock| {
            sock.send_to(addr, &msg).await.map_err(netstack_err)
        })
    }

    /// Receive a datagram from the socket.
    #[napi(ts_return_type = "Promise<Datagram>")]
    pub fn recv_from<'env>(
        &self,
        env: &'env Env,
        cancel: Option<&CancelToken>,
    ) -> Result<PromiseRaw<'env, Datagram>> {
        self.sock.spawn(env, cancel, async move |sock| {
            let (who, msg) = sock.recv_from_bytes().await.map_err(netstack_err)?;

            Ok(Datagram {
                data: msg.to_vec().into(),
                from: who.into(),
            })
        })
    }

    /// Get the local endpoint this socket is bound to.
    #[napi]
    pub fn local_address(&self) -> AddressInfo {
        self.local_addr.into()
    }

    /// Close the socket, rejecting any pending operations.
    #[napi]
    pub fn close(&self) {
        self.sock.close();
    }
}
