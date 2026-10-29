use std::net::SocketAddr;

use bytes::{Buf, Bytes};
use napi::{
    Env,
    bindgen_prelude::{Buffer, PromiseRaw, Result, Uint8Array},
};
use napi_derive::napi;

use crate::{
    AddressInfo,
    closable::{CancelToken, Closable},
    error::netstack_err,
};

/// A listening TCP socket.
#[napi]
pub struct TcpListener {
    listener: Closable<tailscale::netstack::TcpListener>,
    local_addr: SocketAddr,
}

/// An established TCP stream.
#[napi]
pub struct TcpStream {
    sock: Closable<tailscale::netstack::TcpStream>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl TcpListener {
    pub(crate) fn new(listener: tailscale::netstack::TcpListener) -> Self {
        Self {
            local_addr: listener.local_addr(),
            listener: Closable::new(listener),
        }
    }
}

impl TcpStream {
    pub(crate) fn new(sock: tailscale::netstack::TcpStream) -> Self {
        Self {
            local_addr: sock.local_addr(),
            remote_addr: sock.remote_addr(),
            sock: Closable::new(sock),
        }
    }
}

#[napi]
impl TcpListener {
    /// Accept a new incoming connection.
    ///
    /// Waits indefinitely until a connection is ready to be accepted.
    #[napi(ts_return_type = "Promise<TcpStream>")]
    pub fn accept<'env>(
        &self,
        env: &'env Env,
        cancel: Option<&CancelToken>,
    ) -> Result<PromiseRaw<'env, TcpStream>> {
        self.listener.spawn(env, cancel, async move |listener| {
            let stream = listener.accept().await.map_err(netstack_err)?;
            Ok(TcpStream::new(stream))
        })
    }

    /// Get the local endpoint this TCP listener is listening on.
    #[napi]
    pub fn local_address(&self) -> AddressInfo {
        self.local_addr.into()
    }

    /// Stop listening, rejecting any pending `accept`s.
    #[napi]
    pub fn close(&self) {
        self.listener.close();
    }
}

#[napi]
impl TcpStream {
    /// Send all of `msg` to the stream.
    #[napi(ts_return_type = "Promise<void>")]
    pub fn send_all<'env>(&self, env: &'env Env, msg: Uint8Array) -> Result<PromiseRaw<'env, ()>> {
        // Use `Bytes` so `msg.clone()` doesn't copy the data.
        let mut msg = Bytes::from(msg.to_vec());

        self.sock.spawn(env, None, async move |sock| {
            while !msg.is_empty() {
                let n = sock.send_bytes(msg.clone()).await.map_err(netstack_err)?;
                msg.advance(n);
            }

            Ok(())
        })
    }

    /// Close the sending half of the connection, once all data already sent has been delivered.
    ///
    /// Data can still be received until the remote end closes its half of the connection.
    #[napi(ts_return_type = "Promise<void>")]
    pub fn shutdown<'env>(&self, env: &'env Env) -> Result<PromiseRaw<'env, ()>> {
        self.sock.spawn(env, None, async move |sock| {
            sock.shutdown().await.map_err(netstack_err)
        })
    }

    /// Receive bytes from the stream, or `null` if the remote end has closed the connection.
    ///
    /// Waits until at least one byte is available.
    #[napi(ts_return_type = "Promise<Buffer | null>")]
    pub fn recv<'env>(
        &self,
        env: &'env Env,
        cancel: Option<&CancelToken>,
    ) -> Result<PromiseRaw<'env, Option<Buffer>>> {
        self.sock.spawn(env, cancel, async move |sock| {
            let buf = sock.recv_bytes().await.map_err(netstack_err)?;

            // The netstack signals end-of-stream with an empty buffer.
            Ok((!buf.is_empty()).then(|| buf.to_vec().into()))
        })
    }

    /// Get the local endpoint this socket is bound to.
    #[napi]
    pub fn local_address(&self) -> AddressInfo {
        self.local_addr.into()
    }

    /// Get the remote endpoint this socket is connected to.
    #[napi]
    pub fn remote_address(&self) -> AddressInfo {
        self.remote_addr.into()
    }

    /// Close the connection, rejecting any pending operations.
    ///
    /// Data which has already been sent is still delivered.
    #[napi]
    pub fn close(&self) {
        self.sock.close();
    }
}
