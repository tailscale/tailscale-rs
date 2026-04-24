use std::sync::Arc;

use rustler::{Encoder, NifResult, ResourceArc};
use tap::Pipe;

use crate::{
    AsyncReply, IpOrSelf, erl_ip::ErlIp, helpers::term_err, ok_arc, sockaddr_to_erl,
    try_reply_async,
};

pub(crate) struct TcpListener {
    inner: Arc<tailscale::netstack::TcpListener>,
}

pub(crate) struct TcpStream {
    inner: Arc<tailscale::netstack::TcpStream>,
}

#[rustler::resource_impl]
impl rustler::Resource for TcpListener {}

#[rustler::resource_impl]
impl rustler::Resource for TcpStream {}

#[rustler::nif]
fn tcp_listen<'e>(
    env: rustler::Env<'e>,
    dev: ResourceArc<crate::Device>,
    ip: IpOrSelf,
    port: u16,
) -> NifResult<AsyncReply<'e>> {
    let dev = dev.inner.clone();

    try_reply_async(env, async move {
        let addr = ip.resolve(&dev).await?;
        let sock = dev
            .tcp_listen((addr, port).into())
            .await
            .map_err(term_err)?;

        ok_arc(TcpListener {
            inner: Arc::new(sock),
        })
    })
    .pipe(Ok)
}

#[rustler::nif]
fn tcp_listen_local_addr(listener: ResourceArc<TcpListener>) -> impl Encoder {
    sockaddr_to_erl(listener.inner.local_addr())
}

#[rustler::nif]
fn tcp_connect<'e>(
    env: rustler::Env<'e>,
    dev: ResourceArc<crate::Device>,
    addr: ErlIp,
    port: u16,
) -> NifResult<AsyncReply<'e>> {
    let dev = dev.inner.clone();

    try_reply_async(env, async move {
        let sock = dev
            .tcp_connect((addr, port).into())
            .await
            .map_err(term_err)?;

        ok_arc(TcpStream {
            inner: Arc::new(sock),
        })
    })
    .pipe(Ok)
}

#[rustler::nif]
fn tcp_accept(env: rustler::Env<'_>, sock: ResourceArc<TcpListener>) -> AsyncReply<'_> {
    let inner = sock.inner.clone();

    try_reply_async(env, async move {
        let stream = inner.accept().await.map_err(term_err)?;

        ok_arc(TcpStream {
            inner: Arc::new(stream),
        })
    })
}

#[rustler::nif]
fn tcp_send(env: rustler::Env, sock: ResourceArc<TcpStream>, msg: Vec<u8>) -> AsyncReply {
    let inner = sock.inner.clone();

    try_reply_async(env, async move { inner.send(&msg).await.map_err(term_err) })
}

#[rustler::nif]
fn tcp_recv(env: rustler::Env, sock: ResourceArc<TcpStream>) -> AsyncReply {
    let inner = sock.inner.clone();

    try_reply_async(env, async move {
        inner
            .recv_bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(term_err)
    })
}

#[rustler::nif]
fn tcp_local_addr(sock: ResourceArc<TcpStream>) -> impl Encoder {
    sockaddr_to_erl(sock.inner.local_addr())
}

#[rustler::nif]
fn tcp_remote_addr(sock: ResourceArc<TcpStream>) -> impl Encoder {
    sockaddr_to_erl(sock.inner.remote_addr())
}
