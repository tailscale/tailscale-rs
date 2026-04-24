use std::sync::Arc;

use rustler::{Encoder, NifResult, ResourceArc};

use crate::{
    IpOrSelf, Result, TOKIO_RUNTIME, atoms, erl_ip::ErlIp, erl_result, helpers::term_err, ok_arc,
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

#[rustler::nif(schedule = "DirtyIo")]
fn tcp_listen(
    dev: ResourceArc<crate::Device>,
    addr: IpOrSelf,
    port: u16,
) -> NifResult<impl Encoder> {
    let dev = dev.inner.clone();

    TOKIO_RUNTIME.block_on(async move {
        let addr = addr.resolve(&dev).await?;
        let sock = dev
            .tcp_listen((addr, port).into())
            .await
            .map_err(term_err)?;

        ok_arc(TcpListener {
            inner: Arc::new(sock),
        })
    })
}

#[rustler::nif]
fn tcp_listen_local_addr(listener: ResourceArc<TcpListener>) -> impl Encoder {
    crate::sockaddr_to_erl(listener.inner.local_addr())
}

#[rustler::nif(schedule = "DirtyIo")]
fn tcp_connect(
    env: rustler::Env,
    dev: ResourceArc<crate::Device>,
    addr: ErlIp,
    port: u16,
) -> NifResult<impl Encoder> {
    let dev = dev.inner.clone();

    TOKIO_RUNTIME
        .block_on(async move {
            let sock = dev
                .tcp_connect((addr, port).into())
                .await
                .map_err(term_err)?;

            ok_arc(TcpStream {
                inner: Arc::new(sock),
            })
        })
        .map(|sock| sock.encode(env))
}

#[rustler::nif(schedule = "DirtyIo")]
fn tcp_accept(env: rustler::Env<'_>, sock: ResourceArc<TcpListener>) -> NifResult<impl Encoder> {
    let inner = sock.inner.clone();

    TOKIO_RUNTIME
        .block_on(async move {
            let stream = inner.accept().await.map_err(term_err)?;

            ok_arc(TcpStream {
                inner: Arc::new(stream),
            })
        })
        .map(|sock| sock.encode(env))
}

#[rustler::nif(schedule = "DirtyIo")]
fn tcp_send(env: rustler::Env, sock: ResourceArc<TcpStream>, msg: Vec<u8>) -> rustler::Term {
    let inner = sock.inner.clone();

    match TOKIO_RUNTIME.block_on(async move { inner.send(&msg).await }) {
        Ok(n) => (atoms::ok(), n).encode(env),
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}

#[rustler::nif(schedule = "DirtyIo")]
fn tcp_recv(env: rustler::Env, sock: ResourceArc<TcpStream>) -> NifResult<impl Encoder> {
    let inner = sock.inner.clone();

    let buf = TOKIO_RUNTIME.block_on(async move {
        let buf = inner.recv_bytes().await?;
        Result::<_>::Ok(buf.to_vec())
    });

    erl_result(env, buf)
}

#[rustler::nif]
fn tcp_local_addr(sock: ResourceArc<TcpStream>) -> impl Encoder {
    crate::sockaddr_to_erl(sock.inner.local_addr())
}

#[rustler::nif]
fn tcp_remote_addr(sock: ResourceArc<TcpStream>) -> impl Encoder {
    crate::sockaddr_to_erl(sock.inner.remote_addr())
}
