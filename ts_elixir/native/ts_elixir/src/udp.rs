use std::sync::Arc;

use rustler::{Binary, Encoder, NifResult, ResourceArc};
use tap::Pipe;

use crate::{
    AsyncReply, Device, IpOrSelf, erl_ip::ErlIp, helpers::term_err, ok_arc, sockaddr_to_erl,
    try_reply_async,
};

pub struct UdpSocket {
    inner: Arc<tailscale::netstack::UdpSocket>,
}

#[rustler::resource_impl]
impl rustler::Resource for UdpSocket {}

#[rustler::nif]
fn udp_bind<'e>(
    env: rustler::Env<'e>,
    dev: ResourceArc<Device>,
    ip: IpOrSelf,
    port: u16,
) -> NifResult<AsyncReply<'e>> {
    let dev = dev.inner.clone();

    try_reply_async(env, async move {
        let addr = ip.resolve(&dev).await?;
        let sock = dev.udp_bind((addr, port).into()).await.map_err(term_err)?;

        ok_arc(UdpSocket {
            inner: Arc::new(sock),
        })
    })
    .pipe(Ok)
}

#[rustler::nif]
fn udp_send<'e>(
    env: rustler::Env<'e>,
    sock: ResourceArc<UdpSocket>,
    addr: ErlIp,
    port: u16,
    msg: Binary,
) -> NifResult<AsyncReply<'e>> {
    let msg = msg.to_vec();
    let sock = sock.inner.clone();

    try_reply_async(env, async move {
        sock.send_to((addr, port).into(), &msg)
            .await
            .map(|_| ())
            .map_err(term_err)
    })
    .pipe(Ok)
}

#[rustler::nif]
fn udp_recv(env: rustler::Env, sock: ResourceArc<UdpSocket>) -> AsyncReply {
    let sock = sock.inner.clone();

    try_reply_async(env, async move {
        sock.recv_from_bytes()
            .await
            .map(|(s, msg)| (ErlIp(s.ip()), s.port(), msg.to_vec()))
            .map_err(term_err)
    })
}

#[rustler::nif]
fn udp_local_addr(sock: ResourceArc<UdpSocket>) -> impl Encoder {
    sockaddr_to_erl(sock.inner.local_addr())
}
