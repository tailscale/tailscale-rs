use std::sync::Arc;

use rustler::{Binary, Encoder, ResourceArc, Term};

use crate::{
    Device, IpOrSelf, Result, TOKIO_RUNTIME, atoms, erl_result, ip_from_erl, ip_to_erl, ok_arc,
};

pub struct UdpSocket {
    inner: Arc<tailscale::netstack::UdpSocket>,
}

#[rustler::resource_impl]
impl rustler::Resource for UdpSocket {}

#[rustler::nif(schedule = "DirtyIo")]
fn udp_bind(env: rustler::Env, dev: ResourceArc<Device>, ip: Term, port: u16) -> impl Encoder {
    let dev = dev.inner.clone();
    let ip = IpOrSelf::new(ip);

    let sock = TOKIO_RUNTIME.block_on(async move {
        let addr = ip.ok_or("invalid ip addr")?.resolve(&dev).await?;
        let sock = dev.udp_bind((addr, port).into()).await?;

        ok_arc(UdpSocket {
            inner: Arc::new(sock),
        })
    });

    erl_result(env, sock)
}

#[rustler::nif(schedule = "DirtyIo")]
fn udp_send<'env>(
    env: rustler::Env<'env>,
    sock: ResourceArc<UdpSocket>,
    ip: Term,
    port: u16,
    msg: Binary,
) -> Term<'env> {
    let addr = ip_from_erl(ip);
    let msg = msg.to_vec();
    let sock = sock.inner.clone();

    match TOKIO_RUNTIME.block_on(async move {
        let addr = addr.ok_or("invalid ip addr")?;

        sock.send_to((addr, port).into(), &msg).await?;

        Result::<_>::Ok(())
    }) {
        Ok(_) => atoms::ok().encode(env),
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}

#[rustler::nif(schedule = "DirtyIo")]
fn udp_recv(env: rustler::Env, sock: ResourceArc<UdpSocket>) -> Term {
    let (who, msg) = match sock.inner.recv_from_bytes_blocking() {
        Ok((who, msg)) => (who, msg),
        Err(e) => return erl_result(env, Result::<()>::Err(e.into())),
    };

    (
        atoms::ok(),
        ip_to_erl(env, who.ip()),
        who.port(),
        msg.to_vec(),
    )
        .encode(env)
}

#[rustler::nif]
fn udp_local_addr(env: rustler::Env, sock: ResourceArc<UdpSocket>) -> impl Encoder {
    crate::sockaddr_to_erl(env, sock.inner.local_addr())
}
