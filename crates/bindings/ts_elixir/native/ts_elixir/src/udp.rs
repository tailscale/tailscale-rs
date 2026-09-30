use std::sync::Arc;

use rustler::{Binary, Encoder, NifResult, ResourceArc, Term};

use crate::{
    Device, IpOrSelf, Result, TOKIO_RUNTIME, atoms, erl_ip::ErlIp, helpers::term_err, ok_arc,
};

pub struct UdpSocket {
    inner: Arc<tailscale::netstack::UdpSocket>,
}

#[rustler::resource_impl]
impl rustler::Resource for UdpSocket {}

#[rustler::nif(schedule = "DirtyIo")]
fn udp_bind(
    env: rustler::Env,
    dev: ResourceArc<Device>,
    ip: IpOrSelf,
    port: u16,
) -> NifResult<impl Encoder> {
    let dev = dev.inner.clone();

    TOKIO_RUNTIME
        .block_on(async move {
            let addr = ip.resolve(&dev).await?;
            let sock = dev.udp_bind((addr, port).into()).await.map_err(term_err)?;

            ok_arc(UdpSocket {
                inner: Arc::new(sock),
            })
        })
        .map(|sock| sock.encode(env))
}

#[rustler::nif(schedule = "DirtyIo")]
fn udp_send<'env>(
    env: rustler::Env<'env>,
    sock: ResourceArc<UdpSocket>,
    ip: ErlIp,
    port: u16,
    msg: Binary,
) -> Term<'env> {
    let msg = msg.to_vec();
    let sock = sock.inner.clone();

    match TOKIO_RUNTIME.block_on(async move {
        sock.send_to((ip.0, port).into(), &msg).await?;

        Result::<_>::Ok(())
    }) {
        Ok(_) => atoms::ok().encode(env),
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}

#[rustler::nif(schedule = "DirtyIo")]
fn udp_recv(env: rustler::Env, sock: ResourceArc<UdpSocket>) -> NifResult<Term> {
    let (who, msg) = sock.inner.recv_from_bytes_blocking().map_err(term_err)?;

    Ok((atoms::ok(), ErlIp(who.ip()), who.port(), msg.to_vec()).encode(env))
}

#[rustler::nif]
fn udp_local_addr(sock: ResourceArc<UdpSocket>) -> impl Encoder {
    crate::sockaddr_to_erl(sock.inner.local_addr())
}
