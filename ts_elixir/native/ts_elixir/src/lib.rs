#![doc = include_str!("../README.md")]

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Once},
};

use rustler::{Encoder, NifResult, ResourceArc, Term};
use tracing::level_filters::LevelFilter;

mod config;
mod erl_ip;
mod helpers;
mod ip_or_self;
mod node_info;
mod tcp;
mod udp;

use config::Keystate;
use erl_ip::ErlIp;
use helpers::{Result, ok_arc, sockaddr_to_erl, term_err};
use ip_or_self::IpOrSelf;
use node_info::NodeInfo;
use tcp::{TcpListener, TcpStream};
use udp::UdpSocket;

use crate::helpers::erl_result;

mod atoms {
    rustler::atoms! {
        ok,
        error,

        ip4,
        ip6,
    }
}

struct Device {
    inner: Arc<tailscale::Device>,
}

#[rustler::resource_impl]
impl rustler::Resource for Device {}

static TOKIO_RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    tracing::debug!("started tokio runtime");

    rt
});

#[rustler::nif]
fn start_tracing() {
    static TRACING_ONCE: Once = Once::new();

    TRACING_ONCE.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            )
            .init();
    });
}

#[rustler::nif(schedule = "DirtyIo")]
fn connect<'env>(
    env: rustler::Env<'env>,
    opts: HashMap<rustler::Atom, Term<'_>>,
) -> NifResult<Term<'env>> {
    let (config, auth_key) = config::config_from_erl(&opts)?;

    let dev = TOKIO_RUNTIME.block_on(async move {
        let dev = tailscale::Device::new(&config, auth_key)
            .await
            .map_err(term_err)?;

        ok_arc(Device {
            inner: Arc::new(dev),
        })
    });

    dev.map(|d| d.encode(env))
}

#[rustler::nif(schedule = "DirtyIo")]
fn load_key_file(env: rustler::Env, path: &str) -> NifResult<impl Encoder> {
    let result = TOKIO_RUNTIME
        .block_on(tailscale::config::load_key_file(path, Default::default()))
        .map(Keystate::from)
        .map_err(Into::into);

    erl_result(env, result)
}

#[rustler::nif(schedule = "DirtyIo")]
fn ipv4_addr(env: rustler::Env, dev: ResourceArc<Device>) -> NifResult<impl Encoder> {
    let dev = dev.inner.clone();
    let addr = TOKIO_RUNTIME.block_on(dev.ipv4_addr());

    erl_result(env, addr.map(|ip| ErlIp(ip.into())).map_err(Into::into))
}

#[rustler::nif(schedule = "DirtyIo")]
fn ipv6_addr(dev: ResourceArc<Device>) -> NifResult<impl Encoder> {
    let dev = dev.inner.clone();

    TOKIO_RUNTIME
        .block_on(dev.ipv6_addr())
        .map(ErlIp::from)
        .map_err(term_err)
}

#[rustler::nif(schedule = "DirtyIo")]
fn peer_by_name(env: rustler::Env<'_>, dev: ResourceArc<Device>, name: &str) -> impl Encoder {
    let dev = dev.inner.clone();
    let name = name.to_owned();

    match TOKIO_RUNTIME.block_on(async move { dev.peer_by_name(&name).await }) {
        Err(e) => (atoms::error(), e.to_string()).encode(env),
        Ok(None) => (atoms::ok(), Option::<()>::None).encode(env),
        Ok(Some(peer)) => (atoms::ok(), NodeInfo::from(peer)).encode(env),
    }
}

#[rustler::nif(schedule = "DirtyIo")]
fn self_node(env: rustler::Env<'_>, dev: ResourceArc<Device>) -> impl Encoder {
    let dev = dev.inner.clone();

    match TOKIO_RUNTIME.block_on(async move { dev.self_node().await }) {
        Err(e) => (atoms::error(), e.to_string()).encode(env),
        Ok(peer) => (atoms::ok(), NodeInfo::from(peer)).encode(env),
    }
}

#[rustler::nif(schedule = "DirtyIo")]
fn peer_by_tailnet_ip(env: rustler::Env<'_>, dev: ResourceArc<Device>, ip: ErlIp) -> impl Encoder {
    let dev = dev.inner.clone();

    match TOKIO_RUNTIME.block_on(async move { dev.peer_by_tailnet_ip(ip.0).await }) {
        Err(e) => (atoms::error(), e.to_string()).encode(env),
        Ok(None) => (atoms::ok(), Option::<()>::None).encode(env),
        Ok(Some(peer)) => (atoms::ok(), NodeInfo::from(peer)).encode(env),
    }
}

#[rustler::nif(schedule = "DirtyIo")]
fn peers_with_route(env: rustler::Env<'_>, dev: ResourceArc<Device>, ip: ErlIp) -> impl Encoder {
    let dev = dev.inner.clone();

    match TOKIO_RUNTIME.block_on(async move { dev.peers_with_route(ip.0).await }) {
        Err(e) => (atoms::error(), e.to_string()).encode(env),
        Ok(peers) => (
            atoms::ok(),
            peers.into_iter().map(NodeInfo::from).collect::<Vec<_>>(),
        )
            .encode(env),
    }
}

fn load(env: rustler::Env, _term: Term) -> bool {
    let ret = env.register::<UdpSocket>().is_ok()
        && env.register::<Device>().is_ok()
        && env.register::<TcpStream>().is_ok()
        && env.register::<TcpListener>().is_ok();
    if ret {
        tracing::debug!("loaded tailscale nifs");
    }

    ret
}

rustler::init!("Elixir.Tailscale.Native", load = load);
