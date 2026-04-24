#![doc = include_str!("../README.md")]

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Once},
};

use rustler::{NifResult, ResourceArc, Term};
use tap::Pipe;
use tracing::level_filters::LevelFilter;

mod async_reply;
mod config;
mod erl_ip;
mod helpers;
mod ip_or_self;
mod node_info;
mod tcp;
mod udp;

use async_reply::{AsyncReply, try_reply_async};
use config::Keystate;
use erl_ip::ErlIp;
use helpers::{ok_arc, sockaddr_to_erl, term_err};
use ip_or_self::IpOrSelf;
use node_info::NodeInfo;
use tcp::{TcpListener, TcpStream};
use udp::UdpSocket;

mod atoms {
    rustler::atoms! {
        ok,
        async_ = "async",
        error,
        nif_panic,
        badarg,
        raise,

        ip4,
        ip6,

        tailscale,
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

#[rustler::nif]
fn connect<'env>(
    env: rustler::Env<'env>,
    opts: HashMap<rustler::Atom, Term<'_>>,
) -> NifResult<AsyncReply<'env>> {
    let (config, auth_key) = config::config_from_erl(&opts)?;

    try_reply_async(env, async move {
        let dev = tailscale::Device::new(&config, auth_key)
            .await
            .map_err(term_err)?;

        ok_arc(Device {
            inner: Arc::new(dev),
        })
    })
    .pipe(Ok)
}

#[rustler::nif]
fn load_key_file(env: rustler::Env, path: String) -> AsyncReply {
    try_reply_async(env, async move {
        tailscale::config::load_key_file(path, Default::default())
            .await
            .map(Keystate::from)
            .map_err(term_err)
    })
}

#[rustler::nif]
fn ipv4_addr(env: rustler::Env, dev: ResourceArc<Device>) -> AsyncReply {
    let dev = dev.inner.clone();

    try_reply_async(env, async move {
        dev.ipv4_addr().await.map(ErlIp::from).map_err(term_err)
    })
}

#[rustler::nif]
fn ipv6_addr(env: rustler::Env<'_>, dev: ResourceArc<Device>) -> AsyncReply<'_> {
    let dev = dev.inner.clone();

    try_reply_async(env, async move {
        dev.ipv6_addr().await.map(ErlIp::from).map_err(term_err)
    })
}

#[rustler::nif]
fn peer_by_name<'e>(env: rustler::Env<'e>, dev: ResourceArc<Device>, name: &str) -> AsyncReply<'e> {
    let dev = dev.inner.clone();
    let name = name.to_owned();

    try_reply_async(env, async move {
        dev.peer_by_name(&name)
            .await
            .map(|opt| opt.map(NodeInfo::from))
            .map_err(term_err)
    })
}

#[rustler::nif]
fn self_node(env: rustler::Env<'_>, dev: ResourceArc<Device>) -> AsyncReply<'_> {
    let dev = dev.inner.clone();

    try_reply_async(env, async move {
        dev.self_node().await.map(NodeInfo::from).map_err(term_err)
    })
}

#[rustler::nif]
fn peer_by_tailnet_ip<'e>(
    env: rustler::Env<'e>,
    dev: ResourceArc<Device>,
    ip: ErlIp,
) -> NifResult<AsyncReply<'e>> {
    let dev = dev.inner.clone();

    try_reply_async(env, async move {
        dev.peer_by_tailnet_ip(ip.into())
            .await
            .map(|x| x.map(NodeInfo::from))
            .map_err(term_err)
    })
    .pipe(Ok)
}

#[rustler::nif]
fn peers_with_route<'e>(
    env: rustler::Env<'e>,
    dev: ResourceArc<Device>,
    ip: ErlIp,
) -> NifResult<AsyncReply<'e>> {
    let dev = dev.inner.clone();

    try_reply_async(env, async move {
        dev.peers_with_route(ip.into())
            .await
            .map(|peers| peers.into_iter().map(NodeInfo::from).collect::<Vec<_>>())
            .map_err(term_err)
    })
    .pipe(Ok)
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
