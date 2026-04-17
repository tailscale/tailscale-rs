#![doc = include_str!("../README.md")]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{Arc, LazyLock},
};

use rustler::{Encoder, ResourceArc, Term};

mod tcp;
mod udp;

use tcp::{TcpListener, TcpStream};
use udp::UdpSocket;

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

#[derive(rustler::NifStruct)]
#[module = "Tailscale.NodeInfo"]
struct NodeInfo<'a> {
    id: i64,
    stable_id: String,
    hostname: String,
    tailnet: Option<String>,
    tags: Vec<String>,
    tailnet_addresses: Vec<Term<'a>>,
    derp_region: Option<u32>,
    node_key: String,
    disco_key: Option<String>,
    machine_key: Option<String>,
    underlay_addresses: Vec<Term<'a>>,
}

impl<'a> NodeInfo<'a> {
    fn from_node(env: rustler::Env<'a>, value: tailscale::NodeInfo) -> Self {
        Self {
            id: value.id,
            stable_id: value.stable_id.0,
            hostname: value.hostname,
            tailnet: value.tailnet,
            tags: value.tags,
            tailnet_addresses: vec![
                ip_to_erl(env, value.tailnet_address.ipv4.addr()),
                ip_to_erl(env, value.tailnet_address.ipv6.addr()),
            ],
            derp_region: value.derp_region.map(|x| x.0.get()),
            node_key: value.node_key.to_string(),
            disco_key: value.disco_key.as_ref().map(ToString::to_string),
            machine_key: value.machine_key.as_ref().map(ToString::to_string),
            underlay_addresses: value
                .underlay_addresses
                .into_iter()
                .map(|x| (ip_to_erl(env, x.ip()), x.port()).encode(env))
                .collect(),
        }
    }
}

type Result<T> = core::result::Result<T, Box<dyn core::error::Error + Send + Sync + 'static>>;

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

fn erl_result(env: rustler::Env, r: Result<impl Encoder>) -> Term {
    match r {
        Ok(t) => (atoms::ok(), t).encode(env),
        Err(e) => (atoms::error(), e.to_string()).encode(env),
    }
}

fn ok_arc<T>(t: T) -> Result<ResourceArc<T>>
where
    T: rustler::Resource,
{
    Ok(ResourceArc::new(t))
}

#[rustler::nif(schedule = "DirtyIo")]
fn connect(env: rustler::Env, config_path: String, auth_key: Option<String>) -> impl Encoder {
    let dev = TOKIO_RUNTIME.block_on(async move {
        let config = tailscale::Config {
            key_state: tailscale::config::load_key_file(config_path, Default::default()).await?,
            client_name: Some("ts_elixir".to_owned()),
            ..Default::default()
        };

        let dev = tailscale::Device::new(&config, auth_key).await?;

        ok_arc(Device {
            inner: Arc::new(dev),
        })
    });

    erl_result(env, dev)
}

#[rustler::nif]
fn start_tracing() -> impl Encoder {
    static TRACING_ONCE: std::sync::Once = std::sync::Once::new();
    TRACING_ONCE.call_once(ts_cli_util::init_tracing);

    atoms::ok()
}

#[rustler::nif(schedule = "DirtyIo")]
fn ipv4_addr(env: rustler::Env, dev: ResourceArc<Device>) -> impl Encoder {
    let dev = dev.inner.clone();
    let addr = TOKIO_RUNTIME.block_on(dev.ipv4_addr());

    erl_result(env, addr.map(|ip| ip_to_erl(env, ip)).map_err(Into::into))
}

#[rustler::nif(schedule = "DirtyIo")]
fn ipv6_addr(env: rustler::Env<'_>, dev: ResourceArc<Device>) -> impl Encoder {
    let dev = dev.inner.clone();

    match TOKIO_RUNTIME.block_on(dev.ipv6_addr()) {
        Err(e) => (atoms::error(), e.to_string()).encode(env),
        Ok(ip) => (atoms::ok(), ip_to_erl(env, ip)).encode(env),
    }
}

#[rustler::nif(schedule = "DirtyIo")]
fn peer_by_name(env: rustler::Env<'_>, dev: ResourceArc<Device>, name: &str) -> impl Encoder {
    let dev = dev.inner.clone();
    let name = name.to_owned();

    match TOKIO_RUNTIME.block_on(async move { dev.peer_by_name(&name).await }) {
        Err(e) => (atoms::error(), e.to_string()).encode(env),
        Ok(None) => (atoms::ok(), Option::<()>::None).encode(env),
        Ok(Some(peer)) => (atoms::ok(), NodeInfo::from_node(env, peer)).encode(env),
    }
}

fn ip_to_erl(env: rustler::Env, ip: impl Into<IpAddr>) -> Term {
    match ip.into() {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            (octets[0], octets[1], octets[2], octets[3]).encode(env)
        }
        IpAddr::V6(ip) => {
            // rustler doesn't provide `impl Encoder` for 8-length tuples
            let segments = ip.segments().map(|segment| segment.encode(env));

            let tuple = rustler::types::tuple::make_tuple(env, &segments);
            tuple.encode(env)
        }
    }
}

enum IpOrSelf {
    Ip(IpAddr),
    SelfV4,
    SelfV6,
}

impl IpOrSelf {
    pub fn new(ip: Term<'_>) -> Option<Self> {
        if let Some(ip) = ip_from_erl(ip) {
            return Some(Self::Ip(ip));
        }

        let atom = ip.decode::<rustler::Atom>().ok()?;
        if atom == atoms::ip4() {
            return Some(Self::SelfV4);
        }

        if atom == atoms::ip6() {
            return Some(Self::SelfV6);
        }

        None
    }

    pub async fn resolve(&self, dev: &tailscale::Device) -> Result<IpAddr> {
        match self {
            IpOrSelf::Ip(ip) => Ok(*ip),
            IpOrSelf::SelfV4 => dev.ipv4_addr().await.map(Into::into).map_err(Into::into),
            IpOrSelf::SelfV6 => dev.ipv6_addr().await.map(Into::into).map_err(Into::into),
        }
    }
}

fn ip_from_erl(ip: Term) -> Option<IpAddr> {
    if let Ok(tuple) = rustler::types::tuple::get_tuple(ip) {
        if tuple.len() == 4 {
            let mut octets = [0u8; 4];

            for (i, elem) in tuple.into_iter().take(4).enumerate() {
                octets[i] = elem.decode().ok()?;
            }

            return Some(Ipv4Addr::from_octets(octets).into());
        }

        if tuple.len() == 8 {
            let mut segments = [0u16; 8];

            for (i, elem) in tuple.into_iter().take(8).enumerate() {
                segments[i] = elem.decode().ok()?;
            }

            return Some(Ipv6Addr::from_segments(segments).into());
        }
    }

    if let Ok(s) = ip.decode::<&str>() {
        return IpAddr::from_str(s).ok();
    }

    None
}

fn sockaddr_to_erl(env: rustler::Env, addr: SocketAddr) -> impl Encoder {
    (ip_to_erl(env, addr.ip()), addr.port())
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
