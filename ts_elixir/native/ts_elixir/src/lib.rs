#![doc = include_str!("../README.md")]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::{Arc, RwLock},
};

use rustler::{Encoder, ResourceArc, Term};
use tokio::task::JoinHandle;

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

type Result<T> = core::result::Result<T, Box<dyn core::error::Error + Send + Sync + 'static>>;

#[rustler::resource_impl]
impl rustler::Resource for Device {}

static TOKIO_RUNTIME: RwLock<Option<tokio::runtime::Runtime>> = RwLock::new(None);

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
    let dev = block_on(async move {
        let config = ts_cli_util::Config::load_or_init(config_path.as_ref()).await?;
        let dev =
            tailscale::Device::new(config.control_config(), auth_key, config.key_state).await?;

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
fn ipv4(env: rustler::Env, dev: ResourceArc<Device>) -> impl Encoder {
    let dev = dev.inner.clone();
    let addr = block_on(async move { dev.ipv4().await });

    erl_result(env, addr.map(|ip| ip_to_erl(env, ip)).map_err(Into::into))
}

#[rustler::nif(schedule = "DirtyIo")]
fn ipv6(env: rustler::Env<'_>, dev: ResourceArc<Device>) -> impl Encoder {
    let dev = dev.inner.clone();

    match block_on(async move { dev.ipv6().await }) {
        Err(e) => (atoms::error(), e.to_string()).encode(env),
        Ok(ip) => (atoms::ok(), ip_to_erl(env, ip)).encode(env),
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
            IpOrSelf::SelfV4 => dev.ipv4().await.map(Into::into).map_err(Into::into),
            IpOrSelf::SelfV6 => dev.ipv6().await.map(Into::into).map_err(Into::into),
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

fn load(env: rustler::Env, _term: Term) -> bool {
    {
        let mut rt = TOKIO_RUNTIME.write().unwrap();
        let _present = rt.insert(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
    }
    tracing::debug!("started tokio runtime");

    let ret = env.register::<UdpSocket>().is_ok()
        && env.register::<Device>().is_ok()
        && env.register::<TcpStream>().is_ok()
        && env.register::<TcpListener>().is_ok();
    if ret {
        tracing::debug!("loaded tailscale nifs");
    }

    ret
}

fn block_on<F>(f: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send,
{
    let (tx, rx) = tokio::sync::oneshot::channel();

    spawn(async move {
        let ret = f.await;
        let _result = tx.send(ret);
    });

    rx.blocking_recv().unwrap()
}

fn spawn<F>(f: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send,
{
    let runtime = TOKIO_RUNTIME.read().unwrap();
    let rt = runtime.as_ref().unwrap();

    rt.spawn(f)
}

rustler::init!("Elixir.Tailscale.Native", load = load);
