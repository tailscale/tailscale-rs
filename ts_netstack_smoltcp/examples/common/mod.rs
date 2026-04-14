#![allow(missing_docs, dead_code)]

use core::net::{Ipv4Addr, SocketAddr};

pub extern crate ts_netstack_smoltcp as netstack;
pub extern crate ts_netstack_smoltcp_core as netcore;
pub extern crate ts_netstack_smoltcp_socket as netsock;

#[cfg(feature = "std")]
use netcore::{HasChannel, NetstackControl, smoltcp};
#[cfg(feature = "std")]
use netstack::{Netstack, WakingPipe, WakingPipeDev};

pub type Result<T> = core::result::Result<T, Box<dyn core::error::Error + Send + Sync + 'static>>;

pub const NETSTACK_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 32, 33);
pub const NETSTACK_IP2: Ipv4Addr = Ipv4Addr::new(192, 168, 32, 34);
pub const TUN_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 32, 32);

pub const PREFIX_LEN: u8 = 24;
pub const PORT: u16 = 1000;

pub fn init() {
    if std::env::var("TOKIO_CONSOLE").is_ok_and(|x| x == "1") {
        console_subscriber::init();
    } else {
        ts_cli_util::init_tracing();
    }

    std::panic::set_hook(Box::new(tracing_panic::panic_hook));
}

pub fn netstack_endpoint() -> SocketAddr {
    (NETSTACK_IP, PORT).into()
}

pub fn netstack2_endpoint() -> SocketAddr {
    (NETSTACK_IP2, PORT).into()
}

pub fn tun_endpoint() -> SocketAddr {
    (TUN_IP, PORT).into()
}

/// Wait for the tun device to actually be ready for socket communication.
#[cfg(feature = "tun")]
pub fn wait_for_tun_blocking() {
    loop {
        // Just try to bind a socket using the `TUN_IP` (port doesn't matter) to ensure
        // the device is ready. On Windows, this can take a few seconds.
        match std::net::TcpListener::bind((TUN_IP, PORT - 1)) {
            Ok(_) => break,
            Err(e) => {
                tracing::debug!(error = %e, "waiting for ips to be assigned to tun");
                std::thread::sleep(core::time::Duration::from_millis(500));
            }
        }
    }

    tracing::info!("tun is ready");
}

/// Wait for the tun device to actually be ready for socket communication.
#[cfg(feature = "tun")]
pub async fn wait_for_tun() {
    loop {
        // Just try to bind a socket using the `TUN_IP` (port doesn't matter) to ensure
        // the device is ready. On Windows, this can take a few seconds.
        match tokio::net::TcpListener::bind((TUN_IP, PORT - 1)).await {
            Ok(_) => break,
            Err(e) => {
                tracing::debug!(error = %e, "waiting for ips to be assigned to tun");
                tokio::time::sleep(core::time::Duration::from_millis(500)).await;
            }
        }
    }

    tracing::info!("tun is ready");
}

#[cfg(feature = "std")]
pub fn spawn_piped_netstacks_threaded(
    config: netcore::Config,
    bound: Option<usize>,
) -> Result<(netcore::Channel, netcore::Channel)> {
    let (mut stack1, mut stack2) = piped_netstacks(config, bound)?;

    let handle1 = stack1.command_channel();
    let handle2 = stack2.command_channel();

    std::thread::spawn(move || {
        stack1.run_blocking(core::time::Duration::from_millis(10));
    });

    std::thread::spawn(move || {
        stack2.run_blocking(core::time::Duration::from_millis(10));
    });

    handle1.set_ips_blocking([NETSTACK_IP.into()])?;
    handle2.set_ips_blocking([NETSTACK_IP2.into()])?;

    Ok((handle1, handle2))
}

#[cfg(feature = "tokio")]
pub async fn spawn_piped_netstacks(
    config: netcore::Config,
    bound: Option<usize>,
) -> Result<(netcore::Channel, netcore::Channel)> {
    let (mut stack1, mut stack2) = piped_netstacks(config, bound)?;

    let handle1 = stack1.command_channel();
    let handle2 = stack2.command_channel();

    tokio::spawn(async move { stack1.run_tokio().await });
    tokio::spawn(async move { stack2.run_tokio().await });

    handle1.set_ips([NETSTACK_IP.into()]).await?;
    handle2.set_ips([NETSTACK_IP2.into()]).await?;

    Ok((handle1, handle2))
}

#[cfg(feature = "std")]
pub fn piped_netstacks(
    config: netcore::Config,
    bound: Option<usize>,
) -> Result<(Netstack<WakingPipeDev>, Netstack<WakingPipeDev>)> {
    let (p1, p2) = WakingPipe::new(bound);

    let p1 = WakingPipeDev {
        pipe: p1,
        mtu: 1500,
        medium: smoltcp::phy::Medium::Ip,
    };

    let p2 = WakingPipeDev {
        pipe: p2,
        mtu: 1500,
        medium: smoltcp::phy::Medium::Ip,
    };

    let stack1 = Netstack::new(p1, config.clone());
    let stack2 = Netstack::new(p2, config.clone());

    Ok((stack1, stack2))
}

/// Run a [`ts_netstack_smoltcp::Netstack`] in a thread backed by a tun device.
#[cfg(feature = "tun")]
pub fn spawn_tun_netstack_threaded() -> Result<netcore::Channel> {
    let tun_dev = tun_rs::DeviceBuilder::new()
        .ipv4(TUN_IP, PREFIX_LEN, None)
        .build_sync()?;

    let tun_dev = netstack::TunRsDevice::from(tun_dev);
    tracing::info!("tun created");

    let mut stack = Netstack::new(tun_dev, Default::default());
    let handle = stack.command_channel();

    std::thread::spawn(move || {
        stack.run_blocking(core::time::Duration::from_millis(10));
    });

    handle.set_ips_blocking([NETSTACK_IP.into()])?;

    Ok(handle)
}

/// Run a [`ts_netstack_smoltcp::Netstack`] in a task backed by a tun device.
#[cfg(all(feature = "tun", feature = "tokio"))]
pub fn spawn_tun_netstack() -> Result<netcore::Channel> {
    let tun_dev = tun_rs::DeviceBuilder::new()
        .ipv4(TUN_IP, PREFIX_LEN, None)
        .build_async()?;

    let tun_dev = netstack::TunRsDeviceAsync::from(tun_dev);
    tracing::info!("tun created");

    let mut stack = Netstack::new(tun_dev, Default::default());
    let handle = stack.command_channel();

    tokio::spawn(async move { stack.run_tokio().await });

    handle.set_ips_blocking([NETSTACK_IP.into()])?;

    Ok(handle)
}

#[cfg(feature = "std")]
#[tracing::instrument(skip_all, level = "info", fields(sock_t = %core::any::type_name::<T>()))]
pub fn socket_pingpong_blocking<T>(mut sock: T)
where
    T: std::io::Read + std::io::Write,
{
    let mut buf = [0; 1024];

    let mut last_send = std::time::Instant::now();

    for i in 0.. {
        std::thread::sleep(
            core::time::Duration::from_millis(300).saturating_sub(last_send.elapsed()),
        );

        sock.write_all(format!("hello {i}").as_bytes()).unwrap();
        sock.flush().unwrap();
        tracing::debug!(?i, "sent hello");
        last_send = std::time::Instant::now();

        let n = sock.read(&mut buf).unwrap();
        let payload = &buf[..n];
        let payload = core::str::from_utf8(payload).unwrap();

        tracing::debug!(%payload, "recv");
    }
}

#[cfg(feature = "tokio")]
#[tracing::instrument(skip_all, level = "info", fields(sock_t = %core::any::type_name::<T>()))]
pub async fn socket_pingpong<T>(mut sock: T)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = [0; 1024];

    let mut ticker = tokio::time::interval(core::time::Duration::from_millis(300));

    for i in 0.. {
        ticker.tick().await;

        sock.write_all(format!("hello {i}").as_bytes())
            .await
            .unwrap();
        sock.flush().await.unwrap();
        tracing::debug!(?i, "sent hello");

        let n = sock.read(&mut buf).await.unwrap();
        let payload = &buf[..n];
        let payload = core::str::from_utf8(payload).unwrap();

        tracing::debug!(%payload, "recv");
    }
}

#[cfg(feature = "std")]
#[tracing::instrument]
pub fn netstack_listen_blocking(listener: netsock::TcpListener) {
    loop {
        let sock = listener.accept_blocking().unwrap();
        tracing::debug!(remote = %sock.remote_endpoint_addr(), "connection accepted");

        std::thread::spawn(move || socket_pingpong_blocking(sock));
    }
}

#[cfg(feature = "tokio")]
#[tracing::instrument]
pub async fn netstack_listen(listener: netsock::TcpListener) {
    loop {
        let sock = listener.accept().await.unwrap();
        tracing::debug!(remote = %sock.remote_endpoint_addr(), "connection accepted");

        tokio::task::spawn(socket_pingpong(sock));
    }
}

// Cargo wants to compile this as an example even though it's a helper module.
fn main() {}
