//! Basic `tailscale` tests.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use tailscale::{Config, Device, Error, netstack::UdpSocket};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

const NET_TIMEOUT: Duration = Duration::from_secs(1);

#[tracing_test::traced_test]
#[tokio::test]
async fn ipv4_addr() {
    if !ts_test_util::run_net_tests() {
        tracing::warn!("net tests disabled");
        return;
    }

    timeout(NET_TIMEOUT, async move {
        let dev = make_ts_device().await.unwrap();
        let ip = dev.ipv4_addr().await.unwrap();
        assert!(!ip.is_unspecified());
    })
    .await
    .unwrap();
}

#[tracing_test::traced_test]
#[tokio::test]
async fn ipv6_addr() {
    if !ts_test_util::run_net_tests() {
        tracing::warn!("net tests disabled");
        return;
    }

    timeout(NET_TIMEOUT, async move {
        let dev = make_ts_device().await.unwrap();
        let ip = dev.ipv6_addr().await.unwrap();
        assert!(!ip.is_unspecified());
    })
    .await
    .unwrap();
}

#[tracing_test::traced_test]
#[tokio::test]
async fn tcp_listen4() {
    if !ts_test_util::run_net_tests() {
        tracing::warn!("net tests disabled");
        return;
    }

    timeout(NET_TIMEOUT, async move {
        let dev = make_ts_device().await.unwrap();

        let _listener = dev
            .tcp_listen((dev.ipv4_addr().await.unwrap(), 1234).into())
            .await
            .unwrap();
    })
    .await
    .unwrap();
}

#[tracing_test::traced_test]
#[tokio::test]
async fn tcp_listen6() {
    if !ts_test_util::run_net_tests() {
        tracing::warn!("net tests disabled");
        return;
    }

    timeout(NET_TIMEOUT, async move {
        let dev = make_ts_device().await.unwrap();

        let _listener = dev
            .tcp_listen((dev.ipv6_addr().await.unwrap(), 1234).into())
            .await
            .unwrap();
    })
    .await
    .unwrap();
}

#[tracing_test::traced_test]
#[tokio::test]
async fn tcp_connect4() {
    if !ts_test_util::run_net_tests() {
        tracing::warn!("net tests disabled");
        return;
    }

    timeout(NET_TIMEOUT, async move {
        let dev = make_ts_device().await.unwrap();
        let ip = dev.ipv4_addr().await.unwrap();

        test_tcp(&dev, (ip, 1234).into()).await;
    })
    .await
    .unwrap();
}

#[tracing_test::traced_test]
#[tokio::test]
async fn tcp_connect6() {
    if !ts_test_util::run_net_tests() {
        tracing::warn!("net tests disabled");
        return;
    }

    timeout(NET_TIMEOUT, async move {
        let dev = make_ts_device().await.unwrap();
        let ip = dev.ipv6_addr().await.unwrap();

        test_tcp(&dev, (ip, 1234).into()).await;
    })
    .await
    .unwrap();
}

async fn test_tcp(dev: &tailscale::Device, listen_addr: SocketAddr) {
    let listener = dev.tcp_listen(listen_addr).await.unwrap();

    let accept_task = tokio::spawn(async move { listener.accept().await });

    let mut conn = dev.tcp_connect(listen_addr).await.unwrap();
    let mut conn2 = accept_task.await.unwrap().unwrap();

    assert_eq!(conn.local_addr(), conn2.remote_addr());
    assert_eq!(conn2.local_addr(), conn.remote_addr());

    test_io_roundtrip(&mut conn, &mut conn2).await;
    test_io_roundtrip(&mut conn2, &mut conn).await;
}

async fn test_io_roundtrip(mut r: impl AsyncRead + Unpin, mut w: impl AsyncWrite + Unpin) {
    w.write_all(b"hello").await.unwrap();
    let mut b = [0u8; b"hello".len()];
    r.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"hello");
}

#[tracing_test::traced_test]
#[tokio::test]
async fn udp4() {
    if !ts_test_util::run_net_tests() {
        tracing::warn!("net tests disabled");
        return;
    }

    timeout(NET_TIMEOUT, async move {
        let dev = make_ts_device().await.unwrap();
        let ip = dev.ipv4_addr().await.unwrap();
        test_udp(&dev, ip.into()).await;
    })
    .await
    .unwrap();
}

#[tracing_test::traced_test]
#[tokio::test]
async fn udp6() {
    if !ts_test_util::run_net_tests() {
        tracing::warn!("net tests disabled");
        return;
    }

    timeout(NET_TIMEOUT, async move {
        let dev = make_ts_device().await.unwrap();
        let ip = dev.ipv6_addr().await.unwrap();
        test_udp(&dev, ip.into()).await;
    })
    .await
    .unwrap();
}

async fn test_udp(dev: &tailscale::Device, ip: IpAddr) {
    let udp1 = dev.udp_bind((ip, 1234).into()).await.unwrap();
    let udp2 = dev.udp_bind((ip, 5678).into()).await.unwrap();

    test_udp_unidir(&udp1, &udp2).await;
    test_udp_unidir(&udp2, &udp1).await;
}

async fn test_udp_unidir(tx: &UdpSocket, rx: &UdpSocket) {
    tx.send_to(rx.local_addr(), b"hello").await.unwrap();

    let (who, msg) = rx.recv_from_bytes().await.unwrap();

    assert_eq!(who, tx.local_addr());
    assert_eq!(msg.as_ref(), b"hello");
}

async fn make_ts_device() -> Result<Device, Error> {
    unsafe { std::env::set_var("TS_RS_EXPERIMENT", "this_is_unstable_software") };

    Device::new(&Config::default(), Some(ts_test_util::auth_key().unwrap())).await
}
