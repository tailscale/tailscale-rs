//! Ping test for UDP functionality against the host's netstack using a TUN.
//! This version constructs the netstack and drives the logic using all async APIs on tokio.
//!
//! You will probably need to run this under `sudo` in order to create the tun device.
//! Don't forget `-E` if you want your user's `RUST_LOG` var.

use core::{borrow::Borrow, net::SocketAddr, time::Duration};
use std::sync::Arc;

mod common;

use common::netsock::{CreateSocket, UdpSocket};

#[tokio::main]
async fn main() -> common::Result<()> {
    common::init();

    let stack_handle = common::spawn_tun_netstack()?;

    common::wait_for_tun().await;
    let host_tun_socket = tokio::net::UdpSocket::bind(common::tun_endpoint()).await?;
    let host_tun_socket = Arc::new(host_tun_socket);

    let sock = stack_handle.udp_bind(common::netstack_endpoint()).await?;
    tracing::debug!(?sock, "netstack socket bound");

    assert_eq!(sock.local_addr(), common::netstack_endpoint());

    let sock = Arc::new(sock);

    let netstack_recv_sock = sock.clone();
    tokio::spawn(netstack_recv(netstack_recv_sock));
    tokio::spawn(netstack_send(sock, common::tun_endpoint()));

    let sock_send = host_tun_socket.clone();
    tokio::spawn(host_send(sock_send, common::netstack_endpoint()));
    tokio::spawn(host_recv(host_tun_socket));

    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[tracing::instrument(skip_all, level = "info")]
async fn host_recv(sock_recv: Arc<tokio::net::UdpSocket>) {
    loop {
        let mut buf = [0; 1024];
        let (n, from) = sock_recv.recv_from(&mut buf).await.unwrap();

        let payload = &buf[..n];
        let payload = core::str::from_utf8(payload).unwrap();
        tracing::debug!(%from, %payload, "recv");
    }
}

#[tracing::instrument(skip_all, level = "info")]
async fn host_send(sock: Arc<tokio::net::UdpSocket>, peer: SocketAddr) {
    loop {
        sock.send_to(b"hi", peer).await.unwrap();
        tracing::debug!("sent hi");

        tokio::time::sleep(Duration::from_millis(330)).await;
    }
}

#[tracing::instrument(skip_all, level = "info")]
async fn netstack_recv(netstack_recv_sock: Arc<UdpSocket>) {
    loop {
        let (who, buf) = netstack_recv_sock.recv_from_bytes().await.unwrap();
        tracing::debug!(%who, buf = %core::str::from_utf8(&buf).unwrap());
    }
}

#[tracing::instrument(skip_all, level = "info")]
async fn netstack_send(sock: impl Borrow<UdpSocket>, peer: SocketAddr) {
    let sock = sock.borrow();

    // Default configuration has no routes, but that shouldn't impede this packet from going out
    sock.send_to(SocketAddr::from(([1, 2, 3, 4], 53)), b"hello")
        .await
        .unwrap();

    for i in 0.. {
        sock.send_to(peer, format!("hello{i}").as_bytes())
            .await
            .unwrap();
        tracing::debug!(i, "sent hello packet");

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
