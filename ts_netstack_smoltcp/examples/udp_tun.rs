//! Ping test for UDP functionality against the host's netstack using a TUN.
//!
//! You will probably need to run this under `sudo` in order to create the tun device.
//! Don't forget `-E` if you want your user's `RUST_LOG` var.

use core::{borrow::Borrow, net::SocketAddr, time::Duration};
use std::sync::Arc;

mod common;

use common::netsock::{CreateSocket, UdpSocket};

fn main() -> common::Result<()> {
    common::init();

    let stack_handle = common::spawn_tun_netstack()?;

    common::wait_for_tun_blocking();
    let host_tun_socket = std::net::UdpSocket::bind(common::tun_endpoint())?;
    let host_tun_socket = Arc::new(host_tun_socket);

    let sock = stack_handle.udp_bind_blocking(common::netstack_endpoint())?;
    tracing::debug!(?sock, "netstack socket bound");

    assert_eq!(sock.local_addr(), common::netstack_endpoint());

    let sock = Arc::new(sock);

    let netstack_recv_sock = sock.clone();
    std::thread::spawn(move || netstack_recv(netstack_recv_sock));
    std::thread::spawn(move || netstack_send(sock, common::tun_endpoint()));

    let sock_send = host_tun_socket.clone();
    std::thread::spawn(move || host_send(sock_send, common::netstack_endpoint()));
    std::thread::spawn(move || host_recv(host_tun_socket));

    loop {
        std::thread::park();
    }
}

#[tracing::instrument(skip_all, level = "info")]
fn host_recv(sock_recv: Arc<std::net::UdpSocket>) {
    loop {
        let mut buf = [0; 1024];
        let (n, from) = sock_recv.recv_from(&mut buf).unwrap();

        let payload = &buf[..n];
        let payload = core::str::from_utf8(payload).unwrap();
        tracing::debug!(%from, %payload, "recv");
    }
}

#[tracing::instrument(skip_all, level = "info")]
fn host_send(sock: Arc<std::net::UdpSocket>, peer: SocketAddr) {
    loop {
        sock.send_to(b"hi", peer).unwrap();
        tracing::debug!("sent hi");

        std::thread::sleep(Duration::from_millis(330));
    }
}

#[tracing::instrument(skip_all, level = "info")]
fn netstack_recv(netstack_recv_sock: Arc<UdpSocket>) {
    loop {
        let (who, buf) = netstack_recv_sock.recv_from_bytes_blocking().unwrap();
        tracing::debug!(%who, buf = %core::str::from_utf8(&buf).unwrap());
    }
}

#[tracing::instrument(skip_all, level = "info")]
fn netstack_send(sock: impl Borrow<UdpSocket>, peer: SocketAddr) {
    let sock = sock.borrow();

    // Default configuration has no routes, but that shouldn't impede this packet from going out
    sock.send_to_blocking(SocketAddr::from(([1, 2, 3, 4], 53)), b"hello")
        .unwrap();

    for i in 0.. {
        sock.send_to_blocking(peer, format!("hello{i}").as_bytes())
            .unwrap();
        tracing::debug!(i, "sent hello packet");

        std::thread::sleep(Duration::from_millis(500));
    }
}
