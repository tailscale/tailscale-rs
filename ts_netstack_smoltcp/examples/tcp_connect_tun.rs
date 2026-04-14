//! Ping test for TCP functionality through the host's netstack using a TUN.
//!
//! A listener is created on the host, and a netstack socket connects to it. They exchange
//! ping messages back and forth indefinitely.
//!
//! You will probably need to run this under `sudo` in order to create the tun device.
//! Don't forget `-E` if you want your user's `RUST_LOG` var.

mod common;

use common::netsock::CreateSocket;

fn main() -> common::Result<()> {
    common::init();

    let stack_handle = common::spawn_tun_netstack()?;

    common::wait_for_tun_blocking();

    let host_tun_listener = std::net::TcpListener::bind(common::tun_endpoint())?;
    std::thread::spawn(move || host_listen(host_tun_listener));

    let sock =
        stack_handle.tcp_connect_blocking(common::netstack_endpoint(), common::tun_endpoint())?;
    tracing::debug!(?sock, "netstack stream connected");

    assert_eq!(sock.local_endpoint_addr(), common::netstack_endpoint());
    assert_eq!(sock.remote_endpoint_addr(), common::tun_endpoint());

    common::socket_pingpong_blocking(sock);

    Ok(())
}

#[tracing::instrument(skip_all, level = "info")]
fn host_listen(listener: std::net::TcpListener) {
    loop {
        let (sock, remote) = listener.accept().unwrap();
        tracing::debug!(%remote, "connection accepted");

        std::thread::spawn(move || common::socket_pingpong_blocking(sock));
    }
}
