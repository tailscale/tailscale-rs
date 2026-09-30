//! Ping test for TCP functionality through the host's netstack using a TUN.
//!
//! A listener is created on the host, and a netstack socket connects to it. They exchange
//! ping messages back and forth indefinitely. This version constructs and runs the netstack
//! on tokio.
//!
//! You will probably need to run this under `sudo` in order to create the tun device.
//! Don't forget `-E` if you want your user's `RUST_LOG` var.

mod common;

use common::netsock::CreateSocket;

#[tokio::main]
async fn main() -> common::Result<()> {
    common::init();

    let stack_handle = common::spawn_tun_netstack()?;

    common::wait_for_tun().await;

    let host_tun_listener = tokio::net::TcpListener::bind(common::tun_endpoint()).await?;
    tokio::spawn(host_listen(host_tun_listener));

    let sock = stack_handle
        .tcp_connect(common::netstack_endpoint(), common::tun_endpoint())
        .await?;
    tracing::debug!(?sock, "netstack stream connected");

    assert_eq!(sock.local_addr(), common::netstack_endpoint());
    assert_eq!(sock.remote_addr(), common::tun_endpoint());

    common::socket_pingpong(sock).await;

    Ok(())
}

#[tracing::instrument(skip_all, level = "info")]
async fn host_listen(listener: tokio::net::TcpListener) {
    loop {
        let (sock, remote) = listener.accept().await.unwrap();
        tracing::debug!(%remote, "connection accepted");

        tokio::spawn(common::socket_pingpong(sock));
    }
}
