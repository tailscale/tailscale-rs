//! Ping test for TCP functionality through the host's netstack using a TUN.
//!
//! A listener is created in the netstack, and the host creates a TCP socket that connects
//! to it. They exchange ping messages back and forth indefinitely. This version constructs
//! and runs the netstack on tokio.
//!
//! You will probably need to run this under `sudo` in order to create the tun device.
//! Don't forget `-E` if you want your user's `RUST_LOG` var.

mod common;

use common::netsock::CreateSocket;

#[tokio::main]
async fn main() -> common::Result<()> {
    common::init();

    let stack_handle = common::spawn_tun_netstack()?;

    let listener = stack_handle.tcp_listen(common::netstack_endpoint()).await?;

    tokio::spawn(common::netstack_listen(listener));

    common::wait_for_tun().await;

    let sock = tokio::net::TcpStream::connect(common::netstack_endpoint()).await?;
    tracing::debug!(?sock, "host stream connected");

    common::socket_pingpong(sock).await;

    Ok(())
}
