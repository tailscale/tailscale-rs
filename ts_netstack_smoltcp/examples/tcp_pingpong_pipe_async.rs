//! Ping test for TCP functionality between two network stacks connected by an in-memory
//! pipe.

mod common;

use common::netsock::CreateSocket;

#[tokio::main]
async fn main() -> common::Result<()> {
    common::init();

    let (stack1, stack2) = common::spawn_piped_netstacks(Default::default(), None).await?;

    let listener = stack2.tcp_listen(common::netstack2_endpoint()).await?;

    tokio::spawn(common::netstack_listen(listener));

    let sock = stack1
        .tcp_connect(common::netstack_endpoint(), common::netstack2_endpoint())
        .await?;

    tracing::debug!(?sock, "netstack stream connected");

    assert_eq!(sock.local_endpoint_addr(), common::netstack_endpoint());
    assert_eq!(sock.remote_endpoint_addr(), common::netstack2_endpoint());

    common::socket_pingpong(sock).await;

    Ok(())
}
