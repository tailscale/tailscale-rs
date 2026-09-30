//! Ping test for TCP functionality between two network stacks connected by an in-memory
//! pipe.

mod common;

use common::netsock::CreateSocket;

fn main() -> common::Result<()> {
    common::init();

    let (stack1, stack2) = common::spawn_piped_netstacks_threaded(Default::default(), None)?;

    let listener = stack2.tcp_listen_blocking(common::netstack2_endpoint())?;
    std::thread::spawn(move || common::netstack_listen(listener));

    let sock =
        stack1.tcp_connect_blocking(common::netstack_endpoint(), common::netstack2_endpoint())?;

    tracing::debug!(?sock, "netstack stream connected");

    assert_eq!(sock.local_addr(), common::netstack_endpoint());
    assert_eq!(sock.remote_addr(), common::netstack2_endpoint());

    common::socket_pingpong_blocking(sock);

    Ok(())
}
