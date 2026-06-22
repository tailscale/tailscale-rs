//! Basic smoke tests for TCP sockets.

use core::{net::SocketAddr, time::Duration};

use ts_netstack_smoltcp::{
    Netstack, WakingPipe, WakingPipeDev,
    netcore::{Channel, HasChannel, NetstackControl},
    netsock::CreateSocket,
};

/// Creates blocking client and server netstacks connected by a [`WakingPipe`], running each
/// netstack in a separate detached thread. Returns the command channels for the netstacks as
/// `(client, server)`.
fn create_blocking_client_server(
    client_ep: SocketAddr,
    server_ep: SocketAddr,
) -> (Channel, Channel) {
    let (p1, p2) = WakingPipe::new(None);
    let dev = |pipe| WakingPipeDev {
        pipe,
        mtu: 1500,
        medium: smoltcp::phy::Medium::Ip,
    };
    let mut client_stack = Netstack::new(dev(p1), Default::default());
    let mut server_stack = Netstack::new(dev(p2), Default::default());
    let (client_ch, server_ch) = (
        client_stack.command_channel(),
        server_stack.command_channel(),
    );
    std::thread::spawn(move || client_stack.run_blocking(Duration::from_millis(1)));
    std::thread::spawn(move || server_stack.run_blocking(Duration::from_millis(1)));
    client_ch.set_ips_blocking([client_ep.ip()]).unwrap();
    server_ch.set_ips_blocking([server_ep.ip()]).unwrap();
    (client_ch, server_ch)
}

/// Ensures [`TcpListener`] correctly accepts half-closed sockets.
///
/// It's possible for a peer to establish a connection, send little/no data, and close their
/// write-half of the connection by sending a `FIN` - all before the [`TcpListener`] has a chance to
/// accept the connection. When the listener goes to accept the socket, it will find it in the
/// `CLOSE_WAIT` state rather than `ESTABLISHED`. This is a "half-closed" socket; the peer's socket
/// will be in the `FIN_WAIT_2` state and unable to send more data to the listener, but can still
/// receive data. The listener's socket will be in `CLOSE_WAIT` and able to send data to the peer,
/// but doesn't expect to receive data from the peer. For more information, see
/// [RFC 9293 Section 3.6.1][9293].
///
/// [`TcpListener`]: [::tcp_netstack_smoltcp::netsock::TcpListener]
/// [9293]: https://www.rfc-editor.org/info/rfc9293/#section-3.6.1
#[test]
fn listener_accepts_half_closed_connection() {
    let client_ep: SocketAddr = "100.64.0.2:32768".parse().unwrap();
    let server_ep: SocketAddr = "100.64.0.1:80".parse().unwrap();
    let (client_ch, server_ch) = create_blocking_client_server(client_ep, server_ep);

    let listener = server_ch.tcp_listen_blocking(server_ep).unwrap();

    // Establish the connection, send a request, and drop the client to send a `FIN` from the client
    // to the listener, all before calling accept_blocking() on the listener...
    let client = client_ch
        .tcp_connect_blocking(client_ep, server_ep)
        .unwrap();
    client.send_blocking(b"request").unwrap();
    // TODO (dylan): This should be a shutdown() (or equivalent) to half-close the client socket
    //               rather than a full close with drop(), but we don't implement half-closes yet.
    //               After https://github.com/tailscale/tailscale-rs/issues/474 merges, update this
    //               test to half-close the client, send "response" from conn to client, and call
    //               client.recv_blocking() to confirm the response.
    drop(client);
    std::thread::sleep(Duration::from_millis(10));

    // ...so when we call accept_blocking(), the listener sees the socket in CLOSE_WAIT.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || tx.send(listener.accept_blocking()));
    let conn = rx
        .recv_timeout(Duration::from_secs(1))
        .expect("accept() never returned the half-closed connection")
        .unwrap();
    let mut buf = [0; 16];
    let n = conn.recv_blocking(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"request");
}
