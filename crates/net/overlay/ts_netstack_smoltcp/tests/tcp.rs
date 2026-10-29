//! Tests for TCP half-close and cancellation.

use core::time::Duration;

use ts_netstack_smoltcp::CreateSocket;

#[path = "../examples/common/mod.rs"]
pub mod common;

/// Long enough for a request to reach the netstack and block.
const BLOCK_TIME: Duration = Duration::from_millis(100);
/// How long to wait for something which should happen.
const TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn shutdown_still_receives() -> common::Result<()> {
    common::init();

    let (stack1, stack2) = common::spawn_piped_netstacks(Default::default(), None).await?;
    let listener = stack2.tcp_listen(common::netstack2_endpoint()).await?;

    let (client, server) = tokio::join!(
        stack1.tcp_connect(common::netstack_endpoint(), common::netstack2_endpoint()),
        listener.accept(),
    );
    let (client, server) = (client?, server?);

    client.send(b"ping").await?;
    client.shutdown().await?;

    let recv = tokio::time::timeout(TIMEOUT, server.recv_bytes()).await??;
    assert_eq!(&recv[..], b"ping");
    let eof = tokio::time::timeout(TIMEOUT, server.recv_bytes()).await??;
    assert!(eof.is_empty());

    server.send(b"pong").await?;
    drop(server);

    let recv = tokio::time::timeout(TIMEOUT, client.recv_bytes()).await??;
    assert_eq!(&recv[..], b"pong");
    let eof = tokio::time::timeout(TIMEOUT, client.recv_bytes()).await??;
    assert!(eof.is_empty());

    Ok(())
}

#[tokio::test]
async fn cancelled_recv_keeps_data() -> common::Result<()> {
    common::init();

    let (stack1, stack2) = common::spawn_piped_netstacks(Default::default(), None).await?;
    let listener = stack2.tcp_listen(common::netstack2_endpoint()).await?;

    let (client, server) = tokio::join!(
        stack1.tcp_connect(common::netstack_endpoint(), common::netstack2_endpoint()),
        listener.accept(),
    );
    let (client, server) = (client?, server?);

    // Cancel a recv which is blocked waiting for data.
    assert!(
        tokio::time::timeout(BLOCK_TIME, server.recv_bytes())
            .await
            .is_err()
    );

    client.send(b"ping").await?;

    let recv = tokio::time::timeout(TIMEOUT, server.recv_bytes()).await??;
    assert_eq!(&recv[..], b"ping");

    Ok(())
}

#[tokio::test]
async fn cancelled_accept_keeps_connection() -> common::Result<()> {
    common::init();

    let (stack1, stack2) = common::spawn_piped_netstacks(Default::default(), None).await?;
    let listener = stack2.tcp_listen(common::netstack2_endpoint()).await?;

    // Cancel an accept which is blocked waiting for a connection.
    assert!(
        tokio::time::timeout(BLOCK_TIME, listener.accept())
            .await
            .is_err()
    );

    let client = stack1
        .tcp_connect(common::netstack_endpoint(), common::netstack2_endpoint())
        .await?;
    let server = tokio::time::timeout(TIMEOUT, listener.accept()).await??;

    client.send(b"ping").await?;
    let recv = tokio::time::timeout(TIMEOUT, server.recv_bytes()).await??;
    assert_eq!(&recv[..], b"ping");

    Ok(())
}
