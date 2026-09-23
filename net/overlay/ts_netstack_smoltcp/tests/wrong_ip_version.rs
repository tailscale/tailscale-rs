//! Test that sending with the wrong IP address type is an error.

use core::net::SocketAddr;

use ts_netstack_smoltcp_socket::CreateSocket;

extern crate ts_netstack_smoltcp_core as netcore;

#[path = "../examples/common/mod.rs"]
pub mod common;

#[tokio::test]
async fn mismatched_ips_tcp() -> common::Result<()> {
    common::init();

    let (stack1, _stack2) = common::spawn_piped_netstacks(Default::default(), None).await?;

    let addr_v4 = "1.2.3.4:5678".parse::<SocketAddr>()?;
    let addr_v6 = "[::1234]:5678".parse::<SocketAddr>()?;

    let ret = stack1.tcp_connect(addr_v4, addr_v6).await;
    assert_eq!(ret.unwrap_err(), netcore::Error::wrong_ip_version());

    let ret = stack1.tcp_connect(addr_v6, addr_v4).await;
    assert_eq!(ret.unwrap_err(), netcore::Error::wrong_ip_version());

    Ok(())
}

#[tokio::test]
async fn mismatched_ips_udp() -> common::Result<()> {
    common::init();

    let (stack1, _stack2) = common::spawn_piped_netstacks(Default::default(), None).await?;

    let addr_v4 = "1.2.3.4:5678".parse::<SocketAddr>()?;
    let addr_v6 = "[::1234]:5678".parse::<SocketAddr>()?;

    let sockv4 = stack1.udp_bind(addr_v4).await?;
    let sockv6 = stack1.udp_bind(addr_v6).await?;

    let ret = sockv4.send_to(addr_v6, b"hi").await;
    assert_eq!(ret.unwrap_err(), netcore::Error::wrong_ip_version());

    let ret = sockv6.send_to(addr_v4, b"hi").await;
    assert_eq!(ret.unwrap_err(), netcore::Error::wrong_ip_version());

    Ok(())
}
