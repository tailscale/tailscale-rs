//! Monitor rtnetlink for debugging.

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::net::IpAddr;

    use futures_util::StreamExt;
    use rtnetlink::{RouteMessageBuilder, packet_core::NetlinkPayload};

    let (runner, handle, mut rx) =
        rtnetlink::new_multicast_connection(ts_netmon::linux::NETLINK_GROUPS)?;

    tokio::spawn(runner);

    let mut link_stream = handle.link().get().execute();
    while let Some(link) = link_stream.next().await {
        eprintln!("{:#?}", link?);
    }

    let mut route_stream = handle
        .route()
        .get(RouteMessageBuilder::<IpAddr>::new().build())
        .execute();

    while let Some(route) = route_stream.next().await {
        eprintln!("{:#?}", route?);
    }

    let mut ip_stream = handle.address().get().execute();
    while let Some(address) = ip_stream.next().await {
        eprintln!("{:#?}", address?);
    }

    eprintln!("\n\nstreaming:");

    while let Some((msg, _)) = rx.next().await {
        let msg = match msg.payload {
            NetlinkPayload::InnerMessage(msg) => msg,
            NetlinkPayload::Error(e) => return Err(e.to_io().into()),
            NetlinkPayload::Done(done) => {
                eprintln!("netlink stream done: {done:?}");
                return Ok(());
            }
            unknown => {
                eprintln!("unknown netlink payload: {unknown:?}");
                continue;
            }
        };

        eprintln!("{msg:#?}");
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("this example is a no-op on non-linux targets")
}
