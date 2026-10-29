//! Basic smoke tests for udp sockets.

use core::net::SocketAddr;

use bytes::Bytes;
use netcore::{HasChannel, Netstack, Pipe, PipeDev, Response, udp};
use smoltcp::{phy::Medium, time::Instant, wire};
use ts_netstack_smoltcp::netcore;

// Rough schematic:
//
//          UDP SOCKET
//             | ^^^
// Cmd chan -> | |||.. <- Response channels (many, one per command)
//             v |||
//         ----------- smoltcp land: inside the box, things look like smoltcp expects.
//         |  STACK  | our Netstack is running in a thread in here just driving smoltcp forward.
//         |    v    |
//         |  PIPE ("net" end, driven by STACK; wrapped by PipeDev)
//         | tx |^ rx|
//         -----------
//              || <- up/down channel       |< smoltcp sees everything below it as "the network",
//              ||                          |< i.e. the thing that actually transports the packets
//           rx v| tx                       |< it emits to their addressee, with whatever meaning
//             PIPE ("phy" end,             |< that happens to have in your scenario (could be
//                   driven directly        |< switched ethernet, routing/forwarding through the
//                   by this test)          |< Internet, whatever -- it doesn't care). in this test
//                                          |< we're inspecting the packets and looping back the one
//                                          |< we know is addressed to the socket

#[test]
fn udp_by_steps() -> ts_cli_util::Result<()> {
    init_trace_panic();

    let mut stack = Netstack::new(
        netcore::Config {
            loopback: true,
            ..Default::default()
        },
        Instant::ZERO,
    );

    let channel = stack.command_channel();

    let jh = std::thread::spawn(move || {
        let _guard = tracing::info_span!("command thread").entered();

        let ep = SocketAddr::from(([127, 0, 0, 1], 1000));

        let Response::Udp(udp::Response::Bound { handle, local }) =
            channel.request_blocking(None, udp::Command::Bind { endpoint: ep })?
        else {
            unreachable!();
        };

        tracing::debug!(%handle, %local, "socket bound");
        assert_eq!(local, ep);

        channel.request_blocking(
            Some(handle),
            udp::Command::Send {
                endpoint: ep,
                buf: Bytes::copy_from_slice(b"hello"),
            },
        )?;

        let Response::Udp(udp::Response::RecvFrom {
            buf,
            remote,
            truncated,
        }) = channel.request_blocking(Some(handle), udp::Command::Recv { max_len: None })?
        else {
            unreachable!();
        };

        assert!(truncated.is_none());

        tracing::debug!(who = %remote, buf = %core::str::from_utf8(&buf)?, "packet received");

        // Default configuration has no routes, but that shouldn't impede this packet from going
        // out, since we're single-interface L3 (functionally point-to-point): we can't actually
        // make a forwarding decision, everything must just go out through the one pipe
        channel.request_blocking(
            Some(handle),
            udp::Command::Send {
                endpoint: SocketAddr::from(([1, 2, 3, 4], 53)),
                buf: Bytes::copy_from_slice(b"hello"),
            },
        )?;

        Ok(()) as ts_cli_util::Result<()>
    });

    let _guard = tracing::info_span!("netstack driver").entered();

    wait_and_process_cmd(&mut stack)?; // bind
    wait_and_process_cmd(&mut stack)?; // send

    let (net, phy) = Pipe::unbounded();
    let mut net = PipeDev {
        pipe: net,
        medium: Medium::Ip,
        mtu: 1536,
    };

    stack.poll_device_io(Instant::ZERO, &mut net); // send goes out

    let pkt = phy.rx.try_recv()?; // the sent packet
    let repr = parse_ip_repr(&pkt).unwrap();
    tracing::debug!(?repr, ?pkt, "outgoing packet");

    phy.tx.try_send(pkt)?; // loop back the send
    tracing::debug!("looped back packet");
    stack.poll_device_io(Instant::ZERO, &mut net);

    wait_and_process_cmd(&mut stack)?; // recv
    stack.poll_device_io(Instant::ZERO, &mut net);

    wait_and_process_cmd(&mut stack)?; // send to 1.2.3.4:53
    stack.poll_device_io(Instant::ZERO, &mut net);

    let pkt = phy.rx.try_recv()?; // the sent packet
    let repr = parse_ip_repr(&pkt).unwrap();
    tracing::debug!(?repr, ?pkt, "outgoing packet");

    jh.join().unwrap()?;

    Ok(())
}

#[test]
fn cancel_safety() -> ts_cli_util::Result<()> {
    init_trace_panic();

    let mut stack = Netstack::new(
        netcore::Config {
            loopback: true,
            ..Default::default()
        },
        Instant::ZERO,
    );

    let channel = stack.command_channel();
    let handle = std::thread::spawn(move || {
        let ep = SocketAddr::from(([127, 0, 0, 1], 1000));

        let Response::Udp(udp::Response::Bound { handle, .. }) = channel
            .request_blocking(None, udp::Command::Bind { endpoint: ep })
            .unwrap()
        else {
            unreachable!();
        };

        handle
    });

    wait_and_process_cmd(&mut stack)?; // bind
    let sock = handle.join().unwrap();

    // poll a request once to get it into the command channel
    {
        use core::task::{Context, Waker};

        let fut = core::pin::pin![stack.request(Some(sock), udp::Command::Recv { max_len: None })];

        let mut ctx = Context::from_waker(Waker::noop());
        assert!(fut.poll(&mut ctx).is_pending());

        // then drop it here. since we only send one packet below, if this request eats it, the
        // below request will never complete
    }

    let (net, phy) = Pipe::unbounded();
    let mut net = PipeDev {
        pipe: net,
        medium: Medium::Ip,
        mtu: 1536,
    };

    // ipv4 from 127.0.0.1:1001 to 127.0.0.1:1000 with udp payload "hi"
    phy.tx.try_send(Bytes::copy_from_slice(&[
        0x45, 0x00, 0x00, 0x1e, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x2a, 0x99, 0x7f, 0x00, 0x00,
        0x01, 0x7f, 0x00, 0x00, 0x01, 0x03, 0xe9, 0x03, 0xe8, 0x00, 0x0a, 0x00, 0x00, 0x68, 0x69,
    ]))?;
    stack.poll_device_io(Instant::ZERO, &mut net);

    wait_and_process_cmd(&mut stack)?;

    let channel = stack.command_channel();
    let handle = std::thread::spawn(move || {
        let Response::Udp(resp) = channel
            .request_blocking(Some(sock), udp::Command::Recv { max_len: None })
            .unwrap()
        else {
            unreachable!();
        };

        resp
    });

    wait_and_process_cmd(&mut stack)?;
    let udp::Response::RecvFrom { remote, buf, .. } = handle.join().unwrap() else {
        unreachable!()
    };

    assert_eq!(remote, SocketAddr::from(([127, 0, 0, 1], 1001)));
    assert_eq!(buf.as_ref(), b"hi");

    Ok(())
}

fn init_trace_panic() {
    static ONCE: std::sync::Once = std::sync::Once::new();

    ONCE.call_once(|| {
        ts_cli_util::init_tracing();
        std::panic::set_hook(Box::new(tracing_panic::panic_hook));
    });
}

fn wait_and_process_cmd(stack: &mut Netstack) -> ts_cli_util::Result<()> {
    let cmd = stack.wait_for_cmd_blocking(None)?;
    stack.process_one_cmd(cmd);

    Ok(())
}

fn parse_ip_repr(overlay_ip_pkt: &[u8]) -> Option<wire::IpRepr> {
    if overlay_ip_pkt.is_empty() {
        tracing::warn!("empty ip packet");
        return None;
    }

    let version = *overlay_ip_pkt.first().unwrap();
    let version = version >> 4; // high 4 bits are the version field

    let repr: wire::IpRepr = match version {
        4 => {
            let pkt = wire::Ipv4Packet::new_checked(overlay_ip_pkt);
            let pkt = match pkt {
                Ok(pkt) => pkt,
                Err(e) => {
                    tracing::error!(err = %e, "invalid ipv4 packet");
                    return None;
                }
            };

            let repr = wire::Ipv4Repr::parse(&pkt, &Default::default()).ok()?;
            repr.into()
        }
        6 => {
            let pkt = wire::Ipv6Packet::new_checked(overlay_ip_pkt);
            let pkt = match pkt {
                Ok(pkt) => pkt,
                Err(e) => {
                    tracing::error!(err = %e, "invalid ipv6 packet");
                    return None;
                }
            };

            let repr = wire::Ipv6Repr::parse(&pkt).ok()?;
            repr.into()
        }
        _ => {
            tracing::error!(
                version,
                packet_len = overlay_ip_pkt.len(),
                "unknown ip version"
            );
            return None;
        }
    };

    Some(repr)
}
