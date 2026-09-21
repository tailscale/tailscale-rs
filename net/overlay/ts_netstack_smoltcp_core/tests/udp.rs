//! Basic smoke tests for udp sockets.

use core::net::SocketAddr;

use bytes::Bytes;
use smoltcp::{phy::Medium, time::Instant, wire};

extern crate ts_netstack_smoltcp_core as netcore;

use netcore::{HasChannel, Netstack, Pipe, PipeDev, Response, udp};

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
    ts_cli_util::init_tracing();
    std::panic::set_hook(Box::new(tracing_panic::panic_hook));

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
