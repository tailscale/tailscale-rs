//! Attempt a dumb handshake with an existing wireguard endpoint.

use core::net::SocketAddr;
use std::{
    future::pending,
    time::{Duration, Instant},
};

use base64::Engine as _;
use bytes::BufMut;
use clap::Parser as _;
use tokio::{
    select,
    time::{interval_at, sleep_until},
};
use ts_keys::{NodePrivateKey, NodePublicKey};
use ts_packet::old::PacketMut;
use ts_time::TimeRange;
use ts_tunnel::Endpoint;
use zerocopy::{FromBytes, IntoBytes, TryFromBytes};
// Minimal example config:
//
//     [Interface]
//     PrivateKey = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
//     ListenPort = 62804
//
//     [Peer]
//     PublicKey = yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy

/// Handshake with a real WireGuard UDP endpoint.
///
/// No meaningful dataplane information is exchanged, this just initiates the wireguard
/// connection itself to verify that the underlying machinery is working.
///
/// Must be running such an endpoint (e.g. via the gui client, or wg-quick) for this
/// example to do anything.
#[derive(clap::Parser, Debug)]
pub struct Args {
    /// Endpoint to communicate with.
    #[clap(short, long)]
    pub endpoint: SocketAddr,

    /// Public key of the endpoint. Can be hex or base64.
    #[clap(long, value_parser = parse_key)]
    pub peer_key: chacha20poly1305::Key,

    /// Our private key. Can be hex or base64.
    #[clap(long, value_parser = parse_key)]
    pub private_key: chacha20poly1305::Key,
}

type BoxResult<T> = Result<T, Box<dyn core::error::Error + Send + Sync>>;

/// Parse a [`chacha20poly1305::Key`] from a string, trying hex (Tailscale-typical) and
/// base64 (WireGuard-typical) formats in succession.
pub fn parse_key(s: &str) -> BoxResult<chacha20poly1305::Key> {
    let s = s.trim().as_bytes();

    let key_bytes =
        hex::decode(s).or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))?;

    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_v: Vec<u8>| "invalid key len")?;

    Ok(key_bytes.into())
}

#[tokio::main]
async fn main() -> BoxResult<()> {
    ts_cli_util::init_tracing();

    let args = Args::parse();

    let privkey = NodePrivateKey::read_from_bytes(args.private_key.as_bytes())
        .map_err(|_| "failed reading private key")?;
    eprintln!(
        "my pubkey: {}",
        base64::engine::general_purpose::STANDARD.encode(privkey.public_key().as_bytes())
    );

    let peer_key = *NodePublicKey::try_ref_from_bytes(args.peer_key.as_bytes())
        .map_err(|_| "failed reading public key")?;

    let mut ep = Endpoint::new(privkey.into());

    let peer_id = ep
        .add_peer(ts_tunnel::PeerConfig {
            key: peer_key,
            psk: [0; 32].into(),
        })
        .ok_or("couldn't add peer")?;

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    eprintln!("socket bound to {}", sock.local_addr()?.port());

    let mut pinger = interval_at(Instant::now().into(), Duration::from_secs(10));

    loop {
        let mut buf = [0u8; 1024];

        select! {
            _ = pinger.tick() => {
                eprintln!("sending ping to peer");

                let mut packet = PacketMut::new(0);
                packet.put_slice(b"test test");

                let ts_tunnel::SendResult { to_peers } = ep.send([(peer_id, vec![packet])]);

                for (peer_id, packets) in to_peers {
                    eprintln!("sending {} packets to {peer_id:?}", packets.len());

                    for packet in packets {
                        sock.send_to(packet.as_ref(), &args.endpoint).await?;
                    }
                }
            },

            res = sock.recv_from(&mut buf) => {
                let (n, from) = res?;
                eprintln!("receive resp (len {n}, from {from})");
                let buf = &buf[..n];

                let ts_tunnel::RecvResult { to_peers, to_local } = ep.recv(vec![PacketMut::from(buf)]);

                eprintln!(
                    "resp: {} packets to peers, {} to local",
                    to_peers.len(),
                    to_local.len()
                );

                for (peer, packets) in to_local {
                    eprintln!("-> local ({peer:?}) ({} packets)", packets.len());
                }

                for (peer, packets) in to_peers {
                    eprintln!("-> {peer:?} ({} packets)", packets.len());

                    if peer == peer_id {
                        for packet in packets {
                            sock.send_to(packet.as_ref(), &args.endpoint).await?;
                        }

                        eprintln!("sent response packets to peer");
                    }
                }
            }

            now = maybe_timeout(ep.next_event()) => {
                let ts_tunnel::EventResult{to_peers} = ep.dispatch_events(now);

                for (peer, packets) in to_peers {
                    eprintln!("-> {peer:?} ({} packets)", packets.len());

                    if peer == peer_id {
                        for packet in packets {
                            sock.send_to(packet.as_ref(), &args.endpoint).await?;
                        }

                        eprintln!("sent response packets to peer");
                    }
                }
            }
        }
    }
}

async fn maybe_timeout(when: Option<TimeRange>) -> Instant {
    match when {
        Some(when) => {
            sleep_until(when.end().into()).await;
            when.end()
        }
        None => pending().await,
    }
}
