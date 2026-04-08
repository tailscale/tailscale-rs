//! Send derp pings to the selected peer.

use core::{borrow::Borrow, sync::atomic::AtomicU32, time::Duration};
use std::sync::Arc;

use clap::Parser;
use tokio::task::JoinSet;
use ts_keys::NodePublicKey;
use ts_packet::PacketMut;
use ts_transport::UnderlayTransport;

/// Authenticate with control, load the derp map, and attempt to exchange derp pings with
/// a selected peer.
#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    /// The key of the peer to ping. If missing, just print received pings.
    #[arg(short, long)]
    peer: Option<NodePublicKey>,

    /// Send pings to this node.
    #[arg(short = 's', long = "self")]
    send_to_self: bool,

    #[clap(flatten)]
    common: ts_cli_util::CommonArgs,
}

#[tokio::main]
async fn main() -> ts_cli_util::Result<()> {
    ts_cli_util::init_tracing();

    let args = Args::parse();

    let (config, mut control, stream) = args.common.connect().await?;

    let (region_id, derp_servers) = ts_cli_util::set_closest_derp(&mut control, stream).await?;

    let mut tasks = JoinSet::new();

    tracing::info!(?region_id, "starting derp transport");

    let derp =
        ts_transport_derp::Client::connect(&derp_servers, &config.key_state.node_keys).await?;
    let derp = Arc::new(derp);

    let peer = args
        .send_to_self
        .then_some(config.key_state.node_keys.public)
        .or(args.peer);

    if let Some(peer) = peer {
        tasks.spawn(derp_send_ping(peer, derp.clone()));
    } else {
        tracing::info!("not sending derp pings, no peer configured");
    }

    tasks.spawn(derp_receive_ping(derp));

    tasks.join_all().await;

    Ok(())
}

static PING_MAX: AtomicU32 = AtomicU32::new(0);

async fn derp_receive_ping(derp: impl Borrow<ts_transport_derp::DefaultClient>) {
    use bytes::Buf;

    let derp = derp.borrow();

    loop {
        let (peer, mut packet) = derp.recv_one().await.unwrap();

        let value = packet.get_u32();
        let value = PING_MAX.fetch_max(value, core::sync::atomic::Ordering::SeqCst);

        tracing::info!(
            from_peer = %peer,
            %value,
            "receive ping"
        );
    }
}

#[tracing::instrument(skip(derp), fields(%peer))]
async fn derp_send_ping(peer: NodePublicKey, derp: impl Borrow<ts_transport_derp::DefaultClient>) {
    use bytes::BufMut;

    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let derp = derp.borrow();

    loop {
        let val = PING_MAX.fetch_add(1, core::sync::atomic::Ordering::SeqCst);

        let mut packet = PacketMut::with_capacity(size_of::<u32>());
        packet.put_u32(val);

        derp.send([(peer, [packet])]).await.unwrap();
        tracing::info!(value = val, "send ping");

        ticker.tick().await;
    }
}
