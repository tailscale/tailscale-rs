//! Simple ping test.

use std::{sync::Arc, time::Duration};

use tokio::task::JoinSet;
use ts_keys::NodeKeyPair;
use ts_transport::UnderlayTransport;
use ts_transport_derp::PeerLookup;

mod common;

#[tokio::main]
async fn main() -> ts_cli_util::Result<()> {
    ts_cli_util::init_tracing();

    let derp_map = common::load_derp_map().await;
    let region = derp_map.get(&common::REGION_1).unwrap();

    let keypair = NodeKeyPair::new();
    let peer_map = &*Box::leak(Box::new(ts_transport_derp::DummyStaticLookup::default()));
    let self_id = peer_map.key_to_id(&keypair.public).unwrap();

    let client = ts_transport_derp::Client::connect(region, &keypair, peer_map).await?;
    tracing::info!("derp handshake done");

    let client = Arc::new(client);

    let mut js = JoinSet::new();

    let pinger = client.clone();
    js.spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));

        loop {
            if let Err(e) = pinger.send([(self_id, vec![vec![1].into()])]).await {
                tracing::error!(err = %e, "ping");
            } else {
                tracing::info!("ping");
            }

            ticker.tick().await;
        }
    });

    let recv = client;
    js.spawn(async move {
        loop {
            match recv.recv_one().await {
                Ok((peer_id, pkt)) => {
                    let peer_key = peer_map.id_to_key(peer_id);

                    tracing::info!(?pkt, %peer_id, ?peer_key, "pong");
                }
                Err(e) => {
                    tracing::error!(err = %e, "recv");
                }
            }
        }
    });

    js.join_all().await;

    Ok(())
}
