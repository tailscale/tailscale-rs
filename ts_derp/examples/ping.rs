//! Simple ping test.

use std::{sync::Arc, time::Duration};

use tokio::task::JoinSet;
use ts_keys::NodeKeyPair;

mod common;

#[tokio::main]
async fn main() -> ts_cli_util::Result<()> {
    ts_cli_util::init_tracing();

    let derp_map = common::load_derp_map().await;
    let region = derp_map.get(&common::REGION_1).unwrap();

    let keypair = NodeKeyPair::new();

    let client = ts_derp::Client::connect(region, &keypair).await?;
    tracing::info!("derp handshake done");

    let client = Arc::new(client);

    let mut js = JoinSet::new();

    let pinger = client.clone();
    js.spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));

        loop {
            if let Err(e) = pinger.send_one(keypair.public, &[1]).await {
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
                Ok((peer_key, pkt)) => {
                    tracing::info!(?pkt, %peer_key, "pong");
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
