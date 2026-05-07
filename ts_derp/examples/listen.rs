//! Maintain an open derp connection and listen for incoming packets, but do nothing else.
//!
//! Intended to test ping/pong/keepalive.

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

    loop {
        match client.recv_one().await {
            Ok((peer, pkt)) => {
                tracing::info!(?peer, ?pkt);
            }
            Err(e) => {
                tracing::error!(err = %e, "recv");
            }
        }
    }
}
