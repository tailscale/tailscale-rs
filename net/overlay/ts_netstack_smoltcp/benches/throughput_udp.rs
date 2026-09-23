//! Throughput test over UDP between two network stacks connected by an in-memory pipe.

use std::time::Instant;

use bytes::BytesMut;
use clap::Parser;
use ts_netstack_smoltcp_socket::CreateSocket;

#[path = "../examples/common/mod.rs"]
mod common;

const BUF_SIZE: usize = 10 * 1400;

#[derive(clap::Parser)]
#[clap(ignore_errors(true))]
struct Args {
    /// Number of seconds to run the throughput test for.
    #[clap(short, long, default_value = "5.0")]
    run_seconds: f64,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> common::Result<()> {
    common::init();
    let args = Args::parse();

    let (ch1, ch2) = common::spawn_piped_netstacks(
        ts_netstack_smoltcp_core::Config {
            udp_buffer_size: BUF_SIZE,
            udp_message_count: 1024,
            command_channel_capacity: Some(128),
            mtu: usize::MAX,
            ..Default::default()
        },
        Some(32),
    )
    .await?;

    let recv_sock = ch1.udp_bind(common::netstack_endpoint()).await?;
    let send_sock = ch2.udp_bind(common::netstack2_endpoint()).await?;

    let jh = tokio::spawn(async move {
        // the sends and receives here are a hacky means of signaling over the socket: wait to get
        // a packet to let us know the other side is ready:

        let (_from, buf) = recv_sock.recv_from_bytes().await.unwrap();
        tracing::info!(len = buf.len(), "receiver synced");

        // then indicate we're ready by sending an empty packet
        recv_sock
            .send_to(common::netstack2_endpoint(), &[])
            .await
            .unwrap();

        loop {
            let (_from, buf) = recv_sock.recv_from_bytes().await.unwrap();

            // empty packet means the remote is done
            if buf.is_empty() {
                break;
            }
        }
    });

    send_sock.send_to(common::netstack_endpoint(), &[]).await?;

    send_sock.recv_from_bytes().await?;
    tracing::info!("sender synced");

    let mut buf = BytesMut::zeroed(BUF_SIZE);
    rand::fill(buf.as_mut());

    tracing::info!("sending");
    let start = Instant::now();
    let mut n_iters = 0;

    while start.elapsed().as_secs_f64() < args.run_seconds {
        send_sock.send_to(common::netstack_endpoint(), &buf).await?;
        n_iters += 1;
    }
    tracing::info!("sending done");

    send_sock.send_to(common::netstack_endpoint(), &[]).await?;

    jh.await?;
    let dur = start.elapsed();

    let packet_rate = dur.as_micros() as f64 / n_iters as f64;
    let data_rate = (n_iters * BUF_SIZE) as f64 / dur.as_secs_f64() / 1_000_000.;

    tracing::info!(duration = ?dur, iters = n_iters, us_per_pkt = packet_rate, data_rate_mbps = data_rate);

    if !tracing::enabled!(tracing::Level::INFO) {
        eprintln!(
            "duration = {dur:?}, iters = {n_iters}, us_per_pkt = {packet_rate}, data_rate_mbps = {data_rate}"
        );
    }

    Ok(())
}
