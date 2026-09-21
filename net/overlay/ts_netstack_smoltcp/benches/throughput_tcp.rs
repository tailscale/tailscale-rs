//! Throughput test over TCP between two network stacks connected by an in-memory pipe.

use std::time::Instant;

use bytes::BytesMut;
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ts_netstack_smoltcp_socket::CreateSocket;

#[path = "../examples/common/mod.rs"]
mod common;

const KB: usize = 1024;

const SEND_BUF_SIZE: usize = 32 * KB;
const RECV_BUF_SIZE: usize = 32 * KB;

const TCP_SOCKET_BUF_SIZE: usize = 256 * KB;

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
            tcp_buffer_size: TCP_SOCKET_BUF_SIZE,
            command_channel_capacity: Some(128),
            mtu: usize::MAX,
            ..Default::default()
        },
        Some(32),
    )
    .await?;

    let recv_listener = ch1.tcp_listen(common::netstack_endpoint()).await?;

    let accept_task = tokio::task::spawn(async move { recv_listener.accept().await });

    let mut send_sock = ch2
        .tcp_connect(common::netstack2_endpoint(), common::netstack_endpoint())
        .await?;

    let mut recv_sock = accept_task.await??;
    tracing::trace!("ready");

    let jh = tokio::spawn(async move {
        let mut n = 0;

        let mut buf = vec![0u8; RECV_BUF_SIZE];
        while let Ok(bytes_read) = recv_sock.read(&mut buf).await
            && bytes_read != 0
        {
            n += bytes_read;
            tracing::trace!(bytes_read, n);
        }

        tracing::info!(read_bytes = n, "receiver completed");
    });

    let mut buf = BytesMut::zeroed(SEND_BUF_SIZE);
    rand::fill(buf.as_mut());

    tracing::info!("sending");
    let start = Instant::now();
    let mut sent_bytes = 0;

    while start.elapsed().as_secs_f64() < args.run_seconds {
        send_sock.write_all(&buf).await?;
        sent_bytes += buf.len();
    }
    tracing::info!("sending done");
    drop(send_sock);

    jh.await?;
    let dur = start.elapsed();

    let data_rate = sent_bytes as f64 / dur.as_secs_f64() / 1_000_000.;

    tracing::info!(duration = ?dur, data_rate_mbps = data_rate);
    if !tracing::enabled!(tracing::Level::INFO) {
        eprintln!("duration = {dur:?}, data_rate_mbps = {data_rate}");
    }

    Ok(())
}
