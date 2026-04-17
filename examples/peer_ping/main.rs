//! Send UDP messages to a peer on a configurable interval.

use std::{error::Error, net::SocketAddr, path::PathBuf, time::Duration};

use clap::Parser;
use tailscale::{Config, Device};
use tracing_subscriber::filter::LevelFilter;

#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    /// Path to a key file to use. Will be created if it doesn't exist.
    #[arg(short = 'c', long, default_value = "tsrs_keys.json")]
    key_file: PathBuf,

    /// The auth key to connect with.
    ///
    /// Can be omitted if the key file is already authenticated.
    #[arg(short = 'k', long)]
    auth_key: Option<String>,

    /// Peer to send messages to.
    #[clap(short, long)]
    peer: SocketAddr,

    /// How often to send messages.
    #[clap(short = 'i', long, default_value_t = 1.0)]
    ping_interval_secs: f64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let args = Args::parse();

    let dev = Device::new(&Config::from_key_file(&args.key_file).await?, args.auth_key).await?;

    let sock = dev.udp_bind((dev.ipv4_addr().await?, 1234).into()).await?;
    let mut ticker = tokio::time::interval(Duration::from_secs_f64(args.ping_interval_secs));

    loop {
        sock.send_to(args.peer, b"hello").await?;
        ticker.tick().await;
    }
}
