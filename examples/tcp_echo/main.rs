//! Run a TCP echo server on the tailnet on a particular port.

use std::{error::Error, path::PathBuf};

use clap::Parser;
use tailscale::{Config, Device};
use tokio::task::spawn;
use tracing_subscriber::filter::LevelFilter;

/// Run a TCP echo server on the tailnet on a particular port.
///
/// To see the server working, try connecting to it with netcat (`nc`):
///
///     $ nc $TAILNET_IPV4 $LISTEN_PORT
///
/// Type a message and hit enter; the server should echo the message back to you.
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

    /// Port to listen on (on tailnet IPv4).
    #[clap(short, long, default_value_t = 1234)]
    listen_port: u16,
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

    let sockaddr = (dev.ipv4_addr().await?, args.listen_port).into();
    let listener = dev.tcp_listen(sockaddr).await?;

    tracing::info!(listening_addr = %sockaddr);

    loop {
        let conn = listener.accept().await?;

        spawn(async move {
            let remote_ep = conn.remote_addr();
            tracing::info!(%remote_ep, "accepted connection");

            let (mut reader, mut writer) = tokio::io::split(conn);
            if let Err(e) = tokio::io::copy(&mut reader, &mut writer).await {
                tracing::error!(%remote_ep, error = %e);
            } else {
                tracing::info!(%remote_ep, "remote hung up");
            }
        });
    }
}
