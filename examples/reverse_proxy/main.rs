//! A TCP reverse proxy server.

use std::{error::Error, net::SocketAddr, path::PathBuf};

use clap::Parser;
use tailscale::{Config, Device, TailnetAddr, TargetStream};
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
    #[arg(short = 'k', long, env = "TS_AUTH_KEY")]
    auth_key: Option<String>,

    /// The hostname this node will request.
    #[arg(short = 'H', long, default_value = "reverse_proxy_example")]
    hostname: Option<String>,

    /// The URL of the control URL to connect to.
    ///
    /// Uses the Tailscale control server by default if unspecified.
    #[arg(long, env = "TS_CONTROL_URL")]
    control_url: Option<url::Url>,

    /// TCP port to listen on (on tailnet IPv4).
    #[clap(short, long, default_value_t = 8080)]
    listen_port: u16,

    /// Target TCP server to connect to.
    #[clap(short, long, default_value = "127.0.0.1:8080")]
    target_address: SocketAddr,
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

    let mut config = Config::default_with_key_file(&args.key_file).await?;
    config.requested_hostname = args.hostname;

    if let Some(url) = args.control_url {
        config.control_server_url = url;
    }

    let dev = Device::new(&config, args.auth_key).await?;
    let listen_addr = (dev.ipv4_addr().await?, args.listen_port).into();
    let proxy = dev.tcp_proxy(listen_addr, None, None).await?;

    tracing::info!(%listen_addr, "listening for incoming TCP connections to proxy");
    loop {
        let bridge = proxy
            .accept_one(async || {
                let stream: Box<dyn TargetStream> = if args.target_address.is_tailnet_addr() {
                    Box::new(dev.tcp_connect(args.target_address).await?)
                } else {
                    Box::new(
                        tokio::net::TcpStream::connect(args.target_address)
                            .await
                            .map_err(|_| tailscale::Error::ConnectionRefused)?,
                    )
                };

                Ok(stream)
            })
            .await?;
        tracing::info!(%bridge, "proxying connection");
    }
}
