#![cfg(target_os = "macos")]

//! Dump route tables on macOS.

use clap::Parser;
use futures_util::StreamExt;
use ts_netmon::bsd::{RouteSocket, net_table, net_table::partial_sockaddr};
use zerocopy::IntoBytes;

#[derive(clap::Parser)]
struct Args {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ts_cli_util::init_tracing();
    let _args = Args::parse();

    let sock = RouteSocket::new()?;
    let mut raw_stream = sock.raw_msg_stream();

    while let Some(msg) = raw_stream.next().await {
        let msg = msg?;

        let (rest, (ty, msg)) = net_table::MessageHeader::parse(msg.as_bytes())
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        let mut iter =
            nom::combinator::iterator(rest, partial_sockaddr::<_, nom::error::Error<_>>());

        let addrs = msg.addrs().into_iter().zip(&mut iter).collect::<Vec<_>>();
        iter.finish()
            .map_err(|e| e.to_string())
            .map_err(std::io::Error::other)?;

        tracing::info!(?ty, ?msg, ?addrs);
    }

    Ok(())
}
