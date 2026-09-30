//! Log all changes captured by netmon.

use std::io;

use tokio_stream::StreamExt;
use ts_netmon::Netmon;

#[tokio::main]
async fn main() -> io::Result<()> {
    ts_cli_util::init_tracing();

    let mon = ts_netmon::platform_mon().ok_or(io::ErrorKind::Unsupported)?;
    let stream = (&mon as &dyn Netmon).with_default_route_events()?;

    let mut stream = core::pin::pin![stream];

    while let Some(evt) = stream.next().await {
        tracing::info!(evt = ?evt?);
    }

    tracing::warn!("stream ended");

    Ok(())
}
