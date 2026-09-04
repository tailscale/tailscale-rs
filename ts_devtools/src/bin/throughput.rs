//! TCP server which sinks all incoming traffic and writes out random data as fast as
//! possible.

use core::{
    convert::Infallible,
    error::Error,
    pin::Pin,
    task::{Context, Poll},
};

use clap::Parser;
use rand::Rng;
use tokio::io::ReadBuf;

#[derive(Debug, Clone, clap::Parser)]
struct Args {
    #[clap(flatten)]
    common: ts_cli_util::CommonArgs,
}

#[tokio::main]
async fn main() -> Result<Infallible, Box<dyn Error + Send + Sync>> {
    ts_cli_util::init_tracing();
    let args = Args::parse();

    let config = args.common.config().await?;

    let dev = tailscale::Device::new(&config, None).await?;
    let listener = dev
        .tcp_listen((dev.ipv4_addr().await?, 1234).into())
        .await?;

    tracing::info!(endpoint = %listener.local_addr(), "tcp socket listening");

    loop {
        let mut sock = match listener.accept().await {
            Ok(sock) => sock,
            Err(e) => {
                tracing::error!(error = %e, "accepting connection");
                continue;
            }
        };

        tracing::info!(remote = %sock.remote_addr(), "accept");

        tokio::task::spawn(async move {
            let mut dst = tokio::io::join(AsyncRng, tokio::io::sink());

            if let Err(e) = tokio::io::copy_bidirectional(&mut sock, &mut dst).await {
                tracing::error!(remote = %sock.remote_addr(), error = %e);
            } else {
                tracing::info!(remote = %sock.remote_addr(), "close");
            }
        });
    }
}

/// [`AsyncRead`][tokio::io::AsyncRead] which always immediately and completely fills any
/// buffer with random data using [`rand::rng`].
///
/// This technically isn't holding tokio correctly because it can potentially do a lot of
/// CPU-bound work inside the poll, but for this informal benchmark it hasn't proven to be
/// a bottleneck.
#[derive(Copy, Clone)]
struct AsyncRng;

impl tokio::io::AsyncRead for AsyncRng {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let unfilled = buf.initialize_unfilled();
        rand::rng().fill_bytes(unfilled);
        let len = unfilled.len();

        buf.advance(len);

        Poll::Ready(Ok(()))
    }
}
