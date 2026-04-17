//! Support for the [`axum`] http server wrapping [`netstack::TcpListener`].
//!
//! # Example
//!
//! ```rust,no_run
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn core::error::Error>> {
//! let dev = tailscale::Device::new(
//!     &tailscale::Config {
//!         key_state: tailscale::load_key_file("tsrs_keys.json", Default::default()).await?,
//!         ..Default::default()
//!     },
//!     Some("YOUR_AUTH_KEY".to_owned()),
//! ).await?;
//!
//! let listener = dev.tcp_listen((dev.ipv4_addr().await?, 80).into()).await?;
//! let listener: tailscale::axum::Listener = listener.into();
//!
//! async fn index() -> &'static str { "Hello world!" }
//! let router = axum::Router::new().route("/", axum::routing::get(index));
//!
//! axum::serve(listener, router).await?;
//! #   Ok(())
//! # }
//! ```

use std::net::SocketAddr;

use crate::netstack;

/// Wrapper type implementing [`axum::serve::Listener`] on [`netstack::TcpListener`].
#[derive(Debug)]
pub struct Listener(netstack::TcpListener);

impl From<netstack::TcpListener> for Listener {
    fn from(listener: netstack::TcpListener) -> Self {
        Self(listener)
    }
}

impl From<Listener> for netstack::TcpListener {
    fn from(listener: Listener) -> Self {
        listener.0
    }
}

impl AsRef<netstack::TcpListener> for Listener {
    fn as_ref(&self) -> &netstack::TcpListener {
        &self.0
    }
}

impl axum::serve::Listener for Listener {
    type Io = netstack::TcpStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let stream = loop {
            match self.0.accept().await {
                Ok(stream) => break stream,
                Err(e) => tracing::error!(err = %e, "tcp accept"),
            }
        };

        let addr = stream.remote_addr();

        (stream, addr)
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.0.local_addr())
    }
}
