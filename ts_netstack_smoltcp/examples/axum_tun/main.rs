//! Example showing axum running on top of the netstack, accessible on the host through a
//! tun device.

use core::{net::SocketAddr, sync::atomic::AtomicUsize};
use std::sync::Arc;

use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};

#[path = "../common/mod.rs"]
mod common;

use common::netsock::CreateSocket;

use crate::common::netsock;

static WWW: include_dir::Dir =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/examples/axum_tun/www");

async fn assets(Path(path): Path<String>) -> axum::response::Response {
    tracing::info!(%path);

    if let Some(result) = WWW
        .get_file(&path)
        .or_else(|| WWW.get_file(format!("{path}/index.html")))
    {
        let mime = mime_guess::from_path(result.path());

        (
            [(
                axum::http::header::CONTENT_TYPE,
                mime.first_or_octet_stream().as_ref(),
            )],
            result.contents(),
        )
            .into_response()
    } else {
        (StatusCode::NOT_FOUND, "not found").into_response()
    }
}

async fn count(count: State<Arc<AtomicUsize>>) -> impl IntoResponse {
    let new = count.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    format!(r#"{{"count": {new}}}"#)
}

#[tokio::main]
async fn main() -> common::Result<()> {
    common::init();

    let handle = common::spawn_tun_netstack()?;
    common::wait_for_tun().await;

    let listener = handle.tcp_listen(common::netstack_endpoint()).await?;

    let router = Router::new()
        .route("/count", post(count))
        .with_state(Arc::new(AtomicUsize::new(0)))
        .route("/{*path}", get(assets));

    let url = format!("http://{}/index.html", common::netstack_endpoint());
    tracing::info!(%url, "http server listening");

    axum::serve(Listener::from(listener), router).await?;

    Ok(())
}

struct Listener(netsock::TcpListener);

impl From<netsock::TcpListener> for Listener {
    fn from(listener: netsock::TcpListener) -> Self {
        Self(listener)
    }
}

impl axum::serve::Listener for Listener {
    type Io = netsock::TcpStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let stream = loop {
            match self.0.accept().await {
                Ok(stream) => break stream,
                Err(e) => tracing::error!(err = %e, "tcp accept"),
            }
        };

        let addr = stream.remote_endpoint();

        (stream, addr)
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.0.local_endpoint())
    }
}
