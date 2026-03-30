//! Example showing axum running on top of the netstack, accessible on the host through a
//! tun device.

use core::sync::atomic::AtomicUsize;
use std::sync::Arc;

use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use clap::Parser;

static WWW: include_dir::Dir = include_dir::include_dir!("$CARGO_MANIFEST_DIR/examples/axum/www");

async fn assets(Path(path): Path<String>) -> axum::response::Response {
    let Some(result) = WWW
        .get_file(&path)
        .or_else(|| WWW.get_file(format!("{path}/index.html")))
    else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };

    let mime = mime_guess::from_path(result.path());

    (
        [(
            axum::http::header::CONTENT_TYPE,
            mime.first_or_octet_stream().as_ref(),
        )],
        result.contents(),
    )
        .into_response()
}

async fn count(count: State<Arc<AtomicUsize>>) -> impl IntoResponse {
    let new = count.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    format!(r#"{{"count": {new}}}"#)
}

#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    #[clap(flatten)]
    common: ts_cli_util::CommonArgs,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn core::error::Error>> {
    ts_cli_util::init_tracing();

    let args = Args::parse();

    let dev = tailscale::Device::from_config(&tailscale::Config {
        auth_key: args.common.auth_key,
        statefile: args.common.statefile,
        ..Default::default()
    })
    .await?;

    let listener = dev.tcp_listen((dev.ipv4().await?, 80).into()).await?;

    let router = Router::new()
        .route("/count", post(count))
        .with_state(Arc::new(AtomicUsize::new(0)))
        .route("/{*path}", get(assets));

    let url = format!("http://{}/index.html", listener.local_endpoint());
    tracing::info!(%url, "http server listening");

    axum::serve(tailscale::axum::Listener::from(listener), router).await?;

    Ok(())
}
