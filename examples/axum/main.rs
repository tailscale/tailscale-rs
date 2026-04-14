//! An `axum`-based HTTP server that serves a simple webpage over the tailnet. Requires
//! `tailscale-rs` to be compiled with the `axum` feature.

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
use tracing::level_filters::LevelFilter;

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
    /// Path to a key file to use. Will be created if it doesn't exist.
    #[arg(short = 'c', long, default_value = "tsrs_keys.json")]
    key_file: std::path::PathBuf,

    /// The auth key to connect with.
    ///
    /// Can be omitted if the key file is already authenticated.
    #[arg(short = 'k', long)]
    auth_key: Option<String>,

    /// Port to bind to.
    #[arg(short, long, default_value_t = 80)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn core::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let args = Args::parse();

    let dev = tailscale::Device::new(
        &tailscale::Config {
            key_state: tailscale::load_key_file(&args.key_file, Default::default()).await?,
            ..Default::default()
        },
        args.auth_key.clone(),
    )
    .await?;

    let listener = dev
        .tcp_listen((dev.ipv4().await?, args.port).into())
        .await?;

    let router = Router::new()
        .route("/count", post(count))
        .with_state(Arc::new(AtomicUsize::new(0)))
        .route("/{*path}", get(assets));

    let url = format!("http://{}/index.html", listener.local_endpoint());
    tracing::info!(%url, "http server listening");

    axum::serve(tailscale::axum::Listener::from(listener), router).await?;

    Ok(())
}
