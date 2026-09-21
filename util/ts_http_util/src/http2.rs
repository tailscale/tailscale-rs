//! HTTP/2 client implementation, and utilities to establish an HTTP/2 connection over TCP or
//! TLS.
use std::{
    fmt::{Debug, Formatter},
    sync::Arc,
};

use http::{Request, Response};
use hyper::{
    body::{Body, Incoming},
    client::conn::http2::SendRequest,
};
use hyper_util::rt::{TokioExecutor, tokio::WithHyperIo};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
    task::JoinSet,
};

use crate::{Client, Error};

/// An HTTP/2 client that can connect to a server and send HTTP requests/receive HTTP responses.
#[derive(Clone)]
pub struct Http2<B> {
    inner: Arc<Inner<B>>,
}

impl<B> Debug for Http2<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http2").finish_non_exhaustive()
    }
}

struct Inner<B> {
    client: Mutex<SendRequest<B>>,
    _runner: JoinSet<()>,
}

impl<B> Client<B> for Http2<B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Send + Sync + 'static,
{
    async fn send(&self, req: Request<B>) -> Result<Response<Incoming>, Error> {
        let mut client = self.inner.client.lock().await;

        client
            .send_request(req)
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, "sending request");
            })
            .map_err(Error::from)
    }
}

/// Establish a connection to an HTTP/2 server over an existing connection.
pub async fn connect<B>(
    io: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
) -> Result<Http2<B>, Error>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: core::error::Error + Send + Sync + 'static,
{
    let (client, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), WithHyperIo::new(io))
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, "http2 handshake");
            })
            .map_err(Error::from)?;

    let mut tasks = JoinSet::new();

    tasks.spawn(async move {
        if let Err(e) = conn.await {
            tracing::error!(?e, "error in http/2 connection; closing connection");
        }
    });

    Ok(Http2 {
        inner: Arc::new(Inner {
            client: Mutex::new(client),
            _runner: tasks,
        }),
    })
}

/// Establish an HTTP/2 connection to the server at the given `url` over plaintext TCP.
pub async fn connect_tcp<B>(url: &url::Url) -> Result<Http2<B>, Error>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: core::error::Error + Send + Sync + 'static,
{
    let conn = crate::dial_tcp(url).await?;
    connect(conn).await
}

/// Establish an HTTP/2 connection to the server at the given `url` over encrypted TLS.
pub async fn connect_tls<B>(url: &url::Url) -> Result<Http2<B>, Error>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: core::error::Error + Send + Sync + 'static,
{
    let conn = crate::dial_tls(url, [b"h2".to_vec()]).await?;
    connect(conn).await
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http_body_util::Empty;
    use tracing_test::traced_test;

    use super::*;
    use crate::ClientExt;

    #[tokio::test]
    #[traced_test]
    async fn http2_over_tls_over_tcp() {
        if !ts_test_util::run_net_tests() {
            return;
        }

        let url: url::Url = "https://controlplane.tailscale.com/key".parse().unwrap();
        let client = connect_tls::<Empty<Bytes>>(&url).await.unwrap();

        let resp = client.get(&url, []).await.unwrap();
        tracing::info!("{:?}", resp);
    }
}
