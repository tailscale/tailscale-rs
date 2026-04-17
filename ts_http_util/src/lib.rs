#![doc = include_str!("../README.md")]

use bytes::Bytes;
use http::header::{CONNECTION, UPGRADE};
pub use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, header::HOST,
};
use http_body_util::{Empty, Full};
use hyper::body::Incoming;
use tokio::net::TcpStream;

mod client;
mod error;
pub mod http1;
pub mod http2;

pub use client::{Client, ClientExt};
pub use error::Error;
pub use http1::Http1;
pub use http2::Http2;
pub use hyper::upgrade::on as upgrade;
pub use sealed::ResponseExt;

/// The body of an HTTP [`Request`] or [`Response`] that's always empty; i.e., the body will always
/// be zero bytes in length.
pub type EmptyBody = Empty<Bytes>;

/// The body of an HTTP [`Request`] or [`Response`] that may contain one or more bytes; i.e., a body
/// may be present.
pub type BytesBody = Full<Bytes>;

/// A connection that has been upgraded from HTTP/1.1 to a different protocol, such as HTTP/2 or
/// DERP, via HTTP/1.1's upgrade mechanism.protocol upgrade
pub type Upgraded = hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>;

/// Upgrade a [`Response`] from HTTP/1.1 to the requested protocol.
pub async fn do_upgrade(resp: Response<Incoming>) -> hyper::Result<Upgraded> {
    let upgraded = hyper::upgrade::on(resp).await?;
    Ok(hyper_util::rt::TokioIo::new(upgraded))
}

mod sealed {
    use futures::TryStreamExt;
    use http_body_util::BodyExt;
    use tokio::io::AsyncRead;
    use tokio_util::io::StreamReader;

    use crate::Error;

    /// Helper methods for [`http::Response`].
    pub trait ResponseExt {
        /// Collect the response body into a [`bytes::Bytes`].
        fn collect_bytes(self) -> impl Future<Output = Result<bytes::Bytes, Error>> + Send;
        /// Convert the response body into an [`AsyncRead`].
        fn into_read(self) -> impl AsyncRead + Send + Unpin + 'static;
    }

    impl<B> ResponseExt for http::Response<B>
    where
        B: hyper::body::Body + Send + Unpin + 'static,
        B::Data: Send + 'static,
        B::Error: core::error::Error + Send + Sync + 'static,
    {
        async fn collect_bytes(self) -> Result<bytes::Bytes, Error> {
            let buf = self
                .into_body()
                .collect()
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "collecting response body");
                    Error::Io
                })?
                .to_bytes();

            Ok(buf)
        }

        fn into_read(self) -> impl AsyncRead + Send + Unpin + 'static {
            StreamReader::new(
                self.into_body()
                    .into_data_stream()
                    .map_err(tokio::io::Error::other),
            )
        }
    }
}

/// Create a [`Request`] to upgrade from HTTP/1.1 to the given `protocol`, which can be sent to the
/// server via an [`Http1`] client to start the [HTTP/1.1 protocol upgrade] process.
///
/// Some protocols, such as TS2021, require additional headers in the initial request to
/// successfully upgrade; these can be provided via `extra_headers`.
///
/// [HTTP/1.1 protocol upgrade]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Protocol_upgrade_mechanism
pub fn make_upgrade_req(
    u: &url::Url,
    protocol: &str,
    extra_headers: impl IntoIterator<Item = (HeaderName, HeaderValue)>,
) -> Result<Request<EmptyBody>, Error> {
    // Use POST for the upgrade request. Some server implementations accept both
    // GET and POST, but others (e.g. Go's testcontrol) only accept POST. POST
    // is what Go's controlhttp client sends, so use it for widest compatibility.
    let mut req = Request::post(u.as_str())
        .header(HOST, u.host_str().ok_or(Error::InvalidParam)?)
        .header(UPGRADE, protocol)
        .header(CONNECTION, "Upgrade")
        .body(EmptyBody::new())
        .map_err(|e| {
            tracing::error!(error = %e, "creating upgrade request");
            Error::InvalidParam
        })?;

    req.headers_mut().extend(extra_headers);

    Ok(req)
}

/// Produce a `Host` header for the given URL.
///
/// Returns `None` if `u.host_str()` is `None` or includes non-ascii-printable characters.
pub fn host_header(u: &url::Url) -> Option<(HeaderName, HeaderValue)> {
    Some((HOST, HeaderValue::from_str(u.host_str()?).ok()?))
}

async fn dial_tcp(url: &url::Url) -> Result<TcpStream, Error> {
    let conn = TcpStream::connect((
        url.host_str().ok_or(Error::InvalidParam)?,
        url.port_or_known_default()
            .ok_or(Error::InvalidParam)
            .inspect_err(|_err| tracing::error!("unknown url port"))?,
    ))
    .await
    .map_err(|e| {
        tracing::error!(error = %e, %url, "dialing tcp");
        Error::Io
    })?;

    Ok(conn)
}

async fn dial_tls(
    url: &url::Url,
    alpn: impl IntoIterator<Item = Vec<u8>>,
) -> Result<ts_tls_util::TlsStream<TcpStream>, Error> {
    let server_name = ts_tls_util::server_name(url)
        .ok_or_else(|| {
            tracing::error!(%url, "parsing server name");
            Error::InvalidParam
        })?
        .to_owned();

    let conn = dial_tcp(url).await?;

    ts_tls_util::connect_alpn(server_name, conn, alpn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "dialing tls connection");

            Error::Io
        })
}
