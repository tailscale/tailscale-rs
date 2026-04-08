//! HTTP/1.1 client implementation, and utilities to establish an HTTP/1.1 connection over TCP or
//! TLS.

use bytes::Bytes;
use http::request::Parts;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response};
use hyper::{
    body::{Body, Incoming},
    client::conn::http1::{self, SendRequest},
};
use hyper_util::rt::tokio::WithHyperIo;
use std::str::FromStr;
use std::{
    fmt::{Debug, Formatter},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
    task::JoinSet,
};

use crate::{Client, Error};

/// "Chunked" value of the [`Transfer-Encoding HTTP header`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Transfer-Encoding).
const ENCODING_CHUNKED: HeaderValue = HeaderValue::from_static("chunked");

/// The maximum number of HTTP headers that will be parsed for a single request.
const MAX_PARSED_HEADERS: usize = 16;

/// An HTTP/1.1 client that can connect to a server and send HTTP requests/receive HTTP responses.
/// Supports the [HTTP/1.1 protocol upgrade mechanism].
///
/// [HTTP/1.1 protocol upgrade mechanism]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Protocol_upgrade_mechanism
#[derive(Clone)]
pub struct Http1<B> {
    inner: Arc<Inner<B>>,
}

impl<B> Debug for Http1<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http1").finish_non_exhaustive()
    }
}

struct Inner<B> {
    client: Mutex<SendRequest<B>>,
    _runner: JoinSet<()>,
}

impl<B> Client<B> for Http1<B>
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
            .map_err(From::from)
    }
}

/// Establish a connection to an HTTP/1.1 server over an existing connection.
pub async fn connect<B>(
    lower: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
) -> Result<Http1<B>, Error>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: core::error::Error + Send + Sync + 'static,
{
    let (client, conn) = http1::handshake(WithHyperIo::new(lower))
        .await
        .inspect_err(|e| {
            tracing::error!(error = %e, "sending request");
        })
        .map_err(Error::from)?;

    let mut joinset = JoinSet::new();

    joinset.spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::error!(?e, "error in http/1.1 connection; closing connection");
        }
    });

    Ok(Http1 {
        inner: Arc::new(Inner {
            client: Mutex::new(client),
            _runner: joinset,
        }),
    })
}

/// Establish an HTTP/1.1 connection to the server at the given `url` over plaintext TCP.
pub async fn connect_tcp<B>(url: &url::Url) -> Result<Http1<B>, Error>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: core::error::Error + Send + Sync + 'static,
{
    let conn = crate::dial_tcp(url).await?;
    connect(conn).await
}

/// Establish an HTTP/1.1 connection to the server at the given `url` over encrypted TLS.
pub async fn connect_tls<B>(url: &url::Url) -> Result<Http1<B>, Error>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: core::error::Error + Send + Sync + 'static,
{
    let conn = crate::dial_tls(url, [b"http/1.1".to_vec()]).await?;
    connect(conn).await
}

/// Parses the given slice into a [`Parts`] containing the HTTP method, version, path, and headers.
/// Returns the [`Parts`] and the offset to the start of the request body in `buf`, or an error.
///
/// Only supports up to [`MAX_PARSED_HEADERS`] individual HTTP headers in a single request; headers
/// beyond this number will be discarded.
fn parse_request_parts(buf: &[u8]) -> Result<(Parts, usize), Error> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_PARSED_HEADERS];
    let mut req = httparse::Request::new(&mut headers);

    let res = req.parse(buf).map_err(|err| {
        tracing::trace!(error = %err, "error parsing http request");
        Error::InvalidParam
    })?;
    if res.is_partial() || req.method.is_none() || req.path.is_none() {
        tracing::trace!(request = ?req, "incomplete http request");
        return Err(Error::InvalidParam);
    }

    let version = match req.version {
        Some(0) => http::Version::HTTP_10,
        Some(1) => http::Version::HTTP_11,
        _ => {
            tracing::trace!(version = req.version, "invalid http version");
            return Err(Error::InvalidParam);
        }
    };

    // We verified req.{method/path} are both Some(_) above - it's okay to unwrap here.
    let mut builder = Request::builder()
        .version(version)
        .method(req.method.unwrap())
        .uri(req.path.unwrap());
    for hdr in req.headers {
        let name = HeaderName::from_str(hdr.name).map_err(|err| {
            tracing::trace!(error = %err, "error parsing http header name");
            Error::InvalidParam
        })?;
        let value = HeaderValue::from_bytes(hdr.value).map_err(|err| {
            tracing::trace!(error = %err, "error parsing http header value");
            Error::InvalidParam
        })?;
        builder = builder.header(name, value);
    }

    let (parts, _) = builder
        .body(())
        .map_err(|err| {
            tracing::trace!(error = %err, "error constructing parts");
            Error::InvalidParam
        })?
        .into_parts();
    Ok((parts, res.unwrap()))
}

/// Parses the given `body` of an HTTP/1 request, transparently handling chunked transfer encoding.
///
/// `body` must contain the full request body before parsing, and only the request body - not the
/// full HTTP request. Transfer encodings other than "chunked", such as "compress", "deflate", or
/// "gzip", are not currently handled and will result in an error.
fn parse_body(headers: &HeaderMap, body: &[u8]) -> Result<Bytes, Error> {
    match headers.get("transfer-encoding") {
        None => Ok(Bytes::copy_from_slice(body)),
        Some(encoding) => {
            if encoding != ENCODING_CHUNKED {
                tracing::trace!(?encoding, "unsupported transfer encoding");
                Err(Error::InvalidParam)
            } else {
                let mut idx = 0;
                let mut bytes = bytes::BytesMut::new();
                while let Ok(httparse::Status::Complete((start_offset, chunk_size))) =
                    httparse::parse_chunk_size(&body[idx..])
                {
                    let start_idx = idx + start_offset;
                    let end_idx = start_idx + chunk_size as usize;
                    let chunk = &body[start_idx..end_idx];
                    tracing::trace!(start_idx, end_idx, ?chunk, "parsed chunk");
                    bytes.extend_from_slice(chunk);
                    idx += start_offset + chunk_size as usize;
                }
                Ok(bytes.freeze())
            }
        }
    }
}

/// Parses the given byte slice into an HTTP/1.0 or HTTP/1.1 request with a [`String`] body, or
/// returns an error.
///
/// This function only supports HTTP requests, and does not support HTTP/0.9, HTTP/2, or HTTP/3
/// requests. `buf` must contain the full request, including body, before parsing.
pub fn parse_request(buf: &[u8]) -> Result<Request<String>, Error> {
    let (parts, offset) = parse_request_parts(buf)?;
    let bytes = parse_body(&parts.headers, &buf[offset..])?;
    let body = String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidParam)?;
    Ok(Request::from_parts(parts, body))
}
