//! Measure latency to derp regions over HTTPS.

use core::{net::SocketAddr, time::Duration};
use std::{io, time::Instant};

use tokio::io::{AsyncRead, AsyncWrite};
use ts_derp::ServerConnInfo;
use ts_http_util::{ClientExt, EmptyBody, Http1};
use url::Url;

/// Errors that may occur while probing derp latency.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// IO error occurred.
    #[error("io error occurred")]
    Io,

    /// Bad HTTP status.
    #[error("bad http status")]
    HttpStatus,

    /// Invalid parameter.
    #[error("invalid parameter")]
    InvalidParam,

    /// Something went wrong which shouldn't have.
    #[error("something went wrong")]
    Unexpected,
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Error::Io
    }
}

impl From<ts_http_util::Error> for Error {
    fn from(err: ts_http_util::Error) -> Self {
        match err {
            ts_http_util::Error::InvalidInput => Error::InvalidParam,
            ts_http_util::Error::Io | ts_http_util::Error::Timeout => Error::Io,
            _ => Error::Unexpected,
        }
    }
}

impl From<ts_derp::dial::Error> for Error {
    fn from(value: ts_derp::dial::Error) -> Self {
        use ts_derp::dial;

        match value {
            dial::Error::Io => Error::Io,
            dial::Error::InvalidParam => Error::InvalidParam,
        }
    }
}

/// Probe configuration.
#[derive(Debug, Copy, Clone)]
pub struct Config {
    /// The number of warmup probes discarded before an actual measurement.
    pub n_warmup: usize,
    /// The number of samples to take.
    pub n_samples: usize,
    /// Whether an HTTP probe should fail on a bad status code (outside 200-299).
    ///
    /// While we can get a valid latency measurement on a bad status code, it may be worth
    /// failing the measurement if we have something in the middle terminating TLS (a
    /// reverse proxy or an MITM box) that significantly impacts the latency measurement
    /// if the backend server is down. E.g., we might get a 503 response far quicker than
    /// we "should" if the proxy is close to us but far from the derp server upstream. Or we
    /// could get a very delayed 504 if the proxy is waiting to decide whether the upstream
    /// is dead. Hence, it might be useful to require a good status code as a heuristic
    /// indication that we have a complete circuit to the derp server.
    ///
    /// For reference, the Go client fails on a bad status, so that's the default behavior
    /// here.
    pub fail_on_status: bool,
}

impl Default for Config {
    fn default() -> Self {
        // Empirically, the first sample often has a higher latency than subsequent ones, but it's
        // usually just the first one.
        //
        // There's some jitter in subsequent samples, but we're not setting clocks off of this, so
        // just do the one by default.
        Self {
            n_warmup: 1,
            n_samples: 1,
            fail_on_status: true,
        }
    }
}

/// Measure the HTTPS latency to a set of servers, conventionally comprising a single DERP region.
///
/// The servers are assumed to be presented in order of preference and are tried serially. Any error
/// during connection or latency measurement causes this function to advance to trying the next
/// server.
///
/// Returns `None` iff no servers could be successfully measured, either due to connectivity errors
/// or because they were not configured to be reachable. See the notes on
/// [`dial_region_tls`][ts_derp::dial::dial_region_tls] and
/// [`dial_region_tcp`][ts_derp::dial::dial_region_tcp] for more details on when
/// servers are treated as not configured for reachability.
pub async fn measure_https_latency<'c>(
    servers: impl IntoIterator<Item = &'c ServerConnInfo>,
    config: Config,
) -> Option<(Duration, &'c ServerConnInfo, SocketAddr)> {
    if config.n_samples == 0 {
        tracing::warn!("requested to measure https latency with 0 samples");
        return None;
    }

    // We `.into_iter()` here so that we can pass a `&mut` iter ref into dial_region_tls below: if a
    // server fails in `measure_server_latency`, this means we can resume trying untested
    // servers by passing what's left in the iterator into `dial_region_tls` on the next loop
    // iteration.
    let mut servers = servers.into_iter();

    loop {
        let (conn, server, remote) = match ts_derp::dial::dial_region_tls(&mut servers).await {
            Ok(Some(x)) => x,
            Ok(None) => {
                tracing::warn!("ran out of servers to dial");
                return None;
            }
            Err(e) => {
                tracing::error!(error = %e, "dialing tls");
                continue;
            }
        };

        match measure_server_latency(conn, server, &config).await {
            Ok(dur) => return Some((dur, server, remote)),
            Err(e) => {
                tracing::error!(error = %e, %remote, %server.hostname, "measuring server latency failed, try next server");
            }
        }
    }
}

/// Measure the round-trip time (RTT) to a DERP server over a previously-established connection
/// `conn`.
///
/// This constructs an HTTP/1.1 client and measures RTT over a number of requests as configured by
/// `config`.
pub async fn measure_server_latency(
    conn: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    server: &ServerConnInfo,
    config: &Config,
) -> Result<Duration, Error> {
    let client: Http1<EmptyBody> = ts_http_util::http1::connect(conn).await?;

    for _ in 0..config.n_warmup {
        if let Err(e) = measure_http_request(server, &client, config.fail_on_status).await {
            tracing::error!(error = %e, "error during https warmup");
        }
    }

    let mut sum = Duration::ZERO;

    for _ in 0..config.n_samples {
        sum += measure_http_request(server, &client, config.fail_on_status).await?;
    }

    Ok(sum / config.n_samples as u32)
}

/// Measure the round-trip time (RTT) of an HTTP GET request.
///
/// This measures just the RTT between initiating the request send and having received the response
/// headers. The time to connect the `http_client` prior to calling this method isn't counted, nor
/// is the time to complete downloading the body.
pub async fn measure_http_request(
    server: &ServerConnInfo,
    http_client: impl ts_http_util::Client<EmptyBody>,
    fail_on_status: bool,
) -> Result<Duration, Error> {
    let url: Url = format!("https://{}/derp/latency-check", server.hostname)
        .parse()
        .map_err(|_| Error::InvalidParam)?;

    let start = Instant::now();
    let resp = http_client.get(&url, None).await?;
    let dur = start.elapsed();

    if fail_on_status && !resp.status().is_success() {
        tracing::error!(status = %resp.status());
        return Err(Error::HttpStatus);
    }

    Ok(dur)
}

#[cfg(test)]
mod test {
    use super::*;

    fn info() -> ServerConnInfo {
        ServerConnInfo::default_from_url(&"https://derp1f.tailscale.com".parse().unwrap()).unwrap()
    }

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn basic_test() {
        if !ts_test_util::run_net_tests() {
            return;
        }

        let info = info();

        let (latency, _info, remote) = measure_https_latency([&info], Default::default())
            .await
            .unwrap();

        tracing::info!(?latency, %remote);
    }

    /// Look at the output here to see the evidence for the `Default` instance for
    /// [`super::Config`]. Empirically, when writing this, only the first request for each
    /// connection actually paid a latency penalty, and the rest were pretty similar.
    #[tracing_test::traced_test]
    #[tokio::test]
    async fn repeated() {
        if !ts_test_util::run_net_tests() {
            return;
        }

        let info = info();

        let (conn, server, remote) = ts_derp::dial::dial_region_tls([&info])
            .await
            .unwrap()
            .unwrap();
        let client: Http1<EmptyBody> = ts_http_util::http1::connect(conn).await.unwrap();

        for _ in 0..10 {
            let latency = measure_http_request(server, &client, true).await.unwrap();

            tracing::info!(?latency, %remote);
        }
    }
}
