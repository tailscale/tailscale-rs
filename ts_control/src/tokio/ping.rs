use alloc::string::String;

use tokio::sync::watch;
use ts_control_serde::PingType;
use ts_http_util::{BytesBody, ClientExt, Http2, Request};
use url::Url;

use crate::StateUpdate;

/// Path requested in HTTP GET via a Control-to-Node (C2N) [`ts_control_serde::PingRequest`] to
/// invoke the C2N echo handler.
const C2N_PATH_ECHO: &str = "/echo";
/// HTTP 400 Bad Request response sent for all unimplemented C2N methods/paths.
const C2N_PATH_UNKNOWN: &str = "HTTP/1.1 400 Bad Request\r\n\r\nunknown c2n path";
/// The start of an HTTP/1.1 200 response with no headers, just missing the body. Intended for use
/// with C2N echo responses, which can append the request body.
const C2N_RESPONSE_ECHO_PREAMBLE: &str = "HTTP/1.1 200 OK\r\n\r\n";

#[derive(Debug, thiserror::Error)]
pub enum PingError {
    #[error(transparent)]
    Http(#[from] ts_http_util::Error),
    #[error(transparent)]
    JoinFailed(#[from] tokio::task::JoinError),
    #[error("C2N ping request is missing payload")]
    MissingPayload,
    #[error(transparent)]
    WatchRecv(#[from] watch::error::RecvError),
}

/// Parses the payload of a Control-to-Node (C2N) [`ts_control_serde::PingRequest`] as an HTTP/1.1
/// request, or returns an error.
fn parse_c2n_ping(payload: &str) -> Result<Request<String>, PingError> {
    let req = ts_http_util::http1::parse_request(payload.as_bytes()).map_err(PingError::Http)?;
    tracing::trace!(
        payload_len = req.body().len(),
        payload = req.body(),
        "extracted payload from ping request body"
    );
    Ok(req)
}

/// Handles [`ts_control_serde::PingRequest`]s from the control plane to this Tailscale node.
/// Currently only handles Control-to-Node (C2N) echo requests; non-C2N requests are skipped with a
/// warning, while C2N requests for an unhandled path return a "400 Bad Request" to the control
/// plane.
///
/// ## C2N Mechanism
///
/// The C2N mechanism provides a way for the control plane to query a Tailscale node about their
/// local state, or request changes to the node state. A lot of debugging and metrics-related
/// features are implemented via this mechanism, along with a number of knobs such as changing the
/// netfilter implementation or forcing a logs flush in the Tailscale Go client.
///
/// Ping requests of type [`PingType::C2N`] contain an entire HTTP/1.1 request as their payload.
/// The method and path of this request determine which handler is invoked; for example, in the
/// Tailscale Go client, "GET /echo ..." invokes the C2N echo handler, while
/// "POST /netfilter-kind ..." changes the netfilter implementation the client uses (on Linux only).
/// The handler must return a full HTTP response to the request containing the requested data and/or
/// status - for example, "HTTP/1.1 200 OK <body>" or "HTTP/1.1 400 Bad Request".
///
/// `tailscale-rs` returns an HTTP 400 Bad Request status with an error message to the control
/// plane for any unimplemented C2N methods/paths.
pub async fn handle_ping(
    state: &StateUpdate,
    control_url: &Url,
    http2_client: &Http2<BytesBody>,
) -> Result<(), PingError> {
    let Some(ping_request) = &state.ping else {
        return Ok(());
    };

    tracing::trace!(request = ?ping_request, "handling ping request");
    for typ in &ping_request.types {
        if typ != &PingType::C2N {
            tracing::warn!(ping_type = ?typ, "ignoring unsupported ping type");
            continue;
        }

        let ping_request_body = ping_request
            .payload
            .as_ref()
            .ok_or(PingError::MissingPayload)?;
        let c2n_request = match parse_c2n_ping(ping_request_body) {
            Ok(c2n_request) => {
                tracing::trace!(?c2n_request, "parsed c2n ping");
                c2n_request
            }
            Err(_) => {
                tracing::warn!(?ping_request_body, "ignoring malformed c2n ping");
                continue;
            }
        };

        let c2n_request_path = c2n_request.uri().path();
        let c2n_response = match c2n_request_path {
            C2N_PATH_ECHO => {
                tracing::trace!(c2n_request_path, "handling c2n echo");
                format!("{}{}", C2N_RESPONSE_ECHO_PREAMBLE, c2n_request.body())
            }
            _ => {
                tracing::debug!(c2n_request_path, "no handler for c2n path");
                C2N_PATH_UNKNOWN.to_string()
            }
        };

        let ping_response_url = control_url
            .join(ping_request.url.path())
            .map_err(|_| PingError::MissingPayload)?;
        tracing::trace!(%ping_response_url, ?c2n_response, "posting c2n response");
        let response = http2_client
            .post(&ping_response_url, None, c2n_response.into())
            .await?;
        if !response.status().is_success() {
            tracing::error!(status = %response.status(), "responding to c2n ping");
        } else {
            tracing::debug!("c2n response sent");
        }
    }

    Ok(())
}
