//! Functionality for connecting to and communicating with the Tailscale control server.

use futures_util::Stream;
use ts_http_util::{BytesBody, Http2};
use url::Url;

use crate::{Error, map_request_builder::MapRequestBuilder};

mod connect;
mod map_stream;
mod ping;
mod prefixed_reader;
mod register;

pub use connect::{
    CONTROL_PROTOCOL_VERSION, connect, fetch_control_key, read_challenge_packet, upgrade_ts2021,
};
pub use map_stream::{FilterUpdate, PeerUpdate, StateUpdate, map_stream, send_map_request};
pub use ping::handle_ping;
pub use register::{RegistrationError, register};

/// Type of the underlying http2 connection to the control server.
pub type HttpConn = Http2<BytesBody>;

/// Start the netmap stream. This connection should already be registered successfully.
pub async fn start_stream(
    control_url: &Url,
    node_keys: &ts_keys::NodeState,
    config: &crate::Config,
    conn: HttpConn,
) -> Result<impl Stream<Item = StateUpdate> + use<>, Error> {
    let builder = MapRequestBuilder::new(node_keys).as_stream();

    let request = if let Some(hostname) = &config.hostname {
        builder.hostname(hostname)
    } else {
        builder
    }
    .build();

    let map_url = control_url.join("machine/map").unwrap();

    let reader = send_map_request(request, &map_url, &conn).await?;
    tracing::info!("netmap stream started");
    Ok(map_stream(reader))
}
