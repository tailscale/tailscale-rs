use alloc::collections::BTreeMap;

use bytes::Bytes;
use futures_util::Stream;
use tokio::io::{AsyncRead, AsyncReadExt};
use ts_control_serde::{MapRequest, MapResponse, PingRequest};
use ts_http_util::{BytesBody, ClientExt, Http2, ResponseExt};
use ts_packet::PacketMut;
use ts_packetfilter as pf;
use ts_packetfilter_state as pf_state;
use url::Url;

use crate::{DialPlan, NodeId};

#[derive(Debug, thiserror::Error, Clone, Copy, Eq, PartialEq)]
#[error("Error sending map request")]
pub(crate) enum MapStreamError {
    SerDe,
    NetworkError,
}

impl From<serde_json::Error> for MapStreamError {
    fn from(error: serde_json::Error) -> Self {
        tracing::error!(%error, "serialization error sending map request");
        MapStreamError::SerDe
    }
}

impl From<ts_http_util::Error> for MapStreamError {
    fn from(error: ts_http_util::Error) -> Self {
        tracing::error!(%error, "http error sending map request");
        MapStreamError::NetworkError
    }
}

impl From<MapStreamError> for crate::Error {
    fn from(e: MapStreamError) -> Self {
        match e {
            MapStreamError::SerDe => crate::Error::Internal(
                crate::InternalErrorKind::SerDe,
                crate::Operation::MapRequest,
            ),
            MapStreamError::NetworkError => {
                crate::Error::NetworkError(crate::Operation::MapRequest)
            }
        }
    }
}

/// An update to the peers recorded in the netmap.
#[derive(Debug)]
pub enum PeerUpdate {
    /// Complete peer state.
    Full(Vec<crate::Node>),

    /// Delta update to the peer state.
    Delta {
        /// Peers added to or changed in the state.
        upsert: Vec<crate::Node>,
        /// Peer [`NodeId`]s removed from the state.
        remove: Vec<NodeId>,
    },
}

/// The components of a packet filter update.
///
/// These can't be merged into a single map due to the update rules.
pub type FilterUpdate = (Option<pf::Ruleset>, BTreeMap<String, Option<pf::Ruleset>>);

/// An update to the netmap state produced from a mapresponse.
#[derive(Debug)]
pub struct StateUpdate {
    /// New derp map is available.
    pub derp: Option<crate::DerpMap>,
    /// New self-node.
    pub node: Option<crate::Node>,
    /// Updates to the set of peers in the netmap.
    pub peer_update: Option<PeerUpdate>,
    /// Send a ping request.
    pub ping: Option<PingRequest>,
    /// Update to the packet filter.
    pub packetfilter: Option<FilterUpdate>,
    /// This URL should be displayed to the user or opened in their browser automatically.
    pub pop_browser_url: Option<Url>,
    /// New dial plan sent by control.
    pub dial_plan: Option<DialPlan>,
}

pub(crate) fn map_stream(reader: impl AsyncRead + Unpin) -> impl Stream<Item = StateUpdate> {
    futures_util::stream::unfold(reader, async |mut reader| {
        let msg_len = reader
            .read_u32_le()
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, "could not read netmap length");
            })
            .ok()?;

        let mut buf = PacketMut::new(msg_len as usize);
        tracing::trace!(?msg_len, "reading netmap");

        reader
            .read_exact(buf.as_mut())
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, "could not read netmap");
            })
            .ok()?;

        let map_response: MapResponse = serde_json::from_slice(buf.as_ref())
            .inspect_err(|e| {
                tracing::error!(error = %e, "deserializing netmap");
            })
            .ok()?;

        tracing::trace!(?msg_len, ?map_response);

        let packetfilter = packet_filter(&map_response);

        fn nonempty<T>(x: &Option<Vec<T>>) -> bool {
            x.as_ref().is_some_and(|x| !x.is_empty())
        }

        let peer_update = if let Some(full_map) = map_response.peers {
            Some(PeerUpdate::Full(full_map.iter().map(Into::into).collect()))
        } else if nonempty(&map_response.peers_removed) || nonempty(&map_response.peers_changed) {
            Some(PeerUpdate::Delta {
                remove: map_response.peers_removed.unwrap_or_default(),
                upsert: map_response
                    .peers_changed
                    .unwrap_or_default()
                    .iter()
                    .map(Into::into)
                    .collect(),
            })
        } else {
            None
        };

        if !map_response.peers_changed_patch.is_empty() {
            tracing::warn!(peers_changed_patch = ?map_response.peers_changed_patch, "ignored peer patch changes");
        }

        Some((
            StateUpdate {
                peer_update,
                node: map_response.node.as_ref().map(Into::into),
                derp: map_response
                    .derp_map
                    .as_ref()
                    .map(|x| crate::convert_derp_map(x).collect()),
                ping: map_response.ping_request,
                packetfilter,
                pop_browser_url: map_response.pop_browser_url.and_then(|u| {
                    u.parse()
                        .inspect_err(|e| tracing::error!(error = %e, "invalid pop browser url"))
                        .ok()
                }),
                dial_plan: map_response.control_dial_plan.map(Into::into),
            },
            reader,
        ))
    })
}

fn packet_filter(map_response: &MapResponse<'_>) -> Option<FilterUpdate> {
    if map_response.packet_filter.is_none() && map_response.packet_filters.is_empty() {
        return None;
    }

    Some((
        map_response
            .packet_filter
            .as_ref()
            .map(|x| pf_state::rules_to_pf(x).collect()),
        map_response
            .packet_filters
            .iter()
            .map(|(rule_name, rules)| {
                (
                    rule_name.to_string(),
                    rules
                        .as_ref()
                        .map(|x| Some(pf_state::rules_to_pf(x).collect()))
                        .unwrap_or_default(),
                )
            })
            .collect(),
    ))
}

#[tracing::instrument(skip_all, fields(map_url = %url.as_str()))]
pub(crate) async fn send_map_request(
    map_request: MapRequest<'_>,
    url: &Url,
    http2_conn: &Http2<BytesBody>,
) -> Result<impl AsyncRead + 'static, MapStreamError> {
    tracing::debug!("sending map request to control server...");

    let body = if cfg!(debug_assertions) {
        serde_json::to_string_pretty(&map_request)?
    } else {
        serde_json::to_string(&map_request)?
    };
    tracing::trace!(
        %body,
        "sending map request"
    );

    let resp = http2_conn.post(url, None, Bytes::from(body).into()).await?;

    let status = resp.status();
    tracing::trace!(?status, "received map response");

    if !status.is_success() {
        tracing::error!(
            status = status.as_u16(),
            "failed to register map updates with unsuccesful HTTP status code"
        );
        return Err(MapStreamError::NetworkError);
    }

    Ok(resp.into_read())
}
