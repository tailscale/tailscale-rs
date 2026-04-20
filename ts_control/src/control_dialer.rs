use core::fmt::{Debug, Formatter};
use std::time::Instant;

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_util::future::FutureExt;
use ts_bitset::BitsetDyn;
use ts_capabilityversion::CapabilityVersion;
use ts_http_util::{BytesBody, Http2};
use url::Url;

use crate::{DialCandidate, DialMode, DialPlan, tokio::ConnectionError};

/// Manages state for control dial plan and handles selection of successive dial candidates.
pub struct ControlDialer {
    plan: DialPlan,
    epoch: usize,
    timestamp: Instant,
    attempted_candidates: ts_dynbitset::DynBitset,
}

impl Default for ControlDialer {
    fn default() -> Self {
        Self {
            plan: DialPlan::default(),
            epoch: 0,
            timestamp: Instant::now(),
            attempted_candidates: Default::default(),
        }
    }
}

/// Creates a TCP connection on the basis of a specific [`DialCandidate`].
///
/// Produced by [`ControlDialer::next_dialer`].
pub trait TcpDialer {
    /// Open a TCP connection using the [`DialCandidate`] assigned to this dialer.
    ///
    /// - `host` is used if the [`DialCandidate`] requires DNS lookup.
    ///   **Ignored** for plain IP [`DialCandidate`]s.
    /// - `port` is the TCP port to connect to.
    ///
    /// Calling this function marks the current candidate as "attempted": the next call to
    /// [`ControlDialer::next_dialer`] will use the next available candidate.
    fn dial(
        self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = tokio::io::Result<TcpStream>> + Send;
}

enum ControlTcpDialer<'a> {
    UseDns,
    Planned {
        attempted: &'a mut ts_dynbitset::DynBitset,
        candidate: &'a DialCandidate,
        index: usize,
    },
}

impl Debug for ControlTcpDialer<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            ControlTcpDialer::UseDns => write!(f, "TcpDialer::Dns"),
            ControlTcpDialer::Planned { candidate, .. } => match &candidate.mode {
                DialMode::Ip(ip) => f.debug_tuple("TcpDialer::Ip").field(ip).finish(),
                DialMode::Ace { ip: Some(ip), host } => f
                    .debug_tuple("TcpDialer::Ace")
                    .field(ip)
                    .field(host)
                    .finish(),
                DialMode::Ace { host, .. } => f.debug_tuple("TcpDialer::Ace").field(host).finish(),
            },
        }
    }
}

impl TcpDialer for ControlTcpDialer<'_> {
    async fn dial(self, host: &str, port: u16) -> tokio::io::Result<TcpStream> {
        match self {
            ControlTcpDialer::UseDns => TcpStream::connect(format!("{host}:{port}")).await,
            ControlTcpDialer::Planned {
                candidate,
                attempted: used,
                index,
            } => {
                used.set(index);

                match candidate.mode {
                    DialMode::Ip(ip) => {
                        TcpStream::connect((ip, port))
                            .timeout(candidate.timeout)
                            .await?
                    }
                    DialMode::Ace { .. } => {
                        unimplemented!()
                    }
                }
            }
        }
    }
}

impl ControlDialer {
    /// Update the stored dial plan with the new `plan`.
    ///
    /// Returns whether the dial plan changed. Resubmission of the same dial plan is
    /// idempotent.
    pub fn update_dial_plan(&mut self, plan: &DialPlan) -> bool {
        if &self.plan == plan {
            return false;
        }

        self.plan = plan.clone();
        self.epoch += 1;
        self.timestamp = Instant::now();

        true
    }

    /// Clear the set of attempted dial candidates.
    ///
    /// This will cause future connection attempts to retry all available dialers in
    /// priority order.
    pub fn clear_attempted(&mut self) {
        self.attempted_candidates.clear_all();
    }

    /// Get the next dialer candidate from the dial plan.
    ///
    /// If all dialers have already been tried, falls back to system DNS.
    ///
    /// NB: the returned [`TcpDialer`] does not mark its corresponding candidate as having
    /// been attempted until [`TcpDialer::dial`] is called -- it is fine semantically to
    /// drop the returned dialer without calling `dial`.
    pub fn next_dialer(&mut self) -> impl TcpDialer + Debug {
        match &self.plan {
            DialPlan::UseDns => ControlTcpDialer::UseDns,
            DialPlan::Plan(candidates) => {
                let mut selected_candidate: Option<(usize, usize, &DialCandidate)> = None;
                let now = Instant::now();

                // TODO(npry): ensure candidate sorting, optimistically stop early
                for (i, candidate) in candidates.iter().enumerate() {
                    if self.attempted_candidates.test(i) {
                        continue;
                    }

                    let start_after = self.timestamp + candidate.start_delay_sec;
                    if start_after > now {
                        continue;
                    }

                    if matches!(candidate.mode, DialMode::Ace { .. }) {
                        // TODO(npry): ACE unsupported
                        continue;
                    }

                    if selected_candidate.is_none_or(|(prio, _idx, elem)| prio < elem.priority) {
                        selected_candidate = Some((candidate.priority, i, candidate));
                    }
                }

                let (i, candidate) = match selected_candidate {
                    Some((_prio, i, elem)) => (i, elem),
                    None => {
                        tracing::warn!(
                            "no dialer candidates available: falling back to system dns"
                        );
                        return ControlTcpDialer::UseDns;
                    }
                };

                ControlTcpDialer::Planned {
                    candidate,
                    index: i,
                    attempted: &mut self.attempted_candidates,
                }
            }
        }
    }

    /// Convenience wrapper for [`next_dialer`][ControlDialer::next_dialer] followed by
    /// [`complete_connection`].
    #[tracing::instrument(skip_all, fields(control_url = %url))]
    pub async fn full_connect_next(
        &mut self,
        url: &Url,
        machine_keys: &ts_keys::MachineKeyPair,
    ) -> Result<Http2<BytesBody>, ConnectionError> {
        let next = self.next_dialer();
        tracing::trace!(selected_control_dialer = ?next);

        let host = url.host_str().ok_or(ConnectionError::ConnectionFailed)?;
        let port = url
            .port_or_known_default()
            .ok_or(ConnectionError::ConnectionFailed)?;

        let conn = next.dial(host, port).await.map_err(|e| {
            tracing::error!(error = %e, %url, %host, port, "dialing tcp");
            ConnectionError::ConnectionFailed
        })?;

        tracing::debug!(
            remote_endpoint = ?conn.peer_addr(),
            "tcp connection to control"
        );

        let client = complete_connection(url, machine_keys, conn).await?;

        Ok(client)
    }
}

/// Complete a connection to control over the supplied I/O `stream`.
///
/// Establishes an http1 connection over `stream`, wrapping it in a TLS connection if
/// `url`'s scheme is `https`. Then upgrades the connection over ts2021 and establishes an
/// inner http2 connection.
pub async fn complete_connection<Io>(
    url: &Url,
    machine_keys: &ts_keys::MachineKeyPair,
    stream: Io,
) -> Result<Http2<BytesBody>, ConnectionError>
where
    Io: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let h1_client = match url.scheme() {
        "https" => {
            let conn = ts_tls_util::connect(
                ts_tls_util::server_name(url).ok_or(ConnectionError::ConnectionFailed)?,
                stream,
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "establishing tls connection");
                ConnectionError::ConnectionFailed
            })?;
            ts_http_util::http1::connect(conn).await?
        }
        "http" => ts_http_util::http1::connect(stream).await?,
        other => {
            tracing::error!(invalid_scheme = other);
            return Err(ConnectionError::ConnectionFailed);
        }
    };
    let control_public_key = crate::tokio::fetch_control_key(url).await?;

    let (handshake, init_msg) = ts_control_noise::Handshake::initialize(
        &crate::tokio::CONTROL_PROTOCOL_VERSION,
        &machine_keys.private,
        &control_public_key,
        CapabilityVersion::CURRENT,
    );

    let conn = crate::tokio::upgrade_ts2021(url, &init_msg, handshake, h1_client).await?;
    let conn = crate::tokio::read_challenge_packet(conn).await?;

    let h2_conn = ts_http_util::http2::connect(conn).await?;
    tracing::debug!("http2 connection to control established");

    Ok(h2_conn)
}
