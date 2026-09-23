use core::{net::SocketAddr, time::Duration};
use std::{sync::Arc, time::Instant};

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use stun_rs::{
    MessageClass, StunMessageBuilder, TransactionId,
    attributes::stun::{Fingerprint, Software, XorMappedAddress},
    methods::BINDING,
};
use tokio::{net::UdpSocket, sync::oneshot};

/// Probes peer devices over STUN.
///
/// A single prober is intended to be long-lived and supports concurrent use.
pub struct StunProber {
    shared: Arc<Shared>,
    _tasks: tokio::task::JoinSet<()>,
}

type StunReply = (Instant, SocketAddr);
type InFlightMap = DashMap<TransactionId, oneshot::Sender<StunReply>>;

/// Internal shared state.
// NOTE(npry): IPv4 and IPv6 sockets are explicitly separated here to avoid the complexity of
// managing a dual-stack socket, as some platforms don't support these, while others have
// support configured conditionally based on the distribution, etc. We just attempt to
// bind both independently, and at the moment, if binding the v6 socket fails, this is
// taken to imply that the platform has IPv6 support turned off.
struct Shared {
    sockv4: UdpSocket,
    sockv6: Option<UdpSocket>,

    in_flight: InFlightMap,
}

/// RAII guard to ensure that a STUN transaction is removed from the in-flight map.
struct TransactionDropGuard<'a> {
    txn: TransactionId,
    txns: &'a InFlightMap,
}

impl Drop for TransactionDropGuard<'_> {
    fn drop(&mut self) {
        self.txns.remove(&self.txn);
    }
}

impl StunProber {
    /// Default port for STUN connections.
    pub const DEFAULT_STUN_PORT: u16 = 3478;

    /// Construct a new prober.
    ///
    /// This binds UDP sockets and spawns tasks.
    pub async fn try_new() -> tokio::io::Result<Self> {
        let shared = Arc::new(Shared::try_new().await?);

        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn({
            let shared = shared.clone();
            async move { shared.run_recv(&shared.sockv4).await }
        });

        if shared.sockv6.is_some() {
            tasks.spawn({
                let shared = shared.clone();
                async move { shared.run_recv(shared.sockv6.as_ref().unwrap()).await }
            });
        }

        Ok(Self {
            shared,
            _tasks: tasks,
        })
    }

    /// Measure the latency to a peer by sending a STUN bind request.
    ///
    /// The return value includes the round-trip duration and STUNned address.
    pub async fn measure(&self, peer: SocketAddr) -> tokio::io::Result<(Duration, SocketAddr)> {
        let (rx, _guard) = self.shared.send_stun(peer).await?;
        let sent = Instant::now();

        let (resp, addr) = rx.await.unwrap();

        Ok((resp.duration_since(sent), addr))
    }
}

impl Shared {
    const SOFTWARE: &str = "tailnode";

    async fn try_new() -> tokio::io::Result<Self> {
        let sockv6 = UdpSocket::bind("[::]:0")
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, "binding v6 socket");
            })
            .ok();

        Ok(Shared {
            sockv4: UdpSocket::bind("0.0.0.0:0").await?,
            sockv6,
            in_flight: DashMap::new(),
        })
    }

    /// Return the socket bound to the given IP stack.
    ///
    /// The IPv6 socket may not exist if the OS does not have IPv6 support enabled.
    fn sock(&self, v4: bool) -> tokio::io::Result<&UdpSocket> {
        if v4 {
            return Ok(&self.sockv4);
        }

        self.sockv6.as_ref().ok_or_else(|| {
            tokio::io::Error::new(
                tokio::io::ErrorKind::Unsupported,
                "platform does not support ipv6",
            )
        })
    }

    async fn send_stun(
        &self,
        addr: SocketAddr,
    ) -> tokio::io::Result<(oneshot::Receiver<StunReply>, TransactionDropGuard<'_>)> {
        let req = StunMessageBuilder::new(BINDING, MessageClass::Request)
            .with_attribute(Software::new(Self::SOFTWARE).unwrap())
            .with_attribute(Fingerprint::default())
            .build();

        let encoder = stun_rs::MessageEncoderBuilder::default().build();
        let mut buf = BytesMut::zeroed(128);
        let n = encoder.encode(&mut buf, &req).unwrap();
        buf.truncate(n);

        let (rx, guard) = self.begin_transaction(*req.transaction_id());
        self.sock(addr.is_ipv4())?.send_to(&buf, addr).await?;

        Ok((rx, guard))
    }

    fn begin_transaction(
        &self,
        txn: TransactionId,
    ) -> (oneshot::Receiver<StunReply>, TransactionDropGuard<'_>) {
        let (tx, rx) = oneshot::channel();
        self.in_flight.insert(txn, tx);

        let guard = TransactionDropGuard {
            txn,
            txns: &self.in_flight,
        };

        (rx, guard)
    }

    fn recv_stun(&self, peer: SocketAddr, buf: Bytes) -> Option<(TransactionId, SocketAddr)> {
        let (msg, _n) = stun_rs::MessageDecoderBuilder::default()
            .build()
            .decode(&buf)
            .inspect_err(|e| {
                tracing::error!(error = %e, peer = %peer, "stun decode");
            })
            .ok()?;

        let Some(addr) = msg.get::<XorMappedAddress>() else {
            tracing::error!("no xor mapped address");
            return None;
        };

        let addr = addr.as_xor_mapped_address().unwrap();

        Some((*msg.transaction_id(), *addr.socket_address()))
    }

    async fn run_recv(&self, sock: &UdpSocket) {
        loop {
            let mut buf = BytesMut::new();

            let who = match sock.recv_buf_from(&mut buf).await {
                Ok((_n, who)) => who,
                Err(e) => {
                    tracing::error!(error = %e, "stun recv");
                    continue;
                }
            };

            let rx_timestamp = Instant::now();
            let b = buf.split().freeze();

            let span = tracing::trace_span!(
                "stun_rx",
                remote_peer = %who,
                len = b.len(),
                tx_id = tracing::field::Empty,
                stun_addr = tracing::field::Empty,
            )
            .entered();

            let Some((tx_id, socket_addr)) = self.recv_stun(who, b) else {
                tracing::trace!("not a stun packet");
                continue;
            };

            span.record("tx_id", tracing::field::display(&tx_id));
            span.record("stun_addr", tracing::field::display(&socket_addr));

            let Some((_, resp_channel)) = self.in_flight.remove(&tx_id) else {
                tracing::trace!("no matching in-flight request");
                continue;
            };

            tracing::trace!("stun ok");
            let _ignore = resp_channel.send((rx_timestamp, socket_addr));
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn stun_test() {
        if !ts_test_util::run_net_tests() {
            return;
        }

        let prober = StunProber::try_new().await.unwrap();
        let mut addrs = tokio::net::lookup_host("derp1f.tailscale.com:3478")
            .await
            .unwrap();
        let addr = addrs.next().unwrap();
        tracing::trace!(%addr);

        let (dur, addr) = prober.measure(addr).await.unwrap();
        tracing::info!(?dur, %addr);
    }
}
