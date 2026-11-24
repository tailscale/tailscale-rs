use std::sync::Arc;

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use ts_netcheck::RegionResult;

use crate::{Error, env::Env};

#[derive(Clone, PartialEq, Eq)]
pub struct DerpLatencyMeasurement {
    pub measurement: Arc<Vec<RegionResult>>,
}

pub struct DerpLatencyMeasurer {
    env: Env,

    /// The most recent derp map we started measuring, used to skip redundant measurements
    /// (control may resend an unchanged derp map in every netmap update).
    last_map: Option<ts_control::DerpMap>,

    /// The in-flight measurement, if any.
    ///
    /// Measurement runs in its own task rather than inside the message handler. Measuring can
    /// take seconds, and blocking the handler that long lets this actor's mailbox fill with
    /// `StateUpdate`s. That blocks the bus (which awaits mailbox capacity when delivering), and
    /// then the bus can't accept our `DerpLatencyMeasurement` publish: a deadlock that wedges
    /// the whole runtime.
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for DerpLatencyMeasurer {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl kameo::Actor for DerpLatencyMeasurer {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Env, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
        env.register(None, &slf).await?;

        tracing::trace!("derp latency measurer running");

        Ok(Self {
            env,
            last_map: None,
            task: None,
        })
    }
}

impl Message<Arc<ts_control::StateUpdate>> for DerpLatencyMeasurer {
    type Reply = ();

    async fn handle(
        &mut self,
        state_update: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let Some(derp_map) = &state_update.derp else {
            return;
        };

        if self.last_map.as_ref() == Some(derp_map) {
            tracing::trace!("derp map unchanged, skipping measurement");
            return;
        }
        self.last_map = Some(derp_map.clone());

        // A newer map supersedes any measurement still in progress.
        if let Some(task) = self.task.take() {
            task.abort();
        }

        tracing::trace!("new derp map: beginning measurement");

        let env = self.env.clone();
        let derp_map = derp_map.clone();
        self.task = Some(tokio::spawn(async move {
            let latencies = ts_netcheck::measure_derp_map(&derp_map, &Default::default()).await;

            tracing::trace!(?latencies, "measurement complete");

            if let Err(e) = env
                .publish(DerpLatencyMeasurement {
                    measurement: Arc::new(latencies),
                })
                .await
            {
                tracing::error!(error = %e, "publishing");
            };
        }));
    }
}

#[cfg(test)]
mod test {
    use core::{net::Ipv4Addr, num::NonZeroU32, time::Duration};

    use kameo::actor::Spawn;
    use ts_derp::{IpUsage, RegionId, RegionInfo, ServerConnInfo, TlsValidationConfig};

    use super::*;

    /// Build a derp map with a single server at `127.0.0.1:port`.
    fn derp_map(port: u16) -> ts_control::DerpMap {
        let region = ts_control::DerpRegion {
            info: RegionInfo {
                name: "test".to_owned(),
                code: "test".to_owned(),
                no_measure_no_home: false,
            },
            servers: vec![ServerConnInfo {
                hostname: "127.0.0.1".to_owned(),
                ipv4: IpUsage::FixedAddr(Ipv4Addr::LOCALHOST),
                ipv6: IpUsage::Disable,
                tls_validation_config: TlsValidationConfig::CommonName {
                    common_name: "127.0.0.1".to_owned(),
                },
                https_port: port,
                stun_port: None,
                stun_only: false,
                supports_port_80: false,
            }],
        };

        [(RegionId(NonZeroU32::new(1).unwrap()), region)].into()
    }

    /// A latency measurement that never completes must not stop the measurer from
    /// draining its mailbox. Otherwise the bus, which awaits mailbox capacity when
    /// delivering, blocks behind it and wedges every actor that publishes.
    #[tokio::test]
    async fn stalled_measurement_does_not_block_bus() {
        // Accept connections and hold them open without ever completing a TLS handshake,
        // so every measurement against this server stalls.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut conns = vec![];
            while let Ok((conn, _)) = listener.accept().await {
                conns.push(conn);
            }
        });

        let env = Env::new(ts_keys::NodeState::generate());
        let measurer = DerpLatencyMeasurer::spawn(env.clone());
        measurer.wait_for_startup_result().await.unwrap();

        let update = Arc::new(ts_control::StateUpdate {
            derp: Some(derp_map(port)),
            node: None,
            peer_update: None,
            ping: None,
            packetfilter: None,
            pop_browser_url: None,
            dial_plan: None,
        });

        // Control may resend the same derp map in every netmap update. Publish far more
        // updates than fit in the measurer's and the bus's mailboxes combined.
        tokio::time::timeout(Duration::from_secs(10), async {
            for _ in 0..500 {
                env.publish(update.clone()).await.unwrap();
            }
        })
        .await
        .expect("bus blocked behind a stalled derp latency measurement");
    }
}
