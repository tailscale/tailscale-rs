use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
};
use tokio::time::MissedTickBehavior;
use ts_derp::IpUsage;

use crate::env::Env;

/// Actor that sends STUN requests to DERP servers to get this node's public IPv4.
pub struct Stunner {
    env: Env,
    stun: Arc<ts_netcheck::StunProber>,
    servers: Vec<SocketAddr>,
}

impl Stunner {
    #[tracing::instrument(skip_all, fields(n_server = self.servers.len()), level = "trace")]
    async fn try_stun(&self) {
        if self.servers.is_empty() {
            tracing::debug!("skipping stun, servers not populated yet");
            return;
        }

        for &server in &self.servers {
            if let Ok(Ok((_dur, x))) =
                tokio::time::timeout(Duration::from_secs(3), self.stun.measure(server)).await
            {
                tracing::debug!(stun_addr = %x);

                self.env
                    .publish(StunAddress {
                        addr: x.ip(),
                        measured: Instant::now(),
                    })
                    .await
                    .unwrap();

                return;
            }
        }

        tracing::warn!("failed to stun");
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct StunAddress {
    pub addr: IpAddr,
    pub measured: Instant,
}

#[derive(Copy, Clone)]
struct Tick;

impl kameo::Actor for Stunner {
    type Args = Env;
    type Error = crate::Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        // panicking in on_start is fine, this is checked as part of Runtime::spawn
        let stun = ts_netcheck::StunProber::try_new().await.unwrap();
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;

        env.scheduler
            .tell(
                kameo_actors::scheduler::SetInterval::new(
                    slf.downgrade(),
                    Duration::from_secs(20),
                    Tick,
                )
                .set_missed_tick_behaviour(MissedTickBehavior::Skip),
            )
            .await?;

        env.register(None, &slf).await?;

        Ok(Self {
            env,
            servers: vec![],
            stun: Arc::new(stun),
        })
    }
}

impl Message<Tick> for Stunner {
    type Reply = ();

    async fn handle(&mut self, _: Tick, _ctx: &mut Context<Self, Self::Reply>) {
        self.try_stun().await;
    }
}

impl Message<Arc<ts_control::StateUpdate>> for Stunner {
    type Reply = ();

    async fn handle(
        &mut self,
        state_update: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let Some(derp_map) = &state_update.derp else {
            return;
        };

        let was_empty = self.servers.is_empty();
        self.servers.clear();

        for region in derp_map.values() {
            for server in &region.servers {
                let Some(stun_port) = server.stun_port else {
                    continue;
                };

                let addr = match server.ipv4 {
                    IpUsage::FixedAddr(a) => (a, stun_port).into(),
                    IpUsage::UseDns => {
                        let addr = tokio::net::lookup_host((server.hostname.as_str(), stun_port))
                            .await
                            .ok()
                            .and_then(|mut x| x.next());

                        let Some(addr) = addr else {
                            continue;
                        };

                        addr
                    }
                    _ => continue,
                };

                tracing::trace!(%addr, "identified stun server");
                self.servers.push(addr);
            }
        }

        tracing::debug!(n_server = self.servers.len(), "updated stun servers");

        if was_empty && !self.servers.is_empty() {
            tracing::trace!("stun server set became populated, trying stun now");
            self.try_stun().await;
        }
    }
}
