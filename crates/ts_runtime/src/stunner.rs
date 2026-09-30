use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use kameo::{
    actor::{ActorRef, Spawn},
    message::{Context, Message},
};
use tokio::{sync::oneshot, time::MissedTickBehavior};
use ts_derp::IpUsage;
use ts_netcheck::stun::TransactionId;
use zerocopy::IntoBytes;

use crate::{dataplane::IncomingStunMsg, direct::DirectActor, env::Env};

/// Actor that sends STUN requests to DERP servers to get this node's public IPv4.
pub struct Stunner {
    env: Env,
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
            if let Ok(Some(x)) =
                tokio::time::timeout(Duration::from_secs(3), self.stun_once(server)).await
            {
                tracing::debug!(stun_addr = %x);

                self.env
                    .publish(StunAddress {
                        addr: x,
                        measured: Instant::now(),
                    })
                    .await
                    .unwrap();

                return;
            }
        }

        tracing::warn!("failed to stun");
    }

    async fn stun_once(&self, ep: SocketAddr) -> Option<SocketAddr> {
        let (tx, rx) = oneshot::channel();
        let env = self.env.clone();

        // Intentionally don't supervise this actor: we're using it as a task that can listen to the
        // bus. We want it to be destroyed when the aref drops (if this function times out in
        // `try_stun`).
        let _aref = StunRoundtripper::spawn((ep, tx, env));

        let (ep, _rxed_inst) = rx.await.ok()?;
        Some(ep)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct StunAddress {
    pub addr: SocketAddr,
    pub measured: Instant,
}

#[derive(Copy, Clone)]
struct Tick;

impl kameo::Actor for Stunner {
    type Args = Env;
    type Error = crate::Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
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

/// Glorified task that just runs a STUN binding request to a specified server endpoint,
/// then reports the result on a response channel.
///
/// Needed (as opposed to spawning a tokio task or [`Task`][crate::Task]) because we need
/// to listen on the bus for the response to our binding request.
struct StunRoundtripper {
    txn: TransactionId,
    resp: Option<oneshot::Sender<(SocketAddr, Instant)>>,
}

impl kameo::Actor for StunRoundtripper {
    type Args = (SocketAddr, oneshot::Sender<(SocketAddr, Instant)>, Env);
    type Error = crate::Error;

    async fn on_start((ep, tx, env): Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<IncomingStunMsg>(&slf).await?;

        let (tid, buf) = ts_netcheck::stun::new_txn();

        env.ask::<DirectActor, _>(None, crate::direct::SendStun { buf, ep }, true)
            .await?;

        Ok(Self {
            txn: tid,
            resp: Some(tx),
        })
    }
}

impl Message<IncomingStunMsg> for StunRoundtripper {
    type Reply = ();

    async fn handle(&mut self, msg: IncomingStunMsg, ctx: &mut Context<Self, Self::Reply>) {
        let Some((txid, addr)) = ts_netcheck::stun::try_decode(msg.pkt.as_bytes()) else {
            return;
        };

        if txid != self.txn {
            return;
        }

        let _ = self.resp.take().unwrap().send((addr, Instant::now()));
        ctx.stop();
    }
}
