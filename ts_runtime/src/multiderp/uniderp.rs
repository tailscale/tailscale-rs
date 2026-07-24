use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use futures::FutureExt;
use kameo::{
    actor::{ActorRef, Spawn, WeakActorRef},
    error::ActorStopReason,
    message::{Context, Message},
};
use smol_str::SmolStr;
use tokio::sync::{Mutex, watch};
use ts_control::DerpRegion;
use ts_dataplane::async_tokio::{FromUnderlay, Rx, ToUnderlay, Tx};
use ts_derp::RegionId;
use ts_keys::{NodeKey, Pair, Public};
use ts_packet::PacketMut;
use ts_transport::{
    BatchRecvIter, PeerId, UnderlayTransport, UnderlayTransportExt, UnderlayTransportId,
};

use crate::{
    Task,
    dataplane::{DataplaneActor, NewUnderlayTransport},
    derp_latency::DerpLatencyMeasurement,
    env::Env,
    multiderp::{Multiderp, SetRegionTransportId},
    peer_tracker::{PeerDb, PeerState},
    task::ErasedTask,
};

#[derive(Clone)]
pub struct Args {
    pub region_id: RegionId,
    pub region: DerpRegion,
    pub env: Env,
}

/// Single-region derp client.
pub struct Uniderp {
    /// Current state to spawn a runner task.
    ///
    /// Retained here because we may need to kill and restart the runner if we get updated region
    /// info.
    runner_state: Runner,

    /// The transport id this region is responsible for.
    transport_id: UnderlayTransportId,

    /// The task runner handling the transport for this region.
    task: ActorRef<ErasedTask>,

    home_derp_tx: watch::Sender<bool>,

    env: Env,
}

impl Uniderp {
    pub fn name(region_id: RegionId) -> SmolStr {
        smol_str::format_smolstr!("derp_region:{region_id}")
    }
}

#[kameo::messages]
impl Uniderp {
    #[message]
    pub fn transport_id(&self) -> Option<UnderlayTransportId> {
        Some(self.transport_id)
    }
}

async fn start_runner(mut runner: Runner) {
    if let Err(e) = runner.run().await {
        tracing::error!(error = %e, region_id = %runner.region_id, "running derp client");
    }
}

impl kameo::Actor for Uniderp {
    type Args = Args;
    type Error = crate::Error;

    async fn on_start(args: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        let (home_derp_tx, home_derp_rx) = watch::channel(false);

        let (transport_id, from_dataplane, to_dataplane) = args
            .env
            .ask::<DataplaneActor, _>(Option::<SmolStr>::None, NewUnderlayTransport, true)
            .await?;

        args.env
            .ask::<Multiderp, _>(
                None,
                SetRegionTransportId(args.region_id, Some(transport_id)),
                true,
            )
            .await?;

        let runner = Runner {
            region_id: args.region_id,
            region: args.region,
            peer_db: Arc::new(RwLock::new(None)),
            home_derp_rx,
            to_dataplane,
            keys: args.env.keys.node_keys.clone(),
            from_dataplane: Arc::new(Mutex::new(from_dataplane)),
        };

        let task = Task::spawn_link(&slf, start_runner(runner.clone()).boxed()).await;

        args.env
            .subscribe::<Arc<ts_control::StateUpdate>>(&slf)
            .await?;
        args.env.subscribe::<Arc<PeerState>>(&slf).await?;
        args.env.subscribe::<DerpLatencyMeasurement>(&slf).await?;

        args.env
            .register(Some(Self::name(args.region_id)), &slf)
            .await?;

        Ok(Self {
            runner_state: runner,
            transport_id,
            home_derp_tx,
            task,
            env: args.env,
        })
    }

    async fn on_stop(
        &mut self,
        _: WeakActorRef<Self>,
        _: ActorStopReason,
    ) -> Result<(), Self::Error> {
        self.env
            .tell::<Multiderp, _>(
                None,
                SetRegionTransportId(self.runner_state.region_id, None),
            )
            .await?;

        Ok(())
    }
}

impl Message<Arc<ts_control::StateUpdate>> for Uniderp {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        ctx: &mut Context<Self, Self::Reply>,
    ) {
        let Some(derp) = &msg.derp else {
            return;
        };

        let Some(region) = derp.get(&self.runner_state.region_id) else {
            tracing::debug!(
                region_id = ?self.runner_state.region_id,
                "derp region disappeared from map, stopping"
            );
            ctx.stop();
            return;
        };

        if &self.runner_state.region == region {
            return;
        }

        tracing::debug!(id = %self.runner_state.region_id, "region changed, restarting task");
        self.runner_state.region = region.clone();

        self.task.unlink(ctx.actor_ref()).await;
        self.task.stop_gracefully().await.unwrap();
        self.task
            .wait_for_shutdown_with_result(|e| {
                if let Err(e) = e {
                    tracing::error!(error = ?e, "shutting down derp task on region update");
                }
            })
            .await;

        self.task = Task::spawn_link(
            ctx.actor_ref(),
            start_runner(self.runner_state.clone()).boxed(),
        )
        .await;
    }
}

impl Message<Arc<PeerState>> for Uniderp {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        let mut db = self.runner_state.peer_db.write().unwrap();
        *db = Some(msg.peers.clone());
    }
}

impl Message<DerpLatencyMeasurement> for Uniderp {
    type Reply = ();

    async fn handle(&mut self, msg: DerpLatencyMeasurement, _ctx: &mut Context<Self, Self::Reply>) {
        let Some(result) = msg.measurement.as_ref().first() else {
            tracing::trace!("received home derp measurement message but none was set");
            return;
        };

        self.home_derp_tx.send_if_modified(|x| {
            let new_val = result.id == self.runner_state.region_id;
            let changed = new_val != *x;
            *x = new_val;

            changed
        });
    }
}

#[derive(Clone)]
struct Runner {
    region_id: RegionId,
    region: DerpRegion,
    home_derp_rx: watch::Receiver<bool>,
    to_dataplane: Tx<FromUnderlay>,
    from_dataplane: Arc<Mutex<Rx<ToUnderlay>>>,
    peer_db: Arc<RwLock<Option<Arc<PeerDb>>>>,
    keys: Pair<NodeKey>,
}

impl Runner {
    const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(10);

    #[tracing::instrument(skip_all, fields(region_id = %self.region_id))]
    async fn run(&mut self) -> Result<(), ts_derp::Error> {
        loop {
            let pending = self.wait_for_activity().await;
            let transport = self.connect(pending).await?;
            self.run_transport(transport).await?;
        }
    }

    #[tracing::instrument(skip_all, level = "trace")]
    async fn wait_for_activity(&mut self) -> Option<(PeerId, Vec<PacketMut>)> {
        tracing::trace!("waiting for packet activity or for this to become home derp");

        let mut from_dataplane = self.from_dataplane.lock().await;

        while !*self.home_derp_rx.borrow_and_update() {
            tokio::select! {
                _ = self.home_derp_rx.changed() => {
                    tracing::trace!(is_home_derp = *self.home_derp_rx.borrow());
                },

                from_net = from_dataplane.recv() => {
                    tracing::trace!("received packet to send");
                    return from_net;
                }
            }
        }

        None
    }

    #[tracing::instrument(skip_all, level = "trace")]
    async fn connect(
        &self,
        pending: Option<(PeerId, Vec<PacketMut>)>,
    ) -> Result<
        impl UnderlayTransport<PeerKey = PeerId, Error = ts_derp::Error> + 'static,
        ts_derp::Error,
    > {
        tracing::trace!("establishing derp connection");

        let client = ts_derp::DefaultClient::connect(&self.region.servers, &self.keys).await?;
        let transport = client.with_key_lookup(PeerDbLookup(self.peer_db.clone()));

        if let Some(pending) = pending {
            tracing::trace!("sending queued packet");
            transport.send([pending]).await?;
        }

        Ok(transport)
    }

    #[tracing::instrument(skip_all, level = "trace")]
    async fn run_transport(
        &mut self,
        transport: impl UnderlayTransport<PeerKey = PeerId, Error = ts_derp::Error>,
    ) -> Result<(), ts_derp::Error> {
        let mut last_activity = Instant::now();
        let mut from_dataplane = self.from_dataplane.lock().await;

        loop {
            let span = tracing::trace_span!("derp_loop");

            let inactivity_timeout =
                (!*self.home_derp_rx.borrow()).then(|| last_activity + Self::INACTIVITY_TIMEOUT);

            tokio::select! {
                from_derp = transport.recv() => {
                    last_activity = Instant::now();

                    for ret in from_derp.batch_iter() {
                        let (peer_id, pkts) = ret?;
                        let pkts = pkts.into_iter().collect::<Vec<_>>();

                        tracing::trace!(parent: &span, %peer_id, len = pkts.len(), "packet from derp server");

                        let Ok(()) = self.to_dataplane.send(pkts) else {
                            tracing::error!(parent: &span, "underlay receive channel closed");
                            break;
                        };
                    }
                },

                from_net = from_dataplane.recv() => {
                    last_activity = Instant::now();

                    let Some(from_net) = from_net else {
                        tracing::warn!(parent: &span, "transport queue closed");
                        return Ok(());
                    };

                    tracing::trace!(parent: &span, peer = %from_net.0, packets = from_net.1.len(), "packets to derp server");

                    transport.send([from_net]).await?;
                },

                _ = option_timeout(inactivity_timeout) => {
                    if !*self.home_derp_rx.borrow_and_update() {
                        tracing::trace!(parent: &span, "timed out and not home derp, closing derp conn");
                        return Ok(());
                    }
                },

                _ = self.home_derp_rx.changed() => {
                    tracing::trace!(is_home_derp = *self.home_derp_rx.borrow());
                },
            }
        }
    }
}

struct PeerDbLookup(Arc<RwLock<Option<Arc<PeerDb>>>>);

impl ts_transport::PeerLookup<PeerId, Public<NodeKey>> for PeerDbLookup {
    fn lookup_key(&self, id: PeerId) -> Option<Public<NodeKey>> {
        let db = self.0.read().unwrap();
        let db = db.as_ref()?;

        let (_, node) = db.get(&id)?;
        Some(node.node_key)
    }
}

impl ts_transport::PeerLookup<Public<NodeKey>, PeerId> for PeerDbLookup {
    fn lookup_key(&self, key: Public<NodeKey>) -> Option<PeerId> {
        let db = self.0.read().unwrap();
        let db = db.as_ref()?;

        let (id, _) = db.get(&key)?;

        Some(id)
    }
}

async fn option_timeout(duration: Option<Instant>) {
    match duration {
        Some(dur) => tokio::time::sleep_until(dur.into()).await,
        None => core::future::pending().await,
    }
}
