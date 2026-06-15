use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use kameo::{
    actor::ActorRef,
    error::SendError,
    message::{Context, Message},
};
use tokio::{sync::watch, task::JoinSet};
use ts_control::DerpRegion;
use ts_derp::RegionId;
use ts_keys::{NodeKeyPair, NodePublicKey};
use ts_transport::{
    BatchRecvIter, PeerId, UnderlayTransport, UnderlayTransportExt, UnderlayTransportId,
};

use crate::{
    Env, Error,
    dataplane::{DataplaneActor, NewUnderlayTransport, UnderlayFromDataplane, UnderlayToDataplane},
    derp_latency::DerpLatencyMeasurement,
    peer_tracker::{PeerDb, PeerState},
};

/// Consumes derp map updates and spawns a task per region that runs an underlay transport.
/// Also consumes home derp indications (for this node) to notify the relevant task that it
/// should keep the transport awake even if there is no traffic.
///
/// Other than the home task (which is always kept alive to receive packets), the transport
/// tasks keep the connection alive as long as there is traffic sent or received, and for a
/// short grace period afterward. Connections are otherwise closed not in use.
pub struct Multiderp {
    env: Env,
    dataplane: ActorRef<DataplaneActor>,
    derps: HashMap<RegionId, RegionEntry>,
    current_home_derp: Option<RegionId>,
    peer_db: Arc<RwLock<Option<Arc<PeerDb>>>>,
    tasks: JoinSet<()>,
}

struct RegionEntry {
    transport_id: UnderlayTransportId,
    home_derp: watch::Sender<bool>,
}

impl Multiderp {
    #[tracing::instrument(skip_all, fields(region_id = %id))]
    async fn ensure_region(
        &mut self,
        id: RegionId,
        region: &DerpRegion,
        mut shutdown: watch::Receiver<bool>,
    ) {
        // TODO(npry): update if region info changes

        if self.derps.contains_key(&id) {
            tracing::trace!("region already existed");
            return;
        }

        let region = region.clone();
        let keys = self.env.keys.node_keys;

        let (transport_id, mut up, down) = match self.dataplane.ask(NewUnderlayTransport).await {
            Ok(val) => val,
            Err(SendError::ActorNotRunning(..) | SendError::ActorStopped) => {
                if !*shutdown.borrow() {
                    panic!("dataplane has stopped but we're not shutting down");
                }

                return;
            }
            Err(e) => unreachable!("{}", e),
        };
        let (home_derp_tx, mut home_derp_rx) = watch::channel(false);

        let peer_db = self.peer_db.clone();

        self.tasks.spawn(async move {
            while !*shutdown.borrow() {
                tokio::select! {
                    _ = shutdown.changed() => {
                        break;
                    },
                    ret = run_derp_once(
                        id,
                        &region,
                        keys,
                        &down,
                        &mut up,
                        &mut home_derp_rx,
                        &peer_db,
                    ) => if let Err(e) = ret {
                        tracing::error!(error = %e, region_id = %id, "running derp client");
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    },
                }

                if up.is_closed() {
                    tracing::warn!(region_id = %id, "underlay up channel closed!");
                    break;
                }

                if down.is_closed() {
                    tracing::warn!(region_id = %id, "underlay down channel closed!");
                    break;
                }
            }
        });

        self.derps.insert(
            id,
            RegionEntry {
                transport_id,
                home_derp: home_derp_tx,
            },
        );
    }
}

#[kameo::messages]
impl Multiderp {
    #[message]
    pub fn transport_id_for_region(&self, id: RegionId) -> Option<UnderlayTransportId> {
        Some(self.derps.get(&id)?.transport_id)
    }
}

struct PeerDbLookup<'a>(&'a RwLock<Option<Arc<PeerDb>>>);

impl ts_transport::PeerLookup<PeerId, NodePublicKey> for PeerDbLookup<'_> {
    fn lookup_key(&self, id: PeerId) -> Option<NodePublicKey> {
        let db = self.0.read().unwrap();
        let db = db.as_ref()?;

        let (_, node) = db.get(&id)?;
        Some(node.node_key)
    }
}

impl ts_transport::PeerLookup<NodePublicKey, PeerId> for PeerDbLookup<'_> {
    fn lookup_key(&self, key: NodePublicKey) -> Option<PeerId> {
        let db = self.0.read().unwrap();
        let db = db.as_ref()?;

        let (id, _) = db.get(&key)?;

        Some(id)
    }
}

#[tracing::instrument(skip_all, fields(region_id = %id), name = "derp runner")]
async fn run_derp_once(
    id: RegionId,
    region: &DerpRegion,
    keys: NodeKeyPair,
    to_dataplane: &UnderlayToDataplane,
    from_dataplane: &mut UnderlayFromDataplane,
    home_derp_rx: &mut watch::Receiver<bool>,
    peer_db: &RwLock<Option<Arc<PeerDb>>>,
) -> Result<(), ts_derp::Error> {
    const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(10);

    loop {
        let mut pending = None;

        tracing::trace!("waiting for packet activity or for this to become home derp");

        while !*home_derp_rx.borrow_and_update() {
            tokio::select! {
                _ = home_derp_rx.changed() => {
                    tracing::trace!(is_home_derp = *home_derp_rx.borrow());
                },

                from_net = from_dataplane.recv() => {
                    tracing::trace!("received packet to send");
                    pending = from_net;
                    break;
                }
            }
        }

        tracing::trace!("establishing derp connection");

        let client = ts_derp::DefaultClient::connect(&region.servers, &keys).await?;
        let transport = client.with_key_lookup(PeerDbLookup(peer_db));

        if let Some(pending) = pending {
            tracing::trace!("sending queued packet");
            transport.send([pending]).await?;
        }

        let mut last_activity = Instant::now();

        loop {
            let span = tracing::trace_span!("derp_loop");

            let inactivity_timeout =
                (!*home_derp_rx.borrow()).then(|| last_activity + INACTIVITY_TIMEOUT);

            tokio::select! {
                from_derp = transport.recv() => {
                    last_activity = Instant::now();

                    for ret in from_derp.batch_iter() {
                        let (peer_id, pkts) = ret?;
                        let pkts = pkts.into_iter().collect::<Vec<_>>();

                        tracing::trace!(parent: &span, %peer_id, len = pkts.len(), "packet from derp server");

                        let Ok(()) = to_dataplane.send((peer_id, pkts)) else {
                            tracing::error!(parent: &span, "underlay receive channel closed");
                            break;
                        };
                    }
                },

                from_net = from_dataplane.recv() => {
                    last_activity = Instant::now();

                    let Some(from_net) = from_net else {
                        tracing::warn!(parent: &span, "transport queue closed");
                        break;
                    };

                    tracing::trace!(parent: &span, peer = %from_net.0, packets = from_net.1.len(), "packets to derp server");

                    transport.send([from_net]).await?;
                },

                _ = option_timeout(inactivity_timeout) => {
                    if !*home_derp_rx.borrow_and_update() {
                        tracing::trace!(parent: &span, "timed out and not home derp, closing derp conn");
                        break;
                    }
                },

                _ = home_derp_rx.changed() => {
                    tracing::trace!(is_home_derp = *home_derp_rx.borrow());
                },
            }
        }
    }
}

async fn option_timeout(duration: Option<Instant>) {
    match duration {
        Some(dur) => tokio::time::sleep_until(dur.into()).await,
        None => core::future::pending().await,
    }
}

impl kameo::Actor for Multiderp {
    type Args = (Env, ActorRef<DataplaneActor>);
    type Error = Error;

    async fn on_start(
        (env, dataplane): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
        env.subscribe::<Arc<PeerState>>(&slf).await?;
        env.subscribe::<DerpLatencyMeasurement>(&slf).await?;

        Ok(Self {
            env,
            dataplane,
            peer_db: Default::default(),
            derps: Default::default(),
            tasks: JoinSet::new(),
            current_home_derp: None,
        })
    }
}

impl Message<Arc<ts_control::StateUpdate>> for Multiderp {
    type Reply = ();

    #[tracing::instrument(skip_all, name = "multiderp map update")]
    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let Some(derp_map) = &msg.derp else {
            return;
        };

        for (id, region) in derp_map {
            self.ensure_region(*id, region, self.env.shutdown.clone())
                .await;

            // If this is the home region and it was just started, it needs to be notified that it's
            // the home region.
            if let Some(home_derp) = self.current_home_derp
                && *id == home_derp
            {
                self.derps
                    .get_mut(&home_derp)
                    .unwrap()
                    .home_derp
                    .send_replace(true);
            }
        }
    }
}

impl Message<Arc<PeerState>> for Multiderp {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        let mut db = self.peer_db.write().unwrap();
        *db = Some(msg.peers.clone());
    }
}

impl Message<DerpLatencyMeasurement> for Multiderp {
    type Reply = ();

    async fn handle(&mut self, msg: DerpLatencyMeasurement, _ctx: &mut Context<Self, Self::Reply>) {
        let Some(result) = msg.measurement.as_ref().first() else {
            tracing::trace!("received home derp measurement message but none was set");
            return;
        };

        // Bail early if the home derp region hasn't changed.
        let new_region_id = result.id;
        if self.current_home_derp == Some(new_region_id) {
            tracing::debug!("received home derp measurement message, no change to home region");
            return;
        }

        // We now know the home derp region has changed. Sanity check - ensure that both the current
        // and new home derp regions exist in the region map. Doing this ahead of time and exiting
        // early avoids nasty unwind logic if we detect a missing region when we try to change it.
        if !self.derps.contains_key(&new_region_id) {
            tracing::error!(%new_region_id, "new home derp region missing in map, not updating");
            return;
        } else if let Some(cur_region_id) = self.current_home_derp
            && !self.derps.contains_key(&cur_region_id)
        {
            tracing::error!(%cur_region_id, "current home derp region missing in map, not updating");
            return;
        }

        // If the current home derp region is populated and differs from the new home derp region,
        // we need to notify the current region that it is no longer the home region before we
        // update.
        if let Some(cur_region_id) = self.current_home_derp {
            // Unwrap is safe, we verified self.derps holds cur_region_id above, and hold &mut self.
            let cur_region = self.derps.get_mut(&cur_region_id).unwrap();
            cur_region.home_derp.send_replace(false);
        }

        // Unwrap is safe, we verified self.derps holds new_region_id above, and hold &mut self.
        let new_region = self.derps.get_mut(&new_region_id).unwrap();
        self.current_home_derp = Some(new_region_id);
        new_region.home_derp.send_replace(true);
        tracing::info!(
            region_id = %new_region_id,
            latency_ms = result.latency.as_secs_f32() * 1000.,
            "new home derp region selected"
        );
    }
}
