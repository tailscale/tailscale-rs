//! Peer path discovery agent.
//!
//! [`PathDiscoverer`] is the top-level supervisor responsible for creating [`PeerPd`] actors in
//! response to [`ActivePeers`] updates (one [`PeerPd`] per peer we are trying to perform path
//! discovery for). As a reminder, [`ActivePeers`] is the set of peers (tracked and published by the
//! dataplane) that have recent _outgoing_ traffic (this node is trying to send packets to the
//! peer). Peers not part of the [`ActivePeers`] set have no retained path information.
//!
//! [`PeerPd`]'s job is to generate disco traffic to attempt to reach the peer through an avenue
//! other than DERP. Currently, this means probing for UDP connectivity by measuring RTT of a disco
//! ping/pong. A `CallMeMaybe` message is sent to the peer before pings go out to attempt to get it
//! to open a reverse path. Once a path is found, it's published to the bus and interested actors
//! may consume it -- most importantly, the route updater will update the underlay route table to
//! use the discovered path, meaning that dataplane traffic will begin using it. If more than one
//! path is found, the path with the lowest RTT latency is selected and published as the best path
//! for this peer.
//!
//! [`PeerPd`]s attempt to perform path discovery immediately on startup and on a repeating time
//! interval thereafter. Currently, the timeout period for ping responses _is_ this interval
//! (`PROBE_PERIOD`). After each interval, the in-flight state is wiped and a new set of
//! `CallMeMaybe` and `Ping` messages go out; hence, if pongs take more time than the interval to
//! come back, the [`PeerPd`] will never record them.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use kameo::{
    actor::{ActorRef, Spawn, WeakActorRef},
    error::ActorStopReason,
    message::{Context, Message},
    supervision::RestartPolicy,
};
use kameo_actors::scheduler::SetInterval;
use smol_str::SmolStr;
use tokio::time::MissedTickBehavior;
use ts_dataplane::async_tokio::ActivePeers;
use ts_disco_protocol::{CallMeMaybe, Ping, Pong};
use ts_keys::DiscoPublicKey;
use ts_transport::{DynEndpoint, PeerId, UnderlayTransportId};
use ts_util::fmt::IterFmt;

use crate::{
    Error,
    dataplane::IncomingDiscoMsg,
    direct::NewEndpoints,
    disco::{Disco, SendDisco},
    env::Env,
    peer_tracker::PeerState,
};

/// Top-level actor responsible for coordinating path discovery for peers.
///
/// Spawns per-peer child actors to handle discovery, then aggregates and debounces results.
pub struct PathDiscoverer {
    active_peers: ActivePeers,
    best_paths: BestPathMap,
    env: Env,
}

pub type BestPathMap = HashMap<PeerId, (UnderlayTransportId, DynEndpoint)>;

#[derive(Clone)]
pub struct BestPaths(pub Arc<BestPathMap>);

#[derive(Clone)]
struct PeerBestPath {
    peer: PeerId,
    ep: Option<(UnderlayTransportId, DynEndpoint)>,
}

impl kameo::Actor for PathDiscoverer {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Env, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<ActivePeers>(&slf).await?;
        env.subscribe::<PeerBestPath>(&slf).await?;
        env.register(None, &slf).await?;

        Ok(Self {
            env,
            best_paths: Default::default(),
            active_peers: Default::default(),
        })
    }

    async fn on_stop(
        &mut self,
        _: WeakActorRef<Self>,
        _: ActorStopReason,
    ) -> Result<(), Self::Error> {
        self.best_paths.clear();
        self.publish_best_paths().await;

        Ok(())
    }
}

impl PathDiscoverer {
    async fn publish_best_paths(&self) {
        self.env
            .publish(BestPaths(Arc::new(self.best_paths.clone())))
            .await
            .unwrap();
    }
}

impl Message<ActivePeers> for PathDiscoverer {
    type Reply = ();

    async fn handle(&mut self, msg: ActivePeers, ctx: &mut Context<Self, Self::Reply>) {
        for &to_create in msg.difference(&self.active_peers) {
            tracing::trace!(peer_id = ?to_create, "spawning actor for active peer");

            let aref = PeerPd::supervise(ctx.actor_ref(), (self.env.clone(), to_create))
                .restart_policy(RestartPolicy::Transient)
                .spawn()
                .await;

            aref.wait_for_startup_result().await.unwrap();
        }

        let mut any_deleted = false;
        for to_delete in self.active_peers.difference(&msg) {
            // deletions are handled by the PeerPds themselves
            any_deleted = any_deleted || self.best_paths.remove(to_delete).is_some();
        }

        if any_deleted {
            self.publish_best_paths().await;
        }

        self.active_peers = msg;
    }
}

impl Message<PeerBestPath> for PathDiscoverer {
    type Reply = ();

    async fn handle(
        &mut self,
        PeerBestPath { peer, ep }: PeerBestPath,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let changed = match ep {
            Some(ep) => {
                let ret = self.best_paths.insert(peer, ep.clone());
                ret != Some(ep)
            }
            None => self.best_paths.remove(&peer).is_some(),
        };

        if !changed {
            return;
        }

        self.publish_best_paths().await;
    }
}

type TxId = [u8; 12];

const PROBE_PERIOD: Duration = Duration::from_millis(5_000);

/// Duration after which peers' "seen endpoints" are cleaned up if they haven't sent traffic.
const SEEN_ENDPOINTS_TIMEOUT: Duration = Duration::from_millis(30_000);

enum ProbeState {
    /// This probe is in-flight with the given transaction id. It was sent at `sent`.
    InFlight { transaction: TxId, sent: Instant },
    /// This probe succeeded, measuring the indicated `latency`.
    Success {
        /// The round-trip latency measured by this probe.
        latency: Duration,
        /// The transport used to perform this probe.
        transport: UnderlayTransportId,
    },
}

/// Single-peer path discovery agent.
struct PeerPd {
    peer_id: PeerId,
    disco_key: Option<DiscoPublicKey>,

    /// Indicates whether we've had enough information to send probes yet.
    ///
    /// If not, we try to immediately send a probe whenever we get new information that might make
    /// this possible.
    ///
    /// This is used as a heuristic improvement to reduce the delay to first probe in the common
    /// case. When [`PeerPd`] spawns, there is _usually_ enough info in the system (in retained bus
    /// messages) to immediately start sending probes for the peer. But since bus messages are sent
    /// asynchronously and with no guaranteed order, we will need to wait briefly (milliseconds at
    /// most in a normal system) for all of them to be delivered/until we have enough local info to
    /// actually send the probes. The message handlers for [`PeerState`] and [`NewEndpoints`] thus
    /// _try_ to call [`PeerPd::start_probes`] only if this field is `false`; that function
    /// evaluates whether it has enough info to actually send the probes, and if so, sets this field
    /// to `true` (preventing anything other than the scheduled probe intervals from triggering
    /// probes).
    started_probing: bool,

    /// Records for current-generation probes (in-flight, or newly succeeded).
    current_probes: HashMap<DynEndpoint, ProbeState>,
    /// Lookup from transaction id to the endpoint to which it corresponds.
    ///
    /// It is expected that we may get incoming pong traffic from endpoints not in this map, e.g.
    /// from timed out probes.
    tx_lookup: HashMap<TxId, DynEndpoint>,
    /// Map holding the previous probe latencies for each endpoint (i.e. from the last probe
    /// generation). This is used to decide a latency while the next probe is in-flight.
    previous_probe_latencies: HashMap<(UnderlayTransportId, DynEndpoint), Duration>,

    this_node_endpoints: Arc<[ts_control::Endpoint]>,

    /// Peer's endpoints learned from control which can be used for disco coordination, i.e. which
    /// can be used to send `CallMeMaybe` messages.
    ///
    /// This field is part of a pair with `endpoints_ctrl` -- the two fields are partitioned out of
    /// the peer's endpoints (reported from control) on the basis of their answer to
    /// [`Endpoint::is_disco_coordinator`][ts_transport::Endpoint::is_disco_coordinator]. This field
    /// has those which respond `true`.
    coord_endpoints_ctrl: HashSet<DynEndpoint>,

    /// Endpoints for this peer derived from the most recent netmap.
    /// Excludes endpoints in [`PeerPd::disco_endpoints_ctrl`].
    endpoints_ctrl: HashSet<DynEndpoint>,

    /// Endpoints for this peer derived from the most recent
    /// [`CallMeMaybe`][ts_disco_protocol::CallMeMaybe] disco message.
    endpoints_cmm: HashSet<DynEndpoint>,

    /// Endpoints for which we've seen disco traffic arrive from this peer, mapped to the instant at
    /// which we most recently saw that traffic.
    ///
    /// We always try to reach out back to the peer over these endpoints, even if they're not
    /// sent by control or in a `CallMeMaybe`.
    seen_peer_endpoints: HashMap<DynEndpoint, Instant>,

    env: Env,
}

impl PeerPd {
    pub fn actor_name(peer_id: PeerId) -> SmolStr {
        smol_str::format_smolstr!("peerpd_{}", peer_id.0)
    }

    async fn start_probes(&mut self) {
        let Some(disco_key) = self.disco_key else {
            tracing::trace!("no disco key known for peer, can't send pings");
            return;
        };

        if self.coord_endpoints_ctrl.is_empty() {
            tracing::trace!("no disco coordinator endpoints, can't send callmemaybes");
            return;
        }

        if self.this_node_endpoints.is_empty() {
            tracing::trace!("no node endpoints, skip");
            return;
        }

        self.started_probing = true;

        self.tx_lookup.clear();
        self.previous_probe_latencies.clear();

        let latencies_was_empty = self.previous_probe_latencies.is_empty();

        for (ep, state) in self.current_probes.drain() {
            let ProbeState::Success { latency, transport } = state else {
                tracing::trace!(?ep, "probe did not succeed before next start_probe");
                continue;
            };

            tracing::trace!(?ep, ?latency, "valid latency");
            self.previous_probe_latencies
                .insert((transport, ep), latency);
        }

        if latencies_was_empty != self.previous_probe_latencies.is_empty() {
            let best = self
                .previous_probe_latencies
                .iter()
                .min_by_key(|&(_, dur)| dur);

            self.env
                .publish_noretain(PeerBestPath {
                    peer: self.peer_id,
                    ep: best.map(|((transport, ep), _latency)| (*transport, ep.clone())),
                })
                .await
                .unwrap();
        }

        // Send `CallMeMaybe`s on all disco coordinator endpoints. Reminder: coord_endpoints_ctrl is
        // already filtered at reception-time by Endpoint::is_disco_coordinator.
        for ep in &self.coord_endpoints_ctrl {
            let cmm_pkt = Disco::mk_pkt::<CallMeMaybe>(
                CallMeMaybe::size_for_endpoint_count(self.this_node_endpoints.len()),
                &self.env.keys.disco_keys,
                &disco_key,
                |cmm| {
                    for (tgt, ep) in cmm
                        .endpoints
                        .iter_mut()
                        .zip(self.this_node_endpoints.iter())
                    {
                        *tgt = ep.endpoint.into();
                    }
                },
            );

            self.env
                .publish_noretain(SendDisco {
                    ep: ep.clone(),
                    buf: cmm_pkt,
                })
                .await
                .unwrap();

            tracing::trace!(?ep, sent_eps = ?self.this_node_endpoints, "sent callmemaybe");
        }

        // Send pings for all non-disco-coordinator endpoints.
        let mut eps = self.seen_peer_endpoints.keys().collect::<HashSet<_>>();
        eps.extend(&self.endpoints_cmm);
        eps.extend(&self.endpoints_ctrl);

        for ep in eps {
            if ep.is_disco_coordinator() {
                continue;
            }

            Self::send_disco_ping(
                &self.env,
                ep.clone(),
                disco_key,
                &mut self.current_probes,
                &mut self.tx_lookup,
            )
            .await;
        }
    }

    // this is an associated fn because we need to do a partial reborrow through self
    #[tracing::instrument(skip_all, fields(?ep, %disco_key, tx_id = tracing::field::Empty))]
    async fn send_disco_ping(
        env: &Env,
        ep: DynEndpoint,
        disco_key: DiscoPublicKey,
        probe_state: &mut HashMap<DynEndpoint, ProbeState>,
        tx_lookup: &mut HashMap<TxId, DynEndpoint>,
    ) {
        // TODO(npry): this currently makes the implicit, awkward, and not-generally-correct
        //   assumption that at most one underlay transport id can carry traffic of a given endpoint
        //   type. this isn't a problem currently because derp (the transport that can currently
        //   have multiple transport ids) doesn't exchange ping/pong traffic, and udp only has one
        //   transport id at the moment, so there's no race (currently, the first latency
        //   report for a given endpoint will win). that's fine conceptually -- we want the fastest
        //   endpoint -- but we should be able to measure all paths concurrently/unambiguously.
        //   intend to refactor so that transaction id allocation occurs in the transport --
        //   probably it reports back to us that it's issued a ping (with timestamp + txid), so we
        //   can correlate it to a possible returned pong

        let tx_id = rand::random();
        tracing::Span::current()
            .record("tx_id", tracing::field::debug(IterFmt::contiguous(&tx_id)));

        let ping_buf = Disco::mk_pkt::<Ping>(
            Ping::size_with_padding(0),
            &env.keys.disco_keys,
            &disco_key,
            |msg| {
                msg.node_key = env.keys.node_keys.public;
                msg.tx_id = tx_id;
            },
        );

        env.publish_noretain(SendDisco {
            ep: ep.clone(),
            buf: ping_buf,
        })
        .await
        .unwrap();

        probe_state.insert(
            ep.clone(),
            ProbeState::InFlight {
                sent: Instant::now(),
                transaction: tx_id,
            },
        );
        tx_lookup.insert(tx_id, ep);

        tracing::trace!(tx_id = ?format_args!("{:x?}", IterFmt::contiguous(&tx_id)), "sent disco ping");
    }

    fn gc_seen_endpoints(&mut self) {
        let now = Instant::now();

        self.seen_peer_endpoints.retain(|_k, &mut v| {
            let age = now - v;

            age <= SEEN_ENDPOINTS_TIMEOUT
        });
    }
}

/// Periodic maintenance message triggering probes.
#[derive(Clone, Copy)]
struct ScheduleProbe;

impl kameo::Actor for PeerPd {
    type Args = (Env, PeerId);
    type Error = Error;

    async fn on_start(
        (env, peer_id): Self::Args,
        slf: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        env.subscribe::<ActivePeers>(&slf).await?;
        env.subscribe::<IncomingDiscoMsg>(&slf).await?;
        env.subscribe::<Arc<PeerState>>(&slf).await?;
        env.subscribe::<NewEndpoints>(&slf).await?;

        env.scheduler
            .ask(
                SetInterval::new(slf.downgrade(), PROBE_PERIOD, ScheduleProbe)
                    .set_missed_tick_behaviour(MissedTickBehavior::Skip),
            )
            .send()
            .await?;

        env.register(Some(Self::actor_name(peer_id)), &slf).await?;

        Ok(Self {
            env,
            peer_id,
            started_probing: false,
            previous_probe_latencies: Default::default(),
            this_node_endpoints: Default::default(),
            disco_key: Default::default(),
            tx_lookup: Default::default(),
            current_probes: Default::default(),
            endpoints_cmm: Default::default(),
            coord_endpoints_ctrl: Default::default(),
            endpoints_ctrl: Default::default(),
            seen_peer_endpoints: Default::default(),
        })
    }
}

impl Message<ScheduleProbe> for PeerPd {
    type Reply = ();

    async fn handle(&mut self, _: ScheduleProbe, _: &mut Context<Self, Self::Reply>) {
        self.gc_seen_endpoints();
        self.start_probes().await;
    }
}

impl Message<Arc<PeerState>> for PeerPd {
    type Reply = ();

    async fn handle(&mut self, state: Arc<PeerState>, _: &mut Context<Self, Self::Reply>) {
        // if this peer was deleted from the netmap, let removal from ActivePeers handle killing
        // this actor, otherwise control flow to PathDiscoverer may get confused. we can wipe out
        // our endpoints and stop doing anything because that doesn't interfere.

        if state.deletions.contains(&self.peer_id) {
            for ep in self
                .endpoints_ctrl
                .drain()
                .chain(self.coord_endpoints_ctrl.drain())
            {
                if self.endpoints_cmm.contains(&ep) || self.seen_peer_endpoints.contains_key(&ep) {
                    continue;
                }

                if let Some(ent) = self.current_probes.remove(&ep)
                    && let ProbeState::InFlight { transaction, .. } = ent
                {
                    self.tx_lookup.remove(&transaction);
                }
            }

            tracing::debug!(peer_id = ?self.peer_id, "peer deletion: state wiped, waiting for disappearance from activepeers");

            return;
        }

        let Some((_, node)) = state.peers.get(&self.peer_id) else {
            return;
        };

        self.disco_key = node.disco_key;

        (self.coord_endpoints_ctrl, self.endpoints_ctrl) = node
            .underlay_addresses
            .iter()
            .copied()
            .map(DynEndpoint::udp)
            .chain(core::iter::once(DynEndpoint::derp(node.node_key)))
            .partition(|x| x.is_disco_coordinator());

        tracing::trace!(peer_id = ?self.peer_id, endpoints_ctrl = ?self.endpoints_ctrl, disco_endpoints_ctrl = ?self.coord_endpoints_ctrl, "endpoint state updated");

        if !self.started_probing {
            self.start_probes().await;
        }
    }
}

impl Message<NewEndpoints> for PeerPd {
    type Reply = ();

    async fn handle(&mut self, msg: NewEndpoints, _ctx: &mut Context<Self, Self::Reply>) {
        self.this_node_endpoints = msg.0;

        if !self.started_probing {
            self.start_probes().await;
        }
    }
}

impl Message<ActivePeers> for PeerPd {
    type Reply = ();

    async fn handle(&mut self, msg: ActivePeers, ctx: &mut Context<Self, Self::Reply>) {
        if !msg.contains(&self.peer_id) {
            tracing::debug!(peer_id = %self.peer_id, "peer went inactive, stopping path discovery");
            ctx.stop();
        }
    }
}

impl Message<IncomingDiscoMsg> for PeerPd {
    type Reply = ();

    #[tracing::instrument(skip_all, fields(sender = ?msg.sender, transport_id = ?msg.transport))]
    async fn handle(&mut self, msg: IncomingDiscoMsg, _ctx: &mut Context<Self, Self::Reply>) {
        let pkt = msg.packet.get();

        if Some(pkt.sender_pubkey()) != self.disco_key.as_ref() {
            return;
        }

        self.seen_peer_endpoints.insert(msg.sender, Instant::now());

        let Some(pong) = pkt.as_msg::<Pong>() else {
            return;
        };

        tracing::trace!("got pong");

        let Some(ep) = self.tx_lookup.remove(&pong.tx_id) else {
            tracing::trace!(tx_id = ?format_args!("{:x?}", IterFmt::contiguous(&pong.tx_id)), "no pong known with this tx id");
            return;
        };

        let Some(entry) = self.current_probes.get_mut(&ep) else {
            // this endpoint must have been removed while the check was in-flight, drop it
            tracing::trace!(peer_id = ?self.peer_id, ?ep, "drop probe with missing state entry");
            return;
        };

        let ProbeState::InFlight { sent, .. } = &entry else {
            tracing::warn!("got ping response but it wasn't in-flight in endpoint entry");
            return;
        };

        let elapsed = Instant::now() - *sent;
        tracing::trace!(rtt = ?elapsed, endpoint = ?ep, peer_id = %self.peer_id, "measured latency");

        *entry = ProbeState::Success {
            latency: elapsed,
            transport: msg.transport,
        };
    }
}
