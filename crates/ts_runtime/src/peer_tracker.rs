//! Peer delta update tracking.

use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use kameo::{
    actor::ActorRef,
    message::{Context, Message},
    reply::ReplySender,
};
use ts_bart::RoutingTable;
use ts_control::Node;
use ts_transport::PeerId;

use crate::{Error, env::Env, kv};

/// Actor that tracks peer delta updates and emits new states.
pub struct PeerTracker {
    seen_state_update: bool,
    pending_requests: Vec<Pending>,
    env: Env,
}

pub(crate) const KV_OWNER: ts_kv_store::Owner = ts_kv_store::Owner("peer tracker");

impl PeerTracker {
    fn peer_by_name_opt(&self, name: &str) -> Option<Node> {
        let name = name.trim_end_matches('.');
        let txn = self.env.kv_store().begin_ro_transaction(KV_OWNER);
        let indexes = txn.Peers.indexes();

        indexes
            .fqdn
            .get(name)
            .or_else(|| indexes.hostname.get(name))
            .map(|(_, node)| node)
    }

    fn peer_by_tailnet_ip_opt(&self, ip: IpAddr) -> Option<Node> {
        let txn = self.env.kv_store().begin_ro_transaction(KV_OWNER);

        let id = txn.PeerIpIndex.with(|v| v.lookup(ip).copied())??;
        txn.Peers.get(&id)
    }

    /// Get the nodes with the closest matching route.
    pub fn get_route(&self, route: ipnet::IpNet) -> Vec<Node> {
        let txn = self.env.kv_store().begin_ro_transaction(KV_OWNER);

        let Some(Some(ids)) = txn.PeerRouteIndex.with(|v| v.lookup_prefix(route).cloned()) else {
            return Vec::new();
        };

        ids.into_iter()
            .map(|id| txn.Peers.get(&id).unwrap())
            .collect()
    }
}

impl kameo::Actor for PeerTracker {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
        env.register(None, &slf).await?;

        Ok(Self {
            pending_requests: Default::default(),
            seen_state_update: false,
            env,
        })
    }
}

enum Pending {
    PeerByName(PeerByName, ReplySender<Option<Node>>),
    AcceptedRoute(PeerByAcceptedRoute, ReplySender<Vec<Node>>),
    TailnetIp(PeerByTailnetIp, ReplySender<Option<Node>>),
}

// For messages with arguments, a struct is generated with the args as fields. They aren't
// documented, and we can't apply attributes directly to the fields. Hence, wrap in a module where
// docs are turned off everywhere.
#[allow(missing_docs)]
mod msg_impl {
    use std::net::IpAddr;

    use kameo::prelude::DelegatedReply;

    use super::*;

    #[kameo::messages]
    impl PeerTracker {
        /// Lookup a peer by name.
        ///
        /// Waits until we've received at least one peer update from control.
        #[message(ctx)]
        pub async fn peer_by_name(
            &mut self,
            ctx: &mut Context<Self, DelegatedReply<Option<Node>>>,
            name: String,
        ) -> DelegatedReply<Option<Node>> {
            let (deleg, sender) = ctx.reply_sender();
            let Some(sender) = sender else { return deleg };

            if !self.seen_state_update {
                tracing::debug!(query = name, "no peer state seen yet, queueing request");

                self.pending_requests
                    .push(Pending::PeerByName(PeerByName { name }, sender));

                return deleg;
            }

            sender.send(self.peer_by_name_opt(&name));

            deleg
        }

        /// Lookup all peers that accept packets addressed to the given IP.
        ///
        /// This includes the peer's tailnet address and any subnet routes it provides. Only
        /// the peers with the most specific subnet route match that covers `ip` will be
        /// returned.
        ///
        /// E.g., suppose:
        ///
        /// - We're querying for `10.1.2.3`
        /// - `PeerA` and `PeerB` have accepted routes for `10.1.2.0/24`
        /// - `PeerC` has an accepted route for `10.1.0.0/16`
        ///
        /// Only `PeerA` and `PeerB` will be returned, since they have the most specific
        /// prefix match.
        #[message(ctx)]
        pub fn peer_by_accepted_route(
            &mut self,
            ctx: &mut Context<Self, DelegatedReply<Vec<Node>>>,
            ip: IpAddr,
        ) -> DelegatedReply<Vec<Node>> {
            let (deleg, sender) = ctx.reply_sender();
            let Some(sender) = sender else { return deleg };

            if !self.seen_state_update {
                tracing::debug!(query = %ip, "no peer state seen yet, queueing request");

                self.pending_requests
                    .push(Pending::AcceptedRoute(PeerByAcceptedRoute { ip }, sender));

                return deleg;
            }

            sender.send(self.get_route(ip.into()));

            deleg
        }

        /// Lookup the peer that has the given tailnet IP address.
        #[message(ctx)]
        pub fn peer_by_tailnet_ip(
            &mut self,
            ctx: &mut Context<Self, DelegatedReply<Option<Node>>>,
            ip: IpAddr,
        ) -> DelegatedReply<Option<Node>> {
            let (deleg, sender) = ctx.reply_sender();
            let Some(sender) = sender else { return deleg };

            if !self.seen_state_update {
                tracing::debug!(query = %ip, "no peer state seen yet, queueing request");

                self.pending_requests
                    .push(Pending::TailnetIp(PeerByTailnetIp { ip }, sender));

                return deleg;
            }

            sender.send(self.peer_by_tailnet_ip_opt(ip));

            deleg
        }
    }
}

pub use msg_impl::*;

#[derive(Debug, Clone, Default)]
pub(crate) struct PeerState {
    pub deletions: HashSet<PeerId>,
    pub upserts: HashSet<PeerId>,
}

impl Message<Arc<ts_control::StateUpdate>> for PeerTracker {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: Arc<ts_control::StateUpdate>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let Some(peer_update) = &msg.peer_update else {
            return;
        };

        let mut upserts = HashSet::default();
        let mut deletions = HashSet::default();

        {
            let mut txn = self.env.kv_store().begin_transaction(KV_OWNER);

            match peer_update {
                ts_control::PeerUpdate::Full(new_nodes) => {
                    tracing::trace!("full peer update");

                    let new_ids = new_nodes
                        .iter()
                        .map(|x| &x.stable_id)
                        .collect::<HashSet<_>>();

                    txn.Peers.retain(|id, peer| {
                        let retain = new_ids.contains(&peer.stable_id);

                        if !retain {
                            deletions.insert(*id);
                        }

                        retain
                    });

                    for node in new_nodes {
                        let peer_id = upsert_peer(&mut txn, node);
                        upserts.insert(peer_id);
                    }
                }

                ts_control::PeerUpdate::Delta {
                    patch,
                    remove,
                    upsert,
                } => {
                    tracing::trace!("delta peer update");

                    for peer in remove {
                        let Some(id) = txn.Peers.indexes().control_id.with(peer, |id, _node| {
                            deletions.insert(*id);
                            *id
                        }) else {
                            tracing::error!(control_node_id = peer, "removed peer was unknown");
                            continue;
                        };

                        // Note(nrc): if we could mutate via an index, then this would be easier
                        txn.Peers.remove(&id);
                    }

                    for peer in upsert {
                        let id = upsert_peer(&mut txn, peer);

                        upserts.insert(id);
                    }

                    for update in patch {
                        let Some(id) =
                            txn.Peers
                                .indexes()
                                .control_id
                                .with(&update.id, |id, _node| {
                                    upserts.insert(*id);
                                    *id
                                })
                        else {
                            tracing::warn!(?update, "no peer for update");
                            continue;
                        };

                        // Note(nrc): if we could mutate via an index, then this would be easier
                        txn.Peers.with_mut(&id, |node| node.apply_update(update));
                    }
                }
            }

            let peer_count = txn.Peers.len();

            match txn.commit() {
                Ok(_) => {
                    tracing::debug!(
                        n_upsert = upserts.len(),
                        n_delete = deletions.len(),
                        peer_count,
                        "new peer state"
                    );
                }
                Err(e @ ts_kv_store::Error::NonUniqueIndexKey(_)) => {
                    tracing::error!(error = %e, "discarding peer update");
                    return;
                }
                Err(ts_kv_store::Error::TransactionFailed) => {
                    panic!("Committing transaction failed");
                }
            }
        }

        self.service_pending_requests();

        if let Err(e) = self
            .env
            .publish(Arc::new(PeerState { upserts, deletions }))
            .await
        {
            tracing::error!(error = %e, "publishing peer state update");
        }
    }
}

// Note(nrc): should this be internal to the store?
fn next_peer_id() -> PeerId {
    static NEXT_PEER_ID: AtomicU32 = AtomicU32::new(0);

    PeerId(NEXT_PEER_ID.fetch_add(1, Ordering::Relaxed))
}

fn upsert_peer(txn: &mut kv::Transaction, peer: &Node) -> PeerId {
    let Some(id) = txn
        .Peers
        .indexes()
        .stable_id
        .with(&peer.stable_id, |id, _| *id)
    else {
        let id = next_peer_id();
        txn.Peers.insert(id, peer.clone());
        return id;
    };

    // Note(nrc): if we could mutate via an index, then this would be easier
    txn.Peers
        .with_mut(&id, |node| *node = peer.clone())
        .unwrap();
    id
}

impl PeerTracker {
    fn service_pending_requests(&mut self) {
        if self.seen_state_update {
            return;
        }

        self.seen_state_update = true;

        if !self.pending_requests.is_empty() {
            tracing::debug!(
                n_pending = self.pending_requests.len(),
                "state update received, servicing pending requests"
            );
        }

        for req in core::mem::take(&mut self.pending_requests) {
            match req {
                Pending::PeerByName(PeerByName { name }, reply) => {
                    reply.send(self.peer_by_name_opt(&name));
                }
                Pending::TailnetIp(PeerByTailnetIp { ip }, reply) => {
                    reply.send(self.peer_by_tailnet_ip_opt(ip));
                }
                Pending::AcceptedRoute(PeerByAcceptedRoute { ip }, reply) => {
                    reply.send(self.get_route(ip.into()));
                }
            }
        }
    }
}
