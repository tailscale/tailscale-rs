//! Peer delta update tracking.

use std::{collections::HashSet, net::IpAddr, sync::Arc};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use kameo::{
    actor::ActorRef,
    message::{Context, Message},
    reply::ReplySender,
};
use ts_control::Node;
use ts_transport::PeerId;

use crate::{Error, env::Env, kv};

mod peer_db;

pub use peer_db::PeerDb;

/// Actor that tracks peer delta updates and emits new states.
pub struct PeerTracker {
    peer_db: PeerDb,
    seen_state_update: bool,
    pending_requests: Vec<Pending>,
    env: Env,
}

impl PeerTracker {
    /// [`ts_kv_store`] owner name for [`PeerTracker`].
    pub const KV_OWNER: &str = "peer_tracker";

    fn peer_by_name_opt(&self, name: &str) -> Option<&Node> {
        let name = name.trim_end_matches('.');
        self.peer_db.get(&name).map(|(_id, node)| node)
    }

    fn peer_by_tailnet_ip_opt(&self, ip: IpAddr) -> Option<&Node> {
        self.peer_db.get(&ip).map(|(_id, node)| node)
    }
}

impl kameo::Actor for PeerTracker {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;
        env.register(None, &slf).await?;

        Ok(Self {
            peer_db: PeerDb::default(),
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

impl kv::KvStore {
    pub fn peer_by_name(&self, name: &str) -> Option<(PeerId, Node)> {
        let name = name.trim_end_matches('.');

        let txn = self.begin_ro_transaction(PeerTracker::KV_OWNER);

        if let Some(ret) = txn
            .table_by::<kv::index::Peers::fqdn>()
            .get(name)
            .unwrap_ok()
        {
            return Some(ret);
        }

        txn.table_by::<kv::index::Peers::hostname>()
            .get(name)
            .unwrap_ok()
    }

    pub fn peers_by_accepted_route(
        &self,
        ip: ipnet::IpNet,
    ) -> impl Iterator<Item = (PeerId, Node)> {
        let txn = self.begin_ro_transaction(PeerTracker::KV_OWNER);

        txn.with::<kv::PeerRouteIndex, _>(|v| v.lookup_prefix(ip).cloned())
            .flatten()
            .into_iter()
            .flat_map(|x| x.into_iter())
            .filter_map(move |id| {
                let node = txn.table::<kv::Peers>().get(&id)?;
                Some((id, node))
            })
    }

    pub fn peer_by_tailnet_ip(&self, ip: IpAddr) -> Option<(PeerId, Node)> {
        let txn = self.begin_ro_transaction(PeerTracker::KV_OWNER);

        let id = txn.with::<kv::PeerIpIndex, _>(|v| v.lookup(ip).copied())??;
        let node = txn.table::<kv::Peers>().get(&id)?;

        Some((id, node))
    }
}

fn clear_ip_idxs(txn: &mut ts_kv_store::Transaction<kv::TableStorage>, peer: &Node)  {
    let mut ip_idx = txn.get_arc::<kv::PeerIpIndex>().unwrap_or_default();
    let mut rt_idx = txn.get_arc::<kv::PeerRouteIndex>().unwrap_or_default();

    // Decrement refcounts so we can (optimistically) Arc::make_mut below
    txn.remove::<kv::PeerIpIndex>();
    txn.remove::<kv::PeerRouteIndex>();

    let id = txn.table_by::<kv::index::Peers::stable_id>().with(&peer.stable_id, |&id, _| id).unwrap_ok();

    {
        let ip_idx = Arc::make_mut(&mut ip_idx);
        ip_idx.remove(peer.tailnet_address.ipv4.into());
        ip_idx.remove(peer.tailnet_address.ipv6.into());

        let rt_idx = Arc::make_mut(&mut rt_idx);
        for &route in &peer.accepted_routes {
            rt_idx.modify(route, |val| match val {
                Some(val) => {
                    let mut some_matched = false;

                    val.retain(|&mut x| {
                        let ids_match = Some(x) == id;
                        some_matched = some_matched || ids_match;

                        !ids_match
                    });

                    assert!(some_matched);

                    if val.is_empty() {
                        RouteModification::Remove
                    } else {
                        RouteModification::Noop
                    }
                },
                None => RouteModification::Noop,
            });
        }
    }

    txn.insert::<kv::PeerIpIndex>(ip_idx);
    txn.insert::<kv::PeerRouteIndex>(rt_idx);
}

fn upsert_peer(txn: &mut ts_kv_store::Transaction<kv::TableStorage>, peer: &Node) -> PeerId {
    static NEXT_PEER_ID: AtomicU32 = AtomicU32::new(0);

    if let Some(id) = txn.table_by::<kv::index::Peers::stable_id>().with_mut(&peer.stable_id, |id, node| {
        *node = peer.clone();
        *id
    }).unwrap_ok() {
        return id;
    }

    let id = NEXT_PEER_ID.fetch_add(1, Ordering::Relaxed);
    txn.table::<kv::Peers>().insert(PeerId(id), peer.clone());

    PeerId(id)
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

            sender.send(self.peer_by_name_opt(&name).cloned());

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

            sender.send(
                self.peer_db
                    .get_route(ip.into())
                    .map(|(_id, node)| node.clone())
                    .collect(),
            );

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

            sender.send(self.peer_by_tailnet_ip_opt(ip).cloned());

            deleg
        }
    }
}

pub use msg_impl::*;
use ts_bart::{RouteModification, RoutingTable, RoutingTableExt};

use crate::kv::ResultExt;

#[derive(Debug, Clone, Default)]
pub(crate) struct PeerState {
    #[allow(unused)]
    pub deletions: HashSet<PeerId>,
    #[allow(unused)]
    pub upserts: HashSet<PeerId>,
    pub peers: Arc<PeerDb>,
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

        let mut txn = self.env.kv_store.begin_transaction(Self::KV_OWNER);

        match peer_update {
            ts_control::PeerUpdate::Full(new_nodes) => {
                tracing::trace!("full peer update");

                let new_ids = new_nodes
                    .iter()
                    .map(|x| &x.stable_id)
                    .collect::<HashSet<_>>();

                txn.table_by::<kv::index::Peers::stable_id>().clear();

                for node in new_nodes {
                    txn.table::<kv::Peers>().insert(node.)
                    let peer_id = self.peer_db.upsert(node);
                    upserts.insert(peer_id);
                }
            }

            ts_control::PeerUpdate::Delta {
                patch,
                remove,
                upsert,
            } => {
                tracing::trace!("delta peer update");

                let mut table = txn.table_by::<kv::index::Peers::control_id>();

                for peer in remove {
                    table.with(peer, |id, _node| {
                        deletions.insert(id);
                    }).unwrap_poison();

                    table.remove(peer);
                }

                for peer in upsert {
                    let id = upsert_peer(&mut txn, peer);
                    upserts.insert(id);
                }

                for update in patch {
                    table.with_mut(&update.id, |id, node| {
                        node.apply_update(update);
                    }).unwrap_poison();

                    if let Some(id) = self.peer_db.patch(update) {
                        upserts.insert(id);
                    } else {
                        tracing::warn!(?update, "no peer for update");
                    }
                }
            }
        }

        tracing::debug!(
            n_upsert = upserts.len(),
            n_delete = deletions.len(),
            peer_count = self.peer_db.peers().len(),
            "new peer state"
        );

        self.service_pending_requests();

        if let Err(e) = self
            .env
            .publish(Arc::new(PeerState {
                upserts,
                deletions,
                peers: Arc::new(self.peer_db.clone()),
            }))
            .await
        {
            tracing::error!(error = %e, "publishing peer state update");
        }
    }
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
                    reply.send(self.peer_by_name_opt(&name).cloned());
                }
                Pending::TailnetIp(PeerByTailnetIp { ip }, reply) => {
                    reply.send(self.peer_by_tailnet_ip_opt(ip).cloned());
                }
                Pending::AcceptedRoute(PeerByAcceptedRoute { ip }, reply) => {
                    reply.send(
                        self.peer_db
                            .get_route(ip.into())
                            .map(|(_id, node)| node.clone())
                            .collect(),
                    );
                }
            }
        }
    }
}
