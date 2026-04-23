//! Peer delta update tracking.

use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
};

use ipnet::IpNet;
use kameo::{
    actor::ActorRef,
    message::{Context, Message},
    reply::ReplySender,
};
use ts_control::{Node, NodeId};
use ts_keys::NodePublicKey;

use crate::{Error, env::Env};

/// Actor that tracks peer delta updates and emits new states.
pub struct PeerTracker {
    peers: HashMap<NodePublicKey, Node>,
    id_to_nodekey: HashMap<NodeId, NodePublicKey>,
    seen_state_update: bool,
    pending_requests: Vec<Pending>,
    env: Env,
}

// TODO(npry): accelerate with indexed data structures, linear search won't be
// acceptable on large tailnets.
impl PeerTracker {
    fn peer_by_name_opt(&self, name: &str) -> Option<&Node> {
        self.peers.values().find(|&peer| peer.matches_name(name))
    }

    fn peer_by_tailnet_ip_opt(&self, ip: IpAddr) -> Option<&Node> {
        self.peers.values().find(|&peer| {
            peer.tailnet_address.ipv4.addr() == ip || peer.tailnet_address.ipv6.addr() == ip
        })
    }
}

impl kameo::Actor for PeerTracker {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        env.subscribe::<Arc<ts_control::StateUpdate>>(&slf).await?;

        Ok(Self {
            peers: Default::default(),
            id_to_nodekey: Default::default(),
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

            sender.send(best_route_match(ip, self.peers.values()));

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

#[derive(Debug, Clone)]
pub(crate) struct PeerState {
    #[allow(unused)]
    pub deletions: HashSet<NodePublicKey>,
    #[allow(unused)]
    pub upserts: HashSet<NodePublicKey>,
    pub peers: Arc<HashMap<NodePublicKey, Node>>,
}

// TODO: rpds

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

        match peer_update {
            ts_control::PeerUpdate::Full(nodes) => {
                tracing::trace!("full peer update");

                deletions = self.peers.keys().copied().collect();

                self.peers.clear();
                self.id_to_nodekey.clear();

                for node in nodes {
                    upserts.insert(node.node_key);
                    deletions.remove(&node.node_key);

                    self.id_to_nodekey.insert(node.id, node.node_key);
                    self.peers.insert(node.node_key, node.clone());
                }
            }

            ts_control::PeerUpdate::Delta { remove, upsert } => {
                tracing::trace!("delta peer update");

                for peer in upsert {
                    self.id_to_nodekey.insert(peer.id, peer.node_key);
                    self.peers.insert(peer.node_key, peer.clone());

                    upserts.insert(peer.node_key);
                }

                for peer in remove {
                    let node_key = self.id_to_nodekey.remove(peer);

                    if let Some(node_key) = node_key {
                        self.peers.remove(&node_key);
                        deletions.insert(node_key);
                    }
                }
            }
        }

        tracing::debug!(
            n_upsert = upserts.len(),
            n_delete = deletions.len(),
            peer_count = self.peers.len(),
            "new peer state"
        );

        if !self.seen_state_update {
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
                        reply.send(best_route_match(ip, self.peers.values()));
                    }
                }
            }
        }

        if let Err(e) = self
            .env
            .publish(PeerState {
                upserts,
                deletions,
                peers: Arc::new(self.peers.clone()),
            })
            .await
        {
            tracing::error!(error = %e, "publishing peer state update");
        }
    }
}

/// Get the most-narrow set of peers that have routes for the given IP.
fn best_route_match<'n, N>(query_ip: IpAddr, it: impl IntoIterator<Item = N>) -> Vec<Node>
where
    N: Borrow<Node> + 'n,
{
    // TODO(npry): accelerate with an indexed data structure, linear search won't be
    // acceptable on large tailnets.

    let (_, matching_peers) = it.into_iter().fold(
        (None, vec![]),
        |(mut best_match, mut matching_peers), peer: N| {
            let peer = peer.borrow();
            let mut peer_best = None;

            for &candidate in &peer.accepted_routes {
                // Normalize all prefixes to truncated form (mask off the host bits).
                let candidate = candidate.trunc();

                if !candidate.contains(&query_ip) {
                    continue;
                }

                if peer_best
                    .as_ref()
                    .is_none_or(|existing: &IpNet| existing.contains(&candidate))
                {
                    peer_best = Some(candidate);
                }
            }

            match (best_match.as_ref(), peer_best) {
                // This peer doesn't match, skip
                (_, None) => return (best_match, matching_peers),

                // No previous match, set unconditionally
                (None, _) => best_match = peer_best,

                // Previous match (same prefix), don't update
                (Some(x), Some(y)) if x == &y => {}

                // New best match, clear old state
                (Some(existing), Some(candidate)) if existing.contains(&candidate) => {
                    matching_peers.clear();
                    best_match = peer_best;
                }

                // This peer doesn't have as good a match
                _ => return (best_match, matching_peers),
            }

            matching_peers.push(peer.clone());

            (best_match, matching_peers)
        },
    );

    matching_peers
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use ipnet::Ipv4Net;
    use ts_control::{StableNodeId, TailnetAddress};

    use super::*;

    fn dummy_node(routes: impl IntoIterator<Item = IpNet>) -> Node {
        Node {
            accepted_routes: routes.into_iter().collect(),

            node_key: Default::default(),
            id: 0,
            stable_id: StableNodeId("".to_owned()),
            disco_key: Default::default(),
            machine_key: None,
            tailnet: None,
            hostname: "".to_owned(),
            tailnet_address: TailnetAddress {
                ipv4: Default::default(),
                ipv6: Default::default(),
            },
            underlay_addresses: vec![],
            node_key_expiry: None,
            derp_region: None,
            tags: vec![],
        }
    }

    fn ipv4net(ip: impl Into<Ipv4Addr>, pfx_len: usize) -> IpNet {
        Ipv4Net::new(ip.into(), pfx_len as _).unwrap().into()
    }

    #[test]
    fn route_match() {
        // no peers, no match
        let m = best_route_match::<Node>([1, 2, 3, 4].into(), []);
        assert!(m.is_empty());

        // peer with no routes, no match
        let m = best_route_match::<Node>([1, 2, 3, 4].into(), [dummy_node([])]);
        assert!(m.is_empty());

        // single peer, single match -- typical case
        let m = best_route_match::<Node>(
            [1, 2, 3, 4].into(),
            [dummy_node([ipv4net([1, 2, 3, 4], 32)])],
        );
        assert_eq!(m.len(), 1);

        // two matches both succeed
        let m = best_route_match::<Node>(
            [1, 2, 3, 4].into(),
            [
                dummy_node([ipv4net([1, 2, 3, 4], 32)]),
                dummy_node([ipv4net([1, 2, 3, 4], 32)]),
            ],
        );
        assert_eq!(m.len(), 2);

        // more-specific match wins
        let m = best_route_match::<Node>(
            [1, 2, 3, 4].into(),
            [
                dummy_node([ipv4net([1, 2, 3, 4], 31)]),
                dummy_node([ipv4net([1, 2, 3, 4], 32)]),
            ],
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].accepted_routes[0].prefix_len(), 32);

        // denormalized prefix
        let m = best_route_match::<Node>(
            [1, 2, 3, 4].into(),
            [
                dummy_node([ipv4net([1, 2, 3, 0], 24)]),
                dummy_node([ipv4net([1, 2, 3, 8], 24)]),
            ],
        );
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].accepted_routes[0].prefix_len(), 24);

        // overlapping routes
        let m = best_route_match::<Node>(
            [1, 2, 3, 4].into(),
            [
                dummy_node([ipv4net([1, 2, 3, 0], 24), ipv4net([1, 2, 3, 123], 24)]),
                dummy_node([ipv4net([1, 2, 3, 8], 24)]),
            ],
        );
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].accepted_routes[0].prefix_len(), 24);
    }
}
