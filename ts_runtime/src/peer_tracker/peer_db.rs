use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    hash::Hash,
    net::IpAddr,
};

use ts_bart::{RouteModification, RoutingTable, RoutingTableExt};
use ts_control::{Node, NodeUpdate, StableNodeId};
use ts_keys::{DiscoPublicKey, NodePublicKey};
use ts_transport::PeerId;

mod private {
    use super::*;

    pub trait Sealed {}

    impl Sealed for PeerId {}
    impl Sealed for NodePublicKey {}
    impl Sealed for DiscoPublicKey {}
    impl Sealed for StableNodeId {}
    impl Sealed for ts_control::NodeId {}
    impl Sealed for PeerName {}
    impl Sealed for &str {}
    impl Sealed for IpAddr {}
    impl Sealed for ipnet::IpNet {}
}

/// A [`Node`] field indexed by [`PeerDb`].
pub trait IndexedField: Debug + private::Sealed {
    /// Look up the peer id that has this field.
    fn lookup(&self, db: &PeerDb) -> Option<PeerId>;
}

type Index<T> = HashMap<T, PeerId>;
type PeerName = String;

/// A database that stores a map of peers by [`PeerId`] and multiple indices.
///
/// Assumes that _all indexed fields_ are unique per-node, with a few notable exceptions:
///
/// - Hostname may be duplicated, though the fqdn (including the tailnet component) may not
///   be.
/// - Accepted routes may overlap.
#[derive(Default, Clone)]
pub struct PeerDb {
    peers: HashMap<PeerId, Node>,
    index_state: IndexState,
    next_id: u32,
}

impl Debug for PeerDb {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.peers.fmt(f)
    }
}

#[derive(Default, Clone)]
struct IndexState {
    /// Index on the node's [`NodePublicKey`].
    nk_idx: Index<NodePublicKey>,
    /// Index on the [`DiscoPublicKey`], assuming it's known.
    disco_idx: Index<DiscoPublicKey>,
    /// Index on the peer [`StableNodeId`].
    stableid_idx: Index<StableNodeId>,
    /// Index for the [`ts_control::NodeId`].
    ///
    /// This is a numeric ID assigned by control which could overlap across different
    /// control regions (by contrast to [`StableNodeId`], which should not). We need this
    /// field because control indicates node patches and deletions by this id rather than
    /// the stable id.
    control_idx: Index<ts_control::NodeId>,
    /// Index on the peer name and FQDN.
    name_idx: Index<PeerName>,
    /// Index on the node's tailnet IPv4 and IPv6.
    ip_idx: ts_bart::Table<PeerId>,
    /// Index on the node's accepted routes.
    ///
    /// These may overlap between nodes, hence this stores a vec of matching node ids for
    /// each route.
    route_idx: ts_bart::Table<smallvec::SmallVec<[PeerId; 2]>>,
}

impl PeerDb {
    /// Apply an update to a node in the peer db.
    ///
    /// The [`NodeUpdate::id`] field is used as the primary key to identify the node.
    pub fn patch(&mut self, update: &NodeUpdate) -> Option<PeerId> {
        let id = update.id.lookup(self)?;
        let mut peer = self.peers.remove(&id).unwrap();
        peer.apply_update(update);
        Some(self.upsert(&peer))
    }

    /// Upsert a node into the peer db.
    ///
    /// The [`StableNodeId`] is used as the primary key to identify the node.
    pub fn upsert(&mut self, new: &Node) -> PeerId {
        let id = self
            .index_state
            .stableid_idx
            .get(&new.stable_id)
            .copied()
            .unwrap_or_else(|| {
                let id = self.next_id;
                self.next_id += 1;

                PeerId(id)
            });

        let old = self.peers.get(&id);

        // no update: same node
        if old.is_some_and(|x| x == new) {
            return id;
        }

        maybe_update_idx(new, old, |x| &x.node_key, &mut self.index_state.nk_idx, id);
        maybe_update_idx(
            new,
            old,
            |x| &x.stable_id,
            &mut self.index_state.stableid_idx,
            id,
        );
        maybe_update_idx(new, old, |x| &x.id, &mut self.index_state.control_idx, id);

        maybe_update(
            new,
            old,
            |x| &x.disco_key,
            &mut self.index_state.disco_idx,
            |old, idx| {
                if let Some(key) = &old.disco_key {
                    let old_id = idx.remove(key);
                    assert!(old_id.is_some_and(|old_id| old_id == id));
                }
            },
            |new, idx| {
                if let Some(key) = &new.disco_key {
                    idx.insert(*key, id);
                }
            },
        );

        // Store both `hostname` and fqdn (no trailing dot) in the `name_idx` index. This _does not_
        // preserve uniqueness for `hostname`; as documented on external API such as
        // `tailscale::Device::peer_by_name`, there may be collisions in this field (typically when
        // nodes are shared into the tailnet with the same name as an existing tailnet device).
        //
        // We don't resolve this conflict here and make it the caller's problem to include the fqdn
        // if there is ambiguity; the index just stores the most recently updated node with a given
        // hostname.
        //
        // Also, this index is overloaded to store both the fqdn and the hostname, but this is
        // fine since the fqdn always includes `.`, while the hostname never does, so they're always
        // distinguishable.
        maybe_update(
            new,
            old,
            |x| (&x.hostname, &x.tailnet),
            &mut self.index_state.name_idx,
            |old, idx| {
                if idx.get(&old.hostname).is_some_and(|&x| x == id) {
                    idx.remove(&old.hostname);
                }

                if let Some(fqdn) = old.fqdn_opt(false) {
                    let removed_id = idx.remove(&fqdn);
                    assert!(removed_id.is_some_and(|removed_id| removed_id == id));
                }
            },
            |new, idx| {
                idx.insert(new.hostname.clone(), id);

                if let Some(fqdn) = new.fqdn_opt(false) {
                    idx.insert(fqdn, id);
                }
            },
        );

        maybe_update(
            new,
            old,
            |x| &x.tailnet_address,
            &mut self.index_state.ip_idx,
            |old, idx| {
                let id4 = idx.remove(old.tailnet_address.ipv4.into());
                let id6 = idx.remove(old.tailnet_address.ipv6.into());

                assert!(id4.is_some_and(|old_id| old_id == id));
                assert!(id6.is_some_and(|old_id| old_id == id));
            },
            |new, idx| {
                idx.insert(new.tailnet_address.ipv4.into(), id);
                idx.insert(new.tailnet_address.ipv6.into(), id);
            },
        );

        maybe_update(
            new,
            old,
            |x| &x.accepted_routes,
            &mut self.index_state,
            |old, idx| {
                for &route in &old.accepted_routes {
                    idx.remove_route(route, id);
                }
            },
            |new, idx| {
                for &route in &new.accepted_routes {
                    idx.route_idx.modify(route, |val| {
                        if let Some(val) = val {
                            val.push(id);
                            return RouteModification::Noop;
                        }

                        RouteModification::Insert(smallvec::smallvec![id])
                    });
                }
            },
        );

        self.peers.insert(id, new.clone());

        id
    }

    /// Remove a peer by a given indexed field.
    pub fn remove(&mut self, field: &dyn IndexedField) -> Option<(PeerId, Node)> {
        let id = field.lookup(self)?;

        let node = self.peers.remove(&id)?;
        self.index_state.remove(id, &node);

        Some((id, node))
    }

    /// Get the node with the given field.
    pub fn get(&self, field: &dyn IndexedField) -> Option<(PeerId, &Node)> {
        let id = field.lookup(self)?;
        let peer = self.peers.get(&id)?;

        Some((id, peer))
    }

    /// Get the nodes with the closest matching route.
    pub fn get_route(&self, route: ipnet::IpNet) -> impl Iterator<Item = (PeerId, &Node)> {
        // this doesn't use IndexedField because more than one result can be returned

        self.index_state
            .route_idx
            .lookup_prefix(route)
            .into_iter()
            .flat_map(|x| x.iter())
            .map(|&id| (id, self.peers.get(&id).unwrap()))
    }

    /// Check whether there is a peer with the given field in the db.
    pub fn has(&self, field: &dyn IndexedField) -> Option<PeerId> {
        field.lookup(self)
    }

    /// Get a reference to the peer map.
    pub const fn peers(&self) -> &HashMap<PeerId, Node> {
        &self.peers
    }

    /// Remove the nodes in the db that don't satisfy the predicate function.
    pub fn retain(&mut self, mut predicate: impl FnMut(PeerId, &Node) -> bool) {
        self.peers.retain(|&id, node| {
            let retain = predicate(id, node);

            if !retain {
                self.index_state.remove(id, node);
            }

            retain
        });
    }
}

impl IndexState {
    fn remove(&mut self, id: PeerId, node: &Node) {
        self.nk_idx.remove(&node.node_key);
        self.stableid_idx.remove(&node.stable_id);
        self.control_idx.remove(&node.id);
        self.ip_idx.remove(node.tailnet_address.ipv4.into());
        self.ip_idx.remove(node.tailnet_address.ipv6.into());

        if self.name_idx.get(&node.hostname).is_some_and(|&x| x == id) {
            self.name_idx.remove(&node.hostname);
        }

        if let Some(fqdn) = node.fqdn_opt(false) {
            self.name_idx.remove(&fqdn);
        }

        for route in &node.accepted_routes {
            self.remove_route(*route, id);
        }

        if let Some(disco) = &node.disco_key {
            self.disco_idx.remove(disco);
        }
    }

    /// Remove `route` from the `route_idx`.
    fn remove_route(&mut self, route: ipnet::IpNet, id: PeerId) {
        self.route_idx.modify(route, |val| match val {
            Some(val) => {
                let mut some_matched = false;

                val.retain(|&mut x| {
                    let ids_match = x == id;
                    if ids_match {
                        some_matched = true;
                    }

                    !ids_match
                });

                assert!(some_matched);

                if val.is_empty() {
                    RouteModification::Remove
                } else {
                    RouteModification::Noop
                }
            }
            None => RouteModification::Noop,
        });
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.nk_idx.is_empty()
            && self.stableid_idx.is_empty()
            && self.control_idx.is_empty()
            && self.ip_idx.size() == 0
            && self.name_idx.is_empty()
            && self.route_idx.size() == 0
            && self.disco_idx.is_empty()
    }
}

/// Attempt to update the `idx` with the `new` node.
///
/// The `accessor` selects a set of fields to check (by `PartialEq`) for whether the `new`
/// node has changed compared to the `old` one:
///
/// - If the value returned by `accessor` is the same between `new` and `old`, nothing
///   happens.
/// - If the value has changed and `old` is `Some`, `remove(old, idx)` is called.
/// - If the value has changed, `insert(new, idx)` is called.
fn maybe_update<'n, T, Idx>(
    new: &'n Node,
    old: Option<&'n Node>,
    accessor: impl Fn(&'n Node) -> T,
    idx: &mut Idx,
    mut remove: impl FnMut(&'n Node, &mut Idx),
    mut insert: impl FnMut(&'n Node, &mut Idx),
) where
    T: PartialEq + 'n,
{
    match old {
        Some(old) if accessor(old) == accessor(new) => {
            return;
        }
        Some(x) => {
            remove(x, idx);
        }
        None => {}
    }

    insert(new, idx)
}

/// Specialization of [`maybe_update`] to work on [`Index`].
fn maybe_update_idx<T>(
    new: &Node,
    old: Option<&Node>,
    accessor: impl Fn(&Node) -> &T,
    idx: &mut Index<T>,
    new_id: PeerId,
) where
    T: Eq + Hash + Clone,
{
    maybe_update(
        new,
        old,
        &accessor,
        idx,
        |old, idx| {
            let old_id = idx.remove(accessor(old));
            assert!(old_id.is_some_and(|old_id| old_id == new_id));
        },
        |new, idx| {
            idx.insert(accessor(new).clone(), new_id);
        },
    )
}

impl IndexedField for PeerId {
    fn lookup(&self, db: &PeerDb) -> Option<PeerId> {
        if db.peers.contains_key(self) {
            Some(*self)
        } else {
            None
        }
    }
}

impl IndexedField for NodePublicKey {
    fn lookup(&self, db: &PeerDb) -> Option<PeerId> {
        db.index_state.nk_idx.get(self).copied()
    }
}

impl IndexedField for DiscoPublicKey {
    fn lookup(&self, db: &PeerDb) -> Option<PeerId> {
        db.index_state.disco_idx.get(self).copied()
    }
}

impl IndexedField for StableNodeId {
    fn lookup(&self, db: &PeerDb) -> Option<PeerId> {
        db.index_state.stableid_idx.get(self).copied()
    }
}

impl IndexedField for ts_control::NodeId {
    fn lookup(&self, db: &PeerDb) -> Option<PeerId> {
        db.index_state.control_idx.get(self).copied()
    }
}

impl IndexedField for PeerName {
    fn lookup(&self, db: &PeerDb) -> Option<PeerId> {
        db.index_state.name_idx.get(self).copied()
    }
}

impl IndexedField for &str {
    fn lookup(&self, db: &PeerDb) -> Option<PeerId> {
        db.index_state.name_idx.get(*self).copied()
    }
}

impl IndexedField for IpAddr {
    fn lookup(&self, db: &PeerDb) -> Option<PeerId> {
        db.index_state.ip_idx.lookup(*self).copied()
    }
}

#[cfg(test)]
mod test {
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        num::NonZeroU32,
    };

    use chrono::DateTime;
    use proptest::{
        collection::{hash_set, vec},
        prelude::{Just, any},
        strategy::Strategy,
    };
    use rand::{
        RngExt,
        distr::{Alphanumeric, SampleString},
    };
    use ts_capabilityversion::CapabilityVersion;
    use ts_control::{NodeLastSeen, NodeStatus, TailnetAddress};

    use super::*;

    fn rand_string(rng: &mut dyn rand::Rng, max_len: usize) -> String {
        let len = rng.random_range(1..max_len);
        Alphanumeric.sample_string(rng, len)
    }

    fn rand_route(rng: &mut dyn rand::Rng) -> ipnet::IpNet {
        if rng.random::<bool>() {
            let ip = rand_ipv4(rng);
            ipnet::Ipv4Net::new(ip, rand::random_range(0..=32))
                .unwrap()
                .trunc()
                .into()
        } else {
            let ip = rand_ipv6(rng);
            ipnet::Ipv6Net::new(ip, rand::random_range(0..=128))
                .unwrap()
                .trunc()
                .into()
        }
    }

    fn rand_ipv4(rng: &mut dyn rand::Rng) -> Ipv4Addr {
        Ipv4Addr::from_octets(rng.random::<[u8; 4]>())
    }

    fn rand_ipv6(rng: &mut dyn rand::Rng) -> Ipv6Addr {
        Ipv6Addr::from_segments(rng.random::<[u16; 8]>())
    }

    fn rand_node() -> Node {
        let mut rng = rand::rng();

        Node {
            stable_id: StableNodeId(rand_string(&mut rng, 32)),
            tailnet_address: TailnetAddress {
                ipv4: rand_ipv4(&mut rng).into(),
                ipv6: rand_ipv6(&mut rng).into(),
            },
            node_key: rng.random::<[u8; 32]>().into(),
            disco_key: rng
                .random::<bool>()
                .then_some(rng.random::<[u8; 32]>().into()),
            machine_key: rng
                .random::<bool>()
                .then_some(rng.random::<[u8; 32]>().into()),
            id: rng.random(),
            accepted_routes: (0..rng.random_range(0..32))
                .map(|_| rand_route(&mut rng))
                .collect(),

            hostname: rand_string(&mut rng, 32),
            tailnet: rng.random::<bool>().then_some(rand_string(&mut rng, 32)),
            capability_version: Default::default(),

            status: NodeStatus::Unknown,
            node_key_expiry: None,
            underlay_addresses: vec![],
            tailnet_lock_key_signature: None,
            derp_region: rng
                .random::<bool>()
                .then_some(ts_derp::RegionId(rng.random())),

            tags: (0..rng.random_range(0..8))
                .map(|_| rand_string(&mut rng, 32))
                .collect(),
            node_capabilities: Default::default(),
        }
    }

    fn validate_indices(db: &PeerDb, node: &Node, id: PeerId) {
        let ipv4 = IpAddr::from(node.tailnet_address.ipv4.addr());
        let ipv6 = IpAddr::from(node.tailnet_address.ipv6.addr());
        let fqdn = node.fqdn_opt(false);

        let mut keys: Vec<&dyn IndexedField> =
            vec![&id, &node.node_key, &node.stable_id, &node.id, &ipv4, &ipv6];

        if let Some(disco) = &node.disco_key {
            keys.push(disco);
        }

        if let Some(fqdn) = &fqdn {
            keys.push(fqdn);
        }

        for k in keys {
            let lookup_id = k.lookup(db).unwrap();
            assert_eq!(lookup_id, id, "wrong id for key {k:?}");

            let (lookup_id, lookup_node) = db.get(k).unwrap();
            assert_eq!(lookup_id, id, "wrong id for key {k:?}");
            assert_eq!(lookup_node, node, "wrong node for key {k:?}");
        }

        // We don't know if the hostname collides, but it should resolve to something
        node.hostname.lookup(db).unwrap();

        for &route in &node.accepted_routes {
            // Generically we don't actually know if this node has the most specific match for this
            // route, but there should at least be one match, and all matches should have at least
            // one route that (inclusively) subsets our route.

            let routes = db.get_route(route).collect::<Vec<_>>();
            assert!(!routes.is_empty());

            for (found_id, found_node) in routes {
                if found_id == id {
                    assert_eq!(found_node, node);
                    break;
                }

                let has_subset = found_node
                    .accepted_routes
                    .iter()
                    .any(|found_route| route.contains(found_route));

                assert!(has_subset);
            }
        }
    }

    /// Assert that the node's routes are all present as the most specific routes in the
    /// db.
    fn assert_has_routes_exact(db: &PeerDb, node: &Node, id: PeerId) {
        for &route in &node.accepted_routes {
            let match_exists = db
                .get_route(route)
                .any(|(found_id, found_node)| found_id == id && found_node == node);

            assert!(match_exists);
        }
    }

    #[test]
    fn test_indices() {
        let mut db = PeerDb::default();
        let node = rand_node();
        let id = db.upsert(&node);

        validate_indices(&db, &node, id);
        assert_has_routes_exact(&db, &node, id);
    }

    #[test]
    fn test_names() {
        let mut db = PeerDb::default();

        let node1 = Node {
            hostname: "test".to_string(),
            tailnet: Some("ts.net".to_string()),
            ..rand_node()
        };
        let node2 = Node {
            hostname: "test".to_string(),
            tailnet: Some("ts2.net".to_string()),
            ..rand_node()
        };
        let node3 = Node {
            hostname: "test".to_string(),
            tailnet: None,
            ..rand_node()
        };

        let id1 = db.upsert(&node1);
        let id2 = db.upsert(&node2);
        let id3 = db.upsert(&node3);

        let nodes = [(id1, &node1), (id2, &node2), (id3, &node3)];

        for (id, node) in &nodes {
            validate_indices(&db, node, *id);
        }

        let (id, node) = db.get(&"test").unwrap();
        assert!(nodes.iter().any(|(x, _node)| *x == id));

        for &(x, curnode) in &nodes {
            if x == id {
                assert_eq!(node, curnode);
            } else {
                assert_ne!(node, curnode);
            }
        }

        let (id, node) = db.get(&"test.ts.net").unwrap();
        assert_eq!(id, id1);
        assert_eq!(node, &node1);

        let (id, node) = db.get(&"test.ts2.net").unwrap();
        assert_eq!(id, id2);
        assert_eq!(node, &node2);
    }

    proptest::prop_compose! {
        fn capability_version_low()(
            capver in 3u16..34,
        ) -> CapabilityVersion {
            CapabilityVersion::new(capver).unwrap()
        }
    }

    proptest::prop_compose! {
        fn capability_version_high()(
            capver in 36u16..133,
        ) -> CapabilityVersion {
            CapabilityVersion::new(capver).unwrap()
        }
    }

    fn capability_version() -> impl Strategy<Value = CapabilityVersion> {
        proptest::prop_oneof![capability_version_low(), capability_version_high()]
    }

    proptest::prop_compose! {
        fn ipv4net()(
            addr: Ipv4Addr,
            pfx in 0u8..=32,
        ) -> ipnet::Ipv4Net {
            ipnet::Ipv4Net::new(addr, pfx).unwrap().trunc()
        }
    }

    proptest::prop_compose! {
        fn ipv6net()(
            addr: Ipv6Addr,
            pfx in 0u8..=32,
        ) -> ipnet::Ipv6Net {
            ipnet::Ipv6Net::new(addr, pfx).unwrap().trunc()
        }
    }

    fn ipnet() -> impl Strategy<Value = ipnet::IpNet> {
        proptest::prop_oneof![
            ipv4net().prop_map(ipnet::IpNet::from),
            ipv6net().prop_map(ipnet::IpNet::from)
        ]
    }

    proptest::prop_compose! {
        fn last_seen()(
            control_ns_since_epoch in any::<Option<i64>>(),
            estimated_ns_since_epoch in any::<i64>(),
        ) -> NodeLastSeen {
            NodeLastSeen {
                control: control_ns_since_epoch.map(DateTime::from_timestamp_nanos),
                estimated: DateTime::from_timestamp_nanos(estimated_ns_since_epoch),
            }
        }
    }

    fn status() -> impl Strategy<Value = NodeStatus> {
        proptest::prop_oneof![
            Just(NodeStatus::Unknown),
            Just(NodeStatus::Online),
            last_seen().prop_map(NodeStatus::Offline),
        ]
    }

    proptest::prop_compose! {
        fn domain_segment()(
            seg in "[[:alpha:]][[:alnum:]]*"
        ) -> String {
            seg
        }
    }

    proptest::prop_compose! {
        fn domain(max_count: usize)(
            segs in proptest::collection::vec(domain_segment(), 0..max_count)
        ) -> String {
            segs.join(".")
        }
    }

    proptest::prop_compose! {
        fn node_capabilities(max_values_per_entry: usize)(
            keys in hash_set(".+", 0..32),
            values in vec(vec(".+", 0..32), 0..max_values_per_entry),
        ) -> BTreeMap<String, Vec<String>> {
            BTreeMap::from_iter(keys.into_iter().zip(values.into_iter()))
        }
    }

    type Key = [u8; 32];
    type TailnetLockSignature = [u8; 32];

    proptest::prop_compose! {
        // This is set up this way to ensure uniqueness among all the required-unique keys in a
        // node. The `hash_set`s ensure that all ids AND stable ids AND node keys etc. are unique.
        fn nodes(n: usize)(
            id in hash_set(any::<i64>(), n),
            stable_id in hash_set(".+", n),
            capability_version in vec(capability_version(), n),
            tags in vec(hash_set(".+", 0..32), n),
            node_capabilities in vec(node_capabilities(3), n),
            accepted_routes in vec(hash_set(ipnet(), 0..32), n),
            status in vec(status(), n),
            node_key in hash_set(any::<Key>(), n),
            machine_key in vec(any::<Option<Key>>(), n),
            disco_key in vec(any::<Option<Key>>(), n),
            tailnet_lock_key_signature in vec(any::<Option<TailnetLockSignature>>(), n),
            ipv4 in hash_set(any::<Ipv4Addr>(), n),
            ipv6 in hash_set(any::<Ipv6Addr>(), n),
            name in hash_set(domain_segment(), n),
            tailnet in vec(domain(5), n),
            has_tailnet in vec(any::<bool>(), n),
            derp_region in vec(any::<Option<NonZeroU32>>(), n),
            underlay_addrs in vec(any::<HashSet<SocketAddr>>(), n),
        ) -> Vec<Node> {
            itertools::izip![
                id,
                stable_id,
                capability_version,
                tags,
                node_capabilities,
                accepted_routes,
                status,
                node_key,
                machine_key,
                disco_key,
                tailnet_lock_key_signature,
                ipv4,
                ipv6,
                name,
                tailnet,
                has_tailnet,
                derp_region,
                underlay_addrs,
            ].map(|(
                id,
                stable_id,
                capability_version,
                tags,
                node_capabilities,
                mut accepted_routes,
                status,
                node_key,
                machine_key,
                disco_key,
                tailnet_lock_key_signature,
                ipv4,
                ipv6,
                name,
                tailnet,
                has_tailnet,
                derp_region,
                underlay_addrs,
            )| {
                accepted_routes.insert(ipnet::Ipv4Net::from(ipv4).into());
                accepted_routes.insert(ipnet::Ipv6Net::from(ipv6).into());

                Node {
                    id,
                    stable_id: StableNodeId(stable_id),
                    capability_version,

                    hostname: name,
                    tailnet: has_tailnet.then_some(tailnet),

                    status,
                    node_key: node_key.into(),
                    disco_key: disco_key.map(Into::into),
                    machine_key: machine_key.map(Into::into),
                    tailnet_lock_key_signature: tailnet_lock_key_signature.map(Into::into),

                    node_key_expiry: None,

                    tailnet_address: TailnetAddress {
                        ipv4: ipv4.into(),
                        ipv6: ipv6.into(),
                    },
                    tags: tags.into_iter().collect(),
                    node_capabilities,

                    derp_region: derp_region.map(ts_derp::RegionId),

                    accepted_routes: accepted_routes.into_iter().collect(),
                    underlay_addresses: underlay_addrs.into_iter().collect(),
                }
            })
            .collect()
        }
    }

    proptest::proptest! {
        #[test]
        fn prop_one_node_indices(mut nodes in nodes(1)) {
            let node = nodes.pop().unwrap();

            let mut db = PeerDb::default();
            let id = db.upsert(&node);

            validate_indices(&db, &node, id);
            assert_has_routes_exact(&db, &node, id);
        }

        #[test]
        fn prop_many_nodes_indexed(nodes in nodes(16)) {
            let mut db = PeerDb::default();

            let mut nodes_by_id = HashMap::new();

            for node in &nodes {
                let id = db.upsert(node);
                nodes_by_id.insert(id, node.clone());
            }

            for (id, node) in &nodes_by_id {
                validate_indices(&db, node, *id);
            }
        }

        #[test]
        fn prop_remove(nodes in nodes(16)) {
            let mut db = PeerDb::default();

            let mut ids = vec![];

            for node in &nodes {
                ids.push((db.upsert(node), node));
            }

            for (id, node) in ids {
                let (removed_id, removed_node) = db.remove(&id).unwrap();

                proptest::prop_assert_eq!(removed_id, id);
                proptest::prop_assert_eq!(&removed_node, node);
            }

            proptest::prop_assert!(db.peers.is_empty());
            proptest::prop_assert!(db.index_state.is_empty());
        }
    }
}
