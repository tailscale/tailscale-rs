use core::{borrow::Borrow, hash::Hash, slice};

use ipnet::IpNet;
use smallvec::{SmallVec, smallvec};
use ts_bart::{RouteModification, RoutingTable, RoutingTableExt};
use ts_control::{DerpRegion, Node, StableNodeId};
use ts_derp::RegionId;
use ts_keys::{DiscoPublicKey, NodePublicKey};
use ts_kv_store::{
    TxnId,
    schema::index::{IndexMaintenance, MultiIndexRead, UniqueIndexRead},
};
use ts_transport::PeerId;

use crate::{control_runner, peer_tracker};

ts_kv_store::store! {
    tables: {
        Peers(
            PeerId => Node;
            peer_tracker::KV_OWNER;
            index(node_key: NodePublicKey; assert);
            index(stable_id: StableNodeId; assert);
            index(control_id: ts_control::NodeId = |node: &Node| Some(node.id); replace);
            index(hostname: String; replace);
            index(fqdn: String = |node: &Node| node.fqdn_opt(false); assert);
            index(disco_key: DiscoPublicKey = |node: &Node| node.disco_key);
            index(
                tailnet_ip: IpNet = |node: &Node| [node.tailnet_address.ipv4.into(), node.tailnet_address.ipv6.into()];
                custom(BartIpIndex)
            );
            index(route: IpNet = |node: &Node| node.accepted_routes.clone(); custom_multi(BartRouteIndex));
        ),

        // Control
        DerpMap(
            RegionId => DerpRegion;
            control_runner::KV_OWNER;
        ),
        DerpLatency(
            RegionId => f64;
            control_runner::KV_OWNER;
        ),
    }
}

type PeerIds = SmallVec<[PeerId; 2]>;

#[derive(Default)]
pub struct BartIpIndex(pub ts_bart::Table<PeerId>);

impl IndexMaintenance<IpNet, PeerId> for BartIpIndex {
    fn insert(&mut self, key: IpNet, base_key: PeerId, _txn_id: TxnId) {
        self.0.insert(key, base_key);
    }

    fn remove<R>(&mut self, key: &IpNet, base_key: &R, _txn_id: TxnId)
    where
        PeerId: Borrow<R>,
        R: ?Sized + Eq,
    {
        self.0.modify(*key, |id| match id {
            Some(id) if (*id).borrow() == base_key => RouteModification::Remove,
            _ => RouteModification::Noop,
        });
    }

    fn clear(&mut self, _txn_id: TxnId) {
        self.0.clear();
    }

    fn commit(&mut self, _txn_id: TxnId) {}
}

impl UniqueIndexRead<IpNet, PeerId> for BartIpIndex {
    fn get<Q>(&self, key: &Q, _txn_id: TxnId) -> Option<&PeerId>
    where
        IpNet: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = IpNet>,
    {
        self.0.lookup_prefix_exact(key.to_owned())
    }
}

#[derive(Default)]
pub struct BartRouteIndex(pub ts_bart::Table<PeerIds>);

impl IndexMaintenance<IpNet, PeerId> for BartRouteIndex {
    fn insert(&mut self, key: IpNet, base_key: PeerId, _txn_id: TxnId) {
        self.0.modify(key, |ids| match ids {
            Some(ids) => {
                if !ids.contains(&base_key) {
                    ids.push(base_key);
                }
                RouteModification::Noop
            }
            None => RouteModification::Insert(smallvec![base_key]),
        });
    }

    fn remove<R>(&mut self, key: &IpNet, base_key: &R, _txn_id: TxnId)
    where
        PeerId: Borrow<R>,
        R: ?Sized + Eq,
    {
        self.0.modify(*key, |ids| match ids {
            Some(ids) => {
                ids.retain(|id| Borrow::<R>::borrow(id) != base_key);
                if ids.is_empty() {
                    RouteModification::Remove
                } else {
                    RouteModification::Noop
                }
            }
            None => RouteModification::Noop,
        });
    }

    fn clear(&mut self, _txn_id: TxnId) {
        self.0.clear();
    }

    fn commit(&mut self, _txn_id: TxnId) {}
}

impl MultiIndexRead<IpNet, PeerId> for BartRouteIndex {
    type BaseKeys<'a> = slice::Iter<'a, PeerId>;

    fn get<Q>(&self, key: &Q, _txn_id: TxnId) -> Option<Self::BaseKeys<'_>>
    where
        IpNet: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = IpNet>,
    {
        self.0
            .lookup_prefix_exact(key.to_owned())
            .map(|ids| ids.iter())
    }
}
