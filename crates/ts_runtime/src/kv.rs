use std::sync::Arc;

use ipnet::IpNet;
use ts_control::{DerpRegion, Node, StableNodeId};
use ts_derp::RegionId;
use ts_keys::{DiscoPublicKey, NodePublicKey};
use ts_kv_store::{
    TxnId,
    schema::index::{CustomIndex, CustomMultiIndex},
};
use ts_transport::PeerId;

use crate::{control_runner, peer_tracker};

#[derive(Default)]
struct BartIpIndex(ts_bart::Table<PeerId>);

impl CustomIndex<IpNet, PeerId> for BartIpIndex {
    type Iter<'a> = todo!();

    fn get<Q>(&self, key: &Q, txn_id: TxnId) -> Option<&PeerId>
    where
        IpNet: std::borrow::Borrow<Q>,
        Q: ?Sized + std::hash::Hash + Eq,
    {
        todo!()
    }

    fn iter(&self, txn_id: TxnId) -> Self::Iter<'_> {
        todo!()
    }

    fn insert(&mut self, key: IpNet, base_key: PeerId, txn_id: TxnId) {
        todo!()
    }

    fn remove(&mut self, key: &IpNet, txn_id: TxnId) {
        todo!()
    }

    fn clear(&mut self, txn_id: TxnId) {
        todo!()
    }

    fn check_consistent(&self, txn_id: TxnId) -> ts_kv_store::Result<()> {
        todo!()
    }

    fn commit(&mut self, txn_id: TxnId) {
        todo!()
    }

    fn rollback(&mut self, txn_id: TxnId) -> bool {
        todo!()
    }

    fn rebuild<'a>(&mut self, data: impl Iterator<Item = (IpNet, &'a PeerId)>)
    where
        PeerId: 'a,
    {
        todo!()
    }
}

#[derive(Default)]
struct BartRouteIndex(ts_bart::Table<smallvec::SmallVec<[PeerId; 2]>>);

impl CustomMultiIndex<IpNet, PeerId> for BartRouteIndex {
    type BaseKeys<'a> = todo!();

    type Iter<'a> = todo!();

    fn get<Q>(&self, key: &Q, txn_id: TxnId) -> Option<Self::BaseKeys<'_>>
    where
        IpNet: std::borrow::Borrow<Q>,
        Q: ?Sized + std::hash::Hash + Eq,
    {
        todo!()
    }

    fn iter(&self, txn_id: TxnId) -> Self::Iter<'_> {
        todo!()
    }

    fn insert(&mut self, key: IpNet, base_key: PeerId, txn_id: TxnId) {
        todo!()
    }

    fn remove<R>(&mut self, key: &IpNet, base_key: &R, txn_id: TxnId)
    where
        PeerId: std::borrow::Borrow<R>,
        R: ?Sized + Eq,
    {
        todo!()
    }

    fn clear(&mut self, txn_id: TxnId) {
        todo!()
    }

    fn commit(&mut self, txn_id: TxnId) {
        todo!()
    }

    fn rollback(&mut self, txn_id: TxnId) -> bool {
        todo!()
    }

    fn rebuild<'a>(&mut self, data: impl Iterator<Item = (IpNet, &'a PeerId)>)
    where
        PeerId: 'a,
    {
        todo!()
    }
}

ts_kv_store::store! {
    kvs: {
        // bart table index augmentations to the Peer table
        PeerIpIndex(Arc<ts_bart::Table<PeerId>>; peer_tracker::KV_OWNER; notify(Clone)),
        PeerRouteIndex(Arc<ts_bart::Table<smallvec::SmallVec<[PeerId; 2]>>>; peer_tracker::KV_OWNER; notify(Clone)),
    }
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
