use ts_control::{DerpRegion, Node, StableNodeId};
use ts_derp::RegionId;
use ts_keys::{DiscoPublicKey, NodePublicKey};
pub use ts_kv_store::Result;
use ts_transport::PeerId;

use crate::{control_runner::ControlRunner, peer_tracker::PeerTracker};

pub trait ResultExt {
    type T;

    fn unwrap_poison(self);

    /// Convert this [`Result`] into an [`Option`] by converting [`ts_kv_store::Error::NotPresent`]
    /// into `None`. Any other error results in a panic.
    fn unwrap_ok(self) -> Option<Self::T>;
}

impl<T> ResultExt for Result<T> {
    type T = T;

    fn unwrap_ok(self) -> Option<Self::T> {
        match self {
            Ok(t) => Some(t),
            Err(ts_kv_store::Error::NotPresent) => None,
            Err(e) => panic!("{e}"),
        }
    }

    fn unwrap_poison(self) {
        if let Err(e @ ts_kv_store::Error::NonUniqueIndexKey(_)) = self {
            panic!("{e}");
        }
    }
}

ts_kv_store::store! {
    kvs: {
        // bart table index augmentations to the Peer table
        PeerIpIndex(ts_bart::Table<PeerId> as Arc; PeerTracker::KV_OWNER; notify(Clone)),
        PeerRouteIndex(ts_bart::Table<smallvec::SmallVec<[PeerId; 2]>> as Arc; PeerTracker::KV_OWNER; notify(Clone)),
    }
    tables: {
        Peers(
            PeerId => Node;
            PeerTracker::KV_OWNER;
            index(node_key: NodePublicKey; assert_unique);
            index(stable_id: StableNodeId; assert_unique);
            index(control_id: ts_control::NodeId = |node: &Node| Some(node.id); assert_unique);
            index(hostname: String);
            index(fqdn: String = |node: &Node| node.fqdn_opt(false); assert_unique);
            index(disco_key: DiscoPublicKey = |node: &Node| node.disco_key);
        ),

        // Control
        DerpMap(
            RegionId => DerpRegion;
            ControlRunner::KV_OWNER;
        ),
        DerpLatency(
            RegionId => f64;
            ControlRunner::KV_OWNER;
        ),
    }
}
