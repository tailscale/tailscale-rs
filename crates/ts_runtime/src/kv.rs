use std::sync::Arc;

use ts_control::{DerpRegion, Node, StableNodeId};
use ts_derp::RegionId;
use ts_keys::{DiscoPublicKey, NodePublicKey};
use ts_transport::PeerId;

use crate::{control_runner, peer_tracker};

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
            control_runner::KV_OWNER;
        ),
        DerpLatency(
            RegionId => f64;
            control_runner::KV_OWNER;
        ),
    }
}
