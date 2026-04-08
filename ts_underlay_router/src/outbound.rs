//! Outbound underlay routing, for originating from the local device.

use std::collections::HashMap;

use ts_keys::NodePublicKey;
use ts_packet::PacketMut;
use ts_transport::UnderlayTransportId;

/// Routes packets that originate from the local device.
#[derive(Default)]
pub struct Router {
    /// The transport to use for sending to each wireguard peer.
    pub table: HashMap<NodePublicKey, UnderlayTransportId>,
}

/// The outcome of routing packets.
pub type Result = HashMap<(UnderlayTransportId, NodePublicKey), Vec<PacketMut>>;

impl Router {
    /// Assigns a batch of packets to their next hop.
    ///
    /// Packets that don't match any routes are dropped.
    pub fn route(
        &self,
        batches: impl IntoIterator<Item = (NodePublicKey, Vec<PacketMut>)>,
    ) -> Result {
        let mut ret = Result::default();

        for (peer_id, packets) in batches {
            if let Some(transport) = self.table.get(&peer_id) {
                ret.entry((*transport, peer_id))
                    .or_default()
                    .extend(packets);
            }
        }

        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outbound_underlay() {
        let peer_a = NodePublicKey::from([1u8; 32]);
        let peer_b = NodePublicKey::from([2u8; 32]);
        let peer_c = NodePublicKey::from([3u8; 32]);
        let peer_d = NodePublicKey::from([4u8; 32]);
        let peer_e = NodePublicKey::from([5u8; 32]);
        let transport_a = 5.into();
        let transport_b = 6.into();
        let transport_c = 7.into();

        let mut router = Router::default();
        router.table.insert(peer_a, transport_b);
        router.table.insert(peer_b, transport_a);
        router.table.insert(peer_c, transport_b);
        router.table.insert(peer_e, transport_c);

        let mut got = router.route([
            (peer_a, vec![b"foo".into(), b"bar".into()]),
            (peer_b, vec![b"qux".into(), b"xyzzy".into()]),
            (peer_c, vec![b"frobozz".into(), b"zork".into()]),
            (peer_d, vec![b"frotz".into(), b"get lamp".into()]),
        ]);

        let mut want = Result::from([
            ((transport_b, peer_a), vec![b"foo".into(), b"bar".into()]),
            ((transport_a, peer_b), vec![b"qux".into(), b"xyzzy".into()]),
            (
                (transport_b, peer_c),
                vec![b"frobozz".into(), b"zork".into()],
            ),
        ]);

        // Hashmap traversal is non-deterministic, so packets from different peers may be reordered.
        // For the test, sort everything.
        for pkts in got.values_mut() {
            pkts.sort();
        }
        for pkts in want.values_mut() {
            pkts.sort();
        }

        let mut got = got.into_iter().collect::<Vec<_>>();
        let mut want = want.into_iter().collect::<Vec<_>>();

        got.sort();
        want.sort();

        assert_eq!(got, want);
    }
}
