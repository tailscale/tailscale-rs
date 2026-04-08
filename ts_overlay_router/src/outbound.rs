//! Outbound overlay routing, for originating from the local device.

use std::collections::HashMap;

use itertools::Itertools;
use ts_bart::{RoutingTable, Table};
use ts_keys::NodePublicKey;
use ts_packet::PacketMut;
use ts_transport::OverlayTransportId;

/// An outbound routing action.
#[derive(Debug, Clone)]
pub enum RouteAction {
    /// Drop the packet.
    ///
    /// This is semantically equivalent to having no route, and can be used
    /// to notch out a set of addresses from a larger route.
    Drop,

    /// Send to a wireguard peer.
    Wireguard(NodePublicKey),

    /// Loop the packet back to a local overlay transport.
    ///
    /// Used for things like DNS serving.
    Loopback(OverlayTransportId),
}

/// Routes packets that originate from the local device.
#[derive(Default)]
pub struct Router {
    table: Table<RouteAction>,
}

/// The result of routing a batch of packets.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Result {
    /// Packets to send through wireguard.
    pub to_wireguard: HashMap<NodePublicKey, Vec<PacketMut>>,
    /// Packets to return to a local transport.
    pub loopback: HashMap<OverlayTransportId, Vec<PacketMut>>,
}

impl Router {
    /// Assigns a batch of packets to their next hop.
    ///
    /// Packets that don't match any routes are dropped.
    pub fn route(&self, packets: impl IntoIterator<Item = PacketMut>) -> Result {
        let mut ret = Result::default();
        let by_dest = packets
            .into_iter()
            .filter_map(|packet| Some((packet.get_dst_addr()?, packet)))
            .into_group_map();

        for (addr, packets) in by_dest {
            let _span =
                tracing::trace_span!("route_by_addr", %addr, n_packets = packets.len()).entered();

            match self.table.lookup(addr) {
                Some(RouteAction::Wireguard(peer)) => {
                    tracing::trace!(%peer, "wireguard");
                    ret.to_wireguard.entry(*peer).or_default().extend(packets);
                }
                Some(RouteAction::Loopback(id)) => {
                    tracing::trace!(overlay_id = ?id, "loopback");
                    ret.loopback.entry(*id).or_default().extend(packets);
                }
                Some(RouteAction::Drop) => {
                    tracing::trace!("explicit drop");
                }
                None => {
                    tracing::trace!("no route");
                }
            }
        }

        ret
    }

    /// Replaces the router's current routes with the provided ones.
    ///
    /// Returns the previous set of routes.
    pub fn swap(&mut self, routes: Table<RouteAction>) -> Table<RouteAction> {
        std::mem::replace(&mut self.table, routes)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    /// Build a minimal IPv4 packet with the given destination.
    fn v4_packet(dst: Ipv4Addr, payload: &[u8]) -> PacketMut {
        let mut packet = PacketMut::new(20);
        packet[0] = 0x45;
        packet[16..20].copy_from_slice(dst.octets().as_ref());
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn test_outbound_overlay() {
        let peer_a = NodePublicKey::from([1u8; 32]);
        let peer_b = NodePublicKey::from([2u8; 32]);
        let magicdns = 42.into();

        let mut routes = Table::default();
        routes.insert(
            "1.2.3.4/32".parse().unwrap(),
            RouteAction::Wireguard(peer_a),
        );
        routes.insert(
            "2.3.4.0/24".parse().unwrap(),
            RouteAction::Wireguard(peer_b),
        );
        routes.insert(
            "100.100.100.100/32".parse().unwrap(),
            RouteAction::Loopback(magicdns),
        );

        let mut router = Router::default();
        let prev = router.swap(routes);
        assert_eq!(prev.size4(), 0);
        assert_eq!(prev.size6(), 0);

        let pkt_a = v4_packet("1.2.3.4".parse().unwrap(), b"for peer A");
        let pkt_b = v4_packet("2.3.4.15".parse().unwrap(), b"for peer B");
        let pkt_magicdns = v4_packet("100.100.100.100".parse().unwrap(), b"for magicdns");
        let pkt_drop = v4_packet("8.8.8.8".parse().unwrap(), b"dropped");
        let packets = vec![pkt_a.clone(), pkt_b.clone(), pkt_magicdns.clone(), pkt_drop];
        let got = router.route(packets);
        let want = Result {
            to_wireguard: HashMap::from([(peer_a, vec![pkt_a]), (peer_b, vec![pkt_b])]),
            loopback: HashMap::from([(magicdns, vec![pkt_magicdns])]),
        };
        assert_eq!(got, want);
    }
}
