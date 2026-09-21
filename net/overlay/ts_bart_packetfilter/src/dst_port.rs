use alloc::vec::Vec;
use core::net::IpAddr;

use hashbrown::HashMap;
use ts_bart::{RoutingTable, RoutingTableExt};
use ts_bitset::{BitsetDyn, BitsetStatic};
use ts_dynbitset::DynBitset;
use ts_packetfilter::DstMatch;

use crate::{PortTrie, RuleId};

type DstMatchId = usize;
type DstMatchBitset = DynBitset;

/// Accelerated lookup for [`DstMatch`] packet filter entries, resolving all
/// matching [`RuleId`]s for a given packet's port and ip.
///
/// This is a unique case compared to `src` lookup because a) each rule can have any number
/// of `DstMatch`es, b) we need to match _both_ dst ip and port, and c) those matches are
/// each scoped to a single `DstMatch`.
///
/// Essentially, `ports.lookup(packet.port) & dsts.lookup_all(packet.ip)` gives the set
/// of `DstMatch`es that match for the packet, and we then resolve the rules to which those
/// `DstMatch`es correspond using `dstmatch_id_to_rule_id`. The layer of indirection
/// is needed to support the many-to-one mapping `DstMatch` -> `Rule`.
#[derive(Debug, Clone, Default)]
pub struct DstMatchLookup {
    /// Resolves IPs to all matching dstport rule IDs.
    dsts: ts_bart::Table<DstMatchBitset>,

    /// Resolve ports to all matching dstport rule IDs.
    ports: PortTrie<DstMatchBitset>,

    /// Lookup from [`DstMatch`] to the set of relevant `DstMatchId`s.
    dstmatch_ids: HashMap<DstMatch, DstMatchBitset>,

    /// Mapping from `DstMatchId` to `RuleId`.
    dstmatch_id_to_rule_id: Vec<Option<RuleId>>,

    /// `DstMatchId`s that are currently unused and should be allocated first.
    freelist: DstMatchBitset,
}

impl DstMatchLookup {
    pub fn insert(&mut self, rule: RuleId, dst: DstMatch) {
        let allocated_id = self.lookup_dstmatch_id(rule, &dst);

        let id: DstMatchId = if let Some(allocated_id) = allocated_id {
            // An id is already allocated for this dst and port range
            allocated_id
        } else if let Some(free) = crate::pop_freelist(&mut self.freelist) {
            // There is an id in the freelist: use it.
            _ = self.dstmatch_id_to_rule_id[free].insert(rule);

            self.dstmatch_ids.entry(dst.clone()).or_default().set(free);

            free
        } else {
            // No free ids: allocate a new one.
            let idx = self.dstmatch_id_to_rule_id.len();
            self.dstmatch_id_to_rule_id.push(Some(rule));

            self.dstmatch_ids.entry(dst.clone()).or_default().set(idx);

            idx
        };

        for &pfx in &dst.ips {
            self.dsts.modify(pfx, |val| {
                if let Some(val) = val {
                    val.set(id);
                    ts_bart::RouteModification::Noop
                } else {
                    ts_bart::RouteModification::Insert(DynBitset::empty().with_bit(id))
                }
            });
        }

        self.ports.modify(dst.ports, &mut |bitset| {
            if let Some(bitset) = bitset {
                bitset.set(id);
                ts_bart::RouteModification::Noop
            } else {
                ts_bart::RouteModification::Insert(DynBitset::empty().with_bit(id))
            }
        });

        self.compact();
    }

    pub fn remove(&mut self, rule: RuleId, dst: &DstMatch) {
        let Some(dst_port_id) = self.lookup_dstmatch_id(rule, dst) else {
            return;
        };

        for &pfx in &dst.ips {
            self.dsts.modify(pfx, |x| {
                if let Some(x) = x {
                    x.clear(dst_port_id);

                    if x.is_empty() {
                        return ts_bart::RouteModification::Remove;
                    }
                }

                ts_bart::RouteModification::Noop
            });
        }

        self.ports.modify(dst.ports.clone(), &mut |bitset| {
            let Some(bitset) = bitset else {
                return ts_bart::RouteModification::Noop;
            };

            bitset.clear(dst_port_id);
            if bitset.is_empty() {
                ts_bart::RouteModification::Remove
            } else {
                ts_bart::RouteModification::Noop
            }
        });

        let entry = self.dstmatch_ids.get_mut(dst).unwrap();
        entry.clear(dst_port_id);

        if entry.is_empty() {
            self.dstmatch_ids.remove(dst);
        }

        let _stored_rule_id = self.dstmatch_id_to_rule_id[dst_port_id].take();
        debug_assert_eq!(Some(rule), _stored_rule_id);

        self.freelist.set(dst_port_id);

        self.compact();
    }

    fn compact(&mut self) {
        // Rule mapping doesn't need to store empty slots at the end -- these represent IDs that
        // can be reused implicitly.
        while let Some(None) = self.dstmatch_id_to_rule_id.last() {
            self.dstmatch_id_to_rule_id.pop();
        }

        self.freelist.zero_from(self.dstmatch_id_to_rule_id.len());
    }

    pub fn clear(&mut self) {
        self.freelist.clear_all();
        self.ports.clear();
        self.dstmatch_ids.clear();
        self.dsts.clear();
        self.dstmatch_id_to_rule_id.clear();
    }

    fn lookup_dstmatch_id(&self, rule: RuleId, dst: &DstMatch) -> Option<DstMatchId> {
        self.dstmatch_ids.get(dst).and_then(|ids| {
            ids.bits()
                .find(|&id| self.dstmatch_id_to_rule_id[id].is_some_and(|r| r == rule))
        })
    }

    pub fn lookup(&self, dst: &IpAddr, port: u16) -> DynBitset {
        let mut port_matches = self
            .ports
            .lookup(port)
            .fold(DynBitset::default(), |mut acc, x| {
                acc.union_inplace(x);
                acc
            });

        let dst_matches = self
            .dsts
            .lookup_all(*dst)
            .fold(DynBitset::default(), |mut acc, x| {
                acc.union_inplace(x);
                acc
            });

        port_matches.intersect_inplace(&dst_matches);

        port_matches
            .bits()
            .filter_map(|x| self.dstmatch_id_to_rule_id[x])
            .collect()
    }
}

#[cfg(test)]
pub mod test {
    use alloc::{boxed::Box, vec};
    use core::net::IpAddr;

    use proptest::prelude::*;
    use ts_bart::StrideOps;

    use super::*;

    #[test]
    fn basic() {
        let mut lookup = DstMatchLookup::default();

        let dst = DstMatch {
            ips: vec!["0.0.0.0/0".parse().unwrap()],
            ports: 0..=0,
        };

        lookup.insert(1, dst);

        let result = lookup.lookup(&"1.2.3.4".parse().unwrap(), 0);
        assert_eq!(DynBitset::from_iter([1]), result);
    }

    #[test]
    fn disjoint_rules() {
        let mut lookup = DstMatchLookup::default();

        let dst1 = DstMatch {
            ips: vec!["0.0.0.0/0".parse().unwrap()],
            ports: 0..=0,
        };

        let dst2 = DstMatch {
            ips: vec!["127.0.0.0/16".parse().unwrap()],
            ports: 0..=0,
        };

        lookup.insert(0, dst1);
        lookup.insert(1, dst2);

        let result = lookup.lookup(&"1.2.3.4".parse().unwrap(), 0);
        assert_eq!(DynBitset::from_iter([0]), result);

        let result = lookup.lookup(&"127.0.123.1".parse().unwrap(), 0);
        assert_eq!(DynBitset::from_iter([0, 1]), result);
    }

    #[test]
    fn overlapping_rules() {
        let mut lookup = DstMatchLookup::default();

        let dst1 = DstMatch {
            ips: vec![
                "127.0.0.0/16".parse().unwrap(),
                "0.0.0.0/0".parse().unwrap(),
            ],
            ports: 0..=0,
        };

        let dst2 = DstMatch {
            ips: vec!["0.0.0.0/0".parse().unwrap()],
            ports: 0..=0,
        };

        lookup.insert(0, dst1);
        lookup.insert(1, dst2);

        let result = lookup.lookup(&"1.2.3.4".parse().unwrap(), 0);
        assert_eq!(DynBitset::from_iter([0, 1]), result);

        let result = lookup.lookup(&"127.0.123.1".parse().unwrap(), 0);
        assert_eq!(DynBitset::from_iter([0, 1]), result);

        lookup.verify_integrity();
    }

    #[test]
    fn shared_crossrule_defn() {
        let mut lookup = DstMatchLookup::default();

        let dst = DstMatch {
            ips: vec!["0.0.0.0/0".parse().unwrap()],
            ports: 0..=0,
        };

        lookup.insert(0, dst.clone());
        lookup.insert(1, dst.clone());

        lookup.verify_integrity();

        let result = lookup.lookup(&"1.2.3.4".parse().unwrap(), 0);
        assert_eq!(DynBitset::from_iter([0, 1]), result);
    }

    #[test]
    fn repeated_rule() {
        let mut lookup = DstMatchLookup::default();

        lookup.insert(
            0,
            DstMatch {
                ips: vec!["64.0.0.0/2".parse().unwrap()],
                ports: 0..=0,
            },
        );

        lookup.insert(
            0,
            DstMatch {
                ips: vec!["0.0.0.0/0".parse().unwrap()],
                ports: 0..=0,
            },
        );

        lookup.insert(
            0,
            DstMatch {
                ips: vec!["0.0.0.0/0".parse().unwrap()],
                ports: 0..=0,
            },
        );

        lookup.verify_integrity();

        let result = lookup.lookup(&"1.2.3.4".parse().unwrap(), 0);
        assert_eq!(DynBitset::from_iter([0]), result);
    }

    #[test]
    fn different_rule_same_match() {
        let mut lookup = DstMatchLookup::default();

        lookup.insert(
            0,
            DstMatch {
                ips: vec!["64.0.0.0/2".parse().unwrap()],
                ports: 0..=0,
            },
        );

        lookup.insert(
            0,
            DstMatch {
                ips: vec!["0.0.0.0/0".parse().unwrap()],
                ports: 0..=0,
            },
        );

        lookup.insert(
            1,
            DstMatch {
                ips: vec!["0.0.0.0/0".parse().unwrap()],
                ports: 0..=0,
            },
        );

        lookup.verify_integrity();

        let result = lookup.lookup(&"1.2.3.4".parse().unwrap(), 0);
        assert_eq!(DynBitset::from_iter([0, 1]), result);
    }

    #[test]
    fn compaction() {
        let mut lookup = DstMatchLookup::default();

        fn dummy_match(n: u16) -> DstMatch {
            DstMatch {
                ips: vec![],
                ports: 0..=n,
            }
        }

        lookup.insert(0, dummy_match(1));
        lookup.insert(0, dummy_match(2));
        lookup.insert(0, dummy_match(3));

        lookup.remove(0, &dummy_match(1));
        assert_eq!(lookup.freelist, DynBitset::default().with_bits(&[0]));

        lookup.remove(0, &dummy_match(2));
        assert_eq!(lookup.freelist, DynBitset::default().with_bits(&[0, 1]));

        lookup.remove(0, &dummy_match(3));
        assert!(lookup.freelist.is_empty());
        assert!(lookup.dstmatch_id_to_rule_id.is_empty());
        assert!(lookup.dstmatch_ids.is_empty());

        lookup.insert(0, dummy_match(1));
        lookup.insert(0, dummy_match(2));

        lookup.remove(0, &dummy_match(2));
        assert!(lookup.freelist.is_empty());
        assert_eq!(lookup.dstmatch_id_to_rule_id.len(), 1);
    }

    #[derive(Debug)]
    enum Op {
        Insert { rule_id: RuleId, dstmatch: DstMatch },
        Remove { rule_id: RuleId, dstmatch: DstMatch },
        Clear,
    }

    prop_compose! {
        pub fn any_ipnet()(ip: IpAddr, pfx: u8) -> ipnet::IpNet {
            let pfx = match ip.is_ipv4() {
                true => pfx % 33,
                false => pfx % 129,
            };

            ipnet::IpNet::new_assert(ip, pfx).trunc()
        }
    }

    prop_compose! {
        pub fn any_dstmatch()(
            mut port_start: u16,
            mut port_end: u16,
            ips in proptest::collection::vec(any_ipnet(), 1..100),
        ) -> DstMatch {
            if port_start > port_end {
                core::mem::swap(&mut port_start, &mut port_end);
            }

            DstMatch {
                ports: port_start..=port_end,
                ips,
            }
        }
    }

    prop_compose! {
        fn any_op()(rule_id in 0usize..1024, variant in 0..3, dstmatch in any_dstmatch()) -> Op {
            match variant {
                0 => Op::Insert { rule_id, dstmatch },
                1 => Op::Remove { rule_id, dstmatch },
                2 => Op::Clear,
                _ => unreachable!(),
            }
        }
    }

    fn apply_op(lookup: &mut DstMatchLookup, op: &Op) {
        match op {
            Op::Clear => {
                lookup.clear();
            }
            Op::Insert { rule_id, dstmatch } => {
                lookup.insert(*rule_id, dstmatch.clone());
            }
            Op::Remove { rule_id, dstmatch } => {
                lookup.remove(*rule_id, dstmatch);
            }
        }
    }

    pub fn bart_bitset(node: &ts_bart::DefaultNode<DynBitset>) -> DynBitset {
        node.descendants(true)
            .flat_map(|(_, node)| match node {
                ts_bart::Child::Path(node) => {
                    Box::new(node.direct_prefixes().map(|(_idx, value)| value))
                        as Box<dyn Iterator<Item = &DynBitset>>
                }
                ts_bart::Child::Leaf { value, .. } | ts_bart::Child::Fringe(value) => {
                    Box::new(core::iter::once(value))
                }
            })
            .fold(DynBitset::default(), |mut acc, x| {
                acc.union_inplace(x);

                acc
            })
    }

    impl DstMatchLookup {
        pub fn dump_rule_ids(&self) -> DynBitset {
            self.dstmatch_id_to_rule_id
                .iter()
                .filter_map(|x| *x)
                .collect::<DynBitset>()
        }

        pub fn verify_integrity(&self) {
            let ipv4_matches = bart_bitset(self.dsts.root(true));
            let ipv6_matches = bart_bitset(self.dsts.root(false));

            let all_ip_rule_matches = ipv4_matches | ipv6_matches;

            let stored_port_dstport_ids =
                self.ports
                    .iter()
                    .fold(DynBitset::default(), |mut acc, (_range, x)| {
                        acc.union_inplace(x);
                        acc
                    });

            assert_eq!(
                all_ip_rule_matches, stored_port_dstport_ids,
                "ip and port dstport ids did not match"
            );

            let ip_rule_ids = all_ip_rule_matches
                .bits()
                .filter_map(|x| self.dstmatch_id_to_rule_id[x])
                .collect::<DynBitset>();

            let stored_rule_ids = self.dump_rule_ids();

            assert_eq!(
                stored_rule_ids, ip_rule_ids,
                "dstport to ruleset mapping did not match ip/port ids"
            );

            assert!(
                !stored_rule_ids.intersects(&self.freelist),
                "stored rule ids found in freelist"
            );
        }
    }

    proptest::proptest! {
        #[test]
        fn random_ops(ops in proptest::collection::vec(any_op(), 0..100)) {
            let mut lookup = DstMatchLookup::default();
            lookup.verify_integrity();

            for op in &ops {
                apply_op(&mut lookup, op);
                lookup.verify_integrity();
            }
        }
    }
}
