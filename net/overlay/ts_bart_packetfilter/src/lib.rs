#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

use ts_bart::{RoutingTable, RoutingTableExt};
use ts_bitset::{BitsetDyn, BitsetStatic};
use ts_dynbitset::DynBitset;
use ts_packetfilter::{Filter, FilterStorage, IpProto, PacketInfo, Rule, Ruleset, filter::CapIter};

mod cap_lookup;
mod dst_port;
mod port_trie;

use cap_lookup::CapLookup;
use dst_port::DstMatchLookup;
#[doc(inline)]
pub use port_trie::PortTrie;

type RuleId = usize;
type RuleBitset = DynBitset;

/// A filter that stores each of its rule components (src ip, src cap, dst ip/port, and ip
/// proto) independently in data structures which can be queried for all matching rules
/// as bitset results.
///
/// The set of rules matching a packet can be computed by querying all the component
/// structures and taking the bitwise intersection of their results: the surviving bits
/// are the rule ids that matched. The ruleset name is resolved via a reverse index from
/// the rule id.
#[derive(Debug, Clone, Default)]
pub struct BartFilter {
    caps: CapLookup,
    srcs: ts_bart::Table<RuleBitset>,
    dsts: DstMatchLookup,
    ip_protos: BTreeMap<IpProto, RuleBitset>,

    /// Lookup rule id -> ruleset name.
    rules_to_rulesets: Vec<Option<String>>,

    /// Unallocated rule IDs that should be claimed by new rules.
    rule_freelist: RuleBitset,

    /// Lookup for ruleset info by name.
    rulesets: BTreeMap<String, RulesetEntry>,
}

fn pop_freelist(b: &mut DynBitset) -> Option<usize> {
    // Want to pop the _first_ id to promote compactness near the beginning of id ranges
    // so it's more likely that our id bitsets will stay small. Ids at the end of the id range
    // will tend to be cleaned up and made implicitly available by compacting operations.
    if let Some(first) = b.first_set() {
        b.clear(first);
        return Some(first);
    }

    None
}

#[derive(Debug, Clone)]
struct RulesetEntry {
    /// The original rule records need to be retained in order to avoid a linear walk of
    /// all the child data structures on ruleset removal. E.g. because we have the
    /// [`DstMatch`] entries, [`DstMatchLookup`] can directly resolve the ids to remove.
    /// Likewise for [`CapLookup`], `srcs`, and `ip_protos`.
    ///
    /// For small filters, it would likely be a favorable tradeoff to just drop this field
    /// and do the linear lookup, as it will be fast enough, and the field can use a
    /// substantial amount of memory. But for large filters that are updated with any
    /// frequency, the linear walk would likely cause substantial pauses in packet
    /// processing.
    ///
    /// This comes at the cost of significant weight of this field.
    ruleset: Ruleset,
    rule_ids: RuleBitset,
}

impl RulesetEntry {
    fn rules_and_ids(&self) -> impl Iterator<Item = (RuleId, &Rule)> {
        self.rule_ids.bits().zip(&self.ruleset)
    }
}

impl BartFilter {
    /// Insert a ruleset under the given name. If it already exists, its state
    /// is cleared before updating.
    fn insert(&mut self, name: &str, ruleset: Ruleset) {
        self.remove(name);

        let mut ent = RulesetEntry {
            ruleset,
            rule_ids: Default::default(),
        };

        for rule in &ent.ruleset {
            let rule_id = if let Some(idx) = pop_freelist(&mut self.rule_freelist) {
                idx
            } else {
                let idx = self.rules_to_rulesets.len();
                self.rules_to_rulesets.push(None);
                idx
            };

            ent.rule_ids.set(rule_id);
            self.rules_to_rulesets[rule_id] = Some(name.to_string());

            for proto in &rule.protos {
                self.ip_protos.entry(*proto).or_default().set(rule_id);
            }

            for cap in &rule.src.caps {
                self.caps.insert(cap, rule_id);
            }

            for &pfx in &rule.src.pfxs {
                self.srcs.modify(pfx, |val| {
                    if let Some(val) = val {
                        val.set(rule_id);
                        ts_bart::RouteModification::Noop
                    } else {
                        ts_bart::RouteModification::Insert(DynBitset::empty().with_bit(rule_id))
                    }
                });
            }

            for dstport in &rule.dst {
                self.dsts.insert(rule_id, dstport.clone());
            }
        }

        self.rulesets.insert(name.to_string(), ent);
        self.compact();
    }

    fn remove(&mut self, ruleset_name: &str) {
        let Some(entry) = self.rulesets.remove(ruleset_name) else {
            return;
        };

        self.rule_freelist.union_inplace(&entry.rule_ids);

        for rule_id in entry.rule_ids.bits() {
            self.rules_to_rulesets[rule_id] = None;
        }

        for (rule_id, rule) in entry.rules_and_ids() {
            for proto in &rule.protos {
                let remove = if let Some(rules) = self.ip_protos.get_mut(proto) {
                    rules.clear(rule_id);
                    rules.is_empty()
                } else {
                    false
                };

                if remove {
                    self.ip_protos.remove(proto);
                }
            }

            for dst in &rule.dst {
                self.dsts.remove(rule_id, dst);
            }

            for cap in &rule.src.caps {
                self.caps.remove(rule_id, cap);
            }

            for &pfx in &rule.src.pfxs {
                self.srcs.modify(pfx, |val| {
                    if let Some(val) = val {
                        val.clear(rule_id);

                        if val.is_empty() {
                            return ts_bart::RouteModification::Remove;
                        }
                    }

                    ts_bart::RouteModification::Noop
                });
            }
        }

        self.compact();
    }

    fn lookup(&self, info: &PacketInfo, caps: CapIter) -> DynBitset {
        let mut src_matches = self.caps.lookup(caps);

        // src cap OR src ip
        if let Some(ip_matches) = self.srcs.lookup(info.src) {
            src_matches.union_inplace(ip_matches);
        }

        // must match src AND ipproto AND dest
        let mut all_matches = src_matches;
        if all_matches.is_empty() {
            return all_matches;
        }

        if let Some(proto_matches) = self.ip_protos.get(&info.ip_proto) {
            all_matches.intersect_inplace(proto_matches);
        } else {
            all_matches.clear_all();
        }

        if all_matches.is_empty() {
            return all_matches;
        }

        let dstport_matches = self.dsts.lookup(&info.dst, info.port);
        all_matches.intersect_inplace(&dstport_matches);

        all_matches
    }

    fn compact(&mut self) {
        while let Some(None) = self.rules_to_rulesets.last() {
            self.rules_to_rulesets.pop();
        }

        // The freelist only needs to actually hold ids within the rule to ruleset mapping -- ids
        // outside that range are implicitly free.
        self.rule_freelist.zero_from(self.rules_to_rulesets.len());
    }
}

impl FilterStorage for BartFilter {
    fn insert_dyn(&mut self, name: &str, ruleset: &mut dyn Iterator<Item = Rule>) {
        self.insert(name, ruleset.collect());
    }

    fn remove(&mut self, name: &str) {
        self.remove(name);
    }

    fn clear(&mut self) {
        self.caps.clear();
        self.srcs.clear();
        self.dsts.clear();
        self.ip_protos.clear();
        self.rule_freelist.clear_all();
        self.rules_to_rulesets.clear();
        self.rulesets.clear();
    }
}

impl Filter for BartFilter {
    fn match_for(&self, info: &PacketInfo, caps: CapIter) -> Option<&str> {
        let all_matches = self.lookup(info, caps);

        // Grab the first match
        all_matches
            .first_set()
            .map(|rule_id| self.rules_to_rulesets[rule_id].as_ref().unwrap().as_str())
    }

    fn matches(&self, info: &PacketInfo, caps: CapIter) -> bool {
        let all_matches = self.lookup(info, caps);

        !all_matches.is_empty()
    }
}

#[cfg(test)]
mod test {
    use alloc::vec;

    use pf::FilterExt;
    use proptest::prelude::*;
    use ts_array256::ArrayStorageSliceExt;
    use ts_packetfilter as pf;

    use super::*;
    use crate::dst_port::test::bart_bitset;

    #[test]
    fn basic() {
        let mut filter = BartFilter::default();
        filter.verify_integrity();

        filter.insert(
            "abc",
            vec![Rule {
                src: pf::SrcMatch {
                    pfxs: vec!["0.0.0.0/0".parse().unwrap()],
                    caps: vec![String::new()],
                },
                protos: vec![IpProto::new(0)],
                dst: vec![pf::DstMatch {
                    ips: vec!["0.0.0.0/0".parse().unwrap()],
                    ports: 0..=0,
                }],
            }],
        );
        filter.verify_integrity();

        assert!(filter.can_access(
            &PacketInfo {
                src: "1.2.3.4".parse().unwrap(),
                dst: "5.6.7.8".parse().unwrap(),
                port: 0,
                ip_proto: IpProto::new(0),
            },
            []
        ));

        filter.remove("abc");
        filter.verify_integrity();
    }

    #[test]
    fn repeated_dst() {
        let mut filter = BartFilter::default();

        let rule = Rule {
            src: pf::SrcMatch {
                pfxs: vec!["0.0.0.0/0".parse().unwrap()],
                caps: vec![String::new()],
            },
            protos: vec![IpProto::new(0)],
            dst: vec![
                pf::DstMatch {
                    ports: 0..=0,
                    ips: vec!["128.0.0.0/1".parse().unwrap()],
                },
                pf::DstMatch {
                    ports: 0..=0,
                    ips: vec!["0.0.0.0/0".parse().unwrap()],
                },
            ],
        };

        filter.insert("", vec![rule]);
        filter.verify_integrity();

        filter.remove("");
        filter.verify_integrity();
    }

    #[test]
    fn rules_in_same_ruleset_distinct() {
        let mut filter = BartFilter::default();

        filter.insert(
            "a",
            vec![
                Rule {
                    src: pf::SrcMatch {
                        pfxs: vec!["128.0.0.0/1".parse().unwrap()],
                        ..Default::default()
                    },
                    protos: vec![IpProto::TCP, IpProto::UDP],
                    dst: vec![pf::DstMatch {
                        ports: 80..=80,
                        ips: vec!["0.0.0.0/0".parse().unwrap()],
                    }],
                },
                Rule {
                    src: pf::SrcMatch {
                        caps: vec!["mycap".to_string()],
                        ..Default::default()
                    },
                    protos: vec![IpProto::TCP, IpProto::UDP],
                    dst: vec![pf::DstMatch {
                        ports: 123..=124,
                        ips: vec!["0.0.0.0/0".parse().unwrap()],
                    }],
                },
            ],
        );

        assert!(!filter.can_access(
            &PacketInfo {
                src: "128.1.1.1".parse().unwrap(), // only first
                dst: "1.1.1.1".parse().unwrap(),   // both
                ip_proto: IpProto::UDP,            // both
                port: 123,                         // second
            },
            []
        ));

        assert!(!filter.can_access(
            &PacketInfo {
                src: "0.1.1.1".parse().unwrap(), // neither
                dst: "1.1.1.1".parse().unwrap(), // both
                ip_proto: IpProto::UDP,          // both
                port: 80,                        // first
            },
            ["mycap"] // second
        ));
    }

    #[test]
    fn compaction() {
        let mut filter = BartFilter::default();

        filter.insert("abc", vec![Rule::default()]);
        filter.insert("def", vec![Rule::default()]);
        filter.insert("ghi", vec![Rule::default()]);

        filter.remove("abc");

        assert_eq!(filter.rule_freelist.count_ones(), 1);
        assert_eq!(filter.rules_to_rulesets.len(), 3);
        assert_eq!(filter.rulesets.len(), 2);

        // compaction should trigger here
        filter.remove("ghi");

        assert_eq!(filter.rule_freelist.count_ones(), 1);
        assert_eq!(filter.rules_to_rulesets.len(), 2);
        assert_eq!(filter.rulesets.len(), 1);

        filter.remove("def");

        assert!(filter.rule_freelist.is_empty());
        assert!(filter.rules_to_rulesets.is_empty());
        assert!(filter.rulesets.is_empty());
    }

    impl BartFilter {
        fn verify_integrity(&self) {
            self.dsts.verify_integrity();
            self.caps.verify_integrity();

            let ruleset_stored_rule_ids =
                self.rulesets
                    .values()
                    .fold(DynBitset::default(), |mut acc, x| {
                        acc.union_inplace(&x.rule_ids);
                        acc
                    });

            let ipv4_matches = bart_bitset(self.srcs.root(true));
            let ipv6_matches = bart_bitset(self.srcs.root(false));

            let src_matches = ipv4_matches | ipv6_matches;

            let ipproto_matches =
                self.ip_protos
                    .values()
                    .fold(DynBitset::default(), |mut acc, x| {
                        acc.union_inplace(x);
                        acc
                    });

            let cap_matches = self.caps.dump_rule_ids();
            let dst_matches = self.dsts.dump_rule_ids();

            // PRE: all rules applied actually have a src match defined
            assert_eq!(src_matches, ipproto_matches, "src <-> ipproto");
            assert_eq!(src_matches, dst_matches, "src <-> dst");
            assert_eq!(src_matches, cap_matches, "src <-> cap");
            assert_eq!(src_matches, ruleset_stored_rule_ids, "src <-> ruleset");

            assert!(!self.rule_freelist.intersects(&src_matches));
        }
    }

    prop_compose! {
        fn any_rule()(
            protos in proptest::collection::vec(any::<i64>(), 1..25),
            caps in proptest::collection::vec(any::<String>(), 1..25),
            dstmatches in proptest::collection::vec(dst_port::test::any_dstmatch(), 1..25),
            srcs in proptest::collection::vec(dst_port::test::any_ipnet(), 1..25),
        ) -> Rule {
            Rule {
                dst: dstmatches,
                protos: protos.into_iter().map(IpProto::new).collect(),
                src: pf::SrcMatch {
                    pfxs: srcs,
                    caps,
                }
            }
        }
    }

    proptest::proptest! {
        #[test]
        fn prop_basic(name: String, rule in any_rule()) {
            let mut filter = BartFilter::default();

            filter.insert(&name, vec![rule.clone()]);
            filter.verify_integrity();

            if let Some(dst) = rule.dst.first() &&
            let Some(dst_pfx) = dst.ips.first() &&
            let Some(src_pfx) = rule.src.pfxs.first() &&
            let Some(proto) = rule.protos.first()
            {
                let packet_info = PacketInfo {
                    dst: dst_pfx.addr(),
                    port: *dst.ports.start(),
                    src: src_pfx.addr(),
                    ip_proto: *proto,
                };
                let cap = rule.src.caps.iter().map(|cap| cap.as_str()).take(1).collect::<Vec<_>>();

                let rules = filter.lookup(&packet_info, &mut cap.iter().copied());
                prop_assert!(!rules.is_empty());
                prop_assert!(filter.can_access(&packet_info, cap));
            }

            filter.remove(&name);
            filter.verify_integrity();

            assert!(filter.rules_to_rulesets.is_empty());
            assert!(filter.rule_freelist.is_empty());
            assert!(filter.rulesets.is_empty());
            assert_eq!(filter.srcs.size(), 0);
        }
    }
}
