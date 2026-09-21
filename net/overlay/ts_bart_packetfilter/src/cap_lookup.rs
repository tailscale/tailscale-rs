use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

use ts_bitset::{BitsetDyn, BitsetStatic};
use ts_dynbitset::DynBitset;

use crate::RuleId;

type CapId = usize;

/// Accelerated capability lookup, resolving an iterator of nodecap names to the set of
/// matching [`RuleId`]s (as a [`DynBitset`]).
#[derive(Debug, Clone, Default)]
pub struct CapLookup {
    /// Lookup from cap name to numeric [`CapId`] (allocated and managed internally by
    /// `CapLookup`).
    ids: BTreeMap<String, CapId>,

    /// Map [`CapId`] to the set of matching rule IDs.
    caps_to_rules: Vec<Option<DynBitset>>,

    /// Set of free [`CapId`]s to be reused. New ids are allocated from the freelist
    /// first to minimize sparseness in `caps_to_rules`.
    freelist: DynBitset,
}

impl CapLookup {
    /// Mark the given `cap_name` as accepting for the given `rule_id`.
    pub fn insert(&mut self, cap_name: &str, rule_id: RuleId) -> CapId {
        let id = if let Some(&id) = self.ids.get(cap_name) {
            id
        } else if let Some(id) = crate::pop_freelist(&mut self.freelist) {
            self.ids.insert(cap_name.to_string(), id);

            id
        } else {
            let id = self.caps_to_rules.len();
            self.ids.insert(cap_name.to_string(), id);
            self.caps_to_rules.push(None);

            id
        };

        self.caps_to_rules[id].get_or_insert_default().set(rule_id);

        id
    }

    /// Unmark the given `cap_name` as accepting for the given `rule_id`.
    pub fn remove(&mut self, rule_id: RuleId, cap_name: &str) {
        let Some(&id) = self.ids.get(cap_name) else {
            return;
        };

        let remove = if let Some(Some(rules)) = self.caps_to_rules.get_mut(id) {
            rules.clear(rule_id);
            rules.is_empty()
        } else {
            false
        };

        if remove {
            if let Some(ent) = self.caps_to_rules.get_mut(id) {
                *ent = None;
            };

            self.ids.remove(cap_name);
            self.freelist.set(id);
        }

        self.compact();
    }

    /// Clear all caps stored in this [`CapLookup`].
    pub fn clear(&mut self) {
        self.caps_to_rules.clear();
        self.ids.clear();
        self.freelist.clear_all();
    }

    /// Resolve all rule IDs for which any of the `caps` in caps accepts.
    pub fn lookup(&self, caps: &mut dyn Iterator<Item = &str>) -> DynBitset {
        caps.filter_map(|c| self.ids.get(c))
            .filter_map(|id| self.caps_to_rules.get(*id)?.as_ref())
            .fold(DynBitset::default(), |mut acc, x| {
                acc.union_inplace(x);
                acc
            })
    }

    fn compact(&mut self) {
        while let Some(None) = self.caps_to_rules.last() {
            self.caps_to_rules.pop();
        }

        self.freelist.zero_from(self.caps_to_rules.len());
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn compaction() {
        let mut lookup = CapLookup::default();

        lookup.insert("abc", 0);
        lookup.insert("def", 0);
        lookup.insert("ghi", 0);

        lookup.remove(0, "abc");
        assert_eq!(lookup.freelist, DynBitset::default().with_bits(&[0]));

        lookup.remove(0, "def");
        assert_eq!(lookup.freelist, DynBitset::default().with_bits(&[0, 1]));

        lookup.remove(0, "ghi");
        assert!(lookup.freelist.is_empty());
        assert!(lookup.caps_to_rules.is_empty());
        assert!(lookup.ids.is_empty());

        lookup.insert("abc", 0);
        lookup.insert("def", 0);

        lookup.remove(0, "def");
        assert!(lookup.freelist.is_empty());
        assert_eq!(lookup.caps_to_rules.len(), 1);
    }

    #[derive(Debug)]
    enum Op {
        Insert { name: String, rule_id: RuleId },
        Remove { name: String, rule_id: RuleId },
        Clear,
    }

    prop_compose! {
        fn any_op()(name: String, rule_id in 0usize..1024, variant in 0..3) -> Op {
            match variant {
                0 => Op::Insert { name, rule_id },
                1 => Op::Remove { name, rule_id },
                2 => Op::Clear,
                _ => unreachable!(),
            }
        }
    }

    fn apply_op(lookup: &mut CapLookup, op: &Op) {
        match op {
            Op::Clear => {
                lookup.clear();
            }
            Op::Insert { name, rule_id } => {
                lookup.insert(name, *rule_id);
            }
            Op::Remove { name, rule_id } => {
                lookup.remove(*rule_id, name);
            }
        }
    }

    impl CapLookup {
        pub fn verify_integrity(&self) {
            let stored_capids = self.ids.values().copied().collect::<DynBitset>();
            let stored_rule_lookup_ids = self
                .caps_to_rules
                .iter()
                .enumerate()
                .filter_map(|(i, x)| x.is_some().then_some(i))
                .collect::<DynBitset>();

            assert_eq!(stored_capids, stored_rule_lookup_ids);
            assert!(!stored_capids.intersects(&self.freelist));
        }

        pub fn dump_rule_ids(&self) -> DynBitset {
            self.caps_to_rules
                .iter()
                .fold(DynBitset::default(), |mut acc, x| {
                    if let Some(b) = x {
                        acc.union_inplace(b);
                    }

                    acc
                })
        }
    }

    proptest::proptest! {
        #[test]
        fn random_ops(ops in proptest::collection::vec(any_op(), 0..100)) {
            let mut lookup = CapLookup::default();
            lookup.verify_integrity();

            for op in &ops {
                apply_op(&mut lookup, op);
                lookup.verify_integrity();
            }
        }
    }
}
