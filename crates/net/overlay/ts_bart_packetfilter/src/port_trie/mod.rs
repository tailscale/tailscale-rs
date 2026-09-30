mod port_prefix;

use alloc::collections::BTreeMap;
use core::{borrow::Borrow, ops::RangeInclusive};

use port_prefix::PortPrefix;
use ts_array256::Array256;
use ts_bart::BaseIndex;

type Storage<T> = smallvec::SmallVec<[T; 1]>;

/// Lookup- and memory-optimized data structure for associating data to sets of ports.
///
/// The point is that we want to be able to test a port's membership in _ranges_ of ports
/// quickly. The idea is that we can make use of the same [`BaseIndex`] approach as
/// [`ts_bart::Node`] to compactly encode "port prefixes", i.e. ranges of ports under a
/// similar binary hierarchy.
///
/// The main conceptual difference between this structure and a [`ts_bart::Node`] is
/// that this is designed to return _all_ prefix matches as the primary API, is fixed
/// at 2 trie layers, and specializes for the full-length prefix case, as single-port
/// filters are expected to be common.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct PortTrie<T> {
    /// `BaseIndex` prefixes (up to /7): upper port bits.
    prefixes: Array256<Storage<T>>,

    /// Children by upper 8 bits of port.
    children: Array256<Storage<Child<T>>>,

    /// Singleton (single port) children.
    ///
    /// These could be nested on [`Child`] like in `bart`, but that suggests a bunch
    /// of extra allocation
    singletons: BTreeMap<u16, T>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
struct Child<T> {
    /// `BaseIndex` prefixes (/8 to /15): lower bits.
    prefixes: Array256<Storage<T>>,
}

impl<T> PortTrie<T> {
    /// The empty [`PortTrie`].
    pub const EMPTY: Self = PortTrie {
        prefixes: Array256::EMPTY,
        children: Array256::EMPTY,
        singletons: BTreeMap::new(),
    };

    /// Modify this port trie in-place.
    ///
    /// Hijacks [`ts_bart::RouteModification`] -- `f` may return:
    ///
    /// - [`ts_bart::RouteModification::Insert`]: an entry is inserted into the structure.
    /// - [`ts_bart::RouteModification::Remove`]: the existing entry (if any) is removed from the
    ///   structure.
    /// - [`ts_bart::RouteModification::Noop`]: the entry is not changed.
    ///
    /// This function may call `f` any number of times as it matches different prefixes.
    ///
    /// NB: `insert` and `remove` are not provided for this type because it is expected to
    /// hold values that in most cases will be modified in-place.
    pub fn modify(
        &mut self,
        ports: RangeInclusive<u16>,
        f: &mut dyn FnMut(Option<&mut T>) -> ts_bart::RouteModification<T>,
    ) {
        for pfx in port_prefix::iter_prefixes(ports) {
            match pfx {
                PortPrefix::Prefix(prefix) => {
                    let entry = self.prefixes.get_mut(prefix.get());
                    match f(entry) {
                        ts_bart::RouteModification::Insert(val) => {
                            self.prefixes.insert(prefix.get(), val);
                        }
                        ts_bart::RouteModification::Remove => {
                            self.prefixes.remove(prefix.get());
                        }
                        _ => {}
                    }
                }
                PortPrefix::ChildPrefix { hi, lo_pfx } => {
                    if !self.children.test(hi) {
                        if let ts_bart::RouteModification::Insert(val) = f(None) {
                            self.children.insert(
                                hi,
                                Child {
                                    prefixes: Array256::from_iter([(lo_pfx.get(), val)]),
                                },
                            );
                        }

                        continue;
                    }

                    let child = self
                        .children
                        .get_mut(hi)
                        .expect("invariant violated: child missing");
                    match f(child.prefixes.get_mut(lo_pfx.get())) {
                        ts_bart::RouteModification::Insert(val) => {
                            child.prefixes.insert(lo_pfx.get(), val);
                        }
                        ts_bart::RouteModification::Remove => {
                            child.prefixes.remove(lo_pfx.get());
                        }
                        _ => {}
                    }
                }
                PortPrefix::Singleton(port) => match f(self.singletons.get_mut(&port)) {
                    ts_bart::RouteModification::Insert(val) => {
                        self.singletons.insert(port, val);
                    }
                    ts_bart::RouteModification::Remove => {
                        self.singletons.remove(&port);
                    }
                    _ => {}
                },
            }
        }
    }

    /// Look up all matching rules for `port`.
    pub fn lookup(&self, port: u16) -> impl Iterator<Item = &T> {
        let mut done = false;
        self.prefix_matches(port)
            .chain(self.child_matches(port))
            .chain(core::iter::from_fn(move || {
                if done {
                    return None;
                }
                done = true;

                self.singletons.get(&port)
            }))
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.singletons.clear();
        self.children.clear();
        self.prefixes.clear();
    }

    /// Iterate all stored port ranges.
    ///
    /// No guarantees are provided about iteration order.
    pub fn iter(&self) -> impl Iterator<Item = (RangeInclusive<u16>, &T)> {
        let singleton_iter = self.singletons.iter().map(|(&k, v)| (k..=k, v));

        let pfx_iter = self.prefixes.iter().map(|(index, t)| {
            let pfx = PortPrefix::Prefix(BaseIndex::new(index));
            (pfx.to_range(), t)
        });

        let child_iter = self.children.iter().flat_map(|(hi, t)| {
            t.prefixes.iter().map(move |(lo_pfx, t)| {
                let lo_idx = BaseIndex::new(lo_pfx);

                let pfx = PortPrefix::ChildPrefix { hi, lo_pfx: lo_idx };

                (pfx.to_range(), t)
            })
        });

        singleton_iter.chain(pfx_iter).chain(child_iter)
    }

    fn prefix_matches(&self, port: u16) -> impl Iterator<Item = &T> {
        let pfx_hi = BaseIndex::from_pfx_7(Self::port_byte(port));

        let mut pfx_matches_hi = *ts_bart::lpm(pfx_hi).borrow();
        pfx_matches_hi.intersect_inplace(self.prefixes.bitset());

        pfx_matches_hi
            .bits()
            .filter_map(|bit| self.prefixes.get(bit as _))
    }

    fn child_matches(&self, port: u16) -> impl Iterator<Item = &T> {
        let mut done = false;

        core::iter::from_fn(move || {
            if done {
                return None;
            }
            done = true;

            self.children.get(Self::port_byte(port))
        })
        .flat_map(move |child| child.lookup(port))
    }

    const fn port_byte(port: u16) -> u8 {
        (port >> 8) as u8
    }
}

impl<T> Child<T> {
    /// Look up the matching rules for the low bits of `port`.
    fn lookup(&self, port: u16) -> impl Iterator<Item = &T> {
        let pfx_lo = BaseIndex::from_pfx_7(Self::port_byte(port));

        let mut pfx_matches_lo = *ts_bart::lpm(pfx_lo).borrow();
        pfx_matches_lo.intersect_inplace(self.prefixes.bitset());

        pfx_matches_lo
            .bits()
            .filter_map(|bit| self.prefixes.get(bit as _))
    }

    const fn port_byte(port: u16) -> u8 {
        (port & 0xff) as _
    }
}

#[cfg(test)]
mod test {
    use alloc::vec::Vec;

    use super::*;

    fn assert_lookup<T>(trie: &mut PortTrie<T>, port: u16, vals: impl IntoIterator<Item = T>)
    where
        T: Clone + PartialEq + core::fmt::Debug + Ord,
    {
        let mut v = trie.lookup(port).cloned().collect::<Vec<_>>();
        v.sort();

        assert_eq!(v, vals.into_iter().collect::<Vec<_>>());
    }

    #[test]
    fn basic() {
        let mut trie = PortTrie::EMPTY;

        trie.modify(80..=80, &mut |t| {
            assert_eq!(None, t);
            ts_bart::RouteModification::Insert(1)
        });

        assert_lookup(&mut trie, 80, [1]);

        trie.modify(70..=90, &mut |t| {
            assert_eq!(None, t);
            ts_bart::RouteModification::Insert(2)
        });

        assert_lookup(&mut trie, 80, [1, 2]);
        assert_lookup(&mut trie, 69, []);
        assert_lookup(&mut trie, 91, []);
        assert_lookup(&mut trie, 90, [2]);
        assert_lookup(&mut trie, 70, [2]);
        assert_lookup(&mut trie, 81, [2]);
        assert_lookup(&mut trie, 79, [2]);
    }

    #[test]
    fn size() {
        std::println!("size_of::<PortTrie>(): {}B", size_of::<PortTrie<()>>());
        std::println!("size_of::<Child>(): {}B", size_of::<Child<()>>());
    }
}
