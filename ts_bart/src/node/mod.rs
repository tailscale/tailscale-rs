//! Single-level trie nodes and operations.
//!
//! Separate from [`iptrie`][crate::iptrie] to maintain a clear dependency
//! ordering: the multi-level trie operations are strictly dependent on the
//! single-level ops.

use core::{
    borrow::Borrow,
    fmt::{Debug, Formatter},
};

use ts_array256::{Array256, ArrayStorage};
use ts_bitset::Bitset256;

use crate::BaseIndex;

mod child;
mod child_storage;
mod descendants;
mod stride_ops;

pub use child::Child;
pub use child_storage::{BoxStorage, InlineStorage, Storage};
pub use stride_ops::{
    NodePrefixIter, PrefixOps, PrefixOpsExt, PrefixReadOps, Stats, StrideBase, StrideOps,
    StrideOpsExt,
};

/// Type alias defining the default child storage type.
///
/// This storage type is considered the best for most applications based on
/// benchmarks and storage size profiling.
pub type DefaultStorage = BoxStorage;

/// Type alias for [`Node`] with [`DefaultStorage`]. Provided to improve
/// inference by concretizing the storage type.
pub type DefaultNode<T> = Node<T, DefaultStorage>;

cfg_if::cfg_if! {
    if #[cfg(feature = "smallvec")] {
        /// Storage for elements in [`Node`] child and prefix arrays.
        /// [`SmallVec`][smallvec::SmallVec] wins marginally in memory size according
        /// to benchmarks, improves majorly on mutation performance (avoiding allocations,
        /// presumably), and has mixed effects on lookup performance.
        type ArrayStore<T> = smallvec::SmallVec<[T; 1]>;
    } else {
        /// Storage for elements in [`Node`] child and prefix arrays.
        type ArrayStore<T> = alloc::vec::Vec<T>;
    }
}

/// A trie node logically covering a single (octet) address stride.
///
/// Contains prefixes (directly owned by this node) and children (descendants
/// in the trie).
///
/// This is the canonical stride-level [`Node`] type for the crate, mirroring
/// go-bart's Full nodes. The operations its supports are abstracted for
/// via the [`StrideOps`] trait -- other implementations are possible, e.g. to
/// support similar functionality to go-bart's `Lite` and `Fast` node types.
#[derive(PartialEq, Eq, Hash)]
pub struct Node<T, C = DefaultStorage>
where
    C: Storage + ?Sized,
{
    /// The prefixes this node covers directly, indexed by [`BaseIndex`].
    ///
    /// If this node is at trie depth 3 via octet path `[192, 168]` for
    /// instance, the prefix entry `12/5` => `34` would represent the overall
    /// trie route mapping `192.168.12.0/21` => 34.
    pub prefixes: Array256<ArrayStore<T>>,

    /// The children contained in this node, indexed by complete prefix
    /// octet.
    pub children: Array256<ArrayStore<Child<C::Container<Self>, T>>>,
}

impl<T, C> Clone for Node<T, C>
where
    C: Storage + ?Sized,
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            prefixes: self.prefixes.clone(),
            children: self.children.clone_with(&|c| match c {
                Child::Path(p) => Child::Path(C::clone(p)),
                Child::Fringe(p) => Child::Fringe(p.clone()),
                Child::Leaf { prefix, value } => Child::Leaf {
                    prefix: *prefix,
                    value: value.clone(),
                },
            }),
        }
    }
}

impl<T, C> Debug for Node<T, C>
where
    T: Debug,
    C: Storage + ?Sized,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        struct IdArrayFormatter<'a, S> {
            ary: &'a Array256<S>,
        }

        impl<S> Debug for IdArrayFormatter<'_, S>
        where
            S: ArrayStorage + AsRef<[S::T]>,
            S::T: Debug,
        {
            fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
                f.debug_map()
                    .entries(self.ary.bitset().bits().map(|i| {
                        (
                            BaseIndex::new(i as _).fmt_prefix(),
                            self.ary.get(i as _).unwrap(),
                        )
                    }))
                    .finish()
            }
        }

        f.debug_struct("Node")
            .field(
                "prefixes",
                &IdArrayFormatter {
                    ary: &self.prefixes,
                },
            )
            .field(
                "children",
                &self
                    .children
                    .custom_storage_fmt(&Child::as_node_ref::<C, _>),
            )
            .finish()
    }
}

impl<T, C> Default for Node<T, C>
where
    C: Storage + ?Sized,
{
    fn default() -> Self {
        Self::EMPTY
    }
}

impl<T, C> Node<T, C>
where
    C: Storage + ?Sized,
{
    /// The empty node value (no children, no prefixes).
    pub const EMPTY: Self = Self {
        prefixes: Array256::EMPTY,
        children: Array256::EMPTY,
    };

    /// Returns whether the node is empty.
    pub const fn is_empty(&self) -> bool {
        self.prefixes.is_empty() && self.children.is_empty()
    }

    /// Return usage statistics for the trie rooted at this node.
    pub fn stats(&self) -> Stats
    where
        Self: StrideOps,
    {
        self.descendant_nodes(true)
            .fold(Stats::default(), |mut stats, (_path, node)| {
                let (leaves, fringes) = node.direct_children().fold(
                    (0, 0),
                    |(leaves, fringes), (_, child)| match child {
                        Child::Fringe(..) => (leaves, fringes + 1),
                        Child::Leaf { .. } => (leaves + 1, fringes),
                        _ => (leaves, fringes),
                    },
                );

                stats.node_count += 1;

                stats.prefix_count += node.prefix_count();
                stats.child_count += node.child_count();

                stats.leaf_count += leaves;
                stats.fringe_count += fringes;

                stats
            })
    }
}

impl<T, C> StrideBase for Node<T, C>
where
    T: 'static,
    C: Storage + ?Sized,
{
    type T = T;
}

impl<T, C> PrefixReadOps for Node<T, C>
where
    T: 'static,
    C: Storage + ?Sized,
{
    fn prefix_bitset(&self) -> &Bitset256 {
        self.prefixes.bitset()
    }

    fn prefix_count(&self) -> usize {
        self.prefixes.len()
    }

    fn lookup_index(&self, idx: BaseIndex) -> Option<(BaseIndex, &Self::T)> {
        let top = self.prefixes.intersection_top(crate::lpm(idx).borrow())?;
        Some((BaseIndex::try_new(top)?, self.prefixes.get(top)?))
    }

    fn get_prefix_exact(&self, idx: BaseIndex) -> Option<&Self::T> {
        self.prefixes.get(idx.get())
    }
}

impl<T, C> PrefixOps for Node<T, C>
where
    T: 'static,
    C: Storage + ?Sized,
{
    fn insert_prefix(&mut self, idx: BaseIndex, value: Self::T) -> Option<Self::T> {
        self.prefixes.insert(idx.into(), value)
    }

    fn remove_prefix(&mut self, idx: BaseIndex) -> Option<Self::T> {
        self.prefixes.remove(idx.into())
    }

    fn get_prefix_exact_mut(&mut self, idx: BaseIndex) -> Option<&mut Self::T> {
        self.prefixes.get_mut(idx.get())
    }
}

impl<T, C> StrideOps for Node<T, C>
where
    T: 'static,
    C: Storage + ?Sized,
{
    fn child_bitset(&self) -> &Bitset256 {
        self.children.bitset()
    }

    fn child_count(&self) -> usize {
        self.children.len()
    }

    fn stats(&self) -> Stats {
        self.stats()
    }

    fn insert_child(
        &mut self,
        addr: u8,
        child: Child<Self, Self::T>,
    ) -> Option<Child<Self, Self::T>> {
        self.children
            .insert(addr, child.map_node(C::new))
            .map(|ret| ret.map_node(C::into_inner))
    }

    fn direct_children(&self) -> impl Iterator<Item = (u8, Child<&Self, &T>)> {
        self.children
            .iter()
            .map(|(addr, child)| (addr, child.as_node_ref::<C, _>()))
    }

    fn remove_child(&mut self, addr: u8) -> Option<Child<Self, Self::T>> {
        self.children
            .remove(addr)
            .map(|ret| ret.map_node(C::into_inner))
    }

    fn get_child(&self, addr: u8) -> Option<Child<&Self, &Self::T>> {
        self.children.get(addr).map(Child::as_node_ref::<C, _>)
    }

    fn get_child_mut(&mut self, addr: u8) -> Option<Child<&mut Self, &mut Self::T>> {
        self.children.get_mut(addr).map(Child::as_node_mut::<C, _>)
    }

    fn direct_prefixes(&self) -> impl Iterator<Item = (BaseIndex, &T)> {
        self.prefixes
            .iter()
            .map(|(idx, value)| (BaseIndex::new(idx), value))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn bart_examples_prefix_crud() {
        let mut node = Node::<usize>::EMPTY;
        let index = BaseIndex::new(32);

        assert_eq!(None, node.insert_prefix(index, 100));
        assert_eq!(1, node.prefix_count());

        assert_eq!(Some(100), node.insert_prefix(index, 111));
        assert_eq!(1, node.prefix_count());
        assert_eq!(Some(111), node.lookup(index).copied());

        assert_eq!(Some(111), node.remove_prefix(index));
        assert_eq!(0, node.prefix_count());
        assert_eq!(None, node.lookup(index));
        assert_eq!(None, node.remove_prefix(index));
    }

    #[test]
    fn bart_examples_contains() {
        let mut node = Node::<()>::EMPTY;
        node.insert_prefix(BaseIndex::new(32), ());

        for idx in [32, 64, 65, 128, 129, 130, 131] {
            assert!(node.supersets_prefix(BaseIndex::new(idx)));
        }

        for idx in [1, 16, 33, 63, 127, 132, 255] {
            assert!(!node.supersets_prefix(BaseIndex::new(idx)));
        }
    }

    #[test]
    fn bart_examples_lookup() {
        let mut node = Node::<usize>::EMPTY;

        node.insert_prefix(BaseIndex::new(32), 1);
        node.insert_prefix(BaseIndex::new(64), 2);

        assert_eq!(Some(&2), node.lookup(BaseIndex::new(128)));
        assert_eq!(
            Some((BaseIndex::new(64), &2)),
            node.lookup_index(BaseIndex::new(128))
        );
        assert_eq!(None, node.lookup(BaseIndex::new(127)));
    }

    #[test]
    fn bart_examples_children_crud() {
        let mut child = Node::<usize>::EMPTY;
        child.insert_prefix(BaseIndex::new(1), 10);

        let mut node = Node::<usize>::EMPTY;
        assert!(node.insert_child(10, Child::Path(child)).is_none());
        assert_eq!(1, node.child_count());

        assert!(node.get_child(10).is_some_and(|c| match c {
            Child::Path(inner) => inner.supersets_prefix(BaseIndex::new(1)),
            _ => false,
        }));

        assert!(node.remove_child(10).is_some());
        assert_eq!(0, node.child_count());
        assert!(node.remove_child(10).is_none());
    }
}
