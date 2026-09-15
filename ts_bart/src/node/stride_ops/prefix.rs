use ts_bitset::Bitset256;

use crate::{BaseIndex, StrideBase};

/// Trie node operations for accessing and mutating prefixes.
pub trait PrefixOps: PrefixReadOps {
    /// Insert a value at the given base index.
    fn insert_prefix(&mut self, idx: BaseIndex, value: Self::T) -> Option<Self::T>;
    /// Remove the value for the given base index.
    fn remove_prefix(&mut self, idx: BaseIndex) -> Option<Self::T>;
    /// Get a mutable reference to the prefix value that matches the given
    /// index exactly.
    fn get_prefix_exact_mut(&mut self, idx: BaseIndex) -> Option<&mut Self::T>;
}

static_assertions::assert_obj_safe!(PrefixOps<T = ()>);

impl<T> PrefixOps for &mut T
where
    T: PrefixOps + ?Sized,
{
    fn insert_prefix(&mut self, idx: BaseIndex, value: Self::T) -> Option<Self::T> {
        (*self).insert_prefix(idx, value)
    }

    fn remove_prefix(&mut self, idx: BaseIndex) -> Option<Self::T> {
        (*self).remove_prefix(idx)
    }

    fn get_prefix_exact_mut(&mut self, idx: BaseIndex) -> Option<&mut Self::T> {
        (*self).get_prefix_exact_mut(idx)
    }
}

/// Read-only operations on prefixes stored in nodes.
pub trait PrefixReadOps: StrideBase {
    /// Get a reference to the prefix bitset.
    fn prefix_bitset(&self) -> &Bitset256;
    /// Lookup the prefix value that covers the given index.
    fn lookup_index(&self, idx: BaseIndex) -> Option<(BaseIndex, &Self::T)>;
    /// Get a reference to the prefix value that matches the given index
    /// exactly.
    fn get_prefix_exact(&self, idx: BaseIndex) -> Option<&Self::T>;

    /// Get the number of prefixes in this node.
    fn prefix_count(&self) -> usize {
        self.prefix_bitset().count_ones()
    }
}

static_assertions::assert_obj_safe!(PrefixReadOps<T = ()>);

impl<T> PrefixReadOps for &T
where
    T: PrefixReadOps + ?Sized,
{
    fn prefix_bitset(&self) -> &Bitset256 {
        (*self).prefix_bitset()
    }

    fn lookup_index(&self, idx: BaseIndex) -> Option<(BaseIndex, &Self::T)> {
        (*self).lookup_index(idx)
    }

    fn get_prefix_exact(&self, idx: BaseIndex) -> Option<&Self::T> {
        (*self).get_prefix_exact(idx)
    }
}

impl<T> PrefixReadOps for &mut T
where
    T: PrefixReadOps + ?Sized,
{
    fn prefix_bitset(&self) -> &Bitset256 {
        (**self).prefix_bitset()
    }

    fn lookup_index(&self, idx: BaseIndex) -> Option<(BaseIndex, &Self::T)> {
        (**self).lookup_index(idx)
    }

    fn get_prefix_exact(&self, idx: BaseIndex) -> Option<&Self::T> {
        (**self).get_prefix_exact(idx)
    }
}

/// Extension methods relating to prefixes.
pub trait PrefixOpsExt: PrefixOps {
    /// Report whether this node's prefix set covers the prefix with the given
    /// index. It does not need to match exactly, `idx` just needs to be
    /// contained in this node's prefix set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_bart::{DefaultNode, BaseIndex, PrefixOps, PrefixOpsExt};
    /// let idx = BaseIndex::from_prefix(0, 2);
    /// let node = DefaultNode::EMPTY.with_prefix(idx, 32);
    /// assert!(node.supersets_prefix(idx)); // exact match
    /// // parent is not contained
    /// assert!(!node.supersets_prefix(idx.parent().unwrap()));
    /// // child indexes are contained
    /// let (child1, child2) = idx.children().unwrap();
    /// assert!(node.supersets_prefix(child1));
    /// assert!(node.supersets_prefix(child2));
    /// ```
    fn supersets_prefix(&self, idx: BaseIndex) -> bool {
        use core::borrow::Borrow;
        self.prefix_bitset().intersects(crate::lpm(idx).borrow())
    }

    /// Lookup a value by [`BaseIndex`].
    ///
    /// This is sugar over [`PrefixReadOps::lookup_index`] to only return the
    /// matched value.
    fn lookup(&self, idx: BaseIndex) -> Option<&Self::T> {
        let (_idx, ret) = self.lookup_index(idx)?;
        Some(ret)
    }

    /// Return this node with the given prefix added.
    ///
    /// Sugar for easily constructing nodes directly.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_bart::{DefaultNode, BaseIndex, PrefixOps, PrefixReadOps, PrefixOpsExt};
    /// let idx = BaseIndex::from_prefix(1, 1);
    /// let node = DefaultNode::EMPTY.with_prefix(idx, 12);
    /// assert_eq!(node.get_prefix_exact(idx).copied(), Some(12));
    /// ```
    fn with_prefix(mut self, idx: BaseIndex, value: Self::T) -> Self
    where
        Self: Sized,
    {
        self.insert_prefix(idx, value);
        self
    }

    /// Iterate prefixes in this node matching `octet`.
    ///
    /// The prefixes are returned in reverse order (most specific to least specific).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_bart::{BaseIndex, DefaultNode, PrefixOpsExt};
    /// let zero_pfx = BaseIndex::from_prefix(0, 0);
    /// let second_half_pfx = BaseIndex::from_prefix(128, 1);
    ///
    /// let node = ts_bart::DefaultNode::EMPTY
    ///     .with_prefix(zero_pfx, 123)
    ///     .with_prefix(second_half_pfx, 456);
    ///
    /// assert_eq!(vec![(zero_pfx, &123)], node.matching_prefixes(1).collect::<Vec<_>>());
    /// assert_eq!(vec![(second_half_pfx, &456), (zero_pfx, &123)], node.matching_prefixes(200).collect::<Vec<_>>());
    /// ```
    fn matching_prefixes(&self, octet: u8) -> NodePrefixIter<'_, Self::T>
    where
        Self: Sized,
    {
        NodePrefixIter::for_octet(self, octet)
    }
}

impl<T> PrefixOpsExt for T where T: PrefixOps + ?Sized {}

/// Iterator for matching prefixes in a single node.
pub struct NodePrefixIter<'n, T> {
    node: &'n dyn PrefixReadOps<T = T>,
    yield_state: Bitset256,
}

impl<'n, T> NodePrefixIter<'n, T>
where
    T: 'static,
{
    /// Construct a [`NodePrefixIter`] yielding the prefixes stored in `node` that
    /// cover `octet`, yielded in reverse order (most to least specific).
    pub fn for_octet(node: &'n dyn PrefixReadOps<T = T>, octet: u8) -> Self {
        use core::borrow::Borrow;

        let idx = BaseIndex::from_pfx_7(octet);

        let mut yield_state = *node.prefix_bitset();
        yield_state.intersect_inplace(crate::lpm(idx).borrow());

        Self { node, yield_state }
    }
}

impl<'n, T> Iterator for NodePrefixIter<'n, T>
where
    T: 'static,
{
    type Item = (BaseIndex, &'n T);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(bit) = self.yield_state.last_set() {
            self.yield_state.clear(bit);

            let index = BaseIndex::new(bit as _);
            if let Some(val) = self.node.get_prefix_exact(index) {
                return Some((index, val));
            }
        }

        None
    }
}

impl<T> core::iter::FusedIterator for NodePrefixIter<'_, T> where T: 'static {}
