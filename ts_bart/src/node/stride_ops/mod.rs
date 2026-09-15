use ts_bitset::Bitset256;

use crate::{BaseIndex, node::Child};

mod prefix;

pub use prefix::{NodePrefixIter, PrefixOps, PrefixOpsExt, PrefixReadOps};

/// Stats about a node and its descendants.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Stats {
    /// The total number of direct prefixes: does not count leaves and fringes.
    pub prefix_count: usize,
    /// The total number of parent-child node relations.
    pub child_count: usize,
    /// The total number of full nodes in the trie.
    pub node_count: usize,
    /// The total number of leaf nodes.
    pub leaf_count: usize,
    /// The total number of fringe nodes.
    pub fringe_count: usize,
}

/// Base trait for stride operations.
pub trait StrideBase {
    /// The kind of value held inside nodes.
    type T: 'static;
}

impl<T> StrideBase for &T
where
    T: StrideBase + ?Sized,
{
    type T = T::T;
}

impl<T> StrideBase for &mut T
where
    T: StrideBase + ?Sized,
{
    type T = T::T;
}

/// Single-stride operations supported by a trie node.
pub trait StrideOps: Default + PrefixOps {
    // The `Default` bound is needed to construct empty values of this type for trie
    // operations.

    /// Iterate the prefixes directly contained in this node.
    fn direct_prefixes(&self) -> impl Iterator<Item = (BaseIndex, &Self::T)>;

    /// Get a reference to the child bitset.
    fn child_bitset(&self) -> &Bitset256;

    /// Get a child node by address.
    fn get_child(&self, addr: u8) -> Option<Child<&Self, &Self::T>>;
    /// Get a mutable reference to a child node by address.
    fn get_child_mut(&mut self, addr: u8) -> Option<Child<&mut Self, &mut Self::T>>;
    /// Insert a child node at the given address.
    fn insert_child(
        &mut self,
        addr: u8,
        child: Child<Self, Self::T>,
    ) -> Option<Child<Self, Self::T>>;
    /// Remove a child node at the given address.
    fn remove_child(&mut self, addr: u8) -> Option<Child<Self, Self::T>>;
    /// Iterate the direct children of this node.
    fn direct_children(&self) -> impl Iterator<Item = (u8, Child<&Self, &Self::T>)>;

    /// Get the number of direct children of this node.
    fn child_count(&self) -> usize {
        self.child_bitset().count_ones()
    }

    /// Calculate trie occupancy stats for this node and its descendants.
    fn stats(&self) -> Stats;
}

mod private {
    pub trait Sealed {}
}

/// Extension methods for nodes implementing [`StrideOps`].
pub trait StrideOpsExt: StrideOps + private::Sealed {
    /// Report whether the node has no children and prefixes.
    fn is_empty(&self) -> bool {
        self.prefix_count() == 0 && self.child_count() == 0
    }

    /// Return this node with the given child added.
    ///
    /// Meant as sugar for easily constructing nodes directly.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_bart::{DefaultNode, Child, StrideOps, StrideOpsExt};
    /// DefaultNode::EMPTY.with_child(
    ///     0,
    ///     DefaultNode::EMPTY
    ///         .with_child(1, Child::Fringe(123))
    ///         .into_child(),
    /// );
    /// ```
    fn with_child(mut self, addr: u8, child: impl Into<Child<Self, Self::T>>) -> Self {
        self.insert_child(addr, child.into());
        self
    }

    /// Wrap this node in a [`Child::Path`].
    fn into_child(self) -> Child<Self, Self::T> {
        Child::Path(self)
    }
}

impl<T> private::Sealed for T where T: StrideOps {}
impl<T> StrideOpsExt for T where T: StrideOps {}
