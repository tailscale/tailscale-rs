use core::fmt::{Debug, Formatter};

use crate::Storage;

/// Entries in a node's `children` array.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Child<Node, T> {
    /// Child containing another node.
    Path(Node),

    /// Path-compressed single descendant.
    ///
    /// If a prefix would be inserted that spans multiple octet strides and
    /// there is no child for the starting octet, it is instead stored as a
    /// single leaf. This is the primary mechanism for path compression.
    Leaf {
        /// The complete prefix for this route.
        prefix: ipnet::IpNet,
        /// Value stored for this route.
        value: T,
    },

    /// Fringe nodes store single /8s for this depth in the trie.
    ///
    /// This can be seen as an optimization over [`Leaf`][Self::Leaf]
    /// for cases where `prefix` lies on this depth's `/8` boundary.
    Fringe(T),
}

impl<Node, T> Debug for Child<Node, T>
where
    Node: Debug,
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Path(inner) => inner.fmt(f),
            Self::Leaf { prefix, value } => {
                write!(f, "Leaf({prefix}: {value:?})")
            }
            Self::Fringe(fringe) => f.debug_tuple("Fringe").field(fringe).finish(),
        }
    }
}

impl<Node, T> Child<&Node, &T> {
    /// When this holds refs, clone the values in the refs to return a
    /// child-of-owned.
    pub fn cloned(self) -> Child<Node, T>
    where
        Node: Clone,
        T: Clone,
    {
        match self {
            Self::Path(n) => Child::Path(n.clone()),
            Self::Leaf { prefix, value } => Child::Leaf {
                prefix,
                value: value.clone(),
            },
            Self::Fringe(value) => Child::Fringe(value.clone()),
        }
    }
}

impl<Node, T> Child<Node, T> {
    /// Convert this ref-to-child into a child-of-ref.
    pub const fn as_ref(&self) -> Child<&Node, &T> {
        match self {
            Self::Path(node) => Child::Path(node),
            Self::Leaf { prefix, value } => Child::Leaf {
                prefix: *prefix,
                value,
            },
            Self::Fringe(t) => Child::Fringe(t),
        }
    }

    /// Convert this ref-mut-to-child into a child-of-ref-mut.
    pub const fn as_mut(&mut self) -> Child<&mut Node, &mut T> {
        match self {
            Self::Path(node) => Child::Path(node),
            Self::Leaf { prefix, value } => Child::Leaf {
                prefix: *prefix,
                value,
            },
            Self::Fringe(t) => Child::Fringe(t),
        }
    }

    /// If this is a path node, apply `f` to the contained value.
    pub fn map_node<Nu>(self, f: impl FnOnce(Node) -> Nu) -> Child<Nu, T> {
        match self {
            Self::Path(node) => Child::Path(f(node)),
            Self::Leaf { prefix, value } => Child::Leaf { prefix, value },
            Self::Fringe(t) => Child::Fringe(t),
        }
    }

    /// Get the value directly contained in this node, if it's a leaf or fringe.
    /// Return `None` iff this is a [`Path`][Child::Path].
    pub fn into_value(self) -> Option<T> {
        match self {
            Child::Leaf { value, .. } | Child::Fringe(value) => Some(value),
            Child::Path(_) => None,
        }
    }

    /// When `Node` is a [`Storage`], this is [`as_ref`][Self::as_ref] except
    /// that it also unwraps the node container type.
    pub fn as_node_ref<C, Inner>(&self) -> Child<&Inner, &T>
    where
        C: Storage<Container<Inner> = Node> + ?Sized,
    {
        self.as_ref().map_node(C::as_ref)
    }

    /// When `Node` is a [`Storage`], this is [`as_mut`][Self::as_mut] except
    /// that it also unwraps the node container type.
    pub fn as_node_mut<C, Inner>(&mut self) -> Child<&mut Inner, &mut T>
    where
        C: Storage<Container<Inner> = Node> + ?Sized,
    {
        self.as_mut().map_node(C::as_mut)
    }

    /// Return the child node if this is a [`Path`][Child::Path].
    pub fn into_node(self) -> Option<Node> {
        match self {
            Child::Path(node) => Some(node),
            _ => None,
        }
    }

    /// Construct a default leaf value for testing.
    #[cfg(test)]
    pub fn dummy_leaf() -> Self
    where
        T: Default,
    {
        Self::Leaf {
            prefix: Default::default(),
            value: Default::default(),
        }
    }

    /// Construct a default fringe value for testing.
    #[cfg(test)]
    pub fn dummy_fringe() -> Self
    where
        T: Default,
    {
        Self::Fringe(Default::default())
    }
}
