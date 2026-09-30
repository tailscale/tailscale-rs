use crate::{
    BaseIndex,
    iptrie::{insert::insert_inner, remove, remove::RemovalInfo, util},
    node::{Child, StrideOps},
};

/// A set of actions that can be taken as part of a call to [`modify`].
#[derive(Debug, Default)]
pub enum RouteModification<T> {
    /// Insert the contained value into the route.
    Insert(T),

    /// Remove the route.
    Remove,

    /// Take no further action on the route. (May modify the route value
    /// in-place.)
    #[default]
    Noop,
}

/// Modify the route at `prefix` using the `modify` closure.
///
/// The closure may return:
///
/// - [`RouteModification::Insert`]: a route will be inserted with the provided
///   value (or replaced if it already exists).
/// - [`RouteModification::Remove`]: the route will be removed (if it exists).
/// - [`RouteModification::Noop`]: the table will not be modified. The closure
///   may modify the value stored in the route (if present).
///
/// If the route was replaced or removed, the return value contains the
/// value that was previously stored.
///
/// Prefer to use [`insert`][crate::iptrie::insert] or
/// [`remove`][crate::iptrie::remove] if  possible; this function is intended as
/// a more-efficient alternative to
/// [`lookup_prefix_exact`][crate::iptrie::lookup_prefix_exact]-then-mutate.
pub fn modify<N>(
    node: &mut N,
    prefix: ipnet::IpNet,
    f: impl FnOnce(Option<&mut N::T>) -> RouteModification<N::T>,
) -> Option<N::T>
where
    N: StrideOps,
{
    let prefix = prefix.trunc();
    let addr = prefix.addr();

    let octets = util::ip_octets(&addr);
    let (ret, removal) = modify_inner(node, octets, &prefix, f);

    if let Some(removal) = removal {
        remove::compress_removal_path(node, removal);
    }

    ret
}

pub fn modify_inner<N>(
    mut node: &mut N,
    octets: &[u8],
    prefix: &ipnet::IpNet,
    f: impl FnOnce(Option<&mut N::T>) -> RouteModification<N::T>,
) -> (Option<N::T>, Option<RemovalInfo<N::T>>)
where
    N: StrideOps,
{
    let mut compression_root_depth: usize = 0;
    let (stride_count, overflow_bits) = util::stride_count_and_overflow(prefix);

    for (depth, octet) in octets.iter().copied().enumerate() {
        // Last full octet from the prefix, entry is in current node's prefix
        // table if it exists
        if depth == stride_count {
            let idx = BaseIndex::from_prefix(octet, overflow_bits);

            let val = node.get_prefix_exact_mut(idx);
            return match f(val) {
                // delete
                RouteModification::Remove => {
                    let ret = node.remove_prefix(idx);
                    let removal_info = remove::try_remove_last_child(
                        node,
                        octets,
                        depth,
                        prefix.addr().is_ipv4(),
                        compression_root_depth,
                    );

                    (ret, removal_info)
                }
                // insert
                RouteModification::Insert(t) => {
                    let ret = node.insert_prefix(idx, t);
                    (ret, None)
                }
                // no-op or modify-in-place
                RouteModification::Noop => (None, None),
            };
        }

        let Some(child) = node.get_child_mut(octet) else {
            // No matching child: call `f` to decide if we should insert
            return match f(None) {
                RouteModification::Remove | RouteModification::Noop => (None, None),
                RouteModification::Insert(t) => {
                    if util::is_fringe(depth, prefix) {
                        node.insert_child(octet, Child::Fringe(t));
                    } else {
                        node.insert_child(
                            octet,
                            Child::Leaf {
                                value: t,
                                prefix: *prefix,
                            },
                        );
                    };

                    (None, None)
                }
            };
        };

        match child {
            // have a leaf at this address, but it doesn't match our prefix: our node doesn't exist.
            // check what `f` wants to do and punt to insert_inner if we need to create.
            Child::Leaf {
                prefix: leaf_prefix,
                ..
            } if leaf_prefix != *prefix => {
                return match f(None) {
                    RouteModification::Noop | RouteModification::Remove => (None, None),
                    RouteModification::Insert(t) => (insert_inner(node, *prefix, t, depth), None),
                };
            }
            // have a fringe at this address, but it doesn't match our prefix: our node doesn't
            // exist. check what `f` wants to do and punt to insert_inner if we need to
            // create.
            Child::Fringe(..) if !util::is_fringe(depth, prefix) => {
                return match f(None) {
                    RouteModification::Noop | RouteModification::Remove => (None, None),
                    RouteModification::Insert(t) => (insert_inner(node, *prefix, t, depth), None),
                };
            }

            // this is the fringe or leaf node that we're supposed to put our value in, if we have
            // one
            Child::Fringe(value) | Child::Leaf { value, .. } => {
                return match f(Some(value)) {
                    RouteModification::Noop => (None, None),
                    RouteModification::Insert(t) => {
                        let insert_val = if util::is_fringe(depth, prefix) {
                            node.insert_child(octet, Child::Fringe(t))
                        } else {
                            node.insert_child(
                                octet,
                                Child::Leaf {
                                    value: t,
                                    prefix: *prefix,
                                },
                            )
                        };

                        (insert_val.unwrap().into_value(), None)
                    }
                    RouteModification::Remove => {
                        let ret = node.remove_child(octet).unwrap().into_value();
                        let removal_info = remove::try_remove_last_child(
                            node,
                            octets,
                            depth,
                            prefix.addr().is_ipv4(),
                            compression_root_depth,
                        );

                        (ret, removal_info)
                    }
                };
            }
            Child::Path(..) => {}
        }

        // The new current node can't be deleted even if one of its children is, and is
        // therefore a new candidate compression root.
        let is_deletable = node.child_count() == 1 && node.prefix_count() == 0;
        if !is_deletable {
            compression_root_depth = depth;
        }

        // the unwraps are safe because we know that the child must be full
        let root = node.get_child_mut(octet).unwrap();
        node = root.into_node().unwrap();
    }

    (None, None)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::DefaultNode;

    fn test_insert<T>(
        node: &mut DefaultNode<T>,
        val: T,
        pfx: &str,
        want_pfxs: usize,
        want_leaves: usize,
        want_fringes: usize,
    ) where
        T: Copy + PartialEq + core::fmt::Debug + 'static,
    {
        assert_eq!(
            None,
            modify(node, crate::pfx!(pfx), |entry| {
                assert_eq!(None, entry);
                RouteModification::Insert(val)
            })
        );
        assert_eq!(
            Some(val),
            modify(node, crate::pfx!(pfx), |entry| {
                assert_eq!(Some(val), entry.copied());
                RouteModification::Insert(val)
            })
        );

        let stats = node.stats();
        assert_eq!(
            (want_pfxs, want_leaves, want_fringes),
            (stats.prefix_count, stats.leaf_count, stats.fringe_count),
            "{node:#?}",
        );
    }

    fn test_remove<T>(
        node: &mut DefaultNode<T>,
        expect: T,
        pfx: &str,
        want_pfxs: usize,
        want_leaves: usize,
        want_fringes: usize,
    ) where
        T: Copy + PartialEq + core::fmt::Debug + 'static,
    {
        assert_eq!(
            Some(expect),
            modify(node, crate::pfx!(pfx), |entry| {
                assert_eq!(Some(expect), entry.copied());
                RouteModification::Remove
            })
        );
        assert_eq!(
            None,
            modify(node, crate::pfx!(pfx), |entry| {
                assert_eq!(None, entry.copied());
                RouteModification::Remove
            })
        );

        let stats = node.stats();
        assert_eq!(
            (want_pfxs, want_leaves, want_fringes),
            (stats.prefix_count, stats.leaf_count, stats.fringe_count),
            "{node:#?}",
        );
    }

    #[test]
    fn basic() {
        let node = &mut DefaultNode::EMPTY.clone();
        assert!(node.is_empty());

        test_insert(node, 3, "0.0.0.0/0", 1, 0, 0);
        test_insert(node, 4, "0.0.0.0/1", 2, 0, 0);
        test_insert(node, 5, "0.0.0.0/8", 2, 0, 1);
        test_insert(node, 6, "1.0.32.0/23", 2, 1, 1);
        test_insert(node, 7, "2.0.0.0/8", 2, 1, 2);

        modify(node, crate::pfx!("2.0.0.0/8"), |val| {
            assert_eq!(Some(&mut 7), val);
            *val.unwrap() = 9;
            RouteModification::Noop
        });

        test_remove(node, 9, "2.0.0.0/8", 2, 1, 1);
        test_remove(node, 3, "0.0.0.0/0", 1, 1, 1);
        test_remove(node, 5, "0.0.0.0/8", 1, 1, 0);
        test_remove(node, 6, "1.0.32.0/23", 1, 0, 0);
        test_remove(node, 4, "0.0.0.0/1", 0, 0, 0);

        assert!(node.is_empty());
    }

    #[test]
    fn nonmatching_fringe_exists() {
        let node = &mut DefaultNode::EMPTY.clone();

        test_insert(node, 3, "0.0.0.0/8", 0, 0, 1);
        test_insert(node, 4, "0.1.2.0/22", 1, 1, 0);
    }

    #[test]
    fn nonmatching_leaf_exists() {
        let node = &mut DefaultNode::EMPTY.clone();

        test_insert(node, 3, "0.2.0.0/15", 0, 1, 0);
        test_insert(node, 4, "0.1.2.0/22", 1, 1, 0);
    }
}
