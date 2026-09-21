use crate::{
    BaseIndex, StrideOpsExt,
    iptrie::util,
    node::{Child, StrideOps},
};

/// Insert a route into the trie rooted at `node` with the given prefix.
pub fn insert<N>(node: &mut N, prefix: ipnet::IpNet, val: N::T) -> Option<N::T>
where
    N: StrideOps,
{
    // Wrapper to avoid exposing the depth parameter
    insert_inner(node, prefix.trunc(), val, 0)
}

pub fn insert_inner<N>(
    mut node: &mut N,
    prefix: ipnet::IpNet,
    val: N::T,
    depth: usize,
) -> Option<N::T>
where
    N: StrideOps,
{
    let (pfx_full_strides, pfx_overflow_bits) = util::stride_count_and_overflow(&prefix);

    for (depth, &octet) in util::ip_octets(&prefix.addr())
        .iter()
        .enumerate()
        .skip(depth)
    {
        if depth == pfx_full_strides {
            return node.insert_prefix(BaseIndex::from_prefix(octet, pfx_overflow_bits), val);
        }

        if !node.child_bitset().test(octet as _) {
            let child = if util::is_fringe(depth, &prefix) {
                Child::Fringe(val)
            } else {
                Child::Leaf { prefix, value: val }
            };

            return node.insert_child(octet, child)?.into_value();
        }

        // Child replacement/recursion is done in three phases:
        //
        // - If the child at `octet` is a match for target prefix, the child already
        //   exists, just replace the value and return.
        // - If it's not a match and it's not a path node, it needs to be upgraded to
        //   one, because there's now more than one prefix under the same address at
        //   this depth. Remove the child, replace it with a path node, then reinsert
        //   the old route value into the new child.
        // - Now the child must be a path node: descend into it.
        //
        // The phases need to be separate in order for the &mut borrow to the child to
        // be released before manipulating the current node.

        // invariant: child is present (bitset test succeeded)
        let replace_child: bool = match node.get_child_mut(octet).unwrap() {
            Child::Leaf {
                prefix: leaf_pfx,
                value: leaf_value,
            } if prefix == leaf_pfx => {
                return Some(core::mem::replace(leaf_value, val));
            }
            Child::Fringe(old) if util::is_fringe(depth, &prefix) => {
                return Some(core::mem::replace(old, val));
            }

            Child::Leaf { .. } => true,
            Child::Fringe(..) => true,

            Child::Path(..) => false,
        };

        if replace_child {
            // invariant: child is still present, so we must be able to replace it
            let removed = node.insert_child(octet, N::default().into_child()).unwrap();

            let Some(Child::Path(n)) = node.get_child_mut(octet) else {
                unreachable!();
            };

            match removed {
                Child::Fringe(old) => {
                    n.insert_prefix(BaseIndex::new(1), old);
                }
                Child::Leaf {
                    prefix: leaf_prefix,
                    value: leaf_value,
                } => {
                    // Recursive call: known to be depth 1 because the node was just inserted and
                    // is empty.
                    insert_inner(n, leaf_prefix, leaf_value, depth + 1);
                }

                _ => unreachable!(),
            }
        }

        // invariant: child is present _and_ a path node
        let next = node.get_child_mut(octet).unwrap().into_node().unwrap();
        node = next;
    }

    None
}
