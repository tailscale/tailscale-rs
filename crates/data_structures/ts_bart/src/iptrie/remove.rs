use crate::{
    BaseIndex,
    iptrie::{insert, util},
    node::{Child, StrideOps},
};

/// Remove the given `prefix` from the trie rooted at `node`.
pub fn remove<N>(node: &mut N, prefix: ipnet::IpNet) -> Option<N::T>
where
    N: StrideOps,
{
    let prefix = prefix.trunc();

    let addr = prefix.addr();
    let octets = util::ip_octets(&addr);
    let (ret, removal) = remove_inner(node, octets, &prefix);

    if let Some(removal) = removal {
        compress_removal_path(node, removal);
    }

    ret
}

fn remove_inner<Node>(
    mut node: &mut Node,
    octets: &[u8],
    prefix: &ipnet::IpNet,
) -> (Option<Node::T>, Option<RemovalInfo<Node::T>>)
where
    Node: StrideOps,
{
    let mut compression_root_depth: usize = 0;
    let (stride_count, overflow_bits) = util::stride_count_and_overflow(prefix);

    for (depth, octet) in octets.iter().copied().enumerate() {
        if depth == stride_count {
            let ret = node.remove_prefix(BaseIndex::from_prefix(octet, overflow_bits));
            let removal_info = try_remove_last_child(
                node,
                octets,
                depth,
                prefix.addr().is_ipv4(),
                compression_root_depth,
            );

            return (ret, removal_info);
        }

        let Some(child) = node.get_child(octet) else {
            return (None, None);
        };

        let has_immediate_child = match child {
            // have a leaf at this address, but it doesn't match, bail
            Child::Leaf {
                prefix: ref leaf_prefix,
                ..
            } if leaf_prefix != prefix => return (None, None),
            // have a fringe at this address, but it doesn't match, bail
            Child::Fringe(..) if !util::is_fringe(depth, prefix) => return (None, None),
            Child::Fringe(..) | Child::Leaf { .. } => true,
            Child::Path(..) => false,
        };

        if has_immediate_child {
            let ret = node.remove_child(octet).unwrap().into_value();
            let removal_info = try_remove_last_child(
                node,
                octets,
                depth,
                prefix.addr().is_ipv4(),
                compression_root_depth,
            );

            return (ret, removal_info);
        }

        // The new current node can't be deleted even if one of its children is, and is
        // therefore a new candidate compression root.
        let is_deletable = node.child_count() == 1 && node.prefix_count() == 0;
        if !is_deletable {
            compression_root_depth = depth;
        }

        // the unwraps are safe because we know that !has_immediate_child, which is only
        // the case if this is a full child
        let root = node.get_child_mut(octet).unwrap();
        node = root.into_node().unwrap();
    }

    (None, None)
}

pub struct RemovalInfo<T> {
    value: T,
    compression_root_depth: usize,
    node_prefix: ipnet::IpNet,
}

pub fn try_remove_last_child<Node>(
    node: &mut Node,
    octets: &[u8],
    depth: usize,
    ipv4: bool,
    compression_root_depth: usize,
) -> Option<RemovalInfo<Node::T>>
where
    Node: StrideOps,
{
    if depth == compression_root_depth {
        // if we're current can't compress higher than the compression root, bail
        return None;
    }

    match (node.child_count(), node.prefix_count()) {
        (0, 1) => {
            let idx = node.prefix_bitset().first_set().unwrap();
            let idx = BaseIndex::new(idx as _);
            let value = node.remove_prefix(idx).unwrap();

            Some(RemovalInfo {
                value,
                node_prefix: util::prefix_from_path(octets, depth, ipv4, idx),
                compression_root_depth,
            })
        }
        (1, 0) => {
            let addr = node.child_bitset().first_set().unwrap() as u8;

            if let Child::Path(..) = node.get_child(addr).unwrap() {
                return None;
            }

            let (prefix, value) = match node.remove_child(addr).unwrap() {
                Child::Fringe(val) => {
                    let prefix = util::fringe_prefix(octets, depth, ipv4, addr);
                    (prefix, val)
                }
                Child::Leaf { prefix, value } => (prefix, value),
                _ => unreachable!(),
            };

            Some(RemovalInfo {
                value,
                node_prefix: prefix,
                compression_root_depth,
            })
        }
        _ => None,
    }
}

pub fn compress_removal_path<Node>(root: &mut Node, info: RemovalInfo<Node::T>)
where
    Node: StrideOps,
{
    // a compression event triggered by a deletion always occurs when the
    // tree has the following form (post-deletion):
    //
    //    ROOT -- .. -- COMPRESSION_ROOT -- DELETE -- .. -- DELETE -> IMMEDIATE
    //
    // where all the nodes shown other than IMMEDIATE are path nodes. on
    // deletion, IMMEDIATE will move up to be an immediate child (leaf, fringe,
    // or prefix) at COMPRESSION_ROOT:
    //
    //    ROOT -- .. -- COMPRESSION_ROOT -> IMMEDIATE
    //
    // to be compressed, the >0 DELETE nodes must all have exactly one child and
    // zero prefixes. the COMPRESSION_ROOT must have any number more than this:
    // any node where $NCHILD + $NPREFIX > 1 is a candidate compression root
    // (and NOT a DELETE node).
    //
    // we can observe these properties as we're descending the tree in remove() and
    // simply track the depth at which the most recent COMPRESSION_ROOT we've
    // seen occurred. after we remove the target prefix, if the current node has
    // exactly one immediate child (and no prefixes), we also delete that child and
    // return it as part of the RemovalInfo. now the whole DELETE node-string can be
    // deleted from COMPRESSION_ROOT in one shot and the value we returned
    // reinserted there as a leaf.

    let mut compression_root = root;
    let addr = info.node_prefix.addr();

    let octets = util::ip_octets(&addr);

    for &octet in &octets[..info.compression_root_depth] {
        let root = compression_root.get_child_mut(octet).unwrap();
        compression_root = root.into_node().unwrap();
    }

    let addr = octets[info.compression_root_depth];
    let removed = compression_root.remove_child(addr);
    assert!(removed.is_some());

    insert::insert_inner(
        compression_root,
        info.node_prefix,
        info.value,
        info.compression_root_depth,
    );
}
