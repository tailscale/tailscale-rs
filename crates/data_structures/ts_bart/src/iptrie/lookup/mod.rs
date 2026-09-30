use core::net::IpAddr;

use crate::{
    BaseIndex, PrefixReadOps, iptrie,
    iptrie::util,
    node::{Child, StrideOps},
};

mod iter;

pub use iter::LookupIter;

/// Lookup the route entry for `prefix` exactly (supernets do not match).
pub fn lookup_prefix_exact<N>(mut node: &N, prefix: ipnet::IpNet) -> Option<&N::T>
where
    N: StrideOps,
{
    let (last_octet_plus_one, last_bits) = util::stride_count_and_overflow(&prefix);

    for (depth, &octet) in util::ip_octets(&prefix.addr()).iter().enumerate() {
        if depth == last_octet_plus_one {
            return node.get_prefix_exact(BaseIndex::from_prefix(octet, last_bits));
        }

        match node.get_child(octet)? {
            Child::Path(child) => {
                node = child;
                continue;
            }
            Child::Leaf {
                prefix: leaf_prefix,
                value,
            } => {
                if prefix == leaf_prefix {
                    return Some(value);
                }
            }
            Child::Fringe(val) => {
                if util::is_fringe(depth, &prefix) {
                    return Some(val);
                }
            }
        }

        return None;
    }

    unreachable!()
}

/// Lookup the route entry (if any) that covers `addr`.
pub fn lookup_address<N>(mut node: &N, addr: IpAddr) -> Option<&N::T>
where
    N: StrideOps,
{
    // PERF(npry): semantically, this function is just `lookup_address_all(node, addr).next()`.
    // However, writing it like that compromises the benchmarks for this function by 30-40%.
    // Hunch on the cause is the direct returns from the Child::Leaf and Child::Fringe cases, as
    // compared to setting the child field on the iterator and having to check it on the first call
    // to `next`.

    let mut stack =
        heapless::Vec::<(&dyn PrefixReadOps<T = N::T>, u8), { iptrie::MAX_DEPTH }>::new();

    for &octet in util::ip_octets(&addr) {
        stack.push((node, octet)).ok().unwrap();

        let Some(child) = node.get_child(octet) else {
            break;
        };

        match child {
            Child::Path(n) => node = n,
            Child::Fringe(val) => return Some(val),
            Child::Leaf { prefix, value } => {
                if prefix.contains(&addr) {
                    return Some(value);
                }

                break;
            }
        }
    }

    let mut pfx_iter_state = None;
    iter::walk_stack(&mut stack, &mut pfx_iter_state)
}

/// Lookup all route entries (if any) that cover `addr`.
///
/// The iterator yields items in reverse prefix length order (most-specific to
/// least-specific).
///
/// # Examples
///
/// ```rust
/// # use ts_bart::{BaseIndex, PrefixOps, PrefixReadOps, PrefixOpsExt, StrideOpsExt};
/// let node = ts_bart::DefaultNode::EMPTY
///     .with_prefix(BaseIndex::from_prefix(0, 0), 3)
///     .with_prefix(BaseIndex::from_pfx_7(123), 2)
///     .with_child(123, ts_bart::DefaultNode::EMPTY.with_prefix(BaseIndex::from_prefix(4, 6), 1).into_child());
///
/// let matches = ts_bart::iptrie::lookup_address_all(&node, "123.4.0.0".parse().unwrap());
/// assert_eq!(vec![1, 2, 3], matches.copied().collect::<Vec<_>>());
/// ```
pub fn lookup_address_all<N>(mut node: &N, addr: IpAddr) -> LookupIter<'_, N::T>
where
    N: StrideOps,
{
    let mut iter = LookupIter::default();

    for &octet in util::ip_octets(&addr) {
        iter.stack.push((node, octet)).ok().unwrap();

        let Some(child) = node.get_child(octet) else {
            break;
        };

        match child {
            Child::Path(n) => node = n,
            Child::Fringe(val) => {
                iter.value = Some(val);
                break;
            }
            Child::Leaf { prefix, value } => {
                if prefix.contains(&addr) {
                    iter.value = Some(value);
                }
                break;
            }
        }
    }

    iter
}

/// Lookup the route that best matches `prefix`.
pub fn lookup_prefix_lpm<N>(mut node: &N, prefix: ipnet::IpNet) -> Option<(ipnet::IpNet, &N::T)>
where
    N: StrideOps,
{
    // PERF(npry): bart-go also has a flag as an argument to this function that
    // selects whether to return the matched prefix or not. I took that out as
    // the result of benchmarking: returning Option<Option<IpNet>, &T>, which
    // would be the natural Rust-y way to express the return type, impedes NRVO
    // -- the benchmark for the return-lpm variant ends up spending most of its
    // time in a stack-to-stack copy of the resulting prefix because the
    // inner Option<IpNet> can't be assigned into the resulting IpNet.
    // Unconditionally returning the matched prefix actually saves about ~15%
    // for the lpm-return case, and doesn't meaningfully affect timing for the
    // non-lpm-return case.

    let prefix = prefix.trunc();
    let mut stack = heapless::Vec::<(&N, u8, usize), { iptrie::MAX_DEPTH }>::new();

    let (last_octet_plus_one, last_bits) = util::stride_count_and_overflow(&prefix);

    for (depth, &octet) in util::ip_octets(&prefix.addr()).iter().enumerate() {
        if depth > last_octet_plus_one {
            break;
        }

        stack.push((node, octet, depth)).ok().unwrap();

        let Some(child) = node.get_child(octet) else {
            break;
        };

        match child {
            Child::Path(n) => node = n,
            Child::Leaf { prefix, value } => {
                if prefix.prefix_len() > prefix.prefix_len() || !prefix.contains(&prefix.addr()) {
                    break;
                }

                return Some((prefix, value));
            }
            Child::Fringe(val) => {
                let fringe_prefix_len = (depth + 1) << 3;
                if fringe_prefix_len > prefix.prefix_len() as usize {
                    break;
                }

                let fringe_prefix = ipnet::IpNet::new_assert(prefix.addr(), fringe_prefix_len as _);
                return Some((fringe_prefix, val));
            }
        }
    }

    while let Some((node, octet, depth)) = stack.pop() {
        if node.prefix_count() == 0 {
            continue;
        }

        let idx = if depth == last_octet_plus_one {
            BaseIndex::from_prefix(octet, last_bits)
        } else {
            BaseIndex::from_pfx_7(octet)
        };

        let Some((top, val)) = node.lookup_index(idx) else {
            continue;
        };

        let lpm_prefix = ipnet::IpNet::new_assert(prefix.addr(), top.prefix_bits(depth));
        return Some((lpm_prefix, val));
    }

    None
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::DefaultNode;

    #[test]
    fn lookup() {
        let mut node = DefaultNode::EMPTY;

        iptrie::insert(&mut node, crate::pfx!("0.0.0.0/0"), 2);

        let matches = lookup_address_all(&node, "1.2.3.4".parse().unwrap());
        assert_eq!(
            alloc::vec![2],
            matches.copied().collect::<alloc::vec::Vec<_>>()
        );

        iptrie::insert(&mut node, crate::pfx!("127.0.0.0/16"), 1);

        let matches = lookup_address_all(&node, "127.0.1.2".parse().unwrap());
        assert_eq!(
            alloc::vec![1, 2],
            matches.copied().collect::<alloc::vec::Vec<_>>()
        );
    }
}
