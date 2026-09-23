//! Operations for multi-level tries of IP-addressed nodes.
//!
//! Implementations assume that they are operating on the root of a trie,
//! i.e. depth 0.
//!
//! Strictly depends on the single-/stride-layer operations as abstracted by
//! [`StrideOps`].

use core::net::IpAddr;

use crate::{
    base_index::BaseIndex,
    node::{Child, PrefixOpsExt, StrideOps},
};

mod insert;
mod lookup;
mod modify;
mod remove;
pub mod util;

pub use insert::insert;
pub use lookup::*;
pub use modify::{RouteModification, modify};
pub use remove::remove;

/// The maximum depth of a path through an octet tree.
pub const MAX_DEPTH: usize = 16;

/// A path through tree octets.
pub type StridePath = [u8; MAX_DEPTH];

/// Report whether `ip` is covered by a route in the trie rooted at `node`.
///
/// # Examples
///
/// ```rust
/// # use ts_bart::{BaseIndex, iptrie::contains, StrideOpsExt, PrefixOpsExt};
/// // Maps 0.0.0.0/4 => 12
/// let node = ts_bart::DefaultNode::EMPTY.with_prefix(BaseIndex::from_prefix(0, 4), 12);
///
/// assert!(contains(&node, "0.1.2.3".parse().unwrap()));
/// assert!(!contains(&node, "128.1.2.3".parse().unwrap()));
/// ```
pub fn contains<N>(mut node: &N, ip: IpAddr) -> bool
where
    N: StrideOps,
{
    for &octet in util::ip_octets(&ip) {
        let index = BaseIndex::from_pfx_7(octet);

        if node.prefix_count() != 0 && node.supersets_prefix(index) {
            return true;
        }

        let Some(child) = node.get_child(octet) else {
            return false;
        };

        match child {
            Child::Path(n) => node = n,
            Child::Fringe(_) => return true,
            Child::Leaf { prefix, .. } => return prefix.contains(&ip),
        }
    }

    false
}

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use super::*;
    use crate::{Node, test_util::unique_prefixes};

    #[test]
    fn bart_examples_insert_get_delete() {
        let mut node = Node::<_>::EMPTY;

        let p1 = ipnet::IpNet::from_str("10.0.0.0/8").unwrap();
        let p2 = ipnet::IpNet::from_str("10.1.0.0/16").unwrap();
        let p3 = ipnet::IpNet::from_str("2001:db8::/32").unwrap();

        assert_eq!(None, insert::insert(&mut node, p1, 100usize));
        assert_eq!(None, insert::insert(&mut node, p2, 200usize));
        assert_eq!(None, insert::insert(&mut node, p3, 300usize));

        std::println!("post-insert: {node:#?}");

        assert_eq!(Some(200), lookup_prefix_exact(&node, p2).copied());
        assert_eq!(Some(100), remove::remove(&mut node, p1));
        assert_eq!(None, lookup_prefix_exact(&node, p1));

        std::println!("post-remove: {node:#?}");
    }

    fn test_insert_delete(
        pfxs: &[&str],
        want_pfxs: usize,
        want_leaves: usize,
        want_fringes: usize,
    ) {
        let mut node = Node::<_>::EMPTY;

        for &pfx in pfxs {
            insert::insert(&mut node, crate::pfx!(pfx), ());
            insert::insert(&mut node, crate::pfx!(pfx), ()); // check idempotency
        }

        let stats = node.stats();

        assert_eq!(want_pfxs, stats.prefix_count);
        assert_eq!(want_leaves, stats.leaf_count);
        assert_eq!(want_fringes, stats.fringe_count);

        for &pfx in pfxs {
            remove::remove(&mut node, crate::pfx!(pfx));
            remove::remove(&mut node, crate::pfx!(pfx)); // idempotency
        }

        let stats = node.stats();

        assert_eq!(0, stats.prefix_count);
        assert_eq!(0, stats.leaf_count);
        assert_eq!(0, stats.fringe_count);
    }

    #[test]
    fn bart_insert_delete_examples() {
        // empty
        test_insert_delete(&[], 0, 0, 0);

        // single prefix
        test_insert_delete(&["0.0.0.0/0"], 1, 0, 0);
        test_insert_delete(&["::/0"], 1, 0, 0);

        // single leaf
        test_insert_delete(&["0.0.0.0/32"], 0, 1, 0);
        test_insert_delete(&["::/32"], 0, 1, 0);

        // single fringe
        test_insert_delete(&["0.0.0.0/8"], 0, 0, 1);
        test_insert_delete(&["::/8"], 0, 0, 1);

        // many prefixes
        test_insert_delete(
            &["0.0.0.0/0", "0.0.0.0/1", "0.0.0.0/2", "0.0.0.0/3"],
            4,
            0,
            0,
        );
        test_insert_delete(&["::/0", "::/1", "::/2", "::/3"], 4, 0, 0);

        // many prefixes with many leaves
        test_insert_delete(
            &[
                // prefixes
                "0.0.0.0/0",
                "0.0.0.0/1",
                "0.0.0.0/2",
                "0.0.0.0/3",
                // leaves
                "0.0.0.0/9",
                "1.0.0.0/9",
                "2.0.0.0/9",
                "3.0.0.0/9",
            ],
            4,
            4,
            0,
        );
        test_insert_delete(
            &[
                "::/0", "::/1", "::/2", "::/3", // prefixes
                "::/9", "0100::/9", "0200::/9", "0300::/9", // leaves
            ],
            4,
            4,
            0,
        );

        // many prefixes with many leaves and fringes
        test_insert_delete(
            &[
                // prefixes
                "0.0.0.0/0",
                "0.0.0.0/1",
                "0.0.0.0/2",
                "0.0.0.0/3",
                // leaves
                "0.0.0.0/9",
                "1.0.0.0/9",
                "2.0.0.0/9",
                "3.0.0.0/9",
                // fringes
                "5.0.0.0/8",
                "6.0.0.0/8",
                "7.0.0.0/8",
                "8.0.0.0/8",
            ],
            4,
            4,
            4,
        );
        test_insert_delete(
            &[
                "::/0", "::/1", "::/2", "::/3", // prefixes
                "::/9", "0100::/9", "0200::/9", "0300::/9", // leaves
                "0400::/8", "0500::/8", "0600::/8", "0700::/8", // fringes
            ],
            4,
            4,
            4,
        );

        // deeper-level prefixes, leaves, fringes
        test_insert_delete(
            &[
                // prefixes level 1
                "0.0.0.0/9",
                "0.0.0.0/10",
                // leaf level 1
                "0.1.0.0/19",
                // fringes
                "0.2.0.0/16",
            ],
            2,
            1,
            1,
        );
        test_insert_delete(&["::/9", "::/10", "0010::/19", "0020::/16"], 2, 1, 1);

        // prefixes and fringes through level 2
        test_insert_delete(
            &[
                "0.0.0.0/12", // pfx in level 1
                "0.0.0.0/16", // fringe in level 1 -> prefix in level 2
                "0.0.0.0/24", // fringe at level 2
            ],
            2,
            0,
            1,
        );
        test_insert_delete(
            &[
                "::/12", // pfx in level 1
                "::/16", // fringe in level 1 -> prefix in level 2
                "::/24", // fringe at level 2
            ],
            2,
            0,
            1,
        );
    }

    proptest::proptest! {
        #[test]
        fn insert_remove(pfxs in unique_prefixes()) {
            const PRINT: bool = false;
            let mut node = Node::<()>::EMPTY;

            for pfx in &pfxs {
                if PRINT {
                    std::println!("insert {pfx}");
                }

                proptest::prop_assert!(insert(&mut node, *pfx, ()).is_none());
            }

            if PRINT {
                for (path, desc) in node.descendants(false) {
                    std::println!("{path:?}: {desc:#?}");
                }
            }

            let stats = node.stats();
            proptest::prop_assert_eq!(pfxs.len(), stats.leaf_count + stats.prefix_count + stats.fringe_count);

            for pfx in &pfxs {
                if PRINT {
                    std::println!("remove {pfx}");
                }

                proptest::prop_assert!(remove(&mut node, *pfx).is_some());
            }

            proptest::prop_assert!(node.is_empty());
        }
    }
}
