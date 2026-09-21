//! Utility functions for working with trie structures, IP addresses, and IP
//! prefixes.
use core::net::IpAddr;

use crate::{
    BaseIndex,
    iptrie::{MAX_DEPTH, StridePath},
};

const DEPTH_MASK: usize = MAX_DEPTH - 1;

/// Return whether the given prefix is a fringe address (/8) at the given
/// depth.
pub const fn is_fringe(depth: usize, prefix: &ipnet::IpNet) -> bool {
    let (octet_count, overflow_bits) = stride_count_and_overflow(prefix);
    depth == octet_count - 1 && overflow_bits == 0
}

/// Reconstruct a complete prefix from a trie traversal path and a final
/// [`BaseIndex`]. Expected to be called within functions in [`iptrie`][super]
/// that walk the node tree.
pub fn prefix_from_path(
    path_octets: &[u8],
    depth: usize,
    ipv4: bool,
    idx: BaseIndex,
) -> ipnet::IpNet {
    let depth = depth & DEPTH_MASK;
    let mut path = StridePath::default();

    let (octet, idx_len) = idx.prefix();

    let octet_depth = path_octets.len().min(depth);
    path[..octet_depth].copy_from_slice(&path_octets[..octet_depth]);
    path[depth] = octet;

    ipnet::IpNet::new_assert(ip_from_path(path, ipv4), depth as u8 * 8 + idx_len)
}

/// Reconstruct a prefix for a fringe node from a trie traversal path. Expected
/// to be called within functions in [`iptrie`][super] that walk the node trie.
pub fn fringe_prefix(path_octets: &[u8], depth: usize, ipv4: bool, last_octet: u8) -> ipnet::IpNet {
    let depth = depth & DEPTH_MASK;
    let mut path = [0u8; MAX_DEPTH];

    let mut i = 0;
    while i < MAX_DEPTH {
        path[i] = match i {
            x if x > depth => 0,
            x if x == depth => last_octet,
            x if x < path_octets.len() => path_octets[i],
            _ => 0,
        };

        i += 1;
    }

    let ip = ip_from_path(path, ipv4);
    let bits = (depth + 1) * 8;

    ipnet::IpNet::new_assert(ip, bits as _)
}

fn ip_from_path(path: StridePath, is4: bool) -> IpAddr {
    if is4 {
        core::net::Ipv4Addr::from(*path.first_chunk::<4>().unwrap()).into()
    } else {
        core::net::Ipv6Addr::from(path).into()
    }
}

/// The count of full 8-bit strides (bits / 8) and the leftover bits in the
/// final stride (bits % 8) for this prefix.
pub const fn stride_count_and_overflow(prefix: &ipnet::IpNet) -> (usize, u8) {
    let len = match prefix {
        ipnet::IpNet::V4(v4) => v4.prefix_len(),
        ipnet::IpNet::V6(v6) => v6.prefix_len(),
    };

    ((len / 8) as _, len % 8)
}

/// Return octets in the address as a slice.
#[allow(unsafe_code)]
pub fn ip_octets(ip: &IpAddr) -> &[u8] {
    static_assertions::const_assert_eq!(4, size_of::<core::net::Ipv4Addr>());
    static_assertions::const_assert_eq!(16, size_of::<core::net::Ipv6Addr>());

    // FIXME(npry): replace with `IpAddr::as_octets` once it stabilizes:
    // https://github.com/rust-lang/rust/issues/137259
    //
    // I used unsafe here because this code is directly in the lookup hot-path
    // (measured very performance-sensitive via the benchmarks), and there
    // aren't to my knowledge any ways to express this without unsafe (or a nightly
    // compiler). Constructing a heapless::Vec would be the obvious thing, but the
    // compiler doesn't seem to be able to see through the fact that the
    // `.octets()` lengths are known a priori in order to optimize that. Even
    // with `push_unchecked()` or `from_slice().unwrap_unchecked()`,
    // we lose ~20-40% performance in the `contains` benchmark because we're doing
    // any work at all actually constructing the heapless::Vec.
    //
    // Unfortunately, the IP address types don't specify #[repr(transparent)], which
    // would pin their struct representation to be equivalent
    // to the inner octet arrays. The `const_assert_eq!`s above are intended to
    // verify that rustc hasn't suddenly decided to do something crazy re:
    // padding or struct alignment (or detect that the libcore internals
    // changed). The representation should just be the plain octet array,
    // in-order. Given the existence of zerocopy, I suspect there are invariants
    // guaranteed by rustc that we could rely upon here to prove that this is
    // definitely sound, but I don't have the citations at hand.
    match ip {
        IpAddr::V4(v4) => unsafe { core::slice::from_raw_parts(v4 as *const _ as *const u8, 4) },
        IpAddr::V6(v6) => unsafe { core::slice::from_raw_parts(v6 as *const _ as *const u8, 16) },
    }
}

#[cfg(test)]
mod test {
    use core::net::Ipv6Addr;

    use super::*;

    /// Construct an [`ipnet::IpNet`]. Just a wrapper around from_str().unwrap()
    /// for convenience in writing tests.
    #[macro_export]
    macro_rules! pfx {
        ($pfx:expr) => {
            <::ipnet::IpNet as ::core::str::FromStr>::from_str($pfx)
                .unwrap()
                .trunc()
        };
    }

    #[test]
    fn bart_examples_stride_count_and_overflow() {
        assert_eq!((0, 0), stride_count_and_overflow(&pfx!("0.0.0.0/0")),);
        assert_eq!((4, 0), stride_count_and_overflow(&pfx!("0.0.0.0/32")),);
        assert_eq!((0, 7), stride_count_and_overflow(&pfx!("10.0.0.0/7")),);
        assert_eq!((1, 6), stride_count_and_overflow(&pfx!("10.20.0.0/14")),);
        assert_eq!((3, 0), stride_count_and_overflow(&pfx!("10.20.30.0/24")),);
        assert_eq!((3, 7), stride_count_and_overflow(&pfx!("10.20.30.40/31")),);

        assert_eq!((0, 0), stride_count_and_overflow(&pfx!("::/0")),);
        assert_eq!((16, 0), stride_count_and_overflow(&pfx!("::/128"),),);
        assert_eq!((3, 7), stride_count_and_overflow(&pfx!("2001:db8::/31"),),);
    }

    const TEST_IPV6: [u8; 16] = {
        let mut ret = [0u8; 16];

        ret.first_chunk_mut::<4>()
            .unwrap()
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);

        ret
    };

    fn test_ipv6_with_octets(idx: &[usize]) -> [u8; 16] {
        let mut ret = TEST_IPV6;

        for &idx in idx {
            ret[idx] = 1;
        }

        ret
    }

    #[test]
    fn bart_examples_cidr_from_path() {
        assert_eq!(
            pfx!("0.0.0.0/0"),
            prefix_from_path(&[], 0, true, BaseIndex::new(1)),
        );
        assert_eq!(
            pfx!("128.0.0.0/1"),
            prefix_from_path(&[], 0, true, BaseIndex::new(3)),
        );
        assert_eq!(
            pfx!("192.128.0.0/9"),
            prefix_from_path(&[192, 168, 0, 0,], 1, true, BaseIndex::new(3)),
        );
        assert_eq!(
            pfx!("10.0.224.0/19"),
            prefix_from_path(&[10, 0, 1, 0,], 2, true, BaseIndex::new(15)),
        );
        assert_eq!(
            pfx!("128.0.0.0/1"),
            prefix_from_path(&[192, 168, 1, 0], 32, true, BaseIndex::new(3)),
        );
        assert_eq!(
            pfx!("0.0.0.0/0"),
            prefix_from_path(&[], 0, true, BaseIndex::new(1)),
        );
        assert_eq!(
            pfx!("10.20.244.0/19"),
            prefix_from_path(
                &[10, 20, 30, 40, 50, 60, 70, 80, 90],
                2,
                true,
                BaseIndex::new(15)
            ),
        );

        assert_eq!(
            pfx!("::/0"),
            prefix_from_path(&[], 0, false, BaseIndex::new(1)),
        );
        assert_eq!(
            pfx!("20f8::/13"),
            prefix_from_path(&TEST_IPV6[..8], 1, false, BaseIndex::new(63)),
        );
        assert_eq!(
            pfx!("2001:db8:0:fc::/62"),
            prefix_from_path(
                &test_ipv6_with_octets(&[7])[..8],
                7,
                false,
                BaseIndex::new(127)
            ),
        );
        assert_eq!(
            pfx!("2001:db8:0:1::fe/127"),
            prefix_from_path(
                &test_ipv6_with_octets(&[7, 15]),
                15,
                false,
                BaseIndex::new(255)
            ),
        );
        assert_eq!(
            pfx!("c000::/2"),
            prefix_from_path(&[0x20, 0x01, 0x0d, 0xb8], 48, false, BaseIndex::new(7)),
        );
    }

    #[test]
    fn bart_examples_cidr_for_fringe() {
        assert_eq!(pfx!("0.0.0.0/8"), fringe_prefix(&[10, 0, 0, 0], 0, true, 0),);
        assert_eq!(
            pfx!("192.0.0.0/16"),
            fringe_prefix(&[192, 168, 0, 0], 1, true, 0),
        );
        assert_eq!(pfx!("0.0.0.0/8"), fringe_prefix(&[], 0, true, 0),);
        assert_eq!(
            pfx!("50.0.0.0/8"),
            fringe_prefix(&[10, 20, 30, 40], 32, true, 50),
        );

        assert_eq!(pfx!("::/8"), fringe_prefix(&TEST_IPV6, 0, false, 0).trunc(),);
        assert_eq!(
            pfx!("2000::/16"),
            fringe_prefix(&TEST_IPV6, 1, false, 0).trunc(),
        );
        assert_eq!(
            pfx!("2001:db8::/64"),
            fringe_prefix(&test_ipv6_with_octets(&[7]), 7, false, 0).trunc(),
        );
        assert_eq!(
            pfx!("2001:db8:0:1::/128"),
            fringe_prefix(&test_ipv6_with_octets(&[7, 15]), 15, false, 0).trunc(),
        );
        assert_eq!(
            pfx!("fe80:0:0:ff::/64"),
            fringe_prefix(
                &Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0).octets(),
                7,
                false,
                0xff,
            )
            .trunc(),
        );
        assert_eq!(pfx!("::/8"), fringe_prefix(&[], 0, false, 0),);
        assert_eq!(
            pfx!("ac10:6300::/24"),
            fringe_prefix(
                &[
                    0xac, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                    0x0c, 0x0d, 0x0e,
                ],
                2,
                false,
                0x63
            ),
        );
    }

    #[test]
    fn bart_examples_test_is_fringe() {
        assert!(is_fringe(0, &pfx!("10.0.0.0/8")));
        assert!(is_fringe(1, &pfx!("192.168.0.0/16")));
        assert!(is_fringe(2, &pfx!("10.0.1.0/24")));
        assert!(is_fringe(3, &pfx!("192.168.1.1/32")));

        assert!(!is_fringe(1, &pfx!("192.128.0.0/9")));
        assert!(!is_fringe(3, &pfx!("10.0.0.1/25")));
        assert!(!is_fringe(0, &pfx!("192.168.0.0/16")));
        assert!(!is_fringe(1, &pfx!("10.0.0.0/8")));

        assert!(is_fringe(0, &pfx!("2001::/8")));
        assert!(is_fringe(1, &pfx!("2001:db8::/16")));
        assert!(is_fringe(7, &pfx!("2001:db8::/64")));
        assert!(is_fringe(15, &pfx!("2001:db8::1/128")));

        assert!(!is_fringe(1, &pfx!("2000::/9")));
        assert!(!is_fringe(8, &pfx!("2001:db8::/65")));
        assert!(!is_fringe(0, &pfx!("2001:db8::/16")));
        assert!(!is_fringe(6, &pfx!("2001:db8::/64")));
    }
}
