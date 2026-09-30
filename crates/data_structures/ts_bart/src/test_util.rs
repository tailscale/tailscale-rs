//! Misc test utilities for use within the crate.

use alloc::vec::Vec;
use core::net::IpAddr;

use proptest::{
    arbitrary::any,
    collection::{SizeRange, vec},
    prelude::Strategy,
};

/// Proptest strategy to generate an [`ipnet::IpNet`] prefix. This function
/// truncates the produced prefix.
pub fn any_prefix() -> impl Strategy<Value = ipnet::IpNet> {
    (any::<IpAddr>(), any::<u8>()).prop_map(|(ip, len)| {
        let len = len % if ip.is_ipv4() { 4 } else { 16 };

        ipnet::IpNet::new_assert(ip, len).trunc()
    })
}

/// Generate a collection of unique, randomly-ordered prefixes. Deduplicates
/// equivalent IPv4/IPv6 prefixes.
pub fn unique_prefixes() -> impl Strategy<Value = Vec<ipnet::IpNet>> {
    vec(any_prefix(), SizeRange::default())
        .prop_map(|mut v| {
            v.sort_by(|a, b| {
                a.prefix_len()
                    .cmp(&b.prefix_len())
                    .then(significant_octets(a).cmp(&significant_octets(b)))
            });
            v.dedup_by(|a, b| {
                a.prefix_len() == b.prefix_len() && significant_octets(a) == significant_octets(b)
            });
            v
        })
        .prop_shuffle()
}

fn significant_octets(prefix: &ipnet::IpNet) -> heapless::Vec<u8, 16> {
    let addr = prefix.trunc().addr();
    let octets = crate::iptrie::util::ip_octets(&addr);
    let relevant = prefix.prefix_len().div_ceil(8);

    heapless::Vec::from_slice(&octets[..relevant as usize]).unwrap()
}

#[test]
fn significant_octets_eq() {
    assert_eq!(
        significant_octets(&crate::pfx!("96.0.0.0/3")),
        significant_octets(&crate::pfx!("6000::/3")),
    );
}
