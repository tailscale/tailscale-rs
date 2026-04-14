#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::borrow::Borrow;

use ts_packetfilter as pf;
#[doc(inline)]
pub use ts_packetfilter::apply_update as apply_update_dyn;
use ts_packetfilter_serde as pf_serde;

/// Convert the given `MapResponse`-deserialized rule into [`pf`] format.
///
/// Returns `None` if the rule is not a network rule.
pub fn rule_to_pf(rule: &pf_serde::FilterRule) -> Option<pf::Rule> {
    let rule = rule.as_network()?;

    let mut caps = vec![];
    let mut src_pfxs = vec![];

    for src in &rule.src_ips {
        match src {
            pf_serde::SrcIp::IpRange(r) => src_pfxs.extend(r.iter_prefixes()),
            pf_serde::SrcIp::NodeCap(cap) => caps.push(cap.to_string()),
        }
    }

    let protos = rule
        .ip_proto
        .iter()
        .copied()
        .map(|proto| {
            let proto: isize = proto.into();
            pf::IpProto::from(proto as i64)
        })
        .collect::<Vec<_>>();

    let dsts = rule
        .dst_ports
        .iter()
        .map(|port| pf::DstMatch {
            ips: port.ip.iter_prefixes().collect(),
            ports: port.ports.clone(),
        })
        .collect();

    Some(pf::Rule {
        src: pf::SrcMatch {
            pfxs: src_pfxs,
            caps,
        },
        protos,
        dst: dsts,
    })
}

/// Convert the given `MapResponse`-deserialized rules into [`pf`] format.
#[inline]
pub fn rules_to_pf<'r, 'f>(
    rules: impl IntoIterator<Item = &'f pf_serde::FilterRule<'r>>,
) -> impl Iterator<Item = pf::Rule>
where
    'r: 'f,
{
    rules.into_iter().filter_map(rule_to_pf)
}

/// Report whether the special key indicating that the filter state should be
/// cleared is present and has a `null` value.
#[inline]
pub fn should_clear_storage<K, V>(packet_filters: &BTreeMap<K, Option<V>>) -> bool
where
    K: Borrow<str> + Ord,
{
    matches!(packet_filters.get(pf::CLEAR_MAP_KEY), Some(&None))
}

/// Update `storage` on the basis of a `MapResponse` update.
///
/// `packet_filter` is the old-style `packet_filter` field, and `update_map` is the
/// `packet_filters` field.
pub fn convert_and_apply_update<'r>(
    mut storage: impl pf::FilterStorage,
    packet_filter: Option<&pf_serde::Ruleset<'r>>,
    update_map: &pf_serde::Map<'r>,
) {
    let should_clear = should_clear_storage(update_map);

    let packet_filter = packet_filter.map(|f| rules_to_pf(f).collect());
    let mut map_iter = update_map
        .iter()
        .map(|(s, r)| (*s, r.as_ref().map(|r| rules_to_pf(r).collect())));

    apply_update_dyn(&mut storage, packet_filter, should_clear, &mut map_iter)
}

/// Update `storage` on the basis of a `MapResponse` update converted to `pf` format.
///
/// `packet_filter` is the old-style `packet_filter` field, and `update_map` is the
/// `packet_filters` field.
pub fn apply_update(
    mut storage: impl pf::FilterStorage,
    packet_filter: Option<pf::Ruleset>,
    update_map: &BTreeMap<String, Option<pf::Ruleset>>,
) {
    let should_clear = should_clear_storage(update_map);

    apply_update_dyn(
        &mut storage,
        packet_filter,
        should_clear,
        &mut update_map.iter().map(|(k, v)| (k.as_str(), v.clone())),
    )
}

#[cfg(test)]
mod test {
    use alloc::{collections::BTreeMap, vec};
    use core::net::IpAddr;
    use std::net::Ipv4Addr;

    use pf::FilterExt;
    use pf_serde::{DstPort, IpProto, NetworkRule, SrcIp};

    use super::*;

    const PROTO: pf::IpProto = pf::IpProto::TCP;
    const PORT: u16 = 80;

    const SRC: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    const DST: IpAddr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

    #[test]
    fn basic() {
        let mut filters = BTreeMap::new();

        convert_and_apply_update(
            &mut filters,
            None,
            &pf_serde::Map::from_iter([(pf::CLEAR_MAP_KEY, None)]),
        );
        assert_eq!(filters.len(), 0);

        convert_and_apply_update(
            &mut filters,
            None,
            &pf_serde::Map::from_iter([(pf::DEFAULT_RULESET_NAME, Some(vec![]))]),
        );
        assert_eq!(filters.len(), 0);

        convert_and_apply_update(
            &mut filters,
            None,
            &pf_serde::Map::from_iter([(
                pf::DEFAULT_RULESET_NAME,
                Some(vec![
                    NetworkRule {
                        src_ips: vec![SrcIp::from(SRC)],
                        ip_proto: IpProto::NULL_DEFAULTS.to_vec(),
                        dst_ports: vec![DstPort {
                            ports: PORT..=PORT,
                            ip: DST.into(),
                        }],
                    }
                    .into(),
                ]),
            )]),
        );
        assert_eq!(filters.len(), 1);
        assert!(filters.can_access(
            &pf::PacketInfo {
                dst: DST,
                ip_proto: PROTO,
                src: SRC,
                port: PORT,
            },
            []
        ));

        convert_and_apply_update(
            &mut filters,
            None,
            &pf_serde::Map::from_iter([(pf::CLEAR_MAP_KEY, None)]),
        );
        assert_eq!(filters.len(), 0);
    }
}
