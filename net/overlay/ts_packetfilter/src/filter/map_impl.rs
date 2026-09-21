//! Non-performance-optimized map-based impls that should relatively obviously
//! work. Baseline functionality without `bart`.

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
};
#[cfg(feature = "std")]
use std::collections::HashMap;

use hashbrown::HashMap as HbHashMap;

use crate::{
    Filter, FilterStorage,
    filter::CapIter,
    rule::{Rule, Ruleset},
};

macro_rules! impl_filter_for_map {
    ($ty:ident) => {
        impl FilterStorage for $ty<String, Ruleset> {
            fn insert_dyn(&mut self, name: &str, ruleset: &mut dyn Iterator<Item = Rule>) {
                self.insert(name.to_string(), ruleset.collect());
            }

            fn remove(&mut self, name: &str) {
                self.remove(name);
            }

            fn clear(&mut self) {
                self.clear();
            }
        }

        impl<'r> Filter for $ty<String, Ruleset> {
            fn match_for(&self, info: &crate::PacketInfo, caps: CapIter) -> Option<&str> {
                let caps = caps.collect::<alloc::collections::BTreeSet<_>>();

                self.iter().find_map(|(name, rules)| {
                    rules
                        .iter()
                        .any(|rule| rule.matches(info, caps.iter().copied()))
                        .then_some(name.as_str())
                })
            }
        }
    };
}

impl_filter_for_map!(BTreeMap);
impl_filter_for_map!(HbHashMap);
#[cfg(feature = "std")]
impl_filter_for_map!(HashMap);

#[cfg(test)]
mod test {
    use alloc::vec;
    use core::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::{
        IpProto, PacketInfo,
        filter::{FilterAndStorage, FilterExt, FilterStorageExt},
        rule::{DstMatch, SrcMatch},
    };

    const RULESET_NAME: &str = "test";
    const PORT: u16 = 80;
    const PROTO: IpProto = IpProto::TCP;
    const CAP: &str = "testcap";

    const SRC: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    const DST: IpAddr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

    const PACKET_INFO: PacketInfo = PacketInfo {
        src: SRC,
        dst: DST,
        ip_proto: PROTO,
        port: PORT,
    };

    fn assert_nomatch<'s>(filters: &dyn Filter, caps: impl IntoIterator<Item = &'s str> + Clone) {
        let access = filters.match_for(&PACKET_INFO, &mut caps.clone().into_iter());
        assert_eq!(None, access);

        assert!(!filters.can_access(&PACKET_INFO, caps.into_iter()));
    }

    fn assert_match_src<'s>(
        filters: &dyn Filter,
        caps: impl IntoIterator<Item = &'s str> + Clone,
        srcip: IpAddr,
    ) {
        let info = PacketInfo {
            src: srcip,
            ..PACKET_INFO
        };
        let access = filters.match_for(&info, &mut caps.clone().into_iter());
        assert_eq!(Some(RULESET_NAME), access);

        assert!(filters.can_access(&info, caps.into_iter()));
    }

    fn assert_match<'s>(filters: &dyn Filter, caps: impl IntoIterator<Item = &'s str> + Clone) {
        assert_match_src(filters, caps, SRC);
    }

    fn default_rule() -> Rule {
        Rule {
            src: SrcMatch {
                caps: vec![],
                pfxs: vec![SRC.into()],
            },
            protos: vec![PROTO],
            dst: vec![DstMatch {
                ports: PORT..=PORT,
                ips: vec![DST.into()],
            }],
        }
    }

    #[test]
    fn empty() {
        let mut filters = BTreeMap::new();
        let filters = &mut filters as &mut dyn FilterAndStorage;

        assert_nomatch(filters, []);
        filters.insert(RULESET_NAME, []);
        assert_nomatch(filters, [CAP]);
    }

    #[test]
    fn match_one_ip() {
        let mut filters = BTreeMap::new();
        let filters = &mut filters as &mut dyn FilterAndStorage;

        filters.insert(RULESET_NAME, [default_rule()]);
        assert_match(filters, [CAP]);
        assert_match(filters, []);
    }

    #[test]
    fn match_one_cap() {
        let mut filters = BTreeMap::new();
        let filters = &mut filters as &mut dyn FilterAndStorage;

        filters.insert(
            RULESET_NAME,
            [Rule {
                src: SrcMatch {
                    caps: vec![CAP.to_string()],
                    ..Default::default()
                },
                ..default_rule()
            }],
        );

        assert_match(filters, [CAP]);
        assert_nomatch(filters, []);
    }

    #[test]
    fn match_ip_or_cap() {
        let mut filters = BTreeMap::new();
        let filters = &mut filters as &mut dyn FilterAndStorage;

        filters.insert(
            RULESET_NAME,
            [Rule {
                src: SrcMatch {
                    caps: vec![CAP.to_string()],
                    pfxs: vec![SRC.into()],
                },
                ..default_rule()
            }],
        );
        assert_match(filters, [CAP]);
        assert_match_src(filters, [], SRC);
    }
}
