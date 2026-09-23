#![allow(dead_code)]

use rand::prelude::IndexedRandom;
use ts_bart::RoutingTable;

use super::load_tables::*;

pub struct ArgsType(
    pub String,
    pub &'static (dyn RoutingTable<Value = TableContents> + Send + Sync),
    pub Box<dyn Fn() -> ipnet::IpNet + Send + Sync>,
);

impl ArgsType {
    pub fn to_bench_args(
        &self,
    ) -> (
        &'static dyn RoutingTable<Value = TableContents>,
        ipnet::IpNet,
    ) {
        (self.1, (self.2)())
    }
}

#[allow(clippy::to_string_trait_impl)]
impl ToString for ArgsType {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

pub fn table_matrix() -> impl Iterator<Item = ArgsType> {
    let addr_v4_first = *PREFIXES_V4.first().unwrap();
    let addr_v4_last = *PREFIXES_V4.last().unwrap();

    let addr_v6_first = *PREFIXES_V6.first().unwrap();
    let addr_v6_last = *PREFIXES_V6.last().unwrap();

    #[derive(Copy, Clone)]
    enum Type {
        Ipv4,
        Ipv6,
        Both,
    }

    #[derive(Copy, Clone)]
    enum Addr {
        Hit(ipnet::IpNet),
        Miss(ipnet::IpNet),
        HitRng,
    }

    itertools::iproduct!(
        [
            #[cfg(not(feature = "smallvec"))]
            (
                "simple/inline/ipv4",
                Type::Ipv4,
                &*SIMPLE_INLINE_V4 as &(dyn RoutingTable<Value = TableContents> + Send + Sync)
            ),
            #[cfg(not(feature = "smallvec"))]
            ("simple/inline/ipv6", Type::Ipv6, &*SIMPLE_INLINE_V6),
            #[cfg(not(feature = "smallvec"))]
            ("split/inline/ipv4", Type::Ipv4, &*TABLE_INLINE_V4),
            #[cfg(not(feature = "smallvec"))]
            ("split/inline/ipv6", Type::Ipv6, &*TABLE_INLINE_V6),
            #[cfg(not(feature = "smallvec"))]
            ("split/inline/full", Type::Both, &*TABLE_INLINE_FULL),
            (
                "simple/box/ipv4",
                Type::Ipv4,
                &*SIMPLE_BOX_V4 as &(dyn RoutingTable<Value = TableContents> + Send + Sync)
            ),
            ("simple/box/ipv6", Type::Ipv6, &*SIMPLE_BOX_V6),
            ("split/box/ipv4", Type::Ipv4, &*TABLE_BOX_V4),
            ("split/box/ipv6", Type::Ipv6, &*TABLE_BOX_V6),
            ("split/box/full", Type::Both, &*TABLE_BOX_FULL),
        ],
        [
            // TODO(npry): generate and test misses
            Addr::Hit(addr_v4_first),
            Addr::Hit(addr_v4_last),
            Addr::Hit(addr_v6_first),
            Addr::Hit(addr_v6_last),
            Addr::HitRng
        ],
    )
    .flat_map(move |((name, typ, table), elem)| match (typ, elem) {
        (Type::Ipv4 | Type::Both, Addr::Hit(pfx @ ipnet::IpNet::V4(_))) => {
            vec![ArgsType(
                format!("{name}/hit/{pfx}"),
                table,
                Box::new(move || pfx) as Box<dyn Fn() -> ipnet::IpNet + Send + Sync>,
            )]
        }
        (Type::Ipv6 | Type::Both, Addr::Hit(pfx @ ipnet::IpNet::V6(_))) => {
            vec![ArgsType(
                format!("{name}/hit/{pfx}"),
                table,
                Box::new(move || pfx) as Box<dyn Fn() -> ipnet::IpNet + Send + Sync>,
            )]
        }
        (Type::Ipv4, Addr::HitRng) => {
            vec![ArgsType(
                format!("{name}/hit/rng"),
                table,
                Box::new(|| {
                    let mut rng = rand::rng();
                    *PREFIXES_V4.choose(&mut rng).unwrap()
                }) as Box<dyn Fn() -> ipnet::IpNet + Send + Sync>,
            )]
        }
        (Type::Ipv6, Addr::HitRng) => {
            vec![ArgsType(
                format!("{name}/hit/rng"),
                table,
                Box::new(|| {
                    let mut rng = rand::rng();
                    *PREFIXES_V6.choose(&mut rng).unwrap()
                }) as Box<dyn Fn() -> ipnet::IpNet + Send + Sync>,
            )]
        }
        (Type::Both, Addr::HitRng) => {
            vec![ArgsType(
                format!("{name}/hit/rng"),
                table,
                Box::new(|| {
                    let mut rng = rand::rng();
                    *PREFIXES.choose(&mut rng).unwrap()
                }) as Box<dyn Fn() -> ipnet::IpNet + Send + Sync>,
            )]
        }
        (Type::Ipv4 | Type::Both, Addr::Miss(pfx @ ipnet::IpNet::V4(_))) => {
            vec![ArgsType(
                format!("{name}/miss/{pfx}"),
                table,
                Box::new(move || pfx) as Box<dyn Fn() -> ipnet::IpNet + Send + Sync>,
            )]
        }
        (Type::Ipv6 | Type::Both, Addr::Miss(pfx @ ipnet::IpNet::V6(_))) => {
            vec![ArgsType(
                format!("{name}/miss/{pfx}"),
                table,
                Box::new(move || pfx) as Box<dyn Fn() -> ipnet::IpNet + Send + Sync>,
            )]
        }
        _ => vec![],
    })
}
