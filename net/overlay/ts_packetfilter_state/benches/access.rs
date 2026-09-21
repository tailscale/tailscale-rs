//! Benchmarks for packet filter lookup performance.
//!
//! Defined here (rather than in [`pf`]) for access to the control serde types, so we can
//! load them from a json file.

use core::{net::IpAddr, str::FromStr};
use std::sync::LazyLock;

use ts_packetfilter::{
    self as pf, FilterExt, FilterStorage,
    filter::{FilterAndStorage, FilterStorageExt},
};
use ts_packetfilter_serde::Ruleset;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

/// Benchmark [`FilterExt::can_access`] with an empty filterset as a baseline.
#[divan::bench(types = [
    pf::BTreeFilter,
    pf::HashMapFilter,
    ts_bart_packetfilter::BartFilter,
])]
fn can_access_empty<T>(bencher: divan::Bencher)
where
    T: FilterAndStorage + Send + Sync + Default,
{
    let mut filters = T::default();
    filters.insert("test", vec![]);

    let ip = IpAddr::from_str("1.2.3.4").unwrap();

    bencher.bench(|| {
        filters.can_access(
            &pf::PacketInfo {
                dst: ip,
                src: ip,
                ip_proto: pf::IpProto::TCP,
                port: 5678,
            },
            [],
        )
    });
}

const SAMPLE_FILTER: &str = include_str!("sample_filter.json");

static SAMPLE_RULESET: LazyLock<Ruleset> =
    LazyLock::new(|| serde_json::from_str::<Ruleset>(SAMPLE_FILTER).unwrap());

fn sample_filters<T>() -> T
where
    T: Default + FilterStorage,
{
    let mut filters = T::default();

    ts_packetfilter_state::convert_and_apply_update(
        &mut filters,
        Some(&SAMPLE_RULESET),
        &Default::default(),
    );

    filters
}
#[divan::bench(types = [
    pf::BTreeFilter,
    pf::HashMapFilter,
    ts_bart_packetfilter::BartFilter,
])]
fn alloc_sample_ruleset<T>(bencher: divan::Bencher)
where
    T: FilterStorage + Default,
{
    bencher.with_inputs(|| &*SAMPLE_RULESET).bench_refs(|x| {
        let mut filters = T::default();
        ts_packetfilter_state::convert_and_apply_update(
            &mut filters,
            Some(*x),
            &Default::default(),
        );
    });
}

fn small_ruleset() -> pf::Ruleset {
    pf::Ruleset::from_iter([pf::Rule {
        dst: vec![pf::DstMatch {
            ips: vec!["0.0.0.0/0".parse().unwrap()],
            ports: 22..=22,
        }],
        src: pf::SrcMatch {
            pfxs: vec!["100.64.0.0/16".parse().unwrap()],
            caps: vec![],
        },
        protos: vec![pf::IpProto::TCP],
    }])
}

#[divan::bench(types = [
    pf::BTreeFilter,
    pf::HashMapFilter,
    ts_bart_packetfilter::BartFilter,
])]
fn alloc_small_ruleset<T>(bencher: divan::Bencher)
where
    T: FilterStorage + Default,
{
    bencher.with_inputs(small_ruleset).bench_values(|x| {
        let mut filters = T::default();
        filters.insert("test", x);
    });
}

macro_rules! sample_bench {
    (
        $name:ident,
        $src:expr,
        $dst:expr,
        $caps:expr,
        $ipproto:expr,
        $port:expr,
        $should_match:expr
    ) => {
        #[divan::bench(types = [pf::BTreeFilter, pf::HashMapFilter, ts_bart_packetfilter::BartFilter])]
        fn $name<T>(bencher: divan::Bencher)
        where
            T: FilterAndStorage + Send + Sync + Default,
        {
            let filters = sample_filters::<T>();

            let info = pf::PacketInfo {
                src: IpAddr::from_str($src).unwrap(),
                dst: IpAddr::from_str($dst).unwrap(),
                port: $port,
                ip_proto: $ipproto,
            };

            // verify that the filter does what we expect
            let result = filters.can_access(&info, $caps);
            assert_eq!(result, $should_match);

            bencher.bench(|| filters.can_access(&info, $caps));
        }
    };
}

// These benches are based on the specific filters in `sample_filter.json`, which has been
// anonymized by ../anonymize_pf.py. If you generate a new `sample_filter.json`, you will
// almost certainly need to update the IPs and ports used here.

// No match at all, expected to be slow for map-based filters, as they will need to iterate through
// everything
sample_bench!(
    can_access_sample_miss,
    "1.2.3.4",
    "5.6.7.8",
    [],
    pf::IpProto::TCP,
    5678,
    false
);

// Match a rule with a wildcard port
sample_bench!(
    can_access_sample_wildcard_port,
    "100.64.30.8",
    "100.64.244.211",
    [],
    pf::IpProto::TCP,
    5678,
    true
);

// Match a rule with a specific port but a wildcard ('*') destination IP
sample_bench!(
    can_access_sample_specific_port_wildcard_ip,
    "100.64.33.42",
    "5.6.7.8",
    [],
    pf::IpProto::TCP,
    40709,
    true
);

// Match a rule with a specific SrcIP and a specific port
sample_bench!(
    can_access_sample_specific_srcdst,
    "100.64.1.77",
    "100.64.122.188",
    [],
    pf::IpProto::TCP,
    51394,
    true
);
