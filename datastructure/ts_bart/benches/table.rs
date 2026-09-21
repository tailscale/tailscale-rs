#![allow(missing_docs)]

use common::{load_tables::*, matrix::*};
use divan::{Bencher, black_box};
use ts_bart::RoutingTable;

mod common;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

#[divan::bench(args = table_matrix())]
fn contains(bencher: Bencher, args: &ArgsType) {
    bencher
        .with_inputs(|| args.to_bench_args())
        .bench_local_values(|(table, addr)| black_box(table).contains(addr.addr()));
}

#[divan::bench(args = table_matrix())]
fn lookup(bencher: Bencher, args: &ArgsType) {
    bencher
        .with_inputs(|| args.to_bench_args())
        .bench_local_values(|(table, addr)| black_box(table).lookup(addr.addr()));
}

#[divan::bench(args = table_matrix())]
fn lookup_prefix(bencher: Bencher, args: &ArgsType) {
    bencher
        .with_inputs(|| args.to_bench_args())
        .bench_local_values(|(table, addr)| black_box(table).lookup_prefix(addr));
}

#[divan::bench(args = table_matrix())]
fn lookup_lpm(bencher: Bencher, args: &ArgsType) {
    bencher
        .with_inputs(|| args.to_bench_args())
        .bench_local_values(|(table, addr)| black_box(table).lookup_prefix_lpm(addr));
}

// Monomorphized benchmarks for a specific table, aiming to enable NRVO

#[divan::bench(name = "lookup_prefix_mono(simple/box/ipv4/hit/7.0.0.0/8)")]
fn lookup_prefix_mono(bencher: Bencher) {
    let addr = "7.0.0.0/8".parse().unwrap();
    let table = &*SIMPLE_BOX_V4;
    bencher.bench_local(|| black_box(table).lookup_prefix(addr));
}

#[divan::bench(name = "lookup_lpm_mono(simple/box/ipv4/hit/7.0.0.0/8)")]
fn lookup_lpm_mono(bencher: Bencher) {
    let addr = "7.0.0.0/8".parse().unwrap();
    let table = &*SIMPLE_BOX_V4;
    bencher.bench_local(|| black_box(table).lookup_prefix_lpm(addr));
}
