#![allow(missing_docs)]

use common::load_tables::*;
use divan::{Bencher, black_box};
use ts_bart::{RouteModification, RoutingTable, RoutingTableExt};

mod common;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

#[divan::bench]
fn insert_miss(bencher: Bencher) {
    #[allow(clippy::let_unit_value)]
    let contents = dummy_contents();

    let pfx = "1.2.3.4/32".parse::<ipnet::IpNet>().unwrap();

    let mut table = TABLE_BOX_V4.clone();
    prune_table(&mut table, "1.0.0.0/8".parse().unwrap());
    println!("table1 size: {}", table.size());

    bencher
        .with_inputs(|| table.clone())
        .bench_values(|table| black_box(table).insert(pfx, contents));
}

#[divan::bench]
fn insert_empty(bencher: Bencher) {
    #[allow(clippy::let_unit_value)]
    let contents = dummy_contents();

    let pfx = "1.2.3.4/32".parse::<ipnet::IpNet>().unwrap();

    bencher.bench(|| black_box(ts_bart::Table::EMPTY).insert(pfx, contents));
}

#[divan::bench]
fn insert_hit(bencher: Bencher) {
    #[allow(clippy::let_unit_value)]
    let contents = dummy_contents();

    let pfx = "7.0.0.0/8".parse().unwrap();

    let mut table = TABLE_BOX_V4.clone();
    prune_table(&mut table, "7.0.0.0/7".parse().unwrap());
    println!("table2 size: {}", table.size());

    bencher
        .with_inputs(|| table.clone())
        .bench_values(|table| black_box(table).insert(pfx, contents));
}

#[divan::bench]
fn modify_miss(bencher: Bencher) {
    let pfx = "1.2.3.4/32".parse::<ipnet::IpNet>().unwrap();

    let mut table = TABLE_BOX_V4.clone();
    prune_table(&mut table, "1.0.0.0/8".parse().unwrap());

    bencher
        .with_inputs(|| {
            let mut table = table.clone();
            table.remove(pfx);
            table
        })
        .bench_values(|table| black_box(table).modify(pfx, |_| RouteModification::Noop));
}

#[divan::bench]
fn modify_empty(bencher: Bencher) {
    let pfx = "1.2.3.4/32".parse::<ipnet::IpNet>().unwrap();

    bencher.bench(|| {
        let table = ts_bart::Table::<TableContents>::EMPTY;
        black_box(table).modify(pfx, |_| RouteModification::Noop);
    });
}

#[divan::bench]
fn modify_hit(bencher: Bencher) {
    let pfx = "7.0.0.0/8".parse().unwrap();

    let mut table = TABLE_BOX_V4.clone();
    prune_table(&mut table, "7.0.0.0/7".parse().unwrap());

    bencher
        .with_inputs(|| {
            let mut table = table.clone();
            #[allow(clippy::unit_arg)]
            table.insert(pfx, dummy_contents());
            table
        })
        .bench_values(|table| black_box(table).modify(pfx, |_| RouteModification::Noop));
}

#[divan::bench]
fn remove_miss(bencher: Bencher) {
    let pfx = "1.2.3.4/32".parse::<ipnet::IpNet>().unwrap();

    let mut table = TABLE_BOX_V4.clone();
    prune_table(&mut table, "1.0.0.0/8".parse().unwrap());

    bencher
        .with_inputs(|| {
            let mut table = table.clone();
            table.remove(pfx);
            table
        })
        .bench_values(|table| black_box(table).remove(pfx));
}

#[divan::bench]
fn remove_empty(bencher: Bencher) {
    let pfx = "1.2.3.4/32".parse::<ipnet::IpNet>().unwrap();

    bencher.bench(|| {
        let table = ts_bart::Table::<TableContents>::EMPTY;
        black_box(table).remove(pfx);
    });
}

#[divan::bench]
fn remove_hit(bencher: Bencher) {
    let pfx = "7.0.0.0/8".parse().unwrap();

    let mut table = TABLE_BOX_V4.clone();
    prune_table(&mut table, "7.0.0.0/7".parse().unwrap());

    bencher
        .with_inputs(|| {
            let mut table = table.clone();
            #[allow(clippy::unit_arg)]
            table.insert(pfx, dummy_contents());
            table
        })
        .bench_values(|table| black_box(table).remove(pfx));
}

fn prune_table<T>(table: &mut dyn RoutingTable<Value = T>, keep_root: ipnet::IpNet)
where
    T: 'static,
{
    for pfx in &*PREFIXES_V4 {
        if !keep_root.contains(pfx) {
            table.remove(*pfx);
        }
    }
}
