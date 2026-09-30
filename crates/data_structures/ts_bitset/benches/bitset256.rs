#![allow(missing_docs)]

//! Benchmark [`Bitset256`] operations.
//!
//! Based on [bart]'s benchmarks for its bitset type.

use divan::{Bencher, black_box};
use ts_bitset::Bitset256;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

fn default_testpattern() -> Bitset256 {
    Bitset256::from([0b1010_1010, 0b1010_1010, 0b1010_1010, 0b1010_1010])
}

fn set_testpattern() -> Bitset256 {
    Bitset256::from([0b1111_1111_1111; 4])
}

// These test-cases are copy-pasted from bart, unclear exactly what they're
// meant to be testing, but it works as a benchmark.
#[divan::bench(args = [64 * 4 - 1, 64 * 3 - 11, 64 * 2 - 11, 64 - 11, 1, 0])]
fn rank(bencher: Bencher, param: usize) {
    bencher
        .with_inputs(default_testpattern)
        .bench_values(|test_bitset| black_box(test_bitset).rank256(param));
}

#[divan::bench]
fn count_ones(bencher: Bencher) {
    bencher
        .with_inputs(default_testpattern)
        .bench_values(|pat_a| black_box(pat_a).count_ones());
}

#[divan::bench]
fn bit_or(bencher: Bencher) {
    bencher
        .with_inputs(|| (default_testpattern(), set_testpattern()))
        .bench_values(|(pat_a, pat_b)| black_box(pat_a) | black_box(pat_b));
}

#[divan::bench]
fn bit_or_assign(bencher: Bencher) {
    bencher
        .with_inputs(|| (default_testpattern(), set_testpattern()))
        .bench_values(|(pat_a, pat_b)| {
            let mut i = black_box(pat_a);
            i |= black_box(pat_b);
            i
        });
}

#[divan::bench]
fn bit_and(bencher: Bencher) {
    bencher
        .with_inputs(|| (default_testpattern(), set_testpattern()))
        .bench_values(|(pat_a, pat_b)| black_box(pat_a) & black_box(pat_b));
}

#[divan::bench]
fn bit_and_assign(bencher: Bencher) {
    bencher
        .with_inputs(|| (default_testpattern(), set_testpattern()))
        .bench_values(|(pat_a, pat_b)| {
            let mut i = black_box(pat_a);
            i &= black_box(pat_b);
            i
        });
}

const ONE_HOT: &[[u64; 4]] = &[
    [0, 0, 0, 0],
    [0, 0, 0, 1],
    [0, 0, 1, 0],
    [0, 1, 0, 0],
    [1, 0, 0, 0],
];

#[divan::bench(args = ONE_HOT)]
fn intersects(bencher: Bencher, i: &[u64; 4]) {
    bencher
        .with_inputs(|| (Bitset256::from([1, 1, 1, 1]), Bitset256::from(*i)))
        .bench_refs(|(reference, test)| black_box(reference).intersects(black_box(test)));
}

#[divan::bench(args = ONE_HOT)]
fn intersection_top(bencher: Bencher, i: &[u64; 4]) {
    bencher
        .with_inputs(|| Bitset256::from(*i))
        .bench_refs(|test| black_box(&test).intersection_top(black_box(test)));
}

#[divan::bench(args = ONE_HOT)]
fn first_set(bencher: Bencher, i: &[u64; 4]) {
    bencher
        .with_inputs(|| Bitset256::from(*i))
        .bench_refs(|test| black_box(&test).first_set());
}

#[divan::bench(args = ONE_HOT)]
fn last_set(bencher: Bencher, i: &[u64; 4]) {
    bencher
        .with_inputs(|| Bitset256::from(*i))
        .bench_refs(|test| black_box(&test).last_set());
}

#[divan::bench(args = ONE_HOT)]
fn next_set(bencher: Bencher, i: &[u64; 4]) {
    bencher
        .with_inputs(|| Bitset256::from(*i))
        .bench_refs(|test| black_box(&test).next_set(0));
}
