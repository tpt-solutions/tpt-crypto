//! Criterion benchmarks for the constant-time primitives in `tpt-crypto-core`.
//!
//! Run with `cargo bench -p tpt-crypto-core`. The numbers feed
//! `benches/BUDGET.md`, which records the vs-`zeroize`/`subtle`/hand-rolled
//! performance targets.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use tpt_crypto_core::zeroize::Zeroize;
use tpt_crypto_core::{ct_eq, ct_select, Choice};

fn bench_ct_select_u64(c: &mut Criterion) {
    let a = 0xDEAD_BEEF_1234_5678u64;
    let b = 0x0123_4567_89AB_CDEFu64;
    let set = Choice::from_u8(1);
    let unset = Choice::from_u8(0);
    c.bench_function("ct_select/u64/set", |bench| {
        bench.iter(|| ct_select(&a, &b, set))
    });
    c.bench_function("ct_select/u64/unset", |bench| {
        bench.iter(|| ct_select(&a, &b, unset))
    });
}

fn bench_ct_eq_slice(c: &mut Criterion) {
    for len in [16usize, 32, 64] {
        let a = vec![0xABu8; len];
        let b = vec![0xABu8; len];
        c.bench_with_input(BenchmarkId::new("ct_eq/slice", len), &len, |bench, _| {
            bench.iter(|| ct_eq(a.as_slice(), b.as_slice()))
        });
    }
}

fn bench_zeroize(c: &mut Criterion) {
    for len in [16usize, 64, 256] {
        c.bench_with_input(
            BenchmarkId::new("zeroize/array", len),
            &len,
            |bench, &len| {
                bench.iter(|| {
                    let mut buf = vec![0xFFu8; len];
                    buf.zeroize();
                    buf
                });
            },
        );
    }
}

criterion_group!(
    benches,
    bench_ct_select_u64,
    bench_ct_eq_slice,
    bench_zeroize
);
criterion_main!(benches);
