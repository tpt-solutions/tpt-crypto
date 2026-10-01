//! Prime-field arithmetic benchmarks, tracking the `tpt-crypto-field` rows of
//! `benches/BUDGET.md`.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use tpt_crypto_field::{Bls12381Fp, Ed25519Scalar, P256Base};

fn field(c: &mut Criterion) {
    let mut g = c.benchmark_group("field/mul");

    let a = P256Base::from_u64(0x1234_5678_9abc_def0);
    let b = P256Base::from_u64(0x0fed_cba9_8765_4321);
    g.throughput(Throughput::Elements(1));
    g.bench_function("p256/mul", |x| {
        x.iter(|| core::hint::black_box(a.mul(&b)))
    });
    g.bench_function("p256/add", |x| {
        x.iter(|| core::hint::black_box(a.add(&b)))
    });

    let c = Bls12381Fp::from_u64(0x1234_5678_9abc_def0);
    let d = Bls12381Fp::from_u64(0x0fed_cba9_8765_4321);
    g.bench_function("bls12_381/fp/mul", |x| {
        x.iter(|| core::hint::black_box(c.mul(&d)))
    });

    let s = Ed25519Scalar::from_u64(12345);
    let t = Ed25519Scalar::from_u64(67890);
    g.bench_function("ed25519/scalar/mul", |x| {
        x.iter(|| core::hint::black_box(s.mul(&t)))
    });

    g.finish();
}

criterion_group!(benches, field);
criterion_main!(benches);