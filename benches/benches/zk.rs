//! Zero-knowledge benchmarks, tracking the `tpt-crypto-zk` rows of
//! `benches/BUDGET.md` (Bulletproofs prove/verify and Pedersen commitments).

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use tpt_crypto_zk::{
    bulletproofs::SeedExpander, prove_range, verify_range, Ed25519Scalar, PedersenGens,
};

fn zk(c: &mut Criterion) {
    let mut g = c.benchmark_group("zk");
    g.throughput(Throughput::Elements(1));

    // Single 32-bit range proof.
    let value = 1_000_000u64;
    let blind = Ed25519Scalar::from_u64(42);

    g.bench_function("bulletproofs/prove/1", |b| {
        b.iter(|| {
            let mut rng = SeedExpander::new(b"bench");
            core::hint::black_box(prove_range(&[value], &[blind], 32, &mut rng))
        })
    });

    // Pre-compute one proof so verification can be timed in isolation.
    let mut rng = SeedExpander::new(b"bench");
    let (proof, commitments) = prove_range(&[value], &[blind], 32, &mut rng);
    g.bench_function("bulletproofs/verify/1", |b| {
        b.iter(|| core::hint::black_box(verify_range(&commitments, &proof, 32).is_ok()))
    });

    let gens = PedersenGens::default();
    g.bench_function("pedersen/commit", |b| {
        b.iter(|| core::hint::black_box(gens.commit_u64(value, &blind)))
    });

    g.finish();
}

criterion_group!(benches, zk);
criterion_main!(benches);
