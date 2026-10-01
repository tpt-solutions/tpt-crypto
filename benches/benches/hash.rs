//! Hash-function throughput benchmarks, tracking the `tpt-crypto-hash` rows of
//! `benches/BUDGET.md`. Throughput is reported over 1 KiB inputs.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use tpt_crypto_hash::blake2b::Blake2b;
use tpt_crypto_hash::blake3::blake3;
use tpt_crypto_hash::k12::kangaroo_twelve;
use tpt_crypto_hash::sha2::Sha256;
use tpt_crypto_hash::sha3::{Sha3_256, Shake128};
use tpt_crypto_hash::{Hasher, Xof};

const KB: usize = 1024;

fn hash(c: &mut Criterion) {
    let data = vec![0xABu8; KB];
    let mut g = c.benchmark_group("hash/1kb");
    g.throughput(Throughput::Bytes(KB as u64));

    g.bench_function("blake2b/1kb", |b| {
        b.iter(|| {
            let mut h = Blake2b::<64>::new();
            h.update(&data);
            core::hint::black_box(h.finalize())
        })
    });

    g.bench_function("sha2-256/1kb", |b| {
        b.iter(|| {
            let mut h = Sha256::new();
            h.update(&data);
            core::hint::black_box(h.finalize())
        })
    });

    g.bench_function("sha3-256/1kb", |b| {
        b.iter(|| {
            let mut h = Sha3_256::new();
            h.update(&data);
            core::hint::black_box(h.finalize())
        })
    });

    g.bench_function("blake3/1kb", |b| {
        b.iter(|| core::hint::black_box(blake3(&data)))
    });

    // K12 and SHAKE are XOFs: squeeze a fixed 32-byte output per iteration.
    let mut out = [0u8; 32];
    g.bench_function("k12/1kb", |b| {
        b.iter(|| {
            kangaroo_twelve(&data, &[], &mut out);
            core::hint::black_box(out)
        })
    });

    g.bench_function("shake128/1kb", |b| {
        b.iter(|| {
            let mut x = Shake128::new();
            x.update(&data);
            x.finalize_xof(&mut out);
            core::hint::black_box(out)
        })
    });

    g.finish();
}

criterion_group!(benches, hash);
criterion_main!(benches);