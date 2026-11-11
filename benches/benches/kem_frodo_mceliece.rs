//! FrodoKEM-640-SHAKE and Classic McEliece mceliece348864 benchmarks, tracking the
//! `tpt-crypto-kem` rows of `benches/BUDGET.md` for those sets.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use tpt_crypto_core::{CryptoRng, Error};
use tpt_crypto_kem::frodo::shake::{decapsulate as frodo_decaps, encapsulate as frodo_encaps, keygen as frodo_keygen};
use tpt_crypto_kem::frodo::Frodo640;
use tpt_crypto_kem::mceliece::{decapsulate as mc_decaps, encapsulate as mc_encaps, keypair as mc_keypair, Mc348864};

/// A cheap deterministic `CryptoRng` for benchmarking (not for production use).
struct BenchRng(u64);

impl CryptoRng for BenchRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        for b in dest.iter_mut() {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            *b = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as u8;
        }
        Ok(())
    }
}

fn frodo(c: &mut Criterion) {
    let mut g = c.benchmark_group("frodokem-640-shake");
    g.throughput(Throughput::Elements(1));
    let mut rng = BenchRng(0x9E37_79B9_7F4A_7C15);
    let (pk, sk) = frodo_keygen::<Frodo640>(&mut rng).expect("keygen");
    g.bench_function("keygen", |b| {
        let mut r = BenchRng(1);
        b.iter(|| core::hint::black_box(frodo_keygen::<Frodo640>(&mut r).unwrap()))
    });
    g.bench_function("encaps", |b| {
        let mut r = BenchRng(2);
        b.iter(|| core::hint::black_box(frodo_encaps::<Frodo640>(&pk, &mut r).unwrap()))
    });
    let (ct, _) = frodo_encaps::<Frodo640>(&pk, &mut rng).expect("encaps");
    g.bench_function("decaps", |b| {
        b.iter(|| core::hint::black_box(frodo_decaps::<Frodo640>(&sk, &ct).unwrap()))
    });
    g.finish();
}

fn mceliece(c: &mut Criterion) {
    let mut g = c.benchmark_group("mceliece-348864");
    g.sample_size(10);
    g.throughput(Throughput::Elements(1));
    let mut rng = BenchRng(0x9E37_79B9_7F4A_7C15);
    let (pk, sk) = mc_keypair::<Mc348864>(&mut rng).expect("keypair");
    g.bench_function("keygen", |b| {
        let mut r = BenchRng(1);
        b.iter(|| core::hint::black_box(mc_keypair::<Mc348864>(&mut r).unwrap()))
    });
    g.bench_function("encaps", |b| {
        let mut r = BenchRng(2);
        b.iter(|| core::hint::black_box(mc_encaps::<Mc348864>(&pk, &mut r).unwrap()))
    });
    let (ct, _) = mc_encaps::<Mc348864>(&pk, &mut rng).expect("encaps");
    g.bench_function("decaps", |b| {
        b.iter(|| core::hint::black_box(mc_decaps::<Mc348864>(&sk, &ct).unwrap()))
    });
    g.finish();
}

criterion_group!(benches, frodo, mceliece);
criterion_main!(benches);
