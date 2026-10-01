//! ML-KEM benchmarks, tracking the `tpt-crypto-kem` rows of `benches/BUDGET.md`
//! (keygen / encaps / decaps for the 768 and 1024 parameter sets).

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use tpt_crypto_core::CryptoRng;
use tpt_crypto_kem::ml_kem::{decapsulate, encapsulate, keygen};
use tpt_crypto_kem::{MlKem1024, MlKem768};

/// A cheap deterministic `CryptoRng` for benchmarking (not for production use).
struct BenchRng(u64);

impl CryptoRng for BenchRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            // xorshift64*
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            *b = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as u8;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), tpt_crypto_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

fn kem(c: &mut Criterion) {
    let mut g = c.benchmark_group("ml-kem");
    g.throughput(Throughput::Elements(1));

    {
        let mut rng = BenchRng(0x9E37_79B9_7F4A_7C15);
        let (pk, sk) = keygen::<MlKem768>(&mut rng);

        g.bench_function("ml-kem-768/keygen", |b| {
            let mut r = BenchRng(1);
            b.iter(|| core::hint::black_box(keygen::<MlKem768>(&mut r)))
        });

        g.bench_function("ml-kem-768/encaps", |b| {
            let mut r = BenchRng(2);
            b.iter(|| core::hint::black_box(encapsulate::<MlKem768>(&pk, &mut r)))
        });

        let (ss, ct) = encapsulate::<MlKem768>(&pk, &mut rng);
        let _ = ss;
        let ct_bytes = ct.as_bytes().to_vec();
        g.bench_function("ml-kem-768/decaps", |b| {
            b.iter(|| core::hint::black_box(decapsulate::<MlKem768>(&sk, &ct_bytes)))
        });
    }

    {
        let mut rng = BenchRng(0xDEAD_BEEF_CAFE_F00D);
        g.bench_function("ml-kem-1024/keygen", |b| {
            let mut r = BenchRng(3);
            b.iter(|| core::hint::black_box(keygen::<MlKem1024>(&mut r)))
        });
    }

    g.finish();
}

criterion_group!(benches, kem);
criterion_main!(benches);
