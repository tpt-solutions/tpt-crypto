//! AEAD throughput benchmarks, tracking the `tpt-crypto-aead` rows of
//! `benches/BUDGET.md`. Each construction encrypts a 1 KiB buffer.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use tpt_crypto_aead::{Aead, Aes128Gcm, Aes128GcmSiv, Aes256Gcm, ChaCha20Poly1305, Nonce};

const KB: usize = 1024;
const NONCE_12: [u8; 12] = [0x11; 12];

fn aead(c: &mut Criterion) {
    let data = vec![0x5Au8; KB];
    let aad = b"bench";
    let nonce = Nonce::<12>::new(NONCE_12);

    let mut g = c.benchmark_group("aead/1kb");
    g.throughput(Throughput::Bytes(KB as u64));

    let c128 = Aes128Gcm::new(&[0x01u8; 16]).expect("valid AES-128 key");
    g.bench_function("aes-128-gcm/1kb", |b| {
        b.iter(|| core::hint::black_box(c128.encrypt(&nonce, aad, &data)))
    });

    let c256 = Aes256Gcm::new(&[0x02u8; 32]).expect("valid AES-256 key");
    g.bench_function("aes-256-gcm/1kb", |b| {
        b.iter(|| core::hint::black_box(c256.encrypt(&nonce, aad, &data)))
    });

    let cc = ChaCha20Poly1305::new(&[0x03u8; 32]);
    g.bench_function("chacha20-poly1305/1kb", |b| {
        b.iter(|| core::hint::black_box(cc.encrypt(&nonce, aad, &data)))
    });

    let siv = Aes128GcmSiv::new(&[0x04u8; 16]).expect("valid AES-128-SIV key");
    g.bench_function("aes-128-gcm-siv/1kb", |b| {
        b.iter(|| core::hint::black_box(siv.encrypt(&nonce, aad, &data)))
    });

    g.finish();
}

criterion_group!(benches, aead);
criterion_main!(benches);
