//! Signature benchmarks, tracking the `tpt-crypto-sig` rows of
//! `benches/BUDGET.md` (Ed25519, ECDSA P-256/P-384, BLS12-381).

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use tpt_crypto_sig::ecdsa::{self, SigningKey, P256, P384};
use tpt_crypto_sig::{bls, ed25519};

const MSG: &[u8] = b"tpt-crypto signature benchmark message";

fn eddsa(c: &mut Criterion) {
    let mut g = c.benchmark_group("sig");
    g.throughput(Throughput::Elements(1));

    let sk = ed25519::SigningKey::from_seed([7u8; 32]);
    let vk = sk.verifying_key();
    let sig = sk.sign(MSG);
    g.bench_function("ed25519/sign", |b| b.iter(|| sk.sign(MSG)));
    g.bench_function("ed25519/verify", |b| {
        b.iter(|| vk.verify(MSG, &sig).unwrap());
    });
    g.finish();
}

fn ecdsa_bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("sig");
    g.throughput(Throughput::Elements(1));

    let sk = SigningKey::<P256>::from_bytes(&[0x11u8; 32]).unwrap();
    let vk = sk.verifying_key();
    let digest = [0x5Au8; 32];
    let sig = sk.sign_prehash(&digest).unwrap();
    g.bench_function("ecdsa-p256/sign", |b| {
        b.iter(|| ecdsa::sign_p256_sha256(&sk, MSG).unwrap());
    });
    g.bench_function("ecdsa-p256/verify", |b| {
        b.iter(|| vk.verify_prehash(&digest, &sig).unwrap());
    });

    let sk = SigningKey::<P384>::from_bytes(&[0x22u8; 48]).unwrap();
    g.bench_function("ecdsa-p384/sign", |b| {
        b.iter(|| ecdsa::sign_p384_sha384(&sk, MSG).unwrap());
    });
    g.finish();
}

fn bls_bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("sig");
    g.throughput(Throughput::Elements(1));
    g.sample_size(10);

    let sk = bls::SecretKey::keygen(&[9u8; 32]).unwrap();
    let pk = sk.public_key();
    let sig = bls::sign(&sk, MSG);
    g.bench_function("bls12-381/sign", |b| b.iter(|| bls::sign(&sk, MSG)));
    g.bench_function("bls12-381/verify", |b| {
        b.iter(|| bls::verify(&pk, MSG, &sig).unwrap());
    });

    let (pks, sigs): (Vec<_>, Vec<_>) = (0u8..64)
        .map(|i| {
            let sk = bls::SecretKey::keygen(&[i.wrapping_add(1); 32]).unwrap();
            (sk.public_key(), bls::sign(&sk, MSG))
        })
        .unzip();
    let agg = bls::aggregate(&sigs).unwrap();
    g.bench_function("bls12-381/verify-agg/64", |b| {
        b.iter(|| bls::verify_aggregate(&pks, MSG, &agg).unwrap());
    });
    g.finish();
}

criterion_group!(benches, eddsa, ecdsa_bench, bls_bench);
criterion_main!(benches);
