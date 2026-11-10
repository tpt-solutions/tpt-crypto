//! Signature benchmarks, tracking the `tpt-crypto-sig` rows of
//! `benches/BUDGET.md` (Ed25519, ECDSA P-256/P-384, BLS12-381, ML-DSA-44/65/87).
//!
//! RSA-2048 PKCS#1 v1.5 verification uses the KAT vector from `tests/rsa.rs`.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use tpt_crypto_sig::ecdsa::{self, SigningKey, P256, P384};
use tpt_crypto_sig::ml_dsa::{self, MlDsa44, MlDsa65, MlDsa87};
use tpt_crypto_sig::rsa::{PublicKey as RsaPublicKey, RsaHash};
use tpt_crypto_sig::{bls, ed25519};

const MSG: &[u8] = b"tpt-crypto signature benchmark message";

// RSA-2048 KAT key and PKCS#1 v1.5 / SHA-256 vector from tests/rsa.rs (OpenSSL-generated).
const RSA_N_HEX: &str = "D19BD5872A55F4389C8BEEA7BF206E4A255C4FA413A8626A4B0A8E5EBAFA9869ABCE391667E9FBA2ED96D399A5E1D145C1807A2E4519091A69F22F3D4B49CC9A11D5B3FBD7CB26B6C610030C314CEB319FB0C98D3CA5CCC7FE7AAAD20CFA0A7E20AD660D11858CC40F69B1416332C5638DB756F5E2584B1F45002314DCBA8260C1D1B46DE621ABC96E73A710165F5164871BB2EB3E74141100285302CCD55D87403EC9B7035D5C3D3139B8E92783DF7E3AB24F878C64A42547F099A2C1E3AFE24E5C90120FB6E280BE7CB4AA26EA96BEF038F1B79015B73C41A9B04FE41E31D0BC65DF2664383041992B9C3559FB4F43647331FADD5DE15CCAE6304D6A6C5F47";
const RSA_SIG_P1_256: &str = "6b21c6e3dcbd45c59279464f2893adc5f49308d518a2440b22fb033bd1a52cb7b4d5054647a698e5e929bba5f4af79d46bc142412b0bf903134b6924fafcf0ea86f076105a8dd3377db05f056a2af2638a7c52f25b00bd041355bdc120672b15b7b23e9fba8af53491665c157963bdf77a82e183b3802271bd05b6634437f5739fac7cd1bfdc4482c0baeb4b7f7a5b0d6fa77e422bc69b7fc53bc3e6fea39254cdf9e7f4a90ae2c78738d640d7cfdcf3ba8e00cbccd2bf5449d321f00ff3be4bbd35512942f68289426063c20997ba2f7330491a58a6a66b8ead82811d5d25c0407bee870feb3016a80489d0062550835946dadf948a2541d2296d12244fc4d9";
const RSA_MSG: &[u8] = b"tpt-crypto RSA vector message";

fn hx(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn rsa_bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("sig");
    g.throughput(Throughput::Elements(1));

    let key = RsaPublicKey::from_components(&hx(RSA_N_HEX), &[0x01, 0x00, 0x01]).unwrap();
    let sig = hx(RSA_SIG_P1_256);
    g.bench_function("rsa2048/pkcs1v15_sha256/verify", |b| {
        b.iter(|| key.verify_pkcs1v15(RsaHash::Sha256, RSA_MSG, &sig).unwrap());
    });
    g.finish();
}

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

fn mldsa_bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("sig");
    g.throughput(Throughput::Elements(1));

    let seed = [0x33u8; 32];
    let (pk, sk) = ml_dsa::keygen_from_seed::<MlDsa44>(&seed);
    let sig = ml_dsa::sign(&sk, MSG, &[]).unwrap();
    g.bench_function("ml-dsa-44/sign", |b| {
        b.iter(|| ml_dsa::sign(&sk, MSG, &[]).unwrap());
    });
    g.bench_function("ml-dsa-44/verify", |b| {
        b.iter(|| ml_dsa::verify(&pk, MSG, &sig, &[]).unwrap());
    });

    let (pk, sk) = ml_dsa::keygen_from_seed::<MlDsa65>(&seed);
    let sig = ml_dsa::sign(&sk, MSG, &[]).unwrap();
    g.bench_function("ml-dsa-65/sign", |b| {
        b.iter(|| ml_dsa::sign(&sk, MSG, &[]).unwrap());
    });
    g.bench_function("ml-dsa-65/verify", |b| {
        b.iter(|| ml_dsa::verify(&pk, MSG, &sig, &[]).unwrap());
    });

    let (pk, sk) = ml_dsa::keygen_from_seed::<MlDsa87>(&seed);
    let sig = ml_dsa::sign(&sk, MSG, &[]).unwrap();
    g.bench_function("ml-dsa-87/sign", |b| {
        b.iter(|| ml_dsa::sign(&sk, MSG, &[]).unwrap());
    });
    g.bench_function("ml-dsa-87/verify", |b| {
        b.iter(|| ml_dsa::verify(&pk, MSG, &sig, &[]).unwrap());
    });
    g.finish();
}

criterion_group!(
    benches,
    eddsa,
    ecdsa_bench,
    bls_bench,
    mldsa_bench,
    rsa_bench
);
criterion_main!(benches);
