//! Temporary vector generator: writes `tests/kat/VECTORS.txt`.
//! Run with `cargo test -p tpt-crypto-zk --test generate_kat -- --nocapture`.

use std::io::Write;

use tpt_crypto_zk::{
    bulletproofs::SeedExpander, prove_range, range_proof_to_bytes, Ed25519Scalar,
    InnerProductProof, PedersenGens, Ristretto, Transcript,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Sanity-check the hex helpers used while generating the file.
#[test]
fn unhex_roundtrip() {
    assert_eq!(unhex("00ff10"), vec![0x00, 0xff, 0x10]);
}

fn range_vectors() -> String {
    let mut text = String::new();
    for (values, n, seed) in [
        (vec![0u64], 8usize, 1u64),
        (vec![255], 8, 2),
        (vec![0xDEAD_BEEF], 32, 3),
        (vec![1, 2], 8, 4),
        (vec![1, 2, 4, 8], 8, 5),
        (vec![u64::MAX], 64, 6),
    ] {
        let blinds: Vec<Ed25519Scalar> = (0..values.len())
            .map(|j| {
                Ed25519Scalar::from_u64(seed.wrapping_mul(0x9E37_79B9).wrapping_add(j as u64 + 1))
            })
            .collect();
        let mut rng = SeedExpander::new(&seed.to_le_bytes());
        let (proof, vs) = prove_range(&values, &blinds, n, &mut rng);
        text.push_str(&format!(
            "[range]\nvalues = {:?}\nn = {}\nseed = {}\ncommitments = {}\nproof = {}\n\n",
            values,
            n,
            seed,
            vs.iter()
                .map(|v| hex(&v.compress()))
                .collect::<Vec<_>>()
                .join(" "),
            hex(&range_proof_to_bytes(&proof)),
        ));
    }
    text
}

fn ipa_vector() -> String {
    let mut rng = SeedExpander::new(b"ipa-kat");
    let n = 8usize;
    let gen = |p: &[u8], i: usize| {
        let mut v = p.to_vec();
        v.extend_from_slice(&i.to_le_bytes());
        Ristretto::map_to_point(&v)
    };
    let g: Vec<Ristretto> = (0..n).map(|i| gen(b"kat.G", i)).collect();
    let h: Vec<Ristretto> = (0..n).map(|i| gen(b"kat.H", i)).collect();
    let a: Vec<Ed25519Scalar> = (0..n).map(|_| rng.next_scalar()).collect();
    let b: Vec<Ed25519Scalar> = (0..n).map(|_| rng.next_scalar()).collect();
    let g_factors = vec![Ed25519Scalar::one(); n];
    let h_factors: Vec<Ed25519Scalar> = (0..n)
        .map(|i| Ed25519Scalar::from_u64(i as u64 + 2))
        .collect();
    let q = Ristretto::map_to_point(b"kat.Q");

    let inner = a
        .iter()
        .zip(b.iter())
        .fold(Ed25519Scalar::zero(), |acc, (x, y)| acc.add(&x.mul(y)));
    let h_scaled: Vec<Ed25519Scalar> = (0..n).map(|i| h_factors[i].mul(&b[i])).collect();
    let p = Ristretto::msm(&a, &g)
        .add(&Ristretto::msm(&h_scaled, &h))
        .add(&q.scalar_mul(&inner));

    let mut t = Transcript::new(b"IPA-KAT");
    let proof = InnerProductProof::create(&mut t, &q, &g_factors, &h_factors, g, h, a, b);

    format!(
        "[ipa]\nn = {}\np = {}\nproof = {}\n\n",
        n,
        hex(&p.compress()),
        hex(&proof.to_bytes()),
    )
}

fn fixed_vectors() -> String {
    let pc = PedersenGens::default();
    let mut t = Transcript::new(b"KAT-domain");
    t.append_message(b"msg", b"hello");
    let ch = t.challenge_scalar(b"ch");

    format!(
        "[pedersen]\ng = {}\nh = {}\ncommit_12345_99 = {}\n\n\
         [transcript]\nchallenge = {}\n",
        hex(&pc.g.compress()),
        hex(&pc.h.compress()),
        hex(&pc
            .commit_u64(12345, &Ed25519Scalar::from_u64(99))
            .compress()),
        hex(&ch.to_bytes()),
    )
}

#[test]
fn generate_kat() {
    let text = format!(
        "# tpt-crypto-zk known-answer vectors (see PROVENANCE.md)\n\n{}{}{}",
        range_vectors(),
        ipa_vector(),
        fixed_vectors(),
    );
    std::fs::create_dir_all("tests/kat").unwrap();
    let mut f = std::fs::File::create("tests/kat/VECTORS.txt").unwrap();
    f.write_all(text.as_bytes()).unwrap();
    println!("wrote {} bytes to tests/kat/VECTORS.txt", text.len());
}
