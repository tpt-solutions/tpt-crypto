//! ML-DSA (FIPS 204) KAT validation against NIST ACVP vectors
//! (`tests/kat/ml_dsa_acvp.txt`, distilled from the official
//! `usnistgov/ACVP-Server` `ML-DSA-keyGen-FIPS204` and `ML-DSA-sigVer-FIPS204`
//! validation sets — see `tests/kat/PROVENANCE.md`).
//!
//! * `[kg]` records: deterministic `keygen_from_seed(ξ)` must reproduce the
//!   ACVP public and secret key bytes for all three parameter sets.
//! * `[sv]` records: `verify` must accept exactly the ACVP-valid signatures
//!   (`external` / pure / no-prehash interface).

use tpt_crypto_sig::ml_dsa::{
    keygen_from_seed, verify, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, PublicKey, Signature,
};

const VECTORS: &str = include_str!("kat/ml_dsa_acvp.txt");

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// One `[section]` block of `key = value` fields.
struct Record {
    kind: String,
    fields: Vec<(String, String)>,
}

fn parse(text: &str) -> Vec<Record> {
    let mut out: Vec<Record> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push(Record {
                kind: name.to_string(),
                fields: Vec::new(),
            });
            continue;
        }
        let (k, v) = line.split_once('=').expect("`key = value` line");
        out.last_mut()
            .expect("field inside a section")
            .fields
            .push((k.trim().to_string(), v.trim().to_string()));
    }
    out
}

fn f<'a>(r: &'a Record, key: &str) -> &'a str {
    &r.fields.iter().find(|(k, _)| k == key).expect(key).1
}

fn run_kg<P: MlDsaParams>(records: &[&Record]) {
    for r in records {
        let seed: [u8; 32] = unhex(f(r, "seed")).try_into().expect("32-byte seed");
        let (pk, sk) = keygen_from_seed::<P>(&seed);
        assert_eq!(
            sk.bytes,
            unhex(f(r, "sk")),
            "[kg count {}] sk",
            f(r, "count")
        );
        assert_eq!(
            pk.bytes,
            unhex(f(r, "pk")),
            "[kg count {}] pk",
            f(r, "count")
        );
    }
}

fn run_sv<P: MlDsaParams>(records: &[&Record]) {
    for r in records {
        let want = f(r, "pass") == "true";
        // Malformed keys/signatures (negative ACVP cases) must parse-fail, not
        // panic; a parse failure counts as a rejected signature.
        let parsed = || {
            Some((
                PublicKey::<P>::from_bytes(&unhex(f(r, "pk")))?,
                Signature::<P>::from_bytes(&unhex(f(r, "sig")))?,
            ))
        };
        let got = match parsed() {
            Some((pk, sig)) => {
                let msg = unhex(f(r, "msg"));
                let ctx = unhex(f(r, "ctx"));
                verify::<P>(&pk, &msg, &sig, &ctx).is_ok()
            }
            None => false,
        };
        assert_eq!(
            got,
            want,
            "[sv ps {} count {}] expected pass={} (msglen {}, ctxlen {})",
            f(r, "ps"),
            f(r, "count"),
            want,
            f(r, "msg").len() / 2,
            f(r, "ctx").len() / 2
        );
    }
}

#[test]
fn acvp_ml_dsa() {
    let records = parse(VECTORS);
    let kg: Vec<&Record> = records.iter().filter(|r| r.kind == "kg").collect();
    let sv: Vec<&Record> = records.iter().filter(|r| r.kind == "sv").collect();
    assert_eq!(kg.len(), 30, "expected 30 keyGen records");
    assert_eq!(sv.len(), 45, "expected 45 sigVer records");

    for ps in 0..3 {
        let name = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"][ps];
        let kg_ps: Vec<&Record> = kg.iter().filter(|r| f(r, "ps") == name).copied().collect();
        let sv_ps: Vec<&Record> = sv.iter().filter(|r| f(r, "ps") == name).copied().collect();
        match ps {
            0 => {
                run_kg::<MlDsa44>(&kg_ps);
                run_sv::<MlDsa44>(&sv_ps);
            }
            1 => {
                run_kg::<MlDsa65>(&kg_ps);
                run_sv::<MlDsa65>(&sv_ps);
            }
            _ => {
                run_kg::<MlDsa87>(&kg_ps);
                run_sv::<MlDsa87>(&sv_ps);
            }
        }
    }
}
