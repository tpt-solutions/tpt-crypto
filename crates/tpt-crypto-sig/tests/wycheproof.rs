//! Project Wycheproof (testvectors_v1) verify-vector harness for Ed25519 and
//! ECDSA P-256 / P-384 (`tests/kat/wycheproof.txt`, distilled — see
//! `tests/kat/PROVENANCE.md`).
//!
//! Policy: a record must be **accepted iff it is a canonical valid
//! signature** — `result = valid` and, for ECDSA, `s` in the low half
//! (`high_s = 0`). The corpus marks high-`s` signatures plain `valid` (the
//! `SignatureMalleability` flag only appears in newer generators), but this
//! crate canonicalises to low-`S` on sign and rejects high-`S` on verify
//! (the Bitcoin / BearSSL policy), so those records must fail. Any failure at
//! any stage (public-key parse, signature parse, verification) counts as a
//! rejection.

use tpt_crypto_hash::sha2::{Sha256, Sha384};
use tpt_crypto_hash::Hasher;
use tpt_crypto_sig as sig;
use tpt_crypto_sig::ecdsa::{EcdsaCurve, P256, P384};

const VECTORS: &str = include_str!("kat/wycheproof.txt");

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

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// True iff the record must verify: `result = valid` and (ECDSA) low-`s`.
fn want_accept(r: &Record) -> bool {
    let valid = f(r, "result") == "valid";
    let high_s = r
        .fields
        .iter()
        .find(|(k, _)| k == "high_s")
        .map(|(_, v)| v.as_str())
        .unwrap_or("0")
        != "0";
    valid && !high_s
}

/// Flags reported in the assert message (absent on most records).
fn flags_of(r: &Record) -> &str {
    r.fields
        .iter()
        .find(|(k, _)| k == "flags")
        .map(|(_, v)| v.as_str())
        .unwrap_or("-")
}

fn digest_sha256(msg: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(msg);
    h.finalize().to_vec()
}

fn digest_sha384(msg: &[u8]) -> Vec<u8> {
    let mut h = Sha384::new();
    h.update(msg);
    h.finalize().to_vec()
}

fn ecdsa_try_verify<C: EcdsaCurve>(r: &Record, digest: fn(&[u8]) -> Vec<u8>) -> bool {
    let pk = unhex(f(r, "pk"));
    let Ok(vk) = sig::ecdsa::VerifyingKey::<C>::from_sec1(&pk) else {
        return false;
    };
    let der = unhex(f(r, "sig"));
    let Ok(s) = sig::ecdsa::Signature::<C>::from_der(&der) else {
        return false;
    };
    let prehash = digest(&unhex(f(r, "msg")));
    sig::ecdsa::VerifyingKey::<C>::verify_prehash(&vk, &prehash, &s).is_ok()
}

fn run_ecdsa<C: EcdsaCurve>(records: &[&Record], digest: fn(&[u8]) -> Vec<u8>) {
    for r in records {
        let got = ecdsa_try_verify::<C>(r, digest);
        assert_eq!(
            got,
            want_accept(r),
            "[{} tcId {}] expected result={} (flags: {})",
            f(r, "curve"),
            f(r, "count"),
            f(r, "result"),
            flags_of(r),
        );
    }
}

#[test]
fn wycheproof_ecdsa_p256_sha256() {
    let records = parse(VECTORS);
    let mine: Vec<&Record> = records
        .iter()
        .filter(|r| r.kind == "sv" && f(r, "curve") == "P-256")
        .collect();
    assert_eq!(mine.len(), 484, "expected 484 P-256 records");
    run_ecdsa::<P256>(&mine, digest_sha256);
}

#[test]
fn wycheproof_ecdsa_p384_sha384() {
    let records = parse(VECTORS);
    let mine: Vec<&Record> = records
        .iter()
        .filter(|r| r.kind == "sv" && f(r, "curve") == "P-384")
        .collect();
    assert_eq!(mine.len(), 504, "expected 504 P-384 records");
    run_ecdsa::<P384>(&mine, digest_sha384);
}

#[test]
fn wycheproof_ed25519() {
    let records = parse(VECTORS);
    let mine: Vec<&Record> = records
        .iter()
        .filter(|r| r.kind == "sv" && f(r, "curve") == "ED25519")
        .collect();
    assert_eq!(mine.len(), 151, "expected 151 Ed25519 records");

    for r in mine {
        let got = (|| -> bool {
            let pk: [u8; 32] = match unhex(f(r, "pk")).try_into() {
                Ok(pk) => pk,
                Err(_) => return false,
            };
            let Some(vk) = sig::ed25519::VerifyingKey::from_bytes(&pk).ok() else {
                return false;
            };
            let raw = unhex(f(r, "sig"));
            if raw.len() != sig::ed25519::SIGNATURE_LEN {
                return false;
            }
            let s = sig::ed25519::Signature::from_bytes(raw.try_into().expect("64 bytes"));
            vk.verify(&unhex(f(r, "msg")), &s).is_ok()
        })();
        assert_eq!(
            got,
            want_accept(r),
            "[ED25519 tcId {}] expected result={} (flags: {})",
            f(r, "count"),
            f(r, "result"),
            flags_of(r),
        );
    }
}
