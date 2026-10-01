//! SLH-DSA (FIPS 205) KAT validation against NIST ACVP vectors
//! (`tests/kat/slh_dsa_acvp.txt`, distilled from the official
//! `usnistgov/ACVP-Server` `SLH-DSA-keyGen/sigGen/sigVer-FIPS205` validation
//! sets — see `tests/kat/PROVENANCE.md`).
//!
//! * `[kg]` — `keygen_from_seeds` reproduces the ACVP `sk`/`pk` bytes.
//! * `[sg-det]` — deterministic `sign` reproduces the ACVP signature bytes.
//! * `[sg-hedged]` — our `verify` accepts the hedged reference signatures.
//! * `[sv]` — `verify` accepts exactly the ACVP-valid signatures.
//!
//! All 12 parameter sets (SHA2/SHAKE × 128/192/256 × s/f).

use tpt_crypto_sig::slh_dsa::{
    keygen_from_seeds, public_key, sign, verify, PublicKey, SecretKey, Signature, SlhDsaParam,
};

const VECTORS: &str = include_str!("kat/slh_dsa_acvp.txt");

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

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

fn param(name: &str) -> SlhDsaParam {
    match name {
        "SLH-DSA-SHA2-128s" => SlhDsaParam::Sha2_128s,
        "SLH-DSA-SHA2-128f" => SlhDsaParam::Sha2_128f,
        "SLH-DSA-SHA2-192s" => SlhDsaParam::Sha2_192s,
        "SLH-DSA-SHA2-192f" => SlhDsaParam::Sha2_192f,
        "SLH-DSA-SHA2-256s" => SlhDsaParam::Sha2_256s,
        "SLH-DSA-SHA2-256f" => SlhDsaParam::Sha2_256f,
        "SLH-DSA-SHAKE-128s" => SlhDsaParam::Shake128s,
        "SLH-DSA-SHAKE-128f" => SlhDsaParam::Shake128f,
        "SLH-DSA-SHAKE-192s" => SlhDsaParam::Shake192s,
        "SLH-DSA-SHAKE-192f" => SlhDsaParam::Shake192f,
        "SLH-DSA-SHAKE-256s" => SlhDsaParam::Shake256s,
        "SLH-DSA-SHAKE-256f" => SlhDsaParam::Shake256f,
        other => panic!("unknown parameter set {other}"),
    }
}

#[test]
fn acvp_slh_dsa() {
    let records = parse(VECTORS);
    for r in &records {
        let param = param(f(r, "ps"));
        match r.kind.as_str() {
            "kg" => {
                let sk_seed = unhex(f(r, "skSeed"));
                let sk_prf = unhex(f(r, "skPrf"));
                let pk_seed = unhex(f(r, "pkSeed"));
                let (pk, sk) = keygen_from_seeds(param, &sk_seed, &sk_prf, &pk_seed)
                    .expect("keygen from seeds");
                assert_eq!(sk.bytes, unhex(f(r, "sk")), "[kg {}] sk", f(r, "count"));
                assert_eq!(pk.bytes, unhex(f(r, "pk")), "[kg {}] pk", f(r, "count"));
            }
            "sg-det" => {
                let sk = SecretKey::from_bytes(param, &unhex(f(r, "sk"))).expect("sk");
                let msg = unhex(f(r, "msg"));
                let ctx = unhex(f(r, "ctx"));
                let sig = sign(param, &sk, &msg, &ctx).expect("deterministic sign");
                assert_eq!(
                    sig.bytes,
                    unhex(f(r, "sig")),
                    "[sg-det {}] signature bytes",
                    f(r, "count")
                );
                let pk = public_key(param, &sk).expect("pk");
                verify(param, &pk, &msg, &sig, &ctx).expect("deterministic sig verifies");
            }
            "sg-hedged" => {
                let sk = SecretKey::from_bytes(param, &unhex(f(r, "sk"))).expect("sk");
                let msg = unhex(f(r, "msg"));
                let ctx = unhex(f(r, "ctx"));
                let sig = Signature::from_bytes(param, &unhex(f(r, "sig"))).expect("sig parses");
                let pk = public_key(param, &sk).expect("pk");
                verify(param, &pk, &msg, &sig, &ctx).expect("hedged reference sig verifies");
            }
            "sv" => {
                let want = f(r, "pass") == "true";
                let parsed = || {
                    let pk = PublicKey::from_bytes(param, &unhex(f(r, "pk"))).ok()?;
                    let sig = Signature::from_bytes(param, &unhex(f(r, "sig"))).ok()?;
                    Some((pk, sig))
                };
                let got = match parsed() {
                    Some((pk, sig)) => {
                        let msg = unhex(f(r, "msg"));
                        let ctx = unhex(f(r, "ctx"));
                        verify(param, &pk, &msg, &sig, &ctx).is_ok()
                    }
                    None => false,
                };
                assert_eq!(got, want, "[sv {}] verify mismatch", f(r, "count"));
            }
            other => panic!("unknown record kind {other}"),
        }
    }
}
