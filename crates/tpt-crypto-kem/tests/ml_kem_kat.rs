//! FIPS 203 KAT validation against the official
//! <https://github.com/post-quantum-cryptography/KAT> `.rsp` vectors.
//!
//! Each vector records seeds `d`/`z`, the encapsulation message `m`, the
//! resulting keypair, a valid ciphertext/shared-secret pair, and an invalid
//! ciphertext `ct_n` with its implicit-rejection shared secret `ss_n`. See
//! `tests/kat/PROVENANCE.md` for source and checksums.

use std::collections::BTreeMap;

use tpt_crypto_kem::ml_kem::{
    decapsulate, encapsulate_msg, keygen_seed, DecapsKey, EncapsKey, MlKem1024, MlKem512, MlKem768,
};
use tpt_crypto_kem::params::MlKemParams;

/// One parsed KAT record.
struct KatVector {
    count: u32,
    d: [u8; 32],
    z: [u8; 32],
    msg: [u8; 32],
    pk: Vec<u8>,
    sk: Vec<u8>,
    ct: Vec<u8>,
    ss: [u8; 32],
    ct_n: Vec<u8>,
    ss_n: [u8; 32],
}

fn arr32(v: &[u8]) -> [u8; 32] {
    v.try_into().expect("32 bytes")
}

/// Parse a `key = value` `.rsp` file into per-`count` records.
fn parse_rsp(path: &str) -> Vec<KatVector> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut out: Vec<KatVector> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("bad line: {line:?}"));
        let key = key.trim();
        if key == "count" && !fields.is_empty() {
            out.push(vector_from_fields(&fields));
            fields.clear();
        }
        fields.insert(key.to_string(), value.trim().to_string());
    }
    if !fields.is_empty() {
        out.push(vector_from_fields(&fields));
    }
    assert!(!out.is_empty(), "no vectors parsed from {path}");
    out
}

fn vector_from_fields(f: &BTreeMap<String, String>) -> KatVector {
    let hex =
        |k: &str| -> Vec<u8> { hex::decode(&f[k]).unwrap_or_else(|e| panic!("hex[{k}]: {e}")) };
    KatVector {
        count: f["count"].parse().expect("count"),
        d: arr32(&hex("d")),
        z: arr32(&hex("z")),
        msg: arr32(&hex("msg")),
        pk: hex("pk"),
        sk: hex("sk"),
        ct: hex("ct"),
        ss: arr32(&hex("ss")),
        ct_n: hex("ct_n"),
        ss_n: arr32(&hex("ss_n")),
    }
}

/// Verify every vector of `path` against the reference implementation.
fn check_file<P: MlKemParams>(path: &str) {
    let vectors = parse_rsp(path);
    for v in &vectors {
        let (ek, dk) = keygen_seed::<P>(&v.d, &v.z);
        assert_eq!(&ek.bytes, &v.pk, "[{path}] count {} pk", v.count);
        assert_eq!(&dk.bytes, &v.sk, "[{path}] count {} sk", v.count);

        let ek = EncapsKey::from_bytes::<P>(&v.pk).expect("valid pk length");
        let dk = DecapsKey::from_bytes::<P>(&v.sk).expect("valid sk length");

        let (ss, ct) = encapsulate_msg::<P>(&ek, &v.msg);
        assert_eq!(&ct.bytes, &v.ct, "[{path}] count {} ct", v.count);
        assert_eq!(&ss, &v.ss, "[{path}] count {} ss", v.count);

        let ss2 = decapsulate::<P>(&dk, &v.ct).expect("valid ct decapsulates");
        assert_eq!(ss2, v.ss, "[{path}] count {} decaps", v.count);

        // Implicit rejection: an invalid ciphertext yields the recorded ss_n.
        let ss_adv = decapsulate::<P>(&dk, &v.ct_n).expect("well-formed ct decapsulates");
        assert_eq!(
            ss_adv, v.ss_n,
            "[{path}] count {} implicit rejection",
            v.count
        );
    }
}

#[test]
fn kat_ml_kem_512() {
    check_file::<MlKem512>(&kat_path("fips203_512.rsp"));
}

#[test]
fn kat_ml_kem_768() {
    check_file::<MlKem768>(&kat_path("fips203_768.rsp"));
}

#[test]
fn kat_ml_kem_1024() {
    check_file::<MlKem1024>(&kat_path("fips203_1024.rsp"));
}

fn kat_path(name: &str) -> String {
    format!("{}/tests/kat/{name}", env!("CARGO_MANIFEST_DIR"))
}
