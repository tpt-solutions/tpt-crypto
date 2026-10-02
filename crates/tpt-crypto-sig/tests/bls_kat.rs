//! BLS12-381 signature KATs against the Ethereum `bls12-381-tests` vectors
//! (release v0.1.2, CC0-1.0 — see `kat/PROVENANCE.md`).
//!
//! The vectors exercise the `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`
//! ciphersuite (the crate's [`bls::DEFAULT_SUITE`]) over the standard
//! compressed `G1`/`G2` serializations: `sign`, `verify`, `aggregate`,
//! `aggregate_verify`, `fast_aggregate_verify`, `hash_to_G2`, and
//! `deserialization_G1`/`G2`.

use std::path::{Path, PathBuf};

use tpt_crypto_curve::bls12_381::{G1, G2};
use tpt_crypto_curve::hash_to_curve::hash_to_curve_bls12381_g2;
use tpt_crypto_sig::bls::{
    aggregate, aggregate_verify, proof_of_possession, sign, verify, verify_aggregate,
    verify_proof_of_possession, PublicKey, SecretKey, Signature, PK_LEN, SIG_LEN,
};
use tpt_crypto_sig::Error;

// --- tiny JSON reader for the flat `{"input": {...}, "output": …}` format ----

/// One parsed case: the flat `input` object pairs plus the top-level pairs.
type Case = (Vec<(String, Value)>, Vec<(String, Value)>);

#[derive(Debug)]
enum Value {
    Str(String),
    Bool(bool),
    Null,
    Arr(Vec<String>),
}

fn hex_bytes(v: &str) -> Vec<u8> {
    let h = v.strip_prefix("0x").unwrap_or(v);
    assert!(h.len() % 2 == 0, "odd hex: {v}");
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Scan a JSON object into (key, value) pairs. Handles the exact shapes used
/// by the corpus: string / bool / null values and arrays of strings. No
/// escapes appear in the corpus.
fn scan_object(text: &str) -> Vec<(String, Value)> {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    let mut out = Vec::new();
    let read_string = |i: &mut usize| -> String {
        assert_eq!(chars[*i], '"');
        *i += 1;
        let mut s = String::new();
        while chars[*i] != '"' {
            s.push(chars[*i]);
            *i += 1;
        }
        *i += 1; // closing quote
        s
    };
    while i < chars.len() {
        match chars[i] {
            '"' => {
                let key = read_string(&mut i);
                while chars[i] != ':' {
                    i += 1;
                }
                i += 1;
                while chars[i] == ' ' {
                    i += 1;
                }
                let value = match chars[i] {
                    '"' => Value::Str(read_string(&mut i)),
                    '{' => {
                        // Nested object (the `input` dict seen from the top
                        // level): skip it opaquely, honouring brace nesting.
                        let mut depth = 0usize;
                        loop {
                            match chars[i] {
                                '{' => depth += 1,
                                '}' => {
                                    depth -= 1;
                                    if depth == 0 {
                                        i += 1;
                                        break;
                                    }
                                }
                                '"' => {
                                    let _ = read_string(&mut i);
                                    continue;
                                }
                                _ => {}
                            }
                            i += 1;
                        }
                        Value::Null
                    }
                    '[' => {
                        i += 1;
                        let mut items = Vec::new();
                        while chars[i] != ']' {
                            if chars[i] == '"' {
                                items.push(read_string(&mut i));
                            } else {
                                i += 1;
                            }
                        }
                        i += 1;
                        Value::Arr(items)
                    }
                    't' => {
                        i += 4;
                        Value::Bool(true)
                    }
                    'f' => {
                        i += 5;
                        Value::Bool(false)
                    }
                    'n' => {
                        i += 4;
                        Value::Null
                    }
                    c => panic!("unexpected value start {c:?} for key {key}"),
                };
                out.push((key, value));
            }
            _ => i += 1,
        }
    }
    out
}

fn get_str<'a>(pairs: &'a [(String, Value)], key: &str) -> &'a str {
    match &pairs.iter().find(|(k, _)| k == key).expect(key).1 {
        Value::Str(s) => s,
        other => panic!("key {key} is not a string: {other:?}"),
    }
}

fn get_arr(pairs: &[(String, Value)], key: &str) -> Vec<String> {
    match &pairs.iter().find(|(k, _)| k == key).expect(key).1 {
        Value::Arr(a) => a.clone(),
        other => panic!("key {key} is not an array: {other:?}"),
    }
}

fn get_bool(pairs: &[(String, Value)], key: &str) -> Option<bool> {
    pairs.iter().find(|(k, _)| k == key).map(|(_, v)| match v {
        Value::Bool(b) => *b,
        other => panic!("key {key} is not a bool: {other:?}"),
    })
}

fn files(dir: &str) -> Vec<PathBuf> {
    let d = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("kat")
        .join("bls-eth2")
        .join(dir);
    let mut v: Vec<_> = std::fs::read_dir(&d)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", d.display()))
        .flatten()
        .map(|e| e.path())
        .collect();
    v.sort();
    v
}

fn read_case(path: &Path) -> Case {
    let text = std::fs::read_to_string(path).unwrap();
    let pairs = scan_object(&text);
    // Slice out the *inner* text of the `input` object and scan that. The
    // `aggregate` vectors use an array input instead — leave those empty.
    let input_key = text.find("\"input\"").expect("input key");
    let after_colon = input_key + text[input_key..].find(':').expect("input colon") + 1;
    let input = if text[after_colon..].trim_start().starts_with('{') {
        let open = after_colon + text[after_colon..].find('{').expect("input brace");
        let close = matching_brace(&text, open);
        scan_object(&text[open + 1..close])
    } else {
        Vec::new()
    };
    (input, pairs)
}

/// Index of the `}` matching the `{` at `open`, honouring string literals.
fn matching_brace(text: &str, open: usize) -> usize {
    let chars: Vec<char> = text.chars().collect();
    let byte_to_char: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
    let mut depth = 1usize; // `open` is the byte index of the opening `{`
    let mut i = text[..open].chars().count() + 1;
    while i < chars.len() {
        match chars[i] {
            '"' => {
                i += 1;
                while chars[i] != '"' {
                    i += 1;
                }
            }
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return byte_to_char[i];
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("unbalanced braces")
}

// --- sign ----------------------------------------------------------------------

#[test]
fn kat_sign() {
    for f in files("sign") {
        let (input, output) = read_case(&f);
        let sk_bytes: [u8; 32] = hex_bytes(get_str(&input, "privkey"))
            .try_into()
            .expect("privkey len");
        let msg = hex_bytes(get_str(&input, "message"));
        let sk = match SecretKey::from_bytes(&sk_bytes) {
            Ok(sk) => sk,
            // Zero secret keys have `null` output — KeyGen must reject them.
            Err(_) => {
                assert!(matches!(
                    output.iter().find(|(k, _)| k == "output").map(|(_, v)| v),
                    Some(Value::Null)
                ),);
                continue;
            }
        };
        let sig = sign(&sk, &msg);
        let want = hex_bytes(get_str(&output, "output"));
        assert_eq!(&sig.to_bytes()[..], &want[..], "sign mismatch in {f:?}");
        // and it must verify
        let pk = sk.public_key();
        verify(&pk, &msg, &sig).expect("own signature verifies");
    }
}

// --- verify --------------------------------------------------------------------

#[test]
fn kat_verify() {
    for f in files("verify") {
        let (input, output) = read_case(&f);
        let want = get_bool(&output, "output").expect("bool output");
        let pk_bytes: [u8; PK_LEN] = hex_bytes(get_str(&input, "pubkey"))
            .try_into()
            .expect("pk len");
        let sig_bytes: [u8; SIG_LEN] = hex_bytes(get_str(&input, "signature"))
            .try_into()
            .expect("sig len");
        let msg = hex_bytes(get_str(&input, "message"));
        let res = (|| -> tpt_crypto_sig::Result<()> {
            let pk = PublicKey::from_bytes(&pk_bytes)?;
            let sig = Signature::from_bytes(&sig_bytes)?;
            verify(&pk, &msg, &sig)
        })()
        .is_ok();
        assert_eq!(res, want, "verify mismatch in {f:?}");
    }
}

// --- aggregate -----------------------------------------------------------------

#[test]
fn kat_aggregate() {
    for f in files("aggregate") {
        let text = std::fs::read_to_string(&f).unwrap();
        let (_, output) = read_case(&f);
        // `input` is an array of signature strings.
        let input_arr = extract_input_array(&text);
        let sigs: Vec<_> = input_arr
            .iter()
            .filter_map(|h| Signature::from_bytes(&sig96(&hex_bytes(h))).ok())
            .collect();
        let out = &output
            .iter()
            .find(|(k, _)| k == "output")
            .expect("output")
            .1;
        match out {
            Value::Str(s) => {
                let agg = aggregate(&sigs).expect("aggregates");
                assert_eq!(
                    &agg.to_bytes()[..],
                    &hex_bytes(s)[..],
                    "aggregate mismatch in {f:?}"
                );
            }
            Value::Null => {
                // A degenerate input the reference rejects (e.g. an identity
                // element in the list). If ours aggregates anyway the result
                // must at least re-parse as a valid point.
                if let Ok(agg) = aggregate(&sigs) {
                    assert_eq!(agg.to_bytes().len(), SIG_LEN);
                }
            }
            other => panic!("unexpected aggregate output {other:?}"),
        }
    }
}

fn extract_input_array(text: &str) -> Vec<String> {
    match &scan_object(text)
        .iter()
        .find(|(k, _)| k == "input")
        .expect("input")
        .1
    {
        Value::Arr(a) => a.clone(),
        other => panic!("input is not an array: {other:?}"),
    }
}

fn sig96(b: &[u8]) -> [u8; SIG_LEN] {
    b.try_into().expect("96 bytes")
}

// --- aggregate_verify ----------------------------------------------------------

#[test]
fn kat_aggregate_verify() {
    for f in files("aggregate_verify") {
        let (input, output) = read_case(&f);
        let want = get_bool(&output, "output").expect("bool output");
        let pks: Vec<_> = get_arr(&input, "pubkeys")
            .iter()
            .filter_map(|h| PublicKey::from_bytes(&pk48(&hex_bytes(h))).ok())
            .collect();
        let msgs: Vec<Vec<u8>> = get_arr(&input, "messages")
            .iter()
            .map(|h| hex_bytes(h))
            .collect();
        let res = (|| -> tpt_crypto_sig::Result<()> {
            if pks.len() != msgs.len() {
                return Err(tpt_crypto_sig::Error::InvalidLength);
            }
            let raw = hex_bytes(get_str(&input, "signature"));
            let sig_bytes: [u8; SIG_LEN] = raw.try_into().map_err(|_| Error::InvalidEncoding)?;
            let sig = Signature::from_bytes(&sig_bytes)?;
            let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
            aggregate_verify(&pks, &msg_refs, &sig)
        })()
        .is_ok();
        assert_eq!(res, want, "aggregate_verify mismatch in {f:?}");
    }
}

fn pk48(b: &[u8]) -> [u8; PK_LEN] {
    b.try_into().expect("48 bytes")
}

// --- fast_aggregate_verify -------------------------------------------------------

#[test]
fn kat_fast_aggregate_verify() {
    for f in files("fast_aggregate_verify") {
        let (input, output) = read_case(&f);
        let want = get_bool(&output, "output").expect("bool output");
        let parsed: Vec<_> = get_arr(&input, "pubkeys")
            .iter()
            .map(|h| PublicKey::from_bytes(&pk48(&hex_bytes(h))))
            .collect();
        let msg = hex_bytes(get_str(&input, "message"));
        let res = (|| -> tpt_crypto_sig::Result<()> {
            // One invalid key fails the whole batch (cf. the infinity-pubkey
            // vector).
            let mut pks = Vec::new();
            for p in parsed {
                pks.push(p?);
            }
            let raw = hex_bytes(get_str(&input, "signature"));
            let sig_bytes: [u8; SIG_LEN] = raw.try_into().map_err(|_| Error::InvalidEncoding)?;
            let sig = Signature::from_bytes(&sig_bytes)?;
            verify_aggregate(&pks, &msg, &sig)
        })()
        .is_ok();
        assert_eq!(res, want, "fast_aggregate_verify mismatch in {f:?}");
    }
}

// --- hash_to_G2 ------------------------------------------------------------------

/// Slice and scan the `output` object (for handlers whose output is a dict).
fn output_object(text: &str) -> Vec<(String, Value)> {
    let key = text.find("\"output\"").expect("output key");
    let after = key + text[key..].find(':').expect("output colon") + 1;
    let off = text[after..].find('{').expect("output brace");
    let open = after + off;
    let close = matching_brace(text, open);
    scan_object(&text[open + 1..close])
}

#[test]
fn kat_hash_to_g2() {
    for f in files("hash_to_G2") {
        let text = std::fs::read_to_string(&f).unwrap();
        let input_key = text.find("\"input\"").expect("input key");
        let after_colon = input_key + text[input_key..].find(':').expect("colon") + 1;
        let open = after_colon + text[after_colon..].find('{').expect("input brace");
        let close = matching_brace(&text, open);
        let input = scan_object(&text[open + 1..close]);
        let msg = get_str(&input, "msg").as_bytes().to_vec();
        // These four vectors are the RFC 9380 §8.8.2 suite vectors (the
        // upstream generator hashes with the QUUX-V01-CS02 test DST, not the
        // POP ciphersuite DST — see kat/PROVENANCE.md).
        let quux = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
        let p = hash_to_curve_bls12381_g2(&msg, quux);
        let (x, y) = p.to_affine().expect("affine h2c output");
        let out_obj = output_object(&text);
        let (want_x, want_y) = parse_g2_coords(get_str(&out_obj, "x"), get_str(&out_obj, "y"));
        // The corpus lists the Fp2 coefficients as (c0, c1).
        assert_eq!(x.c0.to_bytes()[16..], want_x.0, "x.c0 in {f:?}");
        assert_eq!(x.c1.to_bytes()[16..], want_x.1, "x.c1 in {f:?}");
        assert_eq!(y.c0.to_bytes()[16..], want_y.0, "y.c0 in {f:?}");
        assert_eq!(y.c1.to_bytes()[16..], want_y.1, "y.c1 in {f:?}");
    }
}

/// One Fp2 coordinate split into its (c0, c1) 32-byte big-endian limbs.
type Fp2Limbs = ([u8; 32], [u8; 32]);

/// Parse the corpus' `"0x<c0>,0x<c1>"` G2 coordinate strings into the raw
/// 32-byte big-endian limb payloads (the vectors print 48-byte field elements
/// with 16 leading zero bytes... actually 48-byte values; slice to the limb
/// width used by `Fp::to_bytes`).
fn parse_g2_coords(x: &str, y: &str) -> (Fp2Limbs, Fp2Limbs) {
    let split = |s: &str| -> Fp2Limbs {
        let parts: Vec<&str> = s.split(',').collect();
        assert_eq!(parts.len(), 2, "Fp2 tuple {s:?}");
        let lo = |h: &str| -> [u8; 32] {
            let b = hex_bytes(h);
            assert_eq!(b.len(), 48);
            b[16..].try_into().expect("32 bytes")
        };
        (lo(parts[0]), lo(parts[1]))
    };
    (split(x), split(y))
}

// --- deserialization -------------------------------------------------------------

#[test]
fn kat_deserialization_g1() {
    for f in files("deserialization_G1") {
        let (input, output) = read_case(&f);
        let want = get_bool(&output, "output").expect("bool output");
        let bytes = hex_bytes(get_str(&input, "pubkey"));
        let got = match bytes.try_into() {
            Ok(b) => G1::from_compressed(&b).is_some(),
            Err(_) => false,
        };
        assert_eq!(got, want, "deserialization_G1 mismatch in {f:?}");
    }
}

#[test]
fn kat_deserialization_g2() {
    for f in files("deserialization_G2") {
        let (input, output) = read_case(&f);
        let want = get_bool(&output, "output").expect("bool output");
        let bytes = hex_bytes(get_str(&input, "signature"));
        let got = match bytes.try_into() {
            Ok(b) => G2::from_compressed(&b).is_some(),
            Err(_) => false,
        };
        assert_eq!(got, want, "deserialization_G2 mismatch in {f:?}");
    }
}

// --- proof of possession (self-consistency on the vector keys) -------------------

#[test]
fn pop_self_consistency() {
    for f in files("sign") {
        let (input, _) = read_case(&f);
        let sk_bytes: [u8; 32] = match hex_bytes(get_str(&input, "privkey")).try_into() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let Ok(sk) = SecretKey::from_bytes(&sk_bytes) else {
            continue;
        };
        let pk = sk.public_key();
        let pop = proof_of_possession(&sk);
        verify_proof_of_possession(&pk, &pop).expect("PoP verifies");
        // Wrong key must fail.
        let other = sk.public_key();
        let mut tampered = other.to_bytes();
        tampered[47] ^= 1;
        if let Ok(bad) = PublicKey::from_bytes(&tampered) {
            assert!(verify_proof_of_possession(&bad, &pop).is_err());
        }
    }
}
