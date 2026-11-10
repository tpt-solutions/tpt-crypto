//! Wycheproof AEAD vectors (C2SP/wycheproof, `testvectors_v1`): AES-GCM and
//! ChaCha20-Poly1305.
//!
//! The files are vendored under `tests/kat/wycheproof/` and pinned by sha256 in
//! `tests/kat/PROVENANCE.md` (`cargo xtask kat-check`).
//!
//! Coverage limits, counted and printed rather than hidden:
//!
//! * Only 96-bit IVs are exercised. The API takes a 12-byte nonce; other IV
//!   lengths go through GHASH and are not wired up.
//! * AES-192 is skipped. Only AES-128 and AES-256 are implemented.
//! * `acceptable` verdicts are skipped: Wycheproof allows either outcome.
//! * Tags are 128 bits throughout (the vectors have no truncated tags).

use serde_json::Value;
use tpt_crypto_aead::{Aead, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, Nonce, Tag};

fn vector_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/kat")
        .join(name)
}

fn load(name: &str) -> Value {
    let text = std::fs::read_to_string(vector_path(name))
        .unwrap_or_else(|e| panic!("cannot read {name}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: bad JSON: {e}"))
}

fn bytes(v: &Value, field: &str) -> Vec<u8> {
    let s = v[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing field {field}"));
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex in {field}: {e}"))
}

#[derive(Default, Debug)]
struct Counts {
    run: usize,
    skipped_iv: usize,
    skipped_key: usize,
    skipped_acceptable: usize,
}

/// Run one AEAD over a Wycheproof file. `seal` takes `(key, nonce, aad, msg)`
/// and returns `(ct, tag)`; `open` takes `(key, nonce, aad, ct, tag)`.
fn run_file(
    file: &str,
    expected_alg: &str,
    key_sizes_bytes: &[usize],
    seal: impl Fn(&[u8], &[u8; 12], &[u8], &[u8]) -> (Vec<u8>, [u8; 16]),
    open: impl Fn(&[u8], &[u8; 12], &[u8], &[u8], &[u8; 16]) -> bool,
) -> Counts {
    let doc = load(file);
    assert_eq!(doc["algorithm"], expected_alg, "{file}");
    let mut counts = Counts::default();
    let mut failures = Vec::new();

    for group in doc["testGroups"].as_array().expect("testGroups") {
        if group["ivSize"] != 96 {
            counts.skipped_iv += group["tests"].as_array().map_or(0, Vec::len);
            continue;
        }
        let key_size_bytes = group["keySize"].as_u64().unwrap_or(0) / 8;
        if !key_sizes_bytes.iter().any(|&k| k as u64 == key_size_bytes) {
            counts.skipped_key += group["tests"].as_array().map_or(0, Vec::len);
            continue;
        }
        assert_eq!(group["tagSize"], 128, "{file}: unexpected tag size");

        for t in group["tests"].as_array().expect("tests") {
            let tc = t["tcId"].as_u64().unwrap_or(0);
            let verdict = t["result"].as_str().unwrap_or("");
            if verdict == "acceptable" {
                counts.skipped_acceptable += 1;
                continue;
            }
            let key = bytes(t, "key");
            let iv = bytes(t, "iv");
            let aad = bytes(t, "aad");
            let msg = bytes(t, "msg");
            let ct = bytes(t, "ct");
            let tag_v = bytes(t, "tag");
            let nonce: [u8; 12] = iv.as_slice().try_into().expect("96-bit iv");
            let tag: [u8; 16] = tag_v.as_slice().try_into().expect("128-bit tag");
            counts.run += 1;

            match verdict {
                "valid" => {
                    let (got_ct, got_tag) = seal(&key, &nonce, &aad, &msg);
                    if got_ct != ct || got_tag != tag {
                        failures.push(format!("tcId {tc}: seal output differs"));
                    }
                    if !open(&key, &nonce, &aad, &ct, &tag) {
                        failures.push(format!("tcId {tc}: valid vector failed to open"));
                    }
                }
                "invalid" => {
                    if open(&key, &nonce, &aad, &ct, &tag) {
                        failures.push(format!("tcId {tc}: invalid vector was accepted"));
                    }
                }
                other => panic!("{file}: tcId {tc}: unknown verdict {other}"),
            }
        }
    }

    eprintln!("{file}: {counts:?}");
    assert!(
        failures.is_empty(),
        "{file}: {} failure(s): {:#?}",
        failures.len(),
        failures
    );
    assert!(counts.run > 0, "{file}: no vectors were run");
    counts
}

#[test]
fn aes_gcm_wycheproof() {
    let file = "wycheproof/aes_gcm_test.json";
    // Only the AES-128 and AES-256 key sizes are implemented; the closure
    // dispatches on the key length.
    let seal = |key: &[u8], nonce: &[u8; 12], aad: &[u8], msg: &[u8]| {
        let mut buf = msg.to_vec();
        let nonce = Nonce::new(*nonce);
        let tag = match key.len() {
            16 => Aes128Gcm::new(key)
                .unwrap()
                .encrypt_in_place_detached(&nonce, aad, &mut buf),
            32 => Aes256Gcm::new(key)
                .unwrap()
                .encrypt_in_place_detached(&nonce, aad, &mut buf),
            n => panic!("unexpected key length {n}"),
        };
        (buf, tag.0)
    };
    let open = |key: &[u8], nonce: &[u8; 12], aad: &[u8], ct: &[u8], tag: &[u8; 16]| {
        let mut buf = ct.to_vec();
        let nonce = Nonce::new(*nonce);
        let tag = Tag::new(*tag);
        match key.len() {
            16 => Aes128Gcm::new(key)
                .unwrap()
                .decrypt_in_place_detached(&nonce, aad, &mut buf, &tag)
                .is_ok(),
            32 => Aes256Gcm::new(key)
                .unwrap()
                .decrypt_in_place_detached(&nonce, aad, &mut buf, &tag)
                .is_ok(),
            _ => false,
        }
    };
    let counts = run_file(file, "AES-GCM", &[16, 32], seal, open);
    assert!(counts.run > 0);
}

#[test]
fn chacha20_poly1305_wycheproof() {
    let file = "wycheproof/chacha20_poly1305_test.json";
    let seal = |key: &[u8], nonce: &[u8; 12], aad: &[u8], msg: &[u8]| {
        let k: [u8; 32] = key.try_into().expect("32-byte key");
        let mut buf = msg.to_vec();
        let tag =
            ChaCha20Poly1305::new(&k).encrypt_in_place_detached(&Nonce::new(*nonce), aad, &mut buf);
        (buf, tag.0)
    };
    let open = |key: &[u8], nonce: &[u8; 12], aad: &[u8], ct: &[u8], tag: &[u8; 16]| {
        let k: [u8; 32] = key.try_into().expect("32-byte key");
        let mut buf = ct.to_vec();
        ChaCha20Poly1305::new(&k)
            .decrypt_in_place_detached(&Nonce::new(*nonce), aad, &mut buf, &Tag::new(*tag))
            .is_ok()
    };
    run_file(file, "CHACHA20-POLY1305", &[32], seal, open);
}
