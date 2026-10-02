//! AES-GCM-SIV (RFC 8452) Appendix C known-answer tests
//! (`tests/kat/rfc8452.txt`, distilled — see `tests/kat/PROVENANCE.md`).
//!
//! Covers C.1 (AEAD_AES_128_GCM_SIV), C.2 (AEAD_AES_256_GCM_SIV) and the C.3
//! counter-wrap tests. Each record must encrypt to the exact reference
//! ciphertext and tag, and decrypt back to the plaintext.

use tpt_crypto_aead::{Aead, Aes128GcmSiv, Aes256GcmSiv, Nonce, Tag};

const VECTORS: &str = include_str!("kat/rfc8452.txt");

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

fn run_alg(alg: &str) -> usize {
    let records = parse(VECTORS);
    let mine: Vec<&Record> = records
        .iter()
        .filter(|r| r.kind == "kat" && f(r, "alg") == alg)
        .collect();
    for r in &mine {
        let key = unhex(f(r, "key"));
        let nonce: [u8; 12] = unhex(f(r, "nonce")).try_into().expect("12-byte nonce");
        let aad = unhex(f(r, "aad"));
        let pt = unhex(f(r, "pt"));
        let want_ct = unhex(f(r, "ct"));
        let want_tag = unhex(f(r, "tag"));

        let nonce = Nonce::<12>::new(nonce);
        if alg == "AES_128_GCM_SIV" {
            let aead = Aes128GcmSiv::new(&key).expect("key len");
            let mut buf = pt.clone();
            let tag = aead.encrypt_in_place_detached(&nonce, &aad, &mut buf);
            assert_eq!(buf, want_ct, "[{alg} count {}] ciphertext", f(r, "count"));
            assert_eq!(
                tag.as_slice(),
                &want_tag[..],
                "[{alg} count {}] tag",
                f(r, "count")
            );

            let mut buf = want_ct.clone();
            aead.decrypt_in_place_detached(&nonce, &aad, &mut buf, &tag)
                .expect("decrypt");
            assert_eq!(buf, pt, "[{alg}] round trip");
        } else {
            let aead = Aes256GcmSiv::new(&key).expect("key len");
            let mut buf = pt.clone();
            let tag = aead.encrypt_in_place_detached(&nonce, &aad, &mut buf);
            assert_eq!(buf, want_ct, "[{alg} count {}] ciphertext", f(r, "count"));
            assert_eq!(
                tag.as_slice(),
                &want_tag[..],
                "[{alg} count {}] tag",
                f(r, "count")
            );

            let mut buf = want_ct.clone();
            aead.decrypt_in_place_detached(&nonce, &aad, &mut buf, &tag)
                .expect("decrypt");
            assert_eq!(buf, pt, "[{alg}] round trip");
        }
    }
    mine.len()
}

#[test]
fn rfc8452_aes_128_gcm_siv() {
    assert_eq!(
        run_alg("AES_128_GCM_SIV"),
        24,
        "expected 24 AES-128 records"
    );
}

#[test]
fn rfc8452_aes_256_gcm_siv() {
    assert_eq!(
        run_alg("AES_256_GCM_SIV"),
        26,
        "expected 26 AES-256 records"
    );
}

#[test]
fn rfc8452_tag_tamper_rejected() {
    let records = parse(VECTORS);
    let r = records
        .iter()
        .find(|r| r.kind == "kat" && f(r, "alg") == "AES_256_GCM_SIV")
        .expect("one AES-256 record");
    let key = unhex(f(r, "key"));
    let nonce = Nonce::<12>::new(unhex(f(r, "nonce")).try_into().expect("12 bytes"));
    let aead = Aes256GcmSiv::new(&key).expect("key len");
    let mut buf = unhex(f(r, "ct"));
    let mut tag_bytes: [u8; 16] = unhex(f(r, "tag")).try_into().expect("16 bytes");
    tag_bytes[0] ^= 1;
    let aad = unhex(f(r, "aad"));
    assert!(aead
        .decrypt_in_place_detached(&nonce, &aad, &mut buf, &Tag::<16>::new(tag_bytes))
        .is_err());
}
