//! FrodoKEM-640-SHAKE against the official reference KAT records.
//!
//! `kat/frodokem640_shake_first3.rsp` is the first three records of the reference
//! `PQCkemKAT_19888_shake.rsp` (see `kat/PROVENANCE.md`). For each record the test
//! re-derives the randomness the way the reference `PQCgenKAT_kem` harness does, from
//! the record's `seed` through the NIST AES-256 CTR-DRBG, and then checks keygen,
//! encapsulation and decapsulation byte-for-byte.

use std::collections::BTreeMap;

use tpt_crypto_aead::Aes;
use tpt_crypto_kem::frodo::{
    decapsulate, encapsulate_derand, keygen_derand, PublicKey, SecretKey, CIPHERTEXT_LEN,
    KEYGEN_RANDOM_LEN, PUBLIC_KEY_LEN, SECRET_KEY_LEN,
};

const RSP: &str = include_str!("kat/frodokem640_shake_first3.rsp");

/// The NIST PQC `randombytes` (AES-256 CTR-DRBG, no derivation function), as used by the
/// reference KAT generator.
struct NistDrbg {
    key: [u8; 32],
    v: [u8; 16],
}

impl NistDrbg {
    fn new(entropy: &[u8; 48]) -> Self {
        let mut d = NistDrbg {
            key: [0; 32],
            v: [0; 16],
        };
        d.update(Some(entropy));
        d
    }

    fn increment_v(&mut self) {
        for i in (0..16).rev() {
            if self.v[i] == 0xff {
                self.v[i] = 0;
            } else {
                self.v[i] += 1;
                break;
            }
        }
    }

    fn update(&mut self, provided: Option<&[u8; 48]>) {
        let aes = Aes::new_256(&self.key);
        let mut temp = [0u8; 48];
        for i in 0..3 {
            self.increment_v();
            temp[16 * i..16 * i + 16].copy_from_slice(&aes.encrypt_block(&self.v));
        }
        if let Some(p) = provided {
            for (t, x) in temp.iter_mut().zip(p) {
                *t ^= x;
            }
        }
        self.key.copy_from_slice(&temp[..32]);
        self.v.copy_from_slice(&temp[32..]);
    }

    fn fill(&mut self, out: &mut [u8]) {
        let mut written = 0;
        while written < out.len() {
            self.increment_v();
            let block = Aes::new_256(&self.key).encrypt_block(&self.v);
            let take = (out.len() - written).min(16);
            out[written..written + take].copy_from_slice(&block[..take]);
            written += take;
        }
        self.update(None);
    }
}

struct Record {
    seed: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
}

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn parse_records(text: &str) -> Vec<Record> {
    let mut out = Vec::new();
    let mut cur: BTreeMap<&str, &str> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once(" = ").expect("key = value");
        if k == "count" && !cur.is_empty() {
            panic!("record boundary without ss");
        }
        cur.insert(k, v);
        if k == "ss" {
            out.push(Record {
                seed: unhex(cur["seed"]),
                pk: unhex(cur["pk"]),
                sk: unhex(cur["sk"]),
                ct: unhex(cur["ct"]),
                ss: unhex(cur["ss"]),
            });
            cur.clear();
        }
    }
    out
}

#[test]
fn official_records_match_keygen_encaps_decaps() {
    let records = parse_records(RSP);
    assert_eq!(records.len(), 3, "expected the three packaged records");
    for (idx, r) in records.iter().enumerate() {
        assert_eq!(r.pk.len(), PUBLIC_KEY_LEN);
        assert_eq!(r.sk.len(), SECRET_KEY_LEN);
        assert_eq!(r.ct.len(), CIPHERTEXT_LEN);

        let entropy: [u8; 48] = r.seed.clone().try_into().expect("48-byte seed");
        let mut drbg = NistDrbg::new(&entropy);

        // Keypair draws 64 bytes of randomness.
        let mut randomness = [0u8; KEYGEN_RANDOM_LEN];
        drbg.fill(&mut randomness);
        let (pk, sk) = keygen_derand(&randomness);
        assert_eq!(pk.bytes, r.pk, "record {idx}: pk");
        assert_eq!(sk.bytes, r.sk, "record {idx}: sk");

        // Encapsulation draws mu (16 bytes) then the salt (32 bytes).
        let mut mu_salt = [0u8; 48];
        drbg.fill(&mut mu_salt);
        let mu: [u8; 16] = mu_salt[..16].try_into().unwrap();
        let salt: [u8; 32] = mu_salt[16..].try_into().unwrap();
        let (ct, ss) = encapsulate_derand(&pk.bytes, &mu, &salt).expect("valid pk");
        assert_eq!(ct, r.ct, "record {idx}: ct");
        assert_eq!(ss.as_slice(), r.ss.as_slice(), "record {idx}: ss");

        let got = decapsulate(&sk, &ct).expect("valid sk and ct");
        assert_eq!(got.as_slice(), r.ss.as_slice(), "record {idx}: decaps");
    }
}

#[test]
fn tampered_ciphertext_is_implicitly_rejected() {
    let r = &parse_records(RSP)[0];
    let sk = SecretKey {
        bytes: r.sk.clone(),
    };
    let _pk = PublicKey {
        bytes: r.pk.clone(),
    };
    let honest = decapsulate(&sk, &r.ct).unwrap();
    assert_eq!(honest.as_slice(), r.ss.as_slice());

    // Flip one bit in c1: decapsulation must not error and must return a value that is
    // not the honest secret, and the same value every time.
    let mut bad = r.ct.clone();
    bad[100] ^= 0x01;
    let rej1 = decapsulate(&sk, &bad).expect("no error on tamper");
    let rej2 = decapsulate(&sk, &bad).expect("no error on tamper");
    assert_ne!(rej1, honest);
    assert_eq!(rej1, rej2);

    // Flip one bit in the salt (last 32 bytes): same behaviour.
    let mut bad_salt = r.ct.clone();
    let last = bad_salt.len() - 1;
    bad_salt[last] ^= 0x80;
    assert_ne!(decapsulate(&sk, &bad_salt).unwrap(), honest);
}

#[test]
fn length_checks_reject_malformed_inputs() {
    let r = &parse_records(RSP)[0];
    let sk = SecretKey {
        bytes: r.sk.clone(),
    };
    assert!(decapsulate(&sk, &r.ct[..r.ct.len() - 1]).is_err());
    let short_pk = PublicKey {
        bytes: r.pk[..r.pk.len() - 1].to_vec(),
    };
    assert!(encapsulate_derand(&short_pk.bytes, &[0; 16], &[0; 32]).is_err());
}
