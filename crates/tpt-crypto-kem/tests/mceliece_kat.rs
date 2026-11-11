//! Classic McEliece mceliece348864 against the official reference KAT records.
//!
//! `kat/mceliece348864_first3_digests.txt` holds the first three records of the official
//! `kat_kem.rsp` (mceliece-kat-20221023): seeds, ciphertexts and shared secrets in full,
//! and SHA-256 digests of the public and secret keys (full keys would be 261 KB each; see
//! `kat/PROVENANCE.md`). For each record the test re-derives the randomness the way the
//! reference KAT harness does, from the seed through the NIST AES-256 CTR-DRBG, and checks
//! keypair, encapsulation and decapsulation.

use std::collections::BTreeMap;

use tpt_crypto_aead::Aes;
use tpt_crypto_core::{CryptoRng, Error};
use tpt_crypto_hash::sha2::sha256;
use tpt_crypto_kem::mceliece::{decapsulate, encapsulate, keypair};

const DIGESTS: &str = include_str!("kat/mceliece348864_first3_digests.txt");

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

impl CryptoRng for NistDrbg {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill(dest);
        Ok(())
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

struct Record {
    seed: Vec<u8>,
    pk_sha256: Vec<u8>,
    sk_sha256: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
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
        cur.insert(k, v);
        if k == "ss" {
            out.push(Record {
                seed: unhex(cur["seed"]),
                pk_sha256: unhex(cur["pk_sha256"]),
                sk_sha256: unhex(cur["sk_sha256"]),
                ct: unhex(cur["ct"]),
                ss: unhex(cur["ss"]),
            });
            cur.clear();
        }
    }
    out
}

#[test]
fn official_records_match() {
    let records = parse_records(DIGESTS);
    assert_eq!(records.len(), 3);
    for (idx, r) in records.iter().enumerate() {
        let entropy: [u8; 48] = r.seed.clone().try_into().expect("48-byte seed");
        let mut drbg = NistDrbg::new(&entropy);

        let (pk, sk) = keypair(&mut drbg).expect("keypair");
        assert_eq!(sha256(&pk).to_vec(), r.pk_sha256, "record {idx}: pk digest");
        assert_eq!(sha256(&sk).to_vec(), r.sk_sha256, "record {idx}: sk digest");

        let (ct, ss) = encapsulate(&pk, &mut drbg).expect("encapsulate");
        assert_eq!(ct, r.ct, "record {idx}: ct");
        assert_eq!(ss.as_slice(), r.ss.as_slice(), "record {idx}: ss");

        let got = decapsulate(&sk, &ct).expect("decapsulate");
        assert_eq!(got.as_slice(), r.ss.as_slice(), "record {idx}: decaps");
    }
}

#[test]
fn tampered_ciphertext_is_implicitly_rejected() {
    let r = &parse_records(DIGESTS)[0];
    let entropy: [u8; 48] = r.seed.clone().try_into().unwrap();
    let mut drbg = NistDrbg::new(&entropy);
    let (_pk, sk) = keypair(&mut drbg).unwrap();
    let honest = decapsulate(&sk, &r.ct).unwrap();
    assert_eq!(honest.as_slice(), r.ss.as_slice());

    let mut bad = r.ct.clone();
    bad[10] ^= 0x04;
    let rej1 = decapsulate(&sk, &bad).expect("no error on tamper");
    let rej2 = decapsulate(&sk, &bad).expect("no error on tamper");
    assert_ne!(rej1, honest);
    assert_eq!(rej1, rej2);
}

#[test]
fn length_checks_reject_malformed_inputs() {
    let r = &parse_records(DIGESTS)[0];
    let entropy: [u8; 48] = r.seed.clone().try_into().unwrap();
    let mut drbg = NistDrbg::new(&entropy);
    let (pk, sk) = keypair(&mut drbg).unwrap();
    assert!(decapsulate(&sk, &r.ct[..r.ct.len() - 1]).is_err());
    assert!(decapsulate(&sk[..sk.len() - 1], &r.ct).is_err());
    assert!(encapsulate(&pk[..pk.len() - 1], &mut drbg).is_err());
}
