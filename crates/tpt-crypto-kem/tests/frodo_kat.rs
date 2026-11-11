//! FrodoKEM (sets 640, 976, 1344; both matrix variants) against official reference KAT
//! records.
//!
//! The `kat/frodokem*_first*.rsp` files are the first records of the reference KAT files
//! in `FrodoKEM/KAT/` of the Microsoft reference repository (see `kat/PROVENANCE.md`).
//! 640 has three records per file, 976 and 1344 one. For each record the test re-derives
//! the randomness the way the reference `PQCgenKAT_kem` harness does, from the record's
//! `seed` through the NIST AES-256 CTR-DRBG, and then checks keygen, encapsulation and
//! decapsulation byte for byte.

use std::collections::BTreeMap;

use tpt_crypto_aead::Aes;
use tpt_crypto_core::Result;
use tpt_crypto_kem::frodo::{
    aes, shake, Frodo1344, Frodo640, Frodo976, FrodoParams, PublicKey, SecretKey,
};

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

type KeygenFn = fn(&[u8]) -> Result<(PublicKey, SecretKey)>;
type EncapsFn = fn(&[u8], &[u8], &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
type DecapsFn = fn(&SecretKey, &[u8]) -> Result<Vec<u8>>;

/// Run every record of one packaged file through one variant's derandomized API.
fn check_variant<P: FrodoParams>(
    name: &str,
    rsp: &str,
    expected_records: usize,
    keygen: KeygenFn,
    encaps: EncapsFn,
    decaps: DecapsFn,
) {
    let records = parse_records(rsp);
    assert_eq!(records.len(), expected_records, "{name}: record count");
    for (idx, r) in records.iter().enumerate() {
        assert_eq!(r.pk.len(), P::PUBLIC_KEY_LEN, "{name}: pk length");
        assert_eq!(r.sk.len(), P::SECRET_KEY_LEN, "{name}: sk length");
        assert_eq!(r.ct.len(), P::CIPHERTEXT_LEN, "{name}: ct length");

        let entropy: [u8; 48] = r.seed.clone().try_into().expect("48-byte seed");
        let mut drbg = NistDrbg::new(&entropy);

        // Keypair draws the key-generation randomness.
        let mut randomness = vec![0u8; P::KEYGEN_RANDOM_LEN];
        drbg.fill(&mut randomness);
        let (pk, sk) = keygen(&randomness).expect("keygen");
        assert_eq!(pk.bytes, r.pk, "{name} record {idx}: pk");
        assert_eq!(sk.bytes, r.sk, "{name} record {idx}: sk");

        // Encapsulation draws mu, then the salt.
        let mut mu_salt = vec![0u8; P::MU_LEN + P::SALT_LEN];
        drbg.fill(&mut mu_salt);
        let (mu, salt) = mu_salt.split_at(P::MU_LEN);
        let (ct, ss) = encaps(&pk.bytes, mu, salt).expect("valid pk");
        assert_eq!(ct, r.ct, "{name} record {idx}: ct");
        assert_eq!(ss, r.ss, "{name} record {idx}: ss");

        let got = decaps(&sk, &ct).expect("valid sk and ct");
        assert_eq!(got, r.ss, "{name} record {idx}: decaps");
    }
}

#[test]
fn kat_640_shake() {
    check_variant::<Frodo640>(
        "640-shake",
        include_str!("kat/frodokem640_shake_first3.rsp"),
        3,
        shake::keygen_derand::<Frodo640>,
        shake::encapsulate_derand::<Frodo640>,
        shake::decapsulate::<Frodo640>,
    );
}

#[test]
fn kat_640_aes() {
    check_variant::<Frodo640>(
        "640-aes",
        include_str!("kat/frodokem640_aes_first3.rsp"),
        3,
        aes::keygen_derand::<Frodo640>,
        aes::encapsulate_derand::<Frodo640>,
        aes::decapsulate::<Frodo640>,
    );
}

#[test]
fn kat_976_shake() {
    check_variant::<Frodo976>(
        "976-shake",
        include_str!("kat/frodokem976_shake_first1.rsp"),
        1,
        shake::keygen_derand::<Frodo976>,
        shake::encapsulate_derand::<Frodo976>,
        shake::decapsulate::<Frodo976>,
    );
}

#[test]
fn kat_976_aes() {
    check_variant::<Frodo976>(
        "976-aes",
        include_str!("kat/frodokem976_aes_first1.rsp"),
        1,
        aes::keygen_derand::<Frodo976>,
        aes::encapsulate_derand::<Frodo976>,
        aes::decapsulate::<Frodo976>,
    );
}

#[test]
fn kat_1344_shake() {
    check_variant::<Frodo1344>(
        "1344-shake",
        include_str!("kat/frodokem1344_shake_first1.rsp"),
        1,
        shake::keygen_derand::<Frodo1344>,
        shake::encapsulate_derand::<Frodo1344>,
        shake::decapsulate::<Frodo1344>,
    );
}

#[test]
fn kat_1344_aes() {
    check_variant::<Frodo1344>(
        "1344-aes",
        include_str!("kat/frodokem1344_aes_first1.rsp"),
        1,
        aes::keygen_derand::<Frodo1344>,
        aes::encapsulate_derand::<Frodo1344>,
        aes::decapsulate::<Frodo1344>,
    );
}

#[test]
fn tampered_ciphertext_is_implicitly_rejected() {
    let r = &parse_records(include_str!("kat/frodokem640_shake_first3.rsp"))[0];
    let sk = SecretKey {
        bytes: r.sk.clone(),
    };
    let honest = shake::decapsulate::<Frodo640>(&sk, &r.ct).unwrap();
    assert_eq!(honest, r.ss);

    // Flip one bit in c1: decapsulation must not error and must return a value that is
    // not the honest secret, and the same value every time.
    let mut bad = r.ct.clone();
    bad[100] ^= 0x01;
    let rej1 = shake::decapsulate::<Frodo640>(&sk, &bad).expect("no error on tamper");
    let rej2 = shake::decapsulate::<Frodo640>(&sk, &bad).expect("no error on tamper");
    assert_ne!(rej1, honest);
    assert_eq!(rej1, rej2);

    // Flip one bit in the salt (last 32 bytes): same behaviour.
    let mut bad_salt = r.ct.clone();
    let last = bad_salt.len() - 1;
    bad_salt[last] ^= 0x80;
    assert_ne!(
        shake::decapsulate::<Frodo640>(&sk, &bad_salt).unwrap(),
        honest
    );
}

#[test]
fn length_checks_reject_malformed_inputs() {
    let r = &parse_records(include_str!("kat/frodokem640_shake_first3.rsp"))[0];
    let sk = SecretKey {
        bytes: r.sk.clone(),
    };
    assert!(shake::decapsulate::<Frodo640>(&sk, &r.ct[..r.ct.len() - 1]).is_err());
    assert!(
        shake::encapsulate_derand::<Frodo640>(&r.pk[..r.pk.len() - 1], &[0; 16], &[0; 32]).is_err()
    );
    assert!(shake::keygen_derand::<Frodo640>(&[0u8; 5]).is_err());
}
