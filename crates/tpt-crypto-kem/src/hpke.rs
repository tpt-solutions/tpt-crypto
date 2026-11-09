//! HPKE (RFC 9180) base mode. Requires `alloc`.
//!
//! Suite: `DHKEM(X25519, HKDF-SHA256)` with `HKDF-SHA256` and either
//! ChaCha20-Poly1305 or AES-128-GCM. Only base mode is provided: no PSK and no
//! sender authentication.
//!
//! [`Context`] is stateful. Each `seal` uses the next sequence-number nonce, and
//! the sender and receiver must process messages in the same order.
//!
//! ```
//! use tpt_crypto_kem::hpke::{setup_base_receiver, setup_base_sender, AeadAlgorithm};
//! # use tpt_crypto_core::CryptoRng;
//! # struct Fixed(u8);
//! # impl CryptoRng for Fixed {
//! #     fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), tpt_crypto_core::Error> {
//! #         for (i, b) in d.iter_mut().enumerate() { *b = self.0.wrapping_add(i as u8); self.0 = self.0.wrapping_add(1); }
//! #         Ok(())
//! #     }
//! # }
//! # let mut rng = Fixed(7);
//! // Receiver key pair (X25519 scalar and public u-coordinate).
//! let sk_r = [0x11u8; 32];
//! let pk_r = tpt_crypto_curve::X25519::diffie_hellman(&sk_r, &tpt_crypto_curve::X25519::BASE);
//!
//! let (enc, mut sender) =
//!     setup_base_sender(AeadAlgorithm::ChaCha20Poly1305, &pk_r, b"info", &mut rng).unwrap();
//! let ct = sender.seal(b"aad", b"hello").unwrap();
//!
//! let mut receiver =
//!     setup_base_receiver(AeadAlgorithm::ChaCha20Poly1305, &enc, &sk_r, b"info").unwrap();
//! assert_eq!(receiver.open(b"aad", &ct).unwrap(), b"hello");
//! ```

use alloc::vec::Vec;
use tpt_crypto_aead::{Aead as _, Aes128Gcm, ChaCha20Poly1305, Nonce};
use tpt_crypto_core::{CryptoRng, Error, Result, Zeroize};
use tpt_crypto_curve::X25519;
use tpt_crypto_hash::kdf::{hkdf_expand, hkdf_extract};
use tpt_crypto_hash::sha2::Sha256;

const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const HPKE_V1: &[u8] = b"HPKE-v1";
const NENC: usize = 32;
const NN: usize = 12;
const NH: usize = 32;

/// AEAD algorithms supported by this suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// AES-128-GCM (HPKE AEAD id `0x0001`).
    Aes128Gcm,
    /// ChaCha20-Poly1305 (HPKE AEAD id `0x0003`).
    ChaCha20Poly1305,
}

impl AeadAlgorithm {
    /// The HPKE `aead_id` code point.
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            AeadAlgorithm::Aes128Gcm => 0x0001,
            AeadAlgorithm::ChaCha20Poly1305 => 0x0003,
        }
    }

    /// Key length `Nk` in bytes.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm => 16,
            AeadAlgorithm::ChaCha20Poly1305 => 32,
        }
    }
}

fn kem_suite_id() -> [u8; 5] {
    let k = KEM_ID.to_be_bytes();
    [b'K', b'E', b'M', k[0], k[1]]
}

fn hpke_suite_id(alg: AeadAlgorithm) -> [u8; 10] {
    let k = KEM_ID.to_be_bytes();
    let d = KDF_ID.to_be_bytes();
    let a = alg.id().to_be_bytes();
    [b'H', b'P', b'K', b'E', k[0], k[1], d[0], d[1], a[0], a[1]]
}

/// `LabeledExtract` (RFC 9180 §4).
fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut labeled_ikm = Vec::with_capacity(HPKE_V1.len() + suite.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(HPKE_V1);
    labeled_ikm.extend_from_slice(suite);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    let mut prk = [0u8; 32];
    hkdf_extract::<Sha256, 64, 32>(salt, &labeled_ikm, &mut prk);
    labeled_ikm.zeroize();
    prk
}

/// `LabeledExpand` (RFC 9180 §4). `out.len()` must be at most `255 * 32`.
fn labeled_expand(suite: &[u8], prk: &[u8], label: &[u8], info: &[u8], out: &mut [u8]) {
    let len = (out.len() as u16).to_be_bytes();
    let mut labeled_info = Vec::with_capacity(2 + HPKE_V1.len() + suite.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&len);
    labeled_info.extend_from_slice(HPKE_V1);
    labeled_info.extend_from_slice(suite);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    hkdf_expand::<Sha256, 64, 32>(prk, &labeled_info, out);
}

/// X25519 DH with the RFC 9180 §7.1.4 check: an all-zero output is rejected.
fn dh(sk: &[u8; 32], pk: &[u8; 32]) -> Result<[u8; 32]> {
    let shared = X25519::diffie_hellman(sk, pk);
    let mut acc = 0u8;
    for b in shared.iter() {
        acc |= b;
    }
    if acc == 0 {
        Err(Error::InvalidKey)
    } else {
        Ok(shared)
    }
}

/// `ExtractAndExpand` for the DHKEM (RFC 9180 §4.1).
fn extract_and_expand(dh: &[u8; 32], kem_context: &[u8]) -> [u8; 32] {
    let suite = kem_suite_id();
    let mut eae_prk = labeled_extract(&suite, b"", b"eae_prk", dh);
    let mut shared = [0u8; 32];
    labeled_expand(&suite, &eae_prk, b"shared_secret", kem_context, &mut shared);
    eae_prk.zeroize();
    shared
}

/// A stateful HPKE context: an AEAD key, base nonce, sequence number, and
/// exporter secret. Secret material is zeroized on drop.
pub struct Context {
    alg: AeadAlgorithm,
    key: Vec<u8>,
    base_nonce: [u8; NN],
    seq: u64,
    exporter_secret: [u8; NH],
}

impl Drop for Context {
    fn drop(&mut self) {
        self.key.zeroize();
        self.base_nonce.zeroize();
        self.exporter_secret.zeroize();
    }
}

impl Context {
    /// Nonce for the current sequence number: `base_nonce XOR seq` (RFC 9180 §5.2).
    fn nonce(&self) -> Result<[u8; NN]> {
        // RFC 9180 caps seq below 2^96 - 1; u64 is never reached in practice,
        // but refuse rather than wrap.
        if self.seq == u64::MAX {
            return Err(Error::Unsupported);
        }
        let mut n = self.base_nonce;
        let s = self.seq.to_be_bytes();
        for i in 0..8 {
            n[NN - 8 + i] ^= s[i];
        }
        Ok(n)
    }

    /// Encrypt `plaintext` with `aad` under the next nonce. Returns `ciphertext || tag`.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::new(self.nonce()?);
        let ct = match self.alg {
            AeadAlgorithm::ChaCha20Poly1305 => {
                let key: &[u8; 32] = self.key.as_slice().try_into().map_err(|_| Error::InvalidKey)?;
                ChaCha20Poly1305::new(key).encrypt(&nonce, aad, plaintext)
            }
            AeadAlgorithm::Aes128Gcm => {
                Aes128Gcm::new(&self.key)?.encrypt(&nonce, aad, plaintext)
            }
        };
        self.seq += 1;
        Ok(ct)
    }

    /// Decrypt and authenticate `ciphertext` (`ciphertext || tag`) under the next
    /// nonce. The sequence number advances only on success.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::new(self.nonce()?);
        let pt = match self.alg {
            AeadAlgorithm::ChaCha20Poly1305 => {
                let key: &[u8; 32] = self.key.as_slice().try_into().map_err(|_| Error::InvalidKey)?;
                ChaCha20Poly1305::new(key).decrypt(&nonce, aad, ciphertext)?
            }
            AeadAlgorithm::Aes128Gcm => {
                Aes128Gcm::new(&self.key)?.decrypt(&nonce, aad, ciphertext)?
            }
        };
        self.seq += 1;
        Ok(pt)
    }

    /// Derive `out.len()` bytes bound to `exporter_context` (RFC 9180 §5.3).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] if `out.len()` exceeds `255 * 32`.
    pub fn export(&self, exporter_context: &[u8], out: &mut [u8]) -> Result<()> {
        if out.len() > 255 * NH {
            return Err(Error::InvalidLength);
        }
        labeled_expand(
            &hpke_suite_id(self.alg),
            &self.exporter_secret,
            b"sec",
            exporter_context,
            out,
        );
        Ok(())
    }
}

/// The base-mode key schedule (RFC 9180 §5.1), with an empty PSK.
fn key_schedule(alg: AeadAlgorithm, shared_secret: &[u8; 32], info: &[u8]) -> Context {
    let suite = hpke_suite_id(alg);
    let psk_id_hash = labeled_extract(&suite, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(&suite, b"", b"info_hash", info);
    let mut ks_context = Vec::with_capacity(1 + 2 * NH);
    ks_context.push(0x00); // mode_base
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);

    let mut secret = labeled_extract(&suite, shared_secret, b"secret", b"");
    let mut key = alloc::vec![0u8; alg.key_len()];
    labeled_expand(&suite, &secret, b"key", &ks_context, &mut key);
    let mut base_nonce = [0u8; NN];
    labeled_expand(&suite, &secret, b"base_nonce", &ks_context, &mut base_nonce);
    let mut exporter_secret = [0u8; NH];
    labeled_expand(&suite, &secret, b"exp", &ks_context, &mut exporter_secret);
    secret.zeroize();
    ks_context.zeroize();

    Context {
        alg,
        key,
        base_nonce,
        seq: 0,
        exporter_secret,
    }
}

/// Sender setup with a caller-supplied ephemeral scalar. Used by
/// [`setup_base_sender`] and by the KAT tests.
fn sender_with_ephemeral(
    alg: AeadAlgorithm,
    sk_e: &[u8; 32],
    pk_r: &[u8; 32],
    info: &[u8],
) -> Result<([u8; NENC], Context)> {
    let enc = X25519::diffie_hellman(sk_e, &X25519::BASE);
    let mut shared_dh = dh(sk_e, pk_r)?;
    let mut kem_context = [0u8; 2 * NENC];
    kem_context[..NENC].copy_from_slice(&enc);
    kem_context[NENC..].copy_from_slice(pk_r);
    let mut shared = extract_and_expand(&shared_dh, &kem_context);
    let ctx = key_schedule(alg, &shared, info);
    shared_dh.zeroize();
    shared.zeroize();
    Ok((enc, ctx))
}

/// Base-mode sender setup: draws a fresh ephemeral key from `rng`.
///
/// Returns the encapsulated key `enc` (send it to the receiver) and the sender
/// context.
///
/// # Errors
///
/// Returns [`Error::RngFailure`] if `rng` fails, and [`Error::InvalidKey`] if
/// `pk_r` is a low-order point that yields an all-zero DH output.
pub fn setup_base_sender<R: CryptoRng>(
    alg: AeadAlgorithm,
    pk_r: &[u8; 32],
    info: &[u8],
    rng: &mut R,
) -> Result<([u8; NENC], Context)> {
    let mut sk_e = [0u8; 32];
    rng.try_fill_bytes(&mut sk_e)?;
    let out = sender_with_ephemeral(alg, &sk_e, pk_r, info);
    sk_e.zeroize();
    out
}

/// Base-mode receiver setup from `enc` and the receiver's X25519 secret key.
///
/// # Errors
///
/// Returns [`Error::InvalidKey`] if `enc` is a low-order point that yields an
/// all-zero DH output.
pub fn setup_base_receiver(
    alg: AeadAlgorithm,
    enc: &[u8; NENC],
    sk_r: &[u8; 32],
    info: &[u8],
) -> Result<Context> {
    let pk_r = X25519::diffie_hellman(sk_r, &X25519::BASE);
    let mut shared_dh = dh(sk_r, enc)?;
    let mut kem_context = [0u8; 2 * NENC];
    kem_context[..NENC].copy_from_slice(enc);
    kem_context[NENC..].copy_from_slice(&pk_r);
    let mut shared = extract_and_expand(&shared_dh, &kem_context);
    let ctx = key_schedule(alg, &shared, info);
    shared_dh.zeroize();
    shared.zeroize();
    Ok(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Official RFC 9180 vectors, base mode, DHKEM(X25519, HKDF-SHA256).
    /// See `tests/kat/PROVENANCE.md`.
    const KAT: &str = include_str!("../tests/kat/hpke_base_x25519.txt");

    struct Seal {
        seq: u64,
        aad: Vec<u8>,
        pt: Vec<u8>,
        ct: Vec<u8>,
        nonce: Vec<u8>,
    }

    struct Record {
        alg: AeadAlgorithm,
        info: Vec<u8>,
        sk_rm: [u8; 32],
        pk_rm: [u8; 32],
        sk_em: [u8; 32],
        enc: [u8; 32],
        key: Vec<u8>,
        base_nonce: Vec<u8>,
        exporter_secret: Vec<u8>,
        seals: Vec<Seal>,
    }

    fn unhex(s: &str) -> Vec<u8> {
        if s == "-" {
            return Vec::new();
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn arr32(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    fn parse() -> Vec<Record> {
        let mut records = Vec::new();
        for line in KAT.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let key = parts.next().unwrap();
            match key {
                "record" => records.push(Record {
                    alg: AeadAlgorithm::Aes128Gcm,
                    info: Vec::new(),
                    sk_rm: [0; 32],
                    pk_rm: [0; 32],
                    sk_em: [0; 32],
                    enc: [0; 32],
                    key: Vec::new(),
                    base_nonce: Vec::new(),
                    exporter_secret: Vec::new(),
                    seals: Vec::new(),
                }),
                "seal" => {
                    let seq: u64 = parts.next().unwrap().parse().unwrap();
                    let aad = unhex(parts.next().unwrap());
                    let pt = unhex(parts.next().unwrap());
                    let ct = unhex(parts.next().unwrap());
                    let nonce = unhex(parts.next().unwrap());
                    records
                        .last_mut()
                        .unwrap()
                        .seals
                        .push(Seal { seq, aad, pt, ct, nonce });
                }
                _ => {
                    let value = parts.next().unwrap_or("-");
                    let r = records.last_mut().unwrap();
                    match key {
                        "aead" => {
                            r.alg = match value {
                                "1" => AeadAlgorithm::Aes128Gcm,
                                "3" => AeadAlgorithm::ChaCha20Poly1305,
                                other => panic!("unexpected aead {other}"),
                            }
                        }
                        "info" => r.info = unhex(value),
                        "skRm" => r.sk_rm = arr32(value),
                        "pkRm" => r.pk_rm = arr32(value),
                        "skEm" => r.sk_em = arr32(value),
                        "enc" => r.enc = arr32(value),
                        "key" => r.key = unhex(value),
                        "base_nonce" => r.base_nonce = unhex(value),
                        "exporter_secret" => r.exporter_secret = unhex(value),
                        _ => {}
                    }
                }
            }
        }
        records
    }

    #[test]
    fn rfc9180_sender_matches_vectors() {
        let records = parse();
        assert!(!records.is_empty());
        for rec in &records {
            let (enc, mut ctx) =
                sender_with_ephemeral(rec.alg, &rec.sk_em, &rec.pk_rm, &rec.info).unwrap();
            assert_eq!(enc, rec.enc, "enc");
            assert_eq!(ctx.key, rec.key, "key");
            assert_eq!(ctx.base_nonce.to_vec(), rec.base_nonce, "base_nonce");
            assert_eq!(ctx.exporter_secret.to_vec(), rec.exporter_secret, "exporter");
            for s in &rec.seals {
                assert_eq!(ctx.seq, s.seq);
                assert_eq!(ctx.nonce().unwrap().to_vec(), s.nonce, "nonce seq {}", s.seq);
                assert_eq!(ctx.seal(&s.aad, &s.pt).unwrap(), s.ct, "ct seq {}", s.seq);
            }
        }
    }

    #[test]
    fn rfc9180_receiver_opens_vectors() {
        for rec in parse() {
            let mut ctx = setup_base_receiver(rec.alg, &rec.enc, &rec.sk_rm, &rec.info).unwrap();
            for s in &rec.seals {
                assert_eq!(ctx.open(&s.aad, &s.ct).unwrap(), s.pt, "seq {}", s.seq);
            }
        }
    }

    #[test]
    fn tampered_ciphertext_is_rejected_without_advancing() {
        let rec = &parse()[0];
        let s = &rec.seals[0];
        let mut ctx = setup_base_receiver(rec.alg, &rec.enc, &rec.sk_rm, &rec.info).unwrap();
        let mut bad = s.ct.clone();
        bad[0] ^= 1;
        assert!(ctx.open(&s.aad, &bad).is_err());
        assert_eq!(ctx.seq, 0, "failed open must not advance the sequence number");
        assert_eq!(ctx.open(&s.aad, &s.ct).unwrap(), s.pt);
    }

    #[test]
    fn export_agrees_between_sender_and_receiver() {
        let rec = &parse()[0];
        let (enc, sender) =
            sender_with_ephemeral(rec.alg, &rec.sk_em, &rec.pk_rm, &rec.info).unwrap();
        let receiver = setup_base_receiver(rec.alg, &enc, &rec.sk_rm, &rec.info).unwrap();
        let mut a = [0u8; 48];
        let mut b = [0u8; 48];
        sender.export(b"ctx", &mut a).unwrap();
        receiver.export(b"ctx", &mut b).unwrap();
        assert_eq!(a, b);
        let mut c = [0u8; 48];
        sender.export(b"other", &mut c).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn low_order_encapsulated_key_is_rejected() {
        let sk = [0x22u8; 32];
        assert_eq!(
            setup_base_receiver(AeadAlgorithm::ChaCha20Poly1305, &[0u8; 32], &sk, b"").err(),
            Some(Error::InvalidKey)
        );
    }
}
