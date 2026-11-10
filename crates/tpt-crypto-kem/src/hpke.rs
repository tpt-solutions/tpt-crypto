//! HPKE (RFC 9180). Requires `alloc`.
//!
//! Suite: `DHKEM(X25519, HKDF-SHA256)` with `HKDF-SHA256` and either
//! ChaCha20-Poly1305 or AES-128-GCM. All four modes are provided:
//!
//! | Mode | Setup functions | Adds |
//! |------|-----------------|------|
//! | base | `setup_base_*` | nothing |
//! | PSK | `setup_psk_*` | a pre-shared key (at least 32 bytes) and its identifier |
//! | auth | `setup_auth_*` | the sender's static X25519 key |
//! | auth-PSK | `setup_auth_psk_*` | both of the above |
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
/// Minimum PSK length. RFC 9180 §5.1 requires the PSK to carry at least 32
/// bytes of entropy; length is the only part this code can check.
const MIN_PSK_LEN: usize = 32;

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

/// HPKE mode (RFC 9180 §5.1). The discriminant is the `mode` byte in the key
/// schedule context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Base = 0x00,
    Psk = 0x01,
    Auth = 0x02,
    AuthPsk = 0x03,
}

impl Mode {
    fn uses_psk(self) -> bool {
        matches!(self, Mode::Psk | Mode::AuthPsk)
    }

    fn uses_auth(self) -> bool {
        matches!(self, Mode::Auth | Mode::AuthPsk)
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
    let mut labeled_info =
        Vec::with_capacity(2 + HPKE_V1.len() + suite.len() + label.len() + info.len());
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

/// `ExtractAndExpand` for the DHKEM (RFC 9180 §4.1). `dh` is one DH output
/// (base, PSK) or two concatenated outputs (auth modes).
fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> [u8; 32] {
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
                let key: &[u8; 32] = self
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?;
                ChaCha20Poly1305::new(key).encrypt(&nonce, aad, plaintext)
            }
            AeadAlgorithm::Aes128Gcm => Aes128Gcm::new(&self.key)?.encrypt(&nonce, aad, plaintext),
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
                let key: &[u8; 32] = self
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidKey)?;
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

/// The key schedule (RFC 9180 §5.1).
///
/// `psk` and `psk_id` must be empty unless `mode` uses a PSK.
fn key_schedule(
    alg: AeadAlgorithm,
    mode: Mode,
    shared_secret: &[u8; 32],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<Context> {
    if mode.uses_psk() {
        if psk.len() < MIN_PSK_LEN {
            return Err(Error::InvalidLength);
        }
    } else if !psk.is_empty() || !psk_id.is_empty() {
        return Err(Error::InvalidLength);
    }

    let suite = hpke_suite_id(alg);
    let psk_id_hash = labeled_extract(&suite, b"", b"psk_id_hash", psk_id);
    let info_hash = labeled_extract(&suite, b"", b"info_hash", info);
    let mut ks_context = Vec::with_capacity(1 + 2 * NH);
    ks_context.push(mode as u8);
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);

    let mut secret = labeled_extract(&suite, shared_secret, b"secret", psk);
    let mut key = alloc::vec![0u8; alg.key_len()];
    labeled_expand(&suite, &secret, b"key", &ks_context, &mut key);
    let mut base_nonce = [0u8; NN];
    labeled_expand(&suite, &secret, b"base_nonce", &ks_context, &mut base_nonce);
    let mut exporter_secret = [0u8; NH];
    labeled_expand(&suite, &secret, b"exp", &ks_context, &mut exporter_secret);
    secret.zeroize();
    ks_context.zeroize();

    Ok(Context {
        alg,
        key,
        base_nonce,
        seq: 0,
        exporter_secret,
    })
}

/// Sender setup with a caller-supplied ephemeral scalar `sk_e`. `sk_s` is the
/// sender's static key and is required exactly when `mode` uses auth.
#[allow(clippy::too_many_arguments)] // mirrors the RFC 9180 key-schedule inputs
fn sender_core(
    alg: AeadAlgorithm,
    mode: Mode,
    sk_e: &[u8; 32],
    pk_r: &[u8; 32],
    sk_s: Option<&[u8; 32]>,
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<([u8; NENC], Context)> {
    if mode.uses_auth() != sk_s.is_some() {
        return Err(Error::InvalidKey);
    }
    let enc = X25519::diffie_hellman(sk_e, &X25519::BASE);
    let mut dh_out = dh(sk_e, pk_r)?.to_vec();
    let mut kem_context = Vec::with_capacity(3 * NENC);
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(pk_r);
    if let Some(sk_s) = sk_s {
        let pk_s = X25519::diffie_hellman(sk_s, &X25519::BASE);
        dh_out.extend_from_slice(&dh(sk_s, pk_r)?);
        kem_context.extend_from_slice(&pk_s);
    }
    let mut shared = extract_and_expand(&dh_out, &kem_context);
    dh_out.zeroize();
    let ctx = key_schedule(alg, mode, &shared, info, psk, psk_id);
    shared.zeroize();
    Ok((enc, ctx?))
}

/// Receiver setup. `pk_s` is the sender's static public key and is required
/// exactly when `mode` uses auth.
#[allow(clippy::too_many_arguments)] // mirrors the RFC 9180 key-schedule inputs
fn receiver_core(
    alg: AeadAlgorithm,
    mode: Mode,
    enc: &[u8; NENC],
    sk_r: &[u8; 32],
    pk_s: Option<&[u8; 32]>,
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<Context> {
    if mode.uses_auth() != pk_s.is_some() {
        return Err(Error::InvalidKey);
    }
    let pk_r = X25519::diffie_hellman(sk_r, &X25519::BASE);
    let mut dh_out = dh(sk_r, enc)?.to_vec();
    let mut kem_context = Vec::with_capacity(3 * NENC);
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(&pk_r);
    if let Some(pk_s) = pk_s {
        dh_out.extend_from_slice(&dh(sk_r, pk_s)?);
        kem_context.extend_from_slice(pk_s);
    }
    let mut shared = extract_and_expand(&dh_out, &kem_context);
    dh_out.zeroize();
    let ctx = key_schedule(alg, mode, &shared, info, psk, psk_id);
    shared.zeroize();
    ctx
}

fn random_scalar<R: CryptoRng>(rng: &mut R) -> Result<[u8; 32]> {
    let mut sk = [0u8; 32];
    rng.try_fill_bytes(&mut sk)?;
    Ok(sk)
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
    let mut sk_e = random_scalar(rng)?;
    let out = sender_core(alg, Mode::Base, &sk_e, pk_r, None, info, &[], &[]);
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
    receiver_core(alg, Mode::Base, enc, sk_r, None, info, &[], &[])
}

/// PSK-mode sender setup.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] if `psk` is shorter than 32 bytes, plus the
/// errors of [`setup_base_sender`].
pub fn setup_psk_sender<R: CryptoRng>(
    alg: AeadAlgorithm,
    pk_r: &[u8; 32],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    rng: &mut R,
) -> Result<([u8; NENC], Context)> {
    let mut sk_e = random_scalar(rng)?;
    let out = sender_core(alg, Mode::Psk, &sk_e, pk_r, None, info, psk, psk_id);
    sk_e.zeroize();
    out
}

/// PSK-mode receiver setup.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] if `psk` is shorter than 32 bytes, plus the
/// errors of [`setup_base_receiver`].
pub fn setup_psk_receiver(
    alg: AeadAlgorithm,
    enc: &[u8; NENC],
    sk_r: &[u8; 32],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<Context> {
    receiver_core(alg, Mode::Psk, enc, sk_r, None, info, psk, psk_id)
}

/// Auth-mode sender setup: authenticates the sender with the static key `sk_s`.
///
/// # Errors
///
/// As [`setup_base_sender`].
pub fn setup_auth_sender<R: CryptoRng>(
    alg: AeadAlgorithm,
    pk_r: &[u8; 32],
    info: &[u8],
    sk_s: &[u8; 32],
    rng: &mut R,
) -> Result<([u8; NENC], Context)> {
    let mut sk_e = random_scalar(rng)?;
    let out = sender_core(alg, Mode::Auth, &sk_e, pk_r, Some(sk_s), info, &[], &[]);
    sk_e.zeroize();
    out
}

/// Auth-mode receiver setup. `pk_s` is the sender's static public key.
///
/// # Errors
///
/// As [`setup_base_receiver`].
pub fn setup_auth_receiver(
    alg: AeadAlgorithm,
    enc: &[u8; NENC],
    sk_r: &[u8; 32],
    info: &[u8],
    pk_s: &[u8; 32],
) -> Result<Context> {
    receiver_core(alg, Mode::Auth, enc, sk_r, Some(pk_s), info, &[], &[])
}

/// Auth-PSK-mode sender setup.
///
/// # Errors
///
/// As [`setup_psk_sender`] and [`setup_auth_sender`].
pub fn setup_auth_psk_sender<R: CryptoRng>(
    alg: AeadAlgorithm,
    pk_r: &[u8; 32],
    info: &[u8],
    sk_s: &[u8; 32],
    psk: &[u8],
    psk_id: &[u8],
    rng: &mut R,
) -> Result<([u8; NENC], Context)> {
    let mut sk_e = random_scalar(rng)?;
    let out = sender_core(
        alg,
        Mode::AuthPsk,
        &sk_e,
        pk_r,
        Some(sk_s),
        info,
        psk,
        psk_id,
    );
    sk_e.zeroize();
    out
}

/// Auth-PSK-mode receiver setup.
///
/// # Errors
///
/// As [`setup_psk_receiver`] and [`setup_auth_receiver`].
pub fn setup_auth_psk_receiver(
    alg: AeadAlgorithm,
    enc: &[u8; NENC],
    sk_r: &[u8; 32],
    info: &[u8],
    pk_s: &[u8; 32],
    psk: &[u8],
    psk_id: &[u8],
) -> Result<Context> {
    receiver_core(alg, Mode::AuthPsk, enc, sk_r, Some(pk_s), info, psk, psk_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Official RFC 9180 vectors, base mode, DHKEM(X25519, HKDF-SHA256).
    const KAT_BASE: &str = include_str!("../tests/kat/hpke_base_x25519.txt");
    /// Official RFC 9180 vectors, PSK, auth, and auth-PSK modes.
    const KAT_MODES: &str = include_str!("../tests/kat/hpke_modes_x25519.txt");

    struct Seal {
        seq: u64,
        aad: Vec<u8>,
        pt: Vec<u8>,
        ct: Vec<u8>,
        nonce: Vec<u8>,
    }

    struct Record {
        mode: u8,
        alg: AeadAlgorithm,
        info: Vec<u8>,
        psk: Vec<u8>,
        psk_id: Vec<u8>,
        sk_rm: [u8; 32],
        pk_rm: [u8; 32],
        sk_sm: [u8; 32],
        pk_sm: [u8; 32],
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

    /// A 32-byte key; `-` marks a key the mode does not use (all zeros).
    fn arr32(s: &str) -> [u8; 32] {
        if s == "-" {
            return [0u8; 32];
        }
        unhex(s).try_into().unwrap()
    }

    fn parse(text: &str) -> Vec<Record> {
        let mut records: Vec<Record> = Vec::new();
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let key = parts.next().unwrap();
            if key == "record" {
                records.push(Record {
                    mode: 0,
                    alg: AeadAlgorithm::Aes128Gcm,
                    info: Vec::new(),
                    psk: Vec::new(),
                    psk_id: Vec::new(),
                    sk_rm: [0; 32],
                    pk_rm: [0; 32],
                    sk_sm: [0; 32],
                    pk_sm: [0; 32],
                    sk_em: [0; 32],
                    enc: [0; 32],
                    key: Vec::new(),
                    base_nonce: Vec::new(),
                    exporter_secret: Vec::new(),
                    seals: Vec::new(),
                });
                continue;
            }
            let r = records.last_mut().unwrap();
            if key == "seal" {
                let seq: u64 = parts.next().unwrap().parse().unwrap();
                let aad = unhex(parts.next().unwrap());
                let pt = unhex(parts.next().unwrap());
                let ct = unhex(parts.next().unwrap());
                let nonce = unhex(parts.next().unwrap());
                r.seals.push(Seal {
                    seq,
                    aad,
                    pt,
                    ct,
                    nonce,
                });
                continue;
            }
            let value = parts.next().unwrap_or("-");
            match key {
                "mode" => r.mode = value.parse().unwrap(),
                "aead" => {
                    r.alg = match value {
                        "1" => AeadAlgorithm::Aes128Gcm,
                        "3" => AeadAlgorithm::ChaCha20Poly1305,
                        other => panic!("unexpected aead {other}"),
                    }
                }
                "info" => r.info = unhex(value),
                "psk" => r.psk = unhex(value),
                "psk_id" => r.psk_id = unhex(value),
                "skRm" => r.sk_rm = arr32(value),
                "pkRm" => r.pk_rm = arr32(value),
                "skSm" => r.sk_sm = arr32(value),
                "pkSm" => r.pk_sm = arr32(value),
                "skEm" => r.sk_em = arr32(value),
                "enc" => r.enc = arr32(value),
                "key" => r.key = unhex(value),
                "base_nonce" => r.base_nonce = unhex(value),
                "exporter_secret" => r.exporter_secret = unhex(value),
                _ => {}
            }
        }
        records
    }

    fn all_records() -> Vec<Record> {
        let mut v = parse(KAT_BASE);
        v.extend(parse(KAT_MODES));
        v
    }

    /// Sender-side setup for a vector, using its fixed ephemeral key.
    fn sender_for(rec: &Record) -> ([u8; 32], Context) {
        let sk_s = (rec.mode & 0x02 != 0).then_some(&rec.sk_sm);
        let (psk, psk_id): (&[u8], &[u8]) = if rec.mode & 0x01 != 0 {
            (&rec.psk, &rec.psk_id)
        } else {
            (&[], &[])
        };
        let mode = match rec.mode {
            0 => Mode::Base,
            1 => Mode::Psk,
            2 => Mode::Auth,
            _ => Mode::AuthPsk,
        };
        sender_core(
            rec.alg, mode, &rec.sk_em, &rec.pk_rm, sk_s, &rec.info, psk, psk_id,
        )
        .unwrap()
    }

    fn receiver_for(rec: &Record, enc: &[u8; 32], pk_s: &[u8; 32]) -> Result<Context> {
        let pk_s = (rec.mode & 0x02 != 0).then_some(pk_s);
        let (psk, psk_id): (&[u8], &[u8]) = if rec.mode & 0x01 != 0 {
            (&rec.psk, &rec.psk_id)
        } else {
            (&[], &[])
        };
        let mode = match rec.mode {
            0 => Mode::Base,
            1 => Mode::Psk,
            2 => Mode::Auth,
            _ => Mode::AuthPsk,
        };
        receiver_core(rec.alg, mode, enc, &rec.sk_rm, pk_s, &rec.info, psk, psk_id)
    }

    #[test]
    fn rfc9180_sender_matches_vectors_all_modes() {
        let records = all_records();
        assert_eq!(records.len(), 8);
        for rec in &records {
            // The vector's static public key must be the one derived from skSm.
            if rec.mode & 0x02 != 0 {
                assert_eq!(X25519::diffie_hellman(&rec.sk_sm, &X25519::BASE), rec.pk_sm);
            }
            let (enc, mut ctx) = sender_for(rec);
            assert_eq!(enc, rec.enc, "mode {} enc", rec.mode);
            assert_eq!(ctx.key, rec.key, "mode {} key", rec.mode);
            assert_eq!(
                ctx.base_nonce.to_vec(),
                rec.base_nonce,
                "mode {} nonce",
                rec.mode
            );
            assert_eq!(
                ctx.exporter_secret.to_vec(),
                rec.exporter_secret,
                "mode {} exp",
                rec.mode
            );
            for s in &rec.seals {
                assert_eq!(ctx.seq, s.seq);
                assert_eq!(
                    ctx.nonce().unwrap().to_vec(),
                    s.nonce,
                    "nonce seq {}",
                    s.seq
                );
                assert_eq!(
                    ctx.seal(&s.aad, &s.pt).unwrap(),
                    s.ct,
                    "mode {} ct seq {}",
                    rec.mode,
                    s.seq
                );
            }
        }
    }

    #[test]
    fn rfc9180_receiver_opens_vectors_all_modes() {
        for rec in all_records() {
            let pk_s = rec.pk_sm;
            let mut ctx = receiver_for(&rec, &rec.enc, &pk_s).unwrap();
            for s in &rec.seals {
                assert_eq!(
                    ctx.open(&s.aad, &s.ct).unwrap(),
                    s.pt,
                    "mode {} seq {}",
                    rec.mode,
                    s.seq
                );
            }
        }
    }

    #[test]
    fn tampered_ciphertext_is_rejected_without_advancing() {
        let rec = &parse(KAT_BASE)[0];
        let s = &rec.seals[0];
        let mut ctx = receiver_for(rec, &rec.enc, &rec.pk_sm).unwrap();
        let mut bad = s.ct.clone();
        bad[0] ^= 1;
        assert!(ctx.open(&s.aad, &bad).is_err());
        assert_eq!(
            ctx.seq, 0,
            "failed open must not advance the sequence number"
        );
        assert_eq!(ctx.open(&s.aad, &s.ct).unwrap(), s.pt);
    }

    #[test]
    fn export_agrees_between_sender_and_receiver() {
        let rec = &parse(KAT_BASE)[0];
        let (enc, sender) = sender_for(rec);
        let receiver = receiver_for(rec, &enc, &rec.pk_sm).unwrap();
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

    #[test]
    fn psk_shorter_than_32_bytes_is_rejected() {
        let rec = parse(KAT_MODES).into_iter().find(|r| r.mode == 1).unwrap();
        let short = [0x55u8; 16];
        assert_eq!(
            setup_psk_receiver(
                rec.alg,
                &rec.enc,
                &rec.sk_rm,
                &rec.info,
                &short,
                &rec.psk_id
            )
            .err(),
            Some(Error::InvalidLength)
        );
    }

    #[test]
    fn wrong_psk_or_mode_does_not_open() {
        let psk_rec = parse(KAT_MODES).into_iter().find(|r| r.mode == 1).unwrap();
        let s = &psk_rec.seals[0];

        // Same key material, different PSK: authentication must fail.
        let mut wrong = setup_psk_receiver(
            psk_rec.alg,
            &psk_rec.enc,
            &psk_rec.sk_rm,
            &psk_rec.info,
            &[0x66u8; 32],
            &psk_rec.psk_id,
        )
        .unwrap();
        assert!(wrong.open(&s.aad, &s.ct).is_err());

        // A base-mode receiver cannot open a PSK-mode message.
        let mut base =
            setup_base_receiver(psk_rec.alg, &psk_rec.enc, &psk_rec.sk_rm, &psk_rec.info).unwrap();
        assert!(base.open(&s.aad, &s.ct).is_err());
    }

    #[test]
    fn auth_with_wrong_sender_key_does_not_open() {
        let rec = parse(KAT_MODES).into_iter().find(|r| r.mode == 2).unwrap();
        let s = &rec.seals[0];
        let impostor_pk = X25519::diffie_hellman(&[0x77u8; 32], &X25519::BASE);
        let mut ctx = receiver_for(&rec, &rec.enc, &impostor_pk).unwrap();
        assert!(ctx.open(&s.aad, &s.ct).is_err());
    }

    #[test]
    fn mode_and_key_arguments_must_agree() {
        let rec = parse(KAT_MODES).into_iter().find(|r| r.mode == 2).unwrap();
        // Auth mode without a sender key is a programming error.
        assert!(sender_core(
            rec.alg,
            Mode::Auth,
            &rec.sk_em,
            &rec.pk_rm,
            None,
            &rec.info,
            &[],
            &[]
        )
        .is_err());
    }
}
