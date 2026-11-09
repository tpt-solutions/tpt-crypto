//! RSA signature **verification** (PKCS#1 v1.5 and RSASSA-PSS, RFC 8017).
//!
//! Only the public-key operation is provided: this module verifies signatures
//! and never touches a private key, so the modular exponentiation runs over
//! public data and is variable-time in the public exponent's bit pattern and
//! the modulus length. Arithmetic is Montgomery multiplication over `u64`
//! limbs.
//!
//! Supported hashes: SHA-256, SHA-384, SHA-512. Modulus sizes of 1024 to
//! 16384 bits are accepted; the public exponent must be odd and at least 3.

use alloc::vec;
use alloc::vec::Vec;

use tpt_crypto_hash::sha2::{Sha256, Sha384, Sha512};
use tpt_crypto_hash::Hasher;

use crate::Error;

type Result<T> = core::result::Result<T, Error>;

/// Hash functions supported for RSA verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaHash {
    /// SHA-256 (32-byte digest).
    Sha256,
    /// SHA-384 (48-byte digest).
    Sha384,
    /// SHA-512 (64-byte digest).
    Sha512,
}

impl RsaHash {
    /// Digest length in bytes (`hLen` in RFC 8017).
    #[must_use]
    pub fn digest_len(self) -> usize {
        match self {
            RsaHash::Sha256 => 32,
            RsaHash::Sha384 => 48,
            RsaHash::Sha512 => 64,
        }
    }

    /// DER `DigestInfo` prefix for PKCS#1 v1.5 (RFC 8017 §9.2, note 1).
    fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            RsaHash::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            RsaHash::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            RsaHash::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }

    /// Hash the concatenation of `parts`.
    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<H: Hasher<N>, const N: usize>(mut h: H, parts: &[&[u8]]) -> Vec<u8> {
            for p in parts {
                h.update(p);
            }
            h.finalize().to_vec()
        }
        match self {
            RsaHash::Sha256 => run(Sha256::new(), parts),
            RsaHash::Sha384 => run(Sha384::new(), parts),
            RsaHash::Sha512 => run(Sha512::new(), parts),
        }
    }
}

/// Smallest and largest accepted modulus sizes, in bits.
const MIN_MODULUS_BITS: usize = 1024;
const MAX_MODULUS_BITS: usize = 16384;

/// An RSA public key `(n, e)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// Modulus as big-endian bytes, no leading zeros.
    n: Vec<u8>,
    /// Public exponent as big-endian bytes, no leading zeros.
    e: Vec<u8>,
    /// Modulus as little-endian `u64` limbs, exactly `k64` limbs.
    n_limbs: Vec<u64>,
}

impl PublicKey {
    /// Build a public key from big-endian modulus and exponent bytes.
    ///
    /// Leading zero bytes are tolerated. Rejects moduli outside
    /// 1024..=16384 bits, even moduli, and exponents that are even or below 3.
    pub fn from_components(n_be: &[u8], e_be: &[u8]) -> Result<Self> {
        let n = trim_leading_zeros(n_be);
        let e = trim_leading_zeros(e_be);
        let bits = bit_len(n);
        if !(MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&bits) {
            return Err(Error::InvalidEncoding);
        }
        if n[n.len() - 1] & 1 == 0 {
            return Err(Error::InvalidEncoding);
        }
        // e must be odd and >= 3, and strictly smaller than n.
        if e.is_empty() || e[e.len() - 1] & 1 == 0 || e == &[1u8][..] || bit_len(e) >= bits {
            return Err(Error::InvalidEncoding);
        }
        let n_limbs = be_to_limbs(n, n.len().div_ceil(8));
        Ok(Self {
            n: n.to_vec(),
            e: e.to_vec(),
            n_limbs,
        })
    }

    /// Modulus length in bytes (`k`).
    #[must_use]
    pub fn modulus_len(&self) -> usize {
        self.n.len()
    }

    /// Big-endian modulus.
    #[must_use]
    pub fn modulus_be(&self) -> &[u8] {
        &self.n
    }

    /// Big-endian public exponent.
    #[must_use]
    pub fn exponent_be(&self) -> &[u8] {
        &self.e
    }

    /// Verify a PKCS#1 v1.5 signature (RSASSA-PKCS1-v1_5) over `msg`.
    pub fn verify_pkcs1v15(&self, hash: RsaHash, msg: &[u8], sig: &[u8]) -> Result<()> {
        let k = self.modulus_len();
        let em = self.raw_public_op(sig)?;
        debug_assert_eq!(em.len(), k);

        let digest = hash.digest(&[msg]);
        let prefix = hash.digest_info_prefix();
        let t_len = prefix.len() + digest.len();
        if k < t_len + 11 {
            return Err(Error::Verification);
        }
        // EM = 00 || 01 || PS (all 0xff, at least 8 bytes) || 00 || T
        let ps_len = k - t_len - 3;
        let mut expected = vec![0xffu8; k];
        expected[0] = 0x00;
        expected[1] = 0x01;
        expected[2 + ps_len] = 0x00;
        expected[3 + ps_len..3 + ps_len + prefix.len()].copy_from_slice(prefix);
        expected[3 + ps_len + prefix.len()..].copy_from_slice(&digest);

        if ct_eq(&em, &expected) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }

    /// Verify an RSASSA-PSS signature (RFC 8017 §8.1.2) over `msg` with MGF1
    /// using the same hash and salt length `salt_len` (TLS 1.3 uses
    /// `salt_len = hLen`).
    pub fn verify_pss(&self, hash: RsaHash, salt_len: usize, msg: &[u8], sig: &[u8]) -> Result<()> {
        let h_len = hash.digest_len();
        let k = self.modulus_len();
        let mod_bits = bit_len(&self.n);
        let em_bits = mod_bits - 1;
        let em_len = em_bits.div_ceil(8);
        if em_len < h_len + salt_len + 2 {
            return Err(Error::Verification);
        }
        let m_full = self.raw_public_op(sig)?;
        // `m` must fit in emLen bytes; the leading k - emLen bytes must be zero.
        let (lead, em) = m_full.split_at(k - em_len);
        if lead.iter().any(|&b| b != 0) {
            return Err(Error::Verification);
        }
        if em[em_len - 1] != 0xbc {
            return Err(Error::Verification);
        }
        let db_len = em_len - h_len - 1;
        let (masked_db, rest) = em.split_at(db_len);
        let h = &rest[..h_len];

        // The top 8*emLen - emBits bits of maskedDB must be zero.
        let top_bits = 8 * em_len - em_bits;
        let top_mask: u8 = 0xff >> top_bits;
        if masked_db[0] & !top_mask != 0 {
            return Err(Error::Verification);
        }

        let db_mask = mgf1(hash, h, db_len);
        let mut db: Vec<u8> = masked_db
            .iter()
            .zip(db_mask.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        db[0] &= top_mask;

        // DB = PS || 0x01 || salt, PS all zero.
        let ps_len = db_len - salt_len - 1;
        if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
            return Err(Error::Verification);
        }
        let salt = &db[db_len - salt_len..];

        let h_prime = hash.digest(&[&[0u8; 8], &hash.digest(&[msg]), salt]);
        if ct_eq(&h_prime, h) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }

    /// Compute `s^e mod n` and return it as `k` big-endian bytes.
    fn raw_public_op(&self, sig: &[u8]) -> Result<Vec<u8>> {
        let k = self.modulus_len();
        if sig.len() != k {
            return Err(Error::Verification);
        }
        let s_limbs = be_to_limbs(sig, self.n_limbs.len());
        // Reject s >= n.
        if !limbs_lt(&s_limbs, &self.n_limbs) {
            return Err(Error::Verification);
        }
        let mont = Montgomery::new(self.n_limbs.clone());
        let base = mont.to_mont(&s_limbs);
        let mut acc = mont.to_mont(&one(self.n_limbs.len()));
        for byte in &self.e {
            for bit in (0..8).rev() {
                acc = mont.mul(&acc, &acc);
                if (byte >> bit) & 1 == 1 {
                    acc = mont.mul(&acc, &base);
                }
            }
        }
        let out = mont.from_mont(&acc);
        Ok(limbs_to_be(&out, k))
    }
}

/// Montgomery arithmetic context for an odd modulus.
struct Montgomery {
    n: Vec<u64>,
    /// `-n^{-1} mod 2^64`.
    n0inv: u64,
    /// `R^2 mod n` with `R = 2^(64 * len)`.
    rr: Vec<u64>,
}

impl Montgomery {
    fn new(n: Vec<u64>) -> Self {
        let s = n.len();
        // Newton iteration for n^{-1} mod 2^64 (n[0] odd).
        let mut inv: u64 = 1;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n[0].wrapping_mul(inv)));
        }
        let n0inv = inv.wrapping_neg();

        // rr = 2^(128 * s) mod n, by repeated modular doubling of 1.
        let mut rr = one(s);
        for _ in 0..(128 * s) {
            double_mod(&mut rr, &n);
        }
        Self { n, n0inv, rr }
    }

    /// CIOS Montgomery product: `a * b * R^{-1} mod n`.
    fn mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let s = self.n.len();
        let mut t = vec![0u64; s + 2];
        for &bi in b.iter().take(s) {
            let mut carry: u128 = 0;
            for j in 0..s {
                let v = t[j] as u128 + (a[j] as u128) * (bi as u128) + carry;
                t[j] = v as u64;
                carry = v >> 64;
            }
            let v = t[s] as u128 + carry;
            t[s] = v as u64;
            t[s + 1] = (v >> 64) as u64;

            let m = t[0].wrapping_mul(self.n0inv);
            let v = t[0] as u128 + (m as u128) * (self.n[0] as u128);
            let mut carry = v >> 64;
            for j in 1..s {
                let v = t[j] as u128 + (m as u128) * (self.n[j] as u128) + carry;
                t[j - 1] = v as u64;
                carry = v >> 64;
            }
            let v = t[s] as u128 + carry;
            t[s - 1] = v as u64;
            let v2 = t[s + 1] as u128 + (v >> 64);
            t[s] = v2 as u64;
            t[s + 1] = 0;
        }
        let mut out = t[..s + 1].to_vec();
        // Final conditional subtraction (result < 2n).
        if out[s] != 0 || !limbs_lt(&out[..s], &self.n) {
            sub_in_place(&mut out, &self.n);
        }
        out.truncate(s);
        out
    }

    fn to_mont(&self, x: &[u64]) -> Vec<u64> {
        self.mul(x, &self.rr)
    }

    #[allow(clippy::wrong_self_convention)]
    fn from_mont(&self, x: &[u64]) -> Vec<u64> {
        self.mul(x, &one(self.n.len()))
    }
}

/// `x <- 2x mod n`, for `x < n`.
fn double_mod(x: &mut [u64], n: &[u64]) {
    let s = n.len();
    let mut carry = 0u64;
    for limb in x.iter_mut().take(s) {
        let next = *limb >> 63;
        *limb = (*limb << 1) | carry;
        carry = next;
    }
    if carry != 0 || !limbs_lt(&x[..s], n) {
        // Subtract n, ignoring the carry bit which cancels out.
        let mut borrow = 0u64;
        for (xi, &ni) in x.iter_mut().zip(n) {
            let (d1, b1) = xi.overflowing_sub(ni);
            let (d2, b2) = d1.overflowing_sub(borrow);
            *xi = d2;
            borrow = (b1 | b2) as u64;
        }
    }
}

/// `out -= n` in place, where `out.len() == n.len() + 1`.
fn sub_in_place(out: &mut [u64], n: &[u64]) {
    let mut borrow = 0u64;
    for (oi, &ni) in out.iter_mut().zip(n) {
        let (d1, b1) = oi.overflowing_sub(ni);
        let (d2, b2) = d1.overflowing_sub(borrow);
        *oi = d2;
        borrow = (b1 | b2) as u64;
    }
    out[n.len()] = out[n.len()].wrapping_sub(borrow);
}

/// `a < b` for equal-length little-endian limb slices.
fn limbs_lt(a: &[u64], b: &[u64]) -> bool {
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

fn one(len: usize) -> Vec<u64> {
    let mut v = vec![0u64; len];
    v[0] = 1;
    v
}

/// Big-endian bytes to little-endian limbs, zero-extended to `len` limbs.
fn be_to_limbs(be: &[u8], len: usize) -> Vec<u64> {
    let mut out = vec![0u64; len];
    for (i, &b) in be.iter().rev().enumerate() {
        out[i / 8] |= (b as u64) << (8 * (i % 8));
    }
    out
}

/// Little-endian limbs to exactly `k` big-endian bytes.
fn limbs_to_be(limbs: &[u64], k: usize) -> Vec<u8> {
    let mut out = vec![0u8; k];
    for i in 0..k {
        let limb = limbs.get(i / 8).copied().unwrap_or(0);
        out[k - 1 - i] = (limb >> (8 * (i % 8))) as u8;
    }
    out
}

fn trim_leading_zeros(b: &[u8]) -> &[u8] {
    let first = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[first..]
}

/// Bit length of a big-endian integer with no leading zero bytes.
fn bit_len(be: &[u8]) -> usize {
    match be.first() {
        None => 0,
        Some(&top) => be.len() * 8 - top.leading_zeros() as usize,
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// MGF1 mask generation (RFC 8017 §B.2.1).
fn mgf1(hash: RsaHash, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + hash.digest_len());
    let mut counter: u32 = 0;
    while out.len() < len {
        out.extend_from_slice(&hash.digest(&[seed, &counter.to_be_bytes()]));
        counter += 1;
    }
    out.truncate(len);
    out
}
