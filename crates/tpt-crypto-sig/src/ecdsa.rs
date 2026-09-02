//! ECDSA over NIST P-256 and P-384 (FIPS 186-5 / SEC1) with RFC 6979
//! deterministic nonces.
//!
//! * Nonce generation is the RFC 6979 §3.2 HMAC-DRBG construction, keyed with
//!   the same hash as the message digest (SHA-256 for P-256, SHA-384 for
//!   P-384). No external RNG is used, so signing is deterministic.
//! * Scalar arithmetic (`k⁻¹`, `e + r·d`) runs through the constant-time
//!   `tpt-crypto-field` scalar field; `[k]G` is the constant-time
//!   double-and-add from `tpt-crypto-curve`.
//! * Signatures are normalised to low-`S` (`S ≤ (n−1)/2`), and verification
//!   rejects a high-`S` signature as non-canonical (matches the common
//!   Bitcoin / BearSSL policy and Wycheproof's `SignatureMalleability` group).
//! * Both fixed (`r ‖ s`, big-endian) and ASN.1 DER encodings are supported.
//!
//! The caller supplies the message digest already computed; `sign_prehash` and
//! `verify_prehash` truncate it to the group bit length per SEC1 §4.1.3.

use alloc::vec::Vec;

use tpt_crypto_core::{Error, Result, SecretBox};
use tpt_crypto_curve::weierstrass::{ProjectivePoint, WeierstrassParams};
use tpt_crypto_field::{FieldElement, FieldParams, MAX_LIMBS};
use tpt_crypto_hash::mac::Hmac;
use tpt_crypto_hash::sha2::{Sha256, Sha384};
use tpt_crypto_hash::Hasher;

/// Largest scalar width we handle (P-384 → 48 bytes).
const MAX_BYTES: usize = 48;

/// Curve + hash binding for an ECDSA instantiation.
pub trait EcdsaCurve: WeierstrassParams {
    /// Byte width of the group order `n` (and of each fixed-encoding integer).
    const N_BYTES: usize;
    /// RFC 6979 / digest HMAC output width in bytes.
    const HMAC_OUT: usize;

    /// One-shot HMAC over the curve's hash. `out` receives `HMAC_OUT` bytes.
    fn hmac(key: &[u8], parts: &[&[u8]], out: &mut [u8]);
}

/// NIST P-256 with SHA-256.
pub use tpt_crypto_curve::weierstrass::P256;
/// NIST P-384 with SHA-384.
pub use tpt_crypto_curve::weierstrass::P384;

impl EcdsaCurve for P256 {
    const N_BYTES: usize = 32;
    const HMAC_OUT: usize = 32;
    fn hmac(key: &[u8], parts: &[&[u8]], out: &mut [u8]) {
        let mut m = Hmac::<Sha256, 64, 32>::new(key);
        for p in parts {
            m.update(p);
        }
        out[..32].copy_from_slice(&m.finalize());
    }
}

impl EcdsaCurve for P384 {
    const N_BYTES: usize = 48;
    const HMAC_OUT: usize = 48;
    fn hmac(key: &[u8], parts: &[&[u8]], out: &mut [u8]) {
        let mut m = Hmac::<Sha384, 128, 48>::new(key);
        for p in parts {
            m.update(p);
        }
        out[..48].copy_from_slice(&m.finalize());
    }
}

type Scalar<C> = FieldElement<<C as WeierstrassParams>::Scalar>;

/// Big-endian bytes (length ≤ `MAX_LIMBS*8`) → scalar, reduced mod `n`.
fn be_to_scalar<C: EcdsaCurve>(be: &[u8]) -> Scalar<C> {
    let mut limbs = [0u64; MAX_LIMBS];
    for (i, &byte) in be.iter().rev().enumerate() {
        limbs[i / 8] |= u64::from(byte) << (8 * (i % 8));
    }
    FieldElement::<C::Scalar>::from_limbs(limbs)
}

/// SEC1 §4.1.3: take the leftmost `N_BYTES` bytes of the digest as an integer,
/// then reduce mod `n`. (`n` is byte-aligned for P-256/P-384.)
fn digest_to_scalar<C: EcdsaCurve>(digest: &[u8]) -> Scalar<C> {
    let take = core::cmp::min(digest.len(), C::N_BYTES);
    be_to_scalar::<C>(&digest[..take])
}

/// Canonical big-endian encoding of a scalar in `N_BYTES` bytes.
fn scalar_to_be<C: EcdsaCurve>(s: &Scalar<C>) -> [u8; MAX_BYTES] {
    let full = s.to_bytes(); // MAX_LIMBS*8, big-endian
    let mut out = [0u8; MAX_BYTES];
    out[..C::N_BYTES].copy_from_slice(&full[full.len() - C::N_BYTES..]);
    out
}

/// Little-endian limb compare: `a >= b`?
fn limbs_ge(a: &[u64; MAX_LIMBS], b: &[u64; MAX_LIMBS]) -> bool {
    for i in (0..MAX_LIMBS).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// Is `s` in the upper half of `[1, n-1]` (i.e. `s > (n-1)/2`)?
fn is_high_s<C: EcdsaCurve>(s: &Scalar<C>) -> bool {
    let neg = Scalar::<C>::zero().sub(s); // n - s
    limbs_ge(&s.to_integer(), &neg.to_integer()) && s.ct_ne_int(&neg)
}

trait IntNe {
    fn ct_ne_int(&self, other: &Self) -> bool;
}
impl<P: FieldParams> IntNe for FieldElement<P> {
    fn ct_ne_int(&self, other: &Self) -> bool {
        self.to_integer() != other.to_integer()
    }
}

/// An ECDSA signature: the two scalars `(r, s)`, with `s` kept low.
#[derive(Clone, Copy)]
pub struct Signature<C: EcdsaCurve> {
    r: Scalar<C>,
    s: Scalar<C>,
}

impl<C: EcdsaCurve> Signature<C> {
    /// Fixed `r ‖ s` big-endian encoding (`2 * N_BYTES` bytes).
    #[must_use]
    pub fn to_fixed(&self) -> Vec<u8> {
        let r = scalar_to_be::<C>(&self.r);
        let s = scalar_to_be::<C>(&self.s);
        let mut out = Vec::with_capacity(2 * C::N_BYTES);
        out.extend_from_slice(&r[..C::N_BYTES]);
        out.extend_from_slice(&s[..C::N_BYTES]);
        out
    }

    /// Parse a fixed `r ‖ s` encoding. Rejects `r` or `s` not in `[1, n-1]`.
    pub fn from_fixed(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 2 * C::N_BYTES {
            return Err(Error::InvalidLength);
        }
        let r = scalar_in_range::<C>(&bytes[..C::N_BYTES])?;
        let s = scalar_in_range::<C>(&bytes[C::N_BYTES..])?;
        Ok(Self { r, s })
    }

    /// ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`.
    #[must_use]
    pub fn to_der(&self) -> Vec<u8> {
        let r = der_integer(&scalar_to_be::<C>(&self.r)[..C::N_BYTES]);
        let s = der_integer(&scalar_to_be::<C>(&self.s)[..C::N_BYTES]);
        let body_len = r.len() + s.len();
        let mut out = Vec::with_capacity(2 + body_len);
        out.push(0x30);
        out.push(body_len as u8);
        out.extend_from_slice(&r);
        out.extend_from_slice(&s);
        out
    }

    /// Parse a DER `SEQUENCE { INTEGER r, INTEGER s }`. Strict: minimal integer
    /// encodings, no trailing bytes, `r`/`s` in `[1, n-1]`.
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        let mut p = Der(bytes);
        let seq = p.take_tlv(0x30)?;
        if !p.0.is_empty() {
            return Err(Error::InvalidEncoding);
        }
        let mut inner = Der(seq);
        let r_bytes = inner.take_tlv(0x02)?;
        let s_bytes = inner.take_tlv(0x02)?;
        if !inner.0.is_empty() {
            return Err(Error::InvalidEncoding);
        }
        let r = der_int_to_scalar::<C>(r_bytes)?;
        let s = der_int_to_scalar::<C>(s_bytes)?;
        Ok(Self { r, s })
    }

    /// The `r` component, big-endian.
    #[must_use]
    pub fn r_bytes(&self) -> [u8; MAX_BYTES] {
        scalar_to_be::<C>(&self.r)
    }
}

/// Parse `N_BYTES` big-endian bytes as a scalar, requiring `1 <= v < n`.
fn scalar_in_range<C: EcdsaCurve>(be: &[u8]) -> Result<Scalar<C>> {
    // Pad/truncate to the field's byte width for `from_bytes`.
    let full_len = MAX_LIMBS * 8;
    let mut buf = [0u8; MAX_LIMBS * 8];
    if be.len() > full_len {
        return Err(Error::InvalidEncoding);
    }
    buf[full_len - be.len()..].copy_from_slice(be);
    let opt = FieldElement::<C::Scalar>::from_bytes(&buf);
    if opt.is_none().into_bool() {
        return Err(Error::InvalidEncoding); // >= n
    }
    let v = opt.unwrap();
    if v.is_zero().into_bool() {
        return Err(Error::InvalidEncoding);
    }
    Ok(v)
}

// ── DER helpers ──────────────────────────────────────────────────────────────

struct Der<'a>(&'a [u8]);

impl<'a> Der<'a> {
    /// Consume one `tag ‖ len ‖ value` and return the value slice.
    fn take_tlv(&mut self, tag: u8) -> Result<&'a [u8]> {
        if self.0.len() < 2 || self.0[0] != tag {
            return Err(Error::InvalidEncoding);
        }
        let len = self.0[1];
        if len & 0x80 != 0 {
            return Err(Error::InvalidEncoding); // long-form length not needed here
        }
        let len = len as usize;
        if self.0.len() < 2 + len {
            return Err(Error::InvalidEncoding);
        }
        let value = &self.0[2..2 + len];
        self.0 = &self.0[2 + len..];
        Ok(value)
    }
}

/// Minimal DER INTEGER encoding of a non-negative big-endian value.
fn der_integer(be: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i + 1 < be.len() && be[i] == 0 {
        i += 1;
    }
    let mut body = Vec::with_capacity(be.len() - i + 1);
    if be[i] & 0x80 != 0 {
        body.push(0x00);
    }
    body.extend_from_slice(&be[i..]);
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(0x02);
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

/// Validate a DER INTEGER body (minimal, non-negative) and map to a scalar in
/// `[1, n-1]`.
fn der_int_to_scalar<C: EcdsaCurve>(body: &[u8]) -> Result<Scalar<C>> {
    if body.is_empty() {
        return Err(Error::InvalidEncoding);
    }
    if body[0] & 0x80 != 0 {
        return Err(Error::InvalidEncoding); // negative
    }
    if body.len() > 1 && body[0] == 0 && body[1] & 0x80 == 0 {
        return Err(Error::InvalidEncoding); // non-minimal
    }
    let trimmed = if body[0] == 0 { &body[1..] } else { body };
    scalar_in_range::<C>(trimmed)
}

// ── RFC 6979 deterministic nonce ─────────────────────────────────────────────

/// RFC 6979 §3.2 iterator over candidate nonces `k` for a given `(x, h1)`.
struct Rfc6979<C: EcdsaCurve> {
    k: [u8; MAX_BYTES],
    v: [u8; MAX_BYTES],
    x_oct: [u8; MAX_BYTES],
    h1_oct: [u8; MAX_BYTES],
    _c: core::marker::PhantomData<C>,
}

impl<C: EcdsaCurve> Rfc6979<C> {
    fn new(x: &Scalar<C>, digest: &[u8]) -> Self {
        let nb = C::N_BYTES;
        let ho = C::HMAC_OUT;

        let mut x_oct = [0u8; MAX_BYTES];
        x_oct[..nb].copy_from_slice(&scalar_to_be::<C>(x)[..nb]);

        // bits2octets(h1): reduce the truncated digest mod n, then int2octets.
        let h1s = digest_to_scalar::<C>(digest);
        let mut h1_oct = [0u8; MAX_BYTES];
        h1_oct[..nb].copy_from_slice(&scalar_to_be::<C>(&h1s)[..nb]);

        let mut k = [0u8; MAX_BYTES];
        let mut v = [0u8; MAX_BYTES];
        for b in v[..ho].iter_mut() {
            *b = 0x01;
        }
        // K = HMAC_K(V ‖ 0x00 ‖ x_oct ‖ h1_oct)
        let mut nk = [0u8; MAX_BYTES];
        C::hmac(
            &k[..ho],
            &[&v[..ho], &[0x00], &x_oct[..nb], &h1_oct[..nb]],
            &mut nk,
        );
        k = nk;
        let mut nv = [0u8; MAX_BYTES];
        C::hmac(&k[..ho], &[&v[..ho]], &mut nv);
        v = nv;
        // K = HMAC_K(V ‖ 0x01 ‖ x_oct ‖ h1_oct)
        let mut nk = [0u8; MAX_BYTES];
        C::hmac(
            &k[..ho],
            &[&v[..ho], &[0x01], &x_oct[..nb], &h1_oct[..nb]],
            &mut nk,
        );
        k = nk;
        let mut nv = [0u8; MAX_BYTES];
        C::hmac(&k[..ho], &[&v[..ho]], &mut nv);
        v = nv;

        Rfc6979 {
            k,
            v,
            x_oct,
            h1_oct,
            _c: core::marker::PhantomData,
        }
    }

    /// Next candidate `k` (already checked to lie in `[1, n-1]`).
    fn next_k(&mut self) -> Scalar<C> {
        let ho = C::HMAC_OUT;
        let nb = C::N_BYTES;
        loop {
            // T = leftmost nb bytes of concatenated HMAC blocks.
            let mut t = [0u8; MAX_BYTES];
            let mut filled = 0;
            while filled < nb {
                let mut nv = [0u8; MAX_BYTES];
                C::hmac(&self.k[..ho], &[&self.v[..ho]], &mut nv);
                self.v = nv;
                let n = core::cmp::min(ho, nb - filled);
                t[filled..filled + n].copy_from_slice(&self.v[..n]);
                filled += n;
            }
            let candidate = scalar_in_range::<C>(&t[..nb]);
            if let Ok(k) = candidate {
                return k;
            }
            // K = HMAC_K(V ‖ 0x00); V = HMAC_K(V)
            let mut nk = [0u8; MAX_BYTES];
            C::hmac(&self.k[..ho], &[&self.v[..ho], &[0x00]], &mut nk);
            self.k = nk;
            let mut nv = [0u8; MAX_BYTES];
            C::hmac(&self.k[..ho], &[&self.v[..ho]], &mut nv);
            self.v = nv;
            let _ = &self.x_oct;
            let _ = &self.h1_oct;
        }
    }
}

// ── Keys ─────────────────────────────────────────────────────────────────────

/// An ECDSA private key: the scalar `d ∈ [1, n-1]`, held in a [`SecretBox`].
pub struct SigningKey<C: EcdsaCurve> {
    d: SecretBox<[u8; MAX_BYTES]>,
    _c: core::marker::PhantomData<C>,
}

impl<C: EcdsaCurve> SigningKey<C> {
    /// Build from a big-endian `N_BYTES` scalar, requiring `1 <= d < n`.
    pub fn from_bytes(be: &[u8]) -> Result<Self> {
        let _ = scalar_in_range::<C>(be)?;
        let mut buf = [0u8; MAX_BYTES];
        buf[..C::N_BYTES].copy_from_slice(be);
        Ok(Self {
            d: SecretBox::new(buf),
            _c: core::marker::PhantomData,
        })
    }

    fn d_scalar(&self) -> Scalar<C> {
        be_to_scalar::<C>(&self.d.expose_secret()[..C::N_BYTES])
    }

    /// The matching public key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey<C> {
        let g = ProjectivePoint::<C>::generator();
        VerifyingKey {
            point: g.mul(&self.d.expose_secret()[..C::N_BYTES]),
        }
    }

    /// Sign a message digest with an RFC 6979 deterministic nonce.
    pub fn sign_prehash(&self, digest: &[u8]) -> Result<Signature<C>> {
        let d = self.d_scalar();
        let e = digest_to_scalar::<C>(digest);
        let g = ProjectivePoint::<C>::generator();

        let mut nonces = Rfc6979::<C>::new(&d, digest);
        // The probability of a retry is ~2^-32; a few iterations always suffice.
        for _ in 0..64 {
            let k = nonces.next_k();
            let r_point = g.mul(&scalar_to_be::<C>(&k)[..C::N_BYTES]);
            let Some((x1, _)) = r_point.to_affine() else {
                continue;
            };
            // r = x1 mod n
            let r = FieldElement::<C::Scalar>::from_limbs(x1.to_integer());
            if r.is_zero().into_bool() {
                continue;
            }
            let kinv_opt = k.invert();
            if kinv_opt.is_none().into_bool() {
                continue;
            }
            let kinv = kinv_opt.unwrap();
            // s = k^{-1} (e + r d) mod n
            let s = kinv.mul(&e.add(&r.mul(&d)));
            if s.is_zero().into_bool() {
                continue;
            }
            let s = if is_high_s::<C>(&s) {
                Scalar::<C>::zero().sub(&s)
            } else {
                s
            };
            return Ok(Signature { r, s });
        }
        Err(Error::RngFailure)
    }
}

/// An ECDSA public key: a curve point.
#[derive(Clone, Copy)]
pub struct VerifyingKey<C: EcdsaCurve> {
    point: ProjectivePoint<C>,
}

impl<C: EcdsaCurve> VerifyingKey<C> {
    /// Parse a SEC1 point encoding (compressed or uncompressed). Rejects the
    /// identity and off-curve points.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self> {
        let point = ProjectivePoint::<C>::from_sec1(bytes).ok_or(Error::InvalidEncoding)?;
        if point.is_identity().into_bool() {
            return Err(Error::InvalidEncoding);
        }
        Ok(Self { point })
    }

    /// SEC1 uncompressed encoding (`04 ‖ X ‖ Y`).
    #[must_use]
    pub fn to_sec1_uncompressed(&self) -> Vec<u8> {
        let mut out = alloc::vec![0u8; 1 + 2 * C::FIELD_BYTES];
        self.point
            .to_sec1_uncompressed(&mut out)
            .expect("non-identity public key");
        out
    }

    /// Verify `sig` over the message digest. Rejects high-`S` (non-canonical).
    pub fn verify_prehash(&self, digest: &[u8], sig: &Signature<C>) -> Result<()> {
        if sig.r.is_zero().into_bool() || sig.s.is_zero().into_bool() {
            return Err(Error::Verification);
        }
        if is_high_s::<C>(&sig.s) {
            return Err(Error::Verification);
        }
        let e = digest_to_scalar::<C>(digest);
        let w_opt = sig.s.invert();
        if w_opt.is_none().into_bool() {
            return Err(Error::Verification);
        }
        let w = w_opt.unwrap();
        let u1 = e.mul(&w);
        let u2 = sig.r.mul(&w);

        let g = ProjectivePoint::<C>::generator();
        let p1 = g.mul(&scalar_to_be::<C>(&u1)[..C::N_BYTES]);
        let p2 = self.point.mul(&scalar_to_be::<C>(&u2)[..C::N_BYTES]);
        let r_point = p1.add(&p2);

        let Some((x1, _)) = r_point.to_affine() else {
            return Err(Error::Verification);
        };
        let v = FieldElement::<C::Scalar>::from_limbs(x1.to_integer());
        if v.ct_ne_int(&sig.r) {
            return Err(Error::Verification);
        }
        Ok(())
    }
}

/// Convenience: SHA-256 digest then P-256 sign.
pub fn sign_p256_sha256(sk: &SigningKey<P256>, msg: &[u8]) -> Result<Signature<P256>> {
    let mut h = Sha256::new();
    h.update(msg);
    sk.sign_prehash(&h.finalize())
}

/// Convenience: SHA-384 digest then P-384 sign.
pub fn sign_p384_sha384(sk: &SigningKey<P384>, msg: &[u8]) -> Result<Signature<P384>> {
    let mut h = Sha384::new();
    h.update(msg);
    sk.sign_prehash(&h.finalize())
}
