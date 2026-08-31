//! X25519 (RFC 7748) Diffie–Hellman over Curve25519 (Montgomery form).
//!
//! The ladder is the standard constant-time Montgomery ladder from RFC 7748 §5.
//! The peer's u-coordinate is reduced mod p (X25519 admits non-canonical
//! inputs), and the shared secret is returned as a 32-byte little-endian value.

use tpt_crypto_ct::{cswap, Choice};
use tpt_crypto_field::{Ed25519Field, MAX_LIMBS};

/// X25519 (Curve25519) Montgomery ladder Diffie–Hellman.
pub struct X25519;

impl X25519 {
    /// The Curve25519 base point u-coordinate = 9.
    pub const BASE: [u8; 32] = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    /// Diffie–Hellman: given a 32-byte scalar and 32-byte public u-coordinate,
    /// compute the shared secret u-coordinate (RFC 7748 §5).
    pub fn diffie_hellman(scalar: &[u8; 32], public_u: &[u8; 32]) -> [u8; 32] {
        let mut k = *scalar;
        // Clamp per RFC 7748 §5.
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;

        let x1 = Self::from_le32(public_u);
        let mut x2 = Ed25519Field::one();
        let mut z2 = Ed25519Field::zero();
        let mut x3 = x1;
        let mut z3 = Ed25519Field::one();

        // `swap` accumulates the parity of the bits processed so far; this is
        // the canonical RFC 7748 §5 conditional-swap bookkeeping. A trailing
        // `cswap(swap, …)` after the loop restores the correct (x2, z2) order.
        let mut swap = false;
        for t in (0..255).rev() {
            let bit = ((k[t / 8] >> (t % 8)) & 1) != 0;
            swap ^= bit;
            let sc = Choice::from(swap);
            cswap(sc, &mut x2, &mut x3);
            cswap(sc, &mut z2, &mut z3);

            let a0 = x2.add(&z2);
            let a1 = x2.sub(&z2);
            let b0 = x3.add(&z3);
            let b1 = x3.sub(&z3);
            let aa = a0.square();
            let bb = a1.square();
            let e = aa.sub(&bb);
            let da = a1.mul(&b0);
            let cb = a0.mul(&b1);
            x3 = da.add(&cb).square();
            z3 = x1.mul(&da.sub(&cb).square());
            x2 = aa.mul(&bb);
            z2 = e.mul(&aa.add(&e.mul(&Self::a24())));
        }
        let sc = Choice::from(swap);
        cswap(sc, &mut x2, &mut x3);
        cswap(sc, &mut z2, &mut z3);

        // Final inversion: result = x2 / z2 = x2 * z2^(p-2) mod p.
        let z2_inv = z2.invert().unwrap_or(Ed25519Field::zero());
        let r = x2.mul(&z2_inv);
        Self::to_le32(&r)
    }

    /// Curve25519 constant `(A - 2) / 4 = (486662 - 2) / 4 = 121665`.
    fn a24() -> Ed25519Field {
        Ed25519Field::from_u64(121665)
    }

    #[doc(hidden)]
    pub fn dbg_trace(
        scalar: &[u8; 32],
        public_u: &[u8; 32],
    ) -> [(usize, bool, [u8; 32], [u8; 32], [u8; 32], [u8; 32]); 255] {
        let mut k = *scalar;
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        let x1 = Self::from_le32(public_u);
        let mut x2 = Ed25519Field::one();
        let mut z2 = Ed25519Field::zero();
        let mut x3 = x1;
        let mut z3 = Ed25519Field::one();
        let mut swap = false;
        let mut out = [(0usize, false, [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]); 255];
        let mut idx = 0usize;
        for t in (0..255).rev() {
            let bit = ((k[t / 8] >> (t % 8)) & 1) != 0;
            swap ^= bit;
            let sc = Choice::from(swap);
            cswap(sc, &mut x2, &mut x3);
            cswap(sc, &mut z2, &mut z3);
            let a0 = x2.add(&z2);
            let a1 = x2.sub(&z2);
            let b0 = x3.add(&z3);
            let b1 = x3.sub(&z3);
            let aa = a0.square();
            let bb = a1.square();
            let e = aa.sub(&bb);
            let da = a1.mul(&b0);
            let cb = a0.mul(&b1);
            x3 = da.add(&cb).square();
            z3 = x1.mul(&da.sub(&cb).square());
            x2 = aa.mul(&bb);
            z2 = e.mul(&aa.add(&e.mul(&Self::a24())));
            out[idx] = (
                t,
                swap,
                Self::to_le32(&x2),
                Self::to_le32(&z2),
                Self::to_le32(&x3),
                Self::to_le32(&z3),
            );
            idx += 1;
        }
        out
    }

    /// Parse a 32-byte little-endian integer as a field element, reducing mod p.
    fn from_le32(bytes: &[u8; 32]) -> Ed25519Field {
        let mut limbs = [0u64; MAX_LIMBS];
        for i in 0..4 {
            let mut v = 0u64;
            for j in 0..8 {
                v |= (bytes[i * 8 + j] as u64) << (8 * j);
            }
            limbs[i] = v;
        }
        Ed25519Field::from_limbs(limbs)
    }

    /// Encode a field element as a 32-byte little-endian value. The internal
    /// `to_bytes` layout is big-endian within the `MAX_LIMBS * 8`-wide buffer,
    /// with the significant limbs at the high end; we reverse that to LE.
    fn to_le32(f: &Ed25519Field) -> [u8; 32] {
        let b = f.to_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = b[16 + (31 - i)];
        }
        out
    }
}
