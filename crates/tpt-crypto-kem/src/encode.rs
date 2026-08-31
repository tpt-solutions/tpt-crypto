//! Bit-packing for ML-KEM ciphertexts and public keys.
//!
//! Coefficients are first [`compress`](crate::poly::compress)ed to `d` bits and
//! then packed little-endian (LSB first) into the output byte string. Both the
//! pack and unpack paths are constant-time: they index only public offsets.

use crate::poly::{decompress, compress, Poly, N};

/// Pack `vals.len()` `d`-bit values into `out` (LSB-first, no secret indexing).
pub fn pack_bits(out: &mut [u8], vals: &[u32], bits: usize) {
    let mut byte_off = 0usize;
    let mut bit_in = 0u32;
    for &v in vals {
        let mut val = v;
        for _ in 0..bits {
            if val & 1 == 1 {
                out[byte_off] |= 1u8 << bit_in;
            }
            val >>= 1;
            bit_in += 1;
            if bit_in == 8 {
                bit_in = 0;
                byte_off += 1;
            }
        }
    }
}

/// Unpack `n` `d`-bit values from `inp` (LSB-first).
pub fn unpack_bits(inp: &[u8], n: usize, bits: usize) -> [u32; 256] {
    let mut out = [0u32; 256];
    let mut byte_off = 0usize;
    let mut bit_in = 0u32;
    for out_i in out.iter_mut().take(n) {
        let mut val = 0u32;
        for b in 0..bits {
            let bit = (inp[byte_off] >> bit_in) & 1;
            val |= (bit as u32) << b;
            bit_in += 1;
            if bit_in == 8 {
                bit_in = 0;
                byte_off += 1;
            }
        }
        *out_i = val;
    }
    out
}

/// Compress and pack a single polynomial (`d` bits per coefficient).
pub fn pack_poly(out: &mut [u8], p: &Poly, d: usize) {
    let mut vals = [0u32; N];
    for i in 0..N {
        vals[i] = compress(p[i], d) as u32;
    }
    pack_bits(out, &vals, d);
}

/// Unpack and decompress a single polynomial (`d` bits per coefficient).
pub fn unpack_poly(inp: &[u8], d: usize) -> Poly {
    let vals = unpack_bits(inp, N, d);
    let mut p = [0i32; N];
    for i in 0..N {
        p[i] = decompress(vals[i] as i32, d);
    }
    p
}
