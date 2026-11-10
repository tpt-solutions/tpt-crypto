//! Binary-level constant-time probes for the ML-KEM bit-packing used on secret
//! data: key encoding in keygen and the re-encryption in decapsulation (todo V3).
//!
//! `cargo xtask ct-asm` compiles this file to assembly and checks the `probe_*`
//! functions for conditional jumps. The probes are compiled only, not called.

#![allow(dead_code)]

use tpt_crypto_kem::encode::{pack_bits, pack_poly};
use tpt_crypto_kem::poly::Poly;

/// 12-bit packing of a secret-derived coefficient vector (keygen's `s` encoding).
/// Compiled for the assembly scan only.
pub fn probe_pack_bits_12(out: &mut [u8], vals: &[u32]) {
    pack_bits(out, vals, 12)
}

/// Compress-and-pack of a polynomial at `d` bits (the `v` and `u` ciphertext path).
/// Compiled for the assembly scan only.
pub fn probe_pack_poly(out: &mut [u8], p: &Poly, d: usize) {
    pack_poly(out, p, d)
}

/// Not run. Taking the addresses keeps the probes in the emitted code.
#[test]
#[ignore = "keeps the probes in the emitted assembly; never run"]
fn keep_probes_alive() {
    std::hint::black_box((
        probe_pack_bits_12 as fn(&mut [u8], &[u32]),
        probe_pack_poly as fn(&mut [u8], &Poly, usize),
    ));
}
