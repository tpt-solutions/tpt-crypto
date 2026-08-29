//! Behavioural tests for [`HmacDrbg`].
//!
//! NIST SP 800-90A CAVP known-answer vectors are pending (see `todo.md`); these
//! checks pin determinism, reseed/additional-input sensitivity, and multi-block
//! output continuity.

use tpt_crypto_core::DrbgCore;
use tpt_crypto_hash::HmacDrbg;
use tpt_crypto_hash::sha2::Sha256;

type Drbg = HmacDrbg<Sha256, 64, 32>;

#[test]
fn deterministic_for_equal_seeds() {
    let mut a = Drbg::new(b"app", b"0123456789abcdef0123456789abcdef");
    let mut b = Drbg::new(b"app", b"0123456789abcdef0123456789abcdef");
    let mut oa = [0u8; 128];
    let mut ob = [0u8; 128];
    a.generate(&mut oa, &[]).unwrap();
    b.generate(&mut ob, &[]).unwrap();
    assert_eq!(oa, ob);
}

#[test]
fn distinct_entropy_distinct_output() {
    let mut a = Drbg::new(b"", b"0123456789abcdef0123456789abcdef");
    let mut b = Drbg::new(b"", b"0123456789abcdef0123456789abcdeF");
    let mut oa = [0u8; 64];
    let mut ob = [0u8; 64];
    a.generate(&mut oa, &[]).unwrap();
    b.generate(&mut ob, &[]).unwrap();
    assert_ne!(oa, ob);
}

#[test]
fn reseed_changes_stream() {
    let mut a = Drbg::new(b"", b"0123456789abcdef0123456789abcdef");
    let mut b = Drbg::new(b"", b"0123456789abcdef0123456789abcdef");
    b.reseed(b"fresh-entropy-fresh-entropy-1234", &[]);
    let mut oa = [0u8; 64];
    let mut ob = [0u8; 64];
    a.generate(&mut oa, &[]).unwrap();
    b.generate(&mut ob, &[]).unwrap();
    assert_ne!(oa, ob);
}

#[test]
fn additional_input_changes_stream() {
    let mut a = Drbg::new(b"", b"0123456789abcdef0123456789abcdef");
    let mut b = Drbg::new(b"", b"0123456789abcdef0123456789abcdef");
    let mut oa = [0u8; 64];
    let mut ob = [0u8; 64];
    a.generate(&mut oa, &[]).unwrap();
    b.generate(&mut ob, b"extra").unwrap();
    assert_ne!(oa, ob);
}

#[test]
fn output_is_prefix_consistent_across_sizes() {
    // A single generate call of N bytes is one contiguous stream; a shorter
    // request from a fresh identical DRBG must be its prefix.
    let mut a = Drbg::new(b"", b"0123456789abcdef0123456789abcdef");
    let mut b = Drbg::new(b"", b"0123456789abcdef0123456789abcdef");
    let mut big = [0u8; 96];
    let mut small = [0u8; 40];
    a.generate(&mut big, &[]).unwrap();
    b.generate(&mut small, &[]).unwrap();
    assert_eq!(&big[..40], &small[..]);
}
