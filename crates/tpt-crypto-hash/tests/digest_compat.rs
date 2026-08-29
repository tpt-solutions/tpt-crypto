//! `digest`-trait compatibility tests, gated behind the `digest` feature.
//!
//! These pin the `digest` v0.10 facade (e.g. `Digest`, `ExtendableOutput`)
//! to known-answer vectors, and cross-check the trait facade against the
//! in-crate one-shot API (whose absolute correctness is covered by `kat.rs`'s
//! official vectors).

#![cfg(feature = "digest")]

use digest::{Digest, ExtendableOutput, Update};
use tpt_crypto_hash::blake2b::blake2b;
use tpt_crypto_hash::blake2b::Blake2b;
use tpt_crypto_hash::blake3::blake3;
use tpt_crypto_hash::blake3::Blake3;
use tpt_crypto_hash::k12::kangaroo_twelve;
use tpt_crypto_hash::k12::KangarooTwelve;

#[test]
fn blake2b_256_matches_kat() {
    // BLAKE2b-256("abc"), from the BLAKE2 test vectors.
    let expected =
        hex::decode("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319").unwrap();
    let mut h = Blake2b::<32>::new();
    Digest::update(&mut h, b"abc");
    assert_eq!(Digest::finalize(h).as_slice(), expected.as_slice());
}

#[test]
fn blake2b_512_matches_one_shot() {
    let mut h = Blake2b::<64>::new();
    Digest::update(&mut h, b"The quick brown fox");
    assert_eq!(
        Digest::finalize(h).as_slice(),
        blake2b(b"The quick brown fox").as_slice()
    );
}

#[test]
fn blake3_xof_matches_one_shot() {
    // `digest::ExtendableOutput` (32 bytes) must agree with the in-crate
    // `blake3()` one-shot, whose absolute value is pinned by `blake3_kat`.
    let mut h = Blake3::new();
    Update::update(&mut h, b"abc");
    let mut out = [0u8; 32];
    ExtendableOutput::finalize_xof_into(h, &mut out);
    assert_eq!(out.as_slice(), blake3(b"abc").as_slice());
}

#[test]
fn blake3_xof_split_invariant() {
    let mut h = Blake3::new();
    Update::update(&mut h, b"split-me");
    let mut full = [0u8; 48];
    ExtendableOutput::finalize_xof_into(h, &mut full);

    let mut h2 = Blake3::new();
    Update::update(&mut h2, b"split-me");
    let mut first = [0u8; 16];
    ExtendableOutput::finalize_xof_into(h2, &mut first);
    assert_eq!(&full[..16], &first[..]);
}

#[test]
fn k12_xof_matches_one_shot() {
    let mut h = KangarooTwelve::new(b"");
    Update::update(&mut h, b"abc");
    let mut out = [0u8; 32];
    ExtendableOutput::finalize_xof_into(h, &mut out);
    let mut one = [0u8; 32];
    kangaroo_twelve(b"abc", b"", &mut one);
    assert_eq!(out.as_slice(), one.as_slice());
}

#[test]
fn k12_xof_consistent_and_distinct() {
    // Self-consistency across two runs, and a basic sanity check that K12 is
    // not aliasing BLAKE3 for the same input.
    let mut out = [0u8; 32];
    let mut out2 = [0u8; 32];
    {
        let mut h = KangarooTwelve::new(b"");
        Update::update(&mut h, b"abc");
        ExtendableOutput::finalize_xof_into(h, &mut out);
    }
    {
        let mut h2 = KangarooTwelve::new(b"");
        Update::update(&mut h2, b"abc");
        ExtendableOutput::finalize_xof_into(h2, &mut out2);
    }
    assert_eq!(out, out2);

    let mut b = Blake3::new();
    Update::update(&mut b, b"abc");
    let mut bout = [0u8; 32];
    ExtendableOutput::finalize_xof_into(b, &mut bout);
    assert_ne!(out, bout);
}
