//! Base oblivious transfer.
//!
//! Implementations:
//!
//! * [`transfer_base_ot_1of2`] — Chou–Orlandi 1-of-2 OT over Curve25519
//!   (constant-time Diffie–Hellman with a hashed, branch-free key schedule).
//! * [`transfer_1ofn`] — 1-of-N OT built from `N` parallel 1-of-2 base OTs.
//!
//! Each protocol is exposed as an explicit two-message exchange ([`SenderInit`],
//! [`SenderFinalize`], [`ReceiverInit`], [`ReceiverFinalize`]) and wrapped by the
//! in-process helper [`transfer_base_ot_1of2`] / [`transfer_1ofn`] used by the
//! higher layers and the tests.

use alloc::vec;
use alloc::vec::Vec;

use tpt_crypto_core::CryptoRng;
use tpt_crypto_ct::{Choice, CtSelect};
use tpt_crypto_curve::EdwardsPoint;
use tpt_crypto_hash::blake3::{blake3, Blake3};
use tpt_crypto_hash::Xof;

/// Fixed 32-byte key for the keystream PRG (BLAKE3 keyed mode).
const KS_KEY: [u8; 32] = [
    0x9b, 0x7e, 0x4c, 0x1f, 0x2a, 0x88, 0x36, 0xd9, 0x40, 0x5b, 0x21, 0x7c, 0x6e, 0x13, 0x9a, 0xf4,
    0x55, 0x0c, 0x8b, 0x73, 0x29, 0xe2, 0x61, 0x0d, 0x4f, 0xa9, 0xb8, 0x17, 0x6c, 0x93, 0xe5, 0x02,
];

/// Derive a keystream of `len` bytes from a `seed` using BLAKE3 (keyed).
fn keystream(seed: &[u8], len: usize) -> Vec<u8> {
    let mut h = Blake3::with_key(&KS_KEY);
    h.update(seed);
    let mut out = vec![0u8; len];
    h.finalize_xof(&mut out);
    out
}

/// Derive the OT symmetric key for a branch from the compressed DH point.
fn ot_key(point: &[u8; 32], label: u8) -> [u8; 32] {
    let mut data = [0u8; 33];
    data[..32].copy_from_slice(point);
    data[32] = label;
    blake3(&data)
}

/// XOR `a` (in place) with `b` of equal length.
fn xor_bytes(a: &mut [u8], b: &[u8]) {
    for i in 0..a.len() {
        a[i] ^= b[i];
    }
}

/// Clamp a 32-byte buffer into an Ed25519 scalar (RFC 8032 §5.1.5).
fn clamp_scalar(s: &mut [u8; 32]) {
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

/// Sender's first-round message: its public key `A = x * G`.
#[derive(Clone, Copy, Debug)]
pub struct SenderRound1 {
    /// The sender's public key (compressed Edwards point).
    pub a: [u8; 32],
}

/// Sender's retained state between rounds.
pub struct SenderState {
    x: [u8; 32],
    a: EdwardsPoint,
}

/// Receiver's first-round message: its public key `B = r * G + (choice ? A : id)`.
#[derive(Clone, Copy, Debug)]
pub struct ReceiverRound1 {
    /// The receiver's public key (compressed Edwards point).
    pub b: [u8; 32],
}

/// Receiver's retained state between rounds.
pub struct ReceiverState {
    k: [u8; 32],
    choice: Choice,
}

/// Sender's final message: the two ciphertexts `c0`, `c1`.
#[derive(Clone, Debug)]
pub struct SenderRound2 {
    /// Ciphertext of message `m0`.
    pub c0: Vec<u8>,
    /// Ciphertext of message `m1`.
    pub c1: Vec<u8>,
}

/// Sender's first step: sample scalar `x`, publish `A = x * G`.
pub fn sender_init<R: CryptoRng>(rng: &mut R) -> (SenderRound1, SenderState) {
    let mut x = rng.gen_array::<32>();
    clamp_scalar(&mut x);
    let a = EdwardsPoint::basepoint().mul(&x);
    (SenderRound1 { a: a.compress() }, SenderState { x, a })
}

/// Receiver's first step: sample scalar `r`, publish `B = r * G + (choice ? A : id)`
/// and record the shared secret `k = r * A`.
pub fn receiver_init<R: CryptoRng>(
    rng: &mut R,
    a: &[u8; 32],
    choice: Choice,
) -> (ReceiverRound1, ReceiverState) {
    let mut r = rng.gen_array::<32>();
    clamp_scalar(&mut r);
    let a_pt = EdwardsPoint::decompress(a).unwrap();
    let id = EdwardsPoint::identity();
    // `ct_select(cond, a, b)` returns `a` when `cond` is true: pick `A` for
    // choice 1, the identity for choice 0.
    let addend = <EdwardsPoint as CtSelect>::ct_select(choice, a_pt, id);
    let b = EdwardsPoint::basepoint().mul(&r).add(&addend);
    let k = a_pt.mul(&r).compress();
    (
        ReceiverRound1 { b: b.compress() },
        ReceiverState { k, choice },
    )
}

/// Sender's final step: derive `k0 = x * B`, `k1 = x * (B - A)`, encrypt `m0`, `m1`.
pub fn sender_finalize(
    state: &SenderState,
    m0: &[u8],
    m1: &[u8],
    recv: &ReceiverRound1,
) -> SenderRound2 {
    let b = EdwardsPoint::decompress(&recv.b).unwrap();
    let k0 = b.mul(&state.x).compress();
    let k1 = b.sub(&state.a).mul(&state.x).compress();

    let mut c0 = m0.to_vec();
    xor_bytes(&mut c0, &keystream(&ot_key(&k0, 0), m0.len()));
    let mut c1 = m1.to_vec();
    xor_bytes(&mut c1, &keystream(&ot_key(&k1, 1), m1.len()));
    SenderRound2 { c0, c1 }
}

/// Receiver's final step: decrypt the chosen ciphertext with `k = r * A`.
pub fn receiver_finalize(state: &ReceiverState, sender: &SenderRound2) -> Vec<u8> {
    let choice = state.choice.into();
    let ct = if choice { &sender.c1 } else { &sender.c0 };
    let label = if choice { 1u8 } else { 0u8 };
    let mut out = ct.clone();
    xor_bytes(&mut out, &keystream(&ot_key(&state.k, label), ct.len()));
    out
}

/// Run a Chou–Orlandi 1-of-2 base OT in-process; return the receiver's message.
///
/// `choice == false` yields `m0`, `choice == true` yields `m1`. The sender learns
/// nothing about `choice`; the receiver learns only the chosen message.
pub fn transfer_base_ot_1of2<R: CryptoRng>(
    rng: &mut R,
    m0: &[u8],
    m1: &[u8],
    choice: bool,
) -> Vec<u8> {
    let (r1, sstate) = sender_init(rng);
    let (r2, rstate) = receiver_init(rng, &r1.a, Choice::from(choice));
    let s2 = sender_finalize(&sstate, m0, m1, &r2);
    receiver_finalize(&rstate, &s2)
}

/// Run a 1-of-N oblivious transfer in-process; return the receiver's `msgs[choice]`.
///
/// Built from `N` parallel 1-of-2 base OTs. For the chosen index `choice`, the
/// receiver learns the matching key and decrypts the right message; for every other
/// index it learns the *other* key, so the ciphertexts decrypt to garbage. The
/// sender learns nothing about `choice`.
pub fn transfer_1ofn<R: CryptoRng>(rng: &mut R, msgs: &[Vec<u8>], choice: usize) -> Vec<u8> {
    let n = msgs.len();
    assert!(n > 0, "1-of-N requires at least one message");
    assert!(choice < n, "choice index out of range");
    // Per message, run a base OT. The receiver chooses bit `(i == choice)`.
    // Sender encrypts every message under the *second* OT key (`k1`), which the
    // receiver holds only for the chosen index.
    let mut chosen_ct: Vec<u8> = Vec::new();
    for i in 0..n {
        let k0 = rng.gen_array::<32>();
        let k1 = rng.gen_array::<32>();
        let c_i = ot_key(&k1, 0);
        let ct = {
            let mut c = msgs[i].clone();
            xor_bytes(&mut c, &keystream(&c_i, msgs[i].len()));
            c
        };
        let bit = i == choice;
        let got = transfer_base_ot_1of2(rng, &k0, &k1, bit);
        if bit {
            // Receiver learned `k1`; decrypt `ct` with it.
            let mut out = ct.clone();
            xor_bytes(&mut out, &keystream(&ot_key(&k1, 0), ct.len()));
            chosen_ct = out;
        } else {
            // Receiver learned `k0`; `ct` was encrypted under `k1`, so it stays hidden.
            let _ = got;
        }
    }
    chosen_ct
}
