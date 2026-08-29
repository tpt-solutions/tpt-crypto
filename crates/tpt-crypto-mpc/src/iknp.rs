//! IKNP oblivious-transfer extension.
//!
//! [`extend_1of2`] turns `κ = 128` base 1-of-2 oblivious transfers into `m <= 128`
//! 1-of-2 OTs (with sender-chosen messages) using the Ishai–Kushilevitz–
//! Nissim–Pinkas correlation-robust hash construction.
//!
//! Security parameter `κ = 128` (16-byte masks). The base phase runs `κ` Chou–
//! Orlandi base OTs whose messages carry the seed correlation `m1 = m0 ⊕ Δ`
//! (Δ a receiver-chosen string with `Δ[0] = 1`). The extension phase then derives
//! one correlated mask pair `(M0[j], M1[j] = M0[j] ⊕ Δ)` per output OT, encrypts
//! the sender's two payloads under those masks, and lets the receiver recover the
//! mask for its (independent, random) choice bit.

use alloc::vec;
use alloc::vec::Vec;

use tpt_crypto_core::CryptoRng;
use tpt_crypto_ct::Choice;
use tpt_crypto_hash::blake3::Blake3;
use tpt_crypto_hash::Xof;

use crate::ot;

/// Security parameter: number of base OTs and the mask width in bits.
const KAPPA: usize = 128;
/// Mask width in bytes (`KAPPA / 8`).
const MASK_BYTES: usize = KAPPA / 8;

/// Fixed 32-byte key for the keystream PRG (BLAKE3 keyed mode).
const KS_KEY: [u8; 32] = [
    0x9b, 0x7e, 0x4c, 0x1f, 0x2a, 0x88, 0x36, 0xd9, 0x40, 0x5b, 0x21, 0x7c, 0x6e, 0x13, 0x9a, 0xf4,
    0x55, 0x0c, 0x8b, 0x73, 0x29, 0xe2, 0x61, 0x0d, 0x4f, 0xa9, 0xb8, 0x17, 0x6c, 0x93, 0xe5, 0x02,
];

/// Fixed-output PRG: 16-byte seed -> 16-byte value (BLAKE3 keyed, squeezed to 16 bytes).
fn prg(seed: &[u8; MASK_BYTES]) -> [u8; MASK_BYTES] {
    let mut out = [0u8; MASK_BYTES];
    let mut h = Blake3::with_key(&KS_KEY);
    h.update(seed);
    h.finalize_xof(&mut out);
    out
}

/// Keystream of `len` bytes from a `seed` (BLAKE3 keyed mode).
fn keystream(seed: &[u8], len: usize) -> Vec<u8> {
    let mut h = Blake3::with_key(&KS_KEY);
    h.update(seed);
    let mut out = vec![0u8; len];
    h.finalize_xof(&mut out);
    out
}

/// XOR `a` (in place) with `b`.
fn xor_bytes(a: &mut [u8], b: &[u8]) {
    for i in 0..a.len() {
        a[i] ^= b[i];
    }
}

/// IKNP 1-of-2 OT extension.
///
/// Returns `(sender_ciphertexts, receiver_messages)` where `sender_ciphertexts[j] =
/// (c0[j], c1[j])` and `receiver_messages[j]` equals `sender_msgs[j][choice[j]]`
/// while revealing nothing else to the receiver. `m = sender_msgs.len()` must be
/// `<= KAPPA`.
pub fn extend_1of2<R: CryptoRng>(
    rng: &mut R,
    sender_msgs: &[(Vec<u8>, Vec<u8>)],
    receiver_choices: &[u8],
) -> (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>) {
    let m = sender_msgs.len();
    assert!(m <= KAPPA, "IKNP supports at most KAPPA extended OTs");
    assert_eq!(m, receiver_choices.len(), "choice count must match message count");

    // Receiver picks a random correlation string Δ with LSB = 1.
    let mut delta = rng.gen_array::<MASK_BYTES>();
    delta[0] |= 1;

    // --- Base phase: κ base OTs with messages (U[i], U[i] ⊕ Δ). ---
    let mut u = [[0u8; MASK_BYTES]; KAPPA];
    let mut recv_u = [[0u8; MASK_BYTES]; KAPPA];
    for i in 0..KAPPA {
        let ui = rng.gen_array::<MASK_BYTES>();
        u[i] = ui;
        let mut m1 = ui;
        xor_bytes(&mut m1, &delta);
        let choice = Choice::from(delta[i] & 1 == 1);
        let got = ot::transfer_base_ot_1of2(rng, &ui.to_vec(), &m1.to_vec(), choice.into());
        let mut g = [0u8; MASK_BYTES];
        g.copy_from_slice(&got[..MASK_BYTES]);
        // Recover U[i] = got ⊕ (choice_bit · Δ).
        if (delta[i] & 1) == 1 {
            xor_bytes(&mut g, &delta);
        }
        recv_u[i] = g;
    }

    // Sender's T-matrices: T0[i] = prg(U[i]); T1[i] = prg(U[i] ⊕ Δ).
    let mut t0 = [[0u8; MASK_BYTES]; KAPPA];
    let mut t1 = [[0u8; MASK_BYTES]; KAPPA];
    for i in 0..KAPPA {
        t0[i] = prg(&u[i]);
        let mut k1 = u[i];
        xor_bytes(&mut k1, &delta);
        t1[i] = prg(&k1);
    }

    // --- Extension phase: encrypt each output under its correlated mask. ---
    let mut sender_cts = Vec::with_capacity(m);
    for j in 0..m {
        let mut m0_mask = [0u8; MASK_BYTES];
        let mut m1_mask = [0u8; MASK_BYTES];
        for i in 0..KAPPA {
            let bit0 = (t0[i][j / 8] >> (j % 8)) & 1;
            let bit1 = (t1[i][j / 8] >> (j % 8)) & 1;
            if bit0 == 1 {
                m0_mask[i / 8] |= 1u8 << (i % 8);
            }
            if bit1 == 1 {
                m1_mask[i / 8] |= 1u8 << (i % 8);
            }
        }
        let len = sender_msgs[j].0.len();
        let mut c0 = sender_msgs[j].0.clone();
        xor_bytes(&mut c0, &keystream(&m0_mask, len));
        let mut c1 = sender_msgs[j].1.clone();
        xor_bytes(&mut c1, &keystream(&m1_mask, len));
        sender_cts.push((c0, c1));
    }

    // Receiver recovers M0[j] from its U-values and decrypts the chosen branch.
    let mut recv_out = Vec::with_capacity(m);
    for j in 0..m {
        let mut m0_mask = [0u8; MASK_BYTES];
        for i in 0..KAPPA {
            let t = prg(&recv_u[i]);
            let bit = (t[j / 8] >> (j % 8)) & 1;
            if bit == 1 {
                m0_mask[i / 8] |= 1u8 << (i % 8);
            }
        }
        let choice = receiver_choices[j] & 1;
        let mut mask = m0_mask;
        if choice == 1 {
            xor_bytes(&mut mask, &delta); // M1 = M0 ⊕ Δ
        }
        let len = sender_cts[j].0.len();
        let ct = if choice == 1 {
            &sender_cts[j].1
        } else {
            &sender_cts[j].0
        };
        let mut out = ct.clone();
        xor_bytes(&mut out, &keystream(&mask, len));
        recv_out.push(out);
    }

    (sender_cts, recv_out)
}
