//! IKNP oblivious-transfer extension.
//!
//! [`extend_1of2`] turns `κ = 128` base 1-of-2 oblivious transfers into `m <= 128`
//! 1-of-2 OTs (with sender-chosen messages) using the Ishai–Kushilevitz–
//! Nissim–Pinkas correlation-robust hash construction.
//!
//! Roles follow the textbook protocol: in the base phase the *extension receiver*
//! acts as the OT sender, offering column `i` of its random matrix `T` and that
//! column XOR its choice vector `r`; the *extension sender* acts as the OT
//! receiver with a random κ-bit string `s`, so it learns
//! `q_i = t_i ⊕ (s_i · r)`. Row-wise this gives `q_j = t_j ⊕ (r_j · s)`, and the
//! correlated masks `H(j, q_j)` / `H(j, q_j ⊕ s)` let the receiver open exactly
//! the branch matching `r_j` via `H(j, t_j)`.

use alloc::vec;
use alloc::vec::Vec;

use tpt_crypto_core::CryptoRng;
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

/// Keystream of `len` bytes from a `seed` (BLAKE3 keyed mode).
fn keystream(seed: &[u8], len: usize) -> Vec<u8> {
    let mut h = Blake3::with_key(&KS_KEY);
    h.update(seed);
    let mut out = vec![0u8; len];
    h.finalize_xof(&mut out);
    out
}

/// Correlation-robust row hash `H(j, row)` -> 32-byte key.
fn row_hash(j: usize, row: &[u8; MASK_BYTES]) -> [u8; 32] {
    let mut h = Blake3::with_key(&KS_KEY);
    h.update(&[j as u8]);
    h.update(row);
    let mut out = [0u8; 32];
    h.finalize_xof(&mut out);
    out
}

/// XOR `a` (in place) with `b`.
fn xor_bytes(a: &mut [u8], b: &[u8]) {
    for i in 0..a.len() {
        a[i] ^= b[i];
    }
}

/// A pair of OT messages `(m0, m1)` carried by the sender.
type OtMsg = (Vec<u8>, Vec<u8>);

/// IKNP 1-of-2 OT extension.
///
/// Returns `(sender_ciphertexts, receiver_messages)` where `sender_ciphertexts[j] =
/// (c0[j], c1[j])` and `receiver_messages[j]` equals `sender_msgs[j][choice[j]]`
/// while revealing nothing else to the receiver. `m = sender_msgs.len()` must be
/// `<= KAPPA`.
pub fn extend_1of2<R: CryptoRng>(
    rng: &mut R,
    sender_msgs: &[OtMsg],
    receiver_choices: &[u8],
) -> (Vec<OtMsg>, Vec<Vec<u8>>) {
    let m = sender_msgs.len();
    assert!(m <= KAPPA, "IKNP supports at most KAPPA extended OTs");
    assert_eq!(
        m,
        receiver_choices.len(),
        "choice count must match message count"
    );

    // Receiver choice vector `r` as a bitstring (bit j = choice j).
    let mut r_bits = [0u8; MASK_BYTES];
    for j in 0..m {
        if receiver_choices[j] & 1 == 1 {
            r_bits[j / 8] |= 1 << (j % 8);
        }
    }

    // Receiver's random matrix `T`, stored by rows (row j spans κ bits).
    let mut t_rows = [[0u8; MASK_BYTES]; KAPPA];
    for row in t_rows.iter_mut().take(m) {
        *row = rng.gen_array::<MASK_BYTES>();
    }

    // Column `i` of `T` as an m-bit bitstring.
    fn column(rows: &[[u8; MASK_BYTES]; KAPPA], m: usize, i: usize) -> [u8; MASK_BYTES] {
        let mut c = [0u8; MASK_BYTES];
        for j in 0..m {
            if (rows[j][i / 8] >> (i % 8)) & 1 == 1 {
                c[j / 8] |= 1 << (j % 8);
            }
        }
        c
    }

    // Sender's random choice string `s` (κ bits).
    let s_bits = rng.gen_array::<MASK_BYTES>();

    // Base phase: for column `i`, receiver (OT sender) offers
    // `(t_col_i, t_col_i ⊕ r)`; sender (OT receiver) uses choice bit `s_i` and
    // obtains `q_col_i = t_col_i ⊕ (s_i · r)`. Scatter it into `q_rows`.
    let mut q_rows = [[0u8; MASK_BYTES]; KAPPA];
    for i in 0..KAPPA {
        let t_col_i = column(&t_rows, m, i);
        let mut m1 = t_col_i;
        xor_bytes(&mut m1, &r_bits);
        let s_i = (s_bits[i / 8] >> (i % 8)) & 1;
        let got = ot::transfer_base_ot_1of2(rng, &t_col_i, &m1, s_i == 1);
        for j in 0..m {
            if (got[j / 8] >> (j % 8)) & 1 == 1 {
                q_rows[j][i / 8] |= 1 << (i % 8);
            }
        }
    }

    // Extension phase: correlated masks per output OT.
    let mut sender_cts = Vec::with_capacity(m);
    let mut recv_out = Vec::with_capacity(m);
    for j in 0..m {
        let len = sender_msgs[j].0.len();

        let mut q_xor_s = q_rows[j];
        xor_bytes(&mut q_xor_s, &s_bits);
        let k0 = row_hash(j, &q_rows[j]);
        let k1 = row_hash(j, &q_xor_s);
        let mut c0 = sender_msgs[j].0.clone();
        xor_bytes(&mut c0, &keystream(&k0, len));
        let mut c1 = sender_msgs[j].1.clone();
        xor_bytes(&mut c1, &keystream(&k1, len));

        // Receiver opens the branch matching `r_j` with `H(j, t_j)`.
        let kr = row_hash(j, &t_rows[j]);
        let choice = receiver_choices[j] & 1;
        let ct = if choice == 1 { &c1 } else { &c0 };
        let mut out = ct.clone();
        xor_bytes(&mut out, &keystream(&kr, len));
        recv_out.push(out);
        sender_cts.push((c0, c1));
    }

    (sender_cts, recv_out)
}
