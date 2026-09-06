//! Beaver triples and constant-time multiplication of secret-shared values.
//!
//! A *Beaver triple* over a field is a random `(a, b, c)` with `a * b == c`, given
//! to the parties as additive shares `(a0, b0, c0)` and `(a1, b1, c1)` so that
//! `a = a0 + a1`, `b = b0 + b1`, `c = c0 + c1`.
//!
//! Such a triple lets two parties multiply their secret-shared inputs `x, y`
//! (with `x = x0 + x1`, `y = y0 + y1`) into a shared `z = x * y` with a single
//! round of interaction and *no* multiplications of secret data: see [`multiply`].

use alloc::vec::Vec;

use tpt_crypto_core::CryptoRng;
use tpt_crypto_field::Field;

use crate::field_share::{FieldCodec, SampleField, Share};
use crate::iknp;
use crate::ot;

/// One party's view of a Beaver triple: its shares of `a`, `b`, `c`.
#[derive(Clone, Copy, Debug)]
pub struct BeaverTriple<F> {
    /// This party's share of `a`.
    pub a: Share<F>,
    /// This party's share of `b`.
    pub b: Share<F>,
    /// This party's share of `c` (with `c == a * b`).
    pub c: Share<F>,
}

impl<F: Field> BeaverTriple<F> {
    /// Trusted-dealer offline generation.
    ///
    /// Returns `(party0, party1)`. The shares satisfy `party0.a + party1.a == a`,
    /// `party0.b + party1.b == b`, `party0.c + party1.c == c`, and
    /// `a * b == c`.
    pub fn deal<R: CryptoRng>(rng: &mut R) -> (BeaverTriple<F>, BeaverTriple<F>)
    where
        F: SampleField,
    {
        let a0 = F::random(rng);
        let a1 = F::random(rng);
        let b0 = F::random(rng);
        let b1 = F::random(rng);
        let a = a0.add(&a1);
        let b = b0.add(&b1);
        let c = a.mul(&b);
        let c0 = F::random(rng);
        let c1 = c.sub(&c0);
        (
            BeaverTriple {
                a: Share::new(a0),
                b: Share::new(b0),
                c: Share::new(c0),
            },
            BeaverTriple {
                a: Share::new(a1),
                b: Share::new(b1),
                c: Share::new(c1),
            },
        )
    }

    /// Offline generation from three 1-of-2 base oblivious transfers.
    ///
    /// A dealer (the sender) samples `(a0, a1)`, `(b0, b1)` and `c = (a0 + a1) *
    /// (b0 + b1)` with `(c0, c1)` a random additive split of `c`. Each pair is
    /// transferred to the receiver (party 1) via a base OT whose choice bit is
    /// uniformly random, so the receiver learns exactly one share of each pair and
    /// the dealer keeps the other — yielding a valid two-party additive split.
    ///
    /// The result is returned as `(party0, party1)` shares; `party0.a + party1.a ==
    /// a`, etc., and `a * b == c`.
    pub fn deal_from_base_ot<R: CryptoRng>(rng: &mut R) -> (BeaverTriple<F>, BeaverTriple<F>)
    where
        F: SampleField + FieldCodec,
    {
        let a0 = F::random(rng);
        let a1 = F::random(rng);
        let b0 = F::random(rng);
        let b1 = F::random(rng);
        let a = a0.add(&a1);
        let b = b0.add(&b1);
        let c = a.mul(&b);
        let c0 = F::random(rng);
        let c1 = c.sub(&c0);
        let pairs: [(F, F); 3] = [(a0, a1), (b0, b1), (c0, c1)];

        let mut p0 = [F::zero(), F::zero(), F::zero()];
        let mut p1 = [F::zero(), F::zero(), F::zero()];
        for i in 0..3 {
            let m0 = pairs[i].0.encode();
            let m1 = pairs[i].1.encode();
            let choice = rng.gen_u32() & 1 == 1;
            let got = ot::transfer_base_ot_1of2(rng, &m0, &m1, choice);
            let received = F::decode(&got).unwrap();
            // `choice == true` means the receiver learned `pairs[i].1`; the dealer
            // keeps the other share so the two sum to the original value.
            if choice {
                p0[i] = pairs[i].0;
                p1[i] = received;
            } else {
                p0[i] = pairs[i].1;
                p1[i] = received;
            }
        }
        (
            BeaverTriple {
                a: Share::new(p0[0]),
                b: Share::new(p0[1]),
                c: Share::new(p0[2]),
            },
            BeaverTriple {
                a: Share::new(p1[0]),
                b: Share::new(p1[1]),
                c: Share::new(p1[2]),
            },
        )
    }

    /// Batched offline generation from an IKNP OT extension.
    ///
    /// Produces `n` Beaver triples, each built from three 1-of-2 extended OTs
    /// (so `3 * n` extended OTs total) over `κ = 128` base OTs. The returned
    /// vector holds `(party0, party1)` pairs satisfying the usual Beaver
    /// relations.
    pub fn deal_many_from_iknp<R: CryptoRng>(
        rng: &mut R,
        n: usize,
    ) -> Vec<(BeaverTriple<F>, BeaverTriple<F>)>
    where
        F: SampleField + FieldCodec,
    {
        let m = 3 * n;
        assert!(m <= 128, "IKNP supports at most 128 extended OTs (κ = 128)");

        let mut x0 = Vec::with_capacity(m);
        let mut x1 = Vec::with_capacity(m);
        let mut msgs: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(m);
        let mut choices: Vec<u8> = Vec::with_capacity(m);
        for _ in 0..n {
            let a0 = F::random(rng);
            let a1 = F::random(rng);
            let b0 = F::random(rng);
            let b1 = F::random(rng);
            let a = a0.add(&a1);
            let b = b0.add(&b1);
            let c = a.mul(&b);
            let c0 = F::random(rng);
            let c1 = c.sub(&c0);
            for (s0, s1) in [(a0, a1), (b0, b1), (c0, c1)] {
                msgs.push((s0.encode(), s1.encode()));
                choices.push(if rng.gen_u32() & 1 == 1 { 1 } else { 0 });
            }
            x0.extend([a0, b0, c0]);
            x1.extend([a1, b1, c1]);
        }

        let (_cts, got) = iknp::extend_1of2(rng, &msgs, &choices);
        let mut recv = Vec::with_capacity(m);
        for g in &got {
            recv.push(F::decode(g).unwrap());
        }

        let mut out = Vec::with_capacity(n);
        for t in 0..n {
            let mut p0 = [F::zero(), F::zero(), F::zero()];
            let mut p1 = [F::zero(), F::zero(), F::zero()];
            for k in 0..3 {
                let j = 3 * t + k;
                // The receiver learned `x_{choice}`; the dealer keeps the other
                // share so the two sum to the original value.
                if choices[j] == 1 {
                    p0[k] = x0[j];
                    p1[k] = recv[j];
                } else {
                    p0[k] = x1[j];
                    p1[k] = recv[j];
                }
            }
            out.push((
                BeaverTriple {
                    a: Share::new(p0[0]),
                    b: Share::new(p0[1]),
                    c: Share::new(p0[2]),
                },
                BeaverTriple {
                    a: Share::new(p1[0]),
                    b: Share::new(p1[1]),
                    c: Share::new(p1[2]),
                },
            ));
        }
        out
    }
}

/// Two-party Beaver multiplication (online phase).
///
/// Given additive sharings `x = x0 + x1`, `y = y0 + y1` and a Beaver triple
/// `(party0, party1)`, return `(z0, z1)` — each party's share of `z = x * y`.
///
/// The parties reveal `d = x - a` and `e = y - b` (the sum of their local deltas)
/// and locally compute `z_i = c_i + a_i * e + b_i * d + (d * e) * (i == 0)`. The
/// public `d * e` term is assigned to party 0 so that `z0 + z1 == x * y` exactly.
pub fn multiply<F: Field>(
    x: &(F, F),
    y: &(F, F),
    t: &(BeaverTriple<F>, BeaverTriple<F>),
) -> (F, F) {
    let dx0 = x.0.sub(&t.0.a.value);
    let dx1 = x.1.sub(&t.1.a.value);
    let d = dx0.add(&dx1);
    let dy0 = y.0.sub(&t.0.b.value);
    let dy1 = y.1.sub(&t.1.b.value);
    let e = dy0.add(&dy1);

    let de = d.mul(&e);
    let z0 =
        t.0.c
            .value
            .add(&t.0.a.value.mul(&e))
            .add(&t.0.b.value.mul(&d))
            .add(&de);
    let z1 =
        t.1.c
            .value
            .add(&t.1.a.value.mul(&e))
            .add(&t.1.b.value.mul(&d));
    (z0, z1)
}
