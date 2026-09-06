//! Property tests for `tpt-crypto-mpc`.
//!
//! Cross-checks the MPC primitives against their functional specification:
//!
//! * `reconstruct(share(x)) == x` for `n`-party additive sharing.
//! * Beaver-multiplied shares reconstruct to `x * y`.
//! * 1-of-2 / 1-of-N / IKNP base OT: the receiver learns *exactly* the chosen
//!   message and nothing else.

use proptest::prelude::*;

use tpt_crypto_core::{CryptoRng, Result};
use tpt_crypto_field::{Field, FieldElement, P256ScalarParams};

use tpt_crypto_mpc::{
    multiply, reconstruct, share_secret, share_secret_2, transfer_1ofn, transfer_base_ot_1of2,
    BeaverTriple,
};

type F = FieldElement<P256ScalarParams>;

/// Small deterministic splitmix64-style RNG implementing [`CryptoRng`].
struct Drng(u64);

impl CryptoRng for Drng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        for b in dest.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
        Ok(())
    }
}

fn field_elem(x: u64) -> F {
    F::from_u64(x)
}

proptest! {
    #[test]
    fn share_reconstruct_roundtrip(n in 2usize..8, x in any::<u64>()) {
        let shares = share_secret(&mut Drng(x.wrapping_add(1)), &field_elem(x), n).unwrap();
        prop_assert_eq!(reconstruct(&shares), field_elem(x));
    }

    #[test]
    fn two_party_share_reconstruct(x in any::<u64>()) {
        let (s0, s1) = share_secret_2(&mut Drng(x.wrapping_add(7)), &field_elem(x));
        prop_assert_eq!(reconstruct(&[s0, s1]), field_elem(x));
    }

    #[test]
    fn share_add_and_scale(x in any::<u64>(), y in any::<u64>()) {
        let (sx0, sx1) = share_secret_2(&mut Drng(x), &field_elem(x));
        let (sy0, sy1) = share_secret_2(&mut Drng(y), &field_elem(y));
        // (x + y) sharing == add of shares
        let sum = sx0.add(&sy0);
        let sum1 = sx1.add(&sy1);
        prop_assert_eq!(reconstruct(&[sum, sum1]), field_elem(x).add(&field_elem(y)));
        // scale by public c
        let c = field_elem(y);
        let sc0 = sx0.scale(&c);
        let sc1 = sx1.scale(&c);
        prop_assert_eq!(reconstruct(&[sc0, sc1]), field_elem(x).mul(&c));
    }

    #[test]
    fn beaver_multiply_reconstructs(x in any::<u64>(), y in any::<u64>()) {
        let (x0, x1) = share_secret_2(&mut Drng(x), &field_elem(x));
        let (y0, y1) = share_secret_2(&mut Drng(y), &field_elem(y));
        let (t0, t1) = BeaverTriple::<F>::deal(&mut Drng(x ^ y));
        let (z0, z1) = multiply(
            &(x0.value, x1.value),
            &(y0.value, y1.value),
            &(t0, t1),
        );
        prop_assert_eq!(z0.add(&z1), field_elem(x).mul(&field_elem(y)));
    }

    #[test]
    fn beaver_multiply_from_base_ot(x in any::<u64>(), y in any::<u64>()) {
        let (x0, x1) = share_secret_2(&mut Drng(x), &field_elem(x));
        let (y0, y1) = share_secret_2(&mut Drng(y), &field_elem(y));
        let (t0, t1) = BeaverTriple::<F>::deal_from_base_ot(&mut Drng(x ^ y ^ 0xABCDEF));
        // sanity: the triple itself is a valid additive split with a*b == c
        let a = t0.a.value.add(&t1.a.value);
        let b = t0.b.value.add(&t1.b.value);
        let c = t0.c.value.add(&t1.c.value);
        prop_assert_eq!(c, a.mul(&b));
        let (z0, z1) = multiply(
            &(x0.value, x1.value),
            &(y0.value, y1.value),
            &(t0, t1),
        );
        prop_assert_eq!(z0.add(&z1), field_elem(x).mul(&field_elem(y)));
    }

    #[test]
    fn base_ot_receiver_learns_chosen(m0 in any::<[u8;32]>(), m1 in any::<[u8;32]>(), choice in any::<bool>()) {
        let out = transfer_base_ot_1of2(&mut Drng(0), &m0, &m1, choice);
        prop_assert_eq!(&out[..], if choice { &m1[..] } else { &m0[..] });
    }

    #[test]
    fn oneofn_receiver_learns_chosen(
        m0 in any::<[u8;32]>(), m1 in any::<[u8;32]>(), m2 in any::<[u8;32]>(), choice in 0usize..3
    ) {
        let msgs = vec![m0.to_vec(), m1.to_vec(), m2.to_vec()];
        let out = transfer_1ofn(&mut Drng(0), &msgs, choice);
        prop_assert_eq!(&out[..], &msgs[choice][..]);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn iknp_receiver_learns_chosen(
        m0a in any::<[u8;32]>(), m0b in any::<[u8;32]>(),
        m1a in any::<[u8;32]>(), m1b in any::<[u8;32]>(),
        m2a in any::<[u8;32]>(), m2b in any::<[u8;32]>(),
        m3a in any::<[u8;32]>(), m3b in any::<[u8;32]>(),
        c in any::<[u8;4]>(),
    ) {
        let msgs = vec![
            (m0a.to_vec(), m0b.to_vec()),
            (m1a.to_vec(), m1b.to_vec()),
            (m2a.to_vec(), m2b.to_vec()),
            (m3a.to_vec(), m3b.to_vec()),
        ];
        let choices = vec![c[0] & 1, c[1] & 1, c[2] & 1, c[3] & 1];
        let (_cts, got) = tpt_crypto_mpc::iknp::extend_1of2(&mut Drng(0), &msgs, &choices);
        for j in 0..4 {
            prop_assert_eq!(&got[j][..], if choices[j] == 1 { &msgs[j].1[..] } else { &msgs[j].0[..] });
        }
    }

    #[test]
    fn beaver_batch_from_iknp(x in any::<u64>(), y in any::<u64>()) {
        let (x0, x1) = share_secret_2(&mut Drng(x), &field_elem(x));
        let (y0, y1) = share_secret_2(&mut Drng(y), &field_elem(y));
        let triples = BeaverTriple::deal_many_from_iknp(&mut Drng(x ^ y), 5);
        let (t0, t1) = &triples[0];
        let (z0, z1) = multiply(
            &(x0.value, x1.value),
            &(y0.value, y1.value),
            &(t0.clone(), t1.clone()),
        );
        prop_assert_eq!(z0.add(&z1), field_elem(x).mul(&field_elem(y)));
    }
}
