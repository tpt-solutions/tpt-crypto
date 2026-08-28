//! Property tests for the constant-time primitives and secret wrappers.

use proptest::prelude::*;
use tpt_crypto_core::secret::SecretBox;
use tpt_crypto_core::zeroize::{Zeroize, Zeroizing};
use tpt_crypto_core::{ct_eq, ct_ne, ct_select, Choice};

proptest! {
    #[test]
    fn ct_select_matches_branch(a in any::<u64>(), b in any::<u64>(), pick in prop::bool::ANY) {
        let c = Choice::from_bool(pick);
        let got = ct_select(&a, &b, c);
        let want = if pick { a } else { b };
        prop_assert_eq!(got, want);
    }

    #[test]
    fn ct_eq_matches_equality(a in any::<u64>(), b in any::<u64>()) {
        prop_assert_eq!(ct_eq(&a, &b).is_true(), a == b);
        prop_assert_eq!(ct_ne(&a, &b).is_true(), a != b);
    }

    #[test]
    fn ct_eq_slice_matches_equality(a in proptest::collection::vec(any::<u8>(), 0..64),
                                    b in proptest::collection::vec(any::<u8>(), 0..64)) {
        prop_assert_eq!(ct_eq(a.as_slice(), b.as_slice()).is_true(), a == b);
    }

    #[test]
    fn zeroize_wipes(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
        let mut buf: Vec<u8> = bytes.clone();
        buf.zeroize();
        prop_assert!(buf.iter().all(|&x| x == 0));
    }

    #[test]
    fn zeroizing_wipes_on_drop(bytes in proptest::collection::vec(any::<u8>(), 1..64)) {
        // Build a Zeroizing<Vec<u8>>; after drop the value is wiped. We cannot
        // observe the dropped memory directly, so assert the wrapper behaves and
        // that `into_inner` yields the original (before drop).
        let z = Zeroizing::new(bytes.clone());
        prop_assert_eq!(z.len(), bytes.len());
        let recovered = z.into_inner();
        prop_assert_eq!(recovered, bytes);
    }

    #[test]
    fn secret_box_expose_round_trips(bytes in proptest::collection::vec(any::<u8>(), 1..64)) {
        let s = SecretBox::new(bytes.clone());
        prop_assert_eq!(s.expose_secret(), &bytes[..]);
    }
}
