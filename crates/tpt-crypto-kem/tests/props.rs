//! Property tests for ML-KEM: KEM round-trip and implicit-rejection of
//! malformed ciphertexts. All checks are constant-time by construction.

use proptest::prelude::*;
use tpt_crypto_core::CryptoRng;
use tpt_crypto_kem::ml_kem::{decapsulate, encapsulate, keygen, MlKem512, MlKem768, MlKem1024};
use tpt_crypto_kem::params::MlKemParams;

/// Deterministic xorshift RNG implementing [`CryptoRng`] for tests.
struct TestRng(u64);

impl CryptoRng for TestRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), tpt_crypto_core::Error> {
        for b in dest.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
        Ok(())
    }
}

/// For every parameter set: `decapsulate(sk, encapsulate(pk).1) == encapsulate(pk).0`.
fn round_trip<P: MlKemParams>(rng: &mut TestRng) {
    let (pk, sk) = keygen::<P>(rng);
    let (ss1, ct) = encapsulate::<P>(&pk, rng);
    let ss2 = decapsulate::<P>(&sk, &ct.bytes).expect("decapsulation must succeed on a valid ciphertext");
    prop_assert_eq!(ss1, ss2);
}

proptest! {
    #[test]
    fn round_trip_512(seed in any::<u64>()) {
        round_trip::<MlKem512>(&mut TestRng(seed.wrapping_add(1)));
    }

    #[test]
    fn round_trip_768(seed in any::<u64>()) {
        round_trip::<MlKem768>(&mut TestRng(seed.wrapping_add(2)));
    }

    #[test]
    fn round_trip_1024(seed in any::<u64>()) {
        round_trip::<MlKem1024>(&mut TestRng(seed.wrapping_add(3)));
    }

    // Malformed ciphertext: a wrong-length input is rejected without panic, and a
    // correct-length but tampered ciphertext yields a result (implicit rejection)
    // and never panics. The decapsulated value must differ from the legitimate
    // shared secret with overwhelming probability when the ciphertext is changed.
    #[test]
    fn malformed_no_panic(seed in any::<u64>(), flip in 0usize..2000) {
        let mut rng = TestRng(seed.wrapping_add(7));
        let (pk, sk) = keygen::<MlKem768>(&mut rng);
        let (ss1, ct) = encapsulate::<MlKem768>(&pk, &mut rng);

        // Wrong length: a constant-time `InvalidCiphertext`, no panic.
        let short = ct.bytes[..ct.bytes.len() / 2].to_vec();
        let r = decapsulate::<MlKem768>(&sk, &short);
        prop_assert!(r.is_err());

        // Correct length, bytes tampered: must not panic and must produce a
        // result. If the flip actually changed a byte it should (almost surely)
        // not equal the legitimate shared secret.
        let mut bad = ct.bytes.clone();
        if !bad.is_empty() {
            let idx = flip % bad.len();
            bad[idx] ^= 0x01;
        }
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            decapsulate::<MlKem768>(&sk, &bad)
        }));
        prop_assert!(r.is_ok(), "decapsulate must not panic on tampered ciphertext");
        if let Ok(Ok(ss2)) = r {
            // A single-bit flip of a valid ciphertext should not recover the
            // legitimate shared secret (implicit rejection). Extremely unlikely
            // to collide.
            if bad != ct.bytes {
                prop_assert_ne!(ss2, ss1);
            }
        }
    }
}
