//! The plain ML-KEM encapsulation API must reject malformed public keys with an
//! error instead of panicking or producing output (FIPS 203 §7.2).

use tpt_crypto_core::{CryptoRng, Error, Result};
use tpt_crypto_kem::ml_kem::{encapsulate, encapsulate_msg, keygen_seed, EncapsKey};
use tpt_crypto_kem::params::{MlKem1024, MlKem512, MlKem768, MlKemParams};

struct Counter(u8);

impl CryptoRng for Counter {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        for b in dest.iter_mut() {
            self.0 = self.0.wrapping_mul(29).wrapping_add(7);
            *b = self.0;
        }
        Ok(())
    }
}

fn valid_key<P: MlKemParams>() -> EncapsKey {
    keygen_seed::<P>(&[0x11; 32], &[0x22; 32]).0
}

fn check_all_params<P: MlKemParams>() {
    let good = valid_key::<P>();
    let mut rng = Counter(3);
    assert!(encapsulate::<P>(&good, &mut rng).is_ok());

    // Wrong length, both short and long.
    let short = EncapsKey {
        bytes: good.bytes[..P::PK_LEN - 1].to_vec(),
    };
    assert_eq!(
        encapsulate_msg::<P>(&short, &[0; 32])
            .err()
            .expect("expected an error"),
        Error::InvalidLength,
        "{} short",
        P::NAME
    );
    let mut long = good.bytes.clone();
    long.push(0);
    let long = EncapsKey { bytes: long };
    assert_eq!(
        encapsulate::<P>(&long, &mut rng)
            .err()
            .expect("expected an error"),
        Error::InvalidLength,
        "{} long",
        P::NAME
    );

    // A 12-bit coefficient of 4095 (>= q = 3329) in the first polynomial.
    let mut bad = good.bytes.clone();
    bad[0] = 0xff;
    bad[1] |= 0x0f;
    let bad = EncapsKey { bytes: bad };
    assert_eq!(
        encapsulate_msg::<P>(&bad, &[0; 32])
            .err()
            .expect("expected an error"),
        Error::InvalidKey,
        "{} out-of-range coefficient",
        P::NAME
    );
}

#[test]
fn malformed_keys_are_errors_for_every_parameter_set() {
    check_all_params::<MlKem512>();
    check_all_params::<MlKem768>();
    check_all_params::<MlKem1024>();
}
