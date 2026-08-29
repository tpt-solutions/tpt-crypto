//! Deterministic RNG used by the test suite.
//!
//! [`TestRng`] is a tiny SHAKE256-based stream so that KAT-style tests are
//! reproducible from a fixed 32-byte seed. It implements [`CryptoRng`] and is
//! only available under `cfg(test)` / when the crate is used as a dependency
//! with `std` (the dev-dependency pulls in `tpt-crypto-hash/std`).

use tpt_crypto_core::{CryptoRng, Error};
use tpt_crypto_hash::sha3::Shake256;
use tpt_crypto_hash::Xof;

/// A deterministic, seedable RNG for tests and examples.
pub struct TestRng {
    xof: Shake256,
}

impl TestRng {
    /// Construct a deterministic RNG from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut x = Shake256::new();
        x.update(seed);
        Self { xof: x }
    }
}

impl CryptoRng for TestRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.xof.squeeze(dest);
        Ok(())
    }
}
