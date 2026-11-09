//! Operating-system cryptographic RNG (feature `os-rng`).
//!
//! [`OsRng`] draws every byte from the platform CSPRNG via `getrandom`
//! (`getrandom(2)` on Linux, `BCryptGenRandom` on Windows, `SecRandomCopyBytes`
//! on macOS / iOS, and so on). It is the recommended default when a caller has
//! no seeded DRBG of its own, so that key generation and nonce creation do not
//! require the caller to find an entropy source first.
//!
//! Failure is reported as [`Error::RngFailure`]; it never falls back to a weaker
//! source.

use crate::{CryptoRng, Error};

/// Operating-system CSPRNG. Zero-sized and stateless.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRng;

impl CryptoRng for OsRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(dest).map_err(|_| Error::RngFailure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_buffer_and_successive_outputs_differ() {
        let mut rng = OsRng;
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.try_fill_bytes(&mut a).unwrap();
        rng.try_fill_bytes(&mut b).unwrap();
        // 2^-256 chance of a false failure; any real OS RNG passes.
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn empty_request_succeeds() {
        assert!(OsRng.try_fill_bytes(&mut []).is_ok());
    }
}
