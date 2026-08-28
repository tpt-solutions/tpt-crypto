//! Cryptographic RNG and DRBG traits.
//!
//! [`CryptoRng`] is the minimal "give me random bytes" trait every RNG in the
//! substrate implements. [`DrbgCore`] is the NIST SP 800-90A-style deterministic
//! random bit generator interface; the concrete `HmacDrbg` and `CtrDrbg` live in
//! `tpt-crypto-hash` / `tpt-crypto-aead` and implement this trait.

use crate::Error;
use core::result::Result;

/// A source of cryptographically secure random bytes.
///
/// A type implements this to be usable anywhere the substrate needs randomness
/// (key generation, nonces, blinding). Only [`try_fill_bytes`] is required; the
/// rest are provided.
pub trait CryptoRng {
    /// Fill `dest` with random bytes.
    ///
    /// # Panics
    ///
    /// The default implementation panics if [`CryptoRng::try_fill_bytes`] returns
    /// an error. Override this method if you need non-panicking failure.
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("CryptoRng::try_fill_bytes failed")
    }

    /// Try to fill `dest` with random bytes, reporting failure via [`Error::RngFailure`].
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error>;

    /// A uniformly random `u32`.
    fn gen_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    /// A uniformly random `u64`.
    fn gen_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    /// A uniformly random byte array of length `N`.
    fn gen_array<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        self.fill_bytes(&mut b);
        b
    }
}

/// A deterministic random bit generator core (NIST SP 800-90A shape).
///
/// A DRBG is seeded from entropy and can then deterministically generate output,
/// optionally reseeding. `HmacDrbg` and `CtrDrbg` (in `tpt-crypto-hash` /
/// `tpt-crypto-aead`) implement this so they can back [`CryptoRng`].
pub trait DrbgCore {
    /// Inject fresh entropy (and optional additional input), resetting the
    /// internal state.
    fn reseed(&mut self, entropy_input: &[u8], additional_input: &[u8]);

    /// Generate `out.len()` bytes into `out`, mixing in `additional_input`.
    fn generate(&mut self, out: &mut [u8], additional_input: &[u8]) -> Result<(), Error>;
}
