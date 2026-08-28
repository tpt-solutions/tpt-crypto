//! Bridge between [`CryptoRng`] and the `rand_core` ecosystem.
//!
//! Two adapters, both enabled by the `rand_core` feature:
//!
//! - [`RandCoreRng`] wraps any `rand_core::RngCore + rand_core::CryptoRng` and
//!   implements our [`CryptoRng`], so external RNGs (e.g. `rand::rngs::OsRng`, a
//!   hardware RNG) can be used wherever the substrate expects one.
//! - [`CoreRng`] wraps any of our [`CryptoRng`] and implements
//!   `rand_core::RngCore + rand_core::CryptoRng`, so a substrate DRBG can be fed
//!   into `rand_core`-based consumers.
//!
//! These newtypes avoid a coherence conflict: a blanket `impl CryptoRng for
//! rand_core::CryptoRng` would be orphan-rule illegal, and a blanket `impl
//! rand_core::RngCore for CryptoRng` could collide with `rand_core`'s own impls.

// We depend on `rand_core` 0.6 (crate alias `rand_core_06`); reference it
// explicitly to avoid clashing with the `rand_core` 0.9 pulled in transitively by
// dev-dependencies.
use crate::{CryptoRng, Error};

/// Adapt a `rand_core` RNG into a `tpt-crypto-core::CryptoRng`.
pub struct RandCoreRng<R>(pub R);

impl<R: rand_core_06::RngCore + rand_core_06::CryptoRng> CryptoRng for RandCoreRng<R> {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest).map_err(|_| Error::RngFailure)
    }
}

/// Adapt a `tpt-crypto-core::CryptoRng` into a `rand_core_06::RngCore` +
/// `rand_core_06::CryptoRng`.
pub struct CoreRng<R>(pub R);

impl<R: CryptoRng> rand_core_06::RngCore for CoreRng<R> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.0.try_fill_bytes(dest).map_err(|_| {
            rand_core_06::Error::from(
                core::num::NonZeroU32::new(rand_core_06::Error::CUSTOM_START)
                    .expect("CUSTOM_START nonzero"),
            )
        })
    }
}

impl<R: CryptoRng> rand_core_06::CryptoRng for CoreRng<R> {}
