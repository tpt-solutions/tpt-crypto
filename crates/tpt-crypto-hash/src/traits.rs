//! Streaming traits shared by every hash in this crate.

/// A fixed-output streaming hash parameterized by its output length `OUT`.
///
/// Every implementation is constant-trace: [`Hasher::update`] and the
/// `finalize` methods never branch or index on secret data.
pub trait Hasher<const OUT: usize> {
    /// The size of the fixed digest in bytes.
    const OUTPUT_SIZE: usize = OUT;

    /// Absorb `data` into the running hash.
    fn update(&mut self, data: &[u8]);

    /// Finalize and return the digest, leaving `self` in its initial state.
    fn finalize_reset(&mut self) -> [u8; OUT];

    /// Finalize, consuming `self`, and return the digest.
    fn finalize(self) -> [u8; OUT]
    where
        Self: Sized;

    /// Reset `self` to its initial state without producing output.
    fn reset(&mut self);
}

/// An extendable-output function (XOF): a hash whose output length is chosen
/// by the caller at finalization time.
pub trait Xof {
    /// Absorb `data` into the running XOF.
    fn update(&mut self, data: &[u8]);

    /// Squeeze `out.len()` bytes, leaving `self` in its initial state.
    fn finalize_xof_reset(&mut self, out: &mut [u8]);

    /// Squeeze `out.len()` bytes, consuming `self`.
    fn finalize_xof(self, out: &mut [u8])
    where
        Self: Sized;

    /// Reset `self` to its initial state without producing output.
    fn reset(&mut self);
}
