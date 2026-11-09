//! Counter-based nonces for protocols that carry explicit nonces.
//!
//! A [`NonceSequence`] is a fixed per-sender prefix followed by a big-endian
//! 64-bit message counter. Each call to [`NonceSequence::next_nonce`] returns the
//! next value and advances the counter; once the counter is exhausted it returns
//! `None` instead of wrapping, so a nonce is never issued twice from one sequence.
//!
//! This is the TLS 1.3 / HPKE construction (RFC 8446 §5.3, RFC 9180 §5.2) with the
//! prefix chosen by the caller. Uniqueness across senders is the caller's job: two
//! sequences must not share a prefix under the same key.

use crate::api::Nonce;

/// A counter nonce generator for `N`-byte nonces (`N >= 8`).
///
/// The first `N - 8` bytes are a fixed prefix; the last 8 bytes are the counter,
/// big-endian, starting at 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonceSequence<const N: usize> {
    prefix: [u8; N],
    counter: u64,
    exhausted: bool,
}

impl<const N: usize> NonceSequence<N> {
    /// Create a sequence whose nonces are `prefix ‖ counter`.
    ///
    /// `prefix` must be exactly `N - 8` bytes; returns `None` otherwise. Using a
    /// type with `N < 8` is a compile-time error.
    pub fn new(prefix: &[u8]) -> Option<Self> {
        const { assert!(N >= 8, "NonceSequence needs N >= 8") };
        if prefix.len() != N - 8 {
            return None;
        }
        let mut p = [0u8; N];
        p[..N - 8].copy_from_slice(prefix);
        Some(Self {
            prefix: p,
            counter: 0,
            exhausted: false,
        })
    }

    /// The next nonce, or `None` once all `2^64` values have been issued.
    pub fn next_nonce(&mut self) -> Option<Nonce<N>> {
        if self.exhausted {
            return None;
        }
        let mut out = self.prefix;
        out[N - 8..].copy_from_slice(&self.counter.to_be_bytes());
        match self.counter.checked_add(1) {
            Some(c) => self.counter = c,
            None => self.exhausted = true,
        }
        Some(Nonce::new(out))
    }

    /// Number of nonces issued so far.
    pub fn issued(&self) -> u64 {
        if self.exhausted {
            u64::MAX
        } else {
            self.counter
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_big_endian_after_prefix() {
        let mut s = NonceSequence::<12>::new(&[1, 2, 3, 4]).unwrap();
        assert_eq!(
            s.next_nonce().unwrap().0,
            [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            s.next_nonce().unwrap().0,
            [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(s.issued(), 2);
    }

    #[test]
    fn rejects_wrong_prefix_length() {
        assert!(NonceSequence::<12>::new(&[0; 3]).is_none());
        assert!(NonceSequence::<12>::new(&[0; 5]).is_none());
        assert!(NonceSequence::<8>::new(&[]).is_some());
    }

    #[test]
    fn stops_at_exhaustion_without_wrapping() {
        let mut s = NonceSequence::<8>::new(&[]).unwrap();
        s.counter = u64::MAX;
        assert_eq!(s.next_nonce().unwrap().0, u64::MAX.to_be_bytes());
        assert!(s.next_nonce().is_none());
        assert!(s.next_nonce().is_none());
        assert_eq!(s.issued(), u64::MAX);
    }

    #[test]
    fn nonces_strictly_increase_so_are_unique() {
        // The counter is big-endian in the trailing bytes, so byte-wise order equals
        // issue order; a strictly increasing run therefore has no repeats.
        let mut s = NonceSequence::<24>::new(&[7; 16]).unwrap();
        let mut prev = s.next_nonce().unwrap().0;
        for _ in 0..4096 {
            let n = s.next_nonce().unwrap().0;
            assert!(n > prev);
            prev = n;
        }
    }
}
