//! Fiat–Shamir transcript (Merlin-style STROBE-lite over SHAKE256).
//!
//! The transcript absorbs labelled messages and produces labelled challenges.
//! Every challenge is derived from the full running [`Shake256`] state (so it
//! binds every prior message) and is folded back into the state, matching
//! Merlin's behaviour. This makes the transcript a sound Fiat–Shamir transform
//! for the protocols in this crate.

use tpt_crypto_field::Ed25519Scalar;
use tpt_crypto_hash::sha3::{Shake256, Xof};

use crate::group::{scalar_from_wide, scalar_le_bytes, Ristretto};

/// A Fiat–Shamir transcript used to derive challenges in zero-knowledge proofs.
#[derive(Clone)]
pub struct Transcript {
    state: Shake256,
}

impl Transcript {
    /// Create a transcript seeded with a domain-separation label.
    pub fn new(domain: &[u8]) -> Self {
        let mut t = Transcript {
            state: Shake256::new(),
        };
        t.state.update(b"tpt-crypto-zk.transcript");
        t.state.update(domain);
        t
    }

    /// Absorb an arbitrary message tagged with `label`.
    pub fn append_message(&mut self, label: &[u8], msg: &[u8]) {
        self.state.update(label);
        self.state.update(&(msg.len() as u64).to_le_bytes());
        self.state.update(msg);
    }

    /// Absorb a compressed group element tagged with `label`.
    pub fn append_point(&mut self, label: &[u8], point: &Ristretto) {
        self.append_message(label, &point.compress());
    }

    /// Absorb a scalar tagged with `label`, using its canonical 32-byte encoding.
    pub fn append_scalar(&mut self, label: &[u8], scalar: &Ed25519Scalar) {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&scalar_le_bytes(scalar));
        self.append_message(label, &buf);
    }

    /// Produce a challenge scalar tagged with `label`.
    ///
    /// The challenge is squeezed from a clone of the running state after a
    /// challenge flag and the label are absorbed, then the result is folded
    /// back into the running state so subsequent messages bind to it.
    pub fn challenge_scalar(&mut self, label: &[u8]) -> Ed25519Scalar {
        let mut t = self.state.clone();
        t.state.update(b"\x01");
        t.state.update(label);
        let mut buf = [0u8; 64];
        t.state.squeeze(&mut buf);
        self.state.update(&buf);
        scalar_from_wide(&buf)
    }
}
