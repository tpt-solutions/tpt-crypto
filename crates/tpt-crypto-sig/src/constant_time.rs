//! Constant-time policy for the signature layer.
//!
//! Every operation in this crate that touches secret material — key
//! generation, signing, hint computation, and (crucially) verification — is
//! written to run in time that does not depend on the secret values:
//!
//! - **No secret-dependent branches.** Challenges, rejection-sampling retries,
//!   and the `*_chknorm` norm checks use bitwise reductions and `ct_select`,
//!   never `if` on a secret coefficient.
//! - **No secret-dependent indexing.** The matrix/vector products and the
//!   polynomial samplers walk fixed iteration orders; the only data-dependent
//!   control flow (the rejection-sampling loops) depends only on public RNG
//!   output, never on the secret.
//! - **Constant-time comparison.** Signature and public-key equality are
//!   performed with [`tpt_crypto_ct::ct_eq_bytes`]; the challenge recomputation
//!   in verification is a constant-time byte comparison.
//! - **Zeroization.** Secret keys live in [`tpt_crypto_core::SecretBox`] and are
//!   wiped on drop; ephemeral masks `y` and seeds are zeroized immediately
//!   after use.
//!
//! The deterministic-vs-hedged mode choice is public (it changes the `rnd`
//! input, not a branch on secret data), so both are constant-time.

#![allow(dead_code)]

/// Marker confirming the crate opts into the workspace constant-time lint set.
pub const CT_POLICY: &str =
    "branch-free on secrets; ct_eq/ct_select only; SecretBox + zeroize on keys";
