//! What "constant-time" guarantees in this substrate, and how to review it.
//!
//! # The promise
//!
//! A function is **constant-time with respect to a secret input** when its
//! *observable behavior* does not depend on the secret's value. The observable
//! behaviors we defend against are:
//!
//! - **Timing** — the number of CPU cycles (and which instructions execute)
//!   must not vary with the secret.
//! - **Control flow** — no branch (`if`/`match`/`loop` condition) may be taken
//!   or not taken based on secret bits.
//! - **Memory access** — no load/store address may depend on secret bits
//!   (this rules out secret-dependent array indexing and table lookups without
//!   masking).
//!
//! We encode this at the type level: a secret lives in [`SecretBox`], which has
//! no `PartialEq`/`Hash`/`Debug`, so you literally cannot branch on it by
//! accident. The only way to act on a secret's value is through [`ct::ct_eq`],
//! [`ct::ct_select`], and the masked operations in `tpt-crypto-ct`, all of which
//! have an execution trace independent of their inputs.
//!
//! # Threat model (in scope for v1)
//!
//! - Software side channels on the supported targets (`x86_64`, `aarch64`,
//!   `thumbv6m`/`thumbv7em`, `wasm32`): timing, secret-dependent branches, and
//!   secret-dependent memory access.
//! - The compiler optimizing away a wipe or introducing a branch — mitigated by
//!   `volatile` writes / `compiler_fence` in [`zeroize`] and by branch-free
//!   arithmetic in [`ct`].
//! - Every constant-time primitive additionally carries a `tpt-telos`
//!   contract (under `specs/`) stating that its execution trace is independent
//!   of the secret, and (where relevant) a `cargo xtask leakage` Welch t-test
//!   class.
//!
//! # Out of scope for v1
//!
//! - Physical attacks: power analysis (DPA/SPA), EM emanation, fault injection,
//!   photon/thermal side channels.
//! - Microarchitectural attacks beyond compiler-level constant-timeness
//!   (e.g. Spectre-class, cache-occupancy), and leakage through OS/hypervisor
//!   primitives. Use constant-time code *and* platform hardening for those.
//! - Leakage through *public* inputs (lengths, algorithm identifiers) is accepted
//!   — only secret-dependent behavior is in scope.
//!
//! # How to review a primitive
//!
//! 1. **No secret branch.** Grep for `if`/`match`/`?`/`==`/`>` whose condition
//!    touches a `SecretBox`/`[u8]` of secret data. The only permitted
//!    secret-derived value is a [`ct::Choice`] fed into `ct_select`/`ct_lookup`.
//! 2. **No secret index.** Grep for indexing (`x[i]`, `.get(i)`) where `i` is
//!    secret. Use `ct_lookup` instead.
//! 3. **Wipe on drop.** Any type holding secret bytes must implement
//!    [`Zeroize`] and be wrapped in [`SecretBox`] or [`Zeroizing`].
//! 4. **No leaky traits.** `SecretBox` must not derive `Debug`/`PartialEq`/
//!    `Hash`. The `trybuild` compile-fail tests pin this.
//! 5. **Telos + leakage.** Confirm a `specs/<primitive>.telos` contract exists
//!    and `cargo xtask verify` / `cargo xtask leakage` pass for it.
//!
//! See [`ct`] for the comparison/selection primitives and `tpt-crypto-ct` for the
//! masked/architecture-optimized layer.
