spec ecdsa_nonce_ct

description:
  ECDSA signing over NIST P-256 / P-384 with an RFC 6979 deterministic
  per-message nonce. The signer derives `k` deterministically from the private
  key `d` and the message hash `h` via HMAC-DRBG (RFC 6979 §3.2), computes
  `R = [k] G`, `r = x(R) mod n`, `s = k^{-1} (h + r d) mod n`, applies low-`s`
  normalisation (`s = min(s, n - s)`), and retries with the next DRBG output if
  `r == 0` or `s == 0`.

  The security contract: both the nonce `k` and the private key `d` are secret,
  and nothing about either may leak through the execution trace. A single bit
  of nonce bias across signatures is enough to recover `d` (lattice attack), so
  the RFC 6979 generation, the scalar inversion, and the scalar multiplication
  must all be constant-time.

  Covers `tpt-crypto-sig` ECDSA once implemented; scalar mul is the
  `scalarmul_ct` path, scalar-field inversion is the `-field` ct `p-2`
  addition chain / ct binary GCD.

inputs:
  d : Scalar    // private key, secret, in [1, n-1]
  h : &[u8]     // message hash, truncated to the group bit length; public

outputs:
  (r, s) : (Scalar, Scalar)   // signature, both in [1, n-1], s low

assumes:
  - `d` is a valid private key produced by a CSPRNG
  - the same `(d, h)` always yields the same `(r, s)` (deterministic)

ensures:
  // functional correctness: the signature verifies under the matching pubkey
  ecdsa_verify([d] G, h, (r, s))
  // RFC 6979 determinism
  sign(d, h) == sign(d, h)
  // canonical form
  1 <= r < n  &&  1 <= s <= (n-1)/2
  // side-channel contract: trace independent of the nonce and the private key
  execution_trace ⟂ (k, d)

non_leaks:
  - `k` comes from the RFC 6979 HMAC-DRBG; HMAC is fixed-time, and the
    "k in [1, n-1]" rejection compares via constant-time range check, looping a
    data-independent-once-then-retry structure (retry probability ~2^-32, and a
    retry reveals only that a uniform draw was out of range, not any bit of d)
  - `r == 0 || s == 0` retry is astronomically rare and, if taken, leaks
    nothing about `d` (it is a property of `k` alone)
  - scalar inversion `k^{-1} mod n` is the constant-time addition chain / binary
    GCD, never Fermat via a secret-dependent square-and-multiply schedule
  - `[k] G` is the fixed-length double-and-add with `ct_select` per bit
  - `r = x(R) mod n` and `s` arithmetic use only branch-free field / scalar ops
  - low-`s` normalisation is a `ct_select` on the `s > (n-1)/2` comparison

verification:
  // functional: RFC 6979 Appendix A.2.5 (P-256 / SHA-256, messages "sample"
  // and "test") and A.2.6 (P-384 / SHA-384, "sample") deterministic-`r`
  // known-answer tests, plus sign/verify round-trips, tamper rejection and
  // low-`S` checks, in `tpt-crypto-sig/tests/ecdsa.rs`.
  // side-channel: discharged structurally — the RFC 6979 HMAC-DRBG is
  // fixed-time, `k⁻¹` and `e + r·d` run through the constant-time
  // `tpt-crypto-field` scalar field, and `[k]G` is the `scalarmul_ct`
  // fixed-length double-and-add — plus the `-ct` / `-field` leakage harness.
  // NIST CAVP `.rsp` / Wycheproof JSON sets still to be added.

evidence:
  cargo-test: -p tpt-crypto-sig --test ecdsa rfc6979
  cargo-test: -p tpt-crypto-sig --test ecdsa round_trip_and_tamper
  cargo-test: -p tpt-crypto-sig --test ecdsa signatures_are_low_s
