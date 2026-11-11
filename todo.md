# tpt-crypto — Build Todo

> The high-assurance, constant-time cryptographic substrate. Pure Rust,
> `no_std`-first, hand-rolled primitives, 100% MIT/Apache dependency chain.
> Per `spec.txt`. License for every crate: `MIT OR Apache-2.0`.
> Author: TPT Solutions. Local `git` only this pass — no GitHub remote, no
> `cargo publish` (metadata is prepped so publishing is a later one-step).
>
> Layering (strict — lower never depends on higher):
> `core → ct → field → curve`, `hash` on `core+ct`, `aead` on `core+ct`,
> `kem`/`sig` on `field+curve+hash`, `zk` on `field+curve+hash`,
> `mpc` on `field+curve+hash`,
> `tpt-crypto` (facade) on everything.

---

## Phase 0 — Repo Bootstrap

(one-time; seed from `tpt-rust-map/template/`, cross-check against `tpt-math/`)

- [x] Root `Cargo.toml`: `[workspace]` `resolver = "2"`,
      `members = ["crates/*", "xtask", "examples"]`
- [x] `[workspace.package]`: `edition = "2021"`, `rust-version = "1.84"`,
      `license = "MIT OR Apache-2.0"`, `authors = ["TPT Solutions"]`,
      `homepage`/`repository` = `https://github.com/tpt-solutions/tpt-crypto`
- [x] `[workspace.dependencies]`: all 11 internal crates as
      `{ version = "0.1.0", path = "crates/<name>", default-features = false }`;
      external: `tpt-math-exact`, `tpt-math-linalg-fixed` (crates.io, `no_std`)
- [x] `[workspace.lints.rust]` `unsafe_code = "forbid"`,
      `unsafe_op_in_unsafe_fn = "deny"`; `[workspace.lints.clippy] all = "warn"`
      (`tpt-crypto-ct` overrides `unsafe_code` locally — see its section)
- [x] `[profile.release]`: `opt-level=3`, `lto="fat"`, `codegen-units=1`,
      `strip="symbols"`, `overflow-checks=true`
- [x] `rust-toolchain.toml`: stable + rustfmt + clippy + miri; targets
      `thumbv6m-none-eabi`, `thumbv7em-none-eabihf`, `wasm32-unknown-unknown`
- [x] `rustfmt.toml` (copy from `tpt-math`)
- [x] `deny.toml`: license allowlist = MIT, Apache-2.0, Apache-2.0 WITH
      LLVM-exception, BSD-2/3-Clause, ISC, Unicode-3.0, CC0-1.0, 0BSD;
      `[bans]` deny `openssl*`, `ring`, `*-sys` C-FFI crates
- [x] `LICENSE-MIT` + `LICENSE-APACHE` at root
- [x] `.gitignore` (Rust: `/target`, `Cargo.lock` kept, `*.log`, `/fuzz/target`)
- [x] `README.md`: vision, layering diagram, crate table, links to `spec.txt`
      and `tpt-rust-map`; constant-time / no_std / MIT-chain guarantees
- [x] `CONTRIBUTING.md` (copy + adapt from `tpt-telos`): no new deps without a
      license note, KAT required for every primitive, ct review checklist
- [x] `SECURITY.md`: disclosure policy, threat model (side channels in scope,
      physical/fault out of scope for v1), what "constant-time" guarantees,
      supported versions
- [x] `AGENTS.md` / `CLAUDE.md` stub (build commands, layering rules)
- [x] `crates/` dir; `xtask/` skeleton; `examples/` skeleton; `specs/` dir;
      `benches/BUDGET.md` stub
- [x] `.github/workflows/ci.yml` (see **CI** section)
- [x] `git init` (local only); initial commit
- [x] Sanity: `cargo build` succeeds on the workspace (6 crates: core, ct, hash,
      field, aead, curve)
- [x] Register the repo in `tpt-rust-map/registry.toml` (new `[[repo]]` entry,
      pillar prefix `tpt-crypto-`) and add `tpt-rust-map/repos/tpt-crypto/`

---

## Per-Crate Checklist Template

Every crate below repeats this shape. The facade `tpt-crypto` uses the umbrella
variant (feature-gated re-exports instead of steps 3–6).

**Standard crate:**
1. [ ] Scaffold `crates/<name>/` — `Cargo.toml` inheriting workspace fields,
   `src/lib.rs` with `#![no_std]`, `#![forbid(unsafe_code)]`,
   `#![cfg_attr(docsrs, feature(doc_cfg))]`, `#![warn(missing_docs)]`
2. [ ] Wire deps + `default = ["std"]` with additive `alloc` / `serde` /
   `rand_core` / trait-compat features (ADR 0001); `[lints] workspace = true`
3. [ ] crates.io metadata: `description`, `readme`, `keywords` (≤5),
   `categories` (`cryptography`, `no-std`, …), `documentation`,
   `[package.metadata.docs.rs] all-features = true`, `rustdoc-args`
4. [ ] Implement scope
5. [ ] Unit tests + doctests; `tests/kat/` corpus + `PROVENANCE.md`
   (source URL, license, sha256 of each vector file); proptest round-trips
6. [ ] `benches/<name>_bench.rs` (criterion, `harness = false`); update
   `benches/BUDGET.md` with the vs-`ring`/`dalek`/`pqcrypto` target
7. [ ] Crate-level + public-API rustdoc; deny `missing_docs`
8. [ ] `cargo fmt --check` + `cargo clippy --all-targets --all-features -D warnings`
   clean
9. [ ] `cargo deny check` clean
10. [ ] `no_std` verification: `cargo xtask no-std` builds it for
    `thumbv6m-none-eabi` (no `alloc` where the crate claims heapless)
11. [ ] Add `specs/<primitive>.telos` contract(s); add to `xtask verify`
12. [ ] `CHANGELOG.md` (`## 0.1.0 — unreleased`)
13. [ ] `cargo publish --dry-run -p <name>` clean
14. [ ] Update `tpt-rust-map/registry.toml`: crate `status` `planned` → `git`

---

## Phase 1 — Constant-Time Foundation  (v0.1 publishable slice)

### crates/tpt-crypto-core
- [x] `Error` enum (non-secret, carries no timing/oracle info): `Verification`,
      `InvalidLength`, `InvalidEncoding`, `RngFailure`, `NotOnCurve`, …
- [x] `SecretBox<T>`: owns `T`, zero-on-`Drop`; **no** `Debug`/`Display`/
      `PartialEq`/`Hash`/`Serialize`; `as_ref`/`expose_secret` gated behind an
      explicit method; `From`/`new`
- [x] `Zeroizing<T>` wrapper — `core::ptr::write_volatile` byte-wipe, no `unsafe`
      leak to callers (any `unsafe` lives here with `// SAFETY:`; if unavoidable,
      this module gets the same local override as `-ct` — decide during impl)
- [x] Traits: `CtEq` (→ `Choice`), `ConstantTimeSelect`; re-export `ct_eq` /
      `ct_select` facades (impl in `-ct`, so `-core` defines only the traits)
- [x] `CryptoRng` trait (fill_bytes, try_fill_bytes) + `DrbgCore`
      (reseed, generate); `HmacDrbg` / `CtrDrbg` live in `-hash`/`-aead`
- [x] `rand_core` bridge behind `rand_core` feature (`impl CryptoRng for R: RngCore + CryptoRng`)
- [x] `constant_time` doc module: what is guaranteed, threat model, how to review
- [x] KATs: n/a; proptest: `SecretBox` never derives leaky traits (compile-fail
      tests via `trybuild`)
- [x] `specs/secret_no_branch.telos` (types encoding no secret-dependent branch)

### crates/tpt-crypto-ct
- [x] Local lint override: `#![deny(unsafe_op_in_unsafe_fn)]`,
      **remove** `forbid(unsafe_code)` for this crate only (documented in
      `lib.rs` header + `SECURITY.md`)
- [x] `Choice` (0/1 as `u8`), `Not`/`BitAnd`/`BitOr`/`BitXor`, `from_u8_lsb`
- [x] `ct_eq` / `ct_ne` for `u8,u16,u32,u64,u128,usize` and `&[u8]` / `&[Limb]`
- [x] `ct_select` / `cmov` / `cswap` for the same set; `ct_select_slice`
- [x] `arch` module (the **only** `unsafe`): x86_64 `cmov` via `core::arch` /
      inline `asm!`, aarch64 `csel`, portable branch-free bitmask fallback;
      every block a `// SAFETY:` comment; `#[cfg]`-gated
- [x] `Masked<T>` — additive `(x ^ r, r)` and multiplicative masking; `remask`,
      `unmask`; masked add/sub/mul over limbs
- [x] Blinding helpers: scalar blinding, base-point blinding scaffolds
- [x] `ct_lookup` — branch-free table lookup (linear scan + `cmov`) for
      window methods in `-curve`
- [x] Leakage harness: `dudect`-style two-class Welch t-test runner
      (`tests/leakage.rs` + `cargo xtask leakage`); classes for `ct_select`,
      `ct_eq`, `ct_lookup`
- [x] KATs: n/a; proptest: `ct_select(c,a,b) == if c {a} else {b}` for all c,a,b
- [x] `specs/ct_select.telos`: `ensures: execution_trace ⟂ cond`
- [x] MIRI: `cargo +nightly miri test -p tpt-crypto-ct` clean
      (portable bitmask backend `#[cfg]`-gated under `miri`; proptest harness
      skipped under `miri` — same laws covered by `#[cfg(test)]` unit tests)

### crates/tpt-crypto-hash
- [x] Sponge/Keccak-f[1600] core (branch-free); SHA3-224/256/384/512,
      SHAKE128/256, cSHAKE, KMAC
      — fixed the pi-step lane index, the SP 800-185 `left_encode`/`encode_string`
      bit-length bug, and KMAC's `bytepad(encode_string(K))` key block +
      `right_encode(L)` finalization.
- [x] Merkle–Damgård SHA-2: SHA-224/256/384/512, SHA-512/256, SHA-512/224
      — fixed corrupt `K64[29]` and wrong SHA-512/256 + SHA-512/224 IVs.
- [x] BLAKE2b (RFC 7693) + keyed mode; BLAKE3 (chunked tree, XOF)
      — BLAKE2b: t/f counter went into the wrong `v[]` lanes and was applied a
      block late; keyed block is now buffered so an empty message finalizes it
      as the last block. BLAKE3: fixed `MSG_SCHEDULE` rows 2-6, the `v[12..16]`
      init (no IV xor), the 8-word chaining-value load, second-half output
      feed-forward, and rebuilt finalization around an `Output` node so the XOF
      re-runs the root compression per output block.
- [x] KangarooTwelve (K12) over Keccak-p[1600,12]
      — fixed `length_encode(0)`, the pi-step index, two `RC12` typos, and
      XOR (not overwrite) absorption across permutations.
- [x] HMAC (generic over any `Hasher`); HKDF (extract/expand)
      — HKDF-Expand no longer feeds a zero `T(0)` block on the first iteration.
- [x] `HmacDrbg` (NIST SP 800-90A) implementing `DrbgCore`
      — Update now stops after the 0x00 pass for empty provided-data; Generate's
      trailing Update passes the real additional-input.
- [x] API: streaming `Hasher` trait (`update`/`finalize`/`finalize_xof`) +
      one-shot free fns; `reset`; const output sizes
- [x] Optional `digest` trait-compat impls behind `digest` feature
       — `src/digest_impls.rs`: SHA-2, SHA-3 (`Digest`) and SHAKE
       (`ExtendableOutput`); BLAKE2b (`Digest`), BLAKE3 & K12
       (`ExtendableOutput`) now implemented. HMAC intentionally does **not**
       implement `digest::Mac` (that trait fixes key length to `KeySize`,
       whereas HMAC accepts arbitrary-length keys) — it exposes its own
       constant-time `Hmac::verify` instead. Covered by
       `tests/digest_compat.rs` (gated on `digest`).
- [~] KATs: NIST CAVP (SHA-2, SHA-3, SHAKE), RFC 7693 (BLAKE2), official BLAKE3
      test vectors, K12 (RFC 9861), RFC 4231 (HMAC), RFC 5869 (HKDF),
      NIST SP 800-185 (cSHAKE/KMAC) — in `tests/kat.rs` +
      `tests/kat/PROVENANCE.md`. NIST SP 800-90A DRBG KAT vectors pending
      (`tests/drbg.rs` pins behavioural properties for now).
- [x] All fixed-time (no data-dependent branch/index); proptest: streaming ==
      one-shot for random chunkings (`tests/props.rs`) + XOF split-invariance.
- [x] `specs/sha256.telos`, `specs/keccak_f.telos`

- [x] **Milestone**: `cargo xtask release-dry-run` clean for `-core`, `-ct`,
       `-hash`; tag `v0.1.0-slice` locally; CI green incl. `miri` + `leakage`
       — `core` and `ct` `cargo publish --dry-run` PASS (packaged cleanly);
       `hash` package is valid but its isolated `publish --dry-run` only fails
       to resolve the not-yet-published `core`/`ct` path deps (publish in
       dependency order: `core` → `ct` → `hash`). `leakage` harness PASS
       (Welch t ≪ 10.0). Tagged `v0.1.0-slice` on a targeted Phase 1 commit
       (`eb1bcfe`); `miri` not run in this environment (CI-only gate).

---

## Phase 2 — Classical Curves & AEAD

### crates/tpt-crypto-field
- [x] `Limb` alias + limb-vector ops on `tpt-math-linalg-fixed`
- [x] `FieldElement<P, const LIMBS: usize>` (P as a `FieldParams` trait impl:
      modulus, R^2, -P^-1 mod 2^64, …) — compiler monomorphizes per curve
- [x] Montgomery mul/sqr (CIOS), Montgomery/Barrett reduction, `add`/`sub`/`neg`
      (all ct, no conditional-subtract branch), `invert` (ct via `p-2` addition
      chain or ct binary-GCD), `sqrt`, `pow_vartime` (public-exp only)
- [x] `to_bytes`/`from_bytes` (canonical, ct reject non-canonical), `is_zero`
- [x] Params: P-256 base+scalar, P-384 base+scalar, BLS12-381 Fp + Fr;
      towers `Fp2`, `Fp6`, `Fp12` for BLS
- [x] Montgomery CIOS overflow-limb bug fix (commit 8836921): the accumulator
      overflow limb was indexed at `t[MAX_LIMBS]` while working limbs only
      filled `t[0..P::LIMBS]`, leaving a gap that corrupted results. Moved to
      `t[n]` adjacent to working limbs. Validated by `tests/smoke.rs`.
- [x] KATs: hand-computed + cross-check vs `tpt-math-exact` big-rational
      reference; Wycheproof field edge cases
      — `tests/kat/field_mul.json` (24 vectors) + `tests/kat/field_reduce.json`
      (21 vectors), hand-computed from the prime definitions and verified against
      Python big-integer arithmetic; see `tests/kat/PROVENANCE.md`.
- [x] proptest: field axioms (assoc/dist/inverse), `from(to(x)) == x`,
      `mul` matches `tpt-math-exact` mod P
      — `tests/field_props.rs`: P-256, P-384, BLS12-381 (Fp+Fr), Ed25519 all
      pass. **FIXED:**
      (a) `P384BaseParams` limbs 0 and 1 were both wrong — set to
      `0x0000_0000_FFFF_FFFF` / `0xFFFF_FFFF_0000_0000` (the earlier "fix" to
      `0x0000_0001_FFFF_FFFF` was backwards).
      (b) The real P-384 / BLS-Fp bug was in `mont_mul`: when `LIMBS == MAX_LIMBS`
      (6), the SOS Montgomery reduction can leave an `(n+1)`-th overflow limb at
      `t[2n]` (result is in `[0, 2p)` and `2p` needs `64·n + 1` bits), which the
      copy-out silently dropped. Now `carry_hi = t[2n]` feeds the final
      conditional subtraction: subtract `p` iff `carry_hi != 0 || out >= p`.
      (c) Removed the `field::const_audit` scratch test module — its in-file
      `mul_mod_ref` / `R = 2^256 mod L` reference was itself buggy and raised
      false "ONE_MONT mismatch" failures against constants that are in fact
      correct (verified: `Ed25519ScalarParams::ONE_MONT == 2^256 mod L`).
- [x] `specs/field_mul.telos` (`result == a*b mod P ∀ a,b<P`),
      `specs/field_reduce.telos`
- [x] BUG: `Fp2/Fp6/Fp12::sqrt` (`extension.rs`) infinite-loops —
      **FIXED:** each tower now hardcodes a genuine non-residue (`1+u` for Fp2,
      `v` for Fp6, `w` for Fp12) and calls `tonelli_shanks_field` directly;
      `find_nonresidue_field` is dead code. The `-curve` h2c carries its own
      dedicated Fp2 sqrt (eprint 2012/685 Alg 9) regardless.
      **ROOT-CAUSE FIXED (2026-10-01):** the tower sqrt returned `None` for
      every non-trivial QR — `Big::shr_bits` shifted bits in from the *lower*
      limb (wrong direction) so `tower_info`'s `T`/`(T+1)/2` exponents were
      garbage; additionally `tonelli_shanks_field` applied its first update
      even in the converged `b == 1` entry state (moving off the root) and
      underflowed `i - found - 1` for non-residues. All tower sqrt paths
      (`Fp2`/`Fp6`/`Fp12`) now verified by the field proptests + BLS G2
      point decompression KATs.

### crates/tpt-crypto-curve
- [x] Scaffold `crates/tpt-crypto-curve/` — `Cargo.toml` (deps: `-field`, `-ct`,
      `-hash`, `-core`), `lib.rs` (`#![no_std]`, `#![forbid(unsafe_code)]`),
      modules `edwards25519`, `montgomery25519`; `tests/kat.rs` with RFC 8032 §7.1
      test 1 and RFC 7748 X25519 vectors
- [x] Ed25519 (RFC 8032): Edwards25519, ct scalar mul (fixed-window + `ct_lookup`),
      point compress/decompress, cofactored verify
      — `src/edwards25519.rs`: extended-coord add/double, w=4 fixed-window
      scalar mul, compress/decompress, `CtEq`, sign/verify. RFC 8032 §7.1 test 1
      (pubkey + full signature + verify + tamper-reject) and compress round-trip
      all PASS (`tests/kat.rs`). Broken scratch `tests/xref.rs` (buggy in-file
      reference impl + wrong `[9u8;32]` base-point vectors) removed.
- [x] X25519 (RFC 7748) Montgomery ladder
       — `src/montgomery25519.rs`: clamp + ladder + `cswap` + final invert.
       **FIXED:** the conditional-swap bookkeeping was wrong — it initialised the
       running parity to `true` and fed `Choice::from(swap).not()` into `cswap`,
       an inversion trick that broke as soon as the post-step `swap = bit` reset
       desynced it from the real accumulated parity. Now the plain RFC 7748 §5
       form: `swap: u8 = 0`, `swap ^= bit`, `cswap(Choice::from_u8_lsb(swap), …)`,
       `swap = bit`, and one final `cswap` after the loop. RFC 7748 §5.2 vectors 1
       & 2 and the §6.1 Alice-basepoint KAT all PASS (`tests/kat.rs`).
- [x] P-256 / P-384 (SEC1): short-Weierstrass complete addition formulas,
      ct scalar mul, point (de)compression, subgroup/on-curve checks
      — `src/weierstrass.rs`: generic `ProjectivePoint<C: WeierstrassParams>`
      over the `-field` base/scalar params, projective `(X:Y:Z)` coords with the
      complete Renes–Costello–Batina formulas (eprint 2015/1060 Alg. 4 add /
      Alg. 6 double, `a = -3`), exception-free for the cofactor-1 curves so one
      branch-free path covers identity / doubling / `P + (−P)`. Fixed-length
      double-and-add scalar mul with a `Field::ct_select` per bit; `is_on_curve`,
      projective `CtEq`, SEC1 compressed/uncompressed encode + `from_sec1`
      (parsing branches on the public tag — not CT). `P256Point` / `P384Point`
      aliases. KATs (`tests/weierstrass.rs`): generator on-curve + `n·G = O`,
      RFC 5903 §8.1/§8.2 ECDH vectors (public key + shared secret) for both
      curves, scalar homomorphism, encode round-trips — all green. Subgroup
      check is trivial (cofactor 1); `is_on_curve` + non-identity suffices.
- [x] BLS12-381: G1/G2 (subgroup checks via endomorphism), Miller loop,
      final exponentiation → GT; `pairing` / `multi_pairing`
      — `src/bls12_381.rs` (gated on `alloc`). `E/Fp: y²=x³+4` (`G1`) and the
      sextic D-twist `E'/Fp²: y²=x³+4(u+1)` (`G2`) in projective coords with the
      RCB a=0 complete/unified addition (Alg 1), fixed-length ct double-and-add.
      Optimal-ate `pairing`: Miller loop done entirely in `Fp12` on the untwisted
      `G2` point `ψ(Q) = (x'·w⁻², y'·w⁻³)` (denominator elimination for the
      degree-6 twist → numerator lines only), seed `x = -0xd201000000010000`
      (conjugate at the end). Final exp is one `f^((p¹²-1)/r)` — the exponent is
      computed by the new `tpt_crypto_field::bls12381_final_exp_exponent()` (added
      `Big::divmod` to `-field/src/big.rs`). Also rewrote the `Fp2`/`Fp6`/`Fp12`
      `invert` in `-field/src/extension.rs` from the slow Fermat path to the
      tower norm formulas (+ `Fp2::mul_by_nonresidue`/`conjugate`,
      `Fp12::conjugate`). Subgroup checks are the definitional `[r]P == O`
      (endomorphism speedup left as a follow-up). Tests
      (`tests/bls12_381.rs`, 7 pass): generators on-curve + torsion-free,
      `[r]G == O`, non-degeneracy, `e(G1,G2)^r == 1`, bilinearity across both
      arguments (`e([3]P,[5]Q) == e([15]P,Q) == e(P,[15]Q)`), additivity,
      `multi_pairing` vs product, `e(P,Q)·e(-P,Q) == 1`. Not constant-time in the
      final-exp exponent (public); no CFRG draft KAT vectors yet.
- [x] hash-to-curve (RFC 9380) for Ed25519, P-256, P-384, BLS12-381 G1/G2
      — `src/hash_to_curve.rs`: `expand_message_xmd` (SHA-256/384/512 + the
      `H2C-OVERSIZE-DST-` rule), `hash_to_field` (fixed-trace Horner OS2IP mod p),
      a generic branch-free Simplified SWU (`(-b/a)(1+tv1)` form, any `a ≠ 0`,
      over `Fp` or `Fp²` — takes `sgn0` + `sqrt` fn-ptrs), the branch-free
      Elligator 2 map for curve25519 + the `sqrt(-486664)` birational map to
      edwards25519, the 11-isogeny (G1) and 3-isogeny over Fp2 (G2), a dedicated
      Fp2 `sqrt` (eprint 2012/685 Alg 9; the field crate's tower `sqrt` hangs —
      `find_nonresidue_field::<Fp2>` only tries base-field candidates, all of
      which are QRs in Fp2), plus `G1`/`G2::from_affine_unchecked`,
      `G1::clear_cofactor` (`[0xd201000000010001]`) and `G2::clear_cofactor`
      (ψ / ψ² Budroni–Pintore, `g2_psi`/`g2_psi2` new in `bls12_381.rs`).
      Suites: `P256_XMD:SHA-256_SSWU_RO_`, `P384_XMD:SHA-384_SSWU_RO_`,
      `edwards25519_XMD:SHA-512_ELL2_RO_`, `BLS12381G1_XMD:SHA-256_SSWU_RO_`,
      `BLS12381G2_XMD:SHA-256_SSWU_RO_` (last two `alloc`).
      `tests/hash_to_curve.rs` (8 pass) checks the CFRG reference vectors:
      `expand_message_xmd` (SHA-256 short + oversize DST, SHA-512) and every
      suite's `P` for `msg ∈ {"", "abc", "abcdef0123456789"}`; G1/G2 also
      on-curve + torsion-free.
      NOTE: the field crate's `Fp2/Fp6/Fp12::sqrt` infinite-loops — separate bug,
      not on the h2c path any more.
- [~] KATs: RFC 8032 (Ed25519), RFC 7748 (X25519), NIST CAVP ECDH (P-256/384),
      draft-irtf-cfrg BLS12-381 vectors, RFC 9380 h2c vectors
      — Ed25519/X25519 done (`tests/kat.rs`); P-256/P-384 ECDH via RFC 5903
      (`tests/weierstrass.rs`) in lieu of the CAVP `.rsp` set; RFC 9380 h2c
      RO vectors for all five suites (P-256, P-384, edwards25519, BLS12-381
      G1 + G2) plus `expand_message_xmd` (SHA-256/512) in
      `tests/hash_to_curve.rs` (provenance in `tests/kat/PROVENANCE.md`).
      draft-irtf-cfrg BLS12-381 *pairing/signature* vectors still pending.
- [~] proptest: `k·(l·P) == (k·l)·P`, `pairing` bilinearity, compress round-trip
      — Weierstrass: `(a+b)·G == a·G + b·G` + SEC1 compress/uncompress round-trip
      covered in `tests/weierstrass.rs`. Pairing bilinearity pending (no BLS).
- [x] `specs/scalarmul_ct.telos` (timing ⟂ scalar)
      — covers the P-256/P-384 fixed-length double-and-add (`ct_select` per bit,
      complete RCB formulas); functional side discharged by the RFC 5903 KATs.

### crates/tpt-crypto-aead
- [x] Scaffold `crates/tpt-crypto-aead/` — `Cargo.toml` (deps `-core`, `-ct`;
      `alloc`/`std`/`aead-trait` features), `lib.rs` (`#![no_std]`,
      `#![forbid(unsafe_code)]`), modules `aes`/`api`/`chacha`/`ctr_drbg`/
      `gcm`/`gcm_siv`/`aead_compat`.
- [~] AES-128/192/256: portable bitsliced (constant-time) + `aes` `target-feature`
      AES-NI path routed through `tpt-crypto-ct::arch`
      — `src/aes.rs`: table-free ct S-box via algebraic GF(2⁸) inversion (not
      bitsliced), key schedule, `encrypt_block`; `x86_64` dispatch to AES-NI
      through `tpt-crypto-ct::arch`. Inline KATs (FIPS-197). Decrypt path / equiv
      inverse not needed (CTR-only use). Perf: no bitsliced parallel path.
- [~] GHASH (carryless mul: portable Shoup-table-free + `pclmulqdq` path); GCM
      — `src/gcm.rs`: branch-free portable GF(2¹²⁸) multiply (GHASH bit order
      fixed — multiplier consumed MSB-first), GHASH, `Aes128Gcm`/`Aes256Gcm`;
      CTR-then-GHASH ordering per SP 800-38D, ct tag verify before plaintext
      release. `pclmulqdq` path routed via `tpt-crypto-ct`. NIST GCM Appendix B
      TC1/TC2 inline KATs pass (verified against OpenSSL).
- [x] ChaCha20 + Poly1305 (RFC 8439); XChaCha20-Poly1305 (draft-irtf-cfrg)
      — `src/chacha.rs`: ChaCha20 block/stream, Poly1305, `ChaCha20Poly1305`,
      `XChaCha20Poly1305` (HChaCha20). **FIXED:** the Poly1305 core used a
      non-standard, incorrect 26-bit limb layout (only the low 2 bits of several
      message bytes were absorbed, so ciphertext tampering in the dropped bits
      went undetected) and `update` treated every call's trailing partial block
      as a terminal short block — broken for the multi-slice AEAD MAC. Replaced
      with the standard poly1305-donna 5×26-bit arithmetic + cross-call
      buffering; the AEAD length block now uses byte counts (RFC 8439), not
      bit counts. `poly1305_rfc8439` now checks the real §2.5.2 vector (plus a
      7-byte-chunked feed). RFC 8439 §2.3.2/§2.4.2 KATs still pass.
- [x] AES-GCM-SIV (RFC 8452) — nonce-misuse resistant; POLYVAL
      — `src/gcm_siv.rs`: POLYVAL (left-shift multiply, correct
      `x¹²⁸+x¹²⁷+x¹²⁶+x¹²¹+1` reduction constant, branch-free), key-derivation,
      `Aes128GcmSiv`/`Aes256GcmSiv`. **FIXED:** `decrypt` recomputed POLYVAL over
      the *ciphertext* — GCM-SIV authenticates the plaintext, so it now decrypts
      first (CTR keyed by the provided tag), then hashes the recovered plaintext,
      then compares (restoring the buffer on a tag mismatch).
      **FIXED (2026-10-03, conformance):** the POLYVAL hash key was
      `E(K_mac, 0^16)` (the GCM GHASH convention); RFC 8452 §4 uses the raw
      derived message-authentication key with no AES call, so every non-empty
      message was non-standard (self-consistent — invisible to round-trip
      props; the old inline KAT only covered the empty-plaintext vector where
      `S = dot(0, H) = 0`). Full RFC 8452 Appendix C corpus landed:
      `tests/kat/rfc8452.txt` (50 vectors: C.1 AES-128, C.2 AES-256, C.3
      counter wrap) + `tests/rfc8452.rs` (encrypt byte-equality + decrypt
      round trip per record) + PROVENANCE.
- [~] `CtrDrbg` (SP 800-90A) implementing `DrbgCore`
      — `src/ctr_drbg.rs`: AES-256 CTR-DRBG (no DF), `update` (key rebuilt into
      fresh `Zeroizing` buffer), instantiate/reseed/generate, inline tests.
      Wired to `DrbgCore`; behavioural tests only. SP-literal reading
      verified against the extracted SP 800-90A §10.2.1 text (XOR combine in
      Instantiate/Reseed, inc-first counter) — **fixed 2026-10-03: the
      counter now increments before encrypting** (§10.2.1.5.1). The NIST
      demo-server sample answers (AWS-LC acvptool test bz2) still could not
      be reproduced under any instantiate/reseed/flow/counter-width
      combination (~6k variants, two independent implementations); left for
      a future pass with the NIST ACVP reference server.
- [x] API: `Aead` trait (`encrypt`/`decrypt` in-place + detached tag), AAD,
      ct tag comparison (`ct_eq`), `Nonce`/`Tag` newtypes
      — `src/api.rs`: const-generic `Aead<NONCE_LEN, TAG_LEN>`, detached +
      alloc-gated combined ops, `Nonce`/`Tag` newtypes, `Tag::ct_eq` via
      `tpt-crypto-ct::ct_eq_bytes`, no `PartialEq` on `Tag`.
- [~] Optional `aead` trait-compat impls behind `aead` feature
      — `src/aead_compat.rs` behind the `aead-trait` feature (`aead` 0.6);
      `cargo test -p tpt-crypto-aead --all-features` builds and passes.
- [~] KATs: NIST GCM/CAVP, RFC 8439, RFC 8452, Wycheproof (AES-GCM, ChaCha20Poly1305)
      — inline per-module vectors (FIPS-197 AES, RFC 8439 ChaCha/Poly1305,
      NIST GCM Appendix B TC1/TC2) + `tests/kat/rfc8452.txt` (full RFC 8452
      Appendix C, 50 records) with PROVENANCE and `tests/props.rs` round-trip/
      bitflip props. Still missing: NIST CAVP GCM `.rsp` / Wycheproof AEAD
      JSON corpora.
- [x] proptest: `decrypt(encrypt(m)) == m`; any ciphertext/tag/AAD bitflip → error
      — `tests/props.rs` (rand-based): round-trip + single-bit-flip rejection for
      AES-128/256-GCM, ChaCha20/XChaCha20-Poly1305, AES-128/256-GCM-SIV. All
      12 pass.
- [x] `specs/aead_tag_verify.telos` (accept iff tag valid; timing ⟂ tag)

- [~] **Milestone**: dry-run clean for `-field`,`-curve`,`-aead`;
      `examples/ring_subset.rs` (ECDSA + AES-GCM + SHA-256 end to end)
      — examples **done**: `examples/src/lib.rs::ring_subset_snippet` doctest +
      `ring_subset_facade_round_trip` test (SHA-256 → ECDSA P-256 → AES-GCM,
      all through the facade, compiled+tested in `cargo test -p
      tpt-crypto-examples`). The publish `--dry-run` half remains blocked on
      the first crates.io publish of `core` → `ct` → `hash` (path deps do not
      resolve against the registry index; publish is explicitly deferred to a
      later one-step pass, per the header note).

---

## Phase 3 — Post-Quantum Core  (headline)

### crates/tpt-crypto-kem
- [x] `poly` module: `R_q = Z_q[X]/(X^n+1)` (Kyber q=3329, n=256), compile-time
      unrolled NTT / inv-NTT / base-mul, Montgomery reduction, `add`/`sub`
      — `src/poly.rs`; lib unit tests + `tests/props.rs` NTT round-trip green.
- [x] Samplers: CBD (centered binomial), ct rejection sampling for uniform,
      SHAKE-based XOF (`parse`), all timing ⟂ secret polynomial
      — `src/sampler.rs`.
- [x] `compress`/`decompress`, `encode`/`decode` (bit-packing), ct
      — `src/encode.rs`.
- [~] K-PKE (IND-CPA) keygen/encrypt/decrypt; ML-KEM (FIPS 203) FO transform →
      ML-KEM-512 / 768 / 1024; implicit-rejection decapsulation (ct)
      — `src/pke.rs` + `src/ml_kem.rs` (alloc-gated). **The round trip was
      silently broken** — `tests/props.rs` discarded its `prop_assert` results
      (`let _ = round_trip(...)`), so a real `decapsulate ∘ encapsulate` never
      recovered the shared secret. Fixes: (a) `kpke_decrypt` used the *public*
      `t̂` instead of the secret `ŝ` (and re-NTT'd it) — now `decapsulate`
      re-derives `ŝ` from the stored seed via `pke::derive_s_hat` and `kpke_decrypt`
      takes `ŝ`; (b) `kpke_encrypt`'s `û = Âᵀr` loop reused `r̂_i` for every
      column instead of `r̂_j` — no matrix-vector product at all; (c) keygen
      applied `poly_tomont` per-iteration to the wrong row index while the inner
      loop kept accumulating un-lifted terms; (d) keygen sampled `e` with η₂
      instead of η₁. FIPS-conformance pass on top: `G = SHA3-512(d ‖ ⟨k⟩)`,
      `H = SHA3-256`, `J = SHAKE256` (were all SHAKE256; `d ‖ k` byte was
      missing), matrix entries taken straight from `SampleNTT` in the correct
      `XOF(ρ, j, i)` index order (no double forward-NTT). `tests/props.rs`
      round-trips now really assert and pass for 512/768/1024; doctest un-ignored.
- [x] Spec API: `ml_kem::keygen::<MlKem768>(rng)`, `encapsulate`, `decapsulate`
- [~] FrodoKEM and Classic McEliece (long-term secrets).
      - [x] FrodoKEM-640-SHAKE: `tpt-crypto-kem::frodo`, a port of the Microsoft reference C.
            Byte-exact against the first three official `PQCkemKAT_19888_shake.rsp` records
            (keygen, encaps, decaps, ss); tamper and length checks in `tests/frodo_kat.rs`.
            Fuzz target `frodokem640_decaps`. Type-checked only, not run here.
      - [x] FrodoKEM-640-AES: `frodo::aes`, same code with an AES-128-ECB matrix generator.
            Byte-exact against the first three official `PQCkemKAT_19888.rsp` records.
            `frodo::shake` and `frodo::aes` share one implementation.
      - [x] FrodoKEM-976 and -1344 (SHAKE and AES): `frodo::{shake,aes}` generic over
            `FrodoParams` (`Frodo640`, `Frodo976`, `Frodo1344`). Byte-exact against the first
            official record of each reference file. The KEM hash is SHAKE256 for 976 and 1344.
            Fuzz targets: frodokem640, frodokem976 and frodokem1344 decapsulation (type-checked only).
      - [x] Classic McEliece mceliece348864: `tpt-crypto-kem::mceliece`, a port of the official
            Reference_Implementation (mceliece-20221023). Keypair, encapsulation and decapsulation
            match the first three official `kat_kem.rsp` records (pk and sk by SHA-256 digest, ct and
            ss in full) through the NIST DRBG. Fuzz target `mceliece348864_decaps`. Debug test run
            takes about 46 s. The file uses a few index loops that mirror the C, with clippy
            allowed for those lints.
      - [x] Classic McEliece 460896, 6688128, 6960119, 8192128: the same generic code
            (`McParams`), with the 13-bit field, the two-plane Benes network, and each set's
            outer reduction terms. Three per-set layout rules are flags: the 8192128 error
            draw, the 6960119 shifted public-key rows, and its padding checks (which reject a
            malformed pk on encapsulation, and set the key to all ones on a malformed
            ciphertext, as the reference does). All five sets match the first three official
            records. The four 13-bit KATs are `#[ignore]`d for debug builds; run them with
            `cargo test --release -p tpt-crypto-kem --test mceliece_kat -- --include-ignored`.
            No fuzz target for the new sets.
      The placeholder modules and `frodo`/`mceliece` features were removed
      (they only returned `Error::Unsupported`). Re-add when the implementations land.
- [x] KATs: FIPS 203 ACVP vectors + NIST `.rsp` KAT files (all param sets)
      — `tests/kat/fips203_{512,768,1024}.rsp` (1000 records each) validated by
      `tests/ml_kem_kat.rs` (keygen/encaps/decaps/implicit-reject, full byte
      equality). Two real implementation bugs surfaced and were fixed on the
      way: (a) `encode_pk`/`decode_pk` used `ρ ‖ t̂` byte order instead of
      FIPS 203's `ByteEncode₁₂(t̂) ‖ ρ`, and (b) the `t̂`/`ŝ` packing applied
      ciphertext-style compression (`ByteEncode_d ∘ Compress_d`) instead of
      plain `ByteEncode₁₂`; the sk layout is now the standard
      `dk_PKE ‖ ek ‖ H(ek) ‖ z` and decapsulation decodes `ŝ` from `dk_PKE`.
      Provenance cross-checked against `kyber-py`; see
      `tests/kat/PROVENANCE.md`.
- [x] proptest: `decapsulate(sk, encapsulate(pk).0) == encapsulate(pk).1`;
      malformed ciphertext → implicit-reject (no panic, no distinguishable time)
      — `tests/props.rs`: round-trip for 512/768/1024 (now with live assertions)
      + implicit-reject on tampered ciphertext, all green.
- [x] `specs/ml_kem_decapsulate.telos` (`ensures: timing ⟂ sk`),
      `specs/ntt_roundtrip.telos`

### crates/tpt-crypto-sig
- [x] Reuse `-kem::poly` for ML-DSA ring (q=8380417, n=256); power2round,
      decompose, `makeHint`/`useHint`, ct
      — own `src/poly.rs` (does **not** reuse `-kem::poly`); power2round /
      decompose / hint helpers. `poly::tests::all_poly_tests` passes.
      **FIXED:** `polyt0_unpack` coefficient `8i+7` read bytes `chunk[10/11/12]`
      instead of `chunk[11/12]` and OR'd in a `<< 13` term that `& 0x1FFF`
      masks away entirely — so ~12.5% of `t₀` coefficients round-tripped wrong,
      which is why `2^d·t1 + t0 ≠ A·s1 + s2` and every verify failed.
      `hint_round_trip` now stress-tests `UseHint(MakeHint(z,r), r)` over 20k
      random `(r, z ∈ [−γ₂, γ₂])` pairs.
- [x] ML-DSA (FIPS 204) keygen/sign/verify → ML-DSA-44 / 65 / 87; hedged +
      deterministic; rejection-sampling loop with ct primitives; `ctx` domain sep
      — `src/ml_dsa/mod.rs` + `src/ml_dsa/sample.rs`. All 6 `ml_dsa::tests`
      round-trips PASS. Fixes beyond the `polyt0_unpack` one: (a) the signer never
      loaded `t₀` and computed the hint as `MakeHint(−c, LowBits(w−c·s₂))` — now
      the FIPS 204 Alg 7 line 33 form `MakeHint(−c·t₀, w − c·s₂ + c·t₀)` with the
      `‖c·t₀‖∞ < γ₂` and `popcount ≤ ω` rejections; (b) keygen now canonicalises
      `t` before `Power2Round`; (c) `HintBitUnpack` now validates (monotone
      counts ≤ ω, strictly-increasing indices, zero tail) and `verify` returns
      `InvalidEncoding` instead of panicking on a mutated signature;
      (d) `μ` now includes the `|Ctx|` length byte (FIPS 204 §5.2).
- [x] SLH-DSA (FIPS 205): WOTS+, XMSS, FORS, hypertree; SHA2 + SHAKE param sets;
      `slh-dsa` feature (alloc-gated)
      — `src/slh_dsa.rs`: all 12 parameter sets (FIPS 205 Table 2), the
      tweakable hashes (SHAKE-256 streams; SHA-2 with the `ADRS_C` compressed
      address, MGF1 masking for `H_msg`, HMAC for `PRF_msg`), WOTS+ chains
      with checksum, XMSS trees + auth paths, FORS, and the `d`-layer
      hypertree; deterministic (default) + hedged signing; `M' = dom ‖
      |ctx| ‖ ctx ‖ M` context formatting. Validated against NIST ACVP
      keyGen/sigGen/sigVer vectors (96 records, all 12 sets) — see
      `tests/kat/slh_dsa_acvp.txt` + `PROVENANCE.md`. **Bugs the vectors
      exposed and fixed:** the ADRS keypair field was lost on type changes
      (WOTS chains after leaf 0 and all FORS nodes hashed with keypair = 0 —
      invisible to round-trips, fatal to cross-implementation verify), the
      hypertree offset used `1 + fors_len` bytes instead of `n + fors_len`,
      and the 256f tree-index mask overflowed `1u64 << 64`.
- [x] Ed25519 sign/verify (on `-curve`), batch verify
      — `src/ed25519.rs`: `SigningKey` (seed in `SecretBox`) / `VerifyingKey` /
      `Signature` newtypes over `-curve`'s RFC 8032 core, with strict §5.1.7
      non-canonical-`S` rejection added at the wrapper. `verify_batch` is the
      random 128-bit linear-combination check
      (`[8]([-Σ zᵢSᵢ]B + Σ zᵢRᵢ + Σ (zᵢkᵢ)Aᵢ) == O`); empty batch vacuous.
      Needed new deps `-curve` + `-field` on `-sig`, and a public
      `edwards25519::scalar` helper module in `-curve` (`reduce_wide_le`,
      `from_le32`, `to_le32`, `is_canonical_le32`, `ORDER_LE`).
      `tests/ed25519.rs`: RFC 8032 §7.1 test-1 KAT (pubkey + signature bytes +
      verify), tamper / wrong-msg / wrong-key rejection, non-canonical-`S`
      rejection, batch verify (all-valid + catches one corrupted entry). All
      4 pass. Ristretto / pre-hash / context variants not implemented.
- [x] ECDSA P-256 / P-384: RFC 6979 deterministic nonce + ct scalar ops;
      low-s normalization; ASN.1 DER + fixed encodings
      — `src/ecdsa.rs`: generic `EcdsaCurve` (P-256/SHA-256, P-384/SHA-384),
      `SigningKey` (d in `SecretBox`) / `VerifyingKey` / `Signature<C>`.
      RFC 6979 §3.2 HMAC-DRBG nonce iterator; `k⁻¹` + `e + r·d` via the ct
      `-field` scalar field; `[k]G` via `-curve` ct double-and-add. Low-`S`
      normalisation on sign + high-`S` rejection on verify. Strict DER
      `SEQUENCE{INTEGER r, INTEGER s}` (minimal, no trailing bytes) and fixed
      `r‖s` encodings; SEC1 pubkey parse/serialise. `tests/ecdsa.rs` (7 pass):
      RFC 6979 App. A.2.5 (P-256, "sample"/"test") + A.2.6 (P-384, "sample")
      deterministic-`r` KATs, pubkey KAT, determinism, round-trip/tamper,
      low-`S`, DER+fixed round-trips + malformed rejection. Discharges
      `specs/ecdsa_nonce_ct.telos` structurally + by KAT.
- [x] BLS12-381 (spec API): `sign`, `verify`, `aggregate`,
      `verify_aggregate` (same-message + distinct-message), proof-of-possession;
      ciphersuites `BLS_SIG_..._{NUL,AUG,POP}_`
      — `src/bls.rs` (alloc-gated) over `-curve`'s G1/G2/pairing + RFC 9380
      hash-to-curve. draft-irtf-cfrg-bls-signature-04 minimal-pubkey-size:
      keys in compressed G1 (48 B), signatures in compressed G2 (96 B); the
      zcash flag format (`0x80` compressed / `0x40` infinity / `0x20` y-sort)
      with on-curve + subgroup validation lives in
      `-curve::bls12_381::{G1,G2}::{to,from}_compressed` (needed a working
      tower `Fp2::sqrt` — see the `-field` note). Verification is one
      `multi_pairing` per check; aggregate semantics per suite (Basic/Pop
      distinct-messages enforced, Aug hashes `pk‖msg`, same-message
      fast-aggregate). Default suite is POP (Ethereum-compatible).
      **Fixed en route:** the pairing-check orientation (BLS verifies
      `e(pk, H(m)) == e(P1, σ)`) and the `aggregate_verify` term signs.
- [x] Spec API: `ml_dsa::keygen::<MlDsa65>`, `sign(sk, msg, ctx)`, `verify(...)`
      — working for all three parameter sets.
- [~] Optional `signature` trait-compat impls behind `signature` feature
      — `src/signature_impls.rs` is a stub.
- [~] KATs: FIPS 204 & 205 ACVP, RFC 8032 (Ed25519), RFC 6979 + NIST CAVP (ECDSA),
      Wycheproof (ECDSA/EdDSA), draft-irtf-cfrg-bls-signature vectors
      — RFC 8032 §7.1 test-1 in `tests/ed25519.rs`; RFC 6979 A.2.5/A.2.6
      deterministic ECDSA KATs in `tests/ecdsa.rs`. BLS **done**:
      `tests/bls_kat.rs` runs the Ethereum `bls12-381-tests` v0.1.2 corpus
      (CC0-1.0, POP ciphersuite) — all green. ML-DSA ACVP **done**:
      `tests/ml_dsa_kat.rs` + `tests/kat/ml_dsa_acvp.txt` (distilled NIST
      ACVP-Server keyGen/sigVer sets; 30 kg + 45 sv records, all three
      parameter sets; provenance cross-checked against `dilithium-py`).
      **Three conformance bugs the ACVP vectors exposed and fixed:**
      (a) `keygen_from_seed` used `SHAKE256(ξ‖1)/SHAKE256(ξ‖2)` instead of
      `H(ξ ‖ ⟨k⟩ ‖ ⟨ℓ⟩)`; (b) `expand_a` NTT'd the already-NTT-domain
      `ExpandA` output (with the matching `mat_vec_mul` Montgomery bookkeeping
      fix); (c) the parameter table's `ω` was 120/196 for ML-DSA-65/87 instead
      of 55/75 — pack/unpack agreed with each other, so round-trips passed
      while every real signature verify failed.
      Wycheproof **done**: `tests/wycheproof.rs` +
      `tests/kat/wycheproof.txt` (all 1139 testvectors_v1 verify records:
      ECDSA P-256/SHA-256 ×484, P-384/SHA-384 ×504, Ed25519 ×151; accept iff
      `valid` and low-s). **Exposed + fixed:** Ed25519 `verify` accepted
      signatures whose `R` decodes to the identity point (tcId 151); the
      wrapper and `verify_batch` now reject identity-`R`. The ACVP sigVer
      harness also asserted nothing until now (`run_sv` printed but never
      checked) — it asserts `got == want` since 2026-10-03. NIST CAVP `.rsp`
      sets not added (Wycheproof + RFC 6979 + RFC 8032 cover the surface).
- [~] proptest: `verify(pk, m, sign(sk, m))` ok; wrong key/msg/ctx → `Verification`;
      `verify_aggregate` iff all inputs valid
      — `tests/ml_dsa_props.rs` now real (rand-based, all 3 param sets): honest
      round-trip, wrong msg/ctx/key → `Verification`, hedged verifies, and every
      single-bit signature mutation is rejected. BLS: `tests/bls_props.rs`
      covers honest sign→verify, aggregate-iff-all-valid (with one tampered
      contribution), same-message aggregation + wrong-message rejection,
      keygen determinism + PoP, and the Aug duplicate-message allowance.
- [~] `specs/bls_aggregate.telos` (`valid iff all input sigs valid`),
      `specs/ecdsa_nonce_ct.telos`
      — both contract files authored. `ecdsa_nonce_ct` is discharged
      (RFC 6979 impl + KATs in `-sig`); `bls_aggregate` is discharged
      functionally by `tests/bls_props.rs` (aggregate-iff-all-valid, incl.
      tampered-contribution rejection) on top of the official vectors.

- [~] **Milestone**: dry-run clean for `-kem`,`-sig`;
      `examples/ml_kem.rs` + `examples/ml_dsa.rs` reproduce `spec.txt` §4
      — examples **done**: `ml_kem_snippet` + `ml_dsa_snippet` doctests and
      facade round-trip tests in `examples/src/lib.rs` (plus the new
      `bls_aggregate_snippet`). `--dry-run` half blocked on first publish of
      the foundation crates (same as the Phase 2 milestone).

---

## Phase 4 — Advanced Primitives + Facade

### crates/tpt-crypto-zk  (`no_std` + `alloc`)
> Crate scaffolded and committed (`4e6c0d9`) with the placeholder `lib.rs`; the
> module set below is being wired up now. **RESOLVED (2026-08-30): the lib now
> compiles** (was ~30 errors). Fixes: `-hash` `Xof` is re-exported at crate
> root (import `tpt_crypto_hash::{sha3::Shake256, Xof}`); `-field` gained a
> `Neg` impl for `FieldElement`; `-curve` `EdwardsPoint::ct_eq` already existed
> (just needed the `CtEq` trait in scope in `-zk`); `-zk` `transcript.rs`/
> `group.rs`/`bulletproofs.rs` updated to the new `Shake256`/`Xof` API
> (`t.state` → `t`, `bytes_to_scalar` → `bytes_to_scalar_checked` taking
> `&[u8]`); `bulletproofs::prove_range` return tuple order fixed; `plonk.rs`
> later replaced by the full GWC19 PLONK verifier (see below). The
> `Pedersen`/`Transcript`/`IPA`/`Bulletproofs` tests now run green (`tests/kat.rs`,
> `tests/range_proof.rs`, `tests/plonk.rs`, `tests/ipa_standalone.rs`).
- [~] Fiat-Shamir `Transcript` (Merlin-style STROBE-lite on SHAKE256):
      `append_message`, `challenge_scalar` — `src/transcript.rs`.
- [~] Pedersen commitments over BLS12-381 G1 / Ed25519 (`commit(value, blinding)`)
      — `src/pedersen.rs` + `src/generators.rs` + `src/group.rs` (Ed25519 only).
- [~] Inner-product argument; Bulletproofs range proofs — single + aggregated,
      ranges up to `2^64` (`prove_range`, `verify_range` per spec API)
      — `src/ipa.rs` + `src/bulletproofs.rs` (`prove_range`/`verify_range`,
      `range_proof_{to,from}_bytes`); `verify_range` is exercised and green.
      **RESOLVED (2026-11-10):** the standalone verifier round-trips honest proofs
      (`tests/ipa_standalone.rs`, sizes 2–32, 3 seeds) and rejects a wrong commitment.
      The analysis below is the historical record.
      **DEFECT FOUND (2026-10-01): `InnerProductProof::verify` (the standalone
      helper in `src/ipa.rs`) rejects honest proofs produced by
      `InnerProductProof::create` — its verification equation is inconsistent
      with the prover.** It is *not* on the range-proof path (`verify_range`
      builds its own multiscalar check from `verification_scalars`, which is
      correct and passes, and is covered end-to-end by `tests/kat.rs` and
      `tests/range_proof.rs`), so the shipped primitive is unaffected — but the
      helper is unusable as written and must be fixed or deleted before anyone
      relies on it.

      *Analysis so far.* The fold is `a' = u·a_L + u⁻¹·a_R` with
      `G' = u⁻¹·G_L + u·G_R`, so the correct relation is
      `P = a'b'Q + Σ(a'·s_i)G_i + Σ(b'·s'_i)H_i − Σu²L − Σu⁻²R`. Two concrete
      faults were identified in `verify`: (1) it appends the `−u²` scalars for
      `L` but never the matching `−u⁻²` scalars for `R`, leaving the final MSM
      misaligned; (2) the `b`-side weight is `s.rev()` rather than the
      inverse-in-reverse-order `1/s[n−1−i]`. Applying both still fails, so a
      third fault remains — most likely in the construction of the `s` vector
      itself (`verification_scalars`, the `s[i] = s[i−k]·u²` recurrence) or in
      how the generator factors are folded into the first round.

      **Deliberately not patched blind.** Two candidate fixes were written,
      tested, and reverted rather than shipped. A parameter sweep over the
      plausible `s` / `1/s` weight conventions × `L`/`R` sign choices found no
      consistent equation (and also confirmed the failure is *not* specific to
      non-constant generator factors — it reproduces with all-ones factors,
      which isolates it to the folding algebra). A correct fix needs a fresh
      derivation of the IPA verifier against the textbook construction, not a
      local tweak. `src/ipa.rs` is therefore **unchanged from `f19794e`**.
- [x] Minimal PLONK verifier (~500 LoC): transcript, KZG **or** IPA commitment
      opening check, permutation + gate checks; accepts any compliant proof
      (no prover — that is `tpt-telos`'s job)
      — `src/plonk.rs`: GWC19 round structure over IPA/Pedersen vector
      commitments (`C = <p,G> + r·H₀`): witness/grand-product/quotient
      commitments, all-at-ζ evaluations, one scalar quotient-identity check at
      ζ (made possible by opening `[z]` at BOTH ζ and ωζ — no linearization
      polynomial, no `[r]`; Schwartz–Zippel soundness at ζ), and two batched
      IPA openings (ζ-batch over 15 polynomials + `[z]` at ωζ). Gate
      `q_l·a + q_r·b + q_o·c + q_m·ab + q_c = 0`; public inputs baked into
      `q_c` (fixed-input vk). Documented field limitation: the Ed25519 scalar
      field has 2-adicity 2, so power-of-two domains are capped at n = 4
      (larger circuits need a 2-adic field, e.g. BLS12-381 Fr — future work).
      Validated by a full reference prover in `tests/plonk_common` (driving
      `tests/plonk.rs`: honest-verify completeness, per-evaluation and
      per-commitment tampering rejection, wrong-public-input rejection,
      serialization round-trip + truncation) and a committed KAT fixture
      (`[plonk]` section of VECTORS.txt).
      **Fixed en route:** `InnerProductProof::verify` dropped the R points
      (it pushed only the −u² weights — needing −u_i^{-2} for R — and `msm`
      zips to the shorter slice, silently truncating); no test covered the
      standalone path (the range proof inlines its own mega-check), which is
      exactly the gap the PLONK work exposed.
- [x] KATs: bulletproofs reference test vectors (dalek-compatible),
      PLONK proof fixtures from a reference prover
      — bulletproofs/IPA/Pedersen/transcript vectors landed in
      `tests/kat/VECTORS.txt` + `tests/kat/PROVENANCE.md` (sha256 registered
      with `cargo xtask kat-check`), driven by `tests/kat.rs` (4 tests) and
      regenerable via `tests/generate_kat.rs`. **No cross-implementation
      vectors exist for this construction** (built directly on `-curve`/
      `-field`), so these are regression vectors, documented as such in
      PROVENANCE; soundness properties are covered by `tests/range_proof.rs`.
      PLONK fixtures still pending (blocked on the verifier, below).
- [x] proptest: honest `prove_range` always verifies; out-of-range value →
      prove fails; tampered proof → verify fails
      — `tests/range_proof.rs`: completeness (incl. after a serialization round
      trip), binding against a wrong commitment, out-of-range rejection,
      parameter validation, plus 2 `proptest!` cases (random values verify;
      single-bit proof flips are rejected). 6 tests, all pass.
- [~] `specs/bulletproofs_verify.telos` (`true iff proof valid for commitment`)
      — contract authored; discharged functionally by `tests/range_proof.rs`
      (accept iff valid, reject on any tamper) + the `[range]` KATs. PLONK's
      analogue is `tests/plonk.rs` + the `[plonk]` KAT fixture.

### crates/tpt-crypto-mpc  (`no_std` + `alloc`)
> Crate scaffolded and committed (`4e6c0d9`). Deps: `-core`, `-ct`, `-field`,
> `-curve`, `-hash` (so this crate sits on `field+curve+hash`, not just
> `field+hash`). **All `-mpc` tests now PASS** (`tests/kat.rs` 6/6,
> `tests/props.rs` 9/9) after the `-curve` Curve25519 fix plus two `-mpc` bugs:
> (a) `ot::receiver_init` had the `ct_select` operands reversed — `ct_select(cond,
> a, b)` returns `a` when `cond` is true, so `ct_select(choice, id, a_pt)` added
> `A` for choice 0 and the identity for choice 1, the wrong way round; now
> `ct_select(choice, a_pt, id)`. (b) `iknp::extend_1of2` indexed `delta[i]` for
> `i` up to `KAPPA = 128` into a 16-byte buffer (panic) and its correlation
> structure was wrong (`recv_u[i]` always recovered `U[i]`, so choice-1 opens
> never worked); rewritten as the textbook IKNP (receiver is the base-OT sender
> offering `T`-columns and `T`-columns⊕`r`, extension sender picks random `s`,
> correlated row masks `H(j,q_j)` / `H(j,q_j⊕s)`).
- [x] Additive secret sharing over `-field` (`share`, `reconstruct`,
      `add`/`scalar_mul` on shares)
      — `src/field_share.rs` (`share_secret`, `share_secret_2`, `reconstruct`,
      `Share::add` / `Share::scale`); `share_reconstruct_kat` + `tests/props.rs`
      `reconstruct(share(x)) == x` pass.
- [x] Beaver triple representation; offline gen (from OT) + online multiply
      — `src/beaver.rs` (`BeaverTriple::deal` / `deal_from_base_ot` /
      `deal_many_from_iknp`, `multiply`). `beaver_from_base_ot_kat` +
      `beaver_batch_from_iknp` + `beaver_multiply_from_base_ot` all PASS.
- [x] Base OT (Chou–Orlandi / simplest OT) on `-curve`; 1-of-2 and 1-of-N
      — `src/ot.rs` (`transfer_base_ot_1of2`, `transfer_1ofn`); `oneofn_kat` +
      `base_ot_kat` pass (`base_ot_kat`'s independent `reference_base_ot`
      cross-check rewritten to run the full encrypt-then-decrypt round trip).
- [x] IKNP OT extension
      — `src/iknp.rs` (`extend_1of2`, κ=128) rewritten to the textbook protocol;
      `iknp_kat` passes.
- [x] KATs: cross-impl vectors where available; otherwise documented reference runs
      — `tests/kat.rs` + `tests/kat/PROVENANCE.md`. All 6 KAT tests pass.
- [x] proptest: `reconstruct(share(x)) == x`; Beaver-multiplied shares
      reconstruct to `a*b`; OT receiver learns exactly one message
      — `tests/props.rs` (9 tests) all pass.
- [x] `specs/secret_share_reconstruct.telos`

### crates/tpt-crypto  (facade — umbrella variant)
1. [x] Scaffold with cargo features gating each re-export:
   `classical` (hash+aead+field+curve+sig-classical), `pq` (kem+sig-pq),
   `bls`, `zk`, `mpc`, `full`; `std`/`alloc` propagate
2. [x] Wire optional deps + matching feature flags per sub-crate
   — `core` + `ct` are now non-optional (the `prelude` / `ct` modules need
   them under every feature set); builds verified for `pq`, `pq,alloc`,
   `classical`, `zk`, `mpc`, `bls`, `--all-features`, and default.
3. [x] `prelude` module: `SecretBox`, `CryptoRng`, and the spec §4 surface
4. [x] Modules matching `spec.txt` §4 **verbatim**: `ml_kem` (gated on
   `pq` + `alloc`), `ml_dsa`, `bulletproofs`, `bls`, `ct` — top-level
   re-exports so §4 snippets compile unchanged.
5. [x] Rustdoc: feature matrix table + "`spec.txt` §4 surface" section in
   the crate-level docs.
6. [x] `fmt` / `clippy` / `deny` clean across feature combinations
   (facade + examples emit no warnings; remaining clippy noise is in the
   pre-existing `-zk` / `-mpc` crates).
7. [x] `examples/`: `examples/src/lib.rs` has compiled+tested doctests +
   unit tests for the §4 secret-handling, ML-KEM, ML-DSA, BLS-aggregate, and
   ring-subset snippets (via the facade; the examples crate enables
   `pq,classical,bls`). Bulletproofs snippet pending that impl.
8. [x] Update `tpt-rust-map/registry.toml` status
   — all `tpt-crypto-*` entries present with `status = "git"` (incl. the new
   `-sig` entry).

- [ ] **Milestone**: `cargo xtask release-dry-run` — all 11 crates
      `cargo publish --dry-run` clean in dependency order
      — blocked on the first real publish (leaf crates `core`/`ct` verified
      clean in Phase 1; every other crate fails only on registry resolution of
      the not-yet-published path deps, not on packaging/metadata).

---

## Cross-Cutting (thread through all phases)

- [x] `xtask`: subcommands `no-std` (owns crate/feature/target list),
      `kat-check` (verify `PROVENANCE.md` sha256s), `leakage` (dudect runner),
      `verify` (shell `tpt-telos-cli` over `specs/*.telos`, print report),
      `release-dry-run` (`cargo publish --dry-run` in topo order), `sbom`
- [~] `fuzz/` (`cargo-fuzz`): targets for every attacker-controlled decoder —
      signature parse, ciphertext parse, public-key parse, proof parse,
      ASN.1 DER, point decompression
      — 8 targets, all type-check clean under `cargo check --bins`
      (`cargo +nightly fuzz build` needs the ASan runtime, absent in this
      environment for *all* targets incl. the pre-existing ones):
      `aes_gcm_decrypt`, `chacha20poly1305_decrypt`, `ml_kem_decaps`,
      `point_decompress`, `signature_verify` (Ed25519), and added this pass —
      `ecdsa_der_parse` (P-256/P-384 `Signature::from_der`; strict-minimal
      INTEGER + trailing-garbage rejection), `ecdsa_public_key_parse`
      (`VerifyingKey::from_sec1`, compressed/uncompressed), and
      `range_proof_parse` (`range_proof_from_bytes` → `verify_range`, driving
      `EdwardsPoint::decompress` and scalar canonicality with untrusted input).
      Each new target asserts a round-trip/canonicality invariant, not just
      "does not panic". CI `fuzz-smoke` still to be confirmed on a toolchain
      with `librustc-nightly_rt.asan`.
- [x] `benches/BUDGET.md`: per-primitive perf target vs `ring` / `dalek` /
      `pqcrypto`; criterion targets build in `bench-smoke`
      — BUDGET.md covers all 11 crates; **all 21 existing criterion benches
      measured (2026-10-03, x86_64 Windows)** and recorded with honest
      status: ML-KEM-768 keygen/encaps and 32-bit bulletproofs proving meet
      their targets; hash/AEAD/ZK targets assumed SIMD-heavy implementations
      and are marked "below target (portable)" — the substrate is
      deliberately table-free, so those are follow-up-SIMD goals, not
      regressions. Several rows (ct/select SSE paths, sig/curve/mpc/plonk
      benches, montgomery-ladder) have no bench yet and stay `pending`.
- [x] `cargo-semver-checks` in CI (runs on tags)
- [x] SBOM artifact (`cargo xtask sbom`) uploaded by CI
      (new `sbom` job in `ci.yml`)
- [~] Trait-compat feature impls (`digest`, `aead`, `signature`,
      `elliptic-curve`) + a `rustls` `CryptoProvider` example
      — `digest` (-hash), `aead` (-aead) and `signature` (-sig: Ed25519,
      ECDSA, ML-DSA, BLS; facade pass-through feature) are done.
      **rustls `CryptoProvider` done (2026-10-03):**
      `examples/src/rustls_provider.rs` implements a complete TLS 1.3
      provider from substrate primitives only — AES-128-GCM and
      ChaCha20-Poly1305 record AEADs, HMAC-SHA-256 + the rustls
      `HkdfUsingHmac` key schedule, a SHA-256 `hash::Hash` provider,
      constant-time X25519 key exchange, and Ed25519 handshake signatures
      with a hand-built self-signed DER certificate. Two in-memory
      handshakes (one per suite) with bidirectional application data are
      covered by tests (`cargo test -p tpt-crypto-examples`); `rustls` is
      built with `default-features = false` (no ring / aws-lc-rs) and
      `cargo deny` stays clean.
      Remaining: `elliptic-curve` ecosystem trait compat. Assessment: a
      faithful `CurveArithmetic`/`PrimeField` adapter surface for
      P-256/P-384 means wrapper types implementing dozens of `ff`-style
      traits (~600+ lines, high API-drift risk) for ecosystem
      interoperability that the `signature` bridge already covers for the
      common case — deferred unless a concrete consumer appears.
- [x] `specs/`: keep the `spec.txt` §5 contract table in sync with real files;
      promote each `telos-verify` check from non-blocking → blocking as it lands
      — §5 table now lists all 14 contracts; `cargo xtask verify`: 14 verified,
      0 pending, 0 failed (all evidence-backed, no `pending:` entries left).
- [x] Final crates.io-prep audit: every crate has description/keywords/categories/
      README/CHANGELOG/`docs.rs` metadata; `cargo package` lists no stray files;
      **do not publish** this pass
      — audited 2026-10-03: fixed `-kem`/`-zk` 6→5 keywords and added the
      missing `[package.metadata.docs.rs]` block to `-ct`/`-curve`/`-field`/
      `-hash`/`-mpc`; package file lists are clean (sources + tests + KAT
      data + README/CHANGELOG only).
- [ ] Per-phase local commit; update this file's checkboxes as work lands

---

## CI — `.github/workflows/ci.yml`

`env: RUSTFLAGS: -D warnings`. Jobs:

- [x] `fmt` — `cargo fmt --check`
- [x] `clippy` — `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [x] `test` — `cargo nextest run --workspace --all-features` + `cargo test --workspace --all-features --doc`
- [x] `no_std` — matrix `thumbv6m-none-eabi` (no `alloc`) / `thumbv7em-none-eabihf` / `wasm32-unknown-unknown`, via `cargo xtask no-std`
- [x] `target-feature-matrix` — build+test `-aead`/`-hash` with and without `aes,sha,avx2,sse4.1` `-C target-feature`
- [x] `cargo-deny` — license + bans gate (**blocking**)
- [x] `miri` — `cargo +nightly miri test -p tpt-crypto-ct`
- [x] `leakage` — `cargo xtask leakage` (Welch t-test thresholds)
- [x] `feature-powerset` — `cargo hack test --feature-powerset -p tpt-crypto`
- [x] `telos-verify` — `cargo xtask verify` (non-blocking → blocking per primitive)
- [x] `bench-smoke` — `cargo bench --no-run`
- [x] `fuzz-smoke` — `cargo +nightly fuzz build`
- [x] `semver-checks` — on tags only

---

## Kernel-project follow-ups (added 2026-11-10)

Consumers and master plan: `../tpt-kernel/todo.md`. The TLS provider in
`../tpt-crypto-rustls` depends on these items.

- [x] RSA verification: PKCS#1 v1.5 and PSS, with SHA-256/384/512. This lets `tpt-crypto-rustls` drop the `rsa` crate.
      — `tpt-crypto-sig::rsa` (public-key only; Montgomery modexp over `u64` limbs,
      1024–16384-bit moduli). `PublicKey::verify_pkcs1v15` / `verify_pss(hash, salt_len, ..)`.
      KAT: `tests/rsa.rs` with RSA-2048 vectors generated by OpenSSL 1.1.1t (all
      three hashes, both paddings) plus wrong-hash/tamper/length/`s >= n` negatives.
      Not yet done: DER/SPKI key parsing (the `rustls` adapter can pass n and e in).
- [x] ECDSA: `verify_prehash` rejects high-S signatures as non-canonical. X.509 and TLS produce them, so either accept them or expose a verifier that does. The adapter in `tpt-crypto-rustls` currently normalises `s` to low-S.
      — added `VerifyingKey::verify_prehash_allow_high_s` (P-256/P-384 unit tests:
      strict rejects `(r, n-s)`, lenient accepts). The `tpt-crypto-rustls` adapter
      still normalises to low-S and should switch to the lenient verifier (cross-repo).
- [x] Overlap: `examples/src/rustls_provider.rs` is a TLS 1.3 provider (AES-128-GCM and ChaCha20-Poly1305, X25519, Ed25519, self-signed DER). `tpt-crypto-rustls` adds TLS 1.2, P-256/P-384, ECDSA and RSA verification, and webpki trust roots. Decide whether to keep both or move the example onto `tpt-crypto-rustls`.
      — decided: keep both. `tpt-crypto-rustls` is the production provider; the
      example stays a self-contained TLS 1.3 reference (header updated), so the
      workspace builds without the sibling repo. Revisit if `tpt-crypto-rustls`
      moves into this workspace.
- [ ] External audit before any production use. The README says this crate is not audited.

---

## Review pass & adoption (added 2026-11-10)

Source: project review (see plan `review-project-fix-any-abstract-valiant.md`).
Each item is its own commit so any can be dropped.

### A. Stubs, stale docs, hygiene
- [x] Remove stale "BLS stub / in progress" wording in `crates/tpt-crypto/src/lib.rs`
      (lines ~13, ~87) and `README.md` (BLS, pairing and h2c are done).
- [x] Fix stale `tr placeholder` comment in `crates/tpt-crypto-sig/src/ml_dsa/mod.rs:462`
      (`tr` is filled later in keygen).
- [x] Replace placeholder `crates/tpt-crypto-sig/benches/sig_bench.rs` with real criterion
      benches. Removed the placeholder; `benches/benches/sig.rs` now covers Ed25519, ECDSA,
      BLS and ML-DSA-44/65/87, with measured rows in `benches/BUDGET.md`.
      - [x] RSA verify bench — `rsa_bench` in `benches/benches/sig.rs` (2048-bit KAT
            vector from `tests/rsa.rs`); row in `benches/BUDGET.md` from a quick run only.
- [x] Remove FrodoKEM / Classic McEliece placeholder modules and features (they only returned
      `Unsupported`; `--all-features` enabled them). Implementations tracked separately:
      - [ ] FrodoKEM-640/976/1344 (SHAKE + sampler reuse).
      - [ ] Classic McEliece (deferred).
- [x] Delete stray `__pycache__/ctr_drbg_ref*.pyc`; add `__pycache__/` to `.gitignore`.
- [ ] Annotate every `[~]` item with its remaining gap; fix the stale zk header note
      ("untested") in the Phase 4 section.
      — zk note: no "untested" wording remains in the crate or this file (checked
      2026-11-11); the Phase 4 section already reads RESOLVED. Per-item `[~]`
      annotation still open.
- [x] Add missing KAT corpora to the list of open gaps: NIST CAVP GCM `.rsp`, Wycheproof AEAD JSON.
      — listed under "Known gaps" in `crates/tpt-crypto-aead/README.md`.
- [x] Replace "local git only this pass" status line in `README.md` with the true state.

### B. Ease-of-use & innovation
- [x] `os-rng` feature: `OsRng: CryptoRng` via `getrandom` 0.3 (std, opt-in; no new
      download — already in `Cargo.lock`). Re-exported from `tpt_crypto_core` and the
      facade prelude. `cargo deny check licenses bans` passes (getrandom is MIT/Apache).
- [x] Fix: `tpt-crypto-aead` failed to build with `--no-default-features` on x86_64
      (AES-NI helper is `std`-only in `-ct`, but the caller was gated on arch alone).
      Hardware path is now gated on `all(x86_64, std)`.
- [~] `tpt_crypto::easy` recipes module (feature `classical` + `os-rng`).
      - [x] `generate_key`, `seal` / `open` (XChaCha20-Poly1305, random 192-bit nonce
            prepended; single-bit-flip rejection test; doctest).
      - [x] `hash`, `hmac`, `hkdf_derive`, Ed25519 `sign` / `verify`, `random_bytes`.
- [x] `NonceSequence` counter-nonce type for protocols that need explicit nonces.
- [x] STREAM-style chunked AEAD for large payloads (age-style), with KATs. Whole-buffer API (`tpt_crypto_aead::stream_seal` / `stream_open`, ChaCha20-Poly1305); KAT is an independent Python `cryptography` vector. No incremental reader/writer yet.
- [~] Hybrid KEM: X25519 + ML-KEM-768 combiner (X-Wing-style), with KATs and fuzz target.
      - [x] `tpt-crypto-kem::xwing`: keygen from a 32-byte seed (SHAKE256 expansion), encaps/decaps,
            SHA3-256 combiner with the draft label. Expansion, X25519 component and combiner are
            checked against Python references. Fuzz targets `xwing_decapsulate` and `xwing_encapsulate_pk`.
      - [ ] Official test vectors: none published yet by the draft, so there is no independent
            end-to-end KAT. Wire format is unstable until the draft is final.
      - [x] Plain ML-KEM `encapsulate` / `encapsulate_msg` now run the FIPS 203 §7.2 check and return
            `Result` (breaking change, crate unreleased). Regression test: `tests/encaps_validation.rs`, all parameter sets.
- [~] Hybrid signature: Ed25519 + ML-DSA-65 composite, with KATs.
      - [x] `tpt-crypto-sig::hybrid`: both signatures required, over `LABEL ‖ len(ctx) ‖ ctx ‖ M`. Ed25519
            component checked against a Python `cryptography` reference. Fuzz target `hybrid_verify`.
      - [ ] This is a crate-specific encoding, not the IETF composite wire format
            (draft-ietf-lamps-pq-composite-sigs). Switch to it once that draft is final, or drop the item.
      - [ ] No independent end-to-end KAT for the ML-DSA half of the hybrid (ML-DSA itself has FIPS 204 KATs).
- [~] HPKE (RFC 9180) in `tpt-crypto-kem::hpke`: all four modes (base, PSK, auth,
      auth-PSK) over DHKEM(X25519, HKDF-SHA256) with ChaCha20-Poly1305 and AES-128-GCM.
      Matches the official vectors for `enc`, key, base nonce, exporter, per-sequence
      nonces and ciphertexts (`tests/kat/hpke_base_x25519.txt`,
      `tests/kat/hpke_modes_x25519.txt`). PSKs shorter than 32 bytes are rejected, per
      RFC 9180 §5.1. Open items:
      - [ ] Hybrid KEM (X25519 + ML-KEM-768) as an HPKE KEM, once the X-Wing draft
            publishes test vectors (its current vectors are a placeholder).
      - [ ] Benchmark row in `benches/BUDGET.md`.
- [~] Key encoding module: DER / PEM / SPKI / PKCS#8 for Ed25519, P-256/384 and RSA public
      keys (closes the RSA SPKI gap); optional JWK. Strict minimal DER; fuzz targets added.
      - [x] `tpt-crypto-sig::encoding`: Ed25519 SPKI + PKCS#8 (RFC 8410), RSA SPKI (RFC 8017),
            strict DER reader, strict base64 PEM. Byte-exact KATs vs Python `cryptography`
            (`tests/kat_encoding.rs`).
      - [x] P-256 / P-384 SPKI and PKCS#8 (named-curve OIDs, uncompressed points). Byte-exact vs OpenSSL (`tests/kat_ec_encoding.rs`).
      - [x] JWK (RFC 7517): `tpt-crypto-sig::jwk` for Ed25519 (RFC 8037) and P-256/P-384
            public keys. Parsing is strict: exact member set, no `d`, no escapes, canonical
            base64url. Unit tests use RFC 8037 A.1 and RFC 7517 A.1 values. Private-key JWKs
            are not supported.
      - [x] Fuzz target for the DER / PEM decoders (`key_der_parse`; type-checked, not run on this host).
- [x] Argon2id (RFC 9106) in `tpt-crypto-hash::argon2` (feature `alloc`). Matches the
      RFC §5.3 tag and H_0 digest; provenance in `tests/kat/PROVENANCE.md`. Only
      Argon2id v0x13 is provided (no d/i variants). `blake2b_var` adds runtime-length BLAKE2b.
      - [x] Fuzz target for parameter / length inputs: `fuzz/fuzz_targets/argon2id_params.rs`
            (invalid parameters must return `Err`; valid small runs must be deterministic).
            Type-checked only; not run, since libFuzzer needs the ASan runtime absent here.
      - [ ] Benchmark row in `benches/BUDGET.md`.
- [x] `tpt_crypto::selftest::run()` power-on KATs. One RFC/FIPS vector each for SHA-256, HMAC, HKDF, X25519 and Ed25519 (inlined, so it works without a filesystem). Covers the classical set only; no ML-KEM / ML-DSA vectors yet.
- [~] Policy profile features `profile-cnsa2` / `profile-modern` (sig + facade).
      - [x] RSA minimum modulus: 2048 (`profile-modern`) / 3072 (`profile-cnsa2`); tests in `tests/rsa_profile.rs`.
      - [ ] Class-level exclusion (Ed25519, X25519, ChaCha20, ...) for CNSA 2.0. Needs a policy decision on which algorithms count as approved; the workspace has no SHA-1/MD5 to remove.

### C. Tooling & adoption
- [~] `tpt-crypto-cli` workspace binary (std): `hash`, `keygen`, `sign` / `verify`,
      `seal` / `open`, `kem encap` / `decap`, `selftest`, `bench`.
      - [x] `selftest`, `hash`, `random`, `sign-keygen` / `sign` / `verify`, `seal-keygen` / `seal` / `open`
            (`crates/tpt-crypto-cli`, end-to-end tests). Output files are never overwritten.
      - [x] `kem-keygen` / `kem-encap` / `kem-decap` (X-Wing hybrid), end-to-end tested.
      - [x] `bench` (quick `Instant` timings; not a substitute for `benches/`).
      - [ ] PEM/DER import and export. Needs a file-format decision first.
- [x] Runnable `cargo run --example` programs: `ml_kem`, `ml_dsa`, `ring_subset`,
      `bls_aggregate`, `hybrid_kem`, `seal_open` — in `examples/examples/`, run with
      `cargo run -p tpt-crypto-examples --example <name>`; each asserts its own round trip.
- [x] Docs book (`docs/`): "which primitive should I use?" chooser, feature-flag guide,
      constant-time guarantees, migration cheat-sheet from `ring` / RustCrypto /
      `aws-lc-rs`. Written from the codebase; the migration table is a mapping to check, not a compatibility claim.
- [ ] `wasm32` bindings crate (wasm-bindgen) with npm package. C-ABI crate only if a
      consumer asks.
- [x] `cargo xtask doctor` (toolchain, targets, nightly/miri, deny/fuzz present).
- [x] `cargo xtask wycheproof-fetch` (download + sha256 into `tests/kat/` PROVENANCE). Fetches AES-GCM and ChaCha20-Poly1305 files, consumed by `tpt-crypto-aead/tests/wycheproof.rs`.
- [x] `cargo xtask new-primitive` (scaffold a crate per AGENTS.md rules). Also adds the workspace dependency entry; the `../tpt-rust-map` registry entry is printed for manual addition (that repo is not present here).
- [x] `cargo xtask coverage` — wraps `cargo llvm-cov --workspace --all-features --summary-only`;
      fails with a clear message when `cargo-llvm-cov` is missing. Not run in the foreground
      (the instrumented suite takes longer than a 10-minute shell call).
- [ ] CI: release workflow (tag → package → publish gate), Dependabot, MSRV job (1.84),
      `cargo-audit` / `cargo-vet`, coverage upload, scheduled long fuzz and leakage runs.
      — added (not yet run on GitHub; no remote here): `.github/dependabot.yml` (cargo +
      github-actions, weekly), `msrv` job (`dtolnay/rust-toolchain@1.84.0`, `cargo check`),
      `ct-asm` job (`cargo xtask ct-asm`), `audit` job (`rustsec/audit-check`). Added since: nightly fuzz (each target 15 min), nightly long leakage, coverage job (lcov artifact). Still open:
      release workflow (publishing, left for the owner) and `cargo-vet`. The new jobs are not yet run on GitHub.
- [ ] Cross-repo: switch `../tpt-crypto-rustls` adapter to
      `verify_prehash_allow_high_s` and its RSA path to `PublicKey::verify_*`.

---

## Verification beyond tests (added 2026-11-10)

Plan: `~/.claude/plans/do-you-think-we-zany-pretzel.md`. Custom-first: Kani rejected as the
centrepiece (CBMC blows up on symbolic 256-bit multiplies and carry loops; no native
Windows support). Honest labels: "exhaustively verified over a bounded domain" and
"binary-checked", not "formally verified". Each item is its own commit.

### V1. Exhaustive bounded-domain proofs (`cargo xtask exhaustive`)
- [x] `-kem::poly`: `freeze` over all `i32` (`freeze` is now branch-free: it was a
      secret-dependent branch); `montgomery_reduce` over its documented range
      `|a| < 2^15·q` (it wraps outside that range, so the full `i32` domain is not
      claimed); `fqmul` over all reduced pairs; `compress`/`decompress` for every
      `x ∈ [0, q)` and `d ∈ {1, 4, 5, 10, 11}`.
- [x] `-sig::poly`: `reduce` over its documented range (it overflows above
      `i32::MAX − 2^22`, as the Dilithium reference does); `canonicalize` on the same
      range; `decompose_impl` over every canonical `a ∈ [0, q)` for both γ₂; `power2round`
      over every canonical `a`; per-position round trips for every value of the η, t₁,
      t₀ and z packers. Not done: the `w₁` packer.
- [x] `-ct`: `ct_select`, `cswap`, `ct_eq` and `ct_ne` over all `u8` pairs (every test
      run) and all `u16` pairs (`cargo xtask exhaustive`, about 5 s in release).
- [x] `exhaustive:` evidence kind in `specs/*.spec`; `cargo xtask verify` runs the named
      test in release with `--include-ignored --exact` and requires it to pass. Wired into
      `ct_select` and `ntt_roundtrip` (the latter as supporting evidence).

### V2. Small-scope field verification
- [x] Small-prime instantiation of `FieldElement` (`tpt-crypto-field/tests/small_field.rs`):
      `FieldParams` is a trait, so test-only fields with `p = 97`, `251`, `65521` and
      `2^64 - 59` are declared. Their Montgomery constants come from
      `gen_small_field.py` (independent of the crate's compile-time derivation). Not
      from `crates/` directly, because those helpers are `pub(crate)`.
- [x] `p = 97`, `251`, `65521`: add, sub, mul, square, neg, invert and the byte encoding
      checked against a `u128` reference over every pair (65521 runs under
      `cargo xtask exhaustive`, about 130 s in release).
- [x] `2^64 - 59` (one full limb, the limb-boundary case): every edge value against
      every other, plus 200 000 sampled pairs. This is sampling, not enumeration.
- [ ] Multi-limb primes (P-256 / P-384 / BLS12-381 base fields): not enumerable. Covered
      only by their KATs.

### V3. Binary-level constant-time checks (`cargo xtask ct-asm`)
- [x] Scanner: compiles probe test targets to release assembly (`--emit asm`), finds
      `probe_*` functions (plain or mangled), and reports conditional jumps. Strict
      targets fail on any jump. Negative control: a secret-dependent loop is caught.
      The stale-assembly and std false-positive problems are fixed.
- [x] Strict: `ct_select` (u8/u16/u64), `cswap`, `ct_eq`, `ct_ne` in `-ct`. No jumps.
- [ ] ML-KEM-768 decapsulation (`-kem`): report-only, 73 conditional jumps, still open.
      Decision: `overflow-checks` stays on (silent wraparound is worse than a panic).
      **Finding (2026-11-11), fixed:** `encode::pack_bits` branched on each coefficient
      bit (`if val & 1 == 1`). It runs on the secret key in keygen and on the re-encrypted
      ciphertext in decapsulation, so this was a secret-dependent branch. It is now an
      unconditional OR. Probe `kem_pack_asm_probe` (report-only: 112 jumps before, 48
      after). The 48 that remain are public bit-counter loops and bounds checks.
      **Coverage gap found:** the scanner reads only each probe's own body. The
      decapsulation probe calls `kpke_encrypt`, `pack`, and `sampler` out of line, so
      the 73 jumps do not include them. Callee probes now exist, all report-only and
      untriaged: `kem_pke_asm_probe` (`kpke_encrypt` 42 jumps, `kpke_decrypt` 13) and
      `kem_cbd_asm_probe` (eta = 2 sampler, 67). Their jumps are mostly loop control over
      public counts, but I have not classified them. Strict status needs straight-line
      code or a flag-source classifier. The checks in the source: `sample_ntt` branches only on public XOF output, `cbd` only on
      the public `eta`, and decapsulation selects with `ct_eq_bytes` and `ct_select_array`.
- [x] Ed25519 field add/sub, Ed25519 point add, and AEAD tag verify (16 and 32 bytes):
      probed and strict (`field_asm_probe`, `curve_asm_probe`, `aead_asm_probe`).
      **Finding (2026-11-11), fixed:** the first scan failed. Two problems:
      (a) `consts::limbs_ge` / `ge_n` / `limbs_eq` branched on limb values, and
      `FieldElement::add` used `carry != 0 || ge_p`. (b) LLVM rewrote the masked
      select in `ct_select_u64` into `cmp`/`jne` for the Ed25519 field add/sub. Fixes:
      comparisons are now borrow-based and accumulated; the `||` is a bitwise OR;
      `Choice::mask_u64` and the `consts::sel` helper use the same mask. `sel` is
      `const fn`, so it has no `black_box` (MSRV 1.84 has no const `black_box`).
      Runtime field arithmetic uses the non-const `ct_select_u64`. The
      compile-time helpers (`mod_reduce`, `reduce_wide`, `sub_mod`) are now
      branch-free too, but nothing is probed for them. Field, curve, sig and ct
      test suites pass after the change.
- [ ] Ed25519 scalar multiplication (`-curve`, `curve_mul_asm_probe`): report-only.
      **Fixed (2026-11-11):** the scan had found 11 jumps. One was a real problem:
      `FieldElement::pow` branched on each exponent bit (`if b == 1 { mul }`). Its doc said
      the exponent may be secret. Every current caller passes a public exponent, so nothing
      leaked, but the contract was wrong. `pow` now multiplies every bit and selects with
      `ct_select_fe`. Field, curve and sig tests pass. Cost: about one extra multiplication
      per exponent bit; not benchmarked. Remaining 5 jumps: fixed-count loops (`decl`/`jne`,
      `cmp $3072`, `addq $-1`/`jb`, `inc`/`jne`). One `testq %r14`/`jne` I have not traced
      to source, so the item stays open.
- [ ] Optional instruction-count equality (callgrind): not started.
- [x] `ct-asm:` evidence kind in `specs/*.spec`: `ct-asm: <pkg> <probe-target>` runs the
      strict binary scan for that target. Wired into `ct_select.spec` (ct_asm_probe) and
      `aead_tag_verify.spec` (aead_asm_probe). `cargo xtask verify`: 14 verified, 0 failed.

### V4. Test-strength audit (`cargo mutants`, installed as cargo-mutants 27.1.0)
- [x] `-ct` `select.rs` and `cmp.rs`: 50 mutants. 37 caught, 12 unviable, 1 missed.
      The missed one (`|` → `^` in the length term of `ct_eq_slices`) is equivalent for
      every length a slice can have (the difference is below 2^63, where the two agree).
      The run found a real bug, now fixed: `ct_eq_slices` reported equal non-empty slices
      as unequal (it ORed `ct_eq`'s 1-for-equal results), and it truncated the length
      difference to 8 bits. It had no tests and no callers. Direct tests in
      `tests/slices.rs`.
- [x] `-field` `consts.rs` helpers changed in the constant-time pass (`sel`, `limbs_ge`,
      `ge_n`, `limbs_eq`): 25 mutants, first run **25 missed**, because the lib tests never
      reached these helpers. Added direct tests against a `u128` reference (`consts::tests`,
      covering `sel`, add/sub with flags, comparisons, `limbs_eq`, `sub_mod`/`add_mod`,
      `reduce_wide`). Rerun: 24 caught, 1 timeout (a `+=`→`*=` counter mutant that hangs
      `limbs_eq`, so it is also detected). `-kem::encode::pack_bits` (the branch-free fix):
      23 of 23 caught by the kem lib tests.
      `-kem::poly` reduction functions (`freeze`, `montgomery_reduce`, `fqmul`): 21 of 21 caught.
      `-sig::poly` (`reduce_mod`, `decompose_*`, `use_hint`, `make_hint`, `high_bits`): 112
      mutants on the lib tests, 90 caught at first. Added `hint_boundaries` (r at and next to
      multiples of 2γ₂, extreme z), `decompose_into_matches_impl` and `reduce_mod_is_canonical`.
      `reduce_mod` is now 10/10 caught. The 21 that remain are equivalent by inspection:
      integer division gives the same constant (`(Q±1)/32`), the `a1` clamp keeps the wrap
      branch dead (`a1 ≤ 43` or `≤ 15`, so `a1·2γ₂ ≠ Q-1`), and the mask-shift mutants
      give the same output. The exhaustive suite (`--test exhaustive decompose_is`) kills the
      live arithmetic mutants, which I confirmed by hand on the `a0` subtraction. The wrap
      branch is dead code. Removing it is left as a choice.
      `-hash::sha3` (SHA-3 / SP 800-185): `keccak_f` 76 of 76 caught by `tests/kat.rs`. The lib
      tests reached none of it (135/135 missed there). The encoders `left_encode`,
      `right_encode` and `bytepad` had 3 survivors, because the KATs only use one-byte
      lengths. `encode_tests` checks SP 800-185 vectors and the `bytepad` length
      formula. Rerun: 50 caught, 1 timeout.
      `-hash::sha2` `compress32`/`compress64`: 148 mutants on `tests/kat.rs`. 9 survived at
      first. Three `*`→`+` in the 64-bit block load (bytes 12–31) survived because the KATs
      only used messages under 12 bytes, so those bytes are zero either way. Added
      `sha2_multi_block` (FIPS 180-4 896-bit SHA-512 and 448-bit SHA-256). Rerun: 142
      caught, 6 missed. Those 6 are the `^`→`|` mutants in `ch` and `maj`, equivalent by
      bit-level argument (`ch`'s terms are disjoint; `maj`'s XOR and OR agree).
      `-hash::blake2b` (`tests/kat.rs`, blake2b filter): 91 mutants. 13 survived at first.
      Added `blake2b_var_known_answers` (BLAKE2b-256("abc") and split input),
      `blake2b_streaming_at_every_split` (every split of every length 0..=260), and
      `blake2b_reuse_matches_fresh` (`reset` and `finalize_reset`). Rerun: 84 caught, 4
      missed, all equivalent. Two are the `t >> 64` high word, which is zero for any
      input under 2^64 bytes. One is `buflen >= 0`, which takes the same branch as the
      `while` loop. One is `|` vs `^` in `blake2b_var` with no overlapping bits. Still not
      run: the other `-field` files.
      `-hash::argon2` (lib tests): 230 mutants, 218 caught, 9 missed. Added
      `memory_and_tag_length_boundaries` and `independent_reference_multi_segment` (tags from the
      RustCrypto `argon2` 0.5 crate, outside the repo). Survivors killed: the `8 * p` memory bound,
      the 4-byte tag minimum, the pass-0 slice-0 branch, the same-lane window, and the window size.
      The RFC vector has `seg = 2`, which cannot tell same-lane from other-lane windows, so it
      was not enough by itself. The `SYNC_POINTS - 1` mutants (`+` and `/`) are equivalent: the
      `(slice + 1) * seg` they change is `q` on the last slice, and the `% q` reduction maps it
      to 0 either way. Not yet run: the other `-field` files.
      `-hash::k12` (`tests/kat.rs` + a `k12::tests` unit test for `right_encode`): 213 mutants.
      Before: 6 missed on the KATs. Added the rate-edge reference test and a unit test
      (`right_encode` at 4 and 5 value bytes; `right_encode` mutants 19 of 19 caught). Final
      run: 203 caught, 4 timeouts (counted as caught), 6 missed. Each survivor is equivalent:
      the `buflen > 0` → `>= 0` absorb branch takes the same path as the block loop; the
      `(suffix & 0x80)` clause is dead (every call uses 0x06, 0x07 or 0x0B, none with bit 7),
      which makes its `==`/`-` mutants unreachable; `produced < len` → `<=` only permutes the
      state after the last output byte; and the `right_encode` mutant at 165 was the one real
      survivor, now killed.
      `-hash::blake3` (`tests/kat.rs`): 168 mutants. The four short KATs never reached the
      chunk tree. Added `blake3_multi_chunk_reference` (9 lengths from 1023 to 10,000, a keyed
      case, and 64-byte XOF), `blake3_streaming_at_chunk_boundaries`,
      `blake3_xof_long_output_and_reset` (65, 100 and 200-byte XOF, which hit the
      non-multiple-of-64 slicing, plus `reset`). The references come from the upstream
      `blake3` crate 1.x, run in a scratch project outside the repo, not from the official
      `test_vectors.json`. The official file was not fetched, so it is not claimed here.
      Rerun: 156 caught, 6 missed, all equivalent. Those are `counter >> 32` vs `<<` (equal
      below 2^32 chunks), `|` vs `^` on disjoint flag bits, `i > 0` vs `>= 0` (the value
      is unused), and `buflen > 0` vs `>= 0` (same branch as the `while` loop).
- [ ] Triage survivors into new tests (done per survivor so far; `-hash::argon2`, `-hash::k12` done, other `-field` files open).
- [x] Gate against discarded results in tests (`let _ = ...prop_assert...`): checked
      2026-11-11 — no `let _ =` wraps an assertion in any `tests/` or `src/` file; the
      remaining `let _` lines discard non-assertion values (e.g. `mpc/src/ot.rs:201`).
- [x] Regression check: reintroduce past bugs (drop `carry_hi`, wrong omega, `polyt0_unpack`
      index), one at a time, source restored after each. The first runs used a scratch worktree at HEAD, the later ones the main tree.
      - `carry_hi` dropped from the field conditional subtract: caught by `field_props` (P-384
        properties fail); the small-prime and KAT tests were not checked for this run.
      - `polyt0_unpack` shift changed (`<< 3` to `<< 4`): caught by the ML-DSA round-trip tests.
      - hint count bound dropped in `unpack_hint`: **not caught** by any existing test. Added
        `hint_count_above_omega_is_rejected` (committed). Verified: passes on the code, fails
        with the bound removed.
      - V1 exhaustive and V4 mutation runs were not repeated per injection.

### V5. Optional, only if a "formally verified" headline is wanted
- [ ] Kani for `-ct` laws and decoder panic-freedom only (small and tractable).
- [ ] Cryptol/SAW equivalence for SHA-256, Keccak-f and ChaCha20.
- [ ] Verus or hax -> F* for the field reduction lemma and ML-KEM.
- [ ] State the proof boundary (Rust/LLVM semantics, not machine code) in `SECURITY.md`
      and `AGENTS.md` whenever any of the above lands.
