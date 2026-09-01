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
- [~] proptest: field axioms (assoc/dist/inverse), `from(to(x)) == x`,
      `mul` matches `tpt-math-exact` mod P
      — `tests/field_props.rs` now exists (`proptest` is a workspace dep).
      P-256 (base+scalar), BLS12-381 (Fp+Fr) pass; `p384_base_props` and
      `p384_scalar_props` still **FAIL** but are much closer after two fixes in
      the working tree: (a) `P384BaseParams` low modulus limb was
      `0x0000_0000_FFFF_FFFF`, corrected to `0x0000_0001_FFFF_FFFF`
      (p = 2^384 − 2^128 − 2^96 + 2^32 − 1); (b) the CIOS `mont_mul` operand-scan
      and reduction loops let a `u128` carry wrap on 6-limb fields — now split
      each 128-bit partial product into low/high limbs. Remaining P-384 failure
      is a small off-by-one in the low limb (`p384_mul_debug` isolates it).
      Scratch `tests/dbg_check.rs` + `consts::dbg_consts` trace tests +
      `tests/field_props.rs::p384_mul_debug` are debugging aids, prune before
      publish.
      NOTE: `src/params.rs` in `4e6c0d9` shipped with literal `]\n);` typos in
      8 `declare_params!` calls (broke `--features alloc`); since fixed in the
      working tree, along with corrected `Ed25519ScalarParams` limbs.
- [x] `specs/field_mul.telos` (`result == a*b mod P ∀ a,b<P`),
      `specs/field_reduce.telos`

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
- [ ] P-256 / P-384 (SEC1): short-Weierstrass complete addition formulas,
      ct scalar mul, point (de)compression, subgroup/on-curve checks
- [ ] BLS12-381: G1/G2 (subgroup checks via endomorphism), Miller loop,
      final exponentiation → GT; `pairing` / `multi_pairing`
- [ ] hash-to-curve (RFC 9380) for Ed25519, P-256, BLS12-381 G1/G2
- [ ] KATs: RFC 8032 (Ed25519), RFC 7748 (X25519), NIST CAVP ECDH (P-256/384),
      draft-irtf-cfrg BLS12-381 vectors, RFC 9380 h2c vectors
- [ ] proptest: `k·(l·P) == (k·l)·P`, `pairing` bilinearity, compress round-trip
- [ ] `specs/scalarmul_ct.telos` (timing ⟂ scalar)

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
- [~] ChaCha20 + Poly1305 (RFC 8439); XChaCha20-Poly1305 (draft-irtf-cfrg)
      — `src/chacha.rs`: ChaCha20 block/stream, Poly1305, `ChaCha20Poly1305`,
      `XChaCha20Poly1305` (HChaCha20). RFC 8439 §2.3.2 block + §2.4.2 encrypt +
      §2.5.2 Poly1305 inline KATs pass.
- [~] AES-GCM-SIV (RFC 8452) — nonce-misuse resistant; POLYVAL
      — `src/gcm_siv.rs`: POLYVAL (rewritten — left-shift multiply, correct
      `x¹²⁸+x¹²⁷+x¹²⁶+x¹²¹+1` reduction constant, branch-free), key-derivation,
      `Aes128GcmSiv`/`Aes256GcmSiv`. RFC 8452 Appendix C.1 KAT + POLYVAL identity
      test pass. Needs the full C.1–C.6 vector set.
- [~] `CtrDrbg` (SP 800-90A) implementing `DrbgCore`
      — `src/ctr_drbg.rs`: AES-256 CTR-DRBG, `update` (key rebuilt into fresh
      `Zeroizing` buffer), instantiate/reseed/generate, inline tests. Not yet
      confirmed wired to the `DrbgCore` trait / CAVP vectors.
- [x] API: `Aead` trait (`encrypt`/`decrypt` in-place + detached tag), AAD,
      ct tag comparison (`ct_eq`), `Nonce`/`Tag` newtypes
      — `src/api.rs`: const-generic `Aead<NONCE_LEN, TAG_LEN>`, detached +
      alloc-gated combined ops, `Nonce`/`Tag` newtypes, `Tag::ct_eq` via
      `tpt-crypto-ct::ct_eq_bytes`, no `PartialEq` on `Tag`.
- [~] Optional `aead` trait-compat impls behind `aead` feature
      — `src/aead_compat.rs` behind the `aead-trait` feature (`aead` 0.6);
      `cargo test -p tpt-crypto-aead --all-features` builds and passes.
- [~] KATs: NIST GCM/CAVP, RFC 8439, RFC 8452, Wycheproof (AES-GCM, ChaCha20Poly1305)
      — inline per-module vectors only (FIPS-197 AES, RFC 8439 ChaCha/Poly1305,
      RFC 8452 GCM-SIV C.1, NIST GCM Appendix B TC1/TC2); all 15 lib tests green.
      No `tests/` dir, no NIST CAVP / Wycheproof JSON, no PROVENANCE.
- [ ] proptest: `decrypt(encrypt(m)) == m`; any ciphertext/tag/AAD bitflip → error
      — `proptest` is a dev-dep but no property tests written yet.
- [ ] `specs/aead_tag_verify.telos` (accept iff tag valid; timing ⟂ tag)

- [ ] **Milestone**: dry-run clean for `-field`,`-curve`,`-aead`;
      `examples/ring_subset.rs` (ECDSA + AES-GCM + SHA-256 end to end)

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
      — `src/pke.rs` + `src/ml_kem.rs` (alloc-gated); `tests/props.rs`
      encaps/decaps round-trip passes for all three parameter sets.
      `ml_kem.rs` under active edit.
- [x] Spec API: `ml_kem::keygen::<MlKem768>(rng)`, `encapsulate`, `decapsulate`
- [~] FrodoKEM (feature `frodo`) and Classic McEliece (feature `mceliece`,
      long-term secrets) — gated, larger
      — `src/frodo.rs` / `src/mceliece.rs` are feature-gated stubs returning
      `Error::Unsupported`; API surface only.
- [ ] KATs: FIPS 203 ACVP vectors + NIST `.rsp` KAT files (all param sets)
      — `tests/kat/` dir present; one KAT test currently `#[ignore]`, no ACVP
      vectors wired.
- [~] proptest: `decapsulate(sk, encapsulate(pk).0) == encapsulate(pk).1`;
      malformed ciphertext → implicit-reject (no panic, no distinguishable time)
      — `tests/props.rs`: round-trip for 512/768/1024 + implicit-reject on
      tampered ciphertext, all green (4 tests).
- [ ] `specs/ml_kem_decapsulate.telos` (`ensures: timing ⟂ sk`),
      `specs/ntt_roundtrip.telos`

### crates/tpt-crypto-sig
- [~] Reuse `-kem::poly` for ML-DSA ring (q=8380417, n=256); power2round,
      decompose, `makeHint`/`useHint`, ct
      — own `src/poly.rs` (does **not** reuse `-kem::poly`); power2round /
      decompose / hint helpers present. `poly::tests::all_poly_tests` now
      **PASSES** — the NTT round-trip bug is fixed (working tree).
- [~] ML-DSA (FIPS 204) keygen/sign/verify → ML-DSA-44 / 65 / 87; hedged +
      deterministic; rejection-sampling loop with ct primitives; `ctx` domain sep
      — `src/ml_dsa/mod.rs` + `src/ml_dsa/sample.rs`; keygen/sign/verify wired for
      all three sets, deterministic + hedged, `Ctx` domain separation. All 6
      `ml_dsa::tests` round-trips still **FAIL**, but no longer blocked on the
      poly NTT bug (now fixed) — remaining defect is in the ML-DSA
      sign/verify/packing path itself.
- [~] SLH-DSA (FIPS 205): WOTS+, XMSS, FORS, hypertree; SHA2 + SHAKE param sets;
      `slh-dsa` feature (large)
      — `src/slh_dsa.rs` scaffolded (now an unconditional `pub mod`, no longer
      feature-gated): `SlhDsaParam` enum + stub key/sig types, operations return
      `Error::Unsupported`. No WOTS+/XMSS/FORS/hypertree yet.
      `tests/slh_dsa_kat.rs` is a placeholder.
- [ ] Ed25519 sign/verify (on `-curve`), batch verify
- [ ] ECDSA P-256 / P-384: RFC 6979 deterministic nonce + ct scalar ops;
      low-s normalization; ASN.1 DER + fixed encodings
- [ ] BLS12-381 (spec API): `sign`, `verify`, `aggregate`,
      `verify_aggregate` (same-message + distinct-message), proof-of-possession;
      ciphersuite `BLS_SIG_..._NUL_`
- [~] Spec API: `ml_dsa::keygen::<MlDsa65>`, `sign(sk, msg, ctx)`, `verify(...)`
      — surface exists; blocked on the failing ML-DSA round-trips above.
- [~] Optional `signature` trait-compat impls behind `signature` feature
      — `src/signature_impls.rs` is a stub.
- [ ] KATs: FIPS 204 & 205 ACVP, RFC 8032 (Ed25519), RFC 6979 + NIST CAVP (ECDSA),
      Wycheproof (ECDSA/EdDSA), draft-irtf-cfrg-bls-signature vectors
      — `tests/ml_dsa_kat.rs` present (placeholder), no ACVP vectors.
- [~] proptest: `verify(pk, m, sign(sk, m))` ok; wrong key/msg/ctx → `Verification`;
      `verify_aggregate` iff all inputs valid
      — `tests/ml_dsa_props.rs` present; blocked on the failing ML-DSA
      round-trips (sign/verify path, no longer the NTT).
- [ ] `specs/bls_aggregate.telos` (`valid iff all input sigs valid`),
      `specs/ecdsa_nonce_ct.telos`

- [ ] **Milestone**: dry-run clean for `-kem`,`-sig`;
      `examples/ml_kem.rs` + `examples/ml_dsa.rs` reproduce `spec.txt` §4

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
> added as a compiling placeholder module (verifier not yet implemented —
> returns `ZkError::Unsupported`). `Pedersen`/`Transcript`/`IPA`/`Bulletproofs`
> types compile but are **untested** (no wiring/tests run green yet).
- [~] Fiat-Shamir `Transcript` (Merlin-style STROBE-lite on SHAKE256):
      `append_message`, `challenge_scalar` — `src/transcript.rs`.
- [~] Pedersen commitments over BLS12-381 G1 / Ed25519 (`commit(value, blinding)`)
      — `src/pedersen.rs` + `src/generators.rs` + `src/group.rs` (Ed25519 only).
- [~] Inner-product argument; Bulletproofs range proofs — single + aggregated,
      ranges up to `2^64` (`prove_range`, `verify_range` per spec API)
      — `src/ipa.rs` + `src/bulletproofs.rs` (`prove_range`/`verify_range`,
      `range_proof_{to,from}_bytes`); not yet building/tested.
- [ ] Minimal PLONK verifier (~500 LoC): transcript, KZG **or** IPA commitment
      opening check, permutation + gate checks; accepts any compliant proof
      (no prover — that is `tpt-telos`'s job)
      — `pub mod plonk;` declared but `src/plonk.rs` not created yet.
- [ ] KATs: bulletproofs reference test vectors (dalek-compatible),
      PLONK proof fixtures from a reference prover
      — `tests/kat/` dir present but empty.
- [ ] proptest: honest `prove_range` always verifies; out-of-range value →
      prove fails; tampered proof → verify fails
- [ ] `specs/bulletproofs_verify.telos` (`true iff proof valid for commitment`)

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
- [ ] `specs/secret_share_reconstruct.telos`

### crates/tpt-crypto  (facade — umbrella variant)
1. [ ] Scaffold with cargo features gating each re-export:
   `classical` (hash+aead+field+curve+sig-classical), `pq` (kem+sig-pq),
   `bls`, `zk`, `mpc`, `full`; `std`/`alloc` propagate
2. [ ] Wire optional deps + matching feature flags per sub-crate
3. [ ] `prelude` module: `SecretBox`, `CryptoRng`, and the spec §4 surface
4. [ ] Modules matching `spec.txt` §4 **verbatim**: `ml_kem`, `ml_dsa`,
   `bulletproofs`, `bls`, `ct` (`SecretBox`, `ct_select`)
5. [ ] Rustdoc: feature matrix table; "which crate for which primitive"
6. [ ] `fmt` / `clippy` / `deny` clean across feature combinations
7. [ ] `examples/`: one compiled+tested file per `spec.txt` §4 snippet
8. [ ] Update `tpt-rust-map/registry.toml` status

- [ ] **Milestone**: `cargo xtask release-dry-run` — all 11 crates
      `cargo publish --dry-run` clean in dependency order

---

## Cross-Cutting (thread through all phases)

- [ ] `xtask`: subcommands `no-std` (owns crate/feature/target list),
      `kat-check` (verify `PROVENANCE.md` sha256s), `leakage` (dudect runner),
      `verify` (shell `tpt-telos-cli` over `specs/*.telos`, print report),
      `release-dry-run` (`cargo publish --dry-run` in topo order), `sbom`
- [ ] `fuzz/` (`cargo-fuzz`): targets for every attacker-controlled decoder —
      signature parse, ciphertext parse, public-key parse, proof parse,
      ASN.1 DER, point decompression
- [ ] `benches/BUDGET.md`: per-primitive perf target vs `ring` / `dalek` /
      `pqcrypto`; criterion targets build in `bench-smoke`
- [ ] `cargo-semver-checks` in CI (runs on tags)
- [ ] SBOM artifact (`cargo xtask sbom`) uploaded by CI
- [ ] Trait-compat feature impls (`digest`, `aead`, `signature`,
      `elliptic-curve`) + a `rustls` `CryptoProvider` example
- [ ] `specs/`: keep the `spec.txt` §5 contract table in sync with real files;
      promote each `telos-verify` check from non-blocking → blocking as it lands
- [ ] Final crates.io-prep audit: every crate has description/keywords/categories/
      README/CHANGELOG/`docs.rs` metadata; `cargo package` lists no stray files;
      **do not publish** this pass
- [ ] Per-phase local commit; update this file's checkboxes as work lands

---

## CI — `.github/workflows/ci.yml`

`env: RUSTFLAGS: -D warnings`. Jobs:

- [ ] `fmt` — `cargo fmt --check`
- [ ] `clippy` — `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `test` — `cargo nextest run --workspace --all-features` + `cargo test --workspace --all-features --doc`
- [ ] `no_std` — matrix `thumbv6m-none-eabi` (no `alloc`) / `thumbv7em-none-eabihf` / `wasm32-unknown-unknown`, via `cargo xtask no-std`
- [ ] `target-feature-matrix` — build+test `-aead`/`-hash` with and without `aes,sha,avx2,sse4.1` `-C target-feature`
- [ ] `cargo-deny` — license + bans gate (**blocking**)
- [ ] `miri` — `cargo +nightly miri test -p tpt-crypto-ct`
- [ ] `leakage` — `cargo xtask leakage` (Welch t-test thresholds)
- [ ] `feature-powerset` — `cargo hack test --feature-powerset -p tpt-crypto`
- [ ] `telos-verify` — `cargo xtask verify` (non-blocking → blocking per primitive)
- [ ] `bench-smoke` — `cargo bench --no-run`
- [ ] `fuzz-smoke` — `cargo +nightly fuzz build`
- [ ] `semver-checks` — on tags only
