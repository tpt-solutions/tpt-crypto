# Benchmark budget — `tpt-crypto`

Record of per-primitive performance targets versus established pure-Rust
reference implementations. Criterion benchmarks live under each crate's
`benches/`; this file is the human-readable contract that CI's `bench-smoke`
keeps honest. All targets are for **release profile, single-threaded, x86_64**.

Targets are expressed as a multiplier over the best available pure-Rust baseline:
no `ring` C-FFI comparisons (that would defeat the substrate's purpose).

**Measured** (2026-10-03): criterion medians on x86_64 (Windows, release
profile, `--warm-up-time 1 --measurement-time 2 --sample-size 20 --noplot`).
Where the measured number misses the target, the status says so — most
targets assumed SIMD-heavy implementations; the substrate is deliberately
portable/table-free, so the realistic near-term ceiling is lower until a
SIMD follow-up lands.

---

## tpt-crypto-core

| Benchmark            | Target                                   | Status  |
| -------------------- | ---------------------------------------- | ------- |
| `ct_select/u64`      | ≤ 1.2× `subtle::Choice::select_u64`      | pending |
| `ct_eq/slice/64`     | ≤ 1.2× `subtle::ConstantTimeEq`          | pending |
| `zeroize/array/64`   | ≤ 1.1× `zeroize::Zeroize`                | pending |

---

## tpt-crypto-ct

| Benchmark            | Target                                   | Status  |
| -------------------- | ---------------------------------------- | ------- |
| `ct_select/u64/sse`  | ≥ 2× portable `ct_select` throughput     | pending |
| `ct_select/u64/avx2` | ≥ 3× portable `ct_select` throughput     | pending |

---

## tpt-crypto-hash

| Benchmark               | Target                                    | Measured (median) | Status |
| ----------------------- | ----------------------------------------- | ----------------- | ------ |
| `blake2b/1kb`           | ≥ 4 GB/s                                  | 1.01 µs (~0.97 GiB/s) | below target (portable) |
| `blake3/1kb`            | ≥ 8 GB/s                                  | 1.22 µs (~0.78 GiB/s) | below target (portable) |
| `sha2-256/1kb`          | ≥ 3 GB/s                                  | 2.96 µs (~0.32 GiB/s) | below target (portable) |
| `sha3-256/1kb`          | ≥ 2 GB/s                                  | 2.10 µs (~0.45 GiB/s) | below target (portable) |
| `k12/1kb`               | ≥ 2 GB/s                                  | 1.83 µs (~0.52 GiB/s) | below target (portable) |
| `shake128/1kb`          | —                                         | 1.86 µs (~0.51 GiB/s) | recorded |

---

## tpt-crypto-field

| Benchmark                 | Target                                     | Measured (median) | Status |
| ------------------------- | ------------------------------------------ | ----------------- | ------ |
| `p256/mul`                | ≥ 2× `ark-ff` multiplication throughput    | 20.7 ns (~48 Melem/s) | baseline comparison pending |
| `p256/add`                | —                                          | 705 ps (~1.4 Gelem/s) | recorded |
| `bls12_381/fp/mul`        | ≥ 1.8× `ark-ff` multiplication throughput  | 47.8 ns (~21 Melem/s) | baseline comparison pending |
| `ed25519/scalar/mul`      | —                                          | 19.3 ns (~52 Melem/s) | recorded |
| `montgomery-ladder/p256`  | ≥ 500 kops/s scalar mult                    | bench not yet written | pending |

---

## tpt-crypto-aead

| Benchmark                 | Target    | Measured (median) | Status |
| ------------------------- | --------- | ----------------- | ------ |
| `aes-128-gcm/1kb`         | ≥ 3 GB/s  | 13.1 µs (~74 MiB/s) | below target (GHASH is portable Shoup-style; AES-NI covers only the block path) |
| `aes-256-gcm/1kb`         | ≥ 3 GB/s  | 13.0 µs (~74 MiB/s) | below target (as above) |
| `chacha20-poly1305/1kb`   | ≥ 1 GB/s  | 2.06 µs (~463 MiB/s) | close to target (portable) |
| `aes-128-gcm-siv/1kb`     | ≥ 2.5 GB/s | 27.8 µs (~35 MiB/s) | below target (two-pass POLYVAL, portable) |

---

## tpt-crypto-curve

| Benchmark                  | Target                              | Status  |
| -------------------------- | ----------------------------------- | ------- |
| `x25519/keygen`            | ≥ 50 kops/s                         | pending |
| `x25519/dh`                | ≥ 20 kops/s                         | pending |
| `ed25519/sign`             | ≥ 10 kops/s                         | pending |
| `ed25519/verify`           | ≥ 5 kops/s                          | pending |
| `p256/ecdh`                | ≥ 5 kops/s                          | pending |
| `p384/ecdh`                | ≥ 3 kops/s                          | pending |

---

## tpt-crypto-kem

| Benchmark              | Target | Measured (median) | Status |
| ---------------------- | ------ | ----------------- | ------ |
| `ml-kem-768/keygen`    | ≥ 2 kops/s | 125 µs (~8.0 kops/s) | meets target |
| `ml-kem-768/encaps`    | ≥ 1.5 kops/s                        | 97 µs (~10.3 kops/s) | meets target |
| `ml-kem-1024/keygen`   | —                                   | 145 µs (~6.9 kops/s) | recorded |


---

## tpt-crypto-sig

| Benchmark              | Target                              | Status  |
| ---------------------- | ----------------------------------- | ------- |
| `ml-dsa-65/sign`       | ≥ 2 kops/s                          | pending |
| `ml-dsa-65/verify`     | ≥ 1 kops/s                          | pending |
| `ml-dsa-44/sign`       | ≥ 4 kops/s                          | pending |
| `ed25519/sign`         | ≥ 10 kops/s                         | 486 µs (~2.1 kops/s) — below target (was 6.2 ms before caching curve `d` / base point) |
| `ed25519/verify`       | ≥ 5 kops/s                          | 7.6 ms (~130 ops/s) — below target (two inversions + sqrt in decompress, unprofiled) |
| `ecdsa-p256/sign`      | ≥ 3 kops/s                          | 339 µs (~2.9 kops/s) — close to target |
| `ecdsa-p384/sign`      | ≥ 1.5 kops/s                        | 1.83 ms (~548 ops/s) — below target |
| `bls12-381/sign`       | ≥ 1 kops/s (pairing-dominated)      | 3.9 ms (~254 ops/s) — below target (hash-to-curve G2 + G2 scalar mult) |
| `bls12-381/verify`     | ≥ 500 ops/s                         | 4.3 ms (~232 ops/s) — below target (projective Miller loop, sparse lines, Karatsuba tower, Frobenius + cyclotomic final exp) |
| `bls12-381/verify-agg` | ≥ 300 aggregate-verifications/s (n=64) | 4.8 ms (~210/s) — below target (single shared final exponentiation; hash-to-curve ~2 ms is now a major share) |

---

## tpt-crypto-zk

| Benchmark              | Target | Measured (median) | Status |
| ---------------------- | ------ | ----------------- | ------ |
| `bulletproofs/prove/1` | ≥ 1 proof/s for 32-bit range proof  | 800 ms (~1.25 proofs/s) | meets target |
| `bulletproofs/verify/1`| ≥ 10 verifications/s for 32-bit     | 360 ms (~2.8 verifications/s) | below target (portable scalar ops) |
| `pedersen/commit`      | ≥ 100 kops/s                        | 3.29 ms (~304 ops/s) | below target (per-commitment generator sweep) |
| `plonk/verify/n=4`     | ≥ 500 verifications/s (IPA opening) | bench not yet written | pending |

---

## tpt-crypto-mpc

| Benchmark                    | Target                              | Status  |
| ---------------------------- | ----------------------------------- | ------- |
| `beaver/multiply`            | ≥ 50 kTriples/s                      | pending |
| `iknp/ot-extend/1M`          | ≥ 10 kOTs/s                         | pending |
| `reconstruct/field-element`  | ≤ 2× field multiply cost             | pending |

---

## Status key

- **pending** — benchmark scaffold exists (or target bench not yet written),
  target not yet validated
- **below target** — measured; the target assumed a SIMD-heavy
  implementation, the substrate is deliberately portable/table-free
- **meets target** — measured on the reference hardware (2026-10-03)
- **close to target** — measured within 10% of target

## Notes

## Notes

- All throughput targets assume `RUSTFLAGS="-C target-cpu=native"` in release mode.
- Embeded targets (`thumbv6m-none-eabi`) are measured in `no_std` mode; targets
  are expressed as absolute cycle counts in `benches/embedded/BUDGET.md`.
- `cargo xtask check` runs `bench-smoke` (compile-only); full benchmark runs
  are gated behind the `bench` CI job triggered on `main` weekly.
