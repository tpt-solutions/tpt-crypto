# Benchmark budget — `tpt-crypto`

Record of per-primitive performance targets versus established pure-Rust
reference implementations. Criterion benchmarks live under each crate's
`benches/`; this file is the human-readable contract that CI's `bench-smoke`
keeps honest. All targets are for **release profile, single-threaded, x86_64**.

Targets are expressed as a multiplier over the best available pure-Rust baseline:
no `ring` C-FFI comparisons (that would defeat the substrate's purpose).

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

| Benchmark               | Target                                    | Status  |
| ----------------------- | ----------------------------------------- | ------- |
| `blake2b/1kb`           | ≥ 4 GB/s                                  | pending |
| `blake3/1kb`            | ≥ 8 GB/s                                  | pending |
| `sha2-256/1kb`          | ≥ 3 GB/s                                  | pending |
| `sha3-256/1kb`          | ≥ 2 GB/s                                  | pending |
| `k12/1kb`               | ≥ 2 GB/s                                  | pending |

---

## tpt-crypto-field

| Benchmark                 | Target                                     | Status  |
| ------------------------- | ------------------------------------------ | ------- |
| `p256/mul`                | ≥ 2× `ark-ff` multiplication throughput    | pending |
| `p384/mul`                | ≥ 1.8× `ark-ff` multiplication throughput  | pending |
| `bls12_381/fp/mul`        | ≥ 1.8× `ark-ff` multiplication throughput  | pending |
| `montgomery-ladder/p256`  | ≥ 500 kops/s scalar mult                    | pending |

---

## tpt-crypto-aead

| Benchmark                 | Target                              | Status  |
| ------------------------- | ----------------------------------- | ------- |
| `aes-128-gcm/1kb`         | ≥ 3 GB/s                           | pending |
| `aes-256-gcm/1kb`         | ≥ 3 GB/s                           | pending |
| `chacha20-poly1305/1kb`   | ≥ 1 GB/s                           | pending |
| `aes-128-gcm-siv/1kb`     | ≥ 2.5 GB/s                         | pending |

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

| Benchmark              | Target                              | Status  |
| ---------------------- | ----------------------------------- | ------- |
| `ml-kem-768/keygen`    | ≥ 2 kops/s                          | pending |
| `ml-kem-768/encaps`    | ≥ 1.5 kops/s                        | pending |
| `ml-kem-768/decaps`    | ≥ 1 kops/s                          | pending |
| `ml-kem-1024/keygen`   | ≥ 1 kops/s                          | pending |

---

## tpt-crypto-sig

| Benchmark              | Target                              | Status  |
| ---------------------- | ----------------------------------- | ------- |
| `ml-dsa-65/sign`       | ≥ 2 kops/s                          | pending |
| `ml-dsa-65/verify`     | ≥ 1 kops/s                          | pending |
| `ml-dsa-44/sign`       | ≥ 4 kops/s                          | pending |
| `ed25519/sign`         | ≥ 10 kops/s                         | pending |
| `ed25519/verify`       | ≥ 5 kops/s                          | pending |
| `ecdsa-p256/sign`      | ≥ 3 kops/s                          | pending |
| `ecdsa-p384/sign`      | ≥ 1.5 kops/s                        | pending |
| `bls12-381/sign`       | ≥ 1 kops/s (pairing-dominated)      | pending |
| `bls12-381/verify`     | ≥ 500 ops/s                         | pending |
| `bls12-381/verify-agg` | ≥ 300 aggregate-verifications/s (n=64) | pending |

---

## tpt-crypto-zk

| Benchmark              | Target                              | Status  |
| ---------------------- | ----------------------------------- | ------- |
| `bulletproofs/prove/1` | ≥ 1 proof/s for 32-bit range proof  | pending |
| `bulletproofs/verify/1`| ≥ 10 verifications/s for 32-bit     | pending |
| `pedersen/commit`      | ≥ 100 kops/s                        | pending |
| `plonk/verify/n=4`     | ≥ 500 verifications/s (IPA opening) | pending |

---

## tpt-crypto-mpc

| Benchmark                    | Target                              | Status  |
| ---------------------------- | ----------------------------------- | ------- |
| `beaver/multiply`            | ≥ 50 kTriples/s                      | pending |
| `iknp/ot-extend/1M`          | ≥ 10 kOTs/s                         | pending |
| `reconstruct/field-element`  | ≤ 2× field multiply cost             | pending |

---

## Status key

- **pending** — benchmark scaffold exists, target not yet validated
- **on-track** — measured within 10% of target
- **met** — measured within target
- **missed** — measured >10% below target (blocking release)

## Notes

- All throughput targets assume `RUSTFLAGS="-C target-cpu=native"` in release mode.
- Embeded targets (`thumbv6m-none-eabi`) are measured in `no_std` mode; targets
  are expressed as absolute cycle counts in `benches/embedded/BUDGET.md`.
- `cargo xtask check` runs `bench-smoke` (compile-only); full benchmark runs
  are gated behind the `bench` CI job triggered on `main` weekly.
