# Constant-time guarantees

This page says what tpt-crypto claims about timing and side channels, what
backs each claim, and what is not checked. Read it before you rely on the library
for secrets.

## What is claimed

- **No secret-dependent branches or memory indices** in the constant-time
  layer (`tpt-crypto-ct`) and the primitives built on it. Secret-dependent
  selection goes through `ct_select`, `ct_eq`, `cmov`, `cswap` and `ct_lookup`.
- **Tag and signature comparison is constant-time.** `Tag` has no `PartialEq`, so a
  timing-leaking `==` cannot be written by accident.
- **Secret scalars and seeds are zeroed on drop** (`SecretBox`, `Zeroizing`).
- **Public-input checks are not treated as secret oracles.** For example, a
  ciphertext of the wrong length is rejected by length alone.

These are design rules. Where a claim is not yet checked by a tool, this page says so.

## What backs the claims

| Mechanism | What it shows | Where |
| --- | --- | --- |
| Source review against the rules above | Intent | `AGENTS.md`, `specs/*.spec` |
| Welch t-test harness (dudect-style) | Statistical timing differences between two secret classes, on the machine it runs on | `cargo xtask leakage` (`tpt-crypto-ct/tests/leakage.rs`) |
| Miri on the constant-time layer | No undefined behaviour in the `unsafe` cmov/csel path | `cargo +nightly miri test -p tpt-crypto-ct` |
| Known-answer vectors | Correct outputs, not timing | `tests/kat/` per crate, `cargo xtask kat-check` |
| Property tests | Algebraic laws across random inputs | `proptest` in most crates |
| Specs bound to evidence | Each claimed property names the test that backs it | `specs/*.spec`, `cargo xtask verify` |

The `unsafe` code is confined to `tpt-crypto-ct`. Each block has a `// SAFETY:`
comment, and the reasoning is in `SECURITY.md`.

## What is not claimed

- **No external audit.** The library has not been reviewed by an independent
  cryptographer or a side-channel lab.
- **No binary-level check.** The planned `cargo xtask ct-asm` (todo V3) would
  inspect release builds for secret-dependent jumps. It is not implemented, so
  the compiler could still turn a branch-free source into one.
- **Statistical timing tests are not proofs.** A Welch test with a finite number
  of samples can miss a leak, and results depend on the CPU, the frequency
  governor and the load. Treat a pass as evidence, not as absence of leakage.
- **No power, electromagnetic or fault-injection resistance.** These are out of
  scope (`SECURITY.md`).
- **No formal verification.** Exhaustive bounded-domain checks, Kani, Cryptol and
  Verus are planned (todo V1, V2, V5). None is in place today.
- **Other crates are less thoroughly checked.** The leakage harness covers the
  constant-time layer. Field, curve and signature code rely on the design rules
  and the test suites, not on a timing harness of their own.

## What you should do

- Use the high-level recipes (`easy`, `hpke`, `xwing`) where they fit. They keep
  the secret-handling paths in one place.
- Keep secrets in `SecretBox` or `Zeroizing`, and avoid copying them into
  ordinary buffers.
- Do not branch on a secret in your own code. Use `ct_select` or the `Choice` type.
- Run `cargo xtask leakage` on the hardware you deploy on. Its results depend on it.
- Read the open items in `todo.md` (V1–V5) before you assume a property holds
  beyond what the tests show.
