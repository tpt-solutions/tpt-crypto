# ML-KEM KAT vectors — PROVENANCE

## Status: UNVERIFIED — DO NOT TRUST

`ml_kem_512.kat`, `ml_kem_768.kat`, `ml_kem_1024.kat` were committed in
`b9f910c` with **no recorded source, URL, license, or checksum**, which
violates the workspace rule (see `AGENTS.md`: "New primitives need KAT vectors +
`PROVENANCE.md`" with "source URL, license, sha256 of each vector file").

An attempt to validate them against a FIPS 203-conformant implementation
(`G = SHA3-512(d ‖ ⟨k⟩)`, `H = SHA3-256`, `J = SHAKE256`) failed at the first
field: the `ρ` prefix of the expected `pk` matches no standard `G` construction
of the vector's `d` seed, and the last 32 bytes of the expected `pk` are byte
-for-byte equal to `SHA3-512(d ‖ 0x02)[0..32]` — a signature of a broken
generator leaking hash output into key material.

**These files are almost certainly not genuine NIST/ACVP vectors.** No test in
this crate consumes them. They are kept only pending a decision to replace them
with real vectors from:

- NIST ACVP: <https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files>
  (`ML-KEM-*` folders), or
- the FIPS 203 reference `intermediate values` /
  <https://github.com/post-quantum-cryptography/KAT>.

When real vectors are added, record here: the exact source URL, its licence, and
`sha256sum` of each `.kat` file, and wire `tests/ml_kem_kat.rs` (removed in this
pass) back in.
