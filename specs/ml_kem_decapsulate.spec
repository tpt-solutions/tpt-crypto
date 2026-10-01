spec ml_kem_decapsulate

description:
  ML-KEM (FIPS 203) decapsulation. Given a decapsulation key `dk` and a
  ciphertext `c`, the operation returns a 32-byte shared secret `ss`. On a
  valid ciphertext `ss` equals the value the encapsulator derived; on an
  invalid or tampered ciphertext the operation performs *implicit rejection* —
  it returns a pseudorandom secret `J(z, c)` derived from the secret rejection
  seed `z`, never an error and never a distinguishable code path.

  Covers `tpt-crypto-kem::ml_kem` for ML-KEM-512 / 768 / 1024. Decapsulation
  re-derives `s_hat` from the stored seed, runs K-PKE decrypt, re-encrypts
  under the decrypted message, and constant-time-selects between the real
  shared secret and the rejection secret on the re-encryption equality check.

inputs:
  dk : DecapsulationKey   // secret (contains s, z, and the public key)
  c  : &[u8]              // ciphertext, attacker-controlled, length fixed per param set

outputs:
  ss : [u8; 32]          // shared secret (always returned)

assumes:
  - `dk` was produced by `ml_kem::keygen` with a CSPRNG
  - `c.len()` is the fixed ciphertext length for the parameter set

ensures:
  // functional correctness for honest ciphertexts
  c == encapsulate(ek, m).ciphertext  =>  ss == encapsulate(ek, m).shared_secret
  // implicit rejection: malformed / tampered ciphertext still yields a value,
  // pseudorandom and bound to both the secret seed and the ciphertext
  reencrypt(decrypt(dk, c)) != c      =>  ss == J(dk.z, c)
  // total function: no panic, no error, for any byte string of the right length
  always_returns_32_bytes
  // side-channel contract: the trace is independent of the secret key and of
  // whether implicit rejection fired
  execution_trace ⟂ (dk, reject_flag)

non_leaks:
  - the real-vs-rejection choice is a single `ct_select` over the 32-byte
    secrets, driven by a `ct_eq` of the re-encrypted ciphertext; no `if`
  - K-PKE decrypt (NTT, base-mul, compress/decompress, decode) is branch-free
    and never indexed by secret coefficients
  - CBD sampling and the re-encryption path run to completion regardless of
    validity; no early exit on a decode or range check

verification:
  // tests/props.rs: decapsulate(dk, encapsulate(ek).ciphertext) recovers the
  // shared secret for 512/768/1024; a tampered ciphertext takes the implicit-
  // reject path (no panic, value differs, still 32 bytes). Timing independence
  // discharged structurally plus the underlying -ct / -field leakage harness.
  // ACVP known-answer vectors still pending.

evidence:
  cargo-test: -p tpt-crypto-kem --test props round_trip
  cargo-test: -p tpt-crypto-kem --test props malformed_no_panic
  cargo-test: -p tpt-crypto-kem --test ml_kem_kat kat_ml_kem
