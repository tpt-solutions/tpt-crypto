spec aead_tag_verify

description:
  Authenticated decryption of an AEAD ciphertext. Given a key `k`, nonce `n`,
  associated data `ad`, ciphertext `c`, and a received authentication tag
  `tag`, the operation recomputes the expected tag over `(k, n, ad, c)` and
  releases the recovered plaintext if and only if the received tag matches the
  expected tag. On a mismatch it returns `Error::Verification` and no plaintext
  bytes are released to the caller (any in-place buffer is restored or zeroed).

  Covers `tpt-crypto-aead`: AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305, and
  XChaCha20-Poly1305, all routed through `api::Aead` and the shared
  `Tag::ct_eq` comparison (`tpt-crypto-ct::ct_eq_bytes`).

inputs:
  k   : Key           // secret
  n   : Nonce         // public (unique per key)
  ad  : &[u8]         // public associated data
  c   : &[u8]         // ciphertext, attacker-controlled
  tag : Tag           // received tag, attacker-controlled

outputs:
  result : Result<Plaintext, Error>   // Ok(m) iff tag valid, else Err(Verification)

assumes:
  - `n` is not reused with `k` for a non-misuse-resistant mode
  - `k` was produced by a CSPRNG

ensures:
  // functional: acceptance is exactly tag correctness
  result.is_ok()  <=>  tag == expected_tag(k, n, ad, c)
  result.is_ok()  =>   result.unwrap() == aead_decrypt(k, n, ad, c)
  // no partial release: on the error path the caller observes no plaintext
  result.is_err() =>   no_plaintext_bytes_released
  // side-channel contract: whether and where the tag differs must not be
  // observable through timing or memory-access patterns
  execution_trace ⟂ (tag, expected_tag, k)

non_leaks:
  - the tag comparison is a full-length constant-time `ct_eq`, never a
    byte-wise early-return `memcmp`
  - the accept/reject branch happens once, after the whole tag is compared,
    and its two arms take indistinguishable time up to the point plaintext is
    or is not handed back
  - GHASH / POLYVAL / Poly1305 evaluation is branch-free and not indexed by
    key or tag bits

verification:
  // discharged by tests/props.rs (rand-based): decrypt(encrypt(m)) == m and
  // every single-bit flip of ciphertext / tag / AAD yields Err(Verification)
  // for all six constructions; tag comparison constant-timeness is covered by
  // the -ct leakage harness over `ct_eq_bytes`.

evidence:
  cargo-test: -p tpt-crypto-aead --test props round_trip
  cargo-test: -p tpt-crypto-aead --test props bitflip
  cargo-test: -p tpt-crypto-ct --features leakage --test leakage leakage_ct_eq -- --test-threads=1
