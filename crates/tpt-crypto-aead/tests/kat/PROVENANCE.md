# AES-GCM-SIV KAT vectors — PROVENANCE

## `rfc8452.txt` — RFC 8452 Appendix C, VERIFIED

Full encrypt-direction known-answer corpus for AES-GCM-SIV.

- Source: <https://www.rfc-editor.org/rfc/rfc8452.txt> Appendix C
  (C.1 `AEAD_AES_128_GCM_SIV`, C.2 `AEAD_AES_256_GCM_SIV`, C.3 counter-wrap
  tests) — distilled 2026-10-03 from the plain-text RFC.
- License: IETF/RFC text — freely reproducible (RFC 8452 is distributed under
  the IETF Trust License; the test vectors are data).
- Distillation: all 50 vectors as flat `key = value` records (`key`/`nonce`/
  `aad`/`pt`/`ct`/`tag`); `ct` is the RFC's `Result` minus the trailing
  16-byte tag. Page-break artefacts in the RFC text were merged so every
  record is one vector.

**Implementation bug these vectors exposed and fixed (2026-10-03):**

The POLYVAL hash key was computed as `H = E(K_mac, 0^16)` (the GCM GHASH
convention). RFC 8452 §4 instead uses the raw derived message-authentication
key as the POLYVAL key — `POLYVAL(key = message_authentication_key, ...)` —
with no AES call. The old inline "C.1 KAT" only covered the empty-plaintext
vector, where `S = dot(0, H) = 0` never touches `H`, so the wrong key was
invisible: every non-empty message encrypted to a different (self-consistent)
ciphertext and tag than the standard. After the fix all 50 Appendix C vectors
pass in both directions (encrypt byte-equality + decrypt round trip).

Checksums (sha256, relative to `crates/tpt-crypto-aead/tests/kat/`):

| File | Sha256 |
| --- | --- |
| `rfc8452.txt` | `4297e1ea82fd764e3d05bb9fd54f0addfca9121e14790cac2cb553068609ccad` |
