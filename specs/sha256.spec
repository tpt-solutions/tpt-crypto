spec sha256

description:
  SHA-256 (FIPS 180-4), the Merkle–Damgård construction over the 64-round
  32-bit compression function. Observed here through its streaming contract:
  any sequence of `update` calls followed by `finalize` yields the same digest
  as the one-shot `sha256` free function applied to the concatenation of the
  updates.

inputs:
   message : bytes          // arbitrary length, up to 2^64 - 1 bits
   chunking : list<bytes>   // any partition of `message`

outputs:
   digest : [u8; 32]

assumes:
   concat(chunking) == message

ensures:
   // streaming equivalence
   fold(Sha256::new(), chunking, update).finalize() == sha256(message)
   // reference correctness against the FIPS 180-4 / NIST CAVP vectors
   sha256(message) == FIPS_180_4_SHA256(message)
   // fixed trace: hashing never branches or indexes on message content
   execution_trace ⟂ message_values

non_leaks:
   - no conditional branch whose target depends on message byte values
   - no memory access whose address depends on message byte values
   - padding length arithmetic depends only on the (public) message length

verification:
   // discharged by NIST CAVP known-answer vectors (empty, "abc") in
   // `tests/kat.rs` and by the `sha256_streaming` / `sha512_streaming`
   // property tests in `tests/props.rs` (random chunkings of random inputs).

evidence:
  cargo-test: -p tpt-crypto-hash --test kat sha2_
  cargo-test: -p tpt-crypto-hash --test props sha256_streaming
  cargo-test: -p tpt-crypto-hash --test props sha512_streaming
