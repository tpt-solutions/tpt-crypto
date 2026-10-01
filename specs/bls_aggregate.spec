spec bls_aggregate

description:
  BLS signature aggregation and aggregate verification over BLS12-381
  (draft-irtf-cfrg-bls-signature, minimal-pubkey-size: public keys in G1,
  signatures in G2, ciphersuite tag `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_`
  with a non-empty domain, i.e. the `NUL` scheme). Individual signatures are
  `sig_i = [sk_i] H(msg_i)`. `aggregate` sums a list of signature points in G2;
  `verify_aggregate` checks one product-of-pairings equation against the list
  of `(pk_i, msg_i)` pairs.

  Two modes:
   - distinct-message (`AggregateVerify`): the messages must be pairwise
     distinct; check `e(g1, sig_agg) == prod_i e(pk_i, H(msg_i))`.
   - same-message (`FastAggregateVerify`): all messages equal `msg`; check
     `e(g1, sig_agg) == e(aggregate_pk, H(msg))` where `aggregate_pk` is the
     G1 sum of the public keys, guarded by proof-of-possession to stop
     rogue-key attacks.

inputs:
  pks  : &[PublicKey]     // G1, subgroup-checked
  msgs : &[&[u8]]         // one per public key
  sig_agg : Signature     // G2, subgroup-checked

outputs:
  result : Result<(), Error>   // Ok(()) iff the aggregate is valid

assumes:
  - every `pk_i` is a valid, subgroup-order G1 point and not the identity
  - `sig_agg` is a valid, subgroup-order G2 point
  - distinct-message mode: `msgs` are pairwise distinct
  - same-message mode: each `pk_i` carries a verified proof-of-possession
  - `pks.len() == msgs.len()` and is non-zero

ensures:
  // soundness + completeness: the aggregate verifies exactly when it is the
  // honest aggregation of individually valid signatures on the given pairs
  result.is_ok()  <=>  exists sigs. ( sig_agg == sum_i sigs[i]
                                      && for all i. bls_verify(pks[i], msgs[i], sigs[i]) )
  // equivalently, the pairing product equation holds
  result.is_ok()  <=>  e(g1_gen, sig_agg) == prod_i e(pks[i], hash_to_g2(msgs[i]))
  // any single invalid or substituted component sig makes the whole check fail
  ( exists i. !bls_verify(pks[i], msgs[i], sigs[i]) )  =>  result.is_err()
  // rejects the degenerate cases
  ( any pk_i == identity || !in_subgroup(pk_i) || !in_subgroup(sig_agg) )  =>  result.is_err()
  ( distinct-message mode && msgs has a duplicate )                        =>  result.is_err()

non_leaks:
  - verification uses only public inputs (public keys, messages, signatures);
    it has no secret operands, so no constant-time obligation applies to
    `verify_aggregate` itself
  - subgroup checks use the endomorphism / cofactor method, not a variable-time
    order multiplication that could branch on point structure

verification:
  // BLS12-381 pairing and signatures are implemented; vectors:
  // draft-irtf-cfrg-bls-signature test vectors (AggregateVerify,
  // FastAggregateVerify), plus proptest bilinearity
  // `e([a]P, [b]Q) == e(P, Q)^{ab}` and:
  //   verify_aggregate(aggregate(sigs)) ok  iff  all individual verifies ok.

evidence:
  cargo-test: -p tpt-crypto-sig --test bls_kat kat_aggregate
  cargo-test: -p tpt-crypto-sig --test bls_kat kat_fast_aggregate_verify
  cargo-test: -p tpt-crypto-sig --test bls_props honest_round_trip_and_aggregate_iff_all_valid
  cargo-test: -p tpt-crypto-curve --test bls12_381 bilinearity
