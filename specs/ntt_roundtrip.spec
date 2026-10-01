spec ntt_roundtrip

description:
  The number-theoretic transform over the ML-KEM ring
  `R_q = Z_q[X]/(X^n + 1)` with `q = 3329`, `n = 256`. `ntt` maps a polynomial
  to its evaluation representation; `inv_ntt` is its exact inverse (including
  the `n^{-1} mod q` normalisation). Base multiplication in the NTT domain
  followed by `inv_ntt` computes the negacyclic convolution product of the two
  input polynomials.

  Covers `tpt-crypto-kem::poly` (compile-time unrolled butterflies, Montgomery
  reduction). All coefficient arithmetic is branch-free.

inputs:
  f : Poly   // coefficients in [0, q)
  g : Poly   // coefficients in [0, q)

outputs:
  // for the round-trip law:
  f_rt : Poly   // inv_ntt(ntt(f))
  // for the convolution law:
  h    : Poly   // inv_ntt(base_mul(ntt(f), ntt(g)))

assumes:
  - inputs are canonical (each coefficient already reduced mod q)

ensures:
  // exact inverse
  inv_ntt(ntt(f)) == f
  ntt(inv_ntt(f))  == f
  // linearity
  ntt(f + g) == ntt(f) + ntt(g)
  // negacyclic convolution: multiplication in R_q via the transform
  h == f * g  in  Z_q[X]/(X^n + 1)
  // outputs canonical
  all_coeffs_in_range(f_rt, 0, q)  &&  all_coeffs_in_range(h, 0, q)
  // constant-time: the transform structure is fixed; no data-dependent control
  execution_trace ⟂ (f, g)

non_leaks:
  - butterfly schedule and twiddle-factor indices are compile-time constants,
    never functions of coefficient values
  - Montgomery / Barrett reduction is branch-free (no conditional subtract on a
    secret)
  - iteration counts depend only on `n`, not on the data

verification:
  // tests/props.rs: inv_ntt(ntt(p)) == p over random polynomials, and
  // schoolbook negacyclic convolution matches base_mul-then-inv_ntt.

evidence:
  cargo-test: -p tpt-crypto-kem --lib ntt_mul_matches_schoolbook
