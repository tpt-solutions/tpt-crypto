#![allow(missing_docs)]

//! Test-only PLONK prover + circuit + polynomial helpers.
//!
//! The shipped crate is verifier-only (`tpt-telos` owns proving); this module
//! exists so the verifier can be validated end-to-end (completeness, soundness
//! negatives, and the committed KAT fixture).

use tpt_crypto_field::CtEq;
use tpt_crypto_hash::{sha3::Shake256, Xof};
use tpt_crypto_zk::plonk::{commit_poly, powers_of, PlonkGens, Proof, VerifyingKey};
use tpt_crypto_zk::{Ed25519Scalar as S, InnerProductProof, Transcript};

// --- polynomial helpers ------------------------------------------------------

/// Horner evaluation.
pub fn poly_eval(c: &[S], x: &S) -> S {
    let mut acc = S::zero();
    for coeff in c.iter().rev() {
        acc = acc.mul(x).add(coeff);
    }
    acc
}

/// Schoolbook product.
pub fn poly_mul(a: &[S], b: &[S]) -> Vec<S> {
    let mut out = vec![S::zero(); a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        for (j, &bj) in b.iter().enumerate() {
            out[i + j] = out[i + j].add(&ai.mul(&bj));
        }
    }
    out
}

pub fn poly_add(a: &[S], b: &[S]) -> Vec<S> {
    let mut out = vec![S::zero(); a.len().max(b.len())];
    for (i, &ai) in a.iter().enumerate() {
        out[i] = out[i].add(&ai);
    }
    for (i, &bi) in b.iter().enumerate() {
        out[i] = out[i].add(&bi);
    }
    out
}

pub fn poly_scale(a: &[S], s: &S) -> Vec<S> {
    a.iter().map(|x| x.mul(s)).collect()
}

/// Pad/truncate to exactly `n` coefficients.
pub fn poly_fix(a: &[S], n: usize) -> Vec<S> {
    let mut out = vec![S::zero(); n];
    for (i, &ai) in a.iter().enumerate().take(n) {
        out[i] = ai;
    }
    out
}

/// Interpolate values on `H = <omega>` (index `i` ↔ point `omega^i`) into
/// coefficient form via Lagrange: `L_i(X) = (omega^i/n)·Σ_k omega^{ik}X^{n−1−k}`.
pub fn interpolate(vals: &[S], omega: &S, n: usize) -> Vec<S> {
    let n_inv = S::from_u64(n as u64).invert().unwrap();
    let mut out = vec![S::zero(); n];
    let mut w_i = S::one();
    for &v in vals.iter().take(n) {
        let scale = w_i.mul(&n_inv).mul(&v);
        let mut wk = S::one();
        for k in 0..n {
            out[n - 1 - k] = out[n - 1 - k].add(&scale.mul(&wk));
            wk = wk.mul(&w_i);
        }
        w_i = w_i.mul(omega);
    }
    out
}

/// Divide `f` by `Z_H = X^n − 1`, returning the quotient padded to `3n`;
/// asserts the remainder is zero (so the quotient identity is exact).
pub fn div_by_vanishing(f: &[S], n: usize) -> Vec<S> {
    let mut q = vec![S::zero(); f.len()];
    // F[j] = Q[j−n] − Q[j] for j ≥ n; solve from the top.
    for j in (n..f.len()).rev() {
        q[j - n] = f[j].add(&q[j]);
    }
    for j in 0..n {
        let r = f[j].add(&q[j]);
        assert!(r.ct_eq(&S::zero()).into_bool(), "nonzero remainder");
    }
    poly_fix(&q, 3 * n)
}

/// `omega^i` by repeated multiplication.
pub fn pow_omega(omega: &S, i: usize) -> S {
    let mut acc = S::one();
    for _ in 0..i {
        acc = acc.mul(omega);
    }
    acc
}

// --- circuit ------------------------------------------------------------------

/// A filled-in PLONK circuit instance (verifier-key material + the witness
/// assignment the test prover proves knowledge of).
pub struct TestCircuit {
    pub n: usize,
    pub k1: S,
    pub k2: S,
    pub omega: S,
    pub q_l: Vec<S>,
    pub q_r: Vec<S>,
    pub q_o: Vec<S>,
    pub q_m: Vec<S>,
    pub q_c: Vec<S>,
    /// a/b/c witness rows (length `n`).
    pub a: Vec<S>,
    pub b: Vec<S>,
    pub c: Vec<S>,
    /// For each wire (0=a, 1=b, 2=c) and row, the σ tag value
    /// `k_{col of representative}·omega^{row of representative}`.
    pub sigma: [Vec<S>; 3],
}

/// The classic tutorial circuit: knowledge of `x` with `x³ + x + 5 = 35`
/// (35 is baked into `q_c`, so the vk fixes the public input).
///
/// Rows: `c = x·x`, `c = c·x`, `c = c + x`, `c = c + 5`, `a = 35` (public-input
/// check), then zero padding up to `n = 8`.
pub fn tutorial_circuit(x: u64) -> TestCircuit {
    // The Ed25519 scalar field has 2-adicity 2, so the domain is n = 4 (the
    // tutorial circuit fits: the "+5" is folded into the public constant).
    let n = 4usize;
    let omega = VerifyingKey::root_of_unity(n).expect("omega");
    // Identity-tag cosets: k1, k2 must satisfy k^4 ≠ 1 (outside H) and
    // (k2/k1)^4 ≠ 1 (distinct cosets).
    let k1 = S::from_u64(2);
    let k2 = S::from_u64(3);
    let four = pow_omega(&S::one(), 0);
    let _ = four;
    assert!(!pow_omega(&k1, n).ct_eq(&S::one()).into_bool(), "k1 ∈ H");
    assert!(!pow_omega(&k2, n).ct_eq(&S::one()).into_bool(), "k2 ∈ H");
    let ratio = k2.mul(&k1.invert().unwrap());
    assert!(
        !pow_omega(&ratio, n).ct_eq(&S::one()).into_bool(),
        "k1·H == k2·H"
    );

    let zero = S::zero();
    let one = S::one();
    let thirty = S::from_u64(30);
    let thirty_five = S::from_u64(35);

    let xv = S::from_u64(x);
    let x2 = xv.mul(&xv);
    let x3 = x2.mul(&xv);
    let x3px = x3.add(&xv);
    // x³ + x + 5 = 35 ⟺ x³ + x = 30.
    assert!(
        x3px.ct_eq(&thirty_five.sub(&S::from_u64(5))).into_bool(),
        "witness invalid"
    );

    let mut q_l = vec![zero; n];
    let mut q_r = vec![zero; n];
    let mut q_o = vec![zero; n];
    let mut q_m = vec![zero; n];
    let mut q_c = vec![zero; n];
    // row0: x·x − c = 0
    q_m[0] = one;
    q_o[0] = one.neg();
    // row1: x²·x − c = 0
    q_m[1] = one;
    q_o[1] = one.neg();
    // row2: a + b − c = 0   (c = x³ + x)
    q_l[2] = one;
    q_r[2] = one;
    q_o[2] = one.neg();
    // row3: a − 30 = 0 (public check: x³ + x + 5 = 35 ⟺ x³ + x = 30; the
    // "+5" of the tutorial expression is folded into this constant).
    q_l[3] = one;
    q_c[3] = thirty.neg();

    let mut a = vec![zero; n];
    let mut b = vec![zero; n];
    let mut c = vec![zero; n];
    a[0] = xv;
    b[0] = xv;
    c[0] = x2;
    a[1] = x2;
    b[1] = xv;
    c[1] = x3;
    a[2] = x3;
    b[2] = xv;
    c[2] = x3px;
    a[3] = x3px;

    // Copy classes: slot = col*n + row. The σ map is the *cycle successor*
    // permutation of each class (wire → next wire in the class, last → first),
    // so σ is a bijection on all 3n slots — that is what makes the grand
    // product cycle close.
    //   x    : a0 → b0 → b1 → b2 → a0
    //   x²   : c0 → a1 → c0
    //   x³   : c1 → a2 → c1
    //   x³+x : c2 → a3 → c2
    //   every other slot: fixed point.
    let mut sigma_succ: Vec<(usize, usize)> = (0..3)
        .flat_map(|col| (0..n).map(move |row| (col, row)))
        .collect();
    let cycle = |succ: &mut Vec<(usize, usize)>, slots: &[(usize, usize)]| {
        for (i, &(sc, sr)) in slots.iter().enumerate() {
            let (nc, nr) = slots[(i + 1) % slots.len()];
            succ[sc * n + sr] = (nc, nr);
        }
    };
    cycle(&mut sigma_succ, &[(0, 0), (1, 0), (1, 1), (1, 2)]);
    cycle(&mut sigma_succ, &[(2, 0), (0, 1)]);
    cycle(&mut sigma_succ, &[(2, 1), (0, 2)]);
    cycle(&mut sigma_succ, &[(2, 2), (0, 3)]);

    // σ tag values: k-of-successor-col times omega^successor-row
    // (col a → 1, col b → k1, col c → k2).
    let k_of = |col: usize| match col {
        0 => one,
        1 => k1,
        _ => k2,
    };
    let mut sigma = [vec![zero; n], vec![zero; n], vec![zero; n]];
    for col in 0..3 {
        for row in 0..n {
            let (nc, nr) = sigma_succ[col * n + row];
            sigma[col][row] = k_of(nc).mul(&pow_omega(&omega, nr));
        }
    }

    TestCircuit {
        n,
        k1,
        k2,
        omega,
        q_l,
        q_r,
        q_o,
        q_m,
        q_c,
        a,
        b,
        c,
        sigma,
    }
}

// --- prover ------------------------------------------------------------------

struct Blinds {
    a: S,
    b: S,
    c: S,
    z: S,
    t_lo: S,
    t_mid: S,
    t_hi: S,
}

/// Derive deterministic blinding factors from a seed (KAT reproducibility).
fn blinds_from_seed(seed: u64) -> Blinds {
    let next = |ctr: u64| {
        let mut buf = [0u8; 64];
        let mut sh = Shake256::new();
        sh.update(b"tpt-crypto-zk.plonk.blind");
        sh.update(&seed.to_le_bytes());
        sh.update(&ctr.to_le_bytes());
        sh.squeeze(&mut buf);
        scalar_from_wide(&buf)
    };
    Blinds {
        a: next(1),
        b: next(2),
        c: next(3),
        z: next(4),
        t_lo: next(5),
        t_mid: next(6),
        t_hi: next(7),
    }
}

fn scalar_from_wide(buf: &[u8; 64]) -> S {
    let mut acc = S::zero();
    let two64 = S::from_u64(2).pow_vartime(&[64]);
    let mut p = S::one();
    for i in 0..8 {
        let mut limb = 0u64;
        for j in 0..8 {
            limb |= (buf[i * 8 + j] as u64) << (8 * j);
        }
        acc = acc.add(&S::from_u64(limb).mul(&p));
        p = p.mul(&two64);
    }
    acc
}

/// Verifying key for a circuit: blinding-free commitments to the selector
/// and permutation polynomials. Usable without any witness (`setup`).
pub fn setup(circ: &TestCircuit) -> VerifyingKey {
    let n = circ.n;
    let gens = PlonkGens::new(n);
    let ql_poly = interpolate(&circ.q_l, &circ.omega, n);
    let qr_poly = interpolate(&circ.q_r, &circ.omega, n);
    let qo_poly = interpolate(&circ.q_o, &circ.omega, n);
    let qm_poly = interpolate(&circ.q_m, &circ.omega, n);
    let qc_poly = interpolate(&circ.q_c, &circ.omega, n);
    let s1_poly = interpolate(&circ.sigma[0], &circ.omega, n);
    let s2_poly = interpolate(&circ.sigma[1], &circ.omega, n);
    let s3_poly = interpolate(&circ.sigma[2], &circ.omega, n);
    VerifyingKey {
        n,
        k1: circ.k1,
        k2: circ.k2,
        q_l: commit_poly(&gens, &ql_poly, &S::zero()),
        q_r: commit_poly(&gens, &qr_poly, &S::zero()),
        q_o: commit_poly(&gens, &qo_poly, &S::zero()),
        q_m: commit_poly(&gens, &qm_poly, &S::zero()),
        q_c: commit_poly(&gens, &qc_poly, &S::zero()),
        sigma_1: commit_poly(&gens, &s1_poly, &S::zero()),
        sigma_2: commit_poly(&gens, &s2_poly, &S::zero()),
        sigma_3: commit_poly(&gens, &s3_poly, &S::zero()),
    }
}

/// Run the full PLONK round structure and produce a proof for `circuit`.
/// The transcript sequence mirrors `VerifyingKey::verify` exactly.
pub fn prove(circ: &TestCircuit, seed: u64) -> (VerifyingKey, Proof) {
    let n = circ.n;
    let gens = PlonkGens::new(n);
    let bl = blinds_from_seed(seed);

    // Interpolate all polynomials over H.
    let a_poly = interpolate(&circ.a, &circ.omega, n);
    let b_poly = interpolate(&circ.b, &circ.omega, n);
    let c_poly = interpolate(&circ.c, &circ.omega, n);
    let ql_poly = interpolate(&circ.q_l, &circ.omega, n);
    let qr_poly = interpolate(&circ.q_r, &circ.omega, n);
    let qo_poly = interpolate(&circ.q_o, &circ.omega, n);
    let qm_poly = interpolate(&circ.q_m, &circ.omega, n);
    let qc_poly = interpolate(&circ.q_c, &circ.omega, n);
    let s1_poly = interpolate(&circ.sigma[0], &circ.omega, n);
    let s2_poly = interpolate(&circ.sigma[1], &circ.omega, n);
    let s3_poly = interpolate(&circ.sigma[2], &circ.omega, n);

    // Sanity: the gate must vanish on every row of H.
    for i in 0..n {
        let pt = pow_omega(&circ.omega, i);
        let g = poly_eval(&ql_poly, &pt)
            .mul(&poly_eval(&a_poly, &pt))
            .add(&poly_eval(&qr_poly, &pt).mul(&poly_eval(&b_poly, &pt)))
            .add(&poly_eval(&qo_poly, &pt).mul(&poly_eval(&c_poly, &pt)))
            .add(
                &poly_eval(&qm_poly, &pt)
                    .mul(&poly_eval(&a_poly, &pt))
                    .mul(&poly_eval(&b_poly, &pt)),
            )
            .add(&poly_eval(&qc_poly, &pt));
        assert!(g.ct_eq(&S::zero()).into_bool(), "gate row {i} unsatisfied");
    }

    // Verifying key (blinding-free commitments to the fixed polynomials).
    let vk = setup(circ);

    let mut t = Transcript::new(b"PLONK");
    t.append_message(b"n", &(n as u64).to_le_bytes());
    t.append_scalar(b"k1", &vk.k1);
    t.append_scalar(b"k2", &vk.k2);
    t.append_message(b"[ql]", &vk.q_l.compress());
    t.append_message(b"[qr]", &vk.q_r.compress());
    t.append_message(b"[qo]", &vk.q_o.compress());
    t.append_message(b"[qm]", &vk.q_m.compress());
    t.append_message(b"[qc]", &vk.q_c.compress());
    t.append_message(b"[s1]", &vk.sigma_1.compress());
    t.append_message(b"[s2]", &vk.sigma_2.compress());
    t.append_message(b"[s3]", &vk.sigma_3.compress());
    let beta = t.challenge_scalar(b"beta");
    let gamma = t.challenge_scalar(b"gamma");

    let a_cm = commit_poly(&gens, &a_poly, &bl.a);
    let b_cm = commit_poly(&gens, &b_poly, &bl.b);
    let c_cm = commit_poly(&gens, &c_poly, &bl.c);
    t.append_message(b"[a]", &a_cm.compress());
    t.append_message(b"[b]", &b_cm.compress());
    t.append_message(b"[c]", &c_cm.compress());

    // Grand product over H (cyclic: z_n must close back to 1).
    let mut z_vals = vec![S::zero(); n];
    z_vals[0] = S::one();
    for i in 0..n {
        let w = pow_omega(&circ.omega, i);
        let av = poly_eval(&a_poly, &w);
        let bv = poly_eval(&b_poly, &w);
        let cv = poly_eval(&c_poly, &w);
        let s1v = poly_eval(&s1_poly, &w);
        let s2v = poly_eval(&s2_poly, &w);
        let s3v = poly_eval(&s3_poly, &w);
        let num = av
            .add(&beta.mul(&w))
            .add(&gamma)
            .mul(&bv.add(&beta.mul(&circ.k1).mul(&w)).add(&gamma))
            .mul(&cv.add(&beta.mul(&circ.k2).mul(&w)).add(&gamma));
        let den = av
            .add(&beta.mul(&s1v))
            .add(&gamma)
            .mul(&bv.add(&beta.mul(&s2v)).add(&gamma))
            .mul(&cv.add(&beta.mul(&s3v)).add(&gamma));
        z_vals[(i + 1) % n] = z_vals[i].mul(&num).mul(&den.invert().unwrap());
    }
    assert!(
        z_vals[0].ct_eq(&S::one()).into_bool(),
        "grand product cycle broken (inconsistent copies)"
    );
    let z_poly = interpolate(&z_vals, &circ.omega, n);
    let z_cm = commit_poly(&gens, &z_poly, &bl.z);
    t.append_message(b"[z]", &z_cm.compress());
    let alpha = t.challenge_scalar(b"alpha");

    // Quotient: F = gate + α(num − den) + α²·init,  t = F / (Xⁿ − 1).
    let gamma_v = [gamma];
    let num1 = poly_add(&poly_add(&a_poly, &[S::zero(), beta]), &gamma_v);
    let num2 = poly_add(
        &poly_add(&b_poly, &[S::zero(), beta.mul(&circ.k1)]),
        &gamma_v,
    );
    let num3 = poly_add(
        &poly_add(&c_poly, &[S::zero(), beta.mul(&circ.k2)]),
        &gamma_v,
    );
    let num = poly_mul(&poly_mul(&poly_mul(&num1, &num2), &num3), &z_poly);

    let den1 = poly_add(&poly_add(&a_poly, &poly_scale(&s1_poly, &beta)), &gamma_v);
    let den2 = poly_add(&poly_add(&b_poly, &poly_scale(&s2_poly, &beta)), &gamma_v);
    let den3 = poly_add(&poly_add(&c_poly, &poly_scale(&s3_poly, &beta)), &gamma_v);
    let z_omega_poly: Vec<S> = (0..n)
        .map(|i| z_poly[i].mul(&pow_omega(&circ.omega, i)))
        .collect();
    let den = poly_mul(&poly_mul(&poly_mul(&den1, &den2), &den3), &z_omega_poly);

    // L₁(X) = (1/n)(X^{n−1} + X^{n−2} + … + 1).
    let n_inv = S::from_u64(n as u64).invert().unwrap();
    let l1 = vec![n_inv; n];
    let init = poly_mul(&poly_add(&z_poly, &[S::one().neg()]), &l1);

    let gate = {
        let t1 = poly_mul(&ql_poly, &a_poly);
        let t2 = poly_mul(&qr_poly, &b_poly);
        let t3 = poly_mul(&qo_poly, &c_poly);
        let t4 = poly_mul(&qm_poly, &poly_mul(&a_poly, &b_poly));
        poly_add(
            &poly_add(&poly_add(&t1, &t2), &poly_add(&t3, &t4)),
            &qc_poly,
        )
    };
    let alpha_sq = alpha.mul(&alpha);
    let f = poly_add(
        &poly_add(
            &gate,
            &poly_scale(&poly_add(&num, &poly_scale(&den, &S::one().neg())), &alpha),
        ),
        &poly_scale(&init, &alpha_sq),
    );
    let t_full = div_by_vanishing(&f, n);
    let t_lo = poly_fix(&t_full[0..n], n);
    let t_mid = poly_fix(&t_full[n..2 * n], n);
    let t_hi = poly_fix(&t_full[2 * n..3 * n], n);

    let t_lo_cm = commit_poly(&gens, &t_lo, &bl.t_lo);
    let t_mid_cm = commit_poly(&gens, &t_mid, &bl.t_mid);
    let t_hi_cm = commit_poly(&gens, &t_hi, &bl.t_hi);
    t.append_message(b"[t_lo]", &t_lo_cm.compress());
    t.append_message(b"[t_mid]", &t_mid_cm.compress());
    t.append_message(b"[t_hi]", &t_hi_cm.compress());
    let zeta = t.challenge_scalar(b"zeta");

    // Round-4 evaluations.
    let eval = |p: &[S]| poly_eval(p, &zeta);
    let omega_zeta = circ.omega.mul(&zeta);
    let z_omega_eval = poly_eval(&z_poly, &omega_zeta);
    let evals = [
        eval(&a_poly),
        eval(&b_poly),
        eval(&c_poly),
        eval(&ql_poly),
        eval(&qr_poly),
        eval(&qo_poly),
        eval(&qm_poly),
        eval(&qc_poly),
        eval(&s1_poly),
        eval(&s2_poly),
        eval(&s3_poly),
        eval(&z_poly),
        z_omega_eval,
        eval(&t_lo),
        eval(&t_mid),
        eval(&t_hi),
    ];
    for e in &evals {
        t.append_scalar(b"e", e);
    }

    let v = t.challenge_scalar(b"v");

    // ζ-batch: 15 polynomials (order matches the verifier's).
    let polys = [
        &a_poly, &b_poly, &c_poly, &z_poly, &ql_poly, &qr_poly, &qo_poly, &qm_poly, &qc_poly,
        &s1_poly, &s2_poly, &s3_poly, &t_lo, &t_mid, &t_hi,
    ];
    let poly_blinds = [
        bl.a,
        bl.b,
        bl.c,
        bl.z,
        S::zero(),
        S::zero(),
        S::zero(),
        S::zero(),
        S::zero(),
        S::zero(),
        S::zero(),
        S::zero(),
        bl.t_lo,
        bl.t_mid,
        bl.t_hi,
    ];
    let mut batch = vec![S::zero(); n];
    let mut r_blind = S::zero();
    let mut v_pow = S::one();
    for (p, r) in polys.iter().zip(poly_blinds.iter()) {
        for (bi, pi) in batch.iter_mut().zip(p.iter()) {
            *bi = bi.add(&v_pow.mul(pi));
        }
        r_blind = r_blind.add(&v_pow.mul(r));
        v_pow = v_pow.mul(&v);
    }

    t.append_scalar(b"r_blind", &r_blind);
    let ones = vec![S::one(); n];
    let zeros = vec![S::zero(); n];
    let ipp_zeta = InnerProductProof::create(
        &mut t,
        &gens.h,
        &ones,
        &zeros,
        gens.g.clone(),
        gens.g.clone(),
        batch,
        powers_of(&zeta, n),
    );

    // The [z]-at-ωζ opening must reveal the *commitment's* blinding: the
    // verifier forms C_z − z_blind·H₀ and needs it to be exactly <z, G>.
    let z_blind = bl.z;
    t.append_scalar(b"z_blind", &z_blind);
    let ipp_z_omega = InnerProductProof::create(
        &mut t,
        &gens.h,
        &ones,
        &zeros,
        gens.g.clone(),
        gens.g.clone(),
        z_poly,
        powers_of(&omega_zeta, n),
    );

    (
        vk,
        Proof {
            a: a_cm.compress(),
            b: b_cm.compress(),
            c: c_cm.compress(),
            z: z_cm.compress(),
            t_lo: t_lo_cm.compress(),
            t_mid: t_mid_cm.compress(),
            t_hi: t_hi_cm.compress(),
            a_eval: evals[0],
            b_eval: evals[1],
            c_eval: evals[2],
            ql_eval: evals[3],
            qr_eval: evals[4],
            qo_eval: evals[5],
            qm_eval: evals[6],
            qc_eval: evals[7],
            s1_eval: evals[8],
            s2_eval: evals[9],
            s3_eval: evals[10],
            z_eval: evals[11],
            z_omega_eval: evals[12],
            t_lo_eval: evals[13],
            t_mid_eval: evals[14],
            t_hi_eval: evals[15],
            r_blind,
            ipp_zeta,
            z_blind,
            ipp_z_omega,
        },
    )
}
