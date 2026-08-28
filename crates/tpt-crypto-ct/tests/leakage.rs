//! dudect-style leakage harness.
//!
//! Runs a two-class Welch t-test over the wall-clock (or cycle) cost of a
//! primitive, partitioning samples by a *secret-dependent* property. A
//! constant-time primitive has no dependence, so the t-statistic stays near
//! zero regardless of class. If timing tracks the secret, `|t|` grows and the
//! test fails.
//!
//! Invoked by `cargo xtask leakage` (which enables the `leakage` feature).
#![cfg(feature = "leakage")]

use std::hint::black_box;
use std::time::Instant;

use tpt_crypto_ct::choice::Choice;
use tpt_crypto_ct::cmp::ct_eq;
use tpt_crypto_ct::lookup::ct_lookup;
use tpt_crypto_ct::select::ct_select;

/// Accumulator for a two-class Welch t-test.
struct Welch {
    n0: f64,
    n1: f64,
    s0: f64,
    s1: f64,
    ss0: f64,
    ss1: f64,
}

impl Welch {
    fn new() -> Self {
        Welch {
            n0: 0.0,
            n1: 0.0,
            s0: 0.0,
            s1: 0.0,
            ss0: 0.0,
            ss1: 0.0,
        }
    }

    fn add(&mut self, class: u8, x: f64) {
        if class == 0 {
            self.n0 += 1.0;
            self.s0 += x;
            self.ss0 += x * x;
        } else {
            self.n1 += 1.0;
            self.s1 += x;
            self.ss1 += x * x;
        }
    }

    /// Welch's t statistic for the two classes.
    fn t(&self) -> f64 {
        if self.n0 < 2.0 || self.n1 < 2.0 {
            return 0.0;
        }
        let m0 = self.s0 / self.n0;
        let m1 = self.s1 / self.n1;
        let v0 = (self.ss0 - self.s0 * self.s0 / self.n0) / (self.n0 - 1.0);
        let v1 = (self.ss1 - self.s1 * self.s1 / self.n1) / (self.n1 - 1.0);
        let denom = (v0 / self.n0 + v1 / self.n1).sqrt();
        if denom == 0.0 {
            return 0.0;
        }
        (m1 - m0) / denom
    }
}

fn samples() -> usize {
    std::env::var("TPT_LEAKAGE_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000)
}

fn threshold() -> f64 {
    std::env::var("TPT_LEAKAGE_T")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10.0)
}

/// Measure the cost of `f` over `reps` repetitions, returning nanoseconds.
fn measure(reps: u32, mut f: impl FnMut()) -> f64 {
    // warm up to settle the pipeline / caches
    for _ in 0..reps / 4 {
        f();
    }
    let start = Instant::now();
    for _ in 0..reps {
        f();
    }
    let elapsed = start.elapsed().as_nanos() as f64;
    elapsed / (reps as f64)
}

#[test]
fn leakage_ct_select() {
    let reps = 64u32;
    let a = 0x1234_5678_9abc_def0u64;
    let b = 0xfedc_ba98_7654_3210u64;
    let mut w = Welch::new();
    for _ in 0..samples() {
        // class 0: choose b; class 1: choose a. The chosen value differs, but
        // the *timing* must be independent of `cond`.
        let class = (black_box(rand_u64()) & 1) as u8;
        let cond = Choice::from_u8_lsb(class);
        let t = measure(reps, || {
            let r = ct_select(cond, black_box(a), black_box(b));
            black_box(r);
        });
        w.add(class, t);
    }
    let t = w.t();
    println!(
        "leakage_ct_select: Welch t = {t:.3} (threshold {:.1})",
        threshold()
    );
    assert!(
        t.abs() < threshold(),
        "ct_select shows timing dependence on cond (t = {t:.3})"
    );
}

#[test]
fn leakage_ct_eq() {
    let reps = 64u32;
    let a = 0x1234_5678_9abc_def0u64;
    let mut w = Welch::new();
    for _ in 0..samples() {
        // class 0: equal inputs; class 1: differing inputs.
        let class = (black_box(rand_u64()) & 1) as u8;
        let b = if class == 0 { a } else { a ^ 0x1 };
        let t = measure(reps, || {
            let r = ct_eq(black_box(&a), black_box(&b));
            black_box(r);
        });
        w.add(class, t);
    }
    let t = w.t();
    println!(
        "leakage_ct_eq: Welch t = {t:.3} (threshold {:.1})",
        threshold()
    );
    assert!(
        t.abs() < threshold(),
        "ct_eq shows timing dependence on equality (t = {t:.3})"
    );
}

#[test]
fn leakage_ct_lookup() {
    let reps = 64u32;
    // A fixed window table; the index is secret.
    let table: Vec<u64> = (0..16u64)
        .map(|i| i.wrapping_mul(0x9e37_79b9_7f4a_7c15))
        .collect();
    let last = table.len() - 1;
    let mut w = Welch::new();
    for _ in 0..samples() {
        // class 0: index 0; class 1: index last.
        let class = (black_box(rand_u64()) & 1) as u8;
        let idx = if class == 0 { 0 } else { last };
        let t = measure(reps, || {
            let r = ct_lookup(black_box(&table), black_box(idx), 0u64);
            black_box(r);
        });
        w.add(class, t);
    }
    let t = w.t();
    println!(
        "leakage_ct_lookup: Welch t = {t:.3} (threshold {:.1})",
        threshold()
    );
    assert!(
        t.abs() < threshold(),
        "ct_lookup shows timing dependence on index (t = {t:.3})"
    );
}

/// Tiny xorshift PRNG so the harness has no external dependencies.
fn rand_u64() -> u64 {
    use std::cell::Cell;
    thread_local! {
        static S: Cell<u64> = const { Cell::new(0x1234_5678_9abc_def1) };
    }
    S.with(|s| {
        let mut x = s.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.set(x);
        x
    })
}
