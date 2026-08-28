//! Branch-free table lookup: [`ct_lookup`].
//!
//! Window-based scalar multiplication (in `-curve`) needs to pick an entry
//! from a precomputed table using a secret index. A naive `table[index]` both
//! branches on the index and performs a secret-dependent memory access. This
//! module performs the selection by linear scan, accepting every entry into
//! the running result only when its position equals the target index — the
//! access pattern is independent of the index.

use crate::select::{ct_eq_usize, CtSelect};

/// Constant-time selection of `table[index]`, or `default` if `index` is out
/// of bounds.
///
/// Scans the whole table and `ct_select`s each element in when its position
/// equals `index`. The number of iterations and the memory access pattern do
/// not depend on `index`, so the trace is independent of the secret.
#[inline]
#[must_use]
pub fn ct_lookup<T: Copy + CtSelect>(table: &[T], index: usize, default: T) -> T {
    let mut out = default;
    for (i, item) in table.iter().enumerate() {
        let eq = ct_eq_usize(i, index);
        out = T::ct_select(eq, *item, out);
    }
    out
}

/// Constant-time selection of a contiguous limb-window from a flat table.
///
/// `table` is a concatenation of `rows` × `width` limbs; returns row `index`
/// into `out` (length `width`). If `index` is out of range, `out` is left
/// untouched (caller supplies a safe default beforehand).
#[inline]
pub fn ct_lookup_limbs(table: &[crate::Limb], index: usize, width: usize, out: &mut [crate::Limb]) {
    let rows = table.len() / width;
    for r in 0..rows {
        let eq = ct_eq_usize(r, index);
        for c in 0..width {
            let src = table.get(r * width + c).copied().unwrap_or(0);
            let cur = out.get(c).copied().unwrap_or(0);
            out[c] = crate::Limb::ct_select(eq, src, cur);
        }
    }
}

/// Constant-time selection of a single byte from a byte table.
#[inline]
#[must_use]
pub fn ct_lookup_bytes(table: &[u8], index: usize, default: u8) -> u8 {
    ct_lookup(table, index, default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_in_range() {
        let t = [10u64, 20, 30, 40];
        for (i, want) in t.iter().enumerate() {
            assert_eq!(ct_lookup(&t, i, 0), *want);
        }
    }

    #[test]
    fn lookup_out_of_range() {
        let t = [10u64, 20, 30];
        assert_eq!(ct_lookup(&t, 99, 77), 77);
    }

    #[test]
    fn lookup_limbs() {
        // two rows of width 2
        let table = [1u64, 2, 3, 4];
        let mut out = [0u64; 2];
        ct_lookup_limbs(&table, 1, 2, &mut out);
        assert_eq!(out, [3, 4]);
        ct_lookup_limbs(&table, 0, 2, &mut out);
        assert_eq!(out, [1, 2]);
    }
}
