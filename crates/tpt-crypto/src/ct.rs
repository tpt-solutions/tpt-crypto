//! Constant-time building blocks re-exported from `tpt-crypto-ct` so
//! downstream callers have a single, stable import path.

pub use tpt_crypto_ct::{
    cmov, cswap, ct_eq_bytes, ct_select_slice, Choice, CtSelect, CtEq,
};
