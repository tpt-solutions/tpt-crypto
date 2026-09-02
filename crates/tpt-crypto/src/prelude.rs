//! The `tpt-crypto` prelude. Import everything you need for the common
//! constant-time, `no_std` workflow.
//!
//! ```
//! use tpt_crypto::prelude::*;
//! ```

pub use tpt_crypto_core::{
    ct_eq, ct_ne, ct_select, ConstantTimeSelect, CryptoRng, CtEq, Error, Result, SecretBox,
    Zeroizing,
};
pub use tpt_crypto_ct::{cmov, cswap, ct_eq_bytes, ct_select_slice, Choice, CtSelect};
