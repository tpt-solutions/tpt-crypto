//! Binary-level constant-time probes (todo V3).
//!
//! Each `probe_*` function is a `#[no_mangle]` wrapper around one constant-time
//! primitive. `cargo xtask ct-asm` compiles this file to assembly in release mode
//! and checks that no `probe_*` function contains a conditional jump, that is, no
//! secret-dependent branch in the emitted code.
//!
//! The probes are only compiled to assembly. They are not called here, and the
//! test harness does not run them.

#![allow(dead_code)]

use tpt_crypto_ct::{cswap, ct_eq, ct_ne, ct_select, Choice};

#[no_mangle]
pub extern "C" fn probe_ct_select_u8(c: u8, a: u8, b: u8) -> u8 {
    ct_select(Choice::from_u8_lsb(c), a, b)
}

#[no_mangle]
pub extern "C" fn probe_ct_select_u16(c: u8, a: u16, b: u16) -> u16 {
    ct_select(Choice::from_u8_lsb(c), a, b)
}

#[no_mangle]
pub extern "C" fn probe_ct_select_u64(c: u8, a: u64, b: u64) -> u64 {
    ct_select(Choice::from_u8_lsb(c), a, b)
}

#[no_mangle]
pub extern "C" fn probe_cswap_u64(c: u8, a: &mut u64, b: &mut u64) {
    cswap(Choice::from_u8_lsb(c), a, b)
}

#[no_mangle]
pub extern "C" fn probe_ct_eq_u8(a: u8, b: u8) -> u8 {
    ct_eq(&a, &b).unwrap_u8()
}

#[no_mangle]
pub extern "C" fn probe_ct_eq_u64(a: u64, b: u64) -> u8 {
    ct_eq(&a, &b).unwrap_u8()
}

#[no_mangle]
pub extern "C" fn probe_ct_ne_u64(a: u64, b: u64) -> u8 {
    ct_ne(&a, &b).unwrap_u8()
}
