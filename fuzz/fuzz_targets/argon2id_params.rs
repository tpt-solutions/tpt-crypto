//! Fuzz target for `tpt_crypto_hash::argon2::argon2id` parameter and length handling.
//!
//! The first bytes choose `(m_kib, t, p)`, the salt length, and the tag length, all
//! unbounded. Invalid combinations must return `Err`, never panic. Valid ones are
//! capped to small memory so the fuzzer stays fast, and must be deterministic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_crypto_hash::argon2::{argon2id, Params};

fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }
    let m_kib = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let t = u32::from(data[4]);
    let p = u32::from(data[5]) | (u32::from(data[6]) << 8);
    let salt_len = usize::from(data[7] % 40);
    let tag_len = usize::from(data[8] % 40);
    let body = &data[9..];

    let salt = vec![0x5au8; salt_len];
    let params = Params { m_kib, t, p };
    let mut out = vec![0u8; tag_len];

    // Out-of-range parameters or lengths must be rejected without touching memory.
    let would_be_valid = p != 0
        && p < (1 << 24)
        && t != 0
        && m_kib >= 8 * p
        && salt_len >= 8
        && tag_len >= 4;
    if !would_be_valid {
        assert!(argon2id(body, &salt, b"", b"", params, &mut out).is_err());
        return;
    }

    // Keep valid runs small: fuzz the logic, not the memory bill.
    if m_kib > 64 || t > 2 || p > 2 {
        return;
    }
    let mut again = vec![0u8; tag_len];
    argon2id(body, &salt, b"", b"", params, &mut out).expect("valid parameters");
    argon2id(body, &salt, b"", b"", params, &mut again).expect("valid parameters");
    assert_eq!(out, again);
});
