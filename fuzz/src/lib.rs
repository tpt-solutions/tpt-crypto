//! Fuzzing harness for `tpt-crypto` attacker-controlled decoders.
//!
//! Each `fuzz_targets/*.rs` file is a `libfuzzer` target (see `cargo-fuzz`).
//! The crate itself carries no code; `fuzz_target!` macros in the targets
//! generate the harness binaries.
