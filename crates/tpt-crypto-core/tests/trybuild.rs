//! Compile-fail tests asserting that [`SecretBox`] implements none of the leaky
//! traits. If any of these start compiling, the secret-handling contract has
//! regressed.

#[test]
fn secret_box_rejects_leaky_traits() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/trybuild/*.rs");
}
