//! Concrete prime-field parameters.
//!
//! Each struct implements [`FieldParams`] by giving the modulus (padded to
//! [`MAX_LIMBS`] little-endian limbs), the limb count, and the exponent `S` of
//! `p - 1`; the remaining Montgomery constants are derived at compile time by the
//! [`FieldElement`] impl.

use crate::consts::MAX_LIMBS;
use crate::field::{FieldElement, FieldParams};

macro_rules! declare_params {
    ($name:ident, $limbs:literal, $modulus:expr) => {
        /// Prime field parameters.
        #[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
        pub struct $name;

        impl FieldParams for $name {
            const LIMBS: usize = $limbs;
            const MODULUS: [u64; MAX_LIMBS] = $modulus;
            const S: u32 = crate::consts::s_of(&Self::MODULUS);
            // Montgomery constants are derived at compile time from the modulus so
            // there is a single source of truth (no hand-computed literals that can
            // disagree between `ONE_MONT`, `R2`, and `MU`).
            const ONE_MONT: [u64; MAX_LIMBS] = crate::consts::one_mont_of(&Self::MODULUS, $limbs);
            const R2: [u64; MAX_LIMBS] = crate::consts::r2_of(&Self::MODULUS, $limbs);
            const MU: u64 = crate::consts::mu_of(&Self::MODULUS);
        }
    };
}

declare_params!(
    P256BaseParams,
    4,
    [
        0xFFFF_FFFF_FFFF_FFFF,
        0x0000_0000_FFFF_FFFF,
        0x0000_0000_0000_0000,
        0xFFFF_FFFF_0000_0001,
        0,
        0,
    ]
);

declare_params!(
    P256ScalarParams,
    4,
    [
        0xF3B9_CAC2_FC63_2551,
        0xBCE6_FAAD_A717_9E84,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_0000_0000,
        0,
        0,
    ]
);

declare_params!(
    P384BaseParams,
    6,
    [
        0x0000_0000_FFFF_FFFF,
        0xFFFF_FFFF_0000_0000,
        0xFFFF_FFFF_FFFF_FFFE,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ]
);

declare_params!(
    P384ScalarParams,
    6,
    [
        0xECEC_196A_CCC5_2973,
        0x581A_0DB2_48B0_A77A,
        0xC763_4D81_F437_2DDF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
    ]
);

declare_params!(
    Bls12381FpParams,
    6,
    [
        0xb9fe_ffff_ffff_aaab,
        0x1eab_fffe_b153_ffff,
        0x6730_d2a0_f6b0_f624,
        0x6477_4b84_f385_12bf,
        0x4b1b_a7b6_434b_acd7,
        0x1a01_11ea_397f_e69a,
    ]
);

declare_params!(
    Bls12381FrParams,
    4,
    [
        0xffff_ffff_0000_0001,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
        0,
        0,
    ]
);

// Ed25519 base field: p = 2^255 - 19 (little-endian limbs).
declare_params!(
    Ed25519FieldParams,
    4,
    [
        0xFFFF_FFFF_FFFF_FFED,
        0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF,
        0x7FFF_FFFF_FFFF_FFFF,
        0,
        0,
    ]
);

// Ed25519 scalar field: L = 2^252 + 27742317777372353535851937790883648493.
// Little-endian limbs of L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed.
declare_params!(
    Ed25519ScalarParams,
    4,
    [
        0xEDD3_F55C_1A63_1258,
        0x14DE_F9DE_A2F7_9CD6,
        0x0000_0000_0000_0000,
        0x1000_0000_0000_0000,
        0,
        0,
    ]
);

/// NIST P-256 base field `GF(p)`.
pub type P256Base = FieldElement<P256BaseParams>;
/// NIST P-256 scalar field `GF(n)`.
pub type P256Scalar = FieldElement<P256ScalarParams>;
/// NIST P-384 base field `GF(p)`.
pub type P384Base = FieldElement<P384BaseParams>;
/// NIST P-384 scalar field `GF(n)`.
pub type P384Scalar = FieldElement<P384ScalarParams>;
/// BLS12-381 base field `GF(p)`.
pub type Bls12381Fp = FieldElement<Bls12381FpParams>;
/// BLS12-381 scalar field `GF(r)`.
pub type Bls12381Fr = FieldElement<Bls12381FrParams>;
/// Ed25519 base field `GF(2^255 - 19)`.
pub type Ed25519Field = FieldElement<Ed25519FieldParams>;
/// Ed25519 scalar field `GF(L)` (the prime-order subgroup scalar field).
pub type Ed25519Scalar = FieldElement<Ed25519ScalarParams>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modulus_nonzero_and_odd() {
        assert_eq!(P256BaseParams::MODULUS[0] & 1, 1);
        assert_eq!(P384BaseParams::MODULUS[0] & 1, 1);
        assert_eq!(Bls12381FpParams::MODULUS[0] & 1, 1);
        assert_eq!(Bls12381FrParams::MODULUS[0] & 1, 1);
    }

    #[test]
    fn s_exponent_sanity() {
        // P-256 and P-384 are 3 mod 4 -> S == 1.
        assert_eq!(P256BaseParams::S, 1);
        assert_eq!(P384BaseParams::S, 1);
        // BLS Fp is 3 mod 4 -> S == 1.
        assert_eq!(Bls12381FpParams::S, 1);
        // BLS Fr is 1 mod 4 with S == 32.
        assert_eq!(Bls12381FrParams::S, 32);
    }
}

