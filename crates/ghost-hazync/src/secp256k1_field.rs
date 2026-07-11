//! Phase 3 M2 (foundation) — secp256k1 **base-field** arithmetic in-circuit.
//!
//! The cost centre of script validation is verifying signatures over
//! **secp256k1**, whose base field `Fp = 2^256 − 2^32 − 977` is not the native
//! (Pallas/Vesta) field the circuit arithmetises over. So every EC operation is
//! *non-native* (foreign-field) arithmetic — emulated over the native field.
//!
//! This module wires secp256k1's modulus into the vendored [`crate::nonnative`]
//! BigNat gadget (bellman-bignat, MIT — nova ships it but keeps it crate-private,
//! so it is vendored under `src/nonnative/`). It provides `mul_mod`/`add_mod`
//! over `Fp`, the primitives the EC point operations (M2 cont.) and ECDSA verify
//! (M3) are built from. `4 × 64-bit` limbs (256-bit) fit the Pallas capacity with
//! room for BigNat's carried intermediates.

use crate::nonnative::bignat::BigNat;
use ff::PrimeField;
use nova_snark::frontend::{ConstraintSystem, SynthesisError};
use num_bigint::BigInt;

pub const LIMB_WIDTH: usize = 64;
pub const N_LIMBS: usize = 4;

/// The secp256k1 base-field prime `p = 2^256 − 2^32 − 977`.
pub fn secp256k1_p() -> BigInt {
    (BigInt::from(1) << 256u32) - (BigInt::from(1) << 32u32) - BigInt::from(977)
}

/// Allocate a base-field element from a value-closure, range-checked to
/// `4 × 64-bit` limbs (well-formed). The closure returns `AssignmentMissing`
/// during shape synthesis; the value should already be reduced mod p.
pub fn alloc_fp_from<Scalar, CS, F>(mut cs: CS, f: F) -> Result<BigNat<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
    F: FnOnce() -> Result<BigInt, SynthesisError>,
{
    let n = BigNat::alloc_from_nat(cs.namespace(|| "limbs"), f, LIMB_WIDTH, N_LIMBS)?;
    n.assert_well_formed(cs.namespace(|| "well_formed"))?;
    Ok(n)
}

/// Allocate a base-field element from a concrete (reduced) integer value.
pub fn alloc_fp<Scalar, CS>(cs: CS, value: BigInt) -> Result<BigNat<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    alloc_fp_from(cs, || Ok(value))
}

/// Enforce two reduced field elements equal.
pub fn enforce_equal<Scalar, CS>(
    cs: CS,
    a: &BigNat<Scalar>,
    b: &BigNat<Scalar>,
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    a.equal_when_carried_regroup(cs, b)
}

/// `z = (x − y) mod p`. Witnesses the difference and constrains `z + y ≡ x`.
pub fn sub_mod<Scalar, CS>(
    mut cs: CS,
    x: &BigNat<Scalar>,
    y: &BigNat<Scalar>,
) -> Result<BigNat<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let diff = alloc_fp_from(cs.namespace(|| "diff"), || {
        let p = secp256k1_p();
        let xv = x.value.clone().ok_or(SynthesisError::AssignmentMissing)?;
        let yv = y.value.clone().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(((xv - yv) % &p + &p) % &p)
    })?;
    let check = add_mod(cs.namespace(|| "diff+y"), &diff, y)?;
    enforce_equal(cs.namespace(|| "diff+y==x"), &check, x)?;
    Ok(diff)
}

/// `z = x⁻¹ mod p`. Witnesses the inverse (Fermat: `x^(p−2)`) and constrains
/// `x · z ≡ 1`. (x must be non-zero — a zero input makes this unsatisfiable.)
pub fn inverse<Scalar, CS>(mut cs: CS, x: &BigNat<Scalar>) -> Result<BigNat<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let inv = alloc_fp_from(cs.namespace(|| "inv"), || {
        let p = secp256k1_p();
        let xv = x.value.clone().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(xv.modpow(&(&p - BigInt::from(2)), &p))
    })?;
    let prod = mul_mod(cs.namespace(|| "x*inv"), x, &inv)?;
    let one = alloc_fp(cs.namespace(|| "one"), BigInt::from(1))?;
    enforce_equal(cs.namespace(|| "x*inv==1"), &prod, &one)?;
    Ok(inv)
}

/// `z = (x / y) mod p = x · y⁻¹`.
pub fn div_mod<Scalar, CS>(
    mut cs: CS,
    x: &BigNat<Scalar>,
    y: &BigNat<Scalar>,
) -> Result<BigNat<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let yinv = inverse(cs.namespace(|| "yinv"), y)?;
    mul_mod(cs.namespace(|| "x*yinv"), x, &yinv)
}

/// The modulus `p` as a BigNat (allocated in `cs`).
pub fn modulus<Scalar, CS>(cs: CS) -> Result<BigNat<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    alloc_fp(cs, secp256k1_p())
}

/// `z = x · y mod p`.
pub fn mul_mod<Scalar, CS>(
    mut cs: CS,
    x: &BigNat<Scalar>,
    y: &BigNat<Scalar>,
) -> Result<BigNat<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let p = modulus(cs.namespace(|| "p"))?;
    let (_quotient, remainder) = x.mult_mod(cs.namespace(|| "mult_mod"), y, &p)?;
    Ok(remainder)
}

/// `z = (x + y) mod p`.
pub fn add_mod<Scalar, CS>(
    mut cs: CS,
    x: &BigNat<Scalar>,
    y: &BigNat<Scalar>,
) -> Result<BigNat<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let p = modulus(cs.namespace(|| "p"))?;
    let sum = x.add(y)?; // un-reduced (may exceed p)
    sum.red_mod(cs.namespace(|| "reduce"), &p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_cs::TestConstraintSystem;
    use nova_snark::provider::PallasEngine;
    use nova_snark::traits::Engine;

    type Scalar = <PallasEngine as Engine>::Scalar;

    fn bn(hex_str: &str) -> BigInt {
        BigInt::parse_bytes(hex_str.as_bytes(), 16).unwrap()
    }

    // secp256k1 generator coordinates — two genuine 256-bit field elements.
    fn gx() -> BigInt {
        bn("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    }
    fn gy() -> BigInt {
        bn("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    }

    #[test]
    fn mul_mod_matches_native_and_is_satisfied() {
        let p = secp256k1_p();
        let x = gx();
        let y = gy();
        let expected = (&x * &y) % &p;

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let xn = alloc_fp(cs.namespace(|| "x"), x).unwrap();
        let yn = alloc_fp(cs.namespace(|| "y"), y).unwrap();
        let z = mul_mod(cs.namespace(|| "z"), &xn, &yn).unwrap();

        assert_eq!(z.value, Some(expected), "x*y mod p value must match native");
        assert!(cs.is_satisfied(), "mul_mod constraints must be satisfied: {:?}", cs.which_is_unsatisfied());
    }

    #[test]
    fn add_mod_matches_native() {
        let p = secp256k1_p();
        // Pick two large elements whose sum exceeds p to exercise the reduction.
        let x = &p - BigInt::from(3);
        let y = &p - BigInt::from(5);
        let expected = (&x + &y) % &p;

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let xn = alloc_fp(cs.namespace(|| "x"), x).unwrap();
        let yn = alloc_fp(cs.namespace(|| "y"), y).unwrap();
        let z = add_mod(cs.namespace(|| "z"), &xn, &yn).unwrap();

        assert_eq!(z.value, Some(expected), "(x+y) mod p value must match native");
        assert!(cs.is_satisfied(), "add_mod constraints must be satisfied: {:?}", cs.which_is_unsatisfied());
    }

    // Soundness: pinning the product to the WRONG value must make the system
    // unsatisfiable — proves mul_mod actually constrains the result (not just
    // that its witness closure computes the right number).
    #[test]
    fn mul_mod_binds_result_rejects_wrong() {
        let p = secp256k1_p();
        let x = gx();
        let y = gy();
        let wrong = ((&x * &y) % &p) + BigInt::from(1);

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let xn = alloc_fp(cs.namespace(|| "x"), x).unwrap();
        let yn = alloc_fp(cs.namespace(|| "y"), y).unwrap();
        let z = mul_mod(cs.namespace(|| "z"), &xn, &yn).unwrap();
        let wrong_n = alloc_fp(cs.namespace(|| "wrong"), wrong).unwrap();
        z.equal_when_carried_regroup(cs.namespace(|| "z==wrong"), &wrong_n).unwrap();

        assert!(!cs.is_satisfied(), "binding the product to a wrong value must be unsatisfiable");
    }
}
