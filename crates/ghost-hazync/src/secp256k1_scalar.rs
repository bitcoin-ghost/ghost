//! Phase 3 M3 (foundation) — secp256k1 **scalar-field** arithmetic (mod the group
//! order `n`), for ECDSA's `u1 = z·s⁻¹`, `u2 = r·s⁻¹`.
//!
//! ECDSA mixes two moduli: point coordinates live mod the base field `p`
//! ([`crate::secp256k1_field`]), but the signature scalars `r, s` and the
//! derived `u1, u2` live mod the group order
//! `n = 0xFFFF…BAAEDCE6AF48A03BBFD25E8CD0364141`. This module provides
//! `mul_mod`/`add_mod`/`inverse` mod `n`, reusing the same BigNat machinery and
//! the field module's allocation helpers — only the modulus differs.

use crate::nonnative::bignat::BigNat;
use crate::secp256k1_field::{alloc_fp, alloc_fp_from, const_bignat, enforce_equal};
use ff::PrimeField;
use nova_snark::frontend::{ConstraintSystem, SynthesisError};
use num_bigint::BigInt;

/// The secp256k1 group order `n`.
pub fn secp256k1_n() -> BigInt {
    BigInt::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap()
}

/// `z = x · y mod n`.
pub fn mul_mod<Scalar, CS>(
    mut cs: CS,
    x: &BigNat<Scalar>,
    y: &BigNat<Scalar>,
) -> Result<BigNat<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let n = const_bignat::<Scalar, CS>(secp256k1_n());
    let (_q, r) = x.mult_mod(cs.namespace(|| "mult_mod"), y, &n)?;
    Ok(r)
}

/// `z = (x + y) mod n`.
pub fn add_mod<Scalar, CS>(
    mut cs: CS,
    x: &BigNat<Scalar>,
    y: &BigNat<Scalar>,
) -> Result<BigNat<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let n = const_bignat::<Scalar, CS>(secp256k1_n());
    let sum = x.add(y)?;
    sum.red_mod(cs.namespace(|| "reduce"), &n)
}

/// `z = x⁻¹ mod n` (Fermat: `x^(n−2)`), constrained by `x · z ≡ 1 (mod n)`.
pub fn inverse<Scalar, CS>(mut cs: CS, x: &BigNat<Scalar>) -> Result<BigNat<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let inv = alloc_fp_from(cs.namespace(|| "inv"), || {
        let n = secp256k1_n();
        let xv = x.value.clone().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(xv.modpow(&(&n - BigInt::from(2)), &n))
    })?;
    let prod = mul_mod(cs.namespace(|| "x*inv"), x, &inv)?;
    let one = alloc_fp(cs.namespace(|| "one"), BigInt::from(1))?;
    enforce_equal(cs.namespace(|| "x*inv==1"), &prod, &one)?;
    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1_field::alloc_fp;
    use crate::test_cs::TestConstraintSystem;
    use nova_snark::provider::PallasEngine;
    use nova_snark::traits::Engine;

    type Scalar = <PallasEngine as Engine>::Scalar;

    fn bn(h: &str) -> BigInt {
        BigInt::parse_bytes(h.as_bytes(), 16).unwrap()
    }

    #[test]
    fn mul_mod_n_matches_native() {
        let n = secp256k1_n();
        let x = bn("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let y = bn("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
        let expected = (&x * &y) % &n;

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let xn = alloc_fp(cs.namespace(|| "x"), x % &n).unwrap();
        let yn = alloc_fp(cs.namespace(|| "y"), y % &n).unwrap();
        let z = mul_mod(cs.namespace(|| "z"), &xn, &yn).unwrap();
        assert_eq!(z.value, Some(expected), "x*y mod n");
        assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
    }

    #[test]
    fn inverse_n_times_x_is_one() {
        let n = secp256k1_n();
        let x = bn("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8") % &n;

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let xn = alloc_fp(cs.namespace(|| "x"), x.clone()).unwrap();
        let inv = inverse(cs.namespace(|| "inv"), &xn).unwrap();
        let expected_inv = x.modpow(&(&n - BigInt::from(2)), &n);
        assert_eq!(inv.value, Some(expected_inv), "x^-1 mod n");
        assert!(cs.is_satisfied(), "unsat (x*inv==1 must hold): {:?}", cs.which_is_unsatisfied());
    }
}
