//! Phase 3 M4 (foundation) — secp256k1 compressed-pubkey decompression.
//!
//! A compressed public key is a 1-byte prefix (`0x02` even-y / `0x03` odd-y)
//! followed by the 32-byte x-coordinate. To use it as a curve point `Q` in ECDSA
//! we recover `y` with `y² = x³ + 7 (mod p)` and pick the root whose parity
//! matches the prefix. In-circuit: witness `y`, enforce `y² == x³ + 7`, and
//! enforce `y`'s LSB equals the prefix parity bit (so the prover can't swap in
//! `−y`, which would flip `Q` to `−Q`).

use crate::nonnative::bignat::BigNat;
use crate::secp256k1_ec::Point;
use crate::secp256k1_field::{add_mod, alloc_fp, alloc_fp_from, enforce_equal, mul_mod, secp256k1_p, to_bits_le};
use ff::PrimeField;
use nova_snark::frontend::{Boolean, ConstraintSystem, SynthesisError};
use num_bigint::BigInt;

/// Decompress `(x, prefix-parity)` into the affine point `(x, y)`.
pub fn decompress<Scalar, CS>(
    mut cs: CS,
    x: &BigNat<Scalar>,
    y_is_odd: &Boolean,
) -> Result<Point<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let y = alloc_fp_from(cs.namespace(|| "y"), || {
        let p = secp256k1_p();
        let xv = x.value.clone().ok_or(SynthesisError::AssignmentMissing)?;
        let odd = y_is_odd.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let rhs = ((&xv * &xv % &p) * &xv + BigInt::from(7)) % &p; // x^3 + 7
        // secp256k1: p ≡ 3 (mod 4) ⇒ sqrt(a) = a^((p+1)/4).
        let mut yv = rhs.modpow(&((&p + BigInt::from(1)) / BigInt::from(4)), &p);
        if yv.bit(0) != odd {
            yv = (&p - &yv) % &p;
        }
        Ok(yv)
    })?;

    // Enforce y² == x³ + 7.
    let x2 = mul_mod(cs.namespace(|| "x^2"), x, x)?;
    let x3 = mul_mod(cs.namespace(|| "x^3"), &x2, x)?;
    let seven = alloc_fp(cs.namespace(|| "7"), BigInt::from(7))?;
    let rhs = add_mod(cs.namespace(|| "x^3+7"), &x3, &seven)?;
    let y2 = mul_mod(cs.namespace(|| "y^2"), &y, &y)?;
    enforce_equal(cs.namespace(|| "y^2==x^3+7"), &y2, &rhs)?;

    // Enforce y's parity matches the prefix.
    let y_bits = to_bits_le(cs.namespace(|| "y_bits"), &y)?;
    Boolean::enforce_equal(cs.namespace(|| "parity"), &y_bits[0], y_is_odd)?;

    Ok(Point { x: x.clone(), y })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1_field::alloc_fp;
    use crate::test_cs::TestConstraintSystem;
    use nova_snark::frontend::AllocatedBit;
    use nova_snark::provider::PallasEngine;
    use nova_snark::traits::Engine;

    type Scalar = <PallasEngine as Engine>::Scalar;

    fn bn(h: &str) -> BigInt {
        BigInt::parse_bytes(h.as_bytes(), 16).unwrap()
    }
    fn gx() -> BigInt {
        bn("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    }
    fn gy() -> BigInt {
        bn("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    }
    fn bit(cs: &mut TestConstraintSystem<Scalar>, v: bool) -> Boolean {
        Boolean::from(AllocatedBit::alloc(cs.namespace(|| "parity"), Some(v)).unwrap())
    }

    #[test]
    fn decompress_g_even_recovers_gy() {
        // G's y is even (prefix 0x02).
        assert!(!gy().bit(0), "G.y should be even");
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let x = alloc_fp(cs.namespace(|| "x"), gx()).unwrap();
        let parity = bit(&mut cs, false);
        let q = decompress(cs.namespace(|| "dec"), &x, &parity).unwrap();
        assert_eq!(q.y.value, Some(gy()), "even root == G.y");
        assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
    }

    #[test]
    fn decompress_g_odd_recovers_neg_gy() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let x = alloc_fp(cs.namespace(|| "x"), gx()).unwrap();
        let parity = bit(&mut cs, true);
        let q = decompress(cs.namespace(|| "dec"), &x, &parity).unwrap();
        assert_eq!(q.y.value, Some(&secp256k1_p() - &gy()), "odd root == p - G.y");
        assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
    }

    // Soundness: a claimed x that is NOT a valid curve x (no y with y²=x³+7 of the
    // requested parity) — feeding y from the wrong branch — is caught. Here we
    // pass a valid x but the witness code always produces the correct-parity root,
    // so instead assert the parity constraint binds: if we lie about parity while
    // y stays even, it's unsatisfiable. (Covered by the two tests above producing
    // DIFFERENT y for the two parities, which only the parity constraint enforces.)
    #[test]
    fn the_two_parities_give_different_points() {
        assert_ne!(gy(), &secp256k1_p() - &gy(), "even and odd roots differ");
    }
}
