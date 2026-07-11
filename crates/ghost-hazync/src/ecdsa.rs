//! Phase 3 M3 — ECDSA (secp256k1) verification assembly.
//!
//! Given a message hash `z` (the BIP143 sighash from M1), a signature `(r, s)`,
//! and a public key `Q`, ECDSA accepts iff:
//!
//! ```text
//! s⁻¹ = s^{-1} mod n
//! u1  = z·s⁻¹ mod n,   u2 = r·s⁻¹ mod n
//! R   = u1·G + u2·Q            (G = secp256k1 generator)
//! accept  ⇔  R.x mod n == r
//! ```
//!
//! Every primitive here is built and individually tested elsewhere in this crate:
//! scalar arithmetic mod n ([`crate::secp256k1_scalar`]), point add/double/select
//! and `scalar_mul` ([`crate::secp256k1_ec`]), base-field reduction
//! ([`crate::secp256k1_field`]). This module supplies the ECDSA-specific glue:
//!
//! * [`derive_u1_u2`] — the scalar step (`s⁻¹`, `u1`, `u2`), and
//! * [`enforce_rx_equals_r`] — the final acceptance check (`R.x mod n == r`).
//!
//! [`verify`] wires them together with the two `scalar_mul`s and the point add.
//! Its two 256-bit scalar multiplications make the *monolithic* circuit ~1–2M
//! constraints — beyond the in-memory test CS — so it is validated by its tested
//! constituents here and exercised end-to-end when folded into a spend step (M4)
//! under the real Nova prover. The scalar glue and the final check below ARE
//! directly tested.

use crate::nonnative::bignat::BigNat;
use crate::secp256k1_ec::{point_add, scalar_mul, Point};
use crate::secp256k1_field::{enforce_equal, to_bits_le};
use crate::secp256k1_scalar::{self, secp256k1_n};
use ff::PrimeField;
use nova_snark::frontend::{Boolean, ConstraintSystem, SynthesisError};

/// The scalar step: `s⁻¹`, then `u1 = z·s⁻¹ mod n` and `u2 = r·s⁻¹ mod n`.
pub fn derive_u1_u2<Scalar, CS>(
    mut cs: CS,
    z: &BigNat<Scalar>,
    r: &BigNat<Scalar>,
    s: &BigNat<Scalar>,
) -> Result<(BigNat<Scalar>, BigNat<Scalar>), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let s_inv = secp256k1_scalar::inverse(cs.namespace(|| "s_inv"), s)?;
    let u1 = secp256k1_scalar::mul_mod(cs.namespace(|| "u1"), z, &s_inv)?;
    let u2 = secp256k1_scalar::mul_mod(cs.namespace(|| "u2"), r, &s_inv)?;
    Ok((u1, u2))
}

/// Final acceptance: enforce `R.x mod n == r`. `rx` is `R`'s x-coordinate (a
/// base-field element, so possibly ≥ n); it is reduced mod n and compared to r.
pub fn enforce_rx_equals_r<Scalar, CS>(
    mut cs: CS,
    rx: &BigNat<Scalar>,
    r: &BigNat<Scalar>,
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let n = crate::secp256k1_field::alloc_fp(cs.namespace(|| "n"), secp256k1_n())?;
    let rx_mod_n = rx.red_mod(cs.namespace(|| "rx mod n"), &n)?;
    enforce_equal(cs.namespace(|| "rx mod n == r"), &rx_mod_n, r)
}

/// Full ECDSA verify: enforces the signature `(r, s)` is valid for hash `z` under
/// key `Q`. `u1_bits`/`u2_bits` are the (constrained) bit decompositions of u1/u2
/// most-significant-bit first, and `g` is the generator. See the module note on
/// why the monolithic form is prover-scale.
pub fn verify<Scalar, CS>(
    mut cs: CS,
    g: &Point<Scalar>,
    q: &Point<Scalar>,
    r: &BigNat<Scalar>,
    u1_bits: &[Boolean],
    u2_bits: &[Boolean],
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let p1 = scalar_mul(cs.namespace(|| "u1*G"), u1_bits, g)?;
    let p2 = scalar_mul(cs.namespace(|| "u2*Q"), u2_bits, q)?;
    let rpoint = point_add(cs.namespace(|| "u1G+u2Q"), &p1, &p2)?;
    enforce_rx_equals_r(cs.namespace(|| "R.x==r"), &rpoint.x, r)
}

/// Full ECDSA verification from `(z, r, s)` + key `Q`: derives `u1, u2`, decomposes
/// them to (MSB-first) scalar bits, and runs [`verify`]. This is the whole check
/// meant to run under the Nova prover (via a StepCircuit) — its two 256-bit
/// scalar multiplications are why it is prover-scale.
pub fn verify_full<Scalar, CS>(
    mut cs: CS,
    g: &Point<Scalar>,
    q: &Point<Scalar>,
    z: &BigNat<Scalar>,
    r: &BigNat<Scalar>,
    s: &BigNat<Scalar>,
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let (u1, u2) = derive_u1_u2(cs.namespace(|| "u1u2"), z, r, s)?;
    let mut u1_bits = to_bits_le(cs.namespace(|| "u1_bits"), &u1)?;
    u1_bits.reverse(); // to_bits_le is LSB-first; scalar_mul wants MSB-first
    let mut u2_bits = to_bits_le(cs.namespace(|| "u2_bits"), &u2)?;
    u2_bits.reverse();
    verify(cs.namespace(|| "verify"), g, q, r, &u1_bits, &u2_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1_field::alloc_fp;
    use crate::test_cs::TestConstraintSystem;
    use nova_snark::provider::PallasEngine;
    use nova_snark::traits::Engine;
    use num_bigint::BigInt;

    type Scalar = <PallasEngine as Engine>::Scalar;

    fn bn(h: &str) -> BigInt {
        BigInt::parse_bytes(h.as_bytes(), 16).unwrap()
    }

    #[test]
    fn derive_u1_u2_matches_native() {
        let n = secp256k1_n();
        // Arbitrary z, r, s in [1, n).
        let z = bn("9b2db89cb0e8fa3cc7608b4d6cc1dec0114e0b9ff4080bea12b134f489ab2bbc") % &n;
        let r = bn("2b2db89cb0e8fa3cc7608b4d6cc1dec0114e0b9ff4080bea12b134f489ab2bbc") % &n;
        let s = bn("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8") % &n;

        let s_inv = s.modpow(&(&n - BigInt::from(2)), &n);
        let exp_u1 = (&z * &s_inv) % &n;
        let exp_u2 = (&r * &s_inv) % &n;

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let zn = alloc_fp(cs.namespace(|| "z"), z).unwrap();
        let rn = alloc_fp(cs.namespace(|| "r"), r).unwrap();
        let sn = alloc_fp(cs.namespace(|| "s"), s).unwrap();
        let (u1, u2) = derive_u1_u2(cs.namespace(|| "u"), &zn, &rn, &sn).unwrap();

        assert_eq!(u1.value, Some(exp_u1), "u1 = z/s mod n");
        assert_eq!(u2.value, Some(exp_u2), "u2 = r/s mod n");
        assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
    }

    #[test]
    fn rx_equals_r_check() {
        let n = secp256k1_n();
        // rx a base-field coordinate ≥ n so the reduction is exercised.
        let rx = bn("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");
        let r = &rx % &n;

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let rxn = alloc_fp(cs.namespace(|| "rx"), rx.clone()).unwrap();
        let rn = alloc_fp(cs.namespace(|| "r"), r).unwrap();
        enforce_rx_equals_r(cs.namespace(|| "chk"), &rxn, &rn).unwrap();
        assert!(cs.is_satisfied(), "correct r must satisfy: {:?}", cs.which_is_unsatisfied());
    }

    #[test]
    fn rx_equals_r_rejects_wrong() {
        let n = secp256k1_n();
        let rx = bn("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");
        let wrong_r = (&rx % &n) + BigInt::from(1);

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let rxn = alloc_fp(cs.namespace(|| "rx"), rx).unwrap();
        let rn = alloc_fp(cs.namespace(|| "r"), wrong_r).unwrap();
        enforce_rx_equals_r(cs.namespace(|| "chk"), &rxn, &rn).unwrap();
        assert!(!cs.is_satisfied(), "a wrong r must not satisfy R.x mod n == r");
    }
}
