//! Phase 3 M2 (cont.) — secp256k1 **elliptic-curve point** operations (affine)
//! in-circuit, on the base-field arithmetic in [`crate::secp256k1_field`].
//!
//! secp256k1 is `y² = x³ + 7` (a = 0). These are the affine group law formulas:
//!
//! * **add** (P ≠ ±Q):  `λ = (y₂−y₁)/(x₂−x₁)`, `x₃ = λ²−x₁−x₂`, `y₃ = λ(x₁−x₃)−y₁`
//! * **double** (y ≠ 0): `λ = 3x₁²/(2y₁)`,      `x₃ = λ²−2x₁`,   `y₃ = λ(x₁−x₃)−y₁`
//!
//! SPIKE: the point at infinity is not represented, and the exceptional cases
//! (P = Q, P = −Q, y = 0) are assumed not to occur — the double-and-add ladder
//! for ECDSA (M3) avoids them for well-formed inputs. Complete/incomplete-
//! addition hardening is a follow-on.

use crate::nonnative::bignat::BigNat;
use crate::secp256k1_field::{add_mod, alloc_fp_from, div_mod, mul_mod, sub_mod, N_LIMBS};
use ff::PrimeField;
use nova_snark::frontend::{Boolean, ConstraintSystem, SynthesisError};

/// An affine secp256k1 point.
pub struct Point<Scalar: PrimeField> {
    pub x: BigNat<Scalar>,
    pub y: BigNat<Scalar>,
}

impl<Scalar: PrimeField> Point<Scalar> {
    fn clone_ref(&self) -> Point<Scalar> {
        Point { x: self.x.clone(), y: self.y.clone() }
    }
}

/// Select `cond ? a : b` over a base-field element, limb by limb: allocate the
/// selected value and constrain `sel_limb − b_limb = cond·(a_limb − b_limb)` for
/// each limb (`cond` is a Boolean, so this is one R1CS constraint per limb).
fn bignat_select<Scalar, CS>(
    mut cs: CS,
    cond: &Boolean,
    a: &BigNat<Scalar>,
    b: &BigNat<Scalar>,
) -> Result<BigNat<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let selected = alloc_fp_from(cs.namespace(|| "sel"), || {
        if cond.get_value().ok_or(SynthesisError::AssignmentMissing)? {
            a.value.clone().ok_or(SynthesisError::AssignmentMissing)
        } else {
            b.value.clone().ok_or(SynthesisError::AssignmentMissing)
        }
    })?;
    for i in 0..N_LIMBS {
        let cond_lc = cond.lc(CS::one(), Scalar::ONE);
        let a_i = a.limbs[i].clone();
        let b_i = b.limbs[i].clone();
        let b_i2 = b_i.clone();
        let sel_i = selected.limbs[i].clone();
        cs.enforce(
            || format!("select_limb_{i}"),
            |_| cond_lc,
            |lc| lc + &a_i - &b_i,
            |lc| lc + &sel_i - &b_i2,
        );
    }
    Ok(selected)
}

/// Select `cond ? a : b` over an affine point.
pub fn point_select<Scalar, CS>(
    mut cs: CS,
    cond: &Boolean,
    a: &Point<Scalar>,
    b: &Point<Scalar>,
) -> Result<Point<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    Ok(Point {
        x: bignat_select(cs.namespace(|| "x"), cond, &a.x, &b.x)?,
        y: bignat_select(cs.namespace(|| "y"), cond, &a.y, &b.y)?,
    })
}

/// `k · P` by left-to-right double-and-add. `bits` is the scalar most-significant
/// bit first, and its top bit is assumed set (so the accumulator starts at `P` —
/// no identity element is represented). Each step doubles, computes `acc + P`,
/// and selects it in iff the bit is set. SPIKE: relies on the incomplete-addition
/// assumption holding along the ladder (true for well-formed ECDSA inputs).
pub fn scalar_mul<Scalar, CS>(
    mut cs: CS,
    bits: &[Boolean],
    p: &Point<Scalar>,
) -> Result<Point<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let mut acc = p.clone_ref();
    for (i, bit) in bits.iter().enumerate().skip(1) {
        let doubled = point_double(cs.namespace(|| format!("dbl_{i}")), &acc)?;
        let added = point_add(cs.namespace(|| format!("add_{i}")), &doubled, p)?;
        acc = point_select(cs.namespace(|| format!("sel_{i}")), bit, &added, &doubled)?;
    }
    Ok(acc)
}

/// `P + Q` for distinct affine points (`P ≠ ±Q`).
pub fn point_add<Scalar, CS>(
    mut cs: CS,
    p: &Point<Scalar>,
    q: &Point<Scalar>,
) -> Result<Point<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let num = sub_mod(cs.namespace(|| "y2-y1"), &q.y, &p.y)?;
    let den = sub_mod(cs.namespace(|| "x2-x1"), &q.x, &p.x)?;
    let lam = div_mod(cs.namespace(|| "lambda"), &num, &den)?;
    let lam2 = mul_mod(cs.namespace(|| "lam^2"), &lam, &lam)?;
    let t = sub_mod(cs.namespace(|| "lam2-x1"), &lam2, &p.x)?;
    let x3 = sub_mod(cs.namespace(|| "x3"), &t, &q.x)?;
    let dx = sub_mod(cs.namespace(|| "x1-x3"), &p.x, &x3)?;
    let ldx = mul_mod(cs.namespace(|| "lam*dx"), &lam, &dx)?;
    let y3 = sub_mod(cs.namespace(|| "y3"), &ldx, &p.y)?;
    Ok(Point { x: x3, y: y3 })
}

/// `2P` (`y ≠ 0`).
pub fn point_double<Scalar, CS>(mut cs: CS, p: &Point<Scalar>) -> Result<Point<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let x_sq = mul_mod(cs.namespace(|| "x1^2"), &p.x, &p.x)?;
    let two_x_sq = add_mod(cs.namespace(|| "2x1^2"), &x_sq, &x_sq)?;
    let three_x_sq = add_mod(cs.namespace(|| "3x1^2"), &two_x_sq, &x_sq)?;
    let two_y = add_mod(cs.namespace(|| "2y1"), &p.y, &p.y)?;
    let lam = div_mod(cs.namespace(|| "lambda"), &three_x_sq, &two_y)?;
    let lam2 = mul_mod(cs.namespace(|| "lam^2"), &lam, &lam)?;
    let two_x = add_mod(cs.namespace(|| "2x1"), &p.x, &p.x)?;
    let x3 = sub_mod(cs.namespace(|| "x3"), &lam2, &two_x)?;
    let dx = sub_mod(cs.namespace(|| "x1-x3"), &p.x, &x3)?;
    let ldx = mul_mod(cs.namespace(|| "lam*dx"), &lam, &dx)?;
    let y3 = sub_mod(cs.namespace(|| "y3"), &ldx, &p.y)?;
    Ok(Point { x: x3, y: y3 })
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
    fn g() -> (BigInt, BigInt) {
        (
            bn("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
            bn("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
        )
    }
    // secp256k1's well-known 2G and 3G — independent oracle values.
    fn two_g() -> (BigInt, BigInt) {
        (
            bn("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
            bn("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
        )
    }
    fn three_g() -> (BigInt, BigInt) {
        (
            bn("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
            bn("388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"),
        )
    }

    fn alloc_point(cs: &mut TestConstraintSystem<Scalar>, tag: &str, p: &(BigInt, BigInt)) -> Point<Scalar> {
        Point {
            x: alloc_fp(cs.namespace(|| format!("{tag}.x")), p.0.clone()).unwrap(),
            y: alloc_fp(cs.namespace(|| format!("{tag}.y")), p.1.clone()).unwrap(),
        }
    }

    #[test]
    fn double_g_equals_2g() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let gp = alloc_point(&mut cs, "G", &g());
        let d = point_double(cs.namespace(|| "2G"), &gp).unwrap();
        let (ex, ey) = two_g();
        assert_eq!(d.x.value, Some(ex), "2G.x");
        assert_eq!(d.y.value, Some(ey), "2G.y");
        assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
    }

    #[test]
    fn add_g_2g_equals_3g() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let gp = alloc_point(&mut cs, "G", &g());
        let g2 = alloc_point(&mut cs, "2G", &two_g());
        let sum = point_add(cs.namespace(|| "G+2G"), &gp, &g2).unwrap();
        let (ex, ey) = three_g();
        assert_eq!(sum.x.value, Some(ex), "3G.x");
        assert_eq!(sum.y.value, Some(ey), "3G.y");
        assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
    }

    // Scalar bits MSB-first (top bit set): k=2 -> [1,0], k=3 -> [1,1].
    fn alloc_bits(cs: &mut TestConstraintSystem<Scalar>, vals: &[bool]) -> Vec<Boolean> {
        use nova_snark::frontend::AllocatedBit;
        vals.iter()
            .enumerate()
            .map(|(i, &b)| Boolean::from(AllocatedBit::alloc(cs.namespace(|| format!("bit_{i}")), Some(b)).unwrap()))
            .collect()
    }

    #[test]
    fn scalar_mul_2_equals_2g() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let gp = alloc_point(&mut cs, "G", &g());
        let bits = alloc_bits(&mut cs, &[true, false]); // 2
        let r = scalar_mul(cs.namespace(|| "2G"), &bits, &gp).unwrap();
        let (ex, ey) = two_g();
        assert_eq!(r.x.value, Some(ex), "2G.x");
        assert_eq!(r.y.value, Some(ey), "2G.y");
        assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
    }

    #[test]
    fn scalar_mul_3_equals_3g() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let gp = alloc_point(&mut cs, "G", &g());
        let bits = alloc_bits(&mut cs, &[true, true]); // 3
        let r = scalar_mul(cs.namespace(|| "3G"), &bits, &gp).unwrap();
        let (ex, ey) = three_g();
        assert_eq!(r.x.value, Some(ex), "3G.x");
        assert_eq!(r.y.value, Some(ey), "3G.y");
        assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
    }
}
