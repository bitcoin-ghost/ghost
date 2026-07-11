//! Phase 3 M2 — secp256k1 elliptic-curve point operations in-circuit.
//!
//! Uses **projective coordinates** `(X:Y:Z)` with the Renes–Costello–Batina
//! (2016) **complete** addition formula for `a = 0` curves (secp256k1 is
//! `y² = x³ + 7`). "Complete" = exception-free: the single formula is correct for
//! ALL inputs — distinct points, doubling (`P + P`), the identity `(0:1:0)`, and
//! `P + (−P) = O` — so `scalar_mul` can start from the identity and handle
//! arbitrary scalars (leading zeros included), which the earlier incomplete
//! affine formulas could not. It also avoids a modular inverse per step (only one
//! at the end, converting back to affine).
//!
//! `b3 = 3·b = 21`.

use crate::nonnative::bignat::BigNat;
use crate::secp256k1_field::{add_mod, alloc_fp, alloc_fp_from, div_mod, mul_mod, sub_mod, N_LIMBS};
use ff::PrimeField;
use nova_snark::frontend::{Boolean, ConstraintSystem, SynthesisError};
use num_bigint::BigInt;

/// An affine secp256k1 point (curve input/output).
pub struct Point<Scalar: PrimeField> {
    pub x: BigNat<Scalar>,
    pub y: BigNat<Scalar>,
}

/// A projective secp256k1 point `(X:Y:Z)`; the identity is `(0:1:0)`.
#[derive(Clone)]
pub struct ProjPoint<Scalar: PrimeField> {
    pub x: BigNat<Scalar>,
    pub y: BigNat<Scalar>,
    pub z: BigNat<Scalar>,
}

/// The projective identity `(0:1:0)`.
pub fn identity<Scalar, CS>(mut cs: CS) -> Result<ProjPoint<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    Ok(ProjPoint {
        x: alloc_fp(cs.namespace(|| "0"), BigInt::from(0))?,
        y: alloc_fp(cs.namespace(|| "1"), BigInt::from(1))?,
        z: alloc_fp(cs.namespace(|| "0z"), BigInt::from(0))?,
    })
}

/// Affine `(x, y)` → projective `(x:y:1)`.
pub fn to_proj<Scalar, CS>(mut cs: CS, p: &Point<Scalar>) -> Result<ProjPoint<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    Ok(ProjPoint {
        x: p.x.clone(),
        y: p.y.clone(),
        z: alloc_fp(cs.namespace(|| "1"), BigInt::from(1))?,
    })
}

/// Projective `(X:Y:Z)` → affine `(X/Z, Y/Z)`. Requires `Z ≠ 0` (not identity).
pub fn to_affine<Scalar, CS>(mut cs: CS, p: &ProjPoint<Scalar>) -> Result<Point<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    Ok(Point {
        x: div_mod(cs.namespace(|| "X_div_Z"), &p.x, &p.z)?,
        y: div_mod(cs.namespace(|| "Y_div_Z"), &p.y, &p.z)?,
    })
}

/// Complete projective addition (RCB 2016, Algorithm 7, `a = 0`). Correct for all
/// inputs including doubling, identity, and `P + (−P)`.
pub fn complete_add<Scalar, CS>(
    mut cs: CS,
    p: &ProjPoint<Scalar>,
    q: &ProjPoint<Scalar>,
) -> Result<ProjPoint<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let b3 = alloc_fp(cs.namespace(|| "b3"), BigInt::from(21))?;
    macro_rules! mul { ($t:literal, $a:expr, $b:expr) => { mul_mod(cs.namespace(|| $t), $a, $b)? }; }
    macro_rules! add { ($t:literal, $a:expr, $b:expr) => { add_mod(cs.namespace(|| $t), $a, $b)? }; }
    macro_rules! sub { ($t:literal, $a:expr, $b:expr) => { sub_mod(cs.namespace(|| $t), $a, $b)? }; }

    let (x1, y1, z1) = (&p.x, &p.y, &p.z);
    let (x2, y2, z2) = (&q.x, &q.y, &q.z);

    let t0 = mul!("t0", x1, x2);
    let t1 = mul!("t1", y1, y2);
    let t2 = mul!("t2", z1, z2);
    let t3 = add!("t3a", x1, y1);
    let t4 = add!("t4a", x2, y2);
    let t3 = mul!("t3b", &t3, &t4);
    let t4 = add!("t4b", &t0, &t1);
    let t3 = sub!("t3c", &t3, &t4);
    let t4 = add!("t4c", y1, z1);
    let x3 = add!("x3a", y2, z2);
    let t4 = mul!("t4d", &t4, &x3);
    let x3 = add!("x3b", &t1, &t2);
    let t4 = sub!("t4e", &t4, &x3);
    let x3 = add!("x3c", x1, z1);
    let y3 = add!("y3a", x2, z2);
    let x3 = mul!("x3d", &x3, &y3);
    let y3 = add!("y3b", &t0, &t2);
    let y3 = sub!("y3c", &x3, &y3);
    let x3 = add!("x3e", &t0, &t0);
    let t0 = add!("t0b", &x3, &t0);
    let t2 = mul!("t2b", &b3, &t2);
    let z3 = add!("z3a", &t1, &t2);
    let t1 = sub!("t1b", &t1, &t2);
    let y3 = mul!("y3d", &b3, &y3);
    let x3 = mul!("x3f", &t4, &y3);
    let t2 = mul!("t2c", &t3, &t1);
    let x3 = sub!("x3g", &t2, &x3);
    let y3 = mul!("y3e", &y3, &t0);
    let t1 = mul!("t1c", &t1, &z3);
    let y3 = add!("y3f", &t1, &y3);
    let t0 = mul!("t0c", &t0, &t3);
    let z3 = mul!("z3b", &z3, &t4);
    let z3 = add!("z3c", &z3, &t0);

    Ok(ProjPoint { x: x3, y: y3, z: z3 })
}

/// Select `cond ? a : b` over a base-field element, limb by limb.
pub(crate) fn bignat_select<Scalar, CS>(
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

/// Select `cond ? a : b` over a projective point.
pub fn proj_select<Scalar, CS>(
    mut cs: CS,
    cond: &Boolean,
    a: &ProjPoint<Scalar>,
    b: &ProjPoint<Scalar>,
) -> Result<ProjPoint<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    Ok(ProjPoint {
        x: bignat_select(cs.namespace(|| "x"), cond, &a.x, &b.x)?,
        y: bignat_select(cs.namespace(|| "y"), cond, &a.y, &b.y)?,
        z: bignat_select(cs.namespace(|| "z"), cond, &a.z, &b.z)?,
    })
}

/// Fixed window width for [`scalar_mul`]. `w=4` minimises total point additions
/// for a 256-bit scalar: the additions drop from one-per-bit to one-per-window
/// (≈ /4), while the 16-entry table costs a one-off precompute and a cheap
/// 15-`proj_select` mux per window (a select is ~26× cheaper than a point add).
pub(crate) const WINDOW: usize = 4;

/// Select `table[idx]` where `idx` is the `WINDOW`-bit value `bits` (MSB first),
/// via a binary mux tree — `2^WINDOW − 1` `proj_select`s, collapsing from the LSB.
pub(crate) fn mux_table<Scalar, CS>(
    mut cs: CS,
    bits: &[Boolean],
    table: &[ProjPoint<Scalar>],
) -> Result<ProjPoint<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let mut layer: Vec<ProjPoint<Scalar>> = table.to_vec();
    for level in 0..WINDOW {
        // Collapse on the least-significant remaining selector bit first.
        let sel = &bits[WINDOW - 1 - level];
        let mut next = Vec::with_capacity(layer.len() / 2);
        for i in 0..layer.len() / 2 {
            next.push(proj_select(
                cs.namespace(|| format!("l{level}_{i}")),
                sel,
                &layer[2 * i + 1], // bit set → odd index
                &layer[2 * i],     // bit clear → even index
            )?);
        }
        layer = next;
    }
    Ok(layer.into_iter().next().unwrap())
}

/// `k · P` (affine) by complete fixed-window double-and-add from the identity.
/// `bits` is the scalar most-significant-bit first; ANY bit pattern is valid
/// (leading zeros included) — the accumulator starts at the identity, the
/// addition is complete, and the scalar is front-padded with zero bits to a whole
/// number of windows (leading zeros do not change the value). The result is
/// returned in affine coordinates (so `k ≠ 0`).
pub fn scalar_mul<Scalar, CS>(
    mut cs: CS,
    bits: &[Boolean],
    p: &Point<Scalar>,
) -> Result<Point<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let pp = to_proj(cs.namespace(|| "P->proj"), p)?;

    // Precompute table[j] = j·P for j in 0..2^WINDOW (table[0] = identity).
    let mut table: Vec<ProjPoint<Scalar>> = Vec::with_capacity(1 << WINDOW);
    table.push(identity(cs.namespace(|| "t0"))?);
    table.push(pp.clone()); // 1·P
    for j in 2..(1 << WINDOW) {
        let next = complete_add(cs.namespace(|| format!("t{j}")), &table[j - 1], &pp)?;
        table.push(next);
    }

    // Front-pad to a whole number of windows (MSB side; zero bits are inert).
    let pad = (WINDOW - bits.len() % WINDOW) % WINDOW;
    let n_windows = (bits.len() + pad) / WINDOW;

    let mut acc = identity(cs.namespace(|| "acc0"))?;
    for wi in 0..n_windows {
        // acc = 2^WINDOW · acc
        for d in 0..WINDOW {
            acc = complete_add(cs.namespace(|| format!("dbl_{wi}_{d}")), &acc, &acc)?;
        }
        // This window's WINDOW bits (MSB first); padded positions are constant 0.
        let wbits: Vec<Boolean> = (0..WINDOW)
            .map(|b| {
                let k = wi * WINDOW + b;
                if k < pad {
                    Boolean::Constant(false)
                } else {
                    bits[k - pad].clone()
                }
            })
            .collect();
        let sel = mux_table(cs.namespace(|| format!("mux_{wi}")), &wbits, &table)?;
        acc = complete_add(cs.namespace(|| format!("add_{wi}")), &acc, &sel)?;
    }
    to_affine(cs.namespace(|| "acc->affine"), &acc)
}

/// `P + Q` (affine, complete) — for distinct or equal points; returns affine
/// (so `P + Q ≠ O`).
pub fn point_add<Scalar, CS>(
    mut cs: CS,
    p: &Point<Scalar>,
    q: &Point<Scalar>,
) -> Result<Point<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let pp = to_proj(cs.namespace(|| "P"), p)?;
    let qq = to_proj(cs.namespace(|| "Q"), q)?;
    let sum = complete_add(cs.namespace(|| "P+Q"), &pp, &qq)?;
    to_affine(cs.namespace(|| "affine"), &sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1_field::{secp256k1_p, alloc_fp};
    use crate::test_cs::TestConstraintSystem;
    use nova_snark::frontend::AllocatedBit;
    use nova_snark::provider::PallasEngine;
    use nova_snark::traits::Engine;

    type Scalar = <PallasEngine as Engine>::Scalar;

    fn bn(h: &str) -> BigInt {
        BigInt::parse_bytes(h.as_bytes(), 16).unwrap()
    }
    fn g() -> (BigInt, BigInt) {
        (bn("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
         bn("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    }
    fn two_g() -> (BigInt, BigInt) {
        (bn("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
         bn("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"))
    }
    fn three_g() -> (BigInt, BigInt) {
        (bn("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
         bn("388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"))
    }
    fn five_g() -> (BigInt, BigInt) {
        (bn("2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"),
         bn("d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6"))
    }

    fn aff(cs: &mut TestConstraintSystem<Scalar>, tag: &str, p: &(BigInt, BigInt)) -> Point<Scalar> {
        Point {
            x: alloc_fp(cs.namespace(|| format!("{tag}.x")), p.0.clone()).unwrap(),
            y: alloc_fp(cs.namespace(|| format!("{tag}.y")), p.1.clone()).unwrap(),
        }
    }
    fn alloc_bits(cs: &mut TestConstraintSystem<Scalar>, vals: &[bool]) -> Vec<Boolean> {
        vals.iter().enumerate()
            .map(|(i, &b)| Boolean::from(AllocatedBit::alloc(cs.namespace(|| format!("bit_{i}")), Some(b)).unwrap()))
            .collect()
    }

    #[test]
    fn add_g_2g_equals_3g() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let gp = aff(&mut cs, "G", &g());
        let g2 = aff(&mut cs, "2G", &two_g());
        let sum = point_add(cs.namespace(|| "G+2G"), &gp, &g2).unwrap();
        let (ex, ey) = three_g();
        assert_eq!(sum.x.value, Some(ex), "3G.x");
        assert_eq!(sum.y.value, Some(ey), "3G.y");
        assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
    }

    // Completeness: the SAME formula doubles (P + P).
    #[test]
    fn add_g_g_doubles_to_2g() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let gp = aff(&mut cs, "G", &g());
        let g2 = aff(&mut cs, "G2", &g());
        let sum = point_add(cs.namespace(|| "G+G"), &gp, &g2).unwrap();
        let (ex, ey) = two_g();
        assert_eq!(sum.x.value, Some(ex), "2G.x (doubling via complete add)");
        assert_eq!(sum.y.value, Some(ey), "2G.y");
        assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
    }

    // Completeness: identity is neutral.
    #[test]
    fn identity_plus_g_is_g() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let id = identity(cs.namespace(|| "id")).unwrap();
        let gp = aff(&mut cs, "G", &g());
        let gpp = to_proj(cs.namespace(|| "Gp"), &gp).unwrap();
        let sum = complete_add(cs.namespace(|| "id+G"), &id, &gpp).unwrap();
        let a = to_affine(cs.namespace(|| "aff"), &sum).unwrap();
        let (gx, gy) = g();
        assert_eq!(a.x.value, Some(gx), "id+G == G (x)");
        assert_eq!(a.y.value, Some(gy), "id+G == G (y)");
        assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
    }

    // Completeness: P + (−P) == identity (Z == 0).
    #[test]
    fn g_plus_neg_g_is_identity() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let (gx, gy) = g();
        let neg = (gx.clone(), &secp256k1_p() - &gy);
        let gp = aff(&mut cs, "G", &g());
        let ng = aff(&mut cs, "-G", &neg);
        let gpp = to_proj(cs.namespace(|| "Gp"), &gp).unwrap();
        let ngp = to_proj(cs.namespace(|| "nGp"), &ng).unwrap();
        let sum = complete_add(cs.namespace(|| "G+(-G)"), &gpp, &ngp).unwrap();
        assert_eq!(sum.z.value, Some(BigInt::from(0)), "G+(-G) is the identity (Z==0)");
        assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
    }

    // Arbitrary scalar with LEADING ZEROS: k = 5 in a 5-bit field [0,0,1,0,1].
    #[test]
    fn scalar_mul_5_with_leading_zeros() {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let gp = aff(&mut cs, "G", &g());
        let bits = alloc_bits(&mut cs, &[false, false, true, false, true]); // 00101 = 5
        let r = scalar_mul(cs.namespace(|| "5G"), &bits, &gp).unwrap();
        let (ex, ey) = five_g();
        assert_eq!(r.x.value, Some(ex), "5G.x");
        assert_eq!(r.y.value, Some(ey), "5G.y");
        assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
    }

    // Native affine reference (point at infinity = None) for a full multi-window check.
    fn n_add(a: &Option<(BigInt, BigInt)>, b: &Option<(BigInt, BigInt)>) -> Option<(BigInt, BigInt)> {
        let p = secp256k1_p();
        let modp = |v: BigInt| ((v % &p) + &p) % &p;
        let inv = |v: &BigInt| v.modpow(&(&p - BigInt::from(2)), &p);
        match (a, b) {
            (None, _) => b.clone(),
            (_, None) => a.clone(),
            (Some((x1, y1)), Some((x2, y2))) => {
                if x1 == x2 && (y1 + y2) % &p == BigInt::from(0) {
                    return None;
                }
                let lam = if x1 == x2 && y1 == y2 {
                    modp((BigInt::from(3) * x1 * x1) * inv(&modp(BigInt::from(2) * y1)))
                } else {
                    modp((y2 - y1) * inv(&modp(x2 - x1)))
                };
                let x3 = modp(&lam * &lam - x1 - x2);
                let y3 = modp(&lam * (x1 - &x3) - y1);
                Some((x3, y3))
            }
        }
    }
    fn n_mul(k: u64) -> (BigInt, BigInt) {
        let base = Some(g());
        let mut acc: Option<(BigInt, BigInt)> = None;
        let mut cur = base;
        let mut kk = k;
        while kk > 0 {
            if kk & 1 == 1 {
                acc = n_add(&acc, &cur);
            }
            cur = n_add(&cur, &cur);
            kk >>= 1;
        }
        acc.unwrap()
    }

    // Multi-window (w=4) with a non-zero top window and front padding: k = 363
    // is 9 bits → padded to 12 → 3 windows, top window = 0b0001.
    #[test]
    fn scalar_mul_matches_native_multiwindow() {
        let k: u64 = 0b1_0110_1011; // 363
        let width = 9;
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let gp = aff(&mut cs, "G", &g());
        let msb_first: Vec<bool> = (0..width).rev().map(|i| (k >> i) & 1 == 1).collect();
        let bits = alloc_bits(&mut cs, &msb_first);
        let r = scalar_mul(cs.namespace(|| "kG"), &bits, &gp).unwrap();
        let (ex, ey) = n_mul(k);
        assert_eq!(r.x.value, Some(ex), "kG.x");
        assert_eq!(r.y.value, Some(ey), "kG.y");
        assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
    }
}
