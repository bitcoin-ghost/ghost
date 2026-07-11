//! GLV endomorphism decomposition for secp256k1 (native reference + constants).
//!
//! secp256k1 has an efficiently-computable endomorphism `φ(x, y) = (β·x, y)`
//! which acts as scalar multiplication by `λ`: `φ(P) = λ·P`, where `β` is a
//! primitive cube root of 1 mod `p` and `λ` is a primitive cube root of 1 mod
//! the group order `n`. GLV uses this to split a 256-bit scalar `k` into two
//! ~128-bit scalars `(k1, k2)` with `k ≡ k1 + k2·λ (mod n)`, so
//! `k·P = k1·P + k2·φ(P)` can be computed with **half the doublings** (a 128-bit
//! double-and-add over the two half-scalars via Shamir/Straus).
//!
//! This module is the NATIVE reference + the vetted constants. Its tests verify
//! every constant by an algebraic identity (so a wrong hex digit fails loudly),
//! and that the decomposition is both valid (`k1 + k2·λ ≡ k`) and small
//! (`|k1|, |k2| < 2^128`). The in-circuit gadgets build on these.

use crate::nonnative::bignat::BigNat;
use crate::secp256k1_ec::{
    bignat_select, complete_add, identity, mux_table, to_affine, to_proj, Point,
};
use crate::secp256k1_field::{
    alloc_fp_from, const_bignat, enforce_equal, mul_mod, sub_mod, to_bits_le, N_LIMBS,
};
use crate::secp256k1_scalar::{self, secp256k1_n};
use ff::PrimeField;
use nova_snark::frontend::{AllocatedBit, Boolean, ConstraintSystem, SynthesisError};
use num_bigint::BigInt;
use num_traits::Signed;

fn h(s: &str) -> BigInt {
    BigInt::parse_bytes(s.as_bytes(), 16).unwrap()
}

/// λ — primitive cube root of unity mod `n` (the endomorphism eigenvalue).
pub(crate) fn secp256k1_lambda() -> BigInt {
    h("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72")
}

/// β — primitive cube root of unity mod `p` (the x-coordinate twist).
pub(crate) fn secp256k1_beta() -> BigInt {
    h("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee")
}

/// Short lattice basis `{(a1, b1), (a2, b2)}` of the kernel `{(x, y) : x + y·λ ≡ 0
/// (mod n)}`, used to round `(k, 0)` to a nearby lattice point.
fn basis() -> (BigInt, BigInt, BigInt, BigInt) {
    let a1 = h("3086d221a7d46bcde86c90e49284eb15");
    let b1 = -h("e4437ed6010e88286f547fa90abfe4c3");
    let a2 = h("114ca50f7a8e2f3f657c1108d9d44cfd8");
    let b2 = h("3086d221a7d46bcde86c90e49284eb15");
    (a1, b1, a2, b2)
}

/// Round `a / m` to the nearest integer (ties away from zero); `m > 0`.
fn round_div(a: &BigInt, m: &BigInt) -> BigInt {
    let two_a = a * 2;
    if a.is_negative() {
        (&two_a - m) / (m * 2)
    } else {
        (&two_a + m) / (m * 2)
    }
}

/// Decompose `k` into signed `(k1, k2)` with `k ≡ k1 + k2·λ (mod n)` and
/// `|k1|, |k2|` ≈ `2^128`. `k` is taken mod `n` first.
pub(crate) fn glv_decompose(k: &BigInt) -> (BigInt, BigInt) {
    let n = secp256k1_n();
    let k = ((k % &n) + &n) % &n;
    let (a1, b1, a2, b2) = basis();
    // c1 = round(b2·k / n), c2 = round(-b1·k / n)
    let c1 = round_div(&(&b2 * &k), &n);
    let c2 = round_div(&(&(-&b1) * &k), &n);
    let k1 = &k - (&c1 * &a1 + &c2 * &a2);
    let k2 = -(&c1 * &b1 + &c2 * &b2);
    (k1, k2)
}

// ===================== in-circuit GLV =====================

/// In-circuit endomorphism `φ(P) = (β·x mod p, y) = λ·P`.
pub(crate) fn phi<Scalar, CS>(mut cs: CS, p: &Point<Scalar>) -> Result<Point<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let beta = const_bignat::<Scalar, CS>(secp256k1_beta());
    let x = mul_mod(cs.namespace(|| "beta*x"), &beta, &p.x)?;
    Ok(Point { x, y: p.y.clone() })
}

/// Conditional point negation: `sign ? (x, p−y) : (x, y)`.
pub(crate) fn conditional_negate<Scalar, CS>(
    mut cs: CS,
    p: &Point<Scalar>,
    sign: &Boolean,
) -> Result<Point<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let zero = const_bignat::<Scalar, CS>(BigInt::from(0));
    let neg_y = sub_mod(cs.namespace(|| "p-y"), &zero, &p.y)?; // (0 − y) mod p
    let y = bignat_select(cs.namespace(|| "sel_y"), sign, &neg_y, &p.y)?;
    Ok(Point {
        x: p.x.clone(),
        y,
    })
}

/// Conditional negation mod n: `sign ? (−m mod n) : m`. `neg` is pinned to `−m`
/// by `m + neg ≡ 0 (mod n)`, so any well-formed witness is bound to the right
/// residue (everything downstream is reduced mod n).
fn condneg_modn<Scalar, CS>(
    mut cs: CS,
    m: &BigNat<Scalar>,
    sign: &Boolean,
) -> Result<BigNat<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let neg = alloc_fp_from(cs.namespace(|| "neg"), || {
        let n = secp256k1_n();
        let mv = m.value.clone().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(((&n - (mv % &n)) % &n + &n) % &n)
    })?;
    let sum = secp256k1_scalar::add_mod(cs.namespace(|| "m+neg"), m, &neg)?;
    let zero = const_bignat::<Scalar, CS>(BigInt::from(0));
    enforce_equal(cs.namespace(|| "m+neg==0"), &sum, &zero)?;
    bignat_select(cs.namespace(|| "sel"), sign, &neg, m)
}

/// Enforce the GLV relation `k ≡ σ1·k1 + σ2·(k2·λ) (mod n)`, σᵢ = −1 iff `sᵢ`.
/// `k1, k2` are the positive magnitudes (each proven `< 2^128` by the caller).
pub(crate) fn enforce_glv_decomposition<Scalar, CS>(
    mut cs: CS,
    k: &BigNat<Scalar>,
    k1: &BigNat<Scalar>,
    s1: &Boolean,
    k2: &BigNat<Scalar>,
    s2: &Boolean,
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let lambda = const_bignat::<Scalar, CS>(secp256k1_lambda());
    let t2 = secp256k1_scalar::mul_mod(cs.namespace(|| "k2*lam"), k2, &lambda)?;
    let u1 = condneg_modn(cs.namespace(|| "u1"), k1, s1)?;
    let u2 = condneg_modn(cs.namespace(|| "u2"), &t2, s2)?;
    let sum = secp256k1_scalar::add_mod(cs.namespace(|| "u1+u2"), &u1, &u2)?;
    enforce_equal(cs.namespace(|| "==k"), &sum, k)
}

/// Constrain the top `N_LIMBS − 2` limbs to zero → value `< 2^128`.
fn enforce_128bit<Scalar, CS>(mut cs: CS, m: &BigNat<Scalar>)
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    for i in 2..N_LIMBS {
        let limb = m.limbs[i].clone();
        cs.enforce(|| format!("hi{i}==0"), |lc| lc, |lc| lc, |lc| lc + &limb);
    }
}

/// Windowed (w=2) Shamir/Straus simultaneous multiply `k1·P1 + k2·P2`. `k1_bits`,
/// `k2_bits` are equal-length, MSB-first, and a whole number of 2-bit windows. A
/// 16-entry table `T[4i+j] = i·P1 + j·P2` feeds a 15-`proj_select` mux per window;
/// each window costs 2 doublings + 1 add — half the doublings of two separate muls.
pub(crate) fn straus_dual<Scalar, CS>(
    mut cs: CS,
    k1_bits: &[Boolean],
    p1: &Point<Scalar>,
    k2_bits: &[Boolean],
    p2: &Point<Scalar>,
) -> Result<Point<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let p1p = to_proj(cs.namespace(|| "p1"), p1)?;
    let p2p = to_proj(cs.namespace(|| "p2"), p2)?;
    let mut m1 = vec![identity(cs.namespace(|| "m1_0"))?, p1p.clone()];
    m1.push(complete_add(cs.namespace(|| "m1_2"), &m1[1], &p1p)?);
    m1.push(complete_add(cs.namespace(|| "m1_3"), &m1[2], &p1p)?);
    let mut m2 = vec![identity(cs.namespace(|| "m2_0"))?, p2p.clone()];
    m2.push(complete_add(cs.namespace(|| "m2_2"), &m2[1], &p2p)?);
    m2.push(complete_add(cs.namespace(|| "m2_3"), &m2[2], &p2p)?);
    let mut table = Vec::with_capacity(16);
    for i in 0..4 {
        for j in 0..4 {
            table.push(complete_add(cs.namespace(|| format!("t{i}{j}")), &m1[i], &m2[j])?);
        }
    }

    let mut acc = identity(cs.namespace(|| "acc0"))?;
    let n_windows = k1_bits.len() / 2;
    for wi in 0..n_windows {
        acc = complete_add(cs.namespace(|| format!("d{wi}a")), &acc, &acc)?;
        acc = complete_add(cs.namespace(|| format!("d{wi}b")), &acc, &acc)?;
        // MSB-first selector: [k1 hi, k1 lo, k2 hi, k2 lo] → idx = 4·(k1 window) + (k2 window).
        let sel = vec![
            k1_bits[2 * wi].clone(),
            k1_bits[2 * wi + 1].clone(),
            k2_bits[2 * wi].clone(),
            k2_bits[2 * wi + 1].clone(),
        ];
        let add = mux_table(cs.namespace(|| format!("mux{wi}")), &sel, &table)?;
        acc = complete_add(cs.namespace(|| format!("a{wi}")), &acc, &add)?;
    }
    to_affine(cs.namespace(|| "affine"), &acc)
}

/// `k·P` via GLV: decompose `k = k1 + k2·λ (mod n)` (witnessed, enforced, each
/// half `< 2^128`), then `k1·P1 + k2·φ(P)` with the signs applied to the points
/// (`P1 = ±P`, `P2 = ±φ(P)`) and a windowed Straus over the 128-bit halves —
/// half the doublings of a plain 256-bit `scalar_mul`.
pub fn glv_scalar_mul<Scalar, CS>(
    mut cs: CS,
    k: &BigNat<Scalar>,
    p: &Point<Scalar>,
) -> Result<Point<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let decomp = k.value.as_ref().map(glv_decompose);
    let k1_val = decomp.as_ref().map(|(a, _)| a.abs());
    let s1_val = decomp.as_ref().map(|(a, _)| a.is_negative());
    let k2_val = decomp.as_ref().map(|(_, b)| b.abs());
    let s2_val = decomp.as_ref().map(|(_, b)| b.is_negative());

    let k1 = alloc_fp_from(cs.namespace(|| "k1"), || {
        k1_val.clone().ok_or(SynthesisError::AssignmentMissing)
    })?;
    let k2 = alloc_fp_from(cs.namespace(|| "k2"), || {
        k2_val.clone().ok_or(SynthesisError::AssignmentMissing)
    })?;
    enforce_128bit(cs.namespace(|| "k1<2^128"), &k1);
    enforce_128bit(cs.namespace(|| "k2<2^128"), &k2);
    let s1 = Boolean::from(AllocatedBit::alloc(cs.namespace(|| "s1"), s1_val)?);
    let s2 = Boolean::from(AllocatedBit::alloc(cs.namespace(|| "s2"), s2_val)?);

    enforce_glv_decomposition(cs.namespace(|| "decomp"), k, &k1, &s1, &k2, &s2)?;

    let p1 = conditional_negate(cs.namespace(|| "P1"), p, &s1)?;
    let phip = phi(cs.namespace(|| "phi"), p)?;
    let p2 = conditional_negate(cs.namespace(|| "P2"), &phip, &s2)?;

    let mut b1 = to_bits_le(cs.namespace(|| "k1bits"), &k1)?;
    b1.truncate(128);
    b1.reverse(); // MSB-first
    let mut b2 = to_bits_le(cs.namespace(|| "k2bits"), &k2)?;
    b2.truncate(128);
    b2.reverse();

    straus_dual(cs.namespace(|| "straus"), &b1, &p1, &b2, &p2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1_ec::Point;
    use crate::secp256k1_field::{alloc_fp, secp256k1_p};
    use crate::test_cs::TestConstraintSystem;
    use nova_snark::provider::PallasEngine;
    use nova_snark::traits::Engine;
    use num_traits::One;

    type S = <PallasEngine as Engine>::Scalar;

    fn n() -> BigInt {
        secp256k1_n()
    }
    fn p() -> BigInt {
        secp256k1_p()
    }
    fn modp(a: &BigInt, m: &BigInt) -> BigInt {
        ((a % m) + m) % m
    }
    fn gx() -> BigInt {
        h("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    }
    fn gy() -> BigInt {
        h("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    }

    // Native affine EC over p (point at infinity = None), for φ(G) == λ·G.
    type Pt = Option<(BigInt, BigInt)>;
    fn ec_add(a: &Pt, b: &Pt) -> Pt {
        let p = p();
        let inv = |v: &BigInt| v.modpow(&(&p - 2), &p);
        match (a, b) {
            (None, _) => b.clone(),
            (_, None) => a.clone(),
            (Some((x1, y1)), Some((x2, y2))) => {
                if x1 == x2 && modp(&(y1 + y2), &p).is_zero_() {
                    return None;
                }
                let lam = if x1 == x2 && y1 == y2 {
                    modp(&(BigInt::from(3) * x1 * x1 * inv(&modp(&(2 * y1), &p))), &p)
                } else {
                    modp(&((y2 - y1) * inv(&modp(&(x2 - x1), &p))), &p)
                };
                let x3 = modp(&(&lam * &lam - x1 - x2), &p);
                let y3 = modp(&(&lam * (x1 - &x3) - y1), &p);
                Some((x3, y3))
            }
        }
    }
    fn ec_mul(k: &BigInt, base: &Pt) -> Pt {
        let mut acc: Pt = None;
        let mut cur = base.clone();
        let mut kk = ((k % &n()) + &n()) % &n();
        while kk > BigInt::from(0) {
            if (&kk % 2) == BigInt::one() {
                acc = ec_add(&acc, &cur);
            }
            cur = ec_add(&cur, &cur);
            kk /= 2;
        }
        acc
    }
    trait IsZero {
        fn is_zero_(&self) -> bool;
    }
    impl IsZero for BigInt {
        fn is_zero_(&self) -> bool {
            *self == BigInt::from(0)
        }
    }

    #[test]
    fn constants_are_valid_cube_roots() {
        let (n, p) = (n(), p());
        let lam = secp256k1_lambda();
        let beta = secp256k1_beta();
        // λ, β are primitive cube roots of unity: x^2 + x + 1 ≡ 0, x ≠ 1.
        assert_eq!(modp(&(&lam * &lam + &lam + 1), &n), BigInt::from(0), "λ²+λ+1 ≡ 0 mod n");
        assert_ne!(lam, BigInt::one(), "λ ≠ 1");
        assert_eq!(modp(&(&beta * &beta + &beta + 1), &p), BigInt::from(0), "β²+β+1 ≡ 0 mod p");
        assert_ne!(beta, BigInt::one(), "β ≠ 1");
    }

    #[test]
    fn basis_is_valid_kernel() {
        let n = n();
        let lam = secp256k1_lambda();
        let (a1, b1, a2, b2) = basis();
        // Each basis vector lies in the kernel: aᵢ + bᵢ·λ ≡ 0 (mod n).
        assert_eq!(modp(&(&a1 + &b1 * &lam), &n), BigInt::from(0), "a1 + b1·λ ≡ 0");
        assert_eq!(modp(&(&a2 + &b2 * &lam), &n), BigInt::from(0), "a2 + b2·λ ≡ 0");
        // Determinant a1·b2 − a2·b1 = ±n.
        let det = &a1 * &b2 - &a2 * &b1;
        assert!(det == n || det == -n.clone(), "det = ±n (got {det})");
    }

    #[test]
    fn endomorphism_matches_lambda() {
        // φ(G) = (β·Gx mod p, Gy) must equal λ·G.
        let g: Pt = Some((gx(), gy()));
        let phi_g: Pt = Some((modp(&(&secp256k1_beta() * gx()), &p()), gy()));
        let lam_g = ec_mul(&secp256k1_lambda(), &g);
        assert_eq!(phi_g, lam_g, "φ(G) == λ·G");
    }

    #[test]
    fn decompose_is_small_and_valid() {
        let n = n();
        let lam = secp256k1_lambda();
        let bound = BigInt::from(1) << 128u32; // want |k1|, |k2| < 2^128
        for kv in [
            h("deadbeefcafef00dfeedface0123456789abcdef0123456789abcdef01234567"),
            h("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"), // n-1
            BigInt::one(),
            h("7fa9f1e2d3c4b5a6978869504132231445566778899aabbccddeeff0011223344"),
        ] {
            let (k1, k2) = glv_decompose(&kv);
            let recon = modp(&(&k1 + &k2 * &lam), &n);
            assert_eq!(recon, modp(&kv, &n), "k1 + k2·λ ≡ k (mod n)");
            assert!(k1.abs() < bound, "|k1| < 2^128 (got {} bits)", k1.abs().bits());
            assert!(k2.abs() < bound, "|k2| < 2^128 (got {} bits)", k2.abs().bits());
        }
    }

    // End-to-end: the in-circuit GLV multiply equals native k·G (exercises
    // decomposition + signs + φ + Straus). ~5M constraints, so kept to two scalars.
    #[test]
    fn glv_scalar_mul_matches_native() {
        for kv in [
            h("deadbeefcafef00dfeedface0123456789abcdef0123456789abcdef01234567"),
            h("7fa9f1e2d3c4b5a6978869504132231445566778899aabbccddeeff0011223344"),
        ] {
            let kmod = modp(&kv, &n());
            let expected = ec_mul(&kmod, &Some((gx(), gy()))).unwrap();
            let mut cs = TestConstraintSystem::<S>::new();
            let k = alloc_fp(cs.namespace(|| "k"), kmod).unwrap();
            let g = Point {
                x: alloc_fp(cs.namespace(|| "gx"), gx()).unwrap(),
                y: alloc_fp(cs.namespace(|| "gy"), gy()).unwrap(),
            };
            let r = glv_scalar_mul(cs.namespace(|| "kG"), &k, &g).unwrap();
            assert_eq!(r.x.value, Some(expected.0), "kG.x");
            assert_eq!(r.y.value, Some(expected.1), "kG.y");
            assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
        }
    }
}
