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

use crate::secp256k1_field::secp256k1_p;
use crate::secp256k1_scalar::secp256k1_n;
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

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::One;

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
}
