//! Phase 3 M4 — ECDSA verification folded into a Nova StepCircuit.
//!
//! The full ECDSA check ([`crate::ecdsa::verify_full`]) is ~1–2M+ constraints
//! (two 256-bit scalar multiplications) — too large for the in-memory test CS.
//! This wraps it in a `StepCircuit` so it runs under the real Nova prover, whose
//! R1CS storage is compact enough to handle it. Each fold step verifies one
//! signature and increments a counter; a run over N spends verifies all N.
//!
//! `z = [verified_count]`.

use crate::ecdsa::verify_full;
use crate::secp256k1_ec::Point;
use crate::secp256k1_field::alloc_fp;
use ff::PrimeField;
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{ConstraintSystem, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;
use num_bigint::BigInt;

/// One ECDSA verification (generator `G`, key `Q`, hash `z`, signature `(r, s)`).
#[derive(Clone, Debug)]
pub struct EcdsaVerifyStep<F: PrimeField> {
    pub gx: BigInt,
    pub gy: BigInt,
    pub qx: BigInt,
    pub qy: BigInt,
    pub z: BigInt,
    pub r: BigInt,
    pub s: BigInt,
    pub _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> StepCircuit<F> for EcdsaVerifyStep<F> {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let g = Point {
            x: alloc_fp(cs.namespace(|| "gx"), self.gx.clone())?,
            y: alloc_fp(cs.namespace(|| "gy"), self.gy.clone())?,
        };
        let q = Point {
            x: alloc_fp(cs.namespace(|| "qx"), self.qx.clone())?,
            y: alloc_fp(cs.namespace(|| "qy"), self.qy.clone())?,
        };
        let zz = alloc_fp(cs.namespace(|| "z"), self.z.clone())?;
        let r = alloc_fp(cs.namespace(|| "r"), self.r.clone())?;
        let s = alloc_fp(cs.namespace(|| "s"), self.s.clone())?;

        // Enforces the signature is valid (unsatisfiable otherwise).
        verify_full(cs.namespace(|| "ecdsa"), &g, &q, &zz, &r, &s)?;

        let count = AllocatedNum::alloc(cs.namespace(|| "count'"), || {
            Ok(z[0].get_value().ok_or(SynthesisError::AssignmentMissing)? + F::ONE)
        })?;
        cs.enforce(
            || "count' = count + 1",
            |lc| lc + z[0].get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + count.get_variable(),
        );
        Ok(vec![count])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_snark::{
        provider::{PallasEngine, VestaEngine},
        traits::{circuit::TrivialCircuit, snark::default_ck_hint, Engine},
        PublicParams, RecursiveSNARK,
    };

    type E1 = PallasEngine;
    type E2 = VestaEngine;
    type S1 = <E1 as Engine>::Scalar;
    type S2 = <E2 as Engine>::Scalar;
    type C1 = EcdsaVerifyStep<S1>;
    type C2 = TrivialCircuit<S2>;

    fn bn(h: &str) -> BigInt {
        BigInt::parse_bytes(h.as_bytes(), 16).unwrap()
    }
    fn p() -> BigInt {
        (BigInt::from(1) << 256u32) - (BigInt::from(1) << 32u32) - BigInt::from(977)
    }
    fn n() -> BigInt {
        bn("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
    }
    fn modp(a: BigInt) -> BigInt {
        let p = p();
        ((a % &p) + &p) % &p
    }
    fn inv(a: &BigInt, m: &BigInt) -> BigInt {
        a.modpow(&(m - BigInt::from(2)), m)
    }
    fn g() -> (BigInt, BigInt) {
        (bn("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
         bn("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    }

    // Native affine EC (point at infinity = None).
    type Pt = Option<(BigInt, BigInt)>;
    fn ec_add(a: &Pt, b: &Pt) -> Pt {
        let p = p();
        match (a, b) {
            (None, _) => b.clone(),
            (_, None) => a.clone(),
            (Some((x1, y1)), Some((x2, y2))) => {
                if x1 == x2 && (y1 + y2) % &p == BigInt::from(0) {
                    return None;
                }
                let lam = if x1 == x2 && y1 == y2 {
                    modp((BigInt::from(3) * x1 * x1) * inv(&modp(BigInt::from(2) * y1), &p))
                } else {
                    modp((y2 - y1) * inv(&modp(x2 - x1), &p))
                };
                let x3 = modp(&lam * &lam - x1 - x2);
                let y3 = modp(&lam * (x1 - &x3) - y1);
                Some((x3, y3))
            }
        }
    }
    fn ec_mul(k: &BigInt, base: &(BigInt, BigInt)) -> (BigInt, BigInt) {
        let mut acc: Pt = None;
        let mut cur = Some(base.clone());
        let mut kk = k.clone();
        while kk > BigInt::from(0) {
            if &kk % 2 == BigInt::from(1) {
                acc = ec_add(&acc, &cur);
            }
            cur = ec_add(&cur, &cur);
            kk /= 2;
        }
        acc.unwrap()
    }

    // Deterministically produce a VALID ECDSA (Q, z, r, s).
    fn make_sig() -> (BigInt, BigInt, BigInt, BigInt, BigInt) {
        let n = n();
        let d = bn("c0ffee0123456789abcdef0011223344556677889900aabbccddeeff001122334") % &n;
        let k = bn("7fa9f1e2d3c4b5a6978869504132231445566778899aabbccddeeff0011223344") % &n;
        let z = bn("deadbeefcafef00dfeedface0123456789abcdef0123456789abcdef01234567") % &n;
        let (qx, qy) = ec_mul(&d, &g());
        let (rx, _) = ec_mul(&k, &g());
        let r = &rx % &n;
        let s = (inv(&k, &n) * (&z + &r * &d)) % &n;
        (qx, qy, z, r, s)
    }

    #[test]
    #[ignore = "prover-scale: two 256-bit scalar muls; run explicitly with --ignored"]
    fn ecdsa_verify_folds_under_nova() {
        let (qx, qy, z, r, s) = make_sig();
        let (gx, gy) = g();
        let step = EcdsaVerifyStep::<S1> {
            gx, gy, qx, qy, z, r, s, _marker: std::marker::PhantomData,
        };
        let c2 = C2::default();
        eprintln!("setup (building public params for the ECDSA circuit)…");
        let pp = PublicParams::<E1, E2, C1, C2>::setup(&step, &c2, &*default_ck_hint(), &*default_ck_hint()).unwrap();
        eprintln!("constraints (primary): {}", pp.num_constraints().0);
        let z0 = vec![S1::from(0u64)];
        let z0s = vec![S2::from(0u64)];
        let mut rs = RecursiveSNARK::<E1, E2, C1, C2>::new(&pp, &step, &c2, &z0, &z0s).unwrap();
        eprintln!("proving step…");
        rs.prove_step(&pp, &step, &c2).unwrap();
        eprintln!("verifying…");
        let zn = rs.verify(&pp, 1, &z0, &z0s).unwrap();
        assert_eq!(zn.0[0], S1::from(1u64), "one signature verified");
    }
}
