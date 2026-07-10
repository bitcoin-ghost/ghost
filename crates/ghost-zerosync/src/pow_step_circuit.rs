//! Phase 1 (in-circuit) — Nova `StepCircuit` for the folding step.
//!
//! Built up in increments so the recursion API is de-risked before the gadget:
//! - **1a (done):** work accumulation `z' = z + w` folded via `RecursiveSNARK`
//!   — proved the Nova IVC pipeline works on our stack.
//! - **1b (this):** carry the 256-bit tip hash in `z` as two field limbs and
//!   enforce **chain linkage** (`header.prev_hash == z.tip`). The block's own
//!   hash is still supplied as a witness (SHA256d comes in 1c), so this proves
//!   *a correctly-linked chain that accumulates work* — everything except the
//!   PoW hashing itself.
//! - 1c: bellpepper **SHA256d** gadget + big-endian target compare, so the
//!   new-tip limbs are *computed* in-circuit and the step matches `fold_header`.
//!
//! State `z = [tip_hi, tip_lo, cumwork]` (arity 3). A 256-bit hash is split into
//! two 128-bit big-endian limbs, each of which fits in the ~255-bit scalar field.

use crate::U256;
use ff::PrimeField;
use nova_snark::frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;

/// Split a big-endian 256-bit value into two 128-bit field limbs `(hi, lo)`.
pub fn hash_to_limbs<F: PrimeField>(h: &U256) -> (F, F) {
    let hi = u128::from_be_bytes(h[0..16].try_into().unwrap());
    let lo = u128::from_be_bytes(h[16..32].try_into().unwrap());
    (u128_to_field(hi), u128_to_field(lo))
}

/// `u128 -> F` as `hi64 * 2^64 + lo64` (ff only guarantees `From<u64>`).
fn u128_to_field<F: PrimeField>(x: u128) -> F {
    let two_64 = {
        let t = F::from(1u64 << 32); // 2^32
        t * t // 2^64
    };
    F::from((x >> 64) as u64) * two_64 + F::from(x as u64)
}

/// One folding step: enforce the block links to the running tip, carry the new
/// tip, and accumulate work. (`new_*` are witnessed now; computed by the SHA256d
/// gadget in 1c.)
#[derive(Clone, Debug)]
pub struct PowStep<F: PrimeField> {
    pub prev_hi: F,
    pub prev_lo: F,
    pub new_hi: F,
    pub new_lo: F,
    pub work: F,
}

impl<F: PrimeField> StepCircuit<F> for PowStep<F> {
    fn arity(&self) -> usize {
        3 // [tip_hi, tip_lo, cumwork]
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // Chain linkage: the block's prev_hash must equal the running tip.
        let prev_hi = AllocatedNum::alloc(cs.namespace(|| "prev_hi"), || Ok(self.prev_hi))?;
        let prev_lo = AllocatedNum::alloc(cs.namespace(|| "prev_lo"), || Ok(self.prev_lo))?;
        cs.enforce(
            || "link_hi: prev_hi == tip_hi",
            |lc| lc + prev_hi.get_variable() - z[0].get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );
        cs.enforce(
            || "link_lo: prev_lo == tip_lo",
            |lc| lc + prev_lo.get_variable() - z[1].get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );

        // New tip (witnessed; SHA256d-computed in 1c).
        let new_hi = AllocatedNum::alloc(cs.namespace(|| "new_hi"), || Ok(self.new_hi))?;
        let new_lo = AllocatedNum::alloc(cs.namespace(|| "new_lo"), || Ok(self.new_lo))?;

        // Work accumulation: cumwork' = cumwork + work.
        let work = AllocatedNum::alloc(cs.namespace(|| "work"), || Ok(self.work))?;
        let cumwork = AllocatedNum::alloc(cs.namespace(|| "cumwork'"), || {
            let prev = z[2].get_value().ok_or(SynthesisError::AssignmentMissing)?;
            let w = work.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(prev + w)
        })?;
        cs.enforce(
            || "cumwork' = cumwork + work",
            |lc| lc + z[2].get_variable() + work.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + cumwork.get_variable(),
        );

        Ok(vec![new_hi, new_lo, cumwork])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cumulative_pow::BlockHeader;
    use nova_snark::{
        provider::{PallasEngine, VestaEngine},
        traits::{circuit::TrivialCircuit, snark::default_ck_hint, Engine},
        PublicParams, RecursiveSNARK,
    };

    type E1 = PallasEngine;
    type E2 = VestaEngine;
    type S1 = <E1 as Engine>::Scalar;
    type S2 = <E2 as Engine>::Scalar;
    type C1 = PowStep<S1>;
    type C2 = TrivialCircuit<S2>;

    fn hdr(prev: U256, nonce: u32) -> BlockHeader {
        BlockHeader { version: 1, prev_hash: prev, merkle_root: [7u8; 32], time: 1_700_000_000, bits: 0x207f_ffff, nonce }
    }

    fn step_from(prev: U256, this: U256, work: u64) -> C1 {
        let (prev_hi, prev_lo) = hash_to_limbs(&prev);
        let (new_hi, new_lo) = hash_to_limbs(&this);
        PowStep { prev_hi, prev_lo, new_hi, new_lo, work: S1::from(work) }
    }

    fn run(steps: &[C1], z0: [S1; 3]) -> Result<Vec<S1>, nova_snark::errors::NovaError> {
        let c2 = C2::default();
        let pp = PublicParams::<E1, E2, C1, C2>::setup(&steps[0], &c2, &*default_ck_hint(), &*default_ck_hint())?;
        let z0_p = z0.to_vec();
        let z0_s = vec![S2::from(0u64)];
        let mut rs = RecursiveSNARK::<E1, E2, C1, C2>::new(&pp, &steps[0], &c2, &z0_p, &z0_s)?;
        for s in steps {
            rs.prove_step(&pp, s, &c2)?;
        }
        rs.verify(&pp, steps.len(), &z0_p, &z0_s).map(|(zn, _)| zn)
    }

    #[test]
    fn linked_chain_folds_to_correct_tip_and_work() {
        let genesis = [0u8; 32];
        let h1 = hdr(genesis, 1);
        let hash1 = h1.hash();
        let h2 = hdr(hash1, 2);
        let hash2 = h2.hash();

        let steps = vec![step_from(genesis, hash1, 3), step_from(hash1, hash2, 5)];
        let (g_hi, g_lo) = hash_to_limbs::<S1>(&genesis);
        let zn = run(&steps, [g_hi, g_lo, S1::from(0u64)]).expect("verify");

        let (t_hi, t_lo) = hash_to_limbs::<S1>(&hash2);
        assert_eq!(zn[0], t_hi, "tip_hi");
        assert_eq!(zn[1], t_lo, "tip_lo");
        assert_eq!(zn[2], S1::from(8u64), "cumwork = 3 + 5");
    }

    #[test]
    fn broken_linkage_fails_to_verify() {
        let genesis = [0u8; 32];
        let hash1 = hdr(genesis, 1).hash();
        // Second step claims a prev_hash that is NOT hash1 → linkage constraint broken.
        let bogus_prev = [0xabu8; 32];
        let steps = vec![step_from(genesis, hash1, 3), step_from(bogus_prev, [0x11u8; 32], 5)];
        let (g_hi, g_lo) = hash_to_limbs::<S1>(&genesis);
        // Either prove_step or verify must reject it — a mis-linked chain must
        // not prove. Guard against a possible panic inside proving as well.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run(&steps, [g_hi, g_lo, S1::from(0u64)])
        }));
        let rejected = match result {
            Err(_) => true,     // proving panicked on the unsatisfied constraint
            Ok(Ok(_)) => false, // verified — must NOT happen
            Ok(Err(_)) => true, // verify/prove returned an error
        };
        assert!(rejected, "a mis-linked chain must not produce a valid proof");
    }
}
