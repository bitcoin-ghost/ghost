//! Phase 1 (in-circuit) — Nova `StepCircuit` for the folding step.
//!
//! This is built up in increments so the fiddly recursion API is de-risked
//! before the expensive gadget:
//! - **1a (this):** a real folding step that *accumulates work* — `z' = z + w_i`
//!   — folded via `RecursiveSNARK`. Proves the Nova IVC pipeline works on our
//!   stack and yields first prove/verify numbers.
//! - 1b: carry the 256-bit tip hash in `z` (two field limbs) + enforce chain
//!   linkage (`header.prev_hash == z.tip`).
//! - 1c: add the bellpepper **SHA256d** gadget + big-endian target comparison,
//!   so the step verifies real PoW — at which point it matches `fold_header`.

use ff::PrimeField;
use nova_snark::frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;

/// One folding step: add this block's work to the running cumulative work.
/// `work` is the field encoding of `work_from_target(target)` for the block.
#[derive(Clone, Debug)]
pub struct WorkStep<F: PrimeField> {
    pub work: F,
}

impl<F: PrimeField> StepCircuit<F> for WorkStep<F> {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // `work` MUST be a witness variable, not a constant folded into the
        // constraint coefficient: Nova folds instances of the *same* R1CS, so
        // every step's constraint structure has to be identical (only the
        // witness values differ). Baking `self.work` into the coefficient made
        // each step a different R1CS → verify: UnSat.
        let work = AllocatedNum::alloc(cs.namespace(|| "work"), || Ok(self.work))?;
        let sum = AllocatedNum::alloc(cs.namespace(|| "cumwork'"), || {
            let prev = z[0].get_value().ok_or(SynthesisError::AssignmentMissing)?;
            let w = work.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(prev + w)
        })?;
        cs.enforce(
            || "cumwork' = cumwork + work",
            |lc| lc + z[0].get_variable() + work.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + sum.get_variable(),
        );
        Ok(vec![sum])
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
    type C1 = WorkStep<S1>;
    type C2 = TrivialCircuit<S2>;

    #[test]
    fn folding_accumulates_work_over_a_header_chain() {
        // Per-block works for a 4-block chain (stand-in for work_from_target).
        let works: Vec<u64> = vec![3, 5, 7, 11];
        let expected: u64 = works.iter().sum();

        let circuits: Vec<C1> = works
            .iter()
            .map(|w| WorkStep { work: S1::from(*w) })
            .collect();
        let c2 = C2::default();

        let pp = PublicParams::<E1, E2, C1, C2>::setup(
            &circuits[0],
            &c2,
            &*default_ck_hint(),
            &*default_ck_hint(),
        )
        .expect("public params");

        let z0_primary = vec![S1::from(0u64)];
        let z0_secondary = vec![S2::from(0u64)];

        let mut rs =
            RecursiveSNARK::<E1, E2, C1, C2>::new(&pp, &circuits[0], &c2, &z0_primary, &z0_secondary)
                .expect("recursive snark init");

        for c in &circuits {
            rs.prove_step(&pp, c, &c2).expect("prove step");
        }

        let (zn, _) = rs
            .verify(&pp, circuits.len(), &z0_primary, &z0_secondary)
            .expect("verify");

        assert_eq!(zn[0], S1::from(expected), "folded cumulative work mismatch");
    }
}
