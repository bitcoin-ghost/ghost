//! Phase 1c — SHA256d gadget: compute a block hash **in-circuit**.
//!
//! `sha256d(bytes)` witnesses the input bytes as bits, runs the nova/bellpepper
//! `sha256` gadget twice, and returns the 256 output `Boolean`s. This is what
//! lets the folding step *derive* the new-tip limbs (instead of witnessing them)
//! and, with a target comparison, enforce real PoW — matching the native
//! [`crate::cumulative_pow::double_sha256`] oracle.
//!
//! Bit convention (bellpepper's): within each byte, **MSB first**; bytes in
//! order. Both the input and the 256-bit output follow this.

use ff::PrimeField;
use nova_snark::frontend::{sha256, AllocatedBit, Boolean, ConstraintSystem, SynthesisError};

/// Witness `bytes` as SHA256-input bits (MSB-first per byte) and return
/// `SHA256(SHA256(bytes))` as 256 `Boolean`s.
pub fn sha256d<Scalar, CS>(mut cs: CS, bytes: &[u8]) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for (i, byte) in bytes.iter().enumerate() {
        for j in (0..8).rev() {
            let b = (byte >> j) & 1 == 1;
            let bit = AllocatedBit::alloc(cs.namespace(|| format!("in_bit_{i}_{j}")), Some(b))?;
            bits.push(Boolean::from(bit));
        }
    }
    let first = sha256(cs.namespace(|| "sha256_1"), &bits)?;
    let second = sha256(cs.namespace(|| "sha256_2"), &first)?;
    Ok(second)
}

/// Read the concrete byte value out of 256 output `Boolean`s (MSB-first).
pub fn bits_to_bytes(bits: &[Boolean]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in bits.chunks(8).enumerate().take(32) {
        let mut byte = 0u8;
        for (j, bit) in chunk.iter().enumerate() {
            if bit.get_value().unwrap_or(false) {
                byte |= 1 << (7 - j);
            }
        }
        out[i] = byte;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cumulative_pow::{double_sha256, BlockHeader};
    use nova_snark::frontend::solver::SatisfyingAssignment;
    use nova_snark::provider::PallasEngine;

    // Witness-generating CS: synthesizes + computes assignments, so the output
    // Booleans carry the concrete hash. (Constraint *satisfaction* is proven by
    // the 1a/1b folding tests; here we verify the gadget computes the right hash.)
    #[test]
    fn in_circuit_sha256d_matches_native_empty() {
        let native = double_sha256(&[]);
        let mut cs = SatisfyingAssignment::<PallasEngine>::new();
        let out = sha256d(&mut cs, &[]).unwrap();
        assert_eq!(bits_to_bytes(&out), native, "SHA256d(empty) mismatch");
    }

    #[test]
    fn in_circuit_sha256d_matches_native_header() {
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [7u8; 32],
            time: 1_700_000_000,
            bits: 0x207f_ffff,
            nonce: 42,
        };
        let bytes = header.serialize();
        let native = double_sha256(&bytes); // == header.hash()

        let mut cs = SatisfyingAssignment::<PallasEngine>::new();
        let out = sha256d(&mut cs, &bytes).unwrap();
        assert_eq!(
            bits_to_bytes(&out),
            native,
            "in-circuit SHA256d must equal native double_sha256(header)"
        );
    }
}
