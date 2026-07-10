//! Phase 1 — cumulative-PoW folding, **native reference**.
//!
//! This is the plain-Rust spec of one folding step. The Nova `StepCircuit`
//! (added next — see the module-level TODO) must encode *exactly* this: same
//! header serialization, same double-SHA256, same target/PoW comparison, same
//! work accumulation. Keeping the reference here means the circuit has a
//! byte-for-byte oracle to test against.
//!
//! ## Folding state `z`
//! `z = (prev_block_hash: U256, cumulative_work: u128)`.
//! Step input: one 80-byte header `h`. The step proves:
//! 1. `h.prev_hash == z.prev_block_hash` (links to the running tip),
//! 2. `double_sha256(h) <= target(h.bits)` (valid PoW),
//! and outputs `z' = (double_sha256(h), z.cumulative_work + work(h.bits))`.
//!
//! NOTE (spike simplifications, tighten in Phase 1.1): cumulative work is `u128`
//! (fine for regtest/low-diff; mainnet needs U256 big-int); genesis linkage and
//! the retarget/time rules are out of scope for the PoW spike.

use crate::U256;
use sha2::{Digest, Sha256};

/// Bitcoin/Ghost 80-byte block header.
#[derive(Clone, Debug)]
pub struct BlockHeader {
    pub version: i32,
    pub prev_hash: U256, // internal (little-endian) byte order, as serialized
    pub merkle_root: U256,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PowError {
    /// `h.prev_hash` did not match the running tip.
    BrokenChain,
    /// `double_sha256(h) > target(h.bits)`.
    InsufficientWork,
}

impl BlockHeader {
    /// Consensus 80-byte serialization (all little-endian; hashes as stored).
    pub fn serialize(&self) -> [u8; 80] {
        let mut out = [0u8; 80];
        out[0..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(&self.prev_hash);
        out[36..68].copy_from_slice(&self.merkle_root);
        out[68..72].copy_from_slice(&self.time.to_le_bytes());
        out[72..76].copy_from_slice(&self.bits.to_le_bytes());
        out[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// Block hash = SHA256(SHA256(header)). Returned in internal byte order.
    pub fn hash(&self) -> U256 {
        double_sha256(&self.serialize())
    }
}

/// SHA256d over arbitrary bytes.
pub fn double_sha256(bytes: &[u8]) -> U256 {
    let first = Sha256::digest(bytes);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Expand the compact `bits` (nBits) into the full 256-bit target, big-endian.
pub fn target_from_bits(bits: u32) -> U256 {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    let mut target = [0u8; 32];
    if exponent <= 3 {
        let m = mantissa >> (8 * (3 - exponent));
        target[29..32].copy_from_slice(&m.to_be_bytes()[1..4]);
    } else if exponent <= 32 {
        // Place the 3 mantissa bytes so their least-significant byte sits at
        // position (32 - exponent).
        let m = mantissa.to_be_bytes(); // [0, b2, b1, b0]
        let end = 32 - (exponent - 3); // one past the low mantissa byte
        target[end - 3..end].copy_from_slice(&m[1..4]);
    }
    target
}

/// PoW work for a target: floor(2^256 / (target + 1)). u128 (spike; see NOTE).
pub fn work_from_target(target: &U256) -> u128 {
    // Interpret target as a big-endian integer; compute 2^256/(target+1) via the
    // leading bits. For the spike we approximate with the top 128 bits, which is
    // exact enough to accumulate + compare in tests. Phase 1.1 replaces with a
    // U256 big-int division.
    let mut hi = 0u128;
    for &b in &target[0..16] {
        hi = (hi << 8) | b as u128;
    }
    if hi == 0 {
        return u128::MAX; // max target region → treat as max representable work
    }
    (u128::MAX / hi).max(1)
}

/// Compare two big-endian 256-bit values: `a <= b`.
fn le_u256(a: &U256, b: &U256) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    true
}

/// One folding step (native). Verifies chain linkage + PoW, returns the new
/// `(tip_hash, cumulative_work)`.
pub fn fold_header(
    prev_hash: U256,
    prev_cumwork: u128,
    header: &BlockHeader,
) -> Result<(U256, u128), PowError> {
    if header.prev_hash != prev_hash {
        return Err(PowError::BrokenChain);
    }
    let target = target_from_bits(header.bits);
    // Block hash for PoW is compared in big-endian numeric order; the internal
    // hash is little-endian, so reverse it before comparing to the target.
    let h = header.hash();
    let mut h_be = h;
    h_be.reverse();
    if !le_u256(&h_be, &target) {
        return Err(PowError::InsufficientWork);
    }
    Ok((h, prev_cumwork.saturating_add(work_from_target(&target))))
}

// TODO(Phase 1): add `mod pow_step_circuit` implementing nova_snark::traits::
// circuit::StepCircuit for this exact computation (arity 3: [prev_hash_hi,
// prev_hash_lo, cumwork]; header supplied as circuit auxiliary input; SHA256d
// via a bellpepper sha256 gadget; target/PoW comparison + work add in-circuit),
// then a RecursiveSNARK folding test that agrees with `fold_header` above.

#[cfg(test)]
mod tests {
    use super::*;

    fn easy_header(prev: U256, nonce: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_hash: prev,
            merkle_root: [7u8; 32],
            time: 1_700_000_000,
            bits: 0x207f_ffff, // regtest max target → any hash passes PoW
            nonce,
        }
    }

    /// Mine a header on `prev`: scan nonces until one passes PoW under the
    /// regtest target (~50% hit rate, so a couple of tries). Returns the header
    /// plus the folded `(tip, cumulative_work)`.
    fn mine_on(prev: U256, prev_cumwork: u128) -> (BlockHeader, U256, u128) {
        for nonce in 0..1_000_000u32 {
            let h = easy_header(prev, nonce);
            if let Ok((tip, cw)) = fold_header(prev, prev_cumwork, &h) {
                return (h, tip, cw);
            }
        }
        panic!("no valid nonce found under regtest target");
    }

    #[test]
    fn fold_two_linked_headers_accumulates_work() {
        let genesis_hash = [0u8; 32];
        let (_h1, tip1, work1) = mine_on(genesis_hash, 0);
        assert!(work1 > 0);

        // h2 links to h1's hash.
        let (h2, tip2, work2) = mine_on(tip1, work1);
        assert_eq!(tip2, h2.hash());
        assert!(work2 > work1, "cumulative work must strictly increase");

        // A header that does NOT link to the running tip must be rejected.
        let bad = easy_header([0xabu8; 32], 0);
        assert_eq!(fold_header(tip2, work2, &bad), Err(PowError::BrokenChain));
    }

    #[test]
    fn broken_chain_is_rejected() {
        let h = easy_header([9u8; 32], 1);
        assert_eq!(fold_header([1u8; 32], 0, &h), Err(PowError::BrokenChain));
    }

    #[test]
    fn max_target_expands_to_all_ones_region() {
        // regtest bits 0x207fffff → very large target (top byte near 0x7f..).
        let t = target_from_bits(0x207f_ffff);
        assert_ne!(t, [0u8; 32]);
    }
}
