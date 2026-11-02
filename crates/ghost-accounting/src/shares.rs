//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: shares.rs                                                                                                      |
//|======================================================================================================================|

//! Share difficulty and proof-of-work checks.

/// Work difficulty calculator
#[derive(Debug, Clone)]
pub struct DifficultyCalculator {
    /// Target difficulty for pool shares
    pub share_difficulty: f64,
    /// Network difficulty
    pub network_difficulty: f64,
}

impl DifficultyCalculator {
    /// Create a new calculator
    pub fn new(share_difficulty: f64, network_difficulty: f64) -> Self {
        Self {
            share_difficulty,
            network_difficulty,
        }
    }

    /// Calculate work from a share
    pub fn calculate_work(&self, share_difficulty: f64) -> f64 {
        // Work is proportional to difficulty
        share_difficulty / self.share_difficulty
    }

    /// Check if share meets pool difficulty
    pub fn meets_share_difficulty(&self, difficulty: f64) -> bool {
        difficulty >= self.share_difficulty
    }

    /// Check if share is a valid block
    pub fn is_valid_block(&self, difficulty: f64) -> bool {
        difficulty >= self.network_difficulty
    }

    /// Calculate difficulty from a hash
    ///
    /// Bitcoin difficulty is calculated as:
    /// difficulty = (0xFFFF * 2^208) / hash_as_number
    ///
    /// Lower hash values = higher difficulty
    pub fn difficulty_from_hash(hash: &[u8; 32]) -> f64 {
        // The hash is a 256-bit number with its most-significant byte at index 31
        // (the PoW leading zeros sit at the high-index end). The share's difficulty
        // is the standard pool difficulty `diff1_target / hash_value`, where the
        // difficulty-1 target (pdiff) is 0xFFFF * 2^208.
        //
        // This uses the FULL hash value, not just the leading-zero count. The old
        // leading-zeros approximation (2^(leading_zeros-32)) ignored everything
        // after the first non-zero byte and so under-counted by up to ~2x — which
        // made C4 verify_share_difficulty reject valid gossiped shares whose `work`
        // (the standard difficulty reported by the SV2/SRI layer) exceeded the
        // approximation. f64 has ~52 bits of mantissa, ample for the difficulty
        // comparison (which carries a 0.1% tolerance); the low bits of the hash do
        // not affect the result.
        let mut hash_value = 0.0_f64;
        for &byte in hash.iter().rev() {
            hash_value = hash_value * 256.0 + byte as f64;
        }

        // All-zero hash (shouldn't occur in practice) — treat as maximal difficulty.
        if hash_value == 0.0 {
            return f64::MAX;
        }

        // diff1_target (pdiff) = 0xFFFF * 2^208. Both factors are exact in f64.
        let diff1_target = 65535.0_f64 * 2.0_f64.powi(208);
        diff1_target / hash_value
    }

    /// Verify that a share hash meets the claimed difficulty
    ///
    /// This is the cryptographic verification that the miner actually did the work
    ///
    /// HIGH-POOL-5: Tolerance reduced from 1% to 0.1% to match L-17 fix in round.rs.
    /// A 1% tolerance allows accumulation gaming where miners systematically
    /// claim higher difficulty than achieved, gaining up to 1% extra reward.
    pub fn verify_share_difficulty(&self, hash: &[u8; 32], claimed_difficulty: f64) -> bool {
        let actual_difficulty = Self::difficulty_from_hash(hash);
        // HIGH-POOL-5: 0.1% tolerance for floating point imprecision (was 1%)
        // This matches the tolerance in round.rs L-17 fix
        actual_difficulty >= claimed_difficulty * 0.999
    }

    /// Independent PoW re-verification (multi-operator). Recompute the share hash from
    /// the raw 80-byte Bitcoin block header and confirm it BOTH equals `expected_hash`
    /// AND meets `claimed_difficulty`.
    ///
    /// A conventional pool trusts its own SRI layer to have validated PoW — fine, one
    /// operator. A DECENTRALISED pool gossips shares between MUTUALLY-DISTRUSTING
    /// operators and pays out on the aggregate, so `verify_share_difficulty` (which only
    /// checks the NUMERIC value of a supplied 32-byte hash) is not enough: a hostile
    /// operator broadcasts a fabricated `share_hash` with an in-range numeric difficulty
    /// and no real hashing, and mints unbounded fake work for its own address. Binding the
    /// hash to a real header preimage is the only thing that makes fabrication impossible —
    /// you cannot produce an 80-byte header whose `sha256d` meets the target without
    /// actually doing the work.
    ///
    /// `header80` is the raw header; the recomputed hash and `expected_hash` are in
    /// INTERNAL byte order (PoW zeros at the high-index end), matching
    /// [`Self::difficulty_from_hash`] and the ledger's stored `share_hash`.
    pub fn verify_pow_preimage(
        header80: &[u8; 80],
        expected_hash: &[u8; 32],
        claimed_difficulty: f64,
    ) -> bool {
        use bitcoin::hashes::{sha256d, Hash};
        let computed = sha256d::Hash::hash(header80).to_byte_array();
        if &computed != expected_hash {
            return false; // the supplied hash is not this header's PoW — fabricated/relayed
        }
        // Reuse the 0.1% difficulty tolerance of the numeric check.
        Self::difficulty_from_hash(&computed) >= claimed_difficulty * 0.999
    }

    /// Tier-bound PoW check: the tier-committed counterpart to [`Self::verify_pow_preimage`].
    ///
    /// [`Self::verify_pow_preimage`] credits `claimed_difficulty`, a figure supplied alongside the
    /// share rather than derived from anything a remote node can recompute. This function instead
    /// credits a tier the share committed to inside its hashed coinbase (see
    /// [`ghost_common::share_binding::verify_share_tier_binding`]), fixed before the hash exists, and
    /// credits **exactly that committed tier** — never the achieved difficulty.
    ///
    /// Given the raw header, its expected internal-order hash, and the committed
    /// `claimed_tier_log2`, this returns `Some(tier_target)` — the difficulty `2^claimed_tier_log2`
    /// to credit — iff:
    ///   1. `sha256d(header) == expected_hash` (the hash is this header's real PoW, not fabricated),
    ///      and
    ///   2. the achieved difficulty is at least the tier's target (the header genuinely met the tier
    ///      it committed to).
    ///
    /// Otherwise `None`.
    ///
    /// Callers must ALSO verify the binding — that the coinbase actually committed to this
    /// `(node_id, claimed_tier_log2)` — via `verify_share_tier_binding`. This function judges the
    /// PoW and fixes the credit; the binding proves the tier was chosen up front. Both are required:
    /// without the binding, `claimed_tier_log2` would once again be a free post-hoc choice.
    pub fn verify_pow_preimage_tier(
        header80: &[u8; 80],
        expected_hash: &[u8; 32],
        claimed_tier_log2: u32,
    ) -> Option<f64> {
        use bitcoin::hashes::{sha256d, Hash};
        let computed = sha256d::Hash::hash(header80).to_byte_array();
        if &computed != expected_hash {
            return None; // the supplied hash is not this header's PoW — fabricated/relayed
        }
        let tier_target = ghost_common::coinbase_tags::tier_target_difficulty(claimed_tier_log2);
        // Reuse the 0.1% tolerance the numeric checks carry for f64 imprecision.
        if Self::difficulty_from_hash(&computed) >= tier_target * 0.999 {
            Some(tier_target)
        } else {
            None
        }
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {

    use super::*;

    #[test]
    fn test_difficulty_calculator() {
        let calc = DifficultyCalculator::new(1000.0, 1_000_000.0);

        assert!(calc.meets_share_difficulty(1500.0));
        assert!(!calc.meets_share_difficulty(500.0));
        assert!(!calc.is_valid_block(500_000.0));
        assert!(calc.is_valid_block(1_500_000.0));
    }

    #[test]
    fn test_difficulty_from_hash_is_precise_not_leading_zero_underestimate() {
        // Regression: difficulty_from_hash was a leading-zeros approximation
        // (2^(leading_zeros-32)) that under-counts by up to ~2x because it ignores
        // everything after the first non-zero byte. The SV2/SRI layer reports the
        // STANDARD difficulty as `work`, so C4 verify_share_difficulty rejected
        // valid gossiped shares whose leading-zero count understated them — every
        // share dropped on the elders, every payout rejected by GHOST-02.
        //
        // The difficulty-1 target (pdiff) is 0xFFFF * 2^208; a hash equal to it has
        // difficulty exactly 1.0.
        let mut diff1 = [0u8; 32];
        diff1[26] = 0xFF;
        diff1[27] = 0xFF;
        let d1 = DifficultyCalculator::difficulty_from_hash(&diff1);
        assert!((d1 - 1.0).abs() < 1e-6, "diff-1 target → 1.0, got {d1}");

        // A hash AT the difficulty-1.5 target: 0xAAAA * 2^208 (0xFFFF / 1.5 = 0xAAAA).
        // Precise difficulty = 1.5. The old leading-zeros formula gave only 1.0
        // (32 leading zero bits, then 0xAA), so verify_share_difficulty(_, 1.5)
        // wrongly REJECTED it.
        let mut h = [0u8; 32];
        h[26] = 0xAA;
        h[27] = 0xAA;
        let d = DifficultyCalculator::difficulty_from_hash(&h);
        assert!((d - 1.5).abs() < 0.01, "diff-1.5 target → ~1.5, got {d}");

        let calc = DifficultyCalculator::new(1.0, 1_000_000.0);
        assert!(
            calc.verify_share_difficulty(&h, 1.5),
            "a hash meeting the claimed standard difficulty must pass C4 \
             (regression: leading-zeros under-count rejected it)"
        );
        // And a hash that genuinely does NOT meet the claimed difficulty is rejected.
        let mut easy = [0u8; 32];
        easy[27] = 0xFF; // difficulty ~1.0
        assert!(
            !calc.verify_share_difficulty(&easy, 4.0),
            "a hash below the claimed difficulty must still be rejected"
        );
    }

    #[test]
    fn pow_preimage_accepts_real_header_and_rejects_fabrication() {
        use bitcoin::consensus::Encodable;
        use bitcoin::hashes::Hash;

        // A REAL header (Bitcoin genesis) — a known-valid PoW preimage.
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let mut bytes = Vec::new();
        genesis.header.consensus_encode(&mut bytes).unwrap();
        let header80: [u8; 80] = bytes.try_into().unwrap();
        let real_hash: [u8; 32] = genesis.header.block_hash().to_byte_array();

        // The genuine header + its hash + a modest difficulty verifies.
        assert!(
            DifficultyCalculator::verify_pow_preimage(&header80, &real_hash, 1.0),
            "a real header whose sha256d == the hash must verify"
        );

        // FABRICATION: a hash that is NOT this header's sha256d is rejected — the core
        // multi-operator defence. An attacker can pick any low-numeric-difficulty value,
        // but cannot produce a header that hashes to it without doing the work.
        let mut fabricated = real_hash;
        fabricated[0] ^= 0x01;
        assert!(
            !DifficultyCalculator::verify_pow_preimage(&header80, &fabricated, 1.0),
            "a hash that isn't the header's preimage must be rejected"
        );

        // A real header + real hash but a claimed difficulty far above what it meets
        // (genesis is ~diff 1) is rejected on the difficulty check.
        assert!(
            !DifficultyCalculator::verify_pow_preimage(&header80, &real_hash, 1e12),
            "must reject work claimed far above the header's actual difficulty"
        );
    }

    /// A REAL header for the tier tests: the Bitcoin genesis header, which meets difficulty ~1
    /// (tier 0 → target 1.0) and no higher.
    fn genesis_header() -> ([u8; 80], [u8; 32]) {
        use bitcoin::consensus::Encodable;
        use bitcoin::hashes::Hash;
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let mut bytes = Vec::new();
        genesis.header.consensus_encode(&mut bytes).unwrap();
        let header80: [u8; 80] = bytes.try_into().unwrap();
        let real_hash: [u8; 32] = genesis.header.block_hash().to_byte_array();
        (header80, real_hash)
    }

    /// The tier-bound credit is the COMMITTED tier, not the achieved difficulty — which is what
    /// removes the post-hoc-claim advantage. Genesis achieves difficulty ~2536, but a share
    /// committed to tier 11 (target 2048) is credited exactly 2048, NOT the 2536 it happened to
    /// reach. Under the legacy numeric check that same header could claim ~2536; here it earns the
    /// tier it committed to before hashing.
    #[test]
    fn tier_credit_is_the_committed_tier_not_the_achieved_difficulty() {
        let (header80, real_hash) = genesis_header();

        let achieved = DifficultyCalculator::difficulty_from_hash(&real_hash);
        assert!(
            (2048.0..4096.0).contains(&achieved),
            "genesis is expected to achieve ~2536 (tier 11); got {achieved}"
        );

        // Committed to tier 11 → credited EXACTLY 2^11 = 2048, strictly below the achieved 2536.
        assert_eq!(
            DifficultyCalculator::verify_pow_preimage_tier(&header80, &real_hash, 11),
            Some(2048.0),
            "credit is the committed tier (2048), not the achieved difficulty (~2536)"
        );
        // The legacy check would have credited the full achieved difficulty for the same header.
        assert!(
            DifficultyCalculator::verify_pow_preimage(&header80, &real_hash, 2048.0)
                && achieved > 2048.0,
            "the legacy path credits more than the tier for the identical work"
        );
    }

    /// A share cannot be credited a tier it did not achieve: genesis reaches ~2536, so tier 12
    /// (target 4096) and above earn nothing. Committing to a fat tier up front only pays if the work
    /// is genuinely there.
    #[test]
    fn a_tier_above_the_achieved_difficulty_is_refused() {
        let (header80, real_hash) = genesis_header();
        assert_eq!(
            DifficultyCalculator::verify_pow_preimage_tier(&header80, &real_hash, 12),
            None,
            "genesis does not achieve tier 12 (difficulty 4096), so it earns no credit at that tier"
        );
        // And a wildly high tier is likewise refused.
        assert_eq!(
            DifficultyCalculator::verify_pow_preimage_tier(&header80, &real_hash, 40),
            None
        );
    }

    /// Fabrication is still impossible in the tier path: a hash that is not the header's real
    /// `sha256d` earns nothing, exactly as in the numeric-claim path.
    #[test]
    fn tier_path_rejects_a_fabricated_hash() {
        let (header80, real_hash) = genesis_header();
        let mut fabricated = real_hash;
        fabricated[0] ^= 0x01;
        assert_eq!(
            DifficultyCalculator::verify_pow_preimage_tier(&header80, &fabricated, 0),
            None,
            "a hash that isn't the header's preimage must earn no credit"
        );
    }

    /// **Below-gate no-change proof (accounting layer).** Adding the tier path must not perturb the
    /// legacy `verify_pow_preimage`, which is the function used below the tier gate. Its verdicts on
    /// a real header — accept at achievable difficulty, reject a fabrication, reject an
    /// over-claim — are exactly as before the tier work landed.
    #[test]
    fn the_legacy_pow_preimage_check_is_unchanged() {
        let (header80, real_hash) = genesis_header();

        assert!(
            DifficultyCalculator::verify_pow_preimage(&header80, &real_hash, 1.0),
            "legacy check still accepts a real header at an achievable difficulty"
        );
        let mut fabricated = real_hash;
        fabricated[0] ^= 0x01;
        assert!(
            !DifficultyCalculator::verify_pow_preimage(&header80, &fabricated, 1.0),
            "legacy check still rejects a fabricated hash"
        );
        assert!(
            !DifficultyCalculator::verify_pow_preimage(&header80, &real_hash, 1e12),
            "legacy check still rejects an over-claim"
        );
    }
}
