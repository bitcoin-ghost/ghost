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

//! Share accounting for mining rewards

use std::collections::HashMap;
use tracing::{debug, error, trace, warn};

use ghost_common::types::{NodeCapabilities, NodeId, RoundId};

/// Work scaling factor for integer arithmetic (H7 security fix)
/// Using 10^12 gives 12 decimal places of precision while fitting in u128
pub const WORK_SCALE: u128 = 1_000_000_000_000;

/// CRIT-MINE-3: Maximum total accumulated work (scaled) to prevent overflow
///
/// This is calculated as: u128::MAX / MAX_MINERS / SAFETY_MARGIN
/// - u128::MAX = ~3.4e38
/// - MAX_MINERS = 200 (from MAX_MINER_OUTPUTS)
/// - WORK_SCALE = 1e12
/// - SAFETY_MARGIN = 1000 (for headroom)
///
/// Result: (3.4e38 / 200 / 1000) = 1.7e35
///
/// In practice, this allows for:
/// - ~1.7e23 work units (unscaled) total per round
/// - At 10 EH/s pool hashrate, this is ~5e12 seconds (~170 million years) of mining
/// - So this limit will never be hit in practice, but prevents overflow attacks
pub const MAX_TOTAL_WORK_SCALED: u128 = u128::MAX / 200 / 1000;

/// Share accounting for a round
///
/// H7 security fix: Work values are stored as scaled u128 internally
/// to prevent floating-point precision errors that could benefit attackers.
/// External APIs still accept f64 for compatibility but convert immediately.
#[derive(Debug, Clone, Default)]
pub struct RoundShares {
    /// Round ID
    pub round_id: RoundId,
    /// Block height
    pub block_height: u64,
    /// Miner shares (miner_id -> scaled work as u128)
    miner_shares_scaled: HashMap<String, u128>,
    /// Miner shares (miner_id -> work) - f64 view for compatibility
    pub miner_shares: HashMap<String, f64>,
    /// Node shares (node_id -> capability shares)
    pub node_shares: HashMap<NodeId, NodeShareInfo>,
    /// Total miner work (scaled as u128)
    total_miner_work_scaled: u128,
    /// Total miner work - f64 view for compatibility
    pub total_miner_work: f64,
    /// Total node capability shares
    pub total_node_shares: i32,
}

/// Node share information
#[derive(Debug, Clone)]
pub struct NodeShareInfo {
    /// Node ID
    pub node_id: NodeId,
    /// Capability shares (0-15)
    pub shares: i32,
    /// Capabilities breakdown
    pub capabilities: NodeCapabilities,
    /// Shares received count
    pub shares_received: u64,
    /// Is in top 100 for this round
    pub in_top_100: bool,
}

impl RoundShares {
    /// Create a new round shares tracker
    pub fn new(round_id: RoundId, block_height: u64) -> Self {
        Self {
            round_id,
            block_height,
            miner_shares_scaled: HashMap::new(),
            miner_shares: HashMap::new(),
            node_shares: HashMap::new(),
            total_miner_work_scaled: 0,
            total_miner_work: 0.0,
            total_node_shares: 0,
        }
    }

    /// Add miner work (H7 security fix)
    ///
    /// Internally stores as scaled u128 to prevent floating-point accumulation errors.
    /// The f64 view is updated for compatibility with existing code.
    ///
    /// Returns false if the work value is invalid (negative, NaN, or Inf).
    pub fn add_miner_work(&mut self, miner_id: &str, work: f64) -> bool {
        // LOW-POOL-2 / SEC-SHARE-1: Validate work is non-negative and log rejection
        if work < 0.0 {
            warn!(
                miner = %miner_id,
                work = work,
                reason = "negative_work",
                "LOW-POOL-2: Rejected share with negative work value"
            );
            return false;
        }

        // LOW-POOL-2 / SEC-SHARE-2: Validate work is finite (not NaN or Inf) and log rejection
        if !work.is_finite() {
            warn!(
                miner = %miner_id,
                work = work,
                reason = "non_finite_work",
                "LOW-POOL-2: Rejected share with non-finite work value (NaN/Inf)"
            );
            return false;
        }

        trace!(miner = %miner_id, work = work, "Adding miner work");

        // L-14: Bounds check before float-to-int conversion
        // Maximum safe work value before scaling would overflow u128:
        // u128::MAX / WORK_SCALE = 340_282_366_920_938_463_463 (approx 3.4e20)
        // f64 can only represent integers exactly up to 2^53 (~9e15)
        // So we use a conservative upper bound that's well within f64 precision
        const MAX_SAFE_WORK: f64 = 1e15; // Well within both f64 precision and u128/WORK_SCALE
        if work > MAX_SAFE_WORK {
            warn!(
                miner = %miner_id,
                work = work,
                max_safe = MAX_SAFE_WORK,
                reason = "exceeds_safe_limit",
                "LOW-POOL-2: Rejected share with work value exceeding safe conversion limit"
            );
            return false;
        }

        // Convert to scaled integer (H7 security fix)
        // L-14: At this point work <= MAX_SAFE_WORK, so work * WORK_SCALE fits in f64 and u128
        let work_scaled = (work * WORK_SCALE as f64) as u128;

        // CRIT-MINE-3: Check for overflow BEFORE adding work
        // Use checked_add to detect overflow instead of silently wrapping
        let new_total = match self.total_miner_work_scaled.checked_add(work_scaled) {
            Some(total) => total,
            None => {
                error!(
                    miner = %miner_id,
                    current_total = self.total_miner_work_scaled,
                    adding = work_scaled,
                    "CRIT-MINE-3 CRITICAL: Total work overflow - would exceed u128::MAX"
                );
                return false;
            }
        };

        // CRIT-MINE-3 / MED-POOL-4: Enforce maximum total work limit
        // MED-POOL-4: Use >= instead of > to reject at exactly the limit
        if new_total >= MAX_TOTAL_WORK_SCALED {
            error!(
                miner = %miner_id,
                current_total = self.total_miner_work_scaled,
                adding = work_scaled,
                new_total = new_total,
                max_allowed = MAX_TOTAL_WORK_SCALED,
                "CRIT-MINE-3 CRITICAL: Total work would exceed MAX_TOTAL_WORK_SCALED - rejecting work submission"
            );
            return false;
        }

        // Update scaled storage (using checked_add for miner's entry too)
        let miner_entry = self
            .miner_shares_scaled
            .entry(miner_id.to_string())
            .or_insert(0);
        match miner_entry.checked_add(work_scaled) {
            Some(new_miner_work) => {
                *miner_entry = new_miner_work;
            }
            None => {
                error!(
                    miner = %miner_id,
                    current_work = *miner_entry,
                    adding = work_scaled,
                    "CRIT-MINE-3 CRITICAL: Miner's work overflow - rejecting"
                );
                return false;
            }
        }

        self.total_miner_work_scaled = new_total;

        // Update f64 view from scaled values (ensures consistency)
        let miner_total_scaled = *self.miner_shares_scaled.get(miner_id).unwrap_or(&0);
        self.miner_shares.insert(
            miner_id.to_string(),
            miner_total_scaled as f64 / WORK_SCALE as f64,
        );
        self.total_miner_work = self.total_miner_work_scaled as f64 / WORK_SCALE as f64;

        true
    }

    /// Get miner work as scaled integer (for precise calculations)
    pub fn miner_work_scaled(&self, miner_id: &str) -> u128 {
        *self.miner_shares_scaled.get(miner_id).unwrap_or(&0)
    }

    /// Get total work as scaled integer (for precise calculations)
    pub fn total_work_scaled(&self) -> u128 {
        self.total_miner_work_scaled
    }

    /// Register a node's capabilities
    pub fn register_node(&mut self, node_id: NodeId, capabilities: NodeCapabilities) {
        let shares = capabilities.total_shares();

        self.node_shares.insert(
            node_id,
            NodeShareInfo {
                node_id,
                shares,
                capabilities,
                shares_received: 0,
                in_top_100: false, // Will be calculated later
            },
        );
    }

    /// Increment node's received share count
    pub fn increment_node_shares(&mut self, node_id: &NodeId) {
        if let Some(info) = self.node_shares.get_mut(node_id) {
            info.shares_received += 1;
        }
    }

    /// Calculate top 100 nodes (by shares received)
    pub fn calculate_top_100_nodes(&mut self) {
        // Sort nodes by shares received and collect their IDs with ranking
        let mut nodes: Vec<_> = self
            .node_shares
            .iter()
            .map(|(id, info)| (*id, info.shares_received))
            .collect();
        nodes.sort_by(|a, b| b.1.cmp(&a.1));

        // Collect top 100 node IDs
        let top_100_ids: Vec<NodeId> = nodes.iter().take(100).map(|(id, _)| *id).collect();

        // Reset all nodes, then mark top 100
        for info in self.node_shares.values_mut() {
            info.in_top_100 = false;
        }
        for id in &top_100_ids {
            if let Some(info) = self.node_shares.get_mut(id) {
                info.in_top_100 = true;
            }
        }

        // Calculate total shares for top 100
        self.total_node_shares = self
            .node_shares
            .values()
            .filter(|n| n.in_top_100)
            .map(|n| n.shares)
            .sum();

        debug!(
            round_id = self.round_id,
            total_nodes = self.node_shares.len(),
            top_100_shares = self.total_node_shares,
            "Calculated top 100 nodes"
        );
    }

    /// Get miner's share of total work (0.0 - 1.0)
    pub fn miner_share_percent(&self, miner_id: &str) -> f64 {
        if self.total_miner_work == 0.0 {
            return 0.0;
        }

        self.miner_shares
            .get(miner_id)
            .map(|w| w / self.total_miner_work)
            .unwrap_or(0.0)
    }

    /// Get node's share of total node shares (0.0 - 1.0)
    pub fn node_share_percent(&self, node_id: &NodeId) -> f64 {
        if self.total_node_shares == 0 {
            return 0.0;
        }

        self.node_shares
            .get(node_id)
            .filter(|n| n.in_top_100)
            .map(|n| n.shares as f64 / self.total_node_shares as f64)
            .unwrap_or(0.0)
    }

    /// Get top N miners by work
    pub fn top_miners(&self, n: usize) -> Vec<(&str, f64)> {
        let mut miners: Vec<_> = self
            .miner_shares
            .iter()
            .map(|(id, work)| (id.as_str(), *work))
            .collect();

        miners.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        miners.truncate(n);
        miners
    }

    /// Get top N miners by scaled u128 work (for payout calculations)
    ///
    /// Returns work as pre-scaled u128 integers, eliminating f64 precision loss
    /// at the RoundShares→PayoutHandler boundary.
    pub fn top_miners_scaled(&self, n: usize) -> Vec<(&str, u128)> {
        let mut miners: Vec<_> = self
            .miner_shares_scaled
            .iter()
            .map(|(id, work)| (id.as_str(), *work))
            .collect();

        miners.sort_by(|a, b| b.1.cmp(&a.1));
        miners.truncate(n);
        miners
    }

    /// Get top 100 nodes by shares received
    pub fn top_100_nodes(&self) -> Vec<&NodeShareInfo> {
        self.node_shares.values().filter(|n| n.in_top_100).collect()
    }

    /// Get nodes outside top 100 (for ledger credits)
    pub fn nodes_outside_top_100(&self) -> Vec<&NodeShareInfo> {
        self.node_shares
            .values()
            .filter(|n| !n.in_top_100)
            .collect()
    }

    /// Get miner count
    pub fn miner_count(&self) -> usize {
        self.miner_shares.len()
    }

    /// Get node count
    pub fn node_count(&self) -> usize {
        self.node_shares.len()
    }
}

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

    /// Verify that a share hash meets the pool's minimum difficulty
    pub fn verify_share_meets_pool_target(&self, hash: &[u8; 32]) -> bool {
        let actual_difficulty = Self::difficulty_from_hash(hash);
        actual_difficulty >= self.share_difficulty
    }

    /// Verify that a hash meets network difficulty (is a valid block)
    pub fn verify_block_hash(&self, hash: &[u8; 32]) -> bool {
        let actual_difficulty = Self::difficulty_from_hash(hash);
        actual_difficulty >= self.network_difficulty
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn test_round_shares() {
        let mut shares = RoundShares::new(1, 100);

        shares.add_miner_work("miner1", 100.0);
        shares.add_miner_work("miner2", 50.0);
        shares.add_miner_work("miner1", 50.0); // Additional work

        assert_eq!(shares.miner_count(), 2);
        assert_eq!(shares.total_miner_work, 200.0);
        assert_eq!(shares.miner_share_percent("miner1"), 0.75);
        assert_eq!(shares.miner_share_percent("miner2"), 0.25);
    }

    #[test]
    fn test_node_shares() {
        let mut shares = RoundShares::new(1, 100);

        let mut caps1 = NodeCapabilities::default();
        caps1.archive_mode = true; // +5
        caps1.public_mining = true; // +3

        let mut caps2 = NodeCapabilities::default();
        caps2.ghost_pay = true; // +4

        shares.register_node([1u8; 32], caps1);
        shares.register_node([2u8; 32], caps2);

        // Simulate share reception
        for _ in 0..10 {
            shares.increment_node_shares(&[1u8; 32]);
        }
        for _ in 0..5 {
            shares.increment_node_shares(&[2u8; 32]);
        }

        shares.calculate_top_100_nodes();

        assert_eq!(shares.total_node_shares, 12); // 8 + 4
    }

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

    /// SEC-SHARE-TEST-1: Verify that negative work values are rejected
    #[test]
    fn test_negative_work_rejected() {
        let mut shares = RoundShares::new(1, 100);

        // Negative work should be rejected
        let result = shares.add_miner_work("miner1", -100.0);
        assert!(!result, "Negative work should return false");

        // Verify no work was actually added
        assert_eq!(shares.total_miner_work, 0.0);
        assert_eq!(shares.miner_count(), 0);

        // Valid work should still be accepted
        let result = shares.add_miner_work("miner1", 100.0);
        assert!(result, "Positive work should return true");
        assert_eq!(shares.total_miner_work, 100.0);
    }

    /// SEC-SHARE-TEST-2: Verify that NaN and Infinity work values are rejected
    #[test]
    fn test_nan_inf_work_rejected() {
        let mut shares = RoundShares::new(1, 100);

        // NaN should be rejected
        let result = shares.add_miner_work("miner1", f64::NAN);
        assert!(!result, "NaN work should return false");
        assert_eq!(shares.miner_count(), 0);

        // Positive infinity should be rejected
        let result = shares.add_miner_work("miner2", f64::INFINITY);
        assert!(!result, "Positive infinity work should return false");
        assert_eq!(shares.miner_count(), 0);

        // Negative infinity should be rejected
        let result = shares.add_miner_work("miner3", f64::NEG_INFINITY);
        assert!(!result, "Negative infinity work should return false");
        assert_eq!(shares.miner_count(), 0);

        // Verify no work was added
        assert_eq!(shares.total_miner_work, 0.0);
    }

    /// L-14: Verify that work values exceeding safe conversion limits are rejected
    #[test]
    fn test_overflow_work_rejected() {
        let mut shares = RoundShares::new(1, 100);

        // Values above MAX_SAFE_WORK (1e15) should be rejected
        let result = shares.add_miner_work("miner1", 1e16);
        assert!(!result, "Work above MAX_SAFE_WORK should return false");
        assert_eq!(shares.miner_count(), 0);

        // Very large values should be rejected
        let result = shares.add_miner_work("miner2", 1e18);
        assert!(!result, "Very large work should return false");
        assert_eq!(shares.miner_count(), 0);

        // Values at the limit should be rejected
        let result = shares.add_miner_work("miner3", 1.0000001e15);
        assert!(!result, "Work at limit boundary should return false");
        assert_eq!(shares.miner_count(), 0);

        // Values below the limit should be accepted
        let result = shares.add_miner_work("miner4", 9e14);
        assert!(result, "Work below MAX_SAFE_WORK should return true");
        assert_eq!(shares.miner_count(), 1);

        // Verify no overflow work was added, only the valid one
        assert!(shares.total_miner_work > 0.0);
    }
}
