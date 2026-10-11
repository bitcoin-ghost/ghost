//! Fee distribution logic shared between ghost-mining (L1) and ghost-pay (L2).
//!
//! Treasury decay schedule: Once treasury reaches 21 BTC, allocation decays over 5 years:
//! - Pre-threshold: 50% treasury, 50% nodes
//! - Year 1: 40% treasury, 60% nodes
//! - Year 2: 30% treasury, 70% nodes
//! - Year 3: 20% treasury, 80% nodes
//! - Year 4: 10% treasury, 90% nodes
//! - Year 5+: 0% treasury, 100% nodes

use chrono::{DateTime, Utc};
use ghost_common::constants::DUST_THRESHOLD_SATS;
use serde::{Deserialize, Serialize};

/// Treasury threshold in satoshis (21 BTC)
pub const TREASURY_THRESHOLD_SATS: u64 = 21 * 100_000_000;

/// Decay rates by year in basis points: (treasury_bps, node_bps) as fractions of pool fee
/// 5000 bps = 50% of the pool fee, 10000 bps = 100% of the pool fee
pub const DECAY_SCHEDULE_BPS: [(u64, u64); 6] = [
    (5000, 5000), // Pre-threshold / Year 0: 50/50
    (4000, 6000), // Year 1: 40/60
    (3000, 7000), // Year 2: 30/70
    (2000, 8000), // Year 3: 20/80
    (1000, 9000), // Year 4: 10/90
    (0, 10000),   // Year 5+: 0/100
];

/// Treasury state for decay calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryState {
    /// Current treasury balance in satoshis
    pub balance_sats: u64,
    /// Timestamp when threshold was reached (None if not yet reached)
    pub threshold_reached_at: Option<DateTime<Utc>>,
}

impl Default for TreasuryState {
    fn default() -> Self {
        Self::new()
    }
}

impl TreasuryState {
    pub fn new() -> Self {
        Self {
            balance_sats: 0,
            threshold_reached_at: None,
        }
    }

    /// Create from stored values
    pub fn from_stored(balance_sats: u64, threshold_reached_at: Option<DateTime<Utc>>) -> Self {
        Self {
            balance_sats,
            threshold_reached_at,
        }
    }

    /// Update balance and check threshold
    pub fn add_funds(&mut self, amount: u64) -> bool {
        self.balance_sats = self.balance_sats.saturating_add(amount);

        // Check if we just crossed threshold
        if self.threshold_reached_at.is_none() && self.balance_sats >= TREASURY_THRESHOLD_SATS {
            self.threshold_reached_at = Some(Utc::now());
            tracing::info!(
                balance = self.balance_sats,
                threshold = TREASURY_THRESHOLD_SATS,
                "Treasury threshold reached - decay begins"
            );
            return true; // Threshold just crossed
        }
        false
    }

    /// Check if threshold has been reached
    pub fn threshold_reached(&self) -> bool {
        self.threshold_reached_at.is_some()
    }

    /// Calculate years since threshold was reached
    ///
    /// M-5 SECURITY: Takes a reference timestamp instead of using Utc::now().
    /// This ensures all nodes calculate the same decay year for a given block,
    /// eliminating TOCTOU vulnerabilities where nodes might calculate different
    /// decay years due to clock drift or processing time differences.
    pub fn years_since_threshold(&self, reference_time: DateTime<Utc>) -> u32 {
        match self.threshold_reached_at {
            None => 0,
            Some(threshold_time) => {
                let elapsed = reference_time.signed_duration_since(threshold_time);
                let days = elapsed.num_days().max(0) as u32;
                // L-2: Using 365-day years as intentional approximation.
                // Decay schedule granularity is yearly - a few days difference has no impact.
                days / 365
            }
        }
    }

    /// Get current fee split rates in basis points (treasury_bps, node_bps)
    /// Returns (treasury_bps, node_bps) where each is a fraction of the pool fee.
    ///
    /// M-5 SECURITY: Takes a reference timestamp for deterministic calculation.
    /// CRIT-PANIC-5: Use saturating arithmetic and .get() for safe array access.
    pub fn get_fee_split_bps(&self, reference_time: DateTime<Utc>) -> (u64, u64) {
        let pre_threshold = *DECAY_SCHEDULE_BPS.first().unwrap_or(&(5000, 5000));
        if self.threshold_reached_at.is_none() {
            return pre_threshold;
        }

        let years = self.years_since_threshold(reference_time) as usize;
        let index = years
            .saturating_add(1)
            .min(DECAY_SCHEDULE_BPS.len().saturating_sub(1));
        *DECAY_SCHEDULE_BPS.get(index).unwrap_or(&(0, 10000))
    }

    /// Get the current decay year (0 = pre-threshold, 1-5 = decay years)
    ///
    /// M-5 SECURITY: Takes a reference timestamp for deterministic calculation.
    pub fn decay_year(&self, reference_time: DateTime<Utc>) -> u32 {
        if self.threshold_reached_at.is_none() {
            0
        } else {
            (self.years_since_threshold(reference_time) + 1).min(5)
        }
    }
}

/// Per-node direct L2 fee split: the node that processed the L2 transaction
/// gets half the fee (pre-threshold), treasury gets the other half.
/// Uses the same `DECAY_SCHEDULE_BPS` decay as the global distribution.
///
/// Returns `(treasury_amount, node_amount)`.
pub fn calculate_node_direct(
    fee_pool: u64,
    treasury_state: &TreasuryState,
    now: DateTime<Utc>,
) -> (u64, u64) {
    if fee_pool == 0 {
        return (0, 0);
    }

    let (treasury_bps, _node_bps) = treasury_state.get_fee_split_bps(now);
    let treasury_amount = (fee_pool as u128 * treasury_bps as u128 / 10000) as u64;
    let node_amount = fee_pool.saturating_sub(treasury_amount);

    (treasury_amount, node_amount)
}

/// L2 fee distribution: splits accumulated fees between treasury and
/// Ghost Pay nodes using the same decay schedule as L1.
#[derive(Debug, Clone)]
pub struct L2FeeDistribution {
    /// Total fee pool being distributed (sum of all undistributed epoch fees)
    pub total_fee_pool: u64,
    /// Treasury allocation (decays over time)
    pub treasury_amount: u64,
    /// Total amount distributed to Ghost Pay nodes
    pub node_pool: u64,
    /// Per-node payouts: (node_id, address, amount)
    pub node_payouts: Vec<(String, String, u64)>,
}

impl L2FeeDistribution {
    /// Calculate L2 fee distribution using the treasury decay schedule.
    ///
    /// - `total_fee_pool`: Sum of accumulated fees from `get_undistributed_fees()`
    /// - `treasury_state`: Current treasury state for decay calculation
    /// - `reference_time`: Block timestamp for deterministic decay year
    /// - `ghost_pay_nodes`: List of (node_id, address, capability_shares) for qualified nodes
    pub fn calculate(
        total_fee_pool: u64,
        treasury_state: &TreasuryState,
        reference_time: DateTime<Utc>,
        ghost_pay_nodes: &[(String, String, i32)],
    ) -> Self {
        if total_fee_pool == 0 {
            return Self {
                total_fee_pool: 0,
                treasury_amount: 0,
                node_pool: 0,
                node_payouts: Vec::new(),
            };
        }

        // Same decay schedule as L1
        let (treasury_bps, _node_bps) = treasury_state.get_fee_split_bps(reference_time);
        let treasury_amount = (total_fee_pool as u128 * treasury_bps as u128 / 10000) as u64;
        let node_pool = total_fee_pool.saturating_sub(treasury_amount);

        // Distribute node_pool among Ghost Pay nodes weighted by capability shares
        let node_payouts = distribute_to_nodes(node_pool, ghost_pay_nodes);

        Self {
            total_fee_pool,
            treasury_amount,
            node_pool,
            node_payouts,
        }
    }
}

/// Distribute `pool` among nodes weighted by capability shares.
///
/// - Sub-dust payouts (<546 sats) are redirected to the top node.
/// - If no nodes qualify, entire pool goes to treasury (returned as empty vec).
pub fn distribute_to_nodes(
    pool: u64,
    nodes: &[(String, String, i32)],
) -> Vec<(String, String, u64)> {
    if pool == 0 || nodes.is_empty() {
        return Vec::new();
    }

    // Filter out nodes with non-positive shares (negative shares would cause
    // overflow when cast to u128 for weighted distribution arithmetic)
    let qualified: Vec<&(String, String, i32)> = nodes.iter().filter(|(_, _, s)| *s > 0).collect();

    // Use i64 to avoid overflow when summing i32 shares
    let total_shares: i64 = qualified.iter().map(|(_, _, s)| *s as i64).sum();
    if total_shares <= 0 {
        return Vec::new();
    }

    // Weighted distribution with exact remainder handling
    let mut payouts: Vec<(String, String, u64)> = Vec::with_capacity(qualified.len());
    let mut distributed = 0u64;

    for (i, (node_id, address, shares)) in qualified.iter().enumerate() {
        let payout = if i == qualified.len() - 1 {
            // Last node gets the remainder (prevents rounding loss)
            pool.saturating_sub(distributed)
        } else {
            (pool as u128 * *shares as u128 / total_shares as u128) as u64
        };
        distributed += payout;
        payouts.push((node_id.clone(), address.clone(), payout));
    }

    // Redirect sub-dust payouts to top node (highest shares)
    let top_idx = payouts
        .iter()
        .enumerate()
        .max_by_key(|(_, (_, _, amt))| *amt)
        .map(|(i, _)| i)
        .unwrap_or(0);

    let mut dust_reclaimed = 0u64;
    for (i, (_, _, amt)) in payouts.iter_mut().enumerate() {
        if i != top_idx && *amt < DUST_THRESHOLD_SATS {
            dust_reclaimed += *amt;
            *amt = 0;
        }
    }
    payouts[top_idx].2 += dust_reclaimed;

    // Remove zero payouts
    payouts.retain(|(_, _, amt)| *amt > 0);
    payouts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_treasury_threshold_constant() {
        assert_eq!(TREASURY_THRESHOLD_SATS, 2_100_000_000); // 21 BTC
    }

    #[test]
    fn test_pre_threshold_split() {
        let state = TreasuryState::new();
        let now = Utc::now();
        let (treasury_bps, node_bps) = state.get_fee_split_bps(now);
        assert_eq!(treasury_bps, 5000); // 50%
        assert_eq!(node_bps, 5000); // 50%
        assert_eq!(state.decay_year(now), 0);
    }

    #[test]
    fn test_threshold_detection() {
        let mut state = TreasuryState::new();

        // Add funds below threshold
        state.add_funds(1_000_000_000); // 10 BTC
        assert!(!state.threshold_reached());

        // Cross threshold
        let crossed = state.add_funds(1_500_000_000); // +15 BTC = 25 BTC total
        assert!(crossed);
        assert!(state.threshold_reached());
        assert!(state.threshold_reached_at.is_some());
    }

    #[test]
    fn test_decay_schedule_bps_values() {
        assert_eq!(DECAY_SCHEDULE_BPS[0], (5000, 5000));
        assert_eq!(DECAY_SCHEDULE_BPS[1], (4000, 6000));
        assert_eq!(DECAY_SCHEDULE_BPS[2], (3000, 7000));
        assert_eq!(DECAY_SCHEDULE_BPS[3], (2000, 8000));
        assert_eq!(DECAY_SCHEDULE_BPS[4], (1000, 9000));
        assert_eq!(DECAY_SCHEDULE_BPS[5], (0, 10000));
    }

    #[test]
    fn test_decay_schedule_bps_sum_100_percent() {
        for (i, (bps_treasury, bps_node)) in DECAY_SCHEDULE_BPS.iter().enumerate() {
            assert_eq!(
                bps_treasury + bps_node,
                10000,
                "BPS sum not 100% at index {}",
                i
            );
        }
    }

    #[test]
    fn test_year_5_full_decay() {
        let now = Utc::now();
        let threshold_time = now - chrono::Duration::days(365 * 6);
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));

        let (treasury_bps, node_bps) = state.get_fee_split_bps(now);
        assert_eq!(treasury_bps, 0);
        assert_eq!(node_bps, 10000);
    }

    #[test]
    fn test_year_3_decay() {
        let now = Utc::now();
        let threshold_time = now - chrono::Duration::days(365 * 2 + 100);
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));

        let (treasury_bps, node_bps) = state.get_fee_split_bps(now);
        assert_eq!(treasury_bps, 2000);
        assert_eq!(node_bps, 8000);
    }

    #[test]
    fn test_get_fee_split_bps() {
        let state = TreasuryState::new();
        let now = Utc::now();

        let (treasury_bps, node_bps) = state.get_fee_split_bps(now);
        assert_eq!(treasury_bps, 5000);
        assert_eq!(node_bps, 5000);

        let threshold_time = now - chrono::Duration::days(365 * 6);
        let decayed_state =
            TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));
        let (treasury_bps, node_bps) = decayed_state.get_fee_split_bps(now);
        assert_eq!(treasury_bps, 0);
        assert_eq!(node_bps, 10000);
    }

    #[test]
    fn test_m5_deterministic_decay_calculation() {
        let threshold_time = Utc::now() - chrono::Duration::days(365 * 2 + 100);
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));

        let block_timestamp = Utc::now();

        let first_years = state.years_since_threshold(block_timestamp);
        let first_split = state.get_fee_split_bps(block_timestamp);

        for _ in 0..1000 {
            assert_eq!(state.years_since_threshold(block_timestamp), first_years);
            assert_eq!(state.get_fee_split_bps(block_timestamp), first_split);
        }
    }

    // L2 Fee Distribution Tests

    #[test]
    fn test_l2_fee_distribution_pre_threshold() {
        let state = TreasuryState::new();
        let now = Utc::now();
        let nodes = vec![
            ("node1".to_string(), "addr1".to_string(), 4),
            ("node2".to_string(), "addr2".to_string(), 4),
        ];

        let dist = L2FeeDistribution::calculate(1000, &state, now, &nodes);

        assert_eq!(dist.treasury_amount, 500);
        assert_eq!(dist.node_pool, 500);
        assert_eq!(dist.treasury_amount + dist.node_pool, dist.total_fee_pool);
    }

    #[test]
    fn test_l2_fee_distribution_year5() {
        let now = Utc::now();
        let threshold_time = now - chrono::Duration::days(365 * 6);
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));
        let nodes = vec![("node1".to_string(), "addr1".to_string(), 4)];

        let dist = L2FeeDistribution::calculate(1000, &state, now, &nodes);

        assert_eq!(dist.treasury_amount, 0);
        assert_eq!(dist.node_pool, 1000);
    }

    #[test]
    fn test_l2_fee_distribution_no_nodes() {
        let state = TreasuryState::new();
        let now = Utc::now();

        let dist = L2FeeDistribution::calculate(1000, &state, now, &[]);

        assert_eq!(dist.treasury_amount, 500);
        assert_eq!(dist.node_pool, 500);
        assert!(dist.node_payouts.is_empty());
    }

    #[test]
    fn test_l2_fee_distribution_dust_redirect() {
        let state = TreasuryState::new();
        let now = Utc::now();
        let nodes = vec![
            ("node1".to_string(), "addr1".to_string(), 100),
            ("node2".to_string(), "addr2".to_string(), 1),
        ];

        let dist = L2FeeDistribution::calculate(1000, &state, now, &nodes);

        assert_eq!(dist.node_payouts.len(), 1);
        assert_eq!(dist.node_payouts[0].0, "node1");
        assert_eq!(dist.node_payouts[0].2, 500);
    }

    #[test]
    fn test_l2_fee_distribution_zero_pool() {
        let state = TreasuryState::new();
        let now = Utc::now();
        let nodes = vec![("node1".to_string(), "addr1".to_string(), 4)];

        let dist = L2FeeDistribution::calculate(0, &state, now, &nodes);

        assert_eq!(dist.treasury_amount, 0);
        assert_eq!(dist.node_pool, 0);
        assert!(dist.node_payouts.is_empty());
    }

    // calculate_node_direct tests

    #[test]
    fn test_node_direct_pre_threshold() {
        let state = TreasuryState::new();
        let now = Utc::now();

        let (treasury, node) = calculate_node_direct(1000, &state, now);
        assert_eq!(treasury, 500);
        assert_eq!(node, 500);
    }

    #[test]
    fn test_node_direct_year5_full_decay() {
        let now = Utc::now();
        let threshold_time = now - chrono::Duration::days(365 * 6);
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));

        let (treasury, node) = calculate_node_direct(1000, &state, now);
        assert_eq!(treasury, 0);
        assert_eq!(node, 1000);
    }

    #[test]
    fn test_node_direct_zero_pool() {
        let state = TreasuryState::new();
        let now = Utc::now();

        let (treasury, node) = calculate_node_direct(0, &state, now);
        assert_eq!(treasury, 0);
        assert_eq!(node, 0);
    }

    #[test]
    fn test_node_direct_no_remainder_loss() {
        let state = TreasuryState::new();
        let now = Utc::now();

        let (treasury, node) = calculate_node_direct(999, &state, now);
        assert_eq!(treasury + node, 999);
    }

    #[test]
    fn test_node_direct_year3_decay() {
        let now = Utc::now();
        let threshold_time = now - chrono::Duration::days(365 * 2 + 100);
        let state = TreasuryState::from_stored(TREASURY_THRESHOLD_SATS, Some(threshold_time));

        let (treasury, node) = calculate_node_direct(10000, &state, now);
        // Year 3: 20% treasury, 80% node
        assert_eq!(treasury, 2000);
        assert_eq!(node, 8000);
    }
}
