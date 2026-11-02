//! Treasury fee schedule read by ghost-mining.
//!
//! Treasury decay schedule: Once treasury reaches 21 BTC, allocation decays over 5 years:
//! - Pre-threshold: 50% treasury, 50% nodes
//! - Year 1: 40% treasury, 60% nodes
//! - Year 2: 30% treasury, 70% nodes
//! - Year 3: 20% treasury, 80% nodes
//! - Year 4: 10% treasury, 90% nodes
//! - Year 5+: 0% treasury, 100% nodes

use chrono::{DateTime, Utc};
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
}
