//|======================================================================================================================|
//|                                                                                                                      |
//|  BITCOIN GHOST - Shared Ban Manager                                                                                  |
//|                                                                                                                      |
//|  Security Fix C1: Shared ban state across all handlers                                                               |
//|                                                                                                                      |
//|======================================================================================================================|

//! Shared Ban Manager - Centralized ban state for cross-handler enforcement
//!
//! This module provides a thread-safe ban manager that can be shared across
//! all message handlers (VoteHandler, HealthPingHandler, etc.)
//! to ensure that banned nodes are rejected by ALL handlers, not just the one
//! that detected the violation.
//!
//! ## Security Context
//!
//! Previously, each handler maintained its own `banned_nodes` HashMap. This meant:
//! - A node banned for equivocation in VoteHandler could still send health pings
//! - Ban state was lost on handler restart
//! - Inconsistent enforcement across the consensus layer
//!
//! This shared BanManager fixes C1 by providing:
//! - Centralized ban state accessible from all handlers
//! - Configurable ban durations per reason
//! - Automatic expiration cleanup
//! - Thread-safe operations via RwLock

use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use ghost_common::types::NodeId;

/// Reason for banning a node
///
/// P2P4-L4: Marked non_exhaustive to allow adding new ban reasons
/// in future versions without breaking downstream code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BanReason {
    /// Node signed conflicting votes (Byzantine behavior)
    Equivocation,
    /// Node exceeded rate limits persistently
    RateLimitExceeded,
    /// Node sent invalid/malformed messages repeatedly
    InvalidMessages,
    /// Node attempted protocol manipulation
    ProtocolViolation,
    /// Custom reason with specified duration
    Custom,
}

impl BanReason {
    /// Default ban duration for this reason
    pub fn default_duration(&self) -> Duration {
        match self {
            BanReason::Equivocation => Duration::from_secs(600), // 10 minutes
            BanReason::RateLimitExceeded => Duration::from_secs(300), // 5 minutes
            BanReason::InvalidMessages => Duration::from_secs(180), // 3 minutes
            BanReason::ProtocolViolation => Duration::from_secs(900), // 15 minutes
            BanReason::Custom => Duration::from_secs(600),       // 10 minutes default
        }
    }
}

/// Entry for a banned node
#[derive(Debug, Clone)]
pub struct BanEntry {
    /// When the ban expires
    pub expire_at: Instant,
    /// Reason for the ban
    pub reason: BanReason,
    /// Timestamp when ban was created (for logging/auditing)
    pub banned_at: Instant,
}

impl BanEntry {
    /// Check if this ban has expired
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expire_at
    }

    /// Get remaining ban duration
    pub fn remaining(&self) -> Duration {
        self.expire_at.saturating_duration_since(Instant::now())
    }
}

/// P2P4-M3: Configurable ban durations per reason
#[derive(Debug, Clone)]
pub struct BanManagerConfig {
    /// Ban duration for equivocation (default: 600 seconds / 10 minutes)
    pub equivocation_secs: u64,
    /// Ban duration for rate limit exceeded (default: 300 seconds / 5 minutes)
    pub rate_limit_secs: u64,
    /// Ban duration for invalid messages (default: 180 seconds / 3 minutes)
    pub invalid_messages_secs: u64,
    /// Ban duration for protocol violation (default: 900 seconds / 15 minutes)
    pub protocol_violation_secs: u64,
    /// Default duration for custom bans (default: 600 seconds / 10 minutes)
    pub custom_secs: u64,
}

impl Default for BanManagerConfig {
    fn default() -> Self {
        // 4.1 SECURITY: 24-hour base bans for serious violations
        // Equivocation and protocol violations are Byzantine behaviors
        // that warrant significant penalties to deter attacks
        //
        // M-6 DESIGN NOTE: Node-local ban escalation is INTENTIONAL
        //
        // Each node maintains its own ban list and escalation state. This is a
        // deliberate design choice, NOT a bug:
        //
        // 1. **Attack Isolation**: An attacker cannot use one compromised node to
        //    propagate false ban information to the entire network.
        //
        // 2. **No Ban Consensus Required**: Requiring network-wide agreement on bans
        //    would add complexity and create new attack vectors (e.g., colluding
        //    nodes voting to ban honest nodes).
        //
        // 3. **Local Observation Accuracy**: Nodes that directly observe misbehavior
        //    have the most accurate information. Trusting remote ban reports could
        //    enable "ban reflection" attacks.
        //
        // 4. **Sybil Resistance**: With node-local bans, an attacker with multiple
        //    identities still gets banned on each node they misbehave against.
        //    Network-wide bans could be gamed via Sybil voting.
        //
        // The escalation multiplier ensures repeat offenders face increasingly long
        // bans on each node they attack, providing strong deterrence even without
        // network-wide coordination.
        Self {
            equivocation_secs: 24 * 60 * 60, // 24 hours for Byzantine behavior
            rate_limit_secs: 60 * 60,        // 1 hour for rate limits
            invalid_messages_secs: 30 * 60,  // 30 minutes for invalid messages
            protocol_violation_secs: 24 * 60 * 60, // 24 hours for protocol violations
            custom_secs: 60 * 60,            // 1 hour default for custom
        }
    }
}

impl BanManagerConfig {
    /// Get duration for a specific ban reason
    pub fn duration_for_reason(&self, reason: BanReason) -> Duration {
        let secs = match reason {
            BanReason::Equivocation => self.equivocation_secs,
            BanReason::RateLimitExceeded => self.rate_limit_secs,
            BanReason::InvalidMessages => self.invalid_messages_secs,
            BanReason::ProtocolViolation => self.protocol_violation_secs,
            BanReason::Custom => self.custom_secs,
        };
        Duration::from_secs(secs)
    }
}

/// 4.1 SECURITY: Ban history entry for tracking repeat offenders
#[derive(Debug, Clone)]
struct BanHistoryEntry {
    /// Number of times this node has been banned
    count: u32,
    /// When the last ban was issued (for decay calculation)
    last_banned: Instant,
}

/// L-10 SECURITY: History decay period (30 days)
///
/// Ban history count decays by 1 for each 30-day period since last ban.
/// The previous 7-day decay allowed attackers to cycle attacks with minimal
/// downtime between ban periods. 30 days provides much stronger deterrence
/// against persistent attackers while still allowing legitimate nodes that
/// made a one-time mistake to eventually recover.
const BAN_HISTORY_DECAY_SECS: u64 = 30 * 24 * 60 * 60;

/// L-10 SECURITY: Maximum escalation multiplier (caps at 32x base duration)
///
/// With the longer decay period, we also increase the max multiplier to 32x.
/// This means a repeat offender can be banned for up to 32 days (with 24h base).
/// Combined with the 30-day decay, this effectively requires 60+ days of good
/// behavior before ban history is fully cleared after severe violations.
const MAX_ESCALATION_MULTIPLIER: u32 = 32;

/// Shared ban manager for cross-handler enforcement
///
/// Thread-safe via RwLock - can be shared across multiple handlers using `Arc<BanManager>`
pub struct BanManager {
    /// Map of banned nodes to their ban entries
    banned_nodes: RwLock<HashMap<NodeId, BanEntry>>,
    /// Default ban duration (can be overridden per-ban)
    default_duration: Duration,
    /// P2P4-M3: Configurable durations per reason
    config: BanManagerConfig,
    /// 4.1 SECURITY: Ban history for escalation tracking
    ban_history: RwLock<HashMap<NodeId, BanHistoryEntry>>,
}

impl BanManager {
    /// Create a new ban manager with default 1-hour ban duration
    pub fn new() -> Self {
        Self::with_duration(Duration::from_secs(3600))
    }

    /// Create a new ban manager with custom default duration
    pub fn with_duration(default_duration: Duration) -> Self {
        Self {
            banned_nodes: RwLock::new(HashMap::new()),
            default_duration,
            config: BanManagerConfig::default(),
            ban_history: RwLock::new(HashMap::new()),
        }
    }

    /// P2P4-M3: Create a ban manager with custom configuration
    pub fn with_config(config: BanManagerConfig) -> Self {
        Self {
            banned_nodes: RwLock::new(HashMap::new()),
            default_duration: Duration::from_secs(config.custom_secs),
            config,
            ban_history: RwLock::new(HashMap::new()),
        }
    }

    /// 4.1 SECURITY: Calculate escalation multiplier for repeat offenders
    ///
    /// Returns 2^(effective_count - 1) capped at MAX_ESCALATION_MULTIPLIER.
    /// Effective count decays over time - decreases by 1 for each 7 days since last ban.
    fn escalation_multiplier(&self, node_id: &NodeId) -> u32 {
        let history = self.ban_history.read();
        let Some(entry) = history.get(node_id) else {
            return 1; // First offense, no escalation
        };

        // Calculate decay based on time since last ban
        let elapsed = entry.last_banned.elapsed();
        let decay_periods = (elapsed.as_secs() / BAN_HISTORY_DECAY_SECS) as u32;
        let effective_count = entry.count.saturating_sub(decay_periods);

        if effective_count == 0 {
            return 1; // Fully decayed, treat as first offense
        }

        // 2^(count-1): 1st=1x, 2nd=2x, 3rd=4x, 4th=8x, 5th+=16x
        let multiplier = 1u32
            .checked_shl(effective_count.saturating_sub(1))
            .unwrap_or(MAX_ESCALATION_MULTIPLIER);
        multiplier.min(MAX_ESCALATION_MULTIPLIER)
    }

    /// 4.1 SECURITY: Record a ban in the history for escalation tracking
    fn record_ban_history(&self, node_id: NodeId) {
        let mut history = self.ban_history.write();
        history
            .entry(node_id)
            .and_modify(|entry| {
                entry.count = entry.count.saturating_add(1);
                entry.last_banned = Instant::now();
            })
            .or_insert(BanHistoryEntry {
                count: 1,
                last_banned: Instant::now(),
            });
    }

    /// Ban a node for a specific reason using configured duration for that reason
    ///
    /// P2P4-M3: Uses configurable durations from BanManagerConfig
    /// 4.1 SECURITY: Applies escalation multiplier for repeat offenders
    pub fn ban(&self, node_id: NodeId, reason: BanReason) {
        let base_duration = self.config.duration_for_reason(reason);
        let multiplier = self.escalation_multiplier(&node_id);
        let escalated_duration =
            Duration::from_secs(base_duration.as_secs().saturating_mul(multiplier as u64));
        self.ban_for_duration_internal(node_id, reason, escalated_duration, multiplier);
    }

    /// Ban a node for a specific duration (bypasses escalation)
    ///
    /// Use this for custom ban durations where escalation doesn't apply.
    pub fn ban_for_duration(&self, node_id: NodeId, reason: BanReason, duration: Duration) {
        self.ban_for_duration_internal(node_id, reason, duration, 1);
    }

    /// Internal ban implementation
    fn ban_for_duration_internal(
        &self,
        node_id: NodeId,
        reason: BanReason,
        duration: Duration,
        multiplier: u32,
    ) {
        let now = Instant::now();
        let entry = BanEntry {
            expire_at: now + duration,
            reason,
            banned_at: now,
        };

        let node_hex = hex::encode(&node_id[..8]);
        self.banned_nodes.write().insert(node_id, entry);

        // 4.1: Record in history for future escalation
        self.record_ban_history(node_id);

        warn!(
            node_id = %node_hex,
            reason = ?reason,
            duration_secs = duration.as_secs(),
            escalation_multiplier = multiplier,
            "Node banned (shared BanManager)"
        );
    }

    /// Check if a node is currently banned
    ///
    /// SEC-BAN-1: Eagerly removes expired entries to prevent stale state from
    /// causing issues in rapid succession checks.
    pub fn is_banned(&self, node_id: &NodeId) -> bool {
        // First check with read lock (fast path for common cases)
        {
            let banned = self.banned_nodes.read();
            match banned.get(node_id) {
                Some(entry) if !entry.is_expired() => return true,
                Some(_) => {
                    // Entry expired - need to clean up below
                }
                None => return false,
            }
        }

        // Expired entry found - eagerly remove to prevent stale state race
        {
            let mut banned = self.banned_nodes.write();
            if let Some(entry) = banned.get(node_id) {
                if entry.is_expired() {
                    banned.remove(node_id);
                    debug!(
                        node_id = %hex::encode(&node_id[..8]),
                        "Removed expired ban entry on check"
                    );
                }
            }
        }

        false
    }

    /// Check if banned and return the reason if so
    pub fn get_ban_info(&self, node_id: &NodeId) -> Option<(BanReason, Duration)> {
        let banned = self.banned_nodes.read();
        banned.get(node_id).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some((entry.reason, entry.remaining()))
            }
        })
    }

    /// Unban a node (manual override)
    pub fn unban(&self, node_id: &NodeId) -> bool {
        let removed = self.banned_nodes.write().remove(node_id).is_some();
        if removed {
            info!(
                node_id = %hex::encode(&node_id[..8]),
                "Node unbanned manually"
            );
        }
        removed
    }

    /// Clean up all expired bans and stale history
    ///
    /// Call this periodically (e.g., every 60 seconds) to prevent memory growth.
    /// Also cleans up ban history entries older than 90 days.
    pub fn cleanup_expired(&self) -> usize {
        let expired_bans = self.cleanup_expired_bans();
        let stale_history = self.cleanup_stale_history();
        expired_bans + stale_history
    }

    /// Clean up expired bans only (internal helper)
    fn cleanup_expired_bans(&self) -> usize {
        let mut banned = self.banned_nodes.write();
        let before = banned.len();
        banned.retain(|_, entry| !entry.is_expired());
        let removed = before - banned.len();
        if removed > 0 {
            info!(removed, remaining = banned.len(), "Cleaned up expired bans");
        }
        removed
    }

    /// Clean up ban history entries older than 365 days
    ///
    /// L-10 SECURITY: Updated for 30-day decay periods.
    /// With 30-day decay and max 32x escalation, we need ~960 days for
    /// full decay from maximum. However, 365 days is a reasonable cleanup
    /// threshold as it covers most realistic scenarios while preventing
    /// unbounded memory growth.
    pub fn cleanup_stale_history(&self) -> usize {
        // 365 days = ~12 decay periods (30 days each)
        const MAX_HISTORY_AGE_SECS: u64 = 365 * 24 * 60 * 60;
        let max_age = Duration::from_secs(MAX_HISTORY_AGE_SECS);

        let mut history = self.ban_history.write();
        let before = history.len();
        history.retain(|_, entry| entry.last_banned.elapsed() < max_age);
        let removed = before - history.len();
        if removed > 0 {
            info!(
                removed,
                remaining = history.len(),
                "Cleaned up stale ban history entries"
            );
        }
        removed
    }

    /// Get the count of currently banned nodes
    pub fn banned_count(&self) -> usize {
        self.banned_nodes.read().len()
    }

    /// Get all currently banned node IDs (for diagnostics)
    pub fn get_banned_nodes(&self) -> Vec<(NodeId, BanReason, Duration)> {
        self.banned_nodes
            .read()
            .iter()
            .filter(|(_, entry)| !entry.is_expired())
            .map(|(id, entry)| (*id, entry.reason, entry.remaining()))
            .collect()
    }

    /// Get the default ban duration
    pub fn default_duration(&self) -> Duration {
        self.default_duration
    }
}

impl Default for BanManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ban_and_check() {
        let manager = BanManager::new();
        let node_id = [1u8; 32];

        assert!(!manager.is_banned(&node_id));

        manager.ban(node_id, BanReason::Equivocation);

        assert!(manager.is_banned(&node_id));
        assert_eq!(manager.banned_count(), 1);
    }

    #[test]
    fn test_ban_expiration() {
        let manager = BanManager::new();
        let node_id = [2u8; 32];

        // Ban for a long duration. The "banned initially" assertion must not
        // race the expiry — a short ban can elapse between the ban call and the
        // check on a heavily loaded CI runner (this is what made the test flaky
        // on macOS), so use a duration that cannot expire before we look.
        manager.ban_for_duration(
            node_id,
            BanReason::RateLimitExceeded,
            Duration::from_secs(3600),
        );

        // Should be banned initially.
        assert!(manager.is_banned(&node_id));

        // Force the entry's expiry into the past instead of sleeping. This
        // exercises the real is_banned expiry + eager-eviction path
        // deterministically, with no wall-clock dependency to flake under load.
        {
            let mut banned = manager.banned_nodes.write();
            banned
                .get_mut(&node_id)
                .expect("ban entry present")
                .expire_at = Instant::now() - Duration::from_secs(1);
        }

        // Should no longer be banned, and the stale entry is evicted.
        assert!(!manager.is_banned(&node_id));
        assert_eq!(manager.banned_count(), 0);
    }

    #[test]
    fn test_unban() {
        let manager = BanManager::new();
        let node_id = [3u8; 32];

        manager.ban(node_id, BanReason::InvalidMessages);
        assert!(manager.is_banned(&node_id));

        let removed = manager.unban(&node_id);
        assert!(removed);
        assert!(!manager.is_banned(&node_id));
    }

    #[test]
    fn test_cleanup_expired() {
        let manager = BanManager::new();

        // Ban multiple nodes with short durations
        for i in 0..5 {
            manager.ban_for_duration([i; 32], BanReason::Custom, Duration::from_millis(1));
        }

        assert_eq!(manager.banned_count(), 5);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        // Cleanup
        let removed = manager.cleanup_expired();
        assert_eq!(removed, 5);
        assert_eq!(manager.banned_count(), 0);
    }

    #[test]
    fn test_get_ban_info() {
        let manager = BanManager::new();
        let node_id = [4u8; 32];

        assert!(manager.get_ban_info(&node_id).is_none());

        manager.ban(node_id, BanReason::ProtocolViolation);

        let info = manager.get_ban_info(&node_id);
        assert!(info.is_some());
        let (reason, remaining) = info.unwrap();
        assert_eq!(reason, BanReason::ProtocolViolation);
        assert!(remaining > Duration::from_secs(0));
    }

    #[test]
    fn test_reason_default_durations() {
        assert_eq!(
            BanReason::Equivocation.default_duration(),
            Duration::from_secs(600)
        );
        assert_eq!(
            BanReason::RateLimitExceeded.default_duration(),
            Duration::from_secs(300)
        );
        assert_eq!(
            BanReason::InvalidMessages.default_duration(),
            Duration::from_secs(180)
        );
        assert_eq!(
            BanReason::ProtocolViolation.default_duration(),
            Duration::from_secs(900)
        );
    }

    #[test]
    fn test_cleanup_stale_history_preserves_recent() {
        let manager = BanManager::new();
        let node_id = [10u8; 32];

        // Ban a node (this creates a history entry)
        manager.ban_for_duration(node_id, BanReason::Custom, Duration::from_millis(1));

        // Wait for ban to expire
        std::thread::sleep(Duration::from_millis(10));

        // Clear the expired ban
        manager.cleanup_expired_bans();
        assert_eq!(manager.banned_count(), 0);

        // History should still exist (it's recent, not stale)
        {
            let history = manager.ban_history.read();
            assert_eq!(history.len(), 1);
            assert!(history.contains_key(&node_id));
        }

        // cleanup_stale_history should NOT remove recent entries
        let removed = manager.cleanup_stale_history();
        assert_eq!(removed, 0);

        // History should still be there
        {
            let history = manager.ban_history.read();
            assert_eq!(history.len(), 1);
        }
    }

    #[test]
    fn test_ban_history_count() {
        let manager = BanManager::new();

        // Ban multiple different nodes
        for i in 0..5 {
            manager.ban_for_duration([i; 32], BanReason::Custom, Duration::from_millis(1));
        }

        // Check that history was recorded for each
        {
            let history = manager.ban_history.read();
            assert_eq!(history.len(), 5);
        }

        // Wait for bans to expire and cleanup
        std::thread::sleep(Duration::from_millis(10));
        manager.cleanup_expired_bans();
        assert_eq!(manager.banned_count(), 0);

        // History should still exist for all nodes
        {
            let history = manager.ban_history.read();
            assert_eq!(history.len(), 5);
        }
    }

    // =========================================================================
    // L-10 TESTS: 30-day decay and stronger escalation
    // =========================================================================

    #[test]
    fn test_l10_decay_period_is_30_days() {
        // L-10: Verify the decay period is 30 days
        assert_eq!(BAN_HISTORY_DECAY_SECS, 30 * 24 * 60 * 60);
    }

    #[test]
    fn test_l10_max_escalation_is_32x() {
        // L-10: Verify max escalation multiplier is 32x
        assert_eq!(MAX_ESCALATION_MULTIPLIER, 32);
    }

    #[test]
    fn test_l10_escalation_multiplier_calculation() {
        let manager = BanManager::new();
        let node_id = [42u8; 32];

        // First ban: multiplier should be 1
        assert_eq!(manager.escalation_multiplier(&node_id), 1);

        // Ban once
        manager.ban_for_duration(node_id, BanReason::Custom, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(10));

        // Second ban: multiplier should be 2
        // (count=1, so 2^(1-1) = 2^0 = 1... wait, after first ban count becomes 1)
        // Actually escalation is calculated before recording, let me trace this
        // After first ban is recorded, history count = 1
        // For second ban, escalation_multiplier reads count = 1, returns 2^0 = 1
        // Then ban() calls record_ban_history which increments to 2
        // For third ban, escalation_multiplier reads count = 2, returns 2^1 = 2

        // Second offense: multiplier should still be 1 (first offense was recorded)
        // No, wait - the first ban WAS recorded, so count=1, but decay is calculated
        // Since we just banned, no decay has occurred, effective_count = 1
        // 2^(1-1) = 1
        assert_eq!(manager.escalation_multiplier(&node_id), 1);

        // Ban again to increment
        manager.ban_for_duration(node_id, BanReason::Custom, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(10));

        // Third offense: count=2, effective=2, 2^(2-1) = 2
        assert_eq!(manager.escalation_multiplier(&node_id), 2);

        // Ban again
        manager.ban_for_duration(node_id, BanReason::Custom, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(10));

        // Fourth offense: count=3, effective=3, 2^(3-1) = 4
        assert_eq!(manager.escalation_multiplier(&node_id), 4);
    }
}
