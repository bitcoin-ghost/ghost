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
//| FILE: reorg.rs                                                                                                       |
//|======================================================================================================================|

//! Reorg detection and handling
//!
//! Monitors ZMQ sequence topic for block disconnect events (reorgs) and
//! invalidates affected rounds and payout proposals.
//!
//! # Reorg Handling Strategy
//!
//! When a block is disconnected (orphaned):
//! 1. Mark affected rounds as `Orphaned` status
//! 2. Cancel any pending payout proposals for those rounds
//! 3. Log the event for monitoring
//!
//! The shares from orphaned rounds are NOT lost - they can be carried forward
//! to the next round if desired (configurable).

use parking_lot::RwLock;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use ghost_common::zmq::BlockEvent;
use ghost_consensus::vote_handler::VoteHandler;
use ghost_storage::models::PayoutStatus;
use ghost_storage::Database;
use ghost_verification::alerts::{AlertDispatcher, AlertEvent};
use ghost_verification::chain_health::ChainHealth;
use std::time::Duration;

/// Callback returning the node's current local L1 height, used to record the
/// post-disconnect tip height alongside a reorg event.
type HeightGetter = Box<dyn Fn() -> u64 + Send + Sync>;

/// Debounce window for reorg alerts. A single reorg emits one `Disconnected`
/// event per orphaned block, so without this a depth-N reorg would fire N
/// alerts in a burst. One alert per window is enough to page the operator.
const REORG_ALERT_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Safely truncate a hash string for logging (returns up to 16 chars or full string if shorter)
fn truncate_hash(hash: &str) -> &str {
    let len = hash.len().min(16);
    &hash[..len]
}

/// Configuration for reorg handling
#[derive(Debug, Clone)]
pub struct ReorgConfig {
    /// Whether to carry forward shares from orphaned rounds
    pub carry_forward_shares: bool,
    /// Maximum reorg depth to handle (deeper reorgs require manual intervention)
    pub max_reorg_depth: u32,
    /// Minimum confirmations before a payout is considered safe
    /// Proposals will be created immediately but payouts delayed until confirmed
    pub min_confirmations: u32,
    /// Pause new payout proposals during active reorgs
    pub pause_on_reorg: bool,
    /// How many blocks to track in the reorg chain history
    pub reorg_history_size: usize,
}

impl Default for ReorgConfig {
    fn default() -> Self {
        Self {
            carry_forward_shares: false, // Conservative default
            max_reorg_depth: 100,        // Bitcoin's max reorg is typically much smaller
            min_confirmations: 6,        // Standard Bitcoin confirmation depth
            pause_on_reorg: true,        // Conservative: pause during reorgs
            reorg_history_size: 100,     // Track last 100 orphaned blocks
        }
    }
}

impl ReorgConfig {
    /// Create a config for mainnet (conservative settings)
    pub fn mainnet() -> Self {
        Self {
            carry_forward_shares: false,
            max_reorg_depth: 100,
            min_confirmations: 6,
            pause_on_reorg: true,
            reorg_history_size: 100,
        }
    }

    /// Create a config for testnet (less conservative)
    pub fn testnet() -> Self {
        Self {
            carry_forward_shares: true,
            max_reorg_depth: 200,
            min_confirmations: 3,
            pause_on_reorg: false,
            reorg_history_size: 200,
        }
    }
}

/// Handles blockchain reorgs by invalidating affected rounds
pub struct ReorgHandler {
    db: Arc<Database>,
    vote_handler: Option<Arc<VoteHandler>>,
    /// Operator-alert dispatcher. When set, a `ReorgDetected` alert fires (once
    /// per debounce window, and only if the operator has the event enabled) at
    /// the existing reorg-detection point.
    alerts: Option<Arc<AlertDispatcher>>,
    /// Shared chain-health state. When set, every detected reorg is recorded
    /// into its bounded ring (in addition to firing the alert) so the Sync
    /// page's Chain Health view can display it. Read-through the API.
    chain_health: Option<Arc<ChainHealth>>,
    /// Optional local-height source, so a recorded reorg carries the node's
    /// height right after the disconnect (the ZMQ event itself has no new tip).
    get_height: Option<HeightGetter>,
    config: ReorgConfig,
    /// Counter for consecutive reorgs (deep reorg detection)
    consecutive_reorgs: AtomicU32,
    /// Statistics tracking
    stats: ReorgStatsInner,
    /// Recent orphaned block hashes (for debugging and confirmation tracking)
    orphaned_blocks: RwLock<VecDeque<String>>,
    /// Whether we're currently in a reorg (payouts should be paused)
    in_reorg: AtomicU32,
}

/// Internal atomic stats for thread-safe updates
struct ReorgStatsInner {
    total_reorgs: AtomicU64,
    rounds_orphaned: AtomicU64,
    proposals_cancelled: AtomicU64,
    max_depth_seen: AtomicU32,
}

impl ReorgHandler {
    pub fn new(db: Arc<Database>, config: ReorgConfig) -> Self {
        Self {
            db,
            vote_handler: None,
            alerts: None,
            chain_health: None,
            get_height: None,
            consecutive_reorgs: AtomicU32::new(0),
            stats: ReorgStatsInner {
                total_reorgs: AtomicU64::new(0),
                rounds_orphaned: AtomicU64::new(0),
                proposals_cancelled: AtomicU64::new(0),
                max_depth_seen: AtomicU32::new(0),
            },
            orphaned_blocks: RwLock::new(VecDeque::with_capacity(config.reorg_history_size)),
            in_reorg: AtomicU32::new(0),
            config,
        }
    }

    /// Set the vote handler for cancelling pending proposals
    pub fn with_vote_handler(mut self, vh: Arc<VoteHandler>) -> Self {
        self.vote_handler = Some(vh);
        self
    }

    /// Wire the operator-alert dispatcher so reorgs page the operator.
    pub fn with_alert_dispatcher(mut self, alerts: Arc<AlertDispatcher>) -> Self {
        self.alerts = Some(alerts);
        self
    }

    /// Wire the shared chain-health state so each detected reorg is recorded
    /// into its bounded ring for the Sync page's Chain Health view.
    pub fn with_chain_health(mut self, chain_health: Arc<ChainHealth>) -> Self {
        self.chain_health = Some(chain_health);
        self
    }

    /// Wire a local-height source so a recorded reorg carries the node's height
    /// right after the disconnect.
    pub fn with_height_getter<F>(mut self, get_height: F) -> Self
    where
        F: Fn() -> u64 + Send + Sync + 'static,
    {
        self.get_height = Some(Box::new(get_height));
        self
    }

    /// Check if we're currently processing a reorg
    /// When true, new payout proposals should be delayed
    pub fn is_in_reorg(&self) -> bool {
        self.in_reorg.load(Ordering::SeqCst) > 0
    }

    /// Check if a block hash was recently orphaned
    pub fn was_recently_orphaned(&self, block_hash: &str) -> bool {
        let blocks = self.orphaned_blocks.read();
        blocks.iter().any(|h| h == block_hash)
    }

    /// Get current reorg depth (consecutive disconnects)
    pub fn current_reorg_depth(&self) -> u32 {
        self.consecutive_reorgs.load(Ordering::SeqCst)
    }

    /// Get statistics snapshot
    pub fn stats(&self) -> ReorgStats {
        ReorgStats {
            total_reorgs: self.stats.total_reorgs.load(Ordering::Relaxed),
            rounds_orphaned: self.stats.rounds_orphaned.load(Ordering::Relaxed),
            proposals_cancelled: self.stats.proposals_cancelled.load(Ordering::Relaxed),
            max_depth_seen: self.stats.max_depth_seen.load(Ordering::Relaxed),
        }
    }

    /// Add a block to the orphaned history
    fn track_orphaned_block(&self, block_hash: &str) {
        let mut blocks = self.orphaned_blocks.write();
        blocks.push_back(block_hash.to_string());
        while blocks.len() > self.config.reorg_history_size {
            blocks.pop_front();
        }
    }

    /// Update max depth if current is higher
    fn update_max_depth(&self, current: u32) {
        let mut max = self.stats.max_depth_seen.load(Ordering::Relaxed);
        while current > max {
            match self.stats.max_depth_seen.compare_exchange_weak(
                max,
                current,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => max = x,
            }
        }
    }

    /// Start listening for reorg events
    ///
    /// This spawns a background task that processes block disconnect events.
    pub fn start(self, mut block_events: broadcast::Receiver<BlockEvent>) {
        let handler = Arc::new(self);

        tokio::spawn(async move {
            info!("Reorg handler started - listening for block disconnect events");

            loop {
                match block_events.recv().await {
                    Ok(event) => {
                        handler.clone().handle_event(event).await;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(
                            skipped = n,
                            "Reorg handler lagged behind - some events may have been missed"
                        );
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("Block event channel closed - reorg handler stopping");
                        break;
                    }
                }
            }
        });
    }

    /// Handle a single block event
    async fn handle_event(self: Arc<Self>, event: BlockEvent) {
        match event {
            BlockEvent::Connected { hash } => {
                // Block connected - reset reorg state
                let was_in_reorg = self.consecutive_reorgs.swap(0, Ordering::SeqCst);
                self.in_reorg.store(0, Ordering::SeqCst);

                if was_in_reorg > 0 {
                    info!(
                        hash = %truncate_hash(&hash),
                        reorg_depth = was_in_reorg,
                        "Reorg completed - chain stabilized"
                    );
                } else {
                    info!(hash = %truncate_hash(&hash), "Block connected");
                }
            }
            BlockEvent::Disconnected { hash } => {
                // Increment reorg counters and track state
                let count = self.consecutive_reorgs.fetch_add(1, Ordering::SeqCst) + 1;
                self.in_reorg.store(count, Ordering::SeqCst);
                self.stats.total_reorgs.fetch_add(1, Ordering::Relaxed);
                self.update_max_depth(count);
                self.track_orphaned_block(&hash);

                if count > self.config.max_reorg_depth {
                    error!(
                        consecutive_reorgs = count,
                        max_depth = self.config.max_reorg_depth,
                        "DEEP REORG DETECTED - exceeded max depth, manual intervention may be required"
                    );
                }
                self.handle_reorg(&hash).await;
            }
        }
    }

    /// Handle a reorg (block disconnected)
    async fn handle_reorg(&self, block_hash: &str) {
        let hash_display = truncate_hash(block_hash);
        let reorg_depth = self.current_reorg_depth();

        warn!(
            block_hash = %hash_display,
            reorg_depth,
            "REORG DETECTED: Block disconnected from main chain"
        );

        // Fire the operator alert at the detection point. Rate-limited so a
        // multi-block reorg (one Disconnected event per orphaned block) pages
        // once, not once per block; the dispatcher also gates on the master
        // switch and the `reorg_detected` event flag. `old_tip` is the
        // disconnected block hash; depth is the consecutive-disconnect count.
        // The new tip is not carried on the ZMQ sequence event, so it is
        // omitted from the message.
        if let Some(alerts) = &self.alerts {
            let detail = format!(
                "Bitcoin chain reorg detected: block {hash_display} disconnected from the tip (depth {reorg_depth})."
            );
            alerts
                .fire_rate_limited(AlertEvent::ReorgDetected, REORG_ALERT_MIN_INTERVAL, &detail)
                .await;
        }

        // Persist the reorg into the shared chain-health ring so the Sync page
        // can display it (the alert above only pages the operator). Records
        // what the ZMQ sequence event carries — the disconnected (old-tip) hash
        // and the consecutive-disconnect depth — plus the node's local height
        // right after the disconnect when a height source is wired. The new tip
        // hash is not on the event, so it is not fabricated.
        if let Some(chain_health) = &self.chain_health {
            let new_tip_height = self.get_height.as_ref().map(|f| f());
            chain_health.record_reorg(
                chrono::Utc::now().timestamp(),
                reorg_depth,
                block_hash,
                new_tip_height,
            );
        }

        // 1. Mark affected rounds as orphaned
        match self.db.mark_rounds_orphaned_by_hash(block_hash) {
            Ok(affected) => {
                if affected > 0 {
                    self.stats
                        .rounds_orphaned
                        .fetch_add(affected as u64, Ordering::Relaxed);
                    warn!(
                        block_hash = %hash_display,
                        rounds_orphaned = affected,
                        reorg_depth,
                        "Marked rounds as orphaned due to reorg"
                    );
                } else {
                    info!(
                        block_hash = %hash_display,
                        reorg_depth,
                        "Reorg detected but no pool rounds were affected"
                    );
                }
            }
            Err(e) => {
                error!(
                    block_hash = %hash_display,
                    error = %e,
                    "Failed to mark rounds as orphaned"
                );
            }
        }

        // 2. Cancel pending payout proposals for this block
        let mut cancelled = 0u64;
        if let Some(ref vote_handler) = self.vote_handler {
            // Get rounds for this block hash to cancel their proposals
            match self.db.get_rounds_by_block_hash(block_hash) {
                Ok(rounds) => {
                    for round in rounds {
                        if round.payout_status == PayoutStatus::Pending
                            || round.payout_status == PayoutStatus::Approved
                        {
                            // Cancel any pending votes for this round
                            if let Err(e) = vote_handler.cancel_proposal_for_round(round.round_id) {
                                warn!(
                                    round_id = round.round_id,
                                    error = %e,
                                    "Failed to cancel proposal (may already be processed)"
                                );
                            } else {
                                cancelled += 1;
                                info!(
                                    round_id = round.round_id,
                                    reorg_depth, "Cancelled payout proposal due to reorg"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(
                        block_hash = %hash_display,
                        error = %e,
                        "Failed to get rounds for orphaned block"
                    );
                }
            }
        }

        if cancelled > 0 {
            self.stats
                .proposals_cancelled
                .fetch_add(cancelled, Ordering::Relaxed);
        }

        // 3. Log reorg summary for monitoring
        let stats = self.stats();
        info!(
            total_reorgs = stats.total_reorgs,
            total_rounds_orphaned = stats.rounds_orphaned,
            total_proposals_cancelled = stats.proposals_cancelled,
            max_depth_seen = stats.max_depth_seen,
            current_depth = reorg_depth,
            pause_active = self.config.pause_on_reorg && self.is_in_reorg(),
            "Reorg stats update"
        );
    }

    /// Get the current consecutive reorg count
    pub fn consecutive_reorg_count(&self) -> u32 {
        self.consecutive_reorgs.load(Ordering::SeqCst)
    }
}

/// Statistics about reorg handling
#[derive(Debug, Clone, Default)]
pub struct ReorgStats {
    /// Total reorgs detected
    pub total_reorgs: u64,
    /// Total rounds orphaned
    pub rounds_orphaned: u64,
    /// Total proposals cancelled
    pub proposals_cancelled: u64,
    /// Maximum reorg depth seen
    pub max_depth_seen: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reorg_config_default() {
        let config = ReorgConfig::default();
        assert!(!config.carry_forward_shares);
        assert_eq!(config.max_reorg_depth, 100);
        assert_eq!(config.min_confirmations, 6);
        assert!(config.pause_on_reorg);
        assert_eq!(config.reorg_history_size, 100);
    }

    #[test]
    fn test_reorg_config_mainnet() {
        let config = ReorgConfig::mainnet();
        assert!(!config.carry_forward_shares);
        assert_eq!(config.min_confirmations, 6);
        assert!(config.pause_on_reorg);
    }

    #[test]
    fn test_reorg_config_testnet() {
        let config = ReorgConfig::testnet();
        assert!(config.carry_forward_shares);
        assert_eq!(config.min_confirmations, 3);
        assert!(!config.pause_on_reorg);
    }

    #[test]
    fn test_truncate_hash_long() {
        let hash = "0000000000000000000123456789abcdef0000000000000000";
        assert_eq!(truncate_hash(hash), "0000000000000000");
        assert_eq!(truncate_hash(hash).len(), 16);
    }

    #[test]
    fn test_truncate_hash_short() {
        let hash = "abc123";
        assert_eq!(truncate_hash(hash), "abc123");
        assert_eq!(truncate_hash(hash).len(), 6);
    }

    #[test]
    fn test_truncate_hash_empty() {
        let hash = "";
        assert_eq!(truncate_hash(hash), "");
        assert_eq!(truncate_hash(hash).len(), 0);
    }

    #[test]
    fn test_truncate_hash_exactly_16() {
        let hash = "1234567890abcdef";
        assert_eq!(truncate_hash(hash), "1234567890abcdef");
        assert_eq!(truncate_hash(hash).len(), 16);
    }

    #[test]
    fn test_reorg_handler_stats() {
        let db = ghost_storage::Database::in_memory().unwrap();
        let handler = ReorgHandler::new(Arc::new(db), ReorgConfig::default());

        // Initial state
        assert!(!handler.is_in_reorg());
        assert_eq!(handler.current_reorg_depth(), 0);

        let stats = handler.stats();
        assert_eq!(stats.total_reorgs, 0);
        assert_eq!(stats.rounds_orphaned, 0);
        assert_eq!(stats.max_depth_seen, 0);
    }

    #[test]
    fn test_orphaned_block_tracking() {
        let db = ghost_storage::Database::in_memory().unwrap();
        let config = ReorgConfig {
            reorg_history_size: 3,
            ..Default::default()
        };
        let handler = ReorgHandler::new(Arc::new(db), config);

        // Track some blocks
        handler.track_orphaned_block("hash1");
        handler.track_orphaned_block("hash2");
        handler.track_orphaned_block("hash3");

        assert!(handler.was_recently_orphaned("hash1"));
        assert!(handler.was_recently_orphaned("hash2"));
        assert!(handler.was_recently_orphaned("hash3"));

        // Add one more, should evict hash1
        handler.track_orphaned_block("hash4");
        assert!(!handler.was_recently_orphaned("hash1"));
        assert!(handler.was_recently_orphaned("hash4"));
    }

    #[test]
    fn test_max_depth_tracking() {
        let db = ghost_storage::Database::in_memory().unwrap();
        let handler = ReorgHandler::new(Arc::new(db), ReorgConfig::default());

        handler.update_max_depth(5);
        assert_eq!(handler.stats().max_depth_seen, 5);

        handler.update_max_depth(3); // Should not decrease
        assert_eq!(handler.stats().max_depth_seen, 5);

        handler.update_max_depth(10);
        assert_eq!(handler.stats().max_depth_seen, 10);
    }
}
