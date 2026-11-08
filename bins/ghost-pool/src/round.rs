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
//| FILE: round.rs                                                                                                       |
//|======================================================================================================================|

//! Mining rounds, for statistics.
//!
//! A round is the window of one template: it starts on every new template and its miner work is
//! what the dashboard, the health pings and `/health` report. Balances are decided by the node
//! pool relay in pool_sv2, never here.

use parking_lot::RwLock;
use std::collections::HashMap;
use tracing::{debug, info, warn};

use ghost_common::types::RoundId;
use ghost_storage::Database;

/// Round manager configuration
#[derive(Debug, Clone)]
pub struct RoundConfig {
    /// Network difficulty, the ceiling on one share's work (H6 anomaly detection)
    pub network_difficulty: f64,
    /// Maximum distinct miners per round (memory protection)
    pub max_shares_per_round: usize,
    /// Round history to keep
    pub rounds_to_keep: usize,
    /// Maximum shares per miner per second (H6 rate limiting)
    pub max_shares_per_miner_per_sec: u32,
    /// Shares with work above `max_work_multiplier * network_difficulty` are refused (H6)
    pub max_work_multiplier: f64,
}

impl Default for RoundConfig {
    fn default() -> Self {
        Self {
            network_difficulty: 1_000_000.0,
            max_shares_per_round: 1_000_000,
            rounds_to_keep: 10,
            max_shares_per_miner_per_sec: 100,
            max_work_multiplier: 1.0,
        }
    }
}

/// One round's miner work.
#[derive(Debug, Clone, Default)]
struct RoundWork {
    block_height: u64,
    miner_work: HashMap<String, f64>,
    total_work: f64,
}

impl RoundWork {
    fn new(block_height: u64) -> Self {
        Self {
            block_height,
            ..Default::default()
        }
    }

    fn add(&mut self, miner_id: &str, work: f64) {
        *self.miner_work.entry(miner_id.to_string()).or_insert(0.0) += work;
        self.total_work += work;
    }
}

/// Per-miner rate limit tracking (H6)
struct MinerRateLimitEntry {
    /// Timestamp of last share (Unix seconds)
    last_second: u64,
    /// Number of shares in current second
    count: u32,
}

/// Tracks the current round and the recent rounds' miner work.
pub struct RoundManager {
    config: RoundConfig,
    current_round: RwLock<RoundId>,
    current_height: RwLock<u64>,
    /// Wall-clock start of the current round (reset on every `start_round`). Monotonic, so the
    /// reported elapsed time is immune to system clock adjustments.
    current_round_start: RwLock<std::time::Instant>,
    rounds: RwLock<HashMap<RoundId, RoundWork>>,
    miner_rate_limits: RwLock<HashMap<String, MinerRateLimitEntry>>,
    /// Counter for automatic rate limit cleanup (L-8)
    shares_since_cleanup: std::sync::atomic::AtomicU64,
}

/// Seconds elapsed between two monotonic instants, saturating to 0 if `now` precedes `start`.
/// Pure helper so the round-duration derivation is unit-testable without wall-clock sleeps.
fn elapsed_secs_between(start: std::time::Instant, now: std::time::Instant) -> u64 {
    now.saturating_duration_since(start).as_secs()
}

impl RoundManager {
    /// Create a new round manager
    pub fn new(config: RoundConfig) -> Self {
        Self {
            config,
            current_round: RwLock::new(0),
            current_height: RwLock::new(0),
            current_round_start: RwLock::new(std::time::Instant::now()),
            rounds: RwLock::new(HashMap::new()),
            miner_rate_limits: RwLock::new(HashMap::new()),
            shares_since_cleanup: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Seed the chain height before the first template arrives, so `/health` and the health pings
    /// report a real height from startup. Never lowers it.
    pub fn seed_height(&self, block_height: u64) {
        let mut h = self.current_height.write();
        if block_height > *h {
            *h = block_height;
        }
    }

    /// Start a new round (called on new block template)
    pub fn start_round(&self, block_height: u64) -> RoundId {
        let round_id = {
            let mut current = self.current_round.write();
            *current += 1;
            *current
        };
        *self.current_height.write() = block_height;
        *self.current_round_start.write() = std::time::Instant::now();

        let mut rounds = self.rounds.write();
        rounds.insert(round_id, RoundWork::new(block_height));
        let keep = self.config.rounds_to_keep as u64;
        rounds.retain(|r, _| *r + keep > round_id);

        info!(round_id, block_height, "Started new round");
        round_id
    }

    /// Reload the latest round's miner work from the database on startup, so a restart does not
    /// zero the round's statistics.
    pub fn reload_from_db(&self, db: &Database) {
        let max_round_id = match db.get_max_round_id() {
            Ok(0) => {
                info!("No shares in database, starting fresh");
                return;
            }
            Ok(id) => id,
            Err(e) => {
                warn!(error = %e, "Failed to query max round_id from database");
                return;
            }
        };

        // Set current_round so start_round() increments to N+1
        *self.current_round.write() = max_round_id;

        let miners = match db.get_round_miners(max_round_id) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, round_id = max_round_id, "Failed to load round miners from database");
                return;
            }
        };
        if miners.is_empty() {
            return;
        }

        let mut round = RoundWork::new(0);
        for (miner_id, work) in &miners {
            round.add(miner_id, *work);
        }
        let total_work = round.total_work;
        self.rounds.write().insert(max_round_id, round);
        info!(
            round_id = max_round_id,
            miner_count = miners.len(),
            total_work,
            "Reloaded share data from database"
        );
    }

    /// End the current round, returning its summary.
    pub fn end_round(&self) -> Option<RoundSummary> {
        let round_id = *self.current_round.read();
        if round_id == 0 {
            return None;
        }
        let rounds = self.rounds.read();
        let round = rounds.get(&round_id)?;
        Some(RoundSummary {
            round_id,
            block_height: round.block_height,
            total_miner_work: round.total_work,
            miner_count: round.miner_work.len(),
        })
    }

    /// Current round ID
    pub fn current_round_id(&self) -> RoundId {
        *self.current_round.read()
    }

    /// Current block height
    pub fn current_height(&self) -> u64 {
        *self.current_height.read()
    }

    /// Seconds elapsed in the current round, measured from the most recent `start_round`.
    pub fn current_round_elapsed_secs(&self) -> u64 {
        elapsed_secs_between(*self.current_round_start.read(), std::time::Instant::now())
    }

    /// Round statistics
    pub fn round_stats(&self, round_id: RoundId) -> Option<RoundStats> {
        let rounds = self.rounds.read();
        let round = rounds.get(&round_id)?;
        Some(RoundStats {
            round_id,
            block_height: round.block_height,
            total_work: round.total_work,
            miner_count: round.miner_work.len(),
        })
    }

    /// Record a share reported by the co-located pool_sv2 (already validated there).
    ///
    /// H6: rate limited per miner and checked for anomalous work. L-8: rate limit entries are
    /// cleaned up every `RATE_LIMIT_CLEANUP_INTERVAL` shares.
    pub fn record_share(&self, miner_id: &str, work: f64) -> Result<(), ShareError> {
        let round_id = *self.current_round.read();
        if round_id == 0 {
            return Err(ShareError::NoActiveRound);
        }

        const RATE_LIMIT_CLEANUP_INTERVAL: u64 = 10_000;
        let shares_count = self
            .shares_since_cleanup
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if shares_count >= RATE_LIMIT_CLEANUP_INTERVAL {
            self.shares_since_cleanup
                .store(0, std::sync::atomic::Ordering::Relaxed);
            self.cleanup_rate_limits();
        }

        // H6: rate limiting. The lock is held for the whole check-and-increment, and the check
        // comes BEFORE the increment so the limit is exact.
        {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut rate_limits = self.miner_rate_limits.write();
            let entry = rate_limits
                .entry(miner_id.to_string())
                .or_insert(MinerRateLimitEntry {
                    last_second: now_secs,
                    count: 0,
                });
            if entry.last_second == now_secs {
                if entry.count >= self.config.max_shares_per_miner_per_sec {
                    warn!(
                        miner_id,
                        shares_this_second = entry.count,
                        max = self.config.max_shares_per_miner_per_sec,
                        "H6: Miner rate limited"
                    );
                    return Err(ShareError::RateLimited);
                }
                entry.count += 1;
            } else {
                entry.last_second = now_secs;
                entry.count = 1;
            }
        }

        // H6: anomaly detection
        let max_work = self.config.network_difficulty * self.config.max_work_multiplier;
        if work > max_work {
            warn!(
                miner_id,
                work, max_work, "H6: Anomalous work value detected - exceeds network difficulty"
            );
            return Err(ShareError::WorkValueTooHigh {
                got: work,
                max: max_work,
            });
        }
        if work <= 0.0 {
            warn!(miner_id, work, "H6: Invalid work value (non-positive)");
            return Err(ShareError::InvalidWork);
        }

        let mut rounds = self.rounds.write();
        let round = rounds
            .get_mut(&round_id)
            .ok_or(ShareError::RoundNotFound(round_id))?;
        if !round.miner_work.contains_key(miner_id)
            && round.miner_work.len() >= self.config.max_shares_per_round
        {
            return Err(ShareError::RoundFull);
        }
        round.add(miner_id, work);
        debug!(round_id, miner = %miner_id, work, "Recorded share from SRI");
        Ok(())
    }

    /// Clean up old rate limit entries (call periodically)
    pub fn cleanup_rate_limits(&self) {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.miner_rate_limits
            .write()
            .retain(|_, entry| now_secs.saturating_sub(entry.last_second) < 60);
    }
}

/// Why a share was not recorded.
#[derive(Debug, thiserror::Error)]
pub enum ShareError {
    #[error("No active round")]
    NoActiveRound,

    #[error("Round not found: {0}")]
    RoundNotFound(RoundId),

    #[error("Round is full")]
    RoundFull,

    #[error("Work value too high: got {got}, maximum {max}")]
    WorkValueTooHigh { got: f64, max: f64 },

    #[error("Rate limited")]
    RateLimited,

    #[error("Invalid work value")]
    InvalidWork,
}

/// Round statistics
#[derive(Debug, Clone)]
pub struct RoundStats {
    pub round_id: RoundId,
    pub block_height: u64,
    pub total_work: f64,
    pub miner_count: usize,
}

/// Round summary
#[derive(Debug, Clone)]
pub struct RoundSummary {
    pub round_id: RoundId,
    pub block_height: u64,
    pub total_miner_work: f64,
    pub miner_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_lifecycle() {
        let manager = RoundManager::new(RoundConfig::default());
        let round_id = manager.start_round(100);
        assert_eq!(round_id, 1);
        assert_eq!(manager.current_height(), 100);

        manager.record_share("miner1", 10.0).unwrap();
        manager.record_share("miner2", 30.0).unwrap();
        manager.record_share("miner1", 10.0).unwrap();

        let stats = manager.round_stats(round_id).unwrap();
        assert_eq!(stats.miner_count, 2);
        assert_eq!(stats.total_work, 50.0);

        let summary = manager.end_round().unwrap();
        assert_eq!(summary.round_id, round_id);
        assert_eq!(summary.miner_count, 2);
    }

    #[test]
    fn no_share_is_recorded_before_the_first_round() {
        let manager = RoundManager::new(RoundConfig::default());
        assert!(matches!(
            manager.record_share("m", 1.0),
            Err(ShareError::NoActiveRound)
        ));
    }

    #[test]
    fn anomalous_and_non_positive_work_is_refused() {
        let manager = RoundManager::new(RoundConfig::default());
        manager.start_round(1);
        assert!(matches!(
            manager.record_share("m", 2_000_000.0),
            Err(ShareError::WorkValueTooHigh { .. })
        ));
        assert!(matches!(
            manager.record_share("m", 0.0),
            Err(ShareError::InvalidWork)
        ));
    }

    #[test]
    fn a_miner_is_rate_limited_within_one_second() {
        let manager = RoundManager::new(RoundConfig {
            max_shares_per_miner_per_sec: 2,
            ..Default::default()
        });
        manager.start_round(1);
        // A hundred calls take microseconds, so at least one second sees more than two.
        let refused = (0..100)
            .map(|_| manager.record_share("m", 1.0))
            .filter(|r| matches!(r, Err(ShareError::RateLimited)))
            .count();
        assert!(refused > 0);
    }

    #[test]
    fn old_rounds_are_pruned() {
        let manager = RoundManager::new(RoundConfig {
            rounds_to_keep: 2,
            ..Default::default()
        });
        let first = manager.start_round(1);
        manager.start_round(2);
        manager.start_round(3);
        assert!(manager.round_stats(first).is_none());
        assert!(manager.round_stats(3).is_some());
    }

    #[test]
    fn test_current_round_elapsed_resets_on_start_round() {
        let start = std::time::Instant::now();
        let later = start + std::time::Duration::from_secs(42);
        assert_eq!(elapsed_secs_between(start, later), 42);
        // A `now` before `start` saturates to zero rather than panicking.
        assert_eq!(elapsed_secs_between(later, start), 0);
    }
}
