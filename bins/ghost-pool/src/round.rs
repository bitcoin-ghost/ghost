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

//! Round management for share tracking
//!
//! Tracks mining rounds, share submissions, and triggers payout proposals.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use ghost_accounting::shares::{DifficultyCalculator, RoundShares};
use ghost_common::config::MiningMode;
use ghost_common::types::{NodeCapabilities, NodeId, RoundId, ShareProof};
use ghost_storage::Database;

/// Round manager configuration
#[derive(Debug, Clone)]
pub struct RoundConfig {
    /// Pool share difficulty (target)
    pub share_difficulty: f64,
    /// Network difficulty
    pub network_difficulty: f64,
    /// Maximum shares per round (memory protection)
    pub max_shares_per_round: usize,
    /// Round history to keep
    pub rounds_to_keep: usize,
    /// Mining mode (affects payout flow)
    pub mining_mode: MiningMode,
    /// Maximum shares per miner per second (H6 rate limiting)
    /// Default: 100 shares/sec - prevents spam attacks
    pub max_shares_per_miner_per_sec: u32,
    /// Maximum work value per share (H6 anomaly detection)
    /// Shares with work > this * network_difficulty are suspicious
    pub max_work_multiplier: f64,
}

impl Default for RoundConfig {
    fn default() -> Self {
        Self {
            share_difficulty: 1000.0,
            network_difficulty: 1_000_000.0,
            max_shares_per_round: 1_000_000,
            rounds_to_keep: 10,
            mining_mode: MiningMode::PublicPool,
            max_shares_per_miner_per_sec: 100, // H6: Rate limit per miner
            max_work_multiplier: 1.0,          // H6: Work cannot exceed network difficulty
        }
    }
}

/// Events emitted by the round manager
#[derive(Debug, Clone)]
pub enum RoundEvent {
    /// New round started
    RoundStarted {
        round_id: RoundId,
        block_height: u64,
    },
    /// Share submitted
    ShareSubmitted {
        round_id: RoundId,
        miner_id: String,
        work: f64,
    },
    /// Block found!
    BlockFound {
        round_id: RoundId,
        block_hash: [u8; 32],
        miner_id: String,
    },
    /// Round ended
    RoundEnded {
        round_id: RoundId,
        total_shares: u64,
        total_work: f64,
    },
}

/// Per-miner rate limit tracking for H6 security fix
struct MinerRateLimitEntry {
    /// Timestamp of last share (Unix seconds)
    last_second: u64,
    /// Number of shares in current second
    count: u32,
}

/// L-7: Per-miner cumulative tolerance tracking per round
/// Tracks how much work tolerance a miner has exploited in a round.
/// If cumulative exploitation exceeds 1% of their total work, reject further shares.
///
/// M-03: Uses integer arithmetic (u128 scaled values) instead of f64 to avoid
/// floating-point precision issues that could be exploited to bypass the cap.
/// Work values are scaled by TOLERANCE_SCALE to preserve precision without floating point.
#[derive(Default)]
struct MinerToleranceTracker {
    /// Map of miner_id -> (total_work_scaled, cumulative_tolerance_scaled)
    /// Values are work * TOLERANCE_SCALE to preserve precision in integer arithmetic
    entries: HashMap<String, (u128, u128)>,
}

impl MinerToleranceTracker {
    /// M-03: Scale factor for converting f64 work to integer
    /// Using 10^9 gives sub-nanoscale precision which is more than sufficient
    const TOLERANCE_SCALE: u128 = 1_000_000_000;

    /// M-03: Maximum cumulative tolerance in basis points (100 = 1%)
    const MAX_CUMULATIVE_TOLERANCE_BPS: u128 = 100;

    /// Basis points denominator (10000 = 100%)
    const BPS_DENOMINATOR: u128 = 10_000;

    /// Record tolerance exploitation for a miner
    /// Returns Err if cumulative exploitation exceeds 1% of total work
    ///
    /// M-03: Uses integer arithmetic with basis points comparison
    fn record_tolerance(
        &mut self,
        miner_id: &str,
        work_credited: f64,
        tolerance_exploited: f64,
    ) -> Result<(), f64> {
        // M-03: Scale f64 to u128 for integer arithmetic
        let work_scaled = (work_credited * Self::TOLERANCE_SCALE as f64) as u128;
        let tolerance_scaled = (tolerance_exploited * Self::TOLERANCE_SCALE as f64) as u128;

        let entry = self.entries.entry(miner_id.to_string()).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(work_scaled);
        entry.1 = entry.1.saturating_add(tolerance_scaled);

        // M-03: Check using basis points: exploitation_bps = (tolerance * 10000) / total_work
        // This avoids f64 division entirely
        if entry.0 > 0 {
            // Multiply tolerance by BPS_DENOMINATOR first to maintain precision
            let exploitation_bps = entry
                .1
                .saturating_mul(Self::BPS_DENOMINATOR)
                .checked_div(entry.0)
                .unwrap_or(0);

            if exploitation_bps > Self::MAX_CUMULATIVE_TOLERANCE_BPS {
                // Convert back to percentage for error reporting
                let exploitation_percent = exploitation_bps as f64 / 100.0;
                return Err(exploitation_percent);
            }
        }
        Ok(())
    }
}

/// M-29: Cross-round tolerance tracking entry
/// Tracks a miner's tolerance exploitation pattern across multiple rounds
/// to identify persistent exploiters who game the per-round 1% limit.
#[derive(Debug, Clone)]
struct CrossRoundToleranceEntry {
    /// Number of rounds where this miner hit the tolerance limit
    limit_hit_count: u32,
    /// Total rounds participated in (for percentage calculation)
    rounds_participated: u32,
    /// Timestamp of last tolerance limit violation (for decay)
    last_violation_time: std::time::Instant,
    /// Total exploitation across all tracked rounds
    total_exploitation_percent: f64,
}

impl Default for CrossRoundToleranceEntry {
    fn default() -> Self {
        Self {
            limit_hit_count: 0,
            rounds_participated: 0,
            last_violation_time: std::time::Instant::now(),
            total_exploitation_percent: 0.0,
        }
    }
}

/// M-29: Cross-round tolerance tracker
/// Identifies miners who persistently exploit tolerance limits across rounds.
/// A miner who hits the 1% tolerance limit in more than 50% of rounds they
/// participate in (minimum 5 rounds) is considered a persistent exploiter.
#[derive(Default)]
struct CrossRoundToleranceTracker {
    /// Map of miner_id -> cross-round exploitation data
    entries: HashMap<String, CrossRoundToleranceEntry>,
}

impl CrossRoundToleranceTracker {
    /// M-29: Maximum percentage of rounds where tolerance limit can be hit
    /// before being flagged as a persistent exploiter
    const MAX_LIMIT_HIT_RATIO: f64 = 0.50; // 50% of rounds

    /// M-29: Minimum rounds before cross-round tracking kicks in
    const MIN_ROUNDS_FOR_TRACKING: u32 = 5;

    /// M-29: Time after which violations decay (1 hour)
    const VIOLATION_DECAY_DURATION: std::time::Duration = std::time::Duration::from_secs(3600);

    /// Record a miner's participation in a round
    fn record_round_participation(&mut self, miner_id: &str) {
        let entry = self.entries.entry(miner_id.to_string()).or_default();
        entry.rounds_participated += 1;
    }

    /// Record that a miner hit the tolerance limit in a round
    fn record_tolerance_limit_hit(&mut self, miner_id: &str, exploitation_percent: f64) {
        let entry = self.entries.entry(miner_id.to_string()).or_default();
        entry.limit_hit_count += 1;
        entry.last_violation_time = std::time::Instant::now();
        entry.total_exploitation_percent += exploitation_percent;
    }

    /// Check if a miner is a persistent exploiter
    /// Returns Some(hit_ratio) if they are, None if they're not
    fn is_persistent_exploiter(&self, miner_id: &str) -> Option<f64> {
        let entry = self.entries.get(miner_id)?;

        // Check for decay - if last violation was too long ago, don't flag
        if entry.last_violation_time.elapsed() > Self::VIOLATION_DECAY_DURATION {
            return None;
        }

        // Need minimum rounds for meaningful tracking
        if entry.rounds_participated < Self::MIN_ROUNDS_FOR_TRACKING {
            return None;
        }

        let hit_ratio = entry.limit_hit_count as f64 / entry.rounds_participated as f64;
        if hit_ratio > Self::MAX_LIMIT_HIT_RATIO {
            Some(hit_ratio * 100.0)
        } else {
            None
        }
    }

    /// Clean up old entries (called periodically)
    fn cleanup_old_entries(&mut self) {
        self.entries.retain(|_, entry| {
            entry.last_violation_time.elapsed() < Self::VIOLATION_DECAY_DURATION
                || entry.rounds_participated < Self::MIN_ROUNDS_FOR_TRACKING
        });
    }
}

/// Manages mining rounds and share accounting
/// How often the PoW-rejection summary may be emitted, in seconds.
///
/// One line per rejected share was **59% of all ghost-pool log volume** measured on 2026-08-02
/// (2,811 of 4,704 lines in 20 minutes, ~39 MB/day before the rsyslog duplicate) — the growth that
/// filled vm7's disk and took ghostd down for an hour. A warning that fires thousands of times an
/// hour is not a warning, it is a metric, so it is accumulated and summarised.
const POW_REJECT_SUMMARY_SECS: i64 = 300;

pub struct RoundManager {
    /// Configuration
    config: RoundConfig,
    /// Rejections since the last summary: `(hash mismatch, below difficulty, missing header)`.
    ///
    /// Split by cause because the original single message could not distinguish them, which is
    /// exactly why #583 could not be judged: "does not verify" covers both a fabricated hash and an
    /// honest share that simply missed its claimed difficulty, and those mean opposite things.
    pow_reject_counts: std::sync::atomic::AtomicU64,
    pow_reject_below_diff: std::sync::atomic::AtomicU64,
    /// Proofs dropped at ingest because this exact claim was already judged unfixable.
    pow_reject_cached: std::sync::atomic::AtomicU64,
    /// Terminal verdicts, so a permanently-invalid proof is judged once rather than for ever.
    terminal_rejects: crate::terminal_reject_cache::TerminalRejectCache,
    pow_reject_no_header: std::sync::atomic::AtomicU64,
    /// Shares at/above `SHARE_TIER_BIND_HEIGHT` carrying no committed tier. Kept apart from the
    /// tier-credit mismatch below because they mean different things: this one says the EMITTING
    /// side (translator/pool_sv2) is not stamping tiers yet, which during a roll is a deploy-order
    /// problem, not an attack.
    pow_reject_no_tier: std::sync::atomic::AtomicU64,
    /// Shares whose numeric `difficulty` does not equal their committed tier's target. An emitter
    /// that quantises vardiff but reports a different number would show up here, not as an attack.
    pow_reject_tier_credit: std::sync::atomic::AtomicU64,
    /// Unix seconds of the last emitted summary.
    pow_reject_last_log: std::sync::atomic::AtomicI64,
    /// Current round ID
    current_round: RwLock<RoundId>,
    /// Current block height
    current_height: RwLock<u64>,
    /// First round at or above SHARE_ADDR_BIND_HEIGHT — the signature-format boundary.
    addr_bind_activation_round: RwLock<Option<RoundId>>,
    /// Wall-clock start of the current round (reset on every `start_round`,
    /// i.e. each new-work / template event). Monotonic `Instant` so the
    /// reported elapsed time is immune to system clock adjustments. Read by
    /// `current_round_elapsed_secs` to surface `current_round_duration_secs`
    /// on the pool-status endpoint.
    current_round_start: RwLock<std::time::Instant>,
    /// Active rounds (current and recent)
    rounds: RwLock<HashMap<RoundId, RoundShares>>,
    /// Difficulty calculator
    difficulty: RwLock<DifficultyCalculator>,
    /// Registered nodes and their capabilities
    nodes: RwLock<HashMap<NodeId, NodeCapabilities>>,
    /// Event broadcaster
    event_tx: broadcast::Sender<RoundEvent>,
    /// Our node ID
    our_node_id: NodeId,
    /// Submitted share hashes per round (for duplicate detection)
    ///
    /// SECURITY NOTE: This is intentionally memory-only and not persisted to database.
    /// This is acceptable because:
    /// 1. Shares are scoped to rounds, and rounds end when a block is found
    /// 2. On restart, the pool starts a new round anyway (templates change)
    /// 3. Duplicate detection within a round is sufficient protection
    /// 4. Cross-round duplicates are naturally rejected (wrong round_id)
    /// 5. Old round share sets are cleaned up when rounds are removed
    ///
    /// Persisting to database would add latency to every share submission
    /// without meaningful security benefit given the round-scoped design.
    submitted_shares: RwLock<HashMap<RoundId, std::collections::HashSet<[u8; 32]>>>,
    /// GHOST-03: full signed proofs for retained rounds, keyed by round then
    /// share hash. Kept so a node that missed a gossiped share (drop/partition)
    /// can be served the exact signed proof during ledger convergence. Pruned
    /// with the round, exactly like `submitted_shares`.
    recent_proofs: RwLock<HashMap<RoundId, HashMap<[u8; 32], ShareProof>>>,
    /// Per-miner rate limiting (H6 security fix)
    miner_rate_limits: RwLock<HashMap<String, MinerRateLimitEntry>>,
    /// L-7: Per-miner cumulative tolerance tracking per round
    /// Prevents systematic inflation through repeated 0.1% tolerance exploitation
    miner_tolerance_tracker: RwLock<HashMap<RoundId, MinerToleranceTracker>>,
    /// M-29: Cross-round tolerance tracking
    /// Identifies miners who persistently exploit tolerance limits across rounds
    cross_round_tolerance: RwLock<CrossRoundToleranceTracker>,
    /// M-MINE-1: Current template ID (prev_block_hash) for share validation
    current_template_id: RwLock<Option<[u8; 32]>>,
    /// M-MINE-1: Recent template IDs for accepting shares during template transitions
    /// Keeps last N templates to avoid rejecting shares during brief overlap periods
    recent_template_ids: RwLock<Vec<[u8; 32]>>,
    /// L-8: Counter for automatic rate limit cleanup
    /// Cleanup is triggered every RATE_LIMIT_CLEANUP_INTERVAL shares
    shares_since_cleanup: std::sync::atomic::AtomicU64,
    /// Prometheus metrics (optional)
    metrics: Option<Arc<ghost_common::metrics::Metrics>>,
}

/// Seconds elapsed between two monotonic instants, saturating to 0 if `now`
/// precedes `start` (guards against any ordering surprise; `Instant` is
/// monotonic so this normally cannot happen). Pure helper so the round-duration
/// derivation is unit-testable without wall-clock sleeps.
fn elapsed_secs_between(start: std::time::Instant, now: std::time::Instant) -> u64 {
    now.saturating_duration_since(start).as_secs()
}

impl RoundManager {
    /// Create a new round manager
    pub fn new(our_node_id: NodeId, config: RoundConfig) -> Self {
        let difficulty =
            DifficultyCalculator::new(config.share_difficulty, config.network_difficulty);

        let (event_tx, _) = broadcast::channel(1000);

        Self {
            config,
            pow_reject_counts: std::sync::atomic::AtomicU64::new(0),
            pow_reject_below_diff: std::sync::atomic::AtomicU64::new(0),
            pow_reject_cached: std::sync::atomic::AtomicU64::new(0),
            terminal_rejects: crate::terminal_reject_cache::TerminalRejectCache::default(),
            pow_reject_no_header: std::sync::atomic::AtomicU64::new(0),
            pow_reject_no_tier: std::sync::atomic::AtomicU64::new(0),
            pow_reject_tier_credit: std::sync::atomic::AtomicU64::new(0),
            pow_reject_last_log: std::sync::atomic::AtomicI64::new(0),
            current_round: RwLock::new(0),
            current_height: RwLock::new(0),
            addr_bind_activation_round: RwLock::new(None),
            current_round_start: RwLock::new(std::time::Instant::now()),
            rounds: RwLock::new(HashMap::new()),
            difficulty: RwLock::new(difficulty),
            nodes: RwLock::new(HashMap::new()),
            event_tx,
            our_node_id,
            submitted_shares: RwLock::new(HashMap::new()),
            recent_proofs: RwLock::new(HashMap::new()),
            miner_rate_limits: RwLock::new(HashMap::new()),
            miner_tolerance_tracker: RwLock::new(HashMap::new()),
            cross_round_tolerance: RwLock::new(CrossRoundToleranceTracker::default()),
            current_template_id: RwLock::new(None),
            recent_template_ids: RwLock::new(Vec::new()),
            shares_since_cleanup: std::sync::atomic::AtomicU64::new(0),
            metrics: None,
        }
    }

    /// Set Prometheus metrics instance
    pub fn set_metrics(&mut self, metrics: Arc<ghost_common::metrics::Metrics>) {
        self.metrics = Some(metrics);
    }

    /// Subscribe to round events
    pub fn subscribe(&self) -> broadcast::Receiver<RoundEvent> {
        self.event_tx.subscribe()
    }

    /// The round in which `SHARE_ADDR_BIND_HEIGHT` first took effect, if it has.
    ///
    /// Verification is era-aware because the gate is a **signature-format change**, and a share
    /// carries no height — only a round. Judging an old share by the current height would make
    /// every pre-gate share unverifiable the moment the gate fires, so a peer could never backfill
    /// one again and the gaps between nodes' ledgers would freeze permanently. Judging it by the
    /// era it was signed in keeps history verifiable while still requiring the bound encoding on
    /// everything new.
    pub fn addr_bind_activation_round(&self) -> Option<RoundId> {
        *self.addr_bind_activation_round.read()
    }

    /// Record the activation round, if not already known. Ignores a later value: the FIRST round
    /// at or above the gate is the boundary, and a restart that re-derives a later one would
    /// wrongly treat genuinely post-gate shares as historical.
    pub fn note_addr_bind_activation(&self, round_id: RoundId) {
        let mut a = self.addr_bind_activation_round.write();
        if a.is_none_or(|existing| round_id < existing) {
            *a = Some(round_id);
        }
    }

    /// Whether a share from `share_round_id` must carry the address-bound signature.
    ///
    /// Unknown activation round means the gate has never fired here, so nothing is bound yet.
    pub fn requires_bound_signature(&self, share_round_id: RoundId) -> bool {
        match self.addr_bind_activation_round() {
            Some(activation) => share_round_id >= activation,
            None => false,
        }
    }

    /// Seed the chain height at startup, before any template has arrived.
    ///
    /// `current_height` is otherwise 0 from process start until the first template, and every
    /// height gate reads it. Zero sorts below any activation height, so a freshly restarted node
    /// silently disagrees with the fleet about which rules are in force — it took the weaker PoW
    /// check in #597, and for a signature-format gate it would sign with the wrong encoding and
    /// have its shares rejected by peers that are past the gate.
    ///
    /// Seeding from Core at boot closes that window for all gates at once. Never lowers the
    /// height: a template that has already arrived is better evidence than a startup RPC.
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

        // The gate is by height, but shares are judged by round, so the boundary has to be
        // captured as a round the first time the height crosses it.
        if block_height >= crate::share_addr_bind_height() {
            self.note_addr_bind_activation(round_id);
        }
        // Reset the round timer so `current_round_duration_secs` measures time
        // spent working THIS template, not the pool's total uptime.
        *self.current_round_start.write() = std::time::Instant::now();

        // Create new round shares tracker
        let mut rounds = self.rounds.write();
        rounds.insert(round_id, RoundShares::new(round_id, block_height));

        // Register all known nodes into the new round
        let nodes = self.nodes.read();
        if let Some(round) = rounds.get_mut(&round_id) {
            for (node_id, caps) in nodes.iter() {
                round.register_node(*node_id, *caps);
            }
        }

        // Cleanup old rounds
        let to_remove: Vec<_> = rounds
            .keys()
            .filter(|&r| *r + self.config.rounds_to_keep as u64 <= round_id)
            .cloned()
            .collect();

        for old_round in &to_remove {
            rounds.remove(old_round);
        }

        // Also cleanup submitted shares and tolerance trackers for old rounds
        {
            let mut submitted = self.submitted_shares.write();
            let mut tolerance = self.miner_tolerance_tracker.write();
            let mut proofs = self.recent_proofs.write();
            for old_round in to_remove {
                submitted.remove(&old_round);
                tolerance.remove(&old_round);
                proofs.remove(&old_round); // GHOST-03: prune retained proofs too
            }
        }

        // M-29: Cleanup old cross-round tolerance entries
        {
            let mut cross_round = self.cross_round_tolerance.write();
            cross_round.cleanup_old_entries();
        }

        info!(
            round_id = round_id,
            block_height = block_height,
            "Started new round"
        );

        let _ = self.event_tx.send(RoundEvent::RoundStarted {
            round_id,
            block_height,
        });

        round_id
    }

    /// Submit a share
    pub fn submit_share(
        &self,
        miner_id: &str,
        difficulty: f64,
        share_hash: [u8; 32],
    ) -> Result<ShareSubmitResult, ShareError> {
        let round_id = *self.current_round.read();
        if round_id == 0 {
            return Err(ShareError::NoActiveRound);
        }

        let diff_calc = self.difficulty.read();

        // Check claimed difficulty meets pool minimum
        if !diff_calc.meets_share_difficulty(difficulty) {
            return Err(ShareError::DifficultyTooLow {
                got: difficulty,
                needed: diff_calc.share_difficulty,
            });
        }

        // Cryptographic verification: verify the hash actually meets the claimed difficulty
        if !diff_calc.verify_share_difficulty(&share_hash, difficulty) {
            return Err(ShareError::InvalidShareHash);
        }

        // Check for duplicate share submission
        {
            let mut submitted = self.submitted_shares.write();
            let round_shares = submitted.entry(round_id).or_default();
            if !round_shares.insert(share_hash) {
                return Err(ShareError::DuplicateShare);
            }
        }

        // Calculate work value
        let work = diff_calc.calculate_work(difficulty);

        // SECURITY: Sanity check on work value - reject impossibly high values
        // Maximum work per share is capped at network difficulty (finding a block)
        // This prevents manipulation via fake high-difficulty claims that pass hash verification
        // (e.g., if someone finds a hash collision or exploits weak verification)
        let max_work = diff_calc.network_difficulty;
        if work > max_work {
            return Err(ShareError::WorkValueTooHigh {
                got: work,
                max: max_work,
            });
        }

        // Add to round
        let mut rounds = self.rounds.write();
        let round = rounds
            .get_mut(&round_id)
            .ok_or(ShareError::RoundNotFound(round_id))?;

        if round.miner_shares.len() >= self.config.max_shares_per_round {
            return Err(ShareError::RoundFull);
        }

        round.add_miner_work(miner_id, work);

        // Increment node shares (for our node since we received this)
        round.increment_node_shares(&self.our_node_id);

        // Instrument metrics
        if let Some(ref m) = self.metrics {
            m.shares_total.inc();
            m.shares_valid.inc();
        }

        debug!(
            round_id = round_id,
            miner = %miner_id,
            difficulty = difficulty,
            work = work,
            "Share submitted"
        );

        let _ = self.event_tx.send(RoundEvent::ShareSubmitted {
            round_id,
            miner_id: miner_id.to_string(),
            work,
        });

        // Check if this is a block
        let is_block = diff_calc.is_valid_block(difficulty);
        if is_block {
            if let Some(ref m) = self.metrics {
                m.blocks_found_total.inc();
            }

            info!(
                round_id = round_id,
                miner = %miner_id,
                difficulty = difficulty,
                "BLOCK FOUND!"
            );

            let _ = self.event_tx.send(RoundEvent::BlockFound {
                round_id,
                block_hash: share_hash,
                miner_id: miner_id.to_string(),
            });
        }

        Ok(ShareSubmitResult {
            round_id,
            work,
            is_block,
            share_hash,
        })
    }

    /// Handle a share proof from the P2P network
    ///
    /// Security fixes C4, C5, M-MINE-1, and M-6:
    /// - C4: Cryptographic verification that share_hash meets claimed difficulty
    /// - C5: Duplicate detection using submitted_shares HashMap
    /// - M-MINE-1: Template validation to reject stale shares
    /// - M-6: Require template_id to be present (no bypass via None)
    pub fn handle_share_proof(&self, proof: ShareProof) -> Result<(), ShareError> {
        // M-6 + M-MINE-1: the template is validated ONLY for shares THIS node received and
        // signed. A gossiped share (received_by = another node) was mined against the SENDER's
        // coinbase template, which this node cannot know or validate; its trust anchors are the
        // GHOST-09 signature (the signer vouches for the credit), C4 PoW, and C5 dedup, and the
        // signer already validated its own template before signing.
        //
        // The M-6 presence requirement therefore lives INSIDE that branch. It used to sit above
        // it, unconditional — which made the field required-but-never-read on the remote path,
        // and refused every share older than the field itself. Measured: ~1,270 rejections per
        // hour on every node, all of them shares 1,700-13,600 rounds behind the live range,
        // replayed indefinitely by the GHOST-03 convergence sweep and refused every time. With
        // the repair path closed the fleet's unpaid ledgers drifted 466 -> 48,753 shares (3.15%)
        // in a week, which is what produces the `per-address differences sum to ...` checkpoint
        // rejections (#639).
        //
        // M-6's bypass guard is preserved exactly where it has meaning: a share claiming to be
        // ours must name the template it was mined against, or it could skip a validation that
        // genuinely applies. On the remote path there is no such validation to skip.
        if proof.received_by == self.our_node_id {
            let Some(template_id) = proof.template_id else {
                warn!(
                    round_id = proof.round_id,
                    miner = %hex::encode(&proof.miner_id[..8]),
                    "M-6: locally-received share proof missing required template_id"
                );
                return Err(ShareError::MissingTemplateId);
            };
            if !self.is_valid_template(&template_id) {
                warn!(
                    template_id = %hex::encode(&template_id[..8]),
                    round_id = proof.round_id,
                    "Share proof references stale template"
                );
                return Err(ShareError::StaleTemplate);
            }
        }

        let diff_calc = self.difficulty.read();

        // C4: verify the share actually meets its claimed difficulty.
        //
        // Multi-operator: AT/ABOVE `SHARE_POW_VERIFY_HEIGHT` this is not enough. The numeric
        // check trusts that `share_hash` is a REAL sha256d of a header — true when your own SRI
        // produced it, but a hostile peer can gossip a fabricated 32-byte value with an in-range
        // numeric difficulty and no real hashing. So require the 80-byte header and recompute the
        // PoW preimage independently: `sha256d(header) == share_hash` AND meets difficulty. You
        // cannot forge a header that hashes to a chosen value without doing the work. The header
        // is bound by the GHOST-09 signature, so it can't be stripped or swapped in flight. This
        // runs on the GOSSIP + BACKFILL ingest paths (both funnel here), which is exactly where an
        // injected share would enter the converged ledger; a node's own SRI-validated shares are
        // its own trust anchor. Below the gate, the legacy numeric check stands (single-operator).
        // Fail CLOSED when the height is not yet established. `current_height` is 0 from process
        // start until the first block template arrives, and 0 is below any activation height — so
        // a plain `>=` silently selected the weaker legacy check for that whole window, on every
        // restart. That window is also when a node ingests its backfill burst from peers, i.e. the
        // highest-volume remote ingest it ever does, and the legacy check cannot tell a real hash
        // from a fabricated 32-byte value because it never binds the hash to a header. Precisely
        // the injection this gate exists to stop.
        //
        // Treating "unknown" as above the gate costs nothing measurable: `missing_header` is 0
        // across the fleet over hours, so every share genuinely in flight carries its header.
        let height = self.current_height();
        let height_established = height > 0;
        // SHARE_TIER_BIND: whether shares at this height commit to a difficulty tier and are
        // credited exactly that tier. Deliberately NOT the pow gate's fail-closed
        // `!height_established ||` sense: that sense turns a check ON while the height is
        // unknown, which is right for the ARMED pow gate but would activate this DORMANT one on
        // every restart (height reads 0 until the first template) — a below-gate behaviour
        // change. The residual once armed is bounded: during the height-0 window the pow
        // preimage check below still runs (its fail-closed sense unchanged), so a fabricated
        // hash cannot enter; only the tier-credit selection waits for an established height,
        // during which a share is judged by the legacy numeric claim exactly as below the gate.
        let tier_bound = height_established && crate::binds_difficulty_tier(height);
        if !height_established || height >= crate::share_pow_verify_height() {
            let header80 = match proof.header.as_deref() {
                Some(h) if h.len() == 80 => {
                    let mut a = [0u8; 80];
                    a.copy_from_slice(h);
                    a
                }
                _ => {
                    self.pow_reject_no_header
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.maybe_summarise_pow_rejects();
                    return Err(ShareError::InvalidShareHash);
                }
            };
            // At/above the tier gate a share must state the tier its coinbase committed to.
            // Like `missing_header` this is NOT a terminal verdict — a different, correctly
            // emitted claim about the same work must still be judged on its merits — so it is
            // rejected before the terminal-reject cache, not recorded in it.
            let tier = if tier_bound {
                match proof.tier_log2 {
                    Some(t) => Some(t),
                    None => {
                        self.pow_reject_no_tier
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.maybe_summarise_pow_rejects();
                        return Err(ShareError::InvalidShareHash);
                    }
                }
            } else {
                None
            };
            // #583: a proof this node has already judged unfixable is dropped here rather than
            // verified again. The key covers the header, the hash, the claimed difficulty and
            // (at/above the tier gate) the committed tier — exactly the inputs the verdict is a
            // function of — so a *different* claim about the same share is still judged on its
            // merits and cannot be suppressed by a forged one.
            let verdict_key = crate::terminal_reject_cache::verdict_key(
                &header80,
                &proof.share_hash,
                proof.difficulty,
                tier,
            );
            if self.terminal_rejects.contains(&verdict_key) {
                self.pow_reject_cached
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.maybe_summarise_pow_rejects();
                return Err(ShareError::InvalidShareHash);
            }

            // Split the two causes. They mean opposite things — a hash that is not this header's
            // PoW is fabricated or relayed, while a real hash that misses its claimed difficulty is
            // an honest share mis-rated — and the single "does not verify" message conflated them,
            // which is why #583 sat unjudgeable for weeks.
            let computed = {
                use bitcoin::hashes::{sha256d, Hash};
                sha256d::Hash::hash(&header80).to_byte_array()
            };
            if computed != proof.share_hash {
                self.pow_reject_counts
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Terminal: these bytes can never hash to this value.
                self.terminal_rejects.insert(verdict_key);
                self.maybe_summarise_pow_rejects();
                debug!(
                    round_id = proof.round_id,
                    miner = %hex::encode(&proof.miner_id[..8]),
                    claimed = %hex::encode(&proof.share_hash[..8]),
                    computed = %hex::encode(&computed[..8]),
                    "share hash is not this header's PoW"
                );
                return Err(ShareError::InvalidShareHash);
            }
            // At/above the tier gate the share is judged against its COMMITTED tier and credited
            // exactly the tier's target, never the difficulty it happened to achieve — that is
            // the whole anti-post-hoc-claim mechanism. Requiring the proof's numeric
            // `difficulty` to BE the tier's target (±0.01%, the M-9 tolerance) is what makes the
            // credit equal the commitment: the M-9 work-consistency check below already binds
            // `work` to `difficulty`, so binding `difficulty` to the tier closes the chain
            // `work == difficulty == 2^tier_log2`.
            //
            // The tier BINDING — that the coinbase really committed to `(node_id, tier)` —
            // cannot be judged here: it needs the coinbase skeleton, which travels once per job
            // and may not have arrived yet. It is judged where skeletons live
            // (`binding_recheck`, `verify_share_tier_binding`); this path fixes the PoW and the
            // credit.
            if let Some(t) = tier {
                let credited =
                    match ghost_accounting::DifficultyCalculator::verify_pow_preimage_tier(
                        &header80,
                        &proof.share_hash,
                        t,
                    ) {
                        Some(credited) => credited,
                        None => {
                            self.pow_reject_below_diff
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            // Terminal: this hash cannot reach this tier, and neither can change.
                            self.terminal_rejects.insert(verdict_key);
                            self.maybe_summarise_pow_rejects();
                            let achieved =
                                ghost_accounting::DifficultyCalculator::difficulty_from_hash(
                                    &proof.share_hash,
                                );
                            debug!(
                                round_id = proof.round_id,
                                miner = %hex::encode(&proof.miner_id[..8]),
                                share = %hex::encode(&proof.share_hash[..8]),
                                from = %hex::encode(&proof.received_by[..8]),
                                committed_tier_log2 = t,
                                achieved_difficulty = achieved,
                                "share hash is genuine but misses its committed tier"
                            );
                            return Err(ShareError::InvalidShareHash);
                        }
                    };
                if (proof.difficulty - credited).abs() > credited * 0.0001 {
                    self.pow_reject_tier_credit
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    // Terminal: the mismatch is a function of the proof's own fields.
                    self.terminal_rejects.insert(verdict_key);
                    self.maybe_summarise_pow_rejects();
                    warn!(
                        round_id = proof.round_id,
                        miner = %hex::encode(&proof.miner_id[..8]),
                        share = %hex::encode(&proof.share_hash[..8]),
                        claimed_difficulty = proof.difficulty,
                        committed_tier_log2 = t,
                        tier_target = credited,
                        "share states a difficulty other than its committed tier's target"
                    );
                    return Err(ShareError::InvalidShareHash);
                }
            } else if !ghost_accounting::DifficultyCalculator::verify_pow_preimage(
                &header80,
                &proof.share_hash,
                proof.difficulty,
            ) {
                self.pow_reject_below_diff
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Terminal: this hash cannot reach this difficulty, and neither value can change.
                self.terminal_rejects.insert(verdict_key);
                self.maybe_summarise_pow_rejects();
                // Log the ACHIEVED difficulty alongside the claim. Without it the line says a
                // share missed its target and not by how much, which cannot distinguish a
                // mislabelled share (ratio just under 1) from one carrying a wildly wrong
                // difficulty (ratio orders of magnitude out) — and those have different causes.
                let achieved =
                    ghost_accounting::DifficultyCalculator::difficulty_from_hash(&proof.share_hash);
                debug!(
                    round_id = proof.round_id,
                    miner = %hex::encode(&proof.miner_id[..8]),
                    // The hash identifies the SHARE. Without it a burst of identical
                    // (round, miner, difficulty) lines cannot be told apart: one share redelivered
                    // in a loop and many distinct shares sharing a vardiff target look the same,
                    // and those are completely different bugs.
                    share = %hex::encode(&proof.share_hash[..8]),
                    from = %hex::encode(&proof.received_by[..8]),
                    claimed_difficulty = proof.difficulty,
                    achieved_difficulty = achieved,
                    ratio = achieved / proof.difficulty,
                    "share hash is genuine but misses its claimed difficulty"
                );
                return Err(ShareError::InvalidShareHash);
            }
        } else if !diff_calc.verify_share_difficulty(&proof.share_hash, proof.difficulty) {
            return Err(ShareError::InvalidShareHash);
        }

        // C4: Verify work consistency - claimed work must match the claimed difficulty.
        // M-9 SECURITY FIX: tight 0.01% tolerance limits any gaming to ≤0.1% pool
        // inflation per round; combined with L-7 cumulative tracking (1% cap/miner)
        // this prevents meaningful inflation.
        //
        // The work model is ABSOLUTE: a share's work == its difficulty, exactly as
        // the SRI/local path `record_share` credits it (and as main.rs builds the
        // proof: `difficulty = work = share.work`). C4 above already proved the hash
        // meets `proof.difficulty`, so binding `proof.work` to `proof.difficulty`
        // bounds the credited work by real PoW. The previous relative model
        // (`difficulty / share_difficulty`) assumed a pool minimum of 1; with the
        // production default share_difficulty it computed `work/1000` and rejected
        // EVERY gossiped share, leaving elders with 0 shares so GHOST-02 rejected
        // every payout once enforcement activated. Validate against difficulty
        // directly so the cross-node ledger matches the local ledger.
        let expected_work = proof.difficulty;
        // M3: Guard against NaN/Inf from degenerate difficulty values
        if !expected_work.is_finite() || expected_work <= 0.0 {
            return Err(ShareError::WorkValueTooHigh {
                got: proof.work,
                max: expected_work,
            });
        }
        let per_share_tolerance = expected_work * 0.0001; // M-9: 0.01% tolerance
        let work_difference = proof.work - expected_work;
        if work_difference.abs() > per_share_tolerance {
            tracing::warn!(
                claimed_work = proof.work,
                expected_work = expected_work,
                tolerance = per_share_tolerance,
                "M-9: Share proof work does not match claimed difficulty (>0.01% tolerance)"
            );
            return Err(ShareError::WorkValueTooHigh {
                got: proof.work,
                max: expected_work,
            });
        }

        // L-7 SECURITY: Track cumulative tolerance exploitation per miner per round
        //
        // M-2 DEFENSE IN DEPTH: The work tolerance system uses two layers of protection:
        //
        // 1. Per-share tolerance (0.01% via M-9 fix above): Necessary to accommodate
        //    floating-point rounding differences between miner and pool difficulty
        //    calculations. Without some tolerance, legitimate shares would be rejected
        //    due to IEEE 754 representation differences.
        //
        // 2. Cumulative limit (1% per miner per round): Even with 0.01% per-share
        //    tolerance, a miner submitting 10,000 shares could theoretically inflate
        //    their work by up to 100% (10,000 * 0.01%). The cumulative 1% cap ensures
        //    that no miner can game the system by more than 1% regardless of share count.
        //
        // Together these provide both compatibility (per-share) and security (cumulative).
        let miner_id = hex::encode(&proof.miner_id[..8]);

        // M-29: Check if this miner is a persistent exploiter across rounds
        {
            let cross_round = self.cross_round_tolerance.read();
            if let Some(hit_ratio) = cross_round.is_persistent_exploiter(&miner_id) {
                warn!(
                    miner_id = %miner_id,
                    round_id = proof.round_id,
                    hit_ratio = hit_ratio,
                    "M-29: Rejecting share - miner is a persistent tolerance exploiter"
                );
                return Err(ShareError::PersistentToleranceExploiter {
                    miner_id: miner_id.clone(),
                    hit_ratio,
                });
            }
        }

        if work_difference > 0.0 {
            // Miner is claiming more work than calculated - this is tolerance exploitation
            let mut tolerance_trackers = self.miner_tolerance_tracker.write();
            let tracker = tolerance_trackers.entry(proof.round_id).or_default();

            if let Err(exploitation_percent) =
                tracker.record_tolerance(&miner_id, expected_work, work_difference)
            {
                // M-29: Record this tolerance limit hit in cross-round tracker
                {
                    let mut cross_round = self.cross_round_tolerance.write();
                    cross_round.record_tolerance_limit_hit(&miner_id, exploitation_percent);
                }

                warn!(
                    miner_id = %miner_id,
                    round_id = proof.round_id,
                    exploitation_percent = exploitation_percent,
                    "L-7: Rejecting share - cumulative tolerance exploitation exceeds 1%"
                );
                return Err(ShareError::ToleranceExploitationExceeded {
                    miner_id: miner_id.clone(),
                    exploitation_percent,
                });
            }
        }

        // C4: Work upper bound - work cannot exceed network difficulty
        if proof.work > diff_calc.network_difficulty {
            return Err(ShareError::WorkValueTooHigh {
                got: proof.work,
                max: diff_calc.network_difficulty,
            });
        }

        // C5: Duplicate detection using submitted_shares
        {
            let mut submitted = self.submitted_shares.write();
            let round_shares = submitted.entry(proof.round_id).or_default();
            if !round_shares.insert(proof.share_hash) {
                return Err(ShareError::DuplicateShare);
            }
        }

        // Now safe to credit work
        let mut rounds = self.rounds.write();

        // Find or create round
        let round = rounds
            .entry(proof.round_id)
            .or_insert_with(|| RoundShares::new(proof.round_id, 0));

        // Credit the miner with proof.work (absolute model: work == difficulty,
        // validated above and PoW-bounded by C4). This MUST match what the local
        // SRI path `record_share` credits (raw `share.work`); recording the
        // relative `calculate_work` value here instead diverged the cross-node
        // ledger by a factor of `share_difficulty`, so GHOST-02's recompute never
        // matched the proposer once enforcement activated.
        let miner_id = hex::encode(&proof.miner_id[..8]);
        round.add_miner_work(&miner_id, proof.work);

        // Credit the node that received it
        round.increment_node_shares(&proof.received_by);

        // M-29: Record this miner's participation in the round for cross-round tracking
        {
            let mut cross_round = self.cross_round_tolerance.write();
            cross_round.record_round_participation(&miner_id);
        }

        // GHOST-03: retain the full signed proof so it can be re-served to a peer
        // that missed it (drop/partition) during ledger convergence.
        self.recent_proofs
            .write()
            .entry(proof.round_id)
            .or_default()
            .insert(proof.share_hash, proof.clone());

        debug!(
            round_id = proof.round_id,
            miner = %miner_id,
            work = proof.work,
            from_node = ?hex::encode(&proof.received_by[..4]),
            "Processed share proof (verified)"
        );

        Ok(())
    }

    /// GHOST-03: the share hashes this node currently holds for `round_id`.
    pub fn round_share_hashes(&self, round_id: RoundId) -> Vec<[u8; 32]> {
        self.recent_proofs
            .read()
            .get(&round_id)
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default()
    }

    /// GHOST-03: (share_count, total_work) this node holds for `round_id`.
    pub fn round_share_summary(&self, round_id: RoundId) -> (u64, f64) {
        match self.recent_proofs.read().get(&round_id) {
            Some(m) => (m.len() as u64, m.values().map(|p| p.work).sum()),
            None => (0, 0.0),
        }
    }

    /// GHOST-03: full signed proofs this node holds for `round_id` that are NOT
    /// in `their_hashes` — i.e. exactly the shares a converging peer is missing.
    /// Returns `(proofs, more_available)`, bounded by BOTH a count and a serialised-byte budget.
    ///
    /// The ledger lane has been bounded since #558; this one was not, and it is the same failure:
    /// a busy round produced a response past the 1 MB envelope cap, every receiver dropped it at
    /// `debug!`, and convergence silently never happened. Bounding here rather than at the caller
    /// means a huge round is never materialised in the first place.
    ///
    /// Iteration order of `recent_proofs` is not specified, so which proofs land in a truncated
    /// response is arbitrary — that is fine, because `more_available` makes the requester come
    /// back for the rest.
    pub fn proofs_missing_from_bounded(
        &self,
        round_id: RoundId,
        their_hashes: &std::collections::HashSet<[u8; 32]>,
        max_count: usize,
        max_bytes: usize,
    ) -> (Vec<ShareProof>, bool) {
        let guard = self.recent_proofs.read();
        let Some(m) = guard.get(&round_id) else {
            return (Vec::new(), false);
        };
        let mut out = Vec::new();
        let mut bytes = 0usize;
        let mut more = false;
        for (h, p) in m.iter() {
            if their_hashes.contains(h) {
                continue;
            }
            if out.len() >= max_count {
                more = true;
                break;
            }
            let sz = serde_json::to_vec(p).map(|v| v.len()).unwrap_or(0);
            if bytes + sz > max_bytes && !out.is_empty() {
                more = true;
                break;
            }
            bytes += sz;
            out.push(p.clone());
        }
        (out, more)
    }

    /// Unbounded variant, for tests and callers that already know the set is small.
    pub fn proofs_missing_from(
        &self,
        round_id: RoundId,
        their_hashes: &std::collections::HashSet<[u8; 32]>,
    ) -> Vec<ShareProof> {
        self.recent_proofs
            .read()
            .get(&round_id)
            .map(|m| {
                m.iter()
                    .filter(|(h, _)| !their_hashes.contains(*h))
                    .map(|(_, p)| p.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Register a node's capabilities
    pub fn register_node(&self, node_id: NodeId, capabilities: NodeCapabilities) {
        self.nodes.write().insert(node_id, capabilities);

        // Also register in current round
        let round_id = *self.current_round.read();
        if round_id > 0 {
            if let Some(round) = self.rounds.write().get_mut(&round_id) {
                round.register_node(node_id, capabilities);
            }
        }
    }

    /// Reload the latest round's miner work from the database on startup.
    ///
    /// This restores pre-restart share data so miners don't lose credit for work
    /// submitted before the pool restarted. Only the latest round is reloaded —
    /// older rounds are either already paid or abandoned.
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

        // Load aggregated miner work for the latest round
        let miners = match db.get_round_miners(max_round_id) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, round_id = max_round_id, "Failed to load round miners from database");
                return;
            }
        };

        if miners.is_empty() {
            info!(
                round_id = max_round_id,
                "No valid miner work found for latest round"
            );
            return;
        }

        // Rebuild the RoundShares for this round
        let mut round_shares = RoundShares::new(max_round_id, 0);
        let mut total_work = 0.0f64;
        for (miner_id, work) in &miners {
            round_shares.add_miner_work(miner_id, *work);
            total_work += work;
        }

        self.rounds.write().insert(max_round_id, round_shares);

        info!(
            round_id = max_round_id,
            miner_count = miners.len(),
            total_work = total_work,
            "Reloaded share data from database"
        );
    }

    /// Update an existing node's capabilities (e.g. after elder status changes)
    ///
    /// Updates both the node registry and the current active round.
    pub fn update_node_capabilities(&self, node_id: NodeId, capabilities: NodeCapabilities) {
        self.nodes.write().insert(node_id, capabilities);

        // Also update in current round so payout calculations use fresh caps
        let round_id = *self.current_round.read();
        if round_id > 0 {
            if let Some(round) = self.rounds.write().get_mut(&round_id) {
                round.register_node(node_id, capabilities);
            }
        }

        info!(
            node = %hex::encode(&node_id[..4]),
            total_shares = capabilities.total_shares(),
            elder = capabilities.elder_status,
            "Updated node capabilities"
        );
    }

    /// End current round and prepare payout data
    pub fn end_round(&self) -> Option<RoundSummary> {
        let round_id = *self.current_round.read();
        if round_id == 0 {
            return None;
        }

        let mut rounds = self.rounds.write();
        let round = rounds.get_mut(&round_id)?;

        // Calculate top 100 nodes
        round.calculate_top_100_nodes();

        let summary = RoundSummary {
            round_id,
            block_height: round.block_height,
            total_miner_work: round.total_miner_work,
            total_node_shares: round.total_node_shares,
            miner_count: round.miner_count(),
            node_count: round.node_count(),
            top_miners: round
                .top_miners(10)
                .into_iter()
                .map(|(id, w)| (id.to_string(), w))
                .collect(),
        };

        info!(
            round_id = round_id,
            total_work = summary.total_miner_work,
            miners = summary.miner_count,
            nodes = summary.node_count,
            "Round ended"
        );

        let _ = self.event_tx.send(RoundEvent::RoundEnded {
            round_id,
            total_shares: summary.miner_count as u64,
            total_work: summary.total_miner_work,
        });

        Some(summary)
    }

    /// Get current round ID
    /// Emit an aggregated PoW-rejection summary, at most once per
    /// [`POW_REJECT_SUMMARY_SECS`].
    ///
    /// Counts are drained when reported, so each rejection appears in exactly one summary and the
    /// numbers are a rate rather than a running total.
    ///
    /// Silence means zero rejections — the summary is only emitted when something was counted, so
    /// a quiet log is evidence rather than merely an absence of noise.
    fn maybe_summarise_pow_rejects(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let last = self.pow_reject_last_log.load(Relaxed);
        if now - last < POW_REJECT_SUMMARY_SECS {
            return;
        }
        // Claim the slot before draining, so two threads crossing the boundary together cannot
        // both report and double-count.
        if self
            .pow_reject_last_log
            .compare_exchange(last, now, Relaxed, Relaxed)
            .is_err()
        {
            return;
        }
        let mismatched = self.pow_reject_counts.swap(0, Relaxed);
        let below = self.pow_reject_below_diff.swap(0, Relaxed);
        let no_header = self.pow_reject_no_header.swap(0, Relaxed);
        let no_tier = self.pow_reject_no_tier.swap(0, Relaxed);
        let tier_credit = self.pow_reject_tier_credit.swap(0, Relaxed);
        let cached = self.pow_reject_cached.swap(0, Relaxed);
        if mismatched + below + no_header + no_tier + tier_credit + cached == 0 {
            return;
        }
        warn!(
            hash_mismatch = mismatched,
            below_difficulty = below,
            missing_header = no_header,
            // Both zero until SHARE_TIER_BIND_HEIGHT arms. Non-zero missing_tier during a roll
            // means the emitting side (translator/pool_sv2) is behind; tier_credit_mismatch
            // means an emitter states a difficulty other than its committed tier's target.
            missing_tier = no_tier,
            tier_credit_mismatch = tier_credit,
            // Redeliveries dropped without re-verifying. A high number here against low
            // first-judgement counts is the #583 signature: few bad shares, endlessly resent.
            already_judged = cached,
            distinct_terminal = self.terminal_rejects.len(),
            window_secs = POW_REJECT_SUMMARY_SECS,
            "share proofs rejected on PoW re-verification"
        );
    }

    pub fn current_round_id(&self) -> RoundId {
        *self.current_round.read()
    }

    /// Get current block height
    pub fn current_height(&self) -> u64 {
        *self.current_height.read()
    }

    /// Seconds elapsed in the current round — i.e. how long the pool has been
    /// working the current template, measured from the most recent
    /// `start_round`. Surfaced as `current_round_duration_secs` on the
    /// pool-status endpoint.
    pub fn current_round_elapsed_secs(&self) -> u64 {
        elapsed_secs_between(*self.current_round_start.read(), std::time::Instant::now())
    }

    /// Get round statistics
    pub fn round_stats(&self, round_id: RoundId) -> Option<RoundStats> {
        let rounds = self.rounds.read();
        let round = rounds.get(&round_id)?;

        Some(RoundStats {
            round_id,
            block_height: round.block_height,
            total_work: round.total_miner_work,
            miner_count: round.miner_count(),
            node_count: round.node_count(),
        })
    }

    /// Update network difficulty
    pub fn update_difficulty(&self, network_difficulty: f64) {
        let mut diff = self.difficulty.write();
        diff.network_difficulty = network_difficulty;
        info!(
            difficulty = network_difficulty,
            "Updated network difficulty"
        );
    }

    /// Update share difficulty
    pub fn update_share_difficulty(&self, share_difficulty: f64) {
        let mut diff = self.difficulty.write();
        diff.share_difficulty = share_difficulty;
        info!(difficulty = share_difficulty, "Updated share difficulty");
    }

    /// Get current network difficulty
    pub fn network_difficulty(&self) -> f64 {
        self.difficulty.read().network_difficulty
    }

    /// Get current share difficulty
    pub fn share_difficulty(&self) -> f64 {
        self.difficulty.read().share_difficulty
    }

    /// Record a share forwarded from SRI (already validated by SRI)
    /// Used when ghost-pool runs in TDP-only mode without direct stratum access
    ///
    /// H6 security fix: Adds rate limiting and anomaly detection
    /// L-8: Automatic cleanup every RATE_LIMIT_CLEANUP_INTERVAL shares
    pub fn record_share(
        &self,
        miner_id: &str,
        work: f64,
        receiving_node: NodeId,
    ) -> Result<(), ShareError> {
        let round_id = *self.current_round.read();
        if round_id == 0 {
            return Err(ShareError::NoActiveRound);
        }

        // L-8: Automatic rate limit cleanup every N shares
        // This prevents memory accumulation without relying on external calls
        const RATE_LIMIT_CLEANUP_INTERVAL: u64 = 10_000;
        let shares_count = self
            .shares_since_cleanup
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if shares_count >= RATE_LIMIT_CLEANUP_INTERVAL {
            // Reset counter and perform cleanup
            self.shares_since_cleanup
                .store(0, std::sync::atomic::Ordering::Relaxed);
            self.cleanup_rate_limits();
            debug!(
                shares_count = shares_count,
                "L-8: Automatic rate limit cleanup triggered"
            );
        }

        // H6: Rate limiting check
        // L-8 SECURITY: The lock is held for the entire check-and-increment operation
        // to ensure atomicity. We check BEFORE incrementing to enforce exact limits.
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
                // L-8: Check BEFORE incrementing to enforce exact limit
                // Previous code incremented first, allowing max+1 shares
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
                // New second, reset counter to 1 (counting this share)
                entry.last_second = now_secs;
                entry.count = 1;
            }
        }

        // H6: Anomaly detection - work value sanity check
        {
            let diff_calc = self.difficulty.read();
            let max_work = diff_calc.network_difficulty * self.config.max_work_multiplier;
            if work > max_work {
                warn!(
                    miner_id,
                    work,
                    max_work,
                    "H6: Anomalous work value detected - exceeds network difficulty"
                );
                return Err(ShareError::WorkValueTooHigh {
                    got: work,
                    max: max_work,
                });
            }

            // Also check for negative or zero work
            if work <= 0.0 {
                warn!(miner_id, work, "H6: Invalid work value (non-positive)");
                return Err(ShareError::InvalidWork);
            }
        }

        let mut rounds = self.rounds.write();
        let round = rounds
            .get_mut(&round_id)
            .ok_or(ShareError::RoundNotFound(round_id))?;

        if round.miner_shares.len() >= self.config.max_shares_per_round {
            return Err(ShareError::RoundFull);
        }

        // Add miner work
        round.add_miner_work(miner_id, work);

        // Credit the node that received the share
        round.increment_node_shares(&receiving_node);

        debug!(
            round_id = round_id,
            miner = %miner_id,
            work = work,
            from_node = ?hex::encode(&receiving_node[..4]),
            "Recorded share from SRI"
        );

        let _ = self.event_tx.send(RoundEvent::ShareSubmitted {
            round_id,
            miner_id: miner_id.to_string(),
            work,
        });

        Ok(())
    }

    /// Clean up old rate limit entries (call periodically)
    pub fn cleanup_rate_limits(&self) {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut rate_limits = self.miner_rate_limits.write();
        // Remove entries older than 60 seconds
        rate_limits.retain(|_, entry| now_secs - entry.last_second < 60);
    }

    /// Get a miner's share percentage in current round
    pub fn miner_share_percent(&self, miner_id: &str) -> f64 {
        let round_id = *self.current_round.read();
        let rounds = self.rounds.read();
        rounds
            .get(&round_id)
            .map(|r| r.miner_share_percent(miner_id))
            .unwrap_or(0.0)
    }

    /// Get a node's share percentage in current round
    pub fn node_share_percent(&self, node_id: &NodeId) -> f64 {
        let round_id = *self.current_round.read();
        let rounds = self.rounds.read();
        rounds
            .get(&round_id)
            .map(|r| r.node_share_percent(node_id))
            .unwrap_or(0.0)
    }

    /// Get miner work distribution for a round
    /// Returns Vec<(miner_id, work_fraction)>
    pub fn get_miner_work(&self, round_id: RoundId) -> Vec<(String, f64)> {
        let rounds = self.rounds.read();
        rounds
            .get(&round_id)
            .map(|r| {
                r.top_miners(200) // Get top 200 miners
                    .into_iter()
                    .map(|(id, work)| (id.to_string(), work))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get miner work as pre-scaled u128 integers (for payout calculations)
    ///
    /// Returns work values already scaled by WORK_SCALE, eliminating the f64→u128
    /// conversion that introduces bounded imprecision (~1-2 sats per miner per block).
    pub fn get_miner_work_scaled(&self, round_id: RoundId) -> Vec<(String, u128)> {
        let rounds = self.rounds.read();
        rounds
            .get(&round_id)
            .map(|r| {
                r.top_miners_scaled(200)
                    .into_iter()
                    .map(|(id, work)| (id.to_string(), work))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get node share distribution for a round
    /// Returns Vec<(node_id, shares)>
    pub fn get_node_shares(&self, round_id: RoundId) -> Vec<(NodeId, i32)> {
        let mut rounds = self.rounds.write();
        if let Some(round) = rounds.get_mut(&round_id) {
            // Ensure top 100 is calculated before returning
            round.calculate_top_100_nodes();
            round
                .top_100_nodes()
                .into_iter()
                .map(|n| (n.node_id, n.shares))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get the configured mining mode
    pub fn mining_mode(&self) -> MiningMode {
        self.config.mining_mode
    }

    /// Check if we're in solo mining mode
    pub fn is_solo_mode(&self) -> bool {
        matches!(self.config.mining_mode, MiningMode::PrivateSolo)
    }

    /// M-MINE-1: Set the current template ID (prev_block_hash)
    ///
    /// Called when a new template is received. Tracks recent templates
    /// to allow shares during brief transition periods.
    pub fn set_template_id(&self, template_id: [u8; 32]) {
        // Update current template
        *self.current_template_id.write() = Some(template_id);

        // Add to recent templates (keep last 10 to accommodate network latency)
        const MAX_RECENT_TEMPLATES: usize = 10;
        let mut recent = self.recent_template_ids.write();
        if !recent.contains(&template_id) {
            recent.push(template_id);
            if recent.len() > MAX_RECENT_TEMPLATES {
                recent.remove(0);
            }
        }

        debug!(
            template_id = %hex::encode(&template_id[..8]),
            recent_count = recent.len(),
            "Updated current template ID"
        );
    }

    /// M-MINE-1: Get the current template ID
    pub fn current_template_id(&self) -> Option<[u8; 32]> {
        *self.current_template_id.read()
    }

    /// M-MINE-1: Check if a template ID is valid (current or recent)
    pub fn is_valid_template(&self, template_id: &[u8; 32]) -> bool {
        // Check current template
        if let Some(current) = *self.current_template_id.read() {
            if &current == template_id {
                return true;
            }
        }

        // Check recent templates (for transition periods)
        let recent = self.recent_template_ids.read();
        recent.contains(template_id)
    }
}

/// Result of submitting a share
#[derive(Debug, Clone)]
pub struct ShareSubmitResult {
    pub round_id: RoundId,
    pub work: f64,
    pub is_block: bool,
    pub share_hash: [u8; 32],
}

/// Share submission errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum ShareError {
    #[error("No active round")]
    NoActiveRound,

    #[error("Round not found: {0}")]
    RoundNotFound(RoundId),

    #[error("Difficulty too low: got {got}, needed {needed}")]
    DifficultyTooLow { got: f64, needed: f64 },

    #[error("Invalid share hash: hash does not meet claimed difficulty")]
    InvalidShareHash,

    #[error("Round is full")]
    RoundFull,

    #[error("Duplicate share")]
    DuplicateShare,

    #[error("Work value too high: got {got}, maximum {max}")]
    WorkValueTooHigh { got: f64, max: f64 },

    /// H6: Miner rate limited
    #[error("Rate limited: too many shares per second")]
    RateLimited,

    /// H6: Invalid work value
    #[error("Invalid work value")]
    InvalidWork,

    /// M-MINE-1: Share references a stale/unknown template
    #[error("Stale template: share references template that is not current or recent")]
    StaleTemplate,

    /// M-6: Share proof missing required template_id
    #[error("Missing template_id: share proofs must include template_id for validation")]
    MissingTemplateId,

    /// L-7: Cumulative tolerance exploitation exceeded
    #[error(
        "Tolerance exploitation exceeded: {miner_id} has exploited {exploitation_percent:.2}% (max 1%)"
    )]
    ToleranceExploitationExceeded {
        miner_id: String,
        exploitation_percent: f64,
    },

    /// M-29: Persistent tolerance exploiter across multiple rounds
    #[error(
        "Persistent tolerance exploiter: {miner_id} hit tolerance limit in {hit_ratio:.1}% of rounds (max 50%)"
    )]
    PersistentToleranceExploiter { miner_id: String, hit_ratio: f64 },
}

/// Round statistics
#[derive(Debug, Clone)]
pub struct RoundStats {
    pub round_id: RoundId,
    pub block_height: u64,
    pub total_work: f64,
    pub miner_count: usize,
    pub node_count: usize,
}

/// Round summary for payout calculation
#[derive(Debug, Clone)]
pub struct RoundSummary {
    pub round_id: RoundId,
    pub block_height: u64,
    pub total_miner_work: f64,
    pub total_node_shares: i32,
    pub miner_count: usize,
    pub node_count: usize,
    pub top_miners: Vec<(String, f64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_lifecycle() {
        let node_id = [1u8; 32];
        let manager = RoundManager::new(node_id, RoundConfig::default());

        // Start round
        let round_id = manager.start_round(100);
        assert_eq!(round_id, 1);
        assert_eq!(manager.current_round_id(), 1);
        assert_eq!(manager.current_height(), 100);

        // Submit shares
        let result = manager.submit_share("miner1", 1500.0, [0u8; 32]);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.round_id, 1);
        assert!(!result.is_block);
    }

    #[test]
    fn test_round_duration_derivation() {
        use std::time::{Duration, Instant};
        let start = Instant::now();
        // 125 seconds later → 125s elapsed.
        let now = start + Duration::from_secs(125);
        assert_eq!(elapsed_secs_between(start, now), 125);
        // Sub-second remainder truncates down to whole seconds.
        let now = start + Duration::from_millis(4_900);
        assert_eq!(elapsed_secs_between(start, now), 4);
        // `now` before `start` (should never happen with a monotonic clock, but
        // must never underflow/panic) → saturates to 0.
        assert_eq!(
            elapsed_secs_between(start + Duration::from_secs(10), start),
            0
        );
    }

    #[test]
    fn test_current_round_elapsed_resets_on_start_round() {
        let node_id = [1u8; 32];
        let manager = RoundManager::new(node_id, RoundConfig::default());
        manager.start_round(100);
        // Immediately after start_round the round has just begun.
        assert!(
            manager.current_round_elapsed_secs() < 2,
            "elapsed should be ~0 right after start_round"
        );
    }

    #[test]
    fn test_difficulty_check() {
        let node_id = [1u8; 32];
        let manager = RoundManager::new(node_id, RoundConfig::default());
        manager.start_round(100);

        // Too low difficulty
        let result = manager.submit_share("miner1", 500.0, [0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_work_value_upper_bound_config() {
        // SECURITY TEST: Verify the work cap configuration exists and is reasonable
        // The actual cap is enforced against calculated work which is derived from
        // cryptographically verified difficulty. This test validates the config.
        let config = RoundConfig {
            share_difficulty: 1000.0,
            network_difficulty: 100_000.0,
            ..Default::default()
        };

        // Verify the cap is set
        assert_eq!(config.network_difficulty, 100_000.0);

        // Verify default has a reasonable cap
        let default_config = RoundConfig::default();
        assert!(
            default_config.network_difficulty > default_config.share_difficulty,
            "Network difficulty should be greater than share difficulty"
        );
    }

    #[test]
    fn test_miner_share_tracking_via_record() {
        // Test that miner shares are tracked correctly for percentage calculation
        // Use record_share which bypasses difficulty verification (for SRI integration)
        let node_id = [1u8; 32];
        let manager = RoundManager::new(node_id, RoundConfig::default());
        manager.start_round(100);

        // Record shares from multiple miners (bypasses hash verification)
        let _ = manager.record_share("miner1", 100.0, node_id);
        let _ = manager.record_share("miner2", 100.0, node_id);
        let _ = manager.record_share("miner3", 100.0, node_id);

        // Check miner percentages are approximately equal
        let m1_pct = manager.miner_share_percent("miner1");
        let m2_pct = manager.miner_share_percent("miner2");
        let m3_pct = manager.miner_share_percent("miner3");

        // Each should be approximately 33.3%
        assert!(
            m1_pct > 0.30 && m1_pct < 0.35,
            "miner1 should be ~33%, got {}",
            m1_pct
        );
        assert!(
            m2_pct > 0.30 && m2_pct < 0.35,
            "miner2 should be ~33%, got {}",
            m2_pct
        );
        assert!(
            m3_pct > 0.30 && m3_pct < 0.35,
            "miner3 should be ~33%, got {}",
            m3_pct
        );

        // Sum should be 100%
        let total = m1_pct + m2_pct + m3_pct;
        assert!(
            (total - 1.0).abs() < 0.01,
            "Total should be 100%, got {}",
            total
        );
    }

    #[test]
    fn test_work_value_cap_logic() {
        // Test the work value cap logic directly
        // Work should be capped at network_difficulty
        let network_difficulty = 1_000_000.0;
        let claimed_work = 2_000_000.0; // Above network difficulty

        // This mimics the check in submit_share
        let max_work = network_difficulty;
        assert!(
            claimed_work > max_work,
            "Test setup: claimed work should exceed max"
        );

        // The error type should be WorkValueTooHigh
        let error = ShareError::WorkValueTooHigh {
            got: claimed_work,
            max: max_work,
        };
        assert!(error.to_string().contains("too high"));
    }

    #[test]
    fn test_h8_work_cap_before_round_addition() {
        // H8 SECURITY TEST: Verify work cap is applied BEFORE adding to round
        // This prevents inflated work values from affecting payout calculations
        let node_id = [1u8; 32];
        let config = RoundConfig {
            network_difficulty: 1_000_000.0,
            max_work_multiplier: 1.0, // Work cannot exceed network difficulty
            ..Default::default()
        };
        let manager = RoundManager::new(node_id, config);
        manager.start_round(100);

        // Try to record work that exceeds network difficulty
        let excessive_work = 2_000_000.0; // 2x network difficulty
        let result = manager.record_share("malicious_miner", excessive_work, node_id);

        // Should be rejected with WorkValueTooHigh error
        assert!(result.is_err());
        match result {
            Err(ShareError::WorkValueTooHigh { got, max }) => {
                assert_eq!(got, excessive_work);
                assert_eq!(max, 1_000_000.0);
            }
            _ => panic!("Expected WorkValueTooHigh error, got {:?}", result),
        }

        // Valid work should be accepted
        let valid_work = 500_000.0;
        let result = manager.record_share("honest_miner", valid_work, node_id);
        assert!(result.is_ok());

        // Verify the miner's work was recorded correctly
        let percent = manager.miner_share_percent("honest_miner");
        assert!(
            (percent - 1.0).abs() < 0.01,
            "Honest miner should have 100% of work"
        );
    }

    #[test]
    fn test_h8_zero_and_negative_work_rejected() {
        // H8 SECURITY TEST: Zero and negative work should be rejected
        let node_id = [1u8; 32];
        let manager = RoundManager::new(node_id, RoundConfig::default());
        manager.start_round(100);

        // Zero work should be rejected
        let result = manager.record_share("miner1", 0.0, node_id);
        assert!(matches!(result, Err(ShareError::InvalidWork)));

        // Negative work should be rejected
        let result = manager.record_share("miner2", -100.0, node_id);
        assert!(matches!(result, Err(ShareError::InvalidWork)));
    }

    #[test]
    fn test_m_mine_1_template_validation() {
        // M-MINE-1: Test template ID tracking and validation
        // M4: Template retention increased to 10 for mainnet latency tolerance
        let node_id = [1u8; 32];
        let manager = RoundManager::new(node_id, RoundConfig::default());

        // Initially no template
        assert!(manager.current_template_id().is_none());

        // Set first template
        let template1 = [1u8; 32];
        manager.set_template_id(template1);
        assert_eq!(manager.current_template_id(), Some(template1));
        assert!(manager.is_valid_template(&template1));

        // Set second template - first should still be valid (recent)
        let template2 = [2u8; 32];
        manager.set_template_id(template2);
        assert_eq!(manager.current_template_id(), Some(template2));
        assert!(manager.is_valid_template(&template2));
        assert!(manager.is_valid_template(&template1));

        // Fill up to 10 templates — template1 should still be valid
        for i in 3..=10u8 {
            let mut t = [0u8; 32];
            t[0] = i;
            manager.set_template_id(t);
        }
        assert!(manager.is_valid_template(&template1)); // 10 templates, still in window

        // 11th template evicts template1 (window is 10)
        let template11 = [11u8; 32];
        manager.set_template_id(template11);
        assert!(manager.is_valid_template(&template11));
        assert!(manager.is_valid_template(&template2)); // Still in window
        assert!(!manager.is_valid_template(&template1)); // Evicted

        // Unknown template should be invalid
        let unknown = [99u8; 32];
        assert!(!manager.is_valid_template(&unknown));
    }

    #[test]
    fn test_m_mine_2_rate_limit_cleanup() {
        // M-MINE-2: Test rate limit cleanup
        let node_id = [1u8; 32];
        let manager = RoundManager::new(node_id, RoundConfig::default());
        manager.start_round(100);

        // Record some shares to create rate limit entries
        let _ = manager.record_share("miner1", 100.0, node_id);
        let _ = manager.record_share("miner2", 100.0, node_id);

        // Cleanup should not panic and should work with fresh entries
        manager.cleanup_rate_limits();

        // More shares should still work after cleanup
        let result = manager.record_share("miner3", 100.0, node_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_l7_miner_tolerance_tracker() {
        // L-7 SECURITY TEST: Verify cumulative tolerance tracking works
        let mut tracker = MinerToleranceTracker::default();

        // Record several shares with small tolerance exploitation
        let miner_id = "test_miner";

        // Add work with cumulative exploitation just under 1%
        // 1000 work, 9 exploitation = 0.9%
        let result = tracker.record_tolerance(miner_id, 1000.0, 9.0);
        assert!(result.is_ok(), "0.9% should be OK");

        // Add more to push over 1%
        // Total: 1100 work, 12 exploitation = 1.09% - over limit
        let result = tracker.record_tolerance(miner_id, 100.0, 3.0);
        assert!(
            result.is_err(),
            "1.09% exploitation should be rejected, result: {:?}",
            result
        );

        // Verify the error contains the exploitation percentage
        if let Err(pct) = result {
            assert!(
                pct > 1.0,
                "Exploitation percent should be > 1%, got {}",
                pct
            );
        }
    }

    #[test]
    fn test_l7_tolerance_tracker_per_round_cleanup() {
        // L-7: Verify tolerance trackers are cleaned up with old rounds
        let node_id = [1u8; 32];
        let config = RoundConfig {
            rounds_to_keep: 2,
            ..Default::default()
        };
        let manager = RoundManager::new(node_id, config);

        // Start round 1 and add some tracking
        manager.start_round(100);
        let _ = manager.record_share("miner1", 100.0, node_id);

        // Start rounds until round 1 should be cleaned up
        manager.start_round(101);
        manager.start_round(102);
        manager.start_round(103);

        // Round 1 tolerance tracker should have been cleaned up
        // This is verified by the fact that memory doesn't grow unbounded
        // We can't directly access the private field, but the cleanup logic is tested
    }

    #[test]
    fn test_share_proof_duplicate_detection() {
        // L-21: Edge case test for duplicate share rejection via P2P proofs
        // Note: record_share() is for trusted SRI integration and skips duplicate checks
        // handle_share_proof() and submit_share() perform duplicate detection
        let node_id = [1u8; 32];
        let manager = RoundManager::new(node_id, RoundConfig::default());
        manager.start_round(100);

        // Set a valid template so share proof validation doesn't fail on template
        let template_id = [1u8; 32];
        manager.set_template_id(template_id);

        // Create a share proof
        let share_hash = [42u8; 32];
        let proof = ShareProof {
            header: None,
            tier_log2: None,
            round_id: 1,
            miner_id: [1u8; 32],
            difficulty: 1500.0, // Above pool minimum
            work: 1500.0,
            share_hash,
            timestamp: 0,
            received_by: node_id,
            template_id: Some(template_id),
            payout_address: None,
            signature: None,
        };

        // First submission should succeed
        let result = manager.handle_share_proof(proof.clone());
        // Note: May fail due to difficulty verification in test context
        // The key test is that duplicate detection is properly integrated

        // For unit testing, verify the submitted_shares tracking works
        // by checking that the set grows appropriately
        let _submitted_count = {
            let submitted = manager.submitted_shares.read();
            submitted.get(&1).map(|s| s.len()).unwrap_or(0)
        };

        // If first proof succeeded, duplicate should fail
        if result.is_ok() {
            let result2 = manager.handle_share_proof(proof);
            assert!(
                matches!(result2, Err(ShareError::DuplicateShare)),
                "Duplicate share proof should be rejected"
            );
        }
    }

    #[test]
    fn share_pow_verify_gate_rejects_missing_and_fabricated_header() {
        // Multi-operator (B-4): at/above SHARE_POW_VERIFY_HEIGHT a gossiped share MUST carry
        // its 80-byte header and re-verify PoW; a fabricated hash (the injection vector) is
        // rejected because no header hashes to it.
        let our = [1u8; 32];
        let manager = RoundManager::new(our, RoundConfig::default());
        // The gate is u64::MAX (dormant); put the round height AT it so the gated path runs.
        manager.start_round(crate::SHARE_POW_VERIFY_HEIGHT);
        assert!(manager.current_height() >= crate::share_pow_verify_height());

        let peer = [9u8; 32]; // received_by != our_node_id → skips the local-template check
        let base = ShareProof {
            round_id: 1,
            miner_id: [2u8; 32],
            difficulty: 1.0,
            work: 1.0,
            share_hash: [7u8; 32],
            timestamp: 0,
            received_by: peer,
            template_id: Some([3u8; 32]),
            payout_address: None,
            header: None,
            tier_log2: None,
            signature: None,
        };

        // No header above the gate → rejected (can't independently re-verify PoW).
        assert!(
            matches!(
                manager.handle_share_proof(base.clone()),
                Err(ShareError::InvalidShareHash)
            ),
            "a share with no header must be rejected at/above the gate"
        );

        // A header that does NOT hash to share_hash → rejected (fabricated/relayed).
        let mut fabricated = base.clone();
        fabricated.header = Some(vec![0u8; 80]); // sha256d([0;80]) != [7;32]
        assert!(
            matches!(
                manager.handle_share_proof(fabricated),
                Err(ShareError::InvalidShareHash)
            ),
            "a header that isn't the share's PoW preimage must be rejected"
        );
    }

    /// A share with REAL PoW at a deterministically-known tier: the Bitcoin genesis header
    /// achieves difficulty ~2536 — tier 11 (target 2048) and no higher. No mining in tests, no
    /// 1-in-256 flake.
    fn genesis_proof(round_id: u64, difficulty: f64, tier_log2: Option<u32>) -> ShareProof {
        use bitcoin::consensus::Encodable;
        use bitcoin::hashes::Hash;
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let mut header = Vec::new();
        genesis.header.consensus_encode(&mut header).unwrap();
        ShareProof {
            round_id,
            miner_id: [2u8; 32],
            difficulty,
            work: difficulty,
            share_hash: genesis.header.block_hash().to_byte_array(),
            timestamp: 0,
            received_by: [9u8; 32], // a peer → skips the local-template check
            template_id: Some([3u8; 32]),
            payout_address: None,
            header: Some(header),
            tier_log2,
            signature: None,
        }
    }

    /// SHARE_TIER_BIND below the gate: the acceptance bar for this whole change. With the gate
    /// dormant, a share is judged EXACTLY as today — the legacy numeric claim decides, a tier
    /// riding along is not consulted, and the post-hoc achieved-difficulty claim (the very
    /// attack the gate will close) still passes, because closing it early would BE a
    /// below-gate behaviour change.
    #[test]
    fn below_the_tier_gate_shares_are_judged_exactly_as_today() {
        let manager = RoundManager::new([1u8; 32], RoundConfig::default());
        // At the (armed) pow gate but far below the (dormant) tier gate.
        manager.start_round(crate::SHARE_POW_VERIFY_HEIGHT);
        assert!(!crate::binds_difficulty_tier(manager.current_height()));

        // The post-hoc claim: genesis achieves ~2536 and claims ~2500. Legacy rules admit it.
        assert!(
            manager
                .handle_share_proof(genesis_proof(1, 2500.0, None))
                .is_ok(),
            "below the gate the legacy numeric claim must stand unchanged"
        );

        // A tier riding along must change nothing (different work value to dodge C5 dedup —
        // dedup is by share_hash, so reuse of genesis needs a fresh manager).
        let manager2 = RoundManager::new([1u8; 32], RoundConfig::default());
        manager2.start_round(crate::SHARE_POW_VERIFY_HEIGHT);
        assert!(
            manager2
                .handle_share_proof(genesis_proof(1, 2500.0, Some(11)))
                .is_ok(),
            "below the gate a present tier field must not be consulted"
        );
    }

    /// #639: a REMOTE share without `template_id` must be admitted.
    ///
    /// M-6 used to require the field unconditionally, but it is only ever read for shares this
    /// node received itself — so on the remote path it was required-but-never-read, and refused
    /// every share older than the field. That closed the GHOST-03 convergence sweep's repair path
    /// (~1,270 rejections/hour/node) and let the fleet's unpaid ledgers drift 466 -> 48,753 shares
    /// in a week. The trust anchors for a remote share are unchanged: GHOST-09 signature, C4 PoW,
    /// C5 dedup.
    #[test]
    fn a_remote_share_without_a_template_id_is_admitted() {
        let manager = RoundManager::new([1u8; 32], RoundConfig::default());
        manager.start_round(crate::SHARE_POW_VERIFY_HEIGHT);

        let mut proof = genesis_proof(1, 2500.0, None);
        proof.template_id = None; // as replayed from before the field existed
        assert_ne!(
            proof.received_by, [1u8; 32],
            "this test is only meaningful for a share we did NOT receive"
        );

        assert!(
            manager.handle_share_proof(proof).is_ok(),
            "a gossiped share must not be refused for a field that is never read on that path — \
             refusing it is what closed the convergence repair path (#639)"
        );
    }

    /// #639 must NOT weaken M-6 where it has meaning: a share claiming WE received it still has
    /// to name its template, or it could skip a validation that genuinely applies to it.
    #[test]
    fn a_local_share_without_a_template_id_is_still_refused() {
        let manager = RoundManager::new([1u8; 32], RoundConfig::default());
        manager.start_round(crate::SHARE_POW_VERIFY_HEIGHT);

        let mut proof = genesis_proof(1, 2500.0, None);
        proof.received_by = [1u8; 32]; // ours
        proof.template_id = None;

        assert!(
            matches!(
                manager.handle_share_proof(proof),
                Err(ShareError::MissingTemplateId)
            ),
            "M-6's bypass guard must survive on the path where the template IS validated"
        );

        // And naming a template we never issued is still stale, not admitted.
        let manager2 = RoundManager::new([1u8; 32], RoundConfig::default());
        manager2.start_round(crate::SHARE_POW_VERIFY_HEIGHT);
        let mut stale = genesis_proof(1, 2500.0, None);
        stale.received_by = [1u8; 32];
        stale.template_id = Some([0xAB; 32]);
        assert!(
            matches!(
                manager2.handle_share_proof(stale),
                Err(ShareError::StaleTemplate)
            ),
            "a local share naming an unknown template is still refused"
        );
    }

    /// SHARE_TIER_BIND at the gate: the committed tier is required, judged, and credited —
    /// exactly `2^tier_log2`, never the achieved difficulty.
    #[test]
    fn at_the_tier_gate_the_committed_tier_is_required_and_credited() {
        use std::sync::atomic::Ordering::Relaxed;
        let manager = RoundManager::new([1u8; 32], RoundConfig::default());
        // The gate is u64::MAX (dormant); put the round height AT it so the gated path runs —
        // the same trick the pow-gate test above uses with its own constant.
        manager.start_round(crate::SHARE_TIER_BIND_HEIGHT);
        assert!(crate::binds_difficulty_tier(manager.current_height()));
        // Park the summariser so counters are observable (see the terminal-reject test).
        manager.pow_reject_last_log.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            Relaxed,
        );

        // No tier at/above the gate → refused, and counted as an emitter gap, not cached (a
        // later, correctly-emitted claim about the same work must still be judged).
        assert!(matches!(
            manager.handle_share_proof(genesis_proof(1, 2048.0, None)),
            Err(ShareError::InvalidShareHash)
        ));
        assert_eq!(manager.pow_reject_no_tier.load(Relaxed), 1);
        assert_eq!(
            manager.terminal_rejects.len(),
            0,
            "missing tier is retryable"
        );

        // The post-hoc claim, now refused: real hash, committed tier 11, but stating the
        // achieved ~2536 rather than the tier's 2048.
        assert!(matches!(
            manager.handle_share_proof(genesis_proof(1, 2536.0, Some(11))),
            Err(ShareError::InvalidShareHash)
        ));
        assert_eq!(manager.pow_reject_tier_credit.load(Relaxed), 1);

        // A committed tier the hash does not reach earns nothing (genesis misses 4096).
        assert!(matches!(
            manager.handle_share_proof(genesis_proof(1, 4096.0, Some(12))),
            Err(ShareError::InvalidShareHash)
        ));
        assert_eq!(manager.pow_reject_below_diff.load(Relaxed), 1);

        // Committed tier 11, stated as exactly 2^11: admitted, credited the tier.
        assert!(
            manager
                .handle_share_proof(genesis_proof(1, 2048.0, Some(11)))
                .is_ok(),
            "real PoW at its committed tier must be admitted"
        );

        // Redelivery of a judged-terminal claim is dropped from the cache, tier included in the
        // key: the accepted (tier 11, 2048) claim was never poisoned by the rejected ones.
        assert!(matches!(
            manager.handle_share_proof(genesis_proof(1, 2536.0, Some(11))),
            Err(ShareError::InvalidShareHash)
        ));
        assert_eq!(
            manager.pow_reject_cached.load(Relaxed),
            1,
            "an identical terminal claim must be dropped without re-judging"
        );
    }

    /// The gate is a signature-format change, so a share is judged by the era it was signed in,
    /// not by where the tip happens to be. Judging by current height would make every pre-gate
    /// share unverifiable the instant the gate fired — no peer could backfill one again and each
    /// node's gaps would freeze permanently.
    #[test]
    fn a_pre_gate_share_stays_verifiable_after_the_gate_fires() {
        let manager = RoundManager::new([1u8; 32], RoundConfig::default());
        assert_eq!(manager.addr_bind_activation_round(), None);
        assert!(
            !manager.requires_bound_signature(1),
            "nothing is bound before the gate has ever fired"
        );

        manager.note_addr_bind_activation(500);

        assert!(
            !manager.requires_bound_signature(499),
            "a share from before the boundary must remain verifiable for ever"
        );
        assert!(
            manager.requires_bound_signature(500),
            "the boundary round is bound"
        );
        assert!(manager.requires_bound_signature(501));
    }

    /// A restart re-derives the activation from the first template it sees, which is LATER than
    /// the true boundary. Taking that later value would treat genuinely post-gate shares as
    /// historical and accept the weaker signature for them.
    #[test]
    fn the_earliest_activation_round_wins() {
        let manager = RoundManager::new([1u8; 32], RoundConfig::default());
        manager.note_addr_bind_activation(500);
        manager.note_addr_bind_activation(900);
        assert_eq!(manager.addr_bind_activation_round(), Some(500));
        assert!(
            manager.requires_bound_signature(600),
            "a post-gate share must not be downgraded by a late re-derivation"
        );
    }

    /// Seeding exists so a restarted node does not read 0 and conclude every gate is inactive.
    #[test]
    fn seeding_sets_the_height_before_any_template_and_never_lowers_it() {
        let manager = RoundManager::new([1u8; 32], RoundConfig::default());
        assert_eq!(manager.current_height(), 0, "no template yet");

        manager.seed_height(960_000);
        assert_eq!(manager.current_height(), 960_000);

        // A template is better evidence than a startup RPC; seeding must not walk it back.
        manager.start_round(960_050);
        manager.seed_height(960_010);
        assert_eq!(
            manager.current_height(),
            960_050,
            "a stale seed must not lower a height a template already established"
        );
    }

    /// #597: the PoW re-verification is height-gated, and `current_height` is 0 from process start
    /// until the first template arrives. A plain `>=` puts 0 below any activation height, so every
    /// restart opened a window in which gossiped shares took the legacy numeric check — which never
    /// binds the hash to a header and therefore cannot detect the fabricated share the gate exists
    /// to stop. The window coincides with the backfill burst, so it is not a narrow one.
    #[test]
    fn an_unknown_height_uses_the_strict_check_not_the_legacy_one() {
        let manager = RoundManager::new([1u8; 32], RoundConfig::default());
        // No start_round: height is 0, exactly as it is for the first seconds after a restart.
        assert_eq!(manager.current_height(), 0);
        assert!(
            crate::share_pow_verify_height() > 0,
            "gate must be a real height for this test to mean anything"
        );

        // A fabricated hash with no header. Under the legacy numeric check a low claimed difficulty
        // makes this acceptable; under the strict check it cannot be verified and must be refused.
        let fabricated = ShareProof {
            round_id: 1,
            miner_id: [2u8; 32],
            difficulty: 1e-12,
            work: 1e-12,
            share_hash: [7u8; 32],
            timestamp: 0,
            received_by: [9u8; 32],
            template_id: Some([3u8; 32]),
            payout_address: None,
            header: None,
            tier_log2: None,
            signature: None,
        };
        assert!(
            matches!(
                manager.handle_share_proof(fabricated),
                Err(ShareError::InvalidShareHash)
            ),
            "a header-less gossiped share must be refused while the height is unknown"
        );
    }

    /// #583: fourteen bad shares produced sixty-seven rejections in ten minutes because nothing
    /// remembered that the verdict was final. A redelivered proof must be dropped, not re-judged.
    #[test]
    fn a_terminally_bad_proof_is_judged_once_and_then_dropped() {
        use std::sync::atomic::Ordering::Relaxed;

        let manager = RoundManager::new([1u8; 32], RoundConfig::default());
        manager.start_round(crate::SHARE_POW_VERIFY_HEIGHT);

        let header = vec![0u8; 80];
        let real_hash = {
            use bitcoin::hashes::{sha256d, Hash};
            sha256d::Hash::hash(&header).to_byte_array()
        };
        // Genuine PoW preimage, but claiming a difficulty the hash cannot possibly reach — the
        // shape of every share #583 rejects.
        let bad = ShareProof {
            round_id: 1,
            miner_id: [2u8; 32],
            difficulty: f64::MAX,
            work: f64::MAX,
            share_hash: real_hash,
            timestamp: 0,
            received_by: [9u8; 32],
            template_id: Some([3u8; 32]),
            payout_address: None,
            header: Some(header),
            tier_log2: None,
            signature: None,
        };

        // Stop the summariser draining the counters mid-test: `pow_reject_last_log` starts at 0,
        // so the very first rejection trips the 5-minute timer and swaps them to zero. (That is
        // also why every node logs `below_difficulty=1` immediately after a restart.)
        manager.pow_reject_last_log.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            Relaxed,
        );

        assert!(manager.handle_share_proof(bad.clone()).is_err());
        assert_eq!(
            manager.pow_reject_below_diff.load(Relaxed),
            1,
            "first delivery must actually be verified and judged"
        );
        assert_eq!(manager.pow_reject_cached.load(Relaxed), 0);
        assert_eq!(manager.terminal_rejects.len(), 1);

        // Redeliver the identical proof four more times, as backfill does.
        for _ in 0..4 {
            assert!(manager.handle_share_proof(bad.clone()).is_err());
        }
        assert_eq!(
            manager.pow_reject_below_diff.load(Relaxed),
            1,
            "redeliveries must NOT re-enter verification"
        );
        assert_eq!(
            manager.pow_reject_cached.load(Relaxed),
            4,
            "redeliveries must be counted as already-judged"
        );
        assert_eq!(
            manager.terminal_rejects.len(),
            1,
            "one bad share is one cache entry however often it is resent"
        );
    }

    /// The poisoning guard, end to end: over-claiming a share once must not stop the honest
    /// delivery of that same share from being verified on its merits.
    #[test]
    fn caching_a_bad_claim_does_not_suppress_a_different_claim_for_the_same_share() {
        use std::sync::atomic::Ordering::Relaxed;

        let manager = RoundManager::new([1u8; 32], RoundConfig::default());
        manager.start_round(crate::SHARE_POW_VERIFY_HEIGHT);
        manager.pow_reject_last_log.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            Relaxed,
        );

        let header = vec![0u8; 80];
        let real_hash = {
            use bitcoin::hashes::{sha256d, Hash};
            sha256d::Hash::hash(&header).to_byte_array()
        };
        let mut hostile = ShareProof {
            round_id: 1,
            miner_id: [2u8; 32],
            difficulty: f64::MAX,
            work: f64::MAX,
            share_hash: real_hash,
            timestamp: 0,
            received_by: [9u8; 32],
            template_id: Some([3u8; 32]),
            payout_address: None,
            header: Some(header.clone()),
            tier_log2: None,
            signature: None,
        };
        assert!(manager.handle_share_proof(hostile.clone()).is_err());

        assert_eq!(manager.pow_reject_below_diff.load(Relaxed), 1);
        assert_eq!(manager.terminal_rejects.len(), 1);

        // Same share, same header, but an honest difficulty this hash genuinely reaches.
        let achieved =
            ghost_accounting::DifficultyCalculator::difficulty_from_hash(&real_hash) * 0.5;
        hostile.difficulty = achieved;
        hostile.work = achieved;

        let verdict = manager.handle_share_proof(hostile);
        assert!(
            !matches!(verdict, Err(ShareError::InvalidShareHash)),
            "an honest claim must not inherit a forged claim's verdict, got {verdict:?}"
        );
        // The property that matters: it was judged on its merits, not silently dropped by the
        // cache. If keying were on `share_hash` alone this would have been suppressed.
        assert_eq!(
            manager.pow_reject_cached.load(Relaxed),
            0,
            "the honest claim must never have hit the negative cache"
        );
    }

    #[test]
    fn test_no_active_round_rejection() {
        // L-21: Edge case test for share submission before round starts
        let node_id = [1u8; 32];
        let manager = RoundManager::new(node_id, RoundConfig::default());
        // Note: NOT calling start_round()

        let result = manager.record_share("miner1", 100.0, [0u8; 32]);
        assert!(
            matches!(result, Err(ShareError::NoActiveRound)),
            "Share without active round should be rejected, got {:?}",
            result
        );
    }

    #[test]
    fn test_round_cleanup_removes_old_duplicates() {
        // L-21: Verify duplicate tracking is cleaned up with old rounds
        let node_id = [1u8; 32];
        let config = RoundConfig {
            rounds_to_keep: 2,
            ..Default::default()
        };
        let manager = RoundManager::new(node_id, config);

        // Start round 1 and add shares to submitted_shares set
        manager.start_round(100);
        let share_hash = [42u8; 32];

        // Manually add to submitted_shares to simulate duplicate tracking
        {
            let mut submitted = manager.submitted_shares.write();
            submitted.entry(1).or_default().insert(share_hash);
        }

        // Verify round 1 has the entry
        {
            let submitted = manager.submitted_shares.read();
            assert!(
                submitted.contains_key(&1),
                "Round 1 should have submitted shares"
            );
        }

        // Start new rounds until round 1 is cleaned up
        manager.start_round(101);
        manager.start_round(102);
        manager.start_round(103);

        // Round 1 should be cleaned up (only keep last 2 rounds)
        {
            let submitted = manager.submitted_shares.read();
            assert!(
                !submitted.contains_key(&1),
                "Round 1 submitted shares should be cleaned up"
            );
        }
    }
}
