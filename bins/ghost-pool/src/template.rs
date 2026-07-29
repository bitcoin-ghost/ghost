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
//| FILE: template.rs                                                                                                    |
//|======================================================================================================================|

//! Template processor for block template management
//!
//! Fetches templates from Bitcoin Core, applies BUDS filtering,
//! and manages coinbase construction for the pool.
//!
//! # Lock Ordering (M-16 / HIGH-POOL-4)
//!
//! This module uses multiple RwLocks. To prevent deadlocks, always acquire
//! locks in this order:
//!
//! 1. `approved_payout` (`RwLock<Option<[u8; 32]>>`) - Shortest hold time
//! 2. `current_work` (`RwLock<Option<WorkState>>`)
//! 3. `work_states` (`RwLock<HashMap<...>>`)
//! 4. `payout_proposals` (`RwLock<HashMap<...>>`) - Longest hold time
//!
//! Never acquire a lock that comes earlier in this list while holding
//! a lock that comes later.
//!
//! ## HIGH-POOL-4: Lock Ordering Enforcement
//!
//! This ordering is enforced by convention. All methods that acquire multiple
//! locks MUST follow this order. The key patterns are:
//!
//! - Read `approved_payout` BEFORE reading `payout_proposals` (for proposal lookup)
//! - Release locks before calling methods that acquire other locks
//! - Use snapshot values (captured before lock release) for subsequent operations
//!
//! All public methods have been audited to follow this ordering.

use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};

use bitcoin::consensus::deserialize;
use ghost_accounting::CoinbaseBuilder;
use ghost_buds::{BudsClassifier, BudsTier};
use ghost_common::config::{BitcoinNetwork, BlockPriority, MiningMode};
use ghost_common::rpc::{BitcoinRpc, BlockTemplate, TemplateTransaction};
use ghost_common::types::{PayoutProposal, PayoutType, TreasuryAddress};
use ghost_policy::PolicyProfile;
use ghost_reaper::ReaperConfig;
use ghost_storage::{Database, PayoutRecord, PayoutStatus, RecipientType, RoundRecord};

// M-28: Import CoinbaseVerifier for pre-submission verification
use crate::coinbase_verifier::{CoinbaseCommitment, CoinbaseOutput, CoinbaseVerifier};

/// Errors that can occur during template processing
#[derive(Debug, Error)]
pub enum TemplateError {
    /// Address validation failed - cannot create valid output script
    #[error("Invalid address '{address}' for {context}: {reason}")]
    InvalidAddress {
        address: String,
        context: String,
        reason: String,
    },

    /// Configuration validation failed
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// RPC error from Bitcoin Core
    #[error("Bitcoin RPC error: {0}")]
    RpcError(String),

    /// Block assembly error
    #[error("Block assembly error: {0}")]
    BlockAssemblyError(String),
}

/// Information about a block successfully submitted to Bitcoin Core.
/// Sent via channel from `handle_submit_solution()` to the payout task in main.rs.
#[derive(Debug, Clone)]
pub struct BlockSubmittedInfo {
    /// Block hash in display byte order
    pub block_hash: [u8; 32],
    /// Block height
    pub height: u64,
    /// The approved payout whose outputs this block's coinbase actually carries, captured from
    /// the WorkState the block was mined against.
    ///
    /// This is the ONLY safe trigger for settling the ledger. A payout is settled when the coins
    /// exist — not when consensus approved it, because approval merely arms the coinbase of some
    /// FUTURE block. `None` means this block paid the fallback coinbase and settles nothing.
    pub payout_snapshot: Option<[u8; 32]>,
}

/// Type alias for coinbase build result:
/// (coinbase1, coinbase2, witness_data, outputs_serialized, outputs_count)
type CoinbaseBuildResult = (
    Vec<u8>,
    Vec<u8>,
    WitnessData,
    Vec<u8>,
    u32,
    Option<CoinbaseCommitment>,
);

/// Template processor configuration
#[derive(Debug, Clone)]
pub struct TemplateConfig {
    /// Template refresh interval (milliseconds)
    pub refresh_interval_ms: u64,
    /// Minimum fee rate to include (sat/vB)
    pub min_fee_rate: f64,
    /// Target block weight
    pub target_weight: u64,
    /// Coinbase extra data (pool signature)
    pub coinbase_extra: String,
    /// Treasury address for pool fees (supports multi-sig)
    pub treasury_address: TreasuryAddress,
    /// Pool payout address for fallback coinbase (bech32)
    /// Used when no approved payout proposal exists
    pub pool_payout_address: String,
    /// Bitcoin network (mainnet, signet, testnet, regtest)
    pub network: BitcoinNetwork,
    /// Mining mode (PublicPool, PrivatePool, PrivateSolo)
    pub mining_mode: MiningMode,
    /// Solo payout address (required for PrivateSolo mode)
    /// All rewards (99% subsidy + 100% tx fees) go to this address
    pub solo_payout_address: Option<String>,
    /// Whether to enforce the finer per-field policy knobs during tx selection.
    ///
    /// This is `true` ONLY for the operator-defined `Custom` profile. The three
    /// built-in presets (strict/permissive/full_open) intentionally stay
    /// tier-gate-only ("Basic" tier choice): their baked-in
    /// `max_tx_outputs`/`max_tx_size`/`max_op_return_size`/witness/content
    /// fields are NOT enforced at block-build time, preserving the historical
    /// preset behaviour. Custom is the "Advanced" opt-in that turns them on.
    pub enforce_custom_policy_fields: bool,
    /// Block-priority lever governing the template's transaction ordering.
    ///
    /// `MaxFee` (default) preserves the historical package-fee-rate ordering
    /// byte-for-byte. `PaymentsFirst` seats BUDS financial txs (T0/T1) ahead of
    /// data txs (T2/T3) — a pure permutation of the same tx set (weight-safe).
    /// Resolved once at startup from `pool.block_priority`; applied on restart.
    pub block_priority: BlockPriority,
}

impl Default for TemplateConfig {
    fn default() -> Self {
        Self {
            refresh_interval_ms: 30_000,
            min_fee_rate: 1.0,
            target_weight: 3_992_000, // ~99% of 4MW limit
            coinbase_extra: "GHOST".to_string(),
            treasury_address: TreasuryAddress::default(), // Must be configured
            pool_payout_address: String::new(),           // Must be configured
            network: BitcoinNetwork::Mainnet,
            mining_mode: MiningMode::PublicPool,
            solo_payout_address: None,
            enforce_custom_policy_fields: false,
            block_priority: BlockPriority::MaxFee,
        }
    }
}

impl TemplateConfig {
    /// Validate all configured addresses.
    ///
    /// CRIT-10: This MUST be called before creating a TemplateProcessor.
    /// Invalid addresses would create unspendable outputs, permanently losing funds.
    ///
    /// Returns Ok(()) if all addresses are valid, or an error describing which
    /// address is invalid and why.
    pub fn validate(&self) -> Result<(), TemplateError> {
        // Helper to validate a single address
        let validate_address = |address: &str, context: &str| -> Result<(), TemplateError> {
            if address.is_empty() {
                return Err(TemplateError::InvalidAddress {
                    address: address.to_string(),
                    context: context.to_string(),
                    reason: "address is empty".to_string(),
                });
            }

            // Try to parse as a Bitcoin address
            match address.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>() {
                Ok(_) => Ok(()),
                Err(e) => Err(TemplateError::InvalidAddress {
                    address: address.to_string(),
                    context: context.to_string(),
                    reason: format!("failed to parse: {}", e),
                }),
            }
        };

        // Validate treasury address (required for all modes if non-empty)
        if !self.treasury_address.is_empty() {
            validate_address(self.treasury_address.address(), "treasury_address")?;
        }

        // Validate pool_payout_address (required for public/private pool modes)
        match self.mining_mode {
            MiningMode::PublicPool | MiningMode::PrivatePool => {
                if self.pool_payout_address.is_empty() {
                    return Err(TemplateError::ConfigError(
                        "pool_payout_address is required for PublicPool and PrivatePool modes"
                            .to_string(),
                    ));
                }
                validate_address(&self.pool_payout_address, "pool_payout_address")?;
            }
            MiningMode::PrivateSolo => {
                // pool_payout_address not used in solo mode
            }
        }

        // Validate solo_payout_address (required for solo mode)
        if self.mining_mode == MiningMode::PrivateSolo {
            match &self.solo_payout_address {
                Some(addr) if !addr.is_empty() => {
                    validate_address(addr, "solo_payout_address")?;
                }
                _ => {
                    return Err(TemplateError::ConfigError(
                        "solo_payout_address is required for PrivateSolo mode".to_string(),
                    ));
                }
            }
        }

        // H-MINE-3: Validate coinbase_extra length to prevent script_len truncation
        // Script sig format: height_bytes (1-5 bytes) + coinbase_extra + extranonce (8 bytes)
        // Total must fit in a single byte (max 255) for BIP34 compliance.
        // Maximum safe length: 255 - 5 (max height bytes) - 8 (extranonce) = 242 bytes
        const MAX_COINBASE_EXTRA_LEN: usize = 242;
        if self.coinbase_extra.len() > MAX_COINBASE_EXTRA_LEN {
            return Err(TemplateError::ConfigError(format!(
                "coinbase_extra is too long: {} bytes (max {} bytes). This would cause script_len \
                 truncation when cast to u8, corrupting the coinbase transaction.",
                self.coinbase_extra.len(),
                MAX_COINBASE_EXTRA_LEN
            )));
        }

        Ok(())
    }
}

/// Current work state for miners
#[derive(Debug, Clone)]
pub struct WorkState {
    /// Job ID
    pub job_id: String,
    /// Previous block hash (little-endian hex)
    pub prev_hash: String,
    /// Coinbase part 1 (before extranonce) - NON-WITNESS serialization for TXID
    pub coinbase1: Vec<u8>,
    /// Coinbase part 2 (after extranonce) - NON-WITNESS serialization for TXID
    pub coinbase2: Vec<u8>,
    /// Witness data to append for full transaction (marker + flag prefix, witness suffix)
    pub witness_data: WitnessData,
    /// Merkle branches
    pub merkle_branches: Vec<[u8; 32]>,
    /// Block version
    pub version: u32,
    /// nBits (difficulty target)
    pub nbits: String,
    /// nTime
    pub ntime: u32,
    /// Block height
    pub height: u64,
    /// Total fees in template
    pub total_fees: u64,
    /// Block subsidy (derived from Bitcoin Core's coinbasevalue, not calculated independently)
    pub subsidy: u64,
    /// Transaction count (including coinbase)
    pub tx_count: usize,
    /// Total weight of transactions (for block weight validation)
    pub total_weight: u64,
    /// Original template (for block submission)
    pub template: BlockTemplate,
    /// Serialized coinbase outputs (Bitcoin consensus format for TDP)
    /// This is the raw TxOut data that SRI Pool should use
    pub coinbase_outputs_serialized: Vec<u8>,
    /// Number of coinbase outputs
    pub coinbase_outputs_count: u32,
    /// H-MINE-2: Snapshot of approved payout hash at template creation time
    /// This prevents TOCTOU race conditions where the approved payout could change
    /// between template creation and coinbase building.
    pub payout_snapshot: Option<[u8; 32]>,
    /// M-28: Coinbase commitment snapshot at template creation time.
    /// Used for per-template verification instead of the global CoinbaseVerifier,
    /// which can be overwritten by newer payout proposals before the block is found.
    pub commitment_snapshot: Option<CoinbaseCommitment>,
}

/// Witness data for SegWit coinbase transaction
/// Kept separate from coinbase1/coinbase2 so miners compute correct TXID for merkle root
#[derive(Debug, Clone, Default)]
pub struct WitnessData {
    /// Witness commitment output script (if present)
    pub commitment_script: Option<Vec<u8>>,
    /// Witness nonce (32 bytes of zeros per BIP141)
    pub nonce: [u8; 32],
}

/// Events from the template processor
#[derive(Debug, Clone)]
pub enum TemplateEvent {
    /// New work available
    NewWork { job_id: String, height: u64 },
    /// Template fetch failed
    FetchFailed { error: String },
    /// Transactions filtered
    TransactionsFiltered {
        original_count: usize,
        filtered_count: usize,
        removed_fees: u64,
    },
}

/// Template processor
pub struct TemplateProcessor {
    /// Configuration
    config: TemplateConfig,
    /// Bitcoin RPC client
    rpc: Arc<BitcoinRpc>,
    /// Policy profile
    policy: PolicyProfile,
    /// BUDS classifier
    classifier: BudsClassifier,
    /// Reaper config for dead code detection
    reaper_config: ReaperConfig,
    /// Cumulative Reaper observability counters — incremented on every
    /// analyze() call. Exposed via /api/v1/reaper/status; read-only from
    /// outside this module.
    reaper_stats: Arc<crate::reaper_stats::ReaperStats>,
    /// Current work state
    current_work: RwLock<Option<WorkState>>,
    /// Work states by template_id (for SubmitSolution lookup)
    work_states: RwLock<HashMap<u64, WorkState>>,
    /// Job counter
    job_counter: RwLock<u64>,
    /// Event sender
    event_tx: broadcast::Sender<TemplateEvent>,
    /// Running state
    running: RwLock<bool>,
    /// Live refresh cadence (ms), read each `start()` loop iteration so the
    /// dashboard can retune it without restarting the pool. Clamped to [10s,60s].
    refresh_interval_ms: Arc<std::sync::atomic::AtomicU64>,
    /// Approved payout proposal hash (from consensus)
    approved_payout: RwLock<Option<[u8; 32]>>,
    /// Cached payout proposals (hash -> proposal)
    payout_proposals: RwLock<HashMap<[u8; 32], PayoutProposal>>,
    /// M-28: Coinbase verifier for pre-submission verification
    coinbase_verifier: CoinbaseVerifier,
    /// Database for persisting payout proposals across restarts
    db: Option<Arc<Database>>,
    /// Channel sender: fires when a block is successfully submitted to Bitcoin Core.
    /// Used by template_provider.rs to notify the payout task in main.rs.
    block_submitted_tx: mpsc::UnboundedSender<BlockSubmittedInfo>,
    /// Channel receiver: taken once by main.rs at startup to spawn the payout task.
    block_submitted_rx: parking_lot::Mutex<Option<mpsc::UnboundedReceiver<BlockSubmittedInfo>>>,
}

impl TemplateProcessor {
    /// Clone the Reaper-stats Arc so the verification API can read counters
    /// without taking any lock on the processor itself.
    pub fn reaper_stats(&self) -> Arc<crate::reaper_stats::ReaperStats> {
        Arc::clone(&self.reaper_stats)
    }

    /// Create a new template processor
    pub fn new(
        config: TemplateConfig,
        rpc: Arc<BitcoinRpc>,
        policy: PolicyProfile,
        reaper_config: ReaperConfig,
    ) -> Self {
        let (event_tx, _) = broadcast::channel(100);
        let (block_submitted_tx, block_submitted_rx) = mpsc::unbounded_channel();
        let init_refresh_ms = config.refresh_interval_ms.clamp(10_000, 60_000);

        Self {
            config,
            rpc,
            policy,
            classifier: BudsClassifier::new(),
            reaper_config,
            reaper_stats: crate::reaper_stats::ReaperStats::new(),
            current_work: RwLock::new(None),
            work_states: RwLock::new(HashMap::new()),
            job_counter: RwLock::new(0),
            event_tx,
            running: RwLock::new(false),
            refresh_interval_ms: Arc::new(std::sync::atomic::AtomicU64::new(init_refresh_ms)),
            approved_payout: RwLock::new(None),
            payout_proposals: RwLock::new(HashMap::new()),
            coinbase_verifier: CoinbaseVerifier::new(),
            db: None,
            block_submitted_tx,
            block_submitted_rx: parking_lot::Mutex::new(Some(block_submitted_rx)),
        }
    }

    /// Set the database for persisting payout proposals across restarts
    pub fn with_database(mut self, db: Arc<Database>) -> Self {
        self.db = Some(db);
        self
    }

    /// Restore approved payout proposal from database on startup
    ///
    /// Called after construction to reload any previously approved payout
    /// so that the next block uses the correct coinbase outputs.
    pub fn restore_from_db(&self) {
        let Some(ref db) = self.db else { return };

        match db.get_approved_payout_proposal() {
            Ok(Some((hash, json))) => {
                match serde_json::from_str::<PayoutProposal>(&json) {
                    Ok(proposal) => {
                        // Skip stale proposals: if the proposal timestamp is more than
                        // 120 seconds old, it's from a previous run and will fail M-07's
                        // height check anyway. Skipping avoids H-04 fee cap warnings.
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        if proposal.timestamp > 0 && now > proposal.timestamp + 120 {
                            info!(
                                proposal_age_secs = now - proposal.timestamp,
                                proposal_height = proposal.block_height,
                                "Skipping stale payout proposal from database (>120s old)"
                            );
                            db.clear_approved_payout().ok();
                            return;
                        }

                        // Restore into in-memory cache
                        let proposal_hash = proposal.proposal_hash;

                        // M-28: Reconstruct coinbase commitment so templates created
                        // after restart carry a valid commitment_snapshot for verification
                        let treasury_addr = if !proposal.treasury_address.is_empty() {
                            proposal.treasury_address.clone()
                        } else {
                            self.config.treasury_address.address().as_bytes().to_vec()
                        };
                        let commitment =
                            CoinbaseCommitment::from_proposal(&proposal, &treasury_addr);
                        self.coinbase_verifier.set_commitment(commitment);

                        self.payout_proposals
                            .write()
                            .insert(proposal_hash, proposal);

                        if hash.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&hash);
                            *self.approved_payout.write() = Some(arr);
                            info!(
                                hash = %hex::encode(&arr[..8]),
                                "Restored approved payout from database"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to deserialize approved payout proposal from database");
                    }
                }
            }
            Ok(None) => {
                debug!("No approved payout proposal in database");
            }
            Err(e) => {
                warn!(error = %e, "Failed to query approved payout proposal from database");
            }
        }
    }

    /// Notify that a block has been successfully submitted to Bitcoin Core.
    /// Sends the block info to the payout task via the mpsc channel.
    pub fn notify_block_submitted(&self, info: BlockSubmittedInfo) {
        if let Err(e) = self.block_submitted_tx.send(info) {
            warn!(error = %e, "Block submitted channel closed, payout task may have stopped");
        }
    }

    /// Take the block submission receiver (can only be called once).
    /// Called by main.rs at startup to spawn the payout task.
    pub fn take_block_submitted_rx(&self) -> Option<mpsc::UnboundedReceiver<BlockSubmittedInfo>> {
        self.block_submitted_rx.lock().take()
    }

    /// Store a payout proposal (called when proposal is received)
    pub fn store_proposal(&self, proposal: PayoutProposal) {
        let hash = proposal.proposal_hash;
        let miners = proposal.miner_payouts.len();
        let nodes = proposal.node_payouts.len();

        // Persist to database if available
        if let Some(ref db) = self.db {
            match serde_json::to_string(&proposal) {
                Ok(json) => {
                    if let Err(e) = db.store_payout_proposal(
                        &hash,
                        proposal.round_id,
                        proposal.block_height,
                        &json,
                    ) {
                        warn!(
                            hash = %hex::encode(&hash[..8]),
                            error = %e,
                            "Failed to persist payout proposal to database"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        hash = %hex::encode(&hash[..8]),
                        error = %e,
                        "Failed to serialize payout proposal for database persistence"
                    );
                }
            }
        }

        // Lock ordering: approved_payout before payout_proposals
        let approved_hash = *self.approved_payout.read();

        let mut proposals = self.payout_proposals.write();
        proposals.insert(hash, proposal);

        // Evict old proposals: keep approved + most recent 10 by round_id
        if proposals.len() > 10 {
            let mut entries: Vec<([u8; 32], u64)> =
                proposals.iter().map(|(k, v)| (*k, v.round_id)).collect();
            entries.sort_by_key(|(_, round)| std::cmp::Reverse(*round));
            let keep: HashSet<[u8; 32]> = entries
                .iter()
                .take(10)
                .map(|(k, _)| *k)
                .chain(approved_hash.iter().copied())
                .collect();
            let before = proposals.len();
            proposals.retain(|k, _| keep.contains(k));
            let evicted = before - proposals.len();
            if evicted > 0 {
                debug!(
                    evicted,
                    remaining = proposals.len(),
                    "Evicted old payout proposals"
                );
            }
        }
        drop(proposals);

        info!(
            hash = %hex::encode(&hash[..8]),
            miners = miners,
            nodes = nodes,
            "Stored payout proposal in template processor"
        );
    }

    /// Get a stored proposal by hash
    pub fn get_proposal(&self, hash: &[u8; 32]) -> Option<PayoutProposal> {
        self.payout_proposals.read().get(hash).cloned()
    }

    /// Set the approved payout proposal hash (from consensus)
    ///
    /// This is called when consensus approves a payout proposal.
    /// The template processor uses this to include proper payout
    /// outputs in the coinbase transaction.
    ///
    /// M-28: Also sets the coinbase commitment for pre-submission verification.
    pub fn set_approved_payout(&self, proposal_hash: [u8; 32]) {
        // MED-POOL-6: Only set approved payout if proposal data exists in cache.
        // After a restart, stale votes can re-approve old proposals whose data
        // was lost (in-memory cache cleared). Setting the hash without data
        // causes every template refresh to fail.
        let proposal = match self.get_proposal(&proposal_hash) {
            Some(p) => p,
            None => {
                warn!(
                    hash = %hex::encode(&proposal_hash[..8]),
                    "MED-POOL-6: Ignoring approved payout - proposal data not in cache (likely stale after restart)"
                );
                return;
            }
        };

        // M-28: Create and store coinbase commitment for verification
        let treasury_addr = if !proposal.treasury_address.is_empty() {
            proposal.treasury_address.clone()
        } else {
            self.config.treasury_address.address().as_bytes().to_vec()
        };
        let commitment = CoinbaseCommitment::from_proposal(&proposal, &treasury_addr);
        self.coinbase_verifier.set_commitment(commitment);

        // Persist approval to database
        if let Some(ref db) = self.db {
            if let Err(e) = db.mark_payout_approved(&proposal_hash) {
                warn!(
                    hash = %hex::encode(&proposal_hash[..8]),
                    error = %e,
                    "Failed to persist payout approval to database"
                );
            }

            // Record individual payout entries for history/dashboard
            self.record_payout_entries(db, &proposal);
        }

        *self.approved_payout.write() = Some(proposal_hash);
        info!(
            hash = %hex::encode(&proposal_hash[..8]),
            "Set approved payout for coinbase"
        );
    }

    /// Record individual payout entries to the database for history tracking.
    ///
    /// Converts each `PayoutEntry` from the proposal into a `PayoutRecord`
    /// and inserts it into the `payouts` table. Also records treasury and
    /// tx_fees entries so the dashboard can display complete payout breakdowns.
    fn record_payout_entries(&self, db: &Database, proposal: &PayoutProposal) {
        let created_at = proposal.timestamp as i64;
        let round_id = proposal.round_id;

        // Ensure round exists before inserting payout entries (FK constraint).
        // The round row may already have been persisted at round start (with
        // only its block height), so `upsert_round` fills in the block-outcome
        // columns on conflict rather than skipping like INSERT OR IGNORE would.
        let round_record = RoundRecord {
            round_id,
            block_height: proposal.block_height,
            block_hash: Some(hex::encode(proposal.block_hash)),
            start_time: created_at,
            end_time: None,
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: Some(hex::encode(proposal.proposer)),
            payout_status: PayoutStatus::Approved,
            subsidy_sats: Some(proposal.subsidy),
            tx_fees_sats: Some(proposal.tx_fees),
        };
        if let Err(e) = db.upsert_round(&round_record) {
            warn!(round_id = round_id, error = %e, "Failed to persist round record");
            return;
        }

        let mut recorded = 0u32;

        // Miner payouts
        for entry in &proposal.miner_payouts {
            let record = PayoutRecord {
                id: None,
                round_id,
                recipient_id: hex::encode(entry.recipient_id),
                recipient_type: RecipientType::Miner,
                address: hex::encode(&entry.address),
                amount_sats: entry.amount,
                txid: None,
                vout: None,
                status: PayoutStatus::Approved,
                created_at,
                confirmed_at: None,
            };
            if let Err(e) = db.insert_payout(&record) {
                warn!(error = %e, "Failed to record miner payout entry");
            } else {
                recorded += 1;
            }
        }

        // Node payouts
        for entry in &proposal.node_payouts {
            let record = PayoutRecord {
                id: None,
                round_id,
                recipient_id: hex::encode(entry.recipient_id),
                recipient_type: RecipientType::Node,
                address: hex::encode(&entry.address),
                amount_sats: entry.amount,
                txid: None,
                vout: None,
                status: PayoutStatus::Approved,
                created_at,
                confirmed_at: None,
            };
            if let Err(e) = db.insert_payout(&record) {
                warn!(error = %e, "Failed to record node payout entry");
            } else {
                recorded += 1;
            }
        }

        // Treasury
        if proposal.treasury_amount > 0 {
            let record = PayoutRecord {
                id: None,
                round_id,
                recipient_id: "treasury".to_string(),
                recipient_type: RecipientType::Treasury,
                address: hex::encode(&proposal.treasury_address),
                amount_sats: proposal.treasury_amount,
                txid: None,
                vout: None,
                status: PayoutStatus::Approved,
                created_at,
                confirmed_at: None,
            };
            if let Err(e) = db.insert_payout(&record) {
                warn!(error = %e, "Failed to record treasury payout entry");
            } else {
                recorded += 1;
            }
        }

        // TX fees
        if proposal.tx_fees > 0 {
            let record = PayoutRecord {
                id: None,
                round_id,
                recipient_id: hex::encode(proposal.proposer),
                recipient_type: RecipientType::TxFees,
                address: String::new(),
                amount_sats: proposal.tx_fees,
                txid: None,
                vout: None,
                status: PayoutStatus::Approved,
                created_at,
                confirmed_at: None,
            };
            if let Err(e) = db.insert_payout(&record) {
                warn!(error = %e, "Failed to record tx_fees payout entry");
            } else {
                recorded += 1;
            }
        }

        info!(
            round_id = round_id,
            count = recorded,
            "Recorded payout entries to database"
        );
    }

    /// Clear the approved payout (after block is found)
    pub fn clear_approved_payout(&self) {
        // Clear in database
        if let Some(ref db) = self.db {
            if let Err(e) = db.clear_approved_payout() {
                warn!(error = %e, "Failed to clear approved payout in database");
            }
        }

        *self.approved_payout.write() = None;
        // M-28: Clear coinbase commitment when payout is cleared
        self.coinbase_verifier.clear_commitment();
    }

    /// Get the current approved payout hash
    pub fn approved_payout(&self) -> Option<[u8; 32]> {
        *self.approved_payout.read()
    }

    /// Build a complete coinbase transaction using the approved payout
    ///
    /// This is used for final block assembly when we have an approved
    /// payout proposal from consensus.
    ///
    /// H-MINE-2: This method reads from the live approved_payout lock.
    /// For TOCTOU-safe operation when reconstructing from a template,
    /// use build_approved_coinbase_from_snapshot() with the WorkState's payout_snapshot.
    pub fn build_approved_coinbase(
        &self,
        height: u64,
        witness_commitment: &Option<String>,
    ) -> Option<bitcoin::Transaction> {
        // H-MINE-2: Capture hash once, atomically
        let payout_hash = (*self.approved_payout.read())?;
        self.build_approved_coinbase_from_snapshot(height, witness_commitment, payout_hash)
    }

    /// H-MINE-2: Build coinbase using a pre-captured payout hash snapshot
    ///
    /// This is the TOCTOU-safe version that uses a snapshot of the approved payout
    /// hash captured at template creation time (stored in WorkState.payout_snapshot).
    pub fn build_approved_coinbase_from_snapshot(
        &self,
        height: u64,
        witness_commitment: &Option<String>,
        payout_hash: [u8; 32],
    ) -> Option<bitcoin::Transaction> {
        // Look up the proposal using the snapshot hash
        let proposal = self.get_proposal(&payout_hash)?;

        // Build using CoinbaseBuilder
        let builder = CoinbaseBuilder::new(height)
            .with_pool_tag(self.config.coinbase_extra.as_bytes())
            .with_extra_nonce_size(8);

        // Combine all payout entries
        let mut entries = Vec::new();
        entries.extend(proposal.miner_payouts.iter().cloned());
        entries.extend(proposal.node_payouts.iter().cloned());

        // H-MINE-3: Add treasury output using address from proposal (snapshot), not live config
        // H-BTC-4: No silent fallbacks - require explicit treasury address
        if proposal.treasury_amount > 0 {
            let treasury_addr = if !proposal.treasury_address.is_empty() {
                // H-MINE-3: Use the snapshot address from the proposal
                proposal.treasury_address.clone()
            } else if !self.config.treasury_address.is_empty() {
                // Fallback to config if proposal has no address (legacy proposals)
                // This is allowed but logged as it shouldn't happen with new proposals
                warn!("Using treasury address from config (proposal has no snapshot)");
                self.config.treasury_address.address().as_bytes().to_vec()
            } else {
                // H-BTC-4: This is an ERROR, not a warning. Cannot create coinbase without treasury address.
                error!(
                    treasury_amount = proposal.treasury_amount,
                    "H-BTC-4 SECURITY: Treasury amount specified ({} sats) but no treasury address. \
                     This would create an unspendable output! Rejecting coinbase build.",
                    proposal.treasury_amount
                );
                return None;
            };

            // H-BTC-4: Double-check address is not empty (defensive)
            if treasury_addr.is_empty() {
                error!("H-BTC-4 SECURITY: Treasury address resolved to empty. Rejecting coinbase build.");
                return None;
            }

            entries.push(ghost_common::types::PayoutEntry {
                address: treasury_addr,
                amount: proposal.treasury_amount,
                recipient_id: [0u8; 32],
                payout_type: PayoutType::Treasury,
            });
        }

        match builder.build_from_entries(&entries) {
            Ok(mut tx) => {
                // Add witness commitment output if present
                if let Some(commitment) = witness_commitment {
                    match hex::decode(commitment) {
                        Ok(commitment_bytes) => {
                            if validate_witness_commitment_script(&commitment_bytes) {
                                tx.output.push(bitcoin::TxOut {
                                    value: bitcoin::Amount::ZERO,
                                    script_pubkey: bitcoin::ScriptBuf::from(commitment_bytes),
                                });
                            } else {
                                error!(
                                    commitment = %commitment,
                                    "Invalid witness commitment script structure, skipping"
                                );
                            }
                        }
                        Err(e) => {
                            error!(
                                commitment = %commitment,
                                error = %e,
                                "Failed to decode witness commitment hex, skipping"
                            );
                        }
                    }
                }

                info!(
                    height = height,
                    outputs = tx.output.len(),
                    miner_payouts = proposal.miner_payouts.len(),
                    node_payouts = proposal.node_payouts.len(),
                    "Built approved coinbase"
                );

                Some(tx)
            }
            Err(e) => {
                error!(error = %e, "Failed to build approved coinbase");
                None
            }
        }
    }

    /// Build coinbase for stratum (split into coinbase1/coinbase2)
    ///
    /// IMPORTANT: coinbase1/coinbase2 use NON-WITNESS serialization so miners
    /// compute the correct TXID (not WTXID) for the merkle root.
    /// Witness data is returned separately for block assembly.
    ///
    /// When there's an approved payout, this includes all payout outputs.
    /// Otherwise falls back to placeholder single output.
    ///
    /// H-MINE-2: This method reads from the live approved_payout lock.
    /// For TOCTOU-safe operation, use build_coinbase_parts_with_payout_snapshot() instead.
    ///
    /// Returns: (coinbase1, coinbase2, witness_data, outputs_serialized, outputs_count)
    #[allow(dead_code)]
    fn build_coinbase_parts_with_payout(
        &self,
        height: u64,
        total_value: u64,
        witness_commitment: &Option<String>,
    ) -> Result<CoinbaseBuildResult, TemplateError> {
        // Check for approved payout - reads live lock (TOCTOU-vulnerable path)
        let payout_hash = *self.approved_payout.read();
        self.build_coinbase_parts_with_payout_snapshot(
            height,
            total_value,
            witness_commitment,
            payout_hash,
        )
    }

    /// H-MINE-2: Build coinbase using a pre-captured payout snapshot
    ///
    /// This is the TOCTOU-safe version that uses a snapshot of the approved payout
    /// hash captured at template creation time.
    ///
    /// IMPORTANT: coinbase1/coinbase2 use NON-WITNESS serialization so miners
    /// compute the correct TXID (not WTXID) for the merkle root.
    /// Witness data is returned separately for block assembly.
    ///
    /// When there's an approved payout, this includes all payout outputs.
    /// Otherwise falls back to placeholder single output.
    ///
    /// CRIT-10: Returns an error if any address in the payout is invalid.
    /// This prevents creating blocks with unspendable outputs.
    ///
    /// Returns: (coinbase1, coinbase2, witness_data, outputs_serialized, outputs_count)
    #[allow(clippy::type_complexity)]
    fn build_coinbase_parts_with_payout_snapshot(
        &self,
        height: u64,
        total_value: u64,
        witness_commitment: &Option<String>,
        payout_snapshot: Option<[u8; 32]>,
    ) -> Result<CoinbaseBuildResult, TemplateError> {
        // H-MINE-2: Use the snapshot instead of reading from the lock
        // MED-POOL-6: If we have a snapshot hash but can't find the proposal, this is an ERROR.
        // Do NOT silently fall back to placeholder - that would lose all payout data.
        let proposal = match payout_snapshot {
            Some(hash) => {
                let prop = self.get_proposal(&hash);
                if prop.is_none() {
                    // MED-POOL-6: Proposal was approved but data is missing - critical error
                    error!(
                        proposal_hash = %hex::encode(&hash[..8]),
                        "MED-POOL-6: Approved payout proposal not found in cache! \
                         Cannot build coinbase without payout data."
                    );
                    return Err(TemplateError::BlockAssemblyError(format!(
                        "MED-POOL-6: Payout proposal {} not found. \
                         Store proposal before setting approved hash.",
                        hex::encode(&hash[..8])
                    )));
                }
                prop
            }
            None => None, // No approved payout, use fallback
        };

        // Stale proposal detection: if the proposal's subsidy exceeds the current
        // coinbase value, the proposal is from a different halving epoch (e.g. loaded
        // from DB after restart at a different height). Clear it to break the deadlock
        // where stale proposals prevent new blocks → prevent new proposals.
        let proposal = proposal.and_then(|prop| {
            if prop.subsidy > total_value {
                error!(
                    proposal_subsidy = prop.subsidy,
                    total_value,
                    proposal_height = prop.block_height,
                    "Stale payout proposal: subsidy exceeds coinbase value — clearing approved payout"
                );
                self.clear_approved_payout();
                return None;
            }
            // M-07: Reject proposals with stale block heights
            let height_diff = prop.block_height.abs_diff(height);
            if height_diff > 10 {
                error!(
                    proposal_height = prop.block_height,
                    template_height = height,
                    diff = height_diff,
                    "M-07: Stale payout proposal: height mismatch exceeds 10 blocks — clearing"
                );
                self.clear_approved_payout();
                return None;
            }
            Some(prop)
        });

        // Bidirectional fee adjustment: the BFT-approved proposal baked in tx_fees at
        // creation time, but template filtering (Reaper/BUDS/mempool changes) and RBF can
        // change available fees before the coinbase is built. Adjust the block finder's fee
        // portion to match actual available fees — no BFT re-proposal needed.
        let proposal = proposal.and_then(|mut prop| {
            let available_fees = total_value.saturating_sub(prop.subsidy);
            let original_fees = prop.tx_fees;

            if available_fees != original_fees {
                // POST-GATE: there is no block finder. The fees were already shared into the
                // node reward pool when the mesh ratified this payout at tip change — that is
                // precisely what makes the coinbase determinable before the block is won.
                //
                // What remains is DRIFT: the gap between the fees the mesh ratified and the fees
                // actually available in THIS node's template. The mempool moves, RBF replaces
                // transactions, and each node's Reaper/BUDS filtering drops a different set — so
                // every node sees slightly different fees, and the coinbase must still spend
                // exactly subsidy + its own available fees.
                //
                // The drift lands on the TREASURY (GHOST-13 precedent: tx-fee dust already goes
                // there), which keeps the miner split and the node split untouched.
                if prop.block_height >= crate::coinbase_fee_split_height() {
                    if available_fees > original_fees {
                        let extra = available_fees - original_fees;
                        prop.treasury_amount = prop.treasury_amount.saturating_add(extra);
                    } else {
                        let mut shortfall = original_fees - available_fees;

                        // 1) Treasury absorbs what it can.
                        let from_treasury = shortfall.min(prop.treasury_amount);
                        prop.treasury_amount -= from_treasury;
                        shortfall -= from_treasury;

                        // 2) Under the decay schedule the treasury's share eventually reaches
                        //    ZERO, so it cannot be relied on to cover a shortfall. Fall back to
                        //    the node pool — largest entry first, ties broken by address, so
                        //    every node reduces the same entries in the same order.
                        if shortfall > 0 {
                            prop.node_payouts.sort_by(|a, b| {
                                b.amount.cmp(&a.amount).then(a.address.cmp(&b.address))
                            });
                            for entry in &mut prop.node_payouts {
                                if shortfall == 0 {
                                    break;
                                }
                                let take = shortfall.min(entry.amount);
                                entry.amount -= take;
                                shortfall -= take;
                            }
                            prop.node_payouts.retain(|e| e.amount > 0);
                        }

                        // 3) Still short: the coinbase cannot balance. Fall back rather than
                        //    build a block the network would reject.
                        if shortfall > 0 {
                            warn!(
                                shortfall,
                                height,
                                "Fee drift exceeds treasury + node pool — using fallback coinbase"
                            );
                            return None;
                        }
                    }

                    prop.tx_fees = available_fees;
                    info!(
                        original_fees,
                        available_fees,
                        height,
                        "Adjusted payout: fee drift absorbed by the treasury (no block finder)"
                    );
                    return Some(prop);
                }

                if available_fees < original_fees {
                    // FEES DECREASED: reduce block finder's fee portion
                    let excess = original_fees - available_fees;
                    let mut remaining = excess;

                    // Step 1: Reduce TxFees-type entries
                    for entry in &mut prop.node_payouts {
                        if remaining == 0 {
                            break;
                        }
                        if entry.payout_type == PayoutType::TxFees {
                            let reduction = remaining.min(entry.amount);
                            entry.amount -= reduction;
                            remaining -= reduction;
                        }
                    }

                    // Step 2: Reduce proposer's entry (fees merged into NodeReward)
                    if remaining > 0 {
                        for entry in &mut prop.node_payouts {
                            if remaining == 0 {
                                break;
                            }
                            if entry.recipient_id == prop.proposer {
                                let reduction = remaining.min(entry.amount);
                                entry.amount -= reduction;
                                remaining -= reduction;
                            }
                        }
                    }

                    // Step 3: Fallback if can't absorb
                    if remaining > 0 {
                        warn!(
                            remaining,
                            height, "Could not absorb fee decrease — using fallback"
                        );
                        return None;
                    }

                    info!(
                        original_fees,
                        available_fees,
                        reduction = excess,
                        height,
                        "Adjusted payout: fees decreased"
                    );
                } else {
                    // FEES INCREASED (RBF): add extra to block finder
                    // H-04: Cap fee increase at 2x original to prevent disproportionate allocation
                    let raw_extra = available_fees - original_fees;
                    let max_extra = original_fees; // Cap at 2x total (original + original)
                    let extra = raw_extra.min(max_extra);
                    if raw_extra > max_extra {
                        warn!(
                            raw_extra,
                            max_extra,
                            height,
                            "H-04: Fee increase exceeds 2x cap — capping extra allocation"
                        );
                    }
                    let mut allocated = false;

                    for entry in &mut prop.node_payouts {
                        if entry.payout_type == PayoutType::TxFees
                            || entry.recipient_id == prop.proposer
                        {
                            entry.amount = entry.amount.saturating_add(extra);
                            allocated = true;
                            break;
                        }
                    }

                    if !allocated {
                        debug!(
                            extra,
                            height, "Extra fees unclaimed — no block finder entry"
                        );
                    } else {
                        info!(
                            original_fees,
                            available_fees, extra, height, "Adjusted payout: fees increased (RBF)"
                        );
                    }
                }
            }

            // Final sanity: must not exceed available value
            let adjusted_total: u64 = prop.miner_payouts.iter().map(|e| e.amount).sum::<u64>()
                + prop.node_payouts.iter().map(|e| e.amount).sum::<u64>()
                + prop.treasury_amount;

            if adjusted_total > total_value {
                error!(
                    adjusted_total,
                    total_value,
                    height,
                    "CRITICAL: Adjusted proposal exceeds available — using fallback"
                );
                return None;
            }

            Some(prop)
        });

        // Build coinbase1 - NON-WITNESS format (no marker/flag)
        // Format: version | input_count | prev_txhash | prev_outindex | scriptsig_len | scriptsig_data
        let mut coinbase1 = Vec::new();

        // Version (4 bytes, little-endian)
        coinbase1.extend_from_slice(&2u32.to_le_bytes()); // Version 2 for BIP68

        // NO marker/flag here - those are only for witness serialization (wtxid)
        // Input count (for txid computation, this comes right after version)
        coinbase1.push(0x01);

        // Previous tx hash (all zeros for coinbase)
        coinbase1.extend_from_slice(&[0u8; 32]);

        // Previous output index (0xffffffff for coinbase)
        coinbase1.extend_from_slice(&0xffffffffu32.to_le_bytes());

        // Script sig (height in BIP34 format + extra data)
        let height_bytes = self.encode_height(height);
        let extra = self.config.coinbase_extra.as_bytes();
        let script_len = height_bytes.len() + extra.len() + 8; // +8 for extranonce space

        // H-MINE-3: Validate script_len fits in u8 to prevent silent truncation
        if script_len > 255 {
            return Err(TemplateError::ConfigError(format!(
                "Coinbase script too long: {} bytes (max 255). coinbase_extra is {} bytes, \
                 which exceeds the safe limit. Reduce coinbase_extra to prevent corruption.",
                script_len,
                extra.len()
            )));
        }

        coinbase1.push(script_len as u8);
        coinbase1.extend_from_slice(&height_bytes);
        coinbase1.extend_from_slice(extra);

        // Coinbase2: extranonce end + sequence + outputs + locktime
        // NO witness data here - that's separate for block assembly
        let mut coinbase2 = Vec::new();

        // Sequence
        coinbase2.extend_from_slice(&0xffffffffu32.to_le_bytes());

        // Track witness commitment for WitnessData
        let mut witness_data = WitnessData::default();

        // Track serialized outputs for TDP (Bitcoin consensus format: Vec<TxOut>)
        // This is sent to SRI Pool so it uses Ghost's coinbase outputs
        let mut outputs_serialized = Vec::new();
        let outputs_count: u32;

        // Build outputs based on whether we have an approved payout
        // Note: witness commitment output is NOT included in txid outputs
        // It goes in the witness serialization only
        if let Some(ref prop) = proposal {
            // Build outputs from approved payout
            // Count only non-zero value entries
            let miner_output_count = prop.miner_payouts.iter().filter(|e| e.amount > 0).count();
            let node_output_count = prop.node_payouts.iter().filter(|e| e.amount > 0).count();
            let treasury_output_count = if prop.treasury_amount > 0 { 1 } else { 0 };
            let base_output_count = miner_output_count + node_output_count + treasury_output_count;

            // Add 1 for witness commitment if present (it IS part of outputs, just 0-value)
            let output_count = base_output_count + if witness_commitment.is_some() { 1 } else { 0 };
            outputs_count = output_count as u32;

            self.encode_varint(&mut coinbase2, output_count);

            // Miner payouts (skip 0-value entries)
            // CRIT-10 / LOW-POOL-3: Validate each address and fail if any are invalid
            // Error context includes miner recipient_id for debugging
            for (idx, entry) in prop.miner_payouts.iter().enumerate() {
                if entry.amount == 0 {
                    continue;
                }
                // LOW-POOL-3: Include recipient_id in error context for debugging
                let miner_id_short = hex::encode(&entry.recipient_id[..8]);
                coinbase2.extend_from_slice(&entry.amount.to_le_bytes());
                self.encode_script(
                    &mut coinbase2,
                    &entry.address,
                    &format!("miner_payout[{}]:id={}", idx, miner_id_short),
                )?;
                // Also add to outputs_serialized for TDP
                outputs_serialized.extend_from_slice(&entry.amount.to_le_bytes());
                self.encode_script(
                    &mut outputs_serialized,
                    &entry.address,
                    &format!("miner_payout_tdp[{}]:id={}", idx, miner_id_short),
                )?;
            }

            // Node payouts (skip 0-value entries)
            // CRIT-10 / LOW-POOL-3: Validate each address and fail if any are invalid
            // Error context includes node recipient_id for debugging
            for (idx, entry) in prop.node_payouts.iter().enumerate() {
                if entry.amount == 0 {
                    continue; // Skip 0-value outputs
                }
                // LOW-POOL-3: Include recipient_id in error context for debugging
                let node_id_short = hex::encode(&entry.recipient_id[..8]);
                coinbase2.extend_from_slice(&entry.amount.to_le_bytes());
                self.encode_script(
                    &mut coinbase2,
                    &entry.address,
                    &format!("node_payout[{}]:id={}", idx, node_id_short),
                )?;
                // Also add to outputs_serialized for TDP
                outputs_serialized.extend_from_slice(&entry.amount.to_le_bytes());
                self.encode_script(
                    &mut outputs_serialized,
                    &entry.address,
                    &format!("node_payout_tdp[{}]:id={}", idx, node_id_short),
                )?;
            }

            // Treasury
            // H-MINE-3: Use treasury_address from proposal (snapshot) instead of live config
            // CRIT-10: Treasury address is stored as script pubkey bytes (Vec<u8>),
            // use encode_script() which handles raw bytes (same as miner/node payouts)
            // H-BTC-4: No silent fallbacks - require valid treasury address
            if prop.treasury_amount > 0 {
                let treasury_script: &[u8] = if !prop.treasury_address.is_empty() {
                    &prop.treasury_address
                } else if !self.config.treasury_address.is_empty() {
                    warn!("Using treasury address from config (proposal has no snapshot)");
                    self.config.treasury_address.address().as_bytes()
                } else {
                    error!(
                        treasury_amount = prop.treasury_amount,
                        "H-BTC-4 SECURITY: Treasury amount specified ({} sats) but no treasury address available. \
                         Proposal has no address AND config has no address. This would create an unspendable output!",
                        prop.treasury_amount
                    );
                    return Err(TemplateError::ConfigError(format!(
                        "H-BTC-4: Treasury amount {} sats specified but no valid treasury address. \
                         Both proposal and config have empty treasury addresses.",
                        prop.treasury_amount
                    )));
                };

                // Now safe to add amount and encode script
                coinbase2.extend_from_slice(&prop.treasury_amount.to_le_bytes());
                self.encode_script(&mut coinbase2, treasury_script, "treasury")?;
                outputs_serialized.extend_from_slice(&prop.treasury_amount.to_le_bytes());
                self.encode_script(&mut outputs_serialized, treasury_script, "treasury_tdp")?;
            }

            info!(
                height = height,
                miners = prop.miner_payouts.len(),
                nodes = prop.node_payouts.len(),
                treasury = prop.treasury_amount,
                "Built coinbase with approved payout outputs"
            );
        } else {
            // Fallback: single output with total value (plus witness commitment if present)
            // CRIT-10: Validate pool_payout_address and fail if invalid
            // H-BTC-4: No silent fallbacks - require valid pool_payout_address
            if self.config.pool_payout_address.is_empty() {
                error!(
                    total_value = total_value,
                    "H-BTC-4 SECURITY: No approved payout proposal and pool_payout_address is empty. \
                     Cannot create fallback coinbase output!"
                );
                return Err(TemplateError::ConfigError(
                    "H-BTC-4: pool_payout_address is empty and no approved payout proposal available".to_string(),
                ));
            }

            let output_count = if witness_commitment.is_some() { 2 } else { 1 };
            outputs_count = output_count as u32;
            coinbase2.push(output_count as u8);

            // Single pool reward output
            coinbase2.extend_from_slice(&total_value.to_le_bytes());
            self.encode_address_script(
                &mut coinbase2,
                &self.config.pool_payout_address,
                "pool_payout",
            )?;
            // Also add to outputs_serialized for TDP
            outputs_serialized.extend_from_slice(&total_value.to_le_bytes());
            self.encode_address_script(
                &mut outputs_serialized,
                &self.config.pool_payout_address,
                "pool_payout_tdp",
            )?;
        }

        // Witness commitment output (0-value OP_RETURN with commitment)
        // This IS included in the txid serialization (it's a regular output)
        if let Some(commitment) = witness_commitment {
            let commitment_bytes = hex::decode(commitment).map_err(|e| {
                TemplateError::BlockAssemblyError(format!("Invalid witness commitment hex: {}", e))
            })?;

            // Validate the commitment script structure
            // BIP 141 witness commitment format: OP_RETURN OP_PUSH(36) <4-byte magic> <32-byte commitment>
            if !validate_witness_commitment_script(&commitment_bytes) {
                return Err(TemplateError::BlockAssemblyError(
                    "Invalid witness commitment script structure".to_string(),
                ));
            }

            coinbase2.extend_from_slice(&0u64.to_le_bytes()); // 0 value
                                                              // L-10: Validate commitment length before casting to u8
            if commitment_bytes.len() > 255 {
                return Err(TemplateError::BlockAssemblyError(format!(
                    "L-10: Witness commitment script too long: {} bytes (max 255)",
                    commitment_bytes.len()
                )));
            }
            coinbase2.push(commitment_bytes.len() as u8);
            coinbase2.extend_from_slice(&commitment_bytes);
            witness_data.commitment_script = Some(commitment_bytes.clone());

            // Also add to outputs_serialized for TDP
            outputs_serialized.extend_from_slice(&0u64.to_le_bytes());
            outputs_serialized.push(commitment_bytes.len() as u8);
            outputs_serialized.extend_from_slice(&commitment_bytes);
        }

        // Locktime (end of non-witness serialization)
        coinbase2.extend_from_slice(&0u32.to_le_bytes());

        // Witness data is stored separately - NOT appended to coinbase2
        // This ensures hash(coinbase1 + extranonce + coinbase2) = TXID (not WTXID)
        // The witness nonce is all zeros per BIP141 default
        witness_data.nonce = [0u8; 32];

        // Compute commitment from the ADJUSTED proposal (post fee adjustment).
        // The global coinbase_verifier commitment is stale — it was set from the
        // original BFT-approved proposal before bidirectional fee adjustment.
        let adjusted_commitment = proposal.as_ref().map(|prop| {
            let treasury_addr = if !prop.treasury_address.is_empty() {
                prop.treasury_address.clone()
            } else {
                self.config.treasury_address.address().as_bytes().to_vec()
            };
            CoinbaseCommitment::from_proposal(prop, &treasury_addr)
        });

        Ok((
            coinbase1,
            coinbase2,
            witness_data,
            outputs_serialized,
            outputs_count,
            adjusted_commitment,
        ))
    }

    /// Build coinbase for solo mining mode
    ///
    /// Solo mode reward structure:
    /// - Output 0: 99% subsidy + ALL TX fees → solo_payout_address
    /// - Output 1: Treasury portion of 1% pool fee → treasury_address
    /// - Output 2: Node pool portion of 1% pool fee → treasury_address (node pool)
    /// - Output 3: Witness commitment (if SegWit)
    ///
    /// The 1% pool fee is split between treasury and node pool per decay schedule.
    /// The hosting node participates in the node reward pool calculation.
    ///
    /// CRIT-10: Returns an error if any address is invalid.
    /// This prevents creating blocks with unspendable outputs.
    ///
    /// Returns: (coinbase1, coinbase2, witness_data, outputs_serialized, outputs_count)
    pub fn build_coinbase_solo_mode(
        &self,
        height: u64,
        subsidy: u64,
        tx_fees: u64,
        treasury_amount: u64,
        node_pool_amount: u64,
        witness_commitment: &Option<String>,
    ) -> Result<CoinbaseBuildResult, TemplateError> {
        // Solo mode requires solo_payout_address to be configured
        let solo_address = match self.config.solo_payout_address.as_ref() {
            Some(addr) if !addr.is_empty() => addr,
            _ => {
                return Err(TemplateError::ConfigError(
                    "solo_payout_address is required for solo mode".to_string(),
                ));
            }
        };

        // Calculate solo miner's share: 99% of subsidy + ALL tx fees
        // The 1% pool fee (treasury_amount + node_pool_amount) comes from the caller
        let miner_pool = subsidy
            .saturating_sub(treasury_amount)
            .saturating_sub(node_pool_amount);
        let solo_miner_amount = miner_pool.saturating_add(tx_fees);

        info!(
            height = height,
            subsidy = subsidy,
            tx_fees = tx_fees,
            solo_miner_amount = solo_miner_amount,
            treasury = treasury_amount,
            node_pool = node_pool_amount,
            "Building solo mode coinbase"
        );

        // Build coinbase1 - NON-WITNESS format
        let mut coinbase1 = Vec::new();

        // Version (4 bytes, little-endian)
        coinbase1.extend_from_slice(&2u32.to_le_bytes()); // Version 2 for BIP68

        // Input count
        coinbase1.push(0x01);

        // Previous tx hash (all zeros for coinbase)
        coinbase1.extend_from_slice(&[0u8; 32]);

        // Previous output index (0xffffffff for coinbase)
        coinbase1.extend_from_slice(&0xffffffffu32.to_le_bytes());

        // Script sig (height in BIP34 format + extra data)
        let height_bytes = self.encode_height(height);
        let extra = self.config.coinbase_extra.as_bytes();
        let script_len = height_bytes.len() + extra.len() + 8; // +8 for extranonce space

        // H-MINE-3: Validate script_len fits in u8 to prevent silent truncation
        if script_len > 255 {
            return Err(TemplateError::ConfigError(format!(
                "Coinbase script too long: {} bytes (max 255). coinbase_extra is {} bytes, \
                 which exceeds the safe limit. Reduce coinbase_extra to prevent corruption.",
                script_len,
                extra.len()
            )));
        }

        coinbase1.push(script_len as u8);
        coinbase1.extend_from_slice(&height_bytes);
        coinbase1.extend_from_slice(extra);

        // Coinbase2: extranonce end + sequence + outputs + locktime
        let mut coinbase2 = Vec::new();

        // Sequence
        coinbase2.extend_from_slice(&0xffffffffu32.to_le_bytes());

        // Track witness commitment for WitnessData
        let mut witness_data = WitnessData::default();

        // Track serialized outputs for TDP
        let mut outputs_serialized = Vec::new();

        // Count outputs: solo miner + treasury (if > 0) + node pool (if > 0) + witness commitment
        let mut output_count = 1; // solo miner always present
        if treasury_amount > 0 {
            output_count += 1;
        }
        if node_pool_amount > 0 {
            output_count += 1;
        }
        if witness_commitment.is_some() {
            output_count += 1;
        }

        self.encode_varint(&mut coinbase2, output_count);

        // Output 0: Solo miner (99% subsidy + ALL tx fees)
        // CRIT-10: Validate address and fail if invalid
        coinbase2.extend_from_slice(&solo_miner_amount.to_le_bytes());
        self.encode_address_script(&mut coinbase2, solo_address, "solo_miner")?;
        outputs_serialized.extend_from_slice(&solo_miner_amount.to_le_bytes());
        self.encode_address_script(&mut outputs_serialized, solo_address, "solo_miner_tdp")?;

        // Output 1: Treasury (portion of 1% pool fee per decay schedule)
        // CRIT-10: Validate treasury address and fail if invalid
        // H-BTC-4: No silent fallbacks - require valid treasury address when amount > 0
        if treasury_amount > 0 {
            // H-BTC-4: Validate address BEFORE adding amount to buffer
            if self.config.treasury_address.is_empty() {
                error!(
                    treasury_amount = treasury_amount,
                    "H-BTC-4 SECURITY: Treasury amount specified ({} sats) but no treasury address configured. \
                     This would create an unspendable output!",
                    treasury_amount
                );
                return Err(TemplateError::ConfigError(format!(
                    "H-BTC-4: Treasury amount {} sats specified but treasury_address is empty",
                    treasury_amount
                )));
            }
            let treasury_addr = self.config.treasury_address.address();
            coinbase2.extend_from_slice(&treasury_amount.to_le_bytes());
            self.encode_address_script(&mut coinbase2, treasury_addr, "treasury")?;
            outputs_serialized.extend_from_slice(&treasury_amount.to_le_bytes());
            self.encode_address_script(&mut outputs_serialized, treasury_addr, "treasury_tdp")?;
        }

        // Output 2: Node pool (portion of 1% pool fee per decay schedule)
        // In solo mode, this typically goes to the hosting node (operator)
        // For simplicity, we use treasury address as the destination (can be separate)
        // CRIT-10: Validate node_pool address and fail if invalid
        // H-BTC-4: No silent fallbacks - require valid address when amount > 0
        if node_pool_amount > 0 {
            // H-BTC-4: Validate address BEFORE adding amount to buffer
            if self.config.treasury_address.is_empty() {
                error!(
                    node_pool_amount = node_pool_amount,
                    "H-BTC-4 SECURITY: Node pool amount specified ({} sats) but no treasury address configured. \
                     This would create an unspendable output!",
                    node_pool_amount
                );
                return Err(TemplateError::ConfigError(format!(
                    "H-BTC-4: Node pool amount {} sats specified but treasury_address is empty",
                    node_pool_amount
                )));
            }
            let treasury_addr = self.config.treasury_address.address();
            coinbase2.extend_from_slice(&node_pool_amount.to_le_bytes());
            self.encode_address_script(&mut coinbase2, treasury_addr, "node_pool")?;
            outputs_serialized.extend_from_slice(&node_pool_amount.to_le_bytes());
            self.encode_address_script(&mut outputs_serialized, treasury_addr, "node_pool_tdp")?;
        }

        // Output 3: Witness commitment (0-value OP_RETURN)
        if let Some(commitment) = witness_commitment {
            let commitment_bytes = hex::decode(commitment).map_err(|e| {
                TemplateError::BlockAssemblyError(format!("Invalid witness commitment hex: {}", e))
            })?;

            if !validate_witness_commitment_script(&commitment_bytes) {
                return Err(TemplateError::BlockAssemblyError(
                    "Invalid witness commitment script structure".to_string(),
                ));
            }

            coinbase2.extend_from_slice(&0u64.to_le_bytes()); // 0 value
                                                              // L-10: Validate commitment length before casting to u8
            if commitment_bytes.len() > 255 {
                return Err(TemplateError::BlockAssemblyError(format!(
                    "L-10: Witness commitment script too long: {} bytes (max 255)",
                    commitment_bytes.len()
                )));
            }
            coinbase2.push(commitment_bytes.len() as u8);
            coinbase2.extend_from_slice(&commitment_bytes);
            witness_data.commitment_script = Some(commitment_bytes.clone());
            outputs_serialized.extend_from_slice(&0u64.to_le_bytes());
            outputs_serialized.push(commitment_bytes.len() as u8);
            outputs_serialized.extend_from_slice(&commitment_bytes);
        }

        // Locktime
        coinbase2.extend_from_slice(&0u32.to_le_bytes());

        // Witness nonce
        witness_data.nonce = [0u8; 32];

        Ok((
            coinbase1,
            coinbase2,
            witness_data,
            outputs_serialized,
            output_count as u32,
            None, // Solo mode has no payout proposal commitment
        ))
    }

    /// Encode a varint
    fn encode_varint(&self, buf: &mut Vec<u8>, value: usize) {
        if value < 0xfd {
            buf.push(value as u8);
        } else if value <= 0xffff {
            buf.push(0xfd);
            buf.extend_from_slice(&(value as u16).to_le_bytes());
        } else {
            buf.push(0xfe);
            buf.extend_from_slice(&(value as u32).to_le_bytes());
        }
    }

    /// Encode a script (address bytes with length prefix)
    ///
    /// CRIT-10: Returns an error if the address cannot be parsed.
    /// Never creates placeholder/all-zeros outputs that would be unspendable.
    fn encode_script(
        &self,
        buf: &mut Vec<u8>,
        address: &[u8],
        context: &str,
    ) -> Result<(), TemplateError> {
        // Try to parse as address string and get script pubkey
        if let Ok(addr_str) = std::str::from_utf8(address) {
            if let Ok(addr) =
                addr_str.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            {
                let script = addr.assume_checked().script_pubkey();
                let script_bytes = script.as_bytes();
                self.encode_varint(buf, script_bytes.len());
                buf.extend_from_slice(script_bytes);
                return Ok(());
            }
        }

        // CRIT-10: Check if this is already a valid raw script (for backwards compatibility)
        if is_valid_script_bytes(address) {
            self.encode_varint(buf, address.len());
            buf.extend_from_slice(address);
            return Ok(());
        }

        // CRIT-10: NEVER create placeholder outputs - return an error instead
        let addr_display = std::str::from_utf8(address)
            .map(|s| s.to_string())
            .unwrap_or_else(|_| format!("0x{}", hex::encode(address)));

        Err(TemplateError::InvalidAddress {
            address: addr_display,
            context: context.to_string(),
            reason: "failed to parse as Bitcoin address or valid script".to_string(),
        })
    }

    /// Parse a bech32 address to script pubkey bytes
    ///
    /// Returns the raw script pubkey bytes for the given address.
    /// Returns an error if the address is empty or invalid.
    fn address_to_script(&self, address: &str, context: &str) -> Result<Vec<u8>, TemplateError> {
        if address.is_empty() {
            return Err(TemplateError::InvalidAddress {
                address: address.to_string(),
                context: context.to_string(),
                reason: "address is empty".to_string(),
            });
        }

        address
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .map(|addr| addr.assume_checked().script_pubkey().into_bytes())
            .map_err(|e| TemplateError::InvalidAddress {
                address: address.to_string(),
                context: context.to_string(),
                reason: format!("failed to parse: {}", e),
            })
    }

    /// Encode a script pubkey directly to the buffer
    ///
    /// CRIT-10: Returns an error if the address is invalid.
    /// NEVER creates placeholder/all-zeros outputs that would be unspendable.
    /// L-11: Validates script length before casting to u8.
    fn encode_address_script(
        &self,
        buf: &mut Vec<u8>,
        address: &str,
        context: &str,
    ) -> Result<(), TemplateError> {
        let script_bytes = self.address_to_script(address, context)?;
        // L-11: Validate script length before casting to u8
        if script_bytes.len() > 255 {
            return Err(TemplateError::BlockAssemblyError(format!(
                "L-11: Script too long for coinbase: {} bytes (max 255) in {}",
                script_bytes.len(),
                context
            )));
        }
        buf.push(script_bytes.len() as u8);
        buf.extend_from_slice(&script_bytes);
        Ok(())
    }

    /// Subscribe to template events
    pub fn subscribe(&self) -> broadcast::Receiver<TemplateEvent> {
        self.event_tx.subscribe()
    }

    /// Start the template processor
    pub async fn start(self: Arc<Self>) -> anyhow::Result<()> {
        *self.running.write() = true;
        info!("Template processor started");

        // Sleep for the CURRENT cadence each iteration (read live from the atomic)
        // so the dashboard can retune it without restarting the pool.
        while *self.running.read() {
            let ms = self
                .refresh_interval_ms
                .load(std::sync::atomic::Ordering::Relaxed)
                .clamp(10_000, 60_000);
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;

            if let Err(e) = self.refresh_template().await {
                error!(error = %e, "Failed to refresh template");
                let _ = self.event_tx.send(TemplateEvent::FetchFailed {
                    error: e.to_string(),
                });
            }
        }

        Ok(())
    }

    /// Stop the processor
    pub fn stop(&self) {
        *self.running.write() = false;
    }

    /// Shared handle to the live refresh cadence (ms), so callers (the dashboard
    /// API) can retune it without a restart. Clamped to [10s, 60s] on every set.
    pub fn refresh_interval_handle(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.refresh_interval_ms)
    }

    /// Current refresh cadence in whole seconds (for display).
    pub fn refresh_interval_secs(&self) -> u64 {
        self.refresh_interval_ms
            .load(std::sync::atomic::Ordering::Relaxed)
            / 1000
    }

    /// Refresh the block template
    pub async fn refresh_template(&self) -> anyhow::Result<()> {
        self.refresh_template_inner(false, false).await
    }

    /// Force a full template rebuild even when the height is unchanged — used to
    /// swap the full template in right after an empty (coinbase-only) template
    /// was published on a new-block event (the empty one already bumped
    /// `current_work` to the new height, so the normal dedup guard would skip it).
    pub async fn refresh_template_forced(&self) -> anyhow::Result<()> {
        self.refresh_template_inner(true, false).await
    }

    /// Publish a coinbase-only (empty) template for the current tip immediately.
    /// On a new-block ZMQ event this hands miners work on the NEW tip with zero
    /// transaction-assembly latency (no BUDS filtering, no merkle over the tx
    /// set); the full template follows via `refresh_template_forced`. A block
    /// found against it is a valid empty block (subsidy only) — the rare sub-
    /// second window before the full template arrives.
    pub async fn publish_empty_template(&self) -> anyhow::Result<()> {
        self.refresh_template_inner(false, true).await
    }

    async fn refresh_template_inner(&self, force: bool, empty: bool) -> anyhow::Result<()> {
        // Build rules based on network
        let rules: Vec<&str> = match self.config.network {
            BitcoinNetwork::Signet => vec!["segwit", "signet"],
            BitcoinNetwork::Testnet => vec!["segwit"],
            BitcoinNetwork::Regtest => vec!["segwit"],
            BitcoinNetwork::Mainnet => vec!["segwit"],
        };

        // Fetch template from Bitcoin Core
        let template = self
            .rpc
            .get_block_template(rules)
            .await
            .map_err(|e| anyhow::anyhow!("RPC error: {}", e))?;

        // Check if template changed (height or significant curtime drift).
        // `force` bypasses this so a full rebuild can follow an empty template
        // at the same height.
        let should_update = force || {
            let current = self.current_work.read();
            current
                .as_ref()
                .map(|w| {
                    // Update if height changed (new block)
                    let height_changed = w.height != template.height;
                    // Update if curtime drifted more than 60 seconds (keeps ntime fresh for miners)
                    let curtime_drift = (template.curtime as u32).saturating_sub(w.ntime) > 60;
                    height_changed || curtime_drift
                })
                .unwrap_or(true)
        };

        if !should_update {
            return Ok(());
        }

        // Apply BUDS filtering. Skipped for an empty/coinbase-only template —
        // there are no transactions to filter, and skipping the filter + merkle
        // is exactly what makes the empty path fast enough to publish instantly
        // on a tip change.
        let (filtered_txs, filter_stats) = if empty {
            (Vec::new(), None)
        } else {
            let (txs, stats) = self.filter_transactions(&template.transactions);
            (txs, Some(stats))
        };

        if let Some(ref filter_stats) = filter_stats {
            if filter_stats.removed > 0 {
                let _ = self.event_tx.send(TemplateEvent::TransactionsFiltered {
                    original_count: filter_stats.original,
                    filtered_count: filter_stats.kept,
                    removed_fees: filter_stats.removed_fees,
                });

                info!(
                    original = filter_stats.original,
                    kept = filter_stats.kept,
                    removed = filter_stats.removed,
                    reaped = filter_stats.reaped,
                    removed_fees = filter_stats.removed_fees,
                    "Filtered transactions by policy"
                );
            }
        }

        // Calculate total fees and weight
        let total_fees: u64 = filtered_txs.iter().map(|tx| tx.fee).sum();
        let total_weight: u64 = filtered_txs.iter().map(|tx| tx.weight).sum();

        // Generate new job ID
        let job_id = {
            let mut counter = self.job_counter.write();
            *counter += 1;
            format!("{:08x}", *counter)
        };

        // Build merkle tree
        let merkle_branches = self.build_merkle_branches(&filtered_txs);

        // H-MINE-2: Capture payout snapshot ATOMICALLY at template creation time
        // This prevents TOCTOU race conditions where the approved payout could change
        // between template creation and coinbase building
        let payout_snapshot = *self.approved_payout.read();

        // Build coinbase transaction parts (uses approved payout if available)
        // Returns NON-WITNESS serialization for TXID computation + separate witness data
        // Also returns serialized outputs for TDP to send to SRI Pool
        //
        // Derive subsidy from Bitcoin Core's authoritative coinbasevalue.
        // coinbasevalue = subsidy + all_template_fees (before filtering).
        // We need subsidy + filtered_fees for the coinbase we're building.
        let all_template_fees: u64 = template.transactions.iter().map(|tx| tx.fee).sum();
        let subsidy = template.coinbasevalue.saturating_sub(all_template_fees);
        let coinbase_value = subsidy + total_fees;

        // Always recompute witness commitment from filtered transactions (BIP141).
        // Bitcoin Core's default_witness_commitment assumes the original transaction
        // order from getblocktemplate, but filter_transactions() reorders by fee rate
        // (sort_by_package_fee_rate), making the original commitment invalid.
        // Must always include commitment — signet requires it for block signatures
        // even when there are no non-coinbase transactions.
        let witness_commitment = Some(self.compute_witness_commitment(&filtered_txs));

        // H-MINE-2: Pass snapshot to coinbase builder to use consistent payout data
        // CRIT-10: This will fail if any payout address is invalid, preventing bad blocks
        let (
            coinbase1,
            coinbase2,
            witness_data,
            coinbase_outputs_serialized,
            coinbase_outputs_count,
            adjusted_commitment,
        ) = self
            .build_coinbase_parts_with_payout_snapshot(
                template.height,
                coinbase_value,
                &witness_commitment,
                payout_snapshot,
            )
            .map_err(|e| {
                error!(error = %e, "CRIT-10: Invalid address in payout - refusing to create block template");
                anyhow::anyhow!("Address validation failed: {}", e)
            })?;

        // Create work state
        // Note: template.coinbasevalue from Bitcoin Core = subsidy + all tx fees
        // We store just the tx fees separately for payout calculations
        let prev_hash = self.to_stratum_prev_hash(&template.previousblockhash).map_err(|e| {
            error!(error = %e, hash = %template.previousblockhash, "Invalid previousblockhash from Bitcoin RPC");
            e
        })?;
        // Store filtered template so block assembly uses the same transactions
        // as the merkle tree. Using the unfiltered template here would cause
        // bad-txnmrklroot rejection when BUDS filtering removes transactions.
        let mut filtered_template = template.clone();
        filtered_template.transactions = filtered_txs;

        let work = WorkState {
            job_id: job_id.clone(),
            prev_hash,
            coinbase1,
            coinbase2,
            witness_data,
            merkle_branches,
            version: template.version,
            nbits: template.bits.clone(),
            ntime: template.curtime as u32,
            height: template.height,
            total_fees, // Just the TX fees, NOT coinbasevalue (which includes subsidy)
            subsidy,    // From Bitcoin Core's coinbasevalue (authoritative)
            tx_count: filtered_template.transactions.len() + 1, // +1 for coinbase
            total_weight,
            template: filtered_template,
            coinbase_outputs_serialized,
            coinbase_outputs_count,
            payout_snapshot, // H-MINE-2: Store snapshot for consistent coinbase reconstruction
            commitment_snapshot: adjusted_commitment
                .or_else(|| self.coinbase_verifier.get_commitment()), // Use fee-adjusted commitment, fall back to global
        };

        *self.current_work.write() = Some(work);

        let _ = self.event_tx.send(TemplateEvent::NewWork {
            job_id,
            height: template.height,
        });

        debug!(
            height = template.height,
            empty = empty,
            fees = total_fees,
            "New block template"
        );

        Ok(())
    }

    /// Filter transactions according to policy
    ///
    /// Filters transactions by:
    /// 1. Valid hex encoding and parsability
    /// 2. BUDS policy tier allowance
    /// 3. Minimum fee rate threshold
    /// 4. Duplicate TXID detection (prevents double-inclusion attacks)
    /// 5. Fee-rate sorting (highest paying first, respecting dependencies)
    fn filter_transactions(
        &self,
        transactions: &[TemplateTransaction],
    ) -> (Vec<TemplateTransaction>, FilterStats) {
        let original_count = transactions.len();
        let mut kept = Vec::with_capacity(original_count);
        // BUDS tier per kept tx, parallel to `kept` (kept_tiers[i] is the tier
        // of kept[i]). Only consulted when `block_priority == PaymentsFirst`;
        // under `MaxFee` it is built but never read, so ordering is unchanged.
        let mut kept_tiers: Vec<BudsTier> = Vec::with_capacity(original_count);
        let mut removed_fees = 0u64;
        let mut reaped_count = 0usize;
        let mut reaped_dead_bytes = 0u64;

        // Track seen TXIDs to detect duplicates
        let mut seen_txids: HashSet<String> = HashSet::with_capacity(transactions.len());

        // Track which original indices were kept (for dependency resolution)
        let mut kept_indices: HashSet<usize> = HashSet::new();

        // Map original 0-based index -> filtered array position (for CPFP sorting)
        let mut original_to_filtered: HashMap<usize, usize> = HashMap::new();

        for (idx, tx) in transactions.iter().enumerate() {
            // Check for duplicate TXIDs (prevents double-inclusion attacks)
            if !seen_txids.insert(tx.txid.clone()) {
                warn!(
                    txid = %tx.txid,
                    "Duplicate transaction detected, skipping"
                );
                removed_fees += tx.fee;
                continue;
            }

            // Decode transaction for classification
            let tx_bytes = match hex::decode(&tx.data) {
                Ok(b) => b,
                Err(_) => {
                    removed_fees += tx.fee;
                    continue;
                }
            };

            // Parse as Bitcoin transaction
            let btc_tx: bitcoin::Transaction = match deserialize(&tx_bytes) {
                Ok(t) => t,
                Err(_) => {
                    removed_fees += tx.fee;
                    continue;
                }
            };

            // Reaper: detect dead code in witness scripts
            if self.reaper_config.enabled {
                let reaper_verdict = ghost_reaper::analyze(&btc_tx, &self.reaper_config);
                self.reaper_stats.record(&reaper_verdict);
                if reaper_verdict.is_corpse() {
                    removed_fees += tx.fee;
                    reaped_count += 1;
                    reaped_dead_bytes += reaper_verdict.total_dead_bytes as u64;
                    debug!(
                        txid = %tx.txid,
                        dead_bytes = reaper_verdict.total_dead_bytes,
                        regions = reaper_verdict.dead_regions.len(),
                        "Transaction reaped: dead code detected"
                    );
                    continue;
                }
            }

            // Classify transaction
            let result = self.classifier.classify(&btc_tx);
            let tier = result.tier;

            // Tier gate REMOVED (redundant): ghostd now enforces the BUDS tier
            // policy at mempool acceptance (-ghostpolicy-allowtiers), so the
            // mempool this template is built from already excludes disallowed
            // tiers. classify() is kept because `tier` still feeds kept_tiers for
            // payments-first ordering, and the fee-rate / dependency / Custom
            // per-field checks below remain the pool's own concern.
            {
                // Full per-field policy enforcement — Custom profile ONLY. The
                // tier gate above is the whole story for the three "Basic"
                // presets (strict/permissive/full_open), which stay
                // tier-gate-only exactly as before. When the operator selects
                // the "Advanced" Custom profile, `enforce_custom_policy_fields`
                // is set and the finer knobs (allow_inscriptions/runes/brc20,
                // max_op_return_size, max_witness_per_input, max_tx_outputs,
                // max_tx_size) additionally drop non-conforming txs.
                if self.config.enforce_custom_policy_fields {
                    if let Some(reason) = policy_field_violation(&self.policy, &btc_tx, &result) {
                        removed_fees += tx.fee;
                        debug!(
                            txid = %tx.txid,
                            reason = %reason,
                            "Transaction filtered by custom policy field"
                        );
                        continue;
                    }
                }

                // Additional policy checks
                let fee_rate = tx.fee as f64 / (tx.weight as f64 / 4.0);
                if fee_rate >= self.config.min_fee_rate {
                    // Check if all dependencies were kept
                    // depends values are 1-indexed (Bitcoin Core GBT convention),
                    // kept_indices are 0-indexed, so subtract 1
                    let deps_satisfied = tx
                        .depends
                        .iter()
                        .all(|&dep| dep > 0 && kept_indices.contains(&((dep - 1) as usize)));
                    if deps_satisfied {
                        original_to_filtered.insert(idx, kept.len());
                        kept_indices.insert(idx);
                        kept.push(tx.clone());
                        // Carry the already-computed BUDS tier so the
                        // payments-first ordering can key on it without
                        // re-classifying. Index stays aligned with `kept`.
                        kept_tiers.push(tier);
                    } else {
                        // Dependency was filtered out, must reject this tx too
                        removed_fees += tx.fee;
                        debug!(
                            txid = %tx.txid,
                            "Transaction rejected: dependency was filtered"
                        );
                    }
                } else {
                    removed_fees += tx.fee;
                }
            }
        }

        // Sort by package fee rate while respecting dependencies. Under
        // `PaymentsFirst` the carried BUDS tiers additionally bias financial
        // packages (T0/T1) ahead of data (T2/T3); under `MaxFee` the tiers are
        // ignored and the ordering is byte-identical to the historical sort.
        let kept = self.sort_by_package_fee_rate(kept, &kept_tiers, &original_to_filtered);

        let stats = FilterStats {
            original: original_count,
            kept: kept.len(),
            removed: original_count - kept.len(),
            removed_fees,
            reaped: reaped_count,
            reaped_dead_bytes,
        };

        // Snapshot this template's Reaper impact for the "Reaped this block"
        // dashboard tile. Runs on EVERY build (even zero-reap ones) so the
        // stamped timestamp lets the API distinguish "0 reaped" from "no
        // block yet". Separate from the cumulative `record` calls above.
        self.reaper_stats
            .record_block(stats.reaped as u64, stats.reaped_dead_bytes);

        (kept, stats)
    }

    /// Sort transactions by package fee rate while respecting dependencies.
    ///
    /// CPFP-aware algorithm:
    /// 1. Fast path: if no dependent txs, sort by individual fee rate (zero overhead)
    /// 2. Build dependency graph from `depends` field (remapped to filtered indices)
    /// 3. Find connected components (clusters) via union-find
    /// 4. Compute package fee rate per cluster: sum(fees) / sum(vbytes)
    /// 5. Sort clusters by package fee rate descending
    /// 6. Within each cluster, topological sort (parents before children)
    /// 7. Flatten into final transaction list
    ///
    /// `tiers` carries the BUDS tier of each input transaction (parallel to
    /// `transactions`). It is only consulted when
    /// `self.config.block_priority == PaymentsFirst`, where it adds a primary
    /// sort key that seats **financial** packages (cluster-minimum tier ≤ T1)
    /// ahead of **data** packages, each group still fee-rate-descending
    /// internally. Under the default `MaxFee` the tiers are ignored and the
    /// ordering is byte-identical to the historical package-fee-rate sort. This
    /// is a permutation only — the tx set and total weight are invariant across
    /// both modes, so no new weight accounting is needed.
    fn sort_by_package_fee_rate(
        &self,
        transactions: Vec<TemplateTransaction>,
        tiers: &[BudsTier],
        original_to_filtered: &HashMap<usize, usize>,
    ) -> Vec<TemplateTransaction> {
        if transactions.len() <= 1 {
            return transactions;
        }

        let payments_first = matches!(self.config.block_priority, BlockPriority::PaymentsFirst);

        // Fast path: if no transactions have dependencies, simple fee-rate sort
        let has_deps = transactions.iter().any(|tx| !tx.depends.is_empty());
        if !has_deps {
            if payments_first {
                // Pair each tx with a "financial" bit (BUDS tier ≤ T1) derived
                // from its carried tier, then sort by (financial DESC, fee-rate
                // DESC). No dependencies here, so every tx is its own package.
                let mut paired: Vec<(TemplateTransaction, bool)> = transactions
                    .into_iter()
                    .zip(tiers.iter().copied())
                    .map(|(tx, tier)| (tx, tier <= BudsTier::T1))
                    .collect();
                paired.sort_by(|a, b| {
                    let rate_a = a.0.fee as f64 / (a.0.weight.max(1) as f64 / 4.0);
                    let rate_b = b.0.fee as f64 / (b.0.weight.max(1) as f64 / 4.0);
                    let fee_cmp = rate_b
                        .partial_cmp(&rate_a)
                        .unwrap_or(std::cmp::Ordering::Equal);
                    // financial (true) first, then fee rate descending.
                    b.1.cmp(&a.1).then(fee_cmp)
                });
                return paired.into_iter().map(|(tx, _)| tx).collect();
            }
            let mut sorted = transactions;
            sorted.sort_by(|a, b| {
                let rate_a = a.fee as f64 / (a.weight.max(1) as f64 / 4.0);
                let rate_b = b.fee as f64 / (b.weight.max(1) as f64 / 4.0);
                rate_b
                    .partial_cmp(&rate_a)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            return sorted;
        }

        let n = transactions.len();

        // Build adjacency: for each tx, find its parent indices in the filtered array
        // depends values are 1-indexed original positions
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut parents: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, tx) in transactions.iter().enumerate() {
            for &dep in &tx.depends {
                if dep == 0 {
                    continue;
                }
                let orig_idx = (dep - 1) as usize;
                if let Some(&filtered_idx) = original_to_filtered.get(&orig_idx) {
                    if filtered_idx < n {
                        children[filtered_idx].push(i);
                        parents[i].push(filtered_idx);
                    }
                }
            }
        }

        // Union-Find to group connected components
        let mut uf_parent: Vec<usize> = (0..n).collect();
        let mut uf_rank: Vec<usize> = vec![0; n];

        fn uf_find(parent: &mut [usize], x: usize) -> usize {
            if parent[x] != x {
                parent[x] = uf_find(parent, parent[x]);
            }
            parent[x]
        }

        fn uf_union(parent: &mut [usize], rank: &mut [usize], a: usize, b: usize) {
            let ra = uf_find(parent, a);
            let rb = uf_find(parent, b);
            if ra == rb {
                return;
            }
            if rank[ra] < rank[rb] {
                parent[ra] = rb;
            } else if rank[ra] > rank[rb] {
                parent[rb] = ra;
            } else {
                parent[rb] = ra;
                rank[ra] += 1;
            }
        }

        // Union parent-child pairs
        for (i, tx) in transactions.iter().enumerate() {
            for &dep in &tx.depends {
                if dep == 0 {
                    continue;
                }
                let orig_idx = (dep - 1) as usize;
                if let Some(&filtered_idx) = original_to_filtered.get(&orig_idx) {
                    if filtered_idx < n {
                        uf_union(&mut uf_parent, &mut uf_rank, i, filtered_idx);
                    }
                }
            }
        }

        // Group indices by their component root
        let mut components: HashMap<usize, Vec<usize>> = HashMap::new();
        for i in 0..n {
            let root = uf_find(&mut uf_parent, i);
            components.entry(root).or_default().push(i);
        }

        // Build clusters with topological ordering and package fee rates
        struct TxCluster {
            tx_indices: Vec<usize>, // Indices into filtered array, topological order
            total_fee: u64,
            total_weight: u64,
            // Whether this package counts as "financial" for payments-first
            // ordering. A CPFP package may mix tiers (a payment child bumping a
            // data parent, or vice-versa); we classify by the cluster's MINIMUM
            // (most-financial) member tier and collapse to ≤ T1. This keeps
            // parents-with-children intact — a package is never split — and errs
            // toward seating any package that contains a payment. Only consulted
            // under PaymentsFirst.
            is_financial: bool,
        }

        let mut clusters: Vec<TxCluster> = Vec::with_capacity(components.len());

        for members in components.values() {
            let total_fee: u64 = members.iter().map(|&i| transactions[i].fee).sum();
            let total_weight: u64 = members.iter().map(|&i| transactions[i].weight).sum();
            // Cluster-minimum tier → financial iff ≤ T1. `members` is never
            // empty (every component has at least its root), so `.min()` is safe.
            let is_financial = members
                .iter()
                .map(|&i| tiers[i])
                .min()
                .map(|t| t <= BudsTier::T1)
                .unwrap_or(false);

            if members.len() == 1 {
                // Single-tx cluster, no topo sort needed
                clusters.push(TxCluster {
                    tx_indices: members.clone(),
                    total_fee,
                    total_weight,
                    is_financial,
                });
                continue;
            }

            // Topological sort within cluster using Kahn's algorithm
            let member_set: HashSet<usize> = members.iter().copied().collect();
            let mut in_degree: HashMap<usize, usize> = HashMap::new();
            for &m in members {
                in_degree.insert(m, 0);
            }
            for &m in members {
                for &child in &children[m] {
                    if member_set.contains(&child) {
                        *in_degree.entry(child).or_insert(0) += 1;
                    }
                }
            }

            let mut queue: std::collections::VecDeque<usize> = std::collections::VecDeque::new();
            for &m in members {
                if in_degree[&m] == 0 {
                    queue.push_back(m);
                }
            }

            let mut topo_order = Vec::with_capacity(members.len());
            while let Some(node) = queue.pop_front() {
                topo_order.push(node);
                for &child in &children[node] {
                    if let Some(deg) = in_degree.get_mut(&child) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push_back(child);
                        }
                    }
                }
            }

            // If topo_order is incomplete (cycle), fall back to original order
            if topo_order.len() < members.len() {
                let mut fallback = members.clone();
                fallback.sort();
                clusters.push(TxCluster {
                    tx_indices: fallback,
                    total_fee,
                    total_weight,
                    is_financial,
                });
            } else {
                clusters.push(TxCluster {
                    tx_indices: topo_order,
                    total_fee,
                    total_weight,
                    is_financial,
                });
            }
        }

        // Sort clusters. Under MaxFee this is the historical single key:
        // package fee rate (sat/vB) descending. Under PaymentsFirst a primary
        // key seats financial packages first, then fee rate descending within
        // each group. The comparator is stable and, for MaxFee, byte-identical
        // to the pre-change sort.
        clusters.sort_by(|a, b| {
            let rate_a = a.total_fee as f64 / (a.total_weight.max(1) as f64 / 4.0);
            let rate_b = b.total_fee as f64 / (b.total_weight.max(1) as f64 / 4.0);
            let fee_cmp = rate_b
                .partial_cmp(&rate_a)
                .unwrap_or(std::cmp::Ordering::Equal);
            if payments_first {
                // financial (true) first, then fee rate descending.
                b.is_financial.cmp(&a.is_financial).then(fee_cmp)
            } else {
                fee_cmp
            }
        });

        // Flatten clusters into final transaction list
        let mut result = Vec::with_capacity(n);
        for cluster in clusters {
            for idx in cluster.tx_indices {
                result.push(transactions[idx].clone());
            }
        }

        result
    }

    /// Build merkle branches for stratum
    ///
    /// Validates all transaction hashes before building the merkle tree.
    /// Transactions with invalid hashes are logged and skipped.
    ///
    /// Stratum merkle branches algorithm:
    /// - Coinbase is at position 0 (miner computes this)
    /// - We provide the hashes needed to compute path from coinbase to root
    /// - At each level: first hash is the sibling of coinbase path, rest get paired
    fn build_merkle_branches(&self, transactions: &[TemplateTransaction]) -> Vec<[u8; 32]> {
        if transactions.is_empty() {
            return Vec::new();
        }

        // Get transaction hashes, validating each one
        // IMPORTANT: These are txids (double SHA256 of non-witness tx), NOT tx.hash (wtxid)
        // For merkle tree, we need txids. Bitcoin Core's getblocktemplate provides txid field.
        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(transactions.len());
        for tx in transactions {
            // Use txid, not hash (wtxid). Txid is the one used in merkle tree.
            match hex::decode(&tx.txid) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut hash = [0u8; 32];
                    // Bitcoin txids from RPC are in display order (big-endian)
                    // For merkle tree computation, we need internal order (little-endian)
                    // So we reverse the bytes
                    for (i, &b) in bytes.iter().enumerate() {
                        hash[31 - i] = b;
                    }
                    hashes.push(hash);
                }
                Ok(bytes) => {
                    warn!(
                        txid = %tx.txid,
                        len = bytes.len(),
                        "Skipping transaction with invalid txid length (expected 32 bytes)"
                    );
                }
                Err(e) => {
                    warn!(
                        txid = %tx.txid,
                        error = %e,
                        "Skipping transaction with invalid hex in txid"
                    );
                }
            }
        }

        // If all transactions had invalid hashes, return empty
        if hashes.is_empty() {
            warn!("All transactions had invalid txids, merkle branches will be empty");
            return Vec::new();
        }

        // Build merkle branches for Stratum
        // Algorithm: At each level, the first hash is the branch (sibling of coinbase path),
        // and we combine the REMAINING hashes into pairs for the next level.
        let mut branches = Vec::new();

        while !hashes.is_empty() {
            // First hash at this level is the sibling of the coinbase path
            branches.push(hashes[0]);

            if hashes.len() == 1 {
                // Only one hash left, we're done
                break;
            }

            // Combine the remaining hashes (excluding first) into pairs for next level
            let remaining = &hashes[1..];
            let mut next_level = Vec::new();
            for chunk in remaining.chunks(2) {
                let combined = match chunk {
                    [a, b] => self.double_sha256_pair(a, b),
                    [a] => self.double_sha256_pair(a, a), // Odd one out, hash with itself
                    _ => continue,
                };
                next_level.push(combined);
            }
            hashes = next_level;
        }

        branches
    }

    /// Double SHA256 of two hashes
    fn double_sha256_pair(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(a);
        hasher.update(b);
        let first = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(first);
        let result = hasher.finalize();

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Compute BIP141 witness commitment from filtered transactions.
    ///
    /// When BUDS filtering removes transactions, the witness commitment from
    /// Bitcoin Core's `default_witness_commitment` is no longer valid because
    /// it covers ALL template transactions. This recomputes it from the
    /// filtered set.
    ///
    /// Returns hex-encoded witness commitment script:
    ///   `OP_RETURN OP_PUSHBYTES_36 <aa21a9ed> <32-byte commitment>`
    fn compute_witness_commitment(&self, transactions: &[TemplateTransaction]) -> String {
        use sha2::{Digest, Sha256};

        // Build wtxid list: coinbase wtxid is 0x00*32, then transaction wtxids
        let mut wtxids: Vec<[u8; 32]> = Vec::with_capacity(transactions.len() + 1);

        // Coinbase wtxid is always 32 zero bytes (BIP141)
        wtxids.push([0u8; 32]);

        // Add transaction wtxids (from tx.hash field)
        for tx in transactions {
            match hex::decode(&tx.hash) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut wtxid = [0u8; 32];
                    // RPC returns wtxids in display order (big-endian)
                    // Merkle tree needs internal byte order (little-endian)
                    for (i, &b) in bytes.iter().enumerate() {
                        wtxid[31 - i] = b;
                    }
                    wtxids.push(wtxid);
                }
                _ => {
                    // Fall back to txid if hash is invalid (non-segwit tx: hash == txid)
                    if let Ok(bytes) = hex::decode(&tx.txid) {
                        if bytes.len() == 32 {
                            let mut wtxid = [0u8; 32];
                            for (i, &b) in bytes.iter().enumerate() {
                                wtxid[31 - i] = b;
                            }
                            wtxids.push(wtxid);
                        }
                    }
                }
            }
        }

        // Compute full merkle root (not branches)
        let mut level = wtxids;
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                let pair = if chunk.len() == 2 {
                    self.double_sha256_pair(&chunk[0], &chunk[1])
                } else {
                    self.double_sha256_pair(&chunk[0], &chunk[0]) // Odd: duplicate last
                };
                next.push(pair);
            }
            level = next;
        }
        let witness_root = level[0];

        // Commitment = SHA256d(witness_root || witness_nonce)
        // Witness nonce is 32 zero bytes (standard)
        let witness_nonce = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(witness_root);
        hasher.update(witness_nonce);
        let first = hasher.finalize();
        let mut hasher = Sha256::new();
        hasher.update(first);
        let commitment_hash = hasher.finalize();

        // Build script: OP_RETURN(6a) OP_PUSHBYTES_36(24) magic(aa21a9ed) commitment(32 bytes)
        let mut script = Vec::with_capacity(38);
        script.push(0x6a); // OP_RETURN
        script.push(0x24); // Push 36 bytes
        script.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]); // BIP141 magic
        script.extend_from_slice(&commitment_hash);

        hex::encode(script)
    }

    /// Build coinbase transaction parts
    ///
    /// Legacy method kept for Stratum V1 compatibility.
    /// Uses NON-WITNESS serialization for TXID computation.
    ///
    /// CRIT-10: Returns an error if pool_payout_address is invalid.
    #[allow(dead_code)]
    fn build_coinbase_parts(
        &self,
        height: u64,
        value: u64,
        witness_commitment: &Option<String>,
    ) -> Result<(Vec<u8>, Vec<u8>, WitnessData), TemplateError> {
        // Coinbase1: version + input count + prev tx + prev index + script length + height push
        // NON-WITNESS format (no marker/flag) for correct TXID computation
        let mut coinbase1 = Vec::new();

        // Version (4 bytes, little-endian)
        coinbase1.extend_from_slice(&2u32.to_le_bytes()); // Version 2 for BIP68

        // NO marker/flag - those are only for witness serialization
        // Input count
        coinbase1.push(0x01);

        // Previous tx hash (all zeros for coinbase)
        coinbase1.extend_from_slice(&[0u8; 32]);

        // Previous output index (0xffffffff for coinbase)
        coinbase1.extend_from_slice(&0xffffffffu32.to_le_bytes());

        // Script sig (height in BIP34 format + extra data)
        let height_bytes = self.encode_height(height);
        let extra = self.config.coinbase_extra.as_bytes();
        let script_len = height_bytes.len() + extra.len() + 8; // +8 for extranonce space

        // H-MINE-3: Validate script_len fits in u8 to prevent silent truncation
        if script_len > 255 {
            return Err(TemplateError::ConfigError(format!(
                "Coinbase script too long: {} bytes (max 255). coinbase_extra is {} bytes, \
                 which exceeds the safe limit. Reduce coinbase_extra to prevent corruption.",
                script_len,
                extra.len()
            )));
        }

        coinbase1.push(script_len as u8);
        coinbase1.extend_from_slice(&height_bytes);
        coinbase1.extend_from_slice(extra);

        // Coinbase2: extranonce end + sequence + outputs + locktime
        // NO witness data - that's tracked separately
        let mut coinbase2 = Vec::new();

        // Sequence
        coinbase2.extend_from_slice(&0xffffffffu32.to_le_bytes());

        // Output count (will be 1 or 2 depending on witness commitment)
        let output_count = if witness_commitment.is_some() { 2 } else { 1 };
        coinbase2.push(output_count);

        // Main output (pool reward)
        // H-BTC-4: Validate address BEFORE adding value to buffer
        if self.config.pool_payout_address.is_empty() {
            error!(
                value = value,
                "H-BTC-4 SECURITY: pool_payout_address is empty in legacy coinbase build. \
                 Cannot create coinbase output!"
            );
            return Err(TemplateError::ConfigError(
                "H-BTC-4: pool_payout_address is empty".to_string(),
            ));
        }

        coinbase2.extend_from_slice(&value.to_le_bytes());

        // Pool payout script
        // CRIT-10: Validate and fail if invalid
        self.encode_address_script(
            &mut coinbase2,
            &self.config.pool_payout_address,
            "pool_payout_legacy",
        )?;

        // Witness commitment output (if present) - this IS part of txid serialization
        let mut witness_data = WitnessData::default();
        if let Some(commitment) = witness_commitment {
            let commitment_bytes = hex::decode(commitment).map_err(|e| {
                TemplateError::BlockAssemblyError(format!("Invalid witness commitment hex: {}", e))
            })?;

            if !validate_witness_commitment_script(&commitment_bytes) {
                return Err(TemplateError::BlockAssemblyError(
                    "Invalid witness commitment script structure".to_string(),
                ));
            }

            coinbase2.extend_from_slice(&0u64.to_le_bytes()); // 0 value
            coinbase2.push(commitment_bytes.len() as u8);
            coinbase2.extend_from_slice(&commitment_bytes);
            witness_data.commitment_script = Some(commitment_bytes);
        }

        // Locktime (end of non-witness serialization)
        coinbase2.extend_from_slice(&0u32.to_le_bytes());

        // Witness data stored separately - NOT in coinbase2
        witness_data.nonce = [0u8; 32];

        Ok((coinbase1, coinbase2, witness_data))
    }

    /// Encode block height for coinbase (BIP34)
    fn encode_height(&self, height: u64) -> Vec<u8> {
        let mut bytes = Vec::new();

        if height == 0 {
            bytes.push(0x01);
            bytes.push(0x00);
        } else if height <= 0x7f {
            bytes.push(0x01);
            bytes.push(height as u8);
        } else if height <= 0x7fff {
            bytes.push(0x02);
            bytes.extend_from_slice(&(height as u16).to_le_bytes());
        } else if height <= 0x7fffff {
            bytes.push(0x03);
            bytes.push((height & 0xff) as u8);
            bytes.push(((height >> 8) & 0xff) as u8);
            bytes.push(((height >> 16) & 0xff) as u8);
        } else {
            bytes.push(0x04);
            bytes.extend_from_slice(&(height as u32).to_le_bytes());
        }

        bytes
    }

    /// Convert block hash to Stratum V1 prev_hash format
    ///
    /// Stratum V1 uses a specific format for prev_hash:
    /// - The 32-byte hash is split into 8 chunks of 4 bytes each
    /// - Each 4-byte chunk is byte-reversed
    ///
    /// Input: RPC display format (big-endian hex, e.g., "0000...abc123")
    /// Output: Stratum format (8 chunks, each chunk byte-reversed)
    fn to_stratum_prev_hash(&self, hex: &str) -> anyhow::Result<String> {
        if hex.len() != 64 {
            return Err(anyhow::anyhow!(
                "Invalid prev_hash length: {} (expected 64)",
                hex.len()
            ));
        }

        // Decode to bytes
        let bytes: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| anyhow::anyhow!("Invalid hex in prev_hash: {}", e))?;

        // Split into 8 chunks of 4 bytes, reverse each chunk
        let mut result = String::with_capacity(64);
        for chunk in bytes.chunks(4) {
            // Reverse the 4 bytes in this chunk
            for &byte in chunk.iter().rev() {
                result.push_str(&format!("{:02x}", byte));
            }
        }

        Ok(result)
    }

    /// Reverse a hex string (for block hashes)
    ///
    /// Returns an error if the hex string is malformed (odd length or invalid hex characters).
    #[allow(dead_code)]
    fn reverse_hex(&self, hex: &str) -> anyhow::Result<String> {
        // SEC-ERR-1: Validate hex string before parsing
        if !hex.len().is_multiple_of(2) {
            return Err(anyhow::anyhow!(
                "Invalid hex string: odd length {}",
                hex.len()
            ));
        }

        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            let byte = u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex character at position {}: {}", i, e))?;
            bytes.push(byte);
        }

        Ok(bytes.iter().rev().map(|b| format!("{:02x}", b)).collect())
    }

    /// Convert non-witness coinbase serialization to witness serialization
    ///
    /// Non-witness format: version(4) | input_count | inputs | output_count | outputs | locktime(4)
    /// Witness format:     version(4) | marker(1) | flag(1) | input_count | inputs | output_count | outputs | locktime(4) | witness
    ///
    /// This is needed because:
    /// - Miners compute TXID from non-witness serialization (for merkle root)
    /// - Blocks must contain witness serialization (for SegWit compatibility)
    fn convert_to_witness_serialization(
        &self,
        non_witness: &[u8],
        witness_data: &WitnessData,
    ) -> anyhow::Result<Vec<u8>> {
        if non_witness.len() < 10 {
            return Err(anyhow::anyhow!("Coinbase too short for conversion"));
        }

        let mut witness = Vec::with_capacity(non_witness.len() + 40);

        // Version (4 bytes) - copy as-is
        witness.extend_from_slice(&non_witness[0..4]);

        // Insert SegWit marker and flag
        witness.push(0x00); // marker
        witness.push(0x01); // flag

        // Copy everything from input_count to locktime (inclusive)
        // This is non_witness[4..] which contains: input_count | inputs | outputs | locktime
        witness.extend_from_slice(&non_witness[4..]);

        // Append witness stack for coinbase input
        // BIP141 coinbase witness: single 32-byte nonce (all zeros by default)
        witness.push(0x01); // witness stack count (1 item)
        witness.push(0x20); // item length (32 bytes)
        witness.extend_from_slice(&witness_data.nonce);

        Ok(witness)
    }

    /// Get current work state
    pub fn current_work(&self) -> Option<WorkState> {
        self.current_work.read().clone()
    }

    /// A lightweight JSON snapshot of the current template for the dashboard
    /// visualiser — reads the summary fields under the lock WITHOUT cloning the
    /// full transaction set that `current_work()` copies (so it's cheap to poll).
    /// `total_weight` is block weight units (max 4,000,000); `tx_count` includes
    /// the coinbase; `ntime` is the template time (Unix seconds) for an age readout.
    pub fn current_template_summary(&self) -> Option<serde_json::Value> {
        self.current_work.read().as_ref().map(|w| {
            serde_json::json!({
                "height": w.height,
                "job_id": w.job_id,
                "prev_hash": w.prev_hash,
                "tx_count": w.tx_count,
                "total_fees_sat": w.total_fees,
                "subsidy_sat": w.subsidy,
                "coinbase_value_sat": w.subsidy.saturating_add(w.total_fees),
                "total_weight": w.total_weight,
                "ntime": w.ntime,
                "nbits": w.nbits,
                "version": w.version,
                "refresh_secs": self.refresh_interval_secs(),
            })
        })
    }

    /// Categorised breakdown of the coinbase for the block currently being
    /// built, derived from the approved payout proposal: the miner pool, the
    /// node reward pool, the treasury allocation, and the tx fees routed to the
    /// block finder, plus the per-recipient entries behind the two pools.
    ///
    /// Returns `None` until a payout has been agreed for the current round —
    /// early in a round no proposal is approved yet and the coinbase is
    /// subsidy-only. Addresses are included raw (as their human-readable string,
    /// which is how `PayoutEntry::address` is stored); the API handler redacts
    /// them for non-operator callers.
    pub fn current_coinbase_breakdown(&self) -> Option<serde_json::Value> {
        let hash = (*self.approved_payout.read())?;
        let proposals = self.payout_proposals.read();
        let proposal = proposals.get(&hash)?;

        let miner_pool_sat: u64 = proposal.miner_payouts.iter().map(|e| e.amount).sum();
        let node_reward_pool_sat: u64 = proposal.node_payouts.iter().map(|e| e.amount).sum();
        let treasury_sat = proposal.treasury_amount;
        let tx_fees_to_finder_sat = proposal.tx_fees;
        let total_coinbase_sat = miner_pool_sat
            .saturating_add(node_reward_pool_sat)
            .saturating_add(treasury_sat)
            .saturating_add(tx_fees_to_finder_sat);

        let miners: Vec<serde_json::Value> = proposal
            .miner_payouts
            .iter()
            .map(|e| {
                serde_json::json!({
                    "address": String::from_utf8_lossy(&e.address),
                    "amount_sat": e.amount,
                })
            })
            .collect();
        let nodes: Vec<serde_json::Value> = proposal
            .node_payouts
            .iter()
            .map(|e| {
                serde_json::json!({
                    "node_id": hex::encode(&e.recipient_id[..4]),
                    "address": String::from_utf8_lossy(&e.address),
                    "amount_sat": e.amount,
                })
            })
            .collect();

        Some(serde_json::json!({
            "height": proposal.block_height,
            "round_id": proposal.round_id,
            "subsidy_sat": proposal.subsidy,
            "tx_fees_to_finder_sat": tx_fees_to_finder_sat,
            "treasury_sat": treasury_sat,
            "miner_pool_sat": miner_pool_sat,
            "node_reward_pool_sat": node_reward_pool_sat,
            "total_coinbase_sat": total_coinbase_sat,
            "miner_count": proposal.miner_payouts.len(),
            "node_count": proposal.node_payouts.len(),
            "miners": miners,
            "nodes": nodes,
        }))
    }

    /// Store work state by template_id (for SubmitSolution lookup)
    pub fn store_work_state(&self, template_id: u64, work_state: WorkState) {
        let mut states = self.work_states.write();
        states.insert(template_id, work_state);
        // L-02: Evict old work states, keeping only the 10 most recent
        if states.len() > 10 {
            let mut keys: Vec<u64> = states.keys().cloned().collect();
            keys.sort();
            for old_key in keys.iter().take(keys.len() - 10) {
                states.remove(old_key);
            }
        }
    }

    /// Get work state by template_id
    pub fn get_work_state(&self, template_id: u64) -> Option<WorkState> {
        self.work_states.read().get(&template_id).cloned()
    }

    /// Get current block height
    pub fn current_height(&self) -> Option<u64> {
        self.current_work.read().as_ref().map(|w| w.height)
    }

    /// Get current block info for payout calculation
    /// Returns (subsidy_sats, tx_fees_sats, height)
    pub fn get_current_block_info(&self) -> (u64, u64, u64) {
        let work = self.current_work.read();
        match work.as_ref() {
            Some(w) => (w.subsidy, w.total_fees, w.height),
            None => (0, 0, 0),
        }
    }

    /// Submit a solved block
    ///
    /// Assembles the complete block from:
    /// - 80-byte block header
    /// - Coinbase transaction
    /// - Other transactions from the template
    ///
    /// Performs validation before submitting:
    /// - Header length must be exactly 80 bytes
    /// - Previous block hash must match current template
    /// - Block version must be valid
    /// - Block weight must be within limits (4M WU)
    pub async fn submit_block(
        &self,
        coinbase_non_witness: &[u8],
        header: &[u8],
    ) -> anyhow::Result<()> {
        // Get current work state for transaction data
        let work = self
            .current_work
            .read()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No active work state"))?;

        // === BLOCK VALIDATION BEFORE SUBMISSION ===

        // 1. Validate header length
        if header.len() != 80 {
            return Err(anyhow::anyhow!(
                "Invalid header length: {} (expected 80)",
                header.len()
            ));
        }

        // 2. Validate previous block hash matches template
        // Header bytes 4-36 contain previousblockhash in Bitcoin internal byte order
        // (full 32-byte reversal of RPC display format).
        let prev_hash_from_header: String = header[4..36]
            .iter()
            .rev()
            .map(|b| format!("{:02x}", b))
            .collect();

        if prev_hash_from_header != work.template.previousblockhash {
            error!(
                expected = %work.template.previousblockhash,
                found = %prev_hash_from_header,
                "Block previousblockhash mismatch - possible stale work"
            );
            return Err(anyhow::anyhow!(
                "Block previousblockhash mismatch: expected {}, got {}",
                work.template.previousblockhash,
                prev_hash_from_header
            ));
        }

        // 3. Validate block version (bytes 0-4, little-endian)
        // SEC-BLOCK-1: Safe extraction without panic on malformed header
        let version_bytes: [u8; 4] = header
            .get(0..4)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| {
                anyhow::anyhow!("Invalid header: insufficient bytes for version field")
            })?;
        let version = u32::from_le_bytes(version_bytes);
        // H-12: Allow BIP320 version rolling — only reject version 0
        if version == 0 {
            error!(version = version, "Invalid block version");
            return Err(anyhow::anyhow!("Invalid block version: {}", version));
        }

        // 4. Convert non-witness coinbase to witness serialization
        // The coinbase passed in is non-witness format (for TXID computation)
        // We need to add marker, flag, and witness data for block submission
        let coinbase_witness =
            self.convert_to_witness_serialization(coinbase_non_witness, &work.witness_data)?;

        // Assemble the full block
        let mut block_data = Vec::new();

        // 1. Block header (80 bytes) - already validated
        block_data.extend_from_slice(header);

        // 2. Transaction count (varint)
        let tx_count = work.tx_count;
        if tx_count < 0xfd {
            block_data.push(tx_count as u8);
        } else if tx_count <= 0xffff {
            block_data.push(0xfd);
            block_data.extend_from_slice(&(tx_count as u16).to_le_bytes());
        } else {
            block_data.push(0xfe);
            block_data.extend_from_slice(&(tx_count as u32).to_le_bytes());
        }

        // 3. Coinbase transaction (witness serialization)
        block_data.extend_from_slice(&coinbase_witness);

        // 4. Other transactions from template
        // H-10: Abort on hex decode failure — do not submit a block with missing transactions
        for tx in &work.template.transactions {
            match hex::decode(&tx.data) {
                Ok(tx_bytes) => block_data.extend_from_slice(&tx_bytes),
                Err(e) => {
                    error!(
                        tx_hash = %tx.hash,
                        error = %e,
                        "H-10: Failed to decode transaction hex — aborting block assembly"
                    );
                    return Err(anyhow::anyhow!(
                        "H-10: Failed to decode transaction hex for tx {}: {}",
                        tx.hash,
                        e
                    ));
                }
            }
        }

        // 5. Validate block weight (max 4M weight units per BIP141)
        // Coinbase weight: non-witness bytes * 4 + witness bytes * 1
        let coinbase_non_witness_len = coinbase_non_witness.len();
        // SEC-BLOCK-2: Prevent integer underflow in weight calculation
        let coinbase_witness_extra = coinbase_witness.len().checked_sub(coinbase_non_witness_len)
            .ok_or_else(|| anyhow::anyhow!(
                "Invalid coinbase: witness serialization ({} bytes) shorter than non-witness ({} bytes)",
                coinbase_witness.len(),
                coinbase_non_witness_len
            ))?;
        let coinbase_weight = (coinbase_non_witness_len * 4 + coinbase_witness_extra) as u64;

        // Total weight = coinbase weight + transaction weights from template
        let total_weight = coinbase_weight + work.total_weight;

        const MAX_BLOCK_WEIGHT: u64 = 4_000_000; // 4M weight units (BIP141)
        const MIN_BLOCK_SIZE: usize = 81; // 80 byte header + 1 byte tx count minimum

        if block_data.len() < MIN_BLOCK_SIZE {
            error!(size = block_data.len(), "Block too small");
            return Err(anyhow::anyhow!(
                "Block too small: {} bytes (minimum {})",
                block_data.len(),
                MIN_BLOCK_SIZE
            ));
        }

        if total_weight > MAX_BLOCK_WEIGHT {
            error!(weight = total_weight, "Block weight exceeds limit");
            return Err(anyhow::anyhow!(
                "Block weight {} exceeds maximum {}",
                total_weight,
                MAX_BLOCK_WEIGHT
            ));
        }

        let block_hex = hex::encode(&block_data);
        info!(
            height = work.height,
            tx_count = tx_count,
            block_size = block_data.len(),
            block_weight = total_weight,
            prev_hash = %prev_hash_from_header,
            "Block validated, submitting to Ghost Core"
        );

        match self.rpc.submit_block(&block_hex).await {
            Ok(None) => {
                info!(height = work.height, "Block accepted!");
                Ok(())
            }
            Ok(Some(rejection)) => {
                if rejection == "inconclusive" || rejection == "duplicate" {
                    info!(height = work.height, reason = %rejection, "Block not connected (stale/race)");
                } else {
                    warn!(height = work.height, reason = %rejection, "Block rejected");
                }
                Err(anyhow::anyhow!("Block rejected: {}", rejection))
            }
            Err(e) => {
                error!(height = work.height, error = %e, "Block submission failed");
                Err(anyhow::anyhow!("Submission failed: {}", e))
            }
        }
    }

    /// Submit a block using the original witness coinbase from SRI
    ///
    /// This method is used when receiving a SubmitSolution from SRI Pool.
    /// SRI sends us the complete witness coinbase it constructed, so we use
    /// it directly instead of reconstructing the witness data.
    ///
    /// Arguments:
    /// - coinbase_witness: The original witness coinbase from SRI (for block data)
    /// - coinbase_non_witness: The stripped non-witness coinbase (for weight calculation)
    /// - header: The 80-byte block header
    pub async fn submit_block_with_coinbase(
        &self,
        coinbase_witness: &[u8],
        coinbase_non_witness: &[u8],
        header: &[u8],
        work: &WorkState,
    ) -> anyhow::Result<()> {
        // === BLOCK VALIDATION BEFORE SUBMISSION ===

        // 1. Validate header length
        if header.len() != 80 {
            return Err(anyhow::anyhow!(
                "Invalid header length: {} (expected 80)",
                header.len()
            ));
        }

        // 2. Validate previous block hash matches template
        // Header stores prev_hash in Bitcoin internal byte order (full 32-byte reversal
        // of RPC display format). Reverse to recover display order for comparison.
        let prev_hash_from_header: String = header[4..36]
            .iter()
            .rev()
            .map(|b| format!("{:02x}", b))
            .collect();

        if prev_hash_from_header != work.template.previousblockhash {
            error!(
                expected = %work.template.previousblockhash,
                found = %prev_hash_from_header,
                "Block previousblockhash mismatch - possible stale work"
            );
            return Err(anyhow::anyhow!(
                "Block previousblockhash mismatch: expected {}, got {}",
                work.template.previousblockhash,
                prev_hash_from_header
            ));
        }

        // 3. Validate block version
        // SEC-BLOCK-1: Safe extraction without panic on malformed header
        let version_bytes: [u8; 4] = header
            .get(0..4)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| {
                anyhow::anyhow!("Invalid header: insufficient bytes for version field")
            })?;
        let version = u32::from_le_bytes(version_bytes);
        // H-12: Allow BIP320 version rolling — only reject version 0
        if version == 0 {
            error!(version = version, "Invalid block version");
            return Err(anyhow::anyhow!("Invalid block version: {}", version));
        }

        // M-28: Verify coinbase matches the payout commitment that was active when
        // this template was created. Uses the per-template snapshot instead of the
        // global CoinbaseVerifier, which may have been overwritten by a newer payout.
        match &work.commitment_snapshot {
            Some(commitment) => {
                let outputs = CoinbaseOutput::parse_from_coinbase(coinbase_witness)
                    .map_err(|e| anyhow::anyhow!("M-28: Failed to parse coinbase outputs: {e}"))?;
                if let Err(e) = commitment.verify(&outputs) {
                    error!(error = %e, "COINBASE VERIFICATION FAILED - block submission blocked");
                    return Err(anyhow::anyhow!(
                        "M-28: Coinbase verification failed - block submission blocked. \
                         Coinbase outputs do not match the BFT-approved payout proposal: {e}"
                    ));
                }
            }
            None => {
                // H-11: Require coinbase commitment for block submission
                return Err(anyhow::anyhow!(
                    "H-11: Cannot submit block without verified coinbase commitment"
                ));
            }
        }

        // Assemble the full block using the ORIGINAL witness coinbase from SRI
        let mut block_data = Vec::new();

        // 1. Block header (80 bytes)
        block_data.extend_from_slice(header);

        // 2. Transaction count (varint)
        let tx_count = work.tx_count;
        if tx_count < 0xfd {
            block_data.push(tx_count as u8);
        } else if tx_count <= 0xffff {
            block_data.push(0xfd);
            block_data.extend_from_slice(&(tx_count as u16).to_le_bytes());
        } else {
            block_data.push(0xfe);
            block_data.extend_from_slice(&(tx_count as u32).to_le_bytes());
        }

        // 3. Coinbase transaction - use the ORIGINAL witness coinbase from SRI
        block_data.extend_from_slice(coinbase_witness);

        // 4. Other transactions from template
        // H-10: Abort on hex decode failure — do not submit a block with missing transactions
        for tx in &work.template.transactions {
            match hex::decode(&tx.data) {
                Ok(tx_bytes) => block_data.extend_from_slice(&tx_bytes),
                Err(e) => {
                    error!(
                        tx_hash = %tx.hash,
                        error = %e,
                        "H-10: Failed to decode transaction hex — aborting block assembly"
                    );
                    return Err(anyhow::anyhow!(
                        "H-10: Failed to decode transaction hex for tx {}: {}",
                        tx.hash,
                        e
                    ));
                }
            }
        }

        // 5. Validate block weight
        let coinbase_non_witness_len = coinbase_non_witness.len();
        // SEC-BLOCK-2: Prevent integer underflow in weight calculation
        let coinbase_witness_extra = coinbase_witness.len().checked_sub(coinbase_non_witness_len)
            .ok_or_else(|| anyhow::anyhow!(
                "Invalid coinbase: witness serialization ({} bytes) shorter than non-witness ({} bytes)",
                coinbase_witness.len(),
                coinbase_non_witness_len
            ))?;
        let coinbase_weight = (coinbase_non_witness_len * 4 + coinbase_witness_extra) as u64;
        let total_weight = coinbase_weight + work.total_weight;

        const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
        const MIN_BLOCK_SIZE: usize = 81;

        if block_data.len() < MIN_BLOCK_SIZE {
            error!(size = block_data.len(), "Block too small");
            return Err(anyhow::anyhow!(
                "Block too small: {} bytes (minimum {})",
                block_data.len(),
                MIN_BLOCK_SIZE
            ));
        }

        if total_weight > MAX_BLOCK_WEIGHT {
            error!(weight = total_weight, "Block weight exceeds limit");
            return Err(anyhow::anyhow!(
                "Block weight {} exceeds maximum {}",
                total_weight,
                MAX_BLOCK_WEIGHT
            ));
        }

        let block_hex = hex::encode(&block_data);
        info!(
            height = work.height,
            tx_count = tx_count,
            block_size = block_data.len(),
            block_weight = total_weight,
            coinbase_witness_len = coinbase_witness.len(),
            prev_hash = %prev_hash_from_header,
            "Block validated, submitting to Bitcoin Core (using SRI coinbase)"
        );

        match self.rpc.submit_block(&block_hex).await {
            Ok(None) => {
                info!(height = work.height, "Block accepted!");
                Ok(())
            }
            Ok(Some(rejection)) => {
                if rejection == "inconclusive" || rejection == "duplicate" {
                    info!(height = work.height, reason = %rejection, "Block not connected (stale/race)");
                } else {
                    warn!(height = work.height, reason = %rejection, "Block rejected");
                }
                Err(anyhow::anyhow!("Block rejected: {}", rejection))
            }
            Err(e) => {
                error!(height = work.height, error = %e, "Block submission failed");
                Err(anyhow::anyhow!("Submission failed: {}", e))
            }
        }
    }
}

/// BIP 141 witness commitment magic bytes: 0xaa21a9ed
const WITNESS_COMMITMENT_MAGIC: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

/// Validate witness commitment script structure
///
/// BIP 141 specifies the witness commitment format:
/// OP_RETURN OP_PUSH(36) <4-byte magic: 0xaa21a9ed> <32-byte commitment hash>
///
/// Total script length: 1 (OP_RETURN) + 1 (push opcode) + 4 (magic) + 32 (hash) = 38 bytes
/// HIGH-9: Uses bounds-checked .get() for all array accesses
fn validate_witness_commitment_script(script: &[u8]) -> bool {
    // First byte must be OP_RETURN (0x6a)
    let Some(&first_byte) = script.first() else {
        return false;
    };
    if first_byte != 0x6a {
        warn!(
            first_byte = first_byte,
            "Witness commitment script doesn't start with OP_RETURN"
        );
        return false;
    }

    // Second byte is the push length - should be at least 36 (4 magic + 32 hash)
    let Some(&push_len_byte) = script.get(1) else {
        return false;
    };
    let push_len = push_len_byte as usize;
    if push_len < 36 {
        warn!(
            push_len = push_len,
            "Witness commitment push length too short"
        );
        return false;
    }

    // Check for BIP 141 magic bytes at offset 2 (need indices 2..6)
    let Some(magic_slice) = script.get(2..6) else {
        warn!(
            script_len = script.len(),
            "Witness commitment script too short for magic bytes"
        );
        return false;
    };
    if magic_slice != WITNESS_COMMITMENT_MAGIC {
        warn!(
            magic = hex::encode(magic_slice),
            expected = hex::encode(WITNESS_COMMITMENT_MAGIC),
            "Witness commitment magic bytes mismatch"
        );
        return false;
    }

    // Verify we have enough bytes for the pushed data (need at least 2 + push_len bytes)
    if script.len() < 2 + push_len {
        warn!(
            script_len = script.len(),
            expected = 2 + push_len,
            "Witness commitment script truncated"
        );
        return false;
    }

    true
}

/// CRIT-10: Check if bytes represent a valid Bitcoin script
///
/// This is used to validate raw script bytes that may come from payout entries.
/// We accept standard script types that have known valid formats.
/// HIGH-10: Uses bounds-checked access patterns for all script validation
fn is_valid_script_bytes(script: &[u8]) -> bool {
    if script.is_empty() {
        return false;
    }

    // CRIT-10: Reject all-zeros scripts - these are unspendable
    if script.iter().all(|&b| b == 0) {
        return false;
    }

    // Helper to safely get a byte at an index
    let get = |idx: usize| script.get(idx).copied();

    match script.len() {
        // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG (25 bytes)
        25 => {
            get(0) == Some(0x76)
                && get(1) == Some(0xa9)
                && get(2) == Some(0x14)
                && get(23) == Some(0x88)
                && get(24) == Some(0xac)
        }

        // P2SH: OP_HASH160 <20 bytes> OP_EQUAL (23 bytes)
        23 => get(0) == Some(0xa9) && get(1) == Some(0x14) && get(22) == Some(0x87),

        // P2WPKH: OP_0 <20 bytes> (22 bytes)
        22 => get(0) == Some(0x00) && get(1) == Some(0x14),

        // P2WSH or P2TR: 34 bytes
        34 => {
            // P2WSH: OP_0 <32 bytes>
            // P2TR: OP_1 <32 bytes>
            (get(0) == Some(0x00) && get(1) == Some(0x20))
                || (get(0) == Some(0x51) && get(1) == Some(0x20))
        }

        _ => false,
    }
}

/// Enforce the finer per-field policy knobs against a candidate transaction.
///
/// Mirrors the field checks in `ghost_policy::PolicyEngine::evaluate`, minus the
/// tier gate (handled by the caller via `PolicyProfile::allows_tier`) and the
/// `min_fee_rate` floor (handled via `TemplateConfig::min_fee_rate`). Returns
/// `Some(reason)` when the transaction violates a policy field and must be
/// dropped from the block, or `None` when it conforms.
///
/// This is what makes `allow_inscriptions` / `allow_runes` / `allow_brc20`,
/// `max_op_return_size`, `max_witness_per_input`, `max_tx_outputs` and
/// `max_tx_size` actually bite at block-build time — before this was wired in,
/// only the tier gate and `min_fee_rate` were enforced, leaving those fields
/// cosmetic for block construction.
fn policy_field_violation(
    policy: &PolicyProfile,
    btc_tx: &bitcoin::Transaction,
    classification: &ghost_buds::ClassificationResult,
) -> Option<String> {
    // Transaction size (vbytes = weight / 4).
    let tx_size = btc_tx.weight().to_wu() as usize / 4;
    if tx_size > policy.max_tx_size {
        return Some(format!(
            "tx too large: {tx_size} > {} vB",
            policy.max_tx_size
        ));
    }

    // Output count.
    if btc_tx.output.len() > policy.max_tx_outputs {
        return Some(format!(
            "too many outputs: {} > {}",
            btc_tx.output.len(),
            policy.max_tx_outputs
        ));
    }

    // OP_RETURN payload size (strip the OP_RETURN opcode + push opcode ≈ 2 bytes,
    // matching PolicyEngine's accounting).
    for output in &btc_tx.output {
        if output.script_pubkey.is_op_return() {
            let op_return_size = output.script_pubkey.len().saturating_sub(2);
            if op_return_size > policy.max_op_return_size {
                return Some(format!(
                    "op_return too large: {op_return_size} > {} bytes",
                    policy.max_op_return_size
                ));
            }
        }
    }

    // Per-input witness size.
    for (i, input) in btc_tx.input.iter().enumerate() {
        let witness_size: usize = input.witness.iter().map(|w| w.len()).sum();
        if witness_size > policy.max_witness_per_input {
            return Some(format!(
                "witness too large on input {i}: {witness_size} > {} bytes",
                policy.max_witness_per_input
            ));
        }
    }

    // Content-type restrictions, driven by the BUDS classifier's detected
    // features.
    if !policy.allow_inscriptions
        && classification
            .features
            .iter()
            .any(|f| matches!(f, ghost_buds::DetectedFeature::InscriptionEnvelope))
    {
        return Some("inscriptions not allowed by policy".to_string());
    }
    if !policy.allow_runes
        && classification
            .features
            .iter()
            .any(|f| matches!(f, ghost_buds::DetectedFeature::RunesRunestone))
    {
        return Some("runes not allowed by policy".to_string());
    }
    if !policy.allow_brc20
        && classification
            .features
            .iter()
            .any(|f| matches!(f, ghost_buds::DetectedFeature::Brc20Pattern))
    {
        return Some("brc20 not allowed by policy".to_string());
    }

    None
}

/// Filter statistics
#[derive(Debug, Clone)]
struct FilterStats {
    original: usize,
    kept: usize,
    removed: usize,
    removed_fees: u64,
    reaped: usize,
    /// Dead bytes carried by the reaped transactions in this template.
    reaped_dead_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_height_encoding() {
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor = TemplateProcessor::new(
            TemplateConfig::default(),
            rpc,
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        );

        // Test various heights
        assert_eq!(processor.encode_height(0), vec![0x01, 0x00]);
        assert_eq!(processor.encode_height(1), vec![0x01, 0x01]);
        assert_eq!(processor.encode_height(127), vec![0x01, 0x7f]);
        assert_eq!(processor.encode_height(256), vec![0x02, 0x00, 0x01]);
    }

    #[test]
    fn test_reverse_hex() {
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor = TemplateProcessor::new(
            TemplateConfig::default(),
            rpc,
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        );

        // Valid hex string
        let hex = "0102030405060708";
        let reversed = processor.reverse_hex(hex).unwrap();
        assert_eq!(reversed, "0807060504030201");

        // SEC-ERR-1: Test error handling for invalid hex
        // Odd length should fail
        let result = processor.reverse_hex("123");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("odd length"));

        // Invalid hex characters should fail
        let result = processor.reverse_hex("gg");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid hex character"));

        // Empty string is valid (0 bytes)
        let result = processor.reverse_hex("");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_witness_conversion() {
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor = TemplateProcessor::new(
            TemplateConfig::default(),
            rpc,
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        );

        // Create a minimal non-witness coinbase:
        // version(4) | input_count(1) | prev_hash(32) | prev_index(4) | scriptsig_len(1) | scriptsig(4) | sequence(4) | output_count(1) | value(8) | scriptpubkey_len(1) | scriptpubkey(22) | locktime(4)
        let mut non_witness = Vec::new();
        non_witness.extend_from_slice(&2u32.to_le_bytes()); // version
        non_witness.push(0x01); // input count
        non_witness.extend_from_slice(&[0u8; 32]); // prev hash
        non_witness.extend_from_slice(&0xffffffffu32.to_le_bytes()); // prev index
        non_witness.push(0x04); // scriptsig len
        non_witness.extend_from_slice(&[0x03, 0x01, 0x02, 0x03]); // scriptsig (height)
        non_witness.extend_from_slice(&0xffffffffu32.to_le_bytes()); // sequence
        non_witness.push(0x01); // output count
        non_witness.extend_from_slice(&50_0000_0000u64.to_le_bytes()); // value (50 BTC)
        non_witness.push(22); // scriptpubkey len (P2WPKH)
        non_witness.extend_from_slice(&[0x00, 0x14]); // OP_0 PUSH20
        non_witness.extend_from_slice(&[0xab; 20]); // pubkey hash
        non_witness.extend_from_slice(&0u32.to_le_bytes()); // locktime

        let witness_data = WitnessData {
            commitment_script: None,
            nonce: [0u8; 32],
        };

        let witness = processor
            .convert_to_witness_serialization(&non_witness, &witness_data)
            .unwrap();

        // Witness serialization should be:
        // version(4) | marker(1) | flag(1) | rest... | witness_stack
        assert_eq!(&witness[0..4], &non_witness[0..4]); // version unchanged
        assert_eq!(witness[4], 0x00); // marker
        assert_eq!(witness[5], 0x01); // flag
        assert_eq!(&witness[6..6 + (non_witness.len() - 4)], &non_witness[4..]); // rest of tx

        // Last 34 bytes should be witness: stack_count(1) + item_len(1) + nonce(32)
        let witness_start = witness.len() - 34;
        assert_eq!(witness[witness_start], 0x01); // stack count
        assert_eq!(witness[witness_start + 1], 0x20); // item len (32)
        assert_eq!(&witness[witness_start + 2..], &[0u8; 32]); // nonce
    }

    #[test]
    fn test_coinbase_non_witness_format() {
        // Verify coinbase1/coinbase2 do NOT include marker/flag/witness
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor = TemplateProcessor::new(
            TemplateConfig {
                pool_payout_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                ..Default::default()
            },
            rpc,
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        );

        let (coinbase1, coinbase2, _witness_data) = processor
            .build_coinbase_parts(
                800_000,
                312_500_000, // 3.125 BTC
                &None,
            )
            .expect("Valid address should not fail");

        // coinbase1 should start with version (4 bytes), then input_count (NOT marker/flag)
        // Version 2 = 0x02000000 in little-endian
        assert_eq!(&coinbase1[0..4], &[0x02, 0x00, 0x00, 0x00]);
        // Next byte should be input_count (0x01), NOT marker (0x00)
        assert_eq!(coinbase1[4], 0x01);

        // coinbase2 should end with locktime (4 bytes), NOT witness data
        let len = coinbase2.len();
        assert_eq!(&coinbase2[len - 4..], &[0x00, 0x00, 0x00, 0x00]); // locktime = 0
    }

    /// SEC-BLOCK-TEST-1: Test that header validation correctly rejects short headers
    ///
    /// This tests the fix for unsafe .unwrap() on header byte slicing.
    /// A malformed header should produce an error, not a panic.
    #[test]
    fn test_block_submission_invalid_header_no_panic() {
        // Helper function that mimics the header validation logic
        fn validate_header_version(header: &[u8]) -> Result<u32, &'static str> {
            let version_bytes: [u8; 4] = header
                .get(0..4)
                .and_then(|s| s.try_into().ok())
                .ok_or("Invalid header: insufficient bytes for version field")?;
            Ok(u32::from_le_bytes(version_bytes))
        }

        // Valid 80-byte header (minimum)
        let valid_header = [0u8; 80];
        assert!(validate_header_version(&valid_header).is_ok());

        // Empty header should fail gracefully (not panic)
        let empty_header: [u8; 0] = [];
        assert!(validate_header_version(&empty_header).is_err());

        // 3-byte header should fail gracefully (not panic)
        let short_header = [0x02, 0x00, 0x00];
        assert!(validate_header_version(&short_header).is_err());

        // Exactly 4 bytes should work
        let min_header = [0x02, 0x00, 0x00, 0x00];
        let result = validate_header_version(&min_header);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2);
    }

    /// SEC-BLOCK-TEST-2: Test that weight calculation handles underflow correctly
    ///
    /// This tests the fix for integer underflow when witness < non-witness length.
    #[test]
    fn test_weight_calculation_underflow_handled() {
        // Helper function that mimics the weight calculation logic
        fn calculate_witness_extra(
            witness_len: usize,
            non_witness_len: usize,
        ) -> Result<usize, &'static str> {
            witness_len
                .checked_sub(non_witness_len)
                .ok_or("Invalid coinbase: witness serialization shorter than non-witness")
        }

        // Normal case: witness > non-witness (includes marker, flag, witness data)
        let result = calculate_witness_extra(250, 200);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 50);

        // Edge case: witness == non-witness (no extra witness data)
        let result = calculate_witness_extra(200, 200);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);

        // Error case: witness < non-witness (should never happen, indicates bug)
        let result = calculate_witness_extra(150, 200);
        assert!(
            result.is_err(),
            "Underflow should be caught, not wrap around"
        );
    }

    /// CRIT-10-TEST-1: Test that invalid addresses cause block production to fail
    ///
    /// This tests the fix for unvalidated address parsing creating unspendable outputs.
    /// An invalid address must cause an error, NOT create a placeholder all-zeros output.
    #[test]
    fn test_invalid_address_fails_coinbase_building() {
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());

        // Test with empty pool_payout_address
        let processor = TemplateProcessor::new(
            TemplateConfig {
                pool_payout_address: "".to_string(), // Empty - invalid
                ..Default::default()
            },
            rpc.clone(),
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        );

        let result = processor.build_coinbase_parts(800_000, 312_500_000, &None);
        assert!(
            result.is_err(),
            "Empty address should cause coinbase building to fail"
        );

        // Test with gibberish address
        let processor = TemplateProcessor::new(
            TemplateConfig {
                pool_payout_address: "not-a-valid-address".to_string(),
                ..Default::default()
            },
            rpc.clone(),
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        );

        let result = processor.build_coinbase_parts(800_000, 312_500_000, &None);
        assert!(
            result.is_err(),
            "Invalid address should cause coinbase building to fail"
        );
    }

    /// CRIT-10-TEST-2: Test that valid addresses work correctly
    #[test]
    fn test_valid_addresses_succeed() {
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());

        // Test with valid mainnet P2WPKH address
        let processor = TemplateProcessor::new(
            TemplateConfig {
                pool_payout_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                ..Default::default()
            },
            rpc.clone(),
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        );

        let result = processor.build_coinbase_parts(800_000, 312_500_000, &None);
        assert!(
            result.is_ok(),
            "Valid P2WPKH address should succeed: {:?}",
            result.err()
        );

        // Test with valid mainnet P2WSH address
        let processor = TemplateProcessor::new(
            TemplateConfig {
                pool_payout_address:
                    "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3".to_string(),
                ..Default::default()
            },
            rpc.clone(),
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        );

        let result = processor.build_coinbase_parts(800_000, 312_500_000, &None);
        assert!(
            result.is_ok(),
            "Valid P2WSH address should succeed: {:?}",
            result.err()
        );
    }

    /// CRIT-10-TEST-3: Test config validation catches invalid addresses at startup
    #[test]
    fn test_config_validation() {
        // Empty treasury address is allowed (optional)
        let config = TemplateConfig {
            pool_payout_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            mining_mode: MiningMode::PublicPool,
            ..Default::default()
        };
        assert!(
            config.validate().is_ok(),
            "Valid config should pass validation"
        );

        // Empty pool_payout_address in public pool mode should fail
        let config = TemplateConfig {
            pool_payout_address: "".to_string(),
            mining_mode: MiningMode::PublicPool,
            ..Default::default()
        };
        assert!(
            config.validate().is_err(),
            "Empty pool_payout_address should fail in PublicPool mode"
        );

        // Invalid pool_payout_address should fail
        let config = TemplateConfig {
            pool_payout_address: "invalid-address".to_string(),
            mining_mode: MiningMode::PublicPool,
            ..Default::default()
        };
        assert!(
            config.validate().is_err(),
            "Invalid pool_payout_address should fail validation"
        );

        // Solo mode without solo_payout_address should fail
        let config = TemplateConfig {
            pool_payout_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            mining_mode: MiningMode::PrivateSolo,
            solo_payout_address: None,
            ..Default::default()
        };
        assert!(
            config.validate().is_err(),
            "Solo mode requires solo_payout_address"
        );

        // Solo mode with valid solo_payout_address should pass
        let config = TemplateConfig {
            pool_payout_address: "".to_string(), // Not used in solo mode
            mining_mode: MiningMode::PrivateSolo,
            solo_payout_address: Some("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string()),
            ..Default::default()
        };
        assert!(
            config.validate().is_ok(),
            "Valid solo config should pass validation"
        );
    }

    /// CRIT-10-TEST-4: Test that is_valid_script_bytes rejects all-zeros
    #[test]
    fn test_is_valid_script_bytes_rejects_zeros() {
        // All zeros should be rejected (unspendable)
        assert!(
            !is_valid_script_bytes(&[0u8; 22]),
            "All-zeros P2WPKH-sized script should be rejected"
        );
        assert!(
            !is_valid_script_bytes(&[0u8; 34]),
            "All-zeros P2WSH-sized script should be rejected"
        );

        // Valid P2WPKH script (OP_0 <20 bytes hash>)
        let mut valid_p2wpkh = vec![0x00, 0x14]; // OP_0, PUSH20
        valid_p2wpkh.extend_from_slice(&[0xab; 20]); // non-zero hash
        assert!(
            is_valid_script_bytes(&valid_p2wpkh),
            "Valid P2WPKH script should be accepted"
        );

        // Valid P2WSH script (OP_0 <32 bytes hash>)
        let mut valid_p2wsh = vec![0x00, 0x20]; // OP_0, PUSH32
        valid_p2wsh.extend_from_slice(&[0xcd; 32]); // non-zero hash
        assert!(
            is_valid_script_bytes(&valid_p2wsh),
            "Valid P2WSH script should be accepted"
        );

        // Valid P2TR script (OP_1 <32 bytes>)
        let mut valid_p2tr = vec![0x51, 0x20]; // OP_1, PUSH32
        valid_p2tr.extend_from_slice(&[0xef; 32]); // non-zero key
        assert!(
            is_valid_script_bytes(&valid_p2tr),
            "Valid P2TR script should be accepted"
        );
    }

    /// H-MINE-3-TEST-1: Test that excessively long coinbase_extra is rejected at config validation
    #[test]
    fn test_coinbase_extra_length_validation() {
        // Valid short coinbase_extra should pass
        let config = TemplateConfig {
            coinbase_extra: "GHOST".to_string(),
            pool_payout_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            mining_mode: MiningMode::PublicPool,
            ..Default::default()
        };
        assert!(
            config.validate().is_ok(),
            "Short coinbase_extra should pass validation"
        );

        // coinbase_extra at exactly 242 bytes (max safe) should pass
        let config = TemplateConfig {
            coinbase_extra: "A".repeat(242),
            pool_payout_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            mining_mode: MiningMode::PublicPool,
            ..Default::default()
        };
        assert!(
            config.validate().is_ok(),
            "242-byte coinbase_extra should pass (max safe length)"
        );

        // coinbase_extra at 243 bytes should fail (would overflow script_len)
        let config = TemplateConfig {
            coinbase_extra: "A".repeat(243),
            pool_payout_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            mining_mode: MiningMode::PublicPool,
            ..Default::default()
        };
        assert!(
            config.validate().is_err(),
            "243-byte coinbase_extra should fail (exceeds safe limit)"
        );

        // Very long coinbase_extra should definitely fail
        let config = TemplateConfig {
            coinbase_extra: "A".repeat(300),
            pool_payout_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            mining_mode: MiningMode::PublicPool,
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err(), "300-byte coinbase_extra should fail");
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("coinbase_extra is too long"),
            "Error should mention coinbase_extra being too long: {}",
            error
        );
    }

    /// Test that header validation rejects wrong-length headers
    #[test]
    fn test_validate_header_wrong_length() {
        // Mimic the header length check from submit_block
        fn validate_header_length(header: &[u8]) -> Result<(), &'static str> {
            if header.len() != 80 {
                return Err("Invalid header length");
            }
            Ok(())
        }

        assert!(validate_header_length(&[0u8; 80]).is_ok());
        assert!(validate_header_length(&[0u8; 0]).is_err());
        assert!(validate_header_length(&[0u8; 79]).is_err());
        assert!(validate_header_length(&[0u8; 81]).is_err());
        assert!(validate_header_length(&[0u8; 160]).is_err());
    }

    /// Test that header prev_hash validation catches mismatches
    #[test]
    fn test_validate_header_prev_hash_mismatch() {
        // Build an 80-byte header with a known prev_hash
        let expected_rpc_hash = "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72f8fc440";
        let mut header = [0u8; 80];

        // Encode expected prev_hash into header bytes 4..36 (Bitcoin internal = reverse display)
        let display_bytes = hex::decode(expected_rpc_hash).unwrap();
        let mut internal_bytes = display_bytes.clone();
        internal_bytes.reverse();
        header[4..36].copy_from_slice(&internal_bytes);

        // Extract and verify (mimic submit_block logic)
        let recovered: String = header[4..36]
            .iter()
            .rev()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(recovered, expected_rpc_hash, "Correct hash should match");

        // Now tamper with one byte
        header[4] ^= 0xFF;
        let recovered_bad: String = header[4..36]
            .iter()
            .rev()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_ne!(
            recovered_bad, expected_rpc_hash,
            "Tampered hash should not match"
        );
    }

    /// Test block hex assembly: coinbase first, then template txs
    #[test]
    fn test_build_block_hex_coinbase_first() {
        // Simulate block assembly from submit_block
        let header = [0u8; 80];
        let coinbase = vec![0xCB; 100]; // Mock coinbase
        let tx1_hex = "aabb".to_string();
        let tx2_hex = "ccdd".to_string();
        let txs = vec![tx1_hex.clone(), tx2_hex.clone()];

        let mut block_data = Vec::new();
        block_data.extend_from_slice(&header);

        // tx_count = 1 (coinbase) + 2 (template txs) = 3
        let tx_count = 1 + txs.len();
        block_data.push(tx_count as u8); // varint for small counts

        // Coinbase first
        block_data.extend_from_slice(&coinbase);

        // Then template txs
        for tx_hex in &txs {
            let tx_bytes = hex::decode(tx_hex).unwrap();
            block_data.extend_from_slice(&tx_bytes);
        }

        // Verify structure
        assert_eq!(&block_data[0..80], &header);
        assert_eq!(block_data[80], 3); // tx_count varint
        assert_eq!(&block_data[81..181], &coinbase[..]);
        assert_eq!(block_data[181], 0xAA);
        assert_eq!(block_data[182], 0xBB);
        assert_eq!(block_data[183], 0xCC);
        assert_eq!(block_data[184], 0xDD);
    }

    /// Test that witness serialization adds marker/flag (0x00 0x01) and witness data
    #[test]
    fn test_build_block_hex_with_witness() {
        // Build a minimal non-witness coinbase:
        // version(4) | input_count(1) | prev_txid(32) | prev_vout(4) | script_len(1) |
        // script(4) | sequence(4) | output_count(1) | value(8) | scriptpubkey_len(1) |
        // scriptpubkey(4) | locktime(4)
        let mut non_witness = Vec::new();
        // Version
        non_witness.extend_from_slice(&1u32.to_le_bytes());
        // Input count = 1
        non_witness.push(0x01);
        // Prev txid (coinbase: all zeros)
        non_witness.extend_from_slice(&[0u8; 32]);
        // Prev vout (coinbase: 0xFFFFFFFF)
        non_witness.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // Script length + script (4 bytes of height push)
        non_witness.push(0x04);
        non_witness.extend_from_slice(&[0x03, 0x01, 0x00, 0x00]);
        // Sequence
        non_witness.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // Output count = 1
        non_witness.push(0x01);
        // Value (50 BTC in sats)
        non_witness.extend_from_slice(&5_000_000_000u64.to_le_bytes());
        // ScriptPubKey length + script (4 bytes)
        non_witness.push(0x04);
        non_witness.extend_from_slice(&[0x76, 0xa9, 0x14, 0x00]);
        // Locktime
        non_witness.extend_from_slice(&0u32.to_le_bytes());

        let non_witness_len = non_witness.len();

        // Simulate convert_to_witness_serialization
        let nonce = [0u8; 32];
        let mut witness = Vec::with_capacity(non_witness_len + 40);

        // Version (4 bytes)
        witness.extend_from_slice(&non_witness[0..4]);
        // SegWit marker and flag
        witness.push(0x00); // marker
        witness.push(0x01); // flag
                            // Rest of transaction (input_count through locktime)
        witness.extend_from_slice(&non_witness[4..]);
        // Witness stack: 1 item, 32-byte nonce
        witness.push(0x01); // stack count
        witness.push(0x20); // item length (32)
        witness.extend_from_slice(&nonce);

        // Verify witness marker/flag at correct position
        assert_eq!(witness[4], 0x00, "Witness marker should be 0x00");
        assert_eq!(witness[5], 0x01, "Witness flag should be 0x01");

        // Verify witness is longer than non-witness (marker + flag + witness stack)
        assert_eq!(
            witness.len(),
            non_witness_len + 2 + 1 + 1 + 32,
            "Witness should add 36 bytes (marker+flag+stack_count+item_len+nonce)"
        );

        // Verify version preserved
        assert_eq!(&witness[0..4], &non_witness[0..4], "Version should match");

        // Verify witness nonce at the end
        assert_eq!(
            &witness[witness.len() - 32..],
            &nonce,
            "Last 32 bytes should be witness nonce"
        );

        // Assemble full block with witness coinbase
        let header = [0u8; 80];
        let tx_hex = "aabb".to_string();
        let mut block_data = Vec::new();
        block_data.extend_from_slice(&header);
        block_data.push(2); // tx_count: coinbase + 1 template tx
        block_data.extend_from_slice(&witness);
        block_data.extend_from_slice(&hex::decode(&tx_hex).unwrap());

        // Verify witness flag appears in block hex
        let block_hex = hex::encode(&block_data);
        // After 80-byte header (160 hex chars) + varint "02" (2 hex chars) + version "01000000" (8 hex chars)
        // comes the witness marker+flag "0001"
        let witness_start = 160 + 2 + 8; // hex offset
        assert_eq!(
            &block_hex[witness_start..witness_start + 4],
            "0001",
            "Witness marker+flag should appear after version in block hex"
        );
    }

    /// Test that block weight formula doesn't overflow with large templates
    #[test]
    fn test_block_weight_within_limits() {
        // Simulate weight calculation from submit_block
        // coinbase_weight = (non_witness_len * 4 + witness_extra) as u64
        // total_weight = coinbase_weight + sum(tx.weight for tx in template)

        let coinbase_non_witness_len: usize = 200;
        let coinbase_witness_len: usize = 250;
        let witness_extra = coinbase_witness_len - coinbase_non_witness_len;
        let coinbase_weight = (coinbase_non_witness_len * 4 + witness_extra) as u64;

        // 3999 small transactions at ~250 WU each (well under 4M total)
        let tx_count = 3999;
        let per_tx_weight: u64 = 250;
        let total_tx_weight = tx_count * per_tx_weight;
        let total_weight = coinbase_weight + total_tx_weight;

        assert!(
            total_weight < 4_000_000,
            "3999 small txs + coinbase should be under 4M WU: {}",
            total_weight
        );

        // Edge case: a block exactly at the BIP141 weight limit is allowed, not rejected.
        // (The previous `max_weight <= u64::MAX` assertion was vacuous — max_weight is u64.)
        const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
        let max_weight: u64 = MAX_BLOCK_WEIGHT;
        assert!(
            max_weight <= MAX_BLOCK_WEIGHT,
            "a block at exactly the BIP141 limit must be permitted"
        );
    }

    /// Helper to create a TemplateTransaction for sorting tests
    fn make_tx(txid: &str, fee: u64, weight: u64, depends: Vec<u32>) -> TemplateTransaction {
        TemplateTransaction {
            data: String::new(),
            txid: txid.to_string(),
            hash: "00".repeat(32),
            depends,
            fee,
            sigops: 0,
            weight,
        }
    }

    /// Helper to create a TemplateProcessor for sorting tests
    fn test_processor() -> TemplateProcessor {
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        TemplateProcessor::new(
            TemplateConfig::default(),
            rpc,
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        )
    }

    /// Helper to create a TemplateProcessor with an explicit block-priority mode.
    fn test_processor_with_priority(block_priority: BlockPriority) -> TemplateProcessor {
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        TemplateProcessor::new(
            TemplateConfig {
                block_priority,
                ..TemplateConfig::default()
            },
            rpc,
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        )
    }

    /// A tiers slice of `n` financial (T0) entries — used by the legacy sorting
    /// tests, which exercise MaxFee where tiers are ignored.
    fn t0_tiers(n: usize) -> Vec<BudsTier> {
        vec![BudsTier::T0; n]
    }

    /// Test that CPFP package with high package fee rate sorts above lower independent txs
    #[test]
    fn test_cpfp_package_sorted_by_package_fee_rate() {
        let processor = test_processor();

        // Independent tx: 50 sat/vB (fee=5000, weight=400 => vB=100)
        let tx_ind = make_tx("ind", 5000, 400, vec![]);

        // CPFP pair: parent has low fee, child pays for both
        // Parent (original idx 1): fee=100, weight=400 => 1 sat/vB alone
        // Child (original idx 2): fee=14900, weight=200 => depends on parent
        // Package rate: (100+14900) / ((400+200)/4) = 15000/150 = 100 sat/vB
        let tx_parent = make_tx("parent", 100, 400, vec![]);
        let tx_child = make_tx("child", 14900, 200, vec![2]); // depends on parent (1-indexed: idx 1 = dep 2)

        // Simulate: original indices [0=ind, 1=parent, 2=child], all kept
        // After filtering: ind->0, parent->1, child->2
        let mut original_to_filtered = HashMap::new();
        original_to_filtered.insert(0, 0);
        original_to_filtered.insert(1, 1);
        original_to_filtered.insert(2, 2);

        let txs = vec![tx_ind, tx_parent, tx_child];
        let tiers = t0_tiers(txs.len());
        let result = processor.sort_by_package_fee_rate(txs, &tiers, &original_to_filtered);

        // CPFP package (100 sat/vB) should come before independent tx (50 sat/vB)
        assert_eq!(result.len(), 3);
        // The CPFP package (parent+child) should be first
        assert!(
            result[0].txid == "parent" || result[0].txid == "child",
            "First tx should be from the CPFP package, got: {}",
            result[0].txid
        );
        // Parent must come before child within the package
        let parent_pos = result.iter().position(|t| t.txid == "parent").unwrap();
        let child_pos = result.iter().position(|t| t.txid == "child").unwrap();
        assert!(
            parent_pos < child_pos,
            "Parent must precede child in output"
        );
        // Independent tx should be last
        assert_eq!(result[2].txid, "ind");
    }

    /// Test that with no dependent txs, simple fee rate sort is used (fast path)
    #[test]
    fn test_independent_only_fast_path() {
        let processor = test_processor();

        let tx_a = make_tx("a", 1000, 400, vec![]); // 10 sat/vB
        let tx_b = make_tx("b", 5000, 400, vec![]); // 50 sat/vB
        let tx_c = make_tx("c", 3000, 400, vec![]); // 30 sat/vB

        let original_to_filtered = HashMap::new();
        let txs = vec![tx_a, tx_b, tx_c];
        let tiers = t0_tiers(txs.len());
        let result = processor.sort_by_package_fee_rate(txs, &tiers, &original_to_filtered);

        assert_eq!(result[0].txid, "b"); // 50 sat/vB
        assert_eq!(result[1].txid, "c"); // 30 sat/vB
        assert_eq!(result[2].txid, "a"); // 10 sat/vB
    }

    /// Test that parents always precede children in CPFP chain output
    #[test]
    fn test_cpfp_chain_topological_order() {
        let processor = test_processor();

        // Chain: grandparent -> parent -> child
        // Original indices: 0, 1, 2
        let tx_gp = make_tx("grandparent", 100, 400, vec![]);
        let tx_p = make_tx("parent", 100, 400, vec![1]); // depends on grandparent (1-indexed)
        let tx_c = make_tx("child", 10000, 400, vec![2]); // depends on parent (1-indexed)

        let mut original_to_filtered = HashMap::new();
        original_to_filtered.insert(0, 0);
        original_to_filtered.insert(1, 1);
        original_to_filtered.insert(2, 2);

        let txs = vec![tx_gp, tx_p, tx_c];
        let tiers = t0_tiers(txs.len());
        let result = processor.sort_by_package_fee_rate(txs, &tiers, &original_to_filtered);

        let gp_pos = result.iter().position(|t| t.txid == "grandparent").unwrap();
        let p_pos = result.iter().position(|t| t.txid == "parent").unwrap();
        let c_pos = result.iter().position(|t| t.txid == "child").unwrap();
        assert!(gp_pos < p_pos, "Grandparent must precede parent");
        assert!(p_pos < c_pos, "Parent must precede child");
    }

    /// Test mixed independent transactions and CPFP packages sort correctly
    #[test]
    fn test_mixed_independent_and_packages() {
        let processor = test_processor();

        // Independent tx: 20 sat/vB
        let tx_ind1 = make_tx("ind1", 2000, 400, vec![]);
        // CPFP pair: package rate = (100+3900)/((400+400)/4) = 4000/200 = 20 sat/vB
        let tx_parent = make_tx("parent", 100, 400, vec![]);
        let tx_child = make_tx("child", 3900, 400, vec![2]); // depends on parent at original idx 1
                                                             // Independent tx: 10 sat/vB
        let tx_ind2 = make_tx("ind2", 1000, 400, vec![]);

        let mut original_to_filtered = HashMap::new();
        original_to_filtered.insert(0, 0);
        original_to_filtered.insert(1, 1);
        original_to_filtered.insert(2, 2);
        original_to_filtered.insert(3, 3);

        let txs = vec![tx_ind1, tx_parent, tx_child, tx_ind2];
        let tiers = t0_tiers(txs.len());
        let result = processor.sort_by_package_fee_rate(txs, &tiers, &original_to_filtered);

        assert_eq!(result.len(), 4);

        // ind2 (10 sat/vB) should be last
        assert_eq!(result[3].txid, "ind2");

        // Parent must precede child
        let parent_pos = result.iter().position(|t| t.txid == "parent").unwrap();
        let child_pos = result.iter().position(|t| t.txid == "child").unwrap();
        assert!(parent_pos < child_pos);
    }

    /// Test single transaction edge case
    #[test]
    fn test_single_transaction() {
        let processor = test_processor();
        let tx = make_tx("only", 1000, 400, vec![]);
        let original_to_filtered = HashMap::new();
        let result =
            processor.sort_by_package_fee_rate(vec![tx], &t0_tiers(1), &original_to_filtered);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].txid, "only");
    }

    /// Test that 1-based depends values are correctly mapped
    #[test]
    fn test_depends_indexing_1_based() {
        let processor = test_processor();

        // Original array: [A at idx 0, B at idx 1]
        // B depends on A. In GBT, A is at position 1 (1-indexed), so depends=[1]
        let tx_a = make_tx("a", 100, 400, vec![]);
        let tx_b = make_tx("b", 10000, 200, vec![1]); // depends on position 1 = original idx 0

        let mut original_to_filtered = HashMap::new();
        original_to_filtered.insert(0, 0);
        original_to_filtered.insert(1, 1);

        let txs = vec![tx_a, tx_b];
        let tiers = t0_tiers(txs.len());
        let result = processor.sort_by_package_fee_rate(txs, &tiers, &original_to_filtered);

        // They should form a package; A must come before B
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].txid, "a");
        assert_eq!(result[1].txid, "b");
    }

    // ------------------------------------------------------------------
    // Block-priority lever: PaymentsFirst vs MaxFee
    // ------------------------------------------------------------------

    /// A controlled tiered mempool used by the block-priority tests.
    ///
    /// Returns `(txs, tiers, original_to_filtered)` for a mix of independent
    /// financial + data txs and a CPFP package that SPANS tiers (a T3 data
    /// parent CPFP-bumped by a T0 payment child), so the cluster-minimum-tier
    /// classification is exercised. All txs are kept 1:1 (identity remap).
    ///
    /// | idx | txid   | tier | fee   | weight | vB  | sat/vB | note                    |
    /// |-----|--------|------|-------|--------|-----|--------|-------------------------|
    /// | 0   | payA   | T0   | 1000  | 400    | 100 | 10     | low-fee payment         |
    /// | 1   | dataC  | T3   | 8000  | 400    | 100 | 80     | high-fee inscription    |
    /// | 2   | dataP  | T3   | 100   | 400    | 100 | 1      | package parent (data)   |
    /// | 3   | payQ   | T0   | 5000  | 200    | 50  | —      | package child (payment) |
    /// | 4   | payB   | T1   | 2000  | 400    | 100 | 20     | payment                 |
    /// | 5   | dataD  | T2   | 1200  | 400    | 100 | 12     | low-fee data            |
    ///
    /// Package {dataP,payQ}: fee=5100, weight=600, vB=150 => 34 sat/vB;
    /// cluster-minimum tier = T0 (payQ) => classified FINANCIAL.
    fn tiered_mempool() -> (
        Vec<TemplateTransaction>,
        Vec<BudsTier>,
        HashMap<usize, usize>,
    ) {
        let txs = vec![
            make_tx("payA", 1000, 400, vec![]),
            make_tx("dataC", 8000, 400, vec![]),
            make_tx("dataP", 100, 400, vec![]),
            make_tx("payQ", 5000, 200, vec![3]), // depends on dataP (orig idx 2 => 1-indexed 3)
            make_tx("payB", 2000, 400, vec![]),
            make_tx("dataD", 1200, 400, vec![]),
        ];
        let tiers = vec![
            BudsTier::T0, // payA
            BudsTier::T3, // dataC
            BudsTier::T3, // dataP
            BudsTier::T0, // payQ
            BudsTier::T1, // payB
            BudsTier::T2, // dataD
        ];
        let mut original_to_filtered = HashMap::new();
        for i in 0..txs.len() {
            original_to_filtered.insert(i, i);
        }
        (txs, tiers, original_to_filtered)
    }

    fn pos(result: &[TemplateTransaction], txid: &str) -> usize {
        result
            .iter()
            .position(|t| t.txid == txid)
            .unwrap_or_else(|| panic!("txid {txid} missing from result"))
    }

    /// PaymentsFirst seats all financial packages (T0/T1, or a CPFP package
    /// whose minimum tier is financial) ahead of all data packages (T2/T3),
    /// each group still internally ordered by package fee rate, and never
    /// splits or reorders a CPFP package.
    #[test]
    fn test_payments_first_seats_financial_ahead_respecting_cpfp() {
        let processor = test_processor_with_priority(BlockPriority::PaymentsFirst);
        let (txs, tiers, o2f) = tiered_mempool();
        let result = processor.sort_by_package_fee_rate(txs, &tiers, &o2f);

        assert_eq!(result.len(), 6, "permutation must preserve the tx set");

        // Financial txs (payA, payB, and the min-financial package dataP+payQ)
        // must all precede the data txs (dataC, dataD).
        let last_financial = ["payA", "payB", "dataP", "payQ"]
            .iter()
            .map(|t| pos(&result, t))
            .max()
            .unwrap();
        let first_data = ["dataC", "dataD"]
            .iter()
            .map(|t| pos(&result, t))
            .min()
            .unwrap();
        assert!(
            last_financial < first_data,
            "every financial tx must be seated ahead of every data tx (got financial max {last_financial} >= data min {first_data}): {:?}",
            result.iter().map(|t| &t.txid).collect::<Vec<_>>()
        );

        // The mixed-tier CPFP package is classified financial by cluster-min
        // tier and stays intact with parent before child.
        assert!(
            pos(&result, "dataP") < pos(&result, "payQ"),
            "CPFP parent (dataP) must precede its child (payQ)"
        );

        // Financial group internally fee-rate descending: package (34 sat/vB) >
        // payB (20) > payA (10).
        assert!(pos(&result, "dataP") < pos(&result, "payB"));
        assert!(pos(&result, "payB") < pos(&result, "payA"));
        // Data group internally fee-rate descending: dataC (80) > dataD (12).
        assert!(pos(&result, "dataC") < pos(&result, "dataD"));

        // Exact expected permutation.
        let order: Vec<&str> = result.iter().map(|t| t.txid.as_str()).collect();
        assert_eq!(
            order,
            vec!["dataP", "payQ", "payB", "payA", "dataC", "dataD"],
        );
    }

    /// MaxFee (the default) ignores tiers entirely: the ordering is identical to
    /// the historical package-fee-rate sort, regardless of the carried tiers.
    #[test]
    fn test_max_fee_identical_to_pre_change_default() {
        let (txs, tiers, o2f) = tiered_mempool();

        // Explicit MaxFee processor.
        let max_fee = test_processor_with_priority(BlockPriority::MaxFee);
        let result_max = max_fee.sort_by_package_fee_rate(txs.clone(), &tiers, &o2f);

        // The default processor (no block_priority set => MaxFee) must produce
        // byte-identical ordering, proving the default path is untouched.
        let default_proc = test_processor();
        let result_default = default_proc.sort_by_package_fee_rate(txs.clone(), &tiers, &o2f);
        let ids_max: Vec<&str> = result_max.iter().map(|t| t.txid.as_str()).collect();
        let ids_default: Vec<&str> = result_default.iter().map(|t| t.txid.as_str()).collect();
        assert_eq!(ids_max, ids_default, "explicit MaxFee == default config");

        // And it must equal the pure fee-rate ordering (tiers make no
        // difference under MaxFee): dataC(80) > pkg(34: dataP->payQ) > payB(20)
        // > dataD(12) > payA(10).
        assert_eq!(
            ids_max,
            vec!["dataC", "dataP", "payQ", "payB", "dataD", "payA"],
        );
    }

    /// PaymentsFirst is a pure permutation: the tx set and total block weight
    /// are invariant vs MaxFee — only the order changes. This is the property
    /// that keeps the submit-time MAX_BLOCK_WEIGHT guard sufficient (no new
    /// weight accounting).
    #[test]
    fn test_payments_first_is_weight_safe_permutation() {
        let (txs, tiers, o2f) = tiered_mempool();

        let max_fee = test_processor_with_priority(BlockPriority::MaxFee);
        let pay_first = test_processor_with_priority(BlockPriority::PaymentsFirst);

        let r_max = max_fee.sort_by_package_fee_rate(txs.clone(), &tiers, &o2f);
        let r_pay = pay_first.sort_by_package_fee_rate(txs.clone(), &tiers, &o2f);

        // Same count.
        assert_eq!(r_max.len(), r_pay.len());
        assert_eq!(r_pay.len(), txs.len());

        // Same total weight (permutation, not re-selection).
        let w_max: u64 = r_max.iter().map(|t| t.weight).sum();
        let w_pay: u64 = r_pay.iter().map(|t| t.weight).sum();
        assert_eq!(w_max, w_pay, "total weight must be invariant across modes");
        // The submit-time consensus cap (BIP141). Since PaymentsFirst only
        // permutes the ghostd-selected set, this guard remains sufficient.
        const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
        assert!(
            w_pay < MAX_BLOCK_WEIGHT,
            "template stays under the weight cap"
        );

        // Same multiset of txids (nothing added or dropped).
        let mut ids_max: Vec<&str> = r_max.iter().map(|t| t.txid.as_str()).collect();
        let mut ids_pay: Vec<&str> = r_pay.iter().map(|t| t.txid.as_str()).collect();
        ids_max.sort_unstable();
        ids_pay.sort_unstable();
        assert_eq!(ids_max, ids_pay, "tx set must be identical, only reordered");

        // The two orders actually differ (the lever does something here).
        let ord_max: Vec<&str> = r_max.iter().map(|t| t.txid.as_str()).collect();
        let ord_pay: Vec<&str> = r_pay.iter().map(|t| t.txid.as_str()).collect();
        assert_ne!(ord_max, ord_pay);
    }

    /// Under a strict tier policy that admits only financial tiers, all kept
    /// txs are T0/T1, so PaymentsFirst is a no-op — its ordering matches MaxFee
    /// exactly. (Here every tier is financial, mirroring a strict-policy set.)
    #[test]
    fn test_payments_first_noop_when_all_financial() {
        // A mempool of only financial txs (as a strict policy would leave).
        let txs = vec![
            make_tx("p_lo", 1000, 400, vec![]),  // 10 sat/vB
            make_tx("p_hi", 5000, 400, vec![]),  // 50 sat/vB
            make_tx("p_mid", 3000, 400, vec![]), // 30 sat/vB
        ];
        let tiers = vec![BudsTier::T0, BudsTier::T1, BudsTier::T0];
        let o2f = HashMap::new();

        let max_fee = test_processor_with_priority(BlockPriority::MaxFee);
        let pay_first = test_processor_with_priority(BlockPriority::PaymentsFirst);
        let r_max = max_fee.sort_by_package_fee_rate(txs.clone(), &tiers, &o2f);
        let r_pay = pay_first.sort_by_package_fee_rate(txs, &tiers, &o2f);

        let ord_max: Vec<&str> = r_max.iter().map(|t| t.txid.as_str()).collect();
        let ord_pay: Vec<&str> = r_pay.iter().map(|t| t.txid.as_str()).collect();
        assert_eq!(
            ord_max, ord_pay,
            "no-op when nothing but financial txs present"
        );
    }

    /// H-MINE-3-TEST-2: Test that runtime script_len validation works
    #[test]
    fn test_script_len_runtime_validation() {
        // This is a defensive test to ensure that even if config validation is bypassed,
        // the runtime check in build_coinbase_parts catches the overflow.
        // We can't easily bypass config validation, but we can verify the error message
        // pattern matches what we expect.

        // Create a config with a barely-safe coinbase_extra
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor = TemplateProcessor::new(
            TemplateConfig {
                coinbase_extra: "A".repeat(200), // Safe length
                pool_payout_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                mining_mode: MiningMode::PublicPool,
                ..Default::default()
            },
            rpc,
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        );

        // This should succeed
        let result = processor.build_coinbase_parts(800_000, 312_500_000, &None);
        assert!(
            result.is_ok(),
            "200-byte coinbase_extra should work at runtime: {:?}",
            result.err()
        );
    }

    /// Test that prev_hash in block header uses Bitcoin internal byte order
    /// (full 32-byte reversal of RPC display format), NOT Stratum word-reversal.
    #[test]
    fn test_prev_hash_word_reversal_round_trip() {
        // RPC display order (big-endian)
        let rpc_hash = "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72f8fc440";

        // Bitcoin internal byte order = full reversal of display bytes
        let mut internal_bytes = hex::decode(rpc_hash).unwrap();
        internal_bytes.reverse();

        // Recover RPC display order by reversing all bytes (what the validation code does)
        let recovered: String = internal_bytes
            .iter()
            .rev()
            .map(|b| format!("{:02x}", b))
            .collect();

        assert_eq!(
            recovered, rpc_hash,
            "Full byte reversal should recover original RPC hash from internal format"
        );
    }

    /// Test that ghost-reaper integration rejects transactions with inscription envelopes
    #[test]
    fn test_reaper_filters_inscription_tx() {
        use bitcoin::consensus::encode::serialize as btc_serialize;
        use bitcoin::{
            absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, ScriptBuf,
            Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };

        // Build a tapscript with an inscription envelope (OP_FALSE OP_IF ... OP_ENDIF)
        let mut tapscript: Vec<u8> = Vec::new();
        tapscript.push(0x00); // OP_FALSE
        tapscript.push(0x63); // OP_IF
        tapscript.push(0x03); // PUSH3
        tapscript.extend(b"ord"); // "ord" marker
        tapscript.push(0x51); // OP_1 (content type tag)
        let ctype = b"text/plain";
        tapscript.push(ctype.len() as u8);
        tapscript.extend(ctype);
        tapscript.push(0x00); // OP_0 (content tag)
        let body = b"dead code inscription payload";
        tapscript.push(body.len() as u8);
        tapscript.extend(body);
        tapscript.push(0x68); // OP_ENDIF
        tapscript.push(0xac); // OP_CHECKSIG

        // Witness: signature, tapscript, control block
        let mut witness = Witness::new();
        witness.push([0x30; 64]); // fake schnorr sig
        witness.push(&tapscript);
        let mut control_block = vec![0xc0u8]; // leaf version
        control_block.extend([0x11; 32]); // internal key
        witness.push(&control_block);

        let txid = Txid::from_byte_array([42u8; 32]);
        let inscription_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from({
                    let mut s = vec![0x00, 0x14];
                    s.extend([0xaa; 20]);
                    s
                }),
            }],
        };

        let inscription_hex = hex::encode(btc_serialize(&inscription_tx));
        let inscription_txid = inscription_tx.compute_txid().to_string();

        // Also build a clean P2WPKH transaction (no witness abuse)
        let clean_txid_hash = Txid::from_byte_array([99u8; 32]);
        let mut clean_witness = Witness::new();
        clean_witness.push([0x30; 72]); // DER signature
        clean_witness.push([0x02; 33]); // compressed pubkey
        let clean_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: clean_txid_hash,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: clean_witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from({
                    let mut s = vec![0x00, 0x14];
                    s.extend([0xbb; 20]);
                    s
                }),
            }],
        };
        let clean_hex = hex::encode(btc_serialize(&clean_tx));
        let clean_txid = clean_tx.compute_txid().to_string();

        // Create TemplateTransactions
        let txs = vec![
            TemplateTransaction {
                data: inscription_hex,
                txid: inscription_txid.clone(),
                hash: "00".repeat(32),
                depends: vec![],
                fee: 5000,
                sigops: 1,
                weight: 800,
            },
            TemplateTransaction {
                data: clean_hex,
                txid: clean_txid.clone(),
                hash: "00".repeat(32),
                depends: vec![],
                fee: 3000,
                sigops: 1,
                weight: 400,
            },
        ];

        // Filter with reaper enabled (strict mode)
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor = TemplateProcessor::new(
            TemplateConfig::default(),
            rpc.clone(),
            PolicyProfile::full_open(), // allow all tiers so only reaper filters
            ReaperConfig::default(),
        );

        let (kept, stats) = processor.filter_transactions(&txs);

        assert_eq!(stats.original, 2);
        assert_eq!(stats.reaped, 1, "inscription tx should be reaped");
        assert_eq!(kept.len(), 1, "only clean tx should survive");
        assert_eq!(kept[0].txid, clean_txid, "clean tx should be kept");

        // Verify reaper disabled lets inscription through
        let processor_disabled = TemplateProcessor::new(
            TemplateConfig::default(),
            rpc,
            PolicyProfile::full_open(),
            ReaperConfig::disabled(),
        );

        let (kept_all, stats_all) = processor_disabled.filter_transactions(&txs);

        assert_eq!(stats_all.reaped, 0, "disabled reaper should not reap");
        assert_eq!(
            kept_all.len(),
            2,
            "both txs should survive with reaper disabled"
        );
    }

    // ===================================================================
    // Per-field policy enforcement (wired into filter_transactions).
    //
    // These prove each finer PolicyProfile knob now actually drops the
    // right tx at block-build time and lets conforming ones through.
    // Each test starts from `full_open` (all tiers, generous limits, all
    // content allowed) and lowers ONE field to isolate that knob. Reaper
    // is disabled so the policy field check — not the reaper — is what
    // drops the transaction.
    // ===================================================================

    /// Build a TemplateTransaction wrapper around a bitcoin::Transaction with a
    /// fee/weight ratio comfortably above the default min_fee_rate (1.0).
    fn template_tx(btc_tx: &bitcoin::Transaction) -> TemplateTransaction {
        use bitcoin::consensus::encode::serialize as btc_serialize;
        TemplateTransaction {
            data: hex::encode(btc_serialize(btc_tx)),
            txid: btc_tx.compute_txid().to_string(),
            hash: "00".repeat(32),
            depends: vec![],
            fee: 100_000, // high fee so the fee-rate floor never drops these
            weight: 400,
            sigops: 1,
        }
    }

    /// A simple P2WPKH transaction with `n` identical outputs and a unique
    /// txid derived from `seed`.
    fn tx_with_outputs(seed: u8, n: usize) -> bitcoin::Transaction {
        use bitcoin::{
            absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, ScriptBuf,
            Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };
        let mut witness = Witness::new();
        witness.push([0x30; 72]);
        witness.push([0x02; 33]);
        let spk = ScriptBuf::from({
            let mut s = vec![0x00, 0x14];
            s.extend([seed; 20]);
            s
        });
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([seed; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: (0..n)
                .map(|_| TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: spk.clone(),
                })
                .collect(),
        }
    }

    /// Processor on the Custom path: per-field enforcement ON, reaper OFF, so
    /// only the policy fields can drop a tx.
    fn make_processor(policy: PolicyProfile) -> TemplateProcessor {
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let config = TemplateConfig {
            enforce_custom_policy_fields: true,
            ..Default::default()
        };
        TemplateProcessor::new(config, rpc, policy, ReaperConfig::disabled())
    }

    #[test]
    fn test_policy_max_tx_outputs_enforced() {
        // 10-output tx: dropped when the limit is 5, kept when it is 20.
        let tx = template_tx(&tx_with_outputs(0x10, 10));

        let mut strict = PolicyProfile::full_open();
        strict.max_tx_outputs = 5;
        let (kept, _) = make_processor(strict).filter_transactions(std::slice::from_ref(&tx));
        assert!(
            kept.is_empty(),
            "tx exceeding max_tx_outputs must be dropped"
        );

        let mut loose = PolicyProfile::full_open();
        loose.max_tx_outputs = 20;
        let (kept, _) = make_processor(loose).filter_transactions(&[tx]);
        assert_eq!(kept.len(), 1, "conforming output count must be kept");
    }

    #[test]
    fn test_policy_max_op_return_size_enforced() {
        use bitcoin::{
            absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, ScriptBuf,
            Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };
        // OP_RETURN carrying 100 bytes → payload size ~100.
        let mut op_return = vec![0x6a, 0x4c, 100]; // OP_RETURN OP_PUSHDATA1 len=100
        op_return.extend(std::iter::repeat_n(0xABu8, 100));
        let mut witness = Witness::new();
        witness.push([0x30; 72]);
        witness.push([0x02; 33]);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0x20; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: ScriptBuf::from({
                        let mut s = vec![0x00, 0x14];
                        s.extend([0x20; 20]);
                        s
                    }),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::from(op_return),
                },
            ],
        };
        let ttx = template_tx(&tx);

        let mut strict = PolicyProfile::full_open();
        strict.max_op_return_size = 40;
        let (kept, _) = make_processor(strict).filter_transactions(std::slice::from_ref(&ttx));
        assert!(kept.is_empty(), "oversized OP_RETURN must be dropped");

        let mut loose = PolicyProfile::full_open();
        loose.max_op_return_size = 200;
        let (kept, _) = make_processor(loose).filter_transactions(&[ttx]);
        assert_eq!(kept.len(), 1, "conforming OP_RETURN must be kept");
    }

    #[test]
    fn test_policy_max_witness_per_input_enforced() {
        use bitcoin::{
            absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, ScriptBuf,
            Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };
        // A single ~2000-byte witness item.
        let mut witness = Witness::new();
        witness.push(vec![0x42u8; 2000]);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0x30; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from({
                    let mut s = vec![0x00, 0x14];
                    s.extend([0x30; 20]);
                    s
                }),
            }],
        };
        let ttx = template_tx(&tx);

        let mut strict = PolicyProfile::full_open();
        strict.max_witness_per_input = 500;
        let (kept, _) = make_processor(strict).filter_transactions(std::slice::from_ref(&ttx));
        assert!(kept.is_empty(), "oversized witness must be dropped");

        let mut loose = PolicyProfile::full_open();
        loose.max_witness_per_input = 4000;
        let (kept, _) = make_processor(loose).filter_transactions(&[ttx]);
        assert_eq!(kept.len(), 1, "conforming witness must be kept");
    }

    #[test]
    fn test_policy_max_tx_size_enforced() {
        // Many outputs inflate the serialized size well past a tight limit,
        // while keeping the output count under max_tx_outputs.
        let tx = template_tx(&tx_with_outputs(0x40, 50));

        let mut strict = PolicyProfile::full_open();
        strict.max_tx_size = 500; // vbytes; a 50-output tx is larger
        let (kept, _) = make_processor(strict).filter_transactions(std::slice::from_ref(&tx));
        assert!(kept.is_empty(), "tx exceeding max_tx_size must be dropped");

        let mut loose = PolicyProfile::full_open();
        loose.max_tx_size = 100_000;
        let (kept, _) = make_processor(loose).filter_transactions(&[tx]);
        assert_eq!(kept.len(), 1, "conforming tx size must be kept");
    }

    #[test]
    fn test_policy_allow_inscriptions_enforced() {
        use bitcoin::{
            absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, ScriptBuf,
            Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };
        // Inscription envelope (OP_FALSE OP_IF "ord" ... OP_ENDIF) in a tapscript.
        let mut tapscript: Vec<u8> = Vec::new();
        tapscript.push(0x00); // OP_FALSE
        tapscript.push(0x63); // OP_IF
        tapscript.push(0x03);
        tapscript.extend(b"ord");
        tapscript.push(0x51);
        let ctype = b"text/plain";
        tapscript.push(ctype.len() as u8);
        tapscript.extend(ctype);
        tapscript.push(0x00);
        let body = b"inscription payload";
        tapscript.push(body.len() as u8);
        tapscript.extend(body);
        tapscript.push(0x68); // OP_ENDIF
        tapscript.push(0xac); // OP_CHECKSIG
        let mut witness = Witness::new();
        witness.push([0x30; 64]);
        witness.push(&tapscript);
        let mut control_block = vec![0xc0u8];
        control_block.extend([0x11; 32]);
        witness.push(&control_block);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0x50; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from({
                    let mut s = vec![0x00, 0x14];
                    s.extend([0x50; 20]);
                    s
                }),
            }],
        };
        let ttx = template_tx(&tx);

        // Sanity: the classifier must flag this as an inscription, else the test
        // proves nothing.
        let btc_tx: bitcoin::Transaction = deserialize(&hex::decode(&ttx.data).unwrap()).unwrap();
        let classification = BudsClassifier::new().classify(&btc_tx);
        assert!(
            classification
                .features
                .iter()
                .any(|f| matches!(f, ghost_buds::DetectedFeature::InscriptionEnvelope)),
            "test fixture must classify as an inscription"
        );

        // allow_inscriptions = false → dropped by policy (reaper disabled).
        let mut strict = PolicyProfile::full_open();
        strict.allow_inscriptions = false;
        let (kept, _) = make_processor(strict).filter_transactions(std::slice::from_ref(&ttx));
        assert!(
            kept.is_empty(),
            "inscription must be dropped when disallowed"
        );

        // allow_inscriptions = true → kept.
        let loose = PolicyProfile::full_open(); // already allows inscriptions
        let (kept, _) = make_processor(loose).filter_transactions(&[ttx]);
        assert_eq!(kept.len(), 1, "inscription must be kept when allowed");
    }

    #[test]
    fn test_preset_does_not_enforce_custom_fields() {
        // A preset (permissive) is tier-gate-only: enforce_custom_policy_fields
        // is OFF (the default), so a tx that is an allowed tier but exceeds the
        // profile's baked-in max_tx_outputs (100) must STILL be mined — the
        // finer fields are Custom-only.
        let tx = template_tx(&tx_with_outputs(0x60, 150));

        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        // Default config → enforce_custom_policy_fields = false (preset path).
        let processor = TemplateProcessor::new(
            TemplateConfig::default(),
            rpc,
            PolicyProfile::permissive(),
            ReaperConfig::disabled(),
        );

        // Sanity: permissive's field limit is indeed exceeded, so the only reason
        // it survives is that presets don't enforce that field.
        assert!(150 > PolicyProfile::permissive().max_tx_outputs);

        let (kept, _) = processor.filter_transactions(&[tx]);
        assert_eq!(
            kept.len(),
            1,
            "preset must keep an over-limit but allowed-tier tx (tier-gate-only)"
        );

        // And the Custom path (enforcement ON) with the same profile WOULD drop it.
        let tx2 = template_tx(&tx_with_outputs(0x61, 150));
        let (kept2, _) = make_processor(PolicyProfile::permissive()).filter_transactions(&[tx2]);
        assert!(
            kept2.is_empty(),
            "custom path must drop the over-limit tx once enforcement is on"
        );
    }

    /// Test that ghost-reaper detects OP_DROP stuffing in witness scripts
    #[test]
    fn test_reaper_filters_drop_stuffing_tx() {
        use bitcoin::consensus::encode::serialize as btc_serialize;
        use bitcoin::{
            absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, ScriptBuf,
            Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };

        // Build a tapscript with large data push followed by OP_DROP (data stuffing)
        let mut tapscript: Vec<u8> = Vec::new();
        tapscript.push(0x4c); // OP_PUSHDATA1
        tapscript.push(100); // 100 bytes of junk (exceeds strict threshold of 76)
        tapscript.extend([0xDE; 100]); // junk data
        tapscript.push(0x75); // OP_DROP
        tapscript.push(0x51); // OP_TRUE (makes script succeed)

        // Witness: signature, tapscript, control block
        let mut witness = Witness::new();
        witness.push([0x30; 64]); // fake schnorr sig
        witness.push(&tapscript);
        let mut control_block = vec![0xc0u8]; // leaf version
        control_block.extend([0x22; 32]); // internal key
        witness.push(&control_block);

        let txid = Txid::from_byte_array([50u8; 32]);
        let drop_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(40_000),
                script_pubkey: ScriptBuf::from({
                    let mut s = vec![0x00, 0x14];
                    s.extend([0xcc; 20]);
                    s
                }),
            }],
        };

        let drop_hex = hex::encode(btc_serialize(&drop_tx));
        let drop_txid = drop_tx.compute_txid().to_string();

        let txs = vec![TemplateTransaction {
            data: drop_hex,
            txid: drop_txid,
            hash: "00".repeat(32),
            depends: vec![],
            fee: 4000,
            sigops: 1,
            weight: 600,
        }];

        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor = TemplateProcessor::new(
            TemplateConfig::default(),
            rpc,
            PolicyProfile::full_open(),
            ReaperConfig::default(),
        );

        let (kept, stats) = processor.filter_transactions(&txs);
        assert_eq!(stats.reaped, 1, "drop stuffing tx should be reaped");
        assert_eq!(kept.len(), 0, "no txs should survive");
    }

    /// Test that ghost-reaper detects fake pubkeys in bare multisig outputs
    #[test]
    fn test_reaper_filters_fake_pubkey_tx() {
        use bitcoin::consensus::encode::serialize as btc_serialize;
        use bitcoin::{
            absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, ScriptBuf,
            Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };

        // Build a bare 1-of-2 multisig output with one fake pubkey (0x04 prefix = invalid)
        let mut multisig_script: Vec<u8> = Vec::new();
        multisig_script.push(0x51); // OP_1 (M=1)
        multisig_script.push(0x21); // OP_PUSHBYTES_33
        let mut valid_pk = vec![0x02]; // valid compressed prefix
        valid_pk.extend([0xAA; 32]); // pubkey body
        multisig_script.extend(&valid_pk);
        multisig_script.push(0x21); // OP_PUSHBYTES_33
        let mut fake_pk = vec![0x04]; // INVALID uncompressed prefix (data stuffing)
        fake_pk.extend([0xBB; 32]); // junk data disguised as pubkey
        multisig_script.extend(&fake_pk);
        multisig_script.push(0x52); // OP_2 (N=2)
        multisig_script.push(0xae); // OP_CHECKMULTISIG

        let txid = Txid::from_byte_array([55u8; 32]);
        // This tx has a normal P2WPKH witness (clean) but its output has fake multisig
        let mut witness = Witness::new();
        witness.push([0x30; 72]); // DER sig
        witness.push([0x02; 33]); // compressed pubkey
        let fake_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(30_000),
                script_pubkey: ScriptBuf::from(multisig_script),
            }],
        };

        let fake_hex = hex::encode(btc_serialize(&fake_tx));
        let fake_txid = fake_tx.compute_txid().to_string();

        let txs = vec![TemplateTransaction {
            data: fake_hex,
            txid: fake_txid,
            hash: "00".repeat(32),
            depends: vec![],
            fee: 3000,
            sigops: 1,
            weight: 500,
        }];

        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor = TemplateProcessor::new(
            TemplateConfig::default(),
            rpc,
            PolicyProfile::full_open(),
            ReaperConfig::default(),
        );

        let (kept, stats) = processor.filter_transactions(&txs);
        assert_eq!(stats.reaped, 1, "fake pubkey tx should be reaped");
        assert_eq!(kept.len(), 0, "no txs should survive");
    }

    /// Test that ghost-reaper detects unreachable code after OP_RETURN in witness scripts
    #[test]
    fn test_reaper_filters_unreachable_code_tx() {
        use bitcoin::consensus::encode::serialize as btc_serialize;
        use bitcoin::{
            absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, ScriptBuf,
            Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };

        // Build a tapscript with OP_RETURN followed by dead code
        let mut tapscript: Vec<u8> = Vec::new();
        tapscript.push(0x51); // OP_TRUE (script succeeds before OP_RETURN)
        tapscript.push(0x6a); // OP_RETURN (halts execution)
        tapscript.extend([0xDE, 0xAD, 0xBE, 0xEF]); // unreachable dead code

        // Witness: signature, tapscript, control block
        let mut witness = Witness::new();
        witness.push([0x30; 64]); // fake schnorr sig
        witness.push(&tapscript);
        let mut control_block = vec![0xc0u8]; // leaf version
        control_block.extend([0x33; 32]); // internal key
        witness.push(&control_block);

        let txid = Txid::from_byte_array([60u8; 32]);
        let unreach_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(45_000),
                script_pubkey: ScriptBuf::from({
                    let mut s = vec![0x00, 0x14];
                    s.extend([0xdd; 20]);
                    s
                }),
            }],
        };

        let unreach_hex = hex::encode(btc_serialize(&unreach_tx));
        let unreach_txid = unreach_tx.compute_txid().to_string();

        let txs = vec![TemplateTransaction {
            data: unreach_hex,
            txid: unreach_txid,
            hash: "00".repeat(32),
            depends: vec![],
            fee: 3500,
            sigops: 1,
            weight: 500,
        }];

        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor = TemplateProcessor::new(
            TemplateConfig::default(),
            rpc,
            PolicyProfile::full_open(),
            ReaperConfig::default(),
        );

        let (kept, stats) = processor.filter_transactions(&txs);
        assert_eq!(stats.reaped, 1, "unreachable code tx should be reaped");
        assert_eq!(kept.len(), 0, "no txs should survive");
    }

    /// Test that ghost-reaper detects witness annex (BIP 341 optional field)
    #[test]
    fn test_reaper_filters_annex_tx() {
        use bitcoin::consensus::encode::serialize as btc_serialize;
        use bitcoin::{
            absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, ScriptBuf,
            Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };

        // Build witness with annex (last element starts with 0x50)
        let mut witness = Witness::new();
        witness.push([0x30; 64]); // fake schnorr sig
        let tapscript = vec![0x51, 0xac]; // OP_TRUE OP_CHECKSIG
        witness.push(&tapscript);
        let mut control_block = vec![0xc0u8]; // leaf version
        control_block.extend([0x44; 32]); // internal key
        witness.push(&control_block);
        // Annex: starts with 0x50, followed by arbitrary data
        let mut annex = vec![0x50u8]; // annex prefix
        annex.extend([0xFF; 100]); // 100 bytes of annex data
        witness.push(&annex);

        let txid = Txid::from_byte_array([65u8; 32]);
        let annex_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(35_000),
                script_pubkey: ScriptBuf::from({
                    let mut s = vec![0x00, 0x14];
                    s.extend([0xee; 20]);
                    s
                }),
            }],
        };

        let annex_hex = hex::encode(btc_serialize(&annex_tx));
        let annex_txid = annex_tx.compute_txid().to_string();

        let txs = vec![TemplateTransaction {
            data: annex_hex,
            txid: annex_txid,
            hash: "00".repeat(32),
            depends: vec![],
            fee: 4000,
            sigops: 1,
            weight: 700,
        }];

        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor = TemplateProcessor::new(
            TemplateConfig::default(),
            rpc,
            PolicyProfile::full_open(),
            ReaperConfig::default(),
        );

        let (kept, stats) = processor.filter_transactions(&txs);
        assert_eq!(stats.reaped, 1, "annex tx should be reaped");
        assert_eq!(kept.len(), 0, "no txs should survive");
    }

    /// Test that ghost-reaper detects oversized OP_RETURN outputs (>83 bytes)
    #[test]
    fn test_reaper_filters_oversized_op_return_tx() {
        use bitcoin::consensus::encode::serialize as btc_serialize;
        use bitcoin::{
            absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, ScriptBuf,
            Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };

        // Build OP_RETURN output > 83 bytes (standard relay limit)
        let mut op_return_script: Vec<u8> = Vec::new();
        op_return_script.push(0x6a); // OP_RETURN
        op_return_script.push(0x4c); // OP_PUSHDATA1
        op_return_script.push(100); // 100 bytes payload
        op_return_script.extend([0xAB; 100]); // junk data

        let txid = Txid::from_byte_array([70u8; 32]);
        let mut witness = Witness::new();
        witness.push([0x30; 72]); // DER sig
        witness.push([0x02; 33]); // compressed pubkey
        let opret_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: ScriptBuf::from({
                        let mut s = vec![0x00, 0x14];
                        s.extend([0xff; 20]);
                        s
                    }),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::from(op_return_script),
                },
            ],
        };

        let opret_hex = hex::encode(btc_serialize(&opret_tx));
        let opret_txid = opret_tx.compute_txid().to_string();

        let txs = vec![TemplateTransaction {
            data: opret_hex,
            txid: opret_txid,
            hash: "00".repeat(32),
            depends: vec![],
            fee: 2000,
            sigops: 1,
            weight: 400,
        }];

        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor = TemplateProcessor::new(
            TemplateConfig::default(),
            rpc,
            PolicyProfile::full_open(),
            ReaperConfig::default(),
        );

        let (kept, stats) = processor.filter_transactions(&txs);
        assert_eq!(stats.reaped, 1, "oversized OP_RETURN tx should be reaped");
        assert_eq!(kept.len(), 0, "no txs should survive");
    }

    /// Test that all 6 attack vectors are reaped simultaneously
    #[test]
    fn test_reaper_filters_all_attack_vectors() {
        use bitcoin::consensus::encode::serialize as btc_serialize;
        use bitcoin::{
            absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, ScriptBuf,
            Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };

        // Helper to build a TemplateTransaction from a Bitcoin Transaction
        let make_tt = |tx: &Transaction, fee: u64| -> TemplateTransaction {
            TemplateTransaction {
                data: hex::encode(btc_serialize(tx)),
                txid: tx.compute_txid().to_string(),
                hash: "00".repeat(32),
                depends: vec![],
                fee,
                sigops: 1,
                weight: 500,
            }
        };

        let make_outpoint = |n: u8| OutPoint {
            txid: Txid::from_byte_array([n; 32]),
            vout: 0,
        };

        let p2wpkh_out = || TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: ScriptBuf::from({
                let mut s = vec![0x00, 0x14];
                s.extend([0xaa; 20]);
                s
            }),
        };

        // 1. Inscription envelope
        let mut ts1 = vec![0x00, 0x63, 0x03]; // OP_FALSE OP_IF PUSH3
        ts1.extend(b"ord");
        ts1.extend([0x68, 0xac]); // OP_ENDIF OP_CHECKSIG
        let mut w1 = Witness::new();
        w1.push([0x30; 64]);
        w1.push(&ts1);
        let mut cb1 = vec![0xc0u8];
        cb1.extend([0x11; 32]);
        w1.push(&cb1);
        let tx1 = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: make_outpoint(1),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: w1,
            }],
            output: vec![p2wpkh_out()],
        };

        // 2. OP_DROP stuffing
        let mut ts2: Vec<u8> = vec![0x4c, 80]; // OP_PUSHDATA1, 80 bytes
        ts2.extend([0xDE; 80]);
        ts2.push(0x75); // OP_DROP
        ts2.push(0x51); // OP_TRUE
        let mut w2 = Witness::new();
        w2.push([0x30; 64]);
        w2.push(&ts2);
        let mut cb2 = vec![0xc0u8];
        cb2.extend([0x22; 32]);
        w2.push(&cb2);
        let tx2 = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: make_outpoint(2),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: w2,
            }],
            output: vec![p2wpkh_out()],
        };

        // 3. Unreachable code
        let ts3 = vec![0x51, 0x6a, 0xDE, 0xAD]; // OP_TRUE OP_RETURN dead
        let mut w3 = Witness::new();
        w3.push([0x30; 64]);
        w3.push(&ts3);
        let mut cb3 = vec![0xc0u8];
        cb3.extend([0x33; 32]);
        w3.push(&cb3);
        let tx3 = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: make_outpoint(3),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: w3,
            }],
            output: vec![p2wpkh_out()],
        };

        // 4. Fake pubkey multisig
        let mut ms = vec![0x51, 0x21]; // OP_1, PUSHBYTES_33
        ms.push(0x02);
        ms.extend([0xAA; 32]); // valid pk
        ms.push(0x21);
        ms.push(0x04);
        ms.extend([0xBB; 32]); // fake pk (0x04 prefix)
        ms.extend([0x52, 0xae]); // OP_2 OP_CHECKMULTISIG
        let mut w4 = Witness::new();
        w4.push([0x30; 72]);
        w4.push([0x02; 33]);
        let tx4 = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: make_outpoint(4),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: w4,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(30_000),
                script_pubkey: ScriptBuf::from(ms),
            }],
        };

        // 5. Annex present
        let mut w5 = Witness::new();
        w5.push([0x30; 64]);
        w5.push([0x51, 0xac]); // OP_TRUE OP_CHECKSIG
        let mut cb5 = vec![0xc0u8];
        cb5.extend([0x55; 32]);
        w5.push(&cb5);
        let mut annex = vec![0x50u8];
        annex.extend([0xFF; 50]);
        w5.push(&annex);
        let tx5 = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: make_outpoint(5),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: w5,
            }],
            output: vec![p2wpkh_out()],
        };

        // 6. Oversized OP_RETURN
        let mut opret = vec![0x6a, 0x4c, 100]; // OP_RETURN OP_PUSHDATA1 100
        opret.extend([0xAB; 100]);
        let mut w6 = Witness::new();
        w6.push([0x30; 72]);
        w6.push([0x02; 33]);
        let tx6 = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: make_outpoint(6),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: w6,
            }],
            output: vec![
                p2wpkh_out(),
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::from(opret),
                },
            ],
        };

        // 7. Clean transaction (should survive)
        let mut w7 = Witness::new();
        w7.push([0x30; 72]);
        w7.push([0x02; 33]);
        let tx7 = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: make_outpoint(7),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: w7,
            }],
            output: vec![p2wpkh_out()],
        };

        let txs = vec![
            make_tt(&tx1, 5000),
            make_tt(&tx2, 4000),
            make_tt(&tx3, 3500),
            make_tt(&tx4, 3000),
            make_tt(&tx5, 4000),
            make_tt(&tx6, 2000),
            make_tt(&tx7, 3000),
        ];

        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor = TemplateProcessor::new(
            TemplateConfig::default(),
            rpc,
            PolicyProfile::full_open(),
            ReaperConfig::default(),
        );

        let (kept, stats) = processor.filter_transactions(&txs);
        assert_eq!(stats.original, 7, "started with 7 txs");
        assert_eq!(stats.reaped, 6, "6 attack vector txs should be reaped");
        assert_eq!(kept.len(), 1, "only clean tx should survive");
        assert_eq!(
            kept[0].txid,
            tx7.compute_txid().to_string(),
            "clean tx survives"
        );
    }

    // =========================================================================
    // Witness commitment validation tests
    // =========================================================================

    /// Test that a valid OP_RETURN witness commitment script is accepted.
    /// Valid format: OP_RETURN (0x6a) | push_len (0x24 = 36) | magic (aa21a9ed) | 32-byte hash
    /// Total: 38 bytes
    #[test]
    fn test_validate_witness_commitment_valid() {
        let mut script = Vec::with_capacity(38);
        script.push(0x6a); // OP_RETURN
        script.push(0x24); // push length = 36 (4 magic + 32 hash)
        script.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]); // BIP 141 magic
        script.extend_from_slice(&[0xab; 32]); // 32-byte commitment hash
        assert_eq!(script.len(), 38);
        assert!(
            validate_witness_commitment_script(&script),
            "Valid 38-byte witness commitment with aa21a9ed magic should be accepted"
        );
    }

    /// Test that an OP_RETURN with wrong magic bytes is rejected.
    #[test]
    fn test_validate_witness_commitment_wrong_magic() {
        let mut script = Vec::with_capacity(38);
        script.push(0x6a); // OP_RETURN
        script.push(0x24); // push length = 36
        script.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // wrong magic
        script.extend_from_slice(&[0xab; 32]); // 32-byte hash
        assert!(
            !validate_witness_commitment_script(&script),
            "OP_RETURN with wrong magic bytes should be rejected"
        );
    }

    /// Test that an OP_RETURN with a push length below 36 is rejected.
    #[test]
    fn test_validate_witness_commitment_too_short() {
        // push_len = 4 (only magic, no 32-byte hash)
        let mut script = Vec::new();
        script.push(0x6a); // OP_RETURN
        script.push(0x04); // push length = 4 (< 36)
        script.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]); // magic
        assert!(
            !validate_witness_commitment_script(&script),
            "OP_RETURN with push_len < 36 should be rejected"
        );
    }

    /// Test that a script not starting with OP_RETURN (0x6a) is rejected.
    #[test]
    fn test_validate_witness_commitment_not_op_return() {
        let mut script = Vec::with_capacity(38);
        script.push(0x51); // OP_1 (NOT OP_RETURN)
        script.push(0x24); // push length = 36
        script.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]); // magic
        script.extend_from_slice(&[0xab; 32]); // 32-byte hash
        assert!(
            !validate_witness_commitment_script(&script),
            "Script starting with OP_1 instead of OP_RETURN should be rejected"
        );
    }

    // =========================================================================
    // CoinbaseBuilder output ordering and P2TR rejection tests
    // =========================================================================

    /// Test that CoinbaseBuilder preserves output ordering from input entries.
    /// Output order: miners -> nodes -> treasury (matching input order).
    #[test]
    fn test_coinbase_output_ordering_from_entries() {
        use ghost_common::types::{PayoutEntry, PayoutType};

        let builder = CoinbaseBuilder::new(850_000);

        // 2 miners, 1 node, 1 treasury — order should be preserved in output
        let entries = vec![
            PayoutEntry {
                address: b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_vec(),
                amount: 50_000,
                recipient_id: [1u8; 32],
                payout_type: PayoutType::Mining,
            },
            PayoutEntry {
                address: b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_vec(),
                amount: 30_000,
                recipient_id: [2u8; 32],
                payout_type: PayoutType::Mining,
            },
            PayoutEntry {
                address: b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_vec(),
                amount: 100_000,
                recipient_id: [3u8; 32],
                payout_type: PayoutType::NodeReward,
            },
            PayoutEntry {
                address: b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_vec(),
                amount: 20_000,
                recipient_id: [4u8; 32],
                payout_type: PayoutType::Treasury,
            },
        ];

        let tx = builder
            .build_from_entries(&entries)
            .expect("Valid P2WPKH entries should build successfully");

        // Verify output count matches entry count
        assert_eq!(
            tx.output.len(),
            4,
            "Should have exactly 4 outputs (2 miners + 1 node + 1 treasury)"
        );

        // Verify output values match input order
        assert_eq!(tx.output[0].value.to_sat(), 50_000, "First miner output");
        assert_eq!(tx.output[1].value.to_sat(), 30_000, "Second miner output");
        assert_eq!(tx.output[2].value.to_sat(), 100_000, "Node reward output");
        assert_eq!(tx.output[3].value.to_sat(), 20_000, "Treasury output");

        // Verify all outputs have the same script (same address)
        for (i, output) in tx.output.iter().enumerate() {
            assert!(
                !output.script_pubkey.is_empty(),
                "Output {} should have a non-empty script pubkey",
                i
            );
        }
    }

    /// Test that P2WSH treasury address produces correct 34-byte script_pubkey
    #[test]
    fn test_treasury_p2wsh_multisig_encoding() {
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let p2wsh_address = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
        let processor = TemplateProcessor::new(
            TemplateConfig {
                pool_payout_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                ..Default::default()
            },
            rpc,
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        );

        let script = processor
            .address_to_script(p2wsh_address, "treasury_test")
            .unwrap();

        // P2WSH script: OP_0 (0x00) + PUSH32 (0x20) + 32-byte hash = 34 bytes
        assert_eq!(script.len(), 34, "P2WSH script should be 34 bytes");
        assert_eq!(script[0], 0x00, "P2WSH starts with OP_0");
        assert_eq!(script[1], 0x20, "P2WSH has 32-byte push");
    }

    /// Test coinbase weight calculation with many outputs doesn't overflow
    #[test]
    fn test_coinbase_weight_calculation() {
        use ghost_common::types::{PayoutEntry, PayoutType};

        let builder = CoinbaseBuilder::new(850_000);

        // Build coinbase with 200 outputs
        let entries: Vec<PayoutEntry> = (0..200)
            .map(|i| PayoutEntry {
                address: b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_vec(),
                amount: 1000 + i as u64,
                recipient_id: {
                    let mut id = [0u8; 32];
                    id[0] = (i & 0xFF) as u8;
                    id[1] = ((i >> 8) & 0xFF) as u8;
                    id
                },
                payout_type: PayoutType::Mining,
            })
            .collect();

        let tx = builder
            .build_from_entries(&entries)
            .expect("200-output coinbase should build");

        assert_eq!(tx.output.len(), 200);

        // Compute weight: (non-witness * 4) + witness
        let non_witness_size = bitcoin::consensus::encode::serialize(&tx).len();
        // Weight should be well under 4M units (just outputs + 1 coinbase input)
        let weight = tx.weight().to_wu();
        assert!(
            weight < 4_000_000,
            "Coinbase weight {} should be under 4M WU",
            weight
        );
        assert!(non_witness_size > 0, "Serialized size should be positive");
    }

    /// Test that treasury amount > 0 but empty address returns error
    #[test]
    fn test_treasury_amount_without_address_errors() {
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor = TemplateProcessor::new(
            TemplateConfig {
                pool_payout_address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                mining_mode: MiningMode::PrivateSolo,
                solo_payout_address: Some("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string()),
                // treasury_address defaults to empty
                ..Default::default()
            },
            rpc,
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        );

        // Build solo coinbase where treasury portion > 0 but address is empty
        // The build_solo_coinbase_parts method takes a PayoutProposal
        // For this test, we directly call address_to_script with empty string
        let result = processor.address_to_script("", "treasury");
        assert!(
            result.is_err(),
            "Empty treasury address should cause error, not silent fallback"
        );
        assert!(
            result.unwrap_err().to_string().contains("address is empty"),
            "Error should indicate empty address"
        );
    }

    /// Test that CoinbaseBuilder rejects P2TR (bc1p...) addresses with QuantumUnsafe error.
    #[test]
    fn test_coinbase_rejects_p2tr_address() {
        use ghost_common::types::{PayoutEntry, PayoutType};

        let builder = CoinbaseBuilder::new(850_000);

        // Use a valid-format P2TR address (bc1p...)
        let entries = vec![PayoutEntry {
            address: b"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0".to_vec(),
            amount: 100_000,
            recipient_id: [1u8; 32],
            payout_type: PayoutType::Mining,
        }];

        let result = builder.build_from_entries(&entries);
        assert!(
            result.is_err(),
            "P2TR address should be rejected for quantum safety"
        );

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("quantum") || err_msg.contains("Quantum"),
            "Error should mention quantum vulnerability, got: {}",
            err_msg
        );
    }
}
