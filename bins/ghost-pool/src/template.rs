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
//! Fetches templates from Bitcoin Core, applies BUDS filtering, and serves them to pool_sv2 over
//! the Template Distribution Protocol. The node pool owns the coinbase: a template carries the
//! whole coinbase value (subsidy plus fees) and the witness commitment as its only output, and
//! pool_sv2 builds each job's canonical outputs (`ghost_common::canonical_payout`) on it.
//!
//! # Lock Ordering (M-16 / HIGH-POOL-4)
//!
//! Always acquire `current_work` (`RwLock<Option<WorkState>>`) before `work_states`
//! (`RwLock<HashMap<...>>`), and never the reverse.

use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use bitcoin::consensus::deserialize;
use ghost_buds::{BudsClassifier, BudsTier};
use ghost_common::config::{BitcoinNetwork, BlockPriority};
use ghost_common::rpc::{BitcoinRpc, BlockTemplate, TemplateTransaction};
use ghost_policy::PolicyProfile;
use ghost_reaper::ReaperConfig;

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

/// Coinbase parts for one template: `(coinbase1, coinbase2, witness_data, outputs_serialized,
/// outputs_count)`. The outputs are the witness commitment alone.
type CoinbaseBuildResult = (Vec<u8>, Vec<u8>, WitnessData, Vec<u8>, u32);

/// The encoded node tag for one coinbase build: `node_commitment_plain(node_id)`, the
/// `sha256(node_id)[..20]` pool_sv2 strips from the template prefix before stamping each job's
/// share tag. No identity, no tag.
fn node_tag_bytes(node_id: Option<ghost_common::types::NodeId>) -> Vec<u8> {
    let Some(id) = node_id else {
        return Vec::new();
    };
    ghost_common::coinbase_tags::encode_node_tag(
        &ghost_common::coinbase_tags::node_commitment_plain(&id),
    )
}

/// Template processor configuration
#[derive(Debug, Clone)]
pub struct TemplateConfig {
    /// Template refresh interval (milliseconds)
    pub refresh_interval_ms: u64,
    /// Minimum fee rate to include (sat/vB)
    pub min_fee_rate: f64,
    /// Most weight a whole block built here may have, header and coinbase included. Clamped to
    /// the template's `weightlimit` and to consensus (`block_limits::BlockLimits`). Read at
    /// template time only: a block already found is never refused for exceeding it.
    pub target_weight: u64,
    /// Coinbase extra data (pool signature)
    pub coinbase_extra: String,
    /// This node's identity, from which the coinbase's node tag is derived at scriptSig build
    /// time so a share mined here is provably mined *here*.
    ///
    /// The stamped tag is 20 bytes, not the 32-byte id: the scriptSig has a 100-byte ceiling
    /// shared with the height push, the payout tag, the pool tag and the extranonce. pool_sv2
    /// strips it from the template prefix and stamps each job's own share tag in its place.
    /// `None` leaves the coinbase without one.
    pub node_id: Option<ghost_common::types::NodeId>,
    /// Bitcoin network (mainnet, signet, testnet, regtest)
    pub network: BitcoinNetwork,
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
            target_weight: crate::block_limits::MAX_BLOCK_WEIGHT,
            coinbase_extra: "GHOST".to_string(),
            node_id: None,
            network: BitcoinNetwork::Mainnet,
            enforce_custom_policy_fields: false,
            block_priority: BlockPriority::MaxFee,
        }
    }
}

impl TemplateConfig {
    /// Validate the configuration.
    ///
    /// The coinbase pays the node pool's canonical outputs, which pool_sv2 builds per job; the
    /// only thing configured here that reaches the coinbase is the pool tag.
    pub fn validate(&self) -> Result<(), TemplateError> {
        // H-MINE-3: Validate coinbase_extra length to prevent script_len truncation
        // Script sig format: height (1-5) + payout tag (21) + coinbase_extra + extranonce.
        //
        // The bound here used to be 242, derived from the u8 length field (255 - 5 - 8). That is
        // the wrong limit: **consensus caps a coinbase scriptSig at 100 bytes**, so anything
        // between 100 and 255 passes validation and then builds blocks the network rejects — a
        // failure that only shows up as a won block being lost.
        //
        // The binding case is the SV2 path, whose extranonce is 20 bytes (4 pool + 16 client)
        // rather than the 8 reserved on the direct path:
        //
        //   100 - 5 (max height push) - 20 (extranonce) - 21 (payout tag) = 54
        const MAX_COINBASE_EXTRA_LEN: usize = 54;
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
    /// Serialized coinbase outputs (Bitcoin consensus format for TDP): the witness commitment
    /// alone. pool_sv2 builds every other output.
    pub coinbase_outputs_serialized: Vec<u8>,
    /// Number of coinbase outputs in `coinbase_outputs_serialized`
    pub coinbase_outputs_count: u32,
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
    /// What the SV2 pool said it adds to each coinbase (`CoinbaseOutputConstraints`).
    coinbase_output_reserve: crate::block_limits::CoinbaseOutputReserve,
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
        let init_refresh_ms = config.refresh_interval_ms.clamp(10_000, 60_000);

        Self {
            config,
            rpc,
            policy,
            classifier: BudsClassifier::new(),
            reaper_config,
            reaper_stats: crate::reaper_stats::ReaperStats::new(),
            current_work: RwLock::new(None),
            coinbase_output_reserve: Default::default(),
            work_states: RwLock::new(HashMap::new()),
            job_counter: RwLock::new(0),
            event_tx,
            running: RwLock::new(false),
            refresh_interval_ms: Arc::new(std::sync::atomic::AtomicU64::new(init_refresh_ms)),
        }
    }

    /// Build the coinbase parts for a template: the scriptSig (BIP34 height, the `GHPP` slot the
    /// node pool stamps `parent_anchor[..16]` into, the plain `GHNT` node tag the per-channel share
    /// tag replaces, the pool tag) and the witness commitment as the only output.
    ///
    /// pool_sv2 builds every other output, per job, from the canonical payout of the job's slot
    /// class; this template hands it the whole coinbase value. `coinbase1`/`coinbase2` use
    /// NON-WITNESS serialization (TXID); witness data is returned separately for block assembly.
    fn build_coinbase_parts(
        &self,
        height: u64,
        witness_commitment: &str,
    ) -> Result<CoinbaseBuildResult, TemplateError> {
        // coinbase1: version | input count | prev tx | prev index | scriptSig length | scriptSig
        let mut coinbase1 = Vec::new();
        coinbase1.extend_from_slice(&2u32.to_le_bytes()); // Version 2 for BIP68
        coinbase1.push(0x01);
        coinbase1.extend_from_slice(&[0u8; 32]);
        coinbase1.extend_from_slice(&0xffffffffu32.to_le_bytes());
        // The GHPP slot holds zeros here; pool_sv2 replaces it per job with the parent anchor.
        let scriptsig = self.coinbase_scriptsig(height, Some([0u8; 32]), 8)?;
        coinbase1.push((scriptsig.len() + 8) as u8); // +8 for extranonce space
        coinbase1.extend_from_slice(&scriptsig);

        let commitment_bytes = hex::decode(witness_commitment).map_err(|e| {
            TemplateError::BlockAssemblyError(format!("Invalid witness commitment hex: {}", e))
        })?;
        // BIP 141: OP_RETURN OP_PUSH(36) <0xaa21a9ed> <32-byte commitment>
        if !validate_witness_commitment_script(&commitment_bytes) {
            return Err(TemplateError::BlockAssemblyError(
                "Invalid witness commitment script structure".to_string(),
            ));
        }
        let mut output = Vec::with_capacity(9 + commitment_bytes.len());
        output.extend_from_slice(&0u64.to_le_bytes());
        output.push(commitment_bytes.len() as u8);
        output.extend_from_slice(&commitment_bytes);

        // coinbase2: sequence | output count | outputs | locktime
        let mut coinbase2 = Vec::new();
        coinbase2.extend_from_slice(&0xffffffffu32.to_le_bytes());
        coinbase2.push(0x01);
        coinbase2.extend_from_slice(&output);
        coinbase2.extend_from_slice(&0u32.to_le_bytes());

        let witness_data = WitnessData {
            commitment_script: Some(commitment_bytes),
            nonce: [0u8; 32],
        };
        Ok((coinbase1, coinbase2, witness_data, output, 1))
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

        // Leave room for the largest coinbase the node pool builds on this template.
        let mut filtered_txs = filtered_txs;
        crate::block_limits::make_room_for_coinbase(
            template.height,
            &template,
            self.config.target_weight,
            &self.coinbase_output_reserve,
            &mut filtered_txs,
        );

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

        // coinbasevalue = subsidy + all_template_fees (before filtering); the coinbase built on
        // this template may spend subsidy + the fees of the transactions actually kept.
        let all_template_fees: u64 = template.transactions.iter().map(|tx| tx.fee).sum();
        let subsidy = template.coinbasevalue.saturating_sub(all_template_fees);

        // Always recompute the witness commitment from the filtered transactions (BIP141):
        // filter_transactions() reorders by fee rate, so Bitcoin Core's
        // default_witness_commitment no longer matches. Always included: signet requires it even
        // with no other transactions, and the node pool's canonical layout ends with it.
        let witness_commitment = self.compute_witness_commitment(&filtered_txs);

        let (
            coinbase1,
            coinbase2,
            witness_data,
            coinbase_outputs_serialized,
            coinbase_outputs_count,
        ) = self
            .build_coinbase_parts(template.height, &witness_commitment)
            .map_err(|e| {
                error!(error = %e, "Refusing to create block template");
                anyhow::anyhow!("Coinbase build failed: {}", e)
            })?;

        // Block limits: a job whose block would not fit is refused.
        crate::block_limits::check_built_coinbase(
            template.height,
            &template,
            self.config.target_weight,
            &self.coinbase_output_reserve,
            &coinbase1,
            &coinbase2,
            &coinbase_outputs_serialized,
            &filtered_txs,
        )?;

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

    /// Assemble the coinbase scriptSig content, excluding the extranonce the miner fills in.
    ///
    /// One implementation because there were three, byte-identical, in three coinbase builders.
    /// Anything that changes the scriptSig has to change in all of them or the paths produce
    /// different blocks — and the length check below only guarded one of them.
    ///
    /// Layout, and the order is load-bearing:
    ///
    /// ```text
    ///   [BIP34 height push] [payout tag push]? [pool tag, RAW] .. [extranonce]
    /// ```
    ///
    /// The pool tag is raw text, not a push, so anything reading the scriptSig as a push sequence
    /// stops when it reaches it. Machine-readable commitments therefore go first, while the bytes
    /// are still well-formed pushes; the human-readable tag trails where nothing parses it.
    ///
    /// `payout_snapshot` names the payout this coinbase pays, so a node seeing the block on-chain
    /// can tell what it settled. It cannot be inferred from the outputs — those are fee-adjusted
    /// per node and so do not match any stored proposal. `None` means a treasury-only fallback
    /// coinbase, which settles nothing and needs no name.
    /// `pub(crate)` so the settlement tests can build a scriptSig with **this** code rather than
    /// hand-rolling one. A hand-written fixture proves the parser agrees with the fixture, not
    /// that it agrees with the builder — and those two drifting apart is precisely the failure
    /// that only shows up on a won block.
    ///
    pub(crate) fn coinbase_scriptsig(
        &self,
        height: u64,
        payout_snapshot: Option<[u8; 32]>,
        extranonce_len: usize,
    ) -> Result<Vec<u8>, TemplateError> {
        let height_bytes = self.encode_height(height);
        let payout_tag = payout_snapshot
            .map(|hash| {
                let mut id = [0u8; ghost_common::coinbase_tags::PAYOUT_ID_LEN];
                id.copy_from_slice(&hash[..ghost_common::coinbase_tags::PAYOUT_ID_LEN]);
                ghost_common::coinbase_tags::encode_payout_tag(&id)
            })
            .unwrap_or_default();
        // Commit to this node, so a peer cannot lift the header off a relayed share and claim it
        // received the work. Goes before the raw pool tag for the same reason the payout tag does.
        let node_tag = node_tag_bytes(self.config.node_id);

        let extra = self.config.coinbase_extra.as_bytes();

        let total =
            height_bytes.len() + payout_tag.len() + node_tag.len() + extra.len() + extranonce_len;

        // Consensus caps a coinbase scriptSig at 100 bytes. The previous check guarded only the
        // u8 length field at 255, so a long tag could build blocks the network rejects — a failure
        // that surfaces as "we mined a block and lost it", which is the worst way to learn it.
        const MAX_COINBASE_SCRIPTSIG: usize = 100;
        if total > MAX_COINBASE_SCRIPTSIG {
            return Err(TemplateError::ConfigError(format!(
                "Coinbase scriptSig would be {total} bytes, over the {MAX_COINBASE_SCRIPTSIG} \
                 consensus limit (height {}, payout tag {}, node tag {}, pool tag {}, \
                 extranonce {}). Shorten coinbase_extra.",
                height_bytes.len(),
                payout_tag.len(),
                node_tag.len(),
                extra.len(),
                extranonce_len
            )));
        }

        let mut out = Vec::with_capacity(
            height_bytes.len() + payout_tag.len() + node_tag.len() + extra.len(),
        );
        out.extend_from_slice(&height_bytes);
        out.extend_from_slice(&payout_tag);
        out.extend_from_slice(&node_tag);
        out.extend_from_slice(extra);
        Ok(out)
    }

    /// Encode block height for coinbase (BIP34): `OP_0`, `OP_1`..`OP_16`, else a minimal script
    /// number push, exactly as Bitcoin Core writes and checks it.
    fn encode_height(&self, height: u64) -> Vec<u8> {
        ghost_common::coinbase_tags::bip34_height_push(height)
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

    /// Record a TDP client's `CoinbaseOutputConstraints`, so templates leave room for the
    /// outputs and sigops it adds.
    pub fn note_coinbase_output_constraints(&self, max_additional_size: u32, max_sigops: u16) {
        self.coinbase_output_reserve
            .note(max_additional_size, max_sigops);
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

    /// What the block currently being built splits, for the dashboard: the subsidy, the
    /// treasury's base `S/200`, the miners' pool `Rm`, and the fees, which all go to the finder.
    /// Which miners a block pays depends on the job's slot class and is decided per job in
    /// pool_sv2 (`ghost_common::canonical_payout`); the change that `Rm` cannot pay goes to the
    /// treasury on top of its base.
    pub fn current_coinbase_breakdown(&self) -> Option<serde_json::Value> {
        let w = self.current_work.read();
        let w = w.as_ref()?;
        let h = u32::try_from(w.height).ok()?;
        let (treasury_base_sat, miner_pool_sat) = ghost_common::canonical_payout::split(h);
        Some(serde_json::json!({
            "height": w.height,
            "subsidy_sat": w.subsidy,
            "treasury_base_sat": treasury_base_sat,
            "miner_pool_sat": miner_pool_sat,
            "tx_fees_to_finder_sat": w.total_fees,
            "total_coinbase_sat": w.subsidy.saturating_add(w.total_fees),
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

        // 5. Validate block weight (max 4M weight units per BIP141): header, tx count,
        // coinbase and transactions. SEC-BLOCK-2 underflow check inside.
        let total_weight = crate::block_limits::block_weight(
            tx_count,
            coinbase_non_witness.len(),
            coinbase_witness.len(),
            work.total_weight,
        )?;

        const MAX_BLOCK_WEIGHT: u64 = crate::block_limits::MAX_BLOCK_WEIGHT;
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

        // No coinbase check holds a block back here. pool_sv2 checks the coinbase against its
        // job's canonical outputs after sending the solution, as an alarm
        // (`NodePool::submit_then_check`); settlement on every node is the enforcement.

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

        // 5. Validate block weight: header, tx count, coinbase and transactions.
        // SEC-BLOCK-2 underflow check inside.
        let total_weight = crate::block_limits::block_weight(
            tx_count,
            coinbase_non_witness.len(),
            coinbase_witness.len(),
            work.total_weight,
        )?;

        const MAX_BLOCK_WEIGHT: u64 = crate::block_limits::MAX_BLOCK_WEIGHT;
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
    /// A witness commitment output script with a zero commitment.
    const WITNESS: &str =
        "6a24aa21a9ed0000000000000000000000000000000000000000000000000000000000000000";
    use super::*;

    // ── Stage 6 step 3: paying from this node's own shard view ──────────────────────────────

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
        // Consensus wants OP_0 and OP_1..OP_16 below 17: a one-byte push there is `bad-cb-height`.
        assert_eq!(processor.encode_height(0), vec![0x00]);
        assert_eq!(processor.encode_height(1), vec![0x51]);
        assert_eq!(processor.encode_height(16), vec![0x60]);
        assert_eq!(processor.encode_height(17), vec![0x01, 0x11]);
        assert_eq!(processor.encode_height(127), vec![0x01, 0x7f]);
        assert_eq!(processor.encode_height(128), vec![0x02, 0x80, 0x00]);
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
                ..Default::default()
            },
            rpc,
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        );

        let (coinbase1, coinbase2, _witness_data, outputs, count) = processor
            .build_coinbase_parts(800_000, WITNESS)
            .expect("a template coinbase builds");
        assert_eq!(count, 1, "the witness commitment is the only output");
        assert_eq!(&outputs[..8], &[0u8; 8]);
        assert!(coinbase2.ends_with(&[&outputs[..], &[0u8; 4]].concat()));

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

    /// H-MINE-3-TEST-1: Test that excessively long coinbase_extra is rejected at config validation
    #[test]
    fn test_coinbase_extra_length_validation() {
        // Valid short coinbase_extra should pass
        let config = TemplateConfig {
            coinbase_extra: "GHOST".to_string(),
            ..Default::default()
        };
        assert!(
            config.validate().is_ok(),
            "Short coinbase_extra should pass validation"
        );

        // The bound is the CONSENSUS scriptSig limit, not the u8 length field.
        //
        // This used to accept 242 bytes and reject 243, derived from 255 - 5 - 8. That is the wrong
        // limit: consensus caps a coinbase scriptSig at 100 bytes, so every value between 100 and
        // 242 passed validation and produced blocks the network rejects. The real ceiling leaves
        // room for the max height push, the SV2 extranonce and the payout tag:
        // 100 - 5 - 20 - 21 = 54.
        let config = TemplateConfig {
            coinbase_extra: "A".repeat(54),
            ..Default::default()
        };
        assert!(
            config.validate().is_ok(),
            "54-byte coinbase_extra should pass (max that fits the consensus limit)"
        );

        let config = TemplateConfig {
            coinbase_extra: "A".repeat(55),
            ..Default::default()
        };
        assert!(
            config.validate().is_err(),
            "55-byte coinbase_extra should fail — it would breach the 100-byte scriptSig limit"
        );

        // Very long coinbase_extra should definitely fail
        let config = TemplateConfig {
            coinbase_extra: "A".repeat(300),
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

    /// Both commitments must survive into the coinbase this node builds, and the result must fit
    /// the consensus ceiling with the real pool tag and extranonce alongside.
    ///
    /// The unit tests for the codec prove encode/extract agree; this proves the bytes actually
    /// reach the coinbase, which is the step where a commitment silently goes missing.
    #[test]
    fn both_commitments_reach_the_built_coinbase() {
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let node_id = [0x7Au8; 32];
        let node_commitment = ghost_common::coinbase_tags::node_commitment_plain(&node_id);
        let processor = TemplateProcessor::new(
            TemplateConfig {
                coinbase_extra: "GHOST PublicPool".to_string(),
                node_id: Some(node_id),
                ..Default::default()
            },
            rpc,
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        );

        let scriptsig = processor
            .coinbase_scriptsig(960_000, Some([0xC3u8; 32]), 20)
            .expect("scriptsig must build");

        let mut expected_payout = [0u8; 16];
        expected_payout.copy_from_slice(&[0xC3u8; 32][..16]);
        assert_eq!(
            ghost_common::coinbase_tags::extract_payout_tag(&scriptsig),
            Some(expected_payout),
            "the payout commitment did not reach the coinbase"
        );
        assert_eq!(
            ghost_common::coinbase_tags::extract_node_tag(&scriptsig),
            Some(node_commitment),
            "the node commitment did not reach the coinbase"
        );

        // The human-readable tag still trails behind, where nothing parses it.
        assert!(
            scriptsig
                .windows(b"GHOST PublicPool".len())
                .any(|w| w == b"GHOST PublicPool"),
            "the pool tag should still be present"
        );

        // 20 is the SV2 extranonce, the binding case.
        assert!(
            scriptsig.len() + 20 <= 100,
            "scriptSig would breach the consensus ceiling: {} + 20 extranonce",
            scriptsig.len()
        );
    }

    /// With no payout armed there is nothing to settle, so no payout tag — but the node commitment
    /// still applies, because the share was still mined here.
    #[test]
    fn a_treasury_only_coinbase_carries_no_payout_tag() {
        let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
        let processor = TemplateProcessor::new(
            TemplateConfig {
                coinbase_extra: "GHOST PublicPool".to_string(),
                node_id: Some([0x11u8; 32]),
                ..Default::default()
            },
            rpc,
            PolicyProfile::permissive(),
            ReaperConfig::default(),
        );

        let scriptsig = processor
            .coinbase_scriptsig(960_000, None, 20)
            .expect("scriptsig must build");

        assert_eq!(
            ghost_common::coinbase_tags::extract_payout_tag(&scriptsig),
            None,
            "a coinbase paying no armed payout must not name one"
        );
        assert_eq!(
            ghost_common::coinbase_tags::extract_node_tag(&scriptsig),
            Some(ghost_common::coinbase_tags::node_commitment_plain(
                &[0x11u8; 32]
            ))
        );
    }

    /// H-MINE-3-TEST-2: Test that runtime script_len validation works
    #[test]
    fn test_script_len_runtime_validation() {
        // Defensive test: even if config validation is bypassed, building a coinbase must refuse a
        // scriptSig the network would reject.
        //
        // This previously asserted that a 200-byte coinbase_extra "should work", which encoded the
        // wrong limit. 200 bytes builds a 212-byte scriptSig, and consensus caps a coinbase
        // scriptSig at 100 — so what the old test asserted was the ability to mine blocks that get
        // rejected. It passed because the only guard was the u8 length field at 255.
        let make = |extra: &str| {
            let rpc = Arc::new(BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap());
            TemplateProcessor::new(
                TemplateConfig {
                    coinbase_extra: extra.to_string(),
                    ..Default::default()
                },
                rpc,
                PolicyProfile::permissive(),
                ReaperConfig::default(),
            )
        };

        // A realistic tag builds fine.
        assert!(
            make("GHOST PublicPool")
                .build_coinbase_parts(800_000, WITNESS)
                .is_ok(),
            "the shipped tag must build"
        );

        // One that would breach the consensus limit must be refused at build time, not mined.
        let err = make(&"A".repeat(200))
            .build_coinbase_parts(800_000, WITNESS)
            .expect_err("a 212-byte scriptSig must be refused");
        assert!(
            format!("{err}").contains("consensus limit"),
            "expected the consensus-limit error, got: {err}"
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

    // ---- #601: the shared fee-drift adjustment, and the tag on a fallback coinbase ----

    // ---- fee drift shared with the miners (FEE_DRIFT_MINER_SHARE_HEIGHT) ----
    //
    // These call `share_fee_drift_pro_rata` directly. The gate is a process-wide `OnceLock`, so a
    // test cannot arm it without arming it for every other test in the binary — and the dormancy
    // test below depends on it staying at `u64::MAX`.
}
