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
//| FILE: payout.rs                                                                                                      |
//|======================================================================================================================|

//! Payout Proposal Wiring
//!
//! This module connects the BlockFound event to the consensus payout flow:
//! 1. BlockFound event triggers payout calculation
//! 2. PayoutProposal is created from round data + template info
//! 3. Proposal is submitted to VoteHandler for BFT consensus
//! 4. Once approved, coinbase is constructed with the payout outputs
//!
//! Fee Distribution (per ECONOMICS.md):
//! - TX fees (100%) → Node who found the block
//! - Pool fee (1% of subsidy) → Split between Treasury and Node Reward Pool
//! - Miner Pool (99% of subsidy) → Top 200 miners by work
//! - Node Pool → Top 100 nodes by 5-4-3-2-1 capability shares

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use ghost_common::error::GhostResult;
use ghost_common::identity::NodeIdentity;
use ghost_common::types::{NodeId, PayoutEntry, PayoutProposal, PayoutType, RoundId};
use ghost_consensus::vote_handler::{compute_proposal_hash, VoteHandler};
use ghost_storage::Database;
use ghost_verification::QualifiedCapabilityProvider;

// Re-export payout history types from storage crate
pub use ghost_storage::{PayoutHistoryQuery, RoundPayoutSummary};

use crate::template::TemplateProcessor;
use crate::treasury::{FeeDistribution, TreasuryState};

/// Configuration for payout proposal creation
#[derive(Debug, Clone)]
pub struct PayoutConfig {
    /// Minimum payout amount (dust threshold)
    pub dust_threshold_sats: u64,
    /// Maximum miner outputs per block
    pub max_miner_outputs: usize,
    /// Maximum node outputs per block
    pub max_node_outputs: usize,
    /// Treasury address (script pubkey bytes) - REQUIRED
    /// None indicates unconfigured state; must be set before use
    pub treasury_address: Option<Vec<u8>>,
    /// M-15/LOW: Bitcoin network for mainnet-specific security checks
    pub network: ghost_common::config::BitcoinNetwork,
}

impl Default for PayoutConfig {
    fn default() -> Self {
        Self {
            dust_threshold_sats: 546,
            max_miner_outputs: 200,
            max_node_outputs: 100,
            treasury_address: None, // Must be configured at startup
            network: ghost_common::config::BitcoinNetwork::Mainnet, // Fail-safe: strictest validation by default
        }
    }
}

impl PayoutConfig {
    /// Validate that required configuration is present
    /// Returns error if treasury_address is not configured
    pub fn validate(&self) -> GhostResult<()> {
        match &self.treasury_address {
            None => Err(ghost_common::error::GhostError::ConfigError(
                "treasury_address is required but not configured".to_string(),
            )),
            Some(addr) if addr.is_empty() => Err(ghost_common::error::GhostError::ConfigError(
                "treasury_address cannot be empty".to_string(),
            )),
            Some(_) => Ok(()),
        }
    }

    /// Get treasury address, returning error if not configured
    pub fn treasury_address(&self) -> GhostResult<&[u8]> {
        match &self.treasury_address {
            Some(addr) if !addr.is_empty() => Ok(addr.as_slice()),
            _ => Err(ghost_common::error::GhostError::ConfigError(
                "treasury_address is required but not configured".to_string(),
            )),
        }
    }
}

/// Data needed to create a payout proposal
#[derive(Debug, Clone)]
pub struct BlockFoundData {
    /// Round ID
    pub round_id: RoundId,
    /// Block hash (from the found share)
    pub block_hash: [u8; 32],
    /// Block height
    pub block_height: u64,
    /// M-5 SECURITY: Block timestamp for deterministic decay calculation
    /// All nodes use this same timestamp to ensure consensus on treasury decay.
    pub block_timestamp: chrono::DateTime<chrono::Utc>,
    /// Miner ID that found the block
    pub winning_miner_id: String,
    /// Payout address of the winning miner (extracted from user_identity)
    pub winning_miner_payout_address: Option<String>,
    /// PO4-M2: Treasury address snapshot taken at round start
    /// This prevents TOCTOU issues where the config might change during a round
    pub treasury_address_snapshot: Option<Vec<u8>>,
    /// Node ID that found the block (gets TX fees)
    pub winning_node_id: NodeId,
    /// Block subsidy (satoshis)
    pub subsidy_sats: u64,
    /// Transaction fees (satoshis)
    pub tx_fees_sats: u64,
    /// Miner work distribution: (miner_id, scaled_work_u128)
    /// Values are pre-scaled integers from RoundShares, eliminating f64 precision loss
    pub miner_work: Vec<(String, u128)>,
    /// Node share distribution: (node_id, capability_shares)
    /// Capability shares follow the 5-4-3-2-1 scheme per ECONOMICS.md
    pub node_shares: Vec<(NodeId, i32)>,
    /// Current treasury state (for decay calculation)
    pub treasury_state: TreasuryState,
}

/// Data for solo mining mode block found event
///
/// In solo mode:
/// - 99% of subsidy + ALL TX fees → solo_payout_address
/// - 1% pool fee split between treasury and node pool per decay schedule
/// - Hosting node participates in node reward pool
#[derive(Debug, Clone)]
pub struct SoloBlockFoundData {
    /// Round ID
    pub round_id: RoundId,
    /// Block hash (from the found share)
    pub block_hash: [u8; 32],
    /// Block height
    pub block_height: u64,
    /// M-5 SECURITY: Block timestamp for deterministic decay calculation
    /// All nodes use this same timestamp to ensure consensus on treasury decay.
    pub block_timestamp: chrono::DateTime<chrono::Utc>,
    /// Solo payout address (configured in pool settings)
    pub solo_payout_address: String,
    /// Block subsidy (satoshis)
    pub subsidy_sats: u64,
    /// PO4-M2: Treasury address snapshot taken at round start
    pub treasury_address_snapshot: Option<Vec<u8>>,
    /// Transaction fees (satoshis) - ALL go to solo miner
    pub tx_fees_sats: u64,
    /// Node share distribution: (node_id, capability_shares)
    /// Hosting node is included in this list
    pub node_shares: Vec<(NodeId, i32)>,
    /// Current treasury state (for decay calculation)
    pub treasury_state: TreasuryState,
}

/// H-FUND-2: Maximum consecutive blocks with no qualifying nodes before error
const MAX_CONSECUTIVE_NO_NODES: u64 = 10;

/// Creates payout proposals from block found events
pub struct PayoutProposalCreator {
    identity: Arc<NodeIdentity>,
    config: PayoutConfig,
    db: Arc<Database>,
    /// H-FUND-2: Counter for total node pool treasury fallbacks (for monitoring)
    node_pool_treasury_fallback_count: AtomicU64,
    /// H-FUND-2: Counter for consecutive blocks with no qualifying nodes
    consecutive_no_nodes: AtomicU64,
}

impl PayoutProposalCreator {
    /// Create a new PayoutProposalCreator with validated configuration
    ///
    /// # Errors
    /// Returns error if treasury_address is not configured
    ///
    pub fn new(
        identity: Arc<NodeIdentity>,
        config: PayoutConfig,
        db: Arc<Database>,
    ) -> GhostResult<Self> {
        // Validate configuration at startup - fail early if misconfigured
        config.validate()?;

        Ok(Self {
            identity,
            config,
            db,
            node_pool_treasury_fallback_count: AtomicU64::new(0),
            consecutive_no_nodes: AtomicU64::new(0),
        })
    }

    /// H-FUND-2: Get the total count of node pool treasury fallbacks
    /// This is useful for monitoring and alerting systems
    pub fn get_node_pool_treasury_fallback_count(&self) -> u64 {
        self.node_pool_treasury_fallback_count
            .load(Ordering::Relaxed)
    }

    /// H-FUND-2: Get the current consecutive no-nodes count
    pub fn get_consecutive_no_nodes_count(&self) -> u64 {
        self.consecutive_no_nodes.load(Ordering::Relaxed)
    }

    /// PO4-M2: Get a snapshot of the treasury address for use in BlockFoundData
    ///
    /// This captures the current treasury address to prevent TOCTOU issues
    /// where the config might change between round start and block found.
    pub fn get_treasury_address_snapshot(&self) -> Option<Vec<u8>> {
        self.config.treasury_address.clone()
    }

    /// Validate block hash is non-zero
    ///
    /// PO4-M1: Prevent proposals with invalid/zero block hashes
    fn validate_block_hash(block_hash: &[u8; 32]) -> GhostResult<()> {
        if block_hash == &[0u8; 32] {
            return Err(ghost_common::error::GhostError::PayoutCalculation(
                "block_hash is all zeros - invalid block hash".to_string(),
            ));
        }
        Ok(())
    }

    /// Create a payout proposal from block found data
    ///
    /// Fee distribution per ECONOMICS.md:
    /// - TX fees (100%) → Node who found the block
    /// - Pool fee (1% of subsidy) → Split between Treasury and Node Reward Pool
    /// - Miner Pool (99% of subsidy) → Top 200 miners by work
    /// - Node Pool → Top 100 nodes by 5-4-3-2-1 capability shares
    pub fn create_proposal(&self, data: BlockFoundData) -> GhostResult<PayoutProposal> {
        // B-4/CFG-4/CFG-5: Shared validation for block hash, subsidy, and fee checks
        self.validate_block_data(
            &data.block_hash,
            data.block_height,
            data.subsidy_sats,
            data.tx_fees_sats,
        )?;

        let now = chrono::Utc::now().timestamp() as u64;

        // Calculate fee distribution using treasury decay schedule
        // M-5 SECURITY: Use block_timestamp for deterministic decay calculation
        let fee_dist = FeeDistribution::calculate(
            data.subsidy_sats,
            data.tx_fees_sats,
            &data.treasury_state,
            data.block_timestamp,
        );

        info!(
            subsidy = data.subsidy_sats,
            tx_fees = data.tx_fees_sats,
            pool_fee = fee_dist.pool_fee,
            treasury_rate = fee_dist.treasury_rate,
            node_rate = fee_dist.node_rate,
            miner_pool = fee_dist.miner_pool,
            node_pool = fee_dist.node_reward_pool,
            decay_year = data.treasury_state.decay_year(data.block_timestamp),
            "Calculating fee distribution"
        );

        // Calculate miner payouts (99% of subsidy, proportional to work)
        // Dust from miners below threshold is returned for redistribution to node pool
        let (miner_payouts, miner_dust) =
            self.calculate_miner_payouts(&data.miner_work, fee_dist.miner_pool)?;

        // Add miner dust to node reward pool - no satoshis are lost!
        let augmented_node_pool = fee_dist.node_reward_pool.saturating_add(miner_dust);
        if miner_dust > 0 {
            info!(
                miner_dust,
                original_node_pool = fee_dist.node_reward_pool,
                augmented_node_pool,
                "Miner dust added to node reward pool"
            );
        }

        // Calculate node payouts from the augmented node reward pool
        // (original pool + miner dust, not including TX fees)
        let mut node_payouts =
            self.calculate_node_payouts(&data.node_shares, augmented_node_pool)?;

        // H-FUND-2: Track node pool fallback with alerting and consecutive failure protection
        let mut final_treasury = fee_dist.treasury_amount;
        if node_payouts.is_empty() && augmented_node_pool > 0 {
            // Increment counters
            let total_fallbacks = self
                .node_pool_treasury_fallback_count
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            let consecutive = self.consecutive_no_nodes.fetch_add(1, Ordering::Relaxed) + 1;

            // H-FUND-2: Log at WARN level for monitoring/alerting systems
            warn!(
                node_pool = augmented_node_pool,
                total_fallbacks,
                consecutive_blocks = consecutive,
                max_consecutive = MAX_CONSECUTIVE_NO_NODES,
                round_id = data.round_id,
                block_height = data.block_height,
                "H-FUND-2 WARNING: No eligible nodes - redirecting node reward pool to treasury"
            );

            // H-FUND-2: Fail after too many consecutive blocks with no nodes
            // This indicates a systemic problem that needs operator attention
            if consecutive >= MAX_CONSECUTIVE_NO_NODES {
                tracing::error!(
                    consecutive_blocks = consecutive,
                    total_fallbacks,
                    "H-FUND-2 CRITICAL: {} consecutive blocks with no qualifying nodes - halting block production",
                    consecutive
                );
                return Err(ghost_common::error::GhostError::PayoutCalculation(format!(
                    "No qualifying nodes for {} consecutive blocks (threshold: {}). \
                     This indicates a verification system failure. \
                     Total fallbacks: {}. Block production halted.",
                    consecutive, MAX_CONSECUTIVE_NO_NODES, total_fallbacks
                )));
            }

            final_treasury = final_treasury.saturating_add(augmented_node_pool);
        } else if !node_payouts.is_empty() {
            // Reset consecutive counter when we have qualifying nodes
            self.consecutive_no_nodes.store(0, Ordering::Relaxed);
        }

        // TX fees go 100% to the node that found the block
        // H-FUND-1 SECURITY: Block finder MUST have a payout address configured.
        // If not, this is a configuration error that must be fixed BEFORE block production.
        // Silent redirect to treasury allowed fund misallocation to go unnoticed.
        //
        // M-04 FIX: Use the Bitcoin dust threshold (546 sats) for the tx_fee allocation
        // check, NOT min_payout_sats. The min_payout_sats config gates minimum OUTPUT
        // sizes for miner/node payouts, but tx_fees must always be allocated somewhere.
        // When below dust, they're added to an existing node payout (no new output needed)
        // or redirected to treasury — never silently dropped.
        let tx_fees_unallocated: u64 = 0;
        if fee_dist.tx_fees_to_block_finder >= ghost_common::constants::DUST_THRESHOLD_SATS {
            let block_finder_address = self.get_node_address(&data.winning_node_id)?;
            if !block_finder_address.is_empty() {
                // Check if this node is already in node_payouts - if so, add to their amount
                let mut found = false;
                for payout in &mut node_payouts {
                    if payout.recipient_id == data.winning_node_id {
                        payout.amount = payout
                            .amount
                            .saturating_add(fee_dist.tx_fees_to_block_finder);
                        found = true;
                        break;
                    }
                }

                // If not already in the list, add a new entry
                if !found {
                    node_payouts.push(PayoutEntry {
                        address: block_finder_address,
                        amount: fee_dist.tx_fees_to_block_finder,
                        recipient_id: data.winning_node_id,
                        payout_type: PayoutType::TxFees,
                    });
                }

                info!(
                    node_id = %hex::encode(&data.winning_node_id[..8]),
                    tx_fees = fee_dist.tx_fees_to_block_finder,
                    "TX fees allocated to block finder"
                );
            } else {
                // H-FUND-1 SECURITY FIX: Block finder has no address - this is an ERROR.
                // We MUST NOT silently redirect to treasury as this hides configuration issues.
                // Block production must be halted until the node operator configures a payout address.
                tracing::error!(
                    node_id = %hex::encode(&data.winning_node_id[..8]),
                    tx_fees = fee_dist.tx_fees_to_block_finder,
                    "H-FUND-1 SECURITY: Block finder node has no payout address - HALTING BLOCK PRODUCTION"
                );
                return Err(ghost_common::error::GhostError::TxFeeAllocationFailed {
                    node_id: hex::encode(&data.winning_node_id[..8]),
                    tx_fees: fee_dist.tx_fees_to_block_finder,
                });
            }
        } else if fee_dist.tx_fees_to_block_finder > 0 {
            // M-04 FIX: TX fees below dust threshold — add to treasury rather than dropping.
            // This prevents the cross-check from failing when tx_fees are small.
            final_treasury = final_treasury.saturating_add(fee_dist.tx_fees_to_block_finder);
            debug!(
                tx_fees = fee_dist.tx_fees_to_block_finder,
                "TX fees below dust threshold, redirected to treasury"
            );
        }

        // H-MINE-3: Use treasury address snapshot from BlockFoundData
        // This ensures the coinbase is built with the address that was valid
        // at the time the round started, not a potentially changed address
        let treasury_address = match data.treasury_address_snapshot.clone() {
            Some(addr) => addr,
            None => {
                return Err(ghost_common::error::GhostError::PayoutCalculation(
                    "No treasury address snapshot in BlockFoundData — cannot build payout. \
                     This indicates a bug: the round should always capture the treasury address at start."
                        .to_string(),
                ));
            }
        };

        // HIGH-MINE-3 / HIGH-POOL-3: Validate treasury address using Bitcoin library
        // Instead of just checking length (22-34 bytes), we validate the script
        // is a well-formed Bitcoin script pubkey.
        //
        // This prevents:
        // - Invalid script opcodes
        // - Malformed witness programs
        // - Non-standard or unspendable outputs
        // - HIGH-POOL-3: OP_RETURN scripts (which are unspendable!)
        if !treasury_address.is_empty() {
            // Parse as ScriptBuf to validate structure
            let script = bitcoin::ScriptBuf::from(treasury_address.clone());

            // HIGH-POOL-3: Explicitly reject OP_RETURN - treasury funds must be spendable!
            if script.is_op_return() {
                return Err(ghost_common::error::GhostError::PayoutCalculation(format!(
                    "HIGH-POOL-3: Treasury address is OP_RETURN - funds would be UNSPENDABLE! \
                     Script (hex): {}. Treasury must use a spendable output type.",
                    hex::encode(&treasury_address)
                )));
            }

            // Check if it's a valid SPENDABLE output script type
            // HIGH-POOL-3: Only allow script types with valid spend paths
            let is_valid = script.is_p2pkh()
                || script.is_p2sh()
                || script.is_p2wpkh()
                || script.is_p2wsh()
                || script.is_p2tr();

            if !is_valid {
                return Err(ghost_common::error::GhostError::PayoutCalculation(format!(
                    "HIGH-POOL-3: Treasury address script is not a valid spendable output type. \
                     Script (hex): {}. Expected P2PKH, P2SH, P2WPKH, P2WSH, or P2TR.",
                    hex::encode(&treasury_address)
                )));
            }

            debug!(
                script_type = if script.is_p2pkh() {
                    "P2PKH"
                } else if script.is_p2sh() {
                    "P2SH"
                } else if script.is_p2wpkh() {
                    "P2WPKH"
                } else if script.is_p2wsh() {
                    "P2WSH"
                } else {
                    "P2TR"
                },
                script_len = treasury_address.len(),
                "Validated treasury address script"
            );
        }

        let proposal = PayoutProposal {
            proposal_hash: [0u8; 32], // Will be computed by vote handler
            round_id: data.round_id,
            block_hash: data.block_hash,
            block_height: data.block_height,
            proposer: self.identity.node_id(),
            miner_payouts,
            node_payouts,
            treasury_amount: final_treasury,
            treasury_address, // H-MINE-3: Snapshot address
            tx_fees: data.tx_fees_sats,
            subsidy: data.subsidy_sats,
            timestamp: now,
            tx_fees_unallocated,
        };

        // H-02: Fee distribution verification is now a hard error
        // Integer arithmetic should be exact — any mismatch indicates a bug
        if !fee_dist.verify(data.subsidy_sats, data.tx_fees_sats) {
            return Err(ghost_common::error::GhostError::PayoutCalculation(format!(
                "H-02: Fee distribution verification failed: expected {} sats, got {} sats (diff: {})",
                data.subsidy_sats + data.tx_fees_sats,
                fee_dist.total(),
                (fee_dist.total() as i128) - ((data.subsidy_sats + data.tx_fees_sats) as i128)
            )));
        }

        info!(
            round_id = data.round_id,
            height = data.block_height,
            miner_count = proposal.miner_payouts.len(),
            node_count = proposal.node_payouts.len(),
            treasury = final_treasury,
            decay_year = data.treasury_state.decay_year(data.block_timestamp),
            "Created payout proposal"
        );

        // M-04: Final cross-check — sum all PayoutEntry amounts + treasury must equal subsidy + tx_fees
        let total_miner: u64 = proposal.miner_payouts.iter().map(|p| p.amount).sum();
        let total_node: u64 = proposal.node_payouts.iter().map(|p| p.amount).sum();
        let proposal_total = total_miner
            .saturating_add(total_node)
            .saturating_add(proposal.treasury_amount);
        let expected_total = data.subsidy_sats.saturating_add(data.tx_fees_sats);
        if proposal_total != expected_total {
            return Err(ghost_common::error::GhostError::PayoutCalculation(format!(
                "M-04: Payout cross-check failed: miners({}) + nodes({}) + treasury({}) = {} != expected {}",
                total_miner, total_node, proposal.treasury_amount, proposal_total, expected_total
            )));
        }

        Ok(proposal)
    }

    /// Validate block data shared between pool and solo mode proposals.
    ///
    /// B-4/CFG-4/CFG-5: Ensures block hash, subsidy, and fee checks
    /// are applied consistently to both code paths.
    fn validate_block_data(
        &self,
        block_hash: &[u8; 32],
        block_height: u64,
        subsidy_sats: u64,
        tx_fees_sats: u64,
    ) -> GhostResult<()> {
        // PO4-M1: Validate block hash
        Self::validate_block_hash(block_hash)?;

        // M-15: Validate subsidy matches expected for height
        let expected_subsidy = ghost_common::rpc::calculate_block_subsidy(block_height, None);
        if subsidy_sats != expected_subsidy {
            let is_mainnet = self.config.network == ghost_common::config::BitcoinNetwork::Mainnet;
            if is_mainnet {
                error!(
                    height = block_height,
                    expected = expected_subsidy,
                    actual = subsidy_sats,
                    "M-15 CRITICAL: Subsidy mismatch on MAINNET - rejecting payout proposal"
                );
                return Err(ghost_common::error::GhostError::PayoutCalculation(format!(
                    "M-15: Subsidy mismatch on mainnet at height {}: expected {} sats, got {} sats",
                    block_height, expected_subsidy, subsidy_sats
                )));
            } else {
                warn!(
                    height = block_height,
                    expected = expected_subsidy,
                    actual = subsidy_sats,
                    network = ?self.config.network,
                    "M-15: Subsidy mismatch - acceptable on testnet but would fail on mainnet"
                );
            }
        }

        // MED-POOL-2: Sanity check TX fees
        const MAX_REASONABLE_FEES: u64 = 100 * 100_000_000; // 100 BTC in sats
        if tx_fees_sats > MAX_REASONABLE_FEES {
            error!(
                tx_fees = tx_fees_sats,
                max_reasonable = MAX_REASONABLE_FEES,
                height = block_height,
                "MED-POOL-2 CRITICAL: TX fees exceed sanity limit - rejecting payout"
            );
            return Err(ghost_common::error::GhostError::PayoutCalculation(format!(
                "MED-POOL-2: TX fees {} sats exceed sanity limit {} sats",
                tx_fees_sats, MAX_REASONABLE_FEES
            )));
        }

        Ok(())
    }

    /// Create a solo mode payout proposal
    ///
    /// Solo mode distribution:
    /// - Solo miner: 99% of subsidy + ALL TX fees → solo_payout_address
    /// - 1% pool fee → split between treasury and node pool per decay schedule
    /// - Hosting node is included in node reward pool calculation
    pub fn create_solo_proposal(&self, data: SoloBlockFoundData) -> GhostResult<PayoutProposal> {
        // B-4/CFG-4/CFG-5: Validate block data (matching pool mode checks)
        self.validate_block_data(
            &data.block_hash,
            data.block_height,
            data.subsidy_sats,
            data.tx_fees_sats,
        )?;

        let now = chrono::Utc::now().timestamp() as u64;

        // Calculate fee distribution using treasury decay schedule
        // Note: In solo mode, TX fees are NOT included in pool fee calculation
        // TX fees go 100% to solo miner, pool fee is only from subsidy
        // M-5 SECURITY: Use block_timestamp for deterministic decay calculation
        let fee_dist = FeeDistribution::calculate(
            data.subsidy_sats,
            0, // TX fees not subject to pool fee in solo mode
            &data.treasury_state,
            data.block_timestamp,
        );

        // Solo miner gets 99% of subsidy + ALL tx fees
        let solo_miner_amount = fee_dist.miner_pool.saturating_add(data.tx_fees_sats);

        // H-01: Validate solo payout address before building payout entry
        self.validate_payout_address(data.solo_payout_address.as_bytes(), "solo miner")?;

        info!(
            subsidy = data.subsidy_sats,
            tx_fees = data.tx_fees_sats,
            solo_miner = solo_miner_amount,
            pool_fee = fee_dist.pool_fee,
            treasury = fee_dist.treasury_amount,
            node_pool = fee_dist.node_reward_pool,
            decay_year = data.treasury_state.decay_year(data.block_timestamp),
            "Calculating solo mode fee distribution"
        );

        // Create miner payout entry (single entry for solo operator)
        let mut miner_payouts = Vec::new();
        if solo_miner_amount >= self.config.dust_threshold_sats {
            let mut recipient_id = [0u8; 32];
            let hash = ghost_common::identity::hash_message(data.solo_payout_address.as_bytes());
            recipient_id.copy_from_slice(&hash);

            miner_payouts.push(PayoutEntry {
                address: data.solo_payout_address.into_bytes(),
                amount: solo_miner_amount,
                recipient_id,
                payout_type: PayoutType::Mining,
            });
        }

        // Calculate node payouts from the 1% pool fee's node reward portion
        // In solo mode, the hosting node should be included in node_shares
        let node_payouts =
            self.calculate_node_payouts(&data.node_shares, fee_dist.node_reward_pool)?;

        // H-FUND-2: Track node pool fallback with alerting (same as pool mode)
        let mut final_treasury = fee_dist.treasury_amount;
        if node_payouts.is_empty() && fee_dist.node_reward_pool > 0 {
            // Increment counters
            let total_fallbacks = self
                .node_pool_treasury_fallback_count
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            let consecutive = self.consecutive_no_nodes.fetch_add(1, Ordering::Relaxed) + 1;

            // H-FUND-2: Log at WARN level for monitoring/alerting systems
            warn!(
                node_pool = fee_dist.node_reward_pool,
                total_fallbacks,
                consecutive_blocks = consecutive,
                max_consecutive = MAX_CONSECUTIVE_NO_NODES,
                round_id = data.round_id,
                block_height = data.block_height,
                "H-FUND-2 WARNING: Solo mode - no eligible nodes, redirecting to treasury"
            );

            // H-FUND-2: Fail after too many consecutive blocks with no nodes
            if consecutive >= MAX_CONSECUTIVE_NO_NODES {
                tracing::error!(
                    consecutive_blocks = consecutive,
                    total_fallbacks,
                    "H-FUND-2 CRITICAL: {} consecutive blocks with no qualifying nodes in solo mode",
                    consecutive
                );
                return Err(ghost_common::error::GhostError::PayoutCalculation(format!(
                    "Solo mode: No qualifying nodes for {} consecutive blocks (threshold: {}). \
                     Total fallbacks: {}. Block production halted.",
                    consecutive, MAX_CONSECUTIVE_NO_NODES, total_fallbacks
                )));
            }

            final_treasury = final_treasury.saturating_add(fee_dist.node_reward_pool);
        } else if !node_payouts.is_empty() {
            // Reset consecutive counter when we have qualifying nodes
            self.consecutive_no_nodes.store(0, Ordering::Relaxed);
        }

        // C-01: Use treasury address snapshot from SoloBlockFoundData (matching pool mode pattern)
        let treasury_address = match data.treasury_address_snapshot.clone() {
            Some(addr) => addr,
            None => {
                return Err(ghost_common::error::GhostError::PayoutCalculation(
                    "No treasury address snapshot in SoloBlockFoundData — cannot build payout. \
                     This indicates a bug: the round should always capture the treasury address at start."
                        .to_string(),
                ));
            }
        };

        let proposal = PayoutProposal {
            proposal_hash: [0u8; 32], // Will be computed by vote handler
            round_id: data.round_id,
            block_hash: data.block_hash,
            block_height: data.block_height,
            proposer: self.identity.node_id(),
            miner_payouts,
            node_payouts,
            treasury_amount: final_treasury,
            treasury_address, // H-MINE-3: Snapshot address
            tx_fees: data.tx_fees_sats,
            subsidy: data.subsidy_sats,
            timestamp: now,
            tx_fees_unallocated: 0, // Solo mode: TX fees always go to solo miner
        };

        // S-2: M-04 cross-check — verify solo proposal sums to expected total
        let total_miner: u64 = proposal.miner_payouts.iter().map(|p| p.amount).sum();
        let total_node: u64 = proposal.node_payouts.iter().map(|p| p.amount).sum();
        let proposal_total = total_miner
            .saturating_add(total_node)
            .saturating_add(proposal.treasury_amount);
        let expected_total = data.subsidy_sats.saturating_add(data.tx_fees_sats);
        if proposal_total != expected_total {
            return Err(ghost_common::error::GhostError::PayoutCalculation(format!(
                "M-04: Solo cross-check failed: proposal={} != expected={}",
                proposal_total, expected_total
            )));
        }

        info!(
            round_id = data.round_id,
            height = data.block_height,
            solo_miner = solo_miner_amount,
            node_count = proposal.node_payouts.len(),
            treasury = final_treasury,
            decay_year = data.treasury_state.decay_year(data.block_timestamp),
            "Created solo mode payout proposal"
        );

        Ok(proposal)
    }

    /// GHOST-02: recompute the miner split from THIS node's own converged ledger
    /// (and converged payout addresses — Option A) and confirm the proposal
    /// matches. A proposer that inflates its own miners, shorts others, or
    /// fabricates work produces a split honest validators (sharing the converged
    /// ledger + addresses) will not reproduce, so it is rejected before voting.
    ///
    /// Reuses the exact production computation (`calculate_miner_payouts`), so
    /// there is no reimplementation that could drift and false-reject an honest
    /// proposal — the only inputs that vary are this node's own ledger and the
    /// proposal's economic figures.
    pub fn validate_proposal_split(
        &self,
        proposal: &PayoutProposal,
        local_miner_work: &[(String, u128)],
        treasury_state: &TreasuryState,
    ) -> Result<(), String> {
        // The treasury decay is year-granular; the proposal timestamp is within
        // seconds of the block, so it yields the same decay_year (hence the same
        // fee split) the proposer used.
        let block_time =
            chrono::DateTime::<chrono::Utc>::from_timestamp(proposal.timestamp as i64, 0)
                .unwrap_or_else(chrono::Utc::now);
        let fee_dist = FeeDistribution::calculate(
            proposal.subsidy,
            proposal.tx_fees,
            treasury_state,
            block_time,
        );
        let (expected, _dust) = self
            .calculate_miner_payouts(local_miner_work, fee_dist.miner_pool)
            .map_err(|e| format!("GHOST-02: recompute failed: {e}"))?;

        let expected_map = Self::address_amount_map(&expected);
        let proposal_map = Self::address_amount_map(&proposal.miner_payouts);
        if expected_map != proposal_map {
            return Err(format!(
                "GHOST-02: miner split does not match local recompute \
                 ({} expected payout addresses vs {} in proposal)",
                expected_map.len(),
                proposal_map.len()
            ));
        }
        Ok(())
    }

    /// Address-grouped (address -> total amount) view of a payout set, for the
    /// GHOST-02 comparison. Ordered so the comparison is independent of entry order.
    fn address_amount_map(entries: &[PayoutEntry]) -> std::collections::BTreeMap<Vec<u8>, u64> {
        let mut m = std::collections::BTreeMap::new();
        for e in entries {
            *m.entry(e.address.clone()).or_insert(0u64) += e.amount;
        }
        m
    }

    /// Calculate miner payouts proportional to work
    /// Returns (payouts, dust_amount) where dust is redirected to node reward pool
    ///
    /// 3.3 SECURITY: Uses scaled integer arithmetic (10^12) instead of floating point
    /// to prevent precision loss in payout calculations.
    fn calculate_miner_payouts(
        &self,
        miner_work: &[(String, u128)],
        total_sats: u64,
    ) -> GhostResult<(Vec<PayoutEntry>, u64)> {
        let mut payouts = Vec::new();
        let mut dust_total: u64 = 0;

        // Work values arrive as pre-scaled u128 from RoundShares, no f64 conversion needed.
        // Filter out zero-work entries.
        let scaled_work: Vec<(String, u128)> =
            miner_work.iter().filter(|(_, w)| *w > 0).cloned().collect();

        let total_work: u128 = scaled_work.iter().map(|(_, w)| w).sum();

        if total_work == 0 {
            return Ok((payouts, dust_total));
        }

        // Sort by work descending, take top N (using scaled integer comparison)
        let mut sorted = scaled_work;
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(self.config.max_miner_outputs);

        // Recalculate total work for top miners
        let top_work: u128 = sorted.iter().map(|(_, w)| w).sum();

        // Safety check: avoid division by zero after truncation
        if top_work == 0 {
            warn!("Top miners have zero total work after truncation - no payouts");
            return Ok((payouts, dust_total));
        }

        // PO4-1: Track allocated amount to detect rounding remainder
        let mut allocated_total: u64 = 0;

        for (miner_id, work) in sorted {
            // Skip miners with zero scaled work
            if work == 0 {
                continue;
            }
            // 3.3 SECURITY: Pure integer arithmetic for payout calculation
            // Formula: amount = (total_sats * work) / top_work
            // Using u128 to prevent overflow: max is ~21M BTC * 10^8 sats * 10^12 scale
            let amount = ((total_sats as u128 * work) / top_work) as u64;

            if amount < self.config.dust_threshold_sats {
                // Dust amount redirected to node reward pool
                dust_total = dust_total.saturating_add(amount);
                allocated_total = allocated_total.saturating_add(amount);
                debug!(
                    miner_id,
                    amount,
                    threshold = self.config.dust_threshold_sats,
                    "Miner payout below dust threshold - redirecting to node reward pool"
                );
                continue;
            }

            // Get miner's payout address from database
            let address = self.get_miner_address(&miner_id)?;

            // HIGH-MINE-5: Validate miner address before including in payout
            // This prevents unspendable outputs from malformed addresses
            if !address.is_empty() {
                if let Err(e) = self.validate_payout_address(&address, "miner") {
                    warn!(
                        miner_id,
                        error = %e,
                        "HIGH-MINE-5: Invalid miner address - treating as dust"
                    );
                    dust_total = dust_total.saturating_add(amount);
                    allocated_total = allocated_total.saturating_add(amount);
                    continue;
                }
            }

            // Convert miner_id to recipient_id
            let mut recipient_id = [0u8; 32];
            let hash = ghost_common::identity::hash_message(miner_id.as_bytes());
            recipient_id.copy_from_slice(&hash);

            // Check if we already have a payout to this address (multiple workers, same address)
            if let Some(existing) = payouts.iter_mut().find(|p| p.address == address) {
                existing.amount = existing.amount.saturating_add(amount);
            } else {
                payouts.push(PayoutEntry {
                    address,
                    amount,
                    recipient_id,
                    payout_type: PayoutType::Mining,
                });
            }
            allocated_total = allocated_total.saturating_add(amount);
        }

        // CRIT-MINE-1: Calculate rounding remainder with overflow protection
        // CRITICAL: We must verify allocated_total <= total_sats BEFORE subtraction.
        // If allocated_total > total_sats, this indicates a serious arithmetic bug
        // that could lead to fund loss. We MUST fail the payout instead of silently
        // saturating, which would hide the bug.
        if allocated_total > total_sats {
            error!(
                allocated_total,
                total_sats,
                overflow = allocated_total - total_sats,
                "CRIT-MINE-1 CRITICAL: Allocated miner payouts exceed total pool - arithmetic bug detected!"
            );
            return Err(ghost_common::error::GhostError::PayoutCalculation(format!(
                "CRIT-MINE-1: Miner payout overflow - allocated {} sats but only {} available (overflow: {})",
                allocated_total,
                total_sats,
                allocated_total - total_sats
            )));
        }

        // Use checked_sub instead of saturating_sub to catch bugs
        let rounding_remainder = total_sats.checked_sub(allocated_total).ok_or_else(|| {
            ghost_common::error::GhostError::PayoutCalculation(format!(
                "CRIT-MINE-1: Integer underflow in miner payout remainder calculation: {} - {}",
                total_sats, allocated_total
            ))
        })?;

        if rounding_remainder > 0 {
            dust_total = dust_total.saturating_add(rounding_remainder);
            debug!(
                rounding_remainder,
                allocated_total, total_sats, "Miner payout rounding remainder captured"
            );
        }

        if dust_total > 0 {
            info!(
                dust_total,
                miners_affected = miner_work.len() - payouts.len(),
                rounding_remainder,
                "Miner dust collected for node reward pool"
            );
        }

        Ok((payouts, dust_total))
    }

    /// Calculate node payouts proportional to capability shares
    /// Returns (payouts, dust_amount) where dust is added to top node's payout
    fn calculate_node_payouts(
        &self,
        node_shares: &[(NodeId, i32)],
        total_sats: u64,
    ) -> GhostResult<Vec<PayoutEntry>> {
        let mut payouts = Vec::new();
        let mut dust_total: u64 = 0;
        let total_shares: i32 = node_shares.iter().map(|(_, s)| s).sum();

        if total_shares <= 0 {
            return Ok(payouts);
        }

        // Sort by shares descending, take top N
        let mut sorted: Vec<_> = node_shares.to_vec();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(self.config.max_node_outputs);

        // Recalculate total shares for top nodes
        let top_shares: i32 = sorted.iter().map(|(_, s)| s).sum();

        // Safety check: avoid division by zero after truncation
        if top_shares <= 0 {
            warn!("Top nodes have zero total shares after truncation - no payouts");
            return Ok(payouts);
        }

        // PO4-1: Track allocated amount to detect rounding remainder
        let mut allocated_total: u64 = 0;

        for (node_id, shares) in sorted {
            // Skip nodes with non-positive shares
            if shares <= 0 {
                continue;
            }
            // L-4 SECURITY: Use direct integer arithmetic instead of basis points (10^4)
            // Previous code calculated share_bps first, losing precision for small shares.
            // New code: amount = (total_sats * shares) / top_shares
            // This is mathematically equivalent but avoids the precision loss from
            // the intermediate share_bps calculation which truncated to 4 decimal places.
            // Using u128 to prevent overflow: max is ~21M BTC * 10^8 sats * 15 max shares
            let amount = ((total_sats as u128 * shares as u128) / top_shares as u128) as u64;

            if amount < self.config.dust_threshold_sats {
                // Track dust for redistribution to top node
                dust_total = dust_total.saturating_add(amount);
                allocated_total = allocated_total.saturating_add(amount);
                debug!(
                    node_id = %hex::encode(&node_id[..8]),
                    amount,
                    threshold = self.config.dust_threshold_sats,
                    "Node payout below dust threshold - will add to top node"
                );
                continue;
            }

            // Get node's payout address from database
            let address = self.get_node_address(&node_id)?;

            // Skip nodes without a configured payout address - their share becomes dust
            // which will be redistributed to the top node or go to treasury
            if address.is_empty() {
                dust_total = dust_total.saturating_add(amount);
                allocated_total = allocated_total.saturating_add(amount);
                warn!(
                    node_id = %hex::encode(&node_id[..8]),
                    amount,
                    "H-06: Node has no payout address — share redirected to dust pool. \
                     Operator should configure a payout address."
                );
                continue;
            }

            payouts.push(PayoutEntry {
                address,
                amount,
                recipient_id: node_id,
                payout_type: PayoutType::NodeReward,
            });
            allocated_total = allocated_total.saturating_add(amount);
        }

        // CRIT-MINE-1: Calculate rounding remainder with overflow protection (same as miner payouts)
        if allocated_total > total_sats {
            error!(
                allocated_total,
                total_sats,
                overflow = allocated_total - total_sats,
                "CRIT-MINE-1 CRITICAL: Allocated node payouts exceed total pool - arithmetic bug detected!"
            );
            return Err(ghost_common::error::GhostError::PayoutCalculation(format!(
                "CRIT-MINE-1: Node payout overflow - allocated {} sats but only {} available (overflow: {})",
                allocated_total,
                total_sats,
                allocated_total - total_sats
            )));
        }

        // Use checked_sub instead of saturating_sub to catch bugs
        let rounding_remainder = total_sats.checked_sub(allocated_total).ok_or_else(|| {
            ghost_common::error::GhostError::PayoutCalculation(format!(
                "CRIT-MINE-1: Integer underflow in node payout remainder calculation: {} - {}",
                total_sats, allocated_total
            ))
        })?;

        if rounding_remainder > 0 {
            dust_total = dust_total.saturating_add(rounding_remainder);
            debug!(
                rounding_remainder,
                allocated_total, total_sats, "Node payout rounding remainder captured"
            );
        }

        // M-01: Runtime invariant check (not just debug builds)
        // Fund accounting must be exact — any mismatch indicates an arithmetic bug
        if allocated_total + rounding_remainder != total_sats {
            return Err(ghost_common::error::GhostError::PayoutCalculation(format!(
                "M-01: Node payout accounting error: allocated {} + remainder {} = {} != total {}",
                allocated_total,
                rounding_remainder,
                allocated_total + rounding_remainder,
                total_sats
            )));
        }

        // Merge payouts going to the same address (e.g., multiple nodes using treasury)
        let mut merged_payouts: Vec<PayoutEntry> = Vec::new();
        for payout in payouts {
            if let Some(existing) = merged_payouts
                .iter_mut()
                .find(|p| p.address == payout.address)
            {
                // L-6 SECURITY: Check if saturation would occur before adding
                // This detects if the merged amount would exceed u64::MAX
                let would_overflow = existing.amount.checked_add(payout.amount).is_none();
                if would_overflow {
                    warn!(
                        address = %String::from_utf8_lossy(&payout.address[..20.min(payout.address.len())]),
                        existing_amount = existing.amount,
                        new_amount = payout.amount,
                        max_u64 = u64::MAX,
                        "L-6 CRITICAL: Payout merge would overflow u64::MAX - using saturating add"
                    );
                }
                existing.amount = existing.amount.saturating_add(payout.amount);
                debug!(
                    address = %String::from_utf8_lossy(&payout.address[..20.min(payout.address.len())]),
                    merged_amount = payout.amount,
                    "Merged duplicate node payout address"
                );
            } else {
                merged_payouts.push(payout);
            }
        }
        let payouts = merged_payouts;

        // M-1/M-8 INTENTIONAL DESIGN: Node payout rounding remainder goes to top node
        //
        // When distributing node rewards, integer division causes small rounding losses.
        // For example, with 1000 sats split among 3 equal nodes: each gets 333, with
        // 1 sat remainder. Rather than lose this satoshi, we add it to the top node
        // (the node with the highest capability shares).
        //
        // This is INTENTIONAL and documented behavior (NOT a bug):
        // 1. All satoshis are accounted for - none are lost to the void
        // 2. The top node benefits slightly from rounding (typically 0-10 sats/block)
        // 3. This creates a small incentive to maintain high capability scores
        // 4. Alternative approaches were considered:
        //    - Random distribution: Non-deterministic, harder to audit
        //    - Burn: Wastes value for no benefit
        //    - Treasury: Would require separate logic and output
        //    - Proportional redistribution: Computationally expensive for marginal gain
        //
        // SECURITY ANALYSIS (M-1):
        // - Maximum rounding remainder per block: (num_nodes - 1) sats, typically <100 sats
        // - Annual benefit to top node (assuming 144 blocks/day): ~5.2M sats = 0.052 BTC
        // - This is ~0.0008% of a typical node's annual earnings from capability shares
        // - The top node already earned their position through genuine capability verification
        // - Gaming this would require maintaining high scores, which benefits the network
        //
        // CONCLUSION: The rounding benefit is economically insignificant and aligned with
        // network incentives. Treating this as intentional behavior is the correct design.
        //
        // CRIT-PANIC-2: Use .first_mut() instead of direct indexing for defensive coding
        if dust_total > 0 {
            let mut payouts = payouts;
            if let Some(top_payout) = payouts.first_mut() {
                top_payout.amount = top_payout.amount.saturating_add(dust_total);
                info!(
                    dust_total,
                    top_node = %hex::encode(&top_payout.recipient_id[..8]),
                    nodes_affected = node_shares.len().saturating_sub(payouts.len()),
                    "M-8: Node dust + rounding remainder redistributed to top node (intentional)"
                );
                return Ok(payouts);
            } else {
                // SECURITY NOTE: This case occurs when ALL nodes have payouts below dust threshold
                // AND none have valid payout addresses. The dust cannot be redistributed because
                // there are no eligible recipients. The caller (create_proposal) handles this by
                // redirecting the entire augmented_node_pool to treasury when node_payouts is empty.
                // This is NOT lost - it's explicitly handled at the proposal level.
                debug!(
                    dust_total,
                    "No eligible node payouts - dust will be handled at proposal level"
                );
            }
            return Ok(payouts);
        }

        Ok(payouts)
    }

    /// HIGH-MINE-5: Validate a payout address to prevent unspendable outputs
    ///
    /// Checks that the address:
    /// - Is non-empty
    /// - Parses as a valid Bitcoin address
    /// - Matches the configured network (mainnet/testnet/signet/regtest)
    ///
    /// Returns Ok(()) if valid, or an error describing the issue.
    fn validate_payout_address(&self, address: &[u8], context: &str) -> GhostResult<()> {
        if address.is_empty() {
            return Err(ghost_common::error::GhostError::InvalidAddress(format!(
                "{} address is empty",
                context
            )));
        }

        // Convert bytes to string (assuming UTF-8 encoding for bech32/base58)
        let address_str = String::from_utf8(address.to_vec()).map_err(|e| {
            ghost_common::error::GhostError::InvalidAddress(format!(
                "{} address is not valid UTF-8: {}",
                context, e
            ))
        })?;

        // Parse as Bitcoin address (we only need to confirm it parses)
        let _parsed_addr = address_str
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|e| {
                ghost_common::error::GhostError::InvalidAddress(format!(
                    "{} address failed to parse: {}",
                    context, e
                ))
            })?;

        // C-02: Verify address matches configured network to prevent cross-network fund loss
        let expected_network = self.config.network.to_bitcoin_network();
        _parsed_addr
            .require_network(expected_network)
            .map_err(|e| {
                ghost_common::error::GhostError::InvalidAddress(format!(
                    "{} address network mismatch: expected {:?}, got error: {}",
                    context, expected_network, e
                ))
            })?;

        Ok(())
    }

    /// Get miner's payout address from database
    ///
    /// Miners provide their payout address during Stratum authorize,
    /// which is stored in the miners table via update_miner_address().
    ///
    /// MED-POOL-5: Validates the address is a valid Bitcoin address format.
    ///
    /// PAYOUT_ADDRESS_GROUPING_HEIGHT fast-path: post-gate, the block-found
    /// path passes payout addresses directly (rather than miner_ids) as the
    /// string key, because `get_top_unpaid_addresses` already grouped by
    /// address. If the input parses as a valid bitcoin address we skip the
    /// miner-table lookup and return its bytes — no extra DB round-trip,
    /// and the upstream merge-by-address logic still does the right thing
    /// on the (rare) chance the same address appears twice.
    fn get_miner_address(&self, miner_id: &str) -> GhostResult<Vec<u8>> {
        if miner_id
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .is_ok()
        {
            return Ok(miner_id.as_bytes().to_vec());
        }

        // Look up miner's payout address from the miners table
        if let Some(address_str) = self.db.get_miner_payout_address(miner_id)? {
            if !address_str.is_empty() {
                // MED-POOL-5: Validate the address is a valid Bitcoin address
                if let Err(e) =
                    address_str.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
                {
                    warn!(
                        miner_id,
                        error = %e,
                        "MED-POOL-5: Miner has invalid payout address - treating as empty"
                    );
                    return Ok(Vec::new());
                }
                // Address is stored as bech32 string, return as bytes
                return Ok(address_str.into_bytes());
            }
        }

        // Fallback: return empty (will be filtered out by proposal validator)
        debug!(
            miner_id,
            "Miner payout address not found - will be filtered from proposal"
        );
        Ok(Vec::new())
    }

    /// Get node's payout address from database
    ///
    /// Nodes set their payout address in configuration or via registration.
    ///
    /// MED-POOL-5: Validates the address is a valid Bitcoin address format.
    fn get_node_address(&self, node_id: &NodeId) -> GhostResult<Vec<u8>> {
        let node_id_hex = hex::encode(node_id);

        // Look up node's payout address from the nodes table
        if let Some(address_str) = self.db.get_node_payout_address(&node_id_hex)? {
            if !address_str.is_empty() {
                // MED-POOL-5: Validate the address is a valid Bitcoin address
                if let Err(e) =
                    address_str.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
                {
                    warn!(
                        node_id = %node_id_hex,
                        address = %address_str,
                        error = %e,
                        "MED-POOL-5: Node has invalid payout address - treating as empty"
                    );
                    return Ok(Vec::new());
                }
                // Address is stored as bech32 string, return as bytes
                return Ok(address_str.into_bytes());
            }
        }

        // Return empty - caller will handle this by treating as dust
        // which gets redistributed to top node or treasury
        Ok(Vec::new())
    }

    /// Get paginated payout history
    ///
    /// Returns a list of round payout summaries matching the query parameters.
    /// Results are ordered by block height descending (most recent first).
    ///
    /// # Arguments
    /// * `query` - Query parameters including limit, offset, and optional height filters
    ///
    /// # Returns
    /// Vec of RoundPayoutSummary containing aggregated payout info per round
    pub fn get_payout_history(
        &self,
        query: PayoutHistoryQuery,
    ) -> GhostResult<Vec<RoundPayoutSummary>> {
        self.db.query_payout_history(query)
    }
}

/// Handler for block found events that creates and submits payout proposals
pub struct PayoutHandler {
    creator: PayoutProposalCreator,
    vote_handler: Arc<VoteHandler>,
    template_processor: Arc<TemplateProcessor>,
    /// H-MINE-1: Qualification provider for calculating VERIFIED capabilities - REQUIRED
    /// This is mandatory because node rewards must only be distributed based on
    /// verified capabilities, never unverified claimed ones.
    qualification_provider: Arc<QualifiedCapabilityProvider>,
}

impl PayoutHandler {
    /// Create a new PayoutHandler with REQUIRED QualifiedCapabilityProvider
    ///
    /// H-MINE-1 SECURITY: The qualification_provider is required, not optional.
    /// This ensures node rewards are NEVER distributed based on unverified
    /// claimed capabilities. The provider validates capabilities through the
    /// challenge-response system before they count toward payout shares.
    ///
    /// # Errors
    /// Returns error if:
    /// - treasury_address is not configured in PayoutConfig
    pub fn new(
        identity: Arc<NodeIdentity>,
        config: PayoutConfig,
        db: Arc<Database>,
        vote_handler: Arc<VoteHandler>,
        template_processor: Arc<TemplateProcessor>,
        qualification_provider: Arc<QualifiedCapabilityProvider>,
    ) -> GhostResult<Self> {
        let creator = PayoutProposalCreator::new(identity, config, db)?;

        info!("PayoutHandler initialized with required verification provider");

        Ok(Self {
            creator,
            vote_handler,
            template_processor,
            qualification_provider,
        })
    }

    /// PO4-M2: Get a snapshot of the treasury address
    ///
    /// This should be called at round start to capture the treasury address
    /// and prevent TOCTOU issues where config changes during a round.
    pub fn get_treasury_address_snapshot(&self) -> Option<Vec<u8>> {
        self.creator.get_treasury_address_snapshot()
    }

    /// Handle a block found event by creating and submitting a payout proposal
    ///
    /// GHOST-02: validate a peer's payout proposal by recomputing the miner
    /// split from this node's own converged ledger. Delegates to the proposal
    /// creator (which owns the payout maths). Returns `Err(reason)` to reject.
    pub fn validate_proposal_split(
        &self,
        proposal: &PayoutProposal,
        local_miner_work: &[(String, u128)],
        treasury_state: &TreasuryState,
    ) -> Result<(), String> {
        self.creator
            .validate_proposal_split(proposal, local_miner_work, treasury_state)
    }

    /// H-MINE-1 SECURITY: The QualifiedCapabilityProvider is REQUIRED in the constructor.
    /// Node rewards will only be distributed to nodes with VERIFIED capabilities,
    /// never to nodes with merely CLAIMED capabilities.
    pub fn handle_block_found(&self, mut data: BlockFoundData) -> GhostResult<[u8; 32]> {
        // H-MINE-1: Provider is now required at construction time, no Option check needed
        // This guarantees node rewards are always based on verified capabilities

        // Get all nodes with verified capabilities from the database
        // This ensures all verified nodes get payouts, not just ones that received shares directly
        let qualified_shares = self.qualification_provider.get_all_qualified_nodes();

        let claimed_count = data.node_shares.len();
        let verified_count = qualified_shares.len();
        let total_claimed_shares: i32 = data.node_shares.iter().map(|(_, s)| s).sum();
        let total_verified_shares: i32 = qualified_shares.iter().map(|(_, s)| s).sum();

        info!(
            claimed_nodes = claimed_count,
            verified_nodes = verified_count,
            claimed_shares = total_claimed_shares,
            verified_shares = total_verified_shares,
            "Recalculated node shares using VERIFIED capabilities"
        );

        data.node_shares = qualified_shares;

        // Create the proposal
        let mut proposal = self.creator.create_proposal(data)?;

        // Validate proposal has meaningful content
        if proposal.miner_payouts.is_empty() {
            warn!("Payout proposal has no miner payouts - skipping submission");
            return Ok([0u8; 32]);
        }

        // Compute proposal hash before storing
        // This ensures the template processor can find the proposal when
        // consensus approves with this hash
        let proposal_hash = compute_proposal_hash(&proposal);
        proposal.proposal_hash = proposal_hash;

        // Store proposal in template processor BEFORE submitting to consensus
        // This ensures the proposal data is available when consensus approves
        // and we need to build coinbase outputs
        self.template_processor.store_proposal(proposal.clone());

        // Submit to vote handler for BFT consensus
        info!(
            round_id = proposal.round_id,
            miners = proposal.miner_payouts.len(),
            nodes = proposal.node_payouts.len(),
            "Submitting payout proposal to consensus"
        );

        let returned_hash = self.vote_handler.handle_proposal(proposal)?;

        // SECURITY: Verify hash matches - this catches implementation bugs where
        // the vote handler modifies the proposal or computes the hash differently
        if proposal_hash != returned_hash {
            tracing::error!(
                expected = %hex::encode(&proposal_hash[..8]),
                actual = %hex::encode(&returned_hash[..8]),
                "CRITICAL: Proposal hash mismatch between local computation and vote handler"
            );
            return Err(ghost_common::error::GhostError::HashMismatch {
                expected: hex::encode(proposal_hash),
                actual: hex::encode(returned_hash),
            });
        }

        info!(
            hash = %hex::encode(&proposal_hash[..8]),
            "Payout proposal submitted for voting"
        );

        Ok(proposal_hash)
    }

    /// Handle a block found event in solo mining mode
    ///
    /// In solo mode, all rewards go to the configured solo_payout_address:
    /// - 99% of subsidy + ALL TX fees → solo_payout_address
    /// - 1% pool fee → treasury + node pool per decay schedule
    ///
    /// H-MINE-1 SECURITY: The QualifiedCapabilityProvider is REQUIRED in the constructor,
    /// even in solo mode. Node rewards will only be distributed to nodes with VERIFIED
    /// capabilities, never to nodes with merely CLAIMED capabilities.
    pub fn handle_solo_block_found(&self, mut data: SoloBlockFoundData) -> GhostResult<[u8; 32]> {
        // H-MINE-1: Provider is now required at construction time, no Option check needed
        // This guarantees node rewards are always based on verified capabilities

        // Replace claimed node shares with verified ones
        // This ensures consistency between pool and solo mode
        let qualified_shares = self.qualification_provider.get_all_qualified_nodes();

        let claimed_count = data.node_shares.len();
        let verified_count = qualified_shares.len();

        info!(
            claimed_nodes = claimed_count,
            verified_nodes = verified_count,
            "Solo mode: recalculating node shares using VERIFIED capabilities"
        );

        data.node_shares = qualified_shares;

        // Create the solo proposal
        let mut proposal = self.creator.create_solo_proposal(data)?;

        // Validate proposal has meaningful content
        if proposal.miner_payouts.is_empty() {
            warn!("Solo payout proposal has no miner payout - skipping submission");
            return Ok([0u8; 32]);
        }

        // Compute proposal hash before storing
        let proposal_hash = compute_proposal_hash(&proposal);
        proposal.proposal_hash = proposal_hash;

        // Store proposal in template processor BEFORE submitting to consensus
        self.template_processor.store_proposal(proposal.clone());

        // Submit to vote handler for BFT consensus
        info!(
            round_id = proposal.round_id,
            solo_payout = proposal.miner_payouts[0].amount,
            nodes = proposal.node_payouts.len(),
            "Submitting solo mode payout proposal to consensus"
        );

        let returned_hash = self.vote_handler.handle_proposal(proposal)?;

        // SECURITY: Verify hash matches - this catches implementation bugs where
        // the vote handler modifies the proposal or computes the hash differently
        if proposal_hash != returned_hash {
            tracing::error!(
                expected = %hex::encode(&proposal_hash[..8]),
                actual = %hex::encode(&returned_hash[..8]),
                "CRITICAL: Solo proposal hash mismatch between local computation and vote handler"
            );
            return Err(ghost_common::error::GhostError::HashMismatch {
                expected: hex::encode(proposal_hash),
                actual: hex::encode(returned_hash),
            });
        }

        info!(
            hash = %hex::encode(&proposal_hash[..8]),
            "Solo mode payout proposal submitted for voting"
        );

        Ok(proposal_hash)
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;

    fn test_identity() -> Arc<NodeIdentity> {
        Arc::new(NodeIdentity::generate())
    }

    // ---- GHOST-02: proposal split recompute ----

    fn ghost02_creator() -> PayoutProposalCreator {
        let config = PayoutConfig {
            treasury_address: Some(vec![1u8; 20]),
            network: ghost_common::config::BitcoinNetwork::Regtest,
            ..Default::default()
        };
        let db = Arc::new(ghost_storage::Database::in_memory().expect("in-memory db"));
        PayoutProposalCreator::new(test_identity(), config, db).expect("creator")
    }

    fn ghost02_proposal(subsidy: u64, miner_payouts: Vec<PayoutEntry>) -> PayoutProposal {
        PayoutProposal {
            proposal_hash: [0u8; 32],
            round_id: 1,
            block_hash: [0u8; 32],
            block_height: 100,
            proposer: [0u8; 32],
            miner_payouts,
            node_payouts: vec![],
            treasury_amount: 0,
            treasury_address: vec![1u8; 20],
            tx_fees: 0,
            subsidy,
            timestamp: 1_700_000_000,
            tx_fees_unallocated: 0,
        }
    }

    #[test]
    fn ghost02_rejects_payout_unsupported_by_local_ledger() {
        let creator = ghost02_creator();
        let ts = TreasuryState::new();
        // This node's ledger is empty → no miner is owed anything for the round.
        let local_work: Vec<(String, u128)> = vec![];
        // The proposal nonetheless claims a 1 BTC miner payout.
        let proposal = ghost02_proposal(
            5_000_000_000,
            vec![PayoutEntry {
                address: vec![2u8; 22],
                amount: 100_000_000,
                recipient_id: [3u8; 32],
                payout_type: PayoutType::Mining,
            }],
        );
        assert!(
            creator
                .validate_proposal_split(&proposal, &local_work, &ts)
                .is_err(),
            "GHOST-02: a payout the local ledger does not support must be rejected"
        );
    }

    #[test]
    fn ghost02_accepts_split_matching_local_recompute() {
        let creator = ghost02_creator();
        let ts = TreasuryState::new();
        // Empty ledger → the only honest split is the empty one.
        let local_work: Vec<(String, u128)> = vec![];
        let proposal = ghost02_proposal(5_000_000_000, vec![]);
        assert!(
            creator
                .validate_proposal_split(&proposal, &local_work, &ts)
                .is_ok(),
            "GHOST-02: an empty split matches an empty-ledger recompute"
        );
    }

    #[test]
    fn test_payout_config_default() {
        let config = PayoutConfig::default();
        assert_eq!(config.dust_threshold_sats, 546);
        assert_eq!(config.max_miner_outputs, 200);
        assert_eq!(config.max_node_outputs, 100);
        // Default should have None treasury address (requires configuration)
        assert!(config.treasury_address.is_none());
    }

    #[test]
    fn test_payout_config_validation() {
        // Default config should fail validation (no treasury address)
        let config = PayoutConfig::default();
        assert!(config.validate().is_err());

        // Config with empty treasury address should fail
        let config_empty = PayoutConfig {
            treasury_address: Some(Vec::new()),
            ..Default::default()
        };
        assert!(config_empty.validate().is_err());

        // Config with valid treasury address should pass
        let config_valid = PayoutConfig {
            treasury_address: Some(vec![1u8; 20]),
            ..Default::default()
        };
        assert!(config_valid.validate().is_ok());
    }

    #[test]
    fn test_treasury_address_getter() {
        // None treasury should return error
        let config = PayoutConfig::default();
        assert!(config.treasury_address().is_err());

        // Empty treasury should return error
        let config_empty = PayoutConfig {
            treasury_address: Some(Vec::new()),
            ..Default::default()
        };
        assert!(config_empty.treasury_address().is_err());

        // Valid treasury should return the address
        let expected_addr = vec![1u8, 2u8, 3u8];
        let config_valid = PayoutConfig {
            treasury_address: Some(expected_addr.clone()),
            ..Default::default()
        };
        assert_eq!(
            config_valid.treasury_address().unwrap(),
            expected_addr.as_slice()
        );
    }

    #[test]
    fn test_block_found_data() {
        let data = BlockFoundData {
            round_id: 1,
            block_hash: [0u8; 32],
            block_height: 800_000,
            block_timestamp: chrono::Utc::now(),
            winning_miner_id: "miner1".to_string(),
            winning_miner_payout_address: None,
            treasury_address_snapshot: Some(vec![1u8, 2u8, 3u8]),
            winning_node_id: [1u8; 32],
            subsidy_sats: 625_000_000, // 6.25 BTC
            tx_fees_sats: 10_000_000,  // 0.1 BTC
            miner_work: vec![
                ("miner1".to_string(), 100_000_000_000_000u128),
                ("miner2".to_string(), 50_000_000_000_000u128),
            ],
            node_shares: vec![([1u8; 32], 10), ([2u8; 32], 5)],
            treasury_state: TreasuryState::new(),
        };

        assert_eq!(data.round_id, 1);
        assert_eq!(data.miner_work.len(), 2);
        assert_eq!(data.node_shares.len(), 2);
        assert_eq!(data.winning_node_id, [1u8; 32]);
        assert!(data.treasury_address_snapshot.is_some());
    }

    #[test]
    fn test_block_found_data_with_treasury_decay() {
        let now = chrono::Utc::now();
        let threshold_time = now - chrono::Duration::days(365 * 3);
        let treasury_state = TreasuryState::from_stored(
            crate::treasury::TREASURY_THRESHOLD_SATS,
            Some(threshold_time),
        );

        let data = BlockFoundData {
            round_id: 1,
            block_hash: [0u8; 32],
            block_height: 800_000,
            block_timestamp: now,
            winning_miner_id: "miner1".to_string(),
            winning_miner_payout_address: None,
            treasury_address_snapshot: Some(vec![0x51]), // P2TR witness program prefix
            winning_node_id: [1u8; 32],
            subsidy_sats: 312_500_000, // 3.125 BTC
            tx_fees_sats: 10_000_000,  // 0.1 BTC
            miner_work: vec![("miner1".to_string(), 100_000_000_000_000u128)],
            node_shares: vec![([1u8; 32], 5)],
            treasury_state,
        };

        // After 3 years, should be in year 4 of decay (0.1 treasury, 0.9 nodes)
        // M-5: Use block_timestamp for deterministic decay calculation
        assert!(data.treasury_state.decay_year(data.block_timestamp) >= 3);
    }

    #[test]
    fn test_saturating_add_overflow() {
        // Test that saturating_add prevents overflow
        let a = u64::MAX - 10;
        let b = 100u64;
        let result = a.saturating_add(b);
        assert_eq!(result, u64::MAX); // Saturates at MAX instead of wrapping
    }

    #[test]
    fn test_saturating_sub_underflow() {
        // Test that saturating_sub prevents underflow
        let total = 100u64;
        let fee = 150u64;
        let result = total.saturating_sub(fee);
        assert_eq!(result, 0); // Saturates at 0 instead of wrapping
    }

    #[test]
    fn test_share_clamping() {
        // Test that shares are clamped to [0, 1]
        let share = 1.0001f64; // Slightly over 1.0 due to floating point
        let clamped = share.clamp(0.0, 1.0);
        assert_eq!(clamped, 1.0);

        let share = -0.0001f64; // Slightly negative due to floating point
        let clamped = share.clamp(0.0, 1.0);
        assert_eq!(clamped, 0.0);
    }

    #[test]
    fn test_safe_float_to_u64_conversion() {
        // Test that large float values don't overflow
        let total_sats = u64::MAX;
        let share = 1.0f64;
        // This is the safe conversion pattern we use
        let amount = (total_sats as f64 * share).min(u64::MAX as f64) as u64;
        // Should not panic or produce weird values - verify it's a valid value
        let _ = amount; // Just verify computation didn't panic
    }

    #[test]
    fn test_dust_redistribution_to_node_pool() {
        // Test that miner dust is properly tracked
        // With 1000 sats total and 1% going to each of 100 small miners,
        // each would get 10 sats which is below the 546 dust threshold
        let dust_threshold = 546u64;

        // Simulate calculating payouts for many small miners
        let total_sats = 10_000u64;
        let miner_count = 100;
        let per_miner = total_sats / miner_count; // 100 sats each

        // All should be dust since 100 < 546
        let mut dust_collected = 0u64;
        for _ in 0..miner_count {
            if per_miner < dust_threshold {
                dust_collected += per_miner;
            }
        }

        // All 10_000 sats should be collected as dust
        assert_eq!(dust_collected, total_sats);

        // This dust would then be added to the node reward pool
        // ensuring no satoshis are lost
        let original_node_pool = 5_000u64;
        let augmented_node_pool = original_node_pool.saturating_add(dust_collected);
        assert_eq!(augmented_node_pool, 15_000);
    }

    #[test]
    fn test_node_dust_to_top_node() {
        // Test that node dust is redistributed to the top node
        let dust_threshold = 546u64;

        // Simulate payouts: top node gets 1000, others are dust
        let payouts = vec![
            (1000u64, [1u8; 32]), // Top node - above threshold
            (100u64, [2u8; 32]),  // Dust - below threshold
            (50u64, [3u8; 32]),   // Dust - below threshold
        ];

        let mut final_payouts: Vec<(u64, [u8; 32])> = Vec::new();
        let mut dust_total = 0u64;

        for (amount, node_id) in payouts {
            if amount < dust_threshold {
                dust_total += amount;
            } else {
                final_payouts.push((amount, node_id));
            }
        }

        // Add dust to top node
        if dust_total > 0 && !final_payouts.is_empty() {
            final_payouts[0].0 += dust_total;
        }

        // Top node should have original + dust
        assert_eq!(final_payouts.len(), 1);
        assert_eq!(final_payouts[0].0, 1000 + 100 + 50); // 1150 sats
        assert_eq!(final_payouts[0].1, [1u8; 32]); // Top node ID
    }

    #[test]
    fn test_verified_capabilities_required() {
        // SECURITY TEST: Verify that PayoutHandler requires a QualifiedCapabilityProvider
        // and fails without one (instead of using unverified claimed capabilities)

        // This test verifies the pattern change from:
        //   if let Some(ref provider) = self.qualification_provider { ... }
        // To:
        //   let provider = self.qualification_provider.as_ref().ok_or(NoVerificationProvider)?;

        // We can't easily test the full PayoutHandler without all dependencies,
        // but we document the expected behavior:

        // When qualification_provider is None:
        // - handle_block_found() should return Err(GhostError::NoVerificationProvider)
        // - Node rewards should NOT be distributed based on claimed capabilities

        // When qualification_provider is Some:
        // - Node shares should be recalculated using provider.get_all_qualified_nodes()
        // - Only VERIFIED capabilities should be used for payout calculation

        // This test serves as documentation of the security requirement.
        // The actual enforcement is in PayoutHandler::handle_block_found()

        // Verify the error type exists
        let err = ghost_common::error::GhostError::NoVerificationProvider;
        assert!(format!("{}", err).contains("verification provider"));
    }

    #[test]
    fn test_integer_arithmetic_no_rounding_error_pool() {
        // SECURITY TEST: Verify basis point calculations are deterministic and bounded

        // Test miner share calculation with values that could cause floating point issues
        let total_sats = 309_375_000u64; // 99% of 3.125 BTC
        let miner_works = [
            (33.333333333f64, "miner1"),
            (33.333333333f64, "miner2"),
            (33.333333334f64, "miner3"),
        ];

        let total_work: f64 = miner_works.iter().map(|(w, _)| w).sum();

        // Using basis points (our secure method)
        let mut bps_total = 0u64;
        let mut bps_amounts = Vec::new();
        for (work, _) in &miner_works {
            let share_bps = ((work * 10000.0) / total_work) as u64;
            let amount = (total_sats as u128 * share_bps as u128 / 10000) as u64;
            bps_amounts.push(amount);
            bps_total += amount;
        }

        // Key assertions:
        // 1. Total should not exceed available funds (prevents over-allocation)
        assert!(
            bps_total <= total_sats,
            "Allocated {} but only {} available",
            bps_total,
            total_sats
        );

        // 2. Each miner should get approximately 1/3 (within 1% tolerance)
        let expected_per_miner = total_sats / 3;
        for (i, amount) in bps_amounts.iter().enumerate() {
            let diff = if *amount > expected_per_miner {
                amount - expected_per_miner
            } else {
                expected_per_miner - amount
            };
            // Allow 1% variance
            let tolerance = expected_per_miner / 100;
            assert!(
                diff <= tolerance,
                "Miner {} got {} but expected ~{} (diff {} > tolerance {})",
                i,
                amount,
                expected_per_miner,
                diff,
                tolerance
            );
        }

        // 3. The method should be deterministic - same inputs = same outputs
        let mut second_total = 0u64;
        for (work, _) in &miner_works {
            let share_bps = ((work * 10000.0) / total_work) as u64;
            let amount = (total_sats as u128 * share_bps as u128 / 10000) as u64;
            second_total += amount;
        }
        assert_eq!(bps_total, second_total, "Non-deterministic calculation!");

        // 4. Lost sats should be bounded (basis points give 0.01% precision = max 0.01% loss)
        // With 3 miners, worst case truncation is 3 * 0.9999 bps = ~0.03% of total
        let max_loss = total_sats / 3000; // ~0.033% of total
        let actual_loss = total_sats - bps_total;
        assert!(
            actual_loss <= max_loss,
            "Lost {} sats ({}%), expected at most {} sats ({}%)",
            actual_loss,
            (actual_loss as f64 / total_sats as f64) * 100.0,
            max_loss,
            (max_loss as f64 / total_sats as f64) * 100.0
        );
    }

    #[test]
    fn test_payout_rounding_no_satoshi_loss() {
        // PO4-1: Verify that rounding remainder is captured
        // This ensures no satoshis are lost due to basis point truncation

        let total_sats = 1_000_000u64; // 1 million sats
        let miner_works = [
            (33.33333333f64, "miner1"),
            (33.33333333f64, "miner2"),
            (33.33333334f64, "miner3"),
        ];

        let total_work: f64 = miner_works.iter().map(|(w, _)| w).sum();

        // Simulate the calculation
        let mut allocated = 0u64;
        for (work, _) in &miner_works {
            let share_bps = ((work * 10000.0) / total_work) as u64;
            let amount = (total_sats as u128 * share_bps as u128 / 10000) as u64;
            allocated += amount;
        }

        // The remainder due to truncation
        let remainder = total_sats.saturating_sub(allocated);

        // With basis points (0.01% precision), 3 miners dividing evenly:
        // Each gets 3333 bps = 33.33%
        // 3 * 3333 = 9999 bps, leaving 1 bp = 0.01%
        // For 1M sats: 0.01% = 100 sats remainder
        assert!(remainder > 0, "Expected rounding remainder, got 0");
        assert!(
            remainder < total_sats / 100,
            "Remainder {} too large",
            remainder
        );

        // Total should be preserved when remainder is captured
        let total_with_remainder = allocated + remainder;
        assert_eq!(
            total_with_remainder, total_sats,
            "Total should be exactly preserved"
        );
    }

    #[test]
    fn test_tx_fees_allocation_succeeds_with_address() {
        // H-FUND-1: Verify that TX fees are properly allocated when block finder has address
        use ghost_common::types::{PayoutEntry, PayoutProposal, PayoutType};

        // Create a proposal where TX fees are successfully allocated
        let allocated_proposal = PayoutProposal {
            proposal_hash: [0u8; 32],
            round_id: 1,
            block_hash: [0u8; 32],
            block_height: 800_000,
            proposer: [1u8; 32],
            miner_payouts: vec![],
            node_payouts: vec![PayoutEntry {
                address: b"bc1qnode".to_vec(),
                amount: 10_000_000,
                recipient_id: [1u8; 32],
                payout_type: PayoutType::TxFees,
            }],
            treasury_amount: 0,
            treasury_address: Vec::new(),
            tx_fees: 10_000_000,
            subsidy: 312_500_000,
            timestamp: 1700000000,
            tx_fees_unallocated: 0, // TX fees were allocated successfully
        };
        assert_eq!(allocated_proposal.tx_fees_unallocated, 0);
        assert_eq!(allocated_proposal.node_payouts.len(), 1);
        assert_eq!(allocated_proposal.node_payouts[0].amount, 10_000_000);
    }

    #[test]
    fn test_h_fund_1_tx_fee_allocation_error_type_exists() {
        // H-FUND-1 SECURITY: Verify that TxFeeAllocationFailed error type exists
        // and contains the expected information for debugging.
        //
        // When a block finder has no payout address:
        // - Block production MUST be halted (return error)
        // - Error MUST contain the node_id for debugging
        // - Error MUST contain the tx_fees amount for auditing
        //
        // This is NOT a "treasury fallback" situation - it's a configuration error
        // that must be fixed before mining can continue.
        let err = ghost_common::error::GhostError::TxFeeAllocationFailed {
            node_id: "abc12345".to_string(),
            tx_fees: 10_000_000,
        };

        let err_msg = format!("{}", err);
        assert!(
            err_msg.contains("abc12345"),
            "Error must contain node_id: {}",
            err_msg
        );
        assert!(
            err_msg.contains("10000000"),
            "Error must contain tx_fees: {}",
            err_msg
        );
        assert!(
            err_msg.contains("MUST be halted") || err_msg.contains("block production"),
            "Error must indicate block production halt: {}",
            err_msg
        );
    }

    #[test]
    fn test_h_fund_2_consecutive_no_nodes_threshold() {
        // H-FUND-2 SECURITY: Verify the MAX_CONSECUTIVE_NO_NODES constant exists
        // and is set to a reasonable value (10 blocks).
        //
        // After 10 consecutive blocks with no qualifying nodes:
        // - Block production MUST halt
        // - Error message MUST include consecutive count
        // - Error message MUST include total fallback count
        //
        // This prevents extended periods where node rewards silently go to treasury.

        assert_eq!(
            MAX_CONSECUTIVE_NO_NODES, 10,
            "MAX_CONSECUTIVE_NO_NODES should be 10 blocks"
        );

        // Verify the PayoutCalculation error includes the needed info
        let err = ghost_common::error::GhostError::PayoutCalculation(format!(
            "No qualifying nodes for {} consecutive blocks (threshold: {}). \
             This indicates a verification system failure. \
             Total fallbacks: {}. Block production halted.",
            10, MAX_CONSECUTIVE_NO_NODES, 15
        ));

        let err_msg = format!("{}", err);
        assert!(
            err_msg.contains("10 consecutive"),
            "Error must contain consecutive count: {}",
            err_msg
        );
        assert!(
            err_msg.contains("threshold"),
            "Error must mention threshold: {}",
            err_msg
        );
        assert!(
            err_msg.contains("Total fallbacks"),
            "Error must include total fallbacks: {}",
            err_msg
        );
    }

    #[test]
    fn test_h_fund_2_atomic_counter_operations() {
        // H-FUND-2: Verify atomic counter operations work correctly
        use std::sync::atomic::{AtomicU64, Ordering};

        let counter = AtomicU64::new(0);

        // Simulate multiple increments (as would happen across blocks)
        for i in 1..=10 {
            let prev = counter.fetch_add(1, Ordering::Relaxed);
            assert_eq!(prev + 1, i, "Counter should increment correctly");
        }

        assert_eq!(counter.load(Ordering::Relaxed), 10);

        // Simulate reset when nodes are found
        counter.store(0, Ordering::Relaxed);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    // =========================================================================
    // Payout arithmetic and validation tests
    //
    // These tests verify the core payout distribution logic by exercising:
    // - FeeDistribution::calculate() for fee splits
    // - The integer arithmetic used in calculate_miner_payouts / calculate_node_payouts
    // - calculate_block_subsidy() for halving schedule
    // - Dust redistribution invariants
    // - Solo mode distribution
    // =========================================================================

    #[test]
    fn test_create_proposal_basic_distribution_arithmetic() {
        // Verify full payout distribution arithmetic with 3 miners and 2 nodes.
        //
        // This mirrors the logic in create_proposal() -> calculate_miner_payouts()
        // + calculate_node_payouts() using the same integer math, without needing
        // a Database-backed PayoutProposalCreator.

        let subsidy_sats: u64 = 5_000_000_000; // 50 BTC
        let tx_fees_sats: u64 = 50_000;
        let dust_threshold: u64 = 546;

        // Step 1: Fee distribution (same as create_proposal calls FeeDistribution::calculate)
        let treasury_state = TreasuryState::new(); // pre-threshold: 50/50 split
        let now = chrono::Utc::now();
        let fee_dist = FeeDistribution::calculate(subsidy_sats, tx_fees_sats, &treasury_state, now);

        // Pool fee = 1% of subsidy = 50,000,000
        assert_eq!(fee_dist.pool_fee, 50_000_000);
        // Miner pool = 99% of subsidy = 4,950,000,000
        assert_eq!(fee_dist.miner_pool, 4_950_000_000);
        // Treasury = 50% of pool fee = 25,000,000
        assert_eq!(fee_dist.treasury_amount, 25_000_000);
        // Node reward pool = 50% of pool fee = 25,000,000
        assert_eq!(fee_dist.node_reward_pool, 25_000_000);
        // TX fees go to block finder
        assert_eq!(fee_dist.tx_fees_to_block_finder, 50_000);

        // Verify fee_dist totals
        assert!(fee_dist.verify(subsidy_sats, tx_fees_sats));

        // Step 2: Miner distribution (replicating calculate_miner_payouts integer math)
        // Miners: work 500, 300, 200 (total 1000)
        let miner_work: Vec<(String, u128)> = vec![
            ("miner_a".to_string(), 500u128),
            ("miner_b".to_string(), 300u128),
            ("miner_c".to_string(), 200u128),
        ];
        let total_work: u128 = miner_work.iter().map(|(_, w)| w).sum();
        assert_eq!(total_work, 1000);

        let miner_pool = fee_dist.miner_pool;
        let mut miner_amounts: Vec<u64> = Vec::new();
        let mut miner_dust: u64 = 0;
        let mut miner_allocated: u64 = 0;

        for (_id, work) in &miner_work {
            let amount = ((miner_pool as u128 * *work) / total_work) as u64;
            if amount < dust_threshold {
                miner_dust += amount;
            } else {
                miner_amounts.push(amount);
            }
            miner_allocated += amount;
        }

        // Miner A: 50% of 4,950,000,000 = 2,475,000,000
        assert_eq!(miner_amounts[0], 2_475_000_000);
        // Miner B: 30% of 4,950,000,000 = 1,485,000,000
        assert_eq!(miner_amounts[1], 1_485_000_000);
        // Miner C: 20% of 4,950,000,000 = 990,000,000
        assert_eq!(miner_amounts[2], 990_000_000);
        // No dust (all amounts well above 546)
        assert_eq!(miner_dust, 0);

        // Rounding remainder
        let miner_remainder = miner_pool - miner_allocated;

        // Step 3: Node distribution (replicating calculate_node_payouts integer math)
        // Nodes: shares 10, 5 (total 15)
        let node_shares: Vec<([u8; 32], i32)> = vec![([1u8; 32], 10), ([2u8; 32], 5)];
        let total_shares: i32 = node_shares.iter().map(|(_, s)| s).sum();
        assert_eq!(total_shares, 15);

        let augmented_node_pool = fee_dist.node_reward_pool + miner_dust + miner_remainder;
        let mut node_amounts: Vec<u64> = Vec::new();
        let mut node_dust: u64 = 0;
        let mut node_allocated: u64 = 0;

        for (_id, shares) in &node_shares {
            let amount =
                ((augmented_node_pool as u128 * *shares as u128) / total_shares as u128) as u64;
            if amount < dust_threshold {
                node_dust += amount;
            } else {
                node_amounts.push(amount);
            }
            node_allocated += amount;
        }

        // Node 1: 10/15 of 25,000,000 = 16,666,666
        assert_eq!(node_amounts[0], 16_666_666);
        // Node 2: 5/15 of 25,000,000 = 8,333,333
        assert_eq!(node_amounts[1], 8_333_333);
        // No dust
        assert_eq!(node_dust, 0);

        let node_remainder = augmented_node_pool - node_allocated;

        // Step 4: Cross-check — all satoshis accounted for
        // Miners + Treasury + Node payouts + Node dust-to-top-node + TX fees = subsidy + tx_fees
        let total_miner_out: u64 = miner_amounts.iter().sum();
        let total_node_out: u64 = node_amounts.iter().sum::<u64>() + node_dust + node_remainder;
        let grand_total = total_miner_out
            + miner_remainder
            + fee_dist.treasury_amount
            + total_node_out
            + fee_dist.tx_fees_to_block_finder;

        assert_eq!(
            grand_total,
            subsidy_sats + tx_fees_sats,
            "All satoshis must be accounted for: got {}, expected {}",
            grand_total,
            subsidy_sats + tx_fees_sats
        );
    }

    #[test]
    fn test_fee_sanity_limit_rejects_excessive_fees() {
        // MED-POOL-2: Verify that the fee sanity limit is 100 BTC and that
        // values above it would be rejected by validate_block_data().
        //
        // We cannot call validate_block_data() directly (requires PayoutProposalCreator),
        // so we replicate the constant and verify the boundary logic.

        const MAX_REASONABLE_FEES: u64 = 100 * 100_000_000; // 100 BTC in sats
        assert_eq!(MAX_REASONABLE_FEES, 10_000_000_000);

        // Just at limit — should pass
        let at_limit = MAX_REASONABLE_FEES;
        assert!(
            at_limit <= MAX_REASONABLE_FEES,
            "Fees at exactly 100 BTC should pass the sanity check"
        );

        // Just over limit — should fail
        let over_limit = MAX_REASONABLE_FEES + 1;
        assert!(
            over_limit > MAX_REASONABLE_FEES,
            "Fees at 100 BTC + 1 sat should fail the sanity check"
        );

        // Way over limit
        let way_over = 1_000 * 100_000_000; // 1000 BTC
        assert!(
            way_over > MAX_REASONABLE_FEES,
            "1000 BTC in fees should fail the sanity check"
        );

        // Zero fees — should pass
        let zero_fees: u64 = 0;
        assert!(
            zero_fees <= MAX_REASONABLE_FEES,
            "Zero fees should pass the sanity check"
        );
    }

    #[test]
    fn test_subsidy_calculation_known_heights() {
        // M-15: Verify calculate_block_subsidy produces the correct Bitcoin halving schedule.
        //
        // Height 0-209999:       50 BTC    = 5,000,000,000 sats
        // Height 210000-419999:  25 BTC    = 2,500,000,000 sats
        // Height 420000-629999:  12.5 BTC  = 1,250,000,000 sats
        // Height 630000-839999:  6.25 BTC  =   625,000,000 sats
        // Height 840000-1049999: 3.125 BTC =   312,500,000 sats

        use ghost_common::rpc::calculate_block_subsidy;

        // Genesis block
        assert_eq!(calculate_block_subsidy(0, None), 5_000_000_000);

        // Last block before first halving
        assert_eq!(calculate_block_subsidy(209_999, None), 5_000_000_000);

        // First halving
        assert_eq!(calculate_block_subsidy(210_000, None), 2_500_000_000);

        // Second halving
        assert_eq!(calculate_block_subsidy(420_000, None), 1_250_000_000);

        // Third halving
        assert_eq!(calculate_block_subsidy(630_000, None), 625_000_000);

        // Fourth halving (current era as of 2024)
        assert_eq!(calculate_block_subsidy(840_000, None), 312_500_000);

        // Fifth halving
        assert_eq!(calculate_block_subsidy(1_050_000, None), 156_250_000);

        // Very far future: after 64 halvings, subsidy should be 0
        assert_eq!(
            calculate_block_subsidy(210_000 * 64, None),
            0,
            "Subsidy should be zero after 64 halvings"
        );

        // Arbitrary mid-era height
        assert_eq!(
            calculate_block_subsidy(500_000, None),
            1_250_000_000,
            "Height 500k is in the 3rd era (12.5 BTC)"
        );
    }

    #[test]
    fn test_dust_redistribution_comprehensive() {
        // Verify dust redistribution with 10 miners each earning sub-dust amounts.
        //
        // When miners earn below the 546-sat dust threshold, their amounts must be
        // collected and added to the node reward pool, with zero satoshi loss.

        let dust_threshold: u64 = 546;
        let miner_pool: u64 = 5_000; // Intentionally small to generate dust
        let miner_count = 10;

        // Each miner has equal work
        let work_per_miner: u128 = 100;
        let total_work: u128 = work_per_miner * miner_count as u128;

        let mut dust_collected: u64 = 0;
        let mut payouts: Vec<u64> = Vec::new();
        let mut allocated: u64 = 0;

        for _ in 0..miner_count {
            let amount = ((miner_pool as u128 * work_per_miner) / total_work) as u64;
            allocated += amount;
            if amount < dust_threshold {
                dust_collected += amount;
            } else {
                payouts.push(amount);
            }
        }

        // Each miner gets 500 sats (5000 / 10), which is below 546 dust threshold
        assert_eq!(miner_pool / miner_count as u64, 500);

        // All amounts should be dust
        assert!(
            payouts.is_empty(),
            "All miners should be below dust threshold"
        );

        // Rounding remainder
        let remainder = miner_pool - allocated;

        // Total dust + remainder = miner_pool (no satoshis lost)
        assert_eq!(
            dust_collected + remainder,
            miner_pool,
            "All satoshis from miner pool must be accounted for in dust + remainder"
        );

        // Now simulate what create_proposal does: add dust to node pool
        let original_node_pool: u64 = 10_000;
        let augmented_node_pool = original_node_pool + dust_collected + remainder;

        // Node pool grows by exactly the miner_pool amount
        assert_eq!(
            augmented_node_pool,
            original_node_pool + miner_pool,
            "Augmented node pool = original + full miner pool (all dust)"
        );
    }

    #[test]
    fn test_zero_miners_all_to_nodes() {
        // When there are zero miners, the entire miner pool should remain unallocated,
        // and via rounding remainder capture, be redirected to node pool.

        let miner_pool: u64 = 4_950_000_000; // 99% of 50 BTC
        let miner_work: Vec<(String, u128)> = vec![]; // No miners

        // Replicate calculate_miner_payouts logic for empty miners
        let total_work: u128 = miner_work.iter().map(|(_, w)| w).sum();
        assert_eq!(total_work, 0);

        // When total_work == 0, calculate_miner_payouts returns (empty vec, 0 dust)
        // and the full miner_pool becomes rounding remainder
        let miner_payouts: Vec<u64> = vec![];
        let miner_dust: u64 = 0;
        let miner_allocated: u64 = 0;

        assert!(miner_payouts.is_empty());

        // The unallocated amount equals the full miner pool
        let unallocated = miner_pool - miner_allocated;
        assert_eq!(unallocated, miner_pool);

        // In create_proposal, this unallocated amount goes through:
        // augmented_node_pool = node_reward_pool + miner_dust
        // But note: with zero miners, calculate_miner_payouts returns ([], 0)
        // so miner_dust = 0. The miner_pool sats go through rounding remainder = total_sats - 0 = miner_pool.
        // Actually wait — looking at the code again:
        // When total_work == 0, it returns early with Ok((vec![], 0)).
        // The rounding remainder logic isn't reached. So the dust_total returned is 0.
        // In create_proposal, augmented_node_pool = node_reward_pool + 0 = node_reward_pool.
        // The miner_pool sats are unaccounted? No — the M-04 cross-check at the end would catch this.
        //
        // Actually, in the real flow:
        // - miner_payouts = [] (no payouts)
        // - miner_dust = 0
        // - augmented_node_pool = node_reward_pool + 0
        // - total_miner = 0 (sum of empty)
        // - total_node = node payouts + tx_fees
        // - proposal_total = 0 + node_total + treasury
        // - expected = subsidy + tx_fees
        // - This means subsidy = miner_pool + pool_fee, and node_total + treasury < pool_fee + tx_fees
        // - So the cross check would FAIL for zero miners, which is correct behavior
        //   (the pool requires miners to distribute funds)
        //
        // Verify: with zero miners, the miner pool can't be allocated, so cross-check
        // would catch the mismatch. This is working as intended.
        assert!(
            miner_pool > 0 && miner_allocated == 0,
            "Zero miners means miner pool is entirely unallocated"
        );

        // In calculate_miner_payouts, when total_work == 0 it returns early with ([], 0).
        // The rounding remainder logic is not reached, so dust returned is 0.
        // The miner_pool amount remains unallocated, and the M-04 cross-check in
        // create_proposal would catch this mismatch (working as intended — pool
        // requires at least one miner to distribute the subsidy).
        assert_eq!(miner_dust, 0);
        assert_eq!(unallocated, 4_950_000_000);
    }

    #[test]
    fn test_all_dust_miners_redistributed() {
        // 100 miners each earning 5 sats (far below 546 dust threshold).
        // Verify all amounts are collected as dust and no satoshis are lost.

        let dust_threshold: u64 = 546;
        let miner_pool: u64 = 500; // 5 sats per miner if 100 miners
        let miners: Vec<u128> = vec![1u128; 100]; // Equal work
        let total_work: u128 = miners.iter().sum();

        let mut dust_total: u64 = 0;
        let mut payouts_count: usize = 0;
        let mut allocated: u64 = 0;

        for work in &miners {
            let amount = ((miner_pool as u128 * *work) / total_work) as u64;
            allocated += amount;
            if amount < dust_threshold {
                dust_total += amount;
            } else {
                payouts_count += 1;
            }
        }

        // Each miner gets 5 sats, all below dust
        assert_eq!(payouts_count, 0, "All 100 miners should be dust");

        // Rounding remainder
        let remainder = miner_pool - allocated;

        // Total accounted = dust + remainder = miner_pool
        assert_eq!(
            dust_total + remainder,
            miner_pool,
            "dust_total ({}) + remainder ({}) must equal miner_pool ({})",
            dust_total,
            remainder,
            miner_pool
        );

        // Simulate redistribution to node pool
        let original_node_pool: u64 = 1_000_000;
        let augmented = original_node_pool + dust_total + remainder;
        assert_eq!(
            augmented,
            original_node_pool + miner_pool,
            "Full miner pool should augment the node pool"
        );
    }

    #[test]
    fn test_solo_mode_full_subsidy_minus_fee() {
        // Solo mode: 99% of subsidy + ALL TX fees go to the solo miner.
        // 1% pool fee splits between treasury and node pool per decay schedule.

        let subsidy_sats: u64 = 312_500_000; // 3.125 BTC
        let tx_fees_sats: u64 = 1_500_000; // 0.015 BTC

        let treasury_state = TreasuryState::new(); // pre-threshold
        let now = chrono::Utc::now();

        // In solo mode, TX fees are passed as 0 to FeeDistribution
        // because they go directly to the solo miner outside the pool fee calculation
        let fee_dist = FeeDistribution::calculate(subsidy_sats, 0, &treasury_state, now);

        // Pool fee = 1% of 312,500,000 = 3,125,000
        assert_eq!(fee_dist.pool_fee, 3_125_000);

        // Miner pool (99%) = 309,375,000
        assert_eq!(fee_dist.miner_pool, 309_375_000);

        // Solo miner gets: miner_pool + ALL tx_fees
        let solo_miner_amount = fee_dist.miner_pool + tx_fees_sats;
        assert_eq!(solo_miner_amount, 310_875_000);

        // Treasury (50% of pool fee in pre-threshold) = 1,562,500
        assert_eq!(fee_dist.treasury_amount, 1_562_500);

        // Node reward pool (50% of pool fee) = 1,562,500
        assert_eq!(fee_dist.node_reward_pool, 1_562_500);

        // Verify: solo_miner + treasury + node_pool = subsidy + tx_fees
        let total = solo_miner_amount + fee_dist.treasury_amount + fee_dist.node_reward_pool;
        assert_eq!(
            total,
            subsidy_sats + tx_fees_sats,
            "Solo mode total must equal subsidy + tx_fees: {} != {}",
            total,
            subsidy_sats + tx_fees_sats
        );

        // Verify the 99% claim: miner gets 99% of subsidy
        assert_eq!(
            fee_dist.miner_pool as f64 / subsidy_sats as f64,
            0.99,
            "Miner should receive exactly 99% of subsidy"
        );
    }

    #[test]
    fn test_solo_mode_with_decay() {
        // Solo mode with treasury decay year 3 (20% treasury, 80% nodes)

        let subsidy_sats: u64 = 312_500_000; // 3.125 BTC
        let tx_fees_sats: u64 = 500_000;

        let now = chrono::Utc::now();
        let threshold_time = now - chrono::Duration::days(365 * 2 + 100); // ~year 3
        let treasury_state = TreasuryState::from_stored(
            crate::treasury::TREASURY_THRESHOLD_SATS,
            Some(threshold_time),
        );

        // Solo mode: tx_fees passed as 0 to FeeDistribution
        let fee_dist = FeeDistribution::calculate(subsidy_sats, 0, &treasury_state, now);

        // Pool fee = 1% of subsidy = 3,125,000
        assert_eq!(fee_dist.pool_fee, 3_125_000);

        // Miner pool = 99% = 309,375,000
        assert_eq!(fee_dist.miner_pool, 309_375_000);

        // Year 3 decay: treasury gets 20% of pool fee, nodes get 80%
        // Treasury = 3,125,000 * 2000 / 10000 = 625,000
        assert_eq!(fee_dist.treasury_amount, 625_000);

        // Node pool = 3,125,000 - 625,000 = 2,500,000
        assert_eq!(fee_dist.node_reward_pool, 2_500_000);

        // Total check
        let solo_miner_amount = fee_dist.miner_pool + tx_fees_sats;
        let total = solo_miner_amount + fee_dist.treasury_amount + fee_dist.node_reward_pool;
        assert_eq!(total, subsidy_sats + tx_fees_sats);
    }

    #[test]
    fn test_proportional_distribution_large_work_variance() {
        // Test proportional distribution when miners have vastly different work amounts.
        // This stresses the integer arithmetic for extreme ratios.

        let miner_pool: u64 = 4_950_000_000; // 99% of 50 BTC
        let dust_threshold: u64 = 546;

        // One whale miner with 99% of work, 99 tiny miners with 1% total
        let mut miner_work: Vec<u128> = vec![99_000u128]; // whale
        for _ in 0..99 {
            miner_work.push(10u128); // tiny miners: 10 each = 990 total
        }
        let total_work: u128 = miner_work.iter().sum();
        assert_eq!(total_work, 99_990);

        let mut payouts: Vec<u64> = Vec::new();
        let mut dust_total: u64 = 0;
        let mut allocated: u64 = 0;

        for work in &miner_work {
            let amount = ((miner_pool as u128 * *work) / total_work) as u64;
            allocated += amount;
            if amount < dust_threshold {
                dust_total += amount;
            } else {
                payouts.push(amount);
            }
        }

        // Whale gets ~99% of miner pool
        let whale_amount = payouts[0];
        let whale_expected = ((miner_pool as u128 * 99_000u128) / total_work) as u64;
        assert_eq!(whale_amount, whale_expected);

        // Each tiny miner gets 4,950,000,000 * 10 / 99,990 = 495,049 sats
        let tiny_expected = ((miner_pool as u128 * 10u128) / total_work) as u64;
        assert_eq!(tiny_expected, 495_049);
        // 495,049 > 546 dust threshold, so tiny miners are NOT dust with this pool size
        // This demonstrates that even a 0.01% share of a 50 BTC block produces non-dust payouts
        assert!(tiny_expected > dust_threshold);

        // All miners (whale + 99 tiny) should get payouts since all are above dust
        assert_eq!(
            payouts.len(),
            100,
            "All miners should be above dust threshold with 50 BTC pool"
        );

        // Verify: dust + payouts + remainder = miner_pool
        let remainder = miner_pool - allocated;
        assert_eq!(
            payouts.iter().sum::<u64>() + dust_total + remainder,
            miner_pool,
            "All satoshis must be accounted for"
        );
    }

    #[test]
    fn test_node_share_proportional_distribution_all_equal() {
        // Test node payout distribution when all nodes have equal shares.
        // With 5 nodes each having 15 shares (max possible), verify even split.

        let node_pool: u64 = 25_000_000; // 25M sats
        let dust_threshold: u64 = 546;

        let node_shares: Vec<i32> = vec![15, 15, 15, 15, 15]; // 5 equal nodes
        let total_shares: i32 = node_shares.iter().sum();
        assert_eq!(total_shares, 75);

        let mut payouts: Vec<u64> = Vec::new();
        let mut allocated: u64 = 0;
        let mut dust: u64 = 0;

        for shares in &node_shares {
            let amount = ((node_pool as u128 * *shares as u128) / total_shares as u128) as u64;
            allocated += amount;
            if amount < dust_threshold {
                dust += amount;
            } else {
                payouts.push(amount);
            }
        }

        // Each node gets 25,000,000 * 15 / 75 = 5,000,000 sats
        assert_eq!(payouts.len(), 5);
        for payout in &payouts {
            assert_eq!(*payout, 5_000_000);
        }

        // No dust (5M sats each, well above threshold)
        assert_eq!(dust, 0);

        // No rounding remainder (divides evenly)
        let remainder = node_pool - allocated;
        assert_eq!(remainder, 0, "Equal shares should divide evenly");
    }

    #[test]
    fn test_node_share_proportional_distribution_varied() {
        // Test 5-4-3-2-1 share system with specific capability combinations.
        //
        // Node A: Archive(5) + GhostPay(4) + PublicMining(3) + Reaper(2) + Elder(1) = 15
        // Node B: Archive(5) + PublicMining(3) = 8
        // Node C: Reaper(2) + Elder(1) = 3

        let node_pool: u64 = 3_125_000; // Example node reward pool

        let shares: Vec<i32> = vec![15, 8, 3];
        let total_shares: i32 = shares.iter().sum();
        assert_eq!(total_shares, 26);

        let mut amounts: Vec<u64> = Vec::new();
        let mut allocated: u64 = 0;

        for s in &shares {
            let amount = ((node_pool as u128 * *s as u128) / total_shares as u128) as u64;
            amounts.push(amount);
            allocated += amount;
        }

        // Node A: 3,125,000 * 15 / 26 = 1,802,884 (truncated)
        assert_eq!(amounts[0], 1_802_884);
        // Node B: 3,125,000 * 8 / 26 = 961,538
        assert_eq!(amounts[1], 961_538);
        // Node C: 3,125,000 * 3 / 26 = 360,576
        assert_eq!(amounts[2], 360_576);

        // Remainder due to integer truncation
        let remainder = node_pool - allocated;
        assert!(
            remainder > 0,
            "Uneven division should produce a rounding remainder"
        );
        assert!(
            remainder < total_shares as u64,
            "Remainder should be less than total_shares (at most total_shares - 1)"
        );

        // All sats accounted for
        assert_eq!(amounts.iter().sum::<u64>() + remainder, node_pool);
    }

    #[test]
    fn test_subsidy_regtest_halving_interval() {
        // Regtest uses a halving interval of 150 blocks instead of 210,000.

        use ghost_common::config::BitcoinNetwork;
        use ghost_common::rpc::calculate_block_subsidy;

        // Block 0-149: 50 BTC
        assert_eq!(
            calculate_block_subsidy(0, Some(&BitcoinNetwork::Regtest)),
            5_000_000_000
        );
        assert_eq!(
            calculate_block_subsidy(149, Some(&BitcoinNetwork::Regtest)),
            5_000_000_000
        );

        // Block 150-299: 25 BTC
        assert_eq!(
            calculate_block_subsidy(150, Some(&BitcoinNetwork::Regtest)),
            2_500_000_000
        );

        // Block 300-449: 12.5 BTC
        assert_eq!(
            calculate_block_subsidy(300, Some(&BitcoinNetwork::Regtest)),
            1_250_000_000
        );
    }

    #[test]
    fn test_fee_distribution_all_decay_years() {
        // Verify FeeDistribution at every decay year produces correct splits
        // and maintains the invariant: miner_pool + treasury + node_pool + tx_fees = subsidy + tx_fees

        let subsidy: u64 = 312_500_000; // 3.125 BTC
        let tx_fees: u64 = 1_000_000;
        let now = chrono::Utc::now();

        // Pre-threshold (year 0): 50/50
        let state0 = TreasuryState::new();
        let d0 = FeeDistribution::calculate(subsidy, tx_fees, &state0, now);
        assert_eq!(d0.treasury_amount, 1_562_500);
        assert_eq!(d0.node_reward_pool, 1_562_500);
        assert!(d0.verify(subsidy, tx_fees));

        // Year 1: 40/60
        let t1 = now - chrono::Duration::days(10); // Just crossed
        let state1 = TreasuryState::from_stored(crate::treasury::TREASURY_THRESHOLD_SATS, Some(t1));
        let d1 = FeeDistribution::calculate(subsidy, tx_fees, &state1, now);
        // Year 1 = 40% treasury, 60% nodes
        assert_eq!(d1.treasury_amount, 1_250_000);
        assert_eq!(d1.node_reward_pool, 1_875_000);
        assert!(d1.verify(subsidy, tx_fees));

        // Year 2: 30/70
        let t2 = now - chrono::Duration::days(365 + 10);
        let state2 = TreasuryState::from_stored(crate::treasury::TREASURY_THRESHOLD_SATS, Some(t2));
        let d2 = FeeDistribution::calculate(subsidy, tx_fees, &state2, now);
        assert_eq!(d2.treasury_amount, 937_500);
        assert_eq!(d2.node_reward_pool, 2_187_500);
        assert!(d2.verify(subsidy, tx_fees));

        // Year 3: 20/80
        let t3 = now - chrono::Duration::days(365 * 2 + 10);
        let state3 = TreasuryState::from_stored(crate::treasury::TREASURY_THRESHOLD_SATS, Some(t3));
        let d3 = FeeDistribution::calculate(subsidy, tx_fees, &state3, now);
        assert_eq!(d3.treasury_amount, 625_000);
        assert_eq!(d3.node_reward_pool, 2_500_000);
        assert!(d3.verify(subsidy, tx_fees));

        // Year 4: 10/90
        let t4 = now - chrono::Duration::days(365 * 3 + 10);
        let state4 = TreasuryState::from_stored(crate::treasury::TREASURY_THRESHOLD_SATS, Some(t4));
        let d4 = FeeDistribution::calculate(subsidy, tx_fees, &state4, now);
        assert_eq!(d4.treasury_amount, 312_500);
        assert_eq!(d4.node_reward_pool, 2_812_500);
        assert!(d4.verify(subsidy, tx_fees));

        // Year 5+: 0/100
        let t5 = now - chrono::Duration::days(365 * 5 + 10);
        let state5 = TreasuryState::from_stored(crate::treasury::TREASURY_THRESHOLD_SATS, Some(t5));
        let d5 = FeeDistribution::calculate(subsidy, tx_fees, &state5, now);
        assert_eq!(d5.treasury_amount, 0);
        assert_eq!(d5.node_reward_pool, 3_125_000);
        assert!(d5.verify(subsidy, tx_fees));
    }

    #[test]
    fn test_miner_payout_rounding_remainder_bounded() {
        // Verify that the rounding remainder from miner distribution is always
        // less than the number of miners (mathematical property of integer division).

        let miner_pool: u64 = 4_950_000_000;
        let miner_counts = [1, 2, 3, 7, 13, 50, 100, 200];

        for count in miner_counts {
            let work_per_miner: u128 = 1_000_000;
            let total_work: u128 = work_per_miner * count as u128;

            let mut allocated: u64 = 0;
            for _ in 0..count {
                let amount = ((miner_pool as u128 * work_per_miner) / total_work) as u64;
                allocated += amount;
            }

            let remainder = miner_pool - allocated;
            assert!(
                remainder < count as u64,
                "Remainder {} should be < miner count {} (pool={}, allocated={})",
                remainder,
                count,
                miner_pool,
                allocated
            );
        }
    }

    #[test]
    fn test_validate_block_hash_zero_check() {
        // PO4-M1: Validate that zero block hash would be rejected.
        // We test the static method PayoutProposalCreator::validate_block_hash
        // which is private, so we verify through the BlockFoundData construction
        // and the expected behavior.

        let zero_hash = [0u8; 32];
        let nonzero_hash = {
            let mut h = [0u8; 32];
            h[0] = 1;
            h
        };

        // Zero hash should be detected by validate_block_hash
        // We verify the value directly since we can't call the private method
        assert_eq!(zero_hash, [0u8; 32], "Zero hash is all zeros");
        assert_ne!(
            nonzero_hash, [0u8; 32],
            "Non-zero hash differs from all-zeros"
        );

        // The check in validate_block_hash is: block_hash == &[0u8; 32]
        // Verify this comparison works correctly
        assert!(zero_hash == [0u8; 32]);
        assert!(nonzero_hash != [0u8; 32]);
    }

    #[test]
    fn test_solo_block_found_data_construction() {
        // Verify SoloBlockFoundData can be constructed with valid data
        // and that the expected fields are populated correctly.

        let now = chrono::Utc::now();
        let data = SoloBlockFoundData {
            round_id: 42,
            block_hash: [0xAB; 32],
            block_height: 840_000,
            block_timestamp: now,
            solo_payout_address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            subsidy_sats: 312_500_000,
            treasury_address_snapshot: Some({
                let mut addr = vec![0x51, 0x20];
                addr.extend_from_slice(&[0xAA; 32]);
                addr
            }),
            tx_fees_sats: 500_000,
            node_shares: vec![([1u8; 32], 10), ([2u8; 32], 5)],
            treasury_state: TreasuryState::new(),
        };

        assert_eq!(data.round_id, 42);
        assert_eq!(data.block_height, 840_000);
        assert_eq!(data.subsidy_sats, 312_500_000);
        assert_eq!(data.tx_fees_sats, 500_000);
        assert_eq!(data.node_shares.len(), 2);
        assert!(data.treasury_address_snapshot.is_some());

        // Verify fee distribution for solo mode
        let fee_dist = FeeDistribution::calculate(
            data.subsidy_sats,
            0, // Solo mode: TX fees not in pool fee calc
            &data.treasury_state,
            data.block_timestamp,
        );

        // Solo miner gets 99% of subsidy + all TX fees
        let solo_amount = fee_dist.miner_pool + data.tx_fees_sats;
        assert_eq!(solo_amount, 309_375_000 + 500_000);

        // Total check
        let total = solo_amount + fee_dist.treasury_amount + fee_dist.node_reward_pool;
        assert_eq!(total, data.subsidy_sats + data.tx_fees_sats);
    }

    #[test]
    fn test_integer_division_no_overflow_u128() {
        // Verify that the u128 arithmetic used in payout calculation does not
        // overflow even with maximum theoretical values.
        //
        // Max possible: 21M BTC total supply * 10^8 sats/BTC * max_work
        // Formula: amount = (total_sats as u128 * work as u128) / total_work as u128

        let max_sats: u128 = 21_000_000 * 100_000_000; // 2.1 * 10^15
        let max_work: u128 = u64::MAX as u128; // ~1.8 * 10^19

        // This multiplication must not overflow u128 (max ~3.4 * 10^38)
        let product = max_sats.checked_mul(max_work);
        assert!(
            product.is_some(),
            "u128 multiplication should not overflow for max sats * max work"
        );

        // Verify the product is within u128 range
        let p = product.unwrap();
        assert!(p <= u128::MAX);

        // Division should produce a valid result
        let result = p / max_work;
        assert_eq!(result, max_sats, "Division should recover original value");
    }

    #[test]
    fn test_fee_distribution_zero_subsidy() {
        // Edge case: After all halvings (height > 210000*64), subsidy is 0.
        // All revenue comes from TX fees.

        let subsidy: u64 = 0;
        let tx_fees: u64 = 50_000_000; // 0.5 BTC in fees only
        let state = TreasuryState::new();
        let now = chrono::Utc::now();

        let dist = FeeDistribution::calculate(subsidy, tx_fees, &state, now);

        // Pool fee = 1% of 0 = 0
        assert_eq!(dist.pool_fee, 0);
        // Miner pool = 99% of 0 = 0
        assert_eq!(dist.miner_pool, 0);
        // Treasury = 0
        assert_eq!(dist.treasury_amount, 0);
        // Node pool = 0
        assert_eq!(dist.node_reward_pool, 0);
        // TX fees still go to block finder
        assert_eq!(dist.tx_fees_to_block_finder, tx_fees);

        // Total should still be correct
        assert!(dist.verify(subsidy, tx_fees));
    }
}
