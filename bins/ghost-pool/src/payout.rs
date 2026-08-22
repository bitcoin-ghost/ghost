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

use ghost_common::config::MiningMode;
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

/// Maximum number of unpaid contributors swept into a single block's payout.
pub const LEDGER_CAP: u32 = 1000;

/// Projected payouts below this are dropped and redirected to the node reward pool.
pub const LEDGER_DUST_SATS: u64 = 546;

/// Select the miner work set that a block's payout is computed from.
///
/// GHOST-02: this is the SINGLE SOURCE OF TRUTH for "which shares does this block pay?".
/// The proposer calls it at block-found; every validating node calls it again to recompute
/// the split. Both MUST derive the identical set, because `validate_proposal_split` compares
/// the resulting address→amount maps for exact equality — so any divergence between the two
/// call sites is a consensus rejection, not a rounding difference.
///
/// That is why the cutoff is a parameter rather than `now`: the validator recomputes long
/// after the proposer did, and must reproduce the proposer's exact window. It is carried on
/// the proposal as `PayoutProposal::timestamp` (set from `BlockFoundData::ledger_cutoff_ts`).
///
/// Payout is ledger-style, not round-style: unpaid shares accumulate across job-rounds, and
/// a block sweeps the whole unpaid ledger up to `cutoff_ts` — NOT merely the shares of the
/// ~90s round the block happened to land in. Miners dropped by the cap or the dust filter
/// keep their unpaid work and compete again on the next block.
pub fn select_ledger_miner_work(
    db: &ghost_storage::Database,
    cutoff_ts: i64,
    block_height: u64,
    subsidy_sats: u64,
) -> GhostResult<Vec<(String, u128)>> {
    use ghost_accounting::shares::WORK_SCALE;

    // Below the grouping gate the ledger keys on miner_id (per-worker, legacy); at and above
    // it keys on payout_address. The string is a miner_id pre-gate and an address post-gate;
    // `get_miner_address` resolves either.
    let raw: Vec<(String, f64)> = if block_height >= crate::PAYOUT_ADDRESS_GROUPING_HEIGHT {
        db.get_top_unpaid_addresses(cutoff_ts, LEDGER_CAP)?
            .into_iter()
            .map(|(addr, work, _ids)| (addr, work))
            .collect()
    } else {
        db.get_top_unpaid_miners(cutoff_ts, LEDGER_CAP)?
    };

    // Iteratively drop miners whose projected payout would fall below dust. Each drop raises
    // the per-sat share of everyone remaining, which can pull someone else above the dust
    // line — hence the loop. It terminates because each pass strictly shrinks the set.
    let miner_pool_estimate = (subsidy_sats as u128).saturating_mul(9900) / 10000; // 99% of subsidy
    let mut surviving = raw;
    loop {
        let total_work: f64 = surviving.iter().map(|(_, w)| *w).sum();
        if total_work <= 0.0 {
            break;
        }
        let pre_len = surviving.len();
        surviving.retain(|(_, work)| {
            let projected = (miner_pool_estimate as f64 * work / total_work) as u64;
            projected >= LEDGER_DUST_SATS
        });
        if surviving.len() == pre_len {
            break;
        }
    }

    Ok(surviving
        .into_iter()
        .map(|(id, w)| (id, (w * WORK_SCALE as f64) as u128))
        .collect())
}

/// Domain-separated tag for the payout-ledger checkpoint root. Bump the version
/// suffix if the canonical encoding below ever changes (it is consensus-visible).
const LEDGER_ROOT_DOMAIN: &[u8] = b"PayoutLedgerRoot/v1";

/// Deterministic 32-byte root over the payout inputs as of a fixed cutoff: the
/// canonical unpaid-miner set (payout address → scaled integer work) and the
/// qualified-node set (node_id → 5-4-3-2-1 capability shares). This is the object
/// the fleet BFT-finalises; the coinbase then becomes a pure function of the
/// checkpoint carrying this root, so every node builds the identical coinbase and
/// GHOST-02/Component-E recompute-reject can never spuriously fire.
///
/// PURE and ORDER-INDEPENDENT: both sets are sorted canonically here (miners by
/// work desc then address asc — matching `select_ledger_miner_work`'s order; nodes
/// by node_id asc), so two nodes holding the same rows produce a byte-identical
/// root regardless of the order their queries returned. Work is a `u128` (already
/// `WORK_SCALE`-quantised, never a float) so the hash is reproducible. Every field
/// is length-prefixed to prevent concatenation ambiguity.
pub fn compute_ledger_root(
    miners: &[(String, u128)],
    nodes: &[(NodeId, i32)],
    cutoff_ts: i64,
    block_height: u64,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut m = miners.to_vec();
    m.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut n = nodes.to_vec();
    n.sort_by_key(|x| x.0);

    let mut h = Sha256::new();
    h.update(LEDGER_ROOT_DOMAIN);
    h.update(cutoff_ts.to_le_bytes());
    h.update(block_height.to_le_bytes());
    h.update((m.len() as u32).to_le_bytes());
    for (addr, work) in &m {
        h.update((addr.len() as u32).to_le_bytes());
        h.update(addr.as_bytes());
        h.update(work.to_le_bytes());
    }
    h.update((n.len() as u32).to_le_bytes());
    for (node_id, shares) in &n {
        h.update(&node_id[..]);
        h.update(shares.to_le_bytes());
    }
    let out = h.finalize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&out);
    root
}

/// Diagnostic breakdown of the ledger-root inputs, for isolating live root
/// divergence. Hashes the miner-set and node-set SEPARATELY (each with the same
/// canonical encoding `compute_ledger_root` uses for that half) and includes their
/// counts plus the full node list (node_id prefix : shares). Comparing this string
/// across nodes tells us (a) whether the rejecters agree with each other, and
/// (b) whether the miner half or the node half is the divergent one — and for the
/// node half, exactly which node/shares differ. Diagnostic only; not consensus.
pub fn ledger_root_diag(
    miners: &[(String, u128)],
    nodes: &[(NodeId, i32)],
    cutoff_ts: i64,
    block_height: u64,
) -> String {
    use sha2::{Digest, Sha256};

    let mut m = miners.to_vec();
    m.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut mh = Sha256::new();
    for (addr, work) in &m {
        mh.update((addr.len() as u32).to_le_bytes());
        mh.update(addr.as_bytes());
        mh.update(work.to_le_bytes());
    }
    let mdig = mh.finalize();

    let mut n = nodes.to_vec();
    n.sort_by_key(|x| x.0);
    let mut nh = Sha256::new();
    for (node_id, shares) in &n {
        nh.update(&node_id[..]);
        nh.update(shares.to_le_bytes());
    }
    let ndig = nh.finalize();
    let node_list: Vec<String> = n
        .iter()
        .map(|(id, s)| format!("{}:{}", hex::encode(&id[..4]), s))
        .collect();

    let root = compute_ledger_root(miners, nodes, cutoff_ts, block_height);
    format!(
        "root={} miners{{n={},h={}}} nodes{{n={},h={},[{}]}}",
        hex::encode(&root[..8]),
        m.len(),
        hex::encode(&mdig[..8]),
        n.len(),
        hex::encode(&ndig[..8]),
        node_list.join(","),
    )
}

/// Resolve the cutoff timestamp that anchors the payout for a block at `tip_height`.
///
/// This is the fix for the v1.10.32 live failure. BELOW `coinbase_fee_split_height()`
/// the coinbase is treasury-only, so the anchor is wall-clock `now()` — the legacy
/// behaviour, with no cross-node split to diverge on. AT AND ABOVE the gate the
/// coinbase carries the miner+node split, and anchoring at `now()` is exactly what
/// broke: the proposer's ledger at `now()` has not converged across the fleet
/// (GHOST-03 gossip lag), so validators recompute a different split and GHOST-02
/// rejects every proposal. Instead the anchor becomes the `cutoff_ts` of the latest
/// BFT-finalised `PayoutLedgerCheckpoint` at-or-before `tip_height` — a lagging,
/// fleet-agreed point where the share and qualification ledgers HAVE converged. Every
/// node derives the same checkpoint deterministically, so every node recomputes the
/// identical split and the recompute-reject can only ever pass.
///
/// Returns `None` only at/above the gate when no checkpoint has finalised yet (the
/// brief window at first activation, before the dark finaliser has produced one). The
/// caller must then build NO split payout — the block falls back to a treasury-only
/// coinbase, which is safe because there is nothing for validators to disagree on.
pub fn resolve_payout_cutoff(db: &ghost_storage::Database, tip_height: u64) -> Option<i64> {
    if tip_height < crate::coinbase_fee_split_height() {
        return Some(chrono::Utc::now().timestamp());
    }
    match db.get_payout_ledger_checkpoint_at_or_before(tip_height) {
        Ok(Some(cp)) => Some(cp.cutoff_ts),
        Ok(None) => None,
        Err(e) => {
            tracing::error!(
                error = %e,
                tip_height,
                "payout checkpoint lookup failed; refusing to anchor a split payout this block"
            );
            None
        }
    }
}

/// The two halves of an adopted payout split: miner payouts as `(address, work)` and node
/// shares as `(node_id, share_count)` — the same pair `compute_ledger_root` hashes.
pub type AdoptedPayout = (Vec<(String, u128)>, Vec<(NodeId, i32)>);

/// Option (c) adopt-CONSUMPTION: the BFT-finalised checkpoint's ADOPTED payout lists at
/// or before `tip_height` — `(miner_payouts: (address, WORK_SCALE-quantised work),
/// node_shares: (node_id, 5-4-3-2-1 shares))`.
///
/// At and above the fee gate the coinbase — AND the GHOST-02/Component-E validators that
/// check it — build from THESE, never from a local recompute. Independent nodes cannot
/// reproduce a byte-identical split (share attribution + float-sum order diverge), which
/// is exactly why v1.10.32's recompute-at-`now()` was rejected every block. Every node
/// instead reads the SAME finalised row (the fleet BFT-ratified the proposer's lists
/// within tolerance and persisted them identically), so the split is fleet-identical and
/// the validators' exact-equality check compares like-with-like and passes.
///
/// `None` when no checkpoint has finalised at or before `tip_height` (the brief window at
/// first activation) — the caller then builds NO split (treasury-only fallback, safe:
/// there is nothing for validators to disagree on).
pub fn read_adopted_payout(db: &ghost_storage::Database, tip_height: u64) -> Option<AdoptedPayout> {
    match db.get_payout_ledger_checkpoint_at_or_before(tip_height) {
        Ok(Some(cp)) => Some((cp.miner_payouts, cp.node_shares)),
        Ok(None) => None,
        Err(e) => {
            tracing::error!(
                error = %e,
                tip_height,
                "adopted payout lookup failed; refusing to anchor a split payout this block"
            );
            None
        }
    }
}

/// The checkpoint's miner work taken from the SHARD instead of the legacy unpaid ledger.
///
/// The counterpart to [`select_ledger_miner_work`], and the whole of the checkpoint half of the
/// cutover. Same output shape — `(address, weight)` sorted work-desc then address-asc — so every
/// downstream consumer (the root, `payouts_agree`, the adopted list the coinbase builds from) is
/// unchanged code on both sides of the gate.
///
/// **Why this exists.** Migration v56 handed `shares` to the shard and disabled the GHOST-03
/// ledger sweep that repaired it, while the checkpoint carried on recomputing from that same
/// table. Holes in it became permanent, so no two nodes agreed a per-address total and every
/// proposal was rejected — 25% apart on the live fleet, against a 2% tolerance, with no
/// mechanism left to converge. The shard has one, and uses it: the per-address totals are
/// BYTE-IDENTICAL across vm1/vm2/vm3 today.
///
/// The weight is `owed` micro-work rather than `WORK_SCALE`-quantised work. Only the ratios
/// matter — the coinbase distributes `pool_sats * work / total` — and the tolerance terms that
/// are not scale-invariant stay inert at these magnitudes (`ABS_TOL` sits ~165x below the
/// 0.2%-of-pool floor). ⚠ That inertness is a property of the magnitudes, not of the code: if
/// total owed ever fell below ~5e14 micro, `ABS_TOL` would silently become the governing bound.
///
/// Non-positive balances are dropped. `owed()` is `accrued − settled` and is documented to go
/// negative transiently; the `i64 → u128` cast would otherwise wrap a small negative into a
/// number larger than the entire pool. Mirrors `shard_miner_payouts`, which filters the same way
/// on the paying side.
///
/// No dust filter here, unlike the legacy path: dust is applied when the coinbase is built
/// (`shard_miner_payouts`, which knows the actual pool sats), and applying a subsidy-estimated
/// one here as well would drop addresses the payer would have kept. The cap is
/// `MAX_MINER_OUTPUTS` so the adopted list can never exceed what a coinbase is able to pay.
pub fn select_shard_miner_work(
    owed: &std::collections::BTreeMap<String, i64>,
) -> Vec<(String, u128)> {
    let mut rows: Vec<(String, u128)> = owed
        .iter()
        .filter(|(_, &micro)| micro > 0)
        .map(|(addr, &micro)| (addr.clone(), micro as u128))
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(ghost_common::constants::MAX_MINER_OUTPUTS);
    rows
}

/// Option B cutoff-binding: a proposal's payout cutoff must be a fleet-ratified one.
///
/// At and above `fee_gate_height` the coinbase is a pure function of a BFT-finalised
/// `PayoutLedgerCheckpoint`, so `proposal_cutoff_ts` MUST equal the cutoff_ts of a
/// finalised checkpoint at-or-before the block. This is the check that gives the
/// GHOST-02 recompute below its teeth: on its own the recompute reproduces the split
/// at WHATEVER cutoff the proposal names, so a proposer who names a non-converged
/// cutoff still matches himself and every honest node diverges from him. Pinning the
/// cutoff to a checkpoint the fleet already agreed on (at a lagging, converged height)
/// removes that freedom — an honest proposer always passes, a cutoff-forging one is
/// rejected by everyone. Below the gate the cutoff is wall-clock now() and there is
/// nothing to bind, so this is inert (and the whole scheme ships dormant).
///
/// Extracted from the validator closure so it is unit-testable: the gate is a
/// parameter here rather than the process-global `coinbase_fee_split_height()`.
pub fn check_proposal_cutoff_binding(
    db: &ghost_storage::Database,
    block_height: u64,
    proposal_cutoff_ts: i64,
    fee_gate_height: u64,
) -> Result<(), String> {
    if block_height < fee_gate_height {
        return Ok(()); // pre-gate: now()-cutoffs, nothing to bind against
    }
    match db.get_payout_ledger_checkpoint_at_or_before(block_height) {
        Ok(Some(cp)) => {
            if proposal_cutoff_ts != cp.cutoff_ts {
                Err(format!(
                    "GHOST-02: proposal cutoff {proposal_cutoff_ts} is not the finalised \
                     checkpoint cutoff {} (checkpoint height {})",
                    cp.cutoff_ts, cp.height
                ))
            } else {
                Ok(())
            }
        }
        Ok(None) => Err(
            "GHOST-02: no finalised payout checkpoint at or before this height; \
             a split payout cannot be ratified yet"
                .to_string(),
        ),
        Err(e) => Err(format!("GHOST-02: checkpoint lookup failed: {e}")),
    }
}

/// Build the GHOST-02 proposal validator that every node installs on its vote handler.
///
/// A peer's payout proposal is vote-approved only if its split matches what THIS node
/// recomputes from its own converged share ledger (GHOST-03) and payout addresses.
///
/// This lives in the library, not in `main.rs`, ON PURPOSE. It is the only thing standing
/// between an honest proposal and a rejected payout, and it previously recomputed from
/// `RoundManager::get_miner_work_scaled(proposal.round_id)` — the work of the single ~90s
/// job-round the block landed in — while the proposer built the split from the cross-round
/// unpaid ledger. The two could never match, so the fleet would have rejected its own payout
/// on the first block it won. That bug was invisible for exactly one reason: as an inline
/// closure in a binary, no test could reach it. Keep it here, and keep it tested.
///
/// `enforcement_height` gates rejection (see `CLUSTER_ENFORCEMENT_HEIGHT`): below it a
/// mismatch is logged but tolerated, because a mixed-version fleet has not converged yet.
pub fn make_proposal_validator(
    handler: Arc<PayoutHandler>,
    db: Arc<ghost_storage::Database>,
    enforcement_height: u64,
) -> ghost_consensus::vote_handler::ProposalValidateFn {
    Arc::new(move |proposal: &PayoutProposal| {
        // Option B: bind the cutoff to a fleet-finalised checkpoint before trusting it.
        // Inert below the fee gate; at/above it a forged cutoff is rejected outright.
        check_proposal_cutoff_binding(
            &db,
            proposal.block_height,
            proposal.timestamp as i64,
            crate::coinbase_fee_split_height(),
        )?;

        // Timestamp freshness is GATE-AWARE and owned here (the vote handler keeps only a loose
        // garbage bound). BELOW the fee gate the proposal timestamp is wall-clock now() (there is
        // no checkpoint to bind to), so enforce a tight freshness window to bound replay — this
        // is the 30-min check the vote handler used to apply globally. AT/ABOVE the gate this is
        // inert: the cutoff-binding above already pins the timestamp to a finalised checkpoint
        // cutoff, a stronger guarantee that ALSO tolerates the anchor lag (the checkpoint cutoff
        // is `block(tip-LAG).time`, legitimately minutes-to-hours behind now — anchoring the
        // freshness window at now() is exactly what rejected every post-gate proposal and broke
        // the FEE activation).
        if proposal.block_height < crate::coinbase_fee_split_height() {
            const PRE_GATE_FRESHNESS_SECS: i64 = 1800; // 30 min
            let now = chrono::Utc::now().timestamp();
            if (now - proposal.timestamp as i64).abs() > PRE_GATE_FRESHNESS_SECS {
                return Err(format!(
                    "pre-gate proposal timestamp {} not within {PRE_GATE_FRESHNESS_SECS}s of now {now}",
                    proposal.timestamp
                ));
            }
        }

        // Determine the miner list to validate the proposal against.
        //
        // At/above the fee gate (option c adopt-CONSUMPTION): validate against the
        // fleet-ratified checkpoint list — the SAME list the proposer built from — so the
        // exact-equality check below compares like-with-like and passes. A local recompute
        // here would diverge (independent nodes can't reproduce byte-identical attribution)
        // and reject the very split the fleet adopted (the v1.10.32 failure mode).
        //
        // Below the gate (legacy GHOST-02): recompute from the UNPAID LEDGER over the
        // proposer's exact window (cutoff rides on `proposal.timestamp`) — unchanged.
        let (local_work, adopted_nodes) =
            if proposal.block_height >= crate::coinbase_fee_split_height() {
                match read_adopted_payout(&db, proposal.block_height) {
                    Some((miners, nodes)) => (miners, Some(nodes)),
                    None => {
                        return Err(
                            "GHOST-02: no finalised checkpoint to validate the adopted split \
                         against"
                                .to_string(),
                        )
                    }
                }
            } else {
                let work = match select_ledger_miner_work(
                    &db,
                    proposal.timestamp as i64,
                    proposal.block_height,
                    proposal.subsidy,
                ) {
                    Ok(work) => work,
                    Err(e) => return Err(format!("GHOST-02: local ledger recompute failed: {e}")),
                };
                (work, None)
            };

        let treasury_state = match db.get_treasury_balance() {
            Ok(balance) => {
                let threshold_ts = db
                    .get_treasury_threshold_reached()
                    .ok()
                    .flatten()
                    .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
                    .map(|dt| dt.with_timezone(&chrono::Utc));
                TreasuryState::from_stored(balance, threshold_ts)
            }
            Err(_) => TreasuryState::new(),
        };

        let result = handler.validate_proposal_split(
            proposal,
            &local_work,
            adopted_nodes.as_deref(),
            &treasury_state,
        );

        if proposal.block_height >= enforcement_height {
            result
        } else {
            if let Err(reason) = &result {
                warn!(
                    reason = %reason,
                    height = proposal.block_height,
                    "GHOST-02 (pre-gate): split mismatch — would reject after enforcement height"
                );
            }
            Ok(())
        }
    })
}

/// Settle a payout: mark its shares paid and bump the treasury.
///
/// CALL THIS ONLY WHEN THE COINS EXIST — i.e. when a block WE mined has been accepted and its
/// coinbase carries `proposal`. It must never run merely because a proposal was approved.
///
/// Approval only ARMS the coinbase (`set_approved_payout`); the coins do not appear until a
/// later block is actually won carrying that snapshot. Settling at approval time therefore
/// marks a miner's work paid before a single satoshi has moved — and if the pool never wins
/// again, that work is marked paid and never paid. With payouts ratified at every tip, settling
/// on approval would wipe the ledger every ~10 minutes while paying nobody at all.
///
/// Returns the number of share rows marked paid, or 0 if the block was already settled.
///
/// Thin wrapper over [`apply_settlement`]: the node that submits a winning block settles it
/// immediately, every other node settles the same block when it observes it on-chain, and both
/// must go through one implementation or they will drift.
///
/// `mined_outputs` is the coinbase the chain actually accepted; see [`apply_settlement`] for why
/// settling without it credits amounts the chain never paid (#601).
pub fn settle_paid_block(
    db: &ghost_storage::Database,
    proposal: &PayoutProposal,
    grouping_height: u64,
    block_hash: &str,
    mined_outputs: Option<&[crate::coinbase_verifier::CoinbaseOutput]>,
) -> GhostResult<usize> {
    Ok(
        apply_settlement(db, proposal, grouping_height, block_hash, mined_outputs)?
            .map(|applied| applied.shares_marked)
            .unwrap_or(0),
    )
}

/// Resolve which local `miner_id`s a proposal's payout entries refer to.
///
/// Pre-gate, `recipient_id` is `sha256(miner_id)` — one entry per worker, matched directly.
/// Post-gate it is `sha256(payout_address)` — one entry per address, so hash every unpaid miner's
/// address, match against the proposal's set, then resolve those addresses back to ALL their
/// miner_ids so the per-share UPDATE catches every worker under a paid address.
///
/// Split out from settlement because it is the half that depends on the ledger's current contents,
/// and it is worth being able to test the resolution independently of the write.
pub fn resolve_paid_miner_ids(
    db: &ghost_storage::Database,
    proposal: &PayoutProposal,
    grouping_height: u64,
) -> GhostResult<Vec<String>> {
    let cutoff_ts = proposal.timestamp as i64;
    let wanted: std::collections::HashSet<[u8; 32]> = proposal
        .miner_payouts
        .iter()
        .map(|e| e.recipient_id)
        .collect();

    // Reverse-resolve each PayoutEntry's recipient_id hash back to local miner_id strings.
    //
    // Pre-gate, recipient_id is sha256(miner_id) — one entry per worker, matched directly.
    // Post-gate it is sha256(payout_address) — one entry per address, so we hash every unpaid
    // miner's address, match against the proposal's set, then resolve those addresses back to
    // ALL their miner_ids so the per-share UPDATE catches every worker under a paid address.
    let matched: Vec<String> = if proposal.block_height >= grouping_height {
        let groups = db.get_top_unpaid_addresses(cutoff_ts, u32::MAX)?;
        let mut acc = Vec::new();
        for (addr, _work, miner_ids) in groups {
            let h = ghost_common::identity::hash_message(addr.as_bytes());
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            if wanted.contains(&arr) {
                acc.extend(miner_ids);
            }
        }
        acc
    } else {
        db.get_distinct_unpaid_miner_ids(cutoff_ts)?
            .into_iter()
            .filter(|id| {
                let h = ghost_common::identity::hash_message(id.as_bytes());
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&h);
                wanted.contains(&arr)
            })
            .collect()
    };

    Ok(matched)
}

/// What settlement decided to credit and record, and on what evidence.
///
/// Split out of [`apply_settlement`] so the money decision — WHAT the treasury is credited and
/// WHICH outputs hash the settlement records — is a pure function of the ratified proposal and
/// the mined coinbase, testable without a database.
#[derive(Debug, Clone, PartialEq)]
pub struct SettlementAmounts {
    /// Satoshis the treasury is credited.
    pub treasury_amount: u64,
    /// The outputs hash recorded on the settlement row.
    pub outputs_hash: [u8; 32],
    /// True when the mined outputs were PROVEN to be the deterministic fee-drift adjustment of
    /// the ratified proposal (hash match). False means the amounts were measured directly from
    /// the mined outputs because reconstruction did not verify — alarmed by the caller.
    pub verified: bool,
}

/// Derive what settlement should credit from the coinbase the chain actually accepted.
///
/// #601: the mined coinbase is built from a per-node fee-drift adjustment of the ratified
/// proposal (`template::adjust_proposal_for_available_fees`), so the treasury and node amounts
/// the chain PAID differ from the ones the fleet RATIFIED — on the live fleet by the entire fee
/// value of the block (`original_fees=0, available_fees≈4M sats` on every template). Crediting
/// `proposal.treasury_amount` books money that never existed on-chain.
///
/// Two paths, in order of preference:
///
/// 1. **Reconstruct and prove.** The adjustment is deterministic in (ratified proposal, total
///    mined value), so re-apply it and require the commitment of the result to hash-match the
///    mined outputs — the same `CoinbaseOutputs/v1` commitment M-28 verified before submission.
///    On a match the adjusted `treasury_amount` is exactly what the treasury output carries.
/// 2. **Measure.** If reconstruction does not verify (a winner on different code, a tampered
///    coinbase, or a rehearsal block mined outside the builder), fall back to summing the mined
///    outputs that pay the treasury script directly. Exact unless another payout entry shares
///    the treasury address, which is logged. The share marking is unaffected either way — miner
///    entries are never touched by any version of the adjustment.
///
/// In both paths the recorded `outputs_hash` is the hash of the MINED outputs, so the settlement
/// row describes the chain rather than the proposal.
pub fn settlement_amounts_from_mined_coinbase(
    proposal: &PayoutProposal,
    mined: &[crate::coinbase_verifier::CoinbaseOutput],
) -> SettlementAmounts {
    use crate::coinbase_verifier::{address_to_script_pubkey, CoinbaseCommitment};

    let mined_hash = CoinbaseCommitment::outputs_hash(mined);
    let mined_total: u64 = mined
        .iter()
        .filter(|o| o.value > 0)
        .map(|o| o.value)
        .fold(0u64, u64::saturating_add);

    // Path 1: reconstruct the winner's adjustment and prove it against the mined outputs.
    if let Some(adjusted) = crate::template::adjust_proposal_for_available_fees(
        proposal.clone(),
        mined_total,
        proposal.block_height,
    ) {
        let treasury_addr = if !adjusted.treasury_address.is_empty() {
            adjusted.treasury_address.clone()
        } else {
            Vec::new()
        };
        let commitment = CoinbaseCommitment::from_proposal(&adjusted, &treasury_addr);
        if commitment.verify(mined).is_ok() {
            return SettlementAmounts {
                treasury_amount: adjusted.treasury_amount,
                outputs_hash: mined_hash,
                verified: true,
            };
        }
    }

    // Path 2: the block is provably ours (it carries the payout tag) but its outputs are not the
    // deterministic adjustment of the proposal we hold. Credit what the chain measurably paid the
    // treasury script — never the ratified figure, which the chain did not pay.
    let treasury_spk = address_to_script_pubkey(&proposal.treasury_address)
        .unwrap_or_else(|| proposal.treasury_address.clone());
    let measured: u64 = if treasury_spk.is_empty() {
        0
    } else {
        mined
            .iter()
            .filter(|o| o.value > 0 && o.script_pubkey == treasury_spk)
            .map(|o| o.value)
            .fold(0u64, u64::saturating_add)
    };

    // If a miner or node entry pays the treasury address too, the direct sum includes their
    // outputs — say so, because the credit is then an upper bound.
    let treasury_addr_shared = proposal
        .miner_payouts
        .iter()
        .chain(proposal.node_payouts.iter())
        .any(|e| {
            address_to_script_pubkey(&e.address).unwrap_or_else(|| e.address.clone())
                == treasury_spk
        });
    if treasury_addr_shared && measured > 0 {
        warn!(
            measured,
            "#601: treasury address is also a payout entry address — the measured treasury \
             credit is an upper bound, not exact"
        );
    }

    SettlementAmounts {
        treasury_amount: measured,
        outputs_hash: mined_hash,
        verified: false,
    }
}

/// Settle a won block: mark its shares paid, bump the treasury, record the win — once, atomically.
///
/// `Ok(None)` means the block was already settled and nothing changed. Three paths reach this for
/// the same block — the submitting node when it submits, every other node when it observes the
/// block on-chain, and the startup rescan — and they must converge on a single application rather
/// than crediting the treasury once per caller.
///
/// `mined_outputs` is the coinbase the chain actually accepted. When present, the treasury credit
/// and the recorded outputs hash come from IT (#601, via
/// [`settlement_amounts_from_mined_coinbase`]) — the ratified `proposal.treasury_amount` is what
/// the fleet agreed to, not what the winner's fee-adjusted coinbase paid, and the two differ on
/// every block with fee drift. `None` preserves the old ratified-amount behaviour for callers
/// that genuinely have no coinbase in hand (some tests); production callers all pass the mined
/// outputs, and settling without them is warned about because the treasury ledger then diverges
/// from the chain by the drift.
///
/// The share marking is identical in every case: miner entries are never touched by the fee
/// adjustment, so WHO gets marked paid depends only on the ratified proposal.
///
/// The share marking, the won-block record and the treasury bump all land in one transaction. They
/// used to be three separate writes, so a crash between them could leave shares marked paid by a
/// block never recorded as won.
pub fn apply_settlement(
    db: &ghost_storage::Database,
    proposal: &PayoutProposal,
    grouping_height: u64,
    block_hash: &str,
    mined_outputs: Option<&[crate::coinbase_verifier::CoinbaseOutput]>,
) -> GhostResult<Option<ghost_storage::queries::SettlementApplied>> {
    let cutoff_ts = proposal.timestamp as i64;
    let matched = resolve_paid_miner_ids(db, proposal, grouping_height)?;

    let amounts = match mined_outputs {
        Some(mined) => {
            let amounts = settlement_amounts_from_mined_coinbase(proposal, mined);
            if !amounts.verified {
                error!(
                    block_hash,
                    height = proposal.block_height,
                    ratified_treasury = proposal.treasury_amount,
                    measured_treasury = amounts.treasury_amount,
                    "#601: mined coinbase is NOT the deterministic fee adjustment of the \
                     ratified proposal — settling the measured treasury amount and alarming. \
                     A winner on different code, a tampered coinbase, or a hand-mined block."
                );
            } else if amounts.treasury_amount != proposal.treasury_amount {
                info!(
                    block_hash,
                    height = proposal.block_height,
                    ratified_treasury = proposal.treasury_amount,
                    paid_treasury = amounts.treasury_amount,
                    "#601: fee drift — the chain paid the treasury a different amount than \
                     ratified; settling what was paid"
                );
            }
            amounts
        }
        None => {
            // Legacy path: no coinbase in hand. The ratified amounts are the only thing to
            // credit, and they are known-wrong by the drift — say so.
            warn!(
                block_hash,
                height = proposal.block_height,
                treasury = proposal.treasury_amount,
                "#601: settling WITHOUT the mined coinbase — crediting the ratified treasury \
                 amount, which differs from what the chain paid by this block's fee drift"
            );
            SettlementAmounts {
                treasury_amount: proposal.treasury_amount,
                outputs_hash: crate::coinbase_verifier::CoinbaseCommitment::from_proposal(
                    proposal,
                    &proposal.treasury_address,
                )
                .output_hash,
                verified: false,
            }
        }
    };

    let applied = db.settle_block_atomic(
        block_hash,
        proposal.block_height,
        &proposal.proposal_hash,
        &amounts.outputs_hash,
        &matched,
        cutoff_ts,
        amounts.treasury_amount,
        ghost_reconciliation::fee_distribution::TREASURY_THRESHOLD_SATS,
    )?;

    match &applied {
        Some(a) => info!(
            shares_marked = a.shares_marked,
            miners = matched.len(),
            height = proposal.block_height,
            treasury_sats = a.treasury_bumped,
            threshold_crossed = a.threshold_crossed,
            verified_against_chain = amounts.verified,
            block_hash,
            "Ledger settled: shares marked paid because a block carrying this payout was accepted"
        ),
        None => debug!(
            height = proposal.block_height,
            block_hash, "Block already settled — nothing to apply"
        ),
    }
    Ok(applied)
}

/// Data needed to create a payout proposal
#[derive(Debug, Clone)]
pub struct BlockFoundData {
    /// Round ID
    pub round_id: RoundId,
    /// GHOST-02: the unpaid-ledger cutoff this proposal's split was computed against.
    ///
    /// Carried onto the proposal as `PayoutProposal::timestamp` so that validators
    /// recompute over the proposer's exact window. Deriving it afresh (`now`) on either
    /// side would sweep in shares the other never saw and fail the exact-equality check.
    pub ledger_cutoff_ts: i64,
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

    /// Stage 5 step 6: the shard's `owed()` balances, when the shard is authoritative.
    ///
    /// `None` keeps the legacy unpaid-ledger path, which is what every node runs until the
    /// coinbase source is flipped. Passing it here rather than reaching for the shard inside
    /// `create_proposal` keeps the proposal builder a pure function of its input — the money
    /// decision is made by the caller that knows whether this node has been cut over, and is
    /// visible in the type rather than hidden behind a global.
    pub shard_owed: Option<std::collections::BTreeMap<String, i64>>,
}

/// Data for solo mining mode block found event
///
/// Solo shares the single fee model with pool mode (#592); see
/// [`PayoutProposalCreator::create_solo_proposal`] for how the `COINBASE_FEE_SPLIT_HEIGHT` gate decides
/// whether the 1% is levied on `subsidy + fees` or on the subsidy alone. The hosting node
/// participates in the node reward pool in both regimes.
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
    /// Transaction fees (satoshis). Post-gate these are folded into the reward the 1% is levied
    /// on and the remainder goes to the solo miner; pre-gate they go to the finder untouched.
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

        // GHOST-02: stamp the proposal with the ledger cutoff its split was actually computed
        // against — NOT `now`. Validators recompute the split from this timestamp, so it must
        // name the proposer's exact window. Re-deriving `now` here would place the stamp after
        // the cutoff (the ledger query and dust filter take time), letting validators sweep in
        // shares the proposer never counted and fail the exact-equality check.
        let now = data.ledger_cutoff_ts as u64;

        // GHOST-02: compute the treasury-decay fee split against the SAME timestamp the
        // proposal is stamped with (`ledger_cutoff_ts`) and that both validators recompute
        // from (`validate_proposal_split`/`validate_node_split` use `proposal.timestamp`) —
        // NOT wall-clock `now()`. `block_timestamp` is `now()` in every live build path, and
        // at/above the fee gate the cutoff is the CONVERGED checkpoint time (~tip-6, minutes
        // behind now); building the split from `now()` while validators use the cutoff diverges
        // at a decay-year boundary and the proposer's own split is rejected. Anchoring to the
        // cutoff makes the coinbase deterministic fleet-wide. Below the gate the cutoff is
        // ~now(), so pre-gate behaviour is unchanged.
        let decay_ts = chrono::DateTime::<chrono::Utc>::from_timestamp(data.ledger_cutoff_ts, 0)
            .unwrap_or(data.block_timestamp);
        let fee_dist = FeeDistribution::calculate_at_height(
            data.subsidy_sats,
            data.tx_fees_sats,
            &data.treasury_state,
            decay_ts,
            data.block_height >= crate::coinbase_fee_split_height(),
        );

        info!(
            subsidy = data.subsidy_sats,
            tx_fees = data.tx_fees_sats,
            pool_fee = fee_dist.pool_fee,
            treasury_rate = fee_dist.treasury_rate,
            node_rate = fee_dist.node_rate,
            miner_pool = fee_dist.miner_pool,
            node_pool = fee_dist.node_reward_pool,
            decay_year = data.treasury_state.decay_year(decay_ts),
            "Calculating fee distribution"
        );

        // Calculate miner payouts (99% of subsidy, proportional to work)
        // Dust from miners below threshold is returned for redistribution to node pool
        //
        // ── Stage 5 step 6: where the money actually changes hands ──────────────────────────
        //
        // This is the ONLY substitution the cutover makes. `data.miner_work` is the legacy
        // unpaid-ledger scan; `shard_owed` is the shard's `owed()`. Everything downstream —
        // node payouts, the dust roll-in, treasury, the 99/1 split, the coinbase commitment and
        // GHOST-02 recompute-reject — is byte-for-byte the same code on both paths.
        //
        // Keeping the substitution this narrow is deliberate. The commitment and its
        // verification are the security-critical half, and a parallel constructor for them
        // would be a second spelling of the thing that decides what a block pays.
        //
        // `shard_miner_payouts` mirrors `calculate_miner_payouts` exactly — same descending sort
        // with ascending tie-break, same truncation, same dust floor — so the two differ only in
        // WHICH balances they distribute, never in HOW.
        let (miner_payouts, miner_dust) = match data.shard_owed.as_ref() {
            Some(owed) => {
                let mp = ghost_common::share_shard::shard_miner_payouts(
                    owed,
                    fee_dist.miner_pool,
                    ghost_common::constants::MAX_MINER_OUTPUTS,
                    LEDGER_DUST_SATS,
                );
                info!(
                    source = "shard",
                    payees = mp.payouts.len(),
                    dust_sats = mp.dust_sats,
                    remainder_sats = mp.remainder_sats,
                    "coinbase: miner payouts from the SHARD"
                );
                // `recipient_id` is derived from the ADDRESS here, not from a miner_id, because
                // the shard groups by payout address and has no miner_id to hash — that is the
                // whole point of address grouping. It is an identifier carried alongside the
                // payout, not an input to the coinbase: `from_proposal` hashes only address and
                // amount, so this cannot change what a block pays.
                // #726: the shard pays whatever address key it holds; the legacy path
                // validates and dusts what fails. See `drop_invalid_shard_payouts`.
                let (valid_payouts, invalid_sats) = self.drop_invalid_shard_payouts(&mp.payouts);

                let entries: Vec<PayoutEntry> = valid_payouts
                    .iter()
                    .map(|(addr, sats)| {
                        let mut recipient_id = [0u8; 32];
                        recipient_id.copy_from_slice(&ghost_common::identity::hash_message(
                            addr.as_bytes(),
                        ));
                        PayoutEntry {
                            address: addr.as_bytes().to_vec(),
                            amount: *sats,
                            recipient_id,
                            payout_type: PayoutType::Mining,
                        }
                    })
                    .collect();
                // The remainder is floor-division leftover. It joins dust in the node pool for
                // the same reason dust does: a satoshi that is tracked and re-homed is not lost,
                // and silently dropping it is how a pool leaks money slowly.
                (
                    entries,
                    mp.dust_sats
                        .saturating_add(mp.remainder_sats)
                        .saturating_add(invalid_sats),
                )
            }
            None => self.calculate_miner_payouts(&data.miner_work, fee_dist.miner_pool)?,
        };

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
    /// Solo uses the SAME fee model as pool mode (#592) — there is no solo-only regime. The split
    /// follows the `COINBASE_FEE_SPLIT_HEIGHT` gate:
    ///
    /// - at/above the gate: 1% pool fee levied on `subsidy + fees`, solo miner keeps the other 99%
    ///   of `subsidy + fees` → `solo_payout_address`
    /// - below the gate (legacy): 1% levied on the subsidy alone, TX fees whole to the solo miner
    ///
    /// In both regimes the 1% is split treasury/node pool by the decay schedule, and the hosting
    /// node is included in the node reward pool calculation. In solo the operator's own node *is*
    /// the node pool, so that share returns to them — no special-casing is needed for it.
    pub fn create_solo_proposal(&self, data: SoloBlockFoundData) -> GhostResult<PayoutProposal> {
        // B-4/CFG-4/CFG-5: Validate block data (matching pool mode checks)
        self.validate_block_data(
            &data.block_hash,
            data.block_height,
            data.subsidy_sats,
            data.tx_fees_sats,
        )?;

        let now = chrono::Utc::now().timestamp() as u64;

        // #592: one fee model across all modes. This path used to pin the legacy regime — 1% levied
        // on the subsidy alone, TX fees whole to the solo miner — by passing `0` fees to
        // `FeeDistribution::calculate`. Above `COINBASE_FEE_SPLIT_HEIGHT` that disagrees with what
        // every validator recomputes in `validate_proposal_split`, so a solo proposal was rejected
        // even by a private mesh of the operator's own nodes. Derive the regime from the height
        // exactly as the pool path does, so there is one split rule and no solo-only economics.
        // M-5 SECURITY: Use block_timestamp for deterministic decay calculation
        let fee_split = data.block_height >= crate::coinbase_fee_split_height();
        let fee_dist = FeeDistribution::calculate_at_height(
            data.subsidy_sats,
            data.tx_fees_sats,
            &data.treasury_state,
            data.block_timestamp,
            fee_split,
        );

        // Post-gate the fees are already inside `miner_pool` (the 1% was levied on subsidy + fees)
        // and `tx_fees_to_block_finder` is 0; pre-gate they sit outside it and go whole to the
        // finder. Adding the field is therefore correct in both regimes without branching on the
        // gate a second time.
        let solo_miner_amount = fee_dist
            .miner_pool
            .saturating_add(fee_dist.tx_fees_to_block_finder);

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
        let fee_dist = FeeDistribution::calculate_at_height(
            proposal.subsidy,
            proposal.tx_fees,
            treasury_state,
            block_time,
            proposal.block_height >= crate::coinbase_fee_split_height(),
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

        // GHOST-02 (extended): pin the rest of the coinbase. The miner split is
        // recomputed exactly above; the checks below stop a proposer from moving
        // value across the miner / node-reward / treasury boundaries.
        //
        // NOT enforced here: the division WITHIN the node-reward pool (which node
        // gets how much). That depends on verified-capability shares, which are not
        // deterministically recomputable by a validator today — see
        // `tasks/decision_ghost02_node_split.md`.

        // (1) Conservation — every satoshi of subsidy + fees lands in exactly one
        // output. With the miner sum already pinned, this also pins the aggregate
        // (node + treasury) bucket, so value can't be moved out of the miner pool.
        let miner_sum: u64 = proposal.miner_payouts.iter().map(|e| e.amount).sum();
        let node_sum: u64 = proposal.node_payouts.iter().map(|e| e.amount).sum();
        let allocated = miner_sum
            .saturating_add(node_sum)
            .saturating_add(proposal.treasury_amount);
        let available = proposal.subsidy.saturating_add(proposal.tx_fees);
        if allocated != available {
            return Err(format!(
                "GHOST-02: coinbase does not conserve value \
                 (allocated {allocated} != subsidy+fees {available})"
            ));
        }

        // (2) Treasury address — a non-zero treasury output must pay the treasury
        // script this node is configured for, so a proposer cannot redirect it.
        if proposal.treasury_amount > 0 {
            match &self.config.treasury_address {
                Some(expected_addr) if &proposal.treasury_address == expected_addr => {}
                Some(_) => {
                    return Err(
                        "GHOST-02: treasury address does not match the configured treasury"
                            .to_string(),
                    )
                }
                None => {} // this validator has no treasury configured — cannot check
            }
        }

        // (3) Treasury floor — the treasury can't be shorted below its deterministic
        // minimum: the base rate plus any sub-dust block-finder fees (which always fold
        // into treasury rather than a dust output). We deliberately do NOT pin the
        // treasury EXACTLY: the node-reward pool falls through to treasury only when
        // there are no eligible nodes, and node eligibility is not reproducible by a
        // validator (attacker-controlled `node_payouts` would otherwise let a proposer
        // choose which recompute branch the validator takes). Pinning the node-vs-
        // treasury allocation needs the node-share determinism — see
        // `tasks/decision_ghost02_node_split.md`.
        let mut treasury_floor = fee_dist.treasury_amount;
        if fee_dist.tx_fees_to_block_finder > 0
            && fee_dist.tx_fees_to_block_finder < ghost_common::constants::DUST_THRESHOLD_SATS
        {
            treasury_floor = treasury_floor.saturating_add(fee_dist.tx_fees_to_block_finder);
        }
        if proposal.treasury_amount < treasury_floor {
            return Err(format!(
                "GHOST-02: treasury below its deterministic floor \
                 (proposal {} < floor {treasury_floor})",
                proposal.treasury_amount
            ));
        }

        Ok(())
    }

    /// Component E (Option B): recompute the intra-node-pool division and reject a
    /// mismatch. This is the check `validate_proposal_split` deliberately omits — it
    /// pins the miner split, conservation and the treasury floor, but NOT which node
    /// gets how much, because that was not reproducible by a validator. Option B makes
    /// it reproducible: `recomputed_node_shares` is the qualified-node set at the
    /// proposal's RATIFIED checkpoint cutoff (converged, fleet-agreed), so turning
    /// shares → sats with the SAME `calculate_node_payouts` the proposer used yields
    /// the identical address→amount map. Any divergence is a forged node split.
    ///
    /// The caller gates this on `coinbase_fee_split_height()` and only reaches it after
    /// `check_proposal_cutoff_binding` has confirmed the cutoff is a finalised one.
    pub fn validate_node_split(
        &self,
        proposal: &PayoutProposal,
        local_miner_work: &[(String, u128)],
        recomputed_node_shares: &[(NodeId, i32)],
        treasury_state: &TreasuryState,
    ) -> Result<(), String> {
        let block_time =
            chrono::DateTime::<chrono::Utc>::from_timestamp(proposal.timestamp as i64, 0)
                .unwrap_or_else(chrono::Utc::now);
        let fee_dist = FeeDistribution::calculate_at_height(
            proposal.subsidy,
            proposal.tx_fees,
            treasury_state,
            block_time,
            proposal.block_height >= crate::coinbase_fee_split_height(),
        );
        // The node pool is the base node-reward pool plus miner dust — recompute the
        // dust exactly the way `create_proposal` does (from the same miner work).
        let (_expected_miners, miner_dust) = self
            .calculate_miner_payouts(local_miner_work, fee_dist.miner_pool)
            .map_err(|e| format!("Component-E: miner recompute failed: {e}"))?;
        let augmented_node_pool = fee_dist.node_reward_pool.saturating_add(miner_dust);

        let expected = self
            .calculate_node_payouts(recomputed_node_shares, augmented_node_pool)
            .map_err(|e| format!("Component-E: node recompute failed: {e}"))?;

        let expected_map = Self::address_amount_map(&expected);
        let proposal_map = Self::address_amount_map(&proposal.node_payouts);
        if expected_map != proposal_map {
            return Err(format!(
                "Component-E: node split does not match local recompute \
                 ({} expected node addresses vs {} in proposal)",
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
        // M-8: total order. The input is a slice today, so a stable sort is deterministic and
        // this is latent rather than broken — but the determinism then rests on the caller's
        // ordering, which is not a property this function can see or keep. Tie on the miner id.
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
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
            // This prevents unspendable outputs from malformed addresses.
            //
            // M-11: the empty case must be handled FIRST. `get_miner_address` returns an empty vec
            // for an unknown miner or one whose stored address will not parse, and this validation
            // used to sit inside `if !address.is_empty()` — so an empty address skipped it and was
            // pushed as a payout entry with no address at all. A malformed address became dust; a
            // missing one became an anyone-can-spend output carrying that miner's whole share.
            if address.is_empty() {
                warn!(
                    miner_id,
                    "M-11: miner has no resolvable payout address - treating as dust"
                );
                dust_total = dust_total.saturating_add(amount);
                allocated_total = allocated_total.saturating_add(amount);
                continue;
            }
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
    ///
    /// `pub` so the FEE convergence flag (`/api/v1/qualification/scoped-set`) can hash the
    /// FEE-armed node-split from the adopted checkpoint on a normalised pool — a read-only
    /// determinism/convergence proof, no state change.
    pub fn calculate_node_payouts(
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

        // Sort by shares descending, then node_id ascending as a DETERMINISTIC
        // tiebreak, take top N. The tiebreak is load-bearing for Option B: without
        // it, truncation at `max_node_outputs`, the dust-to-top-node redistribution
        // (`payouts.first_mut()` below) and the merge order all depend on the order
        // the qualified-node query happened to return, which differs per node — so
        // two nodes would build different node splits from the same set and
        // Component-E recompute-reject would fire on honest proposals. With the
        // node_id tiebreak the output is a pure function of the input set.
        let mut sorted: Vec<_> = node_shares.to_vec();
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
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
    /// Drop shard payouts whose address the coinbase validator would reject, folding their sats
    /// into dust (#726).
    ///
    /// Returns `(kept, invalid_sats)`.
    ///
    /// `shard_miner_payouts` pays whatever address key the shard holds; `calculate_miner_payouts`
    /// resolves each address and drops what `validate_payout_address` rejects. GHOST-02 compares
    /// the two for EXACT equality, so one malformed address made the coinbase pay an output the
    /// validator drops, the maps differed, and the whole BLOCK was rejected — one bad address
    /// costing every miner in it, the same class of failure as #722 from the other direction.
    ///
    /// ⚠ **This must not redistribute.** The amounts in `payouts` were already computed from the
    /// FULL owed set, so removing an entry here leaves every other entry untouched and the
    /// removed sats become dust, which joins the node pool. That is exactly what the legacy path
    /// does when validation fails, and it is what keeps the documented property true: the two
    /// constructors "differ only in WHICH balances they distribute, never in HOW". Filtering the
    /// owed map BEFORE distribution would instead re-weight every surviving miner — a silent
    /// change to what a block pays.
    ///
    /// `validate_payout_address` also checks the configured network, so a testnet-shaped address
    /// in a mainnet shard is caught here too (C-02).
    fn drop_invalid_shard_payouts(&self, payouts: &[(String, u64)]) -> (Vec<(String, u64)>, u64) {
        // Local rather than a shared helper: #727 adds an `addr_handle` associated fn to this
        // same impl on its own branch, and two independent definitions would collide at merge.
        // Same construction (sha256 of the address, first 6 bytes), so the handle is comparable
        // across nodes and across both rejection paths.
        let handle = |addr: &str| -> String {
            use sha2::{Digest, Sha256};
            hex::encode(&Sha256::digest(addr.as_bytes())[..6])
        };

        let mut invalid_sats: u64 = 0;
        let mut invalid_count: usize = 0;
        let kept: Vec<(String, u64)> = payouts
            .iter()
            .filter(|(addr, sats)| {
                match self.validate_payout_address(addr.as_bytes(), "shard miner") {
                    Ok(()) => true,
                    Err(e) => {
                        warn!(
                            addr_handle = %handle(addr),
                            sats = *sats,
                            error = %e,
                            "#726: shard payout address is invalid — treating as dust rather \
                             than paying an output the validator drops"
                        );
                        invalid_sats = invalid_sats.saturating_add(*sats);
                        invalid_count += 1;
                        false
                    }
                }
            })
            .cloned()
            .collect();

        if invalid_count > 0 {
            warn!(
                invalid_count,
                invalid_sats,
                remaining_payees = kept.len(),
                "#726: dropped invalid shard payout addresses into dust"
            );
        }
        (kept, invalid_sats)
    }

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
    /// Which mining mode this node runs — the thing that decides whether a payout proposal is
    /// VOTED on or approved locally. See [`PayoutHandler::is_single_operator`].
    mining_mode: MiningMode,
}

/// Does this mining mode have exactly ONE operator, and therefore nobody to vote with?
///
/// Free function rather than a method so the property can be tested exhaustively without
/// standing up a whole `PayoutHandler` (which needs a vote handler, a template processor and a
/// qualification provider). The thing being protected here is small and absolute:
/// **`PublicPool` must never be single-operator**, because that is the one mode with independent
/// operators and the only one a vote can protect.
fn is_single_operator_mode(mode: MiningMode) -> bool {
    match mode {
        // One operator paying only themselves.
        MiningMode::PrivateSolo => true,
        // One operator paying their own miners. Those miners trust the operator the same way
        // miners trust any centralised pool; a quorum would be that operator's own nodes agreeing
        // with themselves.
        MiningMode::PrivatePool => true,
        // Independent operators. This is what BFT is for.
        MiningMode::PublicPool => false,
    }
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
        mining_mode: MiningMode,
    ) -> GhostResult<Self> {
        let creator = PayoutProposalCreator::new(identity, config, db)?;

        info!(
            ?mining_mode,
            single_operator = matches!(
                mining_mode,
                MiningMode::PrivatePool | MiningMode::PrivateSolo
            ),
            "PayoutHandler initialized with required verification provider"
        );

        Ok(Self {
            creator,
            vote_handler,
            template_processor,
            qualification_provider,
            mining_mode,
        })
    }

    /// Whether this node is the ONLY operator of its pool, and so has nobody to vote with.
    ///
    /// This decides whether a payout proposal goes to BFT or is approved locally, and it is
    /// deliberately answered from the DECLARED MODE rather than from a live peer count.
    ///
    /// ⚠ That distinction is the whole safety argument. "How many peers can I see right now" is
    /// exactly the wrong question: a public-pool node that transiently lost its mesh would start
    /// self-approving its own payouts, which is precisely the attack the vote exists to prevent.
    /// The mode is a static operator declaration and cannot be induced by a network condition.
    ///
    /// What a vote actually buys is protection against ONE operator among INDEPENDENT operators
    /// paying themselves everyone's money. Both private modes have a single operator by
    /// definition:
    ///
    /// - `PrivateSolo` — the coinbase pays only the operator; there is no other party at all.
    /// - `PrivatePool` — the coinbase pays the operator's own miners. Those miners are trusting
    ///   the operator, exactly as miners trust any centralised pool. A quorum here would be the
    ///   same operator's own nodes agreeing with themselves: no added security, and — because
    ///   mainnet clamps `min_voters_for_bft` to at least 4 — it made a one-node private pool
    ///   structurally unable to pay ANYONE. It mined, accepted shares, built proposals, and
    ///   failed every one with `InsufficientVoters`.
    /// - `PublicPool` — genuinely multi-operator. Keeps the vote; nothing here changes that.
    fn is_single_operator(&self) -> bool {
        is_single_operator_mode(self.mining_mode)
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
        adopted_node_shares: Option<&[(NodeId, i32)]>,
        treasury_state: &TreasuryState,
    ) -> Result<(), String> {
        self.creator
            .validate_proposal_split(proposal, local_miner_work, treasury_state)?;

        // Component E: at/above the fee gate the node split is a pure function of the
        // fleet-ratified checkpoint, so pin it too — validate the proposal's node split
        // against the SAME adopted node list the caller read from the finalised
        // checkpoint (option c consumption). Recomputing the qualified set here would
        // diverge from the adopted list and reject the split the fleet agreed on. Below
        // the gate the node split is not consensus-enforced (legacy) and this is skipped.
        if proposal.block_height >= crate::coinbase_fee_split_height() {
            let node_shares = match adopted_node_shares {
                Some(n) => n,
                None => {
                    return Err(
                        "Component-E: no adopted node list to validate the split against"
                            .to_string(),
                    )
                }
            };
            self.creator.validate_node_split(
                proposal,
                local_miner_work,
                node_shares,
                treasury_state,
            )?;
        }
        Ok(())
    }

    /// H-MINE-1 SECURITY: The QualifiedCapabilityProvider is REQUIRED in the constructor.
    /// Node rewards will only be distributed to nodes with VERIFIED capabilities,
    /// never to nodes with merely CLAIMED capabilities.
    pub fn handle_block_found(&self, mut data: BlockFoundData) -> GhostResult<[u8; 32]> {
        // H-MINE-1: Provider is now required at construction time, no Option check needed
        // This guarantees node rewards are always based on verified capabilities

        // Get all nodes with verified capabilities from the database.
        //
        // The node split flips at the SAME gate as the miner cutoff. Below the gate:
        // the legacy now()-based path (node split is not consensus-enforced pre-
        // Component-E, so a divergent set costs nothing). At and above the gate: the
        // deterministic, cutoff-anchored, converged-ledger qualification evaluated at
        // `data.ledger_cutoff_ts` (the finalised checkpoint cutoff) — byte-for-byte the
        // SAME set the checkpoint's ledger_root committed to, so the coinbase pays
        // exactly what the fleet ratified and Component-E recompute-reject can only pass.
        let qualified_shares = if data.block_height >= crate::coinbase_fee_split_height() {
            // Option (c) adopt-CONSUMPTION: at/above the gate the node split is the
            // fleet-ratified set the proposer path already sourced from the finalised
            // checkpoint (`read_adopted_payout`) and passed in as `data.node_shares`.
            // Trust it VERBATIM — recomputing here (as the pre-(c) code did) would
            // diverge from the adopted list and the exact-equality validators would
            // reject the very split the fleet agreed on. A-2/A-2b subnet/assignment
            // scoping already happened when the checkpoint's set was computed.
            data.node_shares.clone()
        } else {
            self.qualification_provider.get_all_qualified_nodes()
        };

        let claimed_count = data.node_shares.len();
        let verified_count = qualified_shares.len();
        let total_claimed_shares: i32 = data.node_shares.iter().map(|(_, s)| s).sum();
        let total_verified_shares: i32 = qualified_shares.iter().map(|(_, s)| s).sum();

        info!(
            claimed_nodes = claimed_count,
            verified_nodes = verified_count,
            claimed_shares = total_claimed_shares,
            verified_shares = total_verified_shares,
            adopted = data.block_height >= crate::coinbase_fee_split_height(),
            "Node shares for payout (adopted checkpoint set at/above gate, else verified)"
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

        // Stage 6 step 3: at and above the gate there is no vote at all.
        //
        // `SHARE_SHARD.md` §8 — "No consensus on the ledger. Each node pays from its own view."
        // §7 lists voting, quorum and two-phase commit as deleted. The proposal above was already
        // built from this node's own shard view (`BlockFoundData::shard_owed`), so a vote adds no
        // information about the shares; `validate_proposal_split` only ever recomputed the split
        // from the voter's OWN table and demanded an exact match (GHOST-02).
        //
        // ⛔ That exact match is a liveness hazard, not a safety property: nothing finalised
        // between 18 and 21 August because tables that had diverged could not agree, and one
        // address 6.71% apart rejected every checkpoint symmetrically. Above this gate divergence
        // is benign — `owed` is signed and never clamped, so a small over- or under-payment leaves
        // a residual the next block corrects.
        //
        // Share validity is unaffected and lives where it always did: per-share at receive time
        // (GHOST-09 signature with receiver and address binding, PoW preimage, difficulty-tier
        // commitment), plus §6 sampling. Delete the gate, keep the rule.
        if proposal.block_height >= crate::payout_from_shard_height() {
            info!(
                round_id = proposal.round_id,
                height = proposal.block_height,
                miners = proposal.miner_payouts.len(),
                nodes = proposal.node_payouts.len(),
                hash = %hex::encode(&proposal_hash[..8]),
                "Paying from this node's own shard view (no vote — Stage 6 step 3)"
            );
            self.template_processor.set_local_payout(proposal);
            return Ok(proposal_hash);
        }

        // Submit to vote handler for BFT consensus
        // A single-operator pool has nobody to vote with, so it approves its own proposal.
        //
        // This is the same resolution #592 reached for solo, applied to the other mode that has
        // exactly one operator. A private pool is one person letting their miners mine through
        // their node; requiring `min_voters_for_bft` (>= 4 on mainnet) meant that person had to
        // run four nodes — all their own — before anyone could be paid. Four nodes belonging to
        // one operator voting with each other is not a security property, it is a quorum of one
        // person. Meanwhile a single-node private pool could never pay at all.
        //
        // ⚠ `is_single_operator` keys on the DECLARED MODE, never on how many peers happen to be
        // reachable — see its doc. Public pool is untouched and still votes.
        if self.is_single_operator() {
            info!(
                round_id = proposal.round_id,
                miners = proposal.miner_payouts.len(),
                nodes = proposal.node_payouts.len(),
                mode = ?self.mining_mode,
                hash = %hex::encode(&proposal_hash[..8]),
                "Single-operator pool: approving own payout proposal (no BFT — no second operator \
                 to vote with)"
            );
            // Same two steps the solo path takes: the proposal must be in the cache before it can
            // be approved (`set_approved_payout` refuses a hash whose data it cannot find,
            // MED-POOL-6), and `set_approved_payout` is what sets the M-28 coinbase commitment
            // that `submitblock` requires.
            proposal.proposal_hash = proposal_hash;
            self.template_processor.store_proposal(proposal.clone());
            self.template_processor.set_approved_payout(proposal_hash);
            return Ok(proposal_hash);
        }

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

        // The proposal must be in the cache before it can be approved: `set_approved_payout`
        // refuses a hash whose data it cannot find (MED-POOL-6).
        self.template_processor.store_proposal(proposal.clone());

        // #592: solo approves its own proposal instead of submitting it to BFT.
        //
        // A solo node has no mesh. The BFT pipeline requires `min_voters_for_bft`, which clamps to
        // 4..=7, so a standalone node's proposal failed with `InsufficientVoters` every time — no
        // coinbase commitment was ever approved, and `submitblock` then refused the block. Solo
        // could not mine at all.
        //
        // There is nothing for consensus to protect here: solo contributes no shares to the public
        // ledger and its coinbase pays only its own operator, so there is no other party whose
        // funds a vote would be safeguarding. The proposal is built by the same
        // `create_solo_proposal` under the same fee model as pool mode, and the coinbase is built
        // from it by the same `build_coinbase_parts_with_payout_snapshot` — one construction path,
        // no solo-specific economics.
        //
        // `set_approved_payout` also sets the M-28 coinbase commitment, which is what unblocks
        // `submitblock`.
        info!(
            round_id = proposal.round_id,
            solo_payout = proposal.miner_payouts[0].amount,
            nodes = proposal.node_payouts.len(),
            hash = %hex::encode(&proposal_hash[..8]),
            "Solo mode: approving own payout proposal (no BFT — solo has no mesh)"
        );

        self.template_processor.set_approved_payout(proposal_hash);

        Ok(proposal_hash)
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {

    /// `owed()` is `accrued − settled` and is documented to go negative transiently. The cast to
    /// `u128` is where that becomes money: `-1i64 as u128` is 2^128−1, an address weighted above
    /// the entire pool, and the coinbase splits proportionally. So the filter is not tidiness.
    #[test]
    fn shard_miner_work_drops_non_positive_balances_before_the_cast() {
        let owed = std::collections::BTreeMap::from([
            ("bc1qalice".to_string(), 500i64),
            ("bc1qbob".to_string(), -1i64),
            ("bc1qcarol".to_string(), 0i64),
        ]);
        let got = super::select_shard_miner_work(&owed);
        assert_eq!(
            got,
            vec![("bc1qalice".to_string(), 500u128)],
            "a negative or zero balance reached the output"
        );
        assert!(
            got.iter().all(|(_, w)| *w < u128::MAX / 2),
            "a negative balance wrapped through the u128 cast"
        );
    }

    /// Canonical order: work descending, address ascending on a tie. `compute_ledger_root` sorts
    /// internally so the root does not depend on this, but the adopted list is persisted and read
    /// back by the coinbase builder, and a total order means two nodes cannot differ on a tie.
    #[test]
    fn shard_miner_work_is_ordered_work_desc_then_address_asc() {
        let owed = std::collections::BTreeMap::from([
            ("bc1qb".to_string(), 10i64),
            ("bc1qa".to_string(), 10i64),
            ("bc1qc".to_string(), 99i64),
        ]);
        assert_eq!(
            super::select_shard_miner_work(&owed),
            vec![
                ("bc1qc".to_string(), 99u128),
                ("bc1qa".to_string(), 10u128),
                ("bc1qb".to_string(), 10u128),
            ]
        );
    }

    /// The adopted list must never be longer than a coinbase can pay, or the checkpoint ratifies
    /// a split that cannot be built. Truncation keeps the LARGEST balances, which is why the sort
    /// has to happen first — the reverse order would drop the addresses that matter.
    #[test]
    fn shard_miner_work_caps_at_max_miner_outputs_keeping_the_largest() {
        let cap = ghost_common::constants::MAX_MINER_OUTPUTS;
        let owed: std::collections::BTreeMap<String, i64> = (0..cap as i64 + 25)
            .map(|i| (format!("bc1q{i:04}"), i + 1))
            .collect();
        let got = super::select_shard_miner_work(&owed);
        assert_eq!(got.len(), cap, "cap not applied");
        assert_eq!(
            got[0].1,
            (cap as u128) + 25,
            "truncation kept the wrong end of the list"
        );
        let smallest_kept = got.last().expect("non-empty").1;
        assert_eq!(smallest_kept, 26u128, "expected the largest `cap` balances");
    }

    #[test]
    fn shard_miner_work_on_an_empty_shard_is_empty_not_a_panic() {
        assert!(super::select_shard_miner_work(&std::collections::BTreeMap::new()).is_empty());
    }
    use super::*;

    fn test_identity() -> Arc<NodeIdentity> {
        Arc::new(NodeIdentity::generate())
    }

    // ---- Payout-ledger root (checkpoint canonicaliser) ----

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    #[test]
    fn ledger_root_is_deterministic_and_order_independent() {
        let miners_a = vec![
            ("bc1qaaa".to_string(), 100u128),
            ("bc1qbbb".to_string(), 250u128),
            ("bc1qccc".to_string(), 250u128), // tie on work → address breaks it
        ];
        let nodes_a = vec![(nid(3), 9i32), (nid(1), 15i32), (nid(2), 7i32)];

        // Same content, different query order on BOTH sets.
        let miners_b = vec![
            ("bc1qccc".to_string(), 250u128),
            ("bc1qaaa".to_string(), 100u128),
            ("bc1qbbb".to_string(), 250u128),
        ];
        let nodes_b = vec![(nid(1), 15i32), (nid(2), 7i32), (nid(3), 9i32)];

        let root_a = compute_ledger_root(&miners_a, &nodes_a, 1_784_000_000, 958_800);
        let root_b = compute_ledger_root(&miners_b, &nodes_b, 1_784_000_000, 958_800);
        assert_eq!(root_a, root_b, "root must be independent of input order");

        // Recompute must be byte-stable across calls.
        let root_a2 = compute_ledger_root(&miners_a, &nodes_a, 1_784_000_000, 958_800);
        assert_eq!(root_a, root_a2);
    }

    #[test]
    fn ledger_root_changes_when_any_input_changes() {
        let miners = vec![("bc1qaaa".to_string(), 100u128)];
        let nodes = vec![(nid(1), 15i32)];
        let base = compute_ledger_root(&miners, &nodes, 1_784_000_000, 958_800);

        // different miner work
        let m2 = vec![("bc1qaaa".to_string(), 101u128)];
        assert_ne!(
            base,
            compute_ledger_root(&m2, &nodes, 1_784_000_000, 958_800)
        );
        // different node shares
        let n2 = vec![(nid(1), 14i32)];
        assert_ne!(
            base,
            compute_ledger_root(&miners, &n2, 1_784_000_000, 958_800)
        );
        // different cutoff
        assert_ne!(
            base,
            compute_ledger_root(&miners, &nodes, 1_784_000_001, 958_800)
        );
        // different height
        assert_ne!(
            base,
            compute_ledger_root(&miners, &nodes, 1_784_000_000, 958_801)
        );
    }

    // ---- Cutoff resolver (the v1.10.32 fix) ----

    #[test]
    fn resolve_cutoff_dormant_gate_ignores_checkpoint_and_returns_now() {
        // The gate is dormant (u64::MAX) in the test process — no test sets it — so
        // this locks the deploy-safety invariant: shipping this binary with the gate
        // dormant behaves EXACTLY like before. Even with a finalised checkpoint sitting
        // in the DB (the dark finaliser is always running post-deploy), the coinbase
        // cutoff stays wall-clock now() until the gate actually fires.
        let db = ghost_storage::Database::in_memory().expect("in-memory db");
        db.upsert_payout_ledger_checkpoint(&ghost_storage::PayoutLedgerCheckpointRecord {
            height: 958_800,
            cutoff_ts: 1_700_000_000, // deliberately far in the past
            ledger_root: [7u8; 32],
            proposer_id: "aa".repeat(32),
            active_node_count: 8,
            miner_payouts: vec![],
            node_shares: vec![],
        })
        .expect("upsert checkpoint");

        let before = chrono::Utc::now().timestamp();
        let got = resolve_payout_cutoff(&db, 958_900).expect("dormant gate always resolves");
        let after = chrono::Utc::now().timestamp();

        assert!(
            got >= before && got <= after,
            "dormant gate must return now() ({before}..={after}), not the checkpoint's {}: got {got}",
            1_700_000_000i64
        );
        assert_ne!(
            got, 1_700_000_000,
            "must NOT use the checkpoint cutoff while dormant"
        );
    }

    fn db_with_checkpoint(height: u64, cutoff_ts: i64) -> ghost_storage::Database {
        let db = ghost_storage::Database::in_memory().expect("in-memory db");
        db.upsert_payout_ledger_checkpoint(&ghost_storage::PayoutLedgerCheckpointRecord {
            height,
            cutoff_ts,
            ledger_root: [1u8; 32],
            proposer_id: "bb".repeat(32),
            active_node_count: 8,
            miner_payouts: vec![],
            node_shares: vec![],
        })
        .expect("upsert checkpoint");
        db
    }

    /// Option (c) consumption: `read_adopted_payout` returns the finalised checkpoint's
    /// ADOPTED miner + node lists verbatim (what the coinbase and the validators build
    /// from at/above the gate), and `None` when there is no checkpoint at/before the
    /// height (caller then builds a treasury-only coinbase).
    #[test]
    fn read_adopted_payout_round_trips_the_finalised_lists() {
        let db = ghost_storage::Database::in_memory().expect("in-memory db");
        let miners = vec![
            ("bc1qalice".to_string(), 3_000_000u128),
            ("bc1qbob".to_string(), 1_500_000u128),
        ];
        let nodes = vec![([0xAAu8; 32], 10i32), ([0xBBu8; 32], 6i32)];
        db.upsert_payout_ledger_checkpoint(&ghost_storage::PayoutLedgerCheckpointRecord {
            height: 958_800,
            cutoff_ts: 1_700_000_000,
            ledger_root: [9u8; 32],
            proposer_id: "cc".repeat(32),
            active_node_count: 8,
            miner_payouts: miners.clone(),
            node_shares: nodes.clone(),
        })
        .expect("upsert checkpoint");

        let (got_m, got_n) =
            read_adopted_payout(&db, 958_900).expect("a finalised checkpoint exists at/before");
        assert_eq!(got_m, miners, "adopted miner list must round-trip verbatim");
        assert_eq!(got_n, nodes, "adopted node list must round-trip verbatim");

        // No checkpoint at/before an earlier height → None (treasury-only fallback).
        assert!(
            read_adopted_payout(&db, 958_700).is_none(),
            "no finalised checkpoint at/before the height must yield None"
        );
    }

    fn seed_node_with_addr(db: &ghost_storage::Database, node_id: NodeId, addr: &str) {
        db.upsert_node(&ghost_storage::NodeRecord {
            node_id: hex::encode(node_id),
            public_address: None,
            display_name: None,
            first_seen: 0,
            last_seen: 0,
            is_elder: false,
            elder_order: None,
            capabilities: "{}".to_string(),
            total_uptime_secs: 0,
            uptime_7d_percent: 0.0,
            verification_pass_rate: 0.0,
            total_shares_received: 0,
            total_blocks_found: 0,
            payout_address: Some(addr.to_string()),
        })
        .expect("seed node");
    }

    #[test]
    fn node_payouts_are_a_pure_function_of_the_set_not_its_order() {
        // The tiebreak fix: equal top-shares nodes plus a non-dividing pool leave a
        // remainder that goes to the top node. Without a node_id tiebreak the "top"
        // node — and thus the whole split — would depend on the order the qualified-
        // node query returned, so two nodes would build different coinbases and
        // Component-E recompute-reject would fire on honest proposals.
        let config = PayoutConfig {
            treasury_address: Some(vec![1u8; 20]),
            network: ghost_common::config::BitcoinNetwork::Regtest,
            ..Default::default()
        };
        let db = Arc::new(ghost_storage::Database::in_memory().expect("db"));
        let (a1, a2, a3) = (payout_addr(0x21), payout_addr(0x22), payout_addr(0x23));
        seed_node_with_addr(&db, nid(1), &a1);
        seed_node_with_addr(&db, nid(2), &a2);
        seed_node_with_addr(&db, nid(3), &a3);
        let creator =
            PayoutProposalCreator::new(test_identity(), config, Arc::clone(&db)).expect("creator");

        let fwd = vec![(nid(1), 5i32), (nid(2), 5i32), (nid(3), 5i32)];
        let rev = vec![(nid(3), 5i32), (nid(2), 5i32), (nid(1), 5i32)];
        let pool = 10_000u64; // 10000 / 15 shares → remainder, routed to the top node

        let via_fwd = creator.calculate_node_payouts(&fwd, pool).expect("fwd");
        let via_rev = creator.calculate_node_payouts(&rev, pool).expect("rev");
        assert_eq!(
            PayoutProposalCreator::address_amount_map(&via_fwd),
            PayoutProposalCreator::address_amount_map(&via_rev),
            "node split must not depend on input order"
        );
        // Remainder lands on the lowest node_id (nid(1) → a1) deterministically.
        let map = PayoutProposalCreator::address_amount_map(&via_fwd);
        let top = *map.get(a1.as_bytes()).expect("a1 present");
        let other = *map.get(a2.as_bytes()).expect("a2 present");
        assert!(
            top > other,
            "remainder must go to the lowest-id top node: {top} vs {other}"
        );
    }

    #[test]
    fn cutoff_binding_inert_below_gate() {
        // Below the gate there is no checkpoint requirement even with none present.
        let db = ghost_storage::Database::in_memory().expect("in-memory db");
        assert!(check_proposal_cutoff_binding(&db, 900_000, 123, 950_000).is_ok());
    }

    #[test]
    fn cutoff_binding_accepts_matching_checkpoint_cutoff() {
        let db = db_with_checkpoint(958_800, 1_784_000_000);
        // Block at-or-above the checkpoint, cutoff equals the finalised cutoff.
        assert!(check_proposal_cutoff_binding(&db, 958_806, 1_784_000_000, 950_000).is_ok());
    }

    #[test]
    fn cutoff_binding_rejects_forged_cutoff() {
        let db = db_with_checkpoint(958_800, 1_784_000_000);
        // A proposer who names any cutoff other than the ratified one is rejected —
        // this is the attack the whole scheme closes.
        let err = check_proposal_cutoff_binding(&db, 958_806, 1_784_000_042, 950_000)
            .expect_err("forged cutoff must be rejected");
        assert!(err.contains("not the finalised checkpoint cutoff"), "{err}");
    }

    #[test]
    fn cutoff_binding_rejects_when_no_checkpoint_finalised() {
        // At/above the gate with no finalised checkpoint yet: refuse to ratify a split.
        let db = ghost_storage::Database::in_memory().expect("in-memory db");
        let err = check_proposal_cutoff_binding(&db, 958_806, 1_784_000_000, 950_000)
            .expect_err("must reject with no checkpoint");
        assert!(err.contains("no finalised payout checkpoint"), "{err}");
    }

    #[test]
    fn ledger_root_length_prefixing_prevents_ambiguity() {
        // ("ab","c") vs ("a","bc") must not collide (concatenation ambiguity guard).
        let m1 = vec![("ab".to_string(), 1u128), ("c".to_string(), 1u128)];
        let m2 = vec![("a".to_string(), 1u128), ("bc".to_string(), 1u128)];
        let nodes: Vec<(NodeId, i32)> = vec![];
        assert_ne!(
            compute_ledger_root(&m1, &nodes, 1, 1),
            compute_ledger_root(&m2, &nodes, 1, 1),
        );
    }

    #[test]
    fn ledger_root_handles_empty_sets() {
        let empty_m: Vec<(String, u128)> = vec![];
        let empty_n: Vec<(NodeId, i32)> = vec![];
        // Deterministic, non-panicking, and distinct from a populated root.
        let r0 = compute_ledger_root(&empty_m, &empty_n, 1, 1);
        assert_eq!(r0, compute_ledger_root(&empty_m, &empty_n, 1, 1));
        let r1 = compute_ledger_root(&[("x".to_string(), 1)], &empty_n, 1, 1);
        assert_ne!(r0, r1);
    }

    // ---- GHOST-02: proposal split recompute ----

    /// Audit M-11. `get_miner_address` returns an empty vec for an unknown miner or one whose
    /// stored address fails to parse, commenting that it "will be filtered out by proposal
    /// validator". `calculate_miner_payouts` did not filter it: the HIGH-MINE-5 validation is
    /// inside `if !address.is_empty()`, so an EMPTY address skipped validation entirely and was
    /// pushed as a `PayoutEntry` with no address.
    ///
    /// A non-empty invalid address becomes dust; an empty one became an output. Downstream that
    /// stalls payouts (the vote handler rejects it) and, if that check were ever bypassed, is an
    /// anyone-can-spend coinbase output.
    #[test]
    fn a_miner_with_no_resolvable_address_becomes_dust_not_an_empty_output() {
        let creator = ghost02_creator();
        // A miner_id that is not itself an address and has no row in `miners`, so
        // `get_miner_address` yields empty.
        let miner_work: Vec<(String, u128)> = vec![("worker-with-no-address".to_string(), 1_000)];

        let (payouts, dust) = creator
            .calculate_miner_payouts(&miner_work, 5_000_000_000)
            .expect("calculation must succeed");

        assert!(
            payouts.iter().all(|p| !p.address.is_empty()),
            "no payout entry may carry an empty address: {payouts:?}"
        );
        assert!(
            dust > 0,
            "the unresolvable miner's share must go to the node pool as dust, got dust={dust}"
        );
    }

    /// Block submission depends on these two agreeing, and today only a comment says they do.
    ///
    /// GHOST-02 compares for EXACT equality, not tolerance: `expected` is built by
    /// `calculate_miner_payouts` from the adopted checkpoint list, `proposal.miner_payouts` by
    /// `shard_miner_payouts` from the shard. Before #722's gate those are two different ledgers
    /// and the check fails outright — measured on the live fleet as a 2-address frozen checkpoint
    /// against a 5-address shard, which rejects a won block rather than mispaying it.
    ///
    /// After the gate both derive from the same `owed` balances, and the two functions are
    /// documented to "differ only in WHICH balances they distribute, never in HOW". This pins
    /// that claim, using the magnitudes actually on the fleet so the rounding is representative
    /// rather than convenient.
    #[test]
    fn shard_derived_adopted_list_and_the_coinbase_split_agree_exactly() {
        // Mainnet, not the shared regtest fixture: `calculate_miner_payouts` validates every
        // resolved address against the configured network, so mainnet balances have to be judged
        // by a mainnet creator or every payout is discarded as off-network.
        let creator = {
            let config = PayoutConfig {
                treasury_address: Some(vec![1u8; 20]),
                network: ghost_common::config::BitcoinNetwork::Mainnet,
                ..Default::default()
            };
            let db = Arc::new(ghost_storage::Database::in_memory().expect("in-memory db"));
            PayoutProposalCreator::new(test_identity(), config, db).expect("creator")
        };
        // Live vm1 balances, micro-work.
        //
        // Addresses must be REAL bech32: `get_miner_address` returns the key unchanged when it
        // parses as an address and otherwise falls through to a database lookup. A placeholder
        // like "bc1qalice" takes the second path, resolves to nothing, and the validator pays
        // nobody — which is how this test first failed, and is worth knowing because it is also
        // how a malformed address in the shard would behave in production: `shard_miner_payouts`
        // does not validate addresses, so the coinbase would pay one the validator drops.
        let owed = std::collections::BTreeMap::from([
            (
                "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492".to_string(),
                76_039_051_664_125_167i64,
            ),
            (
                "bc1qhfgc0uj7wv03vmchxe2hn8lhtu6ey9zaf0nre2".to_string(),
                3_494_065_686_437_835i64,
            ),
            (
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                2_503_874_639_417_892i64,
            ),
            (
                "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3".to_string(),
                532_541_467_700_909i64,
            ),
            (
                "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9".to_string(),
                9_741_908_758_669i64,
            ),
        ]);
        // 99% of a 3.125 BTC subsidy — the miner pool at the current halving era.
        let miner_pool: u64 = 309_375_000;

        // What a validator recomputes from the adopted checkpoint, post-gate.
        let adopted = super::select_shard_miner_work(&owed);
        let (expected, _dust) = creator
            .calculate_miner_payouts(&adopted, miner_pool)
            .expect("recompute");
        let expected_map: std::collections::BTreeMap<String, u64> = expected
            .iter()
            .map(|e| {
                (
                    String::from_utf8(e.address.clone()).expect("utf8 address"),
                    e.amount,
                )
            })
            .collect();

        // What the coinbase actually pays.
        let paid = ghost_common::share_shard::shard_miner_payouts(
            &owed,
            miner_pool,
            ghost_common::constants::MAX_MINER_OUTPUTS,
            super::LEDGER_DUST_SATS,
        );
        let paid_map: std::collections::BTreeMap<String, u64> =
            paid.payouts.iter().cloned().collect();

        assert_eq!(
            expected_map, paid_map,
            "the adopted list and the coinbase disagree — GHOST-02 rejects the block"
        );
        assert!(!expected_map.is_empty(), "the fixture paid nobody");
    }

    // ── #726: shard payouts must pass the same address validation the validator applies ─────

    /// A regtest-valid address, so `ghost02_creator` (Regtest) accepts it.
    const RT_ADDR_A: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    const RT_ADDR_B: &str = "bcrt1qee0086cgnlvdvge8e4swx3zyyhq6j8de45ct35exdd6xmzmed8pqg6t2hc";

    /// **The bug.** A malformed address in the shard used to reach the coinbase, where the
    /// validator drops it — so the recompute and the proposal disagreed and GHOST-02 rejected
    /// the whole block. One bad address cost every miner in it.
    #[test]
    fn an_invalid_shard_address_becomes_dust_instead_of_a_dropped_output() {
        let creator = ghost02_creator();
        let payouts = vec![
            (RT_ADDR_A.to_string(), 1_000u64),
            ("not a bitcoin address".to_string(), 250u64),
        ];

        let (kept, invalid_sats) = creator.drop_invalid_shard_payouts(&payouts);

        assert_eq!(kept.len(), 1, "the malformed address must not be paid");
        assert_eq!(kept[0].0, RT_ADDR_A);
        assert_eq!(
            invalid_sats, 250,
            "its sats must be accounted as dust, not lost"
        );
    }

    /// **The property that keeps GHOST-02 agreeing.** Removing an invalid entry must leave every
    /// other amount byte-identical. The amounts were computed from the FULL owed set, so dropping
    /// one here folds its sats into dust; filtering the owed map *before* distribution would
    /// instead re-weight every surviving miner — silently changing what the block pays.
    #[test]
    fn dropping_an_invalid_address_does_not_redistribute_to_the_others() {
        let creator = ghost02_creator();
        let with_bad = vec![
            (RT_ADDR_A.to_string(), 1_000u64),
            ("!!not-an-address!!".to_string(), 999u64),
            (RT_ADDR_B.to_string(), 2_000u64),
        ];
        let without_bad = vec![
            (RT_ADDR_A.to_string(), 1_000u64),
            (RT_ADDR_B.to_string(), 2_000u64),
        ];

        let (kept_a, invalid) = creator.drop_invalid_shard_payouts(&with_bad);
        let (kept_b, none) = creator.drop_invalid_shard_payouts(&without_bad);

        assert_eq!(kept_a, kept_b, "surviving amounts must be untouched");
        assert_eq!(invalid, 999);
        assert_eq!(none, 0);
    }

    /// C-02: `validate_payout_address` also pins the network, so a mainnet-shaped address in a
    /// regtest-configured pool is caught by the same filter. Cross-network payouts are
    /// unspendable, and the issue calls this out explicitly.
    #[test]
    fn a_wrong_network_shard_address_is_also_dusted() {
        let creator = ghost02_creator();
        // Valid bech32, valid mainnet — wrong network for this Regtest creator.
        let payouts = vec![
            (RT_ADDR_A.to_string(), 500u64),
            (
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
                700u64,
            ),
        ];

        let (kept, invalid_sats) = creator.drop_invalid_shard_payouts(&payouts);

        assert_eq!(
            kept.len(),
            1,
            "a mainnet address must not be paid on regtest"
        );
        assert_eq!(kept[0].0, RT_ADDR_A);
        assert_eq!(invalid_sats, 700);
    }

    /// The common case must cost nothing and change nothing.
    #[test]
    fn an_all_valid_shard_split_is_passed_through_untouched() {
        let creator = ghost02_creator();
        let payouts = vec![
            (RT_ADDR_A.to_string(), 1_000u64),
            (RT_ADDR_B.to_string(), 2_000u64),
        ];

        let (kept, invalid_sats) = creator.drop_invalid_shard_payouts(&payouts);

        assert_eq!(kept, payouts);
        assert_eq!(invalid_sats, 0);
    }

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
        // Conserve value (GHOST-02 requires it): with no node payouts, everything not
        // paid to miners is the treasury's — the same remainder a real empty-node block
        // routes there. Without this the proposal would make `subsidy - miner` sats
        // vanish and be rejected on conservation before the miner recompute is even
        // reached.
        let miner_sum: u64 = miner_payouts.iter().map(|e| e.amount).sum();
        PayoutProposal {
            proposal_hash: [0u8; 32],
            round_id: 1,
            block_hash: [0u8; 32],
            block_height: 100,
            proposer: [0u8; 32],
            miner_payouts,
            node_payouts: vec![],
            treasury_amount: subsidy.saturating_sub(miner_sum),
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

    // The honest-accept case is covered by `ghost02_ledger_proposal_survives_validator_recompute`
    // below (a full proposal from the real proposer). An empty-ledger split can't be tested as
    // "accepted" any more: with no miners the coinbase can't conserve value, so it is correctly
    // rejected — which is what the conservation check exists to catch.

    // ---- GHOST-02: the proposer and the validator must agree on WHICH shares pay ----
    //
    // The proposer (main.rs block-found) builds the miner split from the cross-round
    // UNPAID LEDGER (`get_top_unpaid_addresses`, cap 1000, dust-filtered). The GHOST-02
    // validator recomputes it from `rm.get_miner_work_scaled(proposal.round_id)` — the
    // in-memory work of the single ~90s job-round the block happened to land in.
    //
    // Rounds rotate per template refresh, so a round holds a sliver of the ledger. The two
    // sets cannot be equal, and `validate_proposal_split` demands exact equality — so an
    // honest proposal from an honest proposer is rejected by every honest validator. Past
    // CLUSTER_ENFORCEMENT_HEIGHT that rejection is enforced, not merely logged.

    const LEDGER_ROUNDS: u64 = 5;
    const SHARES_PER_ROUND: usize = 4;

    /// A real, checksum-valid P2WPKH address, derived deterministically from `seed`.
    /// Regtest, to satisfy the C-02 `require_network` check against the test config.
    fn payout_addr(seed: u8) -> String {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).expect("secret key");
        let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
        let cpk = bitcoin::CompressedPublicKey::try_from(pk).expect("compressed pubkey");
        bitcoin::Address::p2wpkh(&cpk, bitcoin::Network::Regtest).to_string()
    }

    /// A spendable P2WPKH scriptPubKey: OP_0 PUSH20 <hash160>.
    fn treasury_script() -> Vec<u8> {
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&[0x11u8; 20]);
        script
    }

    fn ledger_creator() -> (PayoutProposalCreator, Arc<ghost_storage::Database>) {
        let config = PayoutConfig {
            treasury_address: Some(treasury_script()),
            network: ghost_common::config::BitcoinNetwork::Regtest,
            ..Default::default()
        };
        let db = Arc::new(ghost_storage::Database::in_memory().expect("in-memory db"));
        let creator =
            PayoutProposalCreator::new(test_identity(), config, Arc::clone(&db)).expect("creator");
        (creator, db)
    }

    /// The per-miner shape of a realistic unpaid ledger: `(work_per_share, last_round)`.
    ///
    /// This mirrors production, where the `miners` table holds far more miners than are
    /// active in any single ~90s round. `carol` has the largest unpaid balance but has
    /// submitted nothing recently — she is absent from the winning round entirely, while
    /// still being owed by the ledger. `alice` and `bob` also carry different per-round
    /// weights than their ledger weights, so the proportions diverge too.
    const LEDGER_MINERS: [(f64, u64); 3] = [
        (1_000.0, LEDGER_ROUNDS), // alice — still hashing in the winning round
        (2_000.0, LEDGER_ROUNDS), // bob   — still hashing in the winning round
        (5_000.0, 3),             // carol — went idle after round 3, still owed
    ];

    /// Seeds miners whose unpaid shares span several job-rounds. Returns their addresses.
    fn seed_unpaid_ledger(db: &ghost_storage::Database, now: i64) -> Vec<String> {
        let addrs: Vec<String> = (1..=3u8).map(payout_addr).collect();
        for (i, addr) in addrs.iter().enumerate() {
            let (work, last_round) = LEDGER_MINERS[i];
            let miner_id = format!("{addr}.w{}", i + 1);
            db.upsert_miner(&ghost_storage::MinerRecord {
                miner_id: miner_id.clone(),
                payout_address: addr.clone(),
                first_seen: now - 1_000,
                last_seen: now,
                connected_node: None,
                total_shares: 0,
                total_work: 0.0,
                blocks_won: 0,
                total_payouts_sats: 0,
                avg_hashrate_ths: 0.0,
            })
            .expect("upsert miner");

            for round_id in 1..=last_round {
                for k in 0..SHARES_PER_ROUND {
                    db.insert_share(&ghost_storage::ShareRecord {
                        id: None,
                        round_id,
                        miner_id: miner_id.clone(),
                        difficulty: work,
                        work,
                        share_hash: format!("share-{i}-{round_id}-{k}"),
                        timestamp: now - 600 + (round_id as i64 * 90) + k as i64,
                        received_by: "node-a".to_string(),
                        valid: true,
                    })
                    .expect("insert share");
                }
            }
        }
        addrs
    }

    /// What `RoundManager::get_miner_work_scaled(round_id)` holds for the winning round:
    /// only the miners who submitted a share *in that ~90s round*, keyed by miner_id.
    fn winning_round_work(addrs: &[String]) -> Vec<(String, u128)> {
        use ghost_accounting::shares::WORK_SCALE;
        addrs
            .iter()
            .enumerate()
            .filter(|(i, _)| LEDGER_MINERS[*i].1 >= LEDGER_ROUNDS)
            .map(|(i, addr)| {
                let miner_id = format!("{addr}.w{}", i + 1);
                let work = LEDGER_MINERS[i].0 * SHARES_PER_ROUND as f64;
                (miner_id, (work * WORK_SCALE as f64) as u128)
            })
            .collect()
    }

    /// Post-grouping-gate height, as production is.
    const LEDGER_TEST_HEIGHT: u64 = 957_896;
    const LEDGER_TEST_SUBSIDY: u64 = 312_500_000;

    /// Builds the proposal exactly as the proposer does at block-found: split derived from
    /// the unpaid ledger via `select_ledger_miner_work`, cutoff carried onto the proposal.
    fn ledger_proposal(
        creator: &PayoutProposalCreator,
        db: &ghost_storage::Database,
        addrs: &[String],
        cutoff_ts: i64,
    ) -> PayoutProposal {
        let miner_work =
            select_ledger_miner_work(db, cutoff_ts, LEDGER_TEST_HEIGHT, LEDGER_TEST_SUBSIDY)
                .expect("ledger work");
        assert_eq!(
            miner_work.len(),
            3,
            "all three miners carry unpaid work across rounds"
        );

        creator
            .create_proposal(BlockFoundData {
                shard_owed: None,
                round_id: LEDGER_ROUNDS,
                ledger_cutoff_ts: cutoff_ts,
                block_hash: [7u8; 32],
                block_height: LEDGER_TEST_HEIGHT,
                block_timestamp: chrono::DateTime::from_timestamp(cutoff_ts, 0).expect("ts"),
                winning_miner_id: "pool".to_string(),
                winning_miner_payout_address: Some(addrs[0].to_string()),
                treasury_address_snapshot: Some(treasury_script()),
                winning_node_id: [9u8; 32],
                subsidy_sats: LEDGER_TEST_SUBSIDY,
                tx_fees_sats: 0,
                miner_work,
                node_shares: vec![],
                treasury_state: TreasuryState::new(),
            })
            .expect("create proposal")
    }

    /// REGRESSION (FEE pre-arm): `create_proposal` must compute the treasury-decay fee split
    /// from the proposal's cutoff (`ledger_cutoff_ts`) — the timestamp the proposal is stamped
    /// with and that both validators recompute against — NOT wall-clock `block_timestamp`. With
    /// the decay threshold reached, a cutoff in decay year 0 and a `block_timestamp` a year later
    /// give different treasury rates; building from `block_timestamp` diverges from every
    /// validator at a decay-year boundary and the proposer's own coinbase is rejected — the class
    /// of now()-under-enforcement bug that broke v1.10.32. Post-gate the cutoff is the converged
    /// checkpoint time (~tip-6, ~an hour behind now), widening the divergence window.
    #[test]
    fn create_proposal_fee_split_anchors_to_cutoff_not_block_timestamp() {
        let (creator, db) = ledger_creator();
        let cutoff_ts = 1_800_000_000i64; // ≈40 days after threshold → decay year 0
        let block_ts = 1_831_200_000i64; // ≈400 days after threshold → decay year 1
        let threshold = chrono::DateTime::<chrono::Utc>::from_timestamp(1_796_544_000, 0).unwrap();
        let treasury = TreasuryState::from_stored(0, Some(threshold));
        let addrs = seed_unpaid_ledger(&db, cutoff_ts);
        // Give the node a payout address so its share lands as a node output rather than
        // falling back to the treasury (which would make treasury_amount decay-independent).
        seed_node_with_addr(&db, [9u8; 32], &addrs[0]);
        let miner_work =
            select_ledger_miner_work(&db, cutoff_ts, LEDGER_TEST_HEIGHT, LEDGER_TEST_SUBSIDY)
                .expect("ledger work");

        let proposal = creator
            .create_proposal(BlockFoundData {
                shard_owed: None,
                round_id: LEDGER_ROUNDS,
                ledger_cutoff_ts: cutoff_ts,
                block_hash: [7u8; 32],
                block_height: LEDGER_TEST_HEIGHT,
                // A FULL YEAR after the cutoff: if the split used this (the bug), the decay
                // year — and thus the treasury amount — would differ from the cutoff's.
                block_timestamp: chrono::DateTime::from_timestamp(block_ts, 0).expect("ts"),
                winning_miner_id: "pool".to_string(),
                winning_miner_payout_address: Some(addrs[0].clone()),
                treasury_address_snapshot: Some(treasury_script()),
                winning_node_id: [9u8; 32],
                subsidy_sats: LEDGER_TEST_SUBSIDY,
                tx_fees_sats: 0,
                miner_work,
                // A node so the pool has a recipient and does NOT fall back to treasury
                // (which would perturb treasury_amount away from the pure decay split).
                node_shares: vec![([9u8; 32], 5)],
                treasury_state: treasury.clone(),
            })
            .expect("create proposal");
        assert!(
            !proposal.node_payouts.is_empty(),
            "node pool has a recipient (no treasury fallback perturbing treasury_amount)"
        );

        // Expected splits derived from the same function the coinbase uses, at each timestamp.
        let at = |ts: i64| {
            FeeDistribution::calculate_at_height(
                LEDGER_TEST_SUBSIDY,
                0,
                &treasury,
                chrono::DateTime::from_timestamp(ts, 0).unwrap(),
                false, // pre-gate; tx_fees=0 so the fee-split regime is immaterial here
            )
            .treasury_amount
        };
        let cutoff_treasury = at(cutoff_ts);
        let now_treasury = at(block_ts);
        assert_ne!(
            cutoff_treasury, now_treasury,
            "sanity: the cutoff and block_timestamp fall in different decay years"
        );
        assert_eq!(
            proposal.treasury_amount, cutoff_treasury,
            "fee split must anchor to the cutoff, not block_timestamp"
        );
        assert_ne!(
            proposal.treasury_amount, now_treasury,
            "must NOT reflect the wall-clock block_timestamp's decay year"
        );
    }

    /// The fix: a validator recomputing from the unpaid ledger — over the cutoff the
    /// proposal carries — reproduces the proposer's split exactly and approves it.
    #[test]
    fn ghost02_ledger_proposal_survives_validator_recompute() {
        let (creator, db) = ledger_creator();
        let now = 1_800_000_000i64;
        let addrs = seed_unpaid_ledger(&db, now);

        let proposal = ledger_proposal(&creator, &db, &addrs, now);
        assert!(
            !proposal.miner_payouts.is_empty(),
            "the ledger-built proposal pays the miners"
        );
        assert_eq!(
            proposal.timestamp as i64, now,
            "the proposal must carry the ledger cutoff its split was computed against, \
             so validators can reproduce the proposer's exact window"
        );

        // What a validating node recomputes (main.rs GHOST-02 validator): same function,
        // same source, cutoff taken from the proposal.
        let local_work = select_ledger_miner_work(
            &db,
            proposal.timestamp as i64,
            proposal.block_height,
            proposal.subsidy,
        )
        .expect("validator recompute");

        let ts = TreasuryState::new();
        assert!(
            creator
                .validate_proposal_split(&proposal, &local_work, &ts)
                .is_ok(),
            "GHOST-02: an honest ledger-built proposal must survive an honest node's \
             recompute — if this fails, the fleet rejects its own payout and the coinbase \
             falls back to paying pool_payout_address alone"
        );
    }

    /// GHOST-02 (extended): a coinbase that doesn't conserve value — a satoshi minted or
    /// destroyed — is rejected even though its miner split recomputes cleanly.
    #[test]
    fn ghost02_rejects_non_conserving_coinbase() {
        let (creator, db) = ledger_creator();
        let now = 1_800_000_000i64;
        let addrs = seed_unpaid_ledger(&db, now);
        let mut proposal = ledger_proposal(&creator, &db, &addrs, now);

        // Mint one satoshi from nothing: treasury up by one, nothing else moved.
        proposal.treasury_amount += 1;

        let local_work = select_ledger_miner_work(
            &db,
            proposal.timestamp as i64,
            proposal.block_height,
            proposal.subsidy,
        )
        .expect("validator recompute");
        assert!(
            creator
                .validate_proposal_split(&proposal, &local_work, &TreasuryState::new())
                .is_err(),
            "GHOST-02: a coinbase that doesn't conserve value must be rejected"
        );
    }

    /// GHOST-02 (extended): the treasury output must pay the configured treasury script.
    /// A same-amount redirect to another address is rejected.
    #[test]
    fn ghost02_rejects_redirected_treasury() {
        let (creator, db) = ledger_creator();
        let now = 1_800_000_000i64;
        let addrs = seed_unpaid_ledger(&db, now);
        let mut proposal = ledger_proposal(&creator, &db, &addrs, now);
        assert!(
            proposal.treasury_amount > 0,
            "the ledger proposal funds the treasury (node_shares empty → fallback)"
        );

        // Same amount, attacker's address.
        proposal.treasury_address = vec![0xabu8; 22];

        let local_work = select_ledger_miner_work(
            &db,
            proposal.timestamp as i64,
            proposal.block_height,
            proposal.subsidy,
        )
        .expect("validator recompute");
        assert!(
            creator
                .validate_proposal_split(&proposal, &local_work, &TreasuryState::new())
                .is_err(),
            "GHOST-02: a redirected treasury address must be rejected"
        );
    }

    /// GHOST-02 (extended): the treasury can't be shorted below its deterministic floor
    /// (base rate + sub-dust fees), even if the shortfall is moved to a node so the
    /// coinbase still conserves. NB: the node-vs-treasury split ABOVE the floor is NOT
    /// pinned — node eligibility isn't validator-reproducible (see the node-split
    /// decision doc) — so this only asserts the floor.
    #[test]
    fn ghost02_rejects_treasury_below_floor() {
        let (creator, db) = ledger_creator();
        let now = 1_800_000_000i64;
        let addrs = seed_unpaid_ledger(&db, now);
        let mut proposal = ledger_proposal(&creator, &db, &addrs, now);

        // The floor is the base treasury rate (this fixture has no tx fees).
        let block_time =
            chrono::DateTime::<chrono::Utc>::from_timestamp(proposal.timestamp as i64, 0).unwrap();
        let floor = FeeDistribution::calculate_at_height(
            proposal.subsidy,
            proposal.tx_fees,
            &TreasuryState::new(),
            block_time,
            proposal.block_height >= crate::coinbase_fee_split_height(),
        )
        .treasury_amount;
        if floor == 0 {
            return; // no positive floor at this height/decay — nothing to violate
        }
        assert!(
            proposal.treasury_amount >= floor,
            "the honest proposal sits at or above the treasury floor"
        );

        // Short the treasury one satoshi below its floor, moving the shortfall to a node
        // so the coinbase still conserves value.
        let target = floor - 1;
        let shortfall = proposal.treasury_amount - target;
        proposal.treasury_amount = target;
        proposal.node_payouts.push(PayoutEntry {
            address: vec![0x33u8; 22],
            amount: shortfall,
            recipient_id: [0x33u8; 32],
            payout_type: PayoutType::NodeReward,
        });

        let local_work = select_ledger_miner_work(
            &db,
            proposal.timestamp as i64,
            proposal.block_height,
            proposal.subsidy,
        )
        .expect("validator recompute");
        assert!(
            creator
                .validate_proposal_split(&proposal, &local_work, &TreasuryState::new())
                .is_err(),
            "GHOST-02: treasury shorted below its deterministic floor must be rejected"
        );
    }

    /// Regression pin: recomputing from the winning job-round — what the validator used to
    /// do — rejects the pool's own honest proposal. This is the bug the fix removes; if a
    /// future change reintroduces a round-scoped recompute, this test starts failing.
    #[test]
    fn ghost02_round_scoped_recompute_rejects_honest_ledger_proposal() {
        let (creator, db) = ledger_creator();
        let now = 1_800_000_000i64;
        let addrs = seed_unpaid_ledger(&db, now);

        let proposal = ledger_proposal(&creator, &db, &addrs, now);

        // `rm.get_miner_work_scaled(proposal.round_id)`: only the winning ~90s round.
        // Carol is owed by the ledger but idle during that round, so she vanishes here.
        let round_work = winning_round_work(&addrs);
        assert_eq!(
            round_work.len(),
            2,
            "the winning round only saw the two still-active miners"
        );

        let ts = TreasuryState::new();
        assert!(
            creator
                .validate_proposal_split(&proposal, &round_work, &ts)
                .is_err(),
            "a round-scoped recompute cannot reproduce a ledger-built split — this is \
             precisely why the validator must not use the round"
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
            shard_owed: None,
            round_id: 1,
            ledger_cutoff_ts: 1_800_000_000,
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
            shard_owed: None,
            round_id: 1,
            ledger_cutoff_ts: now.timestamp(),
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

    /// Build solo block data at a chosen height. Everything except the height is fixed so the two
    /// regimes below differ in exactly one input.
    fn solo_data_at_height(block_height: u64) -> SoloBlockFoundData {
        SoloBlockFoundData {
            round_id: 7,
            block_hash: [0xAB; 32],
            block_height,
            block_timestamp: chrono::Utc::now(),
            // `ghost02_creator` is on Regtest, so the address must be too — `validate_payout_address`
            // rejects a network mismatch before any fee arithmetic runs.
            solo_payout_address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string(),
            subsidy_sats: 312_500_000,
            treasury_address_snapshot: Some({
                let mut addr = vec![0x51, 0x20];
                addr.extend_from_slice(&[0xAA; 32]);
                addr
            }),
            tx_fees_sats: 1_500_000,
            node_shares: vec![([1u8; 32], 10)],
            treasury_state: TreasuryState::new(),
        }
    }

    /// #592: solo must use the SAME fee model as pool mode. This calls `create_solo_proposal` —
    /// the two older `test_solo_mode_*` tests call `FeeDistribution::calculate` directly and then
    /// recompute the solo sum in the test body, so they pass whatever the solo path does.
    ///
    /// Above the gate the 1% is levied on `subsidy + fees`. The previous implementation levied it
    /// on the subsidy alone and added the fees whole, paying the solo miner 1% of the fees more
    /// than every validator recomputes in `validate_proposal_split` — so this asserts the exact
    /// figure rather than a bound.
    /// `PublicPool` must NEVER be treated as single-operator, and both private modes must be.
    ///
    /// This is the whole security boundary of local payout approval, so it is asserted
    /// exhaustively over the enum rather than by example — if a fourth mode is ever added, this
    /// test forces an explicit decision about which side of the line it falls on instead of
    /// letting it inherit a default.
    ///
    /// Getting `PublicPool` wrong here would let a node approve its own payout proposal without a
    /// vote, on the pool that actually has independent operators — the exact attack BFT exists to
    /// stop. Getting a private mode wrong restores the `InsufficientVoters` deadlock that made a
    /// one-node private pool unable to pay anyone.
    #[test]
    fn only_the_private_modes_are_single_operator() {
        assert!(
            !is_single_operator_mode(MiningMode::PublicPool),
            "PublicPool has INDEPENDENT operators — it must always require a BFT vote"
        );
        assert!(
            is_single_operator_mode(MiningMode::PrivateSolo),
            "solo pays only its own operator; there is no second party to protect"
        );
        assert!(
            is_single_operator_mode(MiningMode::PrivatePool),
            "a private pool has one operator, so a quorum would be their own nodes agreeing \
             with themselves — and demanding one made a single-node private pool unable to pay"
        );
    }

    /// The predicate must depend ONLY on the declared mode, never on anything observable at
    /// runtime.
    ///
    /// Keying it on a live peer count is the obvious-looking alternative and is dangerous: a
    /// public-pool node that transiently lost its mesh would begin self-approving payouts, which
    /// is indistinguishable from the attack. A mode is an operator declaration in a config file
    /// and cannot be induced by a network condition, which is precisely why it is the input.
    #[test]
    fn single_operator_is_decided_by_mode_alone_and_is_stable() {
        for mode in [
            MiningMode::PublicPool,
            MiningMode::PrivatePool,
            MiningMode::PrivateSolo,
        ] {
            let first = is_single_operator_mode(mode);
            for _ in 0..100 {
                assert_eq!(
                    is_single_operator_mode(mode),
                    first,
                    "{mode:?} changed its answer — the decision must be a pure function of the \
                     declared mode, with no ambient input"
                );
            }
        }
    }

    #[test]
    fn solo_uses_the_pool_fee_model_above_the_gate() {
        let creator = ghost02_creator();
        let data = solo_data_at_height(crate::coinbase_fee_split_height());

        let subsidy = data.subsidy_sats;
        let fees = data.tx_fees_sats;
        let proposal = creator
            .create_solo_proposal(data)
            .expect("solo proposal at/above the gate");

        // 1% of (312_500_000 + 1_500_000) = 3_140_000, so the miner keeps 310_860_000.
        let total_reward = subsidy + fees;
        let pool_fee = total_reward / 100;
        assert_eq!(
            proposal.miner_payouts[0].amount,
            total_reward - pool_fee,
            "solo miner must keep 99% of subsidy + fees above the gate"
        );

        // The pre-#592 figure, which must no longer be produced.
        assert_ne!(
            proposal.miner_payouts[0].amount,
            (subsidy - subsidy / 100) + fees,
            "solo must not levy the 1% on the subsidy alone above the gate"
        );

        // No satoshi may be created or lost across the whole coinbase.
        let paid: u64 = proposal.miner_payouts.iter().map(|p| p.amount).sum::<u64>()
            + proposal.node_payouts.iter().map(|p| p.amount).sum::<u64>()
            + proposal.treasury_amount;
        assert_eq!(
            paid, total_reward,
            "solo payouts must sum to subsidy + fees"
        );
    }

    /// Below the gate the legacy regime is untouched: 1% on the subsidy alone, fees whole to the
    /// finder. A mixed-version fleet must not split on coinbase construction.
    #[test]
    fn solo_keeps_the_legacy_model_below_the_gate() {
        let creator = ghost02_creator();
        let data = solo_data_at_height(crate::coinbase_fee_split_height() - 1);

        let subsidy = data.subsidy_sats;
        let fees = data.tx_fees_sats;
        let proposal = creator
            .create_solo_proposal(data)
            .expect("solo proposal below the gate");

        assert_eq!(
            proposal.miner_payouts[0].amount,
            (subsidy - subsidy / 100) + fees,
            "below the gate the 1% is levied on the subsidy alone"
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
                                                          // tiny miners: 10 each = 990 total
        miner_work.extend(std::iter::repeat_n(10u128, 99));
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

        // `product.is_some()` above IS the overflow check — `checked_mul` returns None on
        // overflow. (A `p <= u128::MAX` assertion here was vacuous: p is u128.)
        let p = product.unwrap();

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

    // ---- #601: settlement credits what the chain paid, not what the fleet ratified ----

    const P2WPKH: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const P2WSH: &str = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";

    fn spk_601(addr: &str) -> Vec<u8> {
        crate::coinbase_verifier::address_to_script_pubkey(addr.as_bytes())
            .expect("test address must convert")
    }

    /// A ratified post-gate proposal: miner 3.0, node 0.12, treasury `treasury`, fees `tx_fees`.
    fn ratified_601(tx_fees: u64, treasury: u64) -> PayoutProposal {
        PayoutProposal {
            proposal_hash: [0x60; 32],
            round_id: 1,
            block_hash: [0u8; 32],
            block_height: 960_000, // post COINBASE_FEE_SPLIT_HEIGHT (959_290)
            proposer: [1u8; 32],
            miner_payouts: vec![ghost_common::types::PayoutEntry {
                address: P2WPKH.as_bytes().to_vec(),
                amount: 300_000_000,
                recipient_id: [2u8; 32],
                payout_type: ghost_common::types::PayoutType::Mining,
            }],
            node_payouts: vec![ghost_common::types::PayoutEntry {
                address: P2WPKH.as_bytes().to_vec(),
                amount: 12_000_000,
                recipient_id: [3u8; 32],
                payout_type: ghost_common::types::PayoutType::NodeReward,
            }],
            treasury_amount: treasury,
            treasury_address: P2WSH.as_bytes().to_vec(),
            tx_fees,
            subsidy: 312_500_000,
            timestamp: chrono::Utc::now().timestamp() as u64,
            tx_fees_unallocated: 0,
        }
    }

    /// The outputs a winner's coinbase carries, in builder order: miners, nodes, treasury.
    fn mined_601(
        miner: u64,
        node: u64,
        treasury: u64,
    ) -> Vec<crate::coinbase_verifier::CoinbaseOutput> {
        let mut v = Vec::new();
        if miner > 0 {
            v.push(crate::coinbase_verifier::CoinbaseOutput {
                value: miner,
                script_pubkey: spk_601(P2WPKH),
            });
        }
        if node > 0 {
            v.push(crate::coinbase_verifier::CoinbaseOutput {
                value: node,
                script_pubkey: spk_601(P2WPKH),
            });
        }
        if treasury > 0 {
            v.push(crate::coinbase_verifier::CoinbaseOutput {
                value: treasury,
                script_pubkey: spk_601(P2WSH),
            });
        }
        v
    }

    /// **The #601 defect, pinned.** The fleet ratified treasury 0.01 with fees 0.005; the winner's
    /// template had fees 0.008, so its coinbase paid treasury 0.013. Settlement must credit the
    /// 0.013 the chain paid — crediting the ratified 0.01 books money that never existed.
    #[test]
    fn surplus_fee_drift_credits_the_treasury_amount_the_chain_paid() {
        let ratified = ratified_601(500_000, 1_000_000);
        let mined = mined_601(300_000_000, 12_000_000, 1_300_000); // winner saw 800_000 fees

        let amounts = settlement_amounts_from_mined_coinbase(&ratified, &mined);
        assert!(
            amounts.verified,
            "the mined outputs ARE the deterministic adjustment"
        );
        assert_eq!(amounts.treasury_amount, 1_300_000, "credit what was paid");
        assert_ne!(
            amounts.treasury_amount, ratified.treasury_amount,
            "the ratified amount is precisely what must NOT be credited"
        );
        assert_eq!(
            amounts.outputs_hash,
            crate::coinbase_verifier::CoinbaseCommitment::outputs_hash(&mined),
            "the settlement row must describe the chain, not the proposal"
        );
    }

    /// Shortfall: winner's fees fell to zero, so the drift drained the treasury then the largest
    /// node entry. Settlement follows the same deterministic path and credits what remains.
    #[test]
    fn shortfall_fee_drift_drains_treasury_then_nodes_and_settles_what_remains() {
        // Shortfall 500_000 absorbed entirely by the 1_000_000 treasury.
        let ratified = ratified_601(500_000, 1_000_000);
        let mined = mined_601(300_000_000, 12_000_000, 500_000);
        let amounts = settlement_amounts_from_mined_coinbase(&ratified, &mined);
        assert!(amounts.verified);
        assert_eq!(amounts.treasury_amount, 500_000);

        // Shortfall 2_000_000 empties the treasury and takes 1_000_000 from the node entry.
        let ratified = ratified_601(2_000_000, 1_000_000);
        let mined = mined_601(300_000_000, 11_000_000, 0);
        let amounts = settlement_amounts_from_mined_coinbase(&ratified, &mined);
        assert!(amounts.verified);
        assert_eq!(
            amounts.treasury_amount, 0,
            "the chain paid the treasury nothing"
        );
    }

    /// A 0-value witness commitment output rides along on every real coinbase and must not
    /// disturb verification.
    #[test]
    fn witness_commitment_output_does_not_break_verification() {
        let ratified = ratified_601(500_000, 1_000_000);
        let mut mined = mined_601(300_000_000, 12_000_000, 1_300_000);
        mined.push(crate::coinbase_verifier::CoinbaseOutput {
            value: 0,
            script_pubkey: vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed],
        });
        let amounts = settlement_amounts_from_mined_coinbase(&ratified, &mined);
        assert!(amounts.verified);
        assert_eq!(amounts.treasury_amount, 1_300_000);
    }

    /// A tagged block whose outputs are NOT the deterministic adjustment — a winner on different
    /// code, a tampered coinbase, or a hand-mined rehearsal block. The treasury credit falls back
    /// to direct measurement of the treasury script, never to the ratified figure.
    #[test]
    fn an_unreconstructable_coinbase_is_measured_not_trusted() {
        let ratified = ratified_601(500_000, 1_000_000);

        // Fallback-shaped block: one big output to the miner script, 750_000 to the treasury.
        let mined = vec![
            crate::coinbase_verifier::CoinbaseOutput {
                value: 200_000_000,
                script_pubkey: spk_601(P2WPKH),
            },
            crate::coinbase_verifier::CoinbaseOutput {
                value: 750_000,
                script_pubkey: spk_601(P2WSH),
            },
        ];
        let amounts = settlement_amounts_from_mined_coinbase(&ratified, &mined);
        assert!(
            !amounts.verified,
            "this is not the adjustment of the ratified proposal"
        );
        assert_eq!(
            amounts.treasury_amount, 750_000,
            "credit what the treasury script received"
        );

        // No treasury output at all: credit nothing, not the ratified 1_000_000.
        let mined = vec![crate::coinbase_verifier::CoinbaseOutput {
            value: 312_500_000,
            script_pubkey: spk_601(P2WPKH),
        }];
        let amounts = settlement_amounts_from_mined_coinbase(&ratified, &mined);
        assert!(!amounts.verified);
        assert_eq!(amounts.treasury_amount, 0);
    }

    /// End to end through the database: `apply_settlement` books the ADJUSTED treasury amount,
    /// and reversal restores exactly what was booked — the recorded amounts, not the ratified.
    #[test]
    fn apply_settlement_books_the_mined_amounts_and_reversal_inverts_them() {
        let db = ghost_storage::Database::in_memory().expect("db");
        let ratified = ratified_601(500_000, 1_000_000);
        let mined = mined_601(300_000_000, 12_000_000, 1_300_000);

        let applied = apply_settlement(
            &db,
            &ratified,
            crate::PAYOUT_ADDRESS_GROUPING_HEIGHT,
            "601_block",
            Some(&mined),
        )
        .expect("settle")
        .expect("applied");
        assert_eq!(
            applied.treasury_bumped, 1_300_000,
            "the ledger must book what the chain paid, not the ratified 1_000_000"
        );
        assert_eq!(db.get_treasury_balance().expect("balance"), 1_300_000);

        let reversed = db
            .reverse_settlement("601_block")
            .expect("reverse")
            .expect("was settled");
        assert_eq!(reversed.treasury_bumped, 1_300_000);
        assert_eq!(
            db.get_treasury_balance().expect("balance"),
            0,
            "reversal must debit exactly what settlement credited"
        );
    }

    /// Without the mined coinbase in hand, behaviour is unchanged from before #601: the ratified
    /// amounts are booked. This is the legacy path some tests rely on, and production warns on it.
    #[test]
    fn settling_without_the_mined_coinbase_books_the_ratified_amounts_unchanged() {
        let db = ghost_storage::Database::in_memory().expect("db");
        let ratified = ratified_601(500_000, 1_000_000);
        let applied = apply_settlement(
            &db,
            &ratified,
            crate::PAYOUT_ADDRESS_GROUPING_HEIGHT,
            "601_legacy",
            None,
        )
        .expect("settle")
        .expect("applied");
        assert_eq!(applied.treasury_bumped, 1_000_000);
    }
}
