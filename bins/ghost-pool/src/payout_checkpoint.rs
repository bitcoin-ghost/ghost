//! Payout-ledger checkpoint finalisation (payout-finalisation P1, task 3).
//!
//! The coherent fix for the payout-agreement problem: instead of every node
//! independently recomputing the coinbase from its own live ledger at `now()`
//! (which is never converged — the v1.10.32 failure), the fleet BFT-**finalises**
//! a `PayoutLedgerCheckpoint {height, cutoff_ts, ledger_root}` at a lagging,
//! chain-committed height. The coinbase then becomes a pure function of the
//! agreed checkpoint (see `tasks/design_payout_finalization.md`).
//!
//! Flow (mirrors the L2 nullifier checkpoint, but decoupled and payout-scoped):
//! - **Voter set**: `voter_set[height % n]` proposes. The voter set is the MPC
//!   elder set below the `ACTIVE_VOTER_SET` gate; at/above it, the converged active
//!   qualified set (all qualified nodes, not just MPC contributors), floored so it
//!   can only ever be a superset of the elders — see `voter_set_for`.
//! - **Propose**: the deterministic proposer computes `ledger_root` from ITS
//!   converged view at `cutoff_ts = block(height).time` and broadcasts the checkpoint.
//! - **Vote**: every voter independently recomputes the root; it votes approve
//!   iff its root equals the proposal's. A node that cannot yet compute the root
//!   (data not converged) **abstains** rather than approving — the C-7 rule.
//! - **Finalise**: at ≥67% approvals (from voter-set members) for a checkpoint hash,
//!   the checkpoint is persisted (`payout_ledger_checkpoints`), identical fleet-wide.
//!
//! Authentication rides the mesh's Noise channel: `envelope.sender` is
//! cryptographically authenticated, so proposer/voter identity is taken from it
//! (and cross-checked against the message's declared field). Messages also carry
//! a signature over their content hash for defence in depth.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

use ghost_common::error::GhostResult;
use ghost_common::identity::NodeIdentity;
use ghost_common::types::NodeId;
use ghost_consensus::{
    MessageEnvelope, MessageHandler, MessageType, PayoutCheckpointSyncEntry,
    PayoutCheckpointSyncRequest, PayoutCheckpointSyncResponse, PayoutLedgerCheckpointMessage,
    PayoutLedgerCheckpointVoteMessage,
};
use ghost_storage::{Database, PayoutLedgerCheckpointRecord};

/// BFT approval threshold (percent of the active/elder set).
const BFT_THRESHOLD_PERCENT: u64 = 67;

/// Backfill cooldown (both client re-request and per-peer serve). Mirrors the L2
/// tree-sync 60s window — bounds request/response churn without stalling recovery.
const SYNC_COOLDOWN_MS: u64 = 60_000;

/// Max checkpoints served per sync response; the requester paginates if capped.
/// Small: holes are typically a single height, and each checkpoint carries the
/// adopted payout lists, so a page must stay well under the 1 MB envelope cap.
const MAX_SYNC_CHECKPOINTS: u64 = 8;

/// Enqueues an outbound broadcast `(msg_type, json_payload)`. Injected so the
/// manager doesn't depend on the mesh directly: `main.rs` wires a closure that
/// pushes to the broadcast task (as `ConvergenceHandler` does), and tests wire a
/// closure that captures messages for in-process routing under induced lag.
pub type BroadcastFn = Arc<dyn Fn(MessageType, Vec<u8>) -> GhostResult<()> + Send + Sync>;

/// The canonical payout a node computes at a cutoff: the miner set (payout address →
/// WORK_SCALE-quantised work) and the qualified-node set (node_id → 5-4-3-2-1 shares),
/// plus their root `H(miners ‖ nodes)`. Option (c): the fleet BFT-ratifies the
/// proposer's `CanonicalPayout` (tolerance-checked, not byte-identical) and ADOPTS it,
/// so agreement no longer needs every node's local ledger to be identical.
#[derive(Clone, Debug)]
pub struct CanonicalPayout {
    pub miner_payouts: Vec<(String, u128)>,
    pub node_shares: Vec<(NodeId, i32)>,
    pub root: [u8; 32],
}

/// One voter's reported recompute: its per-address miner work and its qualified-node set (#606).
pub type VoterReport = (Vec<(String, u128)>, Vec<(NodeId, i32)>);

pub type ComputeRootFn = Arc<dyn Fn(i64, u64) -> Option<CanonicalPayout> + Send + Sync>;

/// How long a resolved voter set stays usable.
///
/// Short on purpose. The storm this exists to stop is many messages about ONE `(height,
/// cutoff_ts)` arriving within seconds of each other, so even a few seconds collapses it; the TTL
/// only has to outlive a checkpoint round, not a checkpoint. Long-lived caching would risk pinning
/// a stale voter set — and therefore a wrong deterministic proposer — after a late
/// `verification_ledger` row changes qualification at a cutoff already passed.
const VOTER_SET_CACHE_TTL_SECS: u64 = 30;

/// Resolved voter sets, keyed by the `(height, cutoff_ts)` they were resolved for.
type VoterSetCache = HashMap<(u64, i64), (Vec<NodeId>, std::time::Instant)>;

/// Miner-work tolerance for option (c). The share SET converges (proven by the union)
/// but attribution (same share → different miner_id representation) and float-sum-order
/// leave a per-address work difference; a voter approves the proposer's canonical payout
/// if every address's work is within `REL_TOL` (relative) or `ABS_TOL` (absolute floor)
/// of its own. This is sound because the fleet is SINGLE-OPERATOR — an honest quorum
/// still bounds any per-block drift to the tolerance, strictly stronger than no split.
const REL_TOL_NUM: u128 = 2; // 2%
const REL_TOL_DEN: u128 = 100;
const ABS_TOL: u128 = 1_000_000_000_000; // ~one share of WORK_SCALE-quantised work

/// Tolerance floor as a fraction of TOTAL pool work, active at/above
/// [`crate::PAYOUT_TOLERANCE_V2_HEIGHT`]. 0.2%.
///
/// The per-address bound above measures error against the wrong denominator. What
/// matters is the error in the COINBASE, which is per-address error over *total* work —
/// so a dust address gets a bound proportional to its (negligible) payout impact rather
/// than to its own tiny work. On 2026-07-25 an address holding 0.02% of pool work sat
/// 101% away from its peers' view and vetoed every payout for four days, while the
/// address holding 90% of the pool agreed to within 0.55%. → #548.
///
/// This is a FLOOR, not a replacement: `max(2% of own, 0.2% of pool)`. For any address
/// large enough to matter the 2% relative bound is far larger and still governs (2% of a
/// 90%-of-pool address is 45× this floor), so the check is not loosened where it carries
/// economic weight.
const POOL_REL_TOL_NUM: u128 = 2;
const POOL_REL_TOL_DEN: u128 = 1000;

/// Cap on the SUM of per-address differences, as a fraction of total pool work (1%).
///
/// Needed because the floor above is per-address: without it, N addresses could each sit
/// 0.2% of the pool away in the same direction and compound into a large coinbase error.
/// Bounding the aggregate makes the worst-case total misallocation explicit regardless of
/// how many addresses are in the ledger.
const AGG_TOL_NUM: u128 = 1;
const AGG_TOL_DEN: u128 = 100;

/// Convergence-stall thresholds, in blocks behind the anchor. Checkpointing normally
/// finalises every block, so `WARN` is already well outside normal; a missed proposal
/// plus one backfill cooldown accounts for a handful of blocks, not eighteen.
const STALL_WARN_BLOCKS: u64 = 18;
/// Past this there is no transient explanation left: payouts have stopped.
const STALL_ERROR_BLOCKS: u64 = 60;
/// Rate limit for the stall alarm — the cadence runs every 30s and the condition
/// persists for as long as the stall does.
const STALL_ALARM_COOLDOWN_MS: u64 = 600_000; // 10 minutes

/// Why a voter refused a proposal. Exists so the reject log names the check that
/// actually failed: a set-shape mismatch and a genuine work disagreement need opposite
/// responses (converge the share set vs. widen the tolerance), and for weeks every one
/// of them logged the same "outside tolerance" line — so the 2026-07-25 stall was chased
/// through three wrong hypotheses before the log could be made to say which check it was.
/// See #548.
#[derive(Debug, PartialEq, Eq)]
enum Disagreement {
    /// Node share-count vectors differ — the node set itself has not converged.
    NodeSet { local: usize, proposed: usize },
    /// Different number of paid addresses. Neither side's work values are at fault.
    MinerCount { local: usize, proposed: usize },
    /// The proposal pays an address we have no work for at all.
    UnknownAddress { addr_hash: String },
    /// Both sides pay this address, but the work differs by more than tolerance.
    WorkOutsideTolerance {
        addr_hash: String,
        local: u128,
        proposed: u128,
        tol: u128,
    },
    /// Every address passed individually, but the differences sum past the aggregate cap
    /// — many small same-direction skews compounding into a real coinbase error.
    AggregateOutsideTolerance { total_diff: u128, tol: u128 },
}

/// Short, cross-node-comparable handle for a payout address. Payout addresses are
/// stored encrypted per-node, so the ciphertext differs everywhere and cannot be
/// grepped across logs; this hash is derived from the decrypted address and so is
/// identical on every node. It also keeps the address↔miner linkage out of the log.
fn addr_handle(addr: &str) -> String {
    hex::encode(&Sha256::digest(addr.as_bytes())[..6])
}

impl std::fmt::Display for Disagreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NodeSet { local, proposed } => {
                write!(
                    f,
                    "node set differs (local {local} entries, proposed {proposed})"
                )
            }
            Self::MinerCount { local, proposed } => write!(
                f,
                "miner count differs (local {local} addresses, proposed {proposed}) \
                 — share sets have not converged; tolerance was never consulted"
            ),
            Self::UnknownAddress { addr_hash } => {
                write!(
                    f,
                    "proposal pays address {addr_hash} which we have no work for"
                )
            }
            Self::WorkOutsideTolerance {
                addr_hash,
                local,
                proposed,
                tol,
            } => write!(
                f,
                "address {addr_hash} work {local} vs {proposed} exceeds tolerance {tol}"
            ),
            Self::AggregateOutsideTolerance { total_diff, tol } => write!(
                f,
                "per-address differences sum to {total_diff}, over the aggregate cap {tol}"
            ),
        }
    }
}

/// Adopt the per-address LOWER MEDIAN of what the voters independently recomputed (#606).
///
/// Before this, finalisation persisted the PROPOSER's list verbatim, tolerance-checked. Voters
/// recomputed their own view, compared it, and then threw their numbers away — so a proposer could
/// skew every address within tolerance (2% relative, 0.2%-of-pool floor, 1% aggregate), be ratified
/// by an honest quorum, and compound the skew at every checkpoint. Taking the median of the reports
/// removes that: a single skewed report cannot move a median that a majority of honest reporters
/// determine.
///
/// `reports` is one entry per in-set voter that reported, each `(address, quantised work)`. The
/// proposer's own list is passed as one of them by the caller — it gets exactly one vote, like
/// everyone else, which is the entire point.
///
/// ## Why the LOWER median and not an average
///
/// The adopted value has to be byte-identical on every node or the root diverges and nothing
/// finalises. With an even number of reporters there is no single middle element, so the rule must be
/// stated rather than left to a library: sort ascending, take index `(n - 1) / 2`.
///
/// An average would reintroduce division and rounding on a consensus-critical value. This file
/// already records float-sum-order as the residual divergence that kept checkpoints from finalising
/// at all, so everything here stays integer micro-work.
///
/// ## Address set
///
/// Only addresses present in a MAJORITY of reports are adopted. An address that only a minority saw
/// is attribution noise or a fabrication, and admitting it on one report's word would hand a single
/// voter the ability to inject a payee — the mirror of the hole being closed. For each adopted
/// address the median is taken over the reports that contain it.
pub fn median_adopted_miner_work(reports: &[Vec<(String, u128)>]) -> Vec<(String, u128)> {
    if reports.is_empty() {
        return Vec::new();
    }
    // A majority of REPORTS, not of the voter set: the caller has already filtered to in-set voters,
    // and finalisation separately refuses when too few reported at all.
    let majority = reports.len() / 2 + 1;

    let mut per_address: std::collections::BTreeMap<&str, Vec<u128>> =
        std::collections::BTreeMap::new();
    for report in reports {
        // Guard against one report double-counting an address and shifting its own median.
        let mut seen = std::collections::HashSet::new();
        for (addr, work) in report {
            if seen.insert(addr.as_str()) {
                per_address.entry(addr.as_str()).or_default().push(*work);
            }
        }
    }

    let mut out: Vec<(String, u128)> = per_address
        .into_iter()
        .filter(|(_, works)| works.len() >= majority)
        .map(|(addr, mut works)| {
            works.sort_unstable();
            (addr.to_string(), works[(works.len() - 1) / 2])
        })
        .collect();
    // Deterministic order for the root: work desc, then address asc — the same total order
    // `get_top_unpaid_addresses` documents, so the adopted list hashes identically everywhere.
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
}

/// How far the proposer's value for an address sits from the adopted median, as a fraction of the
/// median. Returns `None` when the median is zero (nothing to be relative to).
///
/// Used to alert when a proposer sits above half the tolerance it is allowed — the detection #606
/// asks for, and the evidence for whether skew is actually happening in practice rather than merely
/// being possible.
pub fn proposer_skew_permille(proposed: u128, median: u128) -> Option<u128> {
    if median == 0 {
        return None;
    }
    let diff = proposed.abs_diff(median);
    Some(diff.saturating_mul(1000) / median)
}

/// Half the per-address relative tolerance, in permille — the alert threshold (#606).
/// `REL_TOL` is 2%, so this is 10 permille.
pub const SKEW_ALERT_PERMILLE: u128 = (REL_TOL_NUM * 1000) / (REL_TOL_DEN * 2);

/// Does the proposer's canonical payout agree with our own within tolerance?
/// Node set: exact (it converges via payout-address gossip). Miner set: identical
/// address keys, each address's work within tolerance. `Ok(())` means agree.
///
/// At/above [`crate::PAYOUT_TOLERANCE_V2_HEIGHT`] the per-address bound gains a floor of
/// [`POOL_REL_TOL_NUM`]/[`POOL_REL_TOL_DEN`] of total pool work and the aggregate
/// difference is capped — see those constants. Below it the original rule applies
/// unchanged, so a node running this build votes identically to one that is not until
/// the gate fires.
fn payouts_agree(
    local: &CanonicalPayout,
    proposed_miners: &[(String, u128)],
    proposed_nodes: &[(NodeId, i32)],
    height: u64,
) -> Result<(), Disagreement> {
    let mut ln = local.node_shares.clone();
    ln.sort();
    let mut pn = proposed_nodes.to_vec();
    pn.sort();
    if ln != pn {
        return Err(Disagreement::NodeSet {
            local: ln.len(),
            proposed: pn.len(),
        });
    }

    let lm: HashMap<&str, u128> = local
        .miner_payouts
        .iter()
        .map(|(a, w)| (a.as_str(), *w))
        .collect();
    if lm.len() != proposed_miners.len() {
        return Err(Disagreement::MinerCount {
            local: lm.len(),
            proposed: proposed_miners.len(),
        });
    }
    // Total pool work from OUR view. Both sides compute their own; they agree to within
    // the aggregate cap enforced below, so the resulting tolerances cannot diverge enough
    // to make one node accept what another rejects by more than that bound.
    let v2 = height >= crate::PAYOUT_TOLERANCE_V2_HEIGHT;
    let total_work: u128 = local.miner_payouts.iter().map(|(_, w)| *w).sum();
    let pool_floor = if v2 {
        total_work / POOL_REL_TOL_DEN * POOL_REL_TOL_NUM
    } else {
        0
    };

    let mut agg_diff: u128 = 0;
    for (addr, pw) in proposed_miners {
        let pw = *pw;
        let Some(&lw) = lm.get(addr.as_str()) else {
            return Err(Disagreement::UnknownAddress {
                addr_hash: addr_handle(addr),
            });
        };
        let diff = lw.max(pw) - lw.min(pw);
        agg_diff = agg_diff.saturating_add(diff);
        let tol = (lw / REL_TOL_DEN * REL_TOL_NUM)
            .max(ABS_TOL)
            .max(pool_floor);
        if diff > tol {
            return Err(Disagreement::WorkOutsideTolerance {
                addr_hash: addr_handle(addr),
                local: lw,
                proposed: pw,
                tol,
            });
        }
    }

    // The per-address floor is per-address: without this, many addresses could each sit
    // just inside it in the same direction and compound. Only meaningful under v2 — below
    // the gate the floor is 0 and every address already passed a bound of its own.
    if v2 {
        let agg_tol = (total_work / AGG_TOL_DEN * AGG_TOL_NUM).max(ABS_TOL);
        if agg_diff > agg_tol {
            return Err(Disagreement::AggregateOutsideTolerance {
                total_diff: agg_diff,
                tol: agg_tol,
            });
        }
    }
    Ok(())
}

/// Optional diagnostic: `(cutoff_ts, height) -> human breakdown` of the root inputs
/// (miner-set + node-set hashed separately, with counts + node list). Injected by
/// `main.rs` to isolate live root divergence; `None` in tests and once diagnosed.
pub type ComputeRootDiagFn = Arc<dyn Fn(i64, u64) -> String + Send + Sync>;

/// Resolves the ACTIVE qualified voter set at a cutoff: `(cutoff_ts, height) -> sorted
/// node ids`. Wired in `main.rs` to the SAME scoped qualified-node query
/// (`get_all_qualified_nodes_at_cutoff_from_db`) that [`ComputeRootFn`] uses to build
/// `node_shares`, so the voter set and the ratified ledger's node set are identical by
/// construction. Once `ACTIVE_VOTER_SET` activates, the payout consensus draws its
/// proposer/quorum/eligibility from this set (all qualified nodes) instead of only the
/// MPC ceremony elders. `None` in tests → the elder floor is always used.
pub type ActiveVoterSetFn = Arc<dyn Fn(i64, u64) -> Vec<NodeId> + Send + Sync>;

struct PendingEntry {
    /// The proposal content (needed to persist on finalise). `None` if a vote
    /// arrived before the proposal (race) — we still tally the approver.
    proposal: Option<PayoutLedgerCheckpointMessage>,
    approvers: HashSet<NodeId>,
    /// What each approving voter reported it recomputed (#606), keyed by voter so a node cannot
    /// weight the median by voting twice. Empty below the median-adoption gate.
    reports: HashMap<NodeId, VoterReport>,
}

struct Pending {
    by_hash: HashMap<[u8; 32], PendingEntry>,
    finalized: bool,
}

impl Pending {
    fn new() -> Self {
        Self {
            by_hash: HashMap::new(),
            finalized: false,
        }
    }
    fn entry(&mut self, hash: [u8; 32]) -> &mut PendingEntry {
        self.by_hash.entry(hash).or_insert_with(|| PendingEntry {
            proposal: None,
            approvers: HashSet::new(),
            reports: HashMap::new(),
        })
    }
}

/// Drives payout-ledger checkpoint proposal/voting/finalisation and also acts as
/// the mesh `MessageHandler` for the two payout-checkpoint message types.
pub struct PayoutCheckpointManager {
    identity: Arc<NodeIdentity>,
    db: Arc<Database>,
    send: BroadcastFn,
    compute_root: ComputeRootFn,
    /// Optional root-input breakdown for live divergence diagnosis.
    diag: Option<ComputeRootDiagFn>,
    /// Optional active-voter-set resolver (see [`ActiveVoterSetFn`]). `None` = elder-only.
    active_voter_set: Option<ActiveVoterSetFn>,
    /// height -> in-flight vote tallies.
    pending: RwLock<HashMap<u64, Pending>>,
    /// Client-side backfill cooldown: last time we broadcast a sync request (ms; 0 = never).
    last_sync_request: RwLock<u64>,
    /// Convergence-stall alarm: last time we raised it (ms; 0 = never). Rate-limits an
    /// otherwise every-30s error to [`STALL_ALARM_COOLDOWN_MS`].
    last_stall_alarm: RwLock<u64>,
    /// Server-side per-peer serve cooldown: requesting node -> last time we served it (ms).
    sync_serves: RwLock<HashMap<NodeId, u64>>,
    /// Memoised voter sets, keyed by the `(height, cutoff_ts)` they were resolved for.
    ///
    /// `voter_set_for` resolves the active voter set by walking qualification, which reaches
    /// `get_all_qualified_nodes_at_cutoff_from_db` -> `majority_capability_qualified` and joins
    /// `verification_ledger` against `nodes`. On a 2026-08-09 profile of ghost-vm6 that chain was
    /// the single largest term in the process — `voter_set_for` alone drew 636 samples against 174
    /// for the canonical-payout recompute everyone assumed was the cost.
    ///
    /// It is called from the MESSAGE path, not a timer: every checkpoint proposal, vote and sync
    /// reply resolves it again. Because a stalled height is re-proposed, the fleet re-resolved the
    /// SAME `(height, cutoff_ts)` continuously — ~2,200 database page reads per second, sustained,
    /// on every node, which is what starved the HTTP API into 504s fleet-wide.
    ///
    /// Keyed rather than global because the answer legitimately differs per height. TTL'd rather
    /// than permanent because a late `verification_ledger` row can change qualification at a cutoff
    /// already passed, and a voter set that can never be revised would pin a wrong proposer for as
    /// long as the process lived.
    voter_set_cache: RwLock<VoterSetCache>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Approvals required to finalise: ceil of 67% of `n` voters.
fn quorum_for(n: usize) -> usize {
    (n as u64 * BFT_THRESHOLD_PERCENT).div_ceil(100) as usize
}

/// The bootstrap-floor decision for `voter_set_for`: widen to
/// the `active` qualified set only when it is a non-empty *superset* of `elders` (both
/// sorted). Otherwise keep `elders`, so the voter set can only grow beyond the established
/// floor, never shrink below it. Pure so the floor invariant is unit-tested independent of
/// the gate/resolver plumbing, and `pub` so the convergence-proof endpoint hashes the
/// EXACT set consensus would use.
pub fn widen_voter_set(elders: Vec<NodeId>, active: Vec<NodeId>) -> Vec<NodeId> {
    if active_is_superset_of_elders(&elders, &active) {
        active
    } else {
        elders
    }
}

/// The superset predicate `widen_voter_set` uses to decide whether to widen. Exposed so the
/// convergence-proof endpoint can report whether the floor engaged (`floored = !this`).
pub fn active_is_superset_of_elders(elders: &[NodeId], active: &[NodeId]) -> bool {
    !active.is_empty() && elders.iter().all(|e| active.binary_search(e).is_ok())
}

impl PayoutCheckpointManager {
    pub fn new(
        identity: Arc<NodeIdentity>,
        db: Arc<Database>,
        send: BroadcastFn,
        compute_root: ComputeRootFn,
    ) -> Self {
        Self {
            identity,
            db,
            send,
            compute_root,
            diag: None,
            active_voter_set: None,
            pending: RwLock::new(HashMap::new()),
            last_sync_request: RwLock::new(0),
            last_stall_alarm: RwLock::new(0),
            sync_serves: RwLock::new(HashMap::new()),
            voter_set_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Attach a diagnostic breakdown closure (see [`ComputeRootDiagFn`]).
    pub fn with_diag(mut self, diag: ComputeRootDiagFn) -> Self {
        self.diag = Some(diag);
        self
    }

    /// Attach the active-voter-set resolver (see [`ActiveVoterSetFn`]). Once
    /// `ACTIVE_VOTER_SET` activates, the consensus draws its voter/proposer/quorum set
    /// from all qualified active nodes instead of only the MPC elders.
    pub fn with_active_voter_set_fn(mut self, f: ActiveVoterSetFn) -> Self {
        self.active_voter_set = Some(f);
        self
    }

    /// Emit the root-input breakdown at INFO under a shared `tag`, if diag is wired.
    fn log_diag(&self, tag: &str, height: u64, cutoff_ts: i64) {
        if let Some(d) = &self.diag {
            info!(
                height,
                tag,
                "payout checkpoint DIAG: {}",
                d(cutoff_ts, height)
            );
        }
    }

    /// Serialise + enqueue an outbound broadcast (fire-and-forget).
    fn broadcast<T: serde::Serialize>(&self, ty: MessageType, msg: &T) {
        match serde_json::to_vec(msg) {
            Ok(bytes) => {
                if let Err(e) = (self.send)(ty, bytes) {
                    warn!(error = %e, "payout checkpoint: enqueue broadcast failed");
                }
            }
            Err(e) => error!(error = %e, "payout checkpoint: serialise failed"),
        }
    }

    /// Deterministic, fleet-agreed elder set, sorted so every node indexes it
    /// identically.
    fn elders_sorted(&self) -> Vec<NodeId> {
        let mut e: Vec<NodeId> = self
            .db
            .get_mpc_elder_node_ids()
            .unwrap_or_default()
            .into_iter()
            .collect();
        e.sort_unstable();
        e
    }

    /// The consensus voter set for `height` at `cutoff_ts` — who may propose, vote, and
    /// count toward quorum. Below the `ACTIVE_VOTER_SET` gate (or with no resolver wired)
    /// this is the MPC elder set, identical to the historical behaviour. At/above the gate
    /// it WIDENS to the converged active qualified set (all qualified nodes, not just MPC
    /// contributors) so post-ceremony joiners participate.
    ///
    /// BOOTSTRAP FLOOR: the active set is used only when it is a *superset* of the current
    /// elders. If a partition or an unqualified elder would make it narrower, we fall back
    /// to the elder set — so the voter set can only ever GROW beyond the established floor,
    /// never shrink below it. This makes the gate strictly no-less-safe than the elder path.
    /// Determinism across the fleet is guaranteed because the active set is the same
    /// convergence-proven qualified set the ledger root already commits to.
    fn voter_set_for(&self, height: u64, cutoff_ts: i64) -> Vec<NodeId> {
        let elders = self.elders_sorted();
        if height >= crate::active_voter_set_height() {
            if let Some(resolve) = &self.active_voter_set {
                if let Some(hit) = self.cached_voter_set(height, cutoff_ts) {
                    return hit;
                }
                let resolved = widen_voter_set(elders, resolve(cutoff_ts, height));
                self.store_voter_set(height, cutoff_ts, &resolved);
                return resolved;
            }
        }
        elders
    }

    /// A cached voter set for this key, if one is present and still fresh.
    fn cached_voter_set(&self, height: u64, cutoff_ts: i64) -> Option<Vec<NodeId>> {
        let cache = self.voter_set_cache.read();
        let (set, at) = cache.get(&(height, cutoff_ts))?;
        (at.elapsed().as_secs() < VOTER_SET_CACHE_TTL_SECS).then(|| set.clone())
    }

    /// Record a resolved voter set, evicting anything already expired.
    ///
    /// Eviction is a full sweep rather than an LRU because the map is small by construction — one
    /// entry per in-flight `(height, cutoff_ts)` — and a sweep cannot leak an entry whose height
    /// the node never revisits, which an LRU bounded only by size can.
    fn store_voter_set(&self, height: u64, cutoff_ts: i64, set: &[NodeId]) {
        let mut cache = self.voter_set_cache.write();
        cache.retain(|_, (_, at)| at.elapsed().as_secs() < VOTER_SET_CACHE_TTL_SECS);
        cache.insert(
            (height, cutoff_ts),
            (set.to_vec(), std::time::Instant::now()),
        );
    }

    /// Deterministic proposer for `height` (round-robin over the voter set at `cutoff_ts`).
    fn proposer_for(&self, height: u64, cutoff_ts: i64) -> Option<NodeId> {
        let v = self.voter_set_for(height, cutoff_ts);
        if v.is_empty() {
            None
        } else {
            Some(v[(height as usize) % v.len()])
        }
    }

    fn already_finalized(&self, height: u64) -> bool {
        if self
            .pending
            .read()
            .get(&height)
            .map(|p| p.finalized)
            .unwrap_or(false)
        {
            return true;
        }
        // Durably persisted at this exact height?
        matches!(
            self.db.get_payout_ledger_checkpoint_at_or_before(height),
            Ok(Some(r)) if r.height == height
        )
    }

    /// Compute the canonical payout WITHOUT blocking the async runtime.
    ///
    /// `compute_root` is a synchronous closure that walks the whole unpaid ledger:
    /// `get_top_unpaid_addresses` scans every unpaid share to produce a handful of per-address
    /// totals. Measured on ghost-vm5 2026-07-31 against 2.76M unpaid rows: **1.60 s wall,
    /// 1.33 s user CPU, returning 78 rows**. It already uses a covering index — the cost is
    /// inherent to the row count, not a missing index.
    ///
    /// Run inline on a runtime worker it starved everything sharing that worker: `/health`
    /// showed a **15 s period with ~5 s blocking windows, 40% of wall-clock blocked**, one
    /// `tokio-runtime-worker` pinned at 72–83% while median latency stayed at 0.4 ms. A pure
    /// tail effect, and the reason #571's read-connection pool could not help — the contention
    /// is CPU on the executor, not connections on the database.
    ///
    /// `spawn_blocking` moves it to the blocking pool, so a long scan can no longer stall
    /// request handling, gossip or voting. It does NOT make the scan cheaper; see #554 for the
    /// remaining options (memoisation — which needs a mutation fingerprint to stay correct, see
    /// the hazard note there — and shrinking the scan via #558's dead-share reconciliation).
    async fn compute_root_off_runtime(
        &self,
        cutoff_ts: i64,
        height: u64,
    ) -> Option<CanonicalPayout> {
        let f = Arc::clone(&self.compute_root);
        match tokio::task::spawn_blocking(move || f(cutoff_ts, height)).await {
            Ok(v) => v,
            Err(e) => {
                // A panic inside the scan must not be read as "not computable" without a
                // trace: that path abstains silently, which is indistinguishable from an
                // unconverged ledger and would hide a real fault.
                warn!(height, error = %e, "payout checkpoint: canonical payout task failed");
                None
            }
        }
    }

    /// Called on a cadence from `main.rs` with the target lagging checkpoint
    /// height. No-op unless this node is the deterministic proposer for it.
    pub async fn maybe_propose(&self, height: u64, cutoff_ts: i64) {
        let me = self.identity.node_id();
        let voters = self.voter_set_for(height, cutoff_ts);
        let proposer = (!voters.is_empty()).then(|| voters[(height as usize) % voters.len()]);
        if proposer != Some(me) || self.already_finalized(height) {
            return;
        }
        let Some(canonical) = self.compute_root_off_runtime(cutoff_ts, height).await else {
            // C-7: cannot compute from our own view — do not propose an
            // unreproducible payout; wait for convergence.
            warn!(
                height,
                "payout checkpoint: canonical payout not computable (data not converged) — not proposing"
            );
            return;
        };

        let active_node_count = voters.len() as u32;
        // Kept for the proposer's OWN vote report (#606): it reports the same numbers it proposed,
        // and they count once, exactly like any other voter's.
        let proposer_own = canonical.clone();
        let mut msg = PayoutLedgerCheckpointMessage {
            height,
            cutoff_ts,
            ledger_root: canonical.root,
            miner_payouts: canonical.miner_payouts,
            node_shares: canonical.node_shares,
            active_node_count,
            proposer: me,
            proposer_signature: [0u8; 64],
            timestamp: now_ms(),
        };
        let hash = msg.checkpoint_hash();
        msg.proposer_signature = self.identity.sign(&hash);

        // Record our own proposal + approval, then broadcast both.
        {
            let mut pending = self.pending.write();
            let p = pending.entry(height).or_insert_with(Pending::new);
            let e = p.entry(hash);
            e.proposal = Some(msg.clone());
            e.approvers.insert(me);
        }
        info!(
            height,
            root = %hex::encode(&msg.ledger_root[..8]),
            miners = msg.miner_payouts.len(),
            nodes = msg.node_shares.len(),
            "payout checkpoint: proposing"
        );
        self.log_diag("propose", height, cutoff_ts);
        self.broadcast(MessageType::PayoutLedgerCheckpoint, &msg);
        // The proposer reports too, and gets exactly one vote like everyone else.
        self.cast_vote(height, hash, true, Some(&proposer_own));
        self.maybe_finalize(height, hash);
    }

    async fn on_proposal(&self, env: &MessageEnvelope) -> GhostResult<()> {
        let msg: PayoutLedgerCheckpointMessage = match serde_json::from_slice(&env.payload) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        // Authorisation: the Noise-authenticated sender must be the declared
        // proposer AND the deterministic proposer for this height.
        if env.sender != msg.proposer
            || self.proposer_for(msg.height, msg.cutoff_ts) != Some(msg.proposer)
        {
            debug!(
                height = msg.height,
                "payout checkpoint: proposal from non-proposer — ignored"
            );
            return Ok(());
        }
        if self.already_finalized(msg.height) {
            return Ok(());
        }
        let hash = msg.checkpoint_hash();

        // INTEGRITY: the proposer's `ledger_root` must actually be the hash of the lists
        // it sent — otherwise the signed `checkpoint_hash` (which commits to `ledger_root`)
        // wouldn't bind the payload, and a proposer could ship one root but different lists.
        let claimed_root = crate::payout::compute_ledger_root(
            &msg.miner_payouts,
            &msg.node_shares,
            msg.cutoff_ts,
            msg.height,
        );
        if claimed_root != msg.ledger_root {
            warn!(
                height = msg.height,
                proposer = %hex::encode(&msg.proposer[..4]),
                "payout checkpoint: proposal root does not match its lists — voting reject"
            );
            self.cast_vote(msg.height, hash, false, None);
            return Ok(());
        }

        // Option (c): recompute our OWN canonical payout and tolerance-check the proposer's.
        let Some(local) = self
            .compute_root_off_runtime(msg.cutoff_ts, msg.height)
            .await
        else {
            // C-7: we lack the data to judge it — abstain (do NOT approve).
            warn!(
                height = msg.height,
                "payout checkpoint: cannot recompute canonical payout — abstaining (needs convergence)"
            );
            self.log_diag("abstain", msg.height, msg.cutoff_ts);
            let height = msg.height;
            let mut pending = self.pending.write();
            let slot = pending
                .entry(height)
                .or_insert_with(Pending::new)
                .entry(hash);
            slot.proposal = Some(msg);
            return Ok(());
        };
        // Approve if the proposer's payout is within tolerance of ours (attribution +
        // float-order noise is same-operator cosmetic); a real misallocation exceeds it.
        let disagreement =
            payouts_agree(&local, &msg.miner_payouts, &msg.node_shares, msg.height).err();
        let approve = disagreement.is_none();
        info!(height = msg.height, approve, "payout checkpoint: vote");
        {
            let mut pending = self.pending.write();
            let p = pending.entry(msg.height).or_insert_with(Pending::new);
            let e = p.entry(hash);
            e.proposal = Some(msg.clone());
            if approve {
                e.approvers.insert(self.identity.node_id());
            }
        }
        if let Some(reason) = &disagreement {
            warn!(
                height = msg.height,
                local_root = %hex::encode(&local.root[..8]),
                proposed_root = %hex::encode(&msg.ledger_root[..8]),
                proposer = %hex::encode(&msg.proposer[..4]),
                %reason,
                "payout checkpoint: disagrees with proposal — voting reject"
            );
            self.log_diag("reject", msg.height, msg.cutoff_ts);
        }
        self.cast_vote(msg.height, hash, approve, Some(&local));
        if approve {
            self.maybe_finalize(msg.height, hash);
        }
        Ok(())
    }

    async fn on_vote(&self, env: &MessageEnvelope) -> GhostResult<()> {
        let vote: PayoutLedgerCheckpointVoteMessage = match serde_json::from_slice(&env.payload) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        // The Noise-authenticated sender must be the voter. Voter-set ELIGIBILITY is
        // enforced authoritatively in `maybe_finalize` (where the proposal — and thus the
        // cutoff that resolves the voter set — is known); here we only accumulate
        // authenticated approvals. The approvers set is a `HashSet<NodeId>` bounded by the
        // authenticated peer set, and finalisation counts only approvers ∩ voter_set, so an
        // ineligible authenticated node's vote can never contribute to quorum.
        if env.sender != vote.voter {
            return Ok(());
        }
        if !vote.approve {
            return Ok(());
        }
        {
            let mut pending = self.pending.write();
            let slot = pending
                .entry(vote.height)
                .or_insert_with(Pending::new)
                .entry(vote.checkpoint_hash);
            slot.approvers.insert(vote.voter);
            // Keyed by voter, so a duplicate vote replaces rather than double-weights (#606).
            if !vote.reported_miner_work.is_empty() || !vote.reported_node_shares.is_empty() {
                slot.reports.insert(
                    vote.voter,
                    (
                        vote.reported_miner_work.clone(),
                        vote.reported_node_shares.clone(),
                    ),
                );
            }
        }
        self.maybe_finalize(vote.height, vote.checkpoint_hash);
        Ok(())
    }

    /// Cast a checkpoint vote, optionally REPORTING this node's own recomputed view (#606).
    ///
    /// `own` is the voter's `CanonicalPayout`. At/above the median-adoption gate an APPROVING vote
    /// carries the voter's own per-address numbers, so finalisation can adopt their median rather
    /// than trusting the proposer's list. Below the gate, and on any reject, nothing is reported —
    /// the wire format stays byte-identical to the old one, which is what keeps a mixed-version
    /// fleet interoperable while the gate is still dormant.
    ///
    /// A reject carries no report deliberately: a voter that disagrees beyond tolerance is saying
    /// the proposal is unusable, not offering a correction to be averaged in.
    fn cast_vote(
        &self,
        height: u64,
        checkpoint_hash: [u8; 32],
        approve: bool,
        own: Option<&CanonicalPayout>,
    ) {
        let (reported_miner_work, reported_node_shares) = match own {
            Some(c) if approve && crate::adopts_payout_median(height) => {
                (c.miner_payouts.clone(), c.node_shares.clone())
            }
            _ => (Vec::new(), Vec::new()),
        };
        let mut vote = PayoutLedgerCheckpointVoteMessage {
            height,
            checkpoint_hash,
            voter: self.identity.node_id(),
            approve,
            signature: [0u8; 64],
            timestamp: now_ms(),
            reported_miner_work,
            reported_node_shares,
        };
        vote.signature = self.identity.sign(&vote.signing_message());
        self.broadcast(MessageType::PayoutLedgerCheckpointVote, &vote);
    }

    /// Persist the checkpoint once ≥67% of elders have approved a hash for which
    /// we hold the proposal content. Idempotent.
    fn maybe_finalize(&self, height: u64, hash: [u8; 32]) {
        let mut pending = self.pending.write();
        let Some(p) = pending.get_mut(&height) else {
            return;
        };
        if p.finalized {
            return;
        }
        // Need the proposal BOTH to resolve the voter set (its cutoff) and to persist. If a
        // vote arrived before the proposal, we hold no content yet — the proposal message
        // will arrive and re-trigger this.
        let (approvers, msg, reports) = {
            let Some(entry) = p.by_hash.get(&hash) else {
                return;
            };
            let Some(msg) = entry.proposal.clone() else {
                return;
            };
            (entry.approvers.clone(), msg, entry.reports.clone())
        };
        // Authoritative eligibility + quorum: resolve the voter set at the proposal's cutoff
        // and count ONLY approvers that are in it. Below the ACTIVE_VOTER_SET gate this is
        // the elder set (identical to the historical `approvers.len() >= quorum(elders)`);
        // at/above it, the widened qualified set.
        let voters = self.voter_set_for(height, msg.cutoff_ts);
        let needed = quorum_for(voters.len());
        if needed == 0 {
            return;
        }
        let approvals = voters.iter().filter(|v| approvers.contains(*v)).count();
        if approvals < needed {
            return;
        }
        // What gets PERSISTED, and therefore what the coinbase pays.
        //
        // Below the median gate: the proposer's lists verbatim, so the coinbase builds from THEM
        // rather than from this node's (divergent) local ledger. That is the behaviour #606 exists
        // to replace — "within tolerance" was "adopted", so a proposer could skew every address and
        // be ratified by an honest quorum.
        //
        // At/above it: the per-address lower median of what the in-set approvers actually
        // recomputed. The proposer's own report is one of them and carries no extra weight.
        let (adopted_miners, adopted_nodes) = if crate::adopts_payout_median(height) {
            // Only in-set voters count, matching the quorum rule above — an out-of-set node must not
            // be able to shift the median any more than it can affect the tally.
            let in_set: Vec<&VoterReport> = voters.iter().filter_map(|v| reports.get(v)).collect();
            let reporting = in_set.len();
            if reporting < needed {
                // Refuse rather than silently falling back to the proposer's list — that fallback IS
                // the vulnerability. A checkpoint that cannot be corroborated does not finalise; the
                // next height re-proposes.
                warn!(
                    height,
                    reporting,
                    needed,
                    "payout checkpoint: too few reports to take a median — not finalising (#606)"
                );
                return;
            }
            let miner_reports: Vec<Vec<(String, u128)>> =
                in_set.iter().map(|(m, _)| m.clone()).collect();
            let medians = median_adopted_miner_work(&miner_reports);

            // Detection, not just correction: say so when the proposer sat beyond half its allowed
            // tolerance from the median. This is the evidence for whether skew actually happens.
            let proposed: std::collections::HashMap<&str, u128> = msg
                .miner_payouts
                .iter()
                .map(|(a, w)| (a.as_str(), *w))
                .collect();
            for (addr, median) in &medians {
                if let Some(p) = proposed.get(addr.as_str()) {
                    if let Some(permille) = proposer_skew_permille(*p, *median) {
                        if permille > SKEW_ALERT_PERMILLE {
                            warn!(
                                height,
                                proposer = %hex::encode(&msg.proposer[..4]),
                                address = %addr_handle(addr),
                                permille,
                                threshold = SKEW_ALERT_PERMILLE,
                                "payout checkpoint: proposer's value is far from the fleet median (#606)"
                            );
                        }
                    }
                }
            }
            // Node shares converge exactly (payout-address gossip), so the proposer's list stands.
            (medians, msg.node_shares.clone())
        } else {
            (msg.miner_payouts.clone(), msg.node_shares.clone())
        };

        let record = PayoutLedgerCheckpointRecord {
            height,
            cutoff_ts: msg.cutoff_ts,
            ledger_root: msg.ledger_root,
            proposer_id: hex::encode(msg.proposer),
            active_node_count: msg.active_node_count,
            miner_payouts: adopted_miners,
            node_shares: adopted_nodes,
        };
        match self.db.upsert_payout_ledger_checkpoint(&record) {
            Ok(()) => {
                p.finalized = true;
                info!(
                    height,
                    root = %hex::encode(&msg.ledger_root[..8]),
                    approvals,
                    needed,
                    "payout ledger checkpoint FINALISED"
                );
            }
            Err(e) => error!(height, error = %e, "payout checkpoint: persist failed"),
        }
    }

    /// Convergence-stall alarm. Called on the propose cadence by EVERY node, proposer or
    /// not, and deliberately separate from [`Self::maybe_request_backfill`] — that returns
    /// early on its own cooldown, which would silence the alarm exactly when it matters.
    ///
    /// Payout checkpointing normally finalises every block, so any sustained gap between
    /// our latest finalised checkpoint and the anchor means the fleet is not converging
    /// and miners are not being paid. That state held for **four days** (2026-07-25 →
    /// 2026-07-29, 557 blocks) without producing a single alarm: proposals were rejected,
    /// each reject logged at `warn`, and nothing aggregated them into "payouts are
    /// stopped". This is that aggregation. → #548.
    ///
    /// Escalates rather than fires once: `warn` past `STALL_WARN_BLOCKS` (a hole the
    /// backfill is still plausibly chasing), `error` past `STALL_ERROR_BLOCKS` (no
    /// transient explanation left — payouts have stopped).
    pub fn check_convergence_stall(&self, target_height: u64) {
        let latest = self
            .db
            .get_latest_payout_ledger_checkpoint()
            .ok()
            .flatten()
            .map(|r| r.height)
            .unwrap_or(0);
        // `latest == 0` means "no checkpoint ever" — a fresh node, not a stall.
        if latest == 0 || latest >= target_height.saturating_sub(STALL_WARN_BLOCKS) {
            return;
        }
        let behind = target_height.saturating_sub(latest);

        let now = now_ms();
        {
            let mut last = self.last_stall_alarm.write();
            if now.saturating_sub(*last) < STALL_ALARM_COOLDOWN_MS {
                return;
            }
            *last = now;
        }

        if behind >= STALL_ERROR_BLOCKS {
            error!(
                latest_finalized = latest,
                anchor_height = target_height,
                blocks_behind = behind,
                "PAYOUT CONVERGENCE FAILED: no payout checkpoint has finalised for \
                 {behind} blocks — miners are NOT being paid. Check the 'voting reject' \
                 warnings for the disagreeing field."
            );
        } else {
            warn!(
                latest_finalized = latest,
                anchor_height = target_height,
                blocks_behind = behind,
                "payout checkpoint: convergence lagging {behind} blocks behind the anchor"
            );
        }
    }

    /// Backfill trigger, called on the propose cadence with `target_height` (= tip − LAG).
    /// If our latest finalised checkpoint lags the anchor, broadcast a bounded sync
    /// request. This recovers holes a *missed* proposal left — including the parked-tip
    /// case (proposals are broadcast once and never rebroadcast, so a dropped packet is
    /// otherwise unrecoverable until the tip advances). Rate-limited to one per cooldown.
    ///
    /// Residual: a hole that opens and is jumped past within one cooldown (tip advancing
    /// <60s after a miss) is not chased — rare, and coinbase-relevant for only one
    /// already-past block. The dominant failure (node behind a parked anchor) is covered.
    pub fn maybe_request_backfill(&self, target_height: u64) {
        let latest = self
            .db
            .get_latest_payout_ledger_checkpoint()
            .ok()
            .flatten()
            .map(|r| r.height)
            .unwrap_or(0);
        if latest >= target_height {
            return; // our max finalised height is at/above the anchor — nothing to pull
        }
        let now = now_ms();
        {
            let mut last = self.last_sync_request.write();
            if now.saturating_sub(*last) < SYNC_COOLDOWN_MS {
                return; // client cooldown
            }
            *last = now;
        }
        // Only ever pull a recent window near the anchor; never trawl ancient history.
        let from_height = (latest + 1).max(target_height.saturating_sub(MAX_SYNC_CHECKPOINTS - 1));
        let req = PayoutCheckpointSyncRequest {
            requesting_node: self.identity.node_id(),
            from_height,
            timestamp: now,
        };
        info!(
            from_height,
            latest,
            target = target_height,
            "payout checkpoint: requesting backfill"
        );
        self.broadcast(MessageType::PayoutLedgerCheckpointSync, &req);
    }

    /// Responder: serve a bounded, ascending page of finalised checkpoints from the
    /// requested height. Per-peer cooldown bounds response churn; the requester paginates.
    async fn on_sync_request(&self, env: &MessageEnvelope) -> GhostResult<()> {
        let req: PayoutCheckpointSyncRequest = match serde_json::from_slice(&env.payload) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        // The Noise-authenticated sender must be the declared requester.
        if env.sender != req.requesting_node {
            return Ok(());
        }
        let now = now_ms();
        {
            let mut serves = self.sync_serves.write();
            if let Some(&last) = serves.get(&req.requesting_node) {
                if now.saturating_sub(last) < SYNC_COOLDOWN_MS {
                    return Ok(()); // per-peer serve cooldown
                }
            }
            serves.insert(req.requesting_node, now);
        }
        let records = match self
            .db
            .get_payout_ledger_checkpoints_from_height(req.from_height, MAX_SYNC_CHECKPOINTS)
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "payout checkpoint: sync query failed");
                return Ok(());
            }
        };
        if records.is_empty() {
            return Ok(());
        }
        let has_more = records.len() as u64 >= MAX_SYNC_CHECKPOINTS;
        let mut checkpoints = Vec::with_capacity(records.len());
        for r in records {
            // proposer_id is stored as hex; parse back to NodeId for the entry.
            let Some(proposer) = decode_node_id(&r.proposer_id) else {
                continue;
            };
            checkpoints.push(PayoutCheckpointSyncEntry {
                height: r.height,
                cutoff_ts: r.cutoff_ts,
                ledger_root: r.ledger_root,
                miner_payouts: r.miner_payouts,
                node_shares: r.node_shares,
                active_node_count: r.active_node_count,
                proposer,
            });
        }
        if checkpoints.is_empty() {
            return Ok(());
        }
        let resp = PayoutCheckpointSyncResponse {
            responding_node: self.identity.node_id(),
            checkpoints,
            has_more,
            timestamp: now,
        };
        debug!(
            count = resp.checkpoints.len(),
            to = %hex::encode(&req.requesting_node[..4]),
            "payout checkpoint: serving backfill"
        );
        self.broadcast(MessageType::PayoutLedgerCheckpointSync, &resp);
        Ok(())
    }

    /// Requester: trustlessly adopt each synced checkpoint (see `apply_synced_checkpoint`).
    async fn on_sync_response(&self, env: &MessageEnvelope) -> GhostResult<()> {
        let resp: PayoutCheckpointSyncResponse = match serde_json::from_slice(&env.payload) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        if env.sender != resp.responding_node {
            return Ok(());
        }
        let mut applied = 0usize;
        for entry in &resp.checkpoints {
            if self.apply_synced_checkpoint(entry).await {
                applied += 1;
            }
        }
        if applied > 0 {
            info!(
                applied,
                from = %hex::encode(&resp.responding_node[..4]),
                "payout checkpoint: backfilled"
            );
        }
        Ok(())
    }

    /// Trustlessly adopt one synced checkpoint: verify authorship + root integrity,
    /// INDEPENDENTLY recompute our own canonical payout, require it agrees within
    /// tolerance, then persist. Never trusts the serving peer (strictly stronger than
    /// L2's signature-only sync). Returns true iff newly persisted.
    /// Async because it recomputes the canonical payout, which is a full unpaid-ledger scan and
    /// must not run on a runtime worker. Catch-up sync applies these in a LOOP, so inline it
    /// blocked for N x 1.6 s exactly when a node was already behind and trying to recover.
    async fn apply_synced_checkpoint(&self, entry: &PayoutCheckpointSyncEntry) -> bool {
        if self.already_finalized(entry.height) {
            return false;
        }
        // Authorship: must be the deterministic proposer for this height.
        if self.proposer_for(entry.height, entry.cutoff_ts) != Some(entry.proposer) {
            return false;
        }
        // Integrity: the root must be the hash of the lists carried.
        let claimed_root = crate::payout::compute_ledger_root(
            &entry.miner_payouts,
            &entry.node_shares,
            entry.cutoff_ts,
            entry.height,
        );
        if claimed_root != entry.ledger_root {
            return false;
        }
        // Trustless: recompute OUR canonical payout and require tolerance agreement.
        let Some(local) = self
            .compute_root_off_runtime(entry.cutoff_ts, entry.height)
            .await
        else {
            return false; // cannot validate yet — skip; a later cadence retries
        };
        if let Err(reason) = payouts_agree(
            &local,
            &entry.miner_payouts,
            &entry.node_shares,
            entry.height,
        ) {
            warn!(
                height = entry.height,
                %reason,
                "payout checkpoint: synced checkpoint disagrees with ours — rejected"
            );
            return false;
        }
        let record = PayoutLedgerCheckpointRecord {
            height: entry.height,
            cutoff_ts: entry.cutoff_ts,
            ledger_root: entry.ledger_root,
            proposer_id: hex::encode(entry.proposer),
            active_node_count: entry.active_node_count,
            miner_payouts: entry.miner_payouts.clone(),
            node_shares: entry.node_shares.clone(),
        };
        match self.db.upsert_payout_ledger_checkpoint(&record) {
            Ok(()) => {
                // Mark pending finalised so we won't re-propose/re-vote this height.
                self.pending
                    .write()
                    .entry(entry.height)
                    .or_insert_with(Pending::new)
                    .finalized = true;
                true
            }
            Err(e) => {
                error!(height = entry.height, error = %e, "payout checkpoint: sync persist failed");
                false
            }
        }
    }
}

/// Decode a hex node-id string back to a `NodeId`.
fn decode_node_id(s: &str) -> Option<NodeId> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Some(id)
}

#[async_trait]
impl MessageHandler for PayoutCheckpointManager {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        match envelope.msg_type {
            MessageType::PayoutLedgerCheckpoint => self.on_proposal(&envelope).await,
            MessageType::PayoutLedgerCheckpointVote => self.on_vote(&envelope).await,
            MessageType::PayoutLedgerCheckpointSync => {
                // Multiplex request/response by trial-deserialise (as L2 tree-sync does):
                // only the request carries `from_height`, so it parses iff it's a request.
                if serde_json::from_slice::<PayoutCheckpointSyncRequest>(&envelope.payload).is_ok()
                {
                    self.on_sync_request(&envelope).await
                } else {
                    self.on_sync_response(&envelope).await
                }
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    //! In-process N-node cluster tests with INDUCED per-node ledger divergence —
    //! the property that only a converged input finalises, and a divergent/lagged
    //! or malicious view can never force a bad checkpoint. This is exactly the
    //! gap that shipped v1.10.32 broken (regtest had no gossip lag → false green).
    use super::*;
    use ghost_storage::MpcContributionRecord;
    use std::sync::Mutex;

    type Outbox = Arc<Mutex<Vec<(MessageType, Vec<u8>)>>>;

    struct Node {
        id: NodeId,
        db: Arc<Database>,
        mgr: PayoutCheckpointManager,
        outbox: Outbox,
    }

    fn register_elders(db: &Database, elders: &[NodeId]) {
        for (i, e) in elders.iter().enumerate() {
            db.save_mpc_contribution(&MpcContributionRecord {
                elder_position: (i as u32) + 1,
                contributor_node_id: hex::encode(e),
                prev_params_hash: [0u8; 32],
                new_params_hash: [0u8; 32],
                contribution_proof: Vec::new(),
                epoch: 0,
                created_at: 0,
            })
            .expect("save elder");
        }
    }

    /// Build `n` nodes whose elder set is all `n` ids (sorted by node_id). The
    /// node at SORTED position `i` computes `roots[i]` from its own view
    /// (`None` = "can't compute yet" → C-7 abstain). Building in sorted order
    /// means `nodes[i].id == elders_sorted[i]`, so the proposer for height `H` is
    /// `nodes[H % n]` — deterministic and controllable.
    /// A shared 3-node qualified set every test uses (node set must match EXACTLY for
    /// approval — it converges via payout-address gossip in production).
    fn node_set() -> Vec<(NodeId, i32)> {
        vec![([1u8; 32], 10), ([2u8; 32], 6), ([3u8; 32], 6)]
    }

    /// Build a `CanonicalPayout` from a miner list (address, work), reusing `node_set()`.
    fn cp(miners: &[(&str, u128)]) -> CanonicalPayout {
        let miner_payouts: Vec<(String, u128)> =
            miners.iter().map(|(a, w)| (a.to_string(), *w)).collect();
        let node_shares = node_set();
        let root = crate::payout::compute_ledger_root(&miner_payouts, &node_shares, CUTOFF, H);
        CanonicalPayout {
            miner_payouts,
            node_shares,
            root,
        }
    }

    /// Each disagreement must be classified as ITS OWN cause, not funnelled into
    /// "outside tolerance" — three of the four causes are not about tolerance at all,
    /// and the single shared message is what kept the four-day 2026-07-25 stall
    /// pointed at the wrong constant. → #548.
    #[test]
    /// The voter set must be resolved ONCE per (height, cutoff_ts), not once per message.
    ///
    /// This is the #554 hot path. `voter_set_for` reaches
    /// `get_all_qualified_nodes_at_cutoff_from_db` -> `majority_capability_qualified` and joins
    /// `verification_ledger` against `nodes`; a 2026-08-09 profile of ghost-vm6 put it at 636
    /// samples, the largest single term in the process and 3.6x the canonical-payout recompute.
    /// It was called from the MESSAGE path, so a re-proposed height re-resolved the same answer
    /// forever — ~2,200 db page reads/sec on every node, which is what 504'd the HTTP API.
    fn the_voter_set_is_resolved_once_per_height_not_once_per_call() {
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        let elders: Vec<NodeId> = (1..=3u8).map(|n| [n; 32]).collect();
        register_elders(&db, &elders);

        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_c = Arc::clone(&calls);
        let resolved: Vec<NodeId> = (1..=5u8).map(|n| [n; 32]).collect();
        let resolved_c = resolved.clone();

        let mgr = PayoutCheckpointManager::new(
            Arc::new(NodeIdentity::generate()),
            Arc::clone(&db),
            Arc::new(|_, _| Ok(())),
            Arc::new(|_c, _h| None),
        )
        .with_active_voter_set_fn(Arc::new(move |_cutoff, _height| {
            calls_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            resolved_c.clone()
        }));

        let height = crate::active_voter_set_height();
        let first = mgr.voter_set_for(height, 1_786_228_093);
        for _ in 0..24 {
            let again = mgr.voter_set_for(height, 1_786_228_093);
            assert_eq!(
                again, first,
                "a cached voter set must equal the resolved one"
            );
        }

        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "25 calls for one (height, cutoff) must resolve the voter set exactly once"
        );
    }

    /// A different height must NOT reuse another height's voter set.
    ///
    /// The cache is keyed, not global: the voter set legitimately differs per height, and serving
    /// one height's answer for another would pin the wrong deterministic proposer.
    #[test]
    fn a_different_height_resolves_its_own_voter_set() {
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        let elders: Vec<NodeId> = (1..=3u8).map(|n| [n; 32]).collect();
        register_elders(&db, &elders);

        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_c = Arc::clone(&calls);
        // Answer depends on height, so a key collision is observable in the RESULT, not just the
        // call count — a cache that ignored height would return node [9;32] for both.
        let mgr = PayoutCheckpointManager::new(
            Arc::new(NodeIdentity::generate()),
            Arc::clone(&db),
            Arc::new(|_, _| Ok(())),
            Arc::new(|_c, _h| None),
        )
        .with_active_voter_set_fn(Arc::new(move |_cutoff, height| {
            calls_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            vec![[(height % 251) as u8; 32], [1u8; 32], [2u8; 32], [3u8; 32]]
        }));

        let base = crate::active_voter_set_height();
        let a = mgr.voter_set_for(base, 1_786_228_093);
        let b = mgr.voter_set_for(base + 1, 1_786_228_093);

        assert_ne!(a, b, "distinct heights must not share a cached voter set");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "each distinct height resolves once"
        );
    }

    /// A different cutoff at the same height must also resolve separately.
    #[test]
    fn a_different_cutoff_resolves_its_own_voter_set() {
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        let elders: Vec<NodeId> = (1..=3u8).map(|n| [n; 32]).collect();
        register_elders(&db, &elders);

        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_c = Arc::clone(&calls);
        let mgr = PayoutCheckpointManager::new(
            Arc::new(NodeIdentity::generate()),
            Arc::clone(&db),
            Arc::new(|_, _| Ok(())),
            Arc::new(|_c, _h| None),
        )
        .with_active_voter_set_fn(Arc::new(move |cutoff, _height| {
            calls_c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            vec![[(cutoff % 251) as u8; 32], [1u8; 32], [2u8; 32], [3u8; 32]]
        }));

        let h = crate::active_voter_set_height();
        let a = mgr.voter_set_for(h, 1_786_228_093);
        let b = mgr.voter_set_for(h, 1_786_228_094);

        assert_ne!(a, b, "the cutoff is part of the key, not decoration");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn disagreement_names_the_check_that_actually_failed() {
        let local = cp(&[("addr_a", 1_000_000_000_000_000), ("addr_b", 500)]);

        // Agreement.
        assert_eq!(
            payouts_agree(&local, &local.miner_payouts, &local.node_shares, H),
            Ok(())
        );

        // A DIFFERENT NUMBER of addresses — the 2026-07-25 case. Must NOT be reported
        // as a tolerance breach: tolerance is never consulted.
        let fewer = [("addr_a".to_string(), 1_000_000_000_000_000u128)];
        assert_eq!(
            payouts_agree(&local, &fewer, &local.node_shares, H),
            Err(Disagreement::MinerCount {
                local: 2,
                proposed: 1
            })
        );

        // Same COUNT, but one address we have no work for at all.
        let swapped = vec![
            ("addr_a".to_string(), 1_000_000_000_000_000u128),
            ("addr_z".to_string(), 500u128),
        ];
        assert!(matches!(
            payouts_agree(&local, &swapped, &local.node_shares, H),
            Err(Disagreement::UnknownAddress { .. })
        ));

        // Node set differs.
        assert!(matches!(
            payouts_agree(&local, &local.miner_payouts, &[([9u8; 32], 1)], H),
            Err(Disagreement::NodeSet { .. })
        ));

        // A genuine work disagreement — the only case that should read as tolerance.
        // 10% apart on a value far above ABS_TOL, so the 2% relative bound governs.
        let skewed = vec![
            ("addr_a".to_string(), 1_100_000_000_000_000u128),
            ("addr_b".to_string(), 500u128),
        ];
        assert!(matches!(
            payouts_agree(&local, &skewed, &local.node_shares, H),
            Err(Disagreement::WorkOutsideTolerance { .. })
        ));

        // ...and a small one stays inside it (ABS_TOL floor covers addr_b's 500).
        let nudged = vec![
            ("addr_a".to_string(), 1_000_000_000_000_001u128),
            ("addr_b".to_string(), 600u128),
        ];
        assert_eq!(
            payouts_agree(&local, &nudged, &local.node_shares, H),
            Ok(())
        );
    }

    /// The v2 tolerance, exercised on the ACTUAL fleet numbers that produced the
    /// four-day stall (`/api/v1/pool/next_payout`, height 960070, work in raw units):
    ///
    /// | address       | min          | max          | apart   |
    /// |---------------|--------------|--------------|---------|
    /// | `bc1qm3…7s3h` | 9,705,821    | 19,521,705   | 101.13% |
    /// | `bc1q9z…q0ej` | 2,412,193,347| 2,490,033,067|   3.23% |
    /// | `bc1qhf…nre2` | 1,858,741,826| 1,879,203,185|   1.10% |
    /// | `bc1q7z…y492` | 47,951,398,285| 48,216,728,458|  0.55% |
    ///
    /// Pre-gate the first two reject and payouts stop. Post-gate all four pass, because
    /// the bound now tracks coinbase impact: the 101% row moves 0.019% of the pool.
    #[test]
    fn v2_floor_stops_a_dust_address_vetoing_the_fleet() {
        // ABS_TOL (1e12) dwarfs these raw values, so scale up to where the RELATIVE
        // bounds actually govern — the regime the live pool is in.
        const S: u128 = 1_000_000;
        let local = cp(&[
            ("bc1qm3", 9_705_821 * S),
            ("bc1q9z", 2_412_193_347 * S),
            ("bc1qhf", 1_858_741_826 * S),
            ("bc1q7z", 47_951_398_285 * S),
        ]);
        let proposed = vec![
            ("bc1qm3".to_string(), 19_521_705 * S),
            ("bc1q9z".to_string(), 2_490_033_067 * S),
            ("bc1qhf".to_string(), 1_879_203_185 * S),
            ("bc1q7z".to_string(), 48_216_728_458 * S),
        ];

        // Pre-gate: the DUST address is what rejects — not the one holding 90% of
        // the pool, which is 0.55% off and passes. This is the live bug.
        let pre = payouts_agree(&local, &proposed, &local.node_shares, H);
        match pre {
            Err(Disagreement::WorkOutsideTolerance { ref addr_hash, .. }) => {
                assert_eq!(*addr_hash, addr_handle("bc1qm3"));
            }
            other => panic!("expected the dust address to veto pre-gate, got {other:?}"),
        }

        // Post-gate: every row passes, and the aggregate stays under its cap.
        assert_eq!(
            payouts_agree(
                &local,
                &proposed,
                &local.node_shares,
                crate::PAYOUT_TOLERANCE_V2_HEIGHT
            ),
            Ok(())
        );
    }

    /// The v2 floor must not become a licence to misallocate: an address moved by far
    /// more than the floor still rejects, and many small same-direction skews that each
    /// clear the floor individually are caught by the aggregate cap.
    #[test]
    fn v2_still_rejects_real_misallocation() {
        const S: u128 = 1_000_000;
        const GATE: u64 = crate::PAYOUT_TOLERANCE_V2_HEIGHT;

        // Single large misallocation: total 100e6*S, so the 0.2% floor is 200_000*S,
        // but 2% of `a` (1_000_000*S) governs. Move `a` by 5% of itself.
        let local = cp(&[
            ("a", 50_000_000 * S),
            ("b", 25_000_000 * S),
            ("c", 25_000_000 * S),
        ]);
        let robbed = vec![
            ("a".to_string(), 47_500_000 * S),
            ("b".to_string(), 25_000_000 * S),
            ("c".to_string(), 25_000_000 * S),
        ];
        assert!(matches!(
            payouts_agree(&local, &robbed, &local.node_shares, GATE),
            Err(Disagreement::WorkOutsideTolerance { .. })
        ));

        // Death by a thousand cuts: 40 dust addresses each moved just INSIDE the
        // 0.2%-of-pool floor, all in the same direction. Every one passes its own
        // bound; together they shift ~8% of the pool. Only the aggregate cap sees it.
        let names: Vec<String> = (0..40).map(|i| format!("x{i}")).collect();
        let mut rows: Vec<(&str, u128)> = names.iter().map(|n| (n.as_str(), 100 * S)).collect();
        rows.push(("big", 100_000_000 * S));
        let local2 = cp(&rows);

        let floor = (100_000_000 * S + 4_000 * S) / POOL_REL_TOL_DEN * POOL_REL_TOL_NUM;
        let mut skewed: Vec<(String, u128)> =
            names.iter().map(|n| (n.clone(), 100 * S + floor)).collect();
        skewed.push(("big".to_string(), 100_000_000 * S));
        assert!(matches!(
            payouts_agree(&local2, &skewed, &local2.node_shares, GATE),
            Err(Disagreement::AggregateOutsideTolerance { .. })
        ));
    }

    /// The address handle must be identical on every node for a given address —
    /// that is the whole point of it (payout addresses are encrypted per-node, so
    /// the stored form is not comparable across logs).
    #[test]
    fn addr_handle_is_stable_and_short() {
        assert_eq!(addr_handle("bc1qexample"), addr_handle("bc1qexample"));
        assert_ne!(addr_handle("bc1qexample"), addr_handle("bc1qexampl3"));
        assert_eq!(addr_handle("bc1qexample").len(), 12);
    }

    /// Build `n` nodes; node at SORTED elder position `i` computes `payouts[i]` from its
    /// own view (`None` = C-7 abstain). Sorted order means `nodes[i].id == elders_sorted[i]`,
    /// so the proposer for height `H` is `nodes[H % n]`.
    fn build(n: usize, payouts: &[Option<CanonicalPayout>]) -> Vec<Node> {
        assert_eq!(n, payouts.len());
        let ids: Vec<Arc<NodeIdentity>> =
            (0..n).map(|_| Arc::new(NodeIdentity::generate())).collect();
        let mut elders: Vec<NodeId> = ids.iter().map(|i| i.node_id()).collect();
        elders.sort_unstable();

        let mut nodes = Vec::new();
        for (pos, &want) in elders.iter().enumerate() {
            let identity = ids.iter().find(|i| i.node_id() == want).unwrap().clone();
            let db = Arc::new(Database::in_memory().expect("db"));
            register_elders(&db, &elders);
            let outbox: Outbox = Arc::new(Mutex::new(Vec::new()));
            let ob = Arc::clone(&outbox);
            let send: BroadcastFn = Arc::new(move |ty, bytes| {
                ob.lock().unwrap().push((ty, bytes));
                Ok(())
            });
            let payout = payouts[pos].clone();
            let compute_root: ComputeRootFn = Arc::new(move |_c, _h| payout.clone());
            let mgr =
                PayoutCheckpointManager::new(identity.clone(), Arc::clone(&db), send, compute_root);
            nodes.push(Node {
                id: identity.node_id(),
                db,
                mgr,
                outbox,
            });
        }
        nodes
    }

    fn drain(n: &Node) -> Vec<(MessageType, Vec<u8>)> {
        std::mem::take(&mut *n.outbox.lock().unwrap())
    }

    /// Deliver every queued broadcast to every other node until the fleet is
    /// quiet (bounded — the flow settles in a couple of rounds).
    async fn gossip_until_quiet(nodes: &[Node]) {
        for _ in 0..20 {
            let mut msgs = Vec::new();
            for n in nodes {
                for (ty, payload) in drain(n) {
                    msgs.push((n.id, ty, payload));
                }
            }
            if msgs.is_empty() {
                break;
            }
            for (from, ty, payload) in msgs {
                for n in nodes {
                    if n.id != from {
                        let env = Arc::new(MessageEnvelope::new(
                            ty,
                            from,
                            payload.clone(),
                            0,
                            [0u8; 64],
                        ));
                        n.mgr.handle_message(env).await.expect("handle");
                    }
                }
            }
        }
    }

    const H: u64 = 100; // 100 % 4 == 0 → proposer is sorted-elder[0] = nodes[0]
    const CUTOFF: i64 = 1_784_000_000;

    /// #606 is ARMED at 961_700. This test pins the two properties that make an armed gate safe.
    ///
    /// The precondition was that every node already accepts an enlarged vote — a report reaches ~70 KB
    /// and a node predating `MAX_PAYOUT_LEDGER_VOTE_SIZE` drops it against the old 1 KB limit, costing
    /// quorum. That was satisfied by rolling `e9ca0c446` to all eight nodes before arming.
    #[test]
    fn median_adoption_gate_is_armed_and_switches_at_exactly_one_height() {
        let h = crate::PAYOUT_MEDIAN_ADOPTION_HEIGHT;
        assert_ne!(
            h,
            u64::MAX,
            "#606 is armed; a dormant value here means arming was reverted"
        );

        // Separated from the other payout behaviour change on purpose: two of them landing together
        // makes a divergence unattributable to either.
        assert!(
            h > crate::OBSERVED_SETTLEMENT_HEIGHT,
            "median adoption must land AFTER observed settlement, not with it"
        );

        // The switch is exact — one height, no window where nodes could disagree about the rule.
        assert!(
            !crate::adopts_payout_median(h - 1),
            "must not adopt one block early"
        );
        assert!(
            crate::adopts_payout_median(h),
            "must adopt at exactly the gate height"
        );
        assert!(
            crate::adopts_payout_median(h + 1),
            "must stay adopted above the gate"
        );
    }

    /// THE #606 CASE. A proposer that skews every address within tolerance must not get its skew
    /// adopted, even though an honest quorum approves the proposal.
    ///
    /// This is the property the old code lacked entirely: finalisation persisted the proposer's list
    /// verbatim, so "within tolerance" WAS "adopted", and the skew compounded at every checkpoint.
    #[test]
    fn a_proposer_skewing_every_address_within_tolerance_is_corrected_by_the_median() {
        let honest = || {
            vec![
                ("bc1qbig".to_string(), 1_000_000u128),
                ("bc1qmid".to_string(), 500_000u128),
                ("bc1qsml".to_string(), 100_000u128),
            ]
        };
        // Proposer skews every address by +1.9% — inside the 2% per-address tolerance, so every
        // honest voter approves it.
        let skewed = vec![
            ("bc1qbig".to_string(), 1_019_000u128),
            ("bc1qmid".to_string(), 509_500u128),
            ("bc1qsml".to_string(), 101_900u128),
        ];

        // Proposer plus four honest voters. The proposer gets exactly one vote.
        let reports = vec![skewed.clone(), honest(), honest(), honest(), honest()];
        let adopted = median_adopted_miner_work(&reports);

        for (addr, work) in &adopted {
            let honest_val = honest()
                .into_iter()
                .find(|(a, _)| a == addr)
                .map(|(_, w)| w)
                .unwrap();
            assert_eq!(
                *work, honest_val,
                "#606: {addr} must adopt the honest median, not the proposer's skew"
            );
        }
        // And the skew is detected, not merely neutralised.
        let skew = proposer_skew_permille(1_019_000, 1_000_000).unwrap();
        assert!(
            skew > SKEW_ALERT_PERMILLE,
            "a 1.9% skew ({skew} permille) must trip the {SKEW_ALERT_PERMILLE} permille alert"
        );
    }

    /// The adopted value must be byte-identical on every node, so the even-count rule cannot be
    /// left to chance. Lower median: sort ascending, take index (n-1)/2. Never an average — that
    /// reintroduces the rounding this file records as the residual that blocked finalisation.
    #[test]
    fn median_is_the_lower_median_and_is_order_independent() {
        let a = vec![("x".to_string(), 10u128)];
        let b = vec![("x".to_string(), 20u128)];
        let c = vec![("x".to_string(), 30u128)];
        let d = vec![("x".to_string(), 40u128)];

        // Even count: lower median of [10,20,30,40] is 20, NOT 25 (the average).
        let even = median_adopted_miner_work(&[a.clone(), b.clone(), c.clone(), d.clone()]);
        assert_eq!(even, vec![("x".to_string(), 20u128)]);

        // Odd count: [10,20,30] -> 20.
        let odd = median_adopted_miner_work(&[a.clone(), b.clone(), c.clone()]);
        assert_eq!(odd, vec![("x".to_string(), 20u128)]);

        // Report arrival order must not change the result — votes arrive over the network.
        let shuffled = median_adopted_miner_work(&[d, b, a, c]);
        assert_eq!(shuffled, even, "median must not depend on report order");
    }

    /// A minority report must not be able to inject a payee. Admitting an address on one voter's
    /// word would be the mirror of the hole #606 closes: influence would pass from the proposer to
    /// any single voter.
    #[test]
    fn an_address_only_a_minority_reported_is_not_adopted() {
        let honest = || vec![("real".to_string(), 100u128)];
        let liar = vec![
            ("real".to_string(), 100u128),
            ("attacker".to_string(), 999_999u128),
        ];
        let adopted = median_adopted_miner_work(&[liar, honest(), honest(), honest()]);
        assert_eq!(
            adopted,
            vec![("real".to_string(), 100u128)],
            "an address in a minority of reports must not be adopted"
        );
    }

    /// One report listing the same address twice must not get two votes toward its own median.
    #[test]
    fn a_duplicated_address_within_one_report_counts_once() {
        let dup = vec![("x".to_string(), 1000u128), ("x".to_string(), 1000u128)];
        let honest = || vec![("x".to_string(), 10u128)];
        // If the duplicate counted twice the values would be [1000,1000,10,10] -> lower median 10
        // by luck; with three honest reports it would be [1000,1000,10,10,10] -> 10 as well. Use
        // two honest reports so double-counting would visibly win: [1000,1000,10,10] -> 10 vs
        // deduped [1000,10,10] -> 10. Make it decisive with one honest report:
        let adopted = median_adopted_miner_work(&[dup, honest()]);
        // Deduped: [1000, 10] -> lower median 10. Double-counted: [1000,1000,10] -> 1000.
        assert_eq!(
            adopted,
            vec![("x".to_string(), 10u128)],
            "a repeated address inside one report must contribute a single value"
        );
    }

    /// Zero median has nothing to be relative to; the alert must not divide by it.
    #[test]
    fn skew_against_a_zero_median_is_undefined_not_a_panic() {
        assert_eq!(proposer_skew_permille(500, 0), None);
        assert_eq!(proposer_skew_permille(1000, 1000), Some(0));
    }

    #[test]
    fn voter_set_floor_only_widens_to_a_superset() {
        let id = |b: u8| -> NodeId { [b; 32] };
        let elders = vec![id(1), id(2), id(3)]; // sorted MPC floor
                                                // A new qualified joiner extends the set → widen to include it.
        let grown = vec![id(1), id(2), id(3), id(4)];
        assert_eq!(widen_voter_set(elders.clone(), grown.clone()), grown);
        // An elder missing (partition / unqualified elder) → keep the elder floor,
        // never a narrower set. BFT tolerates the absent elder within 33%.
        let narrower = vec![id(1), id(2), id(4)];
        assert_eq!(widen_voter_set(elders.clone(), narrower), elders.clone());
        // Empty active set (no convergence) → floor.
        assert_eq!(widen_voter_set(elders.clone(), vec![]), elders.clone());
        // Exactly the elders (no joiners) → the same set (a superset of itself).
        assert_eq!(widen_voter_set(elders.clone(), elders.clone()), elders);
    }

    #[tokio::test]
    async fn convergent_fleet_finalises_and_adopts_lists() {
        let payout = cp(&[
            ("bc1qaaa", 1_000_000_000_000_000),
            ("bc1qbbb", 500_000_000_000_000),
        ]);
        let nodes = build(4, &vec![Some(payout.clone()); 4]);
        assert_eq!(nodes[0].mgr.proposer_for(H, CUTOFF), Some(nodes[0].id));
        assert_eq!(
            nodes[0].mgr.voter_set_for(H, CUTOFF).len(),
            4,
            "gate off → elder floor of 4"
        );
        assert_eq!(quorum_for(4), 3, "67% of 4 = 3");
        for n in &nodes {
            n.mgr.maybe_propose(H, CUTOFF).await;
        }
        gossip_until_quiet(&nodes).await;
        for n in &nodes {
            let rec =
                n.db.get_latest_payout_ledger_checkpoint()
                    .unwrap()
                    .expect("every node finalises");
            assert_eq!(rec.ledger_root, payout.root);
            assert_eq!(rec.height, H);
            // Adopt-on-finalise: the canonical lists are persisted verbatim.
            assert_eq!(
                rec.miner_payouts, payout.miner_payouts,
                "adopted miner list"
            );
            assert_eq!(rec.node_shares.len(), 3, "adopted node list");
        }
    }

    #[tokio::test]
    async fn within_tolerance_divergence_still_finalises() {
        // THE option-(c) property: nodes DON'T have byte-identical ledgers. The proposer
        // says a miner has 1_000_000..., peers each computed a slightly different value
        // (attribution/float noise) — all within 2% — so they ADOPT the proposer's list.
        let proposer = cp(&[("bc1qaaa", 1_000_000_000_000_000)]);
        let near1 = cp(&[("bc1qaaa", 1_005_000_000_000_000)]); // +0.5%
        let near2 = cp(&[("bc1qaaa", 995_000_000_000_000)]); //  -0.5%
        let near3 = cp(&[("bc1qaaa", 1_010_000_000_000_000)]); // +1.0%
        let nodes = build(
            4,
            &[
                Some(proposer.clone()),
                Some(near1),
                Some(near2),
                Some(near3),
            ],
        );
        for n in &nodes {
            n.mgr.maybe_propose(H, CUTOFF).await;
        }
        gossip_until_quiet(&nodes).await;
        for n in &nodes {
            let rec =
                n.db.get_latest_payout_ledger_checkpoint()
                    .unwrap()
                    .expect("finalises within tolerance");
            // Every node adopted the PROPOSER's exact value — convergence by adoption.
            assert_eq!(rec.miner_payouts, proposer.miner_payouts);
        }
    }

    #[tokio::test]
    async fn gross_misallocation_outside_tolerance_rejected() {
        // Proposer + one peer agree; two peers computed a value 2x off (WAY beyond 2%).
        // Those two reject → only 2 approvals < 3 → nothing finalises (safe).
        let a = cp(&[("bc1qaaa", 1_000_000_000_000_000)]);
        let gross = cp(&[("bc1qaaa", 2_000_000_000_000_000)]);
        let nodes = build(
            4,
            &[Some(a.clone()), Some(a), Some(gross.clone()), Some(gross)],
        );
        for n in &nodes {
            n.mgr.maybe_propose(H, CUTOFF).await;
        }
        gossip_until_quiet(&nodes).await;
        for n in &nodes {
            assert!(n
                .db
                .get_latest_payout_ledger_checkpoint()
                .unwrap()
                .is_none());
        }
    }

    #[tokio::test]
    async fn c7_abstainer_does_not_block_liveness() {
        let a = cp(&[("bc1qaaa", 1_000_000_000_000_000)]);
        let nodes = build(4, &[Some(a.clone()), Some(a.clone()), Some(a), None]);
        for n in &nodes {
            n.mgr.maybe_propose(H, CUTOFF).await;
        }
        gossip_until_quiet(&nodes).await;
        for n in &nodes {
            n.db.get_latest_payout_ledger_checkpoint()
                .unwrap()
                .expect("finalises despite one abstainer");
        }
    }

    #[tokio::test]
    async fn proposal_root_not_matching_its_lists_rejected() {
        // Integrity: a proposal whose ledger_root does NOT hash its own lists is rejected
        // even from the real proposer — otherwise the signed hash wouldn't bind the payload.
        let a = cp(&[("bc1qaaa", 1_000_000_000_000_000)]);
        let nodes = build(4, &vec![Some(a.clone()); 4]);
        let proposer = nodes[0].id;
        let msg = PayoutLedgerCheckpointMessage {
            height: H,
            cutoff_ts: CUTOFF,
            ledger_root: [9u8; 32], // does NOT match the lists below
            miner_payouts: a.miner_payouts.clone(),
            node_shares: a.node_shares.clone(),
            active_node_count: 4,
            proposer,
            proposer_signature: [0u8; 64],
            timestamp: 0,
        };
        let payload = serde_json::to_vec(&msg).unwrap();
        for n in &nodes[1..] {
            let env = Arc::new(MessageEnvelope::new(
                MessageType::PayoutLedgerCheckpoint,
                proposer,
                payload.clone(),
                0,
                [0u8; 64],
            ));
            n.mgr.handle_message(env).await.unwrap();
        }
        gossip_until_quiet(&nodes).await;
        for n in &nodes {
            assert!(n
                .db
                .get_latest_payout_ledger_checkpoint()
                .unwrap()
                .is_none());
        }
    }

    /// A finalised checkpoint record for `H`, authored by the deterministic proposer.
    fn finalised_record(nodes: &[Node], p: &CanonicalPayout) -> PayoutLedgerCheckpointRecord {
        PayoutLedgerCheckpointRecord {
            height: H,
            cutoff_ts: CUTOFF,
            ledger_root: p.root,
            proposer_id: hex::encode(nodes[(H as usize) % nodes.len()].id),
            active_node_count: nodes.len() as u32,
            miner_payouts: p.miner_payouts.clone(),
            node_shares: p.node_shares.clone(),
        }
    }

    #[tokio::test]
    async fn backfill_recovers_a_missed_checkpoint() {
        // Nodes 0-2 finalised H; node 3 MISSED the once-only proposal (a hole). Its
        // cadence backfill request pulls H from a peer and it adopts it TRUSTLESSLY.
        let payout = cp(&[("bc1qaaa", 1_000_000_000_000_000)]);
        let nodes = build(4, &vec![Some(payout.clone()); 4]);
        let rec = finalised_record(&nodes, &payout);
        for n in &nodes[..3] {
            n.db.upsert_payout_ledger_checkpoint(&rec).unwrap();
        }
        assert!(nodes[3]
            .db
            .get_latest_payout_ledger_checkpoint()
            .unwrap()
            .is_none());

        nodes[3].mgr.maybe_request_backfill(H);
        gossip_until_quiet(&nodes).await;

        let got = nodes[3]
            .db
            .get_latest_payout_ledger_checkpoint()
            .unwrap()
            .expect("node 3 backfilled the hole");
        assert_eq!(got.height, H);
        assert_eq!(got.ledger_root, payout.root);
        assert_eq!(
            got.miner_payouts, payout.miner_payouts,
            "adopted exact lists"
        );
    }

    #[tokio::test]
    async fn synced_checkpoint_outside_tolerance_is_rejected() {
        // A peer serves an integrity-valid, correctly-authored checkpoint whose payout
        // is 2x off. Trustless apply recomputes locally and rejects it — no blind trust.
        let good = cp(&[("bc1qaaa", 1_000_000_000_000_000)]);
        let nodes = build(4, &vec![Some(good); 4]);
        let gross_miners = vec![("bc1qaaa".to_string(), 2_000_000_000_000_000u128)];
        let gross_nodes = node_set();
        let gross_root = crate::payout::compute_ledger_root(&gross_miners, &gross_nodes, CUTOFF, H);
        let entry = PayoutCheckpointSyncEntry {
            height: H,
            cutoff_ts: CUTOFF,
            ledger_root: gross_root,
            miner_payouts: gross_miners,
            node_shares: gross_nodes,
            active_node_count: 4,
            proposer: nodes[(H as usize) % 4].id,
        };
        assert!(
            !nodes[3].mgr.apply_synced_checkpoint(&entry).await,
            "outside tolerance → rejected"
        );
        assert!(nodes[3]
            .db
            .get_latest_payout_ledger_checkpoint()
            .unwrap()
            .is_none());

        // Correct lists but WRONG proposer (not the deterministic proposer for H) → rejected.
        let mut bad_author = entry.clone();
        bad_author.miner_payouts = vec![("bc1qaaa".to_string(), 1_000_000_000_000_000)];
        bad_author.ledger_root = crate::payout::compute_ledger_root(
            &bad_author.miner_payouts,
            &bad_author.node_shares,
            CUTOFF,
            H,
        );
        bad_author.proposer = nodes[((H as usize) + 1) % 4].id;
        assert!(
            !nodes[3].mgr.apply_synced_checkpoint(&bad_author).await,
            "wrong proposer → rejected"
        );
    }

    #[tokio::test]
    async fn backfill_request_fires_only_when_behind() {
        let payout = cp(&[("bc1qaaa", 1_000_000_000_000_000)]);
        let nodes = build(4, &vec![Some(payout.clone()); 4]);
        let n = &nodes[3];

        // Behind the anchor (no checkpoints yet) → a sync request is broadcast.
        n.mgr.maybe_request_backfill(H);
        assert!(
            drain(n)
                .iter()
                .any(|(ty, _)| *ty == MessageType::PayoutLedgerCheckpointSync),
            "behind → backfill request"
        );

        // Caught up (finalised H) → request for anchor H is a no-op (latest >= target).
        n.db.upsert_payout_ledger_checkpoint(&finalised_record(&nodes, &payout))
            .unwrap();
        *n.mgr.last_sync_request.write() = 0; // clear cooldown so silence is the real reason
        n.mgr.maybe_request_backfill(H);
        assert!(drain(n).is_empty(), "caught up → no request");
    }
}
