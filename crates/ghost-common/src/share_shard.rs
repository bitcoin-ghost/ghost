//! Share shard: the network shard's deterministic core.
//!
//! The shard replaces "store every share forever and scan them" with a balance table small enough
//! to ship whole (§4.3 of `SHARE_SHARD.md`). Everything here is a pure function of its inputs —
//! nothing reads a clock, a database, or the network — and the encodings are pinned by golden
//! vectors, exactly as `share_batch.rs` does for the fold it shares with this module.
//!
//! The state is **two quantities, both grow-only** (§4.4):
//!
//! ```text
//!    accrued[node][addr]   grow-only · gossiped · merged per-cell by max
//!    settled[addr]         grow-only · derived from the chain · never gossiped
//!
//!    owed[addr]  =  Σ accrued[·][addr]  −  settled[addr]
//! ```
//!
//! ⚠ They must stay two quantities. A single counter that the rebase subtracts from is
//! inconsistent with max-merge: a node that slept through a settlement re-advertises its
//! pre-settlement value, the max resurrects it, and the address is paid twice. Splitting into two
//! monotone quantities removes that failure by construction — a stale `accrued` simply loses the
//! max, and `settled` never crosses the mesh at all, so there is nothing stale to resurrect.
//!
//! `owed` is **signed and never clamped at zero**. A node that overpays relative to another's view
//! leaves a negative residual which then accrues back up; clamping destroys exactly that
//! correction.
//!
//! Dark code: nothing wires this into a runtime path yet.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::identity::{verify_signature, NodeIdentity};
use crate::share_batch::{canonical_sort, creditable_difficulty, fold_shares};
use crate::types::{NodeId, ShareProof};

/// Domain tag for the table commitment. Bump the version on ANY encoding change — a root computed
/// under a different encoding is not comparable, and a silent change would split the fleet rather
/// than fail loudly.
const TABLE_ROOT_DOMAIN: &[u8] = b"ShardTableRoot/v1";

/// Domain tag for epoch-summary signing bytes. Same versioning rule as the table root.
const EPOCH_SUMMARY_DOMAIN: &[u8] = b"ShardEpochSummary/v1";

/// How many blocks an epoch spans. Operator decision 2026-08-13.
///
/// Six blocks is roughly an hour on this chain, which sets how often work lands in the ledger —
/// the only one of these numbers anybody actually feels. Shorter epochs mean more summary traffic
/// for fresher balances; longer means chunkier movement.
pub const EPOCH_BLOCKS: NonZeroU64 = NonZeroU64::new(6).expect("6 is not zero");

/// How many epochs a node keeps raw shares so peers can sample its claims. Operator decision.
///
/// This is squeezed from both sides. Too short and a peer asks for evidence that has already been
/// dropped — and because that is indistinguishable on the wire from refusing to be audited, an
/// honest node gets accused for following the rules. Too long and we are hoarding shares again,
/// which is the whole defect this design exists to delete.
///
/// Six epochs is ~6 hours, ~9 MB of shares at current rates, against the 1.7M rows the old ledger
/// carries. There is room to be generous here and it is the right direction to err: over-retaining
/// costs megabytes, under-retaining costs a false accusation.
///
/// ⚠ **Invariant: this must exceed the sampling window with margin**, so anything an honest
/// requester could reasonably ask for is still held. Pinned by test below.
pub const RETENTION_EPOCHS: u64 = 6;

/// How long after publication a summary is still actively being sampled: one epoch for it to
/// propagate and be sampled, one more for the follow-up requests a subset response forces.
///
/// Named rather than left implicit so the retention invariant is something a test can state.
/// Raising this without raising [`RETENTION_EPOCHS`] is the mistake it exists to catch.
pub const SAMPLING_WINDOW_EPOCHS: u64 = 2;

/// The retention invariant, enforced by the compiler rather than by a test run.
///
/// A relationship between two constants cannot be got wrong at runtime, so it should not be
/// possible to *build* it wrong either. The failure this prevents is asymmetric: over-retaining
/// costs megabytes, while under-retaining makes an honest node that correctly dropped expired
/// evidence indistinguishable on the wire from one refusing to be audited — so it gets accused for
/// following the rules. Doubling is the margin: a peer must be able to sample, hit a subset
/// response, and come back, with the evidence still there.
const _: () = assert!(
    RETENTION_EPOCHS >= SAMPLING_WINDOW_EPOCHS * 2,
    "RETENTION_EPOCHS must be at least twice SAMPLING_WINDOW_EPOCHS"
);

/// The tier floor a share must have committed to before its work crosses the mesh.
///
/// Stage 2 ships **R = 1**: defined as the vardiff floor, so every share that exists today is
/// network tier and behaviour is byte-for-byte what it is now. Raising R later is a coordinated
/// roll of this one constant, and it divides mesh traffic, verification compute and memory by R
/// simultaneously.
///
/// Defined in terms of `MIN_DIFFICULTY_TIER_LOG2` rather than repeating its value, because the
/// coupling to the vardiff floor is real and was previously documented but unenforced — a floor
/// that moved without this moving would silently drop every share between the two.
///
/// Baked into the binary, NEVER read from local config. A node-local value in an eligibility test
/// is exactly how M-6 split the fleet: validity must be a pure function of the share (§12.1).
pub const NETWORK_TIER_LOG2: u32 = crate::coinbase_tags::MIN_DIFFICULTY_TIER_LOG2;

/// Whether a share crosses the mesh under the network-tier rule.
///
/// ⚠ **A share with no tier is NOT refused.** `tier_log2` is `None` only for shares mined before
/// the tier gate, and a share must be judged by the rules of the era it was mined in — the lesson
/// that cost four days and a fleet-wide quarantine when a height-derived predicate was applied to
/// shares of every era at once. Refusing them here would be M-6 all over again: a receive-side
/// check rejecting what a peer legitimately sent, deterministically, for ever, which no amount of
/// retransmission can fix.
///
/// Pre-gate shares are excluded from the shard by a different route — the fold's input query
/// requires a tier — so letting them cross the mesh costs nothing and keeps the legacy ledger
/// whole.
///
/// One spelling, called by the send side and the receive side both. Two copies of a gossip
/// predicate that disagree is a partition that looks like a bug in something else.
pub fn crosses_network_tier(tier_log2: Option<u32>) -> bool {
    match tier_log2 {
        Some(tier) => tier >= NETWORK_TIER_LOG2,
        None => true,
    }
}

/// What a miner-pool distribution came to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MinerPayouts {
    /// `(payout address, satoshis)`, in the order the coinbase should carry them.
    pub payouts: Vec<(String, u64)>,
    /// Satoshis that fell below the dust threshold. These are NOT lost — the existing coinbase
    /// builder rolls miner dust into the node reward pool, and that behaviour is preserved.
    pub dust_sats: u64,
    /// Floor-division leftover. Tracked rather than discarded so a caller can assert that every
    /// satoshi is accounted for; silently dropping it is how a pool leaks money slowly.
    pub remainder_sats: u64,
}

/// Distribute a miner pool over the shard's owed balances.
///
/// This deliberately mirrors the live `calculate_miner_payouts` **exactly** — same descending
/// sort with an ascending tie-break, same truncation before the total is recomputed, same floor
/// division, same dust rule. It has to: this function exists first to be *compared* against the
/// live path, and any arithmetic difference would make every shadow diff non-zero for reasons that
/// have nothing to do with drift, which would make the soak signal worthless.
///
/// One intended difference: the shard is keyed on **payout address**, where the live path keys on
/// miner id and resolves an address afterwards. Two miners paying to one address are one row here.
/// That is the address grouping the design wants, not a discrepancy.
///
/// Balances that are zero or **negative** take no part. A negative `owed` means that address has
/// been overpaid relative to this node's view (§4.4) and is working the debt off; paying it again
/// would be paying twice for the same work.
///
/// Integer arithmetic throughout, in `u128`, because this decides who gets paid what and a float
/// would make the answer depend on the order the additions happened to be done in.
pub fn shard_miner_payouts(
    owed: &BTreeMap<String, i64>,
    pool_sats: u64,
    max_outputs: usize,
    dust_threshold_sats: u64,
) -> MinerPayouts {
    let mut out = MinerPayouts::default();

    let mut positive: Vec<(&String, u128)> = owed
        .iter()
        .filter(|(_, &micro)| micro > 0)
        .map(|(addr, &micro)| (addr, micro as u128))
        .collect();
    if positive.is_empty() || pool_sats == 0 {
        out.remainder_sats = pool_sats;
        return out;
    }

    // Descending by owed, ascending by address on a tie.
    //
    // ⚠ The tie-break is LATENT, not load-bearing, and no test can kill it today: the input is a
    // `BTreeMap`, so it already arrives address-ascending, and a stable sort preserves that even
    // without the `then_with`. It is defence against the input type changing to something
    // unordered — a `Vec` or a `HashMap` — at which point the result would start depending on the
    // caller's iteration order and two nodes with identical balances could build different
    // coinbases. The live path carries the same latency, documented there as M-8.
    positive.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    positive.truncate(max_outputs);

    // Recomputed AFTER truncation, exactly as the live path does — the pool is shared among those
    // actually paid, not diluted by addresses that did not make the cut.
    let top: u128 = positive.iter().map(|(_, w)| *w).sum();
    if top == 0 {
        out.remainder_sats = pool_sats;
        return out;
    }

    let mut allocated: u64 = 0;
    for (addr, work) in positive {
        let amount = ((pool_sats as u128 * work) / top) as u64;
        allocated = allocated.saturating_add(amount);
        if amount < dust_threshold_sats {
            out.dust_sats = out.dust_sats.saturating_add(amount);
            continue;
        }
        out.payouts.push((addr.clone(), amount));
    }
    out.remainder_sats = pool_sats.saturating_sub(allocated);
    out
}

/// Convert satoshis a matured coinbase actually paid into the micro-work they discharge.
///
/// `accrued` and `settled` are micro-work; a coinbase pays satoshis. Discharging a payment means
/// converting at the rate the payment was computed under: the miner pool was shared out in
/// proportion to owed work, so `sats : pool_sats` is the same ratio as `discharged : top_work`.
///
/// ⚠ **`top_work` is the paying node's own view**, so two nodes whose tables differ by gossip lag
/// discharge slightly different amounts for the same block. That is deterministic-given-a-table,
/// not identical-across-nodes, and §4.6 previously overclaimed it. It is safe because [`owed`] is
/// signed and never clamped: discharge too much and the residual goes negative and accrues back
/// up; too little and the next block pays it. The differences wash out exactly as payment
/// differences do.
///
/// Returns 0 when the pool is empty — a block that paid miners nothing discharges nothing, rather
/// than dividing by zero or silently discharging everything.
///
/// [`owed`]: ShardTable::owed
pub fn discharged_micro_work(paid_sats: u64, pool_sats: u64, top_work: i64) -> i64 {
    if pool_sats == 0 || top_work <= 0 || paid_sats == 0 {
        return 0;
    }
    // u128 throughout: top_work is micro-work across the whole pool and paid_sats is satoshis, so
    // the product overflows u64 long before either value is unreasonable.
    let discharged = (paid_sats as u128).saturating_mul(top_work as u128) / pool_sats as u128;
    discharged.min(i64::MAX as u128) as i64
}

/// Which epoch a block height falls in.
///
/// Height-keyed and nothing else (§12.2). The previous design keyed windows to each node's local
/// clock, which made summaries incomparable *in principle* — two nodes looking at the same chain
/// must name the same epoch, and only a function of height alone cannot do otherwise. The length
/// stays a parameter rather than reading [`EPOCH_BLOCKS`] directly so tests can drive small
/// epochs; `NonZeroU64` because a zero-block epoch is not a smaller choice, it is a meaningless
/// one, and the type refuses it where a runtime check could be skipped.
pub fn epoch_for_height(height: u64, epoch_blocks: NonZeroU64) -> u64 {
    height / epoch_blocks.get()
}

/// The Merkle tree used over an epoch's network-tier share hashes, taken by injection.
///
/// The tree that MUST be injected is `ghost_reconciliation::compute_merkle_root` — the only tree
/// in the workspace with membership proofs (single SHA-256, leaf-count-bound, odd leaves carried
/// forward; **never** Bitcoin's sha256d construction). It cannot be imported here:
/// `ghost-reconciliation` depends on this crate, so the dependency would be a cycle. Callers pass
/// it in instead, and the cross-crate golden vector in this module's tests pins the tree's
/// encoding so the two crates cannot drift apart silently.
pub type MerkleRootFn = fn(&[[u8; 32]]) -> [u8; 32];

/// Why a summary was refused.
///
/// Refusal happens BEFORE any counter moves (§12.3): max-merging an unverified counter lets a
/// liar's inflated number win, and a max cannot be undone — so the ordering in
/// [`ShardTable::apply_summary`] is load-bearing, and a rejected summary must leave the table
/// byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SummaryRejection {
    /// The signature does not verify against `node_id` — which IS the ed25519 pubkey, so there is
    /// no key-distribution step whose absence this could be confused with.
    #[error("signature does not verify against the summary's node_id")]
    BadSignature,
    /// A delta is negative, or a total is smaller than the delta it claims to include.
    #[error("summary is structurally malformed: a delta is negative or exceeds its total")]
    MalformedDeltas,
    /// The evidence share count differs from the signed `share_count`.
    #[error("evidence count differs from the summary's share_count")]
    EvidenceCountMismatch,
    /// The evidence repeats a share hash — folding it would double-credit the work.
    #[error("evidence contains a duplicated share hash")]
    DuplicateEvidence,
    /// A share in the evidence has no payout address, so its work is attributable to nobody.
    #[error("evidence contains a share with no payout address")]
    UnattributedEvidence,
    /// A share's difficulty fails [`creditable_difficulty`] — non-finite, non-positive, or large
    /// enough to saturate the fold.
    #[error("evidence contains a share whose difficulty is not creditable")]
    NonCreditableEvidence,
    /// The Merkle root over the evidence does not match the signed `share_root`.
    #[error("merkle root over the evidence does not match the summary's share_root")]
    RootMismatch,
    /// The evidence folds to different per-address deltas than the summary declares. Exact
    /// equality — a tolerance here would be an admission the mechanism cannot converge (§12.5).
    #[error("per-address deltas do not match the evidence fold")]
    DeltaMismatch,
    /// The summary is for an epoch below the pre-genesis floor.
    ///
    /// Not a fault: the work it carries is already in the genesis column, so merging it would
    /// double-count. Expected during the rolling cutover, from peers not yet armed.
    #[error("summary is for a pre-genesis epoch, below the arming floor")]
    PreGenesisEpoch,
    /// The summary was produced under a different genesis than ours — one side is not armed.
    ///
    /// Not misbehaviour, and expected throughout the rolling cutover. Refusing matters because
    /// `total_micro` is cumulative: an unarmed peer's total spans pre-genesis work, which the
    /// epoch floor cannot catch once the epoch itself is at or above the floor.
    #[error("summary was produced under a different genesis — one side is not yet armed")]
    GenesisMismatch,
    /// The summary claims [`GENESIS_NODE_ID`], the reserved opening-balance column.
    ///
    /// Checked before the signature, because the point is that no signature should make this
    /// admissible: the genesis column is written once locally at the Stage 5 ceremony from a
    /// compile-time pin and is never a thing a peer tells you.
    #[error("summary claims the reserved genesis column, which no peer may write")]
    ReservedColumn,
}

/// One address row of an epoch summary.
///
/// `delta_micro` is what this epoch's evidence backs — it is checked against the fold of the
/// shares under `share_root`. `total_micro` is the node's cumulative `accrued` for the address
/// after this epoch, and is the quantity a receiver max-merges. Carrying both is what makes the
/// summary channel a CRDT: deltas alone cannot be max-merged, and applying them additively would
/// need exactly-once delivery — which gossip does not provide — while a cumulative total makes
/// duplicate, stale and out-of-order delivery all harmless (a later epoch's total already
/// includes every earlier delta, so a missed epoch leaves nothing behind).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochDelta {
    /// Micro-work accrued in this epoch, backed by the evidence under `share_root`.
    pub delta_micro: i64,
    /// Cumulative accrued micro-work after this epoch — the max-merged quantity.
    pub total_micro: i64,
}

/// A node's signed per-epoch statement of what its column accrued and why.
///
/// This is the only way a remote node's counter enters the table: verified first, max-merged
/// second (§12.3). The shares themselves never travel with it — the `share_root` commits to them
/// so that §6's sampling can audit any epoch after the fact via
/// `ghost_reconciliation::verify_merkle_proof` against `share_root` and `share_count`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochSummary {
    /// Epoch index, derived from block height via [`epoch_for_height`] — never from wall-clock
    /// time (§12.2).
    pub epoch: u64,
    /// The summarising node. This IS its ed25519 verifying key, so verification needs no key
    /// distribution.
    pub node_id: NodeId,
    /// Per-address rows, keyed by payout address. `BTreeMap` so iteration — and therefore the
    /// signing bytes — is address-ascending on every node.
    pub deltas: BTreeMap<String, EpochDelta>,
    /// How many network-tier shares back this epoch. Signed so a sampling verifier knows the leaf
    /// count the proofs must be checked against — the tree binds it, and so does the signature.
    pub share_count: u32,
    /// Merkle root over the epoch's network-tier share hashes, in canonical share order.
    #[serde(with = "crate::serde_hex::bytes32")]
    pub share_root: [u8; 32],
    /// Which genesis this node is running, or `None` if it has not been armed.
    ///
    /// ⚠ This closes a hole the epoch floor could not. The floor rejects epochs *below* it, but
    /// `total_micro` is **cumulative** by design (§6 — it must be, or deltas could not be
    /// max-merged), so a summary at an epoch at or *above* the floor from a not-yet-armed node
    /// still carries pre-genesis work. An armed node max-merging that total credits pre-genesis
    /// work a second time on top of the genesis column, and because merge is a max it is
    /// permanent. Comparing markers refuses that summary outright.
    ///
    /// The value is the table root of the genesis column alone — the same quantity the ceremony
    /// pins and `verify_loaded_genesis` checks, so armed nodes agree on it by construction and
    /// there is no new thing to keep in sync.
    ///
    /// `serde(default)` so a summary written before this field existed decodes as `None`, which is
    /// exactly what an unarmed node means.
    #[serde(default)]
    pub genesis_marker: Option<[u8; 32]>,
    /// ed25519 signature by `node_id` over [`EpochSummary::signing_bytes`].
    pub signature: Vec<u8>,
}

impl EpochSummary {
    /// Build and sign this node's summary for an epoch.
    ///
    /// `prior_column` is the node's OWN column before this epoch — each node writes only its own
    /// column (§4.4), so the totals are `prior + delta` and nothing else. The evidence is screened
    /// with the same checks [`EpochSummary::verify`] applies, so a node can never sign a summary
    /// its peers would refuse: one spelling of the predicate on both sides.
    /// `genesis_marker` is this node's [`ShardTable::genesis_marker`] — `None` until armed.
    pub fn build(
        epoch: u64,
        identity: &NodeIdentity,
        prior_column: &BTreeMap<String, i64>,
        evidence: &[ShareProof],
        merkle_root: MerkleRootFn,
        genesis_marker: Option<[u8; 32]>,
    ) -> Result<Self, SummaryRejection> {
        let screened = check_evidence(evidence)?;

        let mut deltas = BTreeMap::new();
        for (addr, delta) in screened.folded {
            let prior = prior_column.get(&addr).copied().unwrap_or(0);
            deltas.insert(
                addr,
                EpochDelta {
                    delta_micro: delta,
                    total_micro: prior.saturating_add(delta),
                },
            );
        }

        let mut summary = EpochSummary {
            epoch,
            node_id: identity.node_id(),
            deltas,
            share_count: screened.hashes.len() as u32,
            share_root: merkle_root(&screened.hashes),
            genesis_marker,
            signature: Vec::new(),
        };
        summary.signature = identity.sign(&summary.signing_bytes()).to_vec();
        Ok(summary)
    }

    /// Canonical bytes the signature covers: domain tag, then every field length-prefixed, in a
    /// fixed order — the `compute_state_root` discipline, so no two distinct summaries can
    /// serialise to the same bytes by running fields together. The signature itself is excluded
    /// because it is *over* these bytes; including it would be circular.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(EPOCH_SUMMARY_DOMAIN);
        m.extend_from_slice(&self.epoch.to_le_bytes());
        m.extend_from_slice(&self.node_id);
        m.extend_from_slice(&(self.deltas.len() as u32).to_le_bytes());
        for (addr, row) in &self.deltas {
            m.extend_from_slice(&(addr.len() as u32).to_le_bytes());
            m.extend_from_slice(addr.as_bytes());
            m.extend_from_slice(&row.delta_micro.to_le_bytes());
            m.extend_from_slice(&row.total_micro.to_le_bytes());
        }
        m.extend_from_slice(&self.share_count.to_le_bytes());
        m.extend_from_slice(&self.share_root);
        // Appended ONLY when armed, and that asymmetry is deliberate rather than lazy.
        //
        // An unarmed node's signing bytes are byte-identical to what every binary produced before
        // this field existed, so its summaries stay verifiable by any peer — which is what makes
        // the armed/unarmed window of the rolling cutover survivable. An armed node's bytes differ,
        // and only armed peers need to verify those: by arming time the whole fleet is on this
        // binary, because Stage 4 deploys and Stage 5 merely flips config.
        //
        // Covered by the signature rather than left bare: an unsigned marker could be stripped by
        // anyone on the wire, turning an armed node's summary back into one an armed peer accepts.
        if let Some(marker) = &self.genesis_marker {
            m.extend_from_slice(marker);
        }
        m
    }

    /// Verify this summary against its evidence. Nothing is mutated here — this is the gate
    /// [`ShardTable::apply_summary`] runs before it touches a counter.
    ///
    /// Order: structure, signature, then evidence. The structural check is first because a
    /// malformed summary is malformed regardless of who signed it; the signature is checked before
    /// the evidence because an unsigned claim does not earn the fold's compute.
    /// The half of verification that needs no shares: structure, then signature.
    ///
    /// This exists as its own function because a *gossiped* summary carries no evidence — peers
    /// receive summaries, not shares — so the mesh handler has to make exactly these two checks and
    /// nothing more. Spelling them twice is how two copies of one predicate drift apart, silently,
    /// with the weaker copy deciding what gets merged. One spelling, two callers.
    ///
    /// Structure is checked before the signature deliberately: malformed is malformed no matter who
    /// signed it, and it is the cheaper test.
    pub fn verify_stateless(&self) -> Result<(), SummaryRejection> {
        // Before the signature, deliberately: no signature should make the reserved genesis
        // column admissible, and checking it first says so rather than implying it.
        if self.node_id == GENESIS_NODE_ID {
            return Err(SummaryRejection::ReservedColumn);
        }
        for row in self.deltas.values() {
            if row.delta_micro < 0 || row.total_micro < row.delta_micro {
                return Err(SummaryRejection::MalformedDeltas);
            }
        }

        let sig: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| SummaryRejection::BadSignature)?;
        if !verify_signature(&self.node_id, &self.signing_bytes(), &sig).unwrap_or(false) {
            return Err(SummaryRejection::BadSignature);
        }

        Ok(())
    }

    pub fn verify(
        &self,
        evidence: &[ShareProof],
        merkle_root: MerkleRootFn,
    ) -> Result<(), SummaryRejection> {
        self.verify_stateless()?;

        if evidence.len() != self.share_count as usize {
            return Err(SummaryRejection::EvidenceCountMismatch);
        }
        let screened = check_evidence(evidence)?;
        if merkle_root(&screened.hashes) != self.share_root {
            return Err(SummaryRejection::RootMismatch);
        }

        let declared: BTreeMap<&String, i64> = self
            .deltas
            .iter()
            .map(|(addr, row)| (addr, row.delta_micro))
            .collect();
        let folded: BTreeMap<&String, i64> =
            screened.folded.iter().map(|(addr, &v)| (addr, v)).collect();
        if declared != folded {
            return Err(SummaryRejection::DeltaMismatch);
        }
        Ok(())
    }
}

/// An epoch's evidence, screened and reduced to the two things a summary is checked against.
struct ScreenedEvidence {
    /// Share hashes in canonical share order — the Merkle root covers an order, and both sides
    /// must derive the same one regardless of arrival order.
    hashes: Vec<[u8; 32]>,
    /// The per-address fold of the evidence, in micro-work.
    folded: BTreeMap<String, i64>,
}

/// Screen an epoch's evidence and reduce it to canonical hashes plus a per-address fold.
///
/// Shared by [`EpochSummary::build`] and [`EpochSummary::verify`] so the two sides can never
/// disagree about what legal evidence is.
fn check_evidence(evidence: &[ShareProof]) -> Result<ScreenedEvidence, SummaryRejection> {
    let mut ordered = evidence.to_vec();
    canonical_sort(&mut ordered);

    for share in &ordered {
        if !creditable_difficulty(share.difficulty) {
            return Err(SummaryRejection::NonCreditableEvidence);
        }
    }

    let hashes: Vec<[u8; 32]> = ordered.iter().map(|s| s.share_hash).collect();
    let mut unique = hashes.clone();
    unique.sort();
    if unique.windows(2).any(|w| w[0] == w[1]) {
        return Err(SummaryRejection::DuplicateEvidence);
    }

    let mut folded = BTreeMap::new();
    let outcome = fold_shares(&mut folded, &ordered);
    if outcome.unattributed != 0 {
        return Err(SummaryRejection::UnattributedEvidence);
    }
    Ok(ScreenedEvidence { hashes, folded })
}

/// Per-node accrued columns: `accrued[node][address]` in micro-work. Cells are strictly positive
/// by construction — a zero is represented by absence, so content-equal tables are always
/// byte-equal and the table root cannot be split by an explicit-zero-versus-absent accident.
pub type AccruedColumns = BTreeMap<NodeId, BTreeMap<String, i64>>;

/// The reserved column holding the opening balances converted from the genesis checkpoint.
///
/// Every node writes the IDENTICAL opening balances here, rather than each into its own column,
/// because [`ShardTable::owed`] sums across columns: a per-node genesis column would make every
/// miner's opening balance `fleet_size` times too large the moment two tables merged, and it would
/// look healthy on any single node until then.
///
/// ⚠ **The all-zero id is reserved by enforcement, not by cryptography.** An earlier version of
/// this reasoned that all-zero bytes are not a valid ed25519 public key and therefore unsignable;
/// that is **false** — `ed25519_dalek::VerifyingKey::from_bytes([0u8; 32])` succeeds, it is a
/// low-order point. So the guarantee is made structurally instead: [`ShardTable::merge_accrued`]
/// skips this column and [`EpochSummary::verify_stateless`] refuses a summary claiming it, so the
/// only writer is [`ShardTable::install_genesis`], which no network path calls. Left to a key
/// property that does not hold, a peer could have max-merged an inflated opening balance that is
/// indistinguishable from genesis and, being a max, permanent.
pub const GENESIS_NODE_ID: NodeId = [0u8; 32];

/// The network shard: the payable state of the pool, small enough to ship whole (§12.6).
///
/// Invariants, enforced by every mutating method:
///
/// - `accrued` cells only grow — locally by addition, remotely by per-cell max. Each node writes
///   only its own column; remote columns arrive exclusively through the verified paths.
/// - `settled` only grows, and is never merged from a peer: every node reads it off the chain it
///   already holds and derives the identical value with no coordination.
/// - Nothing in merged state ever decreases, which is what makes merge idempotent, commutative
///   and associative — out-of-order and duplicate delivery are irrelevant, and a missing message
///   makes a node behind, never wrong.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShardTable {
    accrued: AccruedColumns,
    settled: BTreeMap<String, i64>,
    /// Epochs strictly below this are pre-genesis and are refused (0 = no floor, the pre-ceremony
    /// state and every start until arming).
    ///
    /// Set at arming from the pinned anchor's height, so it is chain-derived and identical on
    /// every node with nothing negotiated. It exists because the Stage 4 soak accrues each node's
    /// own work into its own column *before* the ceremony, and genesis then credits that same work
    /// again for the whole fleet — so without a floor the overlap is counted twice, and resetting
    /// the column cannot fix it because a not-yet-armed peer re-advertises the higher value and
    /// wins the max.
    ///
    /// Refusing these epochs does not break "a missing message makes you behind, never wrong":
    /// they are pre-genesis, so everything they carry is already in the genesis column.
    epoch_floor: u64,
}

impl ShardTable {
    /// An empty shard.
    pub fn new() -> Self {
        Self::default()
    }

    /// The accrued columns, read-only. Mutation goes through the verified paths only.
    pub fn accrued(&self) -> &AccruedColumns {
        &self.accrued
    }

    /// The settled balances, read-only.
    pub fn settled(&self) -> &BTreeMap<String, i64> {
        &self.settled
    }

    /// Credit micro-work to `(node, address)` — the local-ingest entry point.
    ///
    /// The caller passes its OWN node id: each node writes only its own column (§4.4), and gossip
    /// never lands here — remote columns arrive via [`ShardTable::apply_summary`] and
    /// [`ShardTable::merge_accrued`], where they are max-merged rather than added, because adding
    /// a re-delivered value is double-counting. Non-positive deltas are ignored: the column is
    /// grow-only and there is no legitimate caller of a decrement.
    pub fn accrue(&mut self, node: NodeId, address: &str, delta_micro: i64) {
        if delta_micro <= 0 {
            return;
        }
        let cell = self
            .accrued
            .entry(node)
            .or_default()
            .entry(address.to_string())
            .or_insert(0);
        *cell = cell.saturating_add(delta_micro);
    }

    /// Record an amount the chain actually paid to `address`.
    ///
    /// Grow-only and chain-derived: the caller reads paid amounts off a matured coinbase (§4.6)
    /// and adds them here. This must NEVER subtract from `accrued` — that is the single-counter
    /// model, and it double-pays the moment a node that slept through the settlement re-advertises
    /// its pre-settlement column (§4.4's worked example).
    pub fn record_settled(&mut self, address: &str, paid_micro: i64) {
        if paid_micro <= 0 {
            return;
        }
        let cell = self.settled.entry(address.to_string()).or_insert(0);
        *cell = cell.saturating_add(paid_micro);
    }

    /// What each address is owed: `Σ accrued[·][addr] − settled[addr]`.
    ///
    /// **Signed, never clamped at zero.** A node that overpays relative to this table's view
    /// leaves a negative residual, and the miner accrues back up from there — clamping would
    /// destroy exactly the correction that makes independent payout views converge (§4.4).
    /// Addresses that appear only in `settled` are included, negative, for the same reason.
    pub fn owed(&self) -> BTreeMap<String, i64> {
        let mut owed: BTreeMap<String, i64> = BTreeMap::new();
        for column in self.accrued.values() {
            for (addr, &value) in column {
                let entry = owed.entry(addr.clone()).or_insert(0);
                *entry = entry.saturating_add(value);
            }
        }
        for (addr, &paid) in &self.settled {
            let entry = owed.entry(addr.clone()).or_insert(0);
            *entry = entry.saturating_sub(paid);
        }
        owed
    }

    /// The pre-genesis epoch floor. Zero means unarmed: every epoch is acceptable.
    pub fn epoch_floor(&self) -> u64 {
        self.epoch_floor
    }

    /// Arm the floor. Derived from the pinned anchor height, never from a peer or a clock.
    pub fn set_epoch_floor(&mut self, floor: u64) {
        self.epoch_floor = floor;
    }

    /// Merge a summary's totals into its node's column — the gossip path, floor enforced.
    ///
    /// The caller has already verified structure, signature and the node's own summary chain; what
    /// is left is "does this epoch belong to the ledger we are now running". Kept here rather than
    /// spelled in the handler so the floor cannot be bypassed by a second call site, which is how
    /// two spellings of one predicate start.
    ///
    /// Zero totals are skipped: absence IS zero in the canonical form, and merging one could only
    /// create a dead cell that splits the table root.
    pub fn merge_verified_summary(
        &mut self,
        summary: &EpochSummary,
    ) -> Result<(), SummaryRejection> {
        if summary.epoch < self.epoch_floor {
            return Err(SummaryRejection::PreGenesisEpoch);
        }
        if summary.genesis_marker != self.genesis_marker() {
            return Err(SummaryRejection::GenesisMismatch);
        }
        let column: BTreeMap<String, i64> = summary
            .deltas
            .iter()
            .filter(|(_, row)| row.total_micro > 0)
            .map(|(addr, row)| (addr.clone(), row.total_micro))
            .collect();
        let mut one = AccruedColumns::new();
        one.insert(summary.node_id, column);
        self.merge_accrued(&one);
        Ok(())
    }

    /// Which genesis this table was opened from — `None` if it has not been armed.
    ///
    /// The root of the genesis column *alone*, so it is stable against everything else the table
    /// accrues afterwards. Armed nodes converted identical bytes, so they agree on it by
    /// construction, and it is the same quantity the ceremony pins — one value, three uses
    /// (the pin, the load-time self-check, and the marker peers compare).
    pub fn genesis_marker(&self) -> Option<[u8; 32]> {
        let column = self.accrued.get(&GENESIS_NODE_ID)?;
        let mut probe = ShardTable::new();
        probe.install_genesis(column.clone());
        Some(probe.compute_table_root())
    }

    /// Whether a peer's table was opened from the same genesis as ours.
    ///
    /// A whole-table sync carries no epoch, so the floor cannot gate it — and it is the path that
    /// would actually resurrect a not-yet-armed peer's pre-genesis column during the rolling
    /// cutover. The genesis column itself is the generation marker: identical on every armed node
    /// by construction, absent on every unarmed one, and already in the payload, so this needs no
    /// new protocol field.
    ///
    /// Both-absent is a match, which keeps every pre-ceremony sync working exactly as it does now.
    pub fn shares_genesis_with(&self, other: &AccruedColumns) -> bool {
        self.accrued.get(&GENESIS_NODE_ID) == other.get(&GENESIS_NODE_ID)
    }

    /// Install the reserved genesis column — the ONLY writer of [`GENESIS_NODE_ID`].
    ///
    /// Called twice in a node's life on paths that are both local: once at the Stage 5 ceremony
    /// from the pinned conversion, and once per process start when the persisted table is
    /// reloaded. Deliberately not reachable from any message handler, which is what makes
    /// "a peer cannot inflate the opening balances" a property of the type rather than a habit.
    ///
    /// Replace, not merge: a max here would let a corrupted larger value on disk survive a
    /// correction. ⚠ That puts the burden on the caller to hold the pinned truth — which the
    /// ceremony caller does and the *reload* caller does not, since it holds whatever is on disk.
    /// A reloaded column must therefore be re-asserted against the pin
    /// (`ghost_accounting::shard_genesis::verify_loaded_genesis`); merge can no longer re-learn
    /// it from a peer, so a truncated or restored-from-backup column would otherwise leave the
    /// node silently under-owing every miner for ever.
    ///
    /// Non-positive cells are dropped, holding the same strictly-positive invariant `accrue` and
    /// `merge_accrued` keep. A negative cell would otherwise count toward `owed` and the table
    /// root in memory while `encrypt_cells` silently refuses to persist it, so the node's root
    /// would change across a restart and the fleet would read that as consensus failure.
    pub fn install_genesis(&mut self, column: BTreeMap<String, i64>) {
        let column: BTreeMap<String, i64> = column.into_iter().filter(|(_, v)| *v > 0).collect();
        if column.is_empty() {
            self.accrued.remove(&GENESIS_NODE_ID);
        } else {
            self.accrued.insert(GENESIS_NODE_ID, column);
        }
    }

    /// Max-merge a peer's accrued columns — the `ShardTableSync` reconciliation path.
    ///
    /// Per-cell max, nothing else: a stale value loses, a duplicate is a no-op, and order cannot
    /// matter, so shipping the whole table (§12.6) needs no diff protocol. `settled` is
    /// deliberately not merged — it never crosses the mesh, so there is nothing to merge and no
    /// stale copy to resurrect. Non-positive incoming cells are skipped: honest tables never
    /// contain them, and merging one could only create a dead cell that splits the table root.
    ///
    /// The reserved genesis column is skipped outright — see [`GENESIS_NODE_ID`]. Every node
    /// derives it from the same pinned checkpoint, so there is nothing to learn from a peer, and
    /// because merging is a max an accepted inflation would be permanent and indistinguishable
    /// from genesis.
    pub fn merge_accrued(&mut self, other: &AccruedColumns) {
        for (node, column) in other {
            if *node == GENESIS_NODE_ID {
                continue;
            }
            for (addr, &value) in column {
                let current = self
                    .accrued
                    .get(node)
                    .and_then(|col| col.get(addr))
                    .copied()
                    .unwrap_or(0);
                if value > current {
                    self.accrued
                        .entry(*node)
                        .or_default()
                        .insert(addr.clone(), value);
                }
            }
        }
    }

    /// Verify a summary against its evidence, and only then max-merge its totals.
    ///
    /// The ordering is load-bearing (§12.3): a max cannot be undone, so an inflated counter that
    /// gets merged before its signature or its evidence is checked has already won. On ANY
    /// rejection the table is byte-identical to before the call.
    pub fn apply_summary(
        &mut self,
        summary: &EpochSummary,
        evidence: &[ShareProof],
        merkle_root: MerkleRootFn,
    ) -> Result<(), SummaryRejection> {
        // Same floor as the gossip path: a pre-genesis epoch's work is already in the genesis
        // column, and full evidence for it makes it no less of a double count.
        if summary.epoch < self.epoch_floor {
            return Err(SummaryRejection::PreGenesisEpoch);
        }
        if summary.genesis_marker != self.genesis_marker() {
            return Err(SummaryRejection::GenesisMismatch);
        }
        summary.verify(evidence, merkle_root)?;

        for (addr, row) in &summary.deltas {
            let current = self
                .accrued
                .get(&summary.node_id)
                .and_then(|col| col.get(addr))
                .copied()
                .unwrap_or(0);
            if row.total_micro > current {
                self.accrued
                    .entry(summary.node_id)
                    .or_default()
                    .insert(addr.clone(), row.total_micro);
            }
        }
        Ok(())
    }

    /// Commit to the whole table — what §12.6 compares across nodes.
    ///
    /// Follows the `compute_state_root` discipline exactly: a domain tag, every field
    /// length-prefixed, entries in canonical (`BTreeMap`) order — so no two distinct tables can
    /// serialise to the same bytes by running fields together. Both quantities are covered:
    /// `owed` derives from both, so drift in either must be visible the same day, not discovered
    /// a quarter later. Nodes compare roots taken against the same chain height; a node that has
    /// not yet settled a matured block differs, and that difference is real.
    pub fn compute_table_root(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(TABLE_ROOT_DOMAIN);

        // Zero cells and empty columns are skipped so the canonical form is computed, not
        // assumed. The mutating methods never create them, but the root must not depend on that
        // being true forever — an explicit zero and an absent cell are the same balance and must
        // commit identically.
        let columns: Vec<(&NodeId, Vec<(&String, i64)>)> = self
            .accrued
            .iter()
            .map(|(node, column)| {
                let cells: Vec<(&String, i64)> = column
                    .iter()
                    .filter(|(_, &v)| v != 0)
                    .map(|(addr, &v)| (addr, v))
                    .collect();
                (node, cells)
            })
            .filter(|(_, cells)| !cells.is_empty())
            .collect();

        h.update((columns.len() as u32).to_le_bytes());
        for (node, cells) in columns {
            h.update(node);
            h.update((cells.len() as u32).to_le_bytes());
            for (addr, value) in cells {
                h.update((addr.len() as u32).to_le_bytes());
                h.update(addr.as_bytes());
                h.update(value.to_le_bytes());
            }
        }

        let settled: Vec<(&String, i64)> = self
            .settled
            .iter()
            .filter(|(_, &v)| v != 0)
            .map(|(addr, &v)| (addr, v))
            .collect();
        h.update((settled.len() as u32).to_le_bytes());
        for (addr, value) in settled {
            h.update((addr.len() as u32).to_le_bytes());
            h.update(addr.as_bytes());
            h.update(value.to_le_bytes());
        }
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_reconciliation::batch::compute_merkle_root;

    /// Deterministic PRNG — a fixed seed so a failure is reproducible from the test name alone,
    /// same as `share_batch.rs`.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 11
        }
        fn shuffle<T>(&mut self, v: &mut [T]) {
            for i in (1..v.len()).rev() {
                let j = (self.next() as usize) % (i + 1);
                v.swap(i, j);
            }
        }
    }

    fn share(ts: u64, hash_byte: u8, addr: &str, difficulty: f64) -> ShareProof {
        ShareProof {
            round_id: 1,
            miner_id: [hash_byte; 32],
            difficulty,
            work: difficulty,
            share_hash: [hash_byte; 32],
            timestamp: ts,
            received_by: [0u8; 32],
            template_id: None,
            payout_address: Some(addr.to_string()),
            header: None,
            tier_log2: None,
            signature: None,
        }
    }

    fn identity() -> NodeIdentity {
        NodeIdentity::generate_without_pow()
    }

    /// A signed summary plus the evidence that backs it — the unit everything applies.
    fn summarise(
        epoch: u64,
        id: &NodeIdentity,
        prior: &BTreeMap<String, i64>,
        evidence: Vec<ShareProof>,
    ) -> (EpochSummary, Vec<ShareProof>) {
        summarise_under(epoch, id, prior, evidence, None)
    }

    /// Same, but stamped with a specific genesis marker — the armed/unarmed distinction.
    fn summarise_under(
        epoch: u64,
        id: &NodeIdentity,
        prior: &BTreeMap<String, i64>,
        evidence: Vec<ShareProof>,
        marker: Option<[u8; 32]>,
    ) -> (EpochSummary, Vec<ShareProof>) {
        let summary = EpochSummary::build(epoch, id, prior, &evidence, compute_merkle_root, marker)
            .expect("evidence is legal");
        (summary, evidence)
    }

    /// The reserved genesis column is not writable by a peer's table.
    ///
    /// It holds every miner's opening balance, identically on all eight nodes, and merging is a
    /// **max** — so a single accepted inflation is permanent and indistinguishable from genesis.
    /// The protection is this skip, not the id being unsignable: `[0u8; 32]` loads fine as an
    /// ed25519 low-order point, which the first draft of the genesis module got wrong.
    #[test]
    fn a_peer_column_cannot_write_the_reserved_genesis_slot() {
        let mut table = ShardTable::new();
        table.install_genesis(BTreeMap::from([("bc1qalice".to_string(), 1_000i64)]));
        let before = table.compute_table_root();

        let mut hostile: AccruedColumns = BTreeMap::new();
        hostile.insert(
            GENESIS_NODE_ID,
            BTreeMap::from([("bc1qalice".to_string(), i64::MAX)]),
        );
        // A legitimate peer column in the same message must still land, or the skip would be a
        // denial-of-service dressed as a guard.
        hostile.insert(
            [7u8; 32],
            BTreeMap::from([("bc1qbob".to_string(), 500i64)]),
        );
        table.merge_accrued(&hostile);

        assert_eq!(
            table.accrued().get(&GENESIS_NODE_ID),
            Some(&BTreeMap::from([("bc1qalice".to_string(), 1_000i64)])),
            "the genesis column must be untouched"
        );
        assert_eq!(
            table.accrued().get(&[7u8; 32]),
            Some(&BTreeMap::from([("bc1qbob".to_string(), 500i64)])),
            "an ordinary peer column in the same merge must still be applied"
        );
        assert_ne!(before, table.compute_table_root(), "bob's column did land");
        assert_eq!(table.owed().get("bc1qalice"), Some(&1_000));
    }

    /// A summary claiming the reserved column is refused BEFORE its signature is examined.
    ///
    /// The ordering is the point: the answer must not depend on whether someone can produce a
    /// signature for the all-zero key, because that is exactly the assumption that turned out to
    /// be wrong. Asserting the variant is `ReservedColumn` rather than `BadSignature` is what
    /// pins the ordering — a garbage signature would fail either way.
    #[test]
    fn a_summary_claiming_the_reserved_column_is_refused_before_its_signature() {
        let id = identity();
        let (mut summary, evidence) = summarise(
            1,
            &id,
            &BTreeMap::new(),
            vec![share(1_000, 1, "bc1qalice", 1.0)],
        );
        summary.node_id = GENESIS_NODE_ID;

        assert_eq!(
            summary.verify_stateless(),
            Err(SummaryRejection::ReservedColumn),
            "must reject as a reserved-column claim, not as a signature failure"
        );

        let mut table = ShardTable::new();
        let before = table.compute_table_root();
        assert_eq!(
            table.apply_summary(&summary, &evidence, compute_merkle_root),
            Err(SummaryRejection::ReservedColumn)
        );
        assert_eq!(
            table.compute_table_root(),
            before,
            "a rejected summary must leave the table byte-identical"
        );
    }

    /// Installing genesis is a replace, not a max — a corrupted larger value on disk must lose to
    /// the pinned truth, or a self-check could never correct anything.
    #[test]
    fn installing_genesis_replaces_rather_than_maxes() {
        let mut table = ShardTable::new();
        table.install_genesis(BTreeMap::from([("bc1qalice".to_string(), i64::MAX)]));
        table.install_genesis(BTreeMap::from([("bc1qalice".to_string(), 1_000i64)]));
        assert_eq!(table.owed().get("bc1qalice"), Some(&1_000));

        // And an empty install clears the column rather than leaving an empty map behind, so the
        // canonical "absent == zero" form the table root depends on is preserved.
        table.install_genesis(BTreeMap::new());
        assert!(table.accrued().get(&GENESIS_NODE_ID).is_none());
        assert_eq!(table.compute_table_root(), ShardTable::new().compute_table_root());
    }

    /// The reload path feeds `install_genesis` raw database rows, so it must hold the same
    /// strictly-positive invariant every other mutator does.
    ///
    /// A negative cell kept in memory would count toward `owed` and the table root while
    /// `encrypt_cells` refuses to persist it — so the node's root would change across a restart
    /// with no write in between, which the fleet reads as consensus failure rather than as the
    /// bad row it is.
    #[test]
    fn installing_genesis_drops_non_positive_cells_like_every_other_mutator() {
        let mut table = ShardTable::new();
        table.install_genesis(BTreeMap::from([
            ("bc1qalice".to_string(), 1_000i64),
            ("bc1qbob".to_string(), 0i64),
            ("bc1qcarol".to_string(), -5i64),
        ]));

        let column = table.accrued().get(&GENESIS_NODE_ID).expect("column");
        assert_eq!(
            column,
            &BTreeMap::from([("bc1qalice".to_string(), 1_000i64)]),
            "zero and negative cells must not survive into the table"
        );
        assert!(!table.owed().contains_key("bc1qcarol"));
    }

    /// The double count the floor exists to stop.
    ///
    /// The Stage 4 soak accrues a node's own work into its own column. Genesis then credits that
    /// same work again, for the whole fleet. Without a floor, a not-yet-armed peer re-advertising
    /// its pre-genesis column wins the max and the overlap is permanent — resetting the column
    /// locally cannot fix it, because the peer puts it straight back.
    #[test]
    fn a_pre_genesis_summary_is_refused_on_both_merge_paths() {
        let id = identity();
        let (summary, evidence) = summarise(
            4,
            &id,
            &BTreeMap::new(),
            vec![share(1_000, 1, "bc1qalice", 1.0)],
        );

        let mut table = ShardTable::new();
        table.set_epoch_floor(10);
        let before = table.compute_table_root();

        assert_eq!(
            table.merge_verified_summary(&summary),
            Err(SummaryRejection::PreGenesisEpoch),
            "gossip path must refuse a pre-genesis epoch"
        );
        assert_eq!(
            table.apply_summary(&summary, &evidence, compute_merkle_root),
            Err(SummaryRejection::PreGenesisEpoch),
            "full-evidence path must refuse it too — evidence makes it no less a double count"
        );
        assert_eq!(
            table.compute_table_root(),
            before,
            "a refused summary must leave the table byte-identical"
        );
    }

    /// The floor must not refuse the epoch it sits on, nor anything after it, nor anything at all
    /// while unarmed — otherwise arming would quietly stop the shard accruing.
    #[test]
    fn the_floor_admits_its_own_epoch_and_everything_after_it() {
        let id = identity();
        for (floor, epoch, expect_ok) in [(0u64, 1u64, true), (10, 10, true), (10, 11, true)] {
            let (summary, _) = summarise(
                epoch,
                &id,
                &BTreeMap::new(),
                vec![share(1_000, 1, "bc1qalice", 1.0)],
            );
            let mut table = ShardTable::new();
            table.set_epoch_floor(floor);
            assert_eq!(
                table.merge_verified_summary(&summary).is_ok(),
                expect_ok,
                "floor={floor} epoch={epoch}"
            );
        }
    }

    /// The hole the epoch floor could NOT close, and the reason the marker exists.
    ///
    /// `total_micro` is cumulative (§6 — it must be, or deltas could not be max-merged), so a
    /// summary at an epoch at or *above* the floor, from a node that has not armed, still carries
    /// pre-genesis work in its running total. Merging it credits that work a second time on top of
    /// the genesis column, and because merge is a max it is permanent. The floor cannot see it: the
    /// epoch is legal, only the total is not.
    #[test]
    fn an_unarmed_peers_post_floor_summary_is_refused_by_an_armed_node() {
        let id = identity();
        let genesis = BTreeMap::from([("bc1qalice".to_string(), 1_000i64)]);

        let mut armed = ShardTable::new();
        armed.install_genesis(genesis.clone());
        armed.set_epoch_floor(10);

        // Epoch 12 is comfortably ABOVE the floor, so the floor admits it — but the peer is
        // unarmed, and its cumulative total spans work already inside the genesis column.
        let (unarmed_summary, evidence) = summarise_under(
            12,
            &id,
            &BTreeMap::from([("bc1qalice".to_string(), 5_000i64)]),
            vec![share(1_000, 1, "bc1qalice", 1.0)],
            None,
        );

        let before = armed.compute_table_root();
        assert_eq!(
            armed.merge_verified_summary(&unarmed_summary),
            Err(SummaryRejection::GenesisMismatch),
            "an armed node must refuse an unarmed peer's summary, floor or no floor"
        );
        assert_eq!(
            armed.apply_summary(&unarmed_summary, &evidence, compute_merkle_root),
            Err(SummaryRejection::GenesisMismatch)
        );
        assert_eq!(armed.compute_table_root(), before);

        // And the same summary, stamped with the same genesis, is accepted — the gate is a gate,
        // not a wall.
        let marker = armed.genesis_marker();
        assert!(marker.is_some());
        let (armed_summary, _) = summarise_under(
            12,
            &id,
            &BTreeMap::from([("bc1qalice".to_string(), 5_000i64)]),
            vec![share(1_000, 1, "bc1qalice", 1.0)],
            marker,
        );
        assert_eq!(armed.merge_verified_summary(&armed_summary), Ok(()));
    }

    /// The mirror case: an unarmed node must refuse an armed peer's summary too, or it would take
    /// on totals computed against a ledger it is not running.
    #[test]
    fn an_unarmed_node_refuses_an_armed_peers_summary() {
        let id = identity();
        let mut armed = ShardTable::new();
        armed.install_genesis(BTreeMap::from([("bc1qalice".to_string(), 1_000i64)]));

        let (armed_summary, _) = summarise_under(
            3,
            &id,
            &BTreeMap::new(),
            vec![share(1_000, 1, "bc1qalice", 1.0)],
            armed.genesis_marker(),
        );

        let mut unarmed = ShardTable::new();
        assert_eq!(
            unarmed.merge_verified_summary(&armed_summary),
            Err(SummaryRejection::GenesisMismatch)
        );
    }

    /// An UNARMED node's signing bytes must be byte-identical to what a pre-marker binary
    /// produced, or the rolling cutover breaks every summary on the wire.
    ///
    /// The marker is appended only when `Some`, precisely so this holds: unarmed summaries stay
    /// verifiable by any peer, and only armed nodes — which by arming time are the whole fleet,
    /// since Stage 4 deploys the binary and Stage 5 only flips config — see the longer bytes.
    #[test]
    fn an_unarmed_summarys_signing_bytes_are_unchanged_and_the_marker_is_signed() {
        let id = identity();
        let (unarmed, _) = summarise_under(
            5,
            &id,
            &BTreeMap::new(),
            vec![share(1_000, 1, "bc1qalice", 1.0)],
            None,
        );
        let (armed, _) = summarise_under(
            5,
            &id,
            &BTreeMap::new(),
            vec![share(1_000, 1, "bc1qalice", 1.0)],
            Some([0xAB; 32]),
        );

        assert_eq!(
            armed.signing_bytes().len(),
            unarmed.signing_bytes().len() + 32,
            "the marker must be covered by the signature, not left bare on the wire"
        );
        assert_eq!(
            armed.signing_bytes()[..unarmed.signing_bytes().len()],
            unarmed.signing_bytes()[..],
            "an unarmed summary's bytes must be a prefix — old peers must still verify them"
        );

        // Stripping the marker on the wire must invalidate the signature, or the gate is bypassable.
        let mut stripped = armed.clone();
        stripped.genesis_marker = None;
        assert_eq!(
            stripped.verify_stateless(),
            Err(SummaryRejection::BadSignature)
        );
        assert_eq!(unarmed.verify_stateless(), Ok(()));
        assert_eq!(armed.verify_stateless(), Ok(()));
    }

    /// A summary encoded before the field existed must decode as unarmed, not fail — mixed-fleet
    /// safety at the serde layer.
    #[test]
    fn a_summary_without_the_marker_field_decodes_as_unarmed() {
        let id = identity();
        let (summary, _) = summarise(5, &id, &BTreeMap::new(), vec![share(1_000, 1, "bc1qa", 1.0)]);
        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&summary).unwrap()).unwrap();
        value.as_object_mut().unwrap().remove("genesis_marker");

        let decoded: EpochSummary = serde_json::from_value(value).expect("must decode");
        assert_eq!(decoded.genesis_marker, None);
        assert_eq!(decoded.verify_stateless(), Ok(()));
    }

    /// Table sync carries no epoch, so the genesis column is the generation marker.
    #[test]
    fn table_sync_matches_only_peers_opened_from_the_same_genesis() {
        let genesis = BTreeMap::from([("bc1qalice".to_string(), 1_000i64)]);

        let unarmed = ShardTable::new();
        let mut armed = ShardTable::new();
        armed.install_genesis(genesis.clone());

        let mut peer_armed = AccruedColumns::new();
        peer_armed.insert(GENESIS_NODE_ID, genesis.clone());
        let mut peer_other = AccruedColumns::new();
        peer_other.insert(
            GENESIS_NODE_ID,
            BTreeMap::from([("bc1qalice".to_string(), 999i64)]),
        );
        let peer_unarmed = AccruedColumns::new();

        // Both-absent matches, so every pre-ceremony sync keeps working unchanged.
        assert!(unarmed.shares_genesis_with(&peer_unarmed));
        assert!(armed.shares_genesis_with(&peer_armed));
        // The mixed-fleet window, in both directions.
        assert!(!armed.shares_genesis_with(&peer_unarmed));
        assert!(!unarmed.shares_genesis_with(&peer_armed));
        // Same anchor or nothing: a peer armed from different bytes is not a peer.
        assert!(!armed.shares_genesis_with(&peer_other));
    }

    /// Epochs come from block height and an epoch length, nothing else — never wall-clock
    /// (§12.2). Same height, same epoch, on any node at any time of day.
    #[test]
    fn a_share_with_no_tier_crosses_the_mesh_unrefused() {
        // The failure being pinned is M-6's shape, and M-6 ran at 2,000-2,900 rejections an hour
        // on every node: a receive-side check that deterministically refuses what a peer
        // legitimately sent. Retransmission never fixes it, because the rejection is a function of
        // the share itself, so the two ledgers simply diverge for ever.
        //
        // `None` means the share predates the tier gate. It must be judged by the rules of its own
        // era, not by one armed after it was mined.
        assert!(
            crosses_network_tier(None),
            "a pre-gate share must not be refused by a rule that did not exist when it was mined"
        );

        // At R = 1 the floor is the vardiff floor, so everything real crosses and the mechanism
        // ships inert — which is what makes raising R later a one-constant roll rather than a
        // behaviour change on the money path.
        assert!(crosses_network_tier(Some(NETWORK_TIER_LOG2)));
        assert!(crosses_network_tier(Some(NETWORK_TIER_LOG2 + 4)));
        assert!(
            !crosses_network_tier(Some(NETWORK_TIER_LOG2 - 1)),
            "a share carrying a tier below the floor is the one case the filter exists for"
        );
    }

    fn owed_map(rows: &[(&str, i64)]) -> BTreeMap<String, i64> {
        rows.iter().map(|(a, m)| (a.to_string(), *m)).collect()
    }

    #[test]
    fn every_satoshi_is_accounted_for_and_none_invented() {
        // Conservation is the property that matters most here: the coinbase total is fixed by
        // consensus, so a satoshi this function loses is one a miner is quietly not paid, and a
        // satoshi it invents is a block the network rejects.
        let owed = owed_map(&[("bc1qa", 7_000), ("bc1qb", 2_000), ("bc1qc", 1_000)]);
        let pool = 1_000_000u64;
        let r = shard_miner_payouts(&owed, pool, 200, 330);

        let paid: u64 = r.payouts.iter().map(|(_, s)| *s).sum();
        assert_eq!(
            paid + r.dust_sats + r.remainder_sats,
            pool,
            "paid + dust + remainder must equal the pool exactly"
        );
    }

    #[test]
    fn negative_and_zero_balances_take_no_part() {
        // A negative `owed` means this node's view has that address overpaid — it is working the
        // debt off (§4.4, balances are signed and never clamped). Paying it again would pay twice
        // for the same work, and clamping to zero instead would silently forgive the overpayment.
        let owed = owed_map(&[("bc1qa", 1_000), ("bc1qneg", -5_000), ("bc1qzero", 0)]);
        let r = shard_miner_payouts(&owed, 100_000, 200, 1);

        let addrs: Vec<&str> = r.payouts.iter().map(|(a, _)| a.as_str()).collect();
        assert_eq!(addrs, vec!["bc1qa"], "only positive balances are paid");
    }

    #[test]
    fn the_order_is_total_so_two_nodes_cannot_differ_on_a_tie() {
        // Pins the OUTPUT property: equal balances come out address-ascending, so two nodes with
        // identical tables build identical coinbases.
        //
        // ⚠ This test cannot kill the explicit tie-break, and saying so is the point. The input is
        // a `BTreeMap`, so it arrives address-ascending and a stable sort keeps that order with or
        // without the `then_with`. Removing the tie-break leaves this test green — verified by
        // mutation. The tie-break guards against the input type changing to something unordered;
        // a test that appeared to cover it would be worse than one that admits it does not.
        let owed = owed_map(&[("bc1qz", 500), ("bc1qa", 500), ("bc1qm", 500)]);
        let r = shard_miner_payouts(&owed, 30_000, 200, 1);

        let addrs: Vec<&str> = r.payouts.iter().map(|(a, _)| a.as_str()).collect();
        assert_eq!(
            addrs,
            vec!["bc1qa", "bc1qm", "bc1qz"],
            "equal balances must order by address, ascending"
        );
    }

    #[test]
    fn the_pool_is_shared_among_those_actually_paid_not_diluted_by_the_cut() {
        // The total is recomputed AFTER truncation, matching the live path. Diluting by addresses
        // that did not make the cut would underpay everyone who did and silently grow the
        // remainder — money going nowhere rather than to the miners entitled to it.
        let owed = owed_map(&[
            ("bc1qa", 100),
            ("bc1qb", 100),
            ("bc1qc", 100),
            ("bc1qd", 100),
        ]);
        let r = shard_miner_payouts(&owed, 1_000, 2, 1);

        let paid: u64 = r.payouts.iter().map(|(_, s)| *s).sum();
        assert_eq!(r.payouts.len(), 2, "only the top two are paid");
        assert_eq!(paid, 1_000, "and they share the WHOLE pool between them");
    }

    #[test]
    fn dust_is_diverted_never_dropped() {
        // Sub-threshold amounts roll into the node reward pool in the existing builder. Counting
        // them as dust rather than dropping them is what keeps conservation true.
        let owed = owed_map(&[("bc1qwhale", 1_000_000), ("bc1qdust", 1)]);
        let r = shard_miner_payouts(&owed, 1_000_000, 200, 330);

        assert!(
            r.payouts.iter().all(|(a, _)| a != "bc1qdust"),
            "a sub-threshold payout must not reach the coinbase"
        );
        let paid: u64 = r.payouts.iter().map(|(_, s)| *s).sum();
        assert_eq!(paid + r.dust_sats + r.remainder_sats, 1_000_000);
    }

    #[test]
    fn a_full_payment_discharges_the_whole_pool_of_work() {
        // The identity that has to hold: if the coinbase paid out the entire miner pool, then the
        // work that pool was computed against is fully discharged. Anything else means a block
        // pays a miner and still leaves them owed for the same work.
        let top_work = 9_000_000i64;
        let pool = 1_000_000u64;
        let a = discharged_micro_work(700_000, pool, top_work);
        let b = discharged_micro_work(200_000, pool, top_work);
        let c = discharged_micro_work(100_000, pool, top_work);
        assert_eq!(
            a + b + c,
            top_work,
            "a full payout discharges the full work"
        );
    }

    #[test]
    fn a_partial_payment_discharges_only_its_share() {
        // Dust and the top-N cut mean the pool is not always fully paid out. What was not paid
        // must stay owed — that is what makes "miners below the cut rotate in" true rather than
        // aspirational.
        let discharged = discharged_micro_work(250_000, 1_000_000, 8_000_000);
        assert_eq!(
            discharged, 2_000_000,
            "a quarter of the pool discharges a quarter of the work"
        );
    }

    #[test]
    fn an_empty_pool_discharges_nothing_rather_than_everything() {
        // The degenerate cases are the dangerous ones: a divide-by-zero here would panic on the
        // block-connected path, and silently discharging everything would wipe the ledger on a
        // block that paid miners nothing.
        assert_eq!(discharged_micro_work(500, 0, 1_000_000), 0);
        assert_eq!(discharged_micro_work(0, 1_000_000, 1_000_000), 0);
        assert_eq!(discharged_micro_work(500, 1_000_000, 0), 0);
        assert_eq!(discharged_micro_work(500, 1_000_000, -5), 0);
    }

    #[test]
    fn epochs_are_derived_from_height_alone() {
        let len = NonZeroU64::new(144).expect("non-zero");
        assert_eq!(epoch_for_height(0, len), 0);
        assert_eq!(epoch_for_height(143, len), 0);
        assert_eq!(epoch_for_height(144, len), 1);
        assert_eq!(epoch_for_height(961_700, len), 6678);
        // A different epoch length is a different schedule, visibly.
        let other = NonZeroU64::new(100).expect("non-zero");
        assert_eq!(epoch_for_height(961_700, other), 9617);
    }

    /// Merge must be idempotent, commutative and associative: any delivery order, any amount of
    /// duplication, and any re-delivery of stale state must land every node on the same table.
    /// This is the property that lets the design delete the repair machinery — there is no state
    /// requiring repair.
    #[test]
    fn merge_is_idempotent_commutative_and_associative() {
        let a = identity();
        let b = identity();

        // Two nodes, two epochs each, with overlapping addresses.
        let (a1, a1_ev) = summarise(
            1,
            &a,
            &BTreeMap::new(),
            vec![share(10, 1, "bc1qalice", 3.0), share(11, 2, "bc1qbob", 1.0)],
        );
        let a_col: BTreeMap<String, i64> = a1
            .deltas
            .iter()
            .map(|(k, r)| (k.clone(), r.total_micro))
            .collect();
        let (a2, a2_ev) = summarise(2, &a, &a_col, vec![share(20, 3, "bc1qalice", 2.0)]);

        let (b1, b1_ev) = summarise(1, &b, &BTreeMap::new(), vec![share(12, 4, "bc1qbob", 5.0)]);
        let b_col: BTreeMap<String, i64> = b1
            .deltas
            .iter()
            .map(|(k, r)| (k.clone(), r.total_micro))
            .collect();
        let (b2, b2_ev) = summarise(2, &b, &b_col, vec![share(21, 5, "bc1qcarol", 4.0)]);

        // The reference: one clean in-order application.
        let mut reference = ShardTable::new();
        for (s, ev) in [(&a1, &a1_ev), (&a2, &a2_ev), (&b1, &b1_ev), (&b2, &b2_ev)] {
            reference
                .apply_summary(s, ev, compute_merkle_root)
                .expect("verifies");
        }
        let reference_root = reference.compute_table_root();

        // A stale partial snapshot (epoch 1 only) that keeps being re-advertised.
        let mut stale = ShardTable::new();
        stale
            .apply_summary(&a1, &a1_ev, compute_merkle_root)
            .expect("verifies");
        stale
            .apply_summary(&b1, &b1_ev, compute_merkle_root)
            .expect("verifies");

        let mut rng = Lcg(0x5AAD);
        for _ in 0..100 {
            // Every summary delivered twice, plus stale and fully-merged table syncs, shuffled.
            let mut ops: Vec<u8> = vec![0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5];
            rng.shuffle(&mut ops);

            let mut table = ShardTable::new();
            for op in ops {
                match op {
                    0 => table
                        .apply_summary(&a1, &a1_ev, compute_merkle_root)
                        .map(|_| ()),
                    1 => table
                        .apply_summary(&a2, &a2_ev, compute_merkle_root)
                        .map(|_| ()),
                    2 => table
                        .apply_summary(&b1, &b1_ev, compute_merkle_root)
                        .map(|_| ()),
                    3 => table
                        .apply_summary(&b2, &b2_ev, compute_merkle_root)
                        .map(|_| ()),
                    4 => {
                        table.merge_accrued(stale.accrued());
                        Ok(())
                    }
                    _ => {
                        table.merge_accrued(reference.accrued());
                        Ok(())
                    }
                }
                .expect("legal summaries verify");
            }

            assert_eq!(
                table.compute_table_root(),
                reference_root,
                "delivery order, duplication or stale re-delivery changed the merged state"
            );
            assert_eq!(table.owed(), reference.owed());
            assert!(
                table.settled().is_empty(),
                "merge must never touch settled — it is chain-derived, not gossiped"
            );
        }
    }

    /// §4.4's worked example, as a test: a node that slept through a settlement re-advertises its
    /// pre-settlement `accrued`, and nobody's `owed` may rise. This is THE bug the two-quantity
    /// split exists to prevent — under a single subtracted-from counter, the max resurrects the
    /// settled balance and the address is paid twice.
    #[test]
    fn a_stale_rejoiner_cannot_resurrect_a_settled_balance() {
        let c = identity();
        let (s1, ev1) = summarise(
            1,
            &c,
            &BTreeMap::new(),
            vec![share(10, 1, "bc1qmirror", 100.0)],
        );

        let mut table = ShardTable::new();
        table
            .apply_summary(&s1, &ev1, compute_merkle_root)
            .expect("verifies");
        assert_eq!(table.owed().get("bc1qmirror"), Some(&100_000_000));

        // D's view of the world, snapshotted before the block lands.
        let pre_settlement = table.accrued().clone();

        // A block pays the address 60 of the 100; every node reads it off the chain.
        table.record_settled("bc1qmirror", 60_000_000);
        assert_eq!(table.owed().get("bc1qmirror"), Some(&40_000_000));
        let settled_root = table.compute_table_root();

        // D comes back and re-advertises everything it holds: the old table, the old summary,
        // both more than once. None of it may move `owed` upward.
        table.merge_accrued(&pre_settlement);
        table
            .apply_summary(&s1, &ev1, compute_merkle_root)
            .expect("still verifies");
        table.merge_accrued(&pre_settlement);

        assert_eq!(
            table.owed().get("bc1qmirror"),
            Some(&40_000_000),
            "a pre-settlement accrued value re-advertised after settlement raised owed — \
             this is the §4.4 double-payment bug"
        );
        assert_eq!(table.compute_table_root(), settled_root);
    }

    /// A negative residual is a CORRECTION, not an error state: a node that overpays relative to
    /// this view leaves `owed` negative, and the address accrues back up through zero. Clamping
    /// at zero would hand the address the overpayment twice.
    #[test]
    fn owed_goes_negative_and_recovers_without_clamping() {
        let node = [0xAA; 32];
        let mut table = ShardTable::new();
        table.accrue(node, "bc1qover", 50_000_000);

        // Another node's view paid out more than we ever saw accrue.
        table.record_settled("bc1qover", 80_000_000);
        assert_eq!(
            table.owed().get("bc1qover"),
            Some(&-30_000_000),
            "the residual must be signed — clamping destroys the correction"
        );

        // The miner keeps working; the residual absorbs the first 30M before owed turns positive.
        table.accrue(node, "bc1qover", 10_000_000);
        assert_eq!(table.owed().get("bc1qover"), Some(&-20_000_000));
        table.accrue(node, "bc1qover", 45_000_000);
        assert_eq!(table.owed().get("bc1qover"), Some(&25_000_000));

        // An address the chain paid but we never saw accrue at all is owed a negative amount,
        // not silently absent.
        table.record_settled("bc1qphantom", 5_000_000);
        assert_eq!(table.owed().get("bc1qphantom"), Some(&-5_000_000));
    }

    /// The root is a function of content alone: any construction order commits identically, and
    /// any difference in content — including in `settled`, and including field boundaries —
    /// commits differently.
    #[test]
    fn table_root_is_deterministic_on_content_not_insertion_order() {
        let n1 = [0x01; 32];
        let n2 = [0x02; 32];

        let build = |ops: &mut dyn Iterator<Item = usize>| {
            let mut t = ShardTable::new();
            for op in ops {
                match op {
                    0 => t.accrue(n1, "bc1qalice", 7),
                    1 => t.accrue(n2, "bc1qalice", 3),
                    2 => t.accrue(n1, "bc1qbob", 11),
                    _ => t.record_settled("bc1qalice", 5),
                }
            }
            t
        };

        let reference = build(&mut [0, 1, 2, 3].into_iter()).compute_table_root();
        let mut rng = Lcg(0xD00D);
        for _ in 0..50 {
            let mut ops = [0usize, 1, 2, 3];
            rng.shuffle(&mut ops);
            assert_eq!(
                build(&mut ops.into_iter()).compute_table_root(),
                reference,
                "insertion order leaked into the table root"
            );
        }

        // Content differences must all be visible…
        let base = build(&mut [0, 1, 2, 3].into_iter());
        let mut one_more = base.clone();
        one_more.accrue(n1, "bc1qalice", 1);
        assert_ne!(base.compute_table_root(), one_more.compute_table_root());

        let mut settled_differs = base.clone();
        settled_differs.record_settled("bc1qalice", 1);
        assert_ne!(
            base.compute_table_root(),
            settled_differs.compute_table_root(),
            "settled is part of the payable state and must be covered by the root"
        );

        // …including which COLUMN holds a value: same totals, different attribution.
        let mut swapped = ShardTable::new();
        swapped.accrue(n2, "bc1qalice", 7);
        swapped.accrue(n1, "bc1qalice", 3);
        swapped.accrue(n1, "bc1qbob", 11);
        swapped.record_settled("bc1qalice", 5);
        assert_ne!(
            base.compute_table_root(),
            swapped.compute_table_root(),
            "per-node attribution must be committed, not just per-address sums"
        );

        // …and address boundaries must be unambiguous under length prefixing. This pair is
        // adversarial: without the length prefix the two tables serialise to the SAME bytes,
        // because 98 is 0x62 ('b') little-endian and 0x6200000000000000's low bytes are seven
        // zeros — the value bytes impersonate the neighbouring address bytes exactly. A softer
        // pair (same addresses re-split, small values) does NOT catch a missing prefix, which a
        // mutation run proved the hard way.
        let mut split_one_way = ShardTable::new();
        split_one_way.accrue(n1, "a", 0x62);
        split_one_way.accrue(n1, "bc", 5);
        let mut split_other_way = ShardTable::new();
        split_other_way.accrue(n1, "ab", 0x6200000000000000);
        split_other_way.accrue(n1, "c", 5);
        assert_ne!(
            split_one_way.compute_table_root(),
            split_other_way.compute_table_root(),
            "address boundaries are ambiguous — length prefixing is not working"
        );
    }

    /// Golden vector, pinning `ShardTableRoot/v1` at the moment the encoding was defined.
    ///
    /// If this ever fails, the encoding changed. The fix is a domain-tag version bump plus a
    /// coordinated roll — **not** updating the expected value here, which would make the test
    /// agree with whatever the code now does.
    #[test]
    fn table_root_golden_vector() {
        let mut table = ShardTable::new();
        table.accrue([0x11; 32], "bc1qalice", 1_500_000);
        table.accrue([0x11; 32], "bc1qbob", 2_750_000);
        table.accrue([0x22; 32], "bc1qalice", 125_000);
        table.record_settled("bc1qalice", 1_000_000);

        assert_eq!(
            hex::encode(table.compute_table_root()),
            "cf16f99095709fca672f7f33b028bba65544bed99224cf755b856ce310cd4867",
            "table-root encoding changed — bump ShardTableRoot/v{{n}} and coordinate the roll, \
             do not edit this vector to match"
        );
    }

    /// Golden vector for the injected Merkle tree, computed with the REAL
    /// `ghost_reconciliation::compute_merkle_root`. The tree cannot be a compile-time dependency
    /// (the crate graph runs the other way), so this pin is what keeps the two crates from
    /// drifting apart silently: if reconciliation's encoding ever changes, this fails here.
    #[test]
    fn epoch_share_root_matches_ghost_reconciliation_golden_vector() {
        let leaves = [[0x01u8; 32], [0x02; 32], [0x03; 32]];
        assert_eq!(
            hex::encode(compute_merkle_root(&leaves)),
            "ead4c48f92b7b77c8560259ec978903d9b0afa288dbce242cb47cc8d2505fba0",
            "ghost-reconciliation's merkle encoding changed under the shard — every signed \
             share_root in flight just became unverifiable; version and gate the change"
        );
    }

    /// Verify-before-merge (§12.3): a summary that fails its signature, its root, or its
    /// delta/evidence agreement must leave the table byte-identical. A max cannot be undone, so
    /// checking after merging is not checking at all.
    #[test]
    fn an_unverifiable_summary_must_not_touch_the_table() {
        let honest = identity();
        let evidence = vec![share(10, 1, "bc1qalice", 3.0), share(11, 2, "bc1qbob", 1.0)];
        let (good, _) = summarise(1, &honest, &BTreeMap::new(), evidence.clone());

        let mut table = ShardTable::new();
        table.accrue([0x77; 32], "bc1qalice", 42);
        let untouched = table.compute_table_root();

        // (a) A tampered summary: the signature no longer covers the inflated delta.
        let mut forged = good.clone();
        forged.deltas.get_mut("bc1qalice").expect("row").total_micro = i64::MAX / 2;
        assert_eq!(
            table.apply_summary(&forged, &evidence, compute_merkle_root),
            Err(SummaryRejection::BadSignature)
        );
        assert_eq!(table.compute_table_root(), untouched);

        // (b) A validly SIGNED summary whose root does not match the evidence: the signer lied
        // about what backs the numbers.
        let mut wrong_root = good.clone();
        wrong_root.share_root = [0xEE; 32];
        wrong_root.signature = honest.sign(&wrong_root.signing_bytes()).to_vec();
        assert_eq!(
            table.apply_summary(&wrong_root, &evidence, compute_merkle_root),
            Err(SummaryRejection::RootMismatch)
        );
        assert_eq!(table.compute_table_root(), untouched);

        // (c) A validly signed summary whose deltas disagree with what the evidence folds to.
        let mut inflated = good.clone();
        {
            let row = inflated.deltas.get_mut("bc1qalice").expect("row");
            row.delta_micro += 1;
            row.total_micro += 1;
        }
        inflated.signature = honest.sign(&inflated.signing_bytes()).to_vec();
        assert_eq!(
            table.apply_summary(&inflated, &evidence, compute_merkle_root),
            Err(SummaryRejection::DeltaMismatch)
        );
        assert_eq!(table.compute_table_root(), untouched);

        // (d) Structurally malformed rows never reach the fold at all.
        let mut negative = good.clone();
        negative.deltas.get_mut("bc1qbob").expect("row").delta_micro = -1;
        negative.signature = honest.sign(&negative.signing_bytes()).to_vec();
        assert_eq!(
            table.apply_summary(&negative, &evidence, compute_merkle_root),
            Err(SummaryRejection::MalformedDeltas)
        );
        assert_eq!(table.compute_table_root(), untouched);

        // And the sane summary still lands, so the gate is a gate, not a wall.
        table
            .apply_summary(&good, &evidence, compute_merkle_root)
            .expect("verifies");
        assert_ne!(table.compute_table_root(), untouched);
    }

    /// A summary built by an honest node verifies against its own evidence — in any arrival
    /// order, because the evidence hashes are canonically sorted on both sides — and survives a
    /// serde round trip, since a stored summary is served verbatim to a syncing peer.
    #[test]
    fn a_built_summary_verifies_and_round_trips() {
        let id = identity();
        let evidence = vec![
            share(30, 9, "bc1qalice", 2.0),
            share(10, 3, "bc1qbob", 1.5),
            share(20, 6, "bc1qalice", 0.5),
        ];
        let prior = BTreeMap::from([("bc1qalice".to_string(), 1_000_000_i64)]);
        let summary = EpochSummary::build(7, &id, &prior, &evidence, compute_merkle_root, None)
            .expect("legal evidence");

        // Totals continue the node's own column: prior + this epoch's fold.
        assert_eq!(summary.deltas["bc1qalice"].delta_micro, 2_500_000);
        assert_eq!(summary.deltas["bc1qalice"].total_micro, 3_500_000);
        assert_eq!(summary.deltas["bc1qbob"].total_micro, 1_500_000);
        assert_eq!(summary.share_count, 3);

        let mut shuffled = evidence.clone();
        shuffled.swap(0, 2);
        summary
            .verify(&shuffled, compute_merkle_root)
            .expect("arrival order must not matter — both sides sort canonically");

        let json = serde_json::to_string(&summary).expect("serialises");
        let back: EpochSummary = serde_json::from_str(&json).expect("deserialises");
        back.verify(&evidence, compute_merkle_root)
            .expect("a round-tripped summary must still verify");
        assert_eq!(back.signing_bytes(), summary.signing_bytes());
    }

    /// Every field must be covered by the signing bytes, or a field could be altered without
    /// invalidating the signature — and the signature is the only thing standing between a
    /// remote counter and the max.
    #[test]
    fn summary_signing_bytes_cover_every_field() {
        let id = identity();
        let evidence = vec![share(10, 1, "bc1qalice", 3.0)];
        let (base, _) = summarise(1, &id, &BTreeMap::new(), evidence);
        let bytes = base.signing_bytes();

        let mut m = base.clone();
        m.epoch += 1;
        assert_ne!(bytes, m.signing_bytes(), "epoch not covered");

        let mut m = base.clone();
        m.node_id = [0x99; 32];
        assert_ne!(bytes, m.signing_bytes(), "node_id not covered");

        let mut m = base.clone();
        m.deltas.get_mut("bc1qalice").expect("row").delta_micro += 1;
        assert_ne!(bytes, m.signing_bytes(), "delta not covered");

        let mut m = base.clone();
        m.deltas.get_mut("bc1qalice").expect("row").total_micro += 1;
        assert_ne!(bytes, m.signing_bytes(), "total not covered");

        let mut m = base.clone();
        m.deltas.insert(
            "bc1qextra".to_string(),
            EpochDelta {
                delta_micro: 1,
                total_micro: 1,
            },
        );
        assert_ne!(bytes, m.signing_bytes(), "delta set not covered");

        let mut m = base.clone();
        m.share_count += 1;
        assert_ne!(bytes, m.signing_bytes(), "share_count not covered");

        let mut m = base.clone();
        m.share_root = [0x99; 32];
        assert_ne!(bytes, m.signing_bytes(), "share_root not covered");

        // The signature is over the bytes, so it cannot be inside them.
        let mut m = base.clone();
        m.signature = vec![0xEE; 64];
        assert_eq!(
            bytes,
            m.signing_bytes(),
            "signing the signature would be circular"
        );
    }

    /// Evidence is screened before anything is derived from it: duplicated hashes would
    /// double-fold, unattributed work belongs to nobody, and a non-creditable difficulty is a
    /// number no proof of work stands behind.
    #[test]
    fn illegal_evidence_is_refused_symmetrically_by_build_and_verify() {
        let id = identity();
        let good = vec![share(10, 1, "bc1qalice", 3.0), share(11, 2, "bc1qbob", 1.0)];
        let (summary, _) = summarise(3, &id, &BTreeMap::new(), good.clone());

        // Same share twice: same hash, double the credit.
        let duplicated = vec![good[0].clone(), good[0].clone()];
        assert_eq!(
            EpochSummary::build(3, &id, &BTreeMap::new(), &duplicated, compute_merkle_root, None)
                .err(),
            Some(SummaryRejection::DuplicateEvidence)
        );

        let mut unattributed = good.clone();
        unattributed[0].payout_address = None;
        assert_eq!(
            summary.verify(&unattributed, compute_merkle_root),
            Err(SummaryRejection::UnattributedEvidence)
        );

        let mut saturating = good.clone();
        saturating[0].difficulty = f64::MAX;
        assert_eq!(
            summary.verify(&saturating, compute_merkle_root),
            Err(SummaryRejection::NonCreditableEvidence)
        );

        // A share count that disagrees with the evidence is caught before the fold runs.
        assert_eq!(
            summary.verify(&good[..1], compute_merkle_root),
            Err(SummaryRejection::EvidenceCountMismatch)
        );
    }
}
