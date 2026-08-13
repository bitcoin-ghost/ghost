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
    pub fn build(
        epoch: u64,
        identity: &NodeIdentity,
        prior_column: &BTreeMap<String, i64>,
        evidence: &[ShareProof],
        merkle_root: MerkleRootFn,
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
        let folded: BTreeMap<&String, i64> = screened
            .folded
            .iter()
            .map(|(addr, &v)| (addr, v))
            .collect();
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

    /// Max-merge a peer's accrued columns — the `ShardTableSync` reconciliation path.
    ///
    /// Per-cell max, nothing else: a stale value loses, a duplicate is a no-op, and order cannot
    /// matter, so shipping the whole table (§12.6) needs no diff protocol. `settled` is
    /// deliberately not merged — it never crosses the mesh, so there is nothing to merge and no
    /// stale copy to resurrect. Non-positive incoming cells are skipped: honest tables never
    /// contain them, and merging one could only create a dead cell that splits the table root.
    pub fn merge_accrued(&mut self, other: &AccruedColumns) {
        for (node, column) in other {
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
        let summary = EpochSummary::build(epoch, id, prior, &evidence, compute_merkle_root)
            .expect("evidence is legal");
        (summary, evidence)
    }

    /// Epochs come from block height and an epoch length, nothing else — never wall-clock
    /// (§12.2). Same height, same epoch, on any node at any time of day.
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
        let a_col: BTreeMap<String, i64> =
            a1.deltas.iter().map(|(k, r)| (k.clone(), r.total_micro)).collect();
        let (a2, a2_ev) = summarise(2, &a, &a_col, vec![share(20, 3, "bc1qalice", 2.0)]);

        let (b1, b1_ev) = summarise(1, &b, &BTreeMap::new(), vec![share(12, 4, "bc1qbob", 5.0)]);
        let b_col: BTreeMap<String, i64> =
            b1.deltas.iter().map(|(k, r)| (k.clone(), r.total_micro)).collect();
        let (b2, b2_ev) = summarise(2, &b, &b_col, vec![share(21, 5, "bc1qcarol", 4.0)]);

        // The reference: one clean in-order application.
        let mut reference = ShardTable::new();
        for (s, ev) in [(&a1, &a1_ev), (&a2, &a2_ev), (&b1, &b1_ev), (&b2, &b2_ev)] {
            reference.apply_summary(s, ev, compute_merkle_root).expect("verifies");
        }
        let reference_root = reference.compute_table_root();

        // A stale partial snapshot (epoch 1 only) that keeps being re-advertised.
        let mut stale = ShardTable::new();
        stale.apply_summary(&a1, &a1_ev, compute_merkle_root).expect("verifies");
        stale.apply_summary(&b1, &b1_ev, compute_merkle_root).expect("verifies");

        let mut rng = Lcg(0x5AAD);
        for _ in 0..100 {
            // Every summary delivered twice, plus stale and fully-merged table syncs, shuffled.
            let mut ops: Vec<u8> = vec![0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5];
            rng.shuffle(&mut ops);

            let mut table = ShardTable::new();
            for op in ops {
                match op {
                    0 => table.apply_summary(&a1, &a1_ev, compute_merkle_root).map(|_| ()),
                    1 => table.apply_summary(&a2, &a2_ev, compute_merkle_root).map(|_| ()),
                    2 => table.apply_summary(&b1, &b1_ev, compute_merkle_root).map(|_| ()),
                    3 => table.apply_summary(&b2, &b2_ev, compute_merkle_root).map(|_| ()),
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
        table.apply_summary(&s1, &ev1, compute_merkle_root).expect("verifies");
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
        table.apply_summary(&s1, &ev1, compute_merkle_root).expect("still verifies");
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
        table.apply_summary(&good, &evidence, compute_merkle_root).expect("verifies");
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
        let summary = EpochSummary::build(7, &id, &prior, &evidence, compute_merkle_root)
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
        assert_eq!(bytes, m.signing_bytes(), "signing the signature would be circular");
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
            EpochSummary::build(3, &id, &BTreeMap::new(), &duplicated, compute_merkle_root)
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
