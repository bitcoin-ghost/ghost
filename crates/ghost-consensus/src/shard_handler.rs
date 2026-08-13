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
//| LICENSE: MIT                                                                                                        |
//| FILE: shard_handler.rs                                                                                              |
//|======================================================================================================================|

//! Pure handlers for the share-shard mesh messages (`docs/SHARE_SHARD.md`).
//!
//! Nothing here reads a clock, a database, a lock or the network, and nothing here is wired into
//! a runtime path — the integration (task spawning, lock order, cadence, gating) is deliberately
//! done separately, by hand. These functions are the VERIFY-THEN-MERGE step and only that:
//!
//! - verification strictly precedes any mutation (§12.3 — a max cannot be undone), and
//! - a rejected message leaves the table byte-identical, which the tests pin by table root.
//!
//! Cross-crate injection: the Merkle verifier is `ghost_reconciliation::verify_merkle_proof` and
//! the share-validity predicate spans the PoW/GHOST-09/binding primitives; both are passed in as
//! function pointers, the same no-cycle pattern as `ghost_common::share_shard::MerkleRootFn`
//! (which pins the injected tree with a cross-crate golden vector).

use std::collections::BTreeMap;

use thiserror::Error;

use ghost_common::identity::{verify_signature, NodeIdentity};
use ghost_common::share_shard::{
    AccruedColumns, EpochSummary, MerkleRootFn, ShardTable, SummaryRejection,
};
use ghost_common::types::{NodeId, ShareProof};

use crate::message::{
    shard_columns_from_accrued, shard_table_sync_signing_bytes, ShardEpochSummaryMessage,
    ShardEvidenceMessage, ShardSampleLeaf, ShardSampleRequestMessage, ShardSampleResponseMessage,
    ShardTableSyncMessage,
};

/// Merkle-proof verifier, taken by injection.
///
/// The function that MUST be injected is `ghost_reconciliation::verify_merkle_proof`
/// `(leaf, proof, root, index, leaf_count) -> bool` — the only verifier matching the tree that
/// `share_shard::MerkleRootFn` commits epochs under (single SHA-256, domain-tagged,
/// leaf-count-bound, odd leaves carried forward). The signature here mirrors it exactly so the
/// real function passes without an adapter, and the tests exercise the real one via the
/// dev-dependency.
pub type MerkleProofFn = fn(&[u8; 32], &[[u8; 32]], &[u8; 32], usize, usize) -> bool;

/// Share-validity predicate, taken by injection: `true` iff the share passes the §6 sampling
/// checks (PoW preimage, GHOST-09 signature, receiver/payout binding).
///
/// ⚠ The injected predicate MUST bind the share's CONTENT to its `share_hash` — i.e. include
/// the PoW preimage check `sha256d(header) == share_hash`. The Merkle path only proves the HASH
/// was committed; without content binding, a malicious reporter could pair a genuine leaf hash
/// with fabricated share fields and frame an honest node. The predicate spans several crates
/// (`DifficultyCalculator`, `share_binding`), which is why it is injected rather than imported.
pub type ShareValidityFn = fn(&ShareProof) -> bool;

// ─────────────────────────────────────────────────────────────────────────────
// Epoch summaries
// ─────────────────────────────────────────────────────────────────────────────

/// Why a gossiped epoch summary was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ShardSummaryRejection {
    /// Refused by the data model's own gate ([`EpochSummary::verify`] via
    /// [`ShardTable::apply_summary`]) — structure, signature, or evidence disagreement.
    #[error(transparent)]
    Summary(#[from] SummaryRejection),
    /// §6 chain check: against the same node's summary for the PREVIOUS epoch,
    /// `total_micro != prior total + delta_micro` for some address both summaries carry.
    #[error("summary breaks the node's own summary chain: total != prior total + delta")]
    ChainMismatch,
    /// Two DIFFERENT signed summaries from the same node for the same epoch. Either one alone
    /// verifies, so this is only detectable against the copy already held — and it is
    /// evidence-grade misbehaviour, not gossip noise: refuse the merge and let the caller
    /// escalate.
    #[error("a different signed summary from this node for this epoch is already held")]
    SummaryEquivocation,
}

/// Verify a summary WITHOUT its share evidence — §6's "always, before any merge" layer.
///
/// The design is explicit that this layer needs no shares: structure, signature, and — when the
/// receiver holds the same node's summary for the immediately preceding epoch — the chain check
/// `total == prior total + delta`. What it cannot check (root/fold agreement) is exactly what
/// §6's asynchronous sampling and the evidence broadcast exist to close; a peer joining
/// mid-stream takes the total on the signature until sampling says otherwise.
///
/// `prior_summary` is the receiver's stored copy of the SAME node's most recent verified
/// summary, if any (a summary from a different node is ignored, defensively). The chain check
/// applies only when it is exactly the previous epoch: epochs may legitimately be missed, and a
/// later total already contains every earlier delta.
pub fn verify_summary_stateless(
    summary: &EpochSummary,
    prior_summary: Option<&EpochSummary>,
) -> Result<(), ShardSummaryRejection> {
    // Structure then signature, borrowed from the type rather than re-spelled here: two copies of
    // one predicate drift apart silently, and the weaker copy is the one that decides what merges.
    summary.verify_stateless()?;

    // Chain checks, only against the same node's history.
    if let Some(prior) = prior_summary.filter(|p| p.node_id == summary.node_id) {
        if prior.epoch == summary.epoch && prior.signing_bytes() != summary.signing_bytes() {
            // Same epoch, different content, both signed: equivocation, not staleness.
            return Err(ShardSummaryRejection::SummaryEquivocation);
        }
        if prior.epoch + 1 == summary.epoch {
            // Consecutive summaries: every address BOTH carry must chain exactly. Addresses
            // only in the new summary may have been last touched in an older epoch, so their
            // prior total is unknowable here — that gap is §6's sampling surface, not ours.
            for (addr, row) in &summary.deltas {
                if let Some(prev) = prior.deltas.get(addr) {
                    if row.total_micro != prev.total_micro.saturating_add(row.delta_micro) {
                        return Err(ShardSummaryRejection::ChainMismatch);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Verify a received epoch summary, and only then merge it into the table.
///
/// Two verification depths, chosen by what the caller holds (§6):
///
/// - `evidence: Some(shares)` — the full gate, delegated wholly to
///   [`ShardTable::apply_summary`]: structure, signature, count, duplicate/attribution
///   screening, Merkle root and exact fold agreement. This is the path for a node applying its
///   own epoch, and for a sampler that has fetched the shares.
/// - `evidence: None` — the gossip path. [`verify_summary_stateless`] (structure, signature,
///   chain against `prior_summary`), then the node's `total_micro`s are max-merged into its
///   column. Merging totals by max is what makes duplicate, stale and out-of-order delivery all
///   harmless: a stale summary simply loses the max.
///
/// On ANY rejection the table is byte-identical to before the call — verification strictly
/// precedes mutation, and the ordering is load-bearing (§12.3).
pub fn apply_shard_epoch_summary(
    table: &mut ShardTable,
    msg: &ShardEpochSummaryMessage,
    prior_summary: Option<&EpochSummary>,
    evidence: Option<&[ShareProof]>,
    merkle_root: MerkleRootFn,
) -> Result<(), ShardSummaryRejection> {
    let summary = &msg.summary;
    match evidence {
        Some(shares) => table
            .apply_summary(summary, shares, merkle_root)
            .map_err(Into::into),
        None => {
            verify_summary_stateless(summary, prior_summary)?;

            // Merge the verified totals as one single-node column, per-cell max. Zero totals
            // are skipped: a zero is represented by absence (the table's canonical-form
            // invariant), and `merge_accrued` would only skip them again anyway.
            let column: BTreeMap<String, i64> = summary
                .deltas
                .iter()
                .filter(|(_, row)| row.total_micro > 0)
                .map(|(addr, row)| (addr.clone(), row.total_micro))
                .collect();
            let mut one_column = AccruedColumns::new();
            one_column.insert(summary.node_id, column);
            table.merge_accrued(&one_column);
            Ok(())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Whole-table sync (§12.6)
// ─────────────────────────────────────────────────────────────────────────────

/// Why a table-sync response was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ShardSyncRejection {
    /// A `Request` was handed to the response handler. Serving a request reads storage and
    /// belongs to the integration, not here.
    #[error("message is a sync request, not a response")]
    NotAResponse,
    /// The wire table is not in canonical form: columns/cells out of order or duplicated, an
    /// empty address or column, or a non-positive cell. Honest tables are canonical by
    /// construction ([`shard_columns_from_accrued`]); anything else is refused BEFORE the
    /// signature check, because a signature over junk is still junk.
    #[error("table is not in canonical wire form")]
    NotCanonical,
    /// The responder's signature does not verify over the served table and root.
    #[error("signature does not verify against the responding node")]
    BadSignature,
}

/// What a merged table sync reports back — the §12.6 comparison, made visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableSyncOutcome {
    /// The responder's whole-table root as served.
    pub remote_root: [u8; 32],
    /// This table's whole-table root AFTER the merge.
    pub local_root_after_merge: [u8; 32],
    /// `remote_root == local_root_after_merge`. A mismatch after merging is a real signal, not
    /// an error: the roots also commit `settled`, which never crosses the mesh — a node that
    /// has not yet settled a matured block differs, and that difference must be surfaced the
    /// same day (§12.6), not clamped away.
    pub roots_match: bool,
}

/// Build a signed whole-table sync response from this node's table — the §12.6 serving side.
///
/// Built and verified through the same canonical encoding ([`shard_columns_from_accrued`] /
/// [`shard_table_sync_signing_bytes`]), so a node can never sign a response its peers would
/// refuse as non-canonical: one spelling of the predicate on both sides.
pub fn build_table_sync_response(
    identity: &NodeIdentity,
    table: &ShardTable,
) -> ShardTableSyncMessage {
    let columns = shard_columns_from_accrued(table.accrued());
    let table_root = table.compute_table_root();
    let signature = identity
        .sign(&shard_table_sync_signing_bytes(
            &identity.node_id(),
            &columns,
            &table_root,
        ))
        .to_vec();
    ShardTableSyncMessage::Response {
        responding_node: identity.node_id(),
        columns,
        table_root,
        signature,
    }
}

/// Rebuild `AccruedColumns` from the wire form, refusing anything non-canonical.
///
/// Strictly ascending on both levels (which also forbids duplicates), no empty addresses, no
/// empty columns, every value strictly positive. Refusal happens before any mutation.
fn columns_to_accrued(columns: &[crate::message::ShardColumn]) -> Option<AccruedColumns> {
    let mut accrued = AccruedColumns::new();
    let mut prev_node: Option<NodeId> = None;
    for col in columns {
        if let Some(prev) = prev_node {
            if col.node_id <= prev {
                return None;
            }
        }
        prev_node = Some(col.node_id);
        if col.cells.is_empty() {
            return None;
        }
        let mut column = BTreeMap::new();
        let mut prev_addr: Option<&str> = None;
        for (addr, value) in &col.cells {
            if addr.is_empty() || *value <= 0 {
                return None;
            }
            if let Some(prev) = prev_addr {
                if addr.as_str() <= prev {
                    return None;
                }
            }
            prev_addr = Some(addr);
            column.insert(addr.clone(), *value);
        }
        accrued.insert(col.node_id, column);
    }
    Some(accrued)
}

/// Verify a table-sync response, and only then max-merge it — the §12.6 receiving side.
///
/// Canonical form, then the responder's signature, then `ShardTable::merge_accrued` — per-cell
/// max, so a stale table loses, a duplicate is a no-op, and delivery order cannot matter.
/// `settled` is never touched: it does not ride in the message and must not (§4.4). On ANY
/// rejection the table is byte-identical to before the call.
pub fn apply_table_sync_response(
    table: &mut ShardTable,
    msg: &ShardTableSyncMessage,
) -> Result<TableSyncOutcome, ShardSyncRejection> {
    let ShardTableSyncMessage::Response {
        responding_node,
        columns,
        table_root,
        signature,
    } = msg
    else {
        return Err(ShardSyncRejection::NotAResponse);
    };

    // Canonical form first: cheap, and a valid signature over a non-canonical table is a
    // misbehaving SIGNER, not a transport error — it must not reach the merge either way.
    let accrued = columns_to_accrued(columns).ok_or(ShardSyncRejection::NotCanonical)?;

    let sig: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| ShardSyncRejection::BadSignature)?;
    let signed = shard_table_sync_signing_bytes(responding_node, columns, table_root);
    if !verify_signature(responding_node, &signed, &sig).unwrap_or(false) {
        return Err(ShardSyncRejection::BadSignature);
    }

    // Only now is the table touched.
    table.merge_accrued(&accrued);
    let local_root_after_merge = table.compute_table_root();
    Ok(TableSyncOutcome {
        remote_root: *table_root,
        local_root_after_merge,
        roots_match: local_root_after_merge == *table_root,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Bad-share evidence (§6, §12.4)
// ─────────────────────────────────────────────────────────────────────────────

/// Why a shard-evidence broadcast was refused. Every arm protects a different party:
/// the reporter's signature makes accusations attributable, the accused's signature and the
/// Merkle path stop framing, and `ShareIsValid` stops a false verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ShardEvidenceRejection {
    /// The reporter's signature does not verify — an anonymous accusation earns nothing.
    #[error("reporter signature does not verify")]
    BadReporterSignature,
    /// The carried summary is not validly signed by the node it names, so nothing binds the
    /// accused to the claimed root: a fabricated summary cannot frame anyone.
    #[error("carried summary is not validly signed by the accused")]
    BadAccusedSignature,
    /// `leaf_index` is outside the epoch's signed `share_count` (or the epoch is empty).
    #[error("leaf index is outside the summary's signed share count")]
    LeafOutOfRange,
    /// The Merkle path does not place `share.share_hash` at `leaf_index` under the accused's
    /// signed root — the share was never part of the epoch it is being blamed on.
    #[error("merkle path does not bind the share to the accused's signed root")]
    ProofDoesNotBindShare,
    /// The share passes the validity predicate: the evidence exonerates the accused, and the
    /// reporter is mistaken or malicious.
    #[error("the share is valid — the evidence exonerates the accused")]
    ShareIsValid,
}

/// A conclusive verdict: the accused signed an epoch root that commits an invalid share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardEvidenceVerdict {
    /// The node whose signed summary commits the bad share.
    pub accused: NodeId,
    /// The epoch the bad share was committed under.
    pub epoch: u64,
}

/// Re-derive the verdict from a bad-share broadcast. Pure and state-free: this NEVER touches a
/// table — grow-only state has no arm for "un-credit a liar", so what a conclusive verdict does
/// (quarantine the column, stop merging that node's summaries, publish onward) is policy and
/// belongs to the integration.
///
/// §12.4's contract is that every peer reaches the same verdict from the same bytes, and this
/// is that computation: reporter signature (accountability), accused's signature (the
/// commitment), leaf range and Merkle path (the binding), then the validity predicate (the
/// offence). The two injected functions are described at [`MerkleProofFn`] and
/// [`ShareValidityFn`] — including the content-binding requirement that stops framing.
pub fn verify_shard_evidence(
    msg: &ShardEvidenceMessage,
    verify_proof: MerkleProofFn,
    share_is_valid: ShareValidityFn,
) -> Result<ShardEvidenceVerdict, ShardEvidenceRejection> {
    if !msg.verify_reporter_signature() {
        return Err(ShardEvidenceRejection::BadReporterSignature);
    }

    let summary = &msg.summary;
    let accused_sig: [u8; 64] = summary
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ShardEvidenceRejection::BadAccusedSignature)?;
    if !verify_signature(&summary.node_id, &summary.signing_bytes(), &accused_sig)
        .unwrap_or(false)
    {
        return Err(ShardEvidenceRejection::BadAccusedSignature);
    }

    let leaf_count = summary.share_count as usize;
    if leaf_count == 0 || msg.leaf_index as usize >= leaf_count {
        return Err(ShardEvidenceRejection::LeafOutOfRange);
    }

    if !verify_proof(
        &msg.share.share_hash,
        &msg.merkle_proof,
        &summary.share_root,
        msg.leaf_index as usize,
        leaf_count,
    ) {
        return Err(ShardEvidenceRejection::ProofDoesNotBindShare);
    }

    if share_is_valid(&msg.share) {
        return Err(ShardEvidenceRejection::ShareIsValid);
    }

    Ok(ShardEvidenceVerdict {
        accused: summary.node_id,
        epoch: summary.epoch,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Leaf sampling (§6 — "sampled, asynchronous")
// ─────────────────────────────────────────────────────────────────────────────

/// The default sample size λ (§9): 20 leaves catch a node faking half its work with
/// probability ~10⁻⁶ per epoch. A tunable open decision, so a constant here rather than a
/// number scattered through call sites.
pub const DEFAULT_SAMPLE_LAMBDA: u32 = 20;

/// Domain tag for the sample-selection hash stream. Versioned like every other shard encoding:
/// changing the stream changes which leaves a given seed selects, which is harmless across
/// nodes (selection is requester-local) but must never happen silently under a fixed seed in a
/// test or a replay.
const SAMPLE_SELECT_DOMAIN: &[u8] = b"ShardSampleSelect/v1";

/// Counter-mode SHA-256 stream for the selection draw.
///
/// Not a general-purpose RNG and deliberately not one: the requirement is a deterministic
/// function of `(entropy, summary identity)` that is uniform enough for index selection, with
/// no process-global state a test cannot pin.
struct SampleStream {
    /// Hasher pre-loaded with the domain tag, the entropy and the summary binding; each draw
    /// clones it and appends the counter.
    base: sha2::Sha256,
    counter: u64,
}

impl SampleStream {
    fn next_u64(&mut self) -> u64 {
        use sha2::Digest;
        let mut h = self.base.clone();
        h.update(self.counter.to_le_bytes());
        self.counter += 1;
        let digest = h.finalize();
        u64::from_le_bytes(digest[..8].try_into().expect("SHA-256 digests hold 32 bytes"))
    }

    /// Uniform draw in `[0, m)`, `m ≥ 1`.
    ///
    /// Rejection sampling rather than a bare modulo: `2⁶⁴ mod m` residues would bias low
    /// indices, and a biased selection under-samples exactly the leaves a clever liar would
    /// then hide behind. The rejection zone is < m ≤ 2³² out of 2⁶⁴, so each draw retries with
    /// probability < 2⁻³²; the loop is deterministic given the seed (the counter advances on
    /// every draw, rejected or not).
    fn uniform(&mut self, m: u32) -> u32 {
        let m = u64::from(m);
        let accept_below = (u64::MAX / m) * m;
        loop {
            let x = self.next_u64();
            if x < accept_below {
                return (x % m) as u32;
            }
        }
    }
}

/// Choose which leaves of a summarised epoch to sample — pure, so the caller supplies the
/// randomness and any run is reproducible from `(summary, lambda, entropy)` alone.
///
/// Returns `min(lambda, share_count)` distinct indices in `[0, share_count)`, ascending. λ
/// larger than the tree is not an error: the whole tree is simply asked for. Sampling is
/// WITHOUT replacement — a repeated index re-audits a leaf already audited, spending a draw
/// without narrowing anything.
///
/// ## The unpredictability property this relies on
///
/// The audit only works if the sampled node CANNOT predict which leaves will be pulled before
/// it signs its summary. A node that can predict its samples commits fabricated work in the
/// never-sampled leaves, keeps the λ predicted ones honest, and §6's ~10⁻⁶ detection bound
/// collapses to exactly 0. So selection is derived from `entropy` — 32 bytes the REQUESTER
/// draws from its own randomness source and keeps private until the request is sent. By the
/// time the responder learns the indices, its root is signed and immutable: serving a
/// different tree yields paths that do not bind (response rejected), and re-signing a
/// friendlier summary for the same epoch is equivocation, refused against the held copy by
/// [`verify_summary_stateless`].
///
/// What BREAKS the property: deriving `entropy` from anything the responder can compute in
/// advance — a hash of the summary, chain data, a round-robin schedule, a fixed per-node seed
/// — or reusing a seed the responder has already seen in a previous request. The summary
/// binding mixed into the stream below is defence in depth against the reuse case (one leaked
/// seed does not replay the same pattern across epochs or targets); it is NOT a substitute for
/// fresh private entropy, because the responder knows its own summary.
pub fn select_sample_indices(
    summary: &EpochSummary,
    lambda: u32,
    entropy: &[u8; 32],
) -> Vec<u32> {
    use sha2::Digest;

    let n = summary.share_count;
    if n == 0 || lambda == 0 {
        return Vec::new();
    }
    if lambda >= n {
        // λ covers the tree: audit all of it. Every index, no draws.
        return (0..n).collect();
    }

    let mut base = sha2::Sha256::new();
    base.update(SAMPLE_SELECT_DOMAIN);
    base.update(entropy);
    base.update(summary.node_id);
    base.update(summary.epoch.to_le_bytes());
    base.update(summary.share_root);
    let mut stream = SampleStream { base, counter: 0 };

    // Partial Fisher–Yates over a VIRTUAL array: only the displaced positions are stored, so
    // memory is O(λ) however large the tree — and unlike draw-and-retry on a set, the draw
    // count is exactly λ regardless of how close λ is to the tree size.
    let mut displaced: BTreeMap<u32, u32> = BTreeMap::new();
    let mut picked = Vec::with_capacity(lambda as usize);
    for i in 0..lambda {
        let j = i + stream.uniform(n - i);
        let value_at_i = displaced.get(&i).copied().unwrap_or(i);
        let value_at_j = displaced.get(&j).copied().unwrap_or(j);
        picked.push(value_at_j);
        // Position i is never revisited, so only j's slot needs the swapped-in value.
        displaced.insert(j, value_at_i);
    }
    // Ascending is the request's canonical form. It leaks nothing: the SET is the sample, and
    // the responder sees it only after its root is already signed.
    picked.sort_unstable();
    picked
}

/// Build a §6 sampling request against a summary this node holds.
///
/// The request pins `(target, epoch, share_root)` from the held summary, so an equivocating
/// node cannot choose which of its signed trees to answer from, and the indices come from
/// [`select_sample_indices`] — see there for the unpredictability contract on `entropy`.
pub fn build_sample_request(
    requesting_node: NodeId,
    summary: &EpochSummary,
    lambda: u32,
    entropy: &[u8; 32],
) -> ShardSampleRequestMessage {
    ShardSampleRequestMessage {
        epoch: summary.epoch,
        target_node: summary.node_id,
        share_root: summary.share_root,
        leaf_indices: select_sample_indices(summary, lambda, entropy),
        requesting_node,
    }
}

/// Build and sign a sampling response from the summarising node's own evidence.
///
/// Pure assembly: fetching the shares and computing the paths reads storage and belongs to the
/// integration; this seals whatever the integration assembled under the responder's signature,
/// bound to the served summary's root. `identity` must be the summarising node — a response
/// signed by anyone else is refused by [`verify_sample_response`], because nobody else holds
/// the evidence or answers for the root.
pub fn build_sample_response(
    identity: &NodeIdentity,
    summary: &EpochSummary,
    leaves: Vec<ShardSampleLeaf>,
) -> ShardSampleResponseMessage {
    let mut response = ShardSampleResponseMessage {
        epoch: summary.epoch,
        responding_node: identity.node_id(),
        share_root: summary.share_root,
        leaves,
        signature: Vec::new(),
    };
    response.signature = identity.sign(&response.signing_message()).to_vec();
    response
}

/// Why a sampling response was refused. A refusal means the RESPONSE proves nothing either
/// way — it is not evidence against the accused (that requires a leaf that BINDS and then
/// fails validity) and not exoneration (the requested leaves remain unaudited).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ShardSampleRejection {
    /// The held summary itself fails structure or signature. Nothing can be judged against an
    /// unverified commitment — and evidence built on it would be refused by every peer as
    /// `BadAccusedSignature`, so the failure surfaces here instead of downstream.
    #[error("the summary sampled against does not verify statelessly")]
    SummaryUnverifiable,
    /// The request does not name the held summary's `(node, epoch, root)` — the caller paired
    /// a response with the wrong audit.
    #[error("request is not bound to the summary sampled against")]
    RequestSummaryMismatch,
    /// The response does not name the request's `(node, epoch, root)`: an answer to a
    /// different audit, or an equivocator answering from its other tree.
    #[error("response is not bound to the summary sampled against")]
    ResponseSummaryMismatch,
    /// The signature does not verify as the summarising node over the served leaves.
    #[error("responder signature does not verify against the summarising node")]
    BadResponderSignature,
    /// A served leaf the request never named, or the same index served twice. Volunteered
    /// leaves are refused even when they would verify: the audit's power is that the CHOICE of
    /// leaves was the requester's, and a responder steering extra leaves in is a responder
    /// choosing its own exam questions.
    #[error("response serves a leaf the request did not name, or serves one twice")]
    UnrequestedLeaf,
    /// A served index at or beyond the summary's signed `share_count`.
    #[error("a served leaf index is outside the summary's signed share count")]
    LeafOutOfRange,
    /// A served Merkle path does not place its share under the signed root. Indistinguishable
    /// from garbage, so the response is rejected whole — but note the asymmetry: an HONEST
    /// response can never trip this, so a responder that does is misbehaving, attributably
    /// (the junk is under its signature).
    #[error("a served merkle path does not bind its share to the signed root")]
    ProofDoesNotBindShare,
}

/// What a verified sampling response established.
#[derive(Debug, Clone)]
pub struct ShardSampleOutcome {
    /// Requested leaves served, bound to the root, and valid: audited clean.
    pub verified: Vec<u32>,
    /// Requested leaves the response did not carry. NOT forgiven — the response cap allows an
    /// honest subset (a worst-case λ of shares outgrows one envelope), so chasing these with a
    /// follow-up request, and deciding when persistent silence becomes suspicion, is the
    /// caller's policy. §6 does not specify what refusal-to-serve means; this deliberately
    /// does not guess.
    pub unanswered: Vec<u32>,
    /// One evidence broadcast per served leaf that BINDS to the signed root and fails the
    /// validity predicate — exactly the [`ShardEvidenceMessage`] that
    /// [`verify_shard_evidence`] accepts, ready to publish. Built here, in the same pass that
    /// found the bad share, because a rejection must be PUBLISHABLE evidence (§12.4) and a
    /// second evidence format would be a second thing to keep correct.
    pub evidence: Vec<ShardEvidenceMessage>,
}

/// Verify a §6 sampling response, and turn any committed-invalid leaf into publishable
/// evidence.
///
/// Pure and state-free like [`verify_shard_evidence`]: no table is touched — what a verdict
/// does (quarantine, publish, chase the unanswered) is integration policy. `reporter` signs
/// any evidence produced and `now_ms` stamps it: both are inputs because nothing in this
/// module reads an identity store or a clock.
///
/// The ordering is the same two-phase shape as the rest of this module: EVERY structural check
/// (binding to the summary, responder signature, requested/range/path per leaf) passes before
/// any verdict is formed, so `Err` means "this response proves nothing" and `Ok` verdicts are
/// never built from a response that is later refused.
pub fn verify_sample_response(
    summary: &EpochSummary,
    request: &ShardSampleRequestMessage,
    response: &ShardSampleResponseMessage,
    reporter: &NodeIdentity,
    now_ms: u64,
    verify_proof: MerkleProofFn,
    share_is_valid: ShareValidityFn,
) -> Result<ShardSampleOutcome, ShardSampleRejection> {
    use std::collections::BTreeSet;

    // The commitment being audited must itself stand up, or the verdicts downstream (and the
    // evidence's `BadAccusedSignature` gate) have nothing to rest on.
    summary
        .verify_stateless()
        .map_err(|_| ShardSampleRejection::SummaryUnverifiable)?;

    // Both messages must name THIS summary — same node, same epoch, same signed root. The root
    // check is what disarms an equivocator: it cannot answer from its other tree.
    if request.target_node != summary.node_id
        || request.epoch != summary.epoch
        || request.share_root != summary.share_root
    {
        return Err(ShardSampleRejection::RequestSummaryMismatch);
    }
    if response.responding_node != summary.node_id
        || response.epoch != summary.epoch
        || response.share_root != summary.share_root
    {
        return Err(ShardSampleRejection::ResponseSummaryMismatch);
    }

    let sig: [u8; 64] = response
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ShardSampleRejection::BadResponderSignature)?;
    if !verify_signature(&summary.node_id, &response.signing_message(), &sig).unwrap_or(false) {
        return Err(ShardSampleRejection::BadResponderSignature);
    }

    // Structural pass over every leaf, before any verdict.
    let requested: BTreeSet<u32> = request.leaf_indices.iter().copied().collect();
    let leaf_count = summary.share_count as usize;
    let mut served: BTreeSet<u32> = BTreeSet::new();
    for leaf in &response.leaves {
        if !requested.contains(&leaf.leaf_index) || !served.insert(leaf.leaf_index) {
            return Err(ShardSampleRejection::UnrequestedLeaf);
        }
        if leaf.leaf_index as usize >= leaf_count {
            return Err(ShardSampleRejection::LeafOutOfRange);
        }
        if !verify_proof(
            &leaf.share.share_hash,
            &leaf.merkle_proof,
            &summary.share_root,
            leaf.leaf_index as usize,
            leaf_count,
        ) {
            return Err(ShardSampleRejection::ProofDoesNotBindShare);
        }
    }

    // Verdict pass: every leaf is now known to be requested, in range, and bound to the signed
    // root, so a validity failure is the accused's own commitment convicting it.
    let mut verified = Vec::new();
    let mut evidence = Vec::new();
    for leaf in &response.leaves {
        if share_is_valid(&leaf.share) {
            verified.push(leaf.leaf_index);
        } else {
            let mut msg = ShardEvidenceMessage {
                summary: summary.clone(),
                share: leaf.share.clone(),
                leaf_index: leaf.leaf_index,
                merkle_proof: leaf.merkle_proof.clone(),
                reporter: reporter.node_id(),
                reporter_signature: [0u8; 64],
                timestamp: now_ms,
            };
            msg.reporter_signature = reporter.sign(&msg.signing_message());
            evidence.push(msg);
        }
    }

    let unanswered: Vec<u32> = requested.difference(&served).copied().collect();
    Ok(ShardSampleOutcome {
        verified,
        unanswered,
        evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_reconciliation::batch::{
        compute_merkle_proof, compute_merkle_root, verify_merkle_proof,
    };

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
        // `generate_without_pow` is `#[cfg(test)]`-private to ghost-common; `generate()` uses
        // the low debug-build PoW difficulty, which is what the mesh tests already pay.
        NodeIdentity::generate()
    }

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

    fn column_of(summary: &EpochSummary) -> BTreeMap<String, i64> {
        summary
            .deltas
            .iter()
            .map(|(k, r)| (k.clone(), r.total_micro))
            .collect()
    }

    fn share_never_valid(_: &ShareProof) -> bool {
        false
    }

    fn share_always_valid(_: &ShareProof) -> bool {
        true
    }

    /// Round trip for all three message types: a stored/relayed message is served verbatim, so
    /// the wire encoding must reproduce signing bytes and signatures exactly.
    #[test]
    fn all_three_shard_messages_round_trip_through_serde() {
        let id = identity();
        let (summary, evidence) =
            summarise(3, &id, &BTreeMap::new(), vec![share(10, 1, "bc1qalice", 2.0)]);

        // Summary message.
        let msg = ShardEpochSummaryMessage {
            summary: summary.clone(),
        };
        let back: ShardEpochSummaryMessage =
            serde_json::from_str(&serde_json::to_string(&msg).expect("serialises"))
                .expect("deserialises");
        assert_eq!(back.summary.signing_bytes(), summary.signing_bytes());
        assert_eq!(back.summary.signature, summary.signature);
        back.summary
            .verify(&evidence, compute_merkle_root)
            .expect("a round-tripped summary must still verify");

        // Table sync: request and response.
        let req = ShardTableSyncMessage::Request {
            requesting_node: id.node_id(),
            table_root: [0xAB; 32],
        };
        let req_back: ShardTableSyncMessage =
            serde_json::from_str(&serde_json::to_string(&req).expect("serialises"))
                .expect("deserialises");
        let ShardTableSyncMessage::Request {
            requesting_node,
            table_root,
        } = req_back
        else {
            panic!("request round-tripped into a different variant");
        };
        assert_eq!(requesting_node, id.node_id());
        assert_eq!(table_root, [0xAB; 32]);

        let mut table = ShardTable::new();
        table
            .apply_summary(&summary, &evidence, compute_merkle_root)
            .expect("verifies");
        let resp = build_table_sync_response(&id, &table);
        let resp_back: ShardTableSyncMessage =
            serde_json::from_str(&serde_json::to_string(&resp).expect("serialises"))
                .expect("deserialises");
        let mut fresh = ShardTable::new();
        let outcome =
            apply_table_sync_response(&mut fresh, &resp_back).expect("round-tripped response applies");
        assert_eq!(fresh.accrued(), table.accrued());
        assert!(outcome.roots_match, "identical tables must report matching roots");

        // Evidence message.
        let proof = compute_merkle_proof(&[evidence[0].share_hash], 0);
        let mut ev = ShardEvidenceMessage {
            summary,
            share: evidence[0].clone(),
            leaf_index: 0,
            merkle_proof: proof,
            reporter: id.node_id(),
            reporter_signature: [0u8; 64],
            timestamp: 1,
        };
        ev.reporter_signature = id.sign(&ev.signing_message());
        let ev_back: ShardEvidenceMessage =
            serde_json::from_str(&serde_json::to_string(&ev).expect("serialises"))
                .expect("deserialises");
        assert_eq!(ev_back.signing_message(), ev.signing_message());
        assert!(ev_back.verify_reporter_signature());
        assert_eq!(ev_back.accused(), ev.accused());
    }

    /// The gossip path (no shares attached) merges a verified summary's totals into the right
    /// column, and stale re-delivery loses the max — the CRDT property the mesh relies on.
    #[test]
    fn a_gossiped_summary_merges_by_max_without_evidence() {
        let a = identity();
        let (s1, _) = summarise(
            1,
            &a,
            &BTreeMap::new(),
            vec![share(10, 1, "bc1qalice", 3.0), share(11, 2, "bc1qbob", 1.0)],
        );
        let (s2, _) = summarise(2, &a, &column_of(&s1), vec![share(20, 3, "bc1qalice", 2.0)]);

        let mut table = ShardTable::new();
        apply_shard_epoch_summary(
            &mut table,
            &ShardEpochSummaryMessage { summary: s1.clone() },
            None,
            None,
            compute_merkle_root,
        )
        .expect("epoch 1 verifies statelessly");
        assert_eq!(table.owed().get("bc1qalice"), Some(&3_000_000));

        apply_shard_epoch_summary(
            &mut table,
            &ShardEpochSummaryMessage { summary: s2.clone() },
            Some(&s1),
            None,
            compute_merkle_root,
        )
        .expect("epoch 2 chains and verifies");
        assert_eq!(table.owed().get("bc1qalice"), Some(&5_000_000));
        assert_eq!(table.owed().get("bc1qbob"), Some(&1_000_000));
        let settled_state = table.compute_table_root();

        // Stale epoch-1 summary re-delivered out of order: harmless, loses the max.
        apply_shard_epoch_summary(
            &mut table,
            &ShardEpochSummaryMessage { summary: s1 },
            None,
            None,
            compute_merkle_root,
        )
        .expect("stale summaries still verify");
        assert_eq!(
            table.compute_table_root(),
            settled_state,
            "a stale summary must lose the max, not roll the column back"
        );
    }

    /// A summary whose signature fails must never mutate state — on either verification depth.
    /// A max cannot be undone, so checking after merging is not checking at all (§12.3).
    #[test]
    fn a_bad_signature_never_mutates_the_table() {
        let a = identity();
        let evidence = vec![share(10, 1, "bc1qalice", 3.0)];
        let (good, _) = summarise(1, &a, &BTreeMap::new(), evidence.clone());

        let mut forged = good.clone();
        forged
            .deltas
            .get_mut("bc1qalice")
            .expect("row")
            .total_micro = i64::MAX / 2;

        let mut table = ShardTable::new();
        table.accrue([0x77; 32], "bc1qcarol", 42);
        let untouched = table.compute_table_root();

        // Gossip path.
        assert_eq!(
            apply_shard_epoch_summary(
                &mut table,
                &ShardEpochSummaryMessage {
                    summary: forged.clone()
                },
                None,
                None,
                compute_merkle_root,
            ),
            Err(ShardSummaryRejection::Summary(
                SummaryRejection::BadSignature
            ))
        );
        assert_eq!(table.compute_table_root(), untouched);

        // Evidence path delegates to the data model's gate and must refuse identically.
        assert_eq!(
            apply_shard_epoch_summary(
                &mut table,
                &ShardEpochSummaryMessage { summary: forged },
                None,
                Some(&evidence),
                compute_merkle_root,
            ),
            Err(ShardSummaryRejection::Summary(
                SummaryRejection::BadSignature
            ))
        );
        assert_eq!(table.compute_table_root(), untouched);

        // And the honest summary still lands: the gate is a gate, not a wall.
        apply_shard_epoch_summary(
            &mut table,
            &ShardEpochSummaryMessage { summary: good },
            None,
            Some(&evidence),
            compute_merkle_root,
        )
        .expect("verifies");
        assert_ne!(table.compute_table_root(), untouched);
    }

    /// §6's chain check: consecutive summaries must satisfy `total == prior total + delta`, and
    /// two different signed summaries for the same epoch are equivocation. Both leave the table
    /// byte-identical.
    #[test]
    fn chain_breaks_and_equivocation_are_refused_before_any_merge() {
        let a = identity();
        let (s1, _) = summarise(1, &a, &BTreeMap::new(), vec![share(10, 1, "bc1qalice", 3.0)]);

        // Epoch 2 signed over a total that skips ahead of the chain by 1 micro.
        let mut inflated_prior = column_of(&s1);
        *inflated_prior.get_mut("bc1qalice").expect("row") += 1;
        let (s2_bad, _) = summarise(2, &a, &inflated_prior, vec![share(20, 2, "bc1qalice", 2.0)]);

        let mut table = ShardTable::new();
        apply_shard_epoch_summary(
            &mut table,
            &ShardEpochSummaryMessage { summary: s1.clone() },
            None,
            None,
            compute_merkle_root,
        )
        .expect("epoch 1 verifies");
        let before = table.compute_table_root();

        assert_eq!(
            apply_shard_epoch_summary(
                &mut table,
                &ShardEpochSummaryMessage { summary: s2_bad },
                Some(&s1),
                None,
                compute_merkle_root,
            ),
            Err(ShardSummaryRejection::ChainMismatch)
        );
        assert_eq!(table.compute_table_root(), before);

        // Same epoch, different signed content: equivocation.
        let (s1_other, _) = summarise(1, &a, &BTreeMap::new(), vec![share(11, 3, "bc1qbob", 5.0)]);
        assert_eq!(
            apply_shard_epoch_summary(
                &mut table,
                &ShardEpochSummaryMessage { summary: s1_other },
                Some(&s1),
                None,
                compute_merkle_root,
            ),
            Err(ShardSummaryRejection::SummaryEquivocation)
        );
        assert_eq!(table.compute_table_root(), before);

        // An identical re-delivery of the held epoch is NOT equivocation — merge is idempotent.
        apply_shard_epoch_summary(
            &mut table,
            &ShardEpochSummaryMessage { summary: s1.clone() },
            Some(&s1),
            None,
            compute_merkle_root,
        )
        .expect("duplicate delivery is harmless");
        assert_eq!(table.compute_table_root(), before);
    }

    /// The §12.6 exchange end to end: a built response applies cleanly; a tampered or
    /// non-canonical one is refused with the table byte-identical; and the root comparison
    /// surfaces a settlement difference instead of hiding it.
    #[test]
    fn table_sync_verifies_then_merges_and_surfaces_drift() {
        let server = identity();
        let (s1, ev1) = summarise(
            1,
            &server,
            &BTreeMap::new(),
            vec![share(10, 1, "bc1qalice", 3.0), share(11, 2, "bc1qbob", 1.0)],
        );
        let mut server_table = ShardTable::new();
        server_table
            .apply_summary(&s1, &ev1, compute_merkle_root)
            .expect("verifies");

        // Clean apply onto an empty table.
        let resp = build_table_sync_response(&server, &server_table);
        let mut client = ShardTable::new();
        let outcome = apply_table_sync_response(&mut client, &resp).expect("applies");
        assert_eq!(client.accrued(), server_table.accrued());
        assert!(outcome.roots_match);

        // A request is not mergeable material.
        let mut untouched_check = client.clone();
        assert_eq!(
            apply_table_sync_response(
                &mut untouched_check,
                &ShardTableSyncMessage::Request {
                    requesting_node: server.node_id(),
                    table_root: [0; 32],
                },
            ),
            Err(ShardSyncRejection::NotAResponse)
        );

        // Tampered cell: signature no longer covers it; table byte-identical.
        let before = client.compute_table_root();
        let ShardTableSyncMessage::Response {
            responding_node,
            columns,
            table_root,
            signature,
        } = resp.clone()
        else {
            panic!("built a request?");
        };
        let mut tampered_columns = columns.clone();
        tampered_columns[0].cells[0].1 = i64::MAX / 2;
        let tampered = ShardTableSyncMessage::Response {
            responding_node,
            columns: tampered_columns,
            table_root,
            signature: signature.clone(),
        };
        assert_eq!(
            apply_table_sync_response(&mut client, &tampered),
            Err(ShardSyncRejection::BadSignature)
        );
        assert_eq!(client.compute_table_root(), before);

        // A VALIDLY SIGNED but non-canonical table (cells out of order) is refused too: the
        // signer is misbehaving, and non-canonical form must never reach the merge.
        let mut disordered = columns.clone();
        disordered[0].cells.reverse();
        let signed = shard_table_sync_signing_bytes(
            &server.node_id(),
            &disordered,
            &table_root,
        );
        let bad_form = ShardTableSyncMessage::Response {
            responding_node: server.node_id(),
            columns: disordered,
            table_root,
            signature: server.sign(&signed).to_vec(),
        };
        assert_eq!(
            apply_table_sync_response(&mut client, &bad_form),
            Err(ShardSyncRejection::NotCanonical)
        );
        assert_eq!(client.compute_table_root(), before);

        // Drift surfacing: the server settles a payout the client has not read yet. The merge
        // still succeeds (accrued is unchanged) but the roots MUST differ — settled is part of
        // the payable state, and hiding the difference is how drift goes unnoticed a quarter.
        server_table.record_settled("bc1qalice", 1_000_000);
        let resp2 = build_table_sync_response(&server, &server_table);
        let outcome2 = apply_table_sync_response(&mut client, &resp2).expect("applies");
        assert!(
            !outcome2.roots_match,
            "a settlement difference must surface as a root mismatch"
        );
        assert_eq!(
            client.settled().len(),
            0,
            "settled must NEVER be merged from a peer"
        );
    }

    /// §12.4 end to end with the REAL Merkle verifier: conclusive against a committed invalid
    /// share; refused when the share is valid, when the path does not bind, when the leaf is out
    /// of range, and when either signature fails.
    #[test]
    fn shard_evidence_convicts_and_refuses_framing() {
        let accused = identity();
        let reporter = identity();
        let shares = vec![
            share(10, 1, "bc1qalice", 3.0),
            share(11, 2, "bc1qbob", 1.0),
            share(12, 3, "bc1qalice", 2.0),
        ];
        let (summary, ordered) = summarise(5, &accused, &BTreeMap::new(), shares);
        // Canonical leaf order is what the root was computed over.
        let leaves: Vec<[u8; 32]> = {
            let mut sorted = ordered.clone();
            ghost_common::share_batch::canonical_sort(&mut sorted);
            sorted.iter().map(|s| s.share_hash).collect()
        };
        let idx = 1usize;
        let bad_share = ordered
            .iter()
            .find(|s| s.share_hash == leaves[idx])
            .expect("leaf exists")
            .clone();

        let mut msg = ShardEvidenceMessage {
            summary: summary.clone(),
            share: bad_share,
            leaf_index: idx as u32,
            merkle_proof: compute_merkle_proof(&leaves, idx),
            reporter: reporter.node_id(),
            reporter_signature: [0u8; 64],
            timestamp: 1,
        };
        msg.reporter_signature = reporter.sign(&msg.signing_message());

        // Conclusive: the injected validity check fails the share, the path binds it.
        let verdict = verify_shard_evidence(&msg, verify_merkle_proof, share_never_valid)
            .expect("evidence is conclusive");
        assert_eq!(verdict.accused, accused.node_id());
        assert_eq!(verdict.epoch, 5);

        // The same bytes exonerate when the share is actually valid.
        assert_eq!(
            verify_shard_evidence(&msg, verify_merkle_proof, share_always_valid),
            Err(ShardEvidenceRejection::ShareIsValid)
        );

        // A share the epoch never committed: path cannot bind it.
        let mut foreign = msg.clone();
        foreign.share = share(99, 0xEE, "bc1qmallory", 9.0);
        foreign.reporter_signature = reporter.sign(&foreign.signing_message());
        assert_eq!(
            verify_shard_evidence(&foreign, verify_merkle_proof, share_never_valid),
            Err(ShardEvidenceRejection::ProofDoesNotBindShare)
        );

        // Leaf index outside the signed share_count.
        let mut out_of_range = msg.clone();
        out_of_range.leaf_index = summary.share_count;
        out_of_range.reporter_signature = reporter.sign(&out_of_range.signing_message());
        assert_eq!(
            verify_shard_evidence(&out_of_range, verify_merkle_proof, share_never_valid),
            Err(ShardEvidenceRejection::LeafOutOfRange)
        );

        // A summary the accused never signed cannot frame them.
        let mut framed = msg.clone();
        framed.summary.share_root = [0xEE; 32];
        framed.reporter_signature = reporter.sign(&framed.signing_message());
        assert_eq!(
            verify_shard_evidence(&framed, verify_merkle_proof, share_never_valid),
            Err(ShardEvidenceRejection::BadAccusedSignature)
        );

        // A tampered relay breaks the reporter's signature before anything else runs.
        let mut relayed = msg.clone();
        relayed.leaf_index = 0; // content changed, signature not re-made
        assert_eq!(
            verify_shard_evidence(&relayed, verify_merkle_proof, share_never_valid),
            Err(ShardEvidenceRejection::BadReporterSignature)
        );
    }

    /// A raw summary for selection tests: selection reads only the identity fields and
    /// `share_count`, never the signature, so no signing is needed to exercise it.
    fn unsigned_summary(share_count: u32) -> EpochSummary {
        EpochSummary {
            epoch: 7,
            node_id: [0x42; 32],
            deltas: BTreeMap::new(),
            share_count,
            share_root: [0x24; 32],
            signature: Vec::new(),
        }
    }

    /// A served leaf for canonical index `idx`, with its real Merkle path.
    fn sample_leaf(
        ordered: &[ShareProof],
        leaves: &[[u8; 32]],
        idx: usize,
    ) -> crate::message::ShardSampleLeaf {
        crate::message::ShardSampleLeaf {
            leaf_index: idx as u32,
            share: ordered
                .iter()
                .find(|s| s.share_hash == leaves[idx])
                .expect("leaf exists")
                .clone(),
            merkle_proof: compute_merkle_proof(leaves, idx),
        }
    }

    /// A summarised epoch of `n` shares plus its canonical leaf order — the fixture every
    /// sampling test audits against.
    fn sampled_epoch(
        accused: &NodeIdentity,
        n: u8,
    ) -> (EpochSummary, Vec<ShareProof>, Vec<[u8; 32]>) {
        let shares: Vec<ShareProof> = (1..=n)
            .map(|i| share(10 + i as u64, i, "bc1qalice", 2.0))
            .collect();
        let (summary, ordered) = summarise(5, accused, &BTreeMap::new(), shares);
        let leaves: Vec<[u8; 32]> = {
            let mut sorted = ordered.clone();
            ghost_common::share_batch::canonical_sort(&mut sorted);
            sorted.iter().map(|s| s.share_hash).collect()
        };
        (summary, ordered, leaves)
    }

    /// The selection policy's whole contract: deterministic under one seed, without
    /// replacement, in range, ascending; a different seed or a different summary moves the
    /// sample; λ at or past the tree asks for all of it; and the degenerate sizes are empty.
    #[test]
    fn selection_is_deterministic_without_replacement_and_covers_small_trees() {
        let summary = unsigned_summary(1_000);
        let entropy = [0xA5; 32];

        let picked = select_sample_indices(&summary, 20, &entropy);
        assert_eq!(picked.len(), 20, "λ=20 against 1,000 leaves must pick 20");
        assert!(
            picked.windows(2).all(|w| w[0] < w[1]),
            "indices must be strictly ascending — sorted AND without replacement"
        );
        assert!(picked.iter().all(|&i| i < 1_000), "an index escaped the tree");
        assert_eq!(
            picked,
            select_sample_indices(&summary, 20, &entropy),
            "the same randomness must reproduce the same sample — selection is pure"
        );

        // Different requester randomness: a different sample. This is the audit's whole value —
        // nothing the RESPONDER holds (it knows its own summary) can predict the indices.
        assert_ne!(
            picked,
            select_sample_indices(&summary, 20, &[0x5A; 32]),
            "two seeds produced one sample"
        );

        // Defence in depth: one leaked seed must not replay the same pattern against another
        // epoch or another root of the same size.
        let mut other_root = unsigned_summary(1_000);
        other_root.share_root = [0xEE; 32];
        assert_ne!(picked, select_sample_indices(&other_root, 20, &entropy));
        let mut other_epoch = unsigned_summary(1_000);
        other_epoch.epoch += 1;
        assert_ne!(picked, select_sample_indices(&other_epoch, 20, &entropy));

        // λ ≥ tree: ask for all of it, not an error.
        let small = unsigned_summary(7);
        let all: Vec<u32> = (0..7).collect();
        assert_eq!(select_sample_indices(&small, 20, &entropy), all);
        assert_eq!(select_sample_indices(&small, 7, &entropy), all);

        // Degenerate sizes select nothing.
        assert!(select_sample_indices(&unsigned_summary(0), 20, &entropy).is_empty());
        assert!(select_sample_indices(&summary, 0, &entropy).is_empty());

        // Without-replacement, pinned where replacement CANNOT hide: at λ = n−1 the draw path
        // (not the ask-for-all shortcut) nearly exhausts the tree, so a selection that fails to
        // track displaced values collides on almost every seed. λ=20-of-1,000 above cannot see
        // that bug — a collision there is a ~20% event per seed, and one lucky seed hides it.
        let dense = unsigned_summary(30);
        for seed in 0..64u8 {
            let picked = select_sample_indices(&dense, 29, &[seed; 32]);
            assert_eq!(picked.len(), 29);
            assert!(
                picked.windows(2).all(|w| w[0] < w[1]),
                "seed {seed}: a repeated index — sampling is replacing"
            );
        }

        // And the built request pins exactly the summary it audits, indices included.
        let req = build_sample_request([0x77; 32], &summary, 20, &entropy);
        assert_eq!(req.epoch, summary.epoch);
        assert_eq!(req.target_node, summary.node_id);
        assert_eq!(req.share_root, summary.share_root);
        assert_eq!(req.leaf_indices, picked);
        assert_eq!(req.requesting_node, [0x77; 32]);
    }

    /// Every draw of `[0, m)` must be reachable, or some leaves are structurally never audited
    /// — a permanent hiding place. With λ = n−1 over many seeds, an unreachable index shows up
    /// as one that only ever appears via the "all of it" path, never via draws.
    #[test]
    fn selection_reaches_every_leaf_across_seeds() {
        let summary = unsigned_summary(11);
        let mut seen = [false; 11];
        for seed in 0..64u8 {
            for &i in &select_sample_indices(&summary, 10, &[seed; 32]) {
                seen[i as usize] = true;
            }
        }
        assert!(
            seen.iter().all(|&s| s),
            "some leaf was never selected across 64 seeds at λ=n−1 — a hiding place: {seen:?}"
        );
    }

    /// Structural refusals, each leaving nothing to act on: a response that fails ANY check
    /// proves nothing, so `Err` — never a partial verdict. The Merkle-path arm is the one the
    /// task turns on: a served leaf whose path does not bind rejects the response whole.
    #[test]
    fn a_response_that_fails_structure_is_rejected_whole() {
        let accused = identity();
        let reporter = identity();
        let (summary, ordered, leaves) = sampled_epoch(&accused, 4);
        let entropy = [0x11; 32];
        let request = build_sample_request(reporter.node_id(), &summary, 2, &entropy);
        assert_eq!(request.leaf_indices.len(), 2);

        let served: Vec<_> = request
            .leaf_indices
            .iter()
            .map(|&i| sample_leaf(&ordered, &leaves, i as usize))
            .collect();
        let good = build_sample_response(&accused, &summary, served.clone());

        // The honest exchange verifies clean, fully answered.
        let outcome = verify_sample_response(
            &summary,
            &request,
            &good,
            &reporter,
            1,
            verify_merkle_proof,
            share_always_valid,
        )
        .expect("an honest response verifies");
        assert_eq!(outcome.verified, request.leaf_indices);
        assert!(outcome.unanswered.is_empty());
        assert!(outcome.evidence.is_empty());

        let check = |response: &ShardSampleResponseMessage| {
            verify_sample_response(
                &summary,
                &request,
                response,
                &reporter,
                1,
                verify_merkle_proof,
                share_always_valid,
            )
        };

        // A leaf whose Merkle path does not bind: here, the right share under the WRONG path
        // (the other requested leaf's), which is exactly what serving a substituted share
        // looks like.
        let mut crossed = served.clone();
        crossed[0].merkle_proof = served[1].merkle_proof.clone();
        let crossed_response = build_sample_response(&accused, &summary, crossed);
        assert_eq!(
            check(&crossed_response).unwrap_err(),
            ShardSampleRejection::ProofDoesNotBindShare
        );

        // A volunteered leaf the request never named — refused even though it would verify.
        let extra_idx = (0..4usize)
            .find(|i| !request.leaf_indices.contains(&(*i as u32)))
            .expect("λ=2 of 4 leaves two unrequested");
        let mut volunteered = served.clone();
        volunteered.push(sample_leaf(&ordered, &leaves, extra_idx));
        let volunteered_response = build_sample_response(&accused, &summary, volunteered);
        assert_eq!(
            check(&volunteered_response).unwrap_err(),
            ShardSampleRejection::UnrequestedLeaf
        );

        // The same leaf twice is the same refusal.
        let mut doubled = served.clone();
        doubled.push(served[0].clone());
        let doubled_response = build_sample_response(&accused, &summary, doubled);
        assert_eq!(
            check(&doubled_response).unwrap_err(),
            ShardSampleRejection::UnrequestedLeaf
        );

        // An index past the signed share_count, even when the request (corrupt or confused)
        // asked for it.
        let mut oob_request = request.clone();
        oob_request.leaf_indices = vec![summary.share_count];
        let mut oob_leaf = served[0].clone();
        oob_leaf.leaf_index = summary.share_count;
        let oob_response = build_sample_response(&accused, &summary, vec![oob_leaf]);
        assert_eq!(
            verify_sample_response(
                &summary,
                &oob_request,
                &oob_response,
                &reporter,
                1,
                verify_merkle_proof,
                share_always_valid,
            )
            .unwrap_err(),
            ShardSampleRejection::LeafOutOfRange
        );

        // Tampered after signing: the responder's signature no longer covers the leaves.
        let mut tampered = good.clone();
        tampered.leaves[0].leaf_index = request.leaf_indices[1];
        assert_eq!(
            check(&tampered)
            .unwrap_err(),
            ShardSampleRejection::BadResponderSignature
        );

        // An impostor CLAIMING the summarising node's identity but signing with its own key —
        // nobody else answers for the root.
        let impostor = identity();
        let mut forged = build_sample_response(&impostor, &summary, served.clone());
        forged.responding_node = summary.node_id;
        forged.signature = impostor.sign(&forged.signing_message()).to_vec();
        assert_eq!(
            check(&forged).unwrap_err(),
            ShardSampleRejection::BadResponderSignature
        );

        // The same impostor answering honestly under its OWN id is caught earlier still: the
        // response is simply not bound to the summary being audited.
        let honest_impostor = build_sample_response(&impostor, &summary, served.clone());
        assert_eq!(
            check(&honest_impostor).unwrap_err(),
            ShardSampleRejection::ResponseSummaryMismatch
        );

        // A response naming a different root: an equivocator answering from its other tree.
        let mut other_tree = good.clone();
        other_tree.share_root = [0xEE; 32];
        assert_eq!(
            check(&other_tree)
            .unwrap_err(),
            ShardSampleRejection::ResponseSummaryMismatch
        );

        // A request paired against the wrong summary.
        let (other_summary, _, _) = sampled_epoch(&identity(), 4);
        let wrong_request = build_sample_request(reporter.node_id(), &other_summary, 2, &entropy);
        assert_eq!(
            verify_sample_response(
                &summary,
                &wrong_request,
                &good,
                &reporter,
                1,
                verify_merkle_proof,
                share_always_valid,
            )
            .unwrap_err(),
            ShardSampleRejection::RequestSummaryMismatch
        );

        // A summary that does not verify statelessly judges nothing.
        let mut broken = summary.clone();
        broken.signature = vec![0xAA; 64];
        assert_eq!(
            verify_sample_response(
                &broken,
                &request,
                &good,
                &reporter,
                1,
                verify_merkle_proof,
                share_always_valid,
            )
            .unwrap_err(),
            ShardSampleRejection::SummaryUnverifiable
        );
    }

    /// The §6 loop closed end to end: a sampled leaf that binds to the signed root but fails
    /// validity comes back as evidence that IS the `verify_shard_evidence` format — same
    /// bytes, same verdict, nothing translated. A subset response leaves the rest unanswered,
    /// not forgiven.
    #[test]
    fn a_failed_sample_becomes_evidence_the_evidence_path_accepts() {
        let accused = identity();
        let reporter = identity();
        let (summary, ordered, leaves) = sampled_epoch(&accused, 5);
        let request = build_sample_request(reporter.node_id(), &summary, 3, &[0x33; 32]);
        assert_eq!(request.leaf_indices.len(), 3);

        // The responder answers only the first two requested leaves — an allowed subset.
        let served: Vec<_> = request.leaf_indices[..2]
            .iter()
            .map(|&i| sample_leaf(&ordered, &leaves, i as usize))
            .collect();
        let response = build_sample_response(&accused, &summary, served);

        let outcome = verify_sample_response(
            &summary,
            &request,
            &response,
            &reporter,
            99,
            verify_merkle_proof,
            share_never_valid,
        )
        .expect("a structurally sound response verifies even when its shares are bad");

        assert!(outcome.verified.is_empty());
        assert_eq!(
            outcome.unanswered,
            vec![request.leaf_indices[2]],
            "an unserved requested leaf must be surfaced, not forgiven"
        );
        assert_eq!(outcome.evidence.len(), 2, "one broadcast per bad committed leaf");

        for (ev, &idx) in outcome.evidence.iter().zip(&request.leaf_indices[..2]) {
            assert_eq!(ev.leaf_index, idx);
            assert_eq!(ev.reporter, reporter.node_id());
            assert_eq!(ev.timestamp, 99);
            // The one-format guarantee: the evidence handler reaches the conviction from these
            // exact bytes with the REAL Merkle verifier.
            let verdict = verify_shard_evidence(ev, verify_merkle_proof, share_never_valid)
                .expect("sampling evidence must be exactly what the evidence path accepts");
            assert_eq!(verdict.accused, accused.node_id());
            assert_eq!(verdict.epoch, summary.epoch);
        }
    }

    /// Round trip for the sampling pair: a request and a response served across the mesh must
    /// re-verify from their wire bytes alone — signature, binding and verdicts intact.
    #[test]
    fn sample_request_and_response_round_trip_through_serde() {
        let accused = identity();
        let reporter = identity();
        let (summary, ordered, leaves) = sampled_epoch(&accused, 3);
        let request = build_sample_request(reporter.node_id(), &summary, 2, &[0x44; 32]);
        let served: Vec<_> = request
            .leaf_indices
            .iter()
            .map(|&i| sample_leaf(&ordered, &leaves, i as usize))
            .collect();
        let response = build_sample_response(&accused, &summary, served);

        let request_back: ShardSampleRequestMessage =
            serde_json::from_str(&serde_json::to_string(&request).expect("serialises"))
                .expect("deserialises");
        assert_eq!(request_back, request);

        let response_back: ShardSampleResponseMessage =
            serde_json::from_str(&serde_json::to_string(&response).expect("serialises"))
                .expect("deserialises");
        assert_eq!(
            response_back.signing_message(),
            response.signing_message(),
            "wire encoding must reproduce the signing bytes exactly"
        );

        let outcome = verify_sample_response(
            &summary,
            &request_back,
            &response_back,
            &reporter,
            1,
            verify_merkle_proof,
            share_always_valid,
        )
        .expect("a round-tripped exchange still verifies");
        assert_eq!(outcome.verified, request.leaf_indices);
    }
}
