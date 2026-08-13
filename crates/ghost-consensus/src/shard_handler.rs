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
    ShardEvidenceMessage, ShardTableSyncMessage,
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
    // Structure first — malformed is malformed regardless of who signed it. Same predicate
    // spelling as `EpochSummary::verify`.
    for row in summary.deltas.values() {
        if row.delta_micro < 0 || row.total_micro < row.delta_micro {
            return Err(SummaryRejection::MalformedDeltas.into());
        }
    }

    // Signature second — an unsigned claim does not earn the comparisons below.
    let sig: [u8; 64] = summary
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ShardSummaryRejection::Summary(SummaryRejection::BadSignature))?;
    if !verify_signature(&summary.node_id, &summary.signing_bytes(), &sig).unwrap_or(false) {
        return Err(SummaryRejection::BadSignature.into());
    }

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
}
