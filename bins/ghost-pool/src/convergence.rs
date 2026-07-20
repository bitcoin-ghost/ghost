//! GHOST-03: ledger convergence.
//!
//! Share propagation is best-effort gossip, so a partition or a dropped
//! broadcast leaves a node permanently missing shares — which, combined with
//! GHOST-02, would let a divergent-but-internally-balanced payout be approved.
//! The `ShareConvergence` request/response message types existed but were never
//! built, sent, or handled. This module implements the protocol:
//!
//! 1. A node advertises the share hashes it holds for a round (a *request*).
//! 2. A peer replies with the full **signed** proofs the requester is missing
//!    (a *response*).
//! 3. The requester applies each missing proof through the normal path, which
//!    re-verifies the GHOST-09 `received_by` signature before crediting.
//!
//! The full signed proofs are re-servable because `RoundManager` retains them
//! per round (see `recent_proofs`). Without that, a node could only detect
//! divergence, not repair it.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use tracing::warn;

use ghost_common::error::GhostResult;
use ghost_common::types::RoundId;
use ghost_consensus::mesh::MessageHandler;
use ghost_consensus::message::{
    MessageEnvelope, MessageType, ShareConvergenceMessage, ShareConvergenceResponse,
};

use crate::round::RoundManager;

/// Wire payload carried under `MessageType::ShareConvergence`. Disambiguates a
/// reconciliation request from a response without adding a second message type
/// (and the exhaustive `MessageType` matches that would come with it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConvergencePayload {
    Request(ShareConvergenceMessage),
    Response(ShareConvergenceResponse),
    /// GHOST-03: reconcile the UNPAID LEDGER over a time window, not a single round.
    ///
    /// The round-scoped exchange above can only repair the round in flight — and rounds rotate
    /// every ~90s, with signed proofs pruned after 10 of them. Anything a node dropped outside
    /// that ~15-minute window was unrecoverable, so every node's ledger drifted permanently and
    /// each summed a different share set. Since the payout is computed from the unpaid ledger and
    /// GHOST-02 compares the resulting split for EXACT equality, that divergence means every node
    /// rejects every payout, forever, with nothing able to repair it.
    ///
    /// The window is bounded so the advertisement stays a sane size; the caller sweeps.
    LedgerRequest(LedgerConvergenceRequest),
    LedgerResponse(LedgerConvergenceResponse),
}

/// Advertises the unpaid shares this node holds in `[since_ts, until_ts)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerConvergenceRequest {
    pub since_ts: i64,
    pub until_ts: i64,
    /// Canonical (internal byte order) share hashes we already have.
    pub share_hashes: Vec<String>,
}

/// The signed proofs the responder holds in that window which the requester did not advertise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerConvergenceResponse {
    pub since_ts: i64,
    pub until_ts: i64,
    /// Canonical JSON of each missing `ShareProof`.
    pub proofs: Vec<Vec<u8>>,
    /// Unpaid shares in the window the responder holds but CANNOT serve, because they predate
    /// schema v41 and their signature no longer exists. Reported so the divergence is visible
    /// rather than silent — no protocol can reconcile these, only a one-time operation.
    pub unservable: usize,
}

/// Cap on proofs served in one response, so a wide window cannot produce an enormous message.
const MAX_PROOFS_PER_RESPONSE: usize = 2_000;

/// Broadcasts a serialized [`ConvergencePayload`] to the mesh under
/// `MessageType::ShareConvergence`. Supplied by production wiring; `None` in
/// tests that drive the exchange directly.
pub type ConvergenceSendFn = Arc<dyn Fn(Vec<u8>) -> GhostResult<()> + Send + Sync>;

/// Drives ledger convergence for one node against its [`RoundManager`].
pub struct ConvergenceHandler {
    round_manager: Arc<RoundManager>,
    send: Option<ConvergenceSendFn>,
    db: Option<Arc<ghost_storage::Database>>,
}

impl ConvergenceHandler {
    pub fn new(round_manager: Arc<RoundManager>) -> Self {
        Self {
            round_manager,
            send: None,
            db: None,
        }
    }

    /// Attach the mesh broadcast used to reply to requests in production.
    pub fn with_send(mut self, send: ConvergenceSendFn) -> Self {
        self.send = Some(send);
        self
    }

    /// Attach the database so backfilled proofs also adopt their signed payout
    /// address (GHOST-02 / Option A), keeping addresses converged on the
    /// convergence path as well as the gossip path.
    pub fn with_db(mut self, db: Arc<ghost_storage::Database>) -> Self {
        self.db = Some(db);
        self
    }

    /// Advertise the unpaid shares we hold in `[since_ts, until_ts)`.
    pub fn build_ledger_request(
        &self,
        since_ts: i64,
        until_ts: i64,
    ) -> GhostResult<LedgerConvergenceRequest> {
        let share_hashes = match &self.db {
            Some(db) => db.unpaid_share_hashes_in(since_ts, until_ts)?,
            None => Vec::new(),
        };
        Ok(LedgerConvergenceRequest {
            since_ts,
            until_ts,
            share_hashes,
        })
    }

    pub fn ledger_request_bytes(&self, since_ts: i64, until_ts: i64) -> GhostResult<Vec<u8>> {
        let payload =
            ConvergencePayload::LedgerRequest(self.build_ledger_request(since_ts, until_ts)?);
        serde_json::to_vec(&payload)
            .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))
    }

    /// Serve the signed proofs we hold in the requester's window that they did not advertise.
    pub fn handle_ledger_request(
        &self,
        req: &LedgerConvergenceRequest,
    ) -> LedgerConvergenceResponse {
        let theirs: std::collections::HashSet<String> = req.share_hashes.iter().cloned().collect();
        let (proofs, unservable) = match &self.db {
            Some(db) => db
                .unpaid_proofs_missing_from(
                    req.since_ts,
                    req.until_ts,
                    &theirs,
                    MAX_PROOFS_PER_RESPONSE,
                )
                .unwrap_or_default(),
            None => (Vec::new(), 0),
        };
        LedgerConvergenceResponse {
            since_ts: req.since_ts,
            until_ts: req.until_ts,
            proofs,
            unservable,
        }
    }

    /// Apply served proofs to our ledger. Each is GHOST-09 verified before it is credited —
    /// convergence bypasses the normal share-receive gate, so a forged backfill must not pass.
    pub fn apply_ledger_response(&self, resp: &LedgerConvergenceResponse) -> usize {
        let mut applied = 0;
        for blob in &resp.proofs {
            let Ok(proof) = serde_json::from_slice::<ghost_common::types::ShareProof>(blob) else {
                continue;
            };
            if !proof.has_valid_received_by_signature() {
                continue; // never credit an unsigned or forged backfill
            }
            if self.accept_proof(&proof) {
                applied += 1;
            }
        }
        if resp.unservable > 0 {
            warn!(
                unservable = resp.unservable,
                since = resp.since_ts,
                until = resp.until_ts,
                "GHOST-03: peer holds unpaid shares it CANNOT serve (pre-v41, signature gone) — \
                 these cannot be reconciled by any protocol and leave the ledgers divergent"
            );
        }
        applied
    }

    /// Credit a verified proof to both the in-memory round view and the `shares` TABLE.
    ///
    /// The table is the only thing the payout ledger reads, so a backfill that lands only in
    /// memory repairs nothing that matters. Idempotent — UNIQUE(share_hash) is the dedup.
    fn accept_proof(&self, proof: &ghost_common::types::ShareProof) -> bool {
        let miner_hex = hex::encode(&proof.miner_id[..8]);
        let from_node = hex::encode(&proof.received_by[..4]);
        let share_hash = hex::encode(proof.share_hash);
        let round_id = proof.round_id;
        let work = proof.work;
        let timestamp = proof.timestamp as i64;

        if self
            .round_manager
            .handle_share_proof(proof.clone())
            .is_err()
        {
            return false;
        }

        let Some(db) = &self.db else {
            return true;
        };

        let record = ghost_storage::models::ShareRecord {
            id: None,
            round_id,
            miner_id: miner_hex.clone(),
            difficulty: work,
            work,
            share_hash,
            timestamp,
            received_by: from_node,
            valid: true,
        };
        let blob = serde_json::to_vec(proof).unwrap_or_default();

        match db.insert_share_with_proof(&record, &blob) {
            Ok(_) => {
                if let Err(e) = db.increment_miner_stats(&miner_hex, 1, work) {
                    warn!(miner = %miner_hex, error = %e, "GHOST-03: miner stats bump failed");
                }
            }
            Err(e) => {
                if !e.to_string().contains("UNIQUE") {
                    warn!(miner = %miner_hex, error = %e, "GHOST-03: backfill persist failed");
                }
            }
        }

        if let Some(addr) = &proof.payout_address {
            let _ = db.adopt_miner_address(&miner_hex, addr);
        }
        true
    }

    /// Build a convergence REQUEST advertising the shares we hold for `round_id`.
    pub fn build_request(&self, round_id: RoundId) -> ShareConvergenceMessage {
        let (share_count, total_work) = self.round_manager.round_share_summary(round_id);
        ShareConvergenceMessage {
            round_id,
            share_count,
            total_work,
            share_hashes: self.round_manager.round_share_hashes(round_id),
        }
    }

    /// Serialize a convergence request for broadcast.
    pub fn request_bytes(&self, round_id: RoundId) -> GhostResult<Vec<u8>> {
        let payload = ConvergencePayload::Request(self.build_request(round_id));
        serde_json::to_vec(&payload)
            .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))
    }

    /// Answer a peer's request with the full signed proofs they are missing.
    pub fn handle_request(&self, req: &ShareConvergenceMessage) -> ShareConvergenceResponse {
        let theirs: HashSet<[u8; 32]> = req.share_hashes.iter().copied().collect();
        let missing = self
            .round_manager
            .proofs_missing_from(req.round_id, &theirs);
        let (share_count, total_work) = self.round_manager.round_share_summary(req.round_id);
        ShareConvergenceResponse {
            round_id: req.round_id,
            share_count,
            total_work,
            missing_shares: missing,
        }
    }

    /// Apply a convergence RESPONSE. Each backfilled proof is GHOST-09-verified
    /// (we bypass the normal share-receive gate here, so we must re-check the
    /// signature) and then fed through the standard validation+dedup path.
    /// Returns the number of shares newly accepted.
    pub fn apply_response(&self, resp: &ShareConvergenceResponse) -> usize {
        let mut applied = 0;
        for proof in &resp.missing_shares {
            if !proof.has_valid_received_by_signature() {
                continue; // GHOST-09: never credit an unsigned/forged backfill
            }

            let miner_hex = hex::encode(&proof.miner_id[..8]);
            let from_node = hex::encode(&proof.received_by[..4]);
            let share_hash = hex::encode(proof.share_hash);
            let round_id = proof.round_id;
            let work = proof.work;
            let timestamp = proof.timestamp as i64;

            if self.round_manager.handle_share_proof(proof.clone()).is_ok() {
                applied += 1;

                if let Some(db) = &self.db {
                    // GHOST-03: persist the backfilled share to the `shares` TABLE.
                    //
                    // This is the whole point of convergence and it was missing. Share gossip
                    // is fire-and-forget (dropped on channel overflow); this protocol exists to
                    // repair those drops. Feeding the RoundManager alone repaired only the
                    // in-memory round view — node-share credit and dedup — while the `shares`
                    // table stayed short. And the `shares` table is the ONLY thing the payout
                    // ledger reads (`select_ledger_miner_work` -> `get_top_unpaid_*`).
                    //
                    // The consequence was permanent, compounding ledger divergence: every node
                    // summed a different share set, so every node computed a different miner
                    // split, so the GHOST-02 exact-equality check rejected every proposal — and
                    // nothing in the system ever repaired it. Safety held; liveness did not.
                    //
                    // Mirrors the live-gossip insert in `share_handler.rs` exactly, so a share
                    // backfilled here is byte-identical to one that arrived first time. The
                    // UNIQUE constraint on `share_hash` makes this idempotent.
                    //
                    // Store the SIGNED PROOF alongside the row (not `insert_share`, which
                    // leaves `proof` NULL). A proof-less row is UNSERVABLE — GHOST-03 backfills
                    // from the stored proof blob, so a node can never re-serve it to a third
                    // node, and the divergence this protocol exists to REPAIR instead
                    // PROPAGATES. The window path (`apply_ledger_response`) already does this;
                    // this round-scoped path was the outlier manufacturing unservable orphans.
                    let share_record = ghost_storage::models::ShareRecord {
                        id: None,
                        round_id,
                        miner_id: miner_hex.clone(),
                        difficulty: work,
                        work,
                        share_hash,
                        timestamp,
                        received_by: from_node,
                        valid: true,
                    };
                    let proof_blob = serde_json::to_vec(proof).unwrap_or_default();

                    match db.insert_share_with_proof(&share_record, &proof_blob) {
                        Ok(_) => {
                            if let Err(e) = db.increment_miner_stats(&miner_hex, 1, work) {
                                warn!(
                                    miner = %miner_hex,
                                    error = %e,
                                    "GHOST-03: failed to increment backfilled miner stats"
                                );
                            }
                        }
                        Err(e) => {
                            // Already had it — the UNIQUE constraint is our dedup.
                            if !e.to_string().contains("UNIQUE") {
                                warn!(
                                    miner = %miner_hex,
                                    error = %e,
                                    "GHOST-03: failed to persist backfilled share"
                                );
                            }
                        }
                    }

                    // GHOST-02 / Option A: adopt the backfilled proof's signed payout
                    // address (first-writer-wins) so addresses converge here too.
                    if let Some(addr) = &proof.payout_address {
                        let _ = db.adopt_miner_address(&miner_hex, addr);
                    }
                }
            }
        }
        applied
    }
}

#[async_trait]
impl MessageHandler for ConvergenceHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        // Shares and convergence share a pubsub topic; only handle convergence.
        if envelope.msg_type != MessageType::ShareConvergence {
            return Ok(());
        }
        let payload: ConvergencePayload = match serde_json::from_slice(&envelope.payload) {
            Ok(p) => p,
            Err(_) => return Ok(()), // not a convergence payload — ignore
        };
        match payload {
            ConvergencePayload::Request(req) => {
                let resp = self.handle_request(&req);
                if resp.missing_shares.is_empty() {
                    return Ok(());
                }
                if let Some(send) = &self.send {
                    let bytes = serde_json::to_vec(&ConvergencePayload::Response(resp))
                        .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))?;
                    send(bytes)?;
                }
            }
            ConvergencePayload::LedgerRequest(req) => {
                let resp = self.handle_ledger_request(&req);
                if resp.proofs.is_empty() {
                    return Ok(());
                }
                if let Some(send) = &self.send {
                    let bytes = serde_json::to_vec(&ConvergencePayload::LedgerResponse(resp))
                        .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))?;
                    send(bytes)?;
                }
            }
            ConvergencePayload::LedgerResponse(resp) => {
                let applied = self.apply_ledger_response(&resp);
                if applied > 0 {
                    tracing::info!(
                        since = resp.since_ts,
                        until = resp.until_ts,
                        applied,
                        "GHOST-03: backfilled unpaid-ledger shares via window convergence"
                    );
                }
            }
            ConvergencePayload::Response(resp) => {
                let applied = self.apply_response(&resp);
                if applied > 0 {
                    tracing::info!(
                        round_id = resp.round_id,
                        applied,
                        "GHOST-03: backfilled missing shares via ledger convergence"
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::round::{RoundConfig, RoundManager};
    use ghost_common::identity::NodeIdentity;
    use ghost_common::types::ShareProof;

    const TPL: [u8; 32] = [0x7c; 32];

    /// difficulty-1.0 hash (32 leading zero bits then 0xFF); unique low nonce.
    fn diff1_hash(nonce: u64) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&nonce.to_le_bytes());
        h[27] = 0xFF;
        h
    }

    fn round_manager() -> Arc<RoundManager> {
        let id = NodeIdentity::generate();
        let cfg = RoundConfig {
            share_difficulty: 1.0,
            network_difficulty: 1_000_000.0,
            ..RoundConfig::default()
        };
        let rm = Arc::new(RoundManager::new(id.node_id(), cfg));
        rm.set_template_id(TPL);
        rm
    }

    fn signed_share(signer: &NodeIdentity, nonce: u64) -> ShareProof {
        let mut p = ShareProof {
            round_id: 1,
            miner_id: [9u8; 32],
            difficulty: 1.0,
            work: 1.0,
            share_hash: diff1_hash(nonce),
            timestamp: 0,
            received_by: signer.node_id(),
            template_id: Some(TPL),
            payout_address: None,
            signature: None,
        };
        p.sign(signer);
        p
    }

    /// The `shares` row a proof becomes — mirrors `share_handler.rs` and `apply_response`.
    fn ledger_row(p: &ShareProof) -> ghost_storage::ShareRecord {
        ghost_storage::ShareRecord {
            id: None,
            round_id: p.round_id,
            miner_id: hex::encode(&p.miner_id[..8]),
            difficulty: p.work,
            work: p.work,
            share_hash: hex::encode(p.share_hash),
            timestamp: p.timestamp as i64,
            received_by: hex::encode(&p.received_by[..4]),
            valid: true,
        }
    }

    /// GHOST-03 must repair the `shares` TABLE, not merely the in-memory round view.
    ///
    /// The payout ledger reads that table and nothing else. Backfilling only the RoundManager
    /// left every node summing a different share set — so every node computed a different miner
    /// split, and the GHOST-02 exact-equality check rejected every payout proposal, permanently,
    /// with nothing in the system able to repair it.
    ///
    /// `convergence_backfills_a_missing_share` (below) asserts only `round_share_hashes`. That
    /// is exactly the blind spot the bug lived in: convergence looked healthy in memory while
    /// the ledger it exists to protect silently diverged.
    #[test]
    fn convergence_backfills_the_payout_ledger_not_just_memory() {
        let producer = NodeIdentity::generate();
        let rm_a = round_manager();
        let rm_b = round_manager();
        let db_a = Arc::new(ghost_storage::Database::in_memory().expect("db a"));
        let db_b = Arc::new(ghost_storage::Database::in_memory().expect("db b"));

        let ch_a = ConvergenceHandler::new(Arc::clone(&rm_a)).with_db(Arc::clone(&db_a));
        let ch_b = ConvergenceHandler::new(Arc::clone(&rm_b)).with_db(Arc::clone(&db_b));

        // A received three shares and persisted them. B's gossip dropped two — the fire-and-
        // forget broadcast overflowed, exactly as it does in production.
        let shares: Vec<ShareProof> = (1..=3).map(|n| signed_share(&producer, n)).collect();
        for s in &shares {
            rm_a.handle_share_proof(s.clone()).expect("A accepts");
            db_a.insert_share(&ledger_row(s)).expect("A persists");
        }
        rm_b.handle_share_proof(shares[0].clone())
            .expect("B accepts the one it got");
        db_b.insert_share(&ledger_row(&shares[0]))
            .expect("B persists the one it got");

        // What a payout would actually be computed from on each node.
        let unpaid_work = |db: &ghost_storage::Database| -> f64 {
            db.get_top_unpaid_miners(i64::MAX, 100)
                .expect("ledger")
                .iter()
                .map(|(_, w)| *w)
                .sum()
        };
        assert_eq!(unpaid_work(&db_a), 3.0);
        assert_eq!(unpaid_work(&db_b), 1.0, "B starts with a short ledger");

        // B advertises what it holds; A replies with the proofs B is missing; B applies them.
        let req = ch_b.build_request(1);
        let resp = ch_a.handle_request(&req);
        let applied = ch_b.apply_response(&resp);
        assert_eq!(applied, 2, "both dropped shares must be backfilled");

        assert_eq!(
            unpaid_work(&db_b),
            unpaid_work(&db_a),
            "after convergence B's PAYOUT LEDGER must equal A's — if it does not, the two nodes \
             compute different miner splits and GHOST-02 rejects the payout forever"
        );

        // And it must be idempotent: re-applying cannot double-credit the work.
        ch_b.apply_response(&resp);
        assert_eq!(
            unpaid_work(&db_b),
            3.0,
            "re-applying a convergence response must not double-count shares"
        );
    }

    /// The whole point: a share dropped in a round that has long since rotated must still be
    /// reconciled. The round-scoped exchange could never do this — it only asks about the round
    /// in flight, and the signed proof is pruned after 10 rounds (~15 min), so anything older was
    /// unrecoverable and the ledgers diverged permanently.
    ///
    /// This is what closes that hole: the unpaid ledger is reconciled over a time window, served
    /// from the persisted proofs (schema v41), so age stops mattering.
    #[test]
    fn ledger_convergence_repairs_a_drop_outside_the_round_window() {
        let producer = NodeIdentity::generate();
        let rm_a = round_manager();
        let rm_b = round_manager();
        let db_a = Arc::new(ghost_storage::Database::in_memory().expect("db a"));
        let db_b = Arc::new(ghost_storage::Database::in_memory().expect("db b"));

        let ch_a = ConvergenceHandler::new(Arc::clone(&rm_a)).with_db(Arc::clone(&db_a));
        let ch_b = ConvergenceHandler::new(Arc::clone(&rm_b)).with_db(Arc::clone(&db_b));

        // Shares from HOURS ago — far outside any round still held in memory. A has all three
        // and stored their signed proofs; B's gossip dropped two.
        let base_ts = 100_000i64;
        let shares: Vec<ShareProof> = (1..=3)
            .map(|n| {
                let mut p = signed_share(&producer, n);
                p.timestamp = (base_ts + n as i64) as u64;
                p.sign(&producer); // re-sign: the timestamp is covered by the signature
                p
            })
            .collect();

        for s in &shares {
            db_a.insert_share_with_proof(&ledger_row(s), &serde_json::to_vec(s).unwrap())
                .expect("A persists with proof");
        }
        db_b.insert_share_with_proof(
            &ledger_row(&shares[0]),
            &serde_json::to_vec(&shares[0]).unwrap(),
        )
        .expect("B persists the one it got");

        let unpaid = |db: &ghost_storage::Database| -> f64 {
            db.get_top_unpaid_miners(i64::MAX, 100)
                .expect("ledger")
                .iter()
                .map(|(_, w)| *w)
                .sum()
        };
        assert_eq!(unpaid(&db_a), 3.0);
        assert_eq!(
            unpaid(&db_b),
            1.0,
            "B's ledger is short — and always would have been"
        );

        // B advertises the window; A serves the proofs B lacks; B applies them.
        let window = (base_ts, base_ts + 3_600);
        let req = ch_b
            .build_ledger_request(window.0, window.1)
            .expect("request");
        assert_eq!(req.share_hashes.len(), 1, "B advertises only what it holds");

        let resp = ch_a.handle_ledger_request(&req);
        assert_eq!(
            resp.proofs.len(),
            2,
            "A serves exactly the two B is missing"
        );
        assert_eq!(resp.unservable, 0, "all of A's shares carry proofs (v41)");

        assert_eq!(ch_b.apply_ledger_response(&resp), 2);
        assert_eq!(
            unpaid(&db_b),
            unpaid(&db_a),
            "the ledgers must now agree — otherwise the two nodes compute different payout \
             splits and GHOST-02 rejects the payout forever"
        );

        // Idempotent: re-applying must not double-count the work.
        ch_b.apply_ledger_response(&resp);
        assert_eq!(unpaid(&db_b), 3.0, "re-applying must not double-count");
    }

    /// A forged backfill must never be credited, even over the ledger path — convergence bypasses
    /// the normal share-receive gate, so it has to verify GHOST-09 itself.
    #[test]
    fn ledger_convergence_rejects_a_forged_backfill() {
        let producer = NodeIdentity::generate();
        let attacker = NodeIdentity::generate();
        let rm_b = round_manager();
        let db_b = Arc::new(ghost_storage::Database::in_memory().expect("db b"));
        let ch_b = ConvergenceHandler::new(Arc::clone(&rm_b)).with_db(Arc::clone(&db_b));

        // A proof claiming to be from `producer`, but signed by someone else.
        let mut forged = signed_share(&producer, 9);
        forged.sign(&attacker);

        let resp = LedgerConvergenceResponse {
            since_ts: 0,
            until_ts: i64::MAX,
            proofs: vec![serde_json::to_vec(&forged).unwrap()],
            unservable: 0,
        };

        assert_eq!(
            ch_b.apply_ledger_response(&resp),
            0,
            "a proof whose received_by signature does not verify must never be credited"
        );
        let unpaid: f64 = db_b
            .get_top_unpaid_miners(i64::MAX, 100)
            .expect("ledger")
            .iter()
            .map(|(_, w)| *w)
            .sum();
        assert_eq!(unpaid, 0.0, "no forged work may reach the payout ledger");
    }

    #[test]
    fn convergence_backfills_a_missing_share() {
        let producer = NodeIdentity::generate();
        let rm_a = round_manager();
        let rm_b = round_manager();

        // A holds the share; B is missing it.
        let share = signed_share(&producer, 1);
        rm_a.handle_share_proof(share.clone()).unwrap();
        assert!(rm_a.round_share_hashes(1).contains(&share.share_hash));
        assert!(!rm_b.round_share_hashes(1).contains(&share.share_hash));

        let ch_a = ConvergenceHandler::new(Arc::clone(&rm_a));
        let ch_b = ConvergenceHandler::new(Arc::clone(&rm_b));
        let request = ch_b.build_request(1); // B advertises (nothing)
        let response = ch_a.handle_request(&request); // A returns the missing share
        assert_eq!(ch_b.apply_response(&response), 1);
        assert!(
            rm_b.round_share_hashes(1).contains(&share.share_hash),
            "B's ledger holds the share after convergence"
        );
    }

    #[test]
    fn convergence_rejects_a_forged_backfill() {
        let attacker = NodeIdentity::generate();
        let victim = NodeIdentity::generate();
        let rm_b = round_manager();

        // received_by = victim, but signed by attacker → GHOST-09 invalid.
        let mut forged = signed_share(&victim, 2);
        forged.sign(&attacker);
        let resp = ShareConvergenceResponse {
            round_id: 1,
            share_count: 1,
            total_work: 1.0,
            missing_shares: vec![forged],
        };
        assert_eq!(
            ConvergenceHandler::new(rm_b).apply_response(&resp),
            0,
            "a forged backfill is rejected (GHOST-09 re-checked on the convergence path)"
        );
    }

    #[test]
    fn remote_share_with_senders_template_is_accepted_local_stays_validated() {
        // M-MINE-1 validates the template against THIS node's templates. A gossiped
        // share (received_by = another node) was mined against the SENDER's coinbase
        // template — which this node cannot know — so M-MINE-1 must NOT reject it:
        // its trust anchors are the GHOST-09 signature (the signer vouches), C4 PoW,
        // and C5 dedup, and the signer already validated its own template. Without
        // this, every cross-node share is dropped as StaleTemplate and GHOST-02
        // rejects every payout once enforcement activates.
        let unknown_template = [0x33u8; 32]; // NOT the node's TPL

        // Remote share: received_by = a different node, signed by it, sender's template.
        let remote_signer = NodeIdentity::generate();
        let mut remote = ShareProof {
            round_id: 1,
            miner_id: [9u8; 32],
            difficulty: 1.0,
            work: 1.0,
            share_hash: diff1_hash(101),
            timestamp: 0,
            received_by: remote_signer.node_id(),
            template_id: Some(unknown_template),
            payout_address: None,
            signature: None,
        };
        remote.sign(&remote_signer);
        let rm = round_manager(); // template = TPL, our_node_id = (internal)
        assert!(
            rm.handle_share_proof(remote.clone()).is_ok(),
            "a gossiped share carrying the sender's (locally-unknown) template must be accepted"
        );
        assert!(rm.round_share_hashes(1).contains(&remote.share_hash));

        // Local share: received_by = self, unknown template → STILL stale-rejected.
        let local_id = NodeIdentity::generate();
        let cfg = RoundConfig {
            share_difficulty: 1.0,
            network_difficulty: 1_000_000.0,
            ..RoundConfig::default()
        };
        let rm_local = Arc::new(RoundManager::new(local_id.node_id(), cfg));
        rm_local.set_template_id(TPL);
        let mut local = ShareProof {
            round_id: 1,
            miner_id: [9u8; 32],
            difficulty: 1.0,
            work: 1.0,
            share_hash: diff1_hash(102),
            timestamp: 0,
            received_by: local_id.node_id(),
            template_id: Some(unknown_template),
            payout_address: None,
            signature: None,
        };
        local.sign(&local_id);
        assert!(
            matches!(
                rm_local.handle_share_proof(local),
                Err(crate::round::ShareError::StaleTemplate)
            ),
            "a LOCAL share (received_by == self) with an unknown template is still stale-rejected"
        );
    }

    #[test]
    fn remote_share_work_consistency_uses_absolute_model_not_pool_min() {
        // M-9 work-consistency must validate proof.work against proof.difficulty
        // (the ABSOLUTE model: work == difficulty, exactly as the SRI/local path
        // `record_share` credits it), NOT proof.difficulty / share_difficulty. The
        // relative model assumes a pool minimum of 1; with the PRODUCTION DEFAULT
        // share_difficulty=1000 it computed calculated_work = work/1000 and rejected
        // every gossiped share, making the elders hold 0 shares and GHOST-02 reject
        // every payout once enforcement activates. C4 already proves the hash meets
        // proof.difficulty, so work==difficulty is fully PoW-bounded.
        let producer = NodeIdentity::generate();
        let cfg = RoundConfig {
            share_difficulty: 1000.0, // PRODUCTION DEFAULT (round_manager() uses 1.0 and hides the bug)
            network_difficulty: 1_000_000.0,
            ..RoundConfig::default()
        };
        let rm = Arc::new(RoundManager::new(NodeIdentity::generate().node_id(), cfg));
        rm.set_template_id(TPL);

        let mut p = ShareProof {
            round_id: 1,
            miner_id: [9u8; 32],
            difficulty: 1.0,
            work: 1.0, // absolute: work == difficulty (what the SRI sets)
            share_hash: diff1_hash(50),
            timestamp: 0,
            received_by: producer.node_id(),
            template_id: Some(TPL),
            payout_address: None,
            signature: None,
        };
        p.sign(&producer);
        assert!(
            rm.handle_share_proof(p.clone()).is_ok(),
            "a gossiped share with work==difficulty must pass M-9 regardless of the local share_difficulty"
        );

        // A share that claims more work than its difficulty justifies is still rejected.
        let mut inflated = p.clone();
        inflated.work = 10.0; // 10x the claimed difficulty
        inflated.sign(&producer);
        assert!(
            matches!(
                rm.handle_share_proof(inflated),
                Err(crate::round::ShareError::WorkValueTooHigh { .. })
            ),
            "claiming work that exceeds the difficulty is still rejected (no inflation)"
        );
    }

    #[test]
    fn proofs_missing_from_excludes_known_hashes() {
        let producer = NodeIdentity::generate();
        let rm = round_manager();
        let s1 = signed_share(&producer, 10);
        let s2 = signed_share(&producer, 11);
        rm.handle_share_proof(s1.clone()).unwrap();
        rm.handle_share_proof(s2.clone()).unwrap();

        // Peer already has s1 → only s2 is "missing".
        let known: std::collections::HashSet<[u8; 32]> = [s1.share_hash].into_iter().collect();
        let missing = rm.proofs_missing_from(1, &known);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].share_hash, s2.share_hash);
    }
}
