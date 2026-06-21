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
}

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
            if self.round_manager.handle_share_proof(proof.clone()).is_ok() {
                applied += 1;
                // GHOST-02 / Option A: adopt the backfilled proof's signed payout
                // address (first-writer-wins) so addresses converge here too.
                if let (Some(db), Some(addr)) = (&self.db, &proof.payout_address) {
                    let miner_hex = hex::encode(&proof.miner_id[..8]);
                    let _ = db.adopt_miner_address(&miner_hex, addr);
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
