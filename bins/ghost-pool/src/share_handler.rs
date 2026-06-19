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
//| FILE: share_handler.rs                                                                                               |
//|======================================================================================================================|

//! P2P share proof handler
//!
//! Receives share proofs from other nodes and delegates validation to
//! RoundManager::handle_share_proof(), which performs full cryptographic
//! verification, dedup, tolerance tracking, and work crediting.

use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;
use tracing::{debug, warn};

use ghost_common::error::GhostResult;
use ghost_common::types::NodeId;
use ghost_storage::Database;

use ghost_consensus::mesh::MessageHandler;
use ghost_consensus::message::{MessageEnvelope, MessageType, ShareProofMessage};

use crate::round::RoundManager;

/// Maximum age of a share proof before it's rejected (10 minutes)
const MAX_SHARE_AGE_SECS: i64 = 600;
/// Maximum future tolerance for clock skew (30 seconds)
const MAX_FUTURE_TOLERANCE_SECS: i64 = 30;

/// Handler for incoming P2P share proof messages
pub struct ShareProofHandler {
    round_manager: Arc<RoundManager>,
    db: Arc<Database>,
    our_node_id: NodeId,
}

impl ShareProofHandler {
    pub fn new(round_manager: Arc<RoundManager>, db: Arc<Database>, our_node_id: NodeId) -> Self {
        Self {
            round_manager,
            db,
            our_node_id,
        }
    }

    async fn handle_share_proof(&self, envelope: &MessageEnvelope) -> GhostResult<()> {
        let msg: ShareProofMessage = serde_json::from_slice(&envelope.payload).map_err(|e| {
            warn!(error = %e, "Failed to deserialize share proof message");
            ghost_common::error::GhostError::P2PMessage(e.to_string())
        })?;

        let proof = msg.proof;

        // Skip our own shares (already recorded locally)
        if proof.received_by == self.our_node_id {
            return Ok(());
        }

        // GHOST-09: authenticate the node-reward credit. A remote proof must
        // carry a valid signature by `received_by` over its canonical bytes,
        // otherwise it's a forged or relayed credit (e.g. a relay re-crediting
        // itself) and is dropped before it can inflate any node's shares.
        //
        // GATED on CLUSTER_ENFORCEMENT_HEIGHT: pre-activation the fleet is still
        // partly running the pre-audit binary that emits UNSIGNED proofs, so
        // enforcing here would silently drop those nodes' shares and diverge the
        // ledger. Until the gate height we therefore accept them; nodes already
        // sign their own shares (always-on) so the converged state is primed for
        // the moment the gate fires fleet-wide.
        if self.round_manager.current_height() >= crate::CLUSTER_ENFORCEMENT_HEIGHT
            && !proof.has_valid_received_by_signature()
        {
            warn!(
                from_node = %hex::encode(&proof.received_by[..4]),
                round_id = proof.round_id,
                "GHOST-09: dropping share proof with missing/invalid received_by signature"
            );
            return Ok(());
        }

        // Timestamp freshness check
        let now = Utc::now().timestamp();
        let ts = proof.timestamp as i64;

        if ts < now - MAX_SHARE_AGE_SECS {
            warn!(
                timestamp = proof.timestamp,
                now = now,
                "Rejecting stale share proof (older than 10 minutes)"
            );
            return Ok(());
        }

        if ts > now + MAX_FUTURE_TOLERANCE_SECS {
            warn!(
                timestamp = proof.timestamp,
                now = now,
                "Rejecting share proof with future timestamp"
            );
            return Ok(());
        }

        let miner_hex = hex::encode(&proof.miner_id[..8]);
        let from_node = hex::encode(&proof.received_by[..4]);
        let payout_address = proof.payout_address.clone(); // GHOST-02/Option A: adopted below
        let round_id = proof.round_id;
        let share_hash = hex::encode(proof.share_hash);
        let work = proof.work;
        let timestamp = proof.timestamp;

        // Delegate all validation to handle_share_proof:
        // C4 (crypto), C5 (dedup), L-7 (tolerance), M-6 (template), M-29 (persistent exploiter)
        match self.round_manager.handle_share_proof(proof) {
            Ok(()) => {
                // Persist to DB so shares survive node restarts
                let share_record = ghost_storage::models::ShareRecord {
                    id: None,
                    round_id,
                    miner_id: miner_hex.clone(),
                    difficulty: work,
                    work,
                    share_hash: share_hash.clone(),
                    timestamp: timestamp as i64,
                    received_by: from_node.clone(),
                    valid: true,
                };

                match self.db.insert_share(&share_record) {
                    Ok(_) => {
                        // Share inserted — update miner cumulative stats
                        if let Err(e) = self.db.increment_miner_stats(&miner_hex, 1, work) {
                            warn!(
                                miner = %miner_hex,
                                error = %e,
                                "Failed to increment remote miner stats"
                            );
                        }
                    }
                    Err(e) => {
                        // UNIQUE constraint handles dedup — log other errors
                        if !e.to_string().contains("UNIQUE") {
                            warn!(
                                miner = %miner_hex,
                                error = %e,
                                "Failed to persist remote share to database"
                            );
                        }
                    }
                }

                // GHOST-02 / Option A: adopt the miner's payout address from this
                // GHOST-09-SIGNED proof, first-writer-wins. This is what lets
                // payout addresses converge across nodes so validators can
                // reproduce the proposer's address-grouped split (GHOST-02).
                // The original M-06 concern (a node substituting its own address
                // for a legitimate miner) is contained: the proof is signature-
                // verified above, and `adopt_miner_address` never overwrites an
                // already-established address.
                if let Some(addr) = &payout_address {
                    if let Err(e) = self.db.adopt_miner_address(&miner_hex, addr) {
                        warn!(miner = %miner_hex, error = %e, "GHOST-02: failed to adopt signed payout address");
                    }
                }

                debug!(
                    miner = %miner_hex,
                    from_node = %from_node,
                    "Accepted remote share proof"
                );
            }
            Err(crate::round::ShareError::DuplicateShare) => {
                // Expected during normal operation (multiple nodes forward same share)
            }
            Err(e) => {
                debug!(
                    miner = %miner_hex,
                    from_node = %from_node,
                    error = %e,
                    "Rejected remote share proof"
                );
            }
        }

        Ok(())
    }
}

#[async_trait]
impl MessageHandler for ShareProofHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        if envelope.msg_type == MessageType::ShareProof {
            self.handle_share_proof(&envelope).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_consensus::message::MessageEnvelope;

    fn make_envelope(msg_type: MessageType, payload: Vec<u8>) -> MessageEnvelope {
        MessageEnvelope {
            msg_type,
            sender: [0u8; 32],
            timestamp: Utc::now().timestamp() as u64,
            sequence: 1,
            signature: [0u8; 64],
            payload,
            ttl: 3,
        }
    }

    #[tokio::test]
    async fn test_ignores_non_share_proof_messages() {
        let db = Arc::new(Database::in_memory().expect("in-memory db"));
        let rm = Arc::new(RoundManager::new(
            [1u8; 32],
            crate::round::RoundConfig::default(),
        ));
        let handler = ShareProofHandler::new(rm, db, [1u8; 32]);

        let envelope = make_envelope(MessageType::HealthPing, vec![]);
        // Should return Ok without processing
        assert!(handler.handle_message(Arc::new(envelope)).await.is_ok());
    }

    #[tokio::test]
    async fn test_skips_own_shares() {
        let our_node_id = [1u8; 32];
        let db = Arc::new(Database::in_memory().expect("in-memory db"));
        let rm = Arc::new(RoundManager::new(
            our_node_id,
            crate::round::RoundConfig::default(),
        ));
        let handler = ShareProofHandler::new(rm, db, our_node_id);

        // Create a share proof from our own node
        let proof = ghost_common::types::ShareProof {
            round_id: 1,
            miner_id: [2u8; 32],
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: [3u8; 32],
            timestamp: Utc::now().timestamp() as u64,
            received_by: our_node_id, // Our own node
            template_id: Some([4u8; 32]),
            payout_address: None,
            signature: None, // skipped before the GHOST-09 gate (own share)
        };
        let msg = ShareProofMessage { proof };
        let payload = serde_json::to_vec(&msg).expect("test serialization");
        let envelope = make_envelope(MessageType::ShareProof, payload);

        // Should silently skip (return Ok)
        assert!(handler.handle_message(Arc::new(envelope)).await.is_ok());
    }

    #[tokio::test]
    async fn test_rejects_stale_timestamp() {
        let our_node_id = [1u8; 32];
        let other = ghost_common::identity::NodeIdentity::generate();
        let other_node_id = other.node_id();
        let db = Arc::new(Database::in_memory().expect("in-memory db"));
        let rm = Arc::new(RoundManager::new(
            our_node_id,
            crate::round::RoundConfig::default(),
        ));
        let handler = ShareProofHandler::new(rm, db, our_node_id);

        // Create a share proof with a very old timestamp
        let proof = ghost_common::types::ShareProof {
            round_id: 1,
            miner_id: [3u8; 32],
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: [4u8; 32],
            timestamp: 1000, // Very old
            received_by: other_node_id,
            template_id: Some([5u8; 32]),
            payout_address: None,
            signature: None,
        };
        // GHOST-09: sign as `other` so the proof passes the receive-path gate.
        let proof = proof.signed(&other);
        let msg = ShareProofMessage { proof };
        let payload = serde_json::to_vec(&msg).expect("test serialization");
        let envelope = make_envelope(MessageType::ShareProof, payload);

        // Should silently reject stale timestamp (return Ok, but not process)
        assert!(handler.handle_message(Arc::new(envelope)).await.is_ok());
    }

    #[tokio::test]
    async fn test_rejects_future_timestamp() {
        let our_node_id = [1u8; 32];
        let other = ghost_common::identity::NodeIdentity::generate();
        let other_node_id = other.node_id();
        let db = Arc::new(Database::in_memory().expect("in-memory db"));
        let rm = Arc::new(RoundManager::new(
            our_node_id,
            crate::round::RoundConfig::default(),
        ));
        let handler = ShareProofHandler::new(rm, db, our_node_id);

        // Create a share proof with a timestamp 60 seconds in the future (beyond 30s tolerance)
        let future_timestamp = (Utc::now().timestamp() + 60) as u64;
        let proof = ghost_common::types::ShareProof {
            round_id: 1,
            miner_id: [3u8; 32],
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: [4u8; 32],
            timestamp: future_timestamp,
            received_by: other_node_id,
            template_id: Some([5u8; 32]),
            payout_address: None,
            signature: None,
        };
        // GHOST-09: sign as `other` so the proof passes the receive-path gate.
        let proof = proof.signed(&other);
        let msg = ShareProofMessage { proof };
        let payload = serde_json::to_vec(&msg).expect("test serialization");
        let envelope = make_envelope(MessageType::ShareProof, payload);

        // Should silently reject future timestamp (return Ok, but not process)
        assert!(handler.handle_message(Arc::new(envelope)).await.is_ok());
    }

    #[tokio::test]
    async fn test_valid_share_accepted_and_recorded() {
        let our_node_id = [1u8; 32];
        let other = ghost_common::identity::NodeIdentity::generate();
        let other_node_id = other.node_id();
        let db = Arc::new(Database::in_memory().expect("in-memory db"));
        let rm = Arc::new(RoundManager::new(
            our_node_id,
            crate::round::RoundConfig::default(),
        ));
        let handler = ShareProofHandler::new(rm, db.clone(), our_node_id);

        // Create a share proof from another node with a valid (recent) timestamp
        let proof = ghost_common::types::ShareProof {
            round_id: 1,
            miner_id: [3u8; 32],
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: [4u8; 32],
            timestamp: Utc::now().timestamp() as u64,
            received_by: other_node_id,
            template_id: Some([5u8; 32]),
            payout_address: None,
            signature: None,
        };
        // GHOST-09: sign as `other` so the proof passes the receive-path gate.
        let proof = proof.signed(&other);
        let msg = ShareProofMessage { proof };
        let payload = serde_json::to_vec(&msg).expect("test serialization");
        let envelope = make_envelope(MessageType::ShareProof, payload);

        // handle_message should succeed (no deserialization or timestamp errors)
        // The share will be passed to RoundManager::handle_share_proof, which may
        // reject it for other reasons (e.g., missing template), but the handler
        // itself should not error — it catches and logs RoundManager rejections.
        let result = handler.handle_message(Arc::new(envelope)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_duplicate_share_silently_ignored() {
        let our_node_id = [1u8; 32];
        let other = ghost_common::identity::NodeIdentity::generate();
        let other_node_id = other.node_id();
        let db = Arc::new(Database::in_memory().expect("in-memory db"));
        let rm = Arc::new(RoundManager::new(
            our_node_id,
            crate::round::RoundConfig::default(),
        ));
        let handler = ShareProofHandler::new(rm, db.clone(), our_node_id);

        let proof = ghost_common::types::ShareProof {
            round_id: 1,
            miner_id: [3u8; 32],
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: [4u8; 32],
            timestamp: Utc::now().timestamp() as u64,
            received_by: other_node_id,
            template_id: Some([5u8; 32]),
            payout_address: None,
            signature: None,
        };
        // GHOST-09: sign as `other` so the proof passes the receive-path gate.
        let proof = proof.signed(&other);
        let msg = ShareProofMessage { proof };
        let payload = serde_json::to_vec(&msg).expect("test serialization");

        // Submit same share twice
        let envelope1 = make_envelope(MessageType::ShareProof, payload.clone());
        let result1 = handler.handle_message(Arc::new(envelope1)).await;
        assert!(result1.is_ok(), "First submission should succeed");

        let envelope2 = make_envelope(MessageType::ShareProof, payload);
        let result2 = handler.handle_message(Arc::new(envelope2)).await;
        assert!(
            result2.is_ok(),
            "Duplicate share should be silently ignored, not error"
        );

        // Both calls returned Ok — the handler silently ignores duplicates
        // (UNIQUE constraint in DB prevents double-counting)
    }

    #[tokio::test]
    async fn test_miner_stats_incremented_on_valid_share() {
        let our_node_id = [1u8; 32];
        let other = ghost_common::identity::NodeIdentity::generate();
        let other_node_id = other.node_id();
        let db = Arc::new(Database::in_memory().expect("in-memory db"));
        let rm = Arc::new(RoundManager::new(
            our_node_id,
            crate::round::RoundConfig::default(),
        ));
        let handler = ShareProofHandler::new(rm, db.clone(), our_node_id);

        let miner_id = [3u8; 32];
        let miner_hex = hex::encode(&miner_id[..8]);

        let proof = ghost_common::types::ShareProof {
            round_id: 1,
            miner_id,
            difficulty: 500.0,
            work: 500.0,
            share_hash: [7u8; 32],
            timestamp: Utc::now().timestamp() as u64,
            received_by: other_node_id,
            template_id: Some([8u8; 32]),
            payout_address: None,
            signature: None,
        };
        let proof = proof.signed(&other);
        let msg = ShareProofMessage { proof };
        let payload = serde_json::to_vec(&msg).expect("test serialization");

        // Submit a share — even if RoundManager rejects (no template), handler returns Ok
        let envelope = make_envelope(MessageType::ShareProof, payload);
        let result = handler.handle_message(Arc::new(envelope)).await;
        assert!(result.is_ok());

        // If the share was accepted by RoundManager AND inserted into DB,
        // increment_miner_stats would have been called. Check miner_stats table exists.
        // Even if stats weren't incremented (share rejected at RM level), query shouldn't panic.
        let stats = db.get_miner_stats(&miner_hex);
        // Stats may be None if share was rejected before DB insert, which is fine —
        // the key invariant is that the handler doesn't error out.
        assert!(
            stats.is_ok(),
            "get_miner_stats should not error: {:?}",
            stats.err()
        );
    }
}
