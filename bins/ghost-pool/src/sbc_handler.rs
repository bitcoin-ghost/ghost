//! Mesh handler for the share-batch chain (WP-5).
//!
//! Routes `ShareBatchProposal` / `ShareBatchVote` / `ShareBatchSync` into
//! [`crate::sbc_shadow::ShadowChain`] and
//! broadcasts what follows. It decides nothing itself — every judgement belongs to the pure driver
//! in `ghost-common`, and every consequence to `ShadowChain`.
//!
//! Dark: registering this is a separate step, so the code can land and be reviewed before any node
//! starts answering batch traffic.

use std::sync::Arc;

use ghost_common::batch_consensus::ProposerSchedule;
use ghost_common::batch_driver::{Action, VoteAction};
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::NodeIdentity;
use ghost_common::share_batch::ShareBatch;
use ghost_common::types::NodeId;
use ghost_consensus::mesh::MessageHandler;
use ghost_consensus::message::{
    MessageEnvelope, MessageType, ShareBatchSyncMessage, ShareBatchVoteMessage,
};
use tracing::{debug, info, warn};

use crate::sbc_checks::NodeBatchChecks;
use crate::sbc_shadow::ShadowChain;

/// Serialise and enqueue an outbound broadcast.
pub type BroadcastFn = Arc<dyn Fn(MessageType, Vec<u8>) -> GhostResult<()> + Send + Sync + 'static>;

/// The current voter set. Supplied rather than read so the handler owns no membership logic — and
/// so a test can pin the set instead of standing up discovery.
pub type VoterSetFn = Arc<dyn Fn() -> Vec<NodeId> + Send + Sync + 'static>;

/// The share checks in force right now. A function rather than a value because the PoW predicate
/// depends on the current height, and a handler that captured it once would keep applying the
/// rules that were in force when the process started.
pub type ChecksFn = Arc<dyn Fn() -> NodeBatchChecks + Send + Sync + 'static>;

pub struct ShareBatchHandler {
    chain: Arc<ShadowChain>,
    identity: Arc<NodeIdentity>,
    send: BroadcastFn,
    voters: VoterSetFn,
    checks: ChecksFn,
}

impl ShareBatchHandler {
    pub fn new(
        chain: Arc<ShadowChain>,
        identity: Arc<NodeIdentity>,
        send: BroadcastFn,
        voters: VoterSetFn,
        checks: ChecksFn,
    ) -> Self {
        Self {
            chain,
            identity,
            send,
            voters,
            checks,
        }
    }

    fn schedule(&self) -> ProposerSchedule {
        ProposerSchedule::new((self.voters)())
    }

    /// Judge a proposed batch and act on the verdict.
    fn on_proposal(&self, envelope: &MessageEnvelope, now: i64) -> GhostResult<()> {
        let batch: ShareBatch = serde_json::from_slice(&envelope.payload)
            .map_err(|e| GhostError::Serialization(format!("share batch proposal: {e}")))?;

        let schedule = self.schedule();
        let checks = (self.checks)();
        let action = self.chain.on_proposal(&batch, &schedule, &checks, now);

        match action {
            Action::Vote {
                batch_hash,
                seq,
                round,
            } => {
                // Signed via the message's OWN helper, not a hand-rolled copy. The handler used to
                // build these bytes inline and produced a different string to `signing_bytes` —
                // no domain tag — which nothing noticed because nothing verified votes at all.
                let mut vote = ShareBatchVoteMessage {
                    seq,
                    batch_hash,
                    voter: self.identity.node_id(),
                    round,
                    signature: [0u8; 64],
                };
                vote.signature = self.identity.sign(&vote.signing_bytes());
                let payload = serde_json::to_vec(&vote)
                    .map_err(|e| GhostError::Serialization(format!("share batch vote: {e}")))?;
                (self.send)(MessageType::ShareBatchVote, payload)?;

                // Count our own vote. Without this a node never contributes to the quorum it is
                // waiting on, and a two-node fleet could never finalise anything.
                self.record_vote(self.identity.node_id(), batch_hash, seq, round, &batch, now);
                debug!(seq, round, "SBC: voted");
            }
            Action::Hold { reason } => {
                debug!(seq = batch.seq, ?reason, "SBC: holding");
                // Being behind is recoverable, and the answer is to ask rather than to wait.
                if let ghost_common::batch_consensus::DeferReason::AheadOfUs { our_seq, .. } =
                    reason
                {
                    let req = ShareBatchSyncMessage::Request { seq: our_seq + 1 };
                    if let Ok(payload) = serde_json::to_vec(&req) {
                        let _ = (self.send)(MessageType::ShareBatchSync, payload);
                    }
                }
            }
            Action::Quarantine { reason, outcome } => {
                // A terminal fault and a fleet-level quorum loss are different facts and an
                // operator needs both — the driver reports them separately for that reason.
                warn!(
                    seq = batch.seq,
                    proposer = %hex::encode(&batch.proposer[..4]),
                    ?reason,
                    ?outcome,
                    "SBC: quarantined a proposer"
                );
            }
            Action::AlreadyVotedElsewhere { .. } => {
                debug!(seq = batch.seq, "SBC: already voted at this sequence");
            }
            Action::ProposerQuarantined => {
                debug!(
                    proposer = %hex::encode(&batch.proposer[..4]),
                    "SBC: ignoring a quarantined proposer"
                );
            }
        }
        Ok(())
    }

    /// Tally a vote, and adopt if it carried.
    #[allow(clippy::too_many_arguments)]
    fn record_vote(
        &self,
        voter: NodeId,
        batch_hash: [u8; 32],
        seq: u64,
        round: u32,
        batch: &ShareBatch,
        now: i64,
    ) {
        let schedule = self.schedule();
        match self
            .chain
            .on_batch_vote(voter, batch_hash, round, seq, &schedule, now)
        {
            VoteAction::Adopt { .. } => {
                match self.chain.finalise(batch, now) {
                    Ok(f) => info!(
                        seq = f.seq,
                        state_root = %hex::encode(&f.state_root[..8]),
                        credited = f.credited,
                        "SBC: adopted"
                    ),
                    // Refusing here is the correct outcome, not a failure to handle: the batch
                    // reached quorum but does not reproduce locally, which is exactly the
                    // divergence the chain exists to surface rather than absorb.
                    Err(e) => warn!(seq, error = %e, "SBC: refused to adopt a finalised batch"),
                }
                self.chain.note_seq_opened(now);
            }
            other => debug!(seq, ?other, "SBC: vote recorded"),
        }
    }

    /// Answer a sync request from what we adopted, or apply a response.
    ///
    /// Request and response are told apart by trial-deserialise, as the payout-checkpoint sync
    /// does — they share a message type and only the shapes distinguish them.
    fn on_sync(&self, envelope: &MessageEnvelope, now: i64) -> GhostResult<()> {
        let msg: ShareBatchSyncMessage = serde_json::from_slice(&envelope.payload)
            .map_err(|e| GhostError::Serialization(format!("share batch sync: {e}")))?;

        match msg {
            ShareBatchSyncMessage::Request { seq } => {
                if let Ok(Some(batch_json)) = self.chain.batch_at(seq) {
                    let resp = ShareBatchSyncMessage::Response { seq, batch_json };
                    let payload = serde_json::to_vec(&resp).map_err(|e| {
                        GhostError::Serialization(format!("share batch sync response: {e}"))
                    })?;
                    (self.send)(MessageType::ShareBatchSync, payload)?;
                } else {
                    // Outside our retention window. Saying nothing is right: a node that cannot
                    // answer must not fabricate one, and the requester will ask a peer that can.
                    debug!(seq, "SBC: sync request outside our window");
                }
            }
            ShareBatchSyncMessage::Response { seq, batch_json } => {
                let batch: ShareBatch = serde_json::from_str(&batch_json)
                    .map_err(|e| GhostError::Serialization(format!("synced batch {seq}: {e}")))?;
                // A synced batch is judged exactly like a proposed one. It arrives from a peer we
                // do not trust, so the only thing that makes it safe is that it must still link to
                // our parent and reproduce its own state root.
                let schedule = self.schedule();
                let checks = (self.checks)();
                match self.chain.on_proposal(&batch, &schedule, &checks, now) {
                    Action::Vote { .. } => match self.chain.finalise(&batch, now) {
                        Ok(f) => info!(seq = f.seq, "SBC: adopted a synced batch"),
                        Err(e) => warn!(seq, error = %e, "SBC: synced batch does not reproduce"),
                    },
                    other => debug!(seq, ?other, "SBC: synced batch not adopted"),
                }
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl MessageHandler for ShareBatchHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        match envelope.msg_type {
            MessageType::ShareBatchProposal => self.on_proposal(&envelope, now),
            MessageType::ShareBatchVote => {
                let vote: ShareBatchVoteMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(format!("share batch vote: {e}")))?;
                // A vote alone cannot finalise: adoption needs the batch itself, and holding a
                // vote for a batch we have not seen is what sync is for.
                // Verify before counting. `signing_bytes` had no caller anywhere in the tree, so
                // every vote was taken on trust: any node could have forged a vote from any peer,
                // at any sequence, for any batch. Quorum built on unverified votes is not quorum.
                if !ghost_common::identity::verify_signature(
                    &vote.voter,
                    &vote.signing_bytes(),
                    &vote.signature,
                )
                .unwrap_or(false)
                {
                    debug!(seq = vote.seq, "SBC: vote signature invalid, dropped");
                    return Ok(());
                }
                let schedule = self.schedule();
                let action = self.chain.on_batch_vote(
                    vote.voter,
                    vote.batch_hash,
                    vote.round,
                    vote.seq,
                    &schedule,
                    now,
                );
                debug!(
                    seq = vote.seq,
                    round = vote.round,
                    ?action,
                    "SBC: peer vote"
                );
                Ok(())
            }
            MessageType::ShareBatchSync => self.on_sync(&envelope, now),
            // Silent, not a warning. `Mesh::register_handler` pushes onto a LIST — every handler
            // is offered every message, so "not mine" is the overwhelmingly common case, not an
            // anomaly. Warning on it produced 168 lines in two minutes on ghost-vm8 (~5,000/hour
            // per node) for entirely normal traffic, which is the log volume #582/#583 exist to
            // stop. Matches the fallback every other handler uses.
            _ => Ok(()),
        }
    }
}
