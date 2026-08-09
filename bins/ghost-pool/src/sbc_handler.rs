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
            Action::Vote { batch_hash, seq } => {
                // Sign sequence AND hash together: the hash alone replays at another sequence, and
                // the sequence alone makes every vote at that height interchangeable.
                let mut signing = Vec::with_capacity(40);
                signing.extend_from_slice(&seq.to_le_bytes());
                signing.extend_from_slice(&batch_hash);
                let vote = ShareBatchVoteMessage {
                    seq,
                    batch_hash,
                    voter: self.identity.node_id(),
                    signature: self.identity.sign(&signing),
                };
                let payload = serde_json::to_vec(&vote)
                    .map_err(|e| GhostError::Serialization(format!("share batch vote: {e}")))?;
                (self.send)(MessageType::ShareBatchVote, payload)?;

                // Count our own vote. Without this a node never contributes to the quorum it is
                // waiting on, and a two-node fleet could never finalise anything.
                self.record_vote(self.identity.node_id(), batch_hash, seq, &batch, now);
                debug!(seq, "SBC: voted");
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
    fn record_vote(
        &self,
        voter: NodeId,
        batch_hash: [u8; 32],
        seq: u64,
        batch: &ShareBatch,
        now: i64,
    ) {
        let schedule = self.schedule();
        match self
            .chain
            .on_batch_vote(voter, batch_hash, seq, &schedule, now)
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
                let schedule = self.schedule();
                let action =
                    self.chain
                        .on_batch_vote(vote.voter, vote.batch_hash, vote.seq, &schedule, now);
                debug!(seq = vote.seq, ?action, "SBC: peer vote");
                Ok(())
            }
            MessageType::ShareBatchSync => self.on_sync(&envelope, now),
            other => {
                warn!(?other, "SBC handler received a message it does not handle");
                Ok(())
            }
        }
    }
}
