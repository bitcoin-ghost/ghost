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
use ghost_common::batch_driver::{PhaseAction, PrecommitAction, PrevoteAction};
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::NodeIdentity;
use ghost_common::share_batch::ShareBatch;
use ghost_common::types::NodeId;
use ghost_consensus::mesh::MessageHandler;
use ghost_consensus::message::{MessageEnvelope, MessageType, ShareBatchSyncMessage};
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
        // TWO-PHASE is the live path. The single-phase driver is still compiled and tested, but
        // nothing routes to it any more: one vote per sequence cannot recover from a round that
        // misses quorum, and that wedged seq=1 permanently on the 2026-08-09 six-node run.
        let action = self
            .chain
            .on_proposal_phase(&batch, &schedule, &checks, now);

        match action {
            PhaseAction::Prevote {
                batch_hash,
                seq,
                round,
            } => {
                // `batch_hash` is what the LOCKING RULE chose, which is not necessarily the batch
                // that just arrived — a locked node prevotes its lock. Broadcasting the arriving
                // hash here instead would defeat the lock entirely.
                self.broadcast_phase_vote(
                    seq,
                    round,
                    batch_hash,
                    ghost_consensus::message::BatchVotePhase::Prevote,
                )?;
                debug!(seq, round, "SBC: prevoted");
            }
            PhaseAction::Hold { reason } => {
                debug!(seq = batch.seq, ?reason, "SBC: holding");
                // Being behind is recoverable, and the answer is to ask rather than to wait.
                if let ghost_common::batch_consensus::DeferReason::AheadOfUs { our_seq, .. } =
                    reason
                {
                    let _ = self.request_sync(our_seq + 1);
                }
            }
            PhaseAction::Quarantine { reason, outcome } => {
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
            PhaseAction::ProposerQuarantined => {
                debug!(
                    proposer = %hex::encode(&batch.proposer[..4]),
                    "SBC: ignoring a quarantined proposer"
                );
            }
        }
        Ok(())
    }

    /// Answer a sync request from what we adopted, or apply a response.
    ///
    /// Request and response are told apart by trial-deserialise, as the payout-checkpoint sync
    /// does — they share a message type and only the shapes distinguish them.
    /// Ask peers for the adopted batch at `seq`.
    ///
    /// One implementation, used both when we fall behind and when a sequence commits to a batch we
    /// never saw. Adoption on the commit path used to have no way to ask at all, so a node that
    /// missed the proposal was simply stuck.
    fn request_sync(&self, seq: u64) -> GhostResult<()> {
        let req = ShareBatchSyncMessage::Request { seq };
        let payload = serde_json::to_vec(&req)
            .map_err(|e| GhostError::Serialization(format!("share batch sync request: {e}")))?;
        (self.send)(MessageType::ShareBatchSync, payload)
    }

    /// Handle a peer's PREVOTE or PRECOMMIT.
    ///
    /// One function for both phases because the payload is identical and the handling is
    /// symmetric; the phase decides which signing domain is checked and which tally is fed. It is
    /// NOT a place to be clever about sharing further — verifying against the wrong domain would
    /// let a prevote be counted as a precommit, which is the forgery two-phase exists to stop.
    fn on_phase_vote(
        &self,
        envelope: &MessageEnvelope,
        phase: ghost_consensus::message::BatchVotePhase,
        now: i64,
    ) -> GhostResult<()> {
        use ghost_consensus::message::{BatchVotePhase, ShareBatchPhaseVoteMessage};

        let vote: ShareBatchPhaseVoteMessage = serde_json::from_slice(&envelope.payload)
            .map_err(|e| GhostError::Serialization(format!("share batch phase vote: {e}")))?;

        let schedule = self.schedule();

        // MEMBERSHIP FIRST, and it is not optional. Verifying a signature against the key the
        // MESSAGE ITSELF names authenticates nothing: any reachable peer could mint six fresh
        // keypairs, sign six prevotes and six precommits for a batch of its choosing, and drive
        // this node to lock and latch `committed` on a value the real fleet never proposed —
        // after which the commit latch makes it refuse the fleet's genuine decision forever.
        if !schedule.voters().contains(&vote.voter) {
            debug!(
                seq = vote.seq,
                ?phase,
                "SBC: phase vote from a non-voter, dropped"
            );
            return Ok(());
        }
        // The envelope signature is verified before dispatch, so `sender` is authenticated. A vote
        // claiming to be from someone other than the peer that sent it is a relay attempt.
        if vote.voter != envelope.sender {
            debug!(
                seq = vote.seq,
                ?phase,
                "SBC: phase vote voter does not match sender, dropped"
            );
            return Ok(());
        }

        // Verified against THIS phase's domain. A prevote's signature does not verify as a
        // precommit, so a replayed prevote is dropped here rather than counted as a commitment.
        if !ghost_common::identity::verify_signature(
            &vote.voter,
            &vote.signing_bytes(phase),
            &vote.signature,
        )
        .unwrap_or(false)
        {
            debug!(
                seq = vote.seq,
                ?phase,
                "SBC: phase vote signature invalid, dropped"
            );
            return Ok(());
        }

        match phase {
            BatchVotePhase::Prevote => {
                let action = self.chain.on_batch_prevote(
                    vote.voter,
                    vote.round,
                    vote.batch_hash,
                    vote.seq,
                    &schedule,
                    now,
                );
                if let PrevoteAction::LockAndPrecommit { batch_hash, round } = action {
                    // A polka. We are now locked on this value — precommit it, and ONLY it.
                    self.broadcast_phase_vote(
                        vote.seq,
                        round,
                        batch_hash,
                        BatchVotePhase::Precommit,
                    )?;
                    info!(
                        seq = vote.seq,
                        round, "SBC: polka — locked and precommitted"
                    );
                } else {
                    debug!(seq = vote.seq, round = vote.round, ?action, "SBC: prevote");
                }
            }
            BatchVotePhase::Precommit => {
                let action = self.chain.on_batch_precommit(
                    vote.voter,
                    vote.round,
                    vote.batch_hash,
                    vote.seq,
                    &schedule,
                    now,
                );
                if let PrecommitAction::Commit { batch_hash, votes } = action {
                    info!(
                        seq = vote.seq,
                        round = vote.round,
                        votes,
                        batch = %hex::encode(&batch_hash[..8]),
                        "SBC: COMMITTED"
                    );
                    // Adoption needs the batch itself, which a vote does not carry. If we do not
                    // hold it this is a sync condition, not a failure — the committed hash is
                    // decided and will not change, so fetching later still adopts the right thing.
                    self.adopt_committed(vote.seq, batch_hash, now);
                } else {
                    debug!(
                        seq = vote.seq,
                        round = vote.round,
                        ?action,
                        "SBC: precommit"
                    );
                }
            }
        }
        Ok(())
    }

    /// Sign and broadcast a phase vote.
    fn broadcast_phase_vote(
        &self,
        seq: u64,
        round: u32,
        batch_hash: [u8; 32],
        phase: ghost_consensus::message::BatchVotePhase,
    ) -> GhostResult<()> {
        use ghost_consensus::message::{BatchVotePhase, ShareBatchPhaseVoteMessage};

        let mut vote = ShareBatchPhaseVoteMessage {
            seq,
            round,
            batch_hash,
            voter: self.identity.node_id(),
            signature: [0u8; 64],
        };
        vote.signature = self.identity.sign(&vote.signing_bytes(phase));
        let payload = serde_json::to_vec(&vote)
            .map_err(|e| GhostError::Serialization(format!("share batch phase vote: {e}")))?;
        let ty = match phase {
            BatchVotePhase::Prevote => MessageType::ShareBatchPrevote,
            BatchVotePhase::Precommit => MessageType::ShareBatchPrecommit,
        };
        (self.send)(ty, payload)?;

        // Count our own vote. Without this a node never contributes to the quorum it is waiting
        // on, and a small fleet could never reach one.
        let schedule = self.schedule();
        let now = chrono::Utc::now().timestamp();
        match phase {
            BatchVotePhase::Prevote => {
                let action = self.chain.on_batch_prevote(
                    self.identity.node_id(),
                    round,
                    batch_hash,
                    seq,
                    &schedule,
                    now,
                );
                // Our own prevote can itself complete the polka on a small fleet.
                if let PrevoteAction::LockAndPrecommit { batch_hash, round } = action {
                    self.broadcast_phase_vote(seq, round, batch_hash, BatchVotePhase::Precommit)?;
                }
            }
            BatchVotePhase::Precommit => {
                let action = self.chain.on_batch_precommit(
                    self.identity.node_id(),
                    round,
                    batch_hash,
                    seq,
                    &schedule,
                    now,
                );
                if let PrecommitAction::Commit { batch_hash, .. } = action {
                    self.adopt_committed(seq, batch_hash, now);
                }
            }
        }
        Ok(())
    }

    /// Adopt a committed batch if we hold it.
    ///
    /// Not holding it is a sync condition and not a failure: the decision is final, so fetching
    /// the batch later still adopts exactly the value the fleet agreed.
    fn adopt_committed(&self, seq: u64, batch_hash: [u8; 32], now: i64) {
        // From the cache of batches we VERIFIED, not the adopted-batch store — that store holds
        // only what has ALREADY been adopted, so looking there for the batch we are about to adopt
        // found nothing on every node and stopped the chain dead at its first commit.
        let Some(batch) = self.chain.remembered_proposal(seq, batch_hash) else {
            warn!(
                seq,
                batch = %hex::encode(&batch_hash[..8]),
                "SBC: committed a batch we never saw — requesting it before adoption"
            );
            // Ask for it. The decision is final and will not change, so adopting later still
            // adopts exactly what the fleet agreed.
            if let Err(e) = self.request_sync(seq) {
                warn!(seq, error = %e, "SBC: could not request the committed batch");
            }
            return;
        };
        match self.chain.finalise(&batch, now) {
            Ok(f) => info!(
                seq = f.seq,
                state_root = %hex::encode(&f.state_root[..8]),
                credited = f.credited,
                "SBC: adopted"
            ),
            // The batch reached quorum but does not reproduce locally — exactly the divergence
            // the chain exists to surface rather than absorb.
            Err(e) => warn!(seq, error = %e, "SBC: refused to adopt a committed batch"),
        }
    }

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
                // Judged with the two-phase driver, but note carefully what is being used and
                // what is NOT. `Prevote` here means only "this batch verified and links to our
                // parent" — it is emphatically not a commitment, and the hash it carries may be
                // this node's LOCKED value rather than the batch in hand. So the verdict gates
                // adoption while the batch being adopted is the one that arrived.
                //
                // That is the correct semantic for catching up: the fleet's decision already
                // happened elsewhere, and what makes a synced batch safe is that it hash-chains
                // to our head and reproduces its own state root. Requiring a local quorum to
                // adopt history would mean a node behind by one link could never rejoin.
                // If we hold an OPINION about what was committed here, it binds. Adopting on
                // chain-validity alone let a peer push an unsolicited response carrying a valid
                // but never-committed batch at the OPEN sequence, forking the receiver against
                // whatever the fleet decided next.
                //
                // `None` means no opinion — a node genuinely catching up on history — and there
                // chain validity IS the argument: the batch must link to our head and reproduce
                // its own state root. Demanding a local quorum to adopt HISTORY would leave a node
                // one link behind permanently unable to rejoin.
                if let Some(decided) = self.chain.committed_at(seq) {
                    if decided != batch.batch_hash() {
                        warn!(
                            seq,
                            "SBC: synced batch is not the one committed here — refused"
                        );
                        return Ok(());
                    }
                }
                match self
                    .chain
                    .on_proposal_phase(&batch, &schedule, &checks, now)
                {
                    PhaseAction::Prevote { .. } => match self.chain.finalise(&batch, now) {
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
            // The single-phase vote type is no longer honoured. Counting it fed a tally nothing
            // reads, and leaving a live route to a dead consensus path is how a reader comes to
            // believe the wrong protocol is running. Old peers emitting it are simply ignored —
            // a mixed fleet cannot reach quorum either way, which is why all eight roll together.
            MessageType::ShareBatchPrevote => self.on_phase_vote(
                &envelope,
                ghost_consensus::message::BatchVotePhase::Prevote,
                now,
            ),
            MessageType::ShareBatchPrecommit => self.on_phase_vote(
                &envelope,
                ghost_consensus::message::BatchVotePhase::Precommit,
                now,
            ),
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
