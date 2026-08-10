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
    /// Precommits we have successfully broadcast, as `(seq, round, batch_hash)`.
    ///
    /// A polka is EDGE-triggered — reported once per `(round, batch)` — so if the precommit it
    /// produces is lost to a full broadcast channel, nothing re-emits it and the node sits locked
    /// but never commit-voting, with no alarm. Recording what actually went out lets the next
    /// message for that sequence notice the gap and retry.
    precommitted: parking_lot::Mutex<std::collections::BTreeSet<(u64, u32, [u8; 32])>>,
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
            precommitted: parking_lot::Mutex::new(std::collections::BTreeSet::new()),
        }
    }

    fn schedule(&self) -> ProposerSchedule {
        ProposerSchedule::new((self.voters)())
    }

    /// Judge a proposed batch and act on the verdict.
    fn on_proposal(&self, envelope: &MessageEnvelope, now: i64) -> GhostResult<()> {
        let batch: ShareBatch = serde_json::from_slice(&envelope.payload)
            .map_err(|e| GhostError::Serialization(format!("share batch proposal: {e}")))?;
        self.judge_and_vote(&batch, now)
    }

    /// Judge a batch and cast whatever vote follows.
    ///
    /// Shared by the message path and by the PROPOSER, which must run its own batch through
    /// exactly this path. `broadcast` filters self, so a proposer never receives its own proposal
    /// back — and without judging it locally it never prevotes it, leaving only N-1 prevoters.
    /// With N=8 and quorum 6 that is fatal at f=2: six live nodes, one of them the silent
    /// proposer, gives five prevotes against a quorum of six. The chain would wedge at exactly the
    /// fault level `bft_threshold(8)=6` advertises it tolerates, and would do it silently.
    pub fn judge_and_vote(&self, batch: &ShareBatch, now: i64) -> GhostResult<()> {
        let batch = batch.clone();
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
        // NOTE: nothing is remembered here, and deliberately so. Request tracking was tried and
        // removed — "we asked" is not proof of being behind, because a peer can induce the request
        // with a junk proposal at head+2 (`verify_batch` defers on POSITION before checking any
        // signature). Adoption is gated on a verified COMMIT CERTIFICATE or our own commit
        // opinion; this function only asks.
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
                    vote.signature,
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

        // Every message for this SEQUENCE is a retry point for a precommit we owe but never got
        // out. Deliberately here and not inside `broadcast_phase_vote`: putting it there made the
        // two mutually recursive, so a full channel recursed until the process stack overflowed —
        // turning the fix for a dropped precommit into a crash triggered by the exact backpressure
        // it was written for. It compiled only because both scopes bind a `vote` with a `.seq`.
        self.retry_owed_precommit(vote.seq);
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
        // Send is fallible (bounded channel, `try_send`). It is attempted BEFORE the self-count
        // was the bug: `?` returned early, so a full channel cost us the broadcast AND our own
        // vote, while the polka edge was already consumed and nothing would re-emit it. Our vote
        // is ours whether or not the network heard it, so count it regardless and let the retry
        // path deal with the broadcast.
        let sent = (self.send)(ty, payload);
        if let (Ok(()), BatchVotePhase::Precommit) = (&sent, phase) {
            let mut done = self.precommitted.lock();
            // Bounded. Nothing removes these on their own — one entry per precommit for the life
            // of the process is a slow but monotone leak on a consensus path.
            while done.len() >= 512 {
                let Some(oldest) = done.iter().next().copied() else {
                    break;
                };
                done.remove(&oldest);
            }
            done.insert((seq, round, batch_hash));
        }
        if let Err(e) = &sent {
            warn!(
                seq,
                round,
                ?phase,
                error = %e,
                "SBC: phase vote not broadcast — will retry on the next message for this sequence"
            );
        }

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
                    vote.signature,
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

    /// Re-emit a precommit this node owes but never managed to broadcast.
    ///
    /// The polka that produced it fires once per `(round, batch)`, so a precommit lost to a full
    /// channel is lost for that round — the node stays locked and never commit-votes, and under
    /// sustained backpressure the sequence cannot close at all. Every subsequent message for the
    /// sequence is a natural retry point, and retrying is free when nothing is owed.
    fn retry_owed_precommit(&self, seq: u64) {
        let Some((round, batch_hash)) = self.chain.lock_at(seq) else {
            return;
        };
        if self.precommitted.lock().contains(&(seq, round, batch_hash)) {
            return;
        }
        if let Err(e) = self.broadcast_phase_vote(
            seq,
            round,
            batch_hash,
            ghost_consensus::message::BatchVotePhase::Precommit,
        ) {
            debug!(seq, round, error = %e, "SBC: precommit retry still blocked");
        } else {
            info!(
                seq,
                round, "SBC: re-emitted a precommit that had been dropped"
            );
        }
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
                    // Attach the proof if we still hold it. Without it the requester can only
                    // fall back to the weaker local-opinion path, which a node that missed this
                    // sequence's consensus can never satisfy.
                    let cert = self.chain.certificate_at(seq);
                    let resp = ShareBatchSyncMessage::Response {
                        seq,
                        batch_json,
                        cert,
                    };
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
            ShareBatchSyncMessage::Response {
                seq,
                batch_json,
                cert,
            } => {
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
                // Two independent bars, because neither alone is enough.
                //
                // If we hold a commit OPINION it binds — a response disagreeing with the decision
                // we watched being made is simply wrong.
                if let Some(decided) = self.chain.committed_at(seq) {
                    if decided != batch.batch_hash() {
                        warn!(
                            seq,
                            "SBC: synced batch is not the one committed here — refused"
                        );
                        return Ok(());
                    }
                } else if let Some(cert) = cert.as_ref().filter(|c| {
                    // Verified against the membership IN FORCE AT THAT SEQUENCE, not the current
                    // set. Those are the same today only because membership is fixed from genesis;
                    // the moment it can change, checking against `schedule()` would make every
                    // certificate minted before the change unverifiable, stranding all prior
                    // history exactly when catch-up matters most.
                    //
                    // The batch carries the membership it was agreed under, and `verify_batch`
                    // faults any batch whose set differs from its parent's — so requiring it to
                    // match OUR set first means the certificate is checked against a membership we
                    // and the chain both agree on, rather than one the sender chose.
                    let batch_voters: Vec<ghost_common::types::NodeId> = {
                        let mut v: Vec<_> = batch.node_shares.iter().map(|(n, _)| *n).collect();
                        v.sort_unstable();
                        v
                    };
                    if batch_voters != self.chain.voter_ids() {
                        warn!(
                            seq,
                            "SBC: synced batch declares a membership we do not hold — refused"
                        );
                        return false;
                    }
                    c.seq == seq
                        && c.batch_hash == batch.batch_hash()
                        && c.verify(&batch_voters, schedule.quorum())
                }) {
                    // A VERIFIED certificate settles it outright. Every signature checks against
                    // the precommit domain for exactly this (seq, round, hash), every signer is a
                    // known voter, and there are at least a quorum of them — so a quorum really
                    // did commit this batch, and no local belief is needed or consulted.
                    //
                    // This is what four rounds of local heuristics were failing to approximate.
                    // The node cannot answer "was this sequence closed?" from its own state; the
                    // peer that watched it close supplies the proof instead.
                    info!(
                        seq,
                        round = cert.round,
                        signers = cert.precommits.len(),
                        "SBC: adopting a synced batch on a verified commit certificate"
                    );
                    // Keep the proof. Otherwise coverage only ever shrinks — a node that caught up
                    // via sync answered later requests with no certificate at all, so a laggard
                    // behind a laggard could never adopt.
                    self.chain.remember_certificate(cert, now);
                } else {
                    // No certificate and no commit opinion: we cannot establish that this sequence
                    // was decided, so we do not adopt. Full stop.
                    //
                    // The previous fallback accepted a response merely because we had ASKED for
                    // it, and that was inducible: a peer sends a junk proposal at head+2,
                    // `verify_batch` defers on POSITION before checking any signature, the hold
                    // path auto-requests head+1 — the open sequence — and the attacker answers it
                    // with a real-but-uncommitted batch. Trying the certificate first protected
                    // nothing, because an attacker simply omits the certificate.
                    //
                    // Removing it costs nothing now: a peer that witnessed the commit HAS the
                    // certificate and will supply it. A peer that has pruned past it cannot help
                    // either way, and the requester asks another. Refusing to adopt what we cannot
                    // verify is the correct answer, not a degradation.
                    debug!(
                        seq,
                        "SBC: sync response carries no verifiable commit proof — not adopted"
                    );
                    return Ok(());
                }
                // Adopted WITHOUT re-asking the rota. Reaching here means either a verified
                // certificate or our own commit opinion already established that a quorum decided
                // this batch, and that settles whose turn it was more strongly than re-deriving
                // the rota from a clock could. Re-asking was not extra safety: `authorise`
                // measures escalation from `(now - parent.close_ts)`, so for history `now` is
                // arbitrary and a certified batch was bounced with `ProposerNotDue` most of the
                // time — with no re-request on that path.
                match self.chain.adopt_committed_batch(&batch, &checks, now) {
                    Ok(Some(f)) => {
                        info!(seq = f.seq, "SBC: adopted a synced batch");
                        // Keep going while we are behind. Catch-up used to advance at most one
                        // sequence per incoming trigger, which is at or below the fleet's own
                        // commit rate — so a gap never closed even when every certificate
                        // verified.
                        if let Err(e) = self.request_sync(seq + 1) {
                            debug!(seq = seq + 1, error = %e, "SBC: could not chain the next sync");
                        }
                    }
                    Ok(None) => debug!(seq, "SBC: synced batch not adopted"),
                    Err(e) => warn!(seq, error = %e, "SBC: synced batch does not reproduce"),
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
