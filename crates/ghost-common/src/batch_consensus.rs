//! Who may propose a batch, and how a stalled sequence gets past a proposer that is not there.
//!
//! The share-batch chain is a hash chain, so `seq` cannot be skipped: if the node whose turn it is
//! is offline, plain round-robin deadlocks and no share is ever agreed again. Escalation is what
//! keeps the chain moving — after a stall interval the turn passes to the next node, then the next,
//! cycling for as long as it takes.
//!
//! Two things make that safe rather than chaotic:
//!
//! - Only the node at the *exact* current escalation proposes, so at most one node is trying at a
//!   time. Acceptance is slightly wider than that (see [`ESCALATION_GRACE_STEPS`](crate::batch_consensus::ESCALATION_GRACE_STEPS)) because clocks
//!   are not identical, and a node whose clock is a few seconds behind must not read a legitimate
//!   proposal as a hostile one.
//! - One vote per `seq`, ever. Two individually-valid batches at the same height must not both
//!   reach 67%, and the only place that can be prevented is at the voter.
//!
//! Dark code: nothing wires this into a runtime path yet.

use std::collections::BTreeMap;

use crate::constants::bft_threshold;

/// How long a sequence may sit unproposed before the turn passes to the next node.
///
/// 90 s matches the existing round cadence, which is the interval the fleet is already known to
/// tolerate: long enough that an ordinary GC pause or a slow block read is not mistaken for an
/// absent proposer, short enough that a genuinely dead node costs one interval rather than a shift.
pub const STALL_ESCALATION_SECS: i64 = 90;

/// How many escalation steps either side of its own a node will still accept a proposal from.
///
/// Clocks differ. Without a grace window, a node a few seconds behind would reject the proposal the
/// rest of the fleet is voting on, and — because verification failure is terminal by design — would
/// treat a healthy peer as Byzantine. One step is enough to absorb any skew that is not itself a
/// fault, and keeps at most two nodes authorised at once rather than, after a full cycle, everyone.
///
/// A prefix window (`0..=current`) was the obvious alternative and is wrong: once escalation passes
/// the size of the ring every node is authorised forever, so a long stall ends with the whole fleet
/// proposing at once and splitting its own vote.
pub const ESCALATION_GRACE_STEPS: u32 = 1;

/// Whether a node may propose a given sequence right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorisation {
    /// Yes — at this escalation step.
    Authorised { escalation: u32 },
    /// It *will* be their turn, but not yet. A fast clock, not a fault: retry, do not quarantine.
    TooEarly { escalation: u32 },
    /// Not their turn at any step near now.
    NotAProposer,
}

/// What a vote attempt did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteDecision {
    /// First vote at this sequence.
    Fresh,
    /// The same batch again — idempotent, so a resend costs nothing.
    Repeat,
    /// A *different* batch at a sequence already voted on. Refused: this is the guard that stops
    /// two valid batches both reaching quorum.
    Conflict { already: [u8; 32] },
}

/// The proposer rota over a voter set.
///
/// Voters are sorted and deduplicated on construction, so every node derives the same rota from the
/// same set regardless of the order it learned them in. That is the whole reason this type exists:
/// a rota that depends on arrival order is a rota two nodes disagree about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposerSchedule {
    voters: Vec<[u8; 32]>,
}

impl ProposerSchedule {
    pub fn new(voters: impl IntoIterator<Item = [u8; 32]>) -> Self {
        let mut voters: Vec<[u8; 32]> = voters.into_iter().collect();
        voters.sort_unstable();
        voters.dedup();
        Self { voters }
    }

    pub fn voters(&self) -> &[[u8; 32]] {
        &self.voters
    }

    pub fn len(&self) -> usize {
        self.voters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.voters.is_empty()
    }

    /// Votes needed to finalise, via the one fleet-wide threshold.
    pub fn quorum(&self) -> usize {
        bft_threshold(self.voters.len())
    }

    /// Whose turn it is at a given escalation step.
    ///
    /// `seq` seeds the rota so consecutive batches do not all start with the same node, and the
    /// escalation offset walks the ring from there.
    pub fn proposer_at(&self, seq: u64, escalation: u32) -> Option<[u8; 32]> {
        if self.voters.is_empty() {
            return None;
        }
        let idx = (seq.wrapping_add(escalation as u64)) % self.voters.len() as u64;
        Some(self.voters[idx as usize])
    }

    /// How many stall intervals have elapsed since the sequence opened.
    ///
    /// Uncapped. It keeps cycling the ring for as long as the stall lasts, which is what a chain
    /// that cannot skip a height needs — there is no point at which "nobody is due" is a safe state.
    pub fn escalation_at(&self, opened_ts: i64, now: i64) -> u32 {
        let elapsed = now.saturating_sub(opened_ts).max(0);
        (elapsed / STALL_ESCALATION_SECS).clamp(0, u32::MAX as i64) as u32
    }

    /// Should *this* node propose right now?
    ///
    /// Deliberately narrower than [`Self::authorise`]: exactly one node proposes at a time, while
    /// acceptance tolerates a step of skew either way. Being generous here instead would put two
    /// nodes on the same sequence and split the vote.
    pub fn is_my_turn(&self, seq: u64, me: &[u8; 32], opened_ts: i64, now: i64) -> bool {
        self.proposer_at(seq, self.escalation_at(opened_ts, now))
            .is_some_and(|p| &p == me)
    }

    /// May this node propose this sequence, as far as we can tell from here?
    ///
    /// Searches the grace window around our own escalation rather than testing one step, because
    /// the sender's clock decides which step *they* proposed at and ours decides which step we
    /// think it is. Distinguishing `TooEarly` from `NotAProposer` matters: the first is a skew
    /// condition to retry, the second is a claim to a turn that is not theirs.
    pub fn authorise(
        &self,
        seq: u64,
        candidate: &[u8; 32],
        opened_ts: i64,
        now: i64,
    ) -> Authorisation {
        if self.voters.is_empty() {
            return Authorisation::NotAProposer;
        }
        let current = self.escalation_at(opened_ts, now);
        let lowest = current.saturating_sub(ESCALATION_GRACE_STEPS);

        for step in lowest..=current {
            if self.proposer_at(seq, step).as_ref() == Some(candidate) {
                return Authorisation::Authorised { escalation: step };
            }
        }
        for step in (current + 1)..=(current + ESCALATION_GRACE_STEPS) {
            if self.proposer_at(seq, step).as_ref() == Some(candidate) {
                return Authorisation::TooEarly { escalation: step };
            }
        }
        Authorisation::NotAProposer
    }
}

/// Why a batch could not be judged yet. **Not** a fault: sync, wait, or ask again.
///
/// The distinction from [`FaultReason`] is the load-bearing part of this module. A fault is
/// terminal — the proposer is quarantined and the batch is never retried — so anything that an
/// honest node could produce merely by holding a different view must land here instead. Getting
/// that wrong does not produce a false alarm; it produces a fleet that quarantines itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeferReason {
    /// Its sequence is at or below our head. Almost always a resend.
    Stale { batch_seq: u64, our_seq: u64 },
    /// Its sequence is beyond our head + 1: we are behind and must catch up first.
    AheadOfUs { batch_seq: u64, our_seq: u64 },
    /// Right sequence, different parent. Ambiguous by nature — it may be us on the wrong parent —
    /// so the answer is to sync and re-judge, never to accuse.
    ParentMismatch,
    /// Their clock is ahead of ours. See [`Authorisation::TooEarly`].
    ProposerTooEarly { escalation: u32 },
    /// Not their turn as far as our voter set goes. Deferred rather than faulted **because voter
    /// sets themselves are not always identical across the fleet** — an honest proposer under a
    /// membership view we have not caught up with would otherwise be quarantined for it.
    ProposerNotDue,
}

/// A defect in the batch itself. Terminal: quarantine the proposer, alarm, never retry.
///
/// Every variant here is decidable from the batch's own bytes plus a parent that is already
/// finalised — so no honest node can produce one by holding a different view. That is the test for
/// membership of this enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultReason {
    /// Time ran backwards against a finalised parent.
    CloseTimeNotForward { close_ts: i64, parent_close_ts: i64 },
    /// Shares are not in the canonical order the batch hash commits to.
    SharesOutOfOrder { at_index: usize },
    /// The same share twice — work counted twice.
    DuplicateShare { share_hash: [u8; 32] },
    /// A share does not prove itself: bad PoW or a bad GHOST-09 signature.
    InvalidShare { share_hash: [u8; 32] },
    /// The claimed state root is not what folding these shares onto the parent state gives.
    StateRootMismatch {
        claimed: [u8; 32],
        computed: [u8; 32],
    },
    /// `truncated` and `pending_count` contradict each other, so a peer cannot tell a full batch
    /// from a starved one — the #558 failure, restated.
    TruncationContradiction { truncated: bool, pending_count: u32 },
    /// The proposer did not sign the batch it proposed.
    ProposerSignatureInvalid,
    /// The batch changed the qualified-node set without authority to.
    ///
    /// Membership is CONSENSUS DATA carried by the chain, not something each node re-derives. It
    /// used to come from a live per-node database query, and that single fact defeated four
    /// successive mechanisms for proving a sequence had committed: quorum is
    /// `bft_threshold(view)`, so nodes disagreed on the bar, and a commit certificate hashes the
    /// voter set, so it could never match. You cannot prove a quorum over a membership the two
    /// parties do not share.
    ///
    /// Carrying it forward makes every node derive the same set from the same chain, with no query
    /// on the consensus path at all. Genesis seeds it from the ratified payout checkpoint — an
    /// object the fleet already agreed on — and it is fixed from there. Changing it is a fault
    /// because a proposer that could rewrite membership could vote itself a quorum.
    MembershipChanged {
        parent_count: usize,
        batch_count: usize,
    },
}

/// The outcome of judging a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchVerdict {
    /// Valid — vote for it, at this round.
    ///
    /// The round is the escalation step the proposer was authorised at, carried out of
    /// verification rather than recomputed by the caller: this is the only place that establishes
    /// WHICH attempt the batch belongs to, and a vote naming a different round than the one that
    /// authorised it would be counted against the wrong candidate.
    Valid { round: u32 },
    /// Cannot judge yet. Recoverable.
    Defer(DeferReason),
    /// Defective. Terminal.
    Fault(FaultReason),
}

/// The checks this module cannot do itself.
///
/// Share validity is policy (difficulty targets, which signature encoding is in force at a height)
/// and proposer signatures need the identity layer. Injecting both keeps the decision logic pure
/// and, more usefully, testable: a test can make a share invalid without constructing a real one.
pub trait BatchChecks {
    /// Does this share prove itself — proof of work, and a GHOST-09 signature over it?
    fn share_is_valid(&self, share: &crate::types::ShareProof) -> bool;
    /// Did this proposer sign this batch hash?
    fn proposer_signed(&self, proposer: &[u8; 32], batch_hash: &[u8; 32], signature: &[u8])
        -> bool;
}

/// Judge a batch against a finalised parent.
///
/// The order of the checks is deliberate: everything recoverable is decided *before* anything that
/// could brand a peer. A batch we are not in a position to judge must never be mistaken for a bad
/// one, because the response to a bad one cannot be taken back.
///
/// `parent_balances` are the running balances after the parent — the state this batch folds onto.
pub fn verify_batch<C: BatchChecks>(
    batch: &crate::share_batch::ShareBatch,
    parent: &crate::share_batch::ShareBatch,
    parent_balances: &BTreeMap<String, i64>,
    schedule: &ProposerSchedule,
    now: i64,
    checks: &C,
) -> BatchVerdict {
    use std::cmp::Ordering;

    // --- position in the chain: are we even looking at the same place? ---
    match batch.seq.cmp(&parent.seq.saturating_add(1)) {
        Ordering::Less => {
            return BatchVerdict::Defer(DeferReason::Stale {
                batch_seq: batch.seq,
                our_seq: parent.seq,
            })
        }
        Ordering::Greater => {
            return BatchVerdict::Defer(DeferReason::AheadOfUs {
                batch_seq: batch.seq,
                our_seq: parent.seq,
            })
        }
        Ordering::Equal => {}
    }
    if batch.prev_batch_hash != parent.batch_hash() {
        return BatchVerdict::Defer(DeferReason::ParentMismatch);
    }

    // --- whose turn: the sequence opened when its parent closed, which every node agrees on ---
    //
    let round = match schedule.authorise(batch.seq, &batch.proposer, parent.close_ts, now) {
        Authorisation::Authorised { escalation } => escalation,
        Authorisation::TooEarly { escalation } => {
            return BatchVerdict::Defer(DeferReason::ProposerTooEarly { escalation })
        }
        Authorisation::NotAProposer => return BatchVerdict::Defer(DeferReason::ProposerNotDue),
    };

    verify_batch_contents(batch, parent, parent_balances, checks, round)
}

/// Verify a batch that a COMMIT CERTIFICATE has already proved was committed.
///
/// Identical to [`verify_batch`] except the proposer rota is not consulted. That is not a
/// relaxation: a certificate is a quorum of signed precommits, and a quorum deciding a batch
/// settles whose turn it was far more strongly than re-deriving the rota from a clock could.
///
/// Everything that makes a synced batch safe is still checked — it must link to our parent,
/// declare the same membership, carry only valid shares in canonical order, and reproduce its own
/// state root.
pub fn verify_committed_batch<C: BatchChecks>(
    batch: &crate::share_batch::ShareBatch,
    parent: &crate::share_batch::ShareBatch,
    parent_balances: &BTreeMap<String, i64>,
    checks: &C,
) -> BatchVerdict {
    use std::cmp::Ordering;

    // Position still matters: a batch that does not follow our head cannot be folded onto it,
    // certificate or not.
    match batch.seq.cmp(&parent.seq.saturating_add(1)) {
        Ordering::Less => {
            return BatchVerdict::Defer(DeferReason::Stale {
                batch_seq: batch.seq,
                our_seq: parent.seq,
            })
        }
        Ordering::Greater => {
            return BatchVerdict::Defer(DeferReason::AheadOfUs {
                batch_seq: batch.seq,
                our_seq: parent.seq,
            })
        }
        Ordering::Equal => {}
    }
    if batch.prev_batch_hash != parent.batch_hash() {
        return BatchVerdict::Defer(DeferReason::ParentMismatch);
    }
    verify_batch_contents(batch, parent, parent_balances, checks, 0)
}

/// Everything about a batch that is its own fault, independent of whose turn it was.
///
/// Split out so a batch already proved committed can be checked without the rota. A commit
/// certificate is a quorum of signed precommits, which SUBSUMES "was the proposer due" — the fleet
/// settled that when it committed. Re-asking is not extra safety, it is a bug: `authorise`
/// measures escalation from `(now - parent.close_ts)`, and for a batch synced long after the fact
/// `now` is arbitrary, so the original proposer sits inside the +/-1 window only about a quarter of
/// the time. A cert-verified batch was being bounced with `ProposerNotDue` on most attempts, and
/// the failure path does not even re-request.
fn verify_batch_contents<C: BatchChecks>(
    batch: &crate::share_batch::ShareBatch,
    parent: &crate::share_batch::ShareBatch,
    parent_balances: &BTreeMap<String, i64>,
    checks: &C,
    round: u32,
) -> BatchVerdict {
    use crate::share_batch::{canonical_cmp, compute_state_root, fold_shares};
    use std::cmp::Ordering;

    // --- from here on, every failure is the batch's own fault ---

    // Membership is carried by the chain, not re-derived per node. A proposer that could rewrite
    // it could hand itself a quorum, so any change is terminal rather than a defer.
    if batch.node_shares != parent.node_shares {
        return BatchVerdict::Fault(FaultReason::MembershipChanged {
            parent_count: parent.node_shares.len(),
            batch_count: batch.node_shares.len(),
        });
    }

    if batch.close_ts <= parent.close_ts {
        return BatchVerdict::Fault(FaultReason::CloseTimeNotForward {
            close_ts: batch.close_ts,
            parent_close_ts: parent.close_ts,
        });
    }

    if batch.truncated != (batch.pending_count > 0) {
        return BatchVerdict::Fault(FaultReason::TruncationContradiction {
            truncated: batch.truncated,
            pending_count: batch.pending_count,
        });
    }

    for (i, pair) in batch.shares.windows(2).enumerate() {
        match canonical_cmp(&pair[0], &pair[1]) {
            Ordering::Less => {}
            Ordering::Equal => {
                return BatchVerdict::Fault(FaultReason::DuplicateShare {
                    share_hash: pair[1].share_hash,
                })
            }
            Ordering::Greater => {
                return BatchVerdict::Fault(FaultReason::SharesOutOfOrder { at_index: i + 1 })
            }
        }
    }

    for share in &batch.shares {
        if !checks.share_is_valid(share) {
            return BatchVerdict::Fault(FaultReason::InvalidShare {
                share_hash: share.share_hash,
            });
        }
    }

    let mut balances = parent_balances.clone();
    fold_shares(&mut balances, &batch.shares);
    let computed = compute_state_root(&balances, batch.seq, batch.close_ts);
    if computed != batch.state_root {
        return BatchVerdict::Fault(FaultReason::StateRootMismatch {
            claimed: batch.state_root,
            computed,
        });
    }

    // Last, because it is the most expensive and the cheap structural checks have already had
    // their chance to reject.
    if !checks.proposer_signed(
        &batch.proposer,
        &batch.batch_hash(),
        &batch.proposer_signature,
    ) {
        return BatchVerdict::Fault(FaultReason::ProposerSignatureInvalid);
    }

    BatchVerdict::Valid { round }
}

/// What recording a peer's vote did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TallyEvent {
    /// Counted.
    Recorded { approvals: usize, needed: usize },
    /// The same vote again. Ignored, not punished — resends happen.
    Duplicate,
    /// This voter has now approved two different batches at one sequence. Their votes are
    /// discarded — every one of them, including the first — because a node that will say two
    /// contradictory things has told us nothing.
    Equivocation {
        voter: [u8; 32],
        first: [u8; 32],
        second: [u8; 32],
    },
    /// Quorum reached. This batch is final.
    Finalised { batch_hash: [u8; 32], votes: usize },
}

/// Votes at one sequence, across every candidate batch proposed for it.
///
/// Per-sequence rather than per-batch on purpose: equivocation is only visible when the candidates
/// are counted together. A tally that only ever saw one batch could not tell that the voter
/// approving it had approved a different one a moment earlier.
#[derive(Debug, Clone)]
pub struct SeqTally {
    seq: u64,
    quorum: usize,
    /// Who each voter approved. One entry per voter — the second, differing entry is equivocation.
    choice: BTreeMap<[u8; 32], [u8; 32]>,
    /// Voters whose votes are void.
    equivocators: std::collections::BTreeSet<[u8; 32]>,
    finalised: Option<[u8; 32]>,
}

impl SeqTally {
    pub fn new(seq: u64, quorum: usize) -> Self {
        Self {
            seq,
            quorum,
            choice: BTreeMap::new(),
            equivocators: std::collections::BTreeSet::new(),
            finalised: None,
        }
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn finalised(&self) -> Option<[u8; 32]> {
        self.finalised
    }

    pub fn equivocators(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.equivocators.iter()
    }

    /// Approvals for one candidate, excluding voters whose word is worthless.
    pub fn approvals_for(&self, batch_hash: &[u8; 32]) -> usize {
        self.choice
            .iter()
            .filter(|(voter, chosen)| *chosen == batch_hash && !self.equivocators.contains(*voter))
            .count()
    }

    /// Record an approval.
    ///
    /// Finalisation is reported once and only once: a batch that has reached quorum is final, and
    /// re-announcing it on every later vote would have a caller applying it repeatedly.
    pub fn record(&mut self, voter: [u8; 32], batch_hash: [u8; 32]) -> TallyEvent {
        if self.equivocators.contains(&voter) {
            return TallyEvent::Duplicate;
        }

        match self.choice.get(&voter) {
            Some(existing) if *existing == batch_hash => return TallyEvent::Duplicate,
            Some(existing) => {
                let first = *existing;
                self.equivocators.insert(voter);
                self.choice.remove(&voter);
                return TallyEvent::Equivocation {
                    voter,
                    first,
                    second: batch_hash,
                };
            }
            None => {
                self.choice.insert(voter, batch_hash);
            }
        }

        let approvals = self.approvals_for(&batch_hash);
        if approvals >= self.quorum && self.finalised.is_none() {
            self.finalised = Some(batch_hash);
            return TallyEvent::Finalised {
                batch_hash,
                votes: approvals,
            };
        }
        TallyEvent::Recorded {
            approvals,
            needed: self.quorum,
        }
    }
}

/// One vote per sequence, remembered.
///
/// Round-robin decides who *asks*; this decides that a node answers once. Without it two valid
/// batches at the same `seq` — which escalation makes possible, since a slow proposer and its
/// successor can both be in flight — could each collect 67% from overlapping sets, and the chain
/// would fork at a height that by construction cannot fork.
#[derive(Debug, Default, Clone)]
pub struct SeqVoteLock {
    voted: BTreeMap<u64, [u8; 32]>,
}

impl SeqVoteLock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a vote, or refuse it.
    ///
    /// Re-voting for the same batch is allowed and reported as `Repeat`: proposals are resent, and
    /// treating a resend as equivocation would punish an honest peer for a dropped packet.
    pub fn try_vote(&mut self, seq: u64, batch_hash: [u8; 32]) -> VoteDecision {
        match self.voted.get(&seq) {
            Some(existing) if *existing == batch_hash => VoteDecision::Repeat,
            Some(existing) => VoteDecision::Conflict { already: *existing },
            None => {
                self.voted.insert(seq, batch_hash);
                VoteDecision::Fresh
            }
        }
    }

    /// What we voted for at a sequence, if anything.
    pub fn vote_at(&self, seq: u64) -> Option<[u8; 32]> {
        self.voted.get(&seq).copied()
    }

    /// Forget sequences below a finalised height.
    ///
    /// Bounded memory matters, but the bound must sit *below* what is final: dropping a lock at a
    /// sequence still in flight would let the same node vote twice for it, which is the one thing
    /// this type exists to prevent.
    pub fn prune_below(&mut self, seq: u64) {
        self.voted.retain(|s, _| *s >= seq);
    }

    pub fn len(&self) -> usize {
        self.voted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.voted.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn voter(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn eight() -> ProposerSchedule {
        ProposerSchedule::new((1..=8u8).map(voter))
    }

    /// Two nodes that learned the voter set in different orders must derive the same rota, or they
    /// disagree about whose proposal is legitimate while both behave correctly.
    #[test]
    fn the_rota_does_not_depend_on_the_order_voters_were_learned() {
        let forwards = ProposerSchedule::new((1..=8u8).map(voter));
        let backwards = ProposerSchedule::new((1..=8u8).rev().map(voter));
        assert_eq!(forwards, backwards);
        for seq in 0..40u64 {
            assert_eq!(forwards.proposer_at(seq, 0), backwards.proposer_at(seq, 0));
        }
    }

    /// A duplicate would give one node two slots in the ring and inflate the quorum denominator.
    #[test]
    fn a_repeated_voter_counts_once() {
        let s = ProposerSchedule::new([voter(1), voter(2), voter(1), voter(2)]);
        assert_eq!(s.len(), 2);
    }

    /// Consecutive sequences must not all fall to the same node.
    #[test]
    fn the_turn_advances_with_the_sequence() {
        let s = eight();
        let first_cycle: Vec<_> = (0..8).map(|q| s.proposer_at(q, 0).unwrap()).collect();
        let mut unique = first_cycle.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), 8, "one full cycle should cover every voter");
        assert_eq!(
            s.proposer_at(8, 0),
            s.proposer_at(0, 0),
            "and then it wraps"
        );
    }

    /// **The deadlock this exists to break.** With the scheduled proposer absent, the turn must
    /// reach somebody else — a hash chain cannot skip the height, so a stuck `seq` is a chain that
    /// never agrees another share.
    #[test]
    fn a_stalled_sequence_passes_to_the_next_node() {
        let s = eight();
        let opened = 1_700_000_000;
        let absent = s.proposer_at(4, 0).unwrap();

        assert!(s.is_my_turn(4, &absent, opened, opened));

        let after_one = opened + STALL_ESCALATION_SECS;
        assert!(
            !s.is_my_turn(4, &absent, opened, after_one),
            "the absent node's turn must end"
        );
        let successor = s.proposer_at(4, 1).unwrap();
        assert_ne!(successor, absent);
        assert!(s.is_my_turn(4, &successor, opened, after_one));
    }

    /// Escalation keeps cycling rather than running out. A node offline for an hour must not leave
    /// the chain with nobody due.
    #[test]
    fn escalation_keeps_cycling_past_a_full_ring() {
        let s = eight();
        let opened = 0;
        let long_stall = STALL_ESCALATION_SECS * 20;
        let k = s.escalation_at(opened, long_stall);
        assert_eq!(k, 20);
        assert!(
            s.proposer_at(0, k).is_some(),
            "somebody is always due, however long the stall"
        );
    }

    /// Exactly one node proposes at a time. If escalation authorised everyone once it exceeded the
    /// ring size, a long stall would end with the whole fleet proposing and splitting its own vote.
    #[test]
    fn only_one_node_proposes_at_a_time_however_long_the_stall() {
        let s = eight();
        let opened = 0;
        for steps in 0..25u32 {
            let now = opened + STALL_ESCALATION_SECS * steps as i64;
            let due = s
                .voters()
                .iter()
                .filter(|v| s.is_my_turn(3, v, opened, now))
                .count();
            assert_eq!(due, 1, "exactly one node is due at escalation {steps}");
        }
    }

    /// Acceptance is one step wider than proposing, in both directions, so ordinary clock skew is
    /// not read as a hostile claim to someone else's turn.
    #[test]
    fn acceptance_tolerates_a_step_of_clock_skew_each_way() {
        let s = eight();
        let opened = 0;
        let now = STALL_ESCALATION_SECS * 5; // our escalation is 5

        let previous = s.proposer_at(2, 4).unwrap();
        let current = s.proposer_at(2, 5).unwrap();
        let next = s.proposer_at(2, 6).unwrap();

        assert_eq!(
            s.authorise(2, &previous, opened, now),
            Authorisation::Authorised { escalation: 4 },
            "a node whose clock is a step behind is still legitimate"
        );
        assert_eq!(
            s.authorise(2, &current, opened, now),
            Authorisation::Authorised { escalation: 5 }
        );
        assert_eq!(
            s.authorise(2, &next, opened, now),
            Authorisation::TooEarly { escalation: 6 },
            "a fast clock is a skew condition to retry, not a fault to quarantine"
        );
    }

    /// The window really is a window. A node three steps away is not authorised — otherwise the
    /// grace that absorbs skew would quietly become "anyone may propose".
    #[test]
    fn a_node_far_from_its_turn_is_not_authorised() {
        let s = eight();
        let opened = 0;
        let now = STALL_ESCALATION_SECS * 5;
        let far = s.proposer_at(2, 9).unwrap();
        assert_eq!(
            s.authorise(2, &far, opened, now),
            Authorisation::NotAProposer
        );
    }

    /// A voter set of one (a fresh single-operator fleet) must still make progress rather than
    /// dividing by zero or finding nobody due.
    #[test]
    fn a_single_voter_is_always_due() {
        let s = ProposerSchedule::new([voter(1)]);
        assert!(s.is_my_turn(0, &voter(1), 0, 0));
        assert!(s.is_my_turn(99, &voter(1), 0, STALL_ESCALATION_SECS * 7));
        assert_eq!(s.quorum(), 1);
    }

    /// An empty set is a lost quorum, not a panic.
    #[test]
    fn an_empty_voter_set_has_nobody_due() {
        let s = ProposerSchedule::new([]);
        assert!(s.is_empty());
        assert_eq!(s.proposer_at(0, 0), None);
        assert_eq!(s.authorise(0, &voter(1), 0, 0), Authorisation::NotAProposer);
    }

    #[test]
    fn quorum_is_the_fleet_wide_threshold() {
        assert_eq!(eight().quorum(), bft_threshold(8));
    }

    /// **The fork guard.** Escalation makes two valid batches at one `seq` possible — a slow
    /// proposer and its successor can both be in flight — and if a node voted for both, each could
    /// collect 67% from overlapping sets and the chain would fork at a height that cannot fork.
    #[test]
    fn a_second_batch_at_the_same_sequence_is_refused() {
        let mut lock = SeqVoteLock::new();
        assert_eq!(lock.try_vote(7, [0xAA; 32]), VoteDecision::Fresh);
        assert_eq!(
            lock.try_vote(7, [0xBB; 32]),
            VoteDecision::Conflict {
                already: [0xAA; 32]
            }
        );
        assert_eq!(lock.vote_at(7), Some([0xAA; 32]));
    }

    /// A resent proposal is not equivocation. Punishing it would make packet loss look Byzantine.
    #[test]
    fn voting_for_the_same_batch_again_is_idempotent() {
        let mut lock = SeqVoteLock::new();
        lock.try_vote(7, [0xAA; 32]);
        assert_eq!(lock.try_vote(7, [0xAA; 32]), VoteDecision::Repeat);
        assert_eq!(lock.len(), 1);
    }

    /// Different sequences are independent — the lock must not become a global one-vote rule.
    #[test]
    fn other_sequences_are_unaffected() {
        let mut lock = SeqVoteLock::new();
        lock.try_vote(7, [0xAA; 32]);
        assert_eq!(lock.try_vote(8, [0xBB; 32]), VoteDecision::Fresh);
    }

    // ---- verify_batch ----

    use crate::share_batch::{compute_state_root, fold_shares, ShareBatch};
    use crate::types::ShareProof;

    /// Accepts everything. Defects are injected by editing the batch, not by faking a checker, so
    /// the tests exercise the real decision path.
    struct AllGood;
    impl BatchChecks for AllGood {
        fn share_is_valid(&self, _: &ShareProof) -> bool {
            true
        }
        fn proposer_signed(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8]) -> bool {
            true
        }
    }

    struct RejectsShares;
    impl BatchChecks for RejectsShares {
        fn share_is_valid(&self, _: &ShareProof) -> bool {
            false
        }
        fn proposer_signed(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8]) -> bool {
            true
        }
    }

    struct RejectsSignature;
    impl BatchChecks for RejectsSignature {
        fn share_is_valid(&self, _: &ShareProof) -> bool {
            true
        }
        fn proposer_signed(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8]) -> bool {
            false
        }
    }

    fn a_share(ts: u64, byte: u8, addr: &str, work: f64) -> ShareProof {
        ShareProof {
            round_id: 1,
            miner_id: [byte; 32],
            difficulty: work,
            work,
            share_hash: [byte; 32],
            timestamp: ts,
            received_by: [0u8; 32],
            template_id: None,
            payout_address: Some(addr.to_string()),
            header: None,
            signature: None,
        }
    }

    const PARENT_CLOSE: i64 = 1_700_000_000;

    fn a_parent() -> ShareBatch {
        ShareBatch {
            seq: 41,
            prev_batch_hash: [0x11; 32],
            close_ts: PARENT_CLOSE,
            proposer: voter(1),
            shares: vec![],
            settled_blocks: vec![],
            node_shares: vec![],
            state_root: [0x22; 32],
            truncated: false,
            pending_count: 0,
            proposer_signature: vec![1, 2, 3],
        }
    }

    /// A well-formed child of `a_parent()`, proposed by whoever is actually due at escalation 0.
    fn a_child(
        parent: &ShareBatch,
        schedule: &ProposerSchedule,
    ) -> (ShareBatch, BTreeMap<String, i64>) {
        let parent_balances: BTreeMap<String, i64> = BTreeMap::new();
        let mut shares = vec![
            a_share(1000, 1, "bc1qalice", 1.5),
            a_share(1000, 2, "bc1qbob", 2.5),
            a_share(1001, 3, "bc1qalice", 0.25),
        ];
        crate::share_batch::canonical_sort(&mut shares);

        let mut balances = parent_balances.clone();
        fold_shares(&mut balances, &shares);
        let close_ts = parent.close_ts + 30;
        let state_root = compute_state_root(&balances, parent.seq + 1, close_ts);

        let batch = ShareBatch {
            seq: parent.seq + 1,
            prev_batch_hash: parent.batch_hash(),
            close_ts,
            proposer: schedule.proposer_at(parent.seq + 1, 0).unwrap(),
            shares,
            settled_blocks: vec![],
            node_shares: vec![],
            state_root,
            truncated: false,
            pending_count: 0,
            proposer_signature: vec![9, 9, 9],
        };
        (batch, parent_balances)
    }

    #[test]
    fn a_well_formed_batch_is_valid() {
        let s = eight();
        let parent = a_parent();
        let (batch, balances) = a_child(&parent, &s);
        assert_eq!(
            verify_batch(&batch, &parent, &balances, &s, PARENT_CLOSE + 1, &AllGood),
            BatchVerdict::Valid { round: 0 }
        );
    }

    /// **The rule that keeps the fleet from quarantining itself.** Everything an honest node can
    /// produce by holding a different view defers; nothing about it is terminal.
    #[test]
    fn view_differences_defer_and_never_fault() {
        let s = eight();
        let parent = a_parent();
        let (good, balances) = a_child(&parent, &s);
        let now = PARENT_CLOSE + 1;

        let mut stale = good.clone();
        stale.seq = parent.seq;
        assert_eq!(
            verify_batch(&stale, &parent, &balances, &s, now, &AllGood),
            BatchVerdict::Defer(DeferReason::Stale {
                batch_seq: parent.seq,
                our_seq: parent.seq
            })
        );

        let mut ahead = good.clone();
        ahead.seq = parent.seq + 5;
        assert_eq!(
            verify_batch(&ahead, &parent, &balances, &s, now, &AllGood),
            BatchVerdict::Defer(DeferReason::AheadOfUs {
                batch_seq: parent.seq + 5,
                our_seq: parent.seq
            })
        );

        let mut other_parent = good.clone();
        other_parent.prev_batch_hash = [0xFF; 32];
        assert_eq!(
            verify_batch(&other_parent, &parent, &balances, &s, now, &AllGood),
            BatchVerdict::Defer(DeferReason::ParentMismatch),
            "a different parent may be us on the wrong chain — sync, never accuse"
        );

        let mut not_due = good.clone();
        not_due.proposer = s.proposer_at(parent.seq + 1, 4).unwrap();
        assert_eq!(
            verify_batch(&not_due, &parent, &balances, &s, now, &AllGood),
            BatchVerdict::Defer(DeferReason::ProposerNotDue),
            "voter sets are not always identical across the fleet, so this cannot be terminal"
        );

        let mut early = good.clone();
        early.proposer = s.proposer_at(parent.seq + 1, 1).unwrap();
        assert_eq!(
            verify_batch(&early, &parent, &balances, &s, now, &AllGood),
            BatchVerdict::Defer(DeferReason::ProposerTooEarly { escalation: 1 })
        );
    }

    /// Position is judged before contents. A batch we are not in a position to judge must not be
    /// branded for a defect we were never entitled to look for.
    #[test]
    fn an_unjudgeable_batch_is_not_branded_for_its_contents() {
        let s = eight();
        let parent = a_parent();
        let (good, balances) = a_child(&parent, &s);

        // Both out of position AND thoroughly defective.
        let mut broken = good.clone();
        broken.seq = parent.seq + 9;
        broken.state_root = [0xAB; 32];
        broken.shares.reverse();
        broken.pending_count = 7;

        assert!(
            matches!(
                verify_batch(&broken, &parent, &balances, &s, PARENT_CLOSE + 1, &AllGood),
                BatchVerdict::Defer(_)
            ),
            "out of position wins over any defect — the response to a fault cannot be taken back"
        );
    }

    /// Reordering breaks the hash the fleet agreed on, and is decidable from the bytes alone.
    #[test]
    fn shares_out_of_canonical_order_are_a_fault() {
        let s = eight();
        let parent = a_parent();
        let (mut batch, balances) = a_child(&parent, &s);
        batch.shares.reverse();
        assert!(matches!(
            verify_batch(&batch, &parent, &balances, &s, PARENT_CLOSE + 1, &AllGood),
            BatchVerdict::Fault(FaultReason::SharesOutOfOrder { .. })
        ));
    }

    /// The same share twice is the same work paid twice.
    #[test]
    fn a_duplicated_share_is_a_fault() {
        let s = eight();
        let parent = a_parent();
        let (mut batch, balances) = a_child(&parent, &s);
        let dup = batch.shares[0].clone();
        batch.shares.insert(1, dup);
        assert_eq!(
            verify_batch(&batch, &parent, &balances, &s, PARENT_CLOSE + 1, &AllGood),
            BatchVerdict::Fault(FaultReason::DuplicateShare {
                share_hash: batch.shares[0].share_hash
            })
        );
    }

    /// The root is the whole point: it is what a validator recomputes instead of trusting.
    #[test]
    fn a_wrong_state_root_is_a_fault() {
        let s = eight();
        let parent = a_parent();
        let (mut batch, balances) = a_child(&parent, &s);
        batch.state_root = [0xAB; 32];
        assert!(matches!(
            verify_batch(&batch, &parent, &balances, &s, PARENT_CLOSE + 1, &AllGood),
            BatchVerdict::Fault(FaultReason::StateRootMismatch { .. })
        ));
    }

    /// A single micro-work difference must be caught — the root exists precisely so that "nearly
    /// the same" is not "the same".
    #[test]
    fn one_micro_work_of_drift_is_caught() {
        let s = eight();
        let parent = a_parent();
        let (mut batch, mut balances) = a_child(&parent, &s);
        // One micro-work — a millionth of a share — added to the parent state the batch folds onto.
        balances.insert("bc1qalice".to_string(), 1);

        assert!(
            matches!(
                verify_batch(&batch, &parent, &balances, &s, PARENT_CLOSE + 1, &AllGood),
                BatchVerdict::Fault(FaultReason::StateRootMismatch { .. })
            ),
            "the root exists so that nearly the same is not the same"
        );

        // And the root an honest node computes from that same state is accepted, so the check is
        // detecting the drift rather than rejecting everything.
        let mut expected = balances.clone();
        fold_shares(&mut expected, &batch.shares);
        batch.state_root = compute_state_root(&expected, batch.seq, batch.close_ts);
        assert_eq!(
            verify_batch(&batch, &parent, &balances, &s, PARENT_CLOSE + 1, &AllGood),
            BatchVerdict::Valid { round: 0 }
        );
    }

    /// `truncated` and `pending_count` must agree, or a peer cannot tell a full batch from a
    /// starved one — which is #558 restated.
    #[test]
    fn a_truncation_flag_that_contradicts_the_count_is_a_fault() {
        let s = eight();
        let parent = a_parent();
        let (mut batch, balances) = a_child(&parent, &s);

        batch.pending_count = 12; // still truncated: false
        assert_eq!(
            verify_batch(&batch, &parent, &balances, &s, PARENT_CLOSE + 1, &AllGood),
            BatchVerdict::Fault(FaultReason::TruncationContradiction {
                truncated: false,
                pending_count: 12
            })
        );

        batch.truncated = true;
        batch.pending_count = 0;
        assert!(matches!(
            verify_batch(&batch, &parent, &balances, &s, PARENT_CLOSE + 1, &AllGood),
            BatchVerdict::Fault(FaultReason::TruncationContradiction { .. })
        ));
    }

    #[test]
    fn a_close_time_that_does_not_advance_is_a_fault() {
        let s = eight();
        let parent = a_parent();
        let (mut batch, balances) = a_child(&parent, &s);
        batch.close_ts = parent.close_ts;
        assert!(matches!(
            verify_batch(&batch, &parent, &balances, &s, PARENT_CLOSE + 1, &AllGood),
            BatchVerdict::Fault(FaultReason::CloseTimeNotForward { .. })
        ));
    }

    #[test]
    fn a_share_that_does_not_prove_itself_is_a_fault() {
        let s = eight();
        let parent = a_parent();
        let (batch, balances) = a_child(&parent, &s);
        assert!(matches!(
            verify_batch(
                &batch,
                &parent,
                &balances,
                &s,
                PARENT_CLOSE + 1,
                &RejectsShares
            ),
            BatchVerdict::Fault(FaultReason::InvalidShare { .. })
        ));
    }

    #[test]
    fn an_unsigned_batch_is_a_fault() {
        let s = eight();
        let parent = a_parent();
        let (batch, balances) = a_child(&parent, &s);
        assert_eq!(
            verify_batch(
                &batch,
                &parent,
                &balances,
                &s,
                PARENT_CLOSE + 1,
                &RejectsSignature
            ),
            BatchVerdict::Fault(FaultReason::ProposerSignatureInvalid)
        );
    }

    // ---- SeqTally ----

    #[test]
    fn a_batch_finalises_at_quorum_and_only_announces_it_once() {
        let mut t = SeqTally::new(9, 6);
        let batch = [0xAA; 32];
        for n in 1..=5u8 {
            assert!(matches!(
                t.record(voter(n), batch),
                TallyEvent::Recorded { .. }
            ));
        }
        assert_eq!(
            t.record(voter(6), batch),
            TallyEvent::Finalised {
                batch_hash: batch,
                votes: 6
            }
        );
        assert!(
            matches!(t.record(voter(7), batch), TallyEvent::Recorded { .. }),
            "a later vote must not re-announce finalisation, or the caller applies it twice"
        );
        assert_eq!(t.finalised(), Some(batch));
    }

    /// **Equivocation voids the voter, not just the second vote.** A node that will approve two
    /// contradictory batches has told us nothing, so its first vote is worth no more than its
    /// second — and leaving that first vote counted is how a two-faced node pushes a batch over
    /// the line.
    #[test]
    fn an_equivocating_voter_stops_counting_for_anything() {
        let mut t = SeqTally::new(9, 3);
        let a = [0xAA; 32];
        let b = [0xBB; 32];

        t.record(voter(1), a);
        t.record(voter(2), a);
        assert_eq!(t.approvals_for(&a), 2);

        assert_eq!(
            t.record(voter(1), b),
            TallyEvent::Equivocation {
                voter: voter(1),
                first: a,
                second: b
            }
        );
        assert_eq!(
            t.approvals_for(&a),
            1,
            "the first vote must be withdrawn too"
        );
        assert_eq!(t.approvals_for(&b), 0);
        assert_eq!(t.equivocators().count(), 1);

        // And they cannot buy their way back in.
        assert_eq!(t.record(voter(1), a), TallyEvent::Duplicate);
        assert_eq!(t.approvals_for(&a), 1);
    }

    /// Two candidates at one sequence is the normal consequence of escalation, not an attack. Both
    /// tally independently; only one can reach quorum, because the vote lock stops any node
    /// backing both.
    #[test]
    fn two_candidates_at_one_sequence_tally_independently() {
        let mut t = SeqTally::new(9, 6);
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        for n in 1..=4u8 {
            t.record(voter(n), a);
        }
        for n in 5..=8u8 {
            t.record(voter(n), b);
        }
        assert_eq!(t.approvals_for(&a), 4);
        assert_eq!(t.approvals_for(&b), 4);
        assert_eq!(t.finalised(), None, "neither reaches 6 of 8 — correct");
    }

    #[test]
    fn a_resent_vote_is_not_equivocation() {
        let mut t = SeqTally::new(9, 6);
        let a = [0xAA; 32];
        t.record(voter(1), a);
        assert_eq!(t.record(voter(1), a), TallyEvent::Duplicate);
        assert_eq!(t.approvals_for(&a), 1);
    }

    /// Pruning bounds the memory, and must only ever drop what is already final: a lock released
    /// at a sequence still in flight would let the same node vote for it twice.
    #[test]
    fn pruning_keeps_the_finalised_boundary_and_above() {
        let mut lock = SeqVoteLock::new();
        for seq in 0..10u64 {
            lock.try_vote(seq, [seq as u8; 32]);
        }
        lock.prune_below(6);
        assert_eq!(lock.vote_at(5), None);
        assert_eq!(
            lock.vote_at(6),
            Some([6u8; 32]),
            "the boundary itself stays"
        );
        assert_eq!(lock.len(), 4);
    }
}

#[cfg(test)]
mod committed_history_tests {
    use super::*;
    use crate::share_batch::{compute_state_root, fold_shares, ShareBatch};
    use crate::types::ShareProof;

    struct AllGood;
    impl BatchChecks for AllGood {
        fn share_is_valid(&self, _: &ShareProof) -> bool {
            true
        }
        fn proposer_signed(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8]) -> bool {
            true
        }
    }

    const PARENT_CLOSE: i64 = 1_000;

    fn parent() -> ShareBatch {
        ShareBatch {
            seq: 0,
            prev_batch_hash: [0u8; 32],
            close_ts: PARENT_CLOSE,
            proposer: [0u8; 32],
            shares: vec![],
            settled_blocks: vec![],
            node_shares: vec![([1u8; 32], 5)],
            state_root: compute_state_root(&BTreeMap::new(), 0, PARENT_CLOSE),
            truncated: false,
            pending_count: 0,
            proposer_signature: vec![],
        }
    }

    fn child(p: &ShareBatch, proposer: [u8; 32]) -> ShareBatch {
        let mut after: BTreeMap<String, i64> = BTreeMap::new();
        let shares: Vec<ShareProof> = vec![];
        fold_shares(&mut after, &shares);
        let close_ts = p.close_ts + 30;
        ShareBatch {
            seq: p.seq + 1,
            prev_batch_hash: p.batch_hash(),
            close_ts,
            proposer,
            shares,
            settled_blocks: vec![],
            node_shares: p.node_shares.clone(),
            state_root: compute_state_root(&after, p.seq + 1, close_ts),
            truncated: false,
            pending_count: 0,
            proposer_signature: vec![9],
        }
    }

    /// **Audit 8, finding A2.** A certified batch adopts whatever the rota says now.
    ///
    /// `authorise` measures escalation from `(now - parent.close_ts)`, so for a batch synced long
    /// after the fact `now` is arbitrary and the original proposer lands inside the ±1 window only
    /// about a quarter of the time. A batch whose commit certificate had ALREADY verified was
    /// bounced with `ProposerNotDue` on most attempts — and that path does not re-request.
    #[test]
    fn a_certified_batch_verifies_whatever_the_rota_says_now() {
        let s = ProposerSchedule::new((1..=8u8).map(|n| [n; 32]));
        let p = parent();
        let balances = BTreeMap::new();

        let due = s.proposer_at(1, 0).expect("due");
        let b = child(&p, due);

        // Sample a full rotation rather than one arbitrary instant. Writing this with a single
        // "an hour later" picked +3600 s — escalation 40, and 40 % 8 == 0, so the rota had turned
        // all the way back to the SAME proposer and the precondition silently did not hold. A
        // magic offset here tests the calendar, not the code.
        let mut rejected_somewhere = false;
        for step in 2..12u32 {
            let later = PARENT_CLOSE + (STALL_ESCALATION_SECS * step as i64);
            if matches!(
                verify_batch(&b, &p, &balances, &s, later, &AllGood),
                BatchVerdict::Defer(DeferReason::ProposerNotDue)
            ) {
                rejected_somewhere = true;
                // And at that very same instant the committed path must accept it.
                assert!(
                    matches!(
                        verify_committed_batch(&b, &p, &balances, &AllGood),
                        BatchVerdict::Valid { .. }
                    ),
                    "certified history must adopt at step {step}, where the rota rejects it"
                );
            }
        }
        assert!(
            rejected_somewhere,
            "precondition: the ordinary path must reject history on the rota at some step"
        );

        assert!(
            matches!(
                verify_committed_batch(&b, &p, &balances, &AllGood),
                BatchVerdict::Valid { .. }
            ),
            "a batch already proved committed must not be re-judged on whose turn it was"
        );
    }

    /// Skipping the rota must NOT skip anything that makes a synced batch safe.
    #[test]
    fn a_certified_batch_still_has_to_link_and_reproduce() {
        let s = ProposerSchedule::new((1..=8u8).map(|n| [n; 32]));
        let p = parent();
        let balances = BTreeMap::new();
        let due = s.proposer_at(1, 0).expect("due");

        let mut orphan = child(&p, due);
        orphan.prev_batch_hash = [0xFF; 32];
        assert!(matches!(
            verify_committed_batch(&orphan, &p, &balances, &AllGood),
            BatchVerdict::Defer(DeferReason::ParentMismatch)
        ));

        let mut wrong = child(&p, due);
        wrong.state_root = [0xFF; 32];
        assert!(matches!(
            verify_committed_batch(&wrong, &p, &balances, &AllGood),
            BatchVerdict::Fault(FaultReason::StateRootMismatch { .. })
        ));

        let mut rewritten = child(&p, due);
        rewritten.node_shares.push(([0xEE; 32], 5));
        assert!(matches!(
            verify_committed_batch(&rewritten, &p, &balances, &AllGood),
            BatchVerdict::Fault(FaultReason::MembershipChanged { .. })
        ));
    }
}
