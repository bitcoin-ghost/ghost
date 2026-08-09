//! The decision layer of the batch chain: what to do, given what has arrived.
//!
//! Everything here is a pure function of state that is handed in. It reads no clock, opens no
//! socket and touches no database — a caller supplies `now` and the inputs, and gets back an
//! action to perform. That is deliberate: consensus logic that reaches for the world cannot be
//! tested for the cases that matter, and the cases that matter here are the rare ones.
//!
//! The pieces it ties together already exist and are each tested on their own:
//! [`ProposerSchedule`] decides whose turn it is, [`crate::batch_consensus::verify_batch`]
//! judges a batch, [`SeqVoteLock`] stops this node backing two batches at one height,
//! [`SeqTally`] counts, and [`Quarantine`] holds what a terminal fault costs a peer.
//!
//! Dark code: nothing wires this into a runtime path yet.

use crate::batch_consensus::{
    verify_batch, BatchChecks, BatchVerdict, DeferReason, FaultReason, ProposerSchedule, SeqTally,
    SeqVoteLock, TallyEvent, VoteDecision,
};
use crate::batch_quarantine::{Quarantine, QuarantineOutcome};
use crate::share_batch::ShareBatch;

/// What the caller should do about a batch that arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Vote for it, and broadcast that vote.
    Vote { batch_hash: [u8; 32], seq: u64 },
    /// Do nothing yet. Recoverable — the reason says whether to sync, wait, or ignore.
    Hold { reason: DeferReason },
    /// The batch is defective. Quarantine its proposer and alarm.
    ///
    /// Carries the quarantine outcome so the caller can tell an ordinary exclusion from the
    /// fleet-level condition of quorum becoming unreachable — different facts, different alarms.
    Quarantine {
        reason: FaultReason,
        outcome: QuarantineOutcome,
    },
    /// This node already voted for a *different* batch at this sequence.
    ///
    /// Not a fault of the proposer: escalation legitimately puts two batches in flight at one
    /// height. Refusing the second vote is the whole reason neither can wrongly reach quorum.
    AlreadyVotedElsewhere { voted_for: [u8; 32] },
    /// The proposer is quarantined, so its batches are not judged at all.
    ///
    /// Judging first would spend real work — verifying every share — on a peer whose answer is
    /// already worthless, which is a cheap denial-of-service to hand out.
    ProposerQuarantined,
}

/// Everything the driver needs to decide, gathered by the caller.
pub struct BatchContext<'a, C: BatchChecks> {
    /// The finalised head this batch should build on.
    pub parent: &'a ShareBatch,
    /// Running balances after the parent.
    pub parent_balances: &'a std::collections::BTreeMap<String, i64>,
    /// The voter set.
    pub schedule: &'a ProposerSchedule,
    /// Share and signature checks.
    pub checks: &'a C,
    /// Wall clock, supplied rather than read.
    pub now: i64,
}

/// Decide what to do with an incoming batch, and record the consequences.
///
/// The order is chosen so nothing expensive happens on behalf of a peer that has already proved
/// itself unreliable, and so nothing irreversible happens before the cheap recoverable checks have
/// had their say.
pub fn on_batch<C: BatchChecks>(
    batch: &ShareBatch,
    ctx: &BatchContext<'_, C>,
    quarantine: &mut Quarantine,
    lock: &mut SeqVoteLock,
) -> Action {
    if quarantine.is_quarantined(&batch.proposer) {
        return Action::ProposerQuarantined;
    }

    match verify_batch(
        batch,
        ctx.parent,
        ctx.parent_balances,
        ctx.schedule,
        ctx.now,
        ctx.checks,
    ) {
        BatchVerdict::Defer(reason) => Action::Hold { reason },
        BatchVerdict::Fault(reason) => {
            let outcome = quarantine.quarantine(
                batch.proposer,
                reason.clone(),
                batch.seq,
                ctx.now,
                ctx.schedule,
            );
            Action::Quarantine { reason, outcome }
        }
        BatchVerdict::Valid { .. } => {
            let hash = batch.batch_hash();
            match lock.try_vote(batch.seq, hash) {
                VoteDecision::Fresh | VoteDecision::Repeat => Action::Vote {
                    batch_hash: hash,
                    seq: batch.seq,
                },
                VoteDecision::Conflict { already } => {
                    Action::AlreadyVotedElsewhere { voted_for: already }
                }
            }
        }
    }
}

/// What arrived with a peer's vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteAction {
    /// Counted; not final yet.
    Counted { approvals: usize, needed: usize },
    /// Final. Adopt this batch as the new head.
    Adopt { batch_hash: [u8; 32], votes: usize },
    /// Ignored — a resend, or a voter whose word is already worthless.
    Ignored,
    /// This voter approved two different batches at one sequence. Its votes are void.
    ///
    /// Provable misbehaviour, from two messages it signed itself — so it is treated exactly like a
    /// batch-level fault, and for the same reason: no honest node can produce it by holding a
    /// different view.
    Equivocation {
        voter: [u8; 32],
        outcome: QuarantineOutcome,
    },
}

/// Record a peer's vote and say whether the sequence is decided.
pub fn on_vote(
    voter: [u8; 32],
    batch_hash: [u8; 32],
    tally: &mut SeqTally,
    quarantine: &mut Quarantine,
    schedule: &ProposerSchedule,
    now: i64,
) -> VoteAction {
    if quarantine.is_quarantined(&voter) {
        return VoteAction::Ignored;
    }

    match tally.record(voter, batch_hash) {
        TallyEvent::Recorded { approvals, needed } => VoteAction::Counted { approvals, needed },
        TallyEvent::Duplicate => VoteAction::Ignored,
        TallyEvent::Finalised { batch_hash, votes } => VoteAction::Adopt { batch_hash, votes },
        TallyEvent::Equivocation {
            voter,
            first,
            second,
        } => {
            let outcome = quarantine.quarantine(
                voter,
                // Reused deliberately: signing two contradictory things is the same *kind* of
                // claim as an internally inconsistent batch — self-refuting on its own evidence.
                FaultReason::ProposerSignatureInvalid,
                tally.seq(),
                now,
                schedule,
            );
            debug_assert_ne!(first, second, "equivocation requires two different batches");
            VoteAction::Equivocation { voter, outcome }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share_batch::{compute_state_root, fold_shares};
    use crate::types::ShareProof;
    use std::collections::BTreeMap;

    struct AllGood;
    impl BatchChecks for AllGood {
        fn share_is_valid(&self, _: &ShareProof) -> bool {
            true
        }
        fn proposer_signed(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8]) -> bool {
            true
        }
    }

    fn voter(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn eight() -> ProposerSchedule {
        ProposerSchedule::new((1..=8u8).map(voter))
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
            proposer_signature: vec![1],
        }
    }

    fn a_child(parent: &ShareBatch, schedule: &ProposerSchedule) -> ShareBatch {
        let balances: BTreeMap<String, i64> = BTreeMap::new();
        let mut shares = vec![ShareProof {
            round_id: 1,
            miner_id: [1u8; 32],
            difficulty: 1.0,
            work: 1.0,
            share_hash: [1u8; 32],
            timestamp: 1000,
            received_by: [0u8; 32],
            template_id: None,
            payout_address: Some("bc1qalice".into()),
            header: None,
            signature: None,
        }];
        crate::share_batch::canonical_sort(&mut shares);
        let mut after = balances.clone();
        fold_shares(&mut after, &shares);
        let close_ts = parent.close_ts + 30;
        ShareBatch {
            seq: parent.seq + 1,
            prev_batch_hash: parent.batch_hash(),
            close_ts,
            proposer: schedule.proposer_at(parent.seq + 1, 0).unwrap(),
            shares,
            settled_blocks: vec![],
            node_shares: vec![],
            state_root: compute_state_root(&after, parent.seq + 1, close_ts),
            truncated: false,
            pending_count: 0,
            proposer_signature: vec![9],
        }
    }

    fn ctx<'a>(
        parent: &'a ShareBatch,
        balances: &'a BTreeMap<String, i64>,
        schedule: &'a ProposerSchedule,
        checks: &'a AllGood,
    ) -> BatchContext<'a, AllGood> {
        BatchContext {
            parent,
            parent_balances: balances,
            schedule,
            checks,
            now: PARENT_CLOSE + 1,
        }
    }

    #[test]
    fn a_valid_batch_is_voted_for() {
        let (schedule, parent, checks, balances) = (eight(), a_parent(), AllGood, BTreeMap::new());
        let batch = a_child(&parent, &schedule);
        let c = ctx(&parent, &balances, &schedule, &checks);

        assert_eq!(
            on_batch(&batch, &c, &mut Quarantine::new(), &mut SeqVoteLock::new()),
            Action::Vote {
                batch_hash: batch.batch_hash(),
                seq: batch.seq
            }
        );
    }

    /// **Nothing expensive is spent on a peer already known to be unreliable.** Verifying a batch
    /// checks every share in it; doing that for a quarantined proposer is a denial-of-service
    /// anyone could trigger by staying quarantined and shouting.
    #[test]
    fn a_quarantined_proposer_is_not_even_judged() {
        let (schedule, parent, checks, balances) = (eight(), a_parent(), AllGood, BTreeMap::new());
        let batch = a_child(&parent, &schedule);

        let mut q = Quarantine::new();
        q.quarantine(
            batch.proposer,
            FaultReason::ProposerSignatureInvalid,
            1,
            0,
            &schedule,
        );

        let c = ctx(&parent, &balances, &schedule, &checks);
        assert_eq!(
            on_batch(&batch, &c, &mut q, &mut SeqVoteLock::new()),
            Action::ProposerQuarantined
        );
    }

    /// A defect quarantines the proposer, and the action carries the quorum picture so the caller
    /// can tell an ordinary exclusion from the fleet losing the ability to agree.
    #[test]
    fn a_defective_batch_quarantines_its_proposer() {
        let (schedule, parent, checks, balances) = (eight(), a_parent(), AllGood, BTreeMap::new());
        let mut batch = a_child(&parent, &schedule);
        batch.state_root = [0xAB; 32];

        let mut q = Quarantine::new();
        let c = ctx(&parent, &balances, &schedule, &checks);
        match on_batch(&batch, &c, &mut q, &mut SeqVoteLock::new()) {
            Action::Quarantine { reason, outcome } => {
                assert!(matches!(reason, FaultReason::StateRootMismatch { .. }));
                assert_eq!(
                    outcome,
                    QuarantineOutcome::Quarantined {
                        remaining: 7,
                        needed: 6
                    }
                );
            }
            other => panic!("expected a quarantine, got {other:?}"),
        }
        assert!(q.is_quarantined(&batch.proposer));
    }

    /// A batch we cannot judge yet must not brand anyone.
    #[test]
    fn an_out_of_position_batch_only_holds() {
        let (schedule, parent, checks, balances) = (eight(), a_parent(), AllGood, BTreeMap::new());
        let mut batch = a_child(&parent, &schedule);
        batch.seq = parent.seq + 7;

        let mut q = Quarantine::new();
        let c = ctx(&parent, &balances, &schedule, &checks);
        assert!(matches!(
            on_batch(&batch, &c, &mut q, &mut SeqVoteLock::new()),
            Action::Hold { .. }
        ));
        assert!(q.is_empty(), "holding must never quarantine");
    }

    /// **The fork guard, end to end.** Escalation can legitimately put two valid batches at one
    /// sequence; this node backs the first and refuses the second, which is what stops both
    /// reaching 67%. The second proposer is *not* at fault.
    #[test]
    fn a_second_valid_batch_at_one_sequence_is_refused_without_blame() {
        let (schedule, parent, checks, balances) = (eight(), a_parent(), AllGood, BTreeMap::new());
        let first = a_child(&parent, &schedule);
        let mut second = a_child(&parent, &schedule);
        second.close_ts += 1; // a different, equally valid batch
        second.state_root = {
            let mut after = balances.clone();
            fold_shares(&mut after, &second.shares);
            compute_state_root(&after, second.seq, second.close_ts)
        };

        let mut q = Quarantine::new();
        let mut lock = SeqVoteLock::new();
        let c = ctx(&parent, &balances, &schedule, &checks);

        assert!(matches!(
            on_batch(&first, &c, &mut q, &mut lock),
            Action::Vote { .. }
        ));
        assert_eq!(
            on_batch(&second, &c, &mut q, &mut lock),
            Action::AlreadyVotedElsewhere {
                voted_for: first.batch_hash()
            }
        );
        assert!(q.is_empty(), "two valid batches is not misbehaviour");
    }

    #[test]
    fn votes_accumulate_and_the_batch_is_adopted_at_quorum() {
        let schedule = eight();
        let mut tally = SeqTally::new(42, schedule.quorum());
        let mut q = Quarantine::new();
        let hash = [0xAA; 32];

        for n in 1..=5u8 {
            assert!(matches!(
                on_vote(voter(n), hash, &mut tally, &mut q, &schedule, 0),
                VoteAction::Counted { .. }
            ));
        }
        assert_eq!(
            on_vote(voter(6), hash, &mut tally, &mut q, &schedule, 0),
            VoteAction::Adopt {
                batch_hash: hash,
                votes: 6
            }
        );
    }

    /// Equivocation is provable from two messages the peer signed itself, so it is treated exactly
    /// like a batch-level fault — and the voter's earlier vote is voided with it.
    #[test]
    fn an_equivocating_voter_is_quarantined() {
        let schedule = eight();
        let mut tally = SeqTally::new(42, schedule.quorum());
        let mut q = Quarantine::new();

        on_vote(voter(2), [0xAA; 32], &mut tally, &mut q, &schedule, 0);
        match on_vote(voter(2), [0xBB; 32], &mut tally, &mut q, &schedule, 0) {
            VoteAction::Equivocation { voter: v, .. } => assert_eq!(v, voter(2)),
            other => panic!("expected equivocation, got {other:?}"),
        }
        assert!(q.is_quarantined(&voter(2)));
        assert_eq!(tally.approvals_for(&[0xAA; 32]), 0);
    }

    /// A quarantined peer's vote is not counted at all.
    #[test]
    fn a_quarantined_voter_is_ignored() {
        let schedule = eight();
        let mut tally = SeqTally::new(42, schedule.quorum());
        let mut q = Quarantine::new();
        q.quarantine(
            voter(3),
            FaultReason::ProposerSignatureInvalid,
            1,
            0,
            &schedule,
        );

        assert_eq!(
            on_vote(voter(3), [0xAA; 32], &mut tally, &mut q, &schedule, 0),
            VoteAction::Ignored
        );
        assert_eq!(tally.approvals_for(&[0xAA; 32]), 0);
    }
}

// ---------------------------------------------------------------------------
// Two-phase driver
//
// Parallel to `on_batch` / `on_vote` above rather than replacing them, so the single-phase path
// stays intact and testable while the shadow chain is migrated. The single-phase path is retained
// ONLY for that migration and must not outlive it: it cannot recover from a round that misses
// quorum, which is what wedged seq=1 on the six-node run of 2026-08-09.
// ---------------------------------------------------------------------------

use crate::batch_two_phase::{PrecommitOutcome, PrevoteOutcome, SeqConsensus};

/// What to do about a batch under two-phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhaseAction {
    /// Prevote for this batch at this round, and broadcast it.
    ///
    /// The hash is what the LOCKING RULE selected, which is not necessarily the batch that
    /// arrived: a locked node prevotes its locked value instead. That substitution is the entire
    /// mechanism preventing a committed batch from being contradicted at a later round.
    Prevote {
        batch_hash: [u8; 32],
        seq: u64,
        round: u32,
    },
    /// Nothing to do yet; recoverable.
    Hold { reason: DeferReason },
    /// Defective batch. Quarantine the proposer.
    Quarantine {
        reason: FaultReason,
        outcome: QuarantineOutcome,
    },
    /// The proposer is already excluded, so the batch is not judged at all.
    ProposerQuarantined,
}

/// Judge an incoming batch and say what to prevote.
pub fn on_batch_phase<C: BatchChecks>(
    batch: &ShareBatch,
    ctx: &BatchContext<'_, C>,
    quarantine: &mut Quarantine,
    consensus: &SeqConsensus,
) -> PhaseAction {
    if quarantine.is_quarantined(&batch.proposer) {
        return PhaseAction::ProposerQuarantined;
    }

    match verify_batch(
        batch,
        ctx.parent,
        ctx.parent_balances,
        ctx.schedule,
        ctx.now,
        ctx.checks,
    ) {
        BatchVerdict::Defer(reason) => PhaseAction::Hold { reason },
        BatchVerdict::Fault(reason) => {
            let outcome = quarantine.quarantine(
                batch.proposer,
                reason.clone(),
                batch.seq,
                ctx.now,
                ctx.schedule,
            );
            PhaseAction::Quarantine { reason, outcome }
        }
        BatchVerdict::Valid { round } => {
            let offered = batch.batch_hash();
            // The locking rule decides what we prevote — NOT the batch that arrived.
            match consensus.what_to_prevote(Some(offered)) {
                Some(batch_hash) => PhaseAction::Prevote {
                    batch_hash,
                    seq: batch.seq,
                    round,
                },
                // Unreachable while `offered` is Some, but expressed rather than unwrapped: a
                // future caller passing None must hold, not panic on a consensus path.
                None => PhaseAction::Hold {
                    reason: DeferReason::ProposerNotDue,
                },
            }
        }
    }
}

/// What a peer's prevote produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrevoteAction {
    /// Counted; no polka yet.
    Counted { votes: usize, needed: usize },
    /// A polka. Lock on this value and precommit it — in that order, because precommitting a value
    /// this node is not locked on is exactly the behaviour two-phase exists to forbid.
    LockAndPrecommit { batch_hash: [u8; 32], round: u32 },
    /// A resend, or a voter whose word is already worthless.
    Ignored,
    /// Two prevotes for different batches in one round. Provable, terminal.
    Equivocation {
        voter: [u8; 32],
        outcome: QuarantineOutcome,
    },
}

/// Record a peer's prevote and say what follows.
pub fn on_prevote(
    voter: [u8; 32],
    round: u32,
    batch_hash: [u8; 32],
    consensus: &mut SeqConsensus,
    quarantine: &mut Quarantine,
    schedule: &ProposerSchedule,
    now: i64,
) -> PrevoteAction {
    if quarantine.is_quarantined(&voter) {
        return PrevoteAction::Ignored;
    }
    match consensus.record_prevote(round, voter, batch_hash) {
        PrevoteOutcome::Counted { votes, needed } => PrevoteAction::Counted { votes, needed },
        PrevoteOutcome::Ignored => PrevoteAction::Ignored,
        PrevoteOutcome::Polka { batch_hash, .. } => {
            // Apply the polka to our own lock first. `apply_polka` refuses stale evidence, so a
            // polka from a round below our lock cannot drag us back to an abandoned candidate.
            consensus.apply_polka(round, batch_hash);
            PrevoteAction::LockAndPrecommit { batch_hash, round }
        }
        PrevoteOutcome::Equivocation { .. } => {
            let outcome = quarantine.quarantine(
                voter,
                FaultReason::ProposerSignatureInvalid,
                consensus.seq(),
                now,
                schedule,
            );
            PrevoteAction::Equivocation { voter, outcome }
        }
    }
}

/// What a peer's precommit produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrecommitAction {
    Counted {
        votes: usize,
        needed: usize,
    },
    /// Final. Adopt this batch — the only path to adoption under two-phase.
    Commit {
        batch_hash: [u8; 32],
        votes: usize,
    },
    Ignored,
    Equivocation {
        voter: [u8; 32],
        outcome: QuarantineOutcome,
    },
}

/// Record a peer's precommit and say whether the sequence is decided.
pub fn on_precommit(
    voter: [u8; 32],
    round: u32,
    batch_hash: [u8; 32],
    consensus: &mut SeqConsensus,
    quarantine: &mut Quarantine,
    schedule: &ProposerSchedule,
    now: i64,
) -> PrecommitAction {
    if quarantine.is_quarantined(&voter) {
        return PrecommitAction::Ignored;
    }
    match consensus.record_precommit(round, voter, batch_hash) {
        PrecommitOutcome::Counted { votes, needed } => PrecommitAction::Counted { votes, needed },
        PrecommitOutcome::Ignored => PrecommitAction::Ignored,
        PrecommitOutcome::Commit { batch_hash, votes } => {
            PrecommitAction::Commit { batch_hash, votes }
        }
        PrecommitOutcome::Equivocation { .. } => {
            let outcome = quarantine.quarantine(
                voter,
                FaultReason::ProposerSignatureInvalid,
                consensus.seq(),
                now,
                schedule,
            );
            PrecommitAction::Equivocation { voter, outcome }
        }
    }
}

#[cfg(test)]
mod phase_driver_tests {
    use super::*;
    use crate::batch_two_phase::SeqConsensus;
    use crate::share_batch::{compute_state_root, fold_shares};
    use crate::types::ShareProof;
    use std::collections::BTreeMap;

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

    fn eight() -> ProposerSchedule {
        ProposerSchedule::new((1..=8u8).map(|n| [n; 32]))
    }

    fn a_parent() -> ShareBatch {
        ShareBatch {
            seq: 0,
            prev_batch_hash: [0u8; 32],
            close_ts: PARENT_CLOSE,
            proposer: [0u8; 32],
            shares: vec![],
            settled_blocks: vec![],
            node_shares: vec![],
            state_root: compute_state_root(&BTreeMap::new(), 0, PARENT_CLOSE),
            truncated: false,
            pending_count: 0,
            proposer_signature: vec![],
        }
    }

    /// A child proposed by whoever is due at `escalation`, so the driver's reported round can be
    /// checked against a known value rather than assumed.
    fn a_child_at(parent: &ShareBatch, schedule: &ProposerSchedule, escalation: u32) -> ShareBatch {
        let mut shares = vec![ShareProof {
            round_id: 1,
            miner_id: [1u8; 32],
            difficulty: 1.0,
            work: 1.0,
            share_hash: [1u8; 32],
            timestamp: 1000,
            received_by: [0u8; 32],
            template_id: None,
            payout_address: Some("bc1qalice".into()),
            header: None,
            signature: None,
        }];
        crate::share_batch::canonical_sort(&mut shares);
        let mut after: BTreeMap<String, i64> = BTreeMap::new();
        fold_shares(&mut after, &shares);
        let close_ts = parent.close_ts + 30;
        ShareBatch {
            seq: parent.seq + 1,
            prev_batch_hash: parent.batch_hash(),
            close_ts,
            proposer: schedule.proposer_at(parent.seq + 1, escalation).unwrap(),
            shares,
            settled_blocks: vec![],
            node_shares: vec![],
            state_root: compute_state_root(&after, parent.seq + 1, close_ts),
            truncated: false,
            pending_count: 0,
            proposer_signature: vec![9],
        }
    }

    /// The prevote must name the round the proposer was AUTHORISED at, not a constant.
    ///
    /// This caught a real defect while being written: the two-phase driver hardcoded `round: 0`,
    /// so every batch would have been prevoted as round 0 regardless of escalation — collapsing
    /// distinct attempts into one tally and defeating the whole point of rounds.
    #[test]
    fn the_prevote_carries_the_round_the_proposer_was_authorised_at() {
        let s = eight();
        let parent = a_parent();
        let balances = BTreeMap::new();
        let checks = AllGood;

        // Escalation 2 means `now` is two stall intervals past the parent's close.
        let escalation = 2u32;
        let batch = a_child_at(&parent, &s, escalation);
        let now =
            PARENT_CLOSE + (crate::batch_consensus::STALL_ESCALATION_SECS * escalation as i64);

        let ctx = BatchContext {
            parent: &parent,
            parent_balances: &balances,
            schedule: &s,
            checks: &checks,
            now,
        };
        let consensus = SeqConsensus::new(1, 6);
        let action = on_batch_phase(&batch, &ctx, &mut Quarantine::new(), &consensus);

        match action {
            PhaseAction::Prevote { round, seq, .. } => {
                assert_eq!(seq, 1);
                assert_eq!(
                    round, escalation,
                    "a hardcoded round collapses every attempt into one tally"
                );
            }
            other => panic!("expected a prevote, got {other:?}"),
        }
    }

    /// **The locking rule at the driver boundary.** A locked node prevotes its LOCK, not the batch
    /// that arrived — even though that batch verified cleanly.
    #[test]
    fn a_locked_node_prevotes_its_lock_not_the_arriving_batch() {
        let s = eight();
        let parent = a_parent();
        let balances = BTreeMap::new();
        let checks = AllGood;
        let batch = a_child_at(&parent, &s, 0);
        let offered = batch.batch_hash();

        let mut consensus = SeqConsensus::new(1, 6);
        let locked_value = [0xEE; 32];
        consensus.apply_polka(0, locked_value);

        let ctx = BatchContext {
            parent: &parent,
            parent_balances: &balances,
            schedule: &s,
            checks: &checks,
            now: PARENT_CLOSE,
        };
        let action = on_batch_phase(&batch, &ctx, &mut Quarantine::new(), &consensus);

        match action {
            PhaseAction::Prevote { batch_hash, .. } => {
                assert_eq!(
                    batch_hash, locked_value,
                    "a valid batch must NOT displace a lock — that is the fork this prevents"
                );
                assert_ne!(batch_hash, offered);
            }
            other => panic!("expected a prevote, got {other:?}"),
        }
    }

    /// A polka drives lock-then-precommit, and a quorum of precommits commits.
    #[test]
    fn a_polka_leads_to_precommit_and_a_quorum_of_those_commits() {
        let s = eight();
        let mut q = Quarantine::new();
        let mut c = SeqConsensus::new(1, 6);
        let target = [0xAB; 32];

        let mut locked = None;
        for n in 1..=8u8 {
            if let PrevoteAction::LockAndPrecommit { batch_hash, round } =
                on_prevote([n; 32], 0, target, &mut c, &mut q, &s, 0)
            {
                locked = Some((batch_hash, round));
            }
        }
        assert_eq!(locked, Some((target, 0)), "a quorum of prevotes is a polka");
        assert_eq!(c.lock(), Some((0, target)), "the polka must set our lock");

        let mut committed = None;
        for n in 1..=8u8 {
            if let PrecommitAction::Commit { batch_hash, votes } =
                on_precommit([n; 32], 0, target, &mut c, &mut q, &s, 0)
            {
                committed = Some((batch_hash, votes));
            }
        }
        assert_eq!(committed, Some((target, 6)));
    }
}
