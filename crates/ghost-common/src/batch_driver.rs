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
    Vote {
        batch_hash: [u8; 32],
        seq: u64,
        /// The escalation step this batch was authorised at. Carried into the vote message so
        /// peers count it against the right attempt — a vote that omits the round is a vote for
        /// whichever candidate the receiver happens to be holding.
        round: u32,
    },
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
        BatchVerdict::Valid { round } => {
            let hash = batch.batch_hash();
            match lock.try_vote(batch.seq, round, hash) {
                VoteDecision::Fresh | VoteDecision::Repeat => Action::Vote {
                    batch_hash: hash,
                    seq: batch.seq,
                    round,
                },
                VoteDecision::Conflict { already } => {
                    Action::AlreadyVotedElsewhere { voted_for: already }
                }
                // A proposal from a round the fleet has moved past. Not a fault and not a vote:
                // voting for it would drag this node back to a candidate that cannot win.
                VoteDecision::Stale { .. } => Action::Hold {
                    reason: DeferReason::ProposerNotDue,
                },
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
    round: u32,
    tally: &mut SeqTally,
    quarantine: &mut Quarantine,
    schedule: &ProposerSchedule,
    now: i64,
) -> VoteAction {
    if quarantine.is_quarantined(&voter) {
        return VoteAction::Ignored;
    }

    match tally.record(voter, round, batch_hash) {
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
                seq: batch.seq,
                round: 0,
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
                on_vote(voter(n), hash, 0, &mut tally, &mut q, &schedule, 0),
                VoteAction::Counted { .. }
            ));
        }
        assert_eq!(
            on_vote(voter(6), hash, 0, &mut tally, &mut q, &schedule, 0),
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

        on_vote(voter(2), [0xAA; 32], 0, &mut tally, &mut q, &schedule, 0);
        match on_vote(voter(2), [0xBB; 32], 0, &mut tally, &mut q, &schedule, 0) {
            VoteAction::Equivocation { voter: v, .. } => assert_eq!(v, voter(2)),
            other => panic!("expected equivocation, got {other:?}"),
        }
        assert!(q.is_quarantined(&voter(2)));
        assert_eq!(tally.approvals_for_round(0, &[0xAA; 32]), 0);
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
            on_vote(voter(3), [0xAA; 32], 0, &mut tally, &mut q, &schedule, 0),
            VoteAction::Ignored
        );
        assert_eq!(tally.approvals_for_round(0, &[0xAA; 32]), 0);
    }
}
