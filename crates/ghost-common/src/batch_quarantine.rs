//! What a terminal verification failure does to the peer that caused it.
//!
//! A [`FaultReason`](crate::batch_consensus::FaultReason) is decidable from a batch's own bytes
//! against a finalised parent, so no honest node can produce one by holding a different view. That
//! is what makes it safe to act on rather than retry — and #583 is what happens when you retry a
//! terminal condition instead: the same rejection, forever, with nothing able to recover.
//!
//! Two decisions shape this module, and both are the opposite of the obvious one.
//!
//! **Quarantine does not change the rota.** The tempting design is to skip a quarantined node's
//! proposal turns. But each node judges faults independently, so two nodes with different
//! quarantine sets would derive different rotas and disagree about who is even allowed to
//! propose — a split produced by the very mechanism meant to contain one. Instead a quarantined
//! peer keeps its turns and simply cannot win a vote here. Escalation already carries the sequence
//! past a proposer who cannot reach quorum, so liveness needs nothing extra.
//!
//! **A quarantine is never refused to preserve quorum.** If enough peers are quarantined that 67%
//! becomes unreachable, the answer is not to start voting for batches known to be invalid — that
//! trades away the only property worth having. It is quarantined anyway, and the loss of quorum is
//! reported as its own condition, because "I can no longer reach agreement" and "this batch is
//! bad" are different facts and an operator needs both.
//!
//! Dark code: nothing wires this into a runtime path yet.

use std::collections::BTreeMap;

use crate::batch_consensus::{FaultReason, ProposerSchedule};

/// Why a peer is quarantined, and what it was doing at the time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineEntry {
    /// The defect that caused it.
    pub reason: FaultReason,
    /// The batch sequence it was proposing.
    pub seq: u64,
    /// When it happened.
    pub since: i64,
}

/// What quarantining a peer did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineOutcome {
    /// Newly quarantined, and quorum is still reachable.
    Quarantined { remaining: usize, needed: usize },
    /// Newly quarantined, and **quorum is now unreachable from this node's view**.
    ///
    /// Separate from the ordinary case because it is a different problem. Either the fleet really
    /// has gone bad, or this node's fault detection has — and both need a human, urgently. The
    /// quarantine still stands: voting for batches known to be invalid is not a recovery.
    QuarantinedQuorumLost { remaining: usize, needed: usize },
    /// Already quarantined; the first reason is kept.
    ///
    /// Deliberately not overwritten — the first fault is the diagnosis, and later ones are mostly
    /// consequences of a peer that is already misbehaving.
    Already { since: i64 },
    /// Not a voter, so there is nothing to exclude.
    NotAVoter,
}

/// Peers whose batches this node will no longer vote for.
#[derive(Debug, Clone, Default)]
pub struct Quarantine {
    entries: BTreeMap<[u8; 32], QuarantineEntry>,
}

impl Quarantine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn is_quarantined(&self, voter: &[u8; 32]) -> bool {
        self.entries.contains_key(voter)
    }

    pub fn entry(&self, voter: &[u8; 32]) -> Option<&QuarantineEntry> {
        self.entries.get(voter)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &QuarantineEntry)> {
        self.entries.iter()
    }

    /// Quarantine a peer for a terminal fault.
    pub fn quarantine(
        &mut self,
        voter: [u8; 32],
        reason: FaultReason,
        seq: u64,
        now: i64,
        schedule: &ProposerSchedule,
    ) -> QuarantineOutcome {
        if !schedule.voters().contains(&voter) {
            return QuarantineOutcome::NotAVoter;
        }
        if let Some(existing) = self.entries.get(&voter) {
            return QuarantineOutcome::Already {
                since: existing.since,
            };
        }

        self.entries.insert(
            voter,
            QuarantineEntry {
                reason,
                seq,
                since: now,
            },
        );

        let remaining = self.usable_voters(schedule);
        let needed = schedule.quorum();
        if remaining < needed {
            QuarantineOutcome::QuarantinedQuorumLost { remaining, needed }
        } else {
            QuarantineOutcome::Quarantined { remaining, needed }
        }
    }

    /// Voters whose word this node still accepts.
    ///
    /// Counted against the **full** voter set's quorum, not a shrunken one. Recomputing the
    /// threshold from the survivors is the classic way a Byzantine minority becomes a majority:
    /// quarantine three of eight and 67% of the remaining five is three, so three nodes could
    /// finalise anything. The bar stays where the whole fleet put it.
    pub fn usable_voters(&self, schedule: &ProposerSchedule) -> usize {
        schedule
            .voters()
            .iter()
            .filter(|v| !self.entries.contains_key(*v))
            .count()
    }

    /// Whether quorum is still reachable from this node's view.
    pub fn quorum_reachable(&self, schedule: &ProposerSchedule) -> bool {
        self.usable_voters(schedule) >= schedule.quorum()
    }

    /// Release a peer. **Operator action only.**
    ///
    /// There is no timer. A fault here is a proof, not a symptom, and an automatic release would
    /// let a genuinely Byzantine node cycle: misbehave, wait out the timeout, misbehave again,
    /// forever, with each round costing the fleet a stalled sequence. Whether a peer has actually
    /// been fixed is not a thing software can observe.
    pub fn release(&mut self, voter: &[u8; 32]) -> Option<QuarantineEntry> {
        self.entries.remove(voter)
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

    fn a_fault() -> FaultReason {
        FaultReason::DuplicateShare {
            share_hash: [1u8; 32],
        }
    }

    #[test]
    fn a_faulting_peer_is_quarantined_and_quorum_survives_one_loss() {
        let mut q = Quarantine::new();
        assert_eq!(
            q.quarantine(voter(3), a_fault(), 9, 100, &eight()),
            QuarantineOutcome::Quarantined {
                remaining: 7,
                needed: 6
            }
        );
        assert!(q.is_quarantined(&voter(3)));
        assert!(q.quorum_reachable(&eight()));
    }

    /// **The rota must not move.** Each node judges faults for itself, so a quarantine that
    /// changed the schedule would have two honest nodes disagreeing about who may propose — a
    /// split created by the mechanism meant to contain one.
    #[test]
    fn quarantine_does_not_change_who_is_due_to_propose() {
        let schedule = eight();
        let before: Vec<_> = (0..16).map(|s| schedule.proposer_at(s, 0)).collect();

        let mut q = Quarantine::new();
        q.quarantine(voter(3), a_fault(), 9, 100, &schedule);
        q.quarantine(voter(5), a_fault(), 10, 100, &schedule);

        let after: Vec<_> = (0..16).map(|s| schedule.proposer_at(s, 0)).collect();
        assert_eq!(
            before, after,
            "the schedule is derived from the voter set alone, and must stay that way"
        );
    }

    /// **The threshold does not shrink with the survivors.** Recomputing 67% over the remaining
    /// nodes is how a quarantined minority becomes a majority: three of eight excluded, and three
    /// of the remaining five could finalise anything.
    #[test]
    fn the_quorum_bar_is_measured_against_the_whole_fleet() {
        let schedule = eight();
        let mut q = Quarantine::new();
        for n in 1..=3u8 {
            q.quarantine(voter(n), a_fault(), 1, 100, &schedule);
        }
        assert_eq!(q.usable_voters(&schedule), 5);
        assert_eq!(schedule.quorum(), 6, "still six of eight, not four of five");
        assert!(!q.quorum_reachable(&schedule));
    }

    /// Losing quorum is reported as its own condition — the quarantine still stands, because
    /// voting for batches known to be invalid is not a recovery.
    #[test]
    fn losing_quorum_is_reported_but_never_prevents_a_quarantine() {
        let schedule = eight();
        let mut q = Quarantine::new();
        for n in 1..=2u8 {
            q.quarantine(voter(n), a_fault(), 1, 100, &schedule);
        }
        assert_eq!(
            q.quarantine(voter(3), a_fault(), 1, 100, &schedule),
            QuarantineOutcome::QuarantinedQuorumLost {
                remaining: 5,
                needed: 6
            }
        );
        assert!(
            q.is_quarantined(&voter(3)),
            "safety is not traded away for liveness"
        );
    }

    /// The first fault is the diagnosis; later ones are mostly consequences.
    #[test]
    fn the_original_reason_is_kept() {
        let schedule = eight();
        let mut q = Quarantine::new();
        q.quarantine(voter(3), a_fault(), 9, 100, &schedule);
        assert_eq!(
            q.quarantine(
                voter(3),
                FaultReason::ProposerSignatureInvalid,
                10,
                200,
                &schedule
            ),
            QuarantineOutcome::Already { since: 100 }
        );
        assert_eq!(q.entry(&voter(3)).unwrap().reason, a_fault());
        assert_eq!(q.entry(&voter(3)).unwrap().seq, 9);
    }

    #[test]
    fn a_stranger_is_not_a_voter_to_exclude() {
        let mut q = Quarantine::new();
        assert_eq!(
            q.quarantine(voter(99), a_fault(), 1, 100, &eight()),
            QuarantineOutcome::NotAVoter
        );
        assert!(q.is_empty());
    }

    /// Release is manual by design: an automatic one lets a Byzantine node misbehave, wait out the
    /// timer, and misbehave again indefinitely.
    #[test]
    fn release_returns_the_entry_and_restores_the_vote() {
        let schedule = eight();
        let mut q = Quarantine::new();
        q.quarantine(voter(3), a_fault(), 9, 100, &schedule);
        let released = q.release(&voter(3)).expect("was quarantined");
        assert_eq!(released.reason, a_fault());
        assert!(!q.is_quarantined(&voter(3)));
        assert_eq!(q.usable_voters(&schedule), 8);
    }
}
