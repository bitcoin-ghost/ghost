//! Two-phase commit for the share-batch chain: prevote, polka, precommit, commit.
//!
//! This replaces one-vote-per-sequence, which was safe and dead. Escalation appoints a new
//! proposer every 90 s while a sequence is open, and each proposes a *different* batch — so under
//! a single vote every node froze on whichever candidate reached it first, votes scattered, and
//! the sequence could never close. On the six-node run of 2026-08-09 five candidates were proposed
//! at `seq=1` and approvals never rose above 1 of 6. A hash chain cannot skip a sequence, so that
//! is terminal rather than slow.
//!
//! Scoping the single vote to `(seq, round)` restores liveness and was implemented and reverted:
//! it forfeits the counting argument (one vote per seq, quorum 6 of 8, so 12 votes from 8 voters
//! is impossible) and replaces it with one that holds only under reliable delivery. On a structure
//! whose entire purpose is that it cannot fork, that is not a trade worth making.
//!
//! ## The protocol
//!
//! - **Prevote.** On a valid batch `B` at round `R`, a node prevotes — unless it is locked, in
//!   which case it prevotes its locked value instead.
//! - **Polka.** `quorum` prevotes for one `B` at one `R`. This is *evidence*: it proves a quorum
//!   considered `B` valid at `R`.
//! - **Precommit.** On seeing a polka, a node **locks** on `(R, B)` and precommits it.
//! - **Commit.** `quorum` precommits for `B` at `R` finalises `B`. Nothing else adopts.
//!
//! ## The locking rule, which is the whole point
//!
//! A node locked on `(R_lock, B_lock)` prevotes `B_lock` in every later round, **unless** it sees
//! a polka for a different `B'` at a round `>= R_lock` — then it relocks and may prevote `B'`.
//!
//! A node unlocks only on proof that a quorum was willing to move. Never on a timer, and never
//! because a new proposal merely arrived.
//!
//! ## Why it is safe
//!
//! If `B` commits at round `R`, at least `quorum` nodes precommitted `B` at `R`, and each locked
//! on `(R, B)` first. For a different `B'` to commit at `R' > R` it needs a polka at `R'`. With 8
//! voters and quorum 6, any two quorums intersect in at least `6 + 6 - 8 = 4` nodes;
//! `bft_threshold(8) = 6` tolerates `f = 2`, and `4 > 2`, so at least two *correct* nodes are in
//! both sets. Those nodes are locked on `(R, B)` and will not prevote `B'` without a polka for
//! `B'` at a round `>= R`. Induction over rounds gives: no two different batches commit at one
//! `seq`. This holds under asynchrony and partition — it assumes no message ever arrives.

use std::collections::{BTreeMap, BTreeSet};

/// What recording a prevote produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrevoteOutcome {
    /// Counted, no polka yet.
    Counted { votes: usize, needed: usize },
    /// A quorum prevoted this batch at this round. The caller should lock and precommit.
    ///
    /// Reported once per `(round, batch)`, because locking and precommitting are actions and a
    /// caller must not perform them again on every later prevote for the same candidate.
    Polka { batch_hash: [u8; 32], votes: usize },
    /// A resend, or a voter already known to contradict itself.
    Ignored,
    /// This voter prevoted two different batches in ONE round. Provable from two messages it
    /// signed itself, so it is terminal and every one of its votes is void.
    Equivocation { first: [u8; 32], second: [u8; 32] },
}

/// What recording a precommit produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecommitOutcome {
    Counted {
        votes: usize,
        needed: usize,
    },
    /// Final. This batch is the sequence's decision.
    Commit {
        batch_hash: [u8; 32],
        votes: usize,
    },
    Ignored,
    Equivocation {
        first: [u8; 32],
        second: [u8; 32],
    },
}

/// Two-phase voting state for a single sequence.
#[derive(Debug, Clone)]
pub struct SeqConsensus {
    seq: u64,
    quorum: usize,
    /// `(round, batch)` -> voters who prevoted it.
    prevotes: BTreeMap<(u32, [u8; 32]), BTreeSet<[u8; 32]>>,
    /// `(round, batch)` -> voters who precommitted it.
    precommits: BTreeMap<(u32, [u8; 32]), BTreeSet<[u8; 32]>>,
    /// `(round, voter)` -> what they prevoted, for equivocation detection *within* a round.
    /// Prevoting `B` at round 3 and `B'` at round 5 is the protocol working, not a fault.
    prevote_choice: BTreeMap<(u32, [u8; 32]), [u8; 32]>,
    precommit_choice: BTreeMap<(u32, [u8; 32]), [u8; 32]>,
    /// Voters whose word is worthless. Their votes are excluded from every tally, including ones
    /// already counted — a node that will say two contradictory things has told us nothing.
    equivocators: BTreeSet<[u8; 32]>,
    /// What THIS node is locked on.
    lock: Option<(u32, [u8; 32])>,
    /// Polkas already reported, so `Polka` is an edge and not a level.
    polkas_seen: BTreeSet<(u32, [u8; 32])>,
    committed: Option<[u8; 32]>,
}

impl SeqConsensus {
    pub fn new(seq: u64, quorum: usize) -> Self {
        Self {
            seq,
            quorum,
            prevotes: BTreeMap::new(),
            precommits: BTreeMap::new(),
            prevote_choice: BTreeMap::new(),
            precommit_choice: BTreeMap::new(),
            equivocators: BTreeSet::new(),
            lock: None,
            polkas_seen: BTreeSet::new(),
            committed: None,
        }
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn committed(&self) -> Option<[u8; 32]> {
        self.committed
    }

    pub fn lock(&self) -> Option<(u32, [u8; 32])> {
        self.lock
    }

    pub fn equivocators(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.equivocators.iter()
    }

    /// Prevotes for one candidate at one round, excluding equivocators.
    pub fn prevotes_for(&self, round: u32, batch_hash: &[u8; 32]) -> usize {
        self.prevotes
            .get(&(round, *batch_hash))
            .map(|v| v.difference(&self.equivocators).count())
            .unwrap_or(0)
    }

    /// Precommits for one candidate at one round, excluding equivocators.
    pub fn precommits_for(&self, round: u32, batch_hash: &[u8; 32]) -> usize {
        self.precommits
            .get(&(round, *batch_hash))
            .map(|v| v.difference(&self.equivocators).count())
            .unwrap_or(0)
    }

    /// **The locking rule.** What this node should prevote at `round`, given the batch on offer.
    ///
    /// A locked node repeats its locked value rather than following a new proposal. That is what
    /// stops a batch being committed at one round and contradicted at the next: the nodes that
    /// made the first commit possible refuse to endorse anything else until shown a quorum has
    /// moved. `None` means there is nothing to prevote — no proposal and no lock.
    pub fn what_to_prevote(&self, proposed: Option<[u8; 32]>) -> Option<[u8; 32]> {
        match self.lock {
            Some((_, locked)) => Some(locked),
            None => proposed,
        }
    }

    /// Record a prevote.
    pub fn record_prevote(
        &mut self,
        round: u32,
        voter: [u8; 32],
        batch_hash: [u8; 32],
    ) -> PrevoteOutcome {
        if self.equivocators.contains(&voter) {
            return PrevoteOutcome::Ignored;
        }
        match self.prevote_choice.get(&(round, voter)) {
            Some(existing) if *existing == batch_hash => return PrevoteOutcome::Ignored,
            Some(existing) => {
                let first = *existing;
                self.equivocators.insert(voter);
                return PrevoteOutcome::Equivocation {
                    first,
                    second: batch_hash,
                };
            }
            None => {
                self.prevote_choice.insert((round, voter), batch_hash);
                self.prevotes
                    .entry((round, batch_hash))
                    .or_default()
                    .insert(voter);
            }
        }

        let votes = self.prevotes_for(round, &batch_hash);
        if votes >= self.quorum && self.polkas_seen.insert((round, batch_hash)) {
            return PrevoteOutcome::Polka { batch_hash, votes };
        }
        PrevoteOutcome::Counted {
            votes,
            needed: self.quorum,
        }
    }

    /// Apply a polka to this node's lock.
    ///
    /// Relocks when the polka is for a different batch at a round at or above the current lock —
    /// the only evidence that releases a lock. A polka at a round *below* the lock is stale and
    /// must not move it: that would let an old round resurrect a candidate the fleet left behind,
    /// which is precisely the fork this design exists to prevent.
    pub fn apply_polka(&mut self, round: u32, batch_hash: [u8; 32]) -> bool {
        match self.lock {
            Some((locked_round, locked_hash)) => {
                if locked_hash == batch_hash {
                    // Same value: refresh the round so later evidence compares against the newest
                    // proof, but this is not a change of mind.
                    if round > locked_round {
                        self.lock = Some((round, batch_hash));
                    }
                    false
                } else if round >= locked_round {
                    self.lock = Some((round, batch_hash));
                    true
                } else {
                    false
                }
            }
            None => {
                self.lock = Some((round, batch_hash));
                true
            }
        }
    }

    /// Record a precommit.
    pub fn record_precommit(
        &mut self,
        round: u32,
        voter: [u8; 32],
        batch_hash: [u8; 32],
    ) -> PrecommitOutcome {
        if self.equivocators.contains(&voter) {
            return PrecommitOutcome::Ignored;
        }
        match self.precommit_choice.get(&(round, voter)) {
            Some(existing) if *existing == batch_hash => return PrecommitOutcome::Ignored,
            Some(existing) => {
                let first = *existing;
                self.equivocators.insert(voter);
                return PrecommitOutcome::Equivocation {
                    first,
                    second: batch_hash,
                };
            }
            None => {
                self.precommit_choice.insert((round, voter), batch_hash);
                self.precommits
                    .entry((round, batch_hash))
                    .or_default()
                    .insert(voter);
            }
        }

        let votes = self.precommits_for(round, &batch_hash);
        if votes >= self.quorum && self.committed.is_none() {
            self.committed = Some(batch_hash);
            return PrecommitOutcome::Commit { batch_hash, votes };
        }
        PrecommitOutcome::Counted {
            votes,
            needed: self.quorum,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(n: u8) -> [u8; 32] {
        [n; 32]
    }
    const A: [u8; 32] = [0xAA; 32];
    const B: [u8; 32] = [0xBB; 32];

    /// Quorum PREVOTES alone must not commit. Only precommits decide.
    ///
    /// Collapsing the two phases is the same as the single-phase design that was reverted, so this
    /// pins the distinction that the whole protocol rests on.
    #[test]
    fn a_polka_alone_does_not_commit() {
        let mut c = SeqConsensus::new(1, 6);
        for n in 0..8u8 {
            c.record_prevote(0, v(n), A);
        }
        assert_eq!(c.committed(), None, "prevotes are evidence, not a decision");
    }

    /// Quorum precommits at one round commits, and reports once.
    #[test]
    fn quorum_precommits_commit_the_sequence() {
        let mut c = SeqConsensus::new(1, 6);
        let mut committed = None;
        for n in 0..8u8 {
            if let PrecommitOutcome::Commit { batch_hash, votes } = c.record_precommit(0, v(n), A) {
                committed = Some((batch_hash, votes));
            }
        }
        assert_eq!(committed, Some((A, 6)), "commit fires exactly at quorum");
        assert_eq!(c.committed(), Some(A));
    }

    /// A polka is an edge, not a level — reported once per (round, batch).
    ///
    /// Locking and precommitting are ACTIONS. Re-reporting on every later prevote would have a
    /// node precommit the same candidate repeatedly.
    #[test]
    fn a_polka_is_reported_once() {
        let mut c = SeqConsensus::new(1, 6);
        let mut polkas = 0;
        for n in 0..8u8 {
            if let PrevoteOutcome::Polka { .. } = c.record_prevote(0, v(n), A) {
                polkas += 1;
            }
        }
        assert_eq!(
            polkas, 1,
            "8 prevotes past a quorum of 6 is still ONE polka"
        );
    }

    /// **The locking rule.** A locked node prevotes its lock, not the new proposal.
    #[test]
    fn a_locked_node_prevotes_its_lock_not_the_new_proposal() {
        let mut c = SeqConsensus::new(1, 6);
        assert!(c.apply_polka(0, A), "first polka locks");
        assert_eq!(
            c.what_to_prevote(Some(B)),
            Some(A),
            "a locked node must not follow a fresh proposal on sight"
        );
    }

    /// A polka for a different batch at a round >= the lock relocks it.
    #[test]
    fn a_polka_at_or_above_the_lock_releases_it() {
        let mut c = SeqConsensus::new(1, 6);
        c.apply_polka(3, A);
        assert!(c.apply_polka(5, B), "evidence at a higher round relocks");
        assert_eq!(c.lock(), Some((5, B)));
        assert_eq!(c.what_to_prevote(Some(A)), Some(B));
    }

    /// A polka at a round BELOW the lock must not move it.
    ///
    /// Otherwise a stale round could resurrect a candidate the fleet has left behind — the exact
    /// fork this design prevents.
    #[test]
    fn a_polka_below_the_lock_does_not_release_it() {
        let mut c = SeqConsensus::new(1, 6);
        c.apply_polka(5, A);
        assert!(!c.apply_polka(2, B), "stale evidence must not unlock");
        assert_eq!(c.lock(), Some((5, A)));
        assert_eq!(c.what_to_prevote(Some(B)), Some(A));
    }

    /// Equivocation is two batches in ONE round and ONE phase.
    #[test]
    fn two_prevotes_in_one_round_is_equivocation() {
        let mut c = SeqConsensus::new(1, 6);
        c.record_prevote(0, v(1), A);
        assert!(matches!(
            c.record_prevote(0, v(1), B),
            PrevoteOutcome::Equivocation { .. }
        ));
    }

    /// Prevoting different batches at DIFFERENT rounds is the protocol working.
    #[test]
    fn prevoting_a_different_batch_at_a_later_round_is_not_equivocation() {
        let mut c = SeqConsensus::new(1, 6);
        c.record_prevote(0, v(1), A);
        assert!(
            !matches!(
                c.record_prevote(1, v(1), B),
                PrevoteOutcome::Equivocation { .. }
            ),
            "changing round is how a failed round is abandoned"
        );
    }

    /// An equivocator's votes are void everywhere, including ones already counted.
    #[test]
    fn an_equivocators_earlier_votes_stop_counting() {
        let mut c = SeqConsensus::new(1, 6);
        for n in 0..5u8 {
            c.record_prevote(0, v(n), A);
        }
        assert_eq!(c.prevotes_for(0, &A), 5);
        c.record_prevote(0, v(0), B); // v0 contradicts itself
        assert_eq!(
            c.prevotes_for(0, &A),
            4,
            "a voter that said two things has told us nothing, retroactively"
        );
    }

    /// Prevotes and precommits are counted separately — a prevote must never satisfy a commit.
    #[test]
    fn prevotes_do_not_count_towards_precommits() {
        let mut c = SeqConsensus::new(1, 6);
        for n in 0..8u8 {
            c.record_prevote(0, v(n), A);
        }
        assert_eq!(c.precommits_for(0, &A), 0);
        assert_eq!(c.committed(), None);
    }

    /// Prevotes must not top up a precommit tally to quorum.
    ///
    /// An earlier version of this test recorded only prevotes, so the precommit path never ran and
    /// a mutation that summed the two phases survived it untouched. A test that cannot execute the
    /// line it is about proves nothing. This one drives BOTH: enough prevotes that the sum would
    /// clear quorum, and strictly fewer precommits than quorum.
    #[test]
    fn prevotes_cannot_top_up_a_precommit_tally() {
        let quorum = 6;
        let mut c = SeqConsensus::new(1, quorum);

        // 8 prevotes — well past quorum on its own.
        for n in 0..8u8 {
            c.record_prevote(0, v(n), A);
        }
        // 3 precommits — short of quorum. Summed with the prevotes it would be 11.
        for n in 0..3u8 {
            c.record_precommit(0, v(n), A);
        }

        assert_eq!(
            c.precommits_for(0, &A),
            3,
            "only precommits count as precommits"
        );
        assert_eq!(
            c.committed(),
            None,
            "3 precommits is short of 6 — prevotes must not make up the difference"
        );

        // And the remaining precommits DO commit it, so this is not passing by inertia.
        for n in 3..6u8 {
            c.record_precommit(0, v(n), A);
        }
        assert_eq!(c.committed(), Some(A), "6 real precommits commit");
    }

    /// **The property the reverted design could not satisfy.**
    ///
    /// Two different batches must never both commit at one sequence, driven over an explicit
    /// adversarial schedule rather than a happy path: `A` commits at round 0 on one side of a
    /// partition, then the other side tries to carry `B` at a later round. The four correct nodes
    /// present in both quorums are locked on `A` and prevote `A`, so `B` cannot reach a polka and
    /// therefore cannot be precommitted into a commit.
    #[test]
    fn two_batches_never_both_commit_at_one_sequence() {
        let quorum = 6;
        // Every node runs its own state; nothing is shared but the messages we choose to deliver.
        let mut nodes: Vec<SeqConsensus> = (0..8).map(|_| SeqConsensus::new(1, quorum)).collect();

        // --- Round 0: nodes 0..5 prevote A, reach a polka, lock, and precommit A. ---
        for node in nodes.iter_mut() {
            for voter in 0..6u8 {
                if let PrevoteOutcome::Polka { batch_hash, .. } =
                    node.record_prevote(0, v(voter), A)
                {
                    node.apply_polka(0, batch_hash);
                }
            }
        }
        for node in nodes.iter_mut() {
            for voter in 0..6u8 {
                node.record_precommit(0, v(voter), A);
            }
        }
        assert_eq!(nodes[0].committed(), Some(A), "A commits at round 0");

        // Every node that saw the polka is locked on A.
        for (i, n) in nodes.iter().enumerate() {
            assert_eq!(n.lock(), Some((0, A)), "node {i} must be locked on A");
        }

        // --- Round 1: an adversary proposes B. Correct nodes prevote their LOCK, not B. ---
        let mut b_prevotes = 0usize;
        for voter in 0..8u8 {
            let locked = nodes[voter as usize].what_to_prevote(Some(B));
            if locked == Some(B) {
                b_prevotes += 1;
            }
        }
        assert_eq!(
            b_prevotes, 0,
            "no correct node prevotes B while locked on A — so B can never reach a polka"
        );

        // Even if the two Byzantine nodes (f = 2) prevote B anyway, it cannot reach quorum.
        let mut probe = SeqConsensus::new(1, quorum);
        for voter in 6..8u8 {
            probe.record_prevote(1, v(voter), B);
        }
        assert!(
            probe.prevotes_for(1, &B) < quorum,
            "f=2 Byzantine prevotes cannot manufacture a polka"
        );

        // And the committed value is unchanged everywhere.
        for (i, n) in nodes.iter().enumerate() {
            assert_eq!(n.committed(), Some(A), "node {i} must still hold A");
        }
    }

    /// A commit is latched: once decided, a later quorum cannot overwrite the decision.
    #[test]
    fn a_committed_sequence_does_not_change_its_mind() {
        let mut c = SeqConsensus::new(1, 6);
        for n in 0..6u8 {
            c.record_precommit(0, v(n), A);
        }
        assert_eq!(c.committed(), Some(A));
        for n in 0..6u8 {
            c.record_precommit(1, v(n), B);
        }
        assert_eq!(
            c.committed(),
            Some(A),
            "the decision is final, not the latest"
        );
    }

    /// The deadlock that motivated all of this: a round that misses quorum must not wedge the
    /// sequence — a later round can still commit.
    #[test]
    fn a_round_that_missed_quorum_does_not_wedge_the_sequence() {
        let mut c = SeqConsensus::new(1, 6);
        // Round 0 stalls at 3 prevotes: no polka, nobody locks.
        for n in 0..3u8 {
            c.record_prevote(0, v(n), A);
        }
        assert_eq!(c.lock(), None);
        assert_eq!(c.committed(), None);

        // Round 1: a full quorum prevotes B, polkas, locks, and precommits.
        for n in 0..8u8 {
            if let PrevoteOutcome::Polka { batch_hash, .. } = c.record_prevote(1, v(n), B) {
                c.apply_polka(1, batch_hash);
            }
        }
        assert_eq!(c.lock(), Some((1, B)));
        for n in 0..8u8 {
            c.record_precommit(1, v(n), B);
        }
        assert_eq!(
            c.committed(),
            Some(B),
            "a failed round must be recoverable, or the chain wedges forever"
        );
    }
}
