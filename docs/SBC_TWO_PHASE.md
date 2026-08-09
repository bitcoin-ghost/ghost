# SBC: two-phase commit for the share-batch chain

Status: design, 2026-08-09. Supersedes the reverted single-phase round proposal
(`9c003b984`, reverted in `92782196d`).

## The problem this must solve

The six-node shadow run deadlocked at `seq=1` and could not recover:

```
peer vote seq=1 action=Counted { approvals: 1, needed: 6 }
already voted at this sequence seq=1
```

Escalation appoints a new proposer every 90 s while a sequence is open, and each
proposes a *different* batch. Under one-vote-per-sequence every node froze on whichever
candidate reached it first, votes scattered across five candidates, and nothing could
reach 6. The lock never expires, so the sequence is wedged permanently — and a hash
chain cannot skip a sequence.

The in-memory locks clear on restart, which makes a fleet restart *look* like a fix. It
is not: it re-wedges on the first round that misses quorum.

## Why the obvious fix was rejected

Scoping the vote lock to `(seq, round)` restores liveness in one line of thinking and
was implemented and reverted. It forfeits the safety argument:

> Each voter votes at most once per `seq`. Quorum is 6 of 8. Two batches both reaching
> quorum would need 12 votes from 8 voters, so at most one batch per `seq` finalises.

With per-round voting, batch A at round R and batch B at round R+1 can each collect 6
votes from overlapping voters at different times. Nothing prevents both finalising. The
replacement argument — a voter's choice is *moved*, so only one candidate holds quorum
at any instant — holds only under reliable delivery, and fails under partition.

That is a real weakening on a structure whose entire purpose is that it cannot fork.
Carrying it "temporarily" would mean WP-6 gets built on top of it.

## Two-phase

The standard solution, and the one this adopts. A round has two votes rather than one.

**Prevote.** On receiving a valid batch `B` for round `R`, a node broadcasts
`Prevote(seq, R, B)` — unless it is locked (below), in which case it prevotes its locked
value.

**Polka.** `quorum` prevotes for the same `B` at round `R`. A polka is *evidence*: it
proves a quorum considered `B` valid at `R`.

**Precommit.** On seeing a polka for `B` at `R`, a node **locks** on `(R, B)` and
broadcasts `Precommit(seq, R, B)`.

**Commit.** `quorum` precommits for `B` at round `R` finalises `B`. This is the only
path to adoption.

### The locking rule

This is the part that makes abandoning a round safe rather than merely convenient:

> A node locked on `(R_lock, B_lock)` prevotes `B_lock` in every later round, **unless**
> it sees a polka for a different `B'` at some round `R_polka >= R_lock`, in which case
> it relocks on `(R_polka, B')` and may prevote `B'`.

A node unlocks only on proof that a quorum was willing to move — never on a timer, and
never because a new proposal simply arrived.

### Why it is safe

Suppose `B` commits at round `R`: at least `quorum` nodes precommitted `B` at `R`, and
each of those locked on `(R, B)` first.

For a different `B'` to commit at any round `R' > R`, it needs a polka at `R'` — quorum
prevotes for `B'`. With 8 voters and quorum 6, any two quorums intersect in at least
`6 + 6 - 8 = 4` nodes. `bft_threshold(8) = 6` tolerates `f = 2` faults, and `4 > f`, so
at least two *correct* nodes appear in both sets. Those nodes are locked on `(R, B)` and
by the locking rule will not prevote `B'` without having seen a polka for `B'` at a round
`>= R`. Induction on rounds gives: no two different batches can commit at one `seq`.

This holds under asynchrony and partition — it does not assume messages arrive.

### Why it stays live

A partition or a dead proposer stalls progress but does not wedge it. When the network
heals, escalation appoints a proposer whose batch can gather a polka; nodes locked on a
stale value relock on seeing it, and the sequence closes. The failure mode is delay, not
deadlock.

## Wire format

Two message types rather than one, so a prevote can never be miscounted as a precommit:

```rust
MessageType::ShareBatchPrevote
MessageType::ShareBatchPrecommit
```

Both carry `{ seq, round, batch_hash, voter, signature }`. The signature covers all four
via a domain-separated `signing_bytes`, with distinct domain tags per phase — signing the
same bytes for both phases would let a prevote be replayed as a precommit, which is
exactly the forgery that collapses the two-phase structure into the single-phase one.

Vote signatures are now verified before counting (`1ac973bce` era work): `signing_bytes`
previously had **zero callers** and votes were taken entirely on trust.

## State per sequence

```
prevotes:   BTreeMap<(round, batch_hash), BTreeSet<voter>>
precommits: BTreeMap<(round, batch_hash), BTreeSet<voter>>
lock:       Option<(round, batch_hash)>
committed:  Option<batch_hash>
```

Equivocation — two different hashes from one voter, in one round, in one phase — remains
a terminal fault and still quarantines. It is genuinely provable misbehaviour from two
messages the peer signed itself. Prevoting `B` at round 3 and `B'` at round 5 is *not*
equivocation; it is the protocol working.

## What is deliberately not changed

- `seq_opened` stays derived from `head.close_ts`. It must remain consensus data; a
  node-local rota clock caused the vm8 divergence and is not to be reintroduced.
- Quarantine stays operator-release-only (`--sbc-release`).
- Escalation and the proposer rota are untouched — two-phase changes what a vote *means*,
  not whose turn it is.

## Test obligations

Each must fail if the mechanism it covers is reverted:

1. A commit requires quorum **precommits** — quorum prevotes alone must not finalise.
2. A node locked on `(R, B)` prevotes `B` at `R+1` when a different batch is proposed.
3. A node locked on `(R, B)` relocks and prevotes `B'` after seeing a polka for `B'` at
   a round `>= R`.
4. A polka at a round **below** the lock does not unlock.
5. Two different batches never both commit at one `seq`, driven adversarially: partition
   the voter set, commit `B` on one side, then attempt to commit `B'` on the other.
6. The seq=1 deadlock resolves: a round that misses quorum is followed by one that
   commits.
7. Equivocation within a single (round, phase) still quarantines.
8. A prevote replayed as a precommit fails signature verification.

Obligation 5 is the one that matters. It is the property the reverted design could not
satisfy, and it should be written as a simulation over an explicit message schedule
rather than a happy-path unit test.

## Sequencing

This is a consensus change on a chain that pays nobody yet, which is the right time to
make it. It must land and soak in shadow before WP-6 wires checkpoints to the coinbase.
