# SBC: round-scoped voting

Status: design, 2026-08-09. Written after the six-node WP-5 shadow run deadlocked at
`seq=1` and stayed there.

## What happened

Six nodes (vm3–vm8) carried the chain, all agreeing on genesis
`cb5ac84706861922` and on the rota clock. Nothing finalised, for over an hour.
The debug log says why:

```
peer vote seq=1 action=Counted { approvals: 1, needed: 6 }
already voted at this sequence seq=1
peer vote seq=1 action=Counted { approvals: 1, needed: 6 }
```

Approvals never rose above 1. In the same window vm4 proposed three times and vm5
twice — five different candidate batches, all at `seq=1`.

## Why it deadlocks

Three mechanisms interact, and each is individually reasonable:

1. **Escalation advances every 90 s.** `escalation_at = (now - seq_opened) / 90`, and
   `seq_opened` only moves when a sequence *finalises*. So while `seq=1` is open, a new
   proposer is designated every 90 s, each producing a *different* batch — different
   proposer, different shares, different `batch_hash`.

2. **`SeqVoteLock` binds one batch_hash per seq, permanently.** A second, different
   batch at the same seq returns `Conflict` and the vote is refused. There is no notion
   of "that attempt failed, here is a new one".

3. **`SeqTally` treats a changed vote as equivocation** — and `on_vote` responds by
   *quarantining the voter* via `FaultReason::ProposerSignatureInvalid`. So a node that
   tried to switch would be excluded from consensus for it.

The result: each node votes for whichever candidate reaches it first and is then frozen.
Votes scatter across five candidates, none reaches 6, and because the lock never
expires the sequence can never recover. It is not slow — it is permanently wedged.

The in-memory locks clear on restart, so a full-fleet restart appears to "fix" it. That
is a trap: the chain wedges again on the first round that misses quorum.

### It is not merely a participation problem

With six participants and `quorum = bft_threshold(8) = 6`, every single participant must
vote for the same batch — zero margin. That makes a missed round near-certain, so the
deadlock triggers immediately. Rolling vm1 and vm2 to eight participants restores a
margin of 2 and would make rounds *usually* succeed. But "usually" is the whole problem:
one missed round still wedges that sequence forever, and a hash chain cannot skip a
sequence.

## The rule that must not be broken

Today's safety argument is sound and worth stating precisely, because the fix must
preserve it:

> Each voter votes at most once per `seq`. Quorum is 6 of 8. Two batches both reaching
> quorum would need 12 votes from 8 voters, so at most one batch per `seq` can ever
> finalise.

Any change that lets a voter vote twice at the same `seq` forfeits this argument and
must replace it with another.

## Design: rounds

A **round** is `(seq, escalation_step)`. The escalation step is exactly what already
decides whose turn it is; it simply is not currently recorded anywhere a voter can see.

Changes:

- `ShareBatchVoteMessage` gains `round: u32`. Serde-default to `0` so an old node's
  votes deserialise rather than erroring.
- The proposer stamps the round it proposed at. `ProposerSchedule::authorise` already
  computes and returns it as `Authorised { escalation }`; today it is discarded.
- `SeqVoteLock` stores `seq -> (round, batch_hash)`:
  - same round, same hash → `Repeat` (a resend, as today)
  - same round, different hash → `Conflict` — genuine equivocation, still a fault
  - **higher round → `Fresh`**, the lock moves
  - lower round → `Stale`, ignored
- `SeqTally` is keyed by `(seq, round)`. Approvals are counted within a round.
  Equivocation means two different hashes from one voter *in the same round*, which is
  still quarantine-worthy. A vote at a higher round is a legitimate new attempt.

This restores liveness: a round that misses quorum is abandoned, and the next escalation
step starts a clean round that every node can vote in.

## The safety gap, stated plainly

Round-scoped voting does **not** by itself preserve the counting argument above. Batch A
at round R and batch B at round R+1 can each collect 6 votes, because the two rounds
draw on overlapping voters at different times. Nothing in a single-phase protocol
prevents that.

The textbook fix is two-phase (Tendermint-style prevote/precommit): a node locks on a
value when it precommits and may only precommit a different value at a higher round if
it has seen a supermajority prevote — a *polka* — for that value at a round at least as
high as its lock. The polka is the evidence that the locked value cannot already have
been committed.

This design does not implement that. What it does instead:

- A voter's vote is **replaced**, not added, when it moves to a higher round, so at any
  instant every voter contributes to exactly one candidate. Since quorum (6) exceeds
  half the voter set (4), **at most one batch can hold quorum at any single instant**.
- A node that has *observed* a batch reach quorum adopts it, closes the sequence
  locally, and stops voting at that sequence.

Under reliable eventual delivery — every vote reaching every node, which the mesh
retries for — these two rules converge the fleet on the first batch to reach quorum.

Under a genuine partition they do not. A fork requires some node to observe A at quorum
while at least four of A's own voters never observe it and move to B. That is a real
asynchronous-safety gap, and it is the price of staying single-phase.

**Therefore:** this is acceptable for WP-5, where the chain is a shadow that pays nobody
and exists to be compared against the live ledger. It is *not* acceptable for WP-6, where
checkpoints feed the coinbase. **WP-6 must not ship until the two-phase protocol is in
place.** That is now a blocking prerequisite, not a nice-to-have.

## What this does not change

- One vote per voter per round. Equivocation within a round is still terminal.
- Quarantine remains operator-release-only (`--sbc-release`).
- `seq_opened` stays derived from `head.close_ts`. It must remain consensus data; a
  node-local rota clock was the previous bug and is not to be reintroduced.

## Test obligations

Each must fail if the mechanism it covers is reverted:

1. A voter that voted at round R can vote for a different batch at round R+1.
2. A voter that votes twice at the *same* round with different hashes still equivocates
   and is still quarantined.
3. A vote at a round *lower* than the lock is ignored, not counted.
4. Two batches at different rounds never both report finalisation from one tally.
5. A round that misses quorum does not prevent the next round from reaching it — the
   deadlock reproduced as a unit test, failing against today's code.
6. A vote message without a `round` field deserialises to round 0.
