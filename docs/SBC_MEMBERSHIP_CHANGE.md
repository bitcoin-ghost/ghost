# SBC: membership change, and how a new node joins

Status: design, 2026-08-10. Written after audit 8 asked the operator's question directly —
*"can new nodes that join the network join in with the quorum?"* — and the answer today
is no.

## What happens now

Membership is seeded at genesis from the ratified payout checkpoint's `node_shares`,
carried forward by every batch, and any change is `FaultReason::MembershipChanged`. That
is deliberate: making membership consensus data removed the root cause of audits 2–7,
where a live per-node query meant no two nodes agreed who was voting, and four successive
mechanisms for proving a commit foundered on it.

The cost is that a node starting after genesis is a non-entity:

- its prevotes and precommits are dropped as non-voter
- it is never in the rota, so it can never propose
- it is never counted toward quorum
- it cannot even **follow** the chain: genesis requires the ratified checkpoint at the
  pinned anchor 961,642 in its own database, and checkpoint backfill will not reach that
  months later — so it never gets a head and holds everything

Under WP-6 (SBC feeding the coinbase) a new operator's miners would earn **nothing,
silently**, because each node batches only shares with `received_by == self` and nobody
batches theirs.

Attrition is one-way. The set can only shrink in practice, and at 3 permanent losses
quorum is unreachable with no remedy.

**v1 is FULL PUBLIC, MULTI-OPERATOR by 2026-08-31. This is a v1 blocker.**

## The rule

Membership changes only by adopting a newer **ratified payout checkpoint**, which is
already a BFT-agreed object — a row in `payout_ledger_checkpoints` exists only because
the fleet finalised it (`queries.rs:9097`, "Persist a finalised payout-ledger
checkpoint").

A batch carries, in addition to `node_shares`:

```
membership_anchor: (height: u64, checkpoint_hash: [u8; 32])
```

`verify_batch` enforces, in this order:

1. **Monotone.** `batch.anchor.height >= parent.anchor.height`. A proposer may only ever
   move membership *forward*. This is what stops cherry-picking: without it, "any ratified
   checkpoint at or below X" is not one object but the entire history, and a proposer
   picks whichever set favours it — one from before a rival qualified, or one where its
   own weight is largest.
2. **Boundary.** The anchor may only change where `seq % MEMBERSHIP_EPOCH == 0`, and the
   new set is effective from the **following** sequence. Without a boundary, every new
   checkpoint is an excuse to reshuffle the rota and move the quorum denominator, in every
   batch.
3. **Held.** The validator must hold that exact checkpoint — matching height *and* hash.
   If it does not, this is a `Defer`, never a `Fault`, and it triggers a checkpoint sync
   request. Not holding an agreed object is our gap, not the proposer's crime.
4. **Exact.** `batch.node_shares` must equal that checkpoint's `node_shares` byte for
   byte. The batch does not *choose* membership, it *states* the value every validator
   computes independently — so the proposer picks nothing.
5. **Unchanged otherwise.** At any sequence that is not a boundary, `node_shares` must
   equal the parent's, exactly as today.

### Which set votes the transition

The set in force for sequence *N* is the **parent's**. A new anchor adopted at *N* takes
effect at *N+1*.

This is not a detail. If the new set voted the batch that introduced it, a proposer would
be voting itself in with the votes of the set it just wrote.

### What must happen alongside

- **Consensus entries above the head must be dropped when the set changes.**
  `SeqConsensus` captures `quorum` at first touch, so entries created by early votes for
  `N+1..N+8` would keep the pre-change quorum frozen. `prune_below` does not reach them.
- **Certificates verify against the set in force at THAT sequence.** Already implemented —
  a synced batch's certificate is checked against the membership the batch carries, after
  requiring it to match ours. Without that, one membership change makes every earlier
  certificate unverifiable and strands all prior history.
- **Certificates must be persisted.** Already implemented (schema v51). With membership
  change they become the only way anyone crosses an epoch boundary.

## How a genuinely new node joins

Membership change alone does **not** answer the operator's question. A node added to the
voter set still cannot participate, because it cannot obtain a head: genesis is only ever
computed locally from the pinned anchor checkpoint, and a new node does not have it.

It needs to join from a **state snapshot**, not from history:

```
SbcSnapshot {
    seq, state_root, close_ts,
    balances,                 // the payable state at that sequence
    node_shares,              // the membership in force
    membership_anchor,
    cert: CommitCertificate,  // proving seq was committed by that membership
}
```

The joiner verifies the certificate against the `node_shares` the snapshot itself carries,
then checks that folding those balances reproduces `state_root` at `(seq, close_ts)`. If
both hold, it adopts the snapshot as its head and participates from `seq + 1`.

That is sound for the same reason the certificate is: the proof is **supplied and
verified**, never inferred from local state the joiner does not have. It also removes the
961,642 pin from the join path entirely — a node joining in 2027 should not need a
checkpoint from 2026.

Note the joiner still cannot verify history *before* the snapshot. That is the accepted
trade every snapshot-sync makes, and it is honest: the snapshot's certificate proves the
fleet agreed that state, which is exactly what a new participant needs.

## Ordering

1. Snapshot join (above) — without it, membership change lets a node into the voter set
   that still cannot obtain a head, which is worse than not adding it: quorum grows while
   participation does not, so the bar rises and liveness falls.
2. Membership change (the rule).
3. Bound `round` against `escalation_at` before multi-operator — audit 8/11's remaining
   Byzantine item, a member spamming distinct rounds grows consensus maps without bound.

## What this does not solve

- **Permanent loss of >f nodes.** If 3 of 8 die permanently, quorum is unreachable and the
  chain cannot adopt the checkpoint that would shrink the set. Recovery requires an
  operator-signed override, which is a deliberate trust escalation and should be designed
  as one rather than fall out of a bug.
- **The split-lock liveness gap** (audit 11): 4 nodes locked on A, 4 unlocked, no polka.
  Safety is unaffected; the remedy today is restarting the locked nodes. A proof-of-lock
  re-proposal is the standard fix.
