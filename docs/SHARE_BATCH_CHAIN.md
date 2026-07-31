# Share-Batch Chain (SBC) — programme plan

Status: **in progress**, started 2026-07-31. Supersedes the convergence-optimisation line of work
(#568, #569, #576, #577), which made an O(entire-ledger) design cheaper instead of replacing it.

## Why

The original specification is: *"node mesh has 67% BFT consensus on mining shares (ledger style)"* —
BFT consensus **establishes** what the shares are, and payouts are read from the agreed ledger.

What was built inverts that. Each node accepts shares into its own private table, the fleet then
tries to make those private ledgers agree afterwards (GHOST-03 sweep), that never fully converges,
so a **tolerance** was added to the payout vote to absorb the difference, and BFT was demoted to
ratifying a *payout proposal* rather than the *shares*.

Everything expensive falls out of that inversion:

| symptom | measured | root |
|---|---|---|
| sweep traffic at zero divergence | ~15–20 GB/day/node | re-advertising the whole set to find a difference that is normally nil |
| `get_top_unpaid_addresses` | 2.76M rows, 1.6 s, per propose AND per vote, ~40% duty | payable state is O(shares), not O(addresses) |
| unpaid ledger | 2,851,125 shares, 06-02 → now | nothing settles (see "settlement" below) |
| unrepairable shares | 1,811,318 (63.5%) `proof IS NULL` | shares entered ledgers without ever being agreed |
| payout staleness | cutoff = `block(tip−6).time`, ~65 min avg | share agreement chained to block arrival |

The sweep's windows are also sliced from each node's **local `now`** (`main.rs:3820`), so no two nodes
use the same bucket boundaries — the mechanism cannot compare summaries even in principle, only
brute-force re-advertise. That is why optimising it could never have worked.

## Target design

A hash-chained sequence of `ShareBatch`es, proposed round-robin on a ~30 s cadence and adopted at
67%. **The adopted chain is the share ledger.** Per-address totals are an integer fold over the
chain, committed in each batch header, byte-identical on every node by construction.

Key properties:

- **Agreement is verification, not election.** A `ShareProof` is self-proving (PoW preimage +
  GHOST-09 signature + receiver binding), so a validator checks *validity*, not *possession*. It
  needs no prior copy of the shares and no clock sync with anyone.
- **No synchronised deadlines.** The proposer's own clock decides the batch contents; a share that
  arrives late simply lands in the next batch. Nothing is lost, because the ledger stays.
- **You vote once, on the shares.** Payout, coinbase and validation are all deterministic functions
  of the adopted batch — no further agreement step.
- **Block arrival consumes, never gates.** An `ArmedPayout` is swapped in at batch finalisation, so
  a tip change is one lock read + integer math + one SHA256. Staleness ≤ ~40 s versus ~3,600 s.
- **Failure mode is "stop", not "pay wrong".** A minority that disagrees cannot adopt and isolates
  itself, loudly; a majority disagreement stalls with the armed payout unchanged.

Deletes: the GHOST-03 sweep, the payout tolerance, the proof-NULL class, and the #554 hot scan.

## Operator decisions (settled — do not relitigate)

| # | decision |
|---|---|
| D1 | **#558: proof-NULL shares are folded into genesis balances** — credited, not written off. Satisfied for free: `get_top_unpaid_addresses` has no `proof` filter, so they are already inside every finalised checkpoint's totals. Adopting those lists verbatim credits them. |
| D2 | **MPC elders cap at 101, and an elder is JUST A NODE** — `ELDER_STATUS_SHARES = 1`, the smallest of five. Early-bird reward, not a governance class. No council, no veto, no decaying committee. |
| D3 | **No vote weighting, no franchise, no epochs.** Electorate stays "active nodes". Sybil resistance belongs on capability proofs, not the ballot — payout theft is bounded by hashrate (a bad coinbase only pays if you win a block), so node-count Sybil buys only denial. |
| D4 | **No staking, no bonds, no deposits.** "It's immoral and people won't do it." |
| D5 | **Settlement depth = 1** — settle at first sight, reverse on reorg. Under-settling risks irreversible double payment; over-settling reverses exactly from recorded amounts. |
| D6 | **Settlement is derived from the observed chain**, not gossiped. The coinbase is the payment record. |
| D7 | **Solo mode bypasses BFT** with a direct coinbase. So `build_coinbase_solo_mode` (currently zero callers) gets **wired up, not deleted**. |
| D8 | **1% of subsidy+fees across all mining modes.** No separate solo fee regime — post-gate validators already require `fee_split=true`, so the solo path's legacy maths would be rejected anyway. |
| D9 | **`private_mining_password` is enforced on the authorize path.** Today it is written to config and never checked while 3333/34255 stay open — an open pool that is merely unlisted. |
| D10 | **Share age bound is batch-relative**: `0 ≤ close_ts − share.timestamp ≤ 30 days`, evaluated identically by every node (never against local clocks). Generous on purpose — a tight bound destroys real miner work during a stall, and this fleet has had a 4-day one. Any age rejection must alarm. |
| D11 | Settlement facts travel as `(block_hash, proposal_hash)` pairs in the batch — a pointer to an on-chain fact, verified against each node's own chain. Not a cut-point "anchor": a node missing a proposal would silently fold nothing and reject a valid batch. |

## Work packages

Sequence. Each is a branch, one purpose per commit, `scripts/record-tests.sh` before any deploy,
canary soak ≥60 min, production roll vm4→vm3→vm2→vm1 (genesis last).

### WP-S — chain-derived settlement (IN PROGRESS)
Fixes a live defect: `settle_paid_block` has one call site, reachable only by the node that
submitted the block, so 7 of 8 never mark shares paid. After a win their ledgers still owe the paid
set and — being the majority — their view reaches quorum, paying the same work twice. Also why the
ledger only grows.

- [x] v49 migration: `ratified_proposals` + `settled_blocks` (`6d3519f76`)
- [x] `outputs_hash_from_raw_coinbase` — one hasher, both sides (`ac5e8ea4a`)
- [x] storage: atomic `settle_block_atomic` + `reverse_settlement` + proposal persistence —
      settle and reverse each ONE transaction (the path this replaces did mark/won-block/treasury
      as three, which a crash can split). Reversal inverts *recorded* amounts, not recomputed ones.
- [x] refactor `settle_paid_block` into shared `apply_settlement` + `resolve_paid_miner_ids`, so
      the submitter path and the observer path cannot diverge (`settle_paid_block` now takes the
      block hash, which is what keys the idempotency)
- [x] ~~seed `ratified_proposals` from the already-persisted approved proposal on first start~~
      **Plan was wrong — corrected 2026-08-01.** The premise was "proposals live only in an
      in-memory map, so a restart loses them". They do not: `payout_proposals` (v18) already stores
      every proposal with its full JSON, `store_proposal` already writes to it
      (`bins/ghost-pool/src/template.rs:519-528`), and nothing prunes it — the only reads are
      `WHERE is_approved = 1`. So there was no history to seed and no second table needed. v49 was
      revised to add `outputs_hash` + an index to the existing table instead of creating a parallel
      `ratified_proposals`, which would have duplicated the JSON and left two places to disagree
      about proposal history. Proposals written before the column simply do not match a coinbase,
      which reads as "I cannot prove this block is mine" rather than a false positive.
- [ ] populate `outputs_hash` on `store_proposal` (the going-forward half of the above)
- [ ] `SettlementObserver`: on_block_connected / on_block_disconnected / rescan
- [ ] wire to a second `BlockEvent` receiver alongside `ReorgHandler` (do not extend ReorgHandler)
- [ ] `OBSERVED_SETTLEMENT_HEIGHT` gate, dry-run below it
- [ ] **red-before test: a non-submitting node settles** (fails on main today)

### WP-1 — attribution bindings (one shared gate)
Two verified forgery holes. Both append to `signing_bytes`, so they share ONE gate — one signature
format transition, one mixed-fleet window.

- `payout_address` is not covered by `signing_bytes`, while it is adopted first-writer-wins and
  payouts group by it since height 946,743 → forgeable payout redirection.
- Nothing binds a share's PoW to the node claiming `received_by`; the signature only proves the
  *named* node signed. Fix: `sha256(node_id)[..20]` in the coinbase scriptsig, verified via a
  content-addressed per-job **skeleton** (`prefix || full_extranonce || suffix`, byte-exact per
  SV2's own share validator) — NOT a full coinbase per proof, which would cost ~29 KB/share at 200
  payees (~10 GB/day) and overflow any sane proof cap.

### WP-2 — SBC core (dark)
Types, canonical order `(timestamp asc, share_hash asc)` in **internal** byte order, integer fold
(`CAST(ROUND(work*1e6) AS INTEGER)` on `canonical_json_f64(work)`), `state_root`, send-side packing
bound. Pure library code, exhaustively tested for determinism before any wiring.

### WP-3 — batch consensus manager (dark)
Propose/vote/finalise/sync. Round-robin `voters[seq % n]`. **Stall escalation is required** —
round-robin alone deadlocks on an offline proposer because `seq` cannot be skipped in a hash chain:
`voters[(seq + k) % n]` in 90 s steps, plus a one-vote-per-seq lock so two individually-valid
batches cannot both reach 67%.

**Verification failure must be terminal** (quarantine + alarm), never retried — see #583 below.

### WP-4 — genesis batch
`seq 0` opening balances from the latest finalised `PayoutLedgerCheckpoint` (already fleet-identical
by adoption). Uses the tolerance machinery one final time. **Must complete while single-operator,
i.e. before 2026-08-31** — target genesis by ~2026-08-20.

### WP-5 — shadow run + trust gate
Both systems live; only checkpoints feed the coinbase. Gate: byte-identical `(seq, state_root)`
across all 8 for a sustained window, zero quorum stalls, drift vs checkpoints bounded and
non-growing, plus a regtest settlement+reorg rehearsal on the shipping binary. **Nothing is armed or
deleted until this passes.**

### WP-6 — consumption cutover
Tip change reads the `ArmedPayout`; proposal binding moves from `cutoff_ts` equality to
`(batch_seq, batch_hash)`. Reverts onto a still-running legacy path, which is why WP-7 is last.

### WP-7 — deletion (LAST)
Sweep, tolerance, tip−6 loop. Only after the cutover has soaked. Keep the checkpoint tables (genesis
provenance) and the treasury-only fallback (cold start / lost quorum floor) forever.

## Open decisions

- Genesis source height (after a read-only preview-hash comparison across all 8)
- Shadow gate duration and criteria
- Whether a real mainnet win is required before deletion, or the regtest rehearsal suffices
- Whether the round-in-flight convergence exchange survives deletion (recommend yes; only the
  historical sweep dies)
- Raw `shares` retention after batching (DB is 3.5 GB/node; working set exceeds RAM on 4 GB nodes)

## Related findings, verified 2026-07-31, not yet filed

1. **`payout_address` unsigned** — forgeable payout redirection. Private board.
2. **`received_by` unbound to PoW** — forgeable share credit. Private board.
3. **Settlement single call site** — WP-S above.
4. **`proposer_signature` never verified** — signed, persisted, no verify call in the tree.
5. **Legacy `PayoutProposal` path has no proposer authorisation on receipt.**
6. **Round-lane `proofs_missing_from` unbounded** — no count cap, byte cap, or `more_available`,
   unlike the ledger lane beside it.
7. **Oversize messages dropped at `debug!`** — no ban, no metric; makes (6) undiagnosable.
8. **`private_mining_password` unchecked** — see D9.
9. **`build_coinbase_solo_mode` unreachable** — see D7 (wire up, don't delete).
10. **f64 dust loop + missing miner-sort tiebreak** at the 200-output truncation boundary —
    determinism survives only because ordering happens to be canonical upstream.

## Issue triage under this pivot

- **Close:** #558 (decided → D1), #584 (export OOM existed to run the #558 reconciliation, which
  genesis adoption replaces), #580 (verify #581 actually runs every integration target first).
- **Re-scope to this programme:** #585, #556 (storage growth — superseded in mechanism, but they are
  the reason it matters), #587 (specific cause fixed by the address change; the general
  builder-vs-validator mismatch survives and changes shape).
- **Gets worse, not better:** #537 — every DB op on one global mutex with no `spawn_blocking`. SBC
  adds a batch apply every 30 s on that same writer. Must be fixed alongside.
- **#583 — reframed, and it changed a design requirement.** Filed as "~2,300 gossiped shares/10min
  rejected on PoW re-verification, may be the upstream source of ledger divergence". Measured
  2026-07-31 on vm1 over 60 min: **574 rejects, 1 distinct miner, 6 distinct rounds** (105088–105173
  against a current 105685). It is not a systemic gossip failure — it is one miner's shares from six
  old rounds re-offered in a tight loop, ~96 retries each, which is why the original count looked
  catastrophic. vm5 on the newer build showed 0 in the same window (build vs traffic difference
  unproven). The real defect is that **unverifiable shares are retried forever**; under SBC that is
  worse than wasted I/O, because a proposer including one gets its batch rejected by all eight.
  Hence the WP-3 requirement: verification failure is terminal, with quarantine and an alarm.
