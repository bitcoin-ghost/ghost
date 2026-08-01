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
- [x] populate `outputs_hash` on `store_proposal`, computed with the same treasury-address
      selection the commitment uses (that selection was duplicated at three sites and is now one
      helper — picking the other branch silently changes the hash)
- [ ] `SettlementObserver`: on_block_connected / on_block_disconnected / rescan
- [ ] wire to a second `BlockEvent` receiver alongside `ReorgHandler`
- [ ] `OBSERVED_SETTLEMENT_HEIGHT` gate, dry-run below it
- [ ] red-before test: a non-submitting node settles (fails on main today)

### WP-1 — attribution bindings (one shared gate)

- [x] **WP-1a: `payout_address` bound into the GHOST-09 signature.** `signing_bytes_bound`
      length-prefixes the address onto the v1 bytes; `sign_bound` / `has_valid_bound_signature` are
      the v2 pair. Signer (`main.rs`) and all three verifiers (`share_handler`, both convergence
      paths) choose the encoding through one predicate, `binds_payout_address(height)`, so they
      cannot disagree about which form is in force. Address-less proofs encode identically under
      both, which is what makes a mixed fleet safe. Gate `SHARE_ADDR_BIND_HEIGHT` is present but
      **UNARMED (`u64::MAX`)** — arming is a separate operator release, and it should carry WP-1b
      too so there is one signature-format transition rather than two.
      Tests assert both directions: v1 *accepts* a redirected payout address (the vulnerability,
      asserted so it cannot be mistaken for safe) and v2 rejects it, plus strip/add/swap cases.
- [ ] WP-1b: receiver binding via per-job coinbase skeletons — UNBLOCKED by D12; size the node
      tag jointly with the payout-identity tag against the ~11-byte margin
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

- [x] **deterministic core** — `crates/ghost-common/src/share_batch.rs`. `micro_work`,
      `canonical_cmp`/`canonical_sort`, `fold_shares`, `compute_state_root`. Pure functions only;
      nothing reads a clock, a database or the network, and nothing is wired into a runtime path.
      11 tests: quantisation matches the SQL (incl. half-away-from-zero), ordering and folding are
      permutation-invariant over 200 shuffles each with a fixed-seed PRNG, folding is associative
      across batch boundaries, eight simulated nodes with different arrival orders derive an
      identical root, a 1-micro-work change is detected, `seq`/`close_ts` are bound, length prefixes
      make address boundaries unambiguous, and a golden vector pins `SbcStateRoot/v1`.
      Unattributed shares (no payout address) are **counted**, not silently dropped as the existing
      INNER JOIN does.
- [x] **send-side packing bound** — `pack_batch(shares, budget_bytes)` splits a pending pool into
      `included` / `deferred` in canonical order and reports `truncated`. Written *parameterised*:
      the mechanism is settled, the budget number stays an open decision (D12/wire), so nothing here
      commits to a cap. Six tests: the split partitions the input exactly at every budget (nothing
      lost or duplicated — a share in neither list is work a miner never gets paid for), a fitting
      batch is not marked truncated, an impossible budget still emits one share rather than wedging
      the chain forever, packing is arrival-order-independent, repeated packing drains and
      terminates, and the estimate is checked against the real encoded length.
- [ ] `ShareBatch` type + `batch_hash` — UNBLOCKED by D12. The struct's settlement field depends on
      how a won block is identified: if the coinbase carries the proposal hash (D12 option 1) the
      batch need only carry `block_hash`, whereas the pair form is needed otherwise. Defining the
      struct now would bake in a guess about a decision that is still open.

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

## ✅ D12 DECIDED 2026-08-01: the coinbase carries a payout-identity tag

Operator agreed option (1). A won block **declares** what it pays, so settlement is a lookup rather
than an inference, and it is exact regardless of per-node fee drift.

Specify it as a **payout identity**, not a proposal hash. Same 16-byte field, meaning gated by
height: the proposal hash before the SBC cutover, the batch identity after. One tag format, one
scriptsig budget, and the coinbase format never changes twice — which matters because it is the one
field where every node must switch at the same block.

Space was the objection and it is resolved: the coinbase tag was trimmed to `GHOST <mode>`
(`crates/ghost-common/src/config.rs`), taking the measured scriptsig from 53 to ~45 bytes and the
margin from ~3 to ~11 with both tags present.

Unblocks: WP-S (all items), WP-1b, and `ShareBatch` in WP-2.

Remaining sizing work before code: confirm the miner-supplied portion of `/pool_tag/miner_tag/` does
not vary in length, or the margin is not fixed either.

## ⚠ ~~BLOCKER~~ RESOLVED — the analysis that produced D12

**Settlement's match key does not work.** WP-S assumed a node can recognise its own won block by
hashing the observed coinbase outputs and finding the proposal that committed to that hash. It
cannot, because the coinbase that gets mined is **not** the coinbase the proposal described.

Evidence — `bins/ghost-pool/src/template.rs:1045-1095`, "bidirectional fee adjustment". Before the
coinbase is built, the approved proposal is mutated to match the fees actually available in *this
node's* template:

- surplus ⇒ `prop.treasury_amount` increased by the extra;
- shortfall ⇒ treasury reduced first, then `node_payouts` amounts reduced largest-first and
  zero entries dropped entirely.

Miner payouts are untouched in both branches. Node payouts are touched on shortfall. Treasury is
touched always.

The commitment is then recomputed from the adjusted proposal (`template.rs:1455-1465`, which states
the pre-adjustment commitment is "stale"). So the on-chain coinbase hashes to the *adjusted*
outputs, while the proposal we stored hashes to the unadjusted ones.

Worse, the adjustment is **per-node by design**: "the mempool moves, RBF replaces transactions, and
each node's Reaper/BUDS filtering drops a different set — so every node sees slightly different
fees". The winner's drift is not reproducible by anyone else, so no observer can derive the hash
either. This is not a bug in the adjustment; it is what makes the coinbase determinable before the
block is won.

Net effect: matching on outputs hash would fail on essentially every real block, silently — a pool
block would look exactly like a stranger's. The v49 column and lookup are still sound plumbing, but
they cannot be the sole match key.

### Options (OPERATOR DECISION — D12)

1. **Tag the coinbase with the proposal hash (recommended).** Put `GHPP‖proposal_hash[..16]` in the
   coinbase scriptsig, so a won block *declares* which proposal it pays and settlement needs no
   amount hashing at all. Exact regardless of drift, and it makes "is this block ours?" a lookup
   rather than an inference. Cost: ~20 bytes of scriptsig, which competes with WP-1b's 20-byte node
   tag against the 100-byte ceiling — so the scriptsig space audit in WP-1b must cover both, and the
   two tags should be specified together.
2. **Match on the drift-invariant subset** — hash only the miner outputs, which the adjustment never
   touches. No coinbase change, but a weaker key: two proposals with an identical miner split (very
   possible across consecutive tips when no new shares landed) would be indistinguishable, and
   settling the wrong one marks the wrong cutoff.
3. **Match on miner outputs, then disambiguate** by checking the block height against the proposal's
   and requiring the coinbase's total to equal subsidy + that block's fees. Heavier, still
   inferential, and it re-introduces per-node fee reasoning.

Recommendation: **(1)**, specified jointly with WP-1b's node tag so the scriptsig budget is settled
once. Until this is decided, the observer cannot be written — it would be built on a key that does
not match.

### Scriptsig budget — MEASURED 2026-08-01, both tags fit

The objection to option (1) was that the coinbase scriptsig might not have room for a second tag
alongside WP-1b's node id. It does. From the live canary config and the code:

| consumer | bytes | source |
|---|---|---|
| BIP34 height push (960k ⇒ 3-byte value + opcode) | 4 | consensus |
| extranonce (`POOL_ALLOCATION_BYTES` 4 + `CLIENT_SEARCH_SPACE_BYTES` 16) | 20 | `bins/pool-sv2/src/lib/channel_manager/mod.rs:54-57` |
| `pool_signature = "- G H O S T - PublicPool"` | 24 | `/etc/ghost/pool-config.toml:7` (ghost-vm5) |
| **used** | **~48** | |
| **consensus ceiling** | **100** | coinbase scriptSig must be 2–100 bytes |
| **spare** | **~52** | |

Proposal tag (4 magic + 16 hash) + node tag (4 magic + 20 hash) = **44 bytes**, leaving ~8 spare. So
option (1) is affordable without touching anything else.

If more headroom is wanted, the cheapest source is `pool_signature`: 24 of the 48 used bytes are
vanity text, and trimming it to e.g. `"-GHOST-"` frees ~17 more. That is an operator preference, not
a technical constraint.

Caveats on the measurement: the 48 is derived from config and constants rather than read off a real
coinbase (the pool has not won a block since 2026-06-02, so there is none recent to inspect), and it
assumes the SRI job builder places the pool signature in the scriptsig as stock SRI does. Both worth
confirming against an actual template before the tags are sized in code — but the conclusion has
~8 bytes of margin even if a byte or two is off, and trimming the signature restores plenty.

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
