> # ⛔ ARCHIVED 2026-08-12 — SUPERSEDED, DO NOT BUILD FROM THIS
>
> **The plan in force is [`docs/SHARE_SHARD.md`](../SHARE_SHARD.md).**
>
> The **diagnosis** in this document is still correct and worth reading — private per-node ledgers,
> an after-the-fact sweep, and a tolerance to absorb what never converged. The **solution** is
> abandoned: a hash-chained, round-robin, BFT-adopted batch chain imposes a total order on data that
> commutes, and that ordering was the source of every incident (the seq=1 deadlock, the vote-lock
> wedge, terminal quarantine, four days of dead chain).
>
> **What survives into the new design:** the fold arithmetic (`micro_work`, `canonical_sort`,
> `fold_shares`, `compute_state_root`), the validity primitives, the storage layer, and the genesis
> snapshot *method*. Measured 2026-08-12: the fold is correct to 0–1 shares/hour.
>
> **What is deleted:** `batch_consensus.rs` (1,789 lines), `batch_two_phase.rs` (635), the global
> hash-chained sequence, the rota, escalation, and quarantine as a liveness hazard.

# Share-Batch Chain (SBC) — programme plan

Status: **ARCHIVED**. Started 2026-07-31, superseded 2026-08-12. Superseded the
convergence-optimisation line of work (#568, #569, #576, #577), which made an O(entire-ledger)
design cheaper instead of replacing it.

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

## Design principle — the system must work itself

Operator, 2026-08-01: *"i want everything to work itself — thats why decentralisation and atomicity
is important."*

This is the test any proposed mechanism has to pass, and it rules out a class of answer that keeps
looking attractive because it is cheap:

- **Detection is not protection.** A check that fires an alarm someone has to read is a human in the
  loop. So is anything that depends on an operator noticing a divergence, comparing nodes by hand, or
  running a reconciliation script.
- **Verification must be local and complete.** A node decides alone, from data it holds, whether
  something is valid. Not by asking peers, not by majority opinion about a fact, not by waiting.
- **"It does not pay today" is not a security argument.** Every hole found in this programme was
  harmless under the economics in force when it was written: the unsigned `payout_address` did not
  matter until grouping moved to address; the payout tolerance was sound until multi-operator. v1
  changes the economics, which is exactly when dormant holes wake up.

Operator, same day: *"thats why self mediating and healing are important!"* — so the bar is three
things, not one:

- **self-verifying** — a node decides validity alone, from data in hand.
- **self-mediating** — disagreement is settled by arithmetic or by the chain, never by negotiation,
  tolerance or an operator's judgement. This is why exact equality replaces the payout tolerance:
  a tolerance *absorbs* disagreement instead of resolving it, which means nobody ever finds out
  which node was wrong.
- **self-healing** — a node that falls behind, misses an event, or ends up in a bad state returns to
  correctness on its own. Not by a script, not by a runbook.

Where the design already meets it: `reconcile()` repairs missed settlements and orphaned ones in
both directions; settlement is idempotent so repeated application converges; a diverged node rebuilds
by replaying the batch chain; content-addressed data is self-certifying, so fetching it from an
untrusted peer is safe.

**Where it does NOT, found by applying this to WP-S:** `SettleOutcome::ProposalMissing` currently
logs a warning and stops. That is a human-in-the-loop answer — a won block sits unsettled until
somebody reads the log. It should fetch the missing proposal from a peer and settle. The response is
self-certifying (a forged proposal cannot hash to the payout id the on-chain coinbase names), so the
fetch needs no trust and no quorum. Tracked in WP-S below.

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
- [x] `SettlementObserver`: connect / disconnect / reconcile. Reconcile is SYMMETRIC — it reverses
      settlements for departed blocks AND settles ones the event stream missed, cursor-driven. An
      earlier version only reversed, which left a node that restarted while a block landed never
      settling it: the same divergence, just rarer.
- [x] wired to a second `BlockEvent` receiver alongside `ReorgHandler` — its own subscription, so
      settlement failing cannot take reorg detection down with it
- [x] `OBSERVED_SETTLEMENT_HEIGHT` gate, UNARMED at `u64::MAX`, dry-run below it
- [x] red-before test: a non-submitting node settles (fails on main today)
- [x] **settlement driven by the REAL coinbase builder, and a reorg round trip.** Every other
      fixture wrote the scriptSig longhand, which proves the parser agrees with the fixture — not
      that it agrees with `coinbase_scriptsig`. Those two drifting apart is only discoverable on a
      won block, so `coinbase_scriptsig` is now `pub(crate)` and the settlement test builds its
      bytes with it. The consensus ceiling is asserted on those same bytes.
      The round trip: settle → orphan → reverse (work owed again, by the amount *recorded*) →
      reverse again is a no-op, not a second credit → block returns → settles through the same
      row. That last step is why settlement is a flag rather than a deletion.
- [x] **the recovery closes its own loop.** `ProposalSyncHandler` is registered on the mesh, so a
      node both asks for a proposal a won block names and serves one to a peer that asks. Asking is
      not enough on its own: the answer lands after the block was observed, and the forward scan is
      cursor-driven, so nothing would ever apply it. `deferred_settlements` (v49) records the block,
      reconciliation retries exactly those — re-asking each pass, dropping any that left the chain —
      and the row survives a restart.
- [x] reconciliation runs on a **timer**, not only at startup, and the event loop wakes it early
      when the broadcast receiver lags. A node that self-heals only when an operator deploys is not
      self-healing.

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
- [ ] WP-1b: receiver binding via per-job coinbase skeletons — UNBLOCKED by D12; shape APPROVED by
      operator 2026-08-01; size the node tag jointly with the payout-identity tag against the
      ~9-byte margin
  - [x] **retention rule** — `bins/ghost-pool/src/skeleton_store.rs`, 10 tests. Operator's call:
        finalisation alone is NOT enough, because a settlement reversal puts shares back into the
        owed set and the binding must still be re-establishable. So: hold until the batch is
        finalised **AND** a reorg depth has passed, floor `RETENTION_FLOOR_BLOCKS = 100` (matching
        `ReorgConfig::max_reorg_depth`, not the shallower `min_confirmations = 6`), and an observed
        reorg **pushes the floor forward** rather than racing it. Ceiling at 10x so a permanently
        stalled chain cannot grow the store without bound — and a ceiling eviction is reported
        distinctly, because a skeleton dropped while still needed turns into an unverifiable share
        and must not be discoverable only as a mystery later.
        Affordable only because the ~29 KB outputs blob is content-addressed and shared across
        every job reusing it; the per-template marginal cost is the merkle path plus prefix, a few
        hundred bytes. Whole coinbases per job would be tens of GB over the same window.
  - [x] **scriptSig budget made real, and one assembler for four sites.** `channels-sv2`'s job
        factory takes `with_extra_script_sig(bytes)` — Ghost's tags arrive pre-encoded, so the
        vendored fork carries budget arithmetic rather than Ghost semantics and stays rebasable.
        Three defects found while sizing it:
        - The tag guard was a literal `61` with its arithmetic in a comment. Adding tags without
          tightening it produces a scriptSig over the 100-byte consensus limit — **discoverable
          only on a won block.** Now derived from named constants.
        - The reserve assumed a 32-byte extranonce; the pool runs 20. Budgeting against the real
          size recovers 12 bytes, which is what makes `/GHOST PublicPool/` fit beside both tags.
        - **`StandardChannel::validate_share` reassembles the scriptSig by hand on the block-found
          path** and knew nothing about extra pushes, so it would have built a different coinbase
          from the one the miner hashed. Two more copies of the prefix/suffix offset existed in the
          factory. All four now call `script_sig_before_extranonce`.

        Measured, at the live configuration: **91 of 100 bytes, 9 spare.** 58 tests pass, including
        the 50 pre-existing vectors — the offset dedup is behaviour-preserving.
  - [x] ~~`pool_sv2`: build and pass the Ghost tags into the factory~~ **Not needed — already
        wired.** `ghost-pool` IS the template provider (`:8442` → `pool_sv2` `:34255` →
        `translator_sv2` `:3333`), and `template_provider.rs` already carries both tags through
        into the TDP `coinbase_prefix`. `pool_sv2` appends its pool tag and extranonce after them.
        The tags reach the mined coinbase today.

### 🔴 PRODUCTION: the coinbase scriptSig is at 99 of 100 bytes

Measured 2026-08-01 from the live `pool_signature` on ghost-vm5 and the real encoders, pinned as a
test in `skeleton_store.rs`:

| | bytes |
|---|---|
| BIP34 height (at ~960k) | 4 |
| payout tag | 21 |
| node tag | 25 |
| `/- G H O S T - PublicPool//` (SRI) | 28 |
| `OP_PUSHBYTES` + extranonce | 21 |
| **total** | **99 / 100** |

**One byte** — *once this branch is deployed and a payout is armed.*

⚠ **CORRECTION, observed on ghost-vm5 2026-08-01 15:57.** The live TDP `coinbase_prefix` is
`0349a80e` — **4 bytes, the BIP34 height push alone**. The deployed binary predates the node tag,
and no payout has been settleable since 2026-06-02, so neither tag is present. The scriptSig on
production today is:

| | bytes |
|---|---|
| BIP34 height | 4 |
| `/- G H O S T - PublicPool//` | 28 |
| `OP_PUSHBYTES` + extranonce | 21 |
| **today** | **53 / 100** |

99 is the figure *after* this branch (node tag, +25) **and** an armed payout (+21). So shortening
`pool_signature` is a **prerequisite for arming**, not a fix for a live hazard. Stated wrongly as
"at 99 today" earlier; the test `a_treasury_only_coinbase_is_far_from_the_limit` already pinned 78
for the no-payout case, which should have prompted the check sooner.

It is latent only because a treasury-only coinbase omits the payout tag (78 bytes) — and nothing
has been settleable since 2026-06-02. **Fixing payouts is what arms this.** That makes it a
prerequisite of this whole programme, not a side note.

Neither program could catch it: `ghost-pool` checks its own scriptSig, `pool_sv2`'s job factory
checks its own tag against a budget that nominally reserves 5 bytes for a template prefix that is
actually 50. The total is now measured on the assembled bytes inside
`script_sig_before_extranonce`, which is the one place that sees all of it.

**OPERATOR:** shortening `pool_signature` to `GHOST PublicPool` (already agreed) takes it to 91/100
— 9 bytes. That is a fleet config change, so it needs your go-ahead.
  - [x] **`StandardChannel::coinbase_skeleton()`** — returns `(prefix, suffix, merkle_path)` where
        `prefix ‖ extranonce ‖ suffix` is the serialized coinbase byte-for-byte. Derived by
        serializing the real coinbase and cutting it, not by re-deriving offsets, so the cut cannot
        drift from what was built. Also extracted `build_coinbase`, so the block-found path and the
        skeleton produce the same transaction differing only in extranonce bytes — two
        constructions would be two chances to differ, and only one of them runs often enough to be
        noticed.
        Two tests: the skeleton reassembles byte-for-byte with the cut landing exactly on the
        extranonce (an off-by-one here rejects *every* honest share), and the skeleton is stable
        across extranonces, which is what makes it worth storing per job rather than per share.
  - [x] **transport — push-with-dedup on the existing share webhook.** Chose push over pull:
        `pool_sv2` has no HTTP listener, so pull would mean a new endpoint and a new auth surface,
        while push reuses the retry and back-pressure the share path already has. A skeleton that
        arrived by another route while the share path was failing would name shares that never
        turned up.
        - `ShareData` gains `extranonce` and `skeleton_id`; `ShareBatch` gains `skeletons`.
        - Deduplicated in the sender (bounded, 64 recent ids), not at the call site: every channel
          referencing a job would otherwise send the same skeleton, and nothing upstream knows what
          the others already did. A job lasts ~30 s against ~2 s batches, so roughly one batch in
          fifteen carries one.
        - Skeletons are **held for the next batch** rather than sent immediately, so one never
          arrives after the shares naming it.
        - All four report sites wired — standard and extended, valid-share and block-found. The
          extended path uses the **non-BIP141** serialization: the txid that folds into the merkle
          root excludes witness data, so the with-BIP141 variant would never reproduce the root.
        - A merkle node of the wrong width yields *no* binding rather than a broken one — an absent
          claim beats one guaranteed to fail.
  - [x] share webhook carries `header80` (already present) and now `extranonce`
  - [ ] ghost-pool side: consume `skeletons`/`skeleton_id`/`extranonce`, store, and call
        `verify_share_node_binding` — still gated, still dark
  - [x] **the unknown-skeleton gap now closes by itself.** Operator asked the right question of
        the first design — "binding unverified" was a *permanent* state, which is not a trade-off,
        it is a defect.
        The cause was a one-way dedup: a skeleton was marked sent when it was *enqueued*, so one
        lost in a failed POST was never offered again, and every later share of that job named
        something the other side would never hold. Nothing could notice, because nothing knew.
        Fixed by only remembering a skeleton as delivered once the batch actually succeeds, and
        forgetting it if the batch is dropped. `announce` runs per share and is suppressed *only*
        by that memory, so clearing an id is sufficient — the very next share re-announces, with no
        retry queue and nothing to track. Tested on the property, not the plumbing.
  - [x] **skeletons persist** (`coinbase_skeletons`, v49). An in-memory store meant a restart left
        every share of the job in flight unverifiable: the skeleton had already been delivered, so
        `pool_sv2` would not offer it again and nothing would ask.
  - [x] **re-verify pass** — `bins/ghost-pool/src/binding_recheck.rs`, 4 tests, on the same
        reconcile tick that retries deferred settlements. `unverified_bindings` records a share
        whose skeleton had not arrived; the list query **joins against the skeletons held**, so a
        pass costs what can now be judged rather than the size of the backlog.
        A refuted binding is *resolved*, not retried — the skeleton was present and the proof did
        not hold, so retrying yields the same answer and queueing it hides a real finding. An
        unusable header is likewise dropped rather than retried forever.
  - [x] receiving types mirrored in `ghost-verification` (`extranonce`, `skeleton_id`,
        `ShareBatch::skeletons`), all `#[serde(default)]` so an older `pool_sv2` still parses

**The gap now closes at every layer** (operator asked whether "binding unverified" ever heals — it
did not, which was a defect, not a trade):

| how the evidence goes missing | what repairs it |
|---|---|
| skeleton lost in a failed POST | sender forgets the id; the next share re-announces |
| ghost-pool restarts | skeleton is on disk |
| share arrived before its skeleton | `unverified_bindings` + the recheck pass |
| skeleton never arrives at all | backlog is counted and logged, so it is visible not inferred |

  - [x] **ingest wired.** `record_share_batch` stores the batch's skeletons **before** its shares —
        a share naming a skeleton carried in the *same* batch must find it, or every one of them
        would defer for no reason and wait a tick to be cleared.
        `accept_skeleton` is a function rather than a closure so the trust-free property has a
        test: a skeleton is stored **only** under the id its own bytes hash to. Without that check
        a peer could put bytes of its choosing under an id shares already point at, and every one
        of those shares would then verify against a coinbase the sender picked — the exact attack
        the binding exists to prevent, reintroduced at the storage layer.
        At ingest a share is judged if its skeleton is held and deferred if not. 7 tests.

**WP-1b is complete end to end** — tag in the coinbase, skeleton cut from the real transaction,
transport with dedup, storage, verification, and repair at every layer where evidence can go
missing. All of it dark: `SHARE_ADDR_BIND_HEIGHT` is `u64::MAX` and nothing acts on a verdict.
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
- [x] `ShareBatch` type + `batch_hash`. Carries `settled_blocks: Vec<[u8;32]>` — block hashes only,
      refining D11: the coinbase now names the payout, so the pair's second half was redundant, but
      the batch must still state WHICH settlements are folded in or nodes observing blocks at
      different moments diverge. Shares are committed by canonical signing bytes, not serialized
      form, so the identity cannot depend on an accident of JSON. `follows()` checks sequence,
      parent and forward time, so a batch on a different chain is a sync condition rather than a
      disagreement. The struct's settlement field depends on
      how a won block is identified: if the coinbase carries the proposal hash (D12 option 1) the
      batch need only carry `block_hash`, whereas the pair form is needed otherwise. Defining the
      struct now would bake in a guess about a decision that is still open.

### WP-3 — batch consensus manager (dark)
Propose/vote/finalise/sync. Round-robin `voters[seq % n]`. **Stall escalation is required** —
round-robin alone deadlocks on an offline proposer because `seq` cannot be skipped in a hash chain:
`voters[(seq + k) % n]` in 90 s steps, plus a one-vote-per-seq lock so two individually-valid
batches cannot both reach 67%.

**Verification failure must be terminal** (quarantine + alarm), never retried — see #583 below.

- [x] **rota + escalation + vote lock** — `crates/ghost-common/src/batch_consensus.rs`. Pure
      functions and one small map; no clock, no network, nothing wired. 15 tests.
      - The rota sorts and dedups its voter set, so two nodes that learned the fleet in different
        orders derive the same schedule — a rota that depends on arrival order is one they disagree
        about while both behave correctly.
      - Escalation is **uncapped and cycling**: there is no point at which "nobody is due" is safe
        for a chain that cannot skip a height.
      - Acceptance uses a **window** around our own escalation (±1 step), not a prefix. A prefix
        (`0..=current`) authorises the entire fleet once a stall exceeds the ring size, so a long
        stall would end with everyone proposing and splitting its own vote. Proposing stays exactly
        one node; only acceptance is widened, and only enough to absorb clock skew.
      - `TooEarly` is distinct from `NotAProposer` **because verification failure is terminal** — a
        node one step ahead on a fast clock must read as a retry, not as a peer to quarantine.
      - `SeqVoteLock` refuses a second *different* batch at a sequence while treating a resend as
        idempotent; pruning keeps the finalised boundary itself, since releasing a lock at a
        sequence still in flight is the one thing the type exists to prevent.
- [x] `bft_threshold(n)` given one home in `constants.rs`, and `voting.rs` now calls it — the
      arithmetic is trivial, which is exactly why two sites rounding it differently is a quorum one
      node believes was reached and another does not. Pinned against the formula it replaced.
- [x] **batch verification, with the terminal/recoverable line drawn explicitly.** `verify_batch`
      returns `Valid` / `Defer(reason)` / `Fault(reason)`, and the split is the load-bearing part:
      a fault is terminal, so anything an honest node could produce merely by holding a different
      view **must** defer. `Defer` covers stale seq, being behind, parent mismatch (it may be *us*
      on the wrong parent), a proposer one step early on a fast clock, and a proposer not due under
      *our* voter set — that last one because voter sets are not always identical fleet-wide, and
      faulting it would have honest nodes quarantining each other over a membership lag.
      `Fault` is only what is decidable from the batch's own bytes against a finalised parent:
      out-of-order shares, a duplicate, a share that does not prove itself, a wrong state root, a
      truncation flag contradicting its count, a close time that does not advance, an unsigned
      batch. Position is judged **before** contents, so a batch we are not entitled to judge is
      never branded for a defect — the response to a fault cannot be taken back. 11 tests.
- [x] **vote tally + equivocation.** `SeqTally` counts per sequence, not per batch, because
      equivocation is only visible when the candidates are counted together. An equivocating voter
      is voided **entirely, including their first vote** — a node that will approve two
      contradictory batches has told us nothing, and leaving the first counted is exactly how a
      two-faced node pushes one over the line. Finalisation is announced once, so a later vote
      cannot have the caller apply the same batch twice. Two candidates at one sequence tally
      independently: that is the normal consequence of escalation, and the vote lock is what stops
      either reaching quorum dishonestly.
- [x] **quarantine** — `crates/ghost-common/src/batch_quarantine.rs`, 7 tests. Two decisions, both
      the opposite of the obvious one:
      - **It does not change the rota.** Skipping a quarantined node's turns is the tempting
        design and it is a split generator: each node judges faults independently, so two nodes
        with different quarantine sets would derive different schedules and disagree about who may
        propose. A quarantined peer keeps its turns and simply cannot win a vote here; escalation
        already carries the sequence past a proposer who cannot reach quorum.
      - **It is never refused to preserve quorum.** If enough peers are excluded that 67% becomes
        unreachable, the answer is not to start voting for batches known to be invalid. It is
        quarantined anyway and the quorum loss is reported as its own condition — "I cannot reach
        agreement" and "this batch is bad" are different facts and an operator needs both.
      - The threshold is measured against the **whole** fleet, never the survivors. Recomputing
        67% over what is left is how a quarantined minority becomes a majority: exclude three of
        eight and three of the remaining five could finalise anything.
      - Release is **operator-only**, no timer. An automatic one lets a Byzantine node misbehave,
        wait it out, and repeat forever.
- [x] **propose/vote/finalise driver** — `crates/ghost-common/src/batch_driver.rs`, 8 tests. Pure:
      no clock, no socket, no database; the caller supplies `now` and the inputs and receives an
      action. Consensus logic that reaches for the world cannot be tested for the rare cases, and
      the rare cases are the entire point.
      A quarantined proposer's batch is **not judged at all** — verifying every share on behalf of
      a peer whose answer is already worthless is a denial-of-service anyone could trigger by
      staying quarantined and shouting. Equivocation on votes routes to the same quarantine as a
      batch fault, for the same reason: it is provable from two messages the peer signed itself.
      Two valid batches at one sequence is **not** misbehaviour — that is escalation working — so
      the second is refused without blame.
- [x] **mesh message types** — `ShareBatchProposal`, `ShareBatchVote`, `ShareBatchSync`, with
      topics, Noise routing and per-type size limits.
      - **The wire limit is the authority and the packer derives its budget from it**
        (`share_batch_pack_budget`), not the reverse. #559, #561, #562 and #568 were all one
        shape: a sender bounding its payload by something other than what the receiver enforces.
        Deriving makes that impossible by construction, and it is asserted — a full batch's
        worst-case JSON expansion (~3.1x, the ratio measured on real proofs) plus overhead must
        still fit, and the budget must hold ≥200 real shares or it is not a batch.
      - Batch traffic rides the **existing** share port. A new port would mean a firewall change
        on every node before a single batch could flow — a deployment step that buys nothing.
      - All three require Noise. The batch chain decides who gets paid, so defaulting a new
        financial message to plaintext is an omission that never announces itself.
      - A vote signs **both** sequence and hash, domain-separated: the hash alone replays at
        another sequence, the sequence alone makes every vote at that height interchangeable.
      - Sync requests by **sequence**, not hash — a node that is behind does not know the hash;
        that is exactly what it is missing.

### WP-4 — genesis batch
`seq 0` opening balances from the latest finalised `PayoutLedgerCheckpoint` (already fleet-identical
by adoption). Uses the tolerance machinery one final time. **Must complete while single-operator,
i.e. before 2026-08-31** — target genesis by ~2026-08-20.

- [x] **the conversion** — `crates/ghost-accounting/src/batch_genesis.rs`, 9 tests. It lives in
      `ghost-accounting` because that is where `WORK_SCALE` lives, so the two scales meet in one
      place instead of a constant being copied.
      - Genesis **converts** the checkpoint, it does not recompute from local shares. Recomputing
        would reintroduce the exact divergence the checkpoint exists to have settled — eight
        slightly different unpaid ledgers giving eight slightly different genesis roots.
      - The scales differ: checkpoint 1e12, batch chain 1e6. The ratio is *derived* from both, so
        changing either cannot leave a hardcoded number quietly wrong.
      - **Truncates, never rounds up.** Under-crediting by a millionth of a share is immaterial;
        crediting work nobody proved is a different kind of thing.
      - The discarded remainder is **reported** (`GenesisRounding`), not swallowed. A conversion
        that quietly loses balance is how an unexplained drift begins.
      - `prev_batch_hash` is the checkpoint hash, so the first link points at the object that
        authorises it. A zero parent would be a chain anyone could start.
      - No shares in the batch: the work is in the balances, and re-listing shares would invite a
        validator to re-derive numbers that were agreed by vote rather than by arithmetic.
- [x] **genesis preview run 2026-08-01 — the fleet is already unanimous.** Read-only across all 8:

      | | |
      |---|---|
      | latest checkpoint height | **960,550** (all 8 agree) |
      | `ledger_root` at 960,548 / 549 / 550 | byte-identical on all 8 |
      | `canonical_payout` blob | **one distinct SHA-256 across the fleet** (1,402 bytes) |
      | payees | 6 miner addresses, 8 node entries (every node 1 share) |
      | ratified work | 62,225,872,225.26 units |
      | truncation loss, whole fleet | **956,544 checkpoint units = 0.96 micro-work** |

      So genesis needs no negotiation and no union: every node converts identical adopted bytes to
      identical opening balances. The union stays available but is now provably unnecessary — the
      466-share raw-ledger spread does not reach the checkpoint, because the checkpoint is adopted
      verbatim rather than recomputed. That was always the design; this is the evidence.

      Golden vector pinned in `batch_genesis.rs` against the real 960,550 bytes:
      `state_root(seq 0, cutoff_ts 1785580254)` =
      `e0c6ee483e18fa65d5a6b17b626515a38415863969441feba8d58e6a943fa9e4`
- [x] **OPERATOR: genesis anchor is height 961,642** (decided 2026-08-09). Chosen over the 960,550
      preview because both are fleet-unanimous but 961,642 is ~1,100 blocks fresher, and every
      block between the anchor and the shadow run is work that has to reach the chain some other
      way — anchoring at 960,550 would have made that gap eight days wide.

      Verified read-only across all 8 on 2026-08-09:

      | | |
      |---|---|
      | `ledger_root` at 961,642 | `0FE9BAC3…FEC0CAA9` — **one distinct value fleet-wide** |
      | `canonical_payout` | 1,316 bytes, identical on all 8 |
      | payees / node entries | 5 miner addresses, 8 nodes |
      | ratified work | 57,490,961,343,949,865,451,520 checkpoint units |
      | truncation loss, whole fleet | 2,451,520 units = **2.45 micro-work** |

      Golden vector pinned in `batch_genesis.rs`:
      `state_root(seq 0, cutoff_ts 1786228093)` =
      `cb5ac8470686192246bfc1330791e85023f2044b58f0b076b167ff89923ddc7f`

      ⚠ Note the truncation figure. The 960,550 test asserts the fleet loses under ONE micro-work,
      which held for that data by luck rather than by rule — six remainders that happened to be
      small. The invariant is per-address: each payee truncates by at most one micro-work, so the
      total is bounded by the payee count. 961,642 discards 2.45 micro-work across five payees and
      is equally correct. Do not read the 960,550 number as a threshold.
- [ ] the ceremony itself: pick it, sign it, adopt it fleet-wide

### WP-5 — shadow run + trust gate (CODE COMPLETE 2026-08-09, NOT YET RUN)
Both systems live; only checkpoints feed the coinbase. Gate: byte-identical `(seq, state_root)`
across all 8 for a sustained window, zero quorum stalls, drift vs checkpoints bounded and
non-growing, plus a regtest settlement+reorg rehearsal on the shipping binary. **Nothing is armed or
deleted until this passes.**

Branch `feat/wp5-shadow-run`, 13 commits, `record-tests.sh` green at `5e0ba6d79`.

- [x] **v50 persistence** — `sbc_balances` (the payable state, ~68 rows), `sbc_batches` (the adopted
      chain, keyed by seq, BOUNDED window), `sbc_quarantine` (operator-release-only, so it cannot
      live in memory). Deliberately NOT a share archive: the programme exists because payable state
      is O(shares) rather than O(addresses), and a share-per-row table here would rebuild that one
      layer down. A test asserts `sbc_batches` has no per-share columns.
      Balances key on H(plaintext address), not the ciphertext — `encrypt_sensitive` draws a fresh
      random nonce per call, so a ciphertext key could never be looked up and every fold would
      scatter a miner's balance across duplicate rows. The hash is also portable between nodes,
      which the per-node ciphertext is not.
- [x] **storage accessors** — `crates/ghost-storage/src/sbc_store.rs`, 8 tests. Replace-not-merge on
      save (a stale row keeps contributing to the next root); a DIFFERENT batch at the same seq is
      refused as equivocation while a resend is idempotent; pruning measures from the batch being
      written rather than MAX(seq) and never drops the head; sync is served verbatim because a
      re-serialisation differing by one byte is a batch hash that no longer verifies.
- [x] **`BatchChecks`** — `bins/ghost-pool/src/sbc_checks.rs`, 9 tests. Validity is PoW preimage +
      GHOST-09 signature and nothing else. Deliberately NARROWER than `handle_share_proof`, which
      also applies C5 dedup, M-6, template staleness, L-7 and M-29 — those decide whether this node
      files a share it was handed, none is a property of the share.
      ⚠ **The shadow run is therefore EXPECTED to credit slightly MORE work than the live ledger.**
      M-6 refuses a remote share for a missing `template_id` on a path that never reads the field,
      stranding historical shares at ~2,000-2,900 rejections/hour on every node. That drift is the
      defect being corrected; the gate needs it BOUNDED and NON-GROWING, not absent.
- [x] **shadow chain** — `bins/ghost-pool/src/sbc_shadow.rs`, 13 tests. A node batches only shares
      IT received; taking a peer's would credit the same work twice with both batches individually
      valid. Persist balances THEN batch, so a crash replays an idempotent fold rather than leaving
      a head ahead of its balances. `build_batch` does not drain the pending pool — only adoption
      does, and only of what was adopted, which is what makes a missed batch a deferral not a loss.
      `finalise` refuses a batch whose stated root does not reproduce locally.
- [x] **propose/vote over the rota**, including stall escalation and persisted quarantine. Judging
      happens against the parent BATCH read back from storage; a parent outside the window is a
      Hold, never a fault, because faulting it would have honest nodes quarantining each other for
      being behind.
- [x] **mesh handler** — `bins/ghost-pool/src/sbc_handler.rs`. A vote signs seq AND hash (the hash
      alone replays at another sequence). The node counts its own vote. Falling behind sends a sync
      REQUEST rather than waiting. A request we cannot answer gets no response rather than a
      fabricated one.
      Added `Serialize`/`Deserialize` to `ShareBatch`, which WP-3 left off — the message types and
      size limits existed but the proposal payload could not be encoded, so the wire path was
      unreachable.
- [x] **runtime wiring behind `pool.share_batch_shadow`**, default FALSE. A config flag rather than
      a height gate on purpose: a height gate flips all eight at once, which is the opposite of what
      a shadow run is for, and this is safe to enable one node at a time.
- [x] **three-node convergence test** — separate ShadowChains, separate databases, separate
      encryption keys, byte-identical `(seq, state_root)` through a full SQLite round trip.
      ⚠ Found by mutation while writing it: **a convergence assertion cannot catch a uniform
      arithmetic error.** Every node runs the same fold, so a fold wrong the same way everywhere
      still agrees — adding 1 to every credit left the roots identical and the test green. Expected
      balances are now pinned BY VALUE as well as by agreement. **Eight nodes agreeing does not by
      itself mean they are right**, which matters for how the gate result is read.
- [ ] OPERATOR: genesis ceremony at 961,642 — must complete while single-operator
- [ ] OPERATOR: canary or fleet for enabling the shadow run. The gate needs all 8 agreeing, so a
      canary cannot demonstrate the property — but it can find whatever stops the process starting.
- [ ] the soak itself, and the regtest settlement+reorg rehearsal

**Nothing here has executed on a real node.** Every claim above rests on unit tests and reading.

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

## ⚠ #558 RE-MEASURED 2026-08-01 — the premise this plan inherited is stale

All 8 nodes, live, `paid_in_proposal_hash IS NULL AND valid = 1`:

| node | unpaid | vs lowest |
|---|---|---|
| vm7 | 2,895,630 | — |
| vm6 | 2,895,634 | +4 |
| vm8 | 2,895,639 | +9 |
| vm4 | 2,895,664 | +34 |
| vm1 | 2,895,674 | +44 |
| vm3 | 2,895,695 | +65 |
| vm5 | 2,895,836 | +206 |
| vm2 | 2,896,096 | +466 |

**Spread 466 shares = 0.0161%.** It was 52,000–62,000 on 07-20. All 8 agree *exactly* on 07-30
(55,617 each). The convergence PRs (#565 #568 #569 #576) did their job.

Two corrections that change decisions:

1. **Proof-NULL shares are UNSERVABLE, not unused.** `get_top_unpaid_addresses` filters on
   `paid_in_proposal_hash IS NULL AND valid = 1` and nothing else — no proof filter. That work
   counts toward payouts today. Calling them "dead" was wrong.
2. **Proof-NULL creation has stopped** — 0 on every node on 08-01, after a declining tail. The
   rate tracked sweep activity: the sweep was *replicating* unservable shares between nodes, which
   is precisely how the ledgers converged. Repair working, not a leak.

**Consequence for WP-4.** A standalone union reconciliation would now add ~466 shares — not worth
doing as its own exercise. Genesis should still take the union (it is exact, cheap, and retires the
question permanently), but it is now a formality rather than a rescue, and it should not be allowed
to delay genesis.

⚠ Tooling note: never read a live pool DB with `immutable=1` — it ignores the WAL and reports
`database disk image is malformed`. vm5 looked corrupt for exactly that reason and is healthy.

## Verification — whole workspace, 2026-08-01

`cargo build --workspace` and `cargo test --workspace --lib`, with CI's own exclusions
(`wraith-wallet-gui`, `ghost-tap-desktop` — Tauri crates that need a pre-built binary resource and
are excluded from the Rust jobs for that reason).

| | |
|---|---|
| build | clean |
| tests | **2,666 passed across 20 crates** |
| clippy on every touched crate | 0 findings |

One failure, and it is **not** from this work:
`integration_tests_sv2::template_provider::tests::test_create_mempool_transaction`. It starts a real
bitcoin node plus an external `sv2-tp` binary, and fails at `fund_wallet()` — which is
`corepc_node` RPC (`new_address` then `generate_to_address(101, …)`) against a bundled bitcoind.
`bitcoind` is not on PATH on this box. Traced by code path rather than assumed: nothing in that
test reaches any crate this branch changes, and the test is already marked heavy/flaky in its own
`cfg_attr`.

## Deploy package — the sequence when we go

Four things are authorised and belong in **one** package rather than three separate touches at
production. Ordered so risk comes down before anything new goes on.

### Stage 0 — reduce risk first (no new code)

Both of these make production safer on their own and neither depends on the branch.

1. **`pool_signature` → `"GHOST PublicPool"`** on all 8, in `/etc/ghost/pool-config.toml`, then
   restart `sri-pool`. Takes the coinbase scriptSig **99 → 91 of 100 bytes**. It is at 99 *today*.
   - Verify: `sha256` the config change per node; after restart confirm `pool_sv2` binds `:34255`
     (it does not bind until its TDP handshake completes, ~60s — see
     `gotcha_pool_sv2_startup_ordering`), and that miners reconnect.
   - Rollback: restore the config file, restart.

2. **Revert #571** (read-pool connections) and re-ship #574 + #575 alone. Returns ~93 MB RSS per
   node on a fleet that is swapping (vm1 `si=4MB/s`, free 137 MB).
   - Verify: RSS per node before/after; `free` shows swap-in dropping.
   - Rollback: the prior binary, backed up before the swap.

### Stage 1 — the branch (schema v49, all gates unarmed)

Everything on `fix/observed-settlement`. Additive migration, guarded and idempotent; every height
gate is `u64::MAX` and nothing acts on a verdict.

- **Canary vm4 first**, then vm3, vm2, vm1 (genesis last) — and vm5-8 in between per the usual
  order. Back up the binary before each swap.
- Verify per node: `is-active`, `/health`, v49 applied (`PRAGMA user_version`), round advancing,
  0 errors in the first 15 minutes, mesh peers ≥ 6.
- What to watch that is **new** in this build:
  - `settlement observer started (dry run below the activation height)` on boot.
  - Reconciliation ticking every 5 min without error.
  - `DRY RUN: would settle this block` if the pool wins — the dry-run proof that matching works.
  - Skeletons arriving: `coinbase_skeletons` gaining rows, `unverified_bindings` staying small.
    A backlog that grows means skeletons are not arriving, which is transport, not shares.
- Rollback: prior binary. v49 is additive so a downgrade reads the old columns fine; the new
  tables are simply ignored.

### Stage 2 — genesis

Pick the height at deploy time (operator delegated this). Any recent finalised checkpoint works —
the 2026-08-01 preview found all 8 nodes byte-identical at 960,548-550, so this is a timing choice.
Re-run the preview against the then-current height first, because the property is what matters, not
the number.

### Stage 3 — shadow run

Both systems live, only checkpoints feeding the coinbase. Gate to pass before anything is armed:
byte-identical `(seq, state_root)` across all 8 for a sustained window, zero quorum stalls, drift
vs checkpoints bounded and non-growing.

### Not in this package

Arming any height gate. `SHARE_ADDR_BIND_HEIGHT` and `OBSERVED_SETTLEMENT_HEIGHT` stay at
`u64::MAX` until the shadow run passes — that is a separate, deliberate release.

## ✅ CLOSED 2026-08-02 — `coinbase_skeletons` pruning wired (was: never pruned)

The retention rule exists and is tested (`bins/ghost-pool/src/skeleton_store.rs`: finalised-batch
condition, reorg floor at `max_reorg_depth`, ceiling, reorg extends rather than races). **It is not
wired.** `SkeletonStore` is an in-memory type with no reference from `main.rs`, and there is no
`DELETE` on `coinbase_skeletons` anywhere in `queries.rs`.

So the table added by WP-1b grows without limit. Measured on vm5 after ~6 hours of live traffic:

```
282 rows, 270 KB, 983 B average  ->  ~47 rows/hour, ~1.1 MB/day
```

Small today only because the coinbase carries few payout outputs. **At the 200-payee design target
the suffix is ~29 KB, i.e. ~34 MB/day and never stops** — on the same 30 GB nodes that ran out of
disk on 2026-08-01.

Arming the gates is what makes the payout set large, so this must be wired **before** arming, not
after. What is missing is small: a `prune_skeletons(before_height, finalised_seq)` query and a call
from the reconcile tick that already runs every 5 minutes. The policy is already written and tested;
only the storage side and the call site are absent.

**Fixed the same night.** `prune_skeletons(height, finalised_seq, floor, ceiling)` implements the
same rule in SQL and is called from the reconcile tick that already runs every 5 minutes. The two
bounds are passed in rather than imported, so the policy stays in one place (`skeleton_store`) and
this is only its storage half.

`note_skeleton_referenced` added alongside, so `last_seq` can be set once the batch chain runs;
until then it stays NULL, which the prune correctly reads as "no batch ever needed it" and releases
on the floor alone.

Two tests pin the behaviour that matters: released at the floor and **not a block before it**, and
a skeleton whose batch has not finalised **survives the floor** and is reported as a *ceiling*
eviction rather than a release — because a skeleton dropped while still needed makes shares
unverifiable and must alarm, not appear in a tidy total.

Filed against #585.

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
