# Share Shard — build and cutover plan

Companion to `SHARE_SHARD.md` (the design). This document is **temporary** — it describes how to get
from the system as it stands to the design, and should be deleted once the cutover has shipped.

Written 2026-08-13. Target: v1 by **2026-08-31**.

## Status — 2026-08-16

⛔ **THE COINBASE NOW PAYS FROM THE SHARD.** `pool.shard_coinbase = true` is set on all 8 nodes,
running `886d0a77f`. Verified on the wire, not inferred:

```
coinbase: miner payouts from the SHARD source="shard" payees=5 dust_sats=0 remainder_sats=3
```

Stages 0–5 are complete, **step 6 (the cutover flip) included**. The legacy machinery has NOT been
removed — it still computes, and rollback is `shard_coinbase = false` plus a restart until the first
block is won.

### Fleet state (measured 2026-08-16)

| | |
|---|---|
| binary | `886d0a77f` on all 8 |
| shard columns | 6, byte-identical fleet-wide |
| accrued | `74422306406440472` micro-work |
| `genesis_installed` | true on all 8, `epoch_floor=160384` |
| `owns_evidence` | **false** on all 8 — see the warning below |
| `shard_settled_blocks` | **0** — the pool has won no blocks since the flip |
| drift vs legacy | flat: mean −87.3e12 over 11 folds, slope **+0.93e12/fold** (not growing) |

### What was proven, and how

| claim | evidence |
|---|---|
| discharge arithmetic works | regtest: coinbase paid the owed address, `discharged_micro=4,999,500,000` against a 5,000,000,000 balance |
| settlement identifies pool blocks | tag → held proposal → `settled matured pool blocks blocks=2 deferred=0` |
| consensus ratifies a shard payout | `Consensus reached: Approved 3/3`, block submitted at height 232 |
| a missed column can be repaired | `table sync RECOVERED columns this node was missing columns_gained=1` on vm1–4 |
| drift is not growing | 11 folds, least-squares slope +0.93e12 |

⚠ The folded evidence in the regtest discharge proof was **synthetic** — a regtest share carries
`work = 2.33e-7`, which is 0.233 micro-work and rounds to **0**, so no real regtest share is ever
payable. The fold arithmetic, coinbase construction, maturity walk and discharge all ran on real
code against a real chain; only the input provenance was synthetic.

⚠ `shard_settled_blocks` is still **0 on mainnet**. The discharge path has never run against real
folded shares. That is the first thing to watch when a block is won.

### What is left

| # | item | state |
|---|---|---|
| 7 | rename `shares` → `shares_archive`, move the fold's DELETE target **in the same change**, then flip `owns_evidence` | **DONE — migration v56; see “Step 7 as built” below** |
| — | Stage 6 deletion release (~26–28k lines, ⚠ now an overstatement — see the three settled decisions) | not started; must NOT ride the cutover binary |
| — | §6 λ-sampling | built in `ghost-consensus`, and a hard precondition for admitting FOREIGN nodes (v1 multi-operator) |
| — | MPC ceremony divergence under concurrent contribution | bootstrap-only (`< MPC_BFT_BOOTSTRAP_COUNT = 4`); mainnet has 8 contributors so a join needs 6 approvals and cannot apply unilaterally |

~~⚠⚠ **`owns_evidence` must stay false until step 7 lands, and step 7 should wait for the first won
block.**~~ **Superseded 2026-08-18.** The first half held and is now satisfied: `owns_evidence`
became true in the same change as the rename. The second half — waiting for a won block — was
dropped deliberately, and the reasoning is worth keeping because it is the kind of gate that reads
as caution and functions as a deadlock:

- the pool's share of the network is 0.0000118% (107.7 TH/s against 912.5 EH/s), so "the first won
  block" is a **~161-year** event. A precondition that cannot occur is not a safety margin, it is
  a decision to keep the legacy path alive permanently;
- what the gate was protecting — the ability to compare the shard's payout against the legacy
  path's — is preserved anyway, because step 7 **quarantines** `shares` rather than deleting it.
  Every row is still readable through `shares_archive` and `shares_all`;
- and the drift that comparison would have measured has already been measured: **−0.12%**,
  proportional across addresses, one-off (genesis truncation plus the epoch floor), not growing.
  On a 3.125 BTC block that is 33,289 sats of 309,375,000 redistributed BETWEEN miners — the
  coinbase splits `pool_sats` proportionally (`amount = pool_sats * work / top`), so a uniform
  shortfall cancels and the pool pays out the same total either way.

**Expect the first block after the flip to pay ~0.1% less than the legacy path would have.** Drift
is −87e12 against 74.4e15 accrued — the shard owes slightly less, by design: the genesis conversion
truncates and never rounds up, and the epoch floor under-credits up to `EPOCH_BLOCKS - 1` heights.
Both are deliberate and in the same direction.

## The three facts that govern the whole plan

**1. The cutover cannot be a sequence of deletions.** `template.rs` hard-refuses block submission
without a verified coinbase commitment (`H-11: Cannot submit block without verified coinbase
commitment`), and `CoinbaseCommitment::from_proposal(&PayoutProposal, …)` is its **only**
constructor. Remove the proposal path without landing a counter-snapshot constructor in the same
change and the pool can never submit a block again.

**2. "No gates" falls out of the snapshot — it is not a separate project.** The three era-aware
gates (`SHARE_ADDR_BIND`, `SHARE_TIER_BIND`, `SHARE_POW_VERIFY`) have pre-gate branches for exactly
one reason: old `shares.proof` blobs get re-verified by the sweep, the round-lane backfill and the
SBC checks. Seed from a snapshot, stop re-reading history, and every pre-gate branch is dead code.
The remaining gates are tip-keyed and mainnet is already past all of them, so collapsing them is
bit-identical on the live fleet.

**3. Gates come in two kinds and only one is safe to delete early.**

| kind | examples | when |
|---|---|---|
| **tip-keyed** | fee split 959_290, address grouping 946_743, cluster enforcement 955_200, observed settlement 961_400 | safe now — tip is past them, collapse is bit-identical |
| **round-keyed** | address-bind, tier-bind, PoW-verify | **last**, after the rebase drops pre-cutover history |

Flipping a round-keyed gate to "always" while any pre-cutover share exists mass-refuses historical
shares and re-arms the #639 replay loop. That is exactly what quarantined vm5 on 2026-08-12.

---

## Stage 0 — preflight (no new code)

- `PRAGMA user_version` on all 8. Code is v52; some nodes have historically drifted ahead from branch
  tests, and the migration runner silently skips a migration the DB claims to have. Reconcile any
  node above 52 **before** a v53 ships.
- **Back up all 8 databases.** Migrations run irreversibly at process startup with no pre-migration
  backup. This backup is the rollback substrate for the whole cutover.
- Disable `ghost-auto-update.timer` fleet-wide; expect `ghost-restart-watch` noise during rolls.
- Baseline fleet uniformity (binaries + translator configs).
- Write the **anchor rehearsal script**: emit `ledger_root` and `sha256(canonical_payout)` at a given
  height from every node. Used three times below.

## Stage 1 — the network shard, dark

New `crates/ghost-common/src/share_shard.rs`, reusing `micro_work`, `canonical_sort`, `fold_shares`,
`compute_state_root` verbatim.

- Counter model exactly as `SHARE_SHARD.md` §4.4 — `accrued` grow-only per `(node, address)` merged
  by per-cell max, `settled` grow-only and chain-derived, `owed = Σaccrued − settled`, signed.
- Epoch summary: `{epoch (height-keyed), node_id, per-address rows of (delta_micro, total_micro),
  merkle root over the epoch's network-tier share hashes, signature}` — see `SHARE_SHARD.md` §6 for
  why both numbers are needed. Sign with `NodeIdentity`; `node_id` **is** the pubkey, so no key
  distribution.
- ⚠ **The Merkle tree cannot be imported.** `ghost-reconciliation` depends on `ghost-common`, so a
  direct call is a dependency cycle. Inject it as a plain `fn` pointer, to which
  `ghost_reconciliation::compute_merkle_root` coerces, and use a **dev-dependency** (dev-dep cycles
  are legal in Cargo) so tests can pin the real tree with a golden vector. That pin is load-bearing:
  it trips if reconciliation's encoding ever changes underneath. Single SHA-256 — never mix it with
  Bitcoin's sha256d trees.
- Migration **v53, strictly additive**: `shard_counters`, `shard_settled`, `shard_epochs`. Key on
  `H(plaintext address)`, never the ciphertext — `encrypt_sensitive` draws a fresh nonce per call, so
  a ciphertext key can never be looked up. Leave all `sbc_*` tables alone.
- Two mesh message types (`EpochSummary`, `ShardTableSync`) plus `ShardEvidence` for §6 rejection.
  Follow the exhaustive-match checklist: topic consts, `topic()`/`topic_str()`, size cap **derived**
  not guessed, `should_use_noise() = true` (financial). Old binaries drop unknown variants at
  deserialise without banning — mixed-fleet safe.
- Behind **`pool.share_shard = false`**, a config flag not a height gate, per the
  `share_batch_shadow` precedent. Deploying the binary starts zero traffic.

**Ships dark. Rollback: flag off, or the `.bak` binary. v53 is additive so an old binary ignores it.**

## Stage 2 — network-tier split, dark

`tier_log2` is already coinbase-committed, signature-bound and PoW-verified, so
`tier_log2 >= NETWORK_TIER_LOG2` is a **pure function of the share** (design §12.1) with no new state.

- Send side: the existing gossip decision point where solo mode already filters. Only network-tier
  shares are broadcast and folded. Miner-tier shares still write locally for vardiff, stats and UI.
- Receive side mirrors it with **the same constant baked into the binary, never local config** —
  a node-local value in a validity test is how M-6 happened.
- **Ship with R = 1** (`NETWORK_TIER_LOG2 = MIN_DIFFICULTY_TIER_LOG2`), byte-for-byte today's
  behaviour. Raise R in a later coordinated roll once the shard has soaked. Put the version field in
  the wire format now — it costs one integer and later it costs a protocol change.
- Nothing in `translator-sv2` or `pool-sv2` changes, so miner-facing behaviour and the deploy smoke
  probes are untouched and `deploy-node.sh` stays usable throughout.

## Stage 3 — coinbase from shard, and settlement

- **Coinbase**: a `shard_payout()` source — `owed ORDER BY micro_work DESC LIMIT N` (N ≈ 200, dust
  floor 330 sats) feeding the existing coinbase builder, treasury append and 99/1 fee split, all
  kept. **Freeze the top-N per epoch, not per template refresh**, or near-equal balances reorder
  every 30 s, churn SV2 jobs and defeat the once-per-job skeleton economy.
- **Dark mode: shadow-build the shard coinbase alongside the live armed one on every refresh and log
  the diff.** This is the soak signal that matters most.
- **Settlement**: repurpose `settlement.rs` — it already matches the coinbase tag and extracts mined
  outputs. At maturity depth, add actual paid amounts to `settled` and drop that epoch's evidence.
  Carry over the #601 credit-from-*mined*-outputs fix.
- **Sampling verifier (λ = 20)** with `ShardEvidence` broadcast on failure. First thing to cut if
  time runs short — see below.

### Shard settlement does NOT belong on the block-connected path

`settlement.rs` (950 lines) settles at the **tip** and carries reorg reversal through
`on_block_disconnected` — it has to, because it acts on a block that may still be undone.

The shard settles at **coinbase maturity**, and that difference removes the whole problem rather
than requiring the machinery to be reused:

- a block 100 deep is past any reorg this code contemplates (`RETENTION_FLOOR_BLOCKS` is also 100),
  so **there is no reversal to handle** — nothing was settled while it could still be undone;
- so nothing needs to hook `on_block_connected` at all. The **epoch task already ticks**: it can
  look back to `tip − 100` and settle any pool block it has not settled yet;
- idempotence comes from recording which block hashes have been settled, not from transaction
  gymnastics on a hot path.

So the wiring is a lookback in the task that already exists, not a change to the tip path. Reuse
`settlement.rs`'s **coinbase parsing** (it already extracts mined outputs and fixed the
internal-vs-display hash-order trap, and #601's credit-from-*mined*-outputs correction lives there)
— but not its lifecycle.

⚠ Two things to get right when it is built:

1. **Convert with `discharged_micro_work`.** `settled` is micro-work and the coinbase pays satoshis;
   the rate is `top_work / pool_sats` from the paying node's view. See §4.6 — this is
   deterministic-given-a-table, not identical across nodes, and that is fine because `owed` is
   signed.
2. **`won_blocks` is empty — this path has never once run in production.** Whatever ships will be
   exercised for the first time by a real block carrying real money. Rehearse it on regtest, and
   treat a first live settlement as an event to watch rather than a step that completed.

### Where the epoch task actually goes (surveyed 2026-08-13, read from the code)

This is the wiring that is deliberately **not** delegated — it is where this project has historically
come unstuck, and it is three specific decisions:

**1. Copy the tip−6 loop's shape — it is the thing being replaced.** `main.rs:3998`:
`tokio::spawn` + `tokio::time::interval(30s)` + **`MissedTickBehavior::Skip`**. The `Skip` is
load-bearing: without it a fold that runs long queues ticks and the backlog folds back-to-back
against the same connection mutex that share ingest uses.

**2. Detect the boundary cheaply where rounds already rotate; fold somewhere else.**
`start_round(height)` sits in the `TemplateEvent::NewWork` handler (`main.rs:10101`), which fires on
**every template refresh (~30 s), not per block**, and already persists era-boundary state — so the
precedent for a small write there exists. Compare `epoch_for_height(height)` against the last epoch
(an integer compare) and signal the epoch task. **Never fold inline here.**

**3. Nothing heavy in the ZMQ path.** `publish_empty_template()` (`main.rs:9860`) must stay
sub-second on a new block; that is what gives miners instant work at a tip change. The fold and its
deletes never touch this path.

Two invariants that follow from storage being one `Mutex<Connection>` shared with
`insert_share_with_proof` (`main.rs:7882`): the fold's deletes must be **bounded batches**, and the
fold must read its input **from the persisted shares table by height range**, never from an
in-memory accumulator — the prior design lost 6,499 pending shares on a restart for exactly that
reason.

## Stage 4 — canary dark soak

Deploy fleet-wide (canaries vm5–8, 60-min soak, then vm1–4). Flip `pool.share_shard = true` on
vm5+vm6, then all 8. **Gate to pass before cutover:**

- identical shard table root on all participating nodes within one epoch of any merge;
- shadow coinbase differs from the live armed coinbase only by post-anchor accrual;
- **balances pinned by value** against an independent SQL fold on at least one node. Eight nodes
  agreeing does not mean eight nodes are right — a uniform fold bug agrees with itself. This is the
  mutation-test lesson from SBC and it is not optional;
- no growth in mesh error or oversize-drop counters.

## Stage 5 — genesis and cutover

Old and new ledgers run side by side **in one binary**, so this is a data event plus a config flip,
not a binary big-bang. That is what removes the need for a height gate *and* the need for downtime.

1. **Pick the anchor** — a finalised checkpoint ≥ ~30 blocks behind tip. Run
   `scripts/shard-anchor-rehearsal.sh --survey` then `--height H`, and require **one distinct
   `ledger_root` and one distinct `canonical_payout` hash across all 8**. If not unanimous, step
   back to the previous finalised height.

   ⚠⚠ **`ledger_root` unanimity does not imply the adopted bytes agree, and the anchor cannot be
   picked freely.** Measured across all 8 nodes on 2026-08-13, over the 182 heights every node
   holds since 961,600:

   | | heights |
   |---|---|
   | `ledger_root` unanimous | **180 / 182** |
   | `canonical_payout` unanimous | **41 / 182** |
   | both, *after* the #606 gate at 961,700 | **3** |

   The cause is in `payout_checkpoint.rs:1046`: the finalise path persists
   `ledger_root: msg.ledger_root` — the **proposer's** root over the **proposer's** list — beside
   `miner_payouts: medians`, the per-address median of `in_set`, which is *the reports that node
   happened to receive*. Different report sets give different medians, so the persisted bytes
   diverge while the root, being copied from one broadcast message, stays unanimous.

   At 962,288 that presents as: identical root on all 8, identical 1,316-byte length, identical
   `cutoff_ts` — and **two distinct blobs**, 5 nodes to 3, differing in three of five payees by
   0.06–0.26% of their work. A ceremony gated on the root alone reads that as unanimous and seeds
   eight nodes from divergent balances, which is undetectable afterwards because each node is
   internally consistent with its own.

   Consequences for the ceremony, in order of how much they change the plan:

   - The rehearsal script gates on the **blob digest**, and treats the root as provenance only.
     It also refuses a NULL/empty `canonical_payout` outright — sha256 of nothing is identical on
     all eight, so a pre-adopt-on-finalise row presents as perfect unanimity for a checkpoint with
     no payees at all.
   - **Anchor selection is a search, not a choice.** Only ~1.6% of post-gate heights qualify, so
     "≥30 blocks behind tip" no longer determines the anchor — survey first, then take the newest
     qualifying height. Budget for the anchor being some hundreds of blocks stale, and therefore
     for a correspondingly larger step-4 gap-fold.
   - At every height where the blobs *do* agree, the ratified root also recomputes from them on
     8/8 — i.e. the median equalled the proposer's list. So a qualifying anchor is strictly
     stronger than the plan asked for, which is why the script reports that check.
   - This is a live integrity gap in its own right, not only a ceremony obstacle: `payout.rs`
     documents the root as the thing making the coinbase "a pure function of the checkpoint", and
     since #606 it is not. Stage 6 deletes this path, so the fix is the cutover — but until then
     GHOST-02 recompute-reject rests on a commitment that no longer covers what is paid.
2. **Pin it.** Convert the checkpoint using the existing `genesis_balances` + `GenesisRounding`
   (truncate, never round up) and its pinned golden vector. ⚠ **Convert the finalised checkpoint —
   never recompute from shares.** Pin the height, `cutoff_ts` and expected opening root as a
   compile-time constant plus golden-vector test. This is a one-time seed pin, not a gate: it names
   the past and never flips future behaviour. Opening balances go in a reserved genesis column so the
   write-your-own-column invariant holds from the first row.

   **Built** — `crates/ghost-accounting/src/shard_genesis.rs`, dark. Anchor currently pinned at
   **962,008** (verified unanimous on all 8, blob sha `a3f7202f…2bebad62`, 5 payees, 8 node
   entries, and the ratified root recomputes from those bytes on 8/8). Re-pin to a fresher
   qualifying height at ceremony time by re-running the survey; the golden vector is the only
   thing that has to change.

   ⚠ **A reloaded genesis column must be re-asserted against the pin, every start.** Because
   `merge_accrued` now skips the reserved column, genesis can no longer be re-learned from any
   peer — so the persisted rows became a single point of silent failure. Lose them (truncation, a
   partial delete, a backup restored from before the ceremony) and the node opens under-owing
   every miner, stays internally consistent, and nothing ever contradicts it: the exact failure
   the module was written to prevent, arriving through the back door.
   `shard_genesis::verify_loaded_genesis` closes it — absent column is fine (that is every
   pre-ceremony start), present-and-wrong refuses to start. **Wiring it into the runtime's load
   path is part of the step-4 arming work, which is not built yet.**

   Two things the build settled that the plan had left implicit:

   - **The reserved column must be shared, not per-node.** `owed()` sums *across* columns, so if
     each node opened into its own column the first merge would multiply every miner's opening
     balance by the fleet size — healthy-looking on any single node right up until gossip. All
     eight write the identical balances into one column, where max-merge is the identity.
   - ⚠ **`[0u8; 32]` is a loadable ed25519 key.** The first draft argued the reserved id was
     unclaimable because all-zero bytes are not a valid public key; `VerifyingKey::from_bytes`
     accepts it as a low-order point, and the test asserting otherwise is what caught it. Left
     standing, a peer could have max-merged an inflated opening balance that is permanent (merge
     is a max) and indistinguishable from genesis. The guarantee is now structural, in
     `ghost-common` beside the invariant: `merge_accrued` skips the column, `verify_stateless`
     rejects a summary claiming it *before* checking the signature, and the sole writer is
     `ShardTable::install_genesis`, which no message handler calls.
3. **Back up all 8 databases.**
4. **Roll node-by-node, vm5 first.** On flip each node converts its own copy of the byte-identical
   checkpoint, **asserts the computed root equals the pin and refuses to start the shard otherwise**
   — a loud local self-check, not a fleet negotiation.

   **Built** as `ShardRuntime::arm_from_genesis`. ⚠ **Two things in the paragraph this replaces were
   wrong, and only building it showed that.**

   **(a) The gap-fold must not be a timestamp range.** "Shares with `timestamp ∈ (cutoff_ts, now]`"
   fails twice: it overlaps the ordinary epoch folds that run from the floor onward, double-crediting
   every share in the intersection; and `now` is a local clock, which is the §12.2 trap that made the
   old sweep's summaries incomparable in principle. What is actually needed is for the **epoch
   watermark to restart at the floor**, after which `tick` catches up epoch by epoch on machinery
   that is already bounded, already idempotent (`shard_epochs` is the durable marker) and already
   retries a failed epoch rather than skipping it. No new fold code, and the input still comes from
   the persisted shares table.

   **(b) "There is no double count" was false.** The Stage 4 soak accrues each node's own work into
   its own column and gossips it; genesis then credits that same work again for the whole fleet, and
   `owed()` sums across columns. Narrowing the fold range cannot fix it — the overlap is already in
   the column. Resetting the column cannot either — a not-yet-armed peer re-advertises the higher
   value and wins the max. So arming replaces the table wholesale and sets a **pre-genesis epoch
   floor** at `epoch_for_height(ANCHOR_HEIGHT) + 1`; summaries below it are refused on **both** merge
   paths. The floor derives from the pin every node carries, so it is chain-derived and identical
   fleet-wide. It does not break "behind, never wrong": those epochs are pre-genesis, so their work
   is already in the genesis column.

   The floor is the anchor's epoch **plus one** because `cutoff_ts` falls partway through the
   anchor's own epoch; folding it would re-credit what genesis covered. That under-credits this
   node's work across at most `EPOCH_BLOCKS - 1` heights — deliberate, same direction as the
   conversion's truncation.

   **(c) The mixed-fleet window does NOT cost nothing.** A whole-table sync carries no epoch, so the
   floor cannot gate it — and it is exactly the path that resurrects an unarmed peer's pre-genesis
   column, permanently, because merging is a max. The genesis column is itself the generation
   marker: identical on every armed node, absent on every unarmed one, already in the payload, so no
   new protocol field. Both-absent matches, leaving every pre-ceremony sync unchanged.

   **(d) The epoch floor alone did not contain the mixed window — `total_micro` is cumulative.**
   The floor rejects epochs *below* it, but a summary at an epoch **at or above** the floor from a
   node that has **not yet armed** still carries pre-genesis work in its running total (§6 requires
   the total to be cumulative, or deltas could not be max-merged). An armed node merging that total
   credits pre-genesis work a second time on top of the genesis column, permanently, and the floor
   cannot see it: the epoch is legal, only the total is not.

   **Fixed** — `EpochSummary` now carries `genesis_marker: Option<[u8; 32]>`, the root of the
   genesis column alone, and both merge paths refuse a mismatch. It is the same quantity the
   ceremony pins and `verify_loaded_genesis` checks, so armed nodes agree by construction. Three
   properties make it mixed-fleet safe, each pinned by a test:

   - the marker is **appended to the signing bytes only when `Some`**, so an unarmed node's bytes
     are byte-identical to what a pre-marker binary produced and stay verifiable by any peer;
   - it **is** covered by the signature when present, so stripping it on the wire — which would turn
     an armed summary back into one an armed peer accepts — invalidates it;
   - `serde(default)` means a summary encoded before the field existed decodes as `None`, which is
     exactly what "unarmed" means.

   The asymmetry is safe because by arming time the whole fleet is on this binary: Stage 4 deploys,
   Stage 5 only flips config.

   ⚠ **Still open, smaller:** arming empties this node's own column, so its next summary restarts
   `total_micro` from the delta alone, and a peer holding the immediately preceding summary rejects
   it as `ChainMismatch` in `verify_summary_stateless` — an honest summary refused at the seam. It
   self-corrects once both sides are armed (the marker refuses the stale chain anyway), but it will
   log rejections during the roll, and the roll should not be read as healthy until they stop.

   Arming also **refuses if anything is already settled**. It cannot fire today (zero blocks won),
   but a genesis checkpoint is an *unpaid* ledger, so a non-empty `settled` disagrees with it about
   history and silently discarding that would be the one destructive act in an additive ceremony.
5. **Converge and verify** — one full-table sync, one distinct root fleet-wide, and spot-check the top
   addresses against the old query while both are still computable.
6. **Flip the coinbase source** fleet-wide, same day. Until this moment the coinbase stays armed from
   the last adopted checkpoint — materially the same list — so a block won at any instant pays a
   defensible split. After the flip, the tip−6 propose loop and the GHOST-03 sweep switch off behind
   the same flag. *(The sweep has no config switch today; adding one is part of Stage 1.)*
7. **Quarantine history, do not destroy it.** Rename `shares` to `shares_archive` and stop writing
   payable state to it. ⚠ **`shard_fold_epoch` deletes evidence from `shares`** — Stage 1 defines no
   separate node-shard table, so the fold's DELETE target must move with the rename in the same
   change, or evidence stops being collected the moment the table is renamed.

### Step 7 as built (migration v56, 2026-08-18)

Three tables where there was one, and the whole change is which of them each query reads:

| | who writes it | who deletes from it | who reads it |
|---|---|---|---|
| `shares` | ingest | `shard_fold_epoch` retention, `delete_old_shares` | the fold, the unpaid ledger, the payout writes |
| `shares_archive` | **nothing, ever** | **nothing, ever** | only through the view |
| `shares_all` (view) | — | — | every human-facing read: leaderboards, hashrate, miner stats and history, pool records |

**The fold's DELETE target did not have to move.** The warning above assumed the rename left no
`shares` behind. v56 leaves a fresh empty one, so ingest keeps writing to `shares` and the fold
keeps deleting from `shares` — both now mean *live shard evidence* instead of *the legacy unpaid
ledger*, which is exactly the separation `owns_evidence` was waiting for.

**What actually needed deciding was the 66 `shares` statements**, because after the rename not one
of them errors — they silently return less. The rule that settled every one: anything that WRITES,
or that computes what a miner is OWED, reads the live table; anything a HUMAN reads goes through
the view. The unpaid ledger collapsing to a six-hour window is the point of the cutover, not a
regression, and a test pins it so that "the leaderboard went to zero, let's point the unpaid query
at the view too" fails rather than quietly reviving a second answer to who is owed what.

Two things fell out of the split that were not on the plan:

- **`UNIQUE(share_hash)` is per-table now**, so it no longer stops a peer from serving back a share
  sitting in the archive. Both import paths rested on that constraint alone; without an explicit
  `shares_all` check, convergence would walk pre-cutover history into the live table and the fold
  would credit it a second time on top of the genesis column. Caught by a test, not by review.
- **`ALTER TABLE … RENAME` carries the `sqlite_sequence` row to the archive**, so a fresh `shares`
  would restart `id` at 1 and collide with archived rows across the view. Seeded from
  `MAX(shares_archive.id)`.

**Why the archive keeps the `idx_shares_*` index names.** SQLite has no `ALTER INDEX … RENAME`, so
freeing those names means `DROP` + `CREATE` — a rebuild of four indexes over millions of rows, at
process startup, writing hundreds of MB of WAL on ghost-vm1, whose root filesystem is at 90%. The
archive's indexes stay where the rename put them and the live table's are created under
`idx_shares_live_*`. `sqlite_master.tbl_name` says which table an index serves; the name no longer
does.

**Ops scripts that step 7 would have broken silently**, all fixed in the same change:

| script | what would have happened |
|---|---|
| `lib/ceremony-backup-remote.sh` | verified a backup by comparing `count(*) FROM shares` — 0 against 0 after the cutover, a check that cannot fail |
| `shard-verify-fold.sh` | re-derives the cumulative column from raw rows retention now deletes, so it would report a designed deletion as a MISMATCH. Now exits 1 UNVERIFIABLE with the reason |
| `reconcile-ledger.sh` | repairs a ledger nothing pays from. Refuses on a v56 node unless overridden |
| `ops/verify_attribution.sh` | windowed counts straddling the cutover under-report. Reads the view |

`deploy-node.sh`'s smoke probe (`count(*) FROM shares WHERE timestamp > $started`) is correct
unchanged — it asks "are new shares landing", which is precisely what the live table answers.

**Rollback:** before step 6, per node — restore the `.bak` binary and flag off; the old machinery
never stopped. After step 6 — flip the source and the loops back on; the old ledger resumes where it
froze. **The point of no return is deleting `shares_archive`. Keep it until v1 has shipped.**

## Stage 6 — deletion release (must NOT ride the cutover binary)

~26–28k lines, roughly half tests. SBC layer ~10.4k · BFT payout path ~11–12k · sweep ~2.2k · dormant
scaffolding ~1.4k · gate collapse ~600.

⚠ **That total is stale as of 2026-08-19 and reads high, but by less than first thought.** Of the
three open decisions, one resolved towards *keeping* code: the voting layer (4,578 lines) survives
with elder revocation, so the BFT payout path's ~11–12k shrinks by up to that much. ⚠ The mesh
node-list checkpoint has since LEFT the deletion budget again (#715): the reason it was deletable —
that it could not converge and so could never be armed — was fixed rather than accepted. That takes
~1.4k of "dormant scaffolding" off the total. Re-count the payout path before quoting a Stage 6 size
to anyone.

**DONE 2026-08-19 — SBC layer deleted, net −8,600 lines.** ~9.6k of candidate files were counted;
the delivered figure is lower because **the layer was not separable**. The shard was built ON TOP of
the batch chain's primitives, so four things had to be rehomed before anything could be removed —
and they are precisely the "rules that must survive their gate" list:

| rehomed to | what | why it survives |
|---|---|---|
| `ghost_common::work_fold` | `fold_shares`, `micro_work`, `canonical_sort`, `creditable_difficulty` | `share_shard.rs`, `shard.rs` and `shard_handler.rs` all fold work with these — one fold, or the shard and its verifiers disagree about money |
| `ghost_pool::share_checks` | `NodeShareChecks` (was `NodeBatchChecks`), `ChecksFn` | §6 sampling and the §12.4 evidence audits judge a PEER's share with it |
| `ghost_accounting::genesis_balances` | `genesis_balances`, `GenesisRounding` | `shard_genesis` reuses the conversion verbatim; it decides opening money |
| `ghost_storage::address_key` | `address_key`, `blob32` | `H(plaintext address)` keying — a ciphertext key silently splits one payee's balance into two rows |

⚠ **Generalise this before Stage 6's later steps.** A superseded layer here is not a self-contained
block to lift out: the replacement was built from its parts. Expect the same of the BFT payout path
and the sweep — find what the shard inherited BEFORE deleting, or the delete takes working machinery
with it.

Deliberately left in place: the `sbc_*` tables and migrations v50–v52 (historical migrations must
stay replayable, and migration v53 already promised exactly this), and the `MessageType::ShareBatch*`
wire variants (dead protocol, but deleting message types is its own change — #675 is the precedent).
Nothing in the workspace uses `deny_unknown_fields`, so live `pool.toml` files still carrying
`share_batch_shadow = false` parse fine and ignore it.

⚠ `share_batch_size` in the sv2, stratum-apps and vendor trees is an unrelated SV2 tuning knob and is
NOT part of this; a naive grep for `share_batch` sweeps it in.

The sweep's ~2.2k is unverified: it is not a module but spread through `convergence.rs`,
`share_handler.rs` and `payout.rs`, so it needs reading rather than counting.

Order: SBC layer → dormant scaffolding → BFT payout path (**this is the cutover release, carrying the
replacement commitment constructor**) → sweep → tip-keyed gate collapse → round-keyed era machinery.

Deleting 10k+ lines in the same release as a money-path cutover is the one reliable way to lose the
rollback position. The operator's requirement is met *functionally* at cutover — the machinery is
unreachable — and physically a release later.

**Rules that must survive their gate** are listed in `SHARE_SHARD.md`; the short version is the
difficulty-tier commitment (anti-inflation), GHOST-09 with receiver and address binding, the PoW
preimage check, the fold arithmetic, `genesis_balances`, settle-by-observation, and the coinbase
self-check before submit. Delete the gate, keep the rule.

---

## Deadline verdict

**Achievable by 2026-08-31: Stages 0–5.** Cutover complete, gates unreachable, shard paying the
coinbase. Roughly 4–6k lines against an unusually complete substrate — but `-j2` builds and the
60-minute soak cadence eat real days.

**Cut in this order if slipping:**

1. **λ-sampling verifier** → early September. Verify-before-merge of signatures plus your own fold is
   sufficient among nodes you own. ⛔ **Hard precondition for admitting any foreign node — do not
   open the mesh without it.**
2. ~~**Stage 6 physical deletion** → first September release.~~ **SUPERSEDED 2026-08-23: Stage 6
   deletion happens BEFORE v1, not after it, and is under way now.** Step 3 shipped dark
   (#731), was armed (#738, gate 964,100) and Release B is written. Two reasons the ordering
   flipped: a public release should not carry a dead payout path plus a sweep doing ~5,000
   pointless DB writes per node per day, and the person this release exists for — a stranger
   running the ninth node — should never meet the legacy machinery at all. ⚠ #608 said "after
   the release"; that has been corrected to match.
3. **Raising R above 1** → after a week of shard soak.
4. Cosmetics: `ShareProof` hex serde, refusing `OpenStandardMiningChannel`.

**Not achievable and should not be attempted:** multi-operator hardening of the shard — Sybil-resistant
counter admission beyond node-ID PoW, sampling economics, R-change protocol versioning. The design is
built for it; the fleet does not need it while single-operator. Note the dependency: **the snapshot
ceremony exploits the single-operator window**, which is precisely why Stages 0–5 must not slip past
it.

## Open decisions blocking scope

**~~Do node rewards survive?~~ SETTLED 2026-08-13: they are KEPT.** Consequences:

- `qualification.rs` (~1,858), `verification_reverify.rs` (~1,322), challenger assignment and the
  **challenge-convergence sweep** all stay. That is ~6–8k lines *not* deleted. ⚠ Do not confuse the
  challenge-convergence sweep with the GHOST-03 share sweep — different ledger
  (`verification_ledger`), and only the latter is deleted.
- Four gates survive **as rules**, losing only their activation heights:
  `VOTER_SET_QUALIFICATION`, `CHALLENGER_ASSIGNMENT`, `STRATUM_HANDSHAKE_PROOF` (962_000),
  `ARCHIVE_TX_PROOF` (dormant — decide separately whether the Archive capability is resurrected).
- The stratum-handshake rule is a **net win**: it is already a challenger probing a peer's stratum
  endpoint, which is most of the machinery §10's harvest mitigation needs.
- ⚠ **The genesis snapshot must carry qualification state, not just miner balances.** `node_shares`
  is read from the checkpoint (`cp.node_shares`), so the Stage-5 conversion has to pin the qualified
  node set and its capability shares alongside the per-address balances. Verify both are
  byte-identical fleet-wide at the anchor, not just the ledger root.
- The payout function `f` covers **three** components — treasury, miner pool, node pool — plus the
  miner-dust-rolls-into-node-pool rule. All three must be deterministic from public data, or the
  "exactly one valid payout" property does not hold.
- Sybil resistance for the node pool is a **precondition for opening the mesh**, not for cutover
  (`SHARE_SHARD.md` §10). The operator's position is that it is not yet complete and will be.

**~~Which epoch does a share belong to?~~ SETTLED 2026-08-13 — bind via the round's recorded height.**

```
   epoch(share) = epoch_for_height( rounds[share.round_id].block_height )
```

No new machinery. `rounds.block_height` is `NOT NULL` and indexed (`idx_rounds_height`),
`start_round(block_height)` stamps it on every rotation, every share carries `round_id`, and
`epoch_for_height` is already in `share_shard.rs`. `first_round_at_or_above_height`
(`queries.rs:2977`) is the inverse and is the same lookup #651 uses to derive the era boundary — so
this reuses a mapping already proven in production rather than inventing one.

Why the round's height and not the share timestamp: it is the height the share was mined *against*,
which is the same era key the tier gate judges by, and it is chain-derived. Using the timestamp would
reintroduce precisely the local-clock bug that made the old sweep's summaries incomparable (§12.2).

Rounds rotate per template refresh (~30 s) so many rounds map to one height, and many heights map to
one epoch. Many-to-one at each step is what makes the binding total and unambiguous.

*(My call, derived from the code rather than an operator decision — override if you disagree.)*

**Table-sync paging is unwritten.** The envelope ceiling is ~2,800 cells; the target scale is orders
of magnitude past that (§12.6). Not needed for an 8-node fleet, so it is not a cutover blocker — but
it *is* a precondition for the network growing, and it should be designed before anyone advertises
that it can.

**~~One spelling of the summary predicate.~~ DONE in Stage 1 — nothing left to decide.**
`EpochSummary::verify_stateless()` is at `share_shard.rs:468`, and `verify()` calls it at :497, so the
stateful path goes *through* the stateless one rather than beside it. The gossip path calls
`verify_stateless()` directly (`shard_handler.rs:129`, :692). One spelling, two callers, as intended.

**~~Elder revocation~~ SETTLED 2026-08-19 — it is KEPT, and it keeps the BFT vote with it.**
Operator's position: a revoked position is burned and never reassigned, and that permanence is what
makes an elder position scarce rather than a rotating seat. v1 ships multi-operator, where "one
operator unilaterally burns another operator's slot" is exactly what a vote exists to prevent — so the
capability is justified by the shipping model, not by whether it has fired yet. It has not:
`burned_elder_numbers`, `elder_registration_votes` and `votes` are all empty on vm1.

Consequences for Stage 6:

- `voting.rs` (1,860) + `vote_handler.rs` (2,718) = **4,578 lines survive**, so the BFT payout path's
  ~11–12k shrinks by up to that much. ⚠ Re-measure before quoting a new Stage 6 total — those two
  files are not wholly payout-specific and the split has not been counted line by line.
- `VoteType::PayoutApproval` goes and `ElderRevocation` becomes the sole live variant.
  `ShareAllocation` is dead already — declared at `types.rs:212` and referenced nowhere but one
  enumerating test — so it should go out with the payout variant.
- The survivors must be **decoupled, not merely left compiling**. `verification_handler.rs`,
  `nullifier_route_handler.rs`, `glyph_handler.rs`, `proposal_sync.rs` and `reorg.rs` import only
  helper types (`RateLimiter`, `BroadcastFn`, `compute_proposal_hash`, `VoteHandler`) — three type
  aliases and a hash function, not the BFT. Those want a small shared module.
- The checker now runs **daily** with a 10-minute initial delay (`aea63b1ba`), not hourly.
  ⚠ That initial delay is a `sleep`, not the old tick-and-discard: at a 24-hour period the old
  pattern would have meant a node restarting more often than daily never runs the check at all.

**~~Mesh node-list checkpoint~~ RESOLVED 2026-08-20 — KEPT, and it works now (#715).**
It was neither deletable nor armable: deleting the producer would kill #402's shim, and arming was
blocked by #625 — the node set came from each node's own 120-second liveness view, so eight nodes
produced up to six different answers and nothing could ever finalise.

Fixed rather than accepted. Membership now comes from the ratified qualified set (identical
fleet-wide by construction, and already carrying liveness via the stratum handshake challenge), and
endpoints come from adverts each node signs for itself, carried in the proposal. A voter re-derives
from the proposal's bytes plus ratified state, consulting nothing local.

⚠ Still dormant: `MESH_NODE_LIST_CHECKPOINT_HEIGHT` remains `u64::MAX`. Arming needs the fleet-wide
measurement the new convergence endpoint makes possible — curl it on all eight and diff `list_root`
and `advert_root` — plus #402's independently-operated seeds, which no code can supply while one
operator runs every node.

Consequence: `widen_voter_set` and `active_is_superset_of_elders` (`payout_checkpoint.rs:490`, `:499`)
have **no consumer that survives Stage 6** — the payout checkpoint (deleted), the mesh checkpoint
(deleted), and the `ACTIVE_VOTER_SET` convergence-proof endpoint (`main.rs:7959`), which exists to
prove the payout gate's voter set before arming and goes with the gate. They are deleted, not
rehomed. Do not extract them into a shared module first; that only adds a module to delete.

## Hazards to design against, not discover

- **The share webhook drops a batch after max retries.** Today the sweep is the backstop; once it is
  gone, a ghost-pool restart becomes permanently unpaid miner work with **no reconciliation path and
  no symptom**. Needs a spool on the `pool-sv2` side or an explicit accepted-loss decision with an
  alarm at zero.
- **Solo-mode suppression must extend to epoch summaries**, or a solo node's work enters the shared
  shard and is paid twice.
- **Fold-then-delete must be one transaction**, and the fold's input must come from the persisted
  shares table by height range — never an in-memory accumulator. The prior design lost 6,499 pending
  shares silently on a restart for exactly this reason.
- **The epoch task must not run inline in the ZMQ block handler** (that path publishes the empty
  template sub-second) and must delete in bounded batches — storage is a single `Mutex<Connection>`
  with no `spawn_blocking`, so a long fold blocks share ingest.
- **Sampling needs a data path that does not exist**: verifying a peer's sampled share needs that
  peer's skeleton, which today never leaves its own node. New message type, size cap, topic and
  subscribe-list entry — miss any one and it fails silently.
- **Grep `scripts/` for share-rate assertions before raising R.** Arming the tier gate previously
  broke three smoke probes and `deploy-node.sh` refused every roll.
- **No VACUUM in a migration** (needs 2× the DB size free; vm1 is tight).
