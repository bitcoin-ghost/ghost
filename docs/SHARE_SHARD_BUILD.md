# Share Shard — build and cutover plan

Companion to `SHARE_SHARD.md` (the design). This document is **temporary** — it describes how to get
from the system as it stands to the design, and should be deleted once the cutover has shipped.

Written 2026-08-13. Target: v1 by **2026-08-31**.

---

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

1. **Pick the anchor** — a finalised checkpoint ≥ ~30 blocks behind tip. Run the rehearsal script and
   require **one distinct `ledger_root` and one distinct `canonical_payout` hash across all 8**. If
   not unanimous, step back to the previous finalised height.
2. **Pin it.** Convert the checkpoint using the existing `genesis_balances` + `GenesisRounding`
   (truncate, never round up) and its pinned golden vector. ⚠ **Convert the finalised checkpoint —
   never recompute from shares.** Pin the height, `cutoff_ts` and expected opening root as a
   compile-time constant plus golden-vector test. This is a one-time seed pin, not a gate: it names
   the past and never flips future behaviour. Opening balances go in a reserved genesis column so the
   write-your-own-column invariant holds from the first row.
3. **Back up all 8 databases.**
4. **Roll node-by-node, vm5 first.** On flip each node converts its own copy of the byte-identical
   checkpoint, **asserts the computed root equals the pin and refuses to start the shard otherwise**
   — a loud local self-check, not a fleet negotiation. Then it **gap-folds**: its own locally-received
   valid network-tier shares with `timestamp ∈ (cutoff_ts, now]` into its own column. Because columns
   are per-node and the checkpoint already credited everything up to `cutoff_ts`, there is no double
   count and no coordination. The mixed-fleet window costs nothing — shares landing on not-yet-cut
   nodes are gap-folded when that node flips.
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

**Rollback:** before step 6, per node — restore the `.bak` binary and flag off; the old machinery
never stopped. After step 6 — flip the source and the loops back on; the old ledger resumes where it
froze. **The point of no return is deleting `shares_archive`. Keep it until v1 has shipped.**

## Stage 6 — deletion release (must NOT ride the cutover binary)

~26–28k lines, roughly half tests. SBC layer ~10.4k · BFT payout path ~11–12k · sweep ~2.2k · dormant
scaffolding ~1.4k · gate collapse ~600.

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
2. **Stage 6 physical deletion** → first September release.
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

**Elder revocation** currently rides the payout vote machinery. With voting deleted it needs a
standalone home or an explicit decision to drop.

**Mesh node-list checkpoint** is deleted as dormant scaffolding, but §10's public-endpoint discovery
eventually needs a successor.

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
