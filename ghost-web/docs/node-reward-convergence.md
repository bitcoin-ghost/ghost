# Node-reward determinism via a converged challenge ledger

Status: **design / spec** (not yet built). Target: first v1.x hardening after v1.
Owns: the GHOST-01 (capability Sybil) fix and the node-split half of GHOST-02.

## Summary

Today the miner half of a block's payout is **deterministic and independently verifiable** —
every node reconciles the same signed share ledger (GHOST-03) and recomputes the same split, so
the GHOST-02 validator can reject a dishonest miner split. The **node-reward half is not**: the
qualification that decides which operators earn a share is computed from data that does not
converge, so no two nodes reliably agree, and a validator cannot recompute-and-reject it.

This spec makes the node-reward half work exactly like the miner half: **one signed, converged
ledger, gated by a count over a fixed cutoff** — not by a wall-clock window over private tables.
The key move is that **challenges become the node equivalent of shares**, and the `uptime_samples`
table (the unreconcilable part) is **retired** — challenge-accrual proves liveness by itself.

## Why today's qualification isn't deterministic

`QualifiedCapabilityProvider::get_all_qualified_nodes()`
(`crates/ghost-verification/src/qualification.rs:595`) produces `Vec<(NodeId, shares)>` from three
inputs, none of which converge:

1. **`now()`-anchored windows.** `lookback_timestamp()` (`qualification.rs:292`) =
   `Utc::now() − 7 days`. Every query keys off each machine's wall clock, so a record at the window
   edge is counted by one node and dropped by another even with identical data.
2. **Challenge tables don't converge.** `archive/policy/stratum/ghostpay_challenges` are populated
   by fire-and-forget `VerificationResult` gossip (`verification_handler.rs:230` →
   `insert_*_challenge`). There is **no backfill / anti-entropy** (unlike GHOST-03 for shares,
   `bins/ghost-pool/src/convergence.rs`), so a dropped/late/rate-limited result is permanently lost
   on that node. Rows are signed + challenger-attributed, so they are **reconcilable** — but nothing
   reconciles them.
3. **Uptime is a private, unsigned opinion — THE blocker.** The 95% uptime gatekeeper
   (`qualification.rs:301`) reads `uptime_samples(node_id, sample_time, was_online)`
   (`migrations.rs:480`), written only when *this* node receives a peer's `HealthPing`
   (`health_handler.rs:944`). Samples are **never gossiped, never signed, and record no observer
   identity.** Node A's tally of B's uptime is private to A; C never sees it. There is no artifact to
   reconcile, so no cutoff can make it deterministic.

Plus: `network_size` (`get_all_node_ids_with_payout`, `queries.rs:2200`) feeds the scaled thresholds
(`qualification.rs:239-288, 621-630`) and is loosely gossiped + cached in per-node memory
(`qualification.rs:164, 623`) — non-deterministic.

### The five capabilities — four converge here, one does not
The reward is the 5-4-3-2-1 set: Archive (+5), GhostPay (+4), Public Mining (+3), Reaper (+2),
Elder (+1). Only the first four are **challenge-verified** — they are the `CapabilityType` variants
(`message.rs:442`: Archive, Policy=Reaper, Stratum=Mining, GhostPay) and are exactly what the
challenge ledger converges. **Elder (+1) is NOT a challenge** — it is assigned by registration order
(first 101 node_ids) and read from the `nodes` registry (`is_node_elder` → `elder_order`). So Elder's
determinism is a SEPARATE convergence problem: the node registry must converge on `elder_order`.
`0e4c4da6` (this branch) already made promotion deterministic (PoW-verified + unique ranks) *given*
a converged registry; the remaining piece is converging the registry itself (nodes rows come from
loosely-gossiped HealthPing registration, `health_handler.rs:933`). Track as a sibling of the
challenge convergence — same "one converged, signed ledger at a fixed cutoff" shape, applied to node
registration. (Coordinator is excluded from `total_shares()` and hard-coded false; not one of the
five.)

## The design

### Principle
The node-reward qualification is a **pure function of one converged, signed ledger evaluated at a
fixed cutoff** — the same shape as the miner ledger. A validator recomputes it from the proposal's
cutoff and rejects a mismatch (completes GHOST-02).

### A. Challenge ledger + convergence (the meat)
- Treat the four `*_challenges` tables as an accruing ledger of signed, challenger-attributed
  results (they already are — signed at `main.rs:8058`, verified at `verification_handler.rs:332`,
  archive/policy verdicts re-derived by the recipient, stratum/ghostpay by distinct-challenger
  majority).
- Add a **GHOST-03-style anti-entropy/backfill** for them: a `ChallengeConvergence`
  request/response (mirror `ShareConvergence` in `message.rs` + `convergence.rs`). A node requests
  challenges it is missing over a window (by `(challenger_id, target, timestamp)` or a running
  sequence); the peer returns the signed results; the requester re-verifies signatures (and
  re-derives verdicts where applicable) before inserting. Add a `UNIQUE(challenger_id, target,
  timestamp)` / dedup key so replays and double-inserts are idempotent (the current schema lacks it
  despite the handler comment).
- Result: after convergence, every node holds the same set of challenge rows.

### B. Count-based, cutoff-anchored qualification (retire `now()`)
- `get_all_qualified_nodes` and every helper take a **`cutoff_ts` parameter** (the proposal's
  tip-change timestamp) instead of calling `lookback_timestamp()`. Window = `[cutoff − W, cutoff]`
  over the converged ledger, OR purely count-based ("the last N challenges by sequence up to
  cutoff"). Count-based is preferred — fully clock-free.
- Gate: a node qualifies for a capability iff, over that window, it has **≥ X challenges for that
  capability AND ≥ 95% passed**. `X` is the minimum-sample floor (replaces "enough challenges over 7
  days"). Shares are then the usual 5-4-3-2-1 per qualified capability.

### C. Retire uptime — challenge-accrual IS the liveness proof
- Delete the `uptime_samples` gatekeeper from qualification. A node that is offline cannot answer
  challenges, so it fails the `≥ X passed challenges` floor — liveness is proven by signed peer
  evidence instead of a private ping counter. `uptime_samples` / `HealthPing`-derived uptime is
  removed from the reward path (health pings may remain for dashboards only).
- This is what makes the whole thing reconcilable: the one input that could not converge is gone.

### D. Issuance coverage (the one new risk)
- Because qualification now depends on *receiving* enough challenges, **issuance must guarantee
  coverage**: every node must be challenged at least `X` times per window, not just random peers.
- Replace/augment the random 3-peer-every-5-min selection (`VerificationTask`, task.rs) with a
  **deterministic round-robin / coverage schedule** so no honest node is starved of challenges by
  other nodes' random choices. Coverage target derived from the converged node set, not a local
  count.

### E. Validator recompute (completes GHOST-02)
- Extend `validate_proposal_split` (`bins/ghost-pool/src/payout.rs`) to recompute the node split:
  `get_all_qualified_nodes(cutoff = proposal.timestamp)` over the converged challenge ledger →
  `calculate_node_payouts` → compare to `proposal.node_payouts` (address→amount map, like the miner
  check). Height-gate it like the existing checks. This replaces tonight's *floor/conservation*
  guardrails with a true recompute-and-reject on the node split, and lets the treasury be pinned
  exactly again (the no-nodes fallback becomes reproducible).

### F. Deterministic network-size / thresholds
- Derive `network_size` and the scaled thresholds from the **converged node set at the cutoff**
  (nodes with a payout address present in the reconciled ledger), not a live loosely-gossiped count
  or per-node cache. Remove the in-memory `cached_network_size` from the consensus path.

## Trust & Sybil (the GHOST-01 angle)
- A challenger cannot fake a pass: archive/policy verdicts are re-derived by the recipient;
  stratum/ghostpay require a majority of *distinct* challengers. So a single malicious/lazy
  challenger can neither inflate a colluder nor grief an honest node.
- Residual: a **clique** of colluding challengers passing each other. Mitigations: the distinct-
  challenger-majority requirement, coverage scheduling that forces cross-clique challenges, and
  (later) weighting challenger trust. Track as the remaining GHOST-01 item — but the converged,
  signed, re-derived ledger is the foundation that makes any of it enforceable.

## Migration / rollout
- **Schema:** add the dedup/UNIQUE key + any sequence column to the `*_challenges` tables; the
  `uptime_samples` table can be left in place but dropped from the reward query. Forward-only
  migration (bump schema; fleet takes it on the next deploy like v41).
- **Gate:** height-gate the new qualification + node-split recompute (like `CLUSTER_ENFORCEMENT_HEIGHT`)
  so the fleet crosses over together; log-only below the gate to soak.
- **Transition:** ship convergence (A) first and let it soak so ledgers actually converge before
  turning on the count-based gate (B/C) and the validator recompute (E). Order: A → soak → B+C+F →
  E behind the gate.

## What it unlocks
- **Independently-verified node split** — the thing that's currently trusted to the proposer.
- **Exact treasury pinning** — the no-nodes fallback becomes reproducible once the node set is
  converged, so GHOST-02 can pin the treasury exactly instead of only its floor.
- **Proposer↔finder binding** and **payout voter set → active nodes** both become sound on top of a
  converged, signed node ledger (see `tasks/design_proposer_finder_binding.md`).

## Risks / open questions
- **Coverage fairness** (D) is the real new design risk — get it wrong and honest nodes fail
  qualification. Needs its own test: every node reaches `X` challenges per window under churn.
- **Window vs count** (B): count-based is cleaner but needs a stable per-capability sequence;
  cutoff-window is simpler but reintroduces an edge (mitigated by the fixed cutoff over a converged
  ledger). Decide during build.
- **Backfill cost:** four tables × fleet; bound the request window and rate-limit like ShareConvergence.
- **Do NOT resurrect membership voting** ([[project_membership_voting]]) — this is deterministic
  recompute over a converged ledger, not a BFT vote on the voter set.

## Sequencing / effort
Real work, days-to-weeks, not overnight: (A) challenge convergence is the largest self-contained
piece and is useful on its own; (D) coverage scheduling is independent; (B/C/F) is the
qualification rewrite; (E) is the GHOST-02 completion and is small once A–D land. Until then,
tonight's conservation + treasury-floor guardrails (`b6f1a643`) hold the line and the node split is
trusted to the block finder within those bounds.

## Component A — build plan (mapped from the code)

Exact structures found (so this is ready to execute):
- **The signed record to retain:** `VerificationResultMessage` (`crates/ghost-common/src/types.rs:1750`)
  — `target_node_id, challenger_id, capability, passed, challenge_data, response_data,
  target_signed_response, timestamp, signature[64]` (signature over target||capability||passed||
  timestamp). This is the "ShareProof" equivalent for challenges.
- **The template to mirror:** `ConvergenceHandler` (`bins/ghost-pool/src/convergence.rs:88`) —
  `build_ledger_request(since,until)` advertises hashes held; `handle_ledger_request` serves signed
  proofs the requester lacks (`unpaid_proofs_missing_from`, cap 2000); `apply_ledger_response`
  re-verifies each signature (`has_valid_received_by_signature`) before crediting. Carried under
  `MessageType::ShareConvergence` with a `ConvergencePayload` enum.
- **The gap:** the 4 `*_challenges` tables (`migrations.rs:488` etc.) store only the DERIVED row
  (`node_id, challenger_id, block_height, expected/response_hash, passed, timestamp`) — **no
  signature, no UNIQUE key.** So today a backfilled challenge can't be re-verified (signature gone)
  and re-gossip double-inserts. This is the same shape as pre-v41 shares.

Steps:
1. **Schema (migration, forward-only).** Retain the signed `VerificationResultMessage` blob + add a
   dedup key. **DECISION NEEDED (small):** either add a `proof TEXT` column + `UNIQUE(challenger_id,
   node_id, timestamp)` to each of the 4 tables (mirrors `shares.proof` exactly), OR add ONE new
   `verification_proofs` ledger table (all capabilities, one place to reconcile) and keep the 4
   tables as the derived view. The single-ledger option is cleaner to converge (one table, one
   backfill) — recommend it.
2. **Retain on receipt.** In `verification_handler.rs:230` `handle_verification_result`, after the
   existing verify/re-derive, persist the signed message blob (into the ledger / proof column)
   idempotently (`INSERT OR IGNORE`).
3. **DB methods** (mirror shares): `verification_keys_in(since,until)`,
   `verification_proofs_missing_from(since,until,theirs,cap)`, `insert_verification_proof(blob)`.
4. **`ChallengeConvergenceHandler`** mirroring `ConvergenceHandler`: build/handle/apply, verifying
   `VerificationResultMessage.signature` (and, where applicable, re-deriving the verdict) before
   insert. New `MessageType::ChallengeConvergence` in `message.rs` + a `ChallengeConvergencePayload`
   enum.
5. **Wire + trigger:** periodic sweep like `ShareConvergence` (main.rs), rate-limited, bounded
   window.
6. **Tests:** idempotent re-insert; a forged/mis-signed backfill is rejected; two divergent nodes
   converge to the same challenge set after an exchange (mirror `convergence.rs` tests).

Only after A soaks do B/C/F (count-based, cutoff-anchored qualification + retire uptime) and E
(node-split recompute) become sound.

## Build status (feat/mesh-hardening, local only — nothing pushed)

**A — challenge convergence: DONE.**
- Schema: `verification_ledger` (v42 migration, single-ledger option chosen) — retains the signed
  `VerificationResultMessage` blob keyed `(challenger_id, target_node_id, capability, timestamp)`.
- Retain-on-receipt: `handle_verification_result` writes the ledger at all four capability sites
  with the re-derived (archive/policy) or challenger-claimed (stratum/ghostpay) verdict.
- DB methods: `verification_keys_in` / `verification_proofs_in` / `verification_proofs_missing_from`
  / `insert_verification_proof`.
- Message + handler: `MessageType::ChallengeConvergence` (Noise, health-monitoring port, 1MB /
  150-proof cap) + `ChallengeConvergencePayload` and request/serve/apply methods on
  `VerificationResultHandler`. Backfill re-applies the full live gates (signature, known-peer,
  archive/policy re-derivation); freshness/rate-limit intentionally skipped (historical, bulk).
  Apply writes ONLY the ledger, never the `*_challenges` tables.
- Wired: an mpsc relay + a periodic sweep in `main.rs` rotate through 1-hour buckets of the
  trailing 7 days. Tests: bidirectional reconciliation + idempotency + forged-proof rejection.

**B/C/F — deterministic qualification: DONE (built, unwired).**
- Storage: `ledger_pass_rate` / `ledger_unique_challengers` / `ledger_challenger_majority` read the
  converged ledger over a bounded `[since, until]`.
- `QualifiedCapabilityProvider::get_all_qualified_nodes_at_cutoff(node_ids, cutoff_ts)` — fixed
  cutoff (no `now()`), converged ledger (no `*_challenges`), no uptime gatekeeper, network size from
  the passed node set (no cache). Tests: cross-node determinism, post-cutoff exclusion with uptime
  retired, stratum majority survives one griefer.
- NOT on the live payout path yet — dead code until E gates it.

**E — validator recompute + proposer switch: NOT STARTED (deliberately).**
This is all-or-nothing at its gate: the proposer's `create_proposal` node_shares source and the
validator's `validate_proposal_split` must BOTH flip to `get_all_qualified_nodes_at_cutoff(cutoff =
proposal.timestamp)` at the same height, or every payout mismatches. Per the rollout order it cannot
be enabled until A has deployed and soaked so ledgers actually converge — and A is not yet deployed.
Precise plan when A is live and soaked:
1. Add `NODE_SPLIT_ENFORCEMENT_HEIGHT` (a later height than `CLUSTER_ENFORCEMENT_HEIGHT`), default
   inert.
2. Proposer: source `node_shares` in `create_proposal`/`create_solo_proposal` from
   `get_all_qualified_nodes_at_cutoff` at/above the gate (below it, keep the live path).
3. Validator: in `validate_proposal_split`, capture the miner `dust` (currently `_dust`), rebuild
   `augmented_node_pool = fee_dist.node_reward_pool + dust`, recompute
   `calculate_node_payouts(get_all_qualified_nodes_at_cutoff(cutoff), augmented_node_pool)`, compare
   the address→amount map to `proposal.node_payouts`, and — with the node split now pinned — replace
   the treasury *floor* with an EXACT treasury check (the no-nodes→treasury fallback is finally
   reproducible). Gate rejection on `NODE_SPLIT_ENFORCEMENT_HEIGHT`, log-only below (like the
   existing miner-split gate in `make_proposal_validator`).
4. Tests: a faithfully-built proposal passes; a node-split tamper and a node↔treasury shift both
   fail above the gate and only log below it.
Until E lands, the conservation + treasury-floor guardrails (`b6f1a643`) hold the node-vs-treasury
line and the division within the node pool is trusted to the block finder within those bounds.
