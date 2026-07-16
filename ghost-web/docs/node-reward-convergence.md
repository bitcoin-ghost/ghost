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
