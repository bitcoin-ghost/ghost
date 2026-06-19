# Bitcoin Ghost — Full-Stack Security Audit (2026-06)

Scope: the entire Ghost stack — `ghostd` (Bitcoin Core fork), `ghost-pool` (decentralized
pool), the consensus mesh, capability verification, the mining/Stratum stack, and the
`ghost-pay` L2 / privacy layer. Conducted by reading the implementing source (every finding
is grounded in `file:line`), not the docs or marketing.

**One-line verdict:** the node fork is genuinely consensus-safe, the coinbase payout path is
genuinely non-custodial, and the ZK/CoinJoin cryptography is real and competent — but the
**incentive-security layer that makes a *decentralized* pool safe against adversarial
participants is not yet sound.** Ghost is secure-by-trusted-operator today; the gaps below
are what must close before the decentralization goal (independent, untrusted node operators)
is safe to pursue.

Severity: **CRITICAL** (funds/consensus can be stolen or halted) · **HIGH** (incentive economy
forgeable) · **MEDIUM** (correctness/robustness) · **LOW** (hygiene/docs).

---

## Findings register

| ID | Sev | Component | One-line | Status |
|----|-----|-----------|----------|--------|
| GHOST-01 | HIGH | ghost-verification | Capability challenges are forgeable; verifier trusts challenger's `passed` boolean with no re-execution | PARTIAL — Reaper/BitcoinPure negative control added + tested (PR #35); PublicMining handshake, GhostPay root-check, and the cross-mesh collusion fix remain (wire-format) |
| GHOST-02 | HIGH | ghost-consensus | Payout-proposal validators don't recompute the split vs their own ledger; no proposer-authorization check | FIXED (PR #45, Option A) — validators recompute the split from their own converged ledger + addresses (signed-address adoption, first-writer-wins) and reject mismatches before voting; wired via a VoteHandler ledger-validator hook. Proposer↔finder binding is a follow-up |
| GHOST-03 | HIGH | ghost-consensus | `ShareConvergence` is dead code — no ledger-convergence protocol; gossip-only | FIXED (PR #43) — convergence implemented + wired live (mesh handler + 30s request); `RoundManager` retains signed proofs; backfill re-verifies GHOST-09. Tested via the harness. Wire-format; coordinated deploy |
| GHOST-04 | CRITICAL | ghost-consensus | Live elder set = 4 < mainnet `MIN_VOTERS_FOR_BFT = 7` → payout BFT cannot reach quorum | FIXED (PR #38) — adaptive floor `clamp(4,7)`; DO NOT deploy in isolation (cluster) |
| GHOST-05 | HIGH | ghost-pay | L2 peg-in mints shielded value with no on-chain deposit verification (custodial) | FIXED (PR #37) — `confirm_lock_funding` verifies the UTXO via `gettxout`; `shield_balance` requires Active lock. Remaining: mandatory `lock_id` (behaviour change) |
| GHOST-06 | MEDIUM | ghost-mpc | `verify_contribution` not called on consensus-approval path; no min-contribution / full hash-pin | PARTIAL (PR #36) — load now fails closed without a pinned BLOCK hash. Remaining: `verify_contribution` on the apply path (needs ceremony harness; future-join only) |
| GHOST-07 | MEDIUM | ghost-pool / verification | `/api/internal/*` binds `0.0.0.0`; secret set on mainnet but bind is over-broad | RESOLVED — no change needed (already fail-closed on mainnet; secret set; bind required for mesh load-balancer polling) |
| GHOST-08 | HIGH | ghost-zkp | `test_accept_all()` (returns `Ok(true)`) compiled into production verifiers | FIXED (PR #33, merged) — bypass branch compiled out under `zk-production` |
| GHOST-09 | MEDIUM | ghost-consensus | `received_by` (node-reward credit) is unauthenticated → credit theft | FIXED (PR #40) — `ShareProof` now carries an ed25519 signature by `received_by`; receive path drops missing/invalid sigs (unsigned ⇒ rejected). Wire-format change; coordinated deploy. **This is the cluster's foundation.** |
| GHOST-10 | MEDIUM | ghost-verification | Uptime gatekeeper only ever records `was_online=true` (no offline samples) | FIXED (PR #34, merged) — time-based liveness denominator |
| GHOST-11 | MEDIUM | ghost-consensus | Equivocation bans are in-memory only; equivocating elder stays an eligible voter | OPEN — persistence is local but propagation is wire-format. Payout-integrity cluster |
| GHOST-12 | MEDIUM | ghost-reconciliation | `MIN_BATCH_SIZE = 1` (comment: "MAINNET: raise back to 10") destroys batch anonymity | FIXED (PR #33, merged) — `MIN_BATCH_SIZE = 10` |
| GHOST-13 | LOW | docs | Doc/reality drift (missing `docs/`, dust→treasury, P2WSH-not-P2TR, MiMC-not-Pedersen, Reaper=BitcoinPure, README stats) | RESOLVED — this audit doc is the corrected reference; CLAUDE.md (gitignored, local) dust note also corrected |

---

## What's strong (verified, not assumed)

- **`ghostd` is consensus-safe.** Every Ghost feature is mempool policy / template selection /
  storage / relay timing. `src/consensus/`, `tx_verify.cpp`, `interpreter.cpp` contain **zero**
  Ghost code. Reaper rejects only via `TX_NOT_STANDARD` in `AcceptToMemoryPool`
  (`src/validation.cpp:915`); Haze strips storage *after* full validation (`validation.cpp:4556`)
  and reuses Core's stock `assumevalid`. A Ghost node accepts every valid Bitcoin block. The
  "no soft fork" claim holds.
- **Coinbase payouts are non-custodial.** Paid directly as coinbase outputs to each recipient's
  own address; `coinbase_tx_value_remaining: 0` (`template_provider.rs:1301`); no operator
  balance; u128 arithmetic with exact reconciliation (`payout.rs:519-531`).
- **Miner work is cryptographically bound** — share hash must meet claimed difficulty, work is
  recomputed and capped, not trusted (`round.rs:570`). A node cannot fabricate hashrate.
- **The ZK circuits and CoinJoin crypto are real** — Groth16/BLS12-381, full R1CS with range
  proofs (`ghost-zkp/src/circuit/*`); Wraith blind-sig CoinJoin is theft-proof (each peer signs
  its own input over the full output set).

---

## Detailed findings

### GHOST-01 (HIGH) — Capability verification is forgeable
The node-reward economy pays by *verified* capabilities, but verifiers **store the challenger's
`passed` boolean verbatim** without re-executing the challenge
(`ghost-consensus/src/verification_handler.rs:275-368`). Colluding known peers sign
`passed=true` for each other. Per-capability probe weakness:
- **PublicMining (+3):** `verify_stratum` is a `/proc/net/tcp` LISTEN check on the node's own
  port (`ghost-verification/src/server.rs:1862-1913`) — `nc -lk <port>` passes. **GAMEABLE.**
- **GhostPay (+4):** verifier never checks `epoch_state_hash` is the true L2 root; any 64-hex
  string + correct nonce hash passes (`task.rs:1813-1849`). **GAMEABLE.**
- **Reaper/BitcoinPure (+2):** challenge only sends a clean T0 tx and asks "is this T0?"; a node
  that filters *nothing* (classifies all as T0) passes — no negative control (`task.rs:1400-1514`).
  **WEAK.**
- **Archive (+5):** merkle cross-check is real, but a fetch-on-demand proxy passes without
  retention (`task.rs:1236-1395`). **WEAK.**
**Sybil cost:** node id is a one-time 2²⁴ PoW (`identity.rs:58`) — seconds per identity.
**Impact:** the node reward pool is Sybil-farmable for ~free once there's a reward worth taking.
**Fix:** make verifiers re-execute (or require a target-signed challenge transcript), harden each
probe (real Stratum handshake; verify L2 root against a known checkpoint; negative-control Reaper
challenges; archive retention sampling), add IP/subnet diversity to challenger counting, and raise
the Sybil floor.

### GHOST-02 (HIGH) — Payout proposals approved without verification
`validate_proposal` checks only internal balance (sums ≤ subsidy+fees, no dust/dup addresses)
(`vote_handler.rs:1202-1303`); it **never recomputes the split against the validator's own share
ledger**, and there is **no check that `proposal.proposer` is the actual block finder**. An honest
elder approves a distribution it cannot corroborate; any node can open a payout session.
**Fix:** validators recompute the expected `(address, amount)` set from their own ledger at the
block's cutoff and reject on mismatch; bind the proposal to the winning block (proposer must be the
finder of `block_hash`).

### GHOST-03 (HIGH) — No ledger-convergence protocol
`ShareConvergenceMessage` / `Response` (`message.rs:408-433`) are defined but **never sent or
handled**. Share propagation is best-effort gossip; a partition or dropped broadcast silently
diverges ledgers, which combined with GHOST-02 lets a divergent-but-balanced proposal be approved,
or stalls quorum.
**Fix:** implement convergence — periodic per-round share-set digests with pull-backfill of
`missing_shares` before a payout proposal is allowed to vote.

### GHOST-04 (CRITICAL) — Elder set below mainnet BFT floor
`MIN_VOTERS_FOR_BFT = 7` on mainnet (`main.rs:1238`, `voting.rs:243-255`); confirmed live
`mpc_contributions` = **4**. `VotingSession::new` returns `InsufficientVoters`, so a mainnet payout
vote **cannot form**. Untested because 0 blocks found and all current hashrate is the operator's,
but the pool cannot pay a real won block today.
**Fix (decision required):** either grow to ≥7 genuinely-independent elders before launch
(preferred, matches the decentralization goal), or set the floor to a defensible `n≥3f+1` for the
bootstrap set with explicit f. Must not silently 3-of-4.

### GHOST-05 (HIGH) — L2 peg-in is custodial / unbacked
`shield_balance` mints L2 value from a client-supplied amount + blinding with **no on-chain deposit
verification** (`bins/ghost-pay/src/main.rs:4365-4444`); `confirm_lock_funding` flips a lock to
Active on a client-asserted txid with no RPC check (`:2368-2461`). Exits are operator-co-signed
(`:6470-6553`). The shielded supply's BTC backing rests on operator/mesh honesty, contradicting the
"non-custodial / trustless" claim.
**Fix:** verify the lock's P2WSH UTXO on-chain (exists, confirmed to depth, holds the claimed
value) before minting; document the cooperative-custody reality and the timelock escape hatch.

### GHOST-06 (MEDIUM) — MPC trusted setup partly bypassed
`verify_contribution` (pairing/Schnorr checks) runs only in tests; elders approve a contribution on
structural + hash-chain checks only (`mpc_handler.rs:384-427`). No minimum-contribution enforcement
(genesis params usable live). Only the note_spend params file is hash-pinned at load
(`ghost-zkp/src/lib.rs:319-338`); unshield/payout params and VKs are not.
**Impact:** the genesis operator may hold the trapdoor → forge shielded value/withdrawals.
**Fix:** call `verify_contribution` on the approval path; enforce ≥1 verified post-genesis
contribution per circuit; hash-pin every params/VK file.

### GHOST-07 (MEDIUM) — Internal API bind too broad
`/api/internal/*` (share/block injection, pool-nodes) binds `0.0.0.0:8080`. `internal_api_secret`
**is** set on mainnet (auth required), but the bind is network-wide.
**Fix:** bind `127.0.0.1` (or firewall to mesh peers); hard-require the secret on mainnet (refuse to
start without it), not just warn.

### GHOST-08 (HIGH) — `test_accept_all()` in production verifiers
`pub fn test_accept_all()` returning `Ok(true)` is compiled into the shipped ZK verifiers (e.g.
`ghost-zkp/src/note_verifier.rs:44-52`), not `#[cfg(test)]`-gated. Any caller that constructs it
bypasses proof verification.
**Fix:** `#[cfg(test)]`-gate or delete; grep for callers.

### GHOST-09 (MEDIUM) — `received_by` unauthenticated
Node-reward credit is attributed to `proof.received_by` (`round.rs:701`), dedup keyed on
`share_hash`. A node can rebroadcast a genuine miner share with `received_by` = itself and race the
origin to steal node-reward credit; nothing binds `received_by` to actually serving the miner.
**Fix:** the origin node signs `received_by` into the share proof; credit only the signed origin.

### GHOST-10 (MEDIUM) — Uptime gate never records downtime
`record_uptime_sample` is only ever called with `was_online=true`
(`health_handler.rs:924`, `main.rs:3958`); no offline-sample path found. Uptime% trends to ~100%
for any node that pings intermittently, weakening the 95%/7-day gate that protects all capabilities.
**Fix:** record `false` samples for elders that miss expected pings within the window.

### GHOST-11 (MEDIUM) — Equivocation bans not persisted/propagated
Bans are in-memory only (`ban_manager.rs:190`); an equivocating elder is banned only on witnessing
nodes, only until restart, and is never removed from `mpc_contributions` — so it remains an eligible
voter next round.
**Fix:** persist bans, broadcast equivocation proofs, and gate voter eligibility on a clean record.

### GHOST-12 (MEDIUM) — L2 batch size 1
`MIN_BATCH_SIZE = 1` with comment "MAINNET: raise back to 10" (`ghost-reconciliation/src/lib.rs:80`).
A single-entry settlement batch destroys batch anonymity.
**Fix:** raise to ≥10 (or the documented target) for mainnet.

### GHOST-13 (LOW) — Documentation drift
`docs/SPECIFICATION.md` / `docs/protocols/*` referenced by README/CLAUDE.md don't exist (real docs:
`ghost-web/docs/`, `ghost-core/doc/`); TX-fee dust → treasury (not "top node"); ghost-locks are
P2WSH (docs say "P2TR"); the L2 commitment is MiMC (docs say "Pedersen"); "+2" is Reaper=BitcoinPure
(two names); README "14 audits / 12 BIPs / 8 specs" not substantiated in-tree.
**Fix:** correct the docs/CLAUDE.md to match the code.

---

## Strategic note

The exploitable surface is uniformly the **mechanism-design / incentive layer** (GHOST-01,02,03,
04,09,10,11) plus the **L2 trust model** (GHOST-05,06,08,12) — not the cryptography or the node
fork, which are sound. These gaps don't bite while the four nodes are one trusted operator; they
bite precisely when independent, untrusted operators arrive — which is the project's stated goal.
**Close GHOST-01 and GHOST-02 first:** they are the load-bearing wall for "nodes taking back
control," because together they decide whether honest nodes can be made to ratify a dishonest
payout or a farmed reward pool.

---

## Remediation status (2026-06-19)

12 of 13 findings are resolved or have a landed fix-PR; only **GHOST-11** (ban
persistence + propagation) remains.

- **Merged to `main`:** GHOST-08/10/12 (#33, #34), GHOST-01/06/05/04 (#35–#38), GHOST-09 signed
  shares (#40), multi-node harness (#42), GHOST-03 ledger convergence (#43), audit doc + register
  (#32, #39, #41, #44).
- **Fix PR open:** GHOST-02 payout-split recompute (#45, Option A).
- **Resolved without code change:** GHOST-07, GHOST-13.

The **multi-node harness now exists** (PR #42): N in-process nodes with real `RoundManager` +
`ShareProofHandler`, a deterministic in-memory router, and fault injection (forgery, partition).
Each remaining fix is now built test-first against it (failing scenario → fix → green).

### The payout-integrity cluster — GHOST-02, GHOST-11 (GHOST-09 ✅, GHOST-03 ✅, harness ✅)

These four are **not independent patches**; they are one design that must ship and be validated
together, because each is a change to the **gossiped consensus wire format** and they interlock:

1. **GHOST-09 (signed shares)** — ✅ **DONE (PR #40)**, the foundation. `ShareProof` now carries an
   ed25519 signature by `received_by`; the gossip-receive path drops missing/invalid signatures
   before crediting (unsigned ⇒ rejected). Forged/relay-mutated `received_by` is unit-test-proven to
   fail. *Wire-format change — coordinated deploy; the rest of the cluster builds on this.*
2. **GHOST-03 (ledger convergence)** builds on signed shares: nodes exchange signed share-set
   digests and backfill gaps so their share ledgers actually agree before a payout vote. *Wire-format.*
3. **GHOST-02 (proposal recompute)** depends on GHOST-03: validators recompute the payout split
   from their *own* converged ledger and reject a proposal that doesn't match, plus check the
   proposer is the real block-finder. Without GHOST-03 this would reject honest proposals.
4. **GHOST-11 (ban persistence + propagation).** NOTE: local enforcement already exists — a banned
   equivocator's votes are rejected at receipt, before submission, and re-checked before a decision,
   and its votes are invalidated in active sessions. The remaining gap is (a) **persistence** so a
   restart doesn't forget the ban (`BanEntry` uses monotonic `Instant`; needs a wall-clock refactor +
   DB) and (b) **propagation** so a node banned on one mesh member is banned on all. *(b) is wire-format.*
5. **GHOST-04 (#38)** already lets the quorum *form* at 4 elders — but quorum without 2–3 means
   votes still ratify on internal checks only, so #38 must NOT deploy ahead of this cluster.

**Status:** the foundation (GHOST-09) is landed. The rest — GHOST-03 convergence, GHOST-02 recompute,
GHOST-11 persistence+propagation — are cross-node behaviours that **cannot be meaningfully validated
in a single process.** Per this repo's "no half-fixes / validate before done" rule, blind-deploying
them to the live mainnet mesh would be reckless. The required next step is a **regtest multi-node
harness** (≥4 ghost-pool nodes, real mesh, fault injection) that demonstrates: signed shares converge,
an honest proposal is ratified, a forged `received_by` / dishonest split / divergent ledger is
rejected, and a banned equivocator loses its vote across restarts and on peer nodes. The cluster is
then implemented against that harness and canaried (VM4 → VM3 → VM2 → VM1) like every consensus deploy.
