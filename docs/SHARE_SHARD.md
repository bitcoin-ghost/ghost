# Share Shard — pool ledger and coinbase design

Status: **design, not built.** Written 2026-08-12.

Supersedes `SHARE_BATCH_CHAIN.md`, `SBC_TWO_PHASE.md` and `SBC_MEMBERSHIP_CHANGE.md` as the
payout/ledger design. Those documents remain for their diagnosis, which is still correct; their
*solution* — a hash-chained, round-robin, BFT-adopted batch chain — is abandoned. See §5.

---

## 1. The vision this serves

Ghost is decentralised mining. Nodes mine together, **each with its own policy and its own block
templates**. Power sits with the node operator. The coinbase pays every contributor directly and
atomically, in the block itself. No middleman, no custody, no permission.

Anyone can run a node. Nodes join and leave whenever they like; a node reuses its own stable ID
when it returns. The target is mainstream adoption — up to 20% of network hashrate — so every
mechanism here must get *cheaper* per node as the network grows, never more expensive.

## 2. The diagnosis

**The current system stores evidence as if it were state.**

A share is *evidence* that work happened. The thing you actually need to keep is a *balance*. Today
the pool keeps every share forever and derives balances by scanning them.

Measured on the live fleet, 2026-08-12:

| | measured |
|---|---|
| unpaid share rows | **1,712,193** (oldest 2026-07-15) |
| proof blob per share | ~1,158 bytes avg, 1,201 max |
| distinct payout targets, post-gate era | **4** |
| `get_top_unpaid_addresses` | 2.76M rows, 1.6 s, per propose **and** per vote, ~40% duty |
| GHOST-03 sweep traffic | 15–20 GB/day/node |
| blocks ever won | **0** |

Four numbers to hold together: the payable state of this pool is **4 rows**, it is represented by
**1.7M share rows**, the query over them runs at 40% duty, and no payout event has ever occurred to
prune them. That ratio *is* the defect. Everything expensive falls out of it.

The convergence machinery inherits the same mistake. The sweep tried to reconcile *shares* —
millions of rows — which is why it cost 15–20 GB/day and still needed a **tolerance** to absorb the
difference it could never close.

## 3. What we already have and keep

- Public mining endpoints, miners connecting over SV1/SV2. **Built.**
- Per-node policy, mempool and block template construction. **Built.**
- Cross-node share gossip. **Built** — verified 2026-08-12: vm5's table holds vm2's and vm6's shares.
- Share validity primitives: PoW preimage check, GHOST-09 signature, receiver binding,
  payout-address binding (armed 961,100), difficulty-tier commitment (armed 962,100).
- `SkeletonData` — coinbase prefix/suffix + merkle path, **carried once per job, not per share**
  (`pool-sv2/src/lib/share_webhook.rs`), landing in `ghost-pool/src/skeleton_store.rs`.
- `verify_share_node_binding` (`crates/ghost-common/src/share_binding.rs:152`), wired at
  `bins/ghost-pool/src/main.rs:7845` and `binding_recheck.rs:127`.
- `micro_work`, `canonical_sort`, `fold_shares`, `compute_state_root`
  (`crates/ghost-common/src/share_batch.rs`) — the fold arithmetic, **measured correct** (§11).

The gap is the coinbase and the ledger behind it. That is what this document specifies.

## 4. The design

```
╔══════════════════════════════════════════════════════════════╗
║  1. MINERS CONNECT TO WHOEVER THEY LIKE                      ║
╚══════════════════════════════════════════════════════════════╝

  Bitaxe  S19   farm            Bitaxe  S19          farm
    │      │      │               │      │             │
    └──────┼──────┘               └──┬───┘             │
           ▼                         ▼                 ▼
     ┌──────────┐              ┌──────────┐      ┌──────────┐
     │  NODE A  │              │  NODE B  │      │  NODE C  │
     │ own      │              │ own      │      │ own      │
     │ policy   │              │ policy   │      │ policy   │
     │ template │              │ template │      │ template │
     └──────────┘              └──────────┘      └──────────┘
           └───────────────────────┴─────────────────┘
                        gossip (tiny, see §4.2)
      anyone can run one · join or leave whenever · stable ID


╔══════════════════════════════════════════════════════════════╗
║  2. TWO DIFFICULTY TIERS                                     ║
╚══════════════════════════════════════════════════════════════╝

  MINER TIER (easy, constant)      NETWORK TIER (hard, rare)
  ───────────────────────────      ─────────────────────────
  ██████████████████████████  ···►  █              █
  never leaves the node             only these cross the mesh
  smooth credit for the miner       1/ratio the traffic


╔══════════════════════════════════════════════════════════════╗
║  3. WHAT EACH NODE STORES                                    ║
╚══════════════════════════════════════════════════════════════╝

  ┌─── MY SHARD ─────────┐   ┌─── NETWORK SHARD ─────────────┐
  │ my miners' shares    │   │  address       unpaid work    │
  │ 80-byte headers      │   │  ───────────   ───────────    │
  │ merkle branch        │   │  bc1q…aa          41,203      │
  │  (once per JOB)      │   │  bc1q…7f          38,110      │
  │                      │   │  …                   …        │
  │ ▸ DELETED each epoch │   │ ▸ KEPT — few hundred rows     │
  │   = EVIDENCE         │   │   = STATE                     │
  └──────────────────────┘   └───────────────────────────────┘


╔══════════════════════════════════════════════════════════════╗
║  4. BUILDING THE COINBASE — no voting, no agreement          ║
╚══════════════════════════════════════════════════════════════╝

     NETWORK SHARD  ──  ORDER BY work DESC  LIMIT N
                                │
                                ▼
                    ┌───────────────────────┐
                    │  COINBASE (atomic)    │
                    │   → bc1q…aa   0.41 ₿  │
                    │   → bc1q…7f   0.38 ₿  │
                    │   → …  (top N)        │
                    └───────────────────────┘

   Node A's list and Node B's list may differ slightly (lag).
   ▸ NOBODY HAS TO AGREE. Whoever wins pays from their own view.


╔══════════════════════════════════════════════════════════════╗
║  5. BLOCK WON → EVERYONE REBASES, FOR FREE                   ║
╚══════════════════════════════════════════════════════════════╝

    NODE A wins ──► broadcasts ──►  ██ BITCOIN CHAIN ██
                                            │
        every node already has the chain    │
      ┌─────────────┬─────────────┬─────────┘
      ▼             ▼             ▼
   NODE A        NODE B        NODE C
   read paid     read paid     read paid
   subtract      subtract      subtract
   drop history  drop history  drop history
```

### 4.1 Node sovereignty

Each node chooses its own transactions, its own policy, its own mempool. **The only thing common
across nodes is the payout split**, because that split *is* the pooling contract. Sovereignty over
what goes in the block; shared arithmetic over who gets paid.

A node may instead run **solo / solopool mode**, paying its own address. That is a legitimate
choice, not an attack — see §10.

### 4.2 Two difficulty tiers

- **Miner tier** — low difficulty, frequent. Local to the node. Gives the miner smooth, responsive
  credit. Never crosses the mesh.
- **Network tier** — high difficulty, rare. Only these enter the network shard and cross to peers.

At ratio R, mesh traffic, verification compute and memory all divide by R simultaneously. The count
of network-tier shares is an unbiased estimator of total work.

This is not new cryptography — it is exactly what every pool already does to its miners, applied one
layer up (node → network).

**Variance is not a problem** because payment is cumulative and long-run: Poisson noise in any one
epoch averages to zero across many blocks. A node having a quiet epoch is paid next time.

### 4.3 The two shards

**Node shard** (mine, transient). My miners' shares: 80-byte header per share plus the merkle branch
carried **once per job**. Deleted once the epoch is summarised. This is evidence, not state.

**Network shard** (everyone's, permanent-until-rebase). Unpaid work per payout address. A few hundred
rows. Never holds a share.

Consequence: building the coinbase becomes `ORDER BY work DESC LIMIT N` over a few hundred rows. The
2.76M-row scan disappears — not optimised, *deleted*.

### 4.4 Convergence — the merge rule

Store a counter per **(node, address)**, not one per address:

```
   balance[addr]  =  Σ  counter[node][addr]          ← sum ACROSS nodes
   merge rule     :  counter[n][addr] = max(mine, theirs)   ← max PER node
```

This is a grow-only counter. Merge is idempotent, commutative and associative, so:

- out-of-order delivery is irrelevant
- duplicate delivery is irrelevant
- **a missing message makes you behind, never wrong**
- there is no state requiring repair

Reconciliation is trivial because the shard is ~15 KB: ship the whole table and merge it. No diff
protocol needed.

**Balances must be signed.** If node A overpays relative to node B's view, B's residual goes negative
and the miner accrues back up from there. Clamping at zero destroys exactly the correction that makes
this work.

### 4.5 The coinbase

Top N by unpaid work from the node's own view of the network shard, paid directly in the block.
Miners below the cut keep accruing and rotate in — nothing is ever lost, they are simply paid less
often.

Nodes do **not** need to agree. Differences are gossip lag and average out across blocks.

### 4.6 Settlement and rebase

When a block pays out, every node reads the **actual paid amounts off the chain** and subtracts them.
Identical everywhere, zero messages, zero coordination — the chain is already replicated to every
node, so anything derived from it is free.

History before the rebase is **dropped**. Rebase at a confirmation depth, not at the tip (§9).

## 5. Why this converges when the last one did not

The old design drifted despite sending *more* data, which is the key evidence that volume was never
the issue.

1. **The failure was deterministic rejection, not lost delivery.** M-6 refused remote shares for a
   missing `template_id` on a path that never read the field — 2,000–2,900 rejections/hour on every
   node. Re-sending a share to a node that will reject it again changes nothing.
2. **Window boundaries came from each node's local clock** (`main.rs:3820`), so summaries could not
   be compared *even in principle*. Brute-force re-advertising was the only move left.

What is structurally different:

- **Validity is a pure function of the share** — PoW and signature, nothing else. No template
  lookup, no staleness test, no local policy. A share one node accepts, every node accepts.
- **Nodes adopt each other's counters instead of re-deriving them.** Re-deriving requires identical
  inputs *and* identical rules. Adopting requires neither.
- **Max has no failure path.** The old merge was "insert shares I am missing", and insertion could
  fail. A max cannot.

## 6. Verification without heavy compute

A node publishes a signed summary per epoch: per-address deltas plus a Merkle root over the
network-tier shares backing them. Peers apply the deltas. **They do not receive the shares.**

Peers randomly sample a handful of shares against the root. 20 random samples catch a node faking
half its work with probability ~10⁻⁶.

This is probabilistic, not proof — a deliberate trade. Full verification means shipping every share
to everyone, which is the traffic being eliminated.

**Rejection must be evidence-based and published.** If node A finds a bad share it broadcasts it, and
every peer reaches the same verdict from the same evidence. A rejection resting on private sampling
luck would let A and B disagree permanently about C's counter — reintroducing exactly the divergence
this design removes.

**No zero-knowledge proving.** It was considered and rejected: requiring a GPU to publish would gate
"anyone can run a node" behind expensive hardware, which contradicts §1. Sampling gets nearly the
same guarantee for nearly no cost.

## 7. What is deleted

```
   ✗ voting      ✗ quorum      ✗ leader / rota    ✗ vote locks
   ✗ sweep       ✗ tolerance   ✗ ledger scans     ✗ GPU proving
   ✗ middleman   ✗ bonds       ✗ permission to join
   ✗ two-phase commit          ✗ terminal quarantine as a liveness hazard
   ✗ the proof-NULL share class  ✗ the tip−6 payout loop
```

From the abandoned SBC work specifically: `batch_consensus.rs` (1,789 lines),
`batch_two_phase.rs` (635), and the global hash-chained sequence. The fold, storage, genesis method
and validity checks survive.

## 8. Settled — do not relitigate

- **Permissionless.** Anyone runs a node. No allowlist, no approval, no bonds *(bonds are vetoed
  and this design does not need them)*.
- **Node sovereignty** over policy, mempool and template. Shared arithmetic only over the payout.
- **Rebase on payout, drop history.**
- **No consensus on the ledger.** Each node pays from its own view.
- **Payout ledger stays; PPLNS-style windowing is rejected.**
- **No GPU or ZK requirement to participate.**
- **Signed balances**, not clamped at zero.

## 9. Open decisions

| decision | notes |
|---|---|
| **Tier ratio R** | Higher = cheaper mesh, noisier short-term attribution. |
| **Top-N size** | 200 outputs ≈ 7 KB of block space surrendered to fee-paying transactions. A revenue trade — pick it deliberately. |
| **Dust floor** | Outputs below ~330 sats cannot be created; below the floor a miner keeps accruing. |
| **Epoch length** | Must be keyed to **block height**, never to wall-clock. See §5.2 and §12. |
| **Sampling rate λ** | 20 gives ~10⁻⁶ against 50% forgery. Tune against measured cost. |
| **Rebase confirmation depth** | Coinbase maturity (100 blocks) is the principled floor — the output is unspendable before then, so a shallower reorg unwinds the payment anyway. Distinct from the existing tip−6 proposal anchor; do not conflate. |
| **Public vs solo mode visibility** | See §10. |

## 10. Residual risks, stated plainly

**Harvest.** A node advertises a public endpoint while quietly running solo mode, takes strangers'
hashrate and pays them nothing. This is the sharpest open risk. Two mitigations, neither complete:

1. The miner's own payout address appearing in the coinbase is sufficient evidence, and the coinbase
   is already in the job (SV1 `coinb1`/`coinb2`; SV2 `NewExtendedMiningJob` prefix/suffix). A miner
   or its proxy can check "am I in here for roughly what I am owed" with no ledger.
2. Endpoints are **public**, so anyone can connect anonymously and inspect a job. An attacker cannot
   distinguish a watchdog from a customer. Bad endpoints are cheaply and continuously auditable by
   anyone, and drop out of discovery.

⚠ **SV2 standard channels are structurally blind** — `NewMiningJob` carries only `merkle_root`, no
coinbase, so a standard-channel miner cannot inspect the payout with *any* firmware. Only
`NewExtendedMiningJob` carries `coinbase_tx_prefix`/`coinbase_tx_suffix`. Consider refusing
`OpenStandardMiningChannel` so every served job is auditable.

⚠ **A miner connecting blind to an unvetted endpoint is trusting that node**, and can lose work until
someone notices. Bounded, and it shrinks as the network grows. Say this out loud in user-facing
documentation; do not bury it.

**Per-node attribution memory** grows as N × addresses rather than addresses alone. At 100 nodes and
500 addresses that is ~50k entries — nothing. At thousands of each it needs watching. The rebase
bounds it: only the unpaid window is tracked, never all history.

**Sampling is probabilistic.** Named in §6, accepted deliberately.

## 11. Measured baseline (2026-08-12)

Grounding numbers, all measured this session, so the design can be judged against reality rather
than against its own description.

- SBC shadow chain reached seq 157 with **byte-identical state roots on all 8 nodes** at every
  sampled sequence. Agreement was never the problem.
- **The fold arithmetic is correct.** Excluding one quarantined node, drift between the shadow chain
  and the live ledger ran at **0–1 shares/hour out of ~1,270/hour**, with four of nine hours at
  exactly zero. 9,699 shares carried 9,699 distinct hashes — no double-credit. `work <> difficulty`
  was 0.
- The entire headline 38% gap was **one node's stale terminal quarantine** (5,827 shares in the
  ledger, 0 in the chain) — a liveness failure of the consensus layer, not an arithmetic failure.

This is why the fold, the canonical sort and `micro_work` carry over untouched while the consensus
layer is deleted.

## 12. Rules that must hold

These are the disciplines whose violation caused the previous design's failures. Each is cheap to
keep and expensive to recover from.

1. **Validity is a pure function of the share.** The moment any node-local state enters the validity
   test, permanent divergence returns. This is precisely how M-6 happened.
2. **Never key a window or an epoch to wall-clock time.** Chain height only. Local `now` is what made
   the sweep's summaries incomparable in principle.
3. **Verify before merging.** Max-merge over an unverified counter lets a liar's inflated number win.
   Verify first, merge second — the ordering is load-bearing.
4. **Rejections must be publishable evidence**, never private sampling luck (§6).
5. **Never add a tolerance.** A tolerance is an admission that the mechanism cannot converge. If the
   numbers disagree, find out why.
6. **Ship the whole table and compare it.** At ~15 KB there is no excuse for not knowing whether the
   network has drifted. Drift must be visible the same day, not discovered a quarter later.
