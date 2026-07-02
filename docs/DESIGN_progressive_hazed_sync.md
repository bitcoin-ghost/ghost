# Design: GHAST Block Download (GBD)

> **GHAST** = **Gh**ost + f**ast**, and a mirror of Bitcoin's IBD (Initial Block
> Download). A faster, less-trusting block download built on Ghost Haze: sync the
> hazed economic graph fast, then progressively complete validation.
>
> **Status:** Draft / theoretical. No implementation, no consensus change — this
> records the idea so it can be argued about, plus a prototype to test the core
> speed hypothesis before committing to it.

## 0. Recommended architecture (what to build)

Pressure-tested against the prototype (§9) and the multi-peer model (§10), GHAST
distils to **four build decisions plus one optional accelerator**:

1. **Hazed economic-graph sync.** Fetch the witness-stripped economic graph
   (~29% of block bytes; 3.49× less data — §9) rather than full blocks. The
   substrate.
2. **Multi-peer parallel range fetch, integrity by PoW + merkle.** Pull disjoint
   height ranges from N peers concurrently; verify each range against its
   header's proof-of-work and merkle root — integrity is *cryptographic, never
   peer-vote* (§10). **Auto-size N to fill but not exceed the local downlink**
   (~5 peers on 100 Mbit, ~40 on 1 Gbit — §10). Drop any peer whose range fails
   its merkle check and re-request elsewhere.
3. **Deferred signature verification (Wisp → Phantom → Apparition).** Reach a
   usable, double-spend-safe UTXO set (**Phantom**/L1) *without* verifying
   signatures — ~34× faster to usable (§9). Verify signatures in a background
   pass to reach full validation (**Apparition**/L2). Expose the safety level as
   honest node state; a mining pool fully validates the recent window regardless.
4. **Pipeline download and processing.** Verify + apply each range as it arrives.
   Download dominates (~37 min on 1 Gbit); CPU is seconds — so this hides CPU
   entirely: total time ≈ download time.

Optional accelerator (best UX):

5. **assumeUTXO hybrid.** Start from a recent UTXO commitment to be usable in
   *seconds* (temporarily trusted, like today's `--sync fast`), then run GHAST in
   the background to *earn back* trustlessness and history. Instant-usable now,
   trustless soon.

Explicitly **not** building (measured dead ends): columnar-CPU batching (~1.04×
at real block sizes — §9) and trust-by-N-peer-agreement (Sybil/eclipse-game-able,
redundant to PoW + merkle — §10).

**Bottom line:** trustless, snapshot-free, *usable in well under an hour on a fat
pipe* — instant with the assumeUTXO hybrid. Bounded by the operator's downlink,
not by CPU or peer count.

## 1. Motivation

A new node has three bad options today:

1. **Full IBD** — download every full block from genesis and validate
   everything (structure, coin set, *and* every signature). Correct and
   trustless, but slow: signature verification is the CPU bottleneck and the
   witness data is the bandwidth bottleneck.
2. **`assumeutxo`** (what the fleet uses now, `--sync fast`) — load a trusted
   UTXO snapshot at a fixed height `H`, serve the tip almost immediately, and
   background-validate genesis→`H`. Fast to *usable*, but it **trusts a
   hardcoded snapshot** and **discards all history before `H`**.
3. **`assumevalid`** — skip signature verification for blocks below a hardcoded
   recent block, trusting that the chain's proof-of-work means the network
   already validated them. Speeds up the CPU side, but still downloads full
   blocks.

We want the best of these: **fast to usable, no hardcoded snapshot, full
history retained, and an honest, explicit trust level at every moment.**

Ghost Haze already does something that turns out to be the enabling substrate:
it strips non-economic data (witness padding, `scriptSig` stuffing, `OP_RETURN`
payloads) from blocks before writing them, **retaining the full economic graph**
(the inputs, outputs, amounts and UTXO transitions).

## 2. Prior art (what is already solved)

Being honest about this so we build on it rather than reinvent it:

- **Headers-first sync** (Bitcoin Core): download and validate *all* block
  headers genesis→tip first (cheap — this is the PoW skeleton), then fetch
  blocks. This is already "pass 1" of a multi-pass design.
- **`assumevalid`**: defer/skip the signature pass, trusting PoW. This is
  exactly the "reach the tip fast, complete validation later" idea.
- **Parallel script validation** (Bitcoin Core): signature/script checks are
  already spread across cores *within* connect-block.
- **Ghost Haze**: physically separates the economic graph from
  witness/spam data at storage time.

The novelty proposed here is **not** any of these individually — it is
**composing them over a columnar Haze store, and exposing validation progress as
a first-class, honestly-labelled node state.**

## 3. Idea A — Hazed IBD (bandwidth + CPU shortcut)

Sequence for a fresh Ghost node:

1. **Header/PoW pass.** Sync and verify all headers against real Bitcoin (PoW,
   difficulty, chain work). Cheap, and it is the Sybil defence — you cannot be
   fed a low-work fake chain. Hazed blocks retain headers, so this works from
   hazed data.
2. **Hazed economic pass.** Pull *hazed* blocks (economic graph only) from the
   **Ghost mesh** and replay them genesis→tip to build the UTXO set. No
   signature verification yet. This is cheap per operation (hash lookups + set
   updates) and low bandwidth (the spam/witness bulk is stripped).
3. **Usable.** The node now has a correct UTXO set and can answer "is this coin
   spendable / already spent" — with an explicit trust caveat (see §5).
4. **Background full pass.** Re-download full blocks from Bitcoin peers, restore
   the stripped data, and verify signatures genesis→tip. Takes as long as it
   takes; no user waits on it.

**Key constraint:** Bitcoin peers serve *full* blocks; Haze is a local strip. So
hazed blocks come **only from Ghost mesh peers**. This is therefore a fast
*mesh bootstrap*, not a general Bitcoin-network sync. The backfill (step 4) is
what re-anchors the node to the wider network trustlessly.

Because the hazed economic pass is bandwidth-bound (confirmed by the prototype,
§9.3), it parallelises across mesh peers by height range — see **§10 Multi-peer
parallel fetch** for the design and measured sweep.

## 4. Idea B — Columnar, multi-pass validation

Instead of validating each block fully before moving on (row-wise), decompose
validation into **layered passes over one data type at a time** (column-wise),
genesis→tip, repeatedly. The important insight is that the passes have
**different parallelism properties**:

| Pass | Validates | Parallelism |
|------|-----------|-------------|
| Headers / PoW | most-work chain skeleton | Sequential (chain-linked), but tiny + cheap |
| Tx structure / merkle | blocks commit to their tx set | Parallel per block |
| **UTXO / economic graph** | no double-spends, correct coin set | **Inherently sequential** — stateful genesis→tip dependency |
| **Signatures / scripts** | authorisation (spender owned the coin) | **Embarrassingly parallel** — batchable, SIMD, multi-core, GPU |

Consequences:

- The **signature pass** is the expensive one *and* the one that parallelises
  best. Running it as a single homogeneous sweep lets us batch-verify
  (`libsecp256k1` batch verification), vectorise, and spread across all cores /
  hardware. This is where "one type of data, processed linearly, is faster" is
  genuinely true.
- The **UTXO pass is inherently sequential** — block `N`'s inputs cannot be
  checked until the coin set from blocks `1..N-1` exists. It cannot be made
  columnar-parallel. Good news: it is the *cheap* pass, so linear is fine.

**Storage caveat:** naive multi-pass re-reads full blocks once per pass = N× I/O.
To make it pay, the chain must be **stored columnar** — economic graph in one
store, witnesses/signatures in another — so each pass streams only its column.
**Haze already makes exactly this cut**, which is why it is the enabling
substrate rather than an unrelated feature.

## 5. Security model (be precise here)

What you can and cannot trust at each stage:

- **PoW** — verifiable from hazed headers → cannot be fed a fake low-work chain.
  *Trustless.*
- **Double-spend** (same UTXO spent twice) — detectable from the economic graph
  alone by tracking the UTXO set. *Trustless.* (This is the correct core insight.)
- **Authorisation** (did the spender actually own the coin / is the signature
  valid) — **not** verifiable without the witness/`scriptSig` signatures. Until
  the signature pass completes you are *trusting* that the most-work chain
  contained only authorised spends — identical to `assumevalid`'s trust.

Therefore the node has genuine, distinct **safety levels**, which should be
**first-class, honestly-labelled state**:

| Level | Reached after | Guarantee |
|-------|---------------|-----------|
| 0 | headers | knows the most-work chain (Sybil-safe skeleton) |
| 1 | UTXO pass | correct coin set, double-spend-safe (authorisation *trusted*) |
| 2 | signature pass | fully validated / trustless |

A node can be usable at each level with an explicit label, and mesh/light peers
could request "get me to level 1" vs "level 2". A **mining pool must not mine on
level < 2 near the tip** — `assumevalid`-style trust is only acceptable for
*deep* blocks with overwhelming PoW behind them; the recent window is always
fully validated.

### 5.1 The one question that decides everything

**Does Ghost Haze strip the signatures, or only spam/padding?**

- If Haze strips witness *padding* / `scriptSig` *stuffing* (inscription/ordinal
  junk) but **keeps the real signatures**, hazed blocks are *still fully
  validatable* — we save space and can verify authorisation. Then hazed sync is
  not even a trust downgrade, just a smaller/faster full validation.
- If Haze strips the **signatures themselves**, then level 1 is a real trust
  step (as in §5) and level 2 requires the backfill.

This must be pinned down in the Haze implementation before the security model is
final. It changes whether hazed sync is "faster full validation" or "staged
trust with deferred verification".

## 6. Relationship to the current fleet

- **Keep `assumeutxo` (`--sync fast`) as the "usable in minutes" path.** It is
  simpler and already deployed.
- **Progressive Hazed Sync is the trustless, full-history alternative** —
  attractive because it needs no hardcoded snapshot and keeps history, at the
  cost of more complexity and more bandwidth than loading one snapshot.
- These are not mutually exclusive: a node could `assumeutxo` to get usable,
  then run the hazed/columnar passes in the background to *earn back* the history
  and the trustless label.

## 7. Open questions / to measure before building

1. **What does Haze actually strip?** (§5.1 — the load-bearing question.)
2. **Column sizes on today's chain.** How large is the witness/signature column
   vs the economic column, post-inscription era? If witnesses are ~60–70% of
   block weight, separating + deferring + batch-verifying them is a large, real
   win. If not, `assumevalid` alone already captures most of the CPU savings.
3. **Reconstruction.** `OP_RETURN` payloads and any stripped bytes must be
   re-fetchable from Bitcoin peers for the backfill; confirm nothing consensus-
   relevant is unrecoverable.
4. **Mesh serving.** Protocol for a Ghost node to serve hazed columns to a
   bootstrapping peer, and how the bootstrapper cross-checks them against real
   Bitcoin (headers/PoW + eventual full backfill).
5. **Pool safety window.** Exactly how deep before `assumevalid`-style trust is
   acceptable; the recent window stays fully validated.

## 8. Naming

- **Process:** **GHAST Block Download** (GBD) — Ghost + fast; the Ghost analogue
  of Bitcoin's IBD.
- **Safety levels** (provisional — a ghost gaining corporeality): **Wisp** (L0,
  headers/PoW) → **Phantom** (L1, economic graph — double-spend-safe,
  authorisation trusted) → **Apparition** (L2, signatures verified — fully real).
- Individual passes: descriptive for now (header / economic / signature).

## 9. Prototype results

A self-contained benchmark prototype lives at `prototypes/ghast-bench/`
(standalone crate, empty `[workspace]` table, real secp256k1 ECDSA + Schnorr —
no mocked crypto). It synthesizes a chain segment in memory and times three
validation strategies over the **identical** workload: **(A)** row-wise
single-threaded (naive), **(B)** row-wise parallel-per-block (the strong
baseline — what Bitcoin Core does), and **(C)** GHAST columnar (pass 1 headers,
pass 2 serial UTXO, pass 3 all signatures collected up front and verified in one
batched parallel sweep). B and C are made fair: both flat-collect inputs and
`par_iter`, so the only difference is batch granularity (per-block vs
whole-chain). See `prototypes/ghast-bench/README.md` for how to run and full
caveats.

### 9.1 Headline run (default workload)

Machine: 16-core WSL2, `rayon` 16 threads. Workload: 300 blocks × 30 tx ×
40 inputs = **360,000 real signatures**. Median of 3 runs after warm-up.

| Strategy | Median | sigs/s | Speedup vs **B** |
|----------|-------:|-------:|-----------------:|
| A row-wise single-threaded | 11.839 s | 30,407 | 0.21× |
| **B row-wise parallel (baseline)** | 2.437 s | 147,740 | 1.00× |
| C GHAST columnar batch (ECDSA) | 1.837 s | 195,993 | **1.33×** |
| C-schnorr columnar (Schnorr, per-sig parallel) | 1.861 s | 193,448 | 1.31× |

- **Hazed bandwidth ratio: 3.49×.** Full blocks = 53.0 MB; economic-graph-only =
  15.2 MB; the witness/signature column is **71.3 %** of full-block bytes.
  Economic-only sync moves **~29 %** of the bytes.
- **Time-to-usable (Phantom / L1): 0.072 s** for passes 1+2 (headers + UTXO, a
  double-spend-safe coin set) vs **2.437 s** for full validation (B) —
  **~34× faster to usable** by deferring the signature pass. (In a real sync the
  gap is far larger, because deferral also defers downloading the witness
  column — the 71 % of bytes above.)

### 9.2 The honest question: does columnar batching (C) actually beat B?

Only at small block sizes. C holds a near-constant ~195k sigs/s regardless of
how the chain is chopped into blocks (one work-stealing pool over everything). B
degrades when blocks are small, because each block is a separate `rayon` join
barrier and a small per-block batch can't fill 16 cores. Sweeping the same
360k-signature workload across block sizes:

| Block size (inputs/block) | B (baseline) | C columnar | **C vs B** |
|---------------------------|-------------:|-----------:|-----------:|
| ~120 (many tiny blocks) | 4.979 s | 1.851 s | **2.69×** |
| ~1,200 (default) | 2.437 s | 1.837 s | **1.33×** |
| ~6,000 (≈ real full block) | 1.913 s | 1.835 s | **1.04×** |

**Verdict: at realistic Bitcoin full-block sizes (~2–6k inputs), columnar
batching gives essentially nothing over per-block parallelism (1.04×) — B
already saturates the cores.** The columnar batch only wins when blocks are
small enough that per-block parallel passes leave cores idle. So Idea B (§4) is
**not** where the real speed comes from on a modern chain.

### 9.3 What the numbers do and do not support

- **Supported — deferral (time-to-usable).** Reaching a double-spend-safe UTXO
  set without the signature pass is ~34× faster here, and far more in a real
  sync where it also avoids downloading the witness column. This is the strongest
  measured GHAST win and directly backs the Wisp→Phantom→Apparition staging and
  the L1-usable state (§5).
- **Supported — bandwidth (hazed ratio).** The witness/signature column is
  ~71 % of block bytes on this (inscription-era-shaped) workload, giving a
  3.49× economic-only bandwidth reduction. This backs Idea A (§3) and answers
  open question §7.2: separating + deferring the witness column is a large, real
  win, independent of any CPU batching. Bandwidth being the true bottleneck is
  what motivates **§10 (multi-peer parallel fetch)** — it parallelises across
  peers where the CPU passes cannot.
- **Not supported — columnar batching as a CPU win (Idea B, §4).** At real
  full-block sizes it is ~parity with what Bitcoin Core already does. The design
  should present Idea B honestly as "no worse, and it enables the streaming
  columnar store that makes deferral + bandwidth cheap", **not** as a
  signature-throughput win. `assumevalid`-style deferral already captures the CPU
  savings; columnar batching does not add to them at scale.

### 9.4 Caveats

Synthetic data; single machine; **verification-only** (no real disk/network
I/O — real IBD is often I/O/bandwidth-bound, which would only raise the value of
the bandwidth win); UTXO pass modelled serial over an in-memory `HashMap` (a
real disk-backed coin DB is slower); Schnorr measured as per-signature parallel
verify, not libsecp256k1's experimental aggregate `schnorrsig_verify_batch`
(not exposed by rust-secp256k1 0.30 — a true batch check would make Schnorr
faster than shown).

## 10. Multi-peer parallel fetch

The prototype (§9) settles which layer is actually the bottleneck: **not CPU**.
At real full-block sizes, signature verification already saturates all cores
(§9.2) and the UTXO/economic pass is trivially cheap (§9.1: ~223 MB/s of
economic graph, ~13 min of CPU for the whole 174 GB hazed graph). What is left,
and what dominates time-to-usable in the real world, is **downloading the hazed
economic graph** — a bandwidth problem. See §9.3: the two supported wins are
deferral and bandwidth, and this section attacks the bandwidth one.

**Bandwidth parallelises across peers where CPU does not help.** A fresh node
fetches **different height ranges from N peers concurrently** and stitches them
together. This is the natural refinement of Idea A (§3, hazed economic pass) and
Idea B (§4, columnar passes): a columnar store is exactly what lets you request
"the economic column for heights `[a, b)`" from one peer while another serves
`[b, c)`.

### 10.1 Integrity is cryptographic, not by peer vote

Each fetched range is verified against **its own header-PoW-committed merkle
root**. The headers (Wisp / L0, §5) are synced and PoW-checked first, so every
block's merkle root is already known and pinned by the most-work chain *before*
any economic data is pulled. The hazed economic graph for a range either hashes
up to the committed merkle root for those heights or it does not. Integrity is
therefore checked **cryptographically, per range, against work the attacker
cannot forge** — the §5 guarantees (PoW trustless, double-spend trustless)
applied per-range.

**We explicitly reject "trust by N-peer agreement".** Deciding a range is
correct because several peers returned the same bytes is:

- **Sybil/eclipse-game-able** — an attacker who supplies your peers (or your
  view of them) manufactures the "agreement" for free; and
- **strictly weaker and redundant** — PoW + merkle already settles integrity
  trustlessly and for free, so a vote adds nothing on top of it.

Peer agreement's only genuine value is **speed** (parallel download) and
**resilience** (a peer whose range fails its merkle check, or that is simply
slow, is dropped and that range re-requested elsewhere — no single peer can
stall or corrupt the sync). It cannot settle the one thing that *is* genuinely
deferred: **signature authorisation** (§5, Apparition / L2). No number of
agreeing peers verifies a signature; only the background signature pass does.
Multi-peer fetch therefore accelerates reaching **Phantom / L1** and changes
nothing about the trust model of **L2**.

### 10.2 The hard ceiling: your own downlink

Fetching from more peers is linear **only until your own downlink saturates**.
Effective bandwidth is `min(N × per_peer_bandwidth, downlink)`; once
`N × per_peer ≥ downlink`, extra peers add **zero** speed (they still add
resilience). "How fast can we get" is bounded by the user's pipe, not by peer
count.

### 10.3 Prototype results (measured CPU + modelled bandwidth)

The `ghast-bench` prototype adds an analytical multi-peer download model. The
**network transfer is modelled** (bandwidth arithmetic, not a real socket); the
**CPU rate is measured** (the §9 header+UTXO throughput, ~223 MB/s of economic
graph, applied to the modelled real size). Assumptions, all CLI-overridable and
echoed at runtime:

- Chain full-block data **600 GB**; economic-only ratio **0.29** (from the §9
  hazed measurement) → **174 GB** hazed economic graph to download.
- Per-peer serve bandwidth **3 MB/s** (= 24 Mbit/s) per connection *(assumption)*.
- Downlink tiers **100 Mbit (12.5 MB/s)** and **1 Gbit (125 MB/s)** *(assumption)*.
- Modelled CPU to build the UTXO set for 174 GB ≈ **779 s (~13 min)** at the
  measured rate. `total to-usable` below is the conservative serial sum
  `download + CPU`; a pipelined implementation overlaps them toward
  `max(download, CPU)`, and since download dominates, `total ≈ download`.

**Downlink tier: 100 Mbit (12.5 MB/s)**

| Peers | Eff BW (MB/s) | Download | Speedup vs N=1 | Saturated? | Total to-usable |
|------:|--------------:|---------:|---------------:|:----------:|----------------:|
| 1 | 3.0 | 58,000 s | 1.00× | no | 16.33 h |
| 10 | 12.5 | 13,920 s | 4.17× | **yes** | 4.08 h |
| 20 | 12.5 | 13,920 s | 4.17× | yes | 4.08 h |
| 30 | 12.5 | 13,920 s | 4.17× | yes | 4.08 h |
| 40 | 12.5 | 13,920 s | 4.17× | yes | 4.08 h |

Saturates at **5 peers**. Peers 10→40 are identical — the 100 Mbit pipe is the
wall; more peers buy nothing but resilience.

**Downlink tier: 1 Gbit (125 MB/s)**

| Peers | Eff BW (MB/s) | Download | Speedup vs N=1 | Saturated? | Total to-usable |
|------:|--------------:|---------:|---------------:|:----------:|----------------:|
| 1 | 3.0 | 58,000 s | 1.00× | no | 16.33 h |
| 10 | 30.0 | 5,800 s | 10.00× | no | 1.83 h |
| 20 | 60.0 | 2,900 s | 20.00× | no | 1.02 h |
| 30 | 90.0 | 1,933 s | 30.00× | no | 0.75 h |
| 40 | 120.0 | 1,450 s | 40.00× | no | 0.62 h |

Linear all the way through N=40 (40×), saturating only at **~42 peers**. On a fat
pipe, peer count is the constraint and each added peer pays off — until the pipe.

### 10.4 Verdict

- **Multi-peer fetch is a large, real win — for bandwidth, which §9 showed is the
  actual bottleneck.** Combined with the 3.49× hazed reduction (downloading
  174 GB instead of 600 GB), it is what makes "usable in well under an hour on a
  1 Gbit line" plausible without a trusted snapshot.
- **It is bounded by the user's downlink.** On 100 Mbit it caps at ~5 peers /
  4.17×; on 1 Gbit it scales linearly to ~42 peers / 40×. Advertising "N peers →
  N× faster" is dishonest past saturation.
- **It changes speed and resilience, never trust.** Integrity stays cryptographic
  (PoW + per-range merkle); authorisation stays deferred to the L2 signature
  pass. Peer agreement is explicitly *not* part of the security argument.

Caveats: network transfer is modelled arithmetic, not real sockets (no TCP
slow-start, no per-peer variance, no stitching/re-request overhead, assumes
perfectly divisible ranges and steady per-peer rates); real peers vary and some
lie (handled by the merkle re-request, but at a latency cost not modelled here);
the CPU rate is measured on a synthetic in-memory segment and extrapolated (a
real disk-backed coin DB at 174 GB is slower — but CPU is dominated by download
regardless).

## 11. Further speed ideas (unmeasured — candidates)

We are now **downlink-bound** (§10). Further speed can only come from three
levers: move *less* data, need less *before* usable, or bypass the internet path.
Ranked by expected payoff:

1. **assumeUTXO hybrid — the "usable sooner" axis.** (Promoted to §0 item 5.)
   Orthogonal to bandwidth: trust a recent UTXO commitment to be usable in
   seconds, then backfill the hazed graph + signatures to earn trustlessness.
   Biggest UX win and it stacks with everything below.
2. **Shrink the economic graph (move less data).**
   - *Churn elision / net-UTXO:* outputs created *and* spent within the synced
     span do not survive into the final coin set. Transmit surviving UTXOs plus
     only the spend records needed for the double-spend check, eliding
     intermediate detail where it is provably safe. Could push well below 174 GB.
   - *Domain-specific compression:* script-template dictionaries, varint amounts,
     address/script dedup — beats generic gzip on structured economic data. Free,
     if marginal.
   - *Utreexo (research):* replace the full UTXO set with a hash accumulator +
     per-input inclusion proofs — slashes the *state* a node must hold, at the
     cost of per-tx proof bandwidth. Worth evaluating against the churn-elision
     approach.
3. **LAN / sneakernet bootstrap — the only way past the §10 ceiling.** When a
   fast local source exists (another Ghost node on the LAN, an NVMe drive), fetch
   the hazed graph over Gbit LAN / local disk and bypass the internet downlink
   entirely. Turns ~37 min into minutes.
4. **Grow the mesh.** Ghost peers store hazed data *ready to serve* (no
   re-hazing); Bitcoin peers require fetching full blocks + hazing locally. More
   mesh peers = more hazed-serving sources to fill fat downlinks.
5. **Shard the UTXO pass.** Partition the coin set (e.g. by txid prefix) and apply
   ranges in parallel with a merge, partially parallelising the otherwise-serial
   pass. Low priority — CPU is not the bottleneck (§9), but relevant once the coin
   DB is disk-backed at 174 GB.

None of these is measured yet; each is a candidate for the next prototype
iteration if/when GHAST is picked up. The obvious next experiment is **churn
elision** — measured below in §12.

## 12. Churn elision — measured

Measured on a live, fully-synced node (`ghostd`, height 956,410, 2026-07-03):

| Metric | Value |
|---|---|
| Total transactions ever (`getchaintxstats`) | 1,389,346,171 |
| Surviving UTXOs (`gettxoutsetinfo none`) | 166,121,169 (~166 M) |
| Surviving set on disk | **11.4 GB** |
| Est. outputs ever created (~2.4 outs/tx) | ~3.3 B |

**Churn ≈ 95%** (94.6–95.4% across 2.2–2.6 outputs/tx) — roughly 19 of every 20
outputs ever created have already been spent. Equivalently, the surviving UTXO
set (11.4 GB) is **~6.6% of the ~174 GB economic graph — about 15× smaller.**

**The catch, and it is the load-bearing one for a trustless design:** churn
elision shrinks the *state you must store*, **not the trustless *download*.** To
prove no double-spend without trusting anyone, every input must be matched to a
real, previously-unspent output — so every spend (hence every churned output's
create *and* spend) must be *processed*. You cannot skip *downloading* a churned
output and still prove trustlessly it was created once and spent once. The only
routes below the 174 GB floor are:

- **trust** a summary of the surviving set — that is exactly `assumeutxo`, which
  we are avoiding; or
- a **commitment** to the UTXO set a fresh node can verify — and **Bitcoin
  consensus commits to no such thing** (assumeUTXO's snapshot hash ships in the
  software, not in the chain).

So on Bitcoin as-is, **the 174 GB economic-graph download is the irreducible
trustless minimum** — and multi-peer fetch (§10) already brings that to ~37 min
on 1 Gbit. Churn elision is a *storage* win (~15×), not a download win.

### 12.1 Where this points: a mesh-attested rolling UTXO commitment

The 95% churn result is exactly what makes a genuinely-better-than-assumeUTXO
path attractive. The surviving set is only ~11 GB, and Ghost already runs a BFT
mesh. So instead of assumeUTXO's *single, static, software-shipped* snapshot
hash, GHAST could use a **rolling UTXO commitment attested by the Ghost mesh's
BFT consensus** at a recent height:

- A fresh node downloads the ~11 GB surviving set + the mesh attestation → usable
  in minutes, trusting the **mesh** (multi-party, live, rotating, *challengeable*)
  rather than one hardcoded value.
- It then runs the trustless GHAST sync (the 174 GB economic graph) **in the
  background to earn full trustlessness** and to *audit* the attestation it
  started from. If the background sync ever disagrees with the attested set,
  that is a detectable, attributable mesh fault.

This is strictly stronger than assumeUTXO — not static, not blind, self-auditing
— while still giving the ~11 GB fast start. It is a real protocol, not a shipped
snapshot, and it is only viable *because* churn is ~95%, making the surviving set
small enough to ship quickly. **This is the recommended "better than assumeUTXO"
direction.**
