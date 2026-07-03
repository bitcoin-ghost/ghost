# Design: GHAST Block Download (GBD)

> **GHAST** = **Gh**ost + f**ast**, and a mirror of Bitcoin's IBD (Initial Block
> Download). A faster, less-trusting block download built on Ghost Haze: sync the
> hazed economic graph fast, then progressively complete validation.
>
> **Status:** Design + measured prototype for a **new project.**
>
> **GHAST is its own project. Its target: the fastest *and* safest IBD for
> Bitcoin.** It is **not** an extension of Ghost Haze. Haze is a separate, already-
> shipped feature whose target is entirely different — **storage reduction + the
> legal concerns of storage for node runners** (stripping data from blocks on
> disk). GHAST *adapts* a few Haze primitives as reusable building blocks (the
> stripped-block format, the chunk downloader, stripped-block P2P, SwiftSync), but
> **GHAST's trust model and design are its own, driven by the IBD goal.** Do not
> measure GHAST against Haze's bootstrap — Haze's hardcoded-assumeUTXO delivery
> correctly serves Haze's goal and is simply not GHAST's design.
>
> The load-bearing §5.1 question (does the stripping remove signatures?) is
> answered: **yes** — see §5.1. §16 catalogues which Haze primitives GHAST can
> reuse; everything else GHAST designs fresh for fast-and-safe IBD.

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

**ANSWERED (from the code, 2026-07-03):** Haze strips the **signatures**.
`ghost-core/src/haze/block_stripper.h` states the stripper *"Removes all hazeable
content: **witness data, scriptSig**, OP_RETURN payloads, and coinbase scriptSig.
Preserves the complete economic graph."* Signatures live in the witness (segwit)
and `scriptSig` (legacy), and both are removed wholesale — not merely padding
(the README's "padding/stuffing" wording is euphemistic). So a hazed block is
**not self-validatable**, and the **staged-trust model of §5 is correct and not
optional**: L1/Phantom trusts authorisation until the background signature pass
restores the witness/scriptSig and reaches L2/Apparition. This resolves the
load-bearing question — the security model above stands as written.

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

## 13. Can the surviving UTXO set be verified without the full sync? (No.)

§12.1 proposes shipping the ~11 GB surviving set with a mesh attestation. The
obvious question a sceptic asks: *can a fresh node verify that set is correct on
its own, cheaply, without downloading the 174 GB economic graph?* The honest
answer is **no** — and it is worth being precise about why, because it is what
forces the trust-then-audit model rather than a pure trustless shortcut.

A UTXO set is correct iff **every** entry (a) was really created by some block
(`created`) and (b) has **never** been spent since (`unspent`). Both halves must
hold. They have very different costs:

- **Proving `created` — possible, but not a shortcut.** Each surviving output can
  carry a merkle proof to the PoW-committed merkle root of the block that created
  it (the headers, Wisp/L0, are already synced and PoW-checked). That proves the
  output once existed, trustlessly. But a merkle branch is ~log₂(txs-in-block)
  hashes (~hundreds of bytes) *per UTXO*, and there are **166 M** of them — the
  proofs in aggregate approach or exceed the size of the economic graph you were
  trying to avoid downloading. It proves creation; it saves nothing.

- **Proving `unspent` — impossible without processing every spend.** This is the
  killer. To know an output was *never later spent*, you need a **non-membership
  proof against the set of all spends** — "no block anywhere spent this coin".
  **Bitcoin consensus commits to no UTXO set and no spent-set accumulator**, so
  there is nothing to prove non-membership *against*. The only way to establish
  that no block spent a given coin is to **look at every block's inputs** — i.e.
  replay the spends of the entire chain, which is exactly processing the full
  174 GB economic graph (§12). No commitment exists to shortcut it, and no
  quantity of merkle-creation-proofs substitutes for it: creation proofs say a
  coin was born, never that it is still alive.

**Conclusion.** On Bitcoin as it is, you cannot independently verify a UTXO set
without doing the full economic-graph sync. So the only way to be *usable in
minutes* is to **trust** an attested commitment; the only way to be *trustless*
is to **download and process the 174 GB**. GHAST's answer is to do both, in
order:

1. **Instantly trust** the mesh-attested commitment to the ~11 GB surviving set
   → usable in minutes (measured in §13.1), trusting the live BFT mesh (§12.1)
   rather than a hardcoded snapshot.
2. **Run the full trustless GHAST sync in the background**, which simultaneously
   (a) *earns* full trustlessness (Apparition/L2) and (b) **audits** the
   attestation: the UTXO set reconstructed genesis→tip must equal the attested
   set. Any mismatch is a detectable, attributable mesh fault (the attesting
   elders signed it). Because the reconstruction is incremental, the audit can be
   run *as the set grows* — surviving coins can be checked off against the
   attested set continuously, not only at the end.

The one thing you *cannot* do is skip the download and remain trustless. Trust is
the price of speed here, and the background sync is what pays it back.

### 13.1 Fast-start prototype results (measured crypto + modelled bandwidth)

`ghast-bench` measures the fast-start path. **Measured:** SHA-256 throughput
(used as the UTXO-commitment compute/verify rate — Bitcoin's assumeUTXO uses a
muhash, a similar order of magnitude) and the real secp256k1 BFT attestation.
**Modelled:** the ~11.4 GB download, reusing the §10 multi-peer bandwidth math.
Figures use the §12 live-node measurement (11.4 GB surviving set, 166 M UTXOs)
and the §10 assumptions (600 GB chain → 174 GB graph; 3 MB/s per peer; 100 Mbit
& 1 Gbit tiers). Measured on this machine:

- **SHA-256: 2.17 GB/s** single-thread → hashing the 11.4 GB set to compute (mesh
  side) or verify (fresh-node side) the commitment takes **~5.3 s each**. (A
  muhash / multi-core hash would be faster; this is a conservative upper bound.)
- **BFT attestation, 8 elders (real Schnorr sigs):** sign **0.15 ms**, verify
  **0.26 ms** total, wire size **544 bytes** (8 × 64-byte sig + 32-byte
  commitment). Trivial, as expected.
- Fast-start total = download(11.4 GB) + commitment verify (5.3 s) + BFT verify
  (0.26 ms). The full trustless path is the §10 174 GB download + UTXO build.

**Downlink tier: 100 Mbit (12.5 MB/s)**

| Peers | Eff BW (MB/s) | dl 11.4 GB | Fast-start total | Full 174 GB | Fast vs full |
|------:|--------------:|-----------:|-----------------:|------------:|-------------:|
| 1 | 3.0 | 3,800 s | 63.4 min | 16.33 h | 15.4× |
| 10 | 12.5 | 912 s | **15.3 min** | 4.08 h | 16.0× |
| 20 | 12.5 | 912 s | 15.3 min | 4.08 h | 16.0× |
| 40 | 12.5 | 912 s | 15.3 min | 4.08 h | 16.0× |

**Downlink tier: 1 Gbit (125 MB/s)**

| Peers | Eff BW (MB/s) | dl 11.4 GB | Fast-start total | Full 174 GB | Fast vs full |
|------:|--------------:|-----------:|-----------------:|------------:|-------------:|
| 1 | 3.0 | 3,800 s | 63.4 min | 16.33 h | 15.4× |
| 10 | 30.0 | 380 s | 6.4 min | 1.83 h | 17.1× |
| 20 | 60.0 | 190 s | 3.3 min | 1.02 h | 18.8× |
| 30 | 90.0 | 127 s | 2.2 min | 0.75 h | 20.5× |
| 40 | 120.0 | 95 s | **1.7 min** | 0.62 h (~37 min) | 22.2× |

### 13.2 Verdict

- **Fast-start is minutes, not tens of minutes.** On a 1 Gbit line with ~40
  peers, a node is usable in **~1.7 min** (95 s download + 5.3 s commitment
  hash + sub-ms sig checks) versus **~37 min** for the full trustless sync —
  **~22× faster**. On a 100 Mbit line it is **~15 min** vs ~4 h, ~16× faster.
- **The commitment verify is negligible next to the download.** Hashing 11.4 GB
  (~5 s) and verifying 8 signatures (~0.26 ms) are rounding error; fast-start is
  *entirely* a download-size win (11.4 GB vs 174 GB, ~15× less data). It is still
  **downlink-bound** — same §10 ceiling; more peers past saturation add
  resilience, not speed.
- **The cost is a bounded trust window.** You trust the mesh attestation from
  minute ~2 until the background 174 GB sync completes (~37 min on 1 Gbit, hours
  on slower links) — after which the node is fully trustless *and* the
  attestation has been audited. This is strictly better than assumeUTXO, whose
  trust in a shipped snapshot hash never expires and is never audited.

Assumptions/caveats: SHA-256 stands in for the real UTXO commitment (muhash) —
same order, not identical; the 11.4 GB download reuses the §10 analytical model
(no real sockets, TCP slow-start, per-peer variance, or stitching overhead); the
BFT set is modelled as 8 independent Schnorr signers (a real Ghost attestation
may use aggregate/threshold sigs, which would be *smaller and faster* than shown);
"usable" here means "has the surviving UTXO set" — L1/Phantom trust semantics
(§5) still apply until the background sig pass reaches L2/Apparition.

## 14. Mesh transport — a live prerequisite (from a real fleet finding)

The live Ghost mesh **already hits the Noise transport's per-message ceiling.**
On 2026-07-02 the fleet logged, 70–130× per node:

```
Noise send failed: Message too large: 84241 > 65519
```

— a checkpoint / tree-sync proposal (84 KB) exceeding the ~64 KB Noise frame
limit, which then drives repeated `Checkpoint reached quorum but proposal data
missing — requesting tree sync` self-healing. GHAST inherits this **exactly**:
hazed range payloads and the ~11 GB surviving set are orders of magnitude larger
than one Noise frame.

So a **chunked / streamed framing layer over the Noise transport is a shared
prerequisite** — it is needed to fix the current checkpoint churn *and* to serve
GHAST ranges at all. Design options: application-level length-prefixed
fragmentation across multiple Noise frames with reassembly, or a dedicated
bulk-transfer stream negotiated per range. This is not optional for GHAST; it is
the same fix the live mesh needs today, so the two efforts share it.

## 15. Open research questions (for direction)

The measured architecture (§0) is solid; these are the next unanswered questions,
in rough priority:

1. **Mesh-attestation protocol (§12.1).** How does the BFT mesh *produce, sign,
   rotate* the UTXO commitment, and how does a fresh node *challenge* it? Cadence,
   quorum, fault attribution, and what a challenger presents when the background
   sync disagrees with the attested set.
2. **Commitment format.** muhash (rolling, cheap incremental update — what
   assumeUTXO uses) vs a Utreexo/merkle accumulator (enables per-UTXO inclusion
   proofs). Trade-off: update cost vs proof capability.
3. **Mesh transport framing (§14).** Prerequisite — needed regardless.
4. **Serving incentives.** Ghost's verified-capability share system could reward
   peers that serve hazed ranges / attest commitments — turning fast bootstrap
   into a paid node capability alongside Archive / GhostPay / Reaper.
5. **The Haze signature question (§5.1).** ANSWERED — Haze strips signatures
   (whole witness + scriptSig). See §5.1 and §16.

## 16. Implementation audit — what already exists vs the real delta (2026-07-03)

A read-only audit of `ghost-core/src/haze/` (evidence cited inline) shows the
module is real, wired end-to-end, and unit-tested — but it implements a
**different trust model than the GHAST §0 vision**, and in one crucial respect
the *opposite* of it.

### Already built + reusable
- **Hazed storage / stripping** (`block_stripper.cpp`, `stripped_block.h`) —
  scriptSig and witness fully removed, OP_RETURN → `OP_RETURN OP_0`. Mature,
  tested, wired at `validation.cpp:4557`. *Caveat: non-standard scriptPubKeys are
  also replaced (`OP_RETURN OP_1`, script discarded, value kept) — the "complete
  economic graph" has an asterisk for non-standard outputs.*
- **Stripped-block P2P (GSB)** — service bits `NODE_GHOST_HAZE`/`NODE_HAZE_CHECKPOINT`,
  serve/redirect + merkle-vs-header check on receipt (`net_processing.cpp:2383,
  4824`). But **single-block** (not a range protocol) and **storage-only** (a
  stripped block cannot be connected to build UTXO).
- **SwiftSync** (`swiftsync.cpp`, wired `validation.cpp:2680`) — bloom-filtered
  churn elision. **Important scope correction to §12:** it saves *LevelDB write
  churn / state I/O during connect*, **not** download or CPU, and not the
  trustless download. Conceptually matches the ~95% churn insight; operationally
  it's a write-saver on full connect.
- **Parallel chunk downloader** (`chunk_downloader.cpp`, 8-way, resume) — solid
  plumbing, but it fetches **UTXO-snapshot chunks** (SHA-256 vs a signed
  manifest), not hazed economic-graph height ranges.

### The critical finding — today's bootstrap is HARDCODED assumeUTXO, not mesh-attested
The live fast-bootstrap trust root is **doubly hardcoded and centralised — strictly
weaker than §12.1's mesh-attested rolling commitment, and arguably *more*
centralised than plain assumeUTXO:**
1. The checkpoint manifest is verified with **one hardcoded Ed25519 key**
   (`checkpoint_signing.cpp:57-89`, `GetTrustedCheckpointKeys`) — not the BFT
   mesh, not rotating, not challengeable.
2. Chunks assemble into an assumeUTXO snapshot and call `ActivateSnapshot`, which
   **requires the base hash to match a compiled-in chainparams assumeUTXO entry**
   (`validation.cpp:5801`, `AssumeutxoForBlockhash`; `-loadtxoutset` "must match a
   hardcoded assumeutxo entry").
3. **A hazed node never earns back trustlessness.** Background IBD is *disabled*
   for hazed nodes (`validation.cpp:5935-5943, 6200-6210`); `ReconstructPartialBlock`
   rebuilds with empty scriptSig+witness (signatures are permanently gone), so
   there is **no economic-graph replay and no signature backfill** — the node
   stays permanently on the trusted snapshot. This is the *inverse* of GHAST's
   trust-then-audit model.

Also: **per-range PoW is never verified** — `VerifyHeadersChain`
(`headers_file.cpp:100-136`) checks only `hashPrevBlock` linkage and never calls
`CheckProofOfWork`. Chain validity currently chains to the signing key, not PoW.

### Delta to build (to reach the better-than-assumeUTXO, safety-levelled vision)
- **P0 — replace the trust root:** (1) mesh-BFT attestation over `{height,
  block_hash, utxo_hash}` replacing the single hardcoded key, with rotation +
  challenge/fault-attribution; (2) let `ActivateSnapshot` accept a mesh-attested
  *rolling* commitment instead of a compiled-in hash; (3) re-enable a
  hazed-compatible background pass that audits the attested set → earns trustless.
- **P1 — the missing GHAST mechanisms:** (4) economic-graph *replay* to build the
  UTXO set from stripped blocks (does not exist); (5) true multi-peer *range*
  fetch with real per-range PoW + merkle (add `CheckProofOfWork`; auto-size
  parallelism to downlink); (6) safety-level state (Wisp/Phantom/Apparition) in
  `gethazestatus` + a "don't mine below L2 near tip" guard; (7) deferred-signature
  background pass + witness backfill from archive peers.
- **P2 — prerequisite:** chunked/streamed framing over the Noise transport (§14).

**Framing — GHAST is its own project, borrowing Haze parts.** The items above are
**Haze primitives GHAST can reuse as components** — the stripped-block format, GSB
serving, SwiftSync, and the parallel-download plumbing are built and sound.
Everything else GHAST **designs fresh for its own goal (fast *and* safe IBD)**: its
trust model (mesh-attested rolling commitment + safety levels + earn-back to
trustless) and the validation-progress machinery (economic-graph replay, real
per-range PoW). Haze's hardcoded-assumeUTXO bootstrap is **not a GHAST gap** — it
is Haze correctly serving Haze's *storage/legal* goal. GHAST has a different
target, so it gets a different design. The point of this audit was to find the
reusable parts, and it did: substantial plumbing, zero of the IBD trust model.

## 17. GHAST trust model — mesh-attested rolling UTXO commitment

This is the P0 from §16: the mechanism that is *genuinely* better than assumeUTXO.
It is designed fresh for GHAST's goal (fastest **and** safest IBD), and it reuses
the Ghost mesh's existing BFT signing infrastructure rather than inventing new
consensus. The design was pinned to real code by a read-only audit of both the
Rust consensus layer (`crates/ghost-consensus/`) and the C++ Haze layer
(`ghost-core/src/haze/`); the reusable primitives it names are cited inline.

### 17.0 The one-paragraph version

Instead of assumeUTXO's *single, static, compiled-in* snapshot hash — or Haze's
*single hardcoded Ed25519 key* (`checkpoint_signing.cpp:81-89`, strictly worse:
one live key vs a release-scrutinised constant) — GHAST attests
`{height, block_hash, utxo_commitment}` with a **BFT quorum of elder Ed25519
signatures**, rolled forward at a buried height on a cadence, verified by a fresh
node against a **chain-of-trust rooted in the mesh's genesis elder set** (the
network's constitution, not a perishable data snapshot). The fresh node trusts it
for *minutes* to be usable, then runs the full trustless GHAST sync in the
background which simultaneously earns trustlessness **and audits the attestation**
— any disagreement is a cryptographically-attributable mesh fault that is
propagated, independently verified, and slashed. Trust is bounded, challengeable,
and self-terminating; assumeUTXO's is permanent, blind, and never audited.

### 17.1 (a) What the mesh attests, and which commitment

**The attested tuple:** `{ height H, block_hash, utxo_commitment C }`, where `H` is
a *buried* height (`H = validated_tip − D`, `D ≥ ~1000` blocks) so no reorg can
ever invalidate a published attestation, and `block_hash` is the hash of the block
at `H` on the most-work header chain (which the fresh node has independently
PoW-verified — §5 Wisp/L0).

**Which commitment — muhash, not merkle/Utreexo.** GHAST attests a **rolling
MuHash** of the UTXO set:

- `MuHash3072` already exists in ghost-core (`src/crypto/muhash.h`), with
  incremental `ApplyCoinHash()` / `RemoveCoinHash()` (`kernel/coinstats.h`) and
  `CoinStatsHashType::MUHASH`. Each connected block updates the commitment in O(new
  outputs + spent inputs) — `insert(created) − remove(spent)`, order-independent,
  no full re-scan. This is exactly what an elder (a fully-synced node) can maintain
  *continuously* so that producing an attestation at height `H` is free.
- The alternative the manifest uses **today** is `hash_serialized_3`
  (`CheckpointManifest.utxo_hash`, `checkpoint.h:93`) — an order-dependent
  full-iteration hash. It is fine to compute *occasionally* (hashing the 11.4 GB
  surviving set is ~5.3 s at the measured 2.17 GB/s, §13.1) but far too slow to
  *roll* every block. **Decision: attest the muhash `C` as the rolling commitment**;
  retain `hash_serialized` only as the snapshot-integrity hash the existing Haze
  chunk-assembly machinery already checks (`AssembleSnapshot`), unchanged.
- **Merkle / Utreexo accumulator — rejected for the attestation.** Its only extra
  capability over muhash is per-UTXO *inclusion proofs*. §13 already proved those
  buy the bootstrap **nothing**: proving a coin was `created` costs ≈ the size of
  the graph you were avoiding (166 M × a merkle branch each), and proving `unspent`
  is *impossible* against a chain that commits to no spent-set. Utreexo's real value
  is shrinking a *running node's stored state* (§18), which is orthogonal to
  GHAST's IBD goal, and no Utreexo implementation exists in the tree. Muhash is the
  right primitive: cheapest to roll, already implemented, and the fresh node
  verifies it by hashing the downloaded set once (§13.1: ~5.3 s — rounding error
  next to the ~95 s–15 min download).

Why `C` is trust-then-audit and not trustless-on-arrival: §13 is the load-bearing
proof. A fresh node cannot verify `C` alone is correct without replaying every
spend (there is no Bitcoin-consensus commitment to shortcut the `unspent` check).
So `C` is *attested* (trusted briefly) and *audited* (earned trustless) — §17.4.

### 17.2 (b) How the BFT mesh produces and signs the attestation

**Reuse the existing checkpoint pipeline, do not build new consensus.** The Rust
consensus layer already runs a BFT checkpoint vote that reaches quorum on a
`{height, commitment_root}` tuple:

- `VotingSession` (`voting.rs:174`) with a **67% BFT threshold** (`voting.rs:25`),
  `MIN_VOTERS_FOR_BFT = 7` on mainnet (bootstrap floor `clamp(4,7)`, GHOST-04).
- `L2CheckpointBlockMessage` (`message.rs:1382`) already carries
  `prev_commitment_root` / `new_commitment_root` and is voted on via
  `L2CheckpointVoteMessage` (`message.rs:1444`); memory records this as the live
  "BFT payout consensus … hardened checkpoint pipeline."
- Votes are **individual Ed25519 signatures** `[u8;64]` collected per voter in a
  `HashMap<NodeId, Vote>` (`voting.rs:657`, `Vote{voter, approve, signature,
  timestamp}`); `NodeId` *is* the elder's Ed25519 public key (`identity.rs`). This
  matches the C++ manifest signature primitive (also Ed25519,
  `checkpoint_signing.cpp`) — one scheme end to end.

**The GHAST attestation:** add `utxo_commitment: [u8;32]` (the muhash `C`) and the
buried `height H` + `block_hash` to the checkpoint block, fold them into
`checkpoint_hash()` (`message.rs:1415`), and vote via the existing path. The
critical rule — reusing the GHOST-02 fix pattern (validators recompute rather than
rubber-stamp): **an elder votes `approve` iff it has independently recomputed the
muhash over its own coin DB at height `H` and it equals the proposer's `C`.** No
elder ever signs a commitment it has not reproduced. This makes a false attestation
require *forging* a quorum, not merely fooling a lazy validator.

**The attestation certificate** (the artefact a fresh node consumes) =
`{ H, block_hash, C, roster_epoch, [ (NodeId, sig) × q ] }` where `q ≥ ⌈2n/3⌉` of
the `n` elders in `roster_epoch`. Wire size is tiny: 7 elders → 448 B of sigs; a
full 68-of-101 quorum → ~6.5 KB — both far under the Noise 64 KB frame, though the
snapshot itself needs the §14 chunked framing. (§13.1 modelled this as 8 Schnorr
sigs / 544 B; the real scheme is Ed25519, same order of magnitude. A future
optimisation is a **threshold/aggregate** signature — FROST or MuSig2 over an elder
group key — collapsing `q` sigs into a single 64-byte attestation; noted, not
required for v1.)

**Cadence / rotation.** Two independent clocks:

1. *Attestation roll:* re-attest at a fresh buried height every epoch (reuse
   `epoch_manager.rs`; e.g. ~daily / 144 blocks). Because `H` is buried by `D`, the
   published attestation is always reorg-stable, and a node syncing *today* gets an
   attestation near *today's* tip — the "rolling" win over assumeUTXO's months-old
   compiled 840k/880k/910k snapshots (`chainparams.cpp:170-189`).
2. *Elder-set rotation:* elders join/leave via the existing MPC-gated + uptime-gated
   + capability-verified membership (they are not open-join Sybils). Each membership
   change is a signed transition — see §17.3 roster chain.

### 17.3 (c) How a fresh node verifies — vs one hardcoded key, vs a compiled hash

**Trust-root comparison:**

| Design | Trust root | Static? | Expires? | Audited? | To subvert, attacker must… |
|---|---|---|---|---|---|
| plain assumeUTXO | compiled-in hash (`chainparams.cpp:170-189`) | yes | never | never | compromise the release / your distro |
| Haze today | **one** hardcoded Ed25519 key (`checkpoint_signing.cpp:81`) | yes | never | never | compromise **1** live signing key |
| **GHAST** | quorum ≥⌈2n/3⌉ elder Ed25519 sigs, roster-chained to genesis | **no (rolls)** | **yes (audited out)** | **yes (§17.4)** | forge **⌈2n/3⌉** elder keys of the epoch roster |

**Fresh-node verification steps:**

1. **Headers / PoW (Wisp/L0).** Sync all headers, verify PoW + chain work. This is
   the Sybil/eclipse anchor — you cannot be fed a low-work fake chain, so
   `block_hash@H` is real with real work behind it. **This is why per-range/header
   `CheckProofOfWork` MUST be added** (the §16 gap: `headers_file.cpp:100-136`
   checks only `hashPrevBlock` linkage today). The entire model rests on this
   anchor.
2. **Obtain + verify the elder roster for `roster_epoch`.** The roster is not
   hardcoded either; only a small **genesis elder set** is shipped in chainparams —
   and *that is a strictly better thing to hardcode than a UTXO hash*: it is the
   network's founding identity (the same keys that already run Ghost consensus and
   payouts), and it never goes stale. From genesis the node walks a **hash-chain of
   signed roster transitions** (each rotation signed by the *prior* quorum) up to
   `roster_epoch`, exactly the pattern GHOST-11 already uses for propagating signed
   membership/equivocation facts. (Optional hardening: also anchor roster roots in
   Bitcoin via `OP_RETURN` for an external witness — heavier, deferred.)
3. **Download the ~11.4 GB surviving set**, recompute its muhash, check `== C`
   (~5.3 s, §13.1). Garbage from an eclipsing peer fails here (and fails per-range
   merkle/PoW) and is re-requested — it cannot be *accepted*.
4. **Verify the quorum:** ≥⌈2n/3⌉ valid Ed25519 sigs over `{H, block_hash, C}` from
   **distinct** roster members (~sub-ms, §13.1).
5. **Activate** the snapshot at `C` (§17.5) → usable in minutes at L1/Phantom.

**Security analysis (Sybil / eclipse / what must be compromised):**

- **Fake-chain feeding — defeated by PoW**, independent of peer honesty. An
  eclipser cannot manufacture `block_hash@H` with real work.
- **Sybil the quorum — infeasible by construction.** Elder membership is
  MPC-ceremony-gated, 95%/7-day-uptime-gated, and capability-verified; it is not
  open registration. Spinning up nodes does not get you votes. To make a fresh node
  accept a *false* set (phantom coins / spent-coin resurrection = inflation/theft)
  the attacker must hold **⌈2n/3⌉ elder secret keys of that epoch's roster** —
  vs **one** key for Haze-today and "compromise the build" for assumeUTXO. Strictly
  the hardest of the three.
- **Eclipse during download — DoS only, never a false accept.** A total eclipse can
  *stall* you (withhold data) or feed garbage (rejected by muhash/merkle/PoW), or
  replay a *stale-but-genuine* attestation — the last is bounded by the freshness
  check (step 1: `H` must be within a recent window of the PoW-verified tip) and the
  rotation cadence. None of these yields acceptance of an unauthorised UTXO.
- **Trust is bounded** to the fast-start window (minutes → background-sync
  completion); assumeUTXO's and Haze's never end.

### 17.4 (d) Challenge, fault attribution, slashing — the self-audit

This is what makes GHAST *strictly* stronger than assumeUTXO rather than "a nicer
assumeUTXO." The trust is not just bounded in time — it is **actively checked**.

- **Audit.** The fresh node runs the full trustless GHAST sync in the background
  (174 GB economic-graph replay, §10/§12). Replaying genesis→`H` it reconstructs the
  UTXO set and computes a running muhash `C'`. At `H`, **`C'` must equal the attested
  `C`.** Because reconstruction is incremental the audit runs *continuously* — each
  surviving coin is checked off as the set grows, not only at the end (§13).
- **Detection.** `C' ≠ C` ⇒ the attestation was false. The node holds *both* sets
  (the downloaded snapshot and its own reconstruction), so it can **diff them to the
  exact offending outpoint(s)** — a phantom output that no block created, or a coin
  spent in the replay but present in the attested set (or vice-versa). Optional:
  attest intermediate muhashes at sub-heights to bisect faster.
- **Attribution — cryptographic, no vote.** The certificate binds every one of the
  ≥⌈2n/3⌉ signers to the false `C`. The challenger publishes a **fraud proof**:
  `{ the signed certificate, the offending outpoint, its evidence }` where the
  evidence is either a merkle-creation-proof to the PoW-committed root (proving a
  "created" coin was never created → contradiction) or the block+input that already
  spent a supposedly-unspent coin (a double-spend witness). Any node verifies the
  fraud proof **independently** — replay to `H`, or check the specific-coin evidence
  — no quorum needed. Fault attribution is trustless.
- **Slashing / rotation — reuse GHOST-11.** A signed-but-false attestation is
  equivocation against the real chain; GHOST-11's machinery already
  **propagates equivocation proofs, independently re-verifies them per peer, bans
  the equivocator, and persists the ban across restarts** (`ban_manager.rs`). GHAST
  routes the fraud proof through it: the offending elders are **evicted from the
  eligible voter set** and their roster entry revoked, and they **forfeit** node
  rewards (elder = +1 share plus their capability shares) — tie to a bond if/when
  the Mix-style bond (#112) lands. The economics hold because detection is
  **certain, not probabilistic**: *every* node that finishes a background sync
  detects the fraud, so the expected cost (all future pool income + bond, globally,
  forever) dominates any transient gain from deceiving nodes still inside their
  minutes-long trust window.

The asymmetry over assumeUTXO in one line: **a corrupt assumeUTXO snapshot is never
detected and deceives forever; a corrupt GHAST attestation is detected by every
full sync and slashes its signers.**

### 17.5 (e) Activation — accept the rolling commitment, not the compiled gate

Today `ChainstateManager::ActivateSnapshot` refuses any snapshot whose base hash is
not a compiled-in entry: `GetParams().AssumeutxoForBlockhash(base_blockhash)` must
return a value (`validation.cpp:5801`; data at `chainparams.cpp:170-189`). GHAST
adds a second acceptance path:

1. Replace the single-key `VerifyCheckpoint` / `GetTrustedCheckpointKeys`
   (`checkpoint_signing.cpp:57-89`) with `VerifyMeshAttestation(manifest, roster)`:
   check (a) ≥⌈2n/3⌉ valid elder sigs over `{H, block_hash, C}` via the
   roster-chain (§17.3), (b) the recomputed muhash of the **loaded** snapshot equals
   the attested `C`, and (c) `block_hash` is on the PoW-verified most-work chain at
   `H`, buried ≥ `D`.
2. Change the manifest's fixed `signature: std::array<uint8_t,64>` (`checkpoint.h:96`)
   to a variable-length attestation `{ roster_epoch, Vec<(NodeId, sig)> }` — a wire
   /format bump (`CHECKPOINT_VERSION`), and add `utxo_commitment` (muhash) alongside
   the retained `hash_serialized` `utxo_hash`.
3. Gate `ActivateSnapshot` on `VerifyMeshAttestation` **OR** the legacy compiled-in
   entry (keep the latter as an air-gapped fallback and as the genesis anchor).
   Because the attestation is *rolling*, activation is no longer pinned to stale
   heights — the node activates near today's tip.
4. **Re-enable a hazed-compatible background pass** (undo the hazed-node IBD disable
   at `validation.cpp:5935-5943, 6200-6210`). Without this GHAST degenerates into
   Haze's permanent-trust model: this pass is what runs the §17.4 audit and earns
   L2/Apparition.

### 17.6 What to build (§17 concrete list)

**P0 — the trust root (the actual "better than assumeUTXO"):**
1. Fold `utxo_commitment` (rolling muhash) + buried `{H, block_hash}` into
   `L2CheckpointBlockMessage` / `checkpoint_hash()`; vote via the existing
   `VotingSession` (67% / floor 7) + `L2CheckpointVoteMessage`. Elder recomputes the
   muhash from its own coin DB before voting (GHOST-02 recompute pattern).
2. Continuous muhash maintenance on elders via `ApplyCoinHash`/`RemoveCoinHash`
   (`crypto/muhash.h`) on each connect; emit an attestation at a buried height per
   epoch (`epoch_manager.rs`).
3. **Elder-roster chain:** ship the *genesis elder set* in chainparams (replacing
   the compiled UTXO hash as the trust anchor); signed roster transitions; fresh-node
   roster walk (reuse GHOST-11 signed-membership propagation).
4. `VerifyMeshAttestation` replacing single-key `VerifyCheckpoint`; variable-length
   attestation cert replacing the fixed 64-byte `signature` field.
5. `ActivateSnapshot` acceptance path for the mesh-attested rolling commitment
   (alongside the `AssumeutxoForBlockhash` gate at `validation.cpp:5801`);
   recompute-and-compare the loaded snapshot's muhash to `C`.
6. Re-enable the hazed background audit pass (`validation.cpp:5935-5943/6200-6210`) →
   earns L2/Apparition and runs the §17.4 audit.
7. **Fraud-proof pipeline:** detect (`C'≠C`, diff to outpoint), attribute (signed
   cert), propagate + ban + slash (reuse GHOST-11 + share/bond forfeiture).
8. **Add per-range/per-header `CheckProofOfWork`** (`headers_file.cpp:100-136`) — the
   PoW anchor the whole model depends on. Non-negotiable.

**P1:**
9. Freshness/burial policy (`D`, cadence); attestation gossip topic (reuse elder
   port 8560 or add one); chunked framing over Noise (§14) for the cert + snapshot.
10. *(optional)* threshold/aggregate signature (FROST / MuSig2 over the elder group
    key) → a single 64-byte attestation instead of `q` sigs.

## 18. Ways to improve GHAST — brainstorm + honest evaluation

Ground rule from the prototype (§9–§13): **the bottleneck is download bandwidth,
not CPU.** At real block sizes signature verification already saturates all cores
(§9.2, columnar batching = 1.04×) and the UTXO build is ~13 min of CPU for the whole
174 GB (§10.3) — dwarfed by the ~37 min (1 Gbit) / ~4 h (100 Mbit) download. So the
honest filter for every idea below is: *does it move less data, need less before
usable, bypass the internet path, or make the result safer?* Ideas that only speed
up CPU are graded down on principle — the numbers say CPU isn't where the time goes.

Ranked, best first.

### 18.1 (HIGH, strategic) A consensus-level UTXO commitment in Ghost's own chain
**Idea.** §12/§13's whole "you must trust-then-audit" result hinges on one fact:
*Bitcoin consensus commits to no UTXO set*, so a fresh node has nothing to verify a
surviving-set against. **Ghost is a fork and controls its own consensus** — it can
commit a rolling muhash of the UTXO set into each block (a coinbase/header
commitment, soft-forkable, like an assumeUTXO the chain itself signs with PoW).
**What it buys.** On Ghost's own chain the fast-start surviving set becomes
**trustlessly verifiable against PoW in minutes** — the §17 mesh attestation
becomes a *convenience/liveness* layer rather than the trust root, and the trust
window in §17.4 shrinks toward zero. It is the one thing §12 said is structurally
impossible on Bitcoin-as-is, made possible precisely because GHAST's home chain is
not Bitcoin-as-is. **Cost.** A Ghost consensus change (soft/hard fork); miners
compute the incremental muhash per block (cheap — `ApplyCoinHash`/`RemoveCoinHash`
already exist and it's O(coins touched)). **Verdict.** Highest-leverage *safety*
idea in the list; only applies to Ghost's own chain (not the Bitcoin mainnet the
current fleet tracks), so it's strategic, not a quick win — but it is the credible
route from "trust-then-audit" to "trustless-in-minutes."

### 18.2 (HIGH, cheap) Incentivise hazed-serving via the verified-capability share system
**Idea.** Add a **Haze-serving / attestation capability** to Ghost's existing
5-4-3-2-1 verified-capability system (Archive+5, GhostPay+4, …), challenge-verified
exactly like the others: a verifier requests a random hazed height-range and checks
it hashes to the PoW-committed merkle root (the same challenge-response framework in
`crates/ghost-verification/` — `task.rs`, `client.rs`, `qualification.rs`).
**What it buys.** It attacks the *supply side* of the only real bottleneck. §10
shows a fresh node on 1 Gbit needs ~42 serving peers to saturate; §11 item 4 flags
"grow the mesh" as a lever. Paying nodes to serve hazed ranges (and to attest)
directly grows that supply and turns fast bootstrap into a first-class paid node
capability. **Cost.** Low — the capability framework, challenge tables, and payout
integration already exist; this is one new capability + one challenge type +
service-bit advertisement (`NODE_GHOST_HAZE`/`NODE_HAZE_CHECKPOINT` already exist,
`protocol.h:369-375`). **Verdict.** Best value-for-effort improvement: high impact
on the actual bottleneck, most of the machinery is built. Ship alongside §17.

### 18.3 (MEDIUM-HIGH, measure next) Domain-specific economic-graph compression
**Idea.** Compress the 174 GB economic graph with structure-aware coding —
script-template dictionaries, varint amounts, address/script dedup across the span —
beating generic gzip on this highly-regular data (§11 item 2). **What it buys.** It
shrinks the *actual bottleneck* (the trustless download) beyond the 3.49× hazing
win; even a further 1.3–2× turns ~37 min into ~20–28 min on 1 Gbit and proportionally
more on thin pipes, and it *stacks* with multi-peer fetch. **Cost.** A shared
compression format both ends agree on; CPU to (de)compress is cheap relative to
bandwidth (the §9 lesson). Gains are **unmeasured** — could be marginal. **Verdict.**
Directly hits the bottleneck at low risk; the obvious **next prototype experiment**
after churn elision. Worth measuring before committing.

### 18.4 (MEDIUM-HIGH, cheap, safety) Safety level as a requestable, advertised service
**Idea.** §5's Wisp/Phantom/Apparition levels already exist as node state; §16 P1
already puts them in `gethazestatus`. Go further: **advertise a node's current
safety level** (service bit / gossip field) and let clients *request* a target
level — a light/SPV client or a bootstrapping peer asks a serving node for "data
sufficient to reach L1" vs "L2," and security-sensitive queries route only to
Apparition/L2 peers. **What it buys.** Turns the honest-labelling from a status
readout into an actionable safety control: the mesh can route around not-yet-fully-
validated nodes, and a pool can *prove* it is mining on L2 (§5 "no mining below L2
near tip"). **Cost.** Low — the state is already computed; expose via service bit +
RPC + one gossip field. **Verdict.** Cheap safety win that complements §17; pairs
naturally with 18.2 (serving capability advertises its level).

### 18.5 (MEDIUM, cheap) Pipeline download↔verify + serve-while-syncing
**Idea.** (a) Overlap range download with verify+apply so total ≈ `max(download,
CPU)` not `download + CPU` (already §0 item 4 — call it out as adopted). (b) Once
past L1, **serve the ranges you have already verified to other bootstrappers while
you finish your own L2** — a node contributes upload capacity before it is fully
synced. **What it buys.** (a) saves the ~13 min CPU tail (§10.3) — real but small
against a 37 min+ download. (b) a network-effect multiplier on serving supply
(compounds 18.2). **Cost.** Low (both are scheduling/plumbing). **Verdict.** (a) is
free and already recommended; (b) is a cheap compounding win. Solid, unspectacular.

### 18.6 (LOW-MEDIUM) Erasure-coding ranges across peers for straggler resilience
**Idea.** Fetch `k`-of-`n` erasure-coded fragments of each range so a slow/failing
peer doesn't force a full re-request. **What it buys.** Lower *tail* latency near
downlink saturation (1 Gbit, ~40 peers) where a single straggler stalls a range.
**Cost.** Coding overhead; peers must precompute/store coded fragments; it fights the
per-range merkle model (coded fragments don't individually hash to the merkle root —
you can only verify *after* reconstruction, losing per-fragment attribution).
**Verdict.** The existing merkle-re-request (§10.1) already gives correctness-
resilience for free; erasure coding only trims the straggler tail near saturation.
Marginal — revisit only if real-socket measurements show straggler stalls dominate.

### 18.7 (LOW for GHAST's goal) Shard the serial UTXO pass by outpoint prefix
**Idea.** Partition the coin set by txid/outpoint prefix and apply ranges in parallel
with a merge (§11 item 5). **What it buys.** Speeds up a pass that §9 measured as
**not the bottleneck** (~13 min CPU vs 37 min+ download). **Cost.** Non-trivial —
correct parallel double-spend detection across shards + merge. **Verdict.** Low
priority by the numbers; only becomes relevant once the coin DB is disk-backed at
174 GB and the UTXO build itself slows materially. Don't build speculatively.

### 18.8 (LOW for GHAST's goal) Utreexo-style accumulator to shrink state
**Idea.** Replace the stored UTXO set with a hash accumulator + per-input inclusion
proofs (§11 item 2). **What it buys.** Shrinks a *running node's* stored state (166 M
/ 11.4 GB → a small accumulator). **Cost.** Per-input proof bandwidth that §13 showed
can exceed the state saved; a large implementation (none exists in-tree); and it does
**not** help the trustless bootstrap download or the §17 trust decision (§13). Same
category as SwiftSync/churn-elision: a *storage/footprint* play, orthogonal to
fast-and-safe IBD. **Verdict.** Interesting for node footprint, out of scope for
GHAST's stated goal; the numbers say it buys the *bootstrap* nothing.

### 18.9 (situational HIGH) LAN / sneakernet bootstrap
**Idea.** When a fast local source exists (another Ghost node on Gbit LAN, an NVMe
drive), fetch the hazed graph + surviving set locally and bypass the internet
downlink entirely (§11 item 3). **What it buys.** The *only* way past the §10
downlink ceiling — turns ~37 min into minutes. **Cost.** Low (it's a source, not a
protocol change) but requires a local source to exist. **Verdict.** High payoff where
applicable, niche otherwise. Cheap to support; ship as an option.

### 18.10 (LOW-MEDIUM, safety hardening) Attestation-cohort diversity
**Idea.** Require §17 attestations to carry sigs from ≥2 *independent* elder cohorts
(distinct operators/jurisdictions), not just any ⌈2n/3⌉. **What it buys.** Raises the
collusion bar beyond raw key-count toward genuine independence — mitigates a quorum
captured by one operator running many elders. **Cost.** Low (a policy predicate on
top of the quorum) but depends on having a meaningful independence signal for the
roster. **Verdict.** Cheap safety hardening for §17; gate on the elder set actually
being operator-diverse (today it is ~4 operators — GHOST-04).

### 18.11 Ranking summary

| # | Idea | Axis | Impact | Cost | Verdict |
|---|------|------|-------:|-----:|---------|
| 18.1 | Ghost-native consensus UTXO commitment | safety | High | High (fork) | Strategic — trustless-in-minutes on Ghost's chain |
| 18.2 | Incentivise hazed-serving (share system) | speed (supply) | High | **Low** | **Build with §17** — best value/effort |
| 18.3 | Economic-graph compression | speed (download) | Med-High | Low-Med | **Measure next** |
| 18.4 | Safety level as a service | safety/UX | Med-High | Low | Cheap, pairs with §17 |
| 18.5 | Pipeline + serve-while-syncing | speed | Med | Low | Free; (b) compounds 18.2 |
| 18.6 | Erasure-coding ranges | resilience | Low-Med | Med | Marginal vs merkle-re-request |
| 18.7 | Shard the UTXO pass | speed (CPU) | Low | Med | Not the bottleneck — defer |
| 18.8 | Utreexo accumulator | state size | Low* | High | Out of scope (*storage, not IBD) |
| 18.9 | LAN / sneakernet | speed | High* | Low | *When a local source exists |
| 18.10 | Attestation-cohort diversity | safety | Low-Med | Low | Cheap §17 hardening |

**Top three to act on:** **(18.2)** serving-incentive capability — highest
value-for-effort, most infra already exists, attacks the real (bandwidth-supply)
bottleneck; **(18.3)** economic-graph compression — the next measurement, directly
shrinks the download; **(18.1)** Ghost-native consensus UTXO commitment — the
strategic move that upgrades §17 from trust-then-audit to trustless-in-minutes on
Ghost's own chain, doing what Bitcoin structurally cannot.
