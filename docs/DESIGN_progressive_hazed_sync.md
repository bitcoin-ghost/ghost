# Design: GHAST Block Download (GBD)

> **GHAST** = **Gh**ost + f**ast**, and a mirror of Bitcoin's IBD (Initial Block
> Download). A faster, less-trusting block download built on Ghost Haze: sync the
> hazed economic graph fast, then progressively complete validation.
>
> **Status:** Draft / theoretical. No implementation, no consensus change — this
> records the idea so it can be argued about, plus a prototype to test the core
> speed hypothesis before committing to it.

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
