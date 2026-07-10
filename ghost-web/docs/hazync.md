# Hazync — recursive validity proof (workstream plan)

*Hazync (Haze + sync) is the Haze family's trustless fast-sync backbone. (Named to avoid collision with the unrelated external **ZeroSync** project, which is cited below only as a proving-system comparison.)*

*The recursive ZK proof that attests the UTXO set is the correct result of validating the chain — replacing checkpoint **trust** with **math**, and unlocking the proof-backed hazed wallet.*

## What we already have (don't reinvent)
- **SwiftSync** (`haze/swiftsync.{h,cpp}`) — Bloom-filter-accelerated fast IBD: during IBD it only persists UTXOs that survive to the checkpoint, tracking short-lived ones in an ephemeral cache. This is our **fast-sync-to-a-UTXO-set** engine.
- **Checkpoint + signing** (`haze/checkpoint*.{h,cpp}`, `chunk_downloader`) — chunked UTXO snapshot (assumeUTXO-shaped) with a *single-signer* signature. This is the current **trust root** we want to replace.
- **GHAST design** (`design/progressive-hazed-sync`, docs §0–§18 + `ghast-bench`) — fast *trustless* IBD design + a "mesh-attested rolling UTXO commitment" trust idea. Useful for the IBD/transport framing; but per the roadmap the **mesh/quorum attestation is superseded by the ZK proof** (Rungs 1–2 dropped).
- **Groth16 ZK stack** (`ghost-zkp`, bellperson/blstrs) + **MPC ceremony** (`ghost-mpc`) — shipping for the *shielded pool* (note/consolidation/unshield circuits).

## The key architecture decision up front
The existing `ghost-zkp` is **Groth16 (bellperson)** — great for fixed shielded-pool circuits, but **Groth16 does not recurse** (no native IVC; per-circuit trusted setup). A validity proof of the whole chain is **incrementally verifiable computation**: step *n*'s proof must verify step *n-1*'s proof. That needs a recursion-friendly system:
- **Nova / SuperNova (folding)** — cheapest recursion, no per-step trusted setup; the natural fit for "fold one block into the running proof." **Recommended default.**
- **Halo2 (accumulation, cycle of curves)** — also viable; heavier.
- **STARK route (à la ZeroSync)** — transparent, but a different stack.
So the proving system for Hazync is a **new choice**, not a reuse of the shielded-pool Groth16 — that's the first real decision.

## The statement to prove
> *Applying every valid block from genesis to height H, starting from the empty UTXO set, yields UTXO-set commitment C_H — and the header chain to H has valid PoW.*

Recursive step (folded per block): given `(prev_commitment C_{h-1}, block_h)`, prove: header PoW valid + links to prev; every tx in block_h is consensus-valid against C_{h-1}; applying its inputs/outputs yields `C_h`. Commit to the UTXO set with a **Utreexo-style accumulator** so `C_h` is compact and the step only touches the coins the block reads/writes.

## Phased plan
- **Phase 0 — scope + choose the system.** Pin the statement precisely; pick Nova/folding vs Halo2 (spike both on a toy IVC); define the UTXO accumulator (Utreexo). *Deliverable: design decision + a "hello-world" folding proof.*
- **Phase 1 — recursive header chain.** Prove a chain of N headers with valid PoW recursively (no UTXO yet). Establishes the IVC machinery end-to-end on our stack. **← first concrete milestone; low-risk, high-learning.**
- **Phase 2 — UTXO accumulator in-circuit.** Fold UTXO add/spend against the accumulator; prove `C_{h-1} → C_h` for *value-only* transactions (no script).
- **Phase 3 — script/tx validation (the hard part).** Bring Ghost's script + RUNG_TX/MLSC validation in-circuit. This is the multi-month body of work (Bitcoin's script zoo + Ghost's extensions); lean on **ZeroSync**'s circuit corpus.
- **Phase 4 — integrate at the tip (prove-then-strip).** Wire the forward prover to SwiftSync/checkpoint: prove each new block, attach the proof, strip. Replaces the single-signer checkpoint signature with a verifiable proof.
- **Phase 5 — historical backfill + quorum tie-in.** One-time genesis→checkpoint proof; then "elder-quorum-**proved** blocks" (the quorum tie-in the operator wants once proofs work).

Then the **proof-backed UTXO wallet path** ([hazedproof.md](hazedproof.md)) lands on top: the wallet spends coins whose inclusion is verified against the proof's committed UTXO root — closing the legacy/coinbase gap and finishing v23.

## Immediate next step
**Phase 1 spike:** a standalone crate (`crates/ghost-hazync` or a `ghast-bench`-style prototype) that folds N Ghost block headers into one recursive proof of cumulative PoW, using a folding scheme. Small, self-contained, and it forces the proving-system decision with real numbers (proof size, prove/verify time) before we commit to the heavy circuit work.
