# ghast-bench

A self-contained benchmark prototype for **GHAST Block Download** (see
`../../docs/DESIGN_progressive_hazed_sync.md`).

It tests the core speed hypothesis: **is columnar / multi-pass block validation
— specifically a single batched, parallel signature pass over the whole chain
segment — faster than traditional row-wise, per-block validation?** It also
quantifies the two GHAST wins that do *not* depend on that question: the hazed
bandwidth reduction, and the "time to usable" from deferring signature
verification.

## What it does

Synthesizes a chain segment in memory. Every transaction input carries a **real
secp256k1 ECDSA + Schnorr signature** over a real message digest that actually
verifies — nothing about the crypto is mocked. It then times three strategies
over the **identical** workload (warm-up run first, then median of N runs):

- **A) Row-wise, single-threaded** — per block: apply UTXO transitions, verify
  each input signature inline, one core. Naive baseline.
- **B) Row-wise, parallel per block** — same serial block/UTXO loop, but each
  block's signatures are verified across a `rayon` pool. **This is the strong
  baseline — it is what Bitcoin Core already does.** The real question is whether
  C beats B.
- **C) GHAST columnar** — pass 1 headers, pass 2 UTXO transitions (serial
  genesis→tip), pass 3 **all** signatures across the whole segment collected up
  front and verified in one batched + parallel sweep.

B and C are made scrupulously fair: both collect inputs into a flat slice and
`par_iter` them, so the *only* difference is the batch granularity (per-block vs
whole-chain).

It also reports:

1. **Hazed bandwidth ratio** — full block bytes (incl. witness/sig column) vs
   economic-graph-only bytes.
2. **Time-to-usable (Phantom / L1)** — wall-clock for passes 1+2 only (UTXO
   built, signatures deferred) vs full validation.
3. **ECDSA-parallel vs Schnorr** separately.
4. **Multi-peer parallel fetch (design §10)** — an analytical model of
   downloading the hazed economic graph from N peers by height range. The
   **network transfer is modelled** (bandwidth arithmetic); the **CPU rate is
   measured** (the header+UTXO throughput from above). Sweeps N peers across
   downlink tiers and shows where added peers stop helping (downlink saturation).

## How to run

```bash
# Build (WSL2: use -j2 to avoid OOM — see repo CLAUDE.md).
cargo build --release -j2

# Default workload (~360k signatures, finishes in a few minutes incl. gen).
cargo run --release

# Custom workload:
cargo run --release -- --blocks 300 --txs 30 --inputs 40 --outputs 2 --runs 3
```

```bash
# Multi-peer model on a fibre pipe, custom peer sweep and per-peer rate:
cargo run --release -- --downlinks-mbps 125 --peers 1,5,10,25,50 --peer-mbps 5
```

CPU-benchmark args (all optional): `--blocks`, `--txs`/`--txs-per-block`,
`--inputs`/`--inputs-per-tx`, `--outputs`/`--outputs-per-tx`, `--runs`, `--seed`.

Multi-peer-fetch args (all optional, defaults are stated assumptions echoed at
runtime):

| Flag | Default | Meaning |
|------|---------|---------|
| `--chain-gb` | `600` | total full-block data of a realistic chain (decimal GB) |
| `--economic-ratio` | `0.29` | economic-only fraction after hazing (from §9 measurement) |
| `--peer-mbps` | `3.0` | per-peer serve bandwidth, MB/s (= 24 Mbit/s) |
| `--downlinks-mbps` | `12.5,125` | comma-list of downlink tiers, MB/s (100 Mbit, 1 Gbit) |
| `--peers` | `1,10,20,30,40` | comma-list of peer counts to sweep |

This crate has an **empty `[workspace]` table** in its `Cargo.toml` so it does
NOT join the giant main workspace (which is slow and OOM-prone in WSL2).

## Caveats (read before trusting the numbers)

- **Synthetic data**, single machine. No real disk or network I/O — this is a
  **verification-CPU + in-memory-UTXO benchmark**, not an end-to-end sync
  benchmark. Real IBD is often I/O- and bandwidth-bound, which would only
  *increase* the relative value of the bandwidth win.
- The **UTXO pass is modelled as serial** (correct per the design) using an
  in-memory `HashMap`; a real coin DB is slower and disk-backed.
- Signatures are independent random keys/digests; real blocks have some
  structure (address reuse, batching) that does not change the verify cost.
- The Schnorr pass is **per-signature Schnorr verify spread across the pool**,
  not libsecp256k1's experimental aggregate `schnorrsig_verify_batch` (not
  exposed by rust-secp256k1 0.30). A true batch check would make Schnorr faster
  than shown here.
- Bandwidth sizes use representative Bitcoin component sizes (72-byte DER sig,
  33-byte pubkey, 36-byte outpoint, etc.); the exact ratio shifts with the real
  witness/economic mix of a given era.
- The **multi-peer fetch is analytical bandwidth arithmetic, not a real
  network**: no TCP slow-start, no per-peer variance, no stitching/re-request
  overhead; it assumes perfectly divisible height ranges and steady per-peer
  rates. Its CPU input is the measured header+UTXO throughput extrapolated to
  the modelled chain size (a real disk-backed coin DB at ~174 GB is slower, but
  CPU is dominated by download regardless).

## Headline result (this machine)

At **real Bitcoin full-block sizes**, columnar batching (C) is ~**parity** with
parallel-row-wise (B) — B already saturates the cores. C only wins on small
blocks. **The genuine GHAST wins are the deferral (time-to-usable) and the
bandwidth (hazed ratio), not the batching.** See §9 of the design doc for the
measured numbers and interpretation.

Bandwidth being the bottleneck, the multi-peer model (§10) shows parallel
range-fetch is a large but **downlink-bounded** win: on a 100 Mbit pipe it caps
at ~5 peers (4.17×); on 1 Gbit it scales linearly through ~42 peers (40×). More
peers past saturation buy resilience, not speed — and never trust (integrity is
cryptographic via PoW + per-range merkle, not peer agreement).
