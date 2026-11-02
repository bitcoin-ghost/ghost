# BUDS

*Bitcoin Unified Data Standard. A classifier that sorts every transaction into one of four tiers based on what it actually contains, so policy decisions can be made on real content rather than gut feel.*

## The problem

When a pool operator says "no inscriptions", how does the software know what an inscription *is*? "It's an OP_FALSE OP_IF in the witness" works for Ordinals envelopes, but BRC-20s use the same envelope, and Runes don't use envelopes at all, and tomorrow someone invents Format-N-Plus-One.

The brittle approach is to keep adding pattern matchers per protocol. The maintainable approach is to classify by what the bytes are *for* — core payment, extended financial, data anchor, heavy data — and have policy decisions reference those classes rather than specific shapes.

BUDS is that classifier. Reaper sits alongside it; so does any future filtering policy.

## How it classifies

The classifier walks each transaction directly: it scans every output's `script_pubkey`, every input's witness items and `script_sig`, and feeds each piece through a pattern detector that returns a set of `DetectedFeature` values. The features and a few aggregate measurements (max OP_RETURN size, max witness size per input, total witness size, transaction weight) are then folded into a single tier verdict.

Four tiers, ordered:

| Tier | Name | Examples | Default policy |
|---|---|---|---|
| **T0** | Core financial (single-sig) | P2PKH, P2WPKH, P2SH-P2WPKH, P2TR key-path payments — no OP_RETURN, standard-sized witnesses | Always allow |
| **T1** | Extended financial | Multisig (any m-of-n), CLTV / CSV timelocks, HTLCs, complex scripts, extended witness sizes (≤400 bytes per input) | Allow by default |
| **T2** | Data-anchoring | Small OP_RETURN (≤80 bytes — Lightning channel commitments, timestamping anchors) | Operator decides |
| **T3** | Heavy data | Inscriptions (Ordinals envelopes), BRC-20, Runes, large OP_RETURN (>80 bytes), oversized witnesses (>1 KB per input or >4 KB total) | Reject by default |

The verdict is the highest tier any element of the transaction triggers. A transaction with a regular P2WPKH input (T0-shaped) and a 200-byte OP_RETURN (heavy data) ends up at T3 — heavy-data wins.

## A small example

A typical Lightning channel close transaction:

```
Input 0   witness:   schnorr_sig (64 bytes) + control_block (33 bytes) + script
                     →   detected: HTLC pattern, P2TR script-path

Output 0  scriptpubkey:   OP_0 + 32-byte hash   (P2WSH multisig 2-of-2)
                     →   detected: Multisig { m: 2, n: 2 }

Output 1  scriptpubkey:   OP_RETURN + 32-byte channel_id
                     →   detected: OpReturn { size: 32 }
```

The classifier sees an HTLC and a multisig (both T1 signals) plus a 32-byte OP_RETURN (a T2 signal). The 32-byte OP_RETURN dominates: verdict **T2**. Allowed under `permissive` and `full_open`; rejected under `bitcoin_pure`.

Same transaction with a 1 KB inscription envelope spliced into Input 0's witness:

```
Input 0   witness:   ... + OP_FALSE OP_IF <1024 bytes JPEG> OP_ENDIF
                     →   detected: InscriptionEnvelope
```

InscriptionEnvelope is a T3 trigger, regardless of anything else in the tx. Verdict **T3**. Rejected by `bitcoin_pure` and `permissive`; only `full_open` would let it through.

## The `DetectedFeature` enum

The detector returns one or more `DetectedFeature` values for each piece of script it analyses. The full list (from `crates/ghost-buds/src/tier.rs`):

```
P2pkh                       T0 candidate
P2wpkh                      T0 candidate
P2sh                        T0 candidate
P2wsh                       T0 candidate
P2tr                        T0 candidate

Multisig { m, n }           T1 trigger
Cltv                        T1 trigger
Csv                         T1 trigger
Htlc                        T1 trigger

OpReturn { size }           T2 if size ≤ 80, T3 otherwise
LargeWitness { bytes }      T3 trigger above thresholds

InscriptionEnvelope         T3 trigger
RunesRunestone              T3 trigger
Brc20Pattern                T3 trigger
```

The accompanying `ClassificationReason` enum records *why* a transaction landed in its tier — `StandardPayment`, `Multisig { m, n }`, `Timelock`, `Htlc`, `ComplexScript`, `SmallOpReturn { size }`, `LargeOpReturn { size }`, `Inscription`, `LargeWitness { total_bytes }`, `Runes`, `Brc20`, or `Unknown`. This is what surfaces in logs and operator tooling, so a rejected transaction always carries a human-readable reason.

The 80-byte OP_RETURN cut-off is deliberate. Bitcoin's standardness rule (and Ghost's) keeps anchor-sized OP_RETURNs at T2 because they're load-bearing for legitimate L2 protocols (for example Lightning channel IDs). Larger payloads jump to T3.

## Policy presets

Three pre-defined presets are baked into `crates/ghost-buds/src/classifier.rs` as `PolicyPreset`:

| Preset | `name` | Allowed tiers |
|---|---|---|
| **Bitcoin Pure** | `bitcoin_pure` | T0 + T1 (rejects all data-anchoring and heavy data — even small Lightning anchors) |
| **Permissive** | `permissive` | T0 + T1 + T2 (allows small OP_RETURN for Lightning + timestamping; still rejects inscriptions / BRC-20 / Runes / large OP_RETURN) |
| **Full Open** | `full_open` | All four tiers (only consensus-invalid transactions get rejected) |

Operators select a preset conceptually as part of their pool configuration, e.g.:

```toml
# Conceptual: select which preset the template builder applies.
# In code, this maps to one of PolicyPreset::bitcoin_pure() / permissive() / full_open()
# in crates/ghost-buds/src/classifier.rs.
[buds]
preset = "permissive"
```

The classifier itself takes an `&[BudsTier]` of allowed tiers — operators wiring this up programmatically can pass `PolicyPreset::permissive().allowed_tiers` directly, or build a custom slice.

This is the layer Reaper sits alongside: Reaper's "Corpse" filtering applies before BUDS classifies. A Reaper-rejected transaction never reaches BUDS. A BUDS-rejected transaction is dropped from the block template after classification.

## Where it runs

Inside the block template builder, in this order:

```
Mempool transaction
       │
       ▼
[Reaper] dead-code analysis ───► Corpse?  ─► drop
       │ Accept
       ▼
[BUDS]   classify + apply preset ──► Tier disallowed?  ─► drop
       │ Accept
       ▼
[Tx selection] fee-rate sort, package eval
       │
       ▼
Block template
```

When a node is connected to its own miners, the BUDS-filtered template is what those miners hash. The merkle tree is rebuilt from the surviving transactions. The block this node mines reflects this node's policy.

## What BUDS isn't

- **Not a network rule.** BUDS is purely a per-node policy tool. Other nodes apply other policies; the chain accepts whatever a miner manages to include.
- **Not a censorship layer.** Operators choose. The classifier's job is to *describe* transactions accurately enough that the operator's choice can be applied programmatically. The default `permissive` preset actually accepts most things — only T3 (heavy data) is rejected.
- **Not stable forever.** New protocols arrive. The detector needs maintenance. A transaction format that doesn't yet match any known pattern lands in whatever tier its script shapes and sizes imply (often T0 if it looks ordinary, T3 if it doesn't) — operators can adjust the allowed tiers list as classifier coverage evolves.

## Performance

Classification has to run on every transaction in every block template, so it has to be fast. The implementation uses pre-compiled pattern matchers, early exit on the first T3 trigger, and result caching for transactions that have been classified before (mempool re-evaluation is common when fees shift).

In practice, BUDS adds well under a millisecond per typical transaction on commodity hardware. Even at 4000 transactions per block, classification is a rounding error compared to merkle reconstruction or signature verification.

## Source

| File | Purpose |
|---|---|
| `crates/ghost-buds/src/classifier.rs` | `BudsClassifier::classify()`, tier determination, `PolicyPreset` |
| `crates/ghost-buds/src/tier.rs` | `BudsTier`, `DetectedFeature`, `ClassificationReason`, `ClassificationResult` |
| `crates/ghost-buds/src/detector.rs` | `PatternDetector` + per-pattern matchers (inscription, runes, BRC-20, HTLC, multisig, etc.) |
| `bins/ghost-pool/src/template.rs` | Template-builder integration |
