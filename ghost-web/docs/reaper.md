# Reaper

*A dead-code detector for Bitcoin transactions. It reads the witness data of every transaction the node sees and rejects the ones that contain bytes which can't possibly affect script execution.*

## The problem

Bitcoin's witness section is meant to carry signatures, public keys, and the data scripts need to verify a spend. Over time, people noticed they could push arbitrary bytes into the witness — pictures, text, JSON — and as long as the script eventually returned true, the transaction was valid. The bytes did nothing for the spend; they were ballast. Inscriptions, BRC-20 tokens, "Ordinals" — most of what arrived after Taproot used variations of this trick.

The chain still validated. But blocks got fatter, fees got weirder, and full nodes started carrying gigabytes of data that had nothing to do with whether anyone was paid. Reaper exists because most pool operators want to mine financial transactions, not data dumps, and they want a tool that decides programmatically rather than by guesswork.

## What it does

Reaper analyses every transaction the node would relay or include in a block. For each input, it figures out *which witness bytes are actually consumed by the script* and which aren't. Bytes that aren't consumed — that get pushed onto the stack and dropped, or that sit inside a branch the script never takes — are "dead". A transaction with too much dead code is a "Corpse" and gets filtered.

Two layers do the work:

| Layer | Where | Speed | Catches |
|---|---|---|---|
| **Layer 1** | C++ inside `ghost-core/src/policy/ghost_reaper.cpp` (invoked from `validation.cpp`) | Fast pattern match, runs before the tx enters the mempool | Five most common patterns (see below) |
| **Layer 2** | Rust inside `ghost-mining` template builder | Full analysis, runs on every tx that reaches block-template construction | Eight detection vectors with a taint-tracking stack simulator |

If a transaction is rejected at Layer 1, it never enters this node's mempool and is never relayed to peers. If it slips past Layer 1 (e.g. an unusual obfuscation), Layer 2 catches it before it lands in a block this node mines.

## What counts as dead code

Eight detection vectors, each with a clear definition. None of these require new opcodes or consensus rules — they're pattern recognition over the witness bytes that already exist.

### 1. Inscription envelopes

```
OP_FALSE OP_IF <data> OP_ENDIF
```

`OP_FALSE` guarantees the branch is never taken, so `<data>` is dead by construction. This is the canonical Ordinals pattern. Both Layer 1 and Layer 2 detect it.

### 2. Drop stuffing

```
<push of ≥76 bytes> OP_DROP
```

A large value pushed onto the stack and immediately discarded. The push exists only to fit data into the transaction. Threshold default: 76 bytes (configurable).

### 3. Unreachable code

Bytecode after a top-level `OP_RETURN` at nesting depth 0. Nothing past `OP_RETURN` can run.

### 4. Fake pubkeys in bare multisig

`OP_M ... OP_N OP_CHECKMULTISIG` outputs where the "pubkey" pushes don't start with `0x02` or `0x03` — i.e. they're not valid compressed-pubkey prefixes — or, with optional curve validation enabled, where the prefix is correct but the point isn't on the secp256k1 curve. Both modes catch BRC-20-style data smuggling that hides under multisig syntax.

### 5. Oversized OP_RETURN

The cap differs by layer. Layer 1 (ghost-core CLI) defaults to 83 bytes, matching Bitcoin's historical standard, configurable via `-ghostreaper-maxopreturn=<n>`. Layer 2 (the Rust `ReaperConfig`) defaults to **82 bytes** — one byte tighter — configurable via the `max_op_return_bytes` field. Either layer rejecting is sufficient to drop the transaction.

### 6. Annex presence

P2TR witness stacks where the last element starts with `0x50` (the annex marker). Annexes are reserved by BIP-341 but currently non-standard and serve no scriptable purpose, so they're dead bytes.

### 7. Excess witness data

This is the powerful one. A taint-tracking simulator executes the witness script symbolically, watching which witness indices contribute to stack values that get consumed by signature-verification opcodes (`OP_CHECKSIG`, `OP_CHECKMULTISIG`, `OP_CHECKSIGADD`). Indices never consumed by any execution path are flagged as excess.

The simulator has safety limits — max 1000 stack depth, 100 IF nesting, 64 branches explored — beyond which it falls back to a conservative byte-counting heuristic. Default excess threshold: 500 bytes per input.

### 8. Legacy scriptSig stuffing

Pre-SegWit transactions can hide data in scriptSig pushes. Standard scriptSig pushes are DER signatures (71-73 bytes, prefix `0x30`), compressed pubkeys (33 bytes, `0x02`/`0x03`), or uncompressed pubkeys (65 bytes, `0x04`). Anything else exceeding 80 bytes is flagged. P2SH redeem-scripts are recursively analysed.

## What Reaper isn't

It's worth being precise about scope:

- **Reaper isn't a censorship layer.** It rejects bytes that don't affect script execution. A normal payment, however weird the address layout, passes cleanly. The "is this transaction useful to anyone" judgement isn't Reaper's call.
- **Reaper isn't BUDS.** They're independent. BUDS classifies a transaction's *purpose* (T0-T3 policy tiers); Reaper classifies a transaction's *content* (dead bytes). A transaction can pass BUDS policy and still be reaped. Reaper can be off while BUDS stays on, and vice versa.
- **Reaper doesn't change consensus.** Reaped transactions are valid by Bitcoin's rules — they just don't go in this node's blocks. Other nodes that don't run Reaper will still relay and mine them.

## A worked example

A miner submits a transaction whose witness looks like:

```
[item 0]  schnorr_sig (64 bytes)
[item 1]  control_block (33 bytes, starts 0xc0)
[item 2]  script:  OP_FALSE OP_IF <8 KB blob> OP_ENDIF OP_DUP OP_HASH160 ...
                   OP_EQUALVERIFY OP_CHECKSIG
```

Reaper's analysis:

1. **Spend type identification.** Item 1 is a 33-byte control block starting `0xc0` → P2TR script-path spend. Item 2 is the witness script.
2. **Inscription detection.** Pattern match: `OP_FALSE OP_IF ... OP_ENDIF` at the top of item 2. The branch is dead by definition — flagged.
3. **Taint simulator.** Runs the rest of the script. The 64-byte signature in item 0 contributes to a stack value consumed by `OP_CHECKSIG`. Marked essential. The 8 KB inside the dead branch contributes to no consumed value. Marked excess.
4. **Verdict.** Total dead bytes = ~8 KB. Total witness bytes = ~8.1 KB. Dead-code ratio = 0.99. Verdict: `Corpse`.
5. **Layer 1 short-circuit.** This transaction would actually have been caught at Layer 1 by the inscription-envelope pattern matcher and never reached the mempool — Layer 2 is the safety net for variants that evade Layer 1.

## Configuration

### ghost-core (Layer 1)

```
-ghostreaper                 enabled / disabled (default: enabled)
-ghostreaper-maxopreturn=<n> Maximum OP_RETURN data bytes (default: 83)
-ghostreaper-mindropsize=<n> Minimum push size for drop stuffing (default: 76)
```

Set in `ghost.conf` or via CLI. Rejection reason: `TX_NOT_STANDARD` with a `ghost-reaper-*` reason string in logs.

### ghost-mining (Layer 2)

```toml
[reaper]
enabled = true
```

Per-vector toggles and thresholds are available in the source (`ReaperConfig` in `crates/ghost-reaper/src/config.rs`) for operators who want to relax specific checks. Default is "all on".

## Where Reaper sits in block construction

```
Transaction enters template builder
       │
       ▼
[Reaper] analyse() ───────► Corpse?  ─► drop, continue with next tx
       │ Accept
       ▼
[BUDS] classify() ────────► Policy check
       │ Pass
       ▼
[Tx selection] fee-rate sort, package eval
       │
       ▼
Block template
```

Reaper runs **before** BUDS so dead-code transactions get filtered cheaply, before any policy classification work.

## What you give up by enabling Reaper

Honestly: some fees. Inscriptions and BRC-20 transactions pay above-market fee rates because they need to fit into restricted block space. By rejecting them, a Reaper-enabled node forgoes that fee revenue.

Two reasons it's still defaultable-on:

1. **The economics are aligning.** As inscriptions volume falls and Bitcoin's fee market normalises, the fee premium shrinks. The network-effect benefit of nodes refusing data dumps grows over the same window.
2. **Capability share.** Running Reaper qualifies a node for the +2 Reaper capability share in Ghost's reward system. Long-run reward economics make this break-even or better for most operators, depending on inscription volume in any given week.

The honest answer: most weeks Reaper is mildly fee-negative and reward-positive. If a network-wide consensus to run it forms, it becomes both fee-positive (clean blocks attract clean transactions) and reward-positive. We can't promise that consensus, only describe the choice.

## Source

| File | Purpose |
|---|---|
| `ghost-core/src/policy/ghost_reaper.cpp` | Layer 1: pattern checks (invoked from `validation.cpp`'s `PreChecks()`) |
| `crates/ghost-reaper/src/analyzer.rs` | Layer 2 entry point + verdict |
| `crates/ghost-reaper/src/simulator.rs` | Taint-tracking stack simulator |
| `crates/ghost-reaper/src/dead_code.rs` | Pattern-based detection |
| `crates/ghost-reaper/src/flow.rs` | Flow analysis (unreachable, dead branches) |
| `crates/ghost-reaper/src/witness.rs` | Spend-type identification, witness breakdown |
| `crates/ghost-reaper/src/output.rs` | Output analysis (OP_RETURN, fake pubkeys) |
| `bins/ghost-pool/src/template.rs` | Template-builder integration |
