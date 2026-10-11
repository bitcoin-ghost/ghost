# Ghost Core

*The Bitcoin Core fork that powers Ghost. 100% consensus-compatible with full operator policy control.*

## Overview

Ghost Core is a fork of Bitcoin Core that maintains full consensus compatibility while adding operator-level policy controls. This means:

- Ghost Core validates all Bitcoin blocks exactly like Bitcoin Core
- Ghost Core nodes are indistinguishable from regular Bitcoin nodes on the network
- Ghost Core adds policy-layer features that don't affect consensus
- You can switch between Bitcoin Core and Ghost Core without resyncing

:::info What "consensus-compatible" means
Ghost Core will always accept any valid Bitcoin block and reject any invalid one. The differences are in what transactions your node relays, what data it stores, and what blocks it builds — all policy-layer decisions that don't affect network consensus.
:::

## Consensus Compatibility

Ghost Core does **not** modify any consensus rules:

- Block validation rules
- Transaction validation rules
- Script execution
- Witness handling
- Chain selection (longest valid chain)
- Proof-of-work verification
- UTXO semantics

All differences are in policy — what your node chooses to relay, store, and build into blocks.

## BUDS Classification

**BUDS (Bitcoin Unified Data Standard)** is Ghost's system for classifying transaction data into tiers based on importance. The T0-T3 tier classification is active in production, used by the ghost-mining template processor for transaction filtering and block construction.

### Tier Definitions

| Tier | Name | Description | Examples |
| --- | --- | --- | --- |
| T0 | Consensus-Critical | Required for block validation | Inputs, outputs, signatures |
| T1 | Economic/System | Required for economic function | Amounts, script pubkeys |
| T2 | Metadata/Application | Structured application data | Ordinals, BRC-20, timestamps |
| T3 | Unknown/Obfuscated | Unstructured or encrypted data | Random OP_RETURN, encrypted blobs |

### BUDS Components

- **Labels** — Semantic meaning (e.g., "ordinal.inscription", "brc20.deploy")
- **Surfaces** — Location in transaction (e.g., "witness.stack[0]", "output[2].script")
- **Regions** — Byte ranges within surfaces
- **Tags** — Labels attached to regions
- **ARBDA** — Worst-tier dominance score for the transaction

Ghost uses BUDS for pruning decisions, mempool filtering, and template construction — but BUDS itself is never consensus-binding.

## Pruning Windows

:::warning Planned Feature
The 3-window pruning model is a proposed design. Currently, Ghost uses standard Bitcoin Core pruning modes.
:::

Ghost proposes a 3-window pruning model that balances storage efficiency with data availability:

### Validator Window (VW)

- **Size:** 576 blocks (~4 days)
- **Configurable:** No (fixed)
- **Pruning:** None — full retention required
- **Purpose:** Reorg safety, validation context

### Operator Window (OW)

- **Size:** Configurable (default 2016 blocks, ~2 weeks)
- **Configurable:** Yes
- **Pruning:** BUDS-based tier pruning allowed
- **Purpose:** Operator-controlled retention

Default OW pruning policy: keep T0, T1, T2 — prune only T3.

:::info Planned Configuration
Specific config keys for window sizes and per-tier pruning have not been defined yet. The 3-window model is design-level; the live node still uses Bitcoin Core's standard pruning options.
:::

### Archive Window (AW)

- **Size:** Infinite
- **Configurable:** Enable/disable
- **Pruning:** None — full chain history
- **Purpose:** Historical audit, Ghost Pay recovery

:::warning Archive Mode Storage
Archive mode requires 2+ TB of storage and growing. Enable only if you have the capacity. Archive nodes earn +5 shares in the reward system.
:::

## Mempool Profiles

Mempool profiles control which transactions your node accepts and relays. Profiles are surfaced through the policy layer:

| Profile | Accepts | Use Case |
| --- | --- | --- |
| standard | All standard transactions | Bitcoin Core behavior |
| strict | T0 + T1 only | Maximum privacy, minimal metadata |
| clean | T0 + T1 only, aggressive filtering | No inscriptions, no OP_RETURN data |
| structured | T0 + T1 + T2 | Allow structured metadata |
| bitcoin_pure | Only "pure" Bitcoin transactions | Filter non-monetary uses |
| ghost | Local only, no relay | Private mempool (Ghost Mode) |

:::info Terminology
**`bitcoin_pure`** here is a `PolicyProfile` (defined in `crates/ghost-policy/src/profile.rs`) — it controls which transactions your node will *relay*. This is distinct from the **Reaper +2 capability share**, which is the node-reward bonus earned by *verified* enforcement of dead-code policy (see [Elder System](elder-system.md)).
:::

## Template Profiles

Template profiles control how your node builds blocks for mining. The `bitcoin_pure`, `permissive`, and `full_open` profiles filter transactions at template build time:

| Profile | Behavior | Use Case |
| --- | --- | --- |
| standard | Bitcoin Core default | Maximum compatibility |
| max_fee | Maximize fee revenue | Default for most miners |
| strict | T0 + T1 only | No metadata in blocks |
| clean | Filter inscriptions, spam | "Clean" blocks |
| structured | Allow T2, filter T3 | Structured apps allowed |
| bitcoin_pure | Only monetary transactions | Bitcoin purist |
| ghost | Private template, hidden contents | Requires Ghost Mode |

## Ghost Mode

Ghost Mode makes your node "invisible" on the network while remaining fully functional. It operates in blocks-only relay mode, syncing with ghostd via RPC:

### Behavior Changes

- No transaction relay (tx INV disabled)
- Private local-only mempool
- Blocks-only peer connections
- Template contents hidden from peers
- Minimal inbound connections

### What Still Works

- Block validation and sync
- Local mining and block submission
- Submitting found blocks to the network
- Connection to Ghost Pool

:::warning Ghost Mode Privacy
Ghost Mode status is never broadcast to the network. Only you and your local Ghost Pool instance know it's enabled. Other nodes see you as a normal blocks-only peer.
:::

```bash
# Enable Ghost Mode
ghostmode=1
```

## Configuration

Full example configuration file:

```bash
# /etc/ghost/pool.toml

# Network
mainnet=1
listen=1

# Ghost Mode (0=off, 1=on)
ghostmode=0

# Archive Mode (0=off, 1=on)
archive=0

# RPC (for local access)
rpcuser=ghostrpc
rpcpassword=your_secure_password
rpcbind=127.0.0.1

# ZMQ (for Ghost Pool)
zmqpubhashblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28333

# Data directory
datadir=/var/lib/ghost/data
```
