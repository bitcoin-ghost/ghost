# Ghost Pay

*Fast, private Bitcoin payments. Shielded notes, zero-knowledge proofs, BFT-consensus settlement.*

## Overview

Ghost Pay is the Layer 2 payment system built into every Ghost node. Unlike Lightning, it doesn't require channels, route-finding, or inbound liquidity. The mental model is simpler:

1. **Shield** — Move Bitcoin into the Ghost Pay shielded set on L1. This creates a *note* you control.
2. **Send** — Spend notes to other recipients. Each spend produces a Groth16 proof and a nullifier; the elder mesh agrees on ordering in seconds.
3. **Settle** — Periodic epoch reconciliation flushes net positions back to L1.

:::info Key Principle
Ghost Pay always settles to Bitcoin. There is no "Ghost coin" or separate token. Shielded notes represent real BTC held in the L2 commitment tree, and reconciliation epochs anchor that state to L1.
:::

### Fees

Ghost Pay charges a flat **10-satoshi fee per L2 transfer** (`L2_TRANSFER_FEE_SATS`) — a fixed amount per payment, not a percentage. It's enforced inside the zero-knowledge spend circuit itself (the transfer's change output is `note_value − amount − 10`), so it can't be bypassed and changing it would require an MPC ceremony reset. The collected fees are split between the Treasury and Node Reward Pool using the same control-decay ratio as the mining-pool fee; after ossification, 100% of Ghost Pay fees go to the Node Reward Pool.

> **Settlement (L1) fees are separate.** Withdrawing a lock to the base chain pays the normal Bitcoin network fee (sat/vB) scaled by a settlement-class multiplier — Economy ×0.5, Standard ×1.0, Express ×1.5. The optional Wraith mixing service may also deduct a per-denomination service fee at L2.

## How It Works

Ghost Pay is built from four moving parts: a Merkle commitment tree, Groth16 proofs, a nullifier set, and a BFT consensus layer running on the elder mesh.

### Shielding Funds

To use Ghost Pay you first move Bitcoin into the shielded set with a standard L1 transaction. The deposit creates a fresh **note commitment** that gets inserted into the L2 Merkle tree. The note's value, recipient, and salt are private — only the commitment is public.

### Sending Payments

A spend produces a small bundle:

- **Groth16 proof** — 192 bytes proving the spender knows a note in the tree, knows its spending key, and is producing valid recipient/change commitments.
- **Public commitments** — recipient note commitment + change note commitment (Pedersen commitments; values stay hidden).
- **Public nullifier** — derived deterministically from the spent note. Once published it permanently marks the note as spent.

The elder mesh receives the spend, each elder verifies the proof and nullifier independently, and they reach BFT agreement on the ordering of nullifiers (67% supermajority on the elder set). New commitments are appended to the L2 tree, and the nullifier is added to the consensus nullifier set.

Confirmation latency is on the order of one consensus round — typically a few seconds.

### Receiving Payments

Receivers don't need to be online to receive. The recipient commitment is public (its preimage is not), and the receiver scans for notes addressed to their viewing key whenever they reconnect. There are no channels to keep open and no "inbound liquidity" requirement.

### Settlement (Reconciliation)

L2 state is anchored back to L1 by `ghost-reconciliation` on an **epoch** schedule:

- Each epoch summarises net deposits and withdrawals.
- The elder mesh agrees on the epoch's reconciliation transaction.
- A single L1 transaction settles the epoch, anchoring the new L2 state root.

Individual L2 spends are never written to L1 — only the epoch summary is. This is what gives Ghost Pay its privacy and throughput properties.

For protocol-level details see [Zero-Knowledge Proofs](zk.md) and [Reconciliation](reconciliation.md).

## Ghost Pay vs Lightning

Ghost Pay and Lightning solve the same problem differently:

| Feature | Lightning | Ghost Pay |
| --- | --- | --- |
| Channels | Required (open/close) | Not needed |
| Routing | Find path through network | Direct, mesh-mediated |
| Inbound Liquidity | Required to receive | Not needed |
| Online Requirement | Must be online to receive | Receive while offline |
| Payment Failures | Common (routing issues) | Rare (no path-finding) |
| Privacy | Limited (onion routing) | Strong (shielded notes + ZK) |
| Max Payment | Limited by channel size | Limited by note value |
| Complexity | High | Low |

:::warning Not a Lightning Replacement
Ghost Pay and Lightning serve different use cases. Lightning excels at high-frequency micropayments and has a larger network. Ghost Pay focuses on simplicity and privacy. They can coexist.
:::

## The Shielded Set

The shielded set is the on-chain anchor for Ghost Pay state.

### Commitment Tree

Every shielded note commits to its value, recipient, and salt under a Pedersen-style commitment. Commitments are appended to a binary Merkle tree of fixed depth. The current root is published with each reconciliation epoch and is the source of truth for what notes exist.

### Nullifier Set

Spending a note publishes its nullifier — a deterministic, unlinkable value derived from the note and the spending key. The elder mesh maintains the consensus nullifier set: any spend whose nullifier is already present is rejected. This is what prevents double-spends without revealing which note was spent.

### BFT Consensus on Nullifiers

Nullifier ordering is agreed across the elder mesh under the same 67% supermajority rule used for share/payout consensus (see [Consensus & Protocol](consensus.md)). The elder set is the trust anchor for Ghost Pay — they collectively sign off on each round of nullifiers and the tree updates that follow.

The nullifier-route handler is implemented in `crates/ghost-consensus/src/nullifier_route_handler.rs`; the proof and tree primitives live in `crates/ghost-zkp/`.

## Privacy Features

Ghost Pay is private by default:

### Stealth Addressing

Recipient identity is unlinkable across spends. The viewing key lets the receiver recognise their notes without exposing them publicly.

### Hidden Amounts

Note values are committed under Pedersen commitments and proven correct in zero knowledge using Groth16. Only sender and receiver learn amounts.

### No Graph Analysis

Spends do not link to specific notes on-chain. Only nullifiers and new commitments are public — neither reveals which prior commitment was consumed.

### Offline Receive

Notes can be received while the recipient is offline. There is no channel to maintain and no online requirement to accept funds.

:::info Privacy vs Compliance
Ghost Pay provides strong privacy but is not designed for illegal use. Users can voluntarily disclose viewing keys or specific spend details for compliance. The goal is privacy by default, transparency by choice.
:::

## Development Status

Ghost Pay is deployed and active on mainnet:

| Phase | Status | Description |
| --- | --- | --- |
| Specification | Complete | Protocol design finalised |
| Reference Implementation | Complete | `ghost-zkp`, `ghost-consensus`, `ghost-reconciliation` |
| Testnet | Complete | Tested on signet |
| Mainnet | Live | Production launch |

:::warning Not Required
Ghost Pay is optional. You can run a Ghost node and mine without ever using Ghost Pay. It is an additional feature for those who want fast, private payments.
:::

## See Also

- [Zero-Knowledge Proofs](zk.md) — Groth16 circuits, MPC trusted setup, verifying-key handling.
- [Reconciliation](reconciliation.md) — epoch-based settlement back to L1.
- [Consensus & Protocol](consensus.md) — the BFT layer that orders nullifiers.
