# Consensus & Protocol

*How Ghost nodes reach agreement on shares, payouts, and Elder status without centralization.*

## Overview

Ghost uses a decentralized consensus mechanism to coordinate mining pool operations across all nodes. Key consensus types:

- **Share Consensus** — Agreement on valid shares during a round
- **Payout Consensus** — Agreement on reward distribution when block found
- **Elder Consensus** — Agreement on Elder status and revocation
- **Treasury Consensus** — Agreement on treasury threshold and decay state

:::info Byzantine Fault Tolerant
Ghost consensus tolerates up to 33% malicious nodes. The system requires 67% supermajority for critical decisions, ensuring honest nodes always win.
:::

## Network Topology

Ghost uses a **full mesh network** where every node connects to every other node:

```text
Ghost Network (Full Mesh)

    Node A ◄────► Node B
       ▲            ▲
       │            │
       ▼            ▼
    Node D ◄────► Node C
```

### Port Assignments

| Port | Purpose | Pattern |
| --- | --- | --- |
| 8555 | Share Propagation | PUB/SUB |
| 8556 | Block Announcements | PUB/SUB |
| 8557 | Consensus Voting | DEALER/ROUTER |
| 8558 | Health Monitoring | PUB/SUB |
| 8559 | Discovery Service | REQ/REP |
| 8560 | Elder Management | PUB/SUB |
| 8561 | Payout Proposal | PUB/SUB |
| 8562 | Payout Transaction | PUB/SUB |
| 8563 | Encrypted P2P (Noise) | point-to-point |

Ports 8555–8562 carry the plaintext ZMQ PUB/SUB and REQ/REP traffic; sensitive
message types (MPC, Elder, Payout, ZK) are additionally tunnelled over an
encrypted Noise channel on **8563**.

## ZMQ Protocol

Ghost uses ZeroMQ for low-latency peer-to-peer communication:

### Why ZMQ?

- **Low latency** — 1-50ms vs 50-200ms for libp2p
- **Proven reliability** — Used by Bitcoin Core
- **Multiple patterns** — PUB-SUB, DEALER-ROUTER, REQ-REP
- **Simple implementation** — Easy to debug

### Message Format

```bash
MessageEnvelope {
  msg_type: MessageType,    // Share, Block, Vote, etc.
  sender:    [u8; 32],      // Node ID (Ed25519 public key)
  timestamp: u64,           // Unix timestamp (ms)
  sequence:  u64,           // Per-sender sequence number (dedup / replay guard)
  signature: [u8; 64],      // Ed25519 signature over the payload
  payload:   Vec<u8>,       // JSON-serialized message
}
```

All messages are signed with **Ed25519** (the node identity key) to prevent
forgery. (Bitcoin transactions — coinbase payouts, treasury spends — are signed
with secp256k1, as Bitcoin requires; the P2P/consensus layer uses Ed25519.)

## Share Consensus

How nodes agree on valid shares:

### Share Validation Rules

1. Hash meets pool difficulty target
2. Derived from valid block template
3. Timestamp within 30 seconds
4. Node signature valid
5. Not a duplicate

### Propagation Flow

```bash
Miner submits share to Node A
        ↓
Node A validates locally
        ↓
Node A broadcasts ShareProof (port 8555)
        ↓ (1-50ms)
All nodes receive via SUB socket
        ↓
Each node validates independently
        ↓
Each node adds to local share ledger
```

### Merkle Commitment

Every 60 seconds, nodes broadcast a commitment of their share ledger:

```bash
ShareCommitment {
  node_id: [u8; 32],
  round_id: [u8; 32],
  merkle_root: [u8; 32],    // Root of share tree
  share_count: u64,
  signature: Vec<u8>,
}
```

If merkle roots don't match, nodes sync their differences.

## Payout Consensus

When a block is found, nodes must agree on payouts:

### Consensus Flow

```bash
Block found by Node A
        ↓
Node A submits block to Bitcoin network (immediate)
        ↓
Node A broadcasts BlockFound (port 8556)
        ↓
All nodes freeze share ledgers
        ↓
All nodes calculate PayoutProposal
        ↓ (1-2 seconds)
All nodes broadcast proposals (port 8561)
        ↓
Each validator RECOMPUTES the split from its own ledger
        ↓
All nodes vote on proposals (port 8557)
        ↓ (5 second timeout)
67% approve → PayoutTransaction created
```

### 67% Supermajority

Payout proposals require 67% agreement. If achieved:

- Winning proposal is accepted
- Finding node creates payout transaction
- All nodes verify and relay to Bitcoin network

### Deterministic split — validators recompute, not median

There is no "median of proposals" fallback. Instead, every validator
**recomputes the payout split from its own converged share ledger** and rejects
a proposal that doesn't match before voting (GHOST-02). Because all honest nodes
converge on the same share set (GHOST-03 ledger convergence) and the split is a
deterministic function of that set + the registered payout addresses, honest
nodes independently arrive at the **same** answer — so an honest proposal gets
67% by construction, and a manipulated one is rejected outright rather than
averaged in.

## Byzantine Fault Tolerance

Ghost consensus is designed to resist Byzantine (malicious) nodes:

### Safety Guarantees

| Property | Guarantee |
| --- | --- |
| Share Consensus | All honest nodes agree on valid shares if 67% are honest |
| Payout Consensus | Correct payouts enforced by honest majority |
| Elder Consensus | Elder list immutable, revocation requires 67% witness |
| Liveness | System never deadlocks; honest nodes converge on the same ledger + split |

### Cryptographic Security

- **Ed25519 signatures** — All P2P/consensus messages authenticated (node identity key)
- **Merkle proofs** — Share inclusion verifiable
- **Hash chains** — State history tamper-proof

## Attack Resistance

### Fake Shares Attack

**Attack:** Malicious node broadcasts invalid shares.

**Defense:** All nodes validate shares independently. Invalid shares are rejected. Repeated violations → peer banned.

### Payout Manipulation Attack

**Attack:** Malicious nodes propose inflated payouts for themselves.

**Defense:** every validator recomputes the payout split from its own converged ledger and rejects a proposal that doesn't match (GHOST-02), so an inflated proposal never reaches 67% — it's rejected, not averaged in.

### Elder Sybil Attack

**Attack:** Attacker registers many nodes to dominate Elder slots.

**Defense:** Only first 101 nodes become Elders. One-time event at launch. Deterministic ordering by (timestamp, hash) prevents manipulation.

### Network Partition Attack

**Attack:** Attacker splits network to cause disagreement.

**Defense:** Full mesh topology with multiple connection paths. Periodic state verification. Self-healing when partition heals.

:::warning 33% Limit
If more than 33% of nodes are malicious, consensus guarantees break down. This is a fundamental limit of BFT systems. Ghost relies on economic incentives (node rewards) to keep the majority honest.
:::

## Hardened cross-node enforcement

The consensus above describes *how* nodes agree. A second layer **enforces** that
agreement so a single dishonest node can't credit itself for work it didn't
receive or push through a payout split nobody else computed. Four enforcement
properties run on the mesh:

| ID | Enforces |
| --- | --- |
| **GHOST-09** | Every `ShareProof` carries an Ed25519 signature by the node that received it (`received_by`). Unsigned or wrongly-signed share proofs are **dropped** — you cannot claim node-reward credit for a share you didn't actually receive. |
| **GHOST-02** | Payout-proposal validators recompute the split from their **own** converged ledger and **reject** a proposal whose split doesn't match — proposers can't inflate their own cut. |
| **GHOST-03** | **Ledger convergence**: nodes reconcile their signed-share sets (a ~30s request loop + backfill that re-verifies GHOST-09), so every honest node holds the same share set before a payout is computed. |
| **GHOST-11** | Equivocation (a node signing two conflicting things) is detected, **banned**, and the ban is propagated and persisted across the fleet. |

### Why it activates at a block height (not a flag)

Turning these on is a **wire-format** change — an old node and a new node must
not disagree about whether an unsigned share is valid mid-rollout. So activation
is gated on a **block height**, `CLUSTER_ENFORCEMENT_HEIGHT`, exactly like the
earlier `PAYOUT_ADDRESS_GROUPING_HEIGHT`:

- **Before the height** the binary still signs shares, converges ledgers and
  propagates equivocation bans (all additive and mixed-version-safe), but it does
  **not** yet drop unsigned shares or reject a mismatched split. This lets the
  fleet roll the new binary out canary-style with no mixed-version enforcement
  window.
- **At the height** both enforcements (GHOST-09 drop + GHOST-02 reject) switch on
  **everywhere at once**, deterministically, because every node runs the same
  constant.

This is the same pattern Bitcoin uses for soft-fork activation: deploy first in a
dormant state, flip at an agreed height.
