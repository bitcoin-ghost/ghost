# Ghost Pool

*Decentralized mining where every node runs its own pool. No middleman, no censorship, no trust required.*

## Overview

**Every Ghost node is its own mining pool.** This is the key differentiator from traditional mining:

| Feature | Traditional Pool | Ghost Pool |
| --- | --- | --- |
| Operator | Centralized company | You (your node) |
| Pool Fee | 2-4% of everything | 1% of subsidy only |
| TX Fees | Pool keeps them | 100% to winning node |
| Block Template | Pool decides contents | You decide contents |
| Censorship | Pool can censor TXs | Impossible — your node, your rules |
| Trust | Trust pool for payouts | Cryptographic consensus |

:::info Why this matters
Mining pools are one of Bitcoin's biggest centralization risks. A handful of pools control the majority of hashrate. Ghost eliminates this by making every node operator their own pool — decentralization at the infrastructure level.
:::

## Architecture

Ghost Pool runs as a daemon alongside Ghost Core:

```text
┌─────────────────────────────────────────────────┐
│              Your Ghost Node                    │
├─────────────────────────────────────────────────┤
│                                                 │
│   Ghost Core ◄──────► Ghost Pool                │
│   (validates)        (manages miners)           │
│        │                   │                    │
│        │                   │                    │
│        ▼                   ▼                    │
│   Bitcoin P2P         Stratum Server            │
│   (blocks)            (miners connect)          │
│                                                 │
│                   ZMQ ◄──────► Ghost Network    │
│                       (share consensus)         │
│                                                 │
└─────────────────────────────────────────────────┘
```

### Components

- **Stratum Server** — Accepts miner connections (V1 and V2)
- **Share Processor** — Validates submitted shares
- **Template Manager** — Gets block templates from Ghost Core
- **Consensus Engine** — Participates in network share consensus
- **Payout Engine** — Calculates and distributes rewards

## Stratum Setup

Ghost Pool supports standard Stratum protocol, so any ASIC miner works out of the box.

### Miner Configuration

```bash
# Point your miner to your Ghost node

URL:      stratum+tcp://your-node-ip:3333
User:     bc1qYourBitcoinAddress.worker1
Password: x  (anything, not used)
```

### Worker Naming

The username format is: `address.workername`

- **address** — Your Bitcoin payout address (required)
- **workername** — Optional identifier for multiple miners

### Protocol Support

| Protocol | Port | Status |
| --- | --- | --- |
| Stratum V1 — hobby | 3333 | Supported |
| Stratum V1 — farm/rental | 4444 | Supported (public mining nodes) |
| Stratum V2 | 34255 | Supported |

:::warning Firewall Configuration
If running public mining, ensure ports 3333 and 4444 are open in your firewall. For private mining (only your own hardware), keep them closed. `reconcile-mining-firewall.sh` does this automatically from `mining_mode`, so a hand edit is only needed if you manage the firewall yourself.
:::

## Share System

Shares are proof of mining work. When a miner finds a hash that meets the pool difficulty, they submit a share.

### Share Validation

Every share must pass these checks:

1. Hash meets pool difficulty target
2. Derived from valid block template
3. Timestamp within 30 seconds
4. Node signature valid
5. Not a duplicate

### Share Difficulty

Pool difficulty auto-adjusts to target ~1 share/second per miner. This provides smooth progress tracking without overwhelming the network.

### Miner Shares vs Node Shares

Ghost has two types of shares:

- **Miner Shares** — Proof of hashrate work, reset each round
- **Node Shares** — Behavior-based rewards (0-15), persistent

Miner shares determine subsidy distribution. Node shares determine node reward pool distribution.

## Share Consensus

Ghost Pool nodes form a mesh network and reach Byzantine Fault Tolerant consensus on shares:

1. **Share Submission** — Miner submits share to their node. Node validates locally.
2. **Gossip Propagation** — Valid share is broadcast to all Ghost nodes via ZMQ.
3. **Independent Validation** — Each node validates the share independently.
4. **Merkle Commitment** — Nodes periodically commit share merkle roots to verify consistency.

### Byzantine Fault Tolerance

The system tolerates up to 33% malicious nodes. Key properties:

- **67% supermajority** required for critical decisions
- **Cryptographic proofs** prevent share forgery
- **Deterministic recompute, not median** — every validator recomputes the payout split from its own converged ledger and rejects a proposal that doesn't match (there is no "median of proposals" fallback)
- **Self-healing** through periodic state verification

## Payout Flow

When a block is found, payouts are calculated deterministically:

### 1% Pool Fee Split

```bash
Block Subsidy (e.g., 3.125 BTC)
├── 99% → Miners (shared by hashrate)
└── 1%  → Pool Fee
         ├── 0.5% → Treasury (until 21 BTC cap)
         └── 0.5% → Node Reward Pool
```

### Miner Payout Formula

```bash
miner_subsidy_share = (miner_shares / total_round_shares) × miner_pool

miner_pool = block_subsidy × 0.99

# If this miner's node found the block:
total_payout = miner_subsidy_share + 100% of TX fees
```

### Node Reward Formula

```bash
node_reward = (node_shares / total_network_shares) × node_reward_pool

node_reward_pool = block_subsidy × 0.005  (rising to 0.01 after decay)
```

:::info TX Fees Are Key
Transaction fees go 100% to the node that found the block — not split with the pool. This is why running your own node matters: when your miners find a block, you keep all the fees.
:::

## Block Found Flow

When a miner finds a block that meets Bitcoin network difficulty:

1. **Block Submission** — Node immediately submits block to Bitcoin network.
2. **BlockFound Broadcast** — Node broadcasts BlockFound message to all Ghost nodes.
3. **Round Freeze** — All nodes freeze their share ledgers for this round.
4. **Payout Proposals** — Each node calculates and broadcasts their payout proposal.
5. **Consensus Vote** — Nodes vote on proposals. 67% agreement required.
6. **Payout Transaction** — Finding node creates and broadcasts payout transaction.
7. **New Round** — All nodes reset share ledgers and begin new round.

Total time from block found to payout broadcast: typically <10 seconds.

## Configuration

Ghost Pool configuration lives in `/etc/ghost/pool.toml`. The authoritative schema is `crates/ghost-common/src/config.rs` — see that file for the full set of keys and defaults. Conceptual sketch:

```toml
# /etc/ghost/pool.toml (illustrative — not the full schema)

# Stratum Server
sv1_stratum_port = 3333    # SV1 (translator) — see SV1_STRATUM_PORT
sv2_stratum_port = 34255   # SV2 (SRI pool)   — see SV2_STRATUM_PORT

# Mesh networking (P2P consensus)
mesh_bind = "0.0.0.0:8555"

# Payout address used for this node's coinbase share
payout_address = "bc1qYourBitcoinAddress"
```

:::warning Illustrative Only
The keys above are conceptual. Do not copy this block verbatim — refer to `crates/ghost-common/src/config.rs` for actual key names, types, and defaults.
:::

### Public vs Private Mining

Control who can connect to your pool:

```bash
# Public mining (anyone can connect)
public_mining=1
stratum_bind=0.0.0.0:3333

# Private mining (only local miners)
public_mining=0
stratum_bind=127.0.0.1:3333
```

Public mining enables the +3 Public Mining share bonus but requires a public IP and open firewall on port 3333 (SV1) and/or 34255 (SV2).
