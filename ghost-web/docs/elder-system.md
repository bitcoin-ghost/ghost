# Elder System

*The first 101 nodes to register become Elders — with permanent bonus rewards and recognition.*

## Overview

The Elder System rewards early adopters who help bootstrap the Ghost network. It's simple:

:::highlight 101
Elder slots — first come, first served
:::

Elders receive a permanent +1 share bonus in the node reward system. This bonus lasts forever, as long as you maintain your node.

:::info Why 101?
101 is enough to establish a robust initial network while remaining exclusive enough to reward true early adopters. It's also a prime number, which has a nice aesthetic quality.
:::

## Selection Process

Elder selection is **rolling** — slots fill continuously as nodes come online, not in a single event at launch:

1. **Node Registration** — You install Ghost Node and it generates a unique 32-byte Node ID. Generating a valid Node ID requires a **proof-of-work** (Sybil resistance — you can't cheaply mint thousands of identities).
2. **Promotion on registration** — Every time a node registers (or refreshes its health), the network runs an atomic promotion pass: while fewer than 101 Elders exist, eligible non-Elder nodes are promoted to fill the open slots.
3. **Ordering** — Promotion is by **Node ID ascending** (lowest Node IDs first), and only nodes that submitted a valid proof-of-work are eligible. The ordering is deterministic, so every node computes the same Elder set.
4. **Elder Assignment** — Positions are assigned in promotion order. Once 101 Elders are held simultaneously, no further promotions happen until a slot reopens (see [Revocation](#revocation)).

### Deterministic Selection

The selection is fully deterministic — all nodes derive the same Elder list from the same on-chain-anchored data. There's no central authority deciding who becomes an Elder.

### Rolling, Not One-Shot

Elder slots are filled as nodes arrive, up to the cap of 101. Today the network holds far fewer than 101 Elders, so any node presenting a valid proof-of-work is promoted immediately; Node ID ordering only breaks ties once more than 101 proof-of-work nodes compete for the remaining slots.

## Benefits

Elders receive a permanent +1 share in the node reward system:

| Share Type | Regular Node | Elder Node |
| --- | --- | --- |
| Archive Mode | +5 | +5 |
| Ghost Pay | +4 | +4 |
| Public Mining | +3 | +3 |
| Reaper | +2 | +2 |
| Elder Status | — | +1 |
| **Maximum Total** | **14** | **15** |

### Economic Impact

The +1 Elder share means ~7.1% more rewards compared to an identical non-Elder node (assuming max shares). Over time, this adds up significantly.

### Recognition

Elders are visible on the network dashboard with their rank (1-101). It's a permanent mark of being an early supporter.

## Requirements

To become an Elder, you must:

1. **Hold a slot** — Be promoted into one of the 101 slots. Promotion is by Node ID (lowest first) among proof-of-work-valid nodes; while the network is below the cap, any valid node is promoted immediately.
2. **Present a valid proof-of-work Node ID** — Elder eligibility requires the PoW-stamped Node ID (Sybil resistance).
3. **Stay online** — Maintain uptime after promotion, or risk revocation (see below).
4. **Run a valid node** — Full sync, passing health checks.

There's no payment, no application, no approval process. Run a valid node while slots remain and you're promoted automatically.

:::callout Current Status
Elder registration is open and rolling. The network currently holds well under the 101-Elder cap, so slots remain available for new operators who run a valid node. Check the [Network page](/pool.html) for the live Elder count and registry.
:::

## Revocation

Elder status can be **permanently lost** if you fail to maintain your node:

:::warning 7-Day Rule
If your Elder node is offline for **7 continuous days**, your Elder status is permanently revoked. No exceptions. No appeals.
:::

### How Revocation Works

1. Your node stops sending health pings
2. Other nodes track your downtime
3. After 7 days, any node can propose revocation
4. 67% of active nodes must witness/confirm
5. Revocation is recorded permanently

### Slots Reopen on Revocation

When an Elder is revoked, its slot **reopens**. The promotion pass runs continuously, so the next eligible node (lowest Node ID with a valid proof-of-work) is promoted into the freed slot. The cap stays at 101 — the network doesn't shrink permanently below it while eligible candidates exist.

- A revoked Elder loses its `is_elder` status and `elder_order`, and is recorded in the retired-nodes table for audit.
- If eligible non-Elder nodes are waiting, one is promoted into the vacated slot on the next registration pass.
- If no eligible candidate is online, the slot simply sits open until one registers.

### Why So Strict?

The 7-day rule ensures Elders are active participants, not just early claimers who abandon the network. It also creates urgency — if you want Elder status, you must commit to running infrastructure.

## FAQ

### Can I buy Elder status?

No. Elder status is non-transferable and non-purchasable. It's tied to a specific Node ID that you generate.

### What if I need to migrate my node?

You can migrate your node to new hardware as long as you preserve your Node ID and the keypair that signed your Elder registration. Back up your node's data directory (the SQLite database under `~/.ghost/` and any key material in your config). If you lose those keys, you lose your Elder status — there is no recovery path.

:::info "ghostnode.dat"
The dashboard UI sometimes refers to a `ghostnode.dat` label, but the node itself does not write a single file by that name. The authoritative state lives in the node's SQLite database and config directory.
:::

### Can I run multiple Elder nodes?

Technically yes, if you get multiple nodes promoted while slots remain. But each node requires separate infrastructure, its own proof-of-work Node ID, and must maintain uptime independently.

### What if I'm offline for 6 days?

You're fine. The rule is 7 *continuous* days. If you come back online after 6 days, the counter resets.

### How do I check my Elder status?

Your node dashboard shows your Elder status, rank, and current uptime. You can also check the [Network page](/pool.html) for the full Elder registry.

### Is Elder status really permanent?

Yes, barring revocation for the 7-day downtime rule. There's no expiration, no renewal, no governance vote that can remove you.
