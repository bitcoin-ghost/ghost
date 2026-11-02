# The node pool

*A Bitcoin mining pool with no operator. Anyone can run a node, or point a miner at someone else's node. A light share chain decides who is owed what, and every block the pool finds pays miners straight from its coinbase. Nobody holds miners' money.*

:::warning Not ready
The node pool has never found a block and has never made a payout. None of it has run on signet or mainnet yet: it must pass regtest and our own signet first. No share-chain genesis is published for mainnet or signet, so a node cannot start on either. Read [Before you mine](#honest-reading) before pointing any hardware at it.
:::

## In one paragraph

Each node runs a Bitcoin node and a Stratum pool. Miners connect to any node and mine with their payout address as their username. The larger shares they find are passed between nodes and form a share chain; the chain with the most work wins, so every node arrives at the same balances without votes, signatures or a roster. When any node's miner finds a Bitcoin block, the coinbase pays the miners the ledger says are owed, exactly. The block's transaction fees go to the node whose miner found it.

## How money moves in a block

- **0.5% of the subsidy goes to the treasury.**
- **The other 99.5% pays miners' ledger balances exactly**, up to 500 outputs, minimum payout 1,000 sats: half the slots go to the oldest balances, half to the largest. Nobody is paid more than they are owed. Any amount a block cannot pay out goes to the treasury.
- **All transaction fees go to the node whose miner found the block**, at that node's fee address.

At today's subsidy that is 312,500,000 sats: 1,562,500 to the treasury and 310,937,500 to miners. At current fees miners keep about 98.95% of the total block value.

The treasury address is a fixed protocol constant. It has not been published yet.

The details are on [The payout rule](#payouts).

## How it works, start to finish

1. **Connect.** A miner connects to any listed node, or to its own. Its username is its payout address. Only P2SH, P2WPKH, P2WSH and P2TR addresses work.
2. **Get a job.** The node builds a coinbase that every other node can recompute: treasury, then the owed miners in a fixed order, then the finder, then the commitments. The node picks the transactions; it cannot pick the miner payouts. The job carries a tag saying who this share credits and how many outputs the job holds.
3. **Mine.** The miner hashes as it would on any pool. Its firmware sees ordinary coinbase bytes.
4. **Share.** A share above the network tier goes to all nodes. Any node checks it alone: the work, the coinbase, the tag and the payouts. A share with wrong payouts earns nothing, so a block that doesn't pay the ledger earns no credit.
5. **Anchor.** About every 54 seconds a share 256 times harder than the network tier becomes an anchor and locks in a batch of recent shares. Jobs refresh within about 2 seconds of each anchor. If two anchors compete, the one with the most work wins and the loser's shares are included again later.
6. **Credit.** Each share credits sats at once, worked out from its own difficulty. Every node reaches the same balance because it runs the same arithmetic on the same chain.
7. **Block found.** A block's outputs come from the balance table as it stood 20 blocks earlier, so a reorg of the share chain can't change what the block should pay.
8. **Settle.** Nodes see the block and retire what it paid. The block records which anchor it built on, so any node can check it from Bitcoin plus the share chain. Coinbase outputs can be spent after 100 confirmations, as usual.
9. **Verify.** `ghost-audit` will let a miner check that their node really credited them. It is not built yet; until it is, a miner is trusting the node it mines on. See [Auditing your node](#ghost-audit).

## What is gone

The node pool replaces the old Ghost network. Node rewards, elders, capabilities, votes, payout checkpoints, solo and private mining modes, job declaration, the L2, Ghost Pay, Wraith and Ghost Tap are all removed. Nodes do not earn a share of block rewards for running; a node's income is the transaction fees of the blocks its own miners find.

The old 8-node network keeps running beside the node pool until a handover. The two share nothing. Balances owed on the old network are carried over into the node pool's starting ledger at the handover; the conversion rate and the handover height have not been set.

## Running a node

Anyone can run a node without asking. Install it with the one-line installer: see [Deployment](#deployment). In short:

- You need a **fee address** (`--fee-address`, P2SH, P2WPKH, P2WSH or P2TR). Every transaction fee of every block your node's miners find is paid to it. It is not how miners are paid: miners are paid from the subsidy, by the ledger, at the address they mine with.
- The node talks to other nodes over the **share-chain relay** on port 8566. Give it relay peers with `--relay-peer host:port`, or wait for others to dial it.
- **No node pool release has been published yet**, and the installer refuses to run without `GHOST_VERSION` naming one. Every release published so far belongs to the old network.
- **No share-chain genesis is published for mainnet or signet.** Until one is, the pool refuses to start on those networks. Regtest works for testing.
- Never run a node pool node on the same server as an old-network node: they use the same unit names, paths and ports.

A node earns nothing for being up. What it gets is the transaction fees of blocks its own miners find, so a node with no miners earns nothing.

### Being listed

Membership is open: no roster, no approval, no signed list. Any node with a valid advert that passes an outside probe will be listed on [the node list](/endpoints.html). The listing service is not built yet; the page shows a placeholder until it is.

## Pointing a miner

See [Mining on the node pool](#mining). In short: `stratum+tcp://<node>:3333` for SV1, or SV2 on port 34255, with `<your payout address>.<worker>` as the username.

## Where to read more

| Page | What it covers |
|---|---|
| [Mining on the node pool](#mining) | Connecting a miner, firmware limits, the sensing loop |
| [The payout rule](#payouts) | Who gets paid, in what order, and how much |
| [Auditing your node](#ghost-audit) | `ghost-audit`, which is coming |
| [Before you mine](#honest-reading) | What has and hasn't been proven, and how long waits are |
| [Deployment](#deployment) | Installing and running a node |
| [`NODE_POOL_SPEC.md`](https://github.com/bitcoin-ghost/ghost/blob/main/docs/NODE_POOL_SPEC.md) | The full specification |
