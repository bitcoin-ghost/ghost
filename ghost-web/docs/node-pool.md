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
9. **Verify.** `ghost-audit` lets a miner check that every job their node sends pays the canonical coinbase and credits them. It is built but not released yet; without it, a miner is trusting the node it mines on. See [Auditing your node](#ghost-audit).

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

Membership is open: no roster, no approval, no signed list, no key. Any node with a valid advert that passes an outside probe is listed on [the node list](/endpoints.html), and nothing else decides it. The list, and the A/AAAA records behind the pool's DNS name, are generated by `ghost-audit list`; nobody edits them by hand. No lister is running yet, so the list is empty.

How a node gets listed:

1. **Be found.** The lister crawls the relays' own address gossip, starting from a few relays it is given. Your node is found once any relay it reaches knows your relay address, which happens as soon as your node dials a peer or a peer dials it. Only literal, publicly routable IP addresses are followed; host names are never resolved.
2. **Advertise your stratum ports.** Your relay port (8566) tells anyone who asks which ports you serve miners on: `advertise_sv1_port` in `[node_pool.relay]` of `/etc/ghost/pool-config.toml` (the installer writes 3333), and SV2 on pool_sv2's own port with its authority key. Ports only: the lister always uses the IP it reached your relay at. A node that advertises no SV1 port cannot be probed and is never listed.
3. **Pass the probe.** Every round (10 minutes by default) the lister connects to your SV1 port like a miner, with its own payout address, takes jobs and checks each one with the same checks as `ghost-audit`: the coinbase pays the canonical outputs and the share tag credits the probe's address. It never submits a share.
4. **Keep passing.** A node is listed after **3 passing probes out of its last 6**, the latest a pass, with **no failed probe** among the 6. It is taken off after **3 probes in a row that did not pass**, or **at once after a failed one**. After being taken off, only passes since then count. A probe that could not measure a node (port closed, too few jobs, the lister's share chain not caught up) is *unmeasured*: it never counts as a pass and never as a failure on its own.

Ports must be open from outside: relay 8566, SV1 3333, and SV2 34255 if you serve it. The DNS records include only listed nodes on SV1 port 3333, since a DNS name carries an address and not a port.

Being listed means a node passed the probe. It does not mean the node is honest with every miner; a miner who doesn't run `ghost-audit` against their own node is trusting it. See [Auditing your node](#ghost-audit).

**Running a lister.** Anyone can run one; nothing makes one list more official than another's. It needs a Bitcoin node and relay peers, like `ghost-audit audit`:

```
ghost-audit list --network signet --genesis-anchor <hex> --genesis-height <h> \
  --relay-peer <host:8566> --rpc-user <user> --rpc-password <pass> \
  --address <a payout address for the probes> \
  --out-json /var/www/node-list.json --out-dns /var/lib/ghost-audit/pool.zone
```

Flags set the policy (`--list-after`, `--window`, `--delist-after`, `--delist-after-fail`), the round interval (`--interval`), discovery limits (`--max-candidates` 1,024, `--max-per-ip` 2, `--max-crawl` 256) and the DNS fragment (`--dns-name`, `--dns-ttl`, `--dns-sv1-port`, `--dns-max`). `--once` runs one round and exits. State is kept in `list-state.json` in the data directory, so a restart keeps each node's history.

**`node-list.json`** (schema `ghost-audit/node-list/v1`): `generated_at` (RFC 3339) and `generated_at_unix`, `network`, `genesis_anchor`, the `policy` applied, the number of `candidates` and `listed` nodes, and `nodes`, sorted by relay address. Each node has `relay`, `host`, `relay_port`; `sv1` (a `stratum+tcp://` URL) and `sv1_port`; `sv2`, `sv2_port` and `sv2_authority_key` (null when not served); `node_id` (from its job stamps), `user_agent` and `protocol_version` (from its relay); `region` (always null: nothing measured says where a node is); `listed_since`, `last_probe`, `last_verdict`, the last probe's `reasons`; and `recent`, the counts of `pass`, `fail` and `unmeasured` probes in the window with the `pass_rate`.

**The DNS fragment** is zone-file lines, one per listed IP, sorted: `pool 300 IN A 203.0.113.5` (AAAA for IPv6), after comment lines saying when it was generated and how many nodes it holds. It is a file only; the lister never calls a DNS provider. An empty fragment means no listed node, and publishing it would leave the name with no address.

## Pointing a miner

See [Mining on the node pool](#mining). In short: `stratum+tcp://<node>:3333` for SV1, or SV2 on port 34255, with `<your payout address>.<worker>` as the username.

## Where to read more

| Page | What it covers |
|---|---|
| [Mining on the node pool](#mining) | Connecting a miner, firmware limits, the sensing loop |
| [The payout rule](#payouts) | Who gets paid, in what order, and how much |
| [Auditing your node](#ghost-audit) | `ghost-audit`: what it checks and how to run it |
| [Before you mine](#honest-reading) | What has and hasn't been proven, and how long waits are |
| [Deployment](#deployment) | Installing and running a node |
| [`NODE_POOL_SPEC.md`](https://github.com/bitcoin-ghost/ghost/blob/main/docs/NODE_POOL_SPEC.md) | The full specification |
