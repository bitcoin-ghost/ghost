# Ghost Solo

Ghost Solo is a solo mining pool. No accounts, no sign-up, no KYC: a miner connects with its
Bitcoin address as its username, and when it finds a block, the block pays it directly, in the
coinbase. Nobody holds a miner's money, and there is no balance, ledger or payout queue.

It replaces the node pool's share chain (the design is archived on `feat/node-pool`, see
`NODE_POOL_SPEC.md` and `NODE_POOL_PLAN.md`).

## The payout rule

Every job a miner is given pays, in this order and nothing else:

1. **The treasury**, `bc1qgxg5ywk835c9fp6arz6d6x50xpk6y0ualt900k`: exactly `subsidy / 200`
   (0.5% of the block subsidy, rounded down; never any part of the fees).
2. **The miner**, at the address in its username: `subsidy - subsidy / 200 + every fee`.
3. **The witness commitment**, as the template provider hands it over.

At today's 3.125 BTC subsidy that is 1,562,500 sats to the treasury and 310,937,500 sats plus all
fees to the miner. The subsidy halves every 210,000 blocks on mainnet and signet and every 150 on
regtest. The coinbase scriptSig carries the BIP34 height, the pool tag (`- G H O S T -`) and the
extranonce; the node pool's `GHPP`/`GHNT` tags and `GHNP` commitment are gone.

The rule is code in one place, `ghost_common::solo` (`solo_outputs`, `check_solo_outputs`), used by
pool_sv2 to build every job and by `ghost-audit` to check one.

## Miners

- **Username**: `<address>` or `<address>.<worker>`. P2WPKH (`bc1q…`), P2TR (`bc1p…`), P2WSH and
  P2SH (`3…`) addresses are accepted; P2PKH (`1…`) is refused, as is a username with no address
  (`no-payout-address`, `payout-address-type-refused`). Password: anything.
- **Ports**: SV1 on **3333** (small miners: Bitaxe, NerdAxe; the lower starting difficulty) and
  **4444** (the farm tier: S19/S21-class and rented hashrate; the higher starting difficulty),
  both through the translator; SV2 on **34255** (pool_sv2 itself, Noise-authenticated).
- **Extended and standard SV2 channels** both work; each channel's coinbase pays that channel's
  own miner, so two miners on one connection are paid separately.

## What happens when a block is found

1. pool_sv2 submits the solution to the local template provider (ghost-mining), which submits the
   block to the local ghostd. This happens first, always: nothing is checked before it.
2. When `[solo] submit_rpc` lists other nodes, pool_sv2 asks the template provider for the
   template's transactions, assembles the whole block and sends it with `submitblock` to every
   listed node at once, in parallel. Each node's answer (`accepted`, `duplicate`, an error) is
   logged and kept with the block.
3. After submitting, the coinbase is checked against the rule on a thread of its own:
   `SOLO_COINBASE_MISMATCH` in the log is an alarm. It never holds a block back.
4. The block is recorded in `blocks-found.json` (height, hash, finder, worker, reward, check,
   submissions) and shows on the miner's page and the pool status.

## Two-node setup

Run two full nodes (ghostd + ghost-mining + pool_sv2 + translator), A and B. Each pool mines on its
own node and also sends every block it finds to the other, so a block reaches the network even if
its own node is slow or down:

```toml
# on node A, /etc/ghost/pool-config.toml
[solo]
network = "mainnet"
state_dir = "/var/lib/ghost/solo"
submit_rpc = ["http://<node B>:8332"]
submit_rpc_auth_file = "/etc/ghost/solo-submit-rpc.auth"   # mode 0600, owned by the pool's user
sv1_ports = [3333, 4444]
```

The credentials file holds `user:password` (for every listed node) or `http://host:port
user:password` lines; a Bitcoin Core `.cookie` file works as is. It may also be named by the
environment variable `GHOST_SOLO_SUBMIT_RPC_AUTH_FILE`. Credentials are never logged: nodes appear
in logs and in `/api/v1/pool/status` as `scheme://host:port`. Node B's `bitcoin.conf` must allow
A's address (`rpcallowip`) and bind its RPC on an interface A can reach; keep that link private
(a VPN or firewall rule), since the RPC password crosses it.

Node B is configured the same way, pointing at A.

## pool_sv2 configuration

`[solo]` is optional; without it the pool runs on mainnet, keeps statistics in memory and submits
to the local node only.

| Key | Default | Meaning |
|---|---|---|
| `network` | `mainnet` | `mainnet`, `signet` or `regtest`: the subsidy schedule, and the network miner addresses are checked against on the API |
| `state_dir` | none (memory) | where `miner-stats.json` and `blocks-found.json` are kept |
| `submit_rpc` | `[]` | other nodes' JSON-RPC URLs every found block is sent to |
| `submit_rpc_auth_file` | none | their credentials (see above) |
| `sv1_ports` | `[3333, 4444]` | the translator's ports, shown in the status |

An old `[node_pool]` section is ignored with a warning. The translator's `quantise_to_tiers` is off
by default and not needed.

## API

pool_sv2 serves, on its loopback monitoring listener, and ghost-mining forwards on its public API:

- `GET /api/v1/miner/{address}`: per address and per worker, hashrate over 15 minutes, 1 hour and
  24 hours; shares accepted, stale and rejected over 24 hours; last share; best share difficulty
  (ever and 24 hours); blocks found with the reward paid; and the mean time to a block at the
  address's hashrate (`network difficulty x 2^32 / hashrate`).
- `GET /api/v1/miner/{address}/history?window=24h|7d|30d`: the same as series.
- `GET /api/v1/pool/status`: network, Bitcoin tip and difficulty, connected miners and workers,
  pool hashrate, best share, blocks found, the fee policy, the ports with the SV2 authority public
  key miners pin (`ports.sv2_authority_public_key`), and each `submit_rpc` node with what the last
  reachability check found (`submit_nodes[]`: `node`, `reachable`, `last_checked_at`,
  `last_ok_at`, `height`, `error`; pool_sv2 asks each node `getblockchaininfo` every 60 s with a
  10 s timeout; credentials never appear).
- `GET /api/v1/pool/miners` (operator only): every payout address with an open channel or a share
  in the last 24 hours, with its online, idle and offline workers, hashrate, shares, best share and
  blocks found, the most hashrate first. It names miners, so ghost-mining serves it only to
  HMAC-signed requests (the dashboard's proxy signs them with `INTERNAL_AUTH_KEY`); unsigned it is
  `401`, and the website proxy never forwards it.

The JSON of each is documented in `bins/pool-sv2/src/lib/solo_api.rs`. The website shows each
node's SV2 key from its live status, and `ghost-web/pool-nodes.json`'s key only when a node does
not report one. `/api/v1/node-pool/status`
still answers, as an alias of `/api/v1/pool/status`; the ledger routes answer `410 Gone`.

## Checking a node

`ghost-audit check --sv1 <host>:3333 --address <your address>` connects as a miner, takes a few
jobs, submits nothing, and checks that each job's coinbase pays the treasury exactly
`subsidy / 200` and your address the rest, with nothing else. `--sv2 <host>:34255
--authority-key <key>` checks the SV2 port the same way. Exit 0 is a pass, 1 a fail.

## End-to-end test

`scripts/regtest-solo/run.sh` (CI workflow `Solo e2e`, `.github/workflows/solo-e2e.yml`) runs two
peered regtest nodes, each the released ghostd + ghost-mining + pool_sv2 (`[solo] submit_rpc` =
the other node) + translator, with miners on 3333, 4444 and SV2 34255 under different addresses.
It checks every pool block's coinbase against the rule (fees included, across regtest's halving at
150), that each block reached both nodes, the three API routes, a pool_sv2 killed while the other
keeps mining, `ghost-audit check` passing an honest node and refusing a hostile build
(`--features solo-fault-injection`, `GHOST_SOLO_FAULT=skim-treasury`), and a stopped submit node
reported unreachable. `run.sh --fetch-ghostd` fetches and verifies ghostd; `run.sh --build` builds
the rest.
