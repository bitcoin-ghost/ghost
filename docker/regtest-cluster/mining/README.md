# Driving a real share → block → payout through the regtest cluster

The full mining stack works end-to-end against the local cluster. Topology:

    sv1_miner.py (SV1) → translator_sv2 (:3333) → pool_sv2 (:34256) → ghost-pool TDP (:8442)

## What works (verified 2026-06-20, real binaries)
1. **Enable TDP on the genesis pool**: start ghost-pool with
   `--tdp-enabled --tdp-port 8442`. It logs `TDP authority public key: <key>` —
   put that in `pool-sv2.toml` under `[template_provider_type.Sv2Tp].public_key`.
2. **pool_sv2** (`pool-sv2.toml.example`): connects to the pool's TDP, listens
   SV2 on `34256`, and POSTs shares to `/api/internal/shares`.
   **Run it inside the pool's network namespace** (`docker run
   --network container:rc-pool1 …`) so the webhook + TDP calls are loopback —
   the share webhook requires loopback **and** an HMAC (H-13), so cross-container
   POSTs get `403`. On regtest no `internal_api_secret` is set, so the dev-mode
   insecure path admits an unsigned loopback POST and `[share_webhook] secret`
   is ignored — it still has to be present, because the field is mandatory and a
   config without it will not parse. On mainnet the two must be equal.
   pool_sv2's listener is then reachable at the pool's own IP:34256.
3. **translator_sv2** (`translator.toml.example`): upstream = the pool's IP:34256,
   serves SV1 on `:3333`. Use `aggregate_channels = false` so the SV1 authorize
   username (a `bcrt1…addr.worker`) flows through as the payout identity.
4. **sv1_miner.py** `<host> <port> <bcrt1addr>.w1`: a ~80-line CPU miner.
   Three SV1 gotchas it gets right (each one cost a debugging round):
   - handle **`mining.set_extranonce`** (the real 16-byte extranonce1 arrives
     after the channel opens, *not* in the subscribe reply);
   - submit the **nonce big-endian** (`f"{nonce:08x}"`) even though the header
     uses it little-endian;
   - mine to the **pool share target** (`diff1/diff // 256`), not the trivial
     regtest network target.

   This yields `submit -> result=True`, pool_sv2 logs `💰 Block Found`, ghost-pool
   records the share, fires the **block-found callback**, and **creates a payout
   proposal** (correct miner + amount) and submits it to BFT consensus.

## ✅ The cross-elder vote gap is CLOSED (2026-08-15)

> **The section that used to sit here said the payout proposal "does not yet reach a
> 4-elder quorum" because HealthPings were not delivered between containers, so peers
> aged out of `get_connected_peers(60)` and encrypted broadcast reached `peer_count=0`.
> That is no longer true, and leaving it standing would repeat the mistake the
> private-IP note in `../README.md` already made: a stale blocker is why nobody re-ran
> the cluster for two months.**

Measured 2026-08-15 with a v1.11.22 binary: all four nodes mesh at **`peer_count: 3`**,
21k mesh messages validated over two hours with **0 bad signatures**, and the payout
path logs **`Checkpoint reached BFT quorum height=92 votes=3`**.

The liveness never needed a transport fix. It was four faults in this directory's own
config — a partially-populated `[ghost_pay]` table, a renamed `public_mining` key, a
hostname `public_address` where an IP is required, and a socat sidecar the README
prescribed but nothing implemented. See `../README.md` for the full list.

**So the full chain is now reachable**, and driving it is the outstanding work:

    sv1_miner.py → share → block found → payout proposal → BFT quorum ✅
      → verified coinbase commitment → block submitted → 100 blocks maturity
      → `ShardRuntime::settle_matured` observes the coinbase and discharges `owed`

That last hop is the one thing the shard's settlement path has **never** done against a
real chain. `bins/ghost-pool/tests/regtest_shard_settlement.rs` covers the RPC round
trip, block-hash byte order and maturity arithmetic, but explicitly not "a block the
POOL mined pays what the shard says it should" — because that needed quorum, which is
this cluster's job and is now possible.

## Driven end to end 2026-08-16 — two blockers found, both new

The whole stack was brought up and a block **was** mined by the pool. Two things stop it
reaching a payout, and neither is the PUB/SUB liveness the old text blamed.

Topology that worked (all in pool1's netns so the internal API stays loopback):

```bash
# pool1 needs EXTRA_ARGS: "--tdp-enabled --tdp-port 8442" in docker-compose.yml
docker run -d --name rc-poolsv2   --network container:rc-pool1 -v …/pool_sv2:/usr/local/bin/pool_sv2:ro       -v …/pool-sv2.toml:/etc/pool-sv2.toml:ro     --entrypoint /usr/local/bin/pool_sv2     bitcoin-ghost/ghost-pool:regtest -c /etc/pool-sv2.toml
docker run -d --name rc-translator --network container:rc-pool1 -v …/translator_sv2:/usr/local/bin/translator_sv2:ro -v …/translator.toml:/etc/translator.toml:ro --entrypoint /usr/local/bin/translator_sv2 bitcoin-ghost/ghost-pool:regtest -c /etc/translator.toml
docker run -d --name rc-miner      --network container:rc-pool1 -v …/sv1_miner.py:/miner.py:ro python:3.11-slim python3 /miner.py 127.0.0.1 3333 "<bcrt1addr>.w1"
```

⚠ Use a ghost-pool built **without** `--features zk-production`. The production binary
refuses to start on regtest: `Trusted-setup verification is unconfigured: neither
ZK_PARAMS_HASH nor ZK_GENESIS_PARAMS_HASH is set`.

Confirmed working: TDP handshake, templates flowing, `💰 Block Found`, the share webhook
firing with the correct payout address, and the payout proposal being built and stored.

### Blocker 1 — every regtest share is worth ZERO micro-work

`get_top_unpaid_miners` sums `CAST(ROUND(work * 1000000) AS INTEGER)` **per row**. A
regtest share has `work = 2.33e-7`, i.e. `0.233` micro-work, which rounds to **0**. So a
miner can submit valid shares indefinitely and remain unpayable, and the proposal fails:

    M-04: Payout cross-check failed: miners(0) + nodes(0) + treasury(50000000)
          = 50000000 != expected 5000000000

Only treasury's 1% is allocated; the 99% has no one to go to. Raising share difficulty
~4,300× fixes the arithmetic but makes the CPU miner take hours per share. For a
settlement rehearsal (where the share path is not what is under test) seed the ledger
instead — 20 rows at `work = 0.01` gives 200,000 micro-work and the proposal then reports
`miner_count=1`.

⚠ Note the interaction: on regtest `share_target` is HARDER than `net_target`, so **every
share is a block**. You cannot accumulate work by mining; the first block always precedes
any payable history.

### Blocker 0 (FIXED) — recreating a container silently reset the node

The pool services had **no volume at `/root/.ghost`**, which is where a node actually
writes its identity, database and MPC contributions (`key_path`/`db_path` in
`pool.template.toml` are not honoured for generation). Any
`docker compose up --force-recreate <node>` therefore gave that node a new id, an empty
database and zero contributions — and doing it to the genesis node collapses the elder
set, which presents as Blocker 2 below and reads exactly like a consensus bug.

Measured 2026-08-16: after three recreates of pool1 (adding TDP flags, swapping binaries)
it held **1** contribution while pool2–4 still held **4**. Fixed by per-node named volumes;
verified by recreating pool1 and confirming it kept node id `75f73cdd` and `MPC Elder #1`.

### Blocker 2 — MPC contributions are REJECTED, so only one elder ever exists

    CRIT-CONS-2: Cannot create voting session: BFT requires at least 3 eligible voters
                 round_id=21 voters=1 required=3
    Failed to create voting session from MPC elders: have=1, need=3

Payout-proposal voting draws voters from the **MPC elder set** — the set of ACCEPTED
contributions, which is not the same as the `Registered N elders` peer registry (that one
reports 4 while voting still sees 1).

Rebuilt clean on 2026-08-16 with state persistence in place, the ceremony still stalls:

- pool1 takes position 1 via `MPC genesis: Auto-applying first contribution (no existing
  contributors to vote)` and becomes Elder #1;
- pool2–4 **do** build and broadcast contributions for position 2 — Noise works,
  `MPC contribution broadcast via Noise sent=3`, and pool1 logs
  `Received MPC contribution position=2` from each;
- pool1 then **rejects every one**: `Cast MPC verification vote position=2 approve=false`,
  i.e. `verify_contribution` returned false (or a classified error) in
  `crates/ghost-consensus/src/mpc_handler.rs`.

So `mpc_contributions` stays at 1 on all four nodes, the elder set never grows, and

    CRIT-CONS-2: Cannot create voting session: BFT requires at least 3 eligible voters
                 round_id=4 voters=1 required=3

⚠ **Unresolved: why verification fails.** The rejection reason is not logged even at
`ghost_consensus::mpc_handler=debug`. Worth checking whether the multi-circuit genesis
(`circuits="note_spend + payout + unshield"`) is being verified against `note_spend`
alone. Mainnet holds 8 accepted contributions, so this path has worked somewhere — a
fresh-cluster-only failure is the likeliest reading, but that is a hypothesis, not a
finding.

**This is the last mile for the settlement rehearsal.** Until the cluster can seat three
elders, no pool-mined block can be submitted, so nothing matures and
`ShardRuntime::settle_matured` cannot be exercised against a pool-won coinbase.
