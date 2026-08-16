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
   the internal API is **localhost-only** (cross-container POSTs get `403`; on
   regtest no `internal_api_secret` is needed, the dev-mode insecure path admits
   loopback). pool_sv2's listener is then reachable at the pool's own IP:34256.
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

⚠ Still open here: the **MPC elder ceremony** reports `not adequately meshed to
contribute (connected to 1/3 elders)`. That is a different quorum from the payout BFT
one above, and whether it blocks block submission on regtest (where the template
comment says no MPC params are needed) has not been established.
