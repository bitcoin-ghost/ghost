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

## The one remaining gap (cross-elder vote)
The payout proposal is created correctly but does not yet reach a 4-elder quorum
in this containerised setup: HealthPings over the ZMQ PUB/SUB data plane aren't
delivered between containers, so peers age out of `get_connected_peers(60)` and
the encrypted broadcast reaches `peer_count=0`. The Noise point-to-point path
(used by the MPC ceremony) works; the PUB/SUB liveness does not. Closing this
(so the block is submitted and the coinbase pays) is the last step — likely the
same test-network/transport family as the private-IP discovery fix (PR #53).
