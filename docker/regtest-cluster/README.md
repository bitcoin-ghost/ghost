# Audit-cluster regtest dry-run

The pre-mainnet validation step from `tasks/plan_audit_cluster_deploy.md` §3:
**4 real `ghost-pool` binaries on a regtest chain, full mesh, the
`CLUSTER_ENFORCEMENT_HEIGHT` gate ON** — proving the audit-hardened binary
completes a real round end-to-end and behaves correctly across the gate, on real
sockets/Noise/ZMQ rather than the in-process harness.

> **Scope split (be honest about it).** The *adversarial* cases — a forged share,
> a deliberately-tampered payout split, an equivocating voter — are already
> proven by the in-process harness (`tests/integration_tests/mesh_cluster.rs`),
> which can inject those faults trivially. A cluster of *honest* real binaries
> cannot manufacture them without a byzantine build. So this regtest cluster's
> job is the part the harness can't cover: **the honest happy path + partition/
> convergence + the gate transition, on real transport.** For full adversarial
> coverage on real binaries, build one node from a `byzantine` branch (see §7).

---

## 1. Prerequisites
- Docker + Compose v2.
- Two images (built from this repo):
  - `bitcoin-ghost/ghostd:regtest` — the ghost-core fork.
  - `bitcoin-ghost/ghost-pool:regtest` — see §2.
- `bitcoin-cli` (or `docker exec`) to drive the chain.

## 2. Build the pool image (regtest, gate-low)
Two regtest-specific build choices:
- **No `--features zk-production`** — regtest needs no MPC params (the
  zk-production start-up guard is mainnet-only).
- **Lower `CLUSTER_ENFORCEMENT_HEIGHT`** so the gate actually fires on a short
  regtest chain (the mainnet default is a far-future placeholder). For the
  dry-run, set it to e.g. `100` in `bins/ghost-pool/src/lib.rs` before building
  — that lets you exercise BOTH sides of the gate (mine to <100 = enforcement
  off, mine past 100 = on). The image must also contain `bash` + `gettext`
  (`envsubst`) for the entrypoint.

```bash
# from repo root, in a regtest build context:
docker build -f docker/Dockerfile --target ghost-pool \
  --build-arg CARGO_FEATURES="" \
  -t bitcoin-ghost/ghost-pool:regtest .
```
(Confirm the Dockerfile's `ghost-pool` target accepts a features build-arg; if
not, build the binary locally `cargo build --release -p ghost-pool` and COPY it.)

## 3. Bring the cluster up (genesis-ordered)
```bash
cd docker/regtest-cluster
export TREASURY_ADDRESS=$(docker run --rm bitcoin-ghost/ghostd:regtest \
  bitcoin-cli -regtest -rpcuser=ghost -rpcpassword=ghostpass getnewaddress || echo bcrt1qSETME)

docker compose up -d bitcoind
# pool1 is the genesis node — start it, wait ~60s for genesis params, THEN the rest
docker compose up -d pool1
sleep 60
docker compose up -d pool2 pool3 pool4
```

## 4. Prime the chain past the gate
```bash
A=$(docker exec rc-bitcoind bitcoin-cli -regtest -rpcuser=ghost -rpcpassword=ghostpass getnewaddress)
docker exec rc-bitcoind bitcoin-cli -regtest -rpcuser=ghost -rpcpassword=ghostpass generatetoaddress 110 "$A"
# >100 ⇒ past CLUSTER_ENFORCEMENT_HEIGHT (if you set it to 100) ⇒ enforcement ON
```

## 5. Verify — the honest path + the gate (the core of the dry-run)
Each node exposes its HTTP API on the host: pool1 `:8080`, pool2 `:8081`,
pool3 `:8082`, pool4 `:8083`.

- **Mesh formed:** `curl -s localhost:8080/health` on each → 3 peers, `is_active`.
- **Shares replicate + ledgers agree:** drive shares through the translator (or
  the pool's share endpoint), then compare per-node share/work totals across
  `:8080..:8083` — they must match (this is GHOST-03 convergence keeping signed
  shares in sync).
- **Honest payout ratifies + pays:** when a block-difficulty share lands, watch
  the logs for a payout proposal reaching 67% and executing; confirm the
  coinbase pays the expected miners. **No `GHOST-02: rejecting payout proposal`
  on a legit block** — that log on an honest round is a FAIL.
- **Gate transition:** mine to a height *below* the gate and confirm an unsigned
  share (from a lagging node) is *accepted*; mine past it and confirm the same
  share is *dropped* (`GHOST-09: dropping share proof…`). This is the exact
  behaviour the rolling deploy relies on.

## 6. Verify — partition → convergence (GHOST-03 on real transport)
```bash
docker network disconnect regtest-cluster_default rc-pool3   # isolate pool3
# ... let pool1 ingest a share pool3 will miss ...
docker network connect regtest-cluster_default rc-pool3      # reconnect
# Within ~30s (the convergence interval) pool3's share ledger should catch up to
# the others — compare totals across nodes again. That's ShareConvergence live.
```

## 7. Adversarial coverage (optional, needs a byzantine node)
To exercise GHOST-09/02/11 *rejection* on real binaries, rebuild ONE node from a
throwaway branch that: signs shares with the wrong key (GHOST-09), proposes an
inflated split (GHOST-02), or double-votes (GHOST-11). Point pool4 at that image
and confirm pools 1-3 drop its shares / reject its proposal / ban it
fleet-wide. **The same three properties are already proven deterministically by
the in-process harness — this only re-confirms them over the wire.**

## 8. Teardown
```bash
docker compose down -v
```

## 9. Sign-off checklist (gates the mainnet deploy)
- [ ] Mesh of 4 forms; each node sees 3 peers.
- [ ] Signed shares replicate; per-node ledgers agree.
- [ ] An honest payout proposal ratifies and pays the right miners, post-gate.
- [ ] No spurious `GHOST-02` rejection on honest blocks.
- [ ] Below the gate an unsigned share is accepted; above it, dropped.
- [ ] A partitioned node backfills via convergence on reconnect.
- [ ] (If §7 run) a byzantine node's shares/proposal/votes are rejected + it's banned.

Only with every box ticked should the gated rolling deploy (`plan` §4) proceed.

---

### Status / caveats
This is a **scaffold** — the compose + configs + runbook are written from the
config schema and the deploy plan, **not yet run end-to-end here**. Expect to
tune: the Dockerfile features/COPY for the regtest binary, the exact share-
submission path (translator vs direct endpoint), and the mesh discovery timing.
File issues against this directory as you shake it out; the in-process harness
remains the deterministic source of truth for the consensus *logic*.
