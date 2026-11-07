# Ghost Solo: work in progress

Running note for the solo pivot on `ghost-solo` (branched from `feat/node-pool` at fb687f804).
No local builds: verified through GitHub CI only (`gh workflow run ci.yml --ref ghost-solo`).
The product is described in `SOLO.md`.

## Done (code written, CI iterating)
- `ghost_common::solo`: treasury script, halving/subsidy, `solo_outputs`, `check_solo_outputs`,
  `SoloNetwork`, payee classes, the 0x4748 TLV constants, coinbase/reserve constants.
- Deleted: ghost-common canonical_payout, share_commit, anchor_chain, slot_class_sensing,
  node_pool_constants, node_pool_genesis_export, node_pool_network, node_pool_u256;
  `crates/ghost-np-relay`; `fuzz/` (its only target was the relay wire); ghost-storage
  `node_pool_{store,views,genesis}`; pool_sv2 node_pool*, tier_binding, held-tip and genesis
  import (`--np-import-genesis` flags), monitoring slot_class fields.
- pool_sv2: `solo.rs` (per-channel solo outputs, post-submit alarm, found blocks, multi-node
  submit via RequestTransactionData), `submit_rpc.rs`, `blocks_found.rs`, `solo_api.rs`
  (`/api/v1/miner/{address}`, `/history`, `/api/v1/pool/status`), `[solo]` config, best share in
  `miner_stats.rs`, tests `solo_tests.rs`, `solo_api_tests.rs`, `tests/solo_jobs.rs`,
  `tests/installer_config.rs`.
- ghost-audit reduced to `ghost-audit check --sv1/--sv2`.
- ghost-mining: payee_class/block_limits/template on `ghost_common::solo`; relay-peers monitor
  no longer started. ghost-verification forwards the new routes (`/api/v1/node-pool/status`
  kept as an alias; ledger routes 410). ghost-cli `node status` reads `/pool/status`.
- Integration harness starts pools with `[solo]` only.
- Translator: `quantise_to_tiers` off in `config/sri/translator-config.toml`;
  `config/sri/pool-config.toml` has `[solo]` instead of `[node_pool]`.

## pool_sv2 `[solo]` keys (settled; for the installer)

All optional; `[node_pool]` / `[node_pool.relay]` are ignored (warning) and should be dropped.

```toml
[solo]
network = "mainnet"                 # mainnet | signet | regtest (default mainnet) -- WRITE IT
state_dir = "/var/lib/ghost/solo"   # miner-stats.json + blocks-found.json (unset = memory only)
submit_rpc = ["http://10.0.0.2:8332"]   # other nodes' JSON-RPC URLs; default []
submit_rpc_auth_file = "/etc/ghost/solo-submit-rpc.auth"  # else env GHOST_SOLO_SUBMIT_RPC_AUTH_FILE
sv1_ports = [3333, 4444]            # shown by /api/v1/pool/status; default [3333, 4444]
```

Credentials file (read at start; unreadable file with submit_rpc set = pool refuses to start;
mode 0600, readable by the pool's user). One entry a line, `#` comments and blank lines ignored:

```text
http://10.0.0.2:8332 user:password   # this endpoint only (matched on scheme://host:port)
user:password                         # every endpoint without its own line
```

A Bitcoin Core `.cookie` (`__cookie__:<hex>`) is valid as is. A URL may also embed
`http://user:pass@host:port`. Credentials are never logged. `coinbase_reward_script` is still a
required top-level key (used only for the internal group channel; any valid address).

Miner refusal codes changed: `no-payout-address`, `payout-address-type-refused` (were
`node-pool-no-payee`, `node-pool-payee-script-refused`). The translator's `quantise_to_tiers`
should be `false`: **installer worker, flip `scripts/install-node.sh` (~line 1892) AND
`config/sri/translator-config.toml` to `quantise_to_tiers = false` in the same commit**
(`check-stratum-config-agreement.sh` fails if they differ; the reference is left `true` until
then so CI stays green).

`bins/pool-sv2/tests/installer_config.rs` still renders the installer's pool config through
`NODE_POOL_FUNCTIONS` / `np_network_defaults` / `np_render_pool_config` / `np_fee_address_check`;
if those are renamed, update that test with them.

## Status
- Rust core: CI run 42393399054 on 96fbfcbc, all 11 jobs success (Format, Clippy, Docs, MSRV,
  Unused deps, Security Audit, Test ubuntu/macos, Integration tests, SV2 integration, Coverage).
- Dormant, left in place: ghost-mining `alert_monitors::spawn_relay_peers_monitor` (not started),
  ghost-verification `/api/v1/node-pool/node-list` + `node_list_path`, ghost-common
  `coinbase_tags` GHPP/GHNT (ghost-mining still emits placeholder slots; pool_sv2 strips them),
  `docs/node-pool-reference/`, np_* migrations (by instruction), translator agent TLV sending and
  `quantise_to_tiers` branch, stale "node pool" comments in the translator.

## Website, proxy and dashboard (Ghost Pool)
- `ghost-web/` rebuilt as Ghost Pool: `index.html` (what it is, the payout rule worked at 3.125 BTC,
  the connect box for both nodes, live stats and blocks found), `connect.html` (Bitaxe/AxeOS,
  Avalon, Antminer, Braiins OS, SV2 with the authority key; primary + backup), `miner.html` +
  `miner.js` (asks every node, adds the answers up, odds from network difficulty x 2^32 / hashrate),
  `faq.html`, `run-a-node.html` (the installer, short), `security.html`, `404.html`. Shared code in
  `pool.js`; the nodes in `pool-nodes.json` (id, name, stratum host, SV2 authority key).
  Removed: pool/nodes/miners/endpoints/downloads pages, `node-pool.js`, `node-list.json`, `docs/`
  (node pool, Haze, Shroud, Reaper, buds, ...), `vendor/three`.
- **To fill in before the site goes live**: `ghost-web/pool-nodes.json` has placeholder stratum
  hosts `pool-a.bitcoinghost.org` / `pool-b.bitcoinghost.org` and no authority keys (the page then
  says the key is not published); the proxy's `/etc/ghost/site-proxy-nodes.json` needs the two
  nodes' public IPs (`scripts/website-proxy/site-proxy-nodes.example.json`).
- `scripts/website-proxy/ghost-site-proxy.py`: a static node list from `--nodes` (read once at
  start; a bad file refuses to start), nodes addressed by id (`/api/pool/<id>/...`), routes
  `/api/v1/pool/status`, `/api/v1/miner/<addr>`, `/api/v1/miner/<addr>/history`; per-node status
  cache; the old first-node `/api/v1/node-pool/status` location is gone (nginx conf updated).
- `dashboard/`: overview, miners (lookup + listed addresses), miner detail, blocks found and
  read-only pool settings from the solo API (`src/lib/api/pool.ts`, `src/lib/pool/view.ts`,
  `src/components/pool/`); share chain page, ledger/sensing/slot-class/genesis types removed;
  relay peers removed from the network page and vitals overlay. Node pages (Zero-Sync, Haze,
  mempool, ...) kept. New CI job **Dashboard** (tsc, lint, `npm test`, `next build`).
- Tests: `scripts/check-miner-page.sh` runs `scripts/web-tests/pool-site.test.js` (10) and
  `miner-page.test.js` (11); proxy `test_ghost_site_proxy.py` (16); dashboard `npm test` 30
  (16 in `tests/pool-pages.test.js`).
- **Pending**: `scripts/frontend-proof/` still drives the node pool regtest harness
  (`scripts/regtest-node-pool/harness.py`, share chain, lister/merge, the old pages). It is not run
  by CI and has not been ported; it needs a solo regtest harness first.
- **API gaps** seen from the front ends: `/api/v1/pool/status` counts connected addresses but does
  not name them, so the dashboard's miner list can only show block finders and looked-up
  addresses; nothing reports whether the other submit node is reachable now (only what it said to
  the last found block); the SV2 authority key is not in the status, so the website's
  `pool-nodes.json` carries it by hand.
