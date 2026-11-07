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
- **Pending**: `scripts/frontend-proof/` drove the node pool regtest harness (share chain,
  lister/merge, the old pages); it now refuses to run (exit 2, `FRONTEND_PROOF_FORCE=1` overrides)
  until it is ported to `scripts/regtest-solo/` and the new pages.
- API gaps: closed, see "API gaps closed" below.

## Installer (Ghost Pool)
- `scripts/install-node.sh` is the Ghost Pool installer: `[solo]` rendered by
  `np_render_pool_config`; `--peer-node <host>` (addnode, found-block target `http://host:8332`,
  rpcallowip/rpcbind, ufw 8332 from that address only), `--submit-node`, `--submit-auth` /
  `GHOST_SUBMIT_AUTH` (root-only `/etc/ghost/solo-submit-rpc.auth`), `--reaper` (off by default,
  `-ghostreaper=disabled`); relay, genesis, lister and fee-address flags gone (the fee/payout
  address flags are accepted and ignored). A re-run or `--uninstall` removes an older install's
  lister. `np_fee_address_check` is now `np_payout_address_check`. User-facing text says
  "Ghost Pool".
- `quantise_to_tiers = false` in both the installer and `config/sri/translator-config.toml`.
- Block reserve: `ghost_common::solo::MAX_COINBASE_BYTES` 22,000 -> 1,000 and
  `BLOCK_RESERVED_WEIGHT` 90,000 -> 8,000 (Core's default); the installer writes
  `blockreservedweight=8000`. The largest solo coinbase as ghost-mining counts it is 284 B
  (42 fixed + 112 scriptSig with a 20-byte extranonce + 9 + 47 commitment + 31 treasury + 43
  P2TR/P2WSH miner); 1,000 leaves room for two 92-byte OP_RETURN outputs with ~2x margin, and
  1,000*4 + 36 + 85*4 = 4,376 WU <= 8,000 (compile-time asserts in solo.rs). Fee transactions
  get 82,000 WU (~2%) more of every block. Existing nodes keep 90,000 until re-installed
  (harmless: ghost-mining only trims when the reserve is too small).
- Tests: test-installer-node-pool.sh (348), -reserve (28), -uninstall (87), -lister (23, now the
  lister's absence and clean-up), test-auto-update-swap.sh section E (/health block_height),
  `bins/pool-sv2/tests/installer_config.rs` (renders [solo], one- and two-node).
- CI run 42415953502 on ff6ba0f8, all 12 jobs success.
- Left for the website worker: `ghost-web/docs/deployment.md` (if it still exists) mentioned
  `blockreservedweight=90000` and `--fee-address`.

## API gaps closed (pool_sv2, ghost-mining, dashboard, website)
- `GET /api/v1/pool/miners` (pool_sv2 loopback API; ghost-mining forwards it on the
  HMAC-authenticated internal router only, so unsigned = 401; the website proxy's allow-list is
  unchanged and its test now also refuses `/api/v1/pool/miners`): every payout address with an open
  channel or a share in 24 h, `{address, connected, workers, online, idle, offline, hashrate_hs,
  shares_24h, last_share_at, best_share, blocks_found}`, most hashrate first.
- `/api/v1/pool/status` `submit_nodes[]` is now objects `{node, reachable, last_checked_at,
  last_ok_at, height, error}` from a background `getblockchaininfo` every 60 s (10 s timeout,
  `submit_rpc.rs` `spawn_health_checks`; reachability changes are logged); `reachable` is null
  before the first check. `ports.sv2_authority_public_key` is the key miners pin.
- Dashboard: miners page lists the active addresses from `/api/v1/pool/miners` (finders and
  looked-up addresses not active are a second table); overview shows each other node's
  reachability (a health warning when one is down) and the SV2 key; settings shows the key. Old
  string `submit_nodes` are still read (`submitNodes()`, reachability unknown).
- Website: `pool.js` takes each node's SV2 key from its live status (`withLiveKeys`), the
  `pool-nodes.json` key only as the fallback, and says when the two differ.
- Tests: pool_sv2 `solo_api_tests.rs` (+3), `submit_rpc.rs` (+2, a fake node), ghost-verification
  `the_miner_list_is_forwarded_only_to_signed_requests`, proxy refusal, dashboard (+4), website (+1).

## Solo end-to-end harness (`scripts/regtest-solo/`, workflow `Solo e2e`)
- `run.sh` (`--fetch-ghostd`, `--build`), `harness.py`, `cpu_miner.py`. Two peered regtest nodes
  (released ghostd v1.11.46 + ghost-mining + pool_sv2 `[solo] submit_rpc` = the other ghostd +
  translator 3333/4444) on 127.0.0.10 / .11; per node a miner on 3333 (P2WPKH), 4444 (P2TR) and SV2
  34255 (`mining_device`, P2WSH). Miners take turns (SIGSTOP/SIGCONT), 138 plain blocks first so
  the pool's blocks cross the halving at 150; fee-paying wallet transactions in two rounds.
- Scenarios: bring-up; mining (every miner finds a block each round); coinbase rule per block
  (treasury exactly subsidy/200, finder subsidy - subsidy/200 + fees, else only the witness
  commitment); fees; halving; submission to both nodes (blocks-found `submitted` + both chains +
  post-submit check, no `SOLO_COINBASE_MISMATCH`); API (status, miner, miners, signed/unsigned via
  ghost-mining); ghost-audit honest on 3333/4444/SV2; failover (one pool_sv2 killed); hostile
  (pool_sv2 `--features solo-fault-injection`, `GHOST_SOLO_FAULT=skim-treasury`, regtest only,
  refused by ghost-audit); reachability (a stopped ghostd reported unreachable); teardown.
- `.github/workflows/solo-e2e.yml`: on push to ghost-solo and workflow_dispatch, 30 min cap, rust
  cache + apt cache + ghostd cache; uploads the run's logs on failure. First run 42418860770:
  every scenario PASS but API (the later pool's hashrate was still null inside its first minute;
  the harness now waits for it), 129 s of harness time.
- Removed: `scripts/regtest-node-pool/` (the share-chain harness; kept on `feat/node-pool`).
