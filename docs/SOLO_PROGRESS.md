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

## Next
- Get CI green.
