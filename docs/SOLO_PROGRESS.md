# Ghost Solo: work in progress

Running note for the solo pivot on `ghost-solo` (branched from `feat/node-pool` at fb687f804).
No local builds: verified through GitHub CI only (`gh workflow run ci.yml --ref ghost-solo`).

## Done
- `ghost_common::solo`: treasury script, halving/subsidy, `solo_outputs`, `check_solo_outputs`,
  `SoloNetwork`, payee classes, the 0x4748 TLV constants, coinbase/reserve constants.
- Deleted from ghost-common: canonical_payout, share_commit, anchor_chain, slot_class_sensing,
  node_pool_constants, node_pool_genesis_export, node_pool_network, node_pool_u256.

## Next
1. Delete `crates/ghost-np-relay` (+ fuzz target `fuzz_relay_wire`), ghost-storage `node_pool_*`.
2. pool_sv2: replace `node_pool.rs` with `solo.rs` (per-channel solo outputs, post-submit
   alarm, blocks found, multi-node submit via RequestTransactionData), drop relay/settlement/
   sensing/genesis import, `[solo]` config, API `/api/v1/miner/{address}` + `/api/v1/pool/status`.
3. Fix users: ghost-mining (payee_class, block_limits, template.rs, alert_monitors),
   ghost-verification forwarding, ghost-cli, translator constants, integration-sv2 harness.
4. ghost-audit reduced to the solo check.
5. Tests, docs/SOLO.md, archive NODE_POOL_SPEC/PLAN, CI green.
