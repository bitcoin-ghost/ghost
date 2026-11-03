# Node pool flag day: operator runbook

Plan Phase 4 (`NODE_POOL_PLAN.md`), as ordered steps. Each step gives the command, the output to
expect, the check that decides whether to go on, and what to do if it fails. Rehearsed end to end
on 2026-11-03, locally, on synthetic old-format databases (section "Rehearsal"); never against the
fleet. Nothing here has been run on mainnet.

## Placeholders: the user's decisions

Nothing below is to be run until every one of these is set. They are not defaults.

| Placeholder | Meaning | Constraint |
|---|---|---|
| `<FREEZE_HEIGHT>` (F) | Export height: the old ledger's last counted state | Must be a height with a **finalised** checkpoint held byte-identical by every exporting node (step 2). Since a 4-node fleet finalises nothing new (plan, "Old fleet with 4 nodes"), choose it while 8 nodes still run, or from what is already finalised |
| `<SATS_PER_WORK>` | Work-to-sats rate | `N`, `N/D` or `I.F`, exact; never defaulted |
| `<EXPORT_SOURCE>` | Which old table the balances come from | The exporter reads **finalised checkpoints only**: since 963,388 the top 200 balances (see "What the export carries"). **Decided 2026-11-03: checkpoint export.** The live fleet owed 3 addresses on 11-03 (public `/api/v1/pool/next_payout`), all inside the top 200; a full-shard-table source is not built. Check at F that the payee count matches `next_payout` |
| `<TREASURY_ADDRESS>` | Compiled treasury | Plan section 5 item 1 |
| `<GENESIS_ANCHOR>` | Mainnet share-chain genesis anchor, 64 hex | Compiled into `MAINNET_START` |
| `<GENESIS_HEIGHT>` (G) | Its `btc_height` | `G + 21 <= R`. Rehearsed with `G = F` |
| `<REPOINT_HEIGHT>` (R) | When miners are told to move | `R >= G + 21`, so no live work is void |
| `<NP_VERSION>` | The node pool release carrying `MAINNET_START` | Cut after step 4 |
| `<OLD_NODES>` | Old nodes that export (vm1..vm8) | Every node that still holds the checkpoint at F |
| `<NEW_NODES>` | Node pool servers | Own servers; never co-hosted with an old node |
| `<P2PKH_POLICY>` | How balances held by P2PKH addresses are carried | The node pool pays only P2SH, P2WPKH, P2WSH and P2TR; the import refuses any other row (step 3). **Decided 2026-11-03:** one P2PKH payee (`148WRj…CXTN`, 0.7% of owed work on 11-03); the user gets a segwit/taproot address from its owner. No re-keying tool exists (a re-keyed row changes the export digest the old nodes agree on), so unless one is built the row is left out of the import and its owner is paid the exported amount once, by hand, after launch |

Paths on an old node: `ghost-mining` runs as `ghost` with `--data-dir /home/ghost/.ghost`, so the
database is `/home/ghost/.ghost/ghost.db`. On a node pool node the relay's store is
`/var/lib/ghost/node-pool.db` (`[node_pool.relay] db_path` in `/etc/ghost/pool-config.toml`); the
genesis table is imported there, **not** into `ghost.db`.

## 0. Before the day

- Back up every old node's `ghost.db` (`ghost-backup.timer`, same disk) and copy one off the node.
  Abort if any node has no backup newer than 24 h.
- Copy the MPC parameter files off-node (plan W0.4); the export carries only their rows.
- Build the exporter (`feat/ledger-export`, plus `feat/ledger-export-fixes`) as the release the old
  fleet runs, or as a standalone binary of the same commit. It only reads.
- Announce F, R and the rate. Work credited by the old fleet after F is not in the export and is
  never paid (see "Known gaps").

## 1. Freeze

There is no freeze switch in the old release: nothing stops it crediting work after F. The freeze
is the choice of F plus the export taken at exactly F. **Decided 2026-11-03:** the old network freezes
at the export; the user shuts the old nodes down once the migration is done (after step 6), so work
after F is only the short window up to repoint.

- **Command** (each old node): `sudo -u ghost /opt/ghost/bin/ghost-cli -conf=/etc/bitcoin/bitcoin.conf getblockcount`
- **Expect**: a height above F.
- **Check**: `scripts/shard-anchor-rehearsal.sh --height <FREEZE_HEIGHT>` (main) reports the
  `canonical_payout` bytes byte-identical on every node in `<OLD_NODES>`, payee count > 0.
  `--survey` lists heights where they are (measured 2026-08-13: only 3 of the post-#606 heights
  agreed on all 8; the root alone agreed far more often and is not the gate).
- **Abort**: no unanimous height near the intended F: pick another F from `--survey`. Nothing has
  changed anywhere yet.

## 2. Export on each old node

- **Command** (read-only; works on a running node; never migrates):

  ```
  sudo -u ghost /opt/ghost/bin/ghost-mining --np-export /home/ghost/np-export-<FREEZE_HEIGHT> \
      --np-export-height <FREEZE_HEIGHT> --np-export-sats-per-work <SATS_PER_WORK> \
      --np-export-db /home/ghost/.ghost/ghost.db --np-export-network bitcoin
  ```

- **Expect**: a summary ending in `LEDGER DIGEST <64 hex>` and `MPC DIGEST <64 hex>`, `(recomputes)`
  after `adopted_root`, and four files: `ledger-export.bin`, `ledger-export.json`,
  `mpc-lineage.json`, `SHA256SUMS`. Rehearsed: 0.04-0.44 s, 36-40 MB RSS (debug build).
- **Check**: `cd /home/ghost/np-export-<FREEZE_HEIGHT> && sha256sum -c SHA256SUMS` prints three
  `OK`. Read every `WARNING:` line. `the checkpoint holds 200 miners, the MAX_MINER_OUTPUTS cap`
  means balances below the top 200 are not exported (decision `<EXPORT_SOURCE>`).
- **Abort/rollback**: the export writes only its own directory and refuses to overwrite one. On
  `no finalised payout checkpoint`, `does not recompute`, `has no canonical_payout` or a bad
  address, go back to step 1 for another F. Never pass `--np-export-allow-root-mismatch` without
  the user's decision. `this database was migrated to the node pool`: the node has been migrated;
  export from its `ghost.db.pre-v65` copy instead.

## 3. Compare digests

- **Command** (operator machine): collect `LEDGER DIGEST` and `sha256sum ledger-export.bin` from
  every node.
- **Expect**: one value.
- **Check**: every node's `ledger-export.bin` byte-identical (`cmp`), and `ledger-export.json`
  identical. The digest is independent of each node's address encryption: rehearsed with four
  databases encrypted under four node keys, one digest.
- **Check, payee classes**: count rows the node pool cannot pay (P2PKH; the old fleet paid it):
  `python3 -c 'import json,sys; t=json.load(open(sys.argv[1]))["genesis_table"]; print(sum(1 for r in t if not (r["script_hex"].startswith(("0014","0020","5120")) or (r["script_hex"].startswith("a914") and len(r["script_hex"])==46))))' ledger-export.json`.
  Expect `0`. Anything else: the import refuses the export (`<n> genesis rows (<n> of them
  P2PKH) owing <sats> sats are not a node pool payee class`). How those balances are carried is
  `<P2PKH_POLICY>`, a user decision, taken before step 4.
- **Abort**: digests differ. The plan's settling rule (a fixed rule per differing miner, e.g. the
  median, published with the differences) is **not built**; stop, pick another F (step 1), or get
  the user's decision on the rule. Nothing has changed anywhere yet.

## 4. Publish the table and digest, and pin

- **Command**: publish `ledger-export.bin`, `ledger-export.json`, `SHA256SUMS` and the digest. On
  any node pool build, compute the table root without a node:

  ```
  pool_sv2 -c <scratch pool-config.toml with an empty db_path> \
      --np-import-genesis <EXPORT_DIR> --np-export-digest <LEDGER_DIGEST>
  ```

  It prints `NODE_POOL_GENESIS_IMPORTED: ... rows=<n> ... queue_since=<F> table_root=<ROOT>` and
  `pin it: [node_pool.relay] genesis_table_digest = "<ROOT>"`.
- **Then**: set `node_pool_network::MAINNET_START = Some(CompiledStart { genesis_anchor:
  <GENESIS_ANCHOR>, genesis_btc_height: <GENESIS_HEIGHT>, genesis_table_digest: Some(<ROOT>) })`,
  the treasury `<TREASURY_ADDRESS>`, merge, and cut `<NP_VERSION>`
  (`scripts/release.sh --node-pool <version>`). The release must carry the digest: a mainnet
  build with the anchor but no compiled digest cannot be pinned by config (pool_sv2 refuses a
  configured `genesis_table_digest` that differs from the compiled one, `None` included), so the
  release cannot be cut before the export.
- **Check**: the published `SHA256SUMS` verifies on a machine that took no part; `ROOT` is the
  same from two independent runs.
- **Abort**: the old fleet is untouched; fix and re-cut. Rollback is "do nothing".

## 5. Install the node pool nodes and import

On each of `<NEW_NODES>` (fresh servers; their `ghost.db` has no old rows):

1. Install: `curl -sSL https://get.bitcoinghost.org | sudo GHOST_VERSION=<NP_VERSION> bash -s -- --fee-address <fee address> --network mainnet`.
2. Stop the pool before the import: `sudo systemctl stop sri-pool sri-translator`. The import runs
   once, offline, before the relay first runs on its store.
3. Import:

   ```
   sudo /opt/ghost/bin/pool_sv2 -c /etc/ghost/pool-config.toml \
       --np-import-genesis <EXPORT_DIR> --np-export-digest <LEDGER_DIGEST>
   sudo /opt/ghost/bin/pool_sv2 -c /etc/ghost/pool-config.toml \
       --np-import-genesis <EXPORT_DIR> --np-export-digest <LEDGER_DIGEST> --np-verify-genesis
   ```

- **Expect**: `NODE_POOL_GENESIS_IMPORTED: ... network=mainnet export_digest=<LEDGER_DIGEST>
  export_height=<F> rows=<n> ... queue_since=<F> table_root=<ROOT>`, then
  `NODE_POOL_GENESIS_VERIFIED: ...` with the same root. Exit 0 each. Rehearsed: 0.41-0.49 s for 200
  and 3,958 rows; verify 0.02 s.
- **Check**: `table_root` equals the published `<ROOT>` on every node.
- **Refusals (exit 2, nothing written)**: rows outside the payee classes (step 3), wrong digest (`is not the published export`), another
  network's export, a store that already holds a table (`an import runs once`), a store the relay
  has run on, a root that is not the compiled pin.
- **Rollback**: before step 7 nothing depends on these nodes: stop them, delete
  `/var/lib/ghost/node-pool.db`, import again.

### 5a. Converting an old node in place (not the plan's path)

If an old server is reused, its `ghost.db` is migrated by v65 when the node pool `ghost-mining`
first opens it.

- **Expect** in the journal: `Running database migrations from=62 to=65`, `v65: pre-v65 backup
  taken and verified backup=<db>.pre-v65 ... user_version=64`, `v65: dropped the old system's tables
  and created np_genesis tables=62 rows=<n>`, `Database migrations complete`. Rehearsed on a 32 MB
  database: 0.34 s including the 0.17 s copy; the file does not shrink (`auto_vacuum=0`, 895 pages
  left on the free list).
- **Refusal**: `v65 REFUSED, nothing changed: money-bearing tables hold rows: ghost_locks (1 rows),
  ...`. Resolve those rows on the old release. With `feat/node-pool-flagday` the refusal leaves the
  database at v62; before it, v63 and v64 had already run (database at v64, no copy taken).
- **Check**: `PRAGMA user_version` is `-65`. The old binary then refuses to start
  (`Error: Database error: Integer -65 out of range at index 0`, exit 1).
- **Rollback**: stop the node pool, restore `<db>.pre-v65` (a v64 database; the old release opens
  it with a `schema is AHEAD` warning and runs), start the old release.

## 6. Genesis anchor at least 20 blocks before repointing

- **Check** on every new node: the start line
  `NODE_POOL_START: network=mainnet genesis_anchor=<GENESIS_ANCHOR> genesis_btc_height=<G> source=compiled ... genesis_table_digest=<ROOT> pinned_digest=<ROOT>`,
  and Bitcoin tip `>= G + 20` before step 7.
- **Abort**: a different anchor or digest on any node: stop that node; it is on another network.

## 7. Repoint miners

- **Command**: publish the node list and DNS (`ghost-audit list`), announce.
- **Check**: `curl -s http://127.0.0.1:9090/api/v1/node-pool/status` on each node: peers > 0, the
  same share-chain tip, `genesis_table_digest` = `<ROOT>`; `ghost-audit probe` passes against each
  node; a sample of genesis payees' `/api/v1/ledger/<address>` shows the imported balance.
- **Rollback**: after the import there is none but forward fixes (plan). Miners can point back at
  the old fleet while it runs, but work done there after F is not in the genesis table.

## 8. Verify, then retire the old fleet

- Every node logs `NP_SETTLE: pool block settled` for each pool block, one ledger digest on all.
- The old fleet stays up until every old database is backed up off-node; then it is switched off.

## What the export carries

The exporter reads the finalised checkpoint at F. From 963,388 that list is
`select_shard_miner_work`: the shard's positive balances, **truncated to the top 200**. On the
rehearsal population (3,958 positive balances): 200 exported, 55.4% of owed work (mainnet-shaped)
and 60.5% (signet), every balance outside the top 200 (all of the tail, including all 2,773
below-floor rows) left out. The fleet's own distribution is unmeasured here.

## Known gaps

- No freeze switch: work the old fleet credits between F and R is not exported.
- Differing digests have no settling tool (step 3).
- Mainnet `MAINNET_START` must carry the digest, so the release follows the export (step 4).
- A full-shard-table export source does not exist; it would need the node's address encryption key,
  which the exporter (by design: "no config is read") does not load.

- P2PKH balances: see `<P2PKH_POLICY>`. The rehearsal population had 600 P2PKH rows of 3,958.

## Rehearsal (2026-11-03)

Local only: no fleet database, no remote host. Old side `feat/ledger-export-fixes` (main
`f1cc40519` plus the exporter, debug build); new side `feat/node-pool-flagday` (release binaries
of the same node pool code, `ghost-mining` debug for the v62 refusal).

**Old databases** were written by the old release's own code
(`bins/ghost-pool/examples/np_flagday_fixture.rs` on `feat/ledger-export-fixes`): `Database::open`
to schema v62, the shard through `ShardTable::install_genesis`/`accrue`/`record_settled` and
`shard_save_table` (encrypted under each node's key, read back, root checked), the checkpoint
through `select_shard_miner_work` (the live path, top 200) and `compute_ledger_root`, kept tables
through `create_round`, `upsert_miner`, `insert_share`, `record_won_block`,
`get_or_create_node_reward`; the dirty variant through `insert_ghost_lock`,
`insert_withdrawal_request_atomic`, `insert_l2_epoch`/`insert_l2_note`, `credit_node_reward`. MPC
rows are raw INSERTs. 4,000 miners (P2WPKH 45%, P2TR 20%, P2PKH 15%, P2SH 10%, P2WSH 10%), 70% dust,
five whales; 3,958 positive balances; 50,000 (mainnet-shaped, 32 MB) or 10,000 (signet, 10.5 MB)
shares. `--uncapped` writes every positive balance into the checkpoint (what a full-table source
would carry; no live code writes that).

| Step | Measured |
|---|---|
| Export, mainnet-shaped, F = 975,000, rate 37/100, 3 copies | 0.04-0.14 s, 36 MB RSS; 200 rows; three byte-identical outputs, digest `8ab6aa8a…a707`; `ledger-export.bin` 31,010 B, JSON 72,808 B; database byte-identical after |
| Export, signet, F = 30, rate 370000, 4 databases under 4 node keys | 0.42-0.68 s, 40 MB RSS; 3,958 rows (2,773 below the floor); one digest on all four; `.bin` 604,325 B, JSON 1,375,259 B |
| Capped vs full | 200 rows carry 55.4% (mainnet-shaped) / 60.5% (signet) of owed work; 3,758 balances left out |
| v65, dirty, v62 database | Refused naming `ghost_locks`, `l2_epochs`, `l2_notes`, `node_rewards`, `withdrawal_requests` (1 row each); with the fix the database stays at v62 with no `np_` table (before it: v64) |
| v65, clean, 32 MB | 0.34 s, of which the `.pre-v65` copy 0.17 s (30.2 MB, user_version 64); 62 tables, 9,805 rows dropped; `user_version` −65 |
| v65, clean, 10.5 MB, inside each harness node | 0.19-0.21 s |
| Old binary on the v65 database | Exit 1, `Integer -65 out of range at index 0`; only the journal-mode header bytes changed |
| Old exporter on the v65 database | Refused by name (`this database was migrated to the node pool`) |
| Import, 200 / 3,958 rows | 0.49 s / 0.41 s, 15 MB RSS; verify 0.02 s; re-import, wrong digest, wrong network refused |
| Signet harness, 4 nodes, each starting ghost-mining on its old v62 database (v65 at first open) and importing the real export | 16 of 16 PASS in 807 s, peak 898 MB: one `table_root` on all four; 20 blocks on genesis-only snapshots (classes 3 to 500, up to 503 outputs) equal to `refimpl_v3`; 97 pool blocks settled on every node, sums exact, mismatched 0; 1,185 eligible genesis rows paid in full, none below the floor paid, ledger API balance = imported − paid to the face unit; reorg, slot classes, fresh node, `ghost-audit` PASS |
| Same harness with the 15% P2PKH population, before the import refused it | 21 PASS, 2 FAIL in 1,619 s: all 170 eligible P2PKH rows paid on signet's empty templates, but the ledger API answered "cannot be paid by the node pool" for them |

Not measured: the fleet's real distribution, size or checkpoint agreement; release-build export
timing; a real P2PKH coinbase on a sigop-heavy mainnet template; the old fleet's behaviour
between F and R; the 24 h soak.
