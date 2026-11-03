# Ledger export (node-pool cutover)

At the node-pool flag day every node runs this export on the current release. The new binary imports
the ledger half as its genesis table, pinned by digest. The MPC half is an archive: those tables are
dropped at cutover. Plan: `docs/NODE_POOL_PLAN.md`, Phase 4 "Migration" (on `feat/node-pool`).

## Command

```
ghost-mining --np-export DIR \
    --np-export-height H \
    --np-export-sats-per-work RATE \
    [--np-export-db FILE] [--np-export-network bitcoin] [--np-export-allow-root-mismatch]
```

- Read-only. The database is opened `SQLITE_OPEN_READ_ONLY` with `PRAGMA query_only`, and it is never
  migrated. No config is read, so the command works on a running or a stopped node. All reads share
  one read transaction. On a WAL database SQLite may create an empty `-shm`/`-wal` beside it; the
  database file itself is not changed.
- `--np-export-db` defaults to `ghost.db` in `--data-dir`.
- Nothing is written unless every check passes. Existing output files are never overwritten.

Output, in `DIR`:

| File | Content |
|---|---|
| `ledger-export.bin` | Canonical bytes. The ledger digest is `sha256` of this file. |
| `ledger-export.json` | The same data, readable, with `digest_sha256` embedded. |
| `mpc-lineage.json` | The four MPC tables. Its digest is `sha256` of this file. |
| `SHA256SUMS` | `sha256sum -c` file for the three above. |

The command prints both digests. Every node that holds the same checkpoint bytes prints the same
ledger digest, so the fleet compares digests to confirm unanimity.

## Which checkpoint

`H` is an exact height. The export never falls back to an older one.

- **Finalised.** A row in `payout_ledger_checkpoints` is written only when the fleet finalises that
  height (`payout_checkpoint.rs`, `maybe_finalize`). The export refuses a height with no row, a row
  with no `canonical_payout` (written before adopt-on-finalise), or a checkpoint with no miners.
- **Root recomputes.** `ledger_root` is recomputed from the adopted lists with
  `payout::compute_ledger_root(miners, node_shares, cutoff_ts, height)`. Since the #606 median gate
  (961,700) the stored root is the proposer's root, while the lists are the per-address median of
  the reports this node received, so the two can differ. The export refuses a mismatch unless
  `--np-export-allow-root-mismatch` is given, which records a warning.
- **Unanimous.** This is a cross-node check. Run `scripts/shard-anchor-rehearsal.sh --survey` to find
  heights whose `canonical_payout` bytes match on all nodes, then run the export on every node and
  compare digests. The digest covers `canonical_payout_sha256`, which is the same hash the
  rehearsal script compares.

Known limits of the source:

- From `CHECKPOINT_FROM_SHARD_HEIGHT` (963,388) on, the checkpoint's miner list is
  `select_shard_miner_work`: the shard's positive balances, truncated to `MAX_MINER_OUTPUTS` (200).
  If the list holds 200 miners the export warns, because balances below the top 200 are not in any
  checkpoint.
- Below that height the list came from the legacy ledger, which was capped and dust-filtered and
  used 1e12 units per work. The export warns and still uses the right unit scale.

## Work to sats

The rate is required and is never defaulted. `RATE` is sats per whole unit of work, exact: `N`,
`N/D` or a decimal `I.F`. It is reduced to lowest terms, so `1/2`, `2/4` and `0.5` give the same
digest.

Checkpoint work is stored in sub-units: `work_units_per_work` = 1,000,000 (shard micro-work) from
963,388 on, and 1e12 before. For each miner:

```
D          = rate_den * work_units_per_work
face_units = floor(work * rate_num * 2^32 / D)          (units of 2^-32 sat)
remainder  = (work * rate_num * 2^32) mod D
```

The arithmetic is exact 256-bit; anything that would leave `u128`, or a face value above `i128::MAX`
(the import's blob limit), is refused. Each miner is floored. The total remainder is reported as
`remainder_face_units + remainder_frac_num / remainder_frac_den` face units, and
`face_units_of_total_work = floor(total_work * rate * 2^32 / work_units_per_work)` equals
`face_units + remainder_face_units`. The export checks this.

## Ledger JSON

- `checkpoint`: `height`, `cutoff_ts`, `ledger_root`, `adopted_root`, `ledger_root_recomputes`,
  `canonical_payout_sha256`, and `node_shares` (node id hex, shares), sorted by node id. The node
  set is included because `ledger_root` commits to it.
- `rate`: `sats_per_work_num`, `sats_per_work_den`, `work_units_per_work`, `face_units_per_sat`
  (= 2^32).
- `miners`: `address` (as the checkpoint keys it), `script_hex` (its scriptPubKey on `network`),
  `work` (checkpoint units, as adopted) and `face_units`. Sorted by script bytes, then address.
  Every address must parse on `network`, and no address may repeat.
- `genesis_table`: `script_hex` and `face_units`, the per-script sum of the floored miner values,
  sorted by script bytes. This is what the node-pool import loads into `np_ledger` (owed in 2^-32
  sat, keyed by payee script). The export does not set `queue_since`; the import decides it.
- `totals`: `work`, `face_units`, the remainder fields, `face_units_of_total_work`.
- `observed`, `warnings` and `deleted` are not covered by the digest: proposer id, active node
  count, this node's highest round, and the blob length.
- **Deleted rows (decided 2026-11-03).** The node pool pays only P2SH, P2WPKH, P2WSH and P2TR, and
  its import refuses any other script. A checkpoint row with any other script (P2PKH) is deleted:
  it is not in `miners`, `genesis_table` or `totals`, and is listed in `deleted` (address and work)
  and named in `warnings`. Every node deletes the same rows from the same checkpoint, so the digest
  still agrees across nodes; `miners` plus `deleted` recompute the checkpoint's `ledger_root`.

All `u128` values are JSON strings.

## Digest

`digest_sha256 = sha256(ledger-export.bin)`. The bytes are a pure function of the JSON, so anyone
holding the JSON can rebuild them. Big-endian throughout, `bytes16(x)` = `u16 len || x`:

```
"GhostLedgerExport/v1"
bytes16(network)
u64 height || i64 cutoff_ts
[32] ledger_root || [32] adopted_root || [32] canonical_payout_sha256
u32 n_nodes, then per node:   [32] node_id || i32 shares
u128 rate_num || u128 rate_den || u128 work_units_per_work || u128 face_units_per_sat
u32 n_miners, then per miner: bytes16(address) || bytes16(script) || u128 work || u128 face_units
u32 n_rows, then per row:     bytes16(script) || u128 face_units
u128 total_work || u128 total_face_units || u128 remainder_face_units
u128 remainder_frac_num || u128 remainder_frac_den || u128 face_units_of_total_work
```

## Checking an export without the node

1. `sha256sum -c SHA256SUMS`.
2. Rebuild `ledger-export.bin` from the JSON using the layout above and compare.
3. Recompute `ledger_root` from `miners[].address`, `miners[].work`, `checkpoint.node_shares`,
   `cutoff_ts` and `height`:

```
sha256( "PayoutLedgerRoot/v1" || i64le cutoff_ts || u64le height
     || u32le n_miners || per miner sorted by (work desc, address asc): u32le len || address || u128le work
     || u32le n_nodes  || per node sorted by node_id: [32] node_id || i32le shares )
```

   It must equal `checkpoint.ledger_root`.
4. Check `face_units` and the totals with the formula above.

## MPC lineage

`mpc-lineage.json` is `{"format": "ghost-mpc-lineage/v1", "tables": {...}}` covering
`mpc_ceremony`, `mpc_contributions`, `mpc_verification_votes` and `mpc_params_files`. Each table has
`present`, `columns` (declared order) and `rows` (arrays in column order, sorted by every column in
order). Blobs are `{"blob_hex": "..."}`. The parameter files themselves are not copied; only their
rows, which include `file_path`. Copy the files off-node separately (plan item W0.4).

## Tests

`bins/ghost-pool/src/node_pool_export.rs`, run with `cargo test -p ghost-mining --lib node_pool_export`.
They use temp databases built by the real migrations and cover: same database twice gives identical
files, the stranger's check (JSON to bytes to digest, recompute `ledger_root`), exact rounding and
remainder, refusal of a height that is not finalised, refusal without a rate, refusal of a root
mismatch unless allowed, wrong-network addresses, no overwrite, the database file unchanged byte for
byte, the MPC dump, and the 256-bit arithmetic.
