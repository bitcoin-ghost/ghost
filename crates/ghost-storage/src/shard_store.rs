//! Persistence for the network shard (`SHARE_SHARD.md` §4.3/§4.4, build Stage 1).
//!
//! Three tables (migration v53) mirror `ghost_common::share_shard::ShardTable` exactly:
//! `shard_counters` is `accrued[node][address]`, `shard_settled` is `settled[address]`, and
//! `shard_epochs` holds this node's own signed epoch summaries. The in-memory table is the truth
//! the fleet compares roots over; these rows exist only so a restart resumes from it rather than
//! from zero, so the round trip must be byte-identical under `compute_table_root` — a load that
//! differs from the save is a node that diverges from the fleet while every local check passes.
//!
//! Keying follows `sbc_balances`: `H(plaintext address)`, never the ciphertext, because
//! `encrypt_sensitive` draws a fresh nonce per call and a ciphertext key can never be looked up.
//! Never `GROUP BY` an encrypted column.
//!
//! Two invariants are load-bearing here rather than in the caller:
//!
//! - **Replace, not merge, on save.** A row absent from the map being saved is DELETED. The only
//!   legitimate shrink is compaction/rebase, and a stale row surviving it would keep contributing
//!   to `owed` and to the table root — internally consistent, externally wrong.
//! - **Fold-then-delete is ONE transaction** ([`Database::shard_fold_epoch`]). Crediting the
//!   column and dropping the epoch's evidence torn apart is either silently lost work (deleted
//!   but never credited) or double-credited work (credited, then re-folded after a crash). The
//!   prior design lost 6,499 pending shares on a restart to exactly this seam.
//!
//! No VACUUM anywhere: it needs 2× the database size free, and vm1 does not have it.
//!
//! Dark: nothing wires these into a runtime path yet.

use std::collections::BTreeMap;

use rusqlite::{params, params_from_iter, Connection};

use ghost_common::error::{GhostError, GhostResult};
use ghost_common::share_shard::{AccruedColumns, EpochSummary, ShardTable, GENESIS_NODE_ID};
use ghost_common::types::NodeId;

use crate::database::Database;
use crate::sbc_store::{address_key, blob32};

/// How many evidence rows one DELETE statement may name.
///
/// The storage handle is a single `Mutex<Connection>` shared with share ingest and template
/// refresh, so statement size must stay bounded — and SQLite's default parameter limit is 999,
/// which an unchunked epoch would exceed anyway. The chunks still run inside ONE transaction:
/// bounding the statement is about lock fairness and limits, not about weakening atomicity.
const EVIDENCE_DELETE_CHUNK: usize = 256;

/// One counter or settled cell ready to write: `(H(address), ciphertext, micro-work)`.
type EncryptedCell = (Vec<u8>, String, i64);

/// A column's rows, encrypted outside the connection lock.
///
/// Encryption draws randomness and allocates; doing it while holding the write connection would
/// stretch the very lock window the bounded-statement rule exists to keep short.
fn encrypt_cells(db: &Database, column: &BTreeMap<String, i64>) -> GhostResult<Vec<EncryptedCell>> {
    column
        .iter()
        // Zero is represented by absence everywhere the table is compared (`compute_table_root`
        // skips it, `merge_accrued` skips it), so the canonical form is what gets persisted.
        .filter(|(_, &micro)| micro > 0)
        .map(|(addr, &micro)| Ok((address_key(addr), db.encrypt_address(addr)?, micro)))
        .collect()
}

/// Replace one node's rows in `shard_counters` — delete-then-insert, inside the caller's
/// transaction. Shared by the plain upsert and the epoch fold so "replace, not merge" is spelled
/// exactly once.
fn replace_column_tx(
    conn: &Connection,
    node: &NodeId,
    cells: &[EncryptedCell],
    epoch: u64,
) -> GhostResult<()> {
    conn.execute(
        "DELETE FROM shard_counters WHERE node_id = ?1",
        params![node.to_vec()],
    )
    .map_err(|e| GhostError::Database(e.to_string()))?;
    for (key, enc, micro) in cells {
        conn.execute(
            "INSERT INTO shard_counters (node_id, address_hash, address_enc, total_micro, \
             updated_epoch) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![node.to_vec(), key, enc, micro, epoch as i64],
        )
        .map_err(|e| GhostError::Database(e.to_string()))?;
    }
    Ok(())
}

/// Record a summary row, inside the caller's transaction.
///
/// Idempotent on `(epoch, node_id, share_root)`: folding an epoch is observed once but may be
/// retried after a crash, and the retry is not an error. A DIFFERENT summary at the same epoch is
/// refused — this node signs exactly one statement per epoch, and silently replacing it would let
/// a signed claim vanish from the record while peers still hold it.
fn store_epoch_tx(
    conn: &Connection,
    summary: &EpochSummary,
    summary_enc: &str,
    published: bool,
) -> GhostResult<()> {
    // Scoped to (epoch, node_id): a different node's summary at the same epoch is the normal
    // case and must not collide. A different ROOT under the same (epoch, node_id) is the node
    // signing two conflicting statements for one epoch — equivocation, not a storage conflict —
    // so it is refused rather than overwritten, and the held row stays available as evidence.
    let existing: Option<Vec<u8>> = conn
        .query_row(
            "SELECT share_root FROM shard_epochs WHERE epoch = ?1 AND node_id = ?2",
            params![summary.epoch as i64, summary.node_id.to_vec()],
            |r| r.get(0),
        )
        .ok();

    if let Some(root) = existing {
        return if root == summary.share_root.to_vec() {
            Ok(())
        } else {
            Err(GhostError::Database(format!(
                "epoch {} already holds a different summary for this node — refusing to overwrite \
                 a signed statement (equivocation; the held row is the evidence)",
                summary.epoch
            )))
        };
    }

    conn.execute(
        "INSERT INTO shard_epochs (epoch, node_id, share_root, share_count, summary_enc, \
         published) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            summary.epoch as i64,
            summary.node_id.to_vec(),
            summary.share_root.to_vec(),
            summary.share_count as i64,
            summary_enc,
            published as i64
        ],
    )
    .map_err(|e| GhostError::Database(e.to_string()))?;
    Ok(())
}

impl Database {
    /// Load the whole shard table, decrypted, ready to compare roots with the fleet.
    ///
    /// Reconstruction goes through the table's own verified-shaped mutators (`merge_accrued`
    /// into an empty table is the identity, `record_settled` from zero likewise) rather than a
    /// backdoor constructor, so the loaded table can only ever hold states the type's invariants
    /// allow.
    ///
    /// A row whose address cannot be decrypted is an ERROR, not a skip — the `sbc_balances`
    /// rule. Silently dropping it would remove a miner from `owed` and from the table root, and
    /// every node that could decrypt it would then compute a different root: a divergence that
    /// looks like consensus failure instead of the key problem it actually is.
    pub fn shard_load_table(&self) -> GhostResult<ShardTable> {
        let counters: Vec<(Vec<u8>, String, i64)> = self.with_connection(|conn| {
            let mut stmt = conn
                .prepare("SELECT node_id, address_enc, total_micro FROM shard_counters")
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let rows = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(rows)
        })?;
        let settled: Vec<(String, i64)> = self.with_connection(|conn| {
            let mut stmt = conn
                .prepare("SELECT address_enc, settled_micro FROM shard_settled")
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let rows = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(rows)
        })?;

        let mut accrued: AccruedColumns = BTreeMap::new();
        for (node, enc, micro) in counters {
            let node = blob32(node, "shard counter node_id")?;
            let addr = self.decrypt_address(&enc)?;
            accrued.entry(node).or_default().insert(addr, micro);
        }

        let mut table = ShardTable::new();
        // The reserved genesis column is split out and installed directly: `merge_accrued` now
        // skips it (so a peer can never inflate the opening balances), and reconstructing our own
        // persisted table through the peer-merge path would therefore silently drop it — every
        // miner's opening balance, gone on the next restart.
        let genesis = accrued.remove(&GENESIS_NODE_ID);
        table.merge_accrued(&accrued);
        if let Some(column) = genesis {
            table.install_genesis(column);
        }
        for (enc, micro) in settled {
            table.record_settled(&self.decrypt_address(&enc)?, micro);
        }
        Ok(table)
    }

    /// Replace the persisted table with `table` — every column and the settled map, one
    /// transaction.
    ///
    /// Replace, not merge: rows absent from `table` are deleted, because the only legitimate way
    /// a cell disappears is compaction/rebase, and a stale survivor would keep contributing to
    /// the next load's root. `epoch` and `height` stamp the rows for diagnosis only — neither is
    /// ever a decision input.
    pub fn shard_save_table(&self, table: &ShardTable, epoch: u64, height: u64) -> GhostResult<()> {
        let columns: Vec<(NodeId, Vec<EncryptedCell>)> = table
            .accrued()
            .iter()
            .map(|(node, column)| Ok((*node, encrypt_cells(self, column)?)))
            .collect::<GhostResult<Vec<_>>>()?;
        let settled: Vec<EncryptedCell> = table
            .settled()
            .iter()
            .filter(|(_, &micro)| micro != 0)
            .map(|(addr, &micro)| Ok((address_key(addr), self.encrypt_address(addr)?, micro)))
            .collect::<GhostResult<Vec<_>>>()?;

        self.with_connection(|conn| {
            conn.execute_batch("BEGIN IMMEDIATE")
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = (|| -> GhostResult<()> {
                conn.execute("DELETE FROM shard_counters", [])
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                for (node, cells) in &columns {
                    for (key, enc, micro) in cells {
                        conn.execute(
                            "INSERT INTO shard_counters (node_id, address_hash, address_enc, \
                             total_micro, updated_epoch) VALUES (?1, ?2, ?3, ?4, ?5)",
                            params![node.to_vec(), key, enc, micro, epoch as i64],
                        )
                        .map_err(|e| GhostError::Database(e.to_string()))?;
                    }
                }
                conn.execute("DELETE FROM shard_settled", [])
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                for (key, enc, micro) in &settled {
                    conn.execute(
                        "INSERT INTO shard_settled (address_hash, address_enc, settled_micro, \
                         last_height) VALUES (?1, ?2, ?3, ?4)",
                        params![key, enc, micro, height as i64],
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                }
                Ok(())
            })();

            match result {
                Ok(()) => conn
                    .execute_batch("COMMIT")
                    .map_err(|e| GhostError::Database(e.to_string())),
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK");
                    Err(e)
                }
            }
        })
    }

    /// Replace ONE node's column — the persistence half of a verified max-merge or of this
    /// node's own accrual, leaving every other column untouched.
    ///
    /// The caller passes the column's full post-merge contents, never a delta: replace semantics
    /// need the whole truth, and handing this method a partial map would delete the rest of the
    /// column — which is exactly what the replace rule is FOR when the shrink is real.
    pub fn shard_upsert_column(
        &self,
        node: &NodeId,
        column: &BTreeMap<String, i64>,
        epoch: u64,
    ) -> GhostResult<()> {
        let cells = encrypt_cells(self, column)?;
        self.with_connection(|conn| {
            conn.execute_batch("BEGIN IMMEDIATE")
                .map_err(|e| GhostError::Database(e.to_string()))?;
            match replace_column_tx(conn, node, &cells, epoch) {
                Ok(()) => conn
                    .execute_batch("COMMIT")
                    .map_err(|e| GhostError::Database(e.to_string())),
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK");
                    Err(e)
                }
            }
        })
    }

    /// Close an epoch: credit this node's column, drop the epoch's evidence, and durably mark
    /// the epoch folded — ONE transaction.
    ///
    /// Torn apart, the seam is money: evidence deleted before the credit lands is work silently
    /// lost on a crash (the 6,499-share lesson), and a credit that lands before the evidence
    /// goes is work double-counted when the survivor rows are re-folded. The summary row is
    /// written LAST inside the transaction because it is the durable "this epoch is folded"
    /// marker — nothing may claim an epoch is folded before everything the claim covers is in
    /// the same commit.
    ///
    /// `column` is this node's full post-fold column (see [`Database::shard_upsert_column`] on
    /// why a delta would be wrong). `evidence` is the epoch's share hashes as `ShareProof`
    /// carries them — INTERNAL byte order, hex-encoded here to match how `shares.share_hash` is
    /// stored (never display order; that mix-up has cost an outage before). Deletes run in
    /// bounded chunks inside the one transaction; missing rows are not an error, because a
    /// retry after a partial failure legitimately finds some already gone.
    ///
    /// Idempotent as a whole: a retry with the same summary replaces the column with the same
    /// contents, deletes nothing, and the summary guard accepts its own root again.
    ///
    /// Returns how many evidence rows were deleted.
    pub fn shard_fold_epoch(
        &self,
        node: &NodeId,
        column: &BTreeMap<String, i64>,
        summary: &EpochSummary,
        evidence: &[[u8; 32]],
    ) -> GhostResult<usize> {
        let cells = encrypt_cells(self, column)?;
        let summary_json = serde_json::to_string(summary)
            .map_err(|e| GhostError::Database(format!("summary does not serialise: {e}")))?;
        let summary_enc = self.encrypt_address(&summary_json)?;
        let hashes: Vec<String> = evidence.iter().map(hex::encode).collect();

        self.with_connection(|conn| {
            conn.execute_batch("BEGIN IMMEDIATE")
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = (|| -> GhostResult<usize> {
                replace_column_tx(conn, node, &cells, summary.epoch)?;

                let mut deleted = 0usize;
                for chunk in hashes.chunks(EVIDENCE_DELETE_CHUNK) {
                    let placeholders = vec!["?"; chunk.len()].join(", ");
                    let sql = format!("DELETE FROM shares WHERE share_hash IN ({placeholders})");
                    deleted += conn
                        .execute(&sql, params_from_iter(chunk.iter()))
                        .map_err(|e| GhostError::Database(e.to_string()))?;
                }

                store_epoch_tx(conn, summary, &summary_enc, false)?;
                Ok(deleted)
            })();

            match result {
                Ok(deleted) => {
                    conn.execute_batch("COMMIT")
                        .map_err(|e| GhostError::Database(e.to_string()))?;
                    Ok(deleted)
                }
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK");
                    Err(e)
                }
            }
        })
    }

    /// Add an amount the chain actually paid to `address` — the persistence twin of
    /// `ShardTable::record_settled`, and additive for the same reason: `settled` only ever
    /// grows, and each block's paid amounts arrive as increments read off the chain at coinbase
    /// maturity (§4.6). Non-positive amounts are ignored exactly as the in-memory side ignores
    /// Settle one matured pool block: record its hash and credit each address's paid micro-work,
    /// ONE transaction. Returns whether anything was applied — `false` means the block was
    /// already settled and NOTHING moved, which is the caller's cue to leave its in-memory
    /// `settled` untouched too.
    ///
    /// The block row is the idempotence record (`shard_settled_blocks`, keyed on block hash), and
    /// it is written in the SAME transaction as the credits, because the seam between them is
    /// money: a block recorded before its credits landed is a payment silently never discharged
    /// (the work is owed forever and the next coinbase pays it again), and credits landing before
    /// the record means a crash between the two discharges the same block twice on replay.
    /// Deliberately NOT the legacy `settled_blocks` table — the two ledgers settle independently,
    /// and a shared record is how one silently starts depending on the other.
    ///
    /// `block_hash` must be DISPLAY order — the caller normalises, because the idempotence key
    /// only works if every caller spells the hash the same way (the internal-order trap has cost
    /// an outage before). `amounts` are per-address micro-work increments; non-positive entries
    /// are ignored exactly as [`ShardTable::record_settled`] ignores them. An empty `amounts`
    /// still records the block: a pool block that paid no currently-owed address discharges
    /// nothing, but must never be re-examined as though it were new.
    pub fn shard_settle_block(
        &self,
        block_hash: &str,
        height: u64,
        amounts: &[(String, i64)],
    ) -> GhostResult<bool> {
        // Encrypted outside the connection lock, same rationale as `encrypt_cells`.
        let cells: Vec<EncryptedCell> = amounts
            .iter()
            .filter(|(_, micro)| *micro > 0)
            .map(|(addr, micro)| Ok((address_key(addr), self.encrypt_address(addr)?, *micro)))
            .collect::<GhostResult<Vec<_>>>()?;
        let discharged_total: i64 = cells.iter().map(|(_, _, m)| *m).sum();
        let settled_ts = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            conn.execute_batch("BEGIN IMMEDIATE")
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = (|| -> GhostResult<bool> {
                // The idempotence gate, first: if the hash is already recorded nothing else in
                // this transaction may run, so a re-examined block cannot discharge twice.
                let inserted = conn
                    .execute(
                        "INSERT OR IGNORE INTO shard_settled_blocks \
                         (block_hash, block_height, discharged_micro, settled_ts) \
                         VALUES (?1, ?2, ?3, ?4)",
                        params![block_hash, height as i64, discharged_total, settled_ts],
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                if inserted == 0 {
                    return Ok(false);
                }
                for (key, enc, micro) in &cells {
                    conn.execute(
                        "INSERT INTO shard_settled (address_hash, address_enc, settled_micro, \
                         last_height) VALUES (?1, ?2, ?3, ?4) \
                         ON CONFLICT(address_hash) DO UPDATE SET \
                         settled_micro = settled_micro + excluded.settled_micro, \
                         last_height = MAX(last_height, excluded.last_height)",
                        params![key, enc, micro, height as i64],
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                }
                Ok(true)
            })();

            match result {
                Ok(applied) => {
                    conn.execute_batch("COMMIT")
                        .map_err(|e| GhostError::Database(e.to_string()))?;
                    Ok(applied)
                }
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK");
                    Err(e)
                }
            }
        })
    }

    /// Persist a summary outside an epoch fold — e.g. one rebuilt for a peer that asked before
    /// the fold's own write was needed. Same guard as the in-fold path: idempotent on the same
    /// root, refuses a different one.
    pub fn shard_store_epoch(&self, summary: &EpochSummary, published: bool) -> GhostResult<()> {
        let summary_json = serde_json::to_string(summary)
            .map_err(|e| GhostError::Database(format!("summary does not serialise: {e}")))?;
        let summary_enc = self.encrypt_address(&summary_json)?;
        self.with_connection(|conn| store_epoch_tx(conn, summary, &summary_enc, published))
    }

    /// The stored summary for `epoch`, or `None`.
    ///
    /// Decrypt-then-deserialise: re-serialisation for a peer is harmless because the signature
    /// covers `signing_bytes`, not the JSON encoding — a round-tripped summary still verifies
    /// (unlike `sbc_batches`, whose batch hash covered the stored bytes themselves).
    pub fn shard_get_epoch(&self, epoch: u64, node: &NodeId) -> GhostResult<Option<EpochSummary>> {
        let enc: Option<String> = self.with_connection(|conn| {
            Ok(conn
                .query_row(
                    "SELECT summary_enc FROM shard_epochs WHERE epoch = ?1 AND node_id = ?2",
                    params![epoch as i64, node.to_vec()],
                    |r| r.get(0),
                )
                .ok())
        })?;
        match enc {
            None => Ok(None),
            Some(enc) => {
                let json = self.decrypt_address(&enc)?;
                let summary = serde_json::from_str(&json).map_err(|e| {
                    GhostError::Database(format!("stored epoch summary does not parse: {e}"))
                })?;
                Ok(Some(summary))
            }
        }
    }

    /// The highest epoch this node holds a summary for, or `None` if it has never folded.
    ///
    /// This is the fold watermark a restart resumes from: the summary row is written in the same
    /// transaction as the fold itself, so "highest stored epoch" and "highest folded epoch" cannot
    /// disagree — which is what makes resume-not-restart safe to derive rather than track.
    pub fn shard_latest_epoch(&self, node: &NodeId) -> GhostResult<Option<u64>> {
        self.with_connection(|conn| {
            conn.query_row(
                "SELECT MAX(epoch) FROM shard_epochs WHERE node_id = ?1",
                params![node.to_vec()],
                |r| r.get::<_, Option<i64>>(0),
            )
            .map_err(|e| GhostError::Database(e.to_string()))
            .map(|opt| opt.map(|v| v as u64))
        })
    }

    /// Drop this node's own epoch summaries at or above `from_epoch`. Returns how many went.
    ///
    /// **Only the Stage 5 arming ceremony calls this**, and it is load-bearing there rather than
    /// tidy-up. Arming replaces the whole table with the genesis balances, which discards the
    /// columns the Stage 4 soak accrued — but the summary rows the soak wrote would survive, and
    /// `shard_fold_epoch`'s idempotence gate reads exactly those rows. The catch-up would then see
    /// every epoch between the anchor and the moment of arming as `AlreadyFolded`, credit nothing,
    /// and every miner's work across that window would vanish with no error anywhere.
    ///
    /// Scoped to `from_epoch` (the arming floor) and to this node's own column: summaries below
    /// the floor are pre-genesis and their work is already inside the genesis balances, so
    /// re-folding them would double-count, and another node's summaries are not ours to delete.
    /// Drop EVERY node's retained summaries at or above `from_epoch`. Returns how many went.
    ///
    /// **Only the Stage 5 arming ceremony calls this**, and it must clear peers' rows as well as
    /// this node's, for a reason that is not obvious until gossip is running.
    ///
    /// Arming rewinds the fold watermark to the floor and re-folds every epoch since the anchor —
    /// dozens of them — with different totals, because the ceremony reset the column. Peers still
    /// hold this node's PRE-arming summaries for those same epochs. On the next broadcast a peer
    /// looks up the same epoch, finds a stored summary with different signing bytes, and returns
    /// `SummaryEquivocation`: the verdict that a node signed two conflicting statements, which §6
    /// treats as publishable evidence of misbehaviour. An honest node would be accused of
    /// equivocating BY THE CEREMONY, and `store_epoch_tx` deliberately refuses to overwrite the
    /// held row, so the stale evidence persists and every re-fold is rejected again.
    ///
    /// Those summaries describe a ledger that no longer exists. Genesis is a reset, so the
    /// evidence of the pre-genesis ledger is cleared with it.
    pub fn shard_clear_all_epochs_from(&self, from_epoch: u64) -> GhostResult<usize> {
        self.with_connection(|conn| {
            conn.execute(
                "DELETE FROM shard_epochs WHERE epoch >= ?1",
                params![from_epoch as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))
        })
    }

    pub fn shard_clear_own_epochs_from(
        &self,
        node: &NodeId,
        from_epoch: u64,
    ) -> GhostResult<usize> {
        self.with_connection(|conn| {
            conn.execute(
                "DELETE FROM shard_epochs WHERE node_id = ?1 AND epoch >= ?2",
                params![node.to_vec(), from_epoch as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))
        })
    }

    /// This node's OWN summaries that have not yet been broadcast, oldest first.
    ///
    /// Drives the gossip relay. Reading from the `published` flag rather than from whatever the
    /// fold just returned is what makes the broadcast survive a restart: a summary folded and
    /// persisted but never put on the wire is still pending on the next start, instead of being
    /// silently lost with the process that folded it.
    ///
    /// Bounded by `limit` so a node that has been offline does not try to broadcast a whole
    /// backlog in one tick — the same lock-fairness reasoning as the fold's bounded batches.
    pub fn shard_unpublished_epochs(
        &self,
        node: &NodeId,
        limit: u32,
    ) -> GhostResult<Vec<EpochSummary>> {
        let rows: Vec<String> = self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT summary_enc FROM shard_epochs \
                     WHERE node_id = ?1 AND published = 0 ORDER BY epoch ASC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let out = stmt
                .query_map(params![node.to_vec(), limit as i64], |r| {
                    r.get::<_, String>(0)
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(out)
        })?;

        let mut summaries = Vec::with_capacity(rows.len());
        for enc in rows {
            // A row that cannot be decrypted or parsed is an ERROR, not a skip: silently dropping
            // it would leave the epoch permanently unpublished with nothing saying why.
            let json = self.decrypt_address(&enc)?;
            summaries.push(serde_json::from_str(&json).map_err(|e| {
                GhostError::Database(format!("stored epoch summary does not parse: {e}"))
            })?);
        }
        Ok(summaries)
    }

    /// Mark an epoch's summary as having been broadcast. Returns whether the row existed —
    /// marking a summary that was never stored is a caller bug worth surfacing, not a silent
    /// no-op.
    pub fn shard_mark_epoch_published(&self, epoch: u64, node: &NodeId) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let n = conn
                .execute(
                    "UPDATE shard_epochs SET published = 1 WHERE epoch = ?1 AND node_id = ?2",
                    params![epoch as i64, node.to_vec()],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(n > 0)
        })
    }

    /// Whether that node's summary for `epoch` has been marked published.
    ///
    /// Published is a property of *our own* broadcast, so this is normally asked about our own
    /// node id; it takes one anyway rather than assuming, because the table now holds peers' rows
    /// too and a query that silently matched the wrong node would be invisible.
    pub fn shard_epoch_published(&self, epoch: u64, node: &NodeId) -> GhostResult<Option<bool>> {
        self.with_connection(|conn| {
            Ok(conn
                .query_row(
                    "SELECT published FROM shard_epochs WHERE epoch = ?1 AND node_id = ?2",
                    params![epoch as i64, node.to_vec()],
                    |r| r.get::<_, i64>(0),
                )
                .ok()
                .map(|v| v != 0))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::share_shard::EpochDelta;

    fn db() -> Database {
        let db = Database::in_memory().expect("in-memory db");
        db.set_encryption_key([0x42u8; 32]);
        db
    }

    fn col(pairs: &[(&str, i64)]) -> BTreeMap<String, i64> {
        pairs.iter().map(|(a, w)| (a.to_string(), *w)).collect()
    }

    /// A structurally valid summary without a real signature — storage never verifies (that is
    /// `apply_summary`'s job, and verification needs the Merkle tree this crate cannot depend
    /// on), it only round-trips.
    fn summary(
        epoch: u64,
        node: NodeId,
        root: [u8; 32],
        rows: &[(&str, i64, i64)],
    ) -> EpochSummary {
        EpochSummary {
            epoch,
            node_id: node,
            deltas: rows
                .iter()
                .map(|(addr, delta, total)| {
                    (
                        addr.to_string(),
                        EpochDelta {
                            delta_micro: *delta,
                            total_micro: *total,
                        },
                    )
                })
                .collect(),
            genesis_marker: None,
            share_count: rows.len() as u32,
            share_root: root,
            signature: vec![0xAB; 64],
        }
    }

    /// Insert a raw share row the way ingest stores it: hex share_hash, internal byte order.
    fn seed_share(db: &Database, hash: [u8; 32], ts: i64) {
        db.with_connection(|conn| {
            conn.execute(
                "INSERT INTO shares (round_id, miner_id, difficulty, work, share_hash, \
                 timestamp, received_by, valid) VALUES (1, 'm', 1.0, 1.0, ?1, ?2, 'n', 1)",
                params![hex::encode(hash), ts],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
        .expect("seed share");
    }

    fn count_shares(db: &Database) -> i64 {
        db.with_connection(|conn| {
            conn.query_row("SELECT COUNT(*) FROM shares", [], |r| r.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))
        })
        .expect("count")
    }

    /// The persisted table must reload byte-identically under `compute_table_root`. The root is
    /// what the fleet compares (§12.6), so a lossy round trip is a node that diverges while every
    /// local check passes — the hardest fault to attribute.
    #[test]
    fn table_round_trips_through_sqlite_byte_identically() {
        let db = db();
        let mut table = ShardTable::new();
        table.accrue([0x11; 32], "bc1qalice", 1_500_000);
        table.accrue([0x11; 32], "bc1qbob", 2_750_000);
        table.accrue([0x22; 32], "bc1qalice", 125_000);
        table.record_settled("bc1qalice", 1_000_000);
        // An address the chain paid that never accrued here: owed is negative, and it must
        // survive persistence, because the negative residual IS the §4.4 correction.
        table.record_settled("bc1qphantom", 5_000_000);

        db.shard_save_table(&table, 9, 961_700).expect("save");
        let loaded = db.shard_load_table().expect("load");

        assert_eq!(
            loaded.compute_table_root(),
            table.compute_table_root(),
            "the persisted table must reload root-identically"
        );
        assert_eq!(loaded, table);
        assert_eq!(loaded.owed().get("bc1qphantom"), Some(&-5_000_000));
    }

    /// A save must REPLACE. The legitimate shrink is compaction/rebase; a row absent from the
    /// saved table that survives in SQLite keeps contributing to the next load's root, and the
    /// node becomes internally consistent and externally wrong.
    #[test]
    fn saving_replaces_rather_than_merges() {
        let db = db();
        let mut before = ShardTable::new();
        before.accrue([0x11; 32], "bc1qalice", 10);
        before.accrue([0x11; 32], "bc1qbob", 20);
        before.accrue([0x22; 32], "bc1qcarol", 30);
        before.record_settled("bc1qalice", 5);
        db.shard_save_table(&before, 1, 100).expect("first save");

        // Post-compaction shape: bob's cell and carol's whole column are gone, settled rebased.
        let mut after = ShardTable::new();
        after.accrue([0x11; 32], "bc1qalice", 40);
        db.shard_save_table(&after, 2, 200).expect("second save");

        let loaded = db.shard_load_table().expect("load");
        assert_eq!(
            loaded, after,
            "rows absent from the saved table must be deleted, not left contributing"
        );
        assert_eq!(loaded.compute_table_root(), after.compute_table_root());
    }

    /// A column upsert replaces that node's column and touches nothing else — per-node replace
    /// is what lets a verified merge persist one column without rewriting the world.
    #[test]
    fn upsert_replaces_one_column_and_leaves_the_others_alone() {
        let db = db();
        db.shard_upsert_column(&[0x11; 32], &col(&[("bc1qalice", 10), ("bc1qbob", 20)]), 1)
            .expect("column A");
        db.shard_upsert_column(&[0x22; 32], &col(&[("bc1qcarol", 30)]), 1)
            .expect("column B");

        // A's next state no longer contains bob (compaction). B must be untouched.
        db.shard_upsert_column(&[0x11; 32], &col(&[("bc1qalice", 50)]), 2)
            .expect("column A again");

        let mut expected = ShardTable::new();
        expected.accrue([0x11; 32], "bc1qalice", 50);
        expected.accrue([0x22; 32], "bc1qcarol", 30);
        assert_eq!(db.shard_load_table().expect("load"), expected);
    }

    /// THE Stage-1 invariant: fold-then-delete is one transaction. A failure anywhere inside it
    /// must leave the counters, the evidence and the epoch record all untouched — a seam here is
    /// either silently lost work or double-counted work depending on which half survived.
    ///
    /// The failure is a real one, not injected: the epoch already holds a DIFFERENT signed
    /// summary, which the guard refuses. The guard runs last, so by then the column has been
    /// replaced and the evidence deleted inside the transaction — all of it must roll back.
    #[test]
    fn fold_then_delete_is_one_transaction() {
        let db = db();
        let node = [0x11; 32];

        // The epoch's evidence, plus a bystander share from another epoch.
        seed_share(&db, [0xA1; 32], 10);
        seed_share(&db, [0xA2; 32], 11);
        seed_share(&db, [0xB1; 32], 99);

        // Pre-fold column state.
        db.shard_upsert_column(&node, &col(&[("bc1qalice", 100)]), 6)
            .expect("prior column");
        let before = db.shard_load_table().expect("load before");

        // Epoch 7 already holds a different summary (different root) — the fold must refuse.
        db.shard_store_epoch(&summary(7, node, [0xEE; 32], &[("bc1qother", 1, 1)]), false)
            .expect("conflicting summary");

        let err = db
            .shard_fold_epoch(
                &node,
                &col(&[("bc1qalice", 160)]),
                &summary(7, node, [0x33; 32], &[("bc1qalice", 60, 160)]),
                &[[0xA1; 32], [0xA2; 32]],
            )
            .expect_err("a conflicting epoch record must fail the fold");
        assert!(
            format!("{err}").contains("different summary"),
            "the refusal must name what it is: {err}"
        );

        // Nothing moved: not the counters, not the evidence.
        assert_eq!(
            db.shard_load_table().expect("load after"),
            before,
            "a failed fold must leave the counters untouched"
        );
        assert_eq!(
            count_shares(&db),
            3,
            "a failed fold must leave the evidence untouched"
        );

        // The same fold against a free epoch lands whole: credit, deletion and marker together.
        let deleted = db
            .shard_fold_epoch(
                &node,
                &col(&[("bc1qalice", 160)]),
                &summary(8, node, [0x33; 32], &[("bc1qalice", 60, 160)]),
                &[[0xA1; 32], [0xA2; 32]],
            )
            .expect("clean fold");
        assert_eq!(deleted, 2);
        assert_eq!(count_shares(&db), 1, "the bystander share must survive");
        let mut expected = ShardTable::new();
        expected.accrue(node, "bc1qalice", 160);
        assert_eq!(db.shard_load_table().expect("load folded"), expected);

        // Retrying the same fold is a no-op that succeeds: same column contents, evidence
        // already gone, same root at the epoch.
        let deleted = db
            .shard_fold_epoch(
                &node,
                &col(&[("bc1qalice", 160)]),
                &summary(8, node, [0x33; 32], &[("bc1qalice", 60, 160)]),
                &[[0xA1; 32], [0xA2; 32]],
            )
            .expect("retry after crash-and-replay must succeed");
        assert_eq!(deleted, 0);
        assert_eq!(db.shard_load_table().expect("load retried"), expected);
    }

    /// Settled amounts accumulate — each block's paid amounts are increments, mirroring
    /// `ShardTable::record_settled` — and non-positive amounts are ignored on both sides so the
    /// persisted and in-memory quantities can never drift on an edge case.
    #[test]
    fn settled_accumulates_and_ignores_non_positive() {
        // Driven through `shard_settle_block`, which is now the ONLY way settled money is written.
        // There used to be a second path with the same SQL and no idempotence row; two spellings
        // of one money write is how the pair drift apart, and the copy without the block hash was
        // the one that could credit twice.
        let db = db();
        db.shard_settle_block("aa", 100, &[("bc1qalice".into(), 60)])
            .expect("pay");
        db.shard_settle_block("bb", 150, &[("bc1qalice".into(), 40)])
            .expect("pay again");
        db.shard_settle_block("cc", 175, &[("bc1qalice".into(), 0)])
            .expect("zero");
        db.shard_settle_block("dd", 180, &[("bc1qalice".into(), -30)])
            .expect("negative");

        let mut expected = ShardTable::new();
        expected.record_settled("bc1qalice", 100);
        assert_eq!(
            db.shard_load_table().expect("load"),
            expected,
            "60 + 40, with zero and negative ignored"
        );
    }

    /// A settled block is settled once: the block row and the per-address credits are one
    /// transaction, and the recorded hash is the idempotence key. A second call with the same
    /// hash — a rewound scan cursor, a restart replaying the same lookback — must apply nothing,
    /// and must say so, because the caller's in-memory `settled` follows this verdict.
    #[test]
    fn settling_a_block_applies_once_and_a_repeat_applies_nothing() {
        let db = db();

        let amounts = vec![("bc1qalice".to_string(), 5_000_000i64)];
        assert!(
            db.shard_settle_block("00aa", 961_700, &amounts)
                .expect("settle"),
            "the first settlement of a block must apply"
        );
        assert!(
            !db.shard_settle_block("00aa", 961_700, &amounts)
                .expect("repeat"),
            "a re-settled block must be a no-op, and say so"
        );

        let mut expected = ShardTable::new();
        expected.record_settled("bc1qalice", 5_000_000);
        assert_eq!(
            db.shard_load_table().expect("load"),
            expected,
            "the credit must have landed exactly once"
        );

        // A DIFFERENT block paying the same address accumulates — per-block idempotence must not
        // become per-address idempotence.
        assert!(db
            .shard_settle_block("00bb", 961_800, &amounts)
            .expect("settle 2"));
        expected.record_settled("bc1qalice", 5_000_000);
        assert_eq!(db.shard_load_table().expect("load"), expected);

        // A pool block that discharged nothing is still recorded, so it is never re-examined as
        // new — but it credits nobody.
        assert!(db.shard_settle_block("00cc", 961_900, &[]).expect("empty"));
        assert!(!db
            .shard_settle_block("00cc", 961_900, &[])
            .expect("empty repeat"));
        assert_eq!(db.shard_load_table().expect("load"), expected);
    }

    /// A stored summary must read back exactly — same signing bytes, same signature — because a
    /// syncing peer will verify what we serve, and `signing_bytes` is what its signature covers.
    /// The equivocation-shaped guard refuses a different summary at an occupied epoch.
    #[test]
    fn epoch_summaries_round_trip_and_refuse_a_conflicting_rewrite() {
        let db = db();
        let node = [0x77; 32];
        let s = summary(
            5,
            node,
            [0x44; 32],
            &[("bc1qalice", 7, 107), ("bc1qbob", 3, 3)],
        );

        db.shard_store_epoch(&s, false).expect("store");
        db.shard_store_epoch(&s, false)
            .expect("storing the same summary again is a retry, not an error");

        let back = db.shard_get_epoch(5, &node).expect("get").expect("present");
        assert_eq!(back.signing_bytes(), s.signing_bytes());
        assert_eq!(back.signature, s.signature);
        assert!(db.shard_get_epoch(6, &node).expect("get").is_none());

        // Published is a flag on the stored row, not part of the summary.
        assert_eq!(
            db.shard_epoch_published(5, &node).expect("flag"),
            Some(false)
        );
        assert!(db.shard_mark_epoch_published(5, &node).expect("mark"));
        assert_eq!(
            db.shard_epoch_published(5, &node).expect("flag"),
            Some(true)
        );
        assert!(
            !db.shard_mark_epoch_published(6, &node)
                .expect("mark missing"),
            "marking an epoch that was never stored must say so"
        );

        // The point of keying on (epoch, node_id): a peer's summary for the SAME epoch is the
        // normal case and must coexist. Keyed on epoch alone this row would have collided, and
        // the table could only ever have held our own summaries — leaving nothing to make an
        // accusation out of.
        let peer = [0x99; 32];
        let peer_summary = summary(5, peer, [0x66; 32], &[("bc1qcarol", 9, 9)]);
        db.shard_store_epoch(&peer_summary, false)
            .expect("a peer's summary at the same epoch must coexist, not collide");
        assert_eq!(
            db.shard_get_epoch(5, &peer)
                .expect("get")
                .expect("present")
                .share_root,
            [0x66; 32]
        );
        assert_eq!(
            db.shard_get_epoch(5, &node)
                .expect("get")
                .expect("present")
                .share_root,
            [0x44; 32],
            "storing a peer's summary must not disturb our own"
        );

        // A different root under the SAME (epoch, node) is that node signing two conflicting
        // statements for one epoch — equivocation, refused, and the held row is the evidence.
        let conflicting = summary(5, node, [0x55; 32], &[("bc1qalice", 8, 108)]);
        db.shard_store_epoch(&conflicting, false)
            .expect_err("a different summary at an occupied (epoch, node) must be refused");
        let kept = db.shard_get_epoch(5, &node).expect("get").expect("present");
        assert_eq!(kept.share_root, [0x44; 32], "the original statement stays");
    }

    /// The fold watermark: the highest epoch THIS node has folded, scoped to this node. Peers'
    /// rows share the table, so an unscoped MAX would resume from a peer's progress — silently
    /// skipping every epoch between our real watermark and theirs, work this node never folds.
    #[test]
    fn latest_epoch_is_scoped_to_the_node_and_absent_when_never_folded() {
        let db = db();
        let node = [0x11; 32];
        let peer = [0x99; 32];

        assert_eq!(
            db.shard_latest_epoch(&node).expect("query"),
            None,
            "a node that never folded has no watermark to resume from"
        );

        db.shard_store_epoch(&summary(3, node, [0x01; 32], &[]), false)
            .expect("store");
        db.shard_store_epoch(&summary(7, node, [0x02; 32], &[]), false)
            .expect("store");
        db.shard_store_epoch(&summary(9, peer, [0x03; 32], &[]), false)
            .expect("peer store");

        assert_eq!(db.shard_latest_epoch(&node).expect("query"), Some(7));
        assert_eq!(db.shard_latest_epoch(&peer).expect("query"), Some(9));
    }
}
