//|======================================================================================================================|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: node_pool_genesis.rs                                                                                           |
//|======================================================================================================================|

//! The imported genesis table (migration v65): the balances the old system owed at the freeze,
//! which every share-chain snapshot folds onto.
//!
//! Written once, by the genesis import (`pool_sv2 --np-import-genesis`), into a store whose
//! ledger is still empty, and never changed after. Read at relay start-up, where its
//! [`table_root`] is checked against the pinned `genesis_table_digest`. The stored provenance row
//! carries the root computed at import, and every read recomputes it and refuses a mismatch, so a
//! hand-edited row cannot reach the relay unnoticed.
//!
//! The genesis table is not part of `np_ledger`: that table holds what the share chain changed
//! (credits and retirements), and settlement folds it onto the genesis table.

use ghost_common::canonical_payout::{table_root, Balance, Table};
use ghost_common::error::{GhostError, GhostResult};
use rusqlite::{params, Connection, OptionalExtension};

use crate::database::Database;
use crate::node_pool_store::{face_from_blob, face_to_blob};

/// The provenance of an imported genesis table (`np_genesis_meta`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpGenesisMeta {
    /// sha256 of the `ledger-export.bin` it was imported from.
    pub export_digest: [u8; 32],
    /// The export's network, as the export names it (`bitcoin`, `signet`, `regtest`).
    pub network: String,
    /// The export's height: the freeze height.
    pub export_height: u64,
    /// The `queue_since` every row at or above the payout floor was given.
    pub queue_since: u32,
    /// Rows imported.
    pub row_count: u64,
    /// `table_root` of the imported table: the digest a node pins.
    pub table_root: [u8; 32],
    /// When it was imported, unix seconds.
    pub imported_at: i64,
}

/// One payee's row in the imported genesis table: the balance carried over at the cutover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NpGenesisBalance {
    /// The row as imported.
    pub balance: Balance,
    /// The export's height (the freeze height): when the balance was carried over.
    pub export_height: u64,
    /// When the table was imported into this store, unix seconds.
    pub imported_at: i64,
    /// The header time of this node's archived block at `export_height`, if it holds one.
    pub chain_time: Option<u32>,
}

/// The `np_*` tables that must be empty for an import: the genesis table is the base every one
/// of them was computed on, so it cannot change under them.
const LEDGER_TABLES: &[&str] = &[
    "np_genesis",
    "np_ledger",
    "np_ledger_events",
    "np_credits",
    "np_retirements",
    "np_anchors",
    "np_batches",
    "np_checkpoints",
    "np_snapshot_roots",
];

fn db_err(e: rusqlite::Error) -> GhostError {
    GhostError::Database(e.to_string())
}

fn blob32(v: Vec<u8>, what: &str) -> GhostResult<[u8; 32]> {
    v.try_into()
        .map_err(|_| GhostError::Database(format!("{what} is not 32 bytes")))
}

fn read_meta(conn: &Connection) -> GhostResult<Option<NpGenesisMeta>> {
    let row = conn
        .query_row(
            "SELECT export_digest, network, export_height, queue_since, row_count, table_root, \
             imported_at FROM np_genesis_meta WHERE id = 1",
            [],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, Vec<u8>>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()
        .map_err(db_err)?;
    let Some((d, network, h, q, n, root, at)) = row else {
        return Ok(None);
    };
    let int = |v: i64, what: &str| {
        u64::try_from(v).map_err(|_| GhostError::Database(format!("np_genesis_meta {what} {v}")))
    };
    Ok(Some(NpGenesisMeta {
        export_digest: blob32(d, "np_genesis_meta export_digest")?,
        network,
        export_height: int(h, "export_height")?,
        queue_since: u32::try_from(q)
            .map_err(|_| GhostError::Database(format!("np_genesis_meta queue_since {q}")))?,
        row_count: int(n, "row_count")?,
        table_root: blob32(root, "np_genesis_meta table_root")?,
        imported_at: at,
    }))
}

fn read_rows(conn: &Connection) -> GhostResult<Table> {
    let mut stmt = conn
        .prepare("SELECT script, owed, queue_since FROM np_genesis")
        .map_err(db_err)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Option<i64>>(2)?,
            ))
        })
        .map_err(db_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_err)?;
    let mut t = Table::new();
    for (s, o, q) in rows {
        let queue_since = q
            .map(|q| {
                u32::try_from(q)
                    .map_err(|_| GhostError::Database(format!("np_genesis queue_since {q}")))
            })
            .transpose()?;
        t.insert(
            s,
            Balance {
                owed: face_from_blob(&o)?,
                queue_since,
            },
        );
    }
    Ok(t)
}

impl Database {
    /// The imported genesis table's provenance, or `None` before the import.
    pub fn np_genesis_meta(&self) -> GhostResult<Option<NpGenesisMeta>> {
        self.with_connection(read_meta)
    }

    /// `script`'s row in the imported genesis table, `None` if it has none (or nothing was
    /// imported). One row, read without recomputing the table's root: the relay checked the
    /// whole table against its pin when it started on this store.
    pub fn np_genesis_balance(&self, script: &[u8]) -> GhostResult<Option<NpGenesisBalance>> {
        self.with_connection(|conn| {
            let Some(m) = read_meta(conn)? else {
                return Ok(None);
            };
            let row = conn
                .query_row(
                    "SELECT owed, queue_since, \
                            (SELECT header FROM np_btc_blocks WHERE height = ?2 LIMIT 1) \
                     FROM np_genesis WHERE script = ?1",
                    params![script, i64::try_from(m.export_height).unwrap_or(i64::MAX)],
                    |r| {
                        Ok((
                            r.get::<_, Vec<u8>>(0)?,
                            r.get::<_, Option<i64>>(1)?,
                            r.get::<_, Option<Vec<u8>>>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(db_err)?;
            let Some((owed, q, header)) = row else {
                return Ok(None);
            };
            let queue_since = q
                .map(|q| {
                    u32::try_from(q)
                        .map_err(|_| GhostError::Database(format!("np_genesis queue_since {q}")))
                })
                .transpose()?;
            Ok(Some(NpGenesisBalance {
                balance: Balance {
                    owed: face_from_blob(&owed)?,
                    queue_since,
                },
                export_height: m.export_height,
                imported_at: m.imported_at,
                chain_time: header
                    .as_deref()
                    .and_then(|h| h.get(68..72))
                    .and_then(|t| <[u8; 4]>::try_from(t).ok())
                    .map(u32::from_le_bytes),
            }))
        })
    }

    /// The genesis table: empty before the import. Refuses rows with no provenance, and a table
    /// whose recomputed `table_root` or row count differs from the one recorded at import.
    pub fn np_genesis_table(&self) -> GhostResult<Table> {
        self.with_connection(|conn| {
            let table = read_rows(conn)?;
            match read_meta(conn)? {
                None if table.is_empty() => Ok(table),
                None => Err(GhostError::Database(format!(
                    "np_genesis holds {} rows but no np_genesis_meta: not written by the import",
                    table.len()
                ))),
                Some(m) => {
                    let root = table_root(&table);
                    if root != m.table_root || table.len() as u64 != m.row_count {
                        return Err(GhostError::Database(format!(
                            "np_genesis does not match its import record: {} rows with root {}, \
                             recorded {} rows with root {}",
                            table.len(),
                            hex::encode(root),
                            m.row_count,
                            hex::encode(m.table_root)
                        )));
                    }
                    Ok(table)
                }
            }
        })
    }

    /// Write the genesis table and its provenance in one transaction. Refuses a second import
    /// and any store whose ledger is not empty (the relay has run on it). `meta.table_root` and
    /// `meta.row_count` must describe `table`.
    pub fn np_import_genesis(&self, table: &Table, meta: &NpGenesisMeta) -> GhostResult<()> {
        if table_root(table) != meta.table_root || table.len() as u64 != meta.row_count {
            return Err(GhostError::Database(
                "the genesis import record does not describe the table it carries".to_string(),
            ));
        }
        self.transaction(|tx| {
            if let Some(m) = read_meta(tx)? {
                return Err(GhostError::Database(format!(
                    "a genesis table is already imported (export {}, table_root {}, {} rows, \
                     at {}): an import runs once",
                    hex::encode(m.export_digest),
                    hex::encode(m.table_root),
                    m.row_count,
                    m.imported_at
                )));
            }
            for t in LEDGER_TABLES {
                let n: i64 = tx
                    .query_row(&format!("SELECT COUNT(*) FROM {t}"), [], |r| r.get(0))
                    .map_err(db_err)?;
                if n != 0 {
                    return Err(GhostError::Database(format!(
                        "{t} holds {n} rows: the genesis table is imported into an empty store, \
                         before the relay first runs on it"
                    )));
                }
            }
            for (script, b) in table {
                tx.execute(
                    "INSERT INTO np_genesis (script, owed, queue_since) VALUES (?1, ?2, ?3)",
                    params![
                        script,
                        face_to_blob(b.owed).to_vec(),
                        b.queue_since.map(i64::from)
                    ],
                )
                .map_err(db_err)?;
            }
            let height = i64::try_from(meta.export_height).map_err(|_| {
                GhostError::Database(format!("export height {}", meta.export_height))
            })?;
            tx.execute(
                "INSERT INTO np_genesis_meta (id, export_digest, network, export_height, \
                 queue_since, row_count, table_root, imported_at) \
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    meta.export_digest.to_vec(),
                    meta.network,
                    height,
                    i64::from(meta.queue_since),
                    table.len() as i64,
                    meta.table_root.to_vec(),
                    meta.imported_at
                ],
            )
            .map_err(db_err)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> Table {
        let mut t = Table::new();
        t.insert(
            vec![0x51, 0x20, 1],
            Balance {
                owed: 5 << 32,
                queue_since: None,
            },
        );
        t.insert(
            vec![0x00, 0x14, 2],
            Balance {
                owed: 2_000 << 32,
                queue_since: Some(974_500),
            },
        );
        t
    }

    fn meta(t: &Table) -> NpGenesisMeta {
        NpGenesisMeta {
            export_digest: [7; 32],
            network: "regtest".into(),
            export_height: 974_500,
            queue_since: 974_500,
            row_count: t.len() as u64,
            table_root: table_root(t),
            imported_at: 1,
        }
    }

    #[test]
    fn an_empty_store_has_an_empty_genesis() {
        let db = Database::in_memory().unwrap();
        assert!(db.np_genesis_table().unwrap().is_empty());
        assert!(db.np_genesis_meta().unwrap().is_none());
    }

    #[test]
    fn import_round_trips_and_runs_once() {
        let db = Database::in_memory().unwrap();
        let t = table();
        db.np_import_genesis(&t, &meta(&t)).unwrap();
        assert_eq!(db.np_genesis_table().unwrap(), t);
        assert_eq!(db.np_genesis_meta().unwrap(), Some(meta(&t)));
        let e = db.np_import_genesis(&t, &meta(&t)).unwrap_err().to_string();
        assert!(e.contains("already imported"), "{e}");
    }

    #[test]
    fn import_refuses_a_record_that_does_not_match_its_table() {
        let db = Database::in_memory().unwrap();
        let t = table();
        let mut m = meta(&t);
        m.table_root[0] ^= 1;
        assert!(db.np_import_genesis(&t, &m).is_err());
        assert!(db.np_genesis_meta().unwrap().is_none());
    }

    #[test]
    fn import_refuses_a_store_whose_ledger_is_not_empty() {
        let db = Database::in_memory().unwrap();
        db.np_apply_block(&[0xA0; 32], 121, &[(vec![0x51], 1)], 0)
            .unwrap();
        let t = table();
        let e = db.np_import_genesis(&t, &meta(&t)).unwrap_err().to_string();
        assert!(e.contains("np_ledger"), "{e}");
        assert!(db.np_genesis_table().unwrap().is_empty());
    }

    #[test]
    fn one_payees_genesis_row_reads_with_its_export_height() {
        let db = Database::in_memory().unwrap();
        assert_eq!(db.np_genesis_balance(&[0x00, 0x14, 2]).unwrap(), None);
        let t = table();
        db.np_import_genesis(&t, &meta(&t)).unwrap();
        let g = db.np_genesis_balance(&[0x00, 0x14, 2]).unwrap().unwrap();
        assert_eq!(g.balance, t[&vec![0x00, 0x14, 2]]);
        assert_eq!(
            (g.export_height, g.imported_at, g.chain_time),
            (974_500, 1, None)
        );
        assert_eq!(db.np_genesis_balance(&[0x00, 0x14, 9]).unwrap(), None);
    }

    #[test]
    fn a_tampered_row_is_refused_on_read() {
        let db = Database::in_memory().unwrap();
        let t = table();
        db.np_import_genesis(&t, &meta(&t)).unwrap();
        db.with_connection(|c| {
            c.execute(
                "UPDATE np_genesis SET owed = ?1",
                params![face_to_blob(9).to_vec()],
            )
            .map_err(db_err)
        })
        .unwrap();
        let e = db.np_genesis_table().unwrap_err().to_string();
        assert!(e.contains("does not match its import record"), "{e}");
    }
}
