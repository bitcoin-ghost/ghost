//|======================================================================================================================|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: migration_v65.rs                                                                                               |
//|======================================================================================================================|

//! Migration v65, the node pool cutover (plan Phase 4): drop the old system's tables and create
//! the genesis table the cutover's ledger export is imported into.
//!
//! In order, each step refusing with no change made:
//!
//! 1. **Halt on money.** Any row in a table that can hold user funds or an unspent claim refuses
//!    the migration, naming every table and its row count: `withdrawal_requests`, `ghost_locks`,
//!    every `l2_*` and `wraith_*` table, Ghost Pay's notes, nullifiers, transfers, shields and
//!    instant payments ([`HALT_TABLES`]), the confirmed pool's staged transactions and pending
//!    reconciliation entries, and a `node_rewards` row with a balance ([`HALT_WHERE`]). Those
//!    rows are value someone may still be owed, have locked or be able to spend; they are
//!    resolved by hand, never dropped by a binary. The old payout ledger is not on the list: the
//!    cutover's ledger export carries it into `np_genesis`.
//! 2. **Backup gate.** If any table to be dropped holds a row, a verified copy of the database
//!    must exist first: `<database>.pre-v65`, written with `VACUUM INTO` (the pattern of
//!    `deploy-node.sh`'s pre-migration gate, #996) after checking that the filesystem has twice
//!    the database free, and verified by attaching it and reading back its schema version and
//!    table count. An existing copy is reused only if it verifies; one that does not is refused,
//!    never overwritten. An in-memory database has nothing on disk to protect and skips the gate.
//!    A database whose old tables are all empty (every node pool server, which never ran the old
//!    system) needs no copy.
//! 3. **Drop and create**, in one transaction: [`DROPPED_TABLES`] go, `np_genesis` and
//!    `np_genesis_meta` are created, the drop is verified against `sqlite_master`, and the schema
//!    version is written in its negated form (below).
//! 4. **Space.** Dropping frees pages but does not shrink the file. With `auto_vacuum =
//!    INCREMENTAL` (every database created by `Database::open` since that pragma was added) the
//!    free list is drained here, one page per step, until it is empty, and the delta is checked.
//!    With `auto_vacuum = 0` (the old fleet's databases) nothing is run: returning the space needs
//!    a full `VACUUM`, which writes a second copy and so needs about twice the database free. It
//!    is never run implicitly.
//!
//! **Old binaries.** A binary from before v65 opening a v65 database would, by the existing rule,
//! warn that the schema is ahead and carry on, against tables that are gone: the old payout,
//! shard and checkpoint code would fail query by query rather than at start. So from v65 the
//! schema version is stored **negated** in `PRAGMA user_version` (v65 is `-65`). Every earlier
//! binary reads `user_version` as a `u32` before anything else, and a negative value fails that
//! conversion, so `Database::open` returns an error and the old binary refuses to start. This
//! binary decodes both forms ([`crate::migrations::decode_schema_version`]). Shell tools that
//! read `user_version` accept the leading `-` (`scripts/lib/migration-backup-gate.sh`,
//! `scripts/backup-databases.sh`).
//!
//! What is kept: the tables code on this branch still reads (`miners`, `shares`,
//! `shares_archive` and the `shares_all` view over both, `rounds`, `nodes`, `peers`,
//! `uptime_samples`, `won_blocks`) and every `np_*` table.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use tracing::{info, warn};

use ghost_common::error::{GhostError, GhostResult};

/// The version this migration writes.
pub(crate) const V65: u32 = 65;

/// Tables whose rows are money (funds someone holds, has locked or may still claim): any row
/// refuses the migration.
pub(crate) const HALT_TABLES: &[&str] = &[
    "withdrawal_requests",
    "ghost_locks",
    // Ghost Pay: notes are funds, nullifiers decide which of them are spent (dropping them alone
    // would make a spent note spendable again in any copy that kept the notes), transfers and
    // shields are notes in flight, and instant payments are amounts accepted or reserved against
    // a lock.
    "confidential_notes",
    "nullifiers",
    "pending_nullifiers",
    "confidential_transfers",
    "pending_l2_shields",
    "accepted_instant_payments",
    "instant_payment_reservations",
    // Verified transactions waiting for a checkpoint: dropping them freezes the sender's funds.
    "confirmed_pool_staging",
    // L2 reconciliation: amounts owed in or out of a batch.
    "reconciliation_entries",
];

/// Table-name prefixes whose rows are money: any row in any matching table refuses.
pub(crate) const HALT_PREFIXES: &[&str] = &["l2_", "wraith_"];

/// Tables where only some rows are money, with the condition that makes a row one. A
/// `node_rewards` row is created at zero by every health report and is money only once it holds
/// a balance.
pub(crate) const HALT_WHERE: &[(&str, &str)] = &[("node_rewards", "balance_sats != 0")];

/// Every table v65 drops. Nothing on this branch reads any of them (checked by grep over every
/// crate and binary when v65 was written; the maintenance prunes of the challenge, vote,
/// verification and health-ping tables, the snapshot manager and the MPC elder and key-value
/// queries were deleted with them).
pub(crate) const DROPPED_TABLES: &[&str] = &[
    // Payout ledger, proposals, settlement.
    "payout_ledger_checkpoints",
    "payout_proposals",
    "payouts",
    "coinbase_skeletons",
    "confirmed_pool_staging",
    "deferred_settlements",
    "epoch_settlements",
    "settled_blocks",
    "node_rewards",
    "reconciliation_entries",
    "reconciliation_state",
    "state_snapshots",
    "block_proposers",
    // Share shard.
    "shard_counters",
    "shard_epochs",
    "shard_settled",
    "shard_settled_blocks",
    // Votes, elders, rotation.
    "votes",
    "elder_approvals",
    "elder_entries",
    "elder_registration_requests",
    "elder_registration_votes",
    "burned_elder_numbers",
    "canonical_elder_lists",
    "retired_nodes",
    "rotation_history",
    "equivocation_proofs",
    "peer_reputation",
    // Capabilities and challenges.
    "archive_challenges",
    "policy_challenges",
    "stratum_challenges",
    "ghostpay_challenges",
    "verification_ledger",
    "verifications",
    "health_pings",
    "unverified_bindings",
    // MPC.
    "mpc_ceremony",
    "mpc_contributions",
    "mpc_params_files",
    "mpc_verification_votes",
    // L2.
    "l2_checkpoints",
    "l2_epoch_fees",
    "l2_epochs",
    "l2_notes",
    "l2_nullifiers",
    "l2_snapshots",
    "l2_state",
    "l2_valid_roots",
    "pending_l2_shields",
    // Wraith.
    "wraith_participants",
    "wraith_rounds",
    // Ghost Pay.
    "accepted_instant_payments",
    "instant_payment_reservations",
    "confidential_notes",
    "confidential_transfers",
    "nullifiers",
    "pending_nullifiers",
    "withdrawal_requests",
    // Locks, glyphs, node-list checkpoints, key-value store.
    "ghost_locks",
    "ghost_glyph_registry",
    "mesh_node_list_checkpoints",
    "kv_store",
];

/// The tables v65 creates: the imported genesis table and its one-row provenance record.
///
/// - `np_genesis`: one row per payee script, `owed` a 32-byte two's complement big-endian face
///   amount (as `np_ledger`), `queue_since` NULL below the payout floor. Written once, by the
///   genesis import (`pool_sv2 --np-import-genesis`); never changed after.
/// - `np_genesis_meta`: the export it came from (`export_digest` = sha256 of
///   `ledger-export.bin`), its network and freeze height, the `queue_since` the import gave,
///   the row count and the resulting `table_root`, the digest a node pins.
pub(crate) const NP_GENESIS_DDL: &str = "
    CREATE TABLE IF NOT EXISTS np_genesis (
        script       BLOB    PRIMARY KEY CHECK (typeof(script) = 'blob' AND length(script) > 0),
        owed         BLOB    NOT NULL CHECK (typeof(owed) = 'blob' AND length(owed) = 32),
        queue_since  INTEGER CHECK (queue_since IS NULL OR queue_since >= 0)
    );
    CREATE TABLE IF NOT EXISTS np_genesis_meta (
        id             INTEGER PRIMARY KEY CHECK (id = 1),
        export_digest  BLOB    NOT NULL CHECK (typeof(export_digest) = 'blob'
                                               AND length(export_digest) = 32),
        network        TEXT    NOT NULL,
        export_height  INTEGER NOT NULL CHECK (export_height >= 0),
        queue_since    INTEGER NOT NULL CHECK (queue_since >= 0),
        row_count      INTEGER NOT NULL CHECK (row_count >= 0),
        table_root     BLOB    NOT NULL CHECK (typeof(table_root) = 'blob'
                                               AND length(table_root) = 32),
        imported_at    INTEGER NOT NULL
    );
";

/// What a v65 run did, for the log and for tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct V65Report {
    /// Tables dropped (present before, gone after).
    pub(crate) dropped: Vec<String>,
    /// Rows the dropped tables held in total.
    pub(crate) rows_dropped: i64,
    /// The backup taken or reused, if the gate required one.
    pub(crate) backup: Option<PathBuf>,
    /// `PRAGMA auto_vacuum` (0 none, 1 full, 2 incremental).
    pub(crate) auto_vacuum: i64,
    /// `freelist_count` after the drop, before any reclaim.
    pub(crate) freelist_after_drop: i64,
    /// `freelist_count` after the reclaim (equal to the above when nothing ran).
    pub(crate) freelist_after_reclaim: i64,
    /// `page_count` after the drop, before any reclaim.
    pub(crate) pages_after_drop: i64,
    /// `page_count` after the reclaim.
    pub(crate) pages_after_reclaim: i64,
}

fn mig(e: impl std::fmt::Display) -> GhostError {
    GhostError::Migration(format!("v65: {e}"))
}

fn count_i64(conn: &Connection, sql: &str) -> GhostResult<i64> {
    conn.query_row(sql, [], |r| r.get(0)).map_err(mig)
}

/// The names of every table present, from `sqlite_master`.
fn tables(conn: &Connection) -> GhostResult<Vec<String>> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .map_err(mig)?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(mig)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(mig)?;
    Ok(rows)
}

fn row_count(conn: &Connection, table: &str) -> GhostResult<i64> {
    // Table names come from `sqlite_master` or the constants above, never from input; quoted
    // anyway.
    count_i64(
        conn,
        &format!("SELECT COUNT(*) FROM \"{}\"", table.replace('"', "\"\"")),
    )
}

/// Money-bearing tables present, with their counts of money rows (every row, or for a
/// [`HALT_WHERE`] table the rows its condition selects), whether or not they hold any.
pub(crate) fn money_tables(conn: &Connection) -> GhostResult<Vec<(String, i64)>> {
    let mut out = Vec::new();
    for t in tables(conn)? {
        if HALT_TABLES.contains(&t.as_str()) || HALT_PREFIXES.iter().any(|p| t.starts_with(p)) {
            let n = row_count(conn, &t)?;
            out.push((t, n));
        } else if let Some((_, cond)) = HALT_WHERE.iter().find(|(w, _)| *w == t) {
            // Both the name and the condition are the constants above, never input.
            let n = count_i64(conn, &format!("SELECT COUNT(*) FROM \"{t}\" WHERE {cond}"))?;
            out.push((t, n));
        }
    }
    Ok(out)
}

/// Step 1: refuse on any money row.
pub(crate) fn refuse_money_rows(conn: &Connection) -> GhostResult<()> {
    let held: Vec<String> = money_tables(conn)?
        .into_iter()
        .filter(|(_, n)| *n != 0)
        .map(|(t, n)| format!("{t} ({n} rows)"))
        .collect();
    if held.is_empty() {
        return Ok(());
    }
    Err(GhostError::Migration(format!(
        "v65 REFUSED, nothing changed: money-bearing tables hold rows: {}. The node pool \
         cutover drops these tables, and their rows are value someone may be owed or have \
         locked. Resolve them (pay out, release or export them by hand) on the old release, \
         then start this binary again. The database is still at its previous schema version.",
        held.join(", ")
    )))
}

/// Rows in the tables this migration drops.
fn rows_to_drop(conn: &Connection) -> GhostResult<(Vec<String>, i64)> {
    let present = tables(conn)?;
    let mut names = Vec::new();
    let mut rows = 0i64;
    for t in DROPPED_TABLES {
        if present.iter().any(|p| p == t) {
            rows += row_count(conn, t)?;
            names.push((*t).to_string());
        }
    }
    Ok((names, rows))
}

/// The main database's file, or `None` for an in-memory or temporary one.
fn main_file(conn: &Connection) -> GhostResult<Option<PathBuf>> {
    let file: Option<String> = conn
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
            [],
            |r| r.get(0),
        )
        .map_err(mig)?;
    Ok(file.filter(|f| !f.is_empty()).map(PathBuf::from))
}

/// Where the gate keeps the pre-v65 copy of `db`.
pub(crate) fn backup_path(db: &Path) -> PathBuf {
    let mut s = db.as_os_str().to_os_string();
    s.push(".pre-v65");
    PathBuf::from(s)
}

/// Bytes free to an unprivileged writer on the filesystem holding `dir`.
#[cfg(unix)]
fn free_bytes(dir: &Path) -> GhostResult<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).map_err(mig)?;
    // SAFETY: `c` is a valid NUL-terminated path and `st` is a properly sized, zeroed out
    // `statvfs` that the call only writes into.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return Err(mig(format!(
            "cannot read free space under {}: {}",
            dir.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

#[cfg(not(unix))]
fn free_bytes(_dir: &Path) -> GhostResult<u64> {
    Err(mig("free space cannot be checked on this platform"))
}

fn file_len(p: &Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

/// Attach `copy` and read back its raw `user_version` and table count. Under SQLCipher an
/// attached file with no `KEY` takes the main database's key, so this works for both.
fn inspect_copy(conn: &Connection, copy: &Path) -> GhostResult<(i64, i64)> {
    let lit = sql_string(copy)?;
    conn.execute_batch(&format!("ATTACH DATABASE {lit} AS v65_backup"))
        .map_err(|e| mig(format!("cannot attach {}: {e}", copy.display())))?;
    let read = (|| -> GhostResult<(i64, i64)> {
        let v = count_i64(conn, "PRAGMA v65_backup.user_version")?;
        let n = count_i64(
            conn,
            "SELECT COUNT(*) FROM v65_backup.sqlite_master WHERE type = 'table'",
        )?;
        Ok((v, n))
    })();
    let detach = conn
        .execute_batch("DETACH DATABASE v65_backup")
        .map_err(mig);
    let r = read?;
    detach?;
    Ok(r)
}

fn sql_string(p: &Path) -> GhostResult<String> {
    let s = p
        .to_str()
        .ok_or_else(|| mig(format!("path is not UTF-8: {}", p.display())))?;
    Ok(format!("'{}'", s.replace('\'', "''")))
}

/// Step 2: a verified copy of the database before anything is dropped. Returns where it is.
pub(crate) fn ensure_backup(conn: &Connection, db: &Path) -> GhostResult<PathBuf> {
    let live_version = count_i64(conn, "PRAGMA user_version")?;
    let live_tables = count_i64(
        conn,
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'",
    )?;
    let dest = backup_path(db);
    if dest.exists() {
        let (v, n) = inspect_copy(conn, &dest)?;
        if v == live_version && n == live_tables {
            info!(
                backup = %dest.display(),
                "v65: reusing the verified pre-v65 copy from an earlier attempt"
            );
            return Ok(dest);
        }
        return Err(GhostError::Migration(format!(
            "v65 REFUSED, nothing changed: {} exists but is not a copy of this database (its \
             user_version is {v} and it has {n} tables; this database is at {live_version} with \
             {live_tables}). It is never overwritten: move it aside and start again.",
            dest.display()
        )));
    }

    let dir = db
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut wal = db.as_os_str().to_os_string();
    wal.push("-wal");
    let size = file_len(db) + file_len(Path::new(&wal));
    let need = size.saturating_mul(2);
    let free = free_bytes(dir)?;
    if free < need {
        return Err(GhostError::Migration(format!(
            "v65 REFUSED, nothing changed: the pre-v65 backup needs twice the database free \
             ({need} bytes) under {}, and {free} are. Free space, or take a copy yourself with \
             `sqlite3 {} \"VACUUM INTO '{}'\"` and start again.",
            dir.display(),
            db.display(),
            dest.display()
        )));
    }

    let lit = sql_string(&dest)?;
    if let Err(e) = conn.execute_batch(&format!("VACUUM INTO {lit}")) {
        let _ = std::fs::remove_file(&dest);
        return Err(GhostError::Migration(format!(
            "v65 REFUSED, nothing changed: the pre-v65 backup to {} failed: {e}",
            dest.display()
        )));
    }
    let (v, n) = match inspect_copy(conn, &dest) {
        Ok(x) => x,
        Err(e) => {
            let _ = std::fs::remove_file(&dest);
            return Err(e);
        }
    };
    if v != live_version || n != live_tables {
        let _ = std::fs::remove_file(&dest);
        return Err(GhostError::Migration(format!(
            "v65 REFUSED, nothing changed: the pre-v65 backup did not verify (user_version {v} \
             with {n} tables against {live_version} with {live_tables})"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600));
    }
    info!(
        backup = %dest.display(),
        bytes = file_len(&dest),
        user_version = v,
        "v65: pre-v65 backup taken and verified"
    );
    Ok(dest)
}

/// Step 3, inside the caller's transaction: drop, create, verify.
fn drop_and_create(conn: &Connection) -> GhostResult<Vec<String>> {
    // Re-checked inside the transaction: nothing may have written a money row since step 1.
    refuse_money_rows(conn)?;
    let (present, _) = rows_to_drop(conn)?;
    // Old tables reference each other; the check is deferred to COMMIT, by which time every
    // referencing table is gone too. (`foreign_keys` itself cannot change inside a transaction.)
    conn.execute_batch("PRAGMA defer_foreign_keys = ON;")
        .map_err(mig)?;
    for t in &present {
        conn.execute_batch(&format!("DROP TABLE IF EXISTS \"{t}\";"))
            .map_err(|e| mig(format!("cannot drop {t}: {e}")))?;
    }
    conn.execute_batch(NP_GENESIS_DDL).map_err(mig)?;
    let left: Vec<String> = tables(conn)?
        .into_iter()
        .filter(|t| DROPPED_TABLES.contains(&t.as_str()))
        .collect();
    if !left.is_empty() {
        return Err(mig(format!("still present after the drop: {left:?}")));
    }
    Ok(present)
}

/// Step 4: drain the free list when the database can return pages.
fn reclaim(conn: &Connection, report: &mut V65Report) -> GhostResult<()> {
    report.auto_vacuum = count_i64(conn, "PRAGMA auto_vacuum")?;
    report.freelist_after_drop = count_i64(conn, "PRAGMA freelist_count")?;
    report.pages_after_drop = count_i64(conn, "PRAGMA page_count")?;
    report.freelist_after_reclaim = report.freelist_after_drop;
    report.pages_after_reclaim = report.pages_after_drop;
    if report.auto_vacuum != 2 {
        if report.freelist_after_drop > 0 {
            info!(
                auto_vacuum = report.auto_vacuum,
                free_pages = report.freelist_after_drop,
                "v65: the dropped tables' pages stay on the free list and are reused; the file \
                 does not shrink. Returning them needs a full VACUUM, which needs about twice the \
                 database free and is never run implicitly"
            );
        }
        return Ok(());
    }
    // ⛔ `PRAGMA incremental_vacuum` frees ONE page per step: `execute` would free one page
    // and return Ok. Step the statement until it stops returning rows.
    let mut stmt = conn.prepare("PRAGMA incremental_vacuum").map_err(mig)?;
    let mut rows = stmt.query([]).map_err(mig)?;
    while rows.next().map_err(mig)?.is_some() {}
    drop(rows);
    drop(stmt);
    report.freelist_after_reclaim = count_i64(conn, "PRAGMA freelist_count")?;
    report.pages_after_reclaim = count_i64(conn, "PRAGMA page_count")?;
    let released = report.pages_after_drop - report.pages_after_reclaim;
    if report.freelist_after_reclaim != 0 || released != report.freelist_after_drop {
        warn!(
            free_before = report.freelist_after_drop,
            free_after = report.freelist_after_reclaim,
            pages_released = released,
            "v65: the free list did not drain completely; maintenance's incremental vacuum \
             returns the rest"
        );
    } else {
        info!(pages_released = released, "v65: free list drained");
    }
    Ok(())
}

/// Run v65 on a database at v64 (the earlier migrations have run). `set_version` writes the
/// schema version inside the same transaction as the drop, so the two commit together.
pub(crate) fn run(
    conn: &Connection,
    set_version: fn(&Connection, u32) -> GhostResult<()>,
) -> GhostResult<V65Report> {
    let mut report = V65Report::default();
    refuse_money_rows(conn)?;
    let (_, rows) = rows_to_drop(conn)?;
    report.rows_dropped = rows;
    if rows > 0 {
        match main_file(conn)? {
            Some(db) => report.backup = Some(ensure_backup(conn, &db)?),
            None => warn!(
                rows,
                "v65: in-memory database, no backup taken (nothing on disk to protect)"
            ),
        }
    }

    conn.execute("BEGIN IMMEDIATE", [])
        .map_err(|e| mig(format!("cannot begin: {e}")))?;
    let body = (|| -> GhostResult<Vec<String>> {
        let dropped = drop_and_create(conn)?;
        set_version(conn, V65)?;
        Ok(dropped)
    })();
    match body {
        Ok(d) => report.dropped = d,
        Err(e) => {
            let _ = conn.execute("ROLLBACK", []);
            return Err(e);
        }
    }
    conn.execute("COMMIT", [])
        .map_err(|e| mig(format!("cannot commit: {e}")))?;
    info!(
        tables = report.dropped.len(),
        rows = report.rows_dropped,
        "v65: dropped the old system's tables and created np_genesis"
    );

    // After COMMIT: space reclamation is housekeeping, not part of the migration, and a failure
    // here leaves a correct database. Logged, not fatal.
    if let Err(e) = reclaim(conn, &mut report) {
        warn!("v65: space reclamation failed (the database is correct): {e}");
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{
        decode_schema_version, encode_schema_version, run_migrations, run_migrations_to,
        schema_version, set_schema_version,
    };

    /// Every table a v65 database holds besides the `np_*` ones and SQLite's own.
    const KEPT: &[&str] = &[
        "miners",
        "nodes",
        "peers",
        "rounds",
        "shares",
        "shares_archive",
        "uptime_samples",
        "won_blocks",
    ];

    fn temp_path(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ghost-v65-{tag}-{}-{:?}.db",
            std::process::id(),
            std::thread::current().id()
        ));
        remove(&p);
        p
    }

    fn remove(p: &Path) {
        for suffix in ["", "-wal", "-shm", ".pre-v65"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", p.display()));
        }
    }

    /// A database at v64 on disk, created the way `Database::open` creates one.
    fn v64_on_disk(p: &Path, incremental: bool) -> Connection {
        let c = Connection::open(p).unwrap();
        c.execute_batch(if incremental {
            "PRAGMA auto_vacuum = INCREMENTAL; PRAGMA journal_mode = WAL;"
        } else {
            "PRAGMA journal_mode = WAL;"
        })
        .unwrap();
        run_migrations_to(&c, 64).unwrap();
        c
    }

    fn v64_in_memory() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        run_migrations_to(&c, 64).unwrap();
        c
    }

    fn raw_version(c: &Connection) -> i64 {
        c.query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap()
    }

    /// Insert one row into any table, giving every NOT NULL column without a default a value of
    /// its declared type, with foreign keys off.
    fn insert_any(c: &Connection, table: &str) {
        c.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        let mut stmt = c
            .prepare(&format!(
                "SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_info('{table}')"
            ))
            .unwrap();
        let cols: Vec<(String, String, bool, Option<String>, i64)> = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let mut names = Vec::new();
        let mut vals = Vec::new();
        for (n, ty, notnull, dflt, pk) in cols {
            if !(notnull || pk > 0) || dflt.is_some() {
                continue;
            }
            let ty = ty.to_ascii_uppercase();
            names.push(format!("\"{n}\""));
            vals.push(if ty.contains("INT") {
                "1".to_string()
            } else if ty.contains("BLOB") {
                "x'00'".to_string()
            } else if ty.contains("REAL") {
                "1.0".to_string()
            } else {
                "'x'".to_string()
            });
        }
        let sql = if names.is_empty() {
            format!("INSERT INTO \"{table}\" DEFAULT VALUES")
        } else {
            format!(
                "INSERT INTO \"{table}\" ({}) VALUES ({})",
                names.join(","),
                vals.join(",")
            )
        };
        c.execute_batch(&sql)
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
    }

    fn insert_votes(c: &Connection, n: usize) {
        let pad = "s".repeat(400);
        for i in 0..n {
            c.execute(
                "INSERT INTO votes (round_id, proposal_hash, voter_id, vote, signature, timestamp) \
                 VALUES (?1, 'p', 'v', 1, ?2, 0)",
                rusqlite::params![i as i64, pad],
            )
            .unwrap();
        }
    }

    fn user_tables(c: &Connection) -> Vec<String> {
        tables(c)
            .unwrap()
            .into_iter()
            .filter(|t| !t.starts_with("sqlite_"))
            .collect()
    }

    fn count(c: &Connection, sql: &str) -> i64 {
        c.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn a_fresh_database_holds_exactly_the_kept_tables() {
        let c = Connection::open_in_memory().unwrap();
        run_migrations(&c).unwrap();
        let mut want: Vec<String> = KEPT.iter().map(|s| s.to_string()).collect();
        let np: Vec<String> = user_tables(&c)
            .into_iter()
            .filter(|t| t.starts_with("np_"))
            .collect();
        assert!(np.contains(&"np_genesis".to_string()));
        assert!(np.contains(&"np_genesis_meta".to_string()));
        assert_eq!(np.len(), 14, "twelve from v63/v64, two from v65: {np:?}");
        want.extend(np);
        want.sort();
        assert_eq!(user_tables(&c), want);
        assert_eq!(
            count(&c, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'view'"),
            1,
            "shares_all stays"
        );
        assert_eq!(
            count(
                &c,
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'"
            ),
            0,
            "the l2 triggers went with their tables"
        );
        // The view still compiles over what is left.
        count(&c, "SELECT COUNT(*) FROM shares_all");
    }

    #[test]
    fn every_dropped_table_existed_at_v64() {
        let c = v64_in_memory();
        let present = user_tables(&c);
        for t in DROPPED_TABLES {
            assert!(present.iter().any(|p| p == t), "{t} is not a v64 table");
        }
        // And everything at v64 is either dropped, kept or np_.
        for t in present {
            assert!(
                DROPPED_TABLES.contains(&t.as_str())
                    || KEPT.contains(&t.as_str())
                    || t.starts_with("np_"),
                "{t} is neither dropped nor kept"
            );
        }
    }

    #[test]
    fn no_kept_table_references_a_dropped_one() {
        let c = Connection::open_in_memory().unwrap();
        run_migrations(&c).unwrap();
        for t in user_tables(&c) {
            let mut stmt = c
                .prepare(&format!(
                    "SELECT \"table\" FROM pragma_foreign_key_list('{t}')"
                ))
                .unwrap();
            let parents: Vec<String> = stmt
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            for p in parents {
                assert!(
                    !DROPPED_TABLES.contains(&p.as_str()),
                    "{t} references dropped {p}"
                );
            }
        }
    }

    #[test]
    fn the_version_is_stored_negated_and_an_old_reader_refuses_it() {
        let c = Connection::open_in_memory().unwrap();
        run_migrations(&c).unwrap();
        assert_eq!(raw_version(&c), -65);
        assert_eq!(schema_version(&c).unwrap(), 65);
        // What every pre-v65 binary does first when it opens a database.
        let old: rusqlite::Result<u32> = c.query_row("PRAGMA user_version;", [], |r| r.get(0));
        assert!(
            old.is_err(),
            "a pre-v65 binary must fail to read the version"
        );
        // Decoding.
        assert_eq!(decode_schema_version(0).unwrap(), 0);
        assert_eq!(decode_schema_version(64).unwrap(), 64);
        assert_eq!(decode_schema_version(-65).unwrap(), 65);
        assert_eq!(decode_schema_version(-70).unwrap(), 70);
        assert!(decode_schema_version(65).is_err());
        assert!(decode_schema_version(-1).is_err());
        assert!(decode_schema_version(-64).is_err());
        for v in [0, 1, 64, 65, 66, 1000] {
            assert_eq!(decode_schema_version(encode_schema_version(v)).unwrap(), v);
        }
        assert_eq!(encode_schema_version(64), 64);
    }

    #[test]
    fn reopening_a_v65_database_is_a_no_op() {
        let c = Connection::open_in_memory().unwrap();
        run_migrations(&c).unwrap();
        let before = user_tables(&c);
        run_migrations(&c).unwrap();
        assert_eq!(user_tables(&c), before);
        assert_eq!(raw_version(&c), -65);
    }

    /// Each money-bearing table, holding one row, refuses the migration and nothing changes.
    #[test]
    fn halts_on_every_money_table_with_rows_and_changes_nothing() {
        let names: Vec<String> = money_tables(&v64_in_memory())
            .unwrap()
            .into_iter()
            .map(|(t, _)| t)
            .collect();
        for want in [
            "withdrawal_requests",
            "ghost_locks",
            "l2_epochs",
            "l2_notes",
            "wraith_rounds",
            "wraith_participants",
            "confidential_notes",
            "nullifiers",
            "pending_nullifiers",
            "accepted_instant_payments",
            "instant_payment_reservations",
            "confidential_transfers",
            "pending_l2_shields",
            "confirmed_pool_staging",
            "reconciliation_entries",
            "node_rewards",
        ] {
            assert!(names.iter().any(|n| n == want), "{want} not covered");
        }
        assert!(names.len() >= 22, "{names:?}");
        for t in &names {
            let c = v64_in_memory();
            if t == "node_rewards" {
                // Covered with its condition below.
                continue;
            }
            if t.starts_with("l2_") && t != "l2_epochs" {
                // The l2 tables' epoch triggers need the epoch to exist.
                insert_any(&c, "l2_epochs");
            }
            insert_any(&c, t);
            insert_votes(&c, 3);
            let before = user_tables(&c);
            let e = run_migrations(&c).unwrap_err().to_string();
            assert!(e.contains("REFUSED") && e.contains(t.as_str()), "{t}: {e}");
            assert_eq!(raw_version(&c), 64, "{t}: version unchanged");
            assert_eq!(user_tables(&c), before, "{t}: no table dropped or created");
            assert_eq!(count(&c, &format!("SELECT COUNT(*) FROM \"{t}\"")), 1);
            assert_eq!(count(&c, "SELECT COUNT(*) FROM votes"), 3);
        }
    }

    /// Every money table is one v65 drops: the halt list guards exactly what would be lost.
    #[test]
    fn every_halt_table_is_a_dropped_one() {
        for t in HALT_TABLES.iter().chain(HALT_WHERE.iter().map(|(t, _)| t)) {
            assert!(
                DROPPED_TABLES.contains(t),
                "{t} is halted on but not dropped"
            );
        }
    }

    /// A `node_rewards` row at zero (what every health report creates) does not halt; one with
    /// a balance does, and nothing changes.
    #[test]
    fn node_rewards_halts_only_on_a_balance() {
        let c = v64_in_memory();
        c.execute(
            "INSERT INTO node_rewards (node_id, balance_sats, created_at, updated_at) \
             VALUES ('zero', 0, 1, 1)",
            [],
        )
        .unwrap();
        assert_eq!(
            money_tables(&c)
                .unwrap()
                .iter()
                .find(|(t, _)| t == "node_rewards")
                .unwrap()
                .1,
            0
        );
        refuse_money_rows(&c).unwrap();

        c.execute(
            "INSERT INTO node_rewards (node_id, balance_sats, created_at, updated_at) \
             VALUES ('owed', 2500, 1, 1)",
            [],
        )
        .unwrap();
        insert_votes(&c, 3);
        let before = user_tables(&c);
        let e = run_migrations(&c).unwrap_err().to_string();
        assert!(
            e.contains("REFUSED") && e.contains("node_rewards (1 rows)"),
            "{e}"
        );
        assert_eq!(raw_version(&c), 64);
        assert_eq!(user_tables(&c), before);
        assert_eq!(count(&c, "SELECT COUNT(*) FROM node_rewards"), 2);
        assert_eq!(count(&c, "SELECT COUNT(*) FROM votes"), 3);

        // Paid back to zero, it migrates.
        c.execute("UPDATE node_rewards SET balance_sats = 0", [])
            .unwrap();
        run_migrations(&c).unwrap();
        assert_eq!(raw_version(&c), -65);
    }

    /// Old rows on disk: the copy is taken and verified first, the tables go, the free list is
    /// drained page by page, and a second open changes nothing.
    #[test]
    fn drops_after_a_verified_backup_and_drains_the_free_list() {
        let p = temp_path("drain");
        let c = v64_on_disk(&p, true);
        insert_votes(&c, 2_000);
        insert_any(&c, "node_rewards");
        insert_any(&c, "rounds");
        let report = run(&c, set_schema_version).unwrap();

        let backup = report.backup.clone().expect("a backup was required");
        assert_eq!(backup, backup_path(&p));
        assert_eq!(report.rows_dropped, 2_001);
        assert_eq!(report.dropped.len(), DROPPED_TABLES.len());
        assert_eq!(report.auto_vacuum, 2);
        assert!(
            report.freelist_after_drop > 50,
            "the votes rows freed pages: {report:?}"
        );
        assert_eq!(report.freelist_after_reclaim, 0, "drained: {report:?}");
        assert_eq!(
            report.pages_after_drop - report.pages_after_reclaim,
            report.freelist_after_drop,
            "every free page went back to the filesystem"
        );
        assert_eq!(count(&c, "PRAGMA freelist_count"), 0);
        assert_eq!(raw_version(&c), -65);
        assert_eq!(
            count(&c, "SELECT COUNT(*) FROM rounds"),
            1,
            "kept rows stay"
        );
        drop(c);

        // The copy is the pre-v65 database.
        let b = Connection::open(&backup).unwrap();
        assert_eq!(raw_version(&b), 64);
        assert_eq!(count(&b, "SELECT COUNT(*) FROM votes"), 2_000);
        drop(b);

        // Reopening through the real path: nothing to do, the copy is left alone.
        let mtime = std::fs::metadata(&backup).unwrap().modified().unwrap();
        let db = crate::Database::open(&p).unwrap();
        db.with_connection(|c| {
            assert_eq!(raw_version(c), -65);
            assert!(!user_tables(c).iter().any(|t| t == "votes"));
            Ok(())
        })
        .unwrap();
        drop(db);
        assert_eq!(
            std::fs::metadata(&backup).unwrap().modified().unwrap(),
            mtime
        );
        remove(&p);
    }

    /// `auto_vacuum = 0` (the old fleet's databases): nothing is reclaimed implicitly.
    #[test]
    fn without_incremental_auto_vacuum_the_free_list_is_left() {
        let p = temp_path("novac");
        let c = v64_on_disk(&p, false);
        insert_votes(&c, 1_000);
        let report = run(&c, set_schema_version).unwrap();
        assert_eq!(report.auto_vacuum, 0);
        assert!(report.freelist_after_drop > 0);
        assert_eq!(report.freelist_after_reclaim, report.freelist_after_drop);
        assert_eq!(report.pages_after_reclaim, report.pages_after_drop);
        drop(c);
        remove(&p);
    }

    /// A file at the backup path that is not a copy of this database is refused, never
    /// overwritten, and nothing changes.
    #[test]
    fn a_stale_backup_file_is_refused_and_nothing_changes() {
        let p = temp_path("stale");
        let c = v64_on_disk(&p, true);
        insert_votes(&c, 5);
        let other = Connection::open(backup_path(&p)).unwrap();
        other
            .execute_batch("CREATE TABLE x (y); PRAGMA user_version = 12;")
            .unwrap();
        drop(other);
        let before = user_tables(&c);
        let e = run_migrations(&c).unwrap_err().to_string();
        assert!(e.contains("is not a copy of this database"), "{e}");
        assert_eq!(raw_version(&c), 64);
        assert_eq!(user_tables(&c), before);
        assert_eq!(count(&c, "SELECT COUNT(*) FROM votes"), 5);
        let b = Connection::open(backup_path(&p)).unwrap();
        assert_eq!(raw_version(&b), 12, "the stale file was not touched");
        drop(b);

        // Moved aside, the migration runs.
        std::fs::remove_file(backup_path(&p)).unwrap();
        run_migrations(&c).unwrap();
        assert_eq!(raw_version(&c), -65);
        drop(c);
        remove(&p);
    }

    /// A copy left by an earlier attempt that verifies is reused.
    #[test]
    fn a_verified_copy_from_an_earlier_attempt_is_reused() {
        let p = temp_path("reuse");
        let c = v64_on_disk(&p, true);
        insert_votes(&c, 5);
        let first = ensure_backup(&c, &p).unwrap();
        let again = ensure_backup(&c, &p).unwrap();
        assert_eq!(first, again);
        run_migrations(&c).unwrap();
        assert_eq!(raw_version(&c), -65);
        drop(c);
        remove(&p);
    }

    /// Empty old tables (a node pool server that never ran the old system): no copy needed.
    #[test]
    fn empty_old_tables_need_no_backup() {
        let p = temp_path("empty");
        let c = v64_on_disk(&p, true);
        let report = run(&c, set_schema_version).unwrap();
        assert!(report.backup.is_none());
        assert!(!backup_path(&p).exists());
        assert_eq!(raw_version(&c), -65);
        drop(c);
        remove(&p);
    }

    /// An encrypted database: the copy is taken under the same key and verifies.
    #[test]
    fn an_encrypted_database_is_backed_up_encrypted() {
        let p = temp_path("enc");
        let key = [0x42u8; 32];
        {
            let c = Connection::open(&p).unwrap();
            c.pragma_update(None, "key", format!("x'{}'", hex::encode(key)))
                .unwrap();
            c.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; PRAGMA journal_mode = WAL;")
                .unwrap();
            run_migrations_to(&c, 64).unwrap();
            insert_votes(&c, 10);
        }
        let db = crate::Database::open_encrypted(&p, &key).unwrap();
        drop(db);
        let b = Connection::open(backup_path(&p)).unwrap();
        assert!(
            b.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r
                .get::<_, i64>(0))
                .is_err(),
            "the copy is encrypted"
        );
        b.pragma_update(None, "key", format!("x'{}'", hex::encode(key)))
            .unwrap();
        assert_eq!(count(&b, "SELECT COUNT(*) FROM votes"), 10);
        assert_eq!(raw_version(&b), 64);
        drop(b);
        remove(&p);
    }

    /// In memory there is nothing on disk to protect: the rows go without a copy.
    #[test]
    fn an_in_memory_database_needs_no_backup() {
        let c = v64_in_memory();
        insert_votes(&c, 3);
        let report = run(&c, set_schema_version).unwrap();
        assert!(report.backup.is_none());
        assert_eq!(report.rows_dropped, 3);
        assert_eq!(raw_version(&c), -65);
    }
}
