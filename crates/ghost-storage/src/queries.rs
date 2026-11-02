//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: queries.rs                                                                                                     |
//|======================================================================================================================|

//! Database query operations

use rusqlite::{params, Connection, OptionalExtension};
use tracing::warn;

use ghost_common::error::{GhostError, GhostResult};

use crate::database::Database;
use crate::models::*;

// =============================================================================
// M-15: BLOB SIZE VALIDATION
// =============================================================================

/// M-15: Maximum allowed BLOB size for storage (1MB)
///
/// Prevents oversized data from being inserted into BLOB columns.
/// Any data exceeding this limit is rejected before the INSERT executes.
pub const MAX_BLOB_SIZE: usize = 1_048_576;

/// M-15: Validate that a blob does not exceed the maximum allowed size.
///
/// Call this before any INSERT that includes BLOB data to prevent
/// oversized payloads from consuming excessive disk/memory.
pub fn validate_blob_size(data: &[u8], field_name: &str) -> GhostResult<()> {
    if data.len() > MAX_BLOB_SIZE {
        return Err(GhostError::Database(format!(
            "M-15: BLOB field '{}' exceeds maximum size: {} bytes (limit: {} bytes)",
            field_name,
            data.len(),
            MAX_BLOB_SIZE
        )));
    }
    Ok(())
}

// =============================================================================
// L-22 FIX: HELPER FUNCTIONS FOR STATUS PARSING WITH ERROR RETURNS
// =============================================================================

/// L-22 FIX: Parse PayoutStatus, returning error on invalid value.
///
/// Unlike the previous implementation that fell back to defaults (which could
/// mask data corruption), this now returns an error to surface the issue.
///
/// # Errors
/// Returns rusqlite::Error if the status string is not a valid PayoutStatus.
fn parse_payout_status_strict(
    status_str: &str,
    context: &str,
) -> Result<PayoutStatus, rusqlite::Error> {
    PayoutStatus::parse(status_str).ok_or_else(|| {
        warn!(
            status_str = status_str,
            context = context,
            "L-22: Invalid PayoutStatus value in database"
        );
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid PayoutStatus '{}' in context '{}'",
                    status_str, context
                ),
            )),
        )
    })
}

// =============================================================================
// L-16: BLOB SIZE LIMITS FOR INSERT OPERATIONS
// =============================================================================

/// L-16: Maximum size for proof_data in equivocation_proofs table (100 KB)
/// Equivocation proofs contain two conflicting vote signatures plus metadata.
/// At most this should be ~2KB, so 100KB provides generous headroom.
pub const MAX_EQUIVOCATION_PROOF_SIZE: usize = 100 * 1024;

/// L-16: Maximum size for rotation_proof in retired_nodes table (10 KB)
/// Rotation proofs contain two signatures and node IDs.
/// At most this should be ~500 bytes, so 10KB provides generous headroom.
pub const MAX_ROTATION_PROOF_SIZE: usize = 10 * 1024;

/// M-2: Maximum size for kv_store values (1 MB)
/// Prevents storage exhaustion attacks through the key-value store API.
pub const MAX_KV_VALUE_SIZE: usize = 1024 * 1024;

/// L-1: Maximum length for node display_name field (128 chars)
pub const MAX_DISPLAY_NAME_LEN: usize = 128;

/// L-1: Maximum length for node public_address field (256 chars)
pub const MAX_PUBLIC_ADDRESS_LEN: usize = 256;

/// L-4: Maximum size for node capabilities JSON (4 KB)
pub const MAX_CAPABILITIES_JSON_SIZE: usize = 4096;

/// LOW-STOR-5: Maximum size for challenge string fields (expected_hash, response_hash, txid, endpoint)
/// Challenge data is small metadata (hashes are 64 hex chars, txids are 64 hex chars, endpoints are URLs).
/// 1 KB provides generous headroom while preventing storage DoS.
pub const MAX_CHALLENGE_FIELD_SIZE: usize = 1024;

/// LOW-STOR-5: Maximum size for node_id and challenger_id fields
/// Node IDs are 64 hex chars (32 bytes). Set to 128 for safety.
pub const MAX_CHALLENGE_ID_SIZE: usize = 128;

// =============================================================================
// SAFE TYPE CONVERSIONS
// =============================================================================

/// SEC-DATA-2: Safely convert i64 to u32 for counts, rejecting negative/overflow
fn i64_to_u32_count(value: i64, field_name: &str) -> Result<u32, rusqlite::Error> {
    if value < 0 || value > u32::MAX as i64 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid {} value: {} (expected 0-{})",
                    field_name,
                    value,
                    u32::MAX
                ),
            )),
        ));
    }
    Ok(value as u32)
}

/// 4.19 SECURITY: Generic i64 to u64 conversion for non-satoshi values (epochs, timestamps, heights)
///
/// SQLite stores all integers as signed i64. This helper validates the conversion for
/// values that should never be negative (epochs, timestamps, block heights, counts).
fn i64_to_u64(value: i64, field_name: &str) -> Result<u64, rusqlite::Error> {
    if value < 0 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid negative {} value: {}", field_name, value),
            )),
        ));
    }
    Ok(value as u64)
}

// =============================================================================
// SHARE QUERIES
//
// Since migration v56 (`SHARE_SHARD_BUILD.md` Stage 5, step 7) there are THREE
// spellings, and picking the wrong one does not error — it silently returns
// less:
//
//   `shares`         the LIVE table. Post-cutover evidence only. Ingest writes
//                    it, `shard_fold_epoch` deletes from it once an epoch ages
//                    out of the retention window (EPOCH_BLOCKS * RETENTION_EPOCHS
//                    = 36 blocks, ~6 h), and `delete_old_shares` prunes it. So
//                    it holds HOURS of history, not months.
//
//   `shares_archive` every share this node held at the cutover. FROZEN: nothing
//                    writes it and nothing deletes from it. It is the rollback
//                    substrate and the audit trail, and it is not payable —
//                    the shard's genesis column already absorbed this work, so
//                    anything that re-credits from here double-pays.
//
//   `shares_all`     a view, `shares UNION ALL shares_archive`. Read-only;
//                    SQLite will not accept a write through it.
//
// The rule, and it is not "use the view when in doubt":
//
//   * anything that WRITES, or that computes what a miner is OWED, reads the
//     live table. The unpaid ledger collapsing to a six-hour window is the
//     POINT of the cutover, not a regression — the shard's `owed()` is what
//     pays now, and a legacy path that could still see months of unpaid work
//     would be a second, disagreeing answer to the same question.
//
//   * anything a HUMAN reads — leaderboards, hashrate, per-miner history and
//     stats, pool records — reads `shares_all`, or the dashboard shows every
//     miner's lifetime resetting to zero on the morning of the deploy.
//
//   * the two import dedup checks read `shares_all` on purpose. `UNIQUE(share_hash)`
//     is per-table now, so it no longer stops a peer from serving us back a
//     share that is sitting in the archive; without the view that share would
//     be re-inserted into the live table and folded a second time.
// =============================================================================

impl Database {
    /// Insert a new share
    pub fn insert_share(&self, share: &ShareRecord) -> GhostResult<i64> {
        self.with_connection_retry("insert_share", |conn| {
            conn.execute(
                "INSERT INTO shares (round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    share.round_id,
                    share.miner_id,
                    share.difficulty,
                    share.work,
                    share.share_hash,
                    share.timestamp,
                    share.received_by,
                    share.valid,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid())
        })
    }

    /// Maximum rows returned by unbounded queries (H-7: OOM prevention)
    pub const MAX_QUERY_RESULTS: u32 = 10000;

    /// Get shares for a round
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_shares_by_round(&self, round_id: u64) -> GhostResult<Vec<ShareRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid
                     FROM shares_all WHERE round_id = ?1 ORDER BY timestamp LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let shares = stmt
                .query_map(params![round_id, Self::MAX_QUERY_RESULTS], |row| {
                    Ok(ShareRecord {
                        id: Some(row.get(0)?),
                        round_id: row.get(1)?,
                        miner_id: row.get(2)?,
                        difficulty: row.get(3)?,
                        work: row.get(4)?,
                        share_hash: row.get(5)?,
                        timestamp: row.get(6)?,
                        received_by: row.get(7)?,
                        valid: row.get(8)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(shares)
        })
    }

    /// Get miner shares for a round
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_miner_shares(&self, round_id: u64, miner_id: &str) -> GhostResult<Vec<ShareRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid
                     FROM shares_all WHERE round_id = ?1 AND miner_id = ?2 ORDER BY timestamp LIMIT ?3",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let shares = stmt
                .query_map(
                    params![round_id, miner_id, Self::MAX_QUERY_RESULTS],
                    |row| {
                        Ok(ShareRecord {
                            id: Some(row.get(0)?),
                            round_id: row.get(1)?,
                            miner_id: row.get(2)?,
                            difficulty: row.get(3)?,
                            work: row.get(4)?,
                            share_hash: row.get(5)?,
                            timestamp: row.get(6)?,
                            received_by: row.get(7)?,
                            valid: row.get(8)?,
                        })
                    },
                )
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(shares)
        })
    }

    /// Get total work for a miner in a round
    pub fn get_miner_work(&self, round_id: u64, miner_id: &str) -> GhostResult<f64> {
        self.with_connection(|conn| {
            let work: f64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(work), 0) FROM shares_all WHERE round_id = ?1 AND miner_id = ?2 AND valid = 1",
                    params![round_id, miner_id],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(work)
        })
    }

    /// Get all miners with work in a round
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_round_miners(&self, round_id: u64) -> GhostResult<Vec<(String, f64)>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT miner_id, SUM(work) as total_work
                     FROM shares_all WHERE round_id = ?1 AND valid = 1
                     GROUP BY miner_id ORDER BY total_work DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let miners = stmt
                .query_map(params![round_id, Self::MAX_QUERY_RESULTS], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(miners)
        })
    }

    /// Get detailed miner stats for a round (includes timing and difficulty data)
    ///
    /// Returns per-miner aggregate stats needed for hashrate calculation.
    pub fn get_round_miners_detailed(&self, round_id: u64) -> GhostResult<Vec<MinerSearchResult>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        miner_id,
                        COUNT(*) as total_shares,
                        SUM(work) as total_work,
                        SUM(CASE WHEN valid = 1 THEN 1 ELSE 0 END) as valid_shares,
                        MIN(timestamp) as first_seen,
                        MAX(timestamp) as last_seen,
                        AVG(difficulty) as avg_difficulty
                     FROM shares_all WHERE round_id = ?1
                     GROUP BY miner_id ORDER BY total_work DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let miners = stmt
                .query_map(params![round_id, Self::MAX_QUERY_RESULTS], |row| {
                    Ok(MinerSearchResult {
                        miner_id: row.get(0)?,
                        total_shares: row.get(1)?,
                        total_work: row.get(2)?,
                        valid_shares: row.get(3)?,
                        first_seen: row.get(4)?,
                        last_seen: row.get(5)?,
                        avg_difficulty: row.get(6)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(miners)
        })
    }

    /// Get aggregate miner stats for hashrate calculation.
    ///
    /// Uses a 30-minute window for accurate hashrate estimation. The wider
    /// window damps Bitaxe-class share variance — a single lucky share can
    /// double the work integrated over a short window, producing 3-4x spikes
    /// on the dashboard that don't reflect real hashrate changes.
    pub fn get_all_miners_stats(&self) -> GhostResult<Vec<MinerSearchResult>> {
        self.with_connection(|conn| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let window_start = now - 1800; // 30 minute window
            let mut stmt = conn
                .prepare(
                    "SELECT
                        miner_id,
                        COUNT(*) as total_shares,
                        SUM(work) as total_work,
                        SUM(CASE WHEN valid = 1 THEN 1 ELSE 0 END) as valid_shares,
                        MIN(timestamp) as first_seen,
                        MAX(timestamp) as last_seen,
                        AVG(difficulty) as avg_difficulty
                     FROM shares_all
                     WHERE timestamp >= ?1
                     GROUP BY miner_id ORDER BY total_work DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let miners = stmt
                .query_map(params![window_start, Self::MAX_QUERY_RESULTS], |row| {
                    Ok(MinerSearchResult {
                        miner_id: row.get(0)?,
                        total_shares: row.get(1)?,
                        total_work: row.get(2)?,
                        valid_shares: row.get(3)?,
                        first_seen: row.get(4)?,
                        last_seen: row.get(5)?,
                        avg_difficulty: row.get(6)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(miners)
        })
    }

    /// Like `get_all_miners_stats` but scoped to shares THIS node received
    /// directly — `received_by = hex(node_id[..8])` (16 hex chars), the same
    /// key `local_hashrate_th` uses. This is the genuinely LOCAL connected-miner
    /// set; it excludes miners whose shares only reached this node via mesh
    /// gossip for payout consensus (which `get_all_miners_stats` includes).
    pub fn get_local_miners_stats(&self, received_by: &str) -> GhostResult<Vec<MinerSearchResult>> {
        self.with_connection(|conn| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let window_start = now - 1800; // 30 minute window
            let mut stmt = conn
                .prepare(
                    "SELECT
                        miner_id,
                        COUNT(*) as total_shares,
                        SUM(work) as total_work,
                        SUM(CASE WHEN valid = 1 THEN 1 ELSE 0 END) as valid_shares,
                        MIN(timestamp) as first_seen,
                        MAX(timestamp) as last_seen,
                        AVG(difficulty) as avg_difficulty
                     FROM shares_all
                     WHERE timestamp >= ?1 AND received_by = ?2
                     GROUP BY miner_id ORDER BY total_work DESC LIMIT ?3",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let miners = stmt
                .query_map(
                    params![window_start, received_by, Self::MAX_QUERY_RESULTS],
                    |row| {
                        Ok(MinerSearchResult {
                            miner_id: row.get(0)?,
                            total_shares: row.get(1)?,
                            total_work: row.get(2)?,
                            valid_shares: row.get(3)?,
                            first_seen: row.get(4)?,
                            last_seen: row.get(5)?,
                            avg_difficulty: row.get(6)?,
                        })
                    },
                )
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(miners)
        })
    }

    /// Find the best (lowest-value hex, most-leading-zeros) valid share
    /// submitted at or after `since_ts` (Unix seconds). Returns `None` if
    /// no shares match. Used to power public pool records (best hash per
    /// window).
    ///
    /// Correctness: `share_hash` is stored INTERNAL byte order (schema v41 —
    /// PoW zeros at the back), so its raw lexicographic order does NOT match
    /// rarity. `reverse_hex(s.share_hash)` yields the DISPLAY-order value
    /// (zeros at the front), which sorts in the same order as the underlying
    /// integer, so `ORDER BY reverse_hex(s.share_hash) ASC LIMIT 1` gives the
    /// share closest to the all-zero target.
    pub fn get_best_share_since(
        &self,
        since_ts: i64,
    ) -> GhostResult<Option<crate::models::BestShare>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    // Only real `address.worker` miners so the best share is
                    // attributed to the miner, not its bare hex(SHA256(id))
                    // gossip-ledger twin (see get_leaderboard_best_hash).
                    // LEFT JOIN rounds resolves the share's block height from
                    // its round_id (NULL if the round row isn't persisted).
                    "SELECT s.share_hash, s.miner_id, s.timestamp, s.difficulty, r.block_height
                     FROM shares_all s
                     LEFT JOIN rounds r ON r.round_id = s.round_id
                     WHERE s.timestamp >= ?1 AND s.valid = 1 AND instr(s.miner_id, '.') > 0
                     ORDER BY reverse_hex(s.share_hash) ASC
                     LIMIT 1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let row = stmt
                .query_row(params![since_ts], Self::map_best_share)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(row)
        })
    }

    /// Find the best (lowest-value hex, most-leading-zeros) valid share in a
    /// specific round. Backs the "current round" best-hash window, which is
    /// scoped by `round_id` rather than a timestamp cutoff so it tracks the
    /// live round exactly. Returns `None` if the round has no real-miner
    /// shares yet.
    pub fn get_best_share_in_round(
        &self,
        round_id: u64,
    ) -> GhostResult<Option<crate::models::BestShare>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    // Same real-miner filter as get_best_share_since; scoped
                    // to a single round instead of a time window.
                    "SELECT s.share_hash, s.miner_id, s.timestamp, s.difficulty, r.block_height
                     FROM shares_all s
                     LEFT JOIN rounds r ON r.round_id = s.round_id
                     WHERE s.round_id = ?1 AND s.valid = 1 AND instr(s.miner_id, '.') > 0
                     ORDER BY reverse_hex(s.share_hash) ASC
                     LIMIT 1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let row = stmt
                .query_row(params![round_id], Self::map_best_share)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(row)
        })
    }

    /// Row mapper shared by the best-share queries: columns must be
    /// `(share_hash, miner_id, timestamp, difficulty, block_height)`.
    fn map_best_share(row: &rusqlite::Row) -> rusqlite::Result<crate::models::BestShare> {
        Ok(crate::models::BestShare {
            share_hash: row.get(0)?,
            miner_id: row.get(1)?,
            timestamp: row.get(2)?,
            difficulty: row.get(3)?,
            block_height: row.get::<_, Option<i64>>(4)?.map(|h| h as u64),
        })
    }

    /// Leaderboard row: a miner's single best share in a time window.
    /// Backs the "best hash" leaderboard tab.
    pub fn get_leaderboard_best_hash(
        &self,
        since_ts: i64,
        limit: u32,
    ) -> GhostResult<Vec<(String, String, i64, f64)>> {
        // Returns (miner_id, best_share_hash, timestamp, difficulty).
        // `share_hash` is stored INTERNAL byte order, so rarity is ranked by
        // `reverse_hex(share_hash)` (DISPLAY order, zeros at the front), not the
        // raw column. A window function picks each miner's rarest share (rn = 1)
        // and the outer ORDER BY ranks miners against each other by the same key.
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    // instr(miner_id,'.') > 0 keeps only real `address.worker`
                    // miners. The shares table also holds replicated cross-node
                    // proofs keyed by the bare `hex(SHA256(id)[..8])` ledger id
                    // (no '.'); without this they appear as phantom leaderboard
                    // rows — the same miner duplicated under its gossip hash.
                    // Two changes from the obvious form, both measured on ghost-vm6 over the
                    // lifetime window (`since_ts = 0`, ~2M archived rows):
                    //
                    //   ROW_NUMBER() over shares_all          28,654 ms
                    //   ROW_NUMBER() per arm, then across     44,803 ms   <- WORSE
                    //   MIN() aggregate over shares_all       34,459 ms
                    //   MIN() aggregate, pre-aggregated        2,206 ms   <- this
                    //
                    // So splitting the arms is necessary but not sufficient: the window function
                    // has to go too. `ROW_NUMBER() OVER (PARTITION BY …)` needs a partitioned
                    // sort of every candidate row; `MIN()` needs one aggregate pass. Splitting a
                    // window function actually costs MORE, because each arm still sorts in full
                    // and a second window pass is added on top — which is why this is not simply
                    // the same edit as `get_leaderboard_shares`.
                    //
                    // ⚠ This relies on SQLite's documented "bare columns in an aggregate query"
                    // rule: when the aggregate is `MIN()`/`MAX()`, the other selected columns
                    // take their values from the row that produced it. That is a SQLite-specific
                    // guarantee, not standard SQL, and it is the whole reason this can replace a
                    // window function. Verified on vm6 across every miner group:
                    // `lower(share_hash) = min(lower(share_hash))` matched for all of them.
                    "SELECT miner_id, share_hash, timestamp, difficulty
                     FROM (
                         SELECT miner_id, share_hash, timestamp, difficulty,
                                MIN(reverse_hex(share_hash)) AS k
                           FROM shares
                          WHERE timestamp >= ?1 AND valid = 1 AND instr(miner_id, '.') > 0
                          GROUP BY miner_id
                         UNION ALL
                         SELECT miner_id, share_hash, timestamp, difficulty,
                                MIN(reverse_hex(share_hash)) AS k
                           FROM shares_archive
                          WHERE timestamp >= ?1 AND valid = 1 AND instr(miner_id, '.') > 0
                          GROUP BY miner_id
                     )
                     GROUP BY miner_id
                     ORDER BY MIN(k) ASC
                     LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![since_ts, limit], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, f64>(3)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rows)
        })
    }

    /// Leaderboard row: total shares and total work contributed by a
    /// miner in a time window. Backs the "shares contributed" tab.
    pub fn get_leaderboard_shares(
        &self,
        since_ts: i64,
        limit: u32,
    ) -> GhostResult<Vec<(String, u64, f64)>> {
        // Returns (miner_id, share_count, total_work). Sorted by
        // total_work descending — "more work" is the honest measure of
        // contribution since miners may be on different share difficulties.
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    // Only real `address.worker` miners; exclude the bare
                    // hex(SHA256(id)) gossip-ledger ids (see get_leaderboard_best_hash).
                    // ⚠ Aggregate each TABLE separately, then merge the per-miner rows — do
                    // NOT `GROUP BY` across `shares_all` directly. Grouping over a UNION ALL
                    // view forces SQLite to materialise the union through a co-routine and sort
                    // every row, which throws away both tables' indexes. Measured on ghost-vm6
                    // (4 GB RAM, 4.5 GB database, 1.7M archived rows in a 30-day window):
                    //
                    //     GROUP BY over shares_all      43,329 ms
                    //     pre-aggregate then merge       3,289 ms   (identical results)
                    //
                    // The inner queries each produce one row per miner, so the outer merge is
                    // over a handful of rows. `?1` is bound twice on purpose.
                    "SELECT miner_id, SUM(c) AS share_count, SUM(w) AS total_work
                     FROM (
                         SELECT miner_id, COUNT(*) AS c, SUM(work) AS w
                           FROM shares
                          WHERE timestamp >= ?1 AND valid = 1 AND instr(miner_id, '.') > 0
                          GROUP BY miner_id
                         UNION ALL
                         SELECT miner_id, COUNT(*) AS c, SUM(work) AS w
                           FROM shares_archive
                          WHERE timestamp >= ?1 AND valid = 1 AND instr(miner_id, '.') > 0
                          GROUP BY miner_id
                     )
                     GROUP BY miner_id
                     ORDER BY total_work DESC
                     LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![since_ts, limit], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, f64>(2)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rows)
        })
    }

    /// Recent valid shares for live visualisation (quasar). Returns
    /// `(miner_id, share_hash, timestamp, work)` ordered by timestamp
    /// ascending, so the caller can append them to a render queue in
    /// submission order. Capped so a single very-active node can't
    /// flood the response.
    pub fn get_recent_valid_shares(
        &self,
        since_ts: i64,
        limit: u32,
    ) -> GhostResult<Vec<(String, String, i64, f64)>> {
        self.with_connection(|conn| {
            // Only real `address.worker` miners (instr(miner_id,'.')>0). The
            // shares table also holds replicated cross-node proofs keyed by the
            // bare hex(SHA256(id)) gossip-ledger id, whose share_hash is stored in
            // INTERNAL little-endian order (leading zeros at the high-index end,
            // for cross-node C4) — so the quasar, which counts leading hex zeros
            // from the FRONT, reads them as 0 bits and renders dead-center dots
            // that never emanate. They are also duplicates of each miner's own
            // local (display-order) shares, which the home node already serves.
            // Excluding them leaves one correctly-oriented particle per real share.
            let mut stmt = conn
                .prepare(
                    "SELECT miner_id, share_hash, timestamp, work
                     FROM shares_all
                     WHERE timestamp > ?1 AND valid = 1 AND instr(miner_id, '.') > 0
                     ORDER BY timestamp ASC
                     LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![since_ts, limit], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, f64>(3)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rows)
        })
    }

    /// Rolling-window miner summary with lifetime share counts. Backs
    /// the "next block payout" projection: the recent work/share numbers
    /// drive the share% and projected-sats math, while `lifetime_shares`
    /// (joined from `miners`) gives a stable "who is this" column that
    /// matches what each miner sees on their individual page.
    ///
    /// Using a time window instead of the current `round_id` avoids the
    /// constant churn — rounds roll on every template (~30s) so a round-
    /// scoped view shows miners dropping in and out faster than a user
    /// can read. The projection is approximate; actual payouts credit
    /// only the round that's active when the block is found.
    ///
    /// Returns `(miner_id, recent_work, recent_share_count, lifetime_shares)`.
    pub fn get_recent_miners_with_lifetime(
        &self,
        since_ts: i64,
        limit: u32,
    ) -> GhostResult<Vec<(String, f64, u64, u64)>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT s.miner_id,
                            SUM(s.work)       AS total_work,
                            COUNT(*)          AS share_count,
                            COALESCE(m.total_shares, 0) AS lifetime_shares
                     FROM shares_all s
                     LEFT JOIN miners m ON s.miner_id = m.miner_id
                     WHERE s.timestamp >= ?1 AND s.valid = 1
                     GROUP BY s.miner_id
                     ORDER BY total_work DESC
                     LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![since_ts, limit], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, f64>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, u64>(3)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rows)
        })
    }

    /// Lifetime-contribution leaderboard straight from the `miners`
    /// table. Filters out dormant entries — a miner must have been seen
    /// within `active_secs` to appear. This is how we hide legacy rows
    /// from old pool configurations (e.g. pre-`aggregate_channels=false`
    /// translator attributions) that still have historical work totals
    /// but haven't had a live share in weeks.
    ///
    /// Ordered by `total_work` desc.
    pub fn get_leaderboard_lifetime(
        &self,
        limit: u32,
        active_secs: i64,
    ) -> GhostResult<Vec<(String, u64, f64)>> {
        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let active_cutoff = now_s - active_secs;
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    // Only real `address.worker` miners; exclude the bare
                    // hex(SHA256(id)) gossip-ledger ids (see get_leaderboard_best_hash).
                    "SELECT miner_id, total_shares, total_work
                     FROM miners
                     WHERE total_shares > 0 AND last_seen >= ?2 AND instr(miner_id, '.') > 0
                     ORDER BY total_work DESC
                     LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![limit, active_cutoff], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, f64>(2)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rows)
        })
    }

    /// Top miners in a round with share counts. Backs the public
    /// "next block payout" endpoint: we show the miner's share %, share
    /// count, and projected sats at the next block find. Ordered by work
    /// desc so the caller can slice the top N for display.
    pub fn get_round_miners_with_counts(
        &self,
        round_id: u64,
        limit: u32,
    ) -> GhostResult<Vec<(String, f64, u64)>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT miner_id, SUM(work) AS total_work, COUNT(*) AS share_count
                     FROM shares_all WHERE round_id = ?1 AND valid = 1
                     GROUP BY miner_id ORDER BY total_work DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![round_id, limit], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, f64>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rows)
        })
    }

    /// Time-bucketed share/work history for a single miner. Backs the
    /// per-miner page's hashrate chart. Buckets are aligned on
    /// `(timestamp / bucket_secs) * bucket_secs` so the same ticks line up
    /// across miners and windows.
    pub fn get_miner_history(
        &self,
        miner_id: &str,
        since_ts: i64,
        bucket_secs: i64,
    ) -> GhostResult<Vec<(i64, u64, f64)>> {
        let bucket = bucket_secs.max(1);
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT (timestamp / ?3) * ?3 AS bucket,
                            COUNT(*) AS share_count,
                            SUM(work) AS total_work
                     FROM shares_all
                     WHERE miner_id = ?1 AND timestamp >= ?2 AND valid = 1
                     GROUP BY bucket
                     ORDER BY bucket ASC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![miner_id, since_ts, bucket], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, f64>(2)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rows)
        })
    }

    /// Get the highest round_id this node has ever issued.
    ///
    /// Returns 0 only on a genuinely fresh install (no rounds and no shares).
    ///
    /// ⚠ This MUST consider `rounds`, not just `shares`. `RoundManager::reload_from_db` uses the
    /// result to restore the round counter, and `start_round()` issues the next id from it — so a
    /// value that is too low re-issues round ids that ALREADY EXIST in `rounds`, carrying the
    /// block height they were created at. `create_round_if_not_exists` then leaves that stale
    /// height in place, and since `shard_epoch_shares` binds a share to its epoch by
    /// `rounds.block_height`, every share submitted against a re-issued id is filed under a
    /// long-past epoch. That epoch is already folded, `fold_epoch` returns `AlreadyFolded`, and
    /// the work is **silently never credited** — the fold just logs `shares=0` while miners are
    /// actively submitting.
    ///
    /// Reading only `shares` made that inevitable rather than unlucky, because the shard's own
    /// fold DELETES the shares it has folded (`shard_fold_epoch`), and `delete_old_shares` prunes
    /// more. Both drag `MAX(round_id) FROM shares` backwards while `rounds` keeps climbing. It was
    /// observed on the regtest cluster with `rounds` at 668 and `shares` at 450: a 218-round
    /// rewind across a restart, after which eight real mined shares were bound to height 338
    /// (epoch 56) and credited to nobody.
    pub fn get_max_round_id(&self) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let max_id: u64 = conn
                .query_row(
                    "SELECT MAX(m) FROM (
                         SELECT COALESCE(MAX(round_id), 0) AS m FROM rounds
                         UNION ALL
                         SELECT COALESCE(MAX(round_id), 0) AS m FROM shares
                     )",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(max_id)
        })
    }

    /// Delete shares older than `retention_secs` seconds. It does two distinct things:
    ///   1. PAID shares (`paid_in_proposal_hash IS NOT NULL`) older than
    ///      `retention_secs` are pruned — a short audit tail, no ledger value.
    ///   2. UNPAID shares (`paid_in_proposal_hash IS NULL`) are NEVER pruned
    ///      by age. They are only reclaimed once their miner has been dark
    ///      (no `last_seen` update) for over **one year**.
    ///
    /// ⚠ This used to describe itself as "the SINGLE authority for the `shares` row lifecycle".
    /// Since step 7 it is not: `Database::shard_fold_epoch` also deletes, dropping each epoch's
    /// evidence `RETENTION_EPOCHS` after folding it, and that is the reaper that actually bounds
    /// the live table now. The promise in (2) — that an active miner's unpaid ledger accumulates
    /// indefinitely — was true of the legacy ledger and is no longer true of `shares`. What
    /// carries a miner's work forward is the shard's grow-only `accrued` counter, not a row here.
    ///
    /// Uses the existing timestamp index for efficient deletion. Returns the number of deleted
    /// rows. Enforces a minimum retention of 1 hour to prevent accidental wipe.
    ///
    /// v56: deletes from the LIVE `shares` only. `shares_archive` is frozen — the point of no
    /// return is dropping it, and retention is not allowed to walk there by accident.
    pub fn delete_old_shares(&self, retention_secs: i64) -> GhostResult<usize> {
        // Guard: minimum 1 hour retention to prevent accidental wipe
        let retention_secs = retention_secs.max(3600);

        // `shares.timestamp` is stored in Unix SECONDS (despite the old
        // ShareRecord docstring). Previous code computed the cutoff in ms
        // which nuked the entire table on every prune tick.
        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let paid_cutoff = now_s - retention_secs;
        // Inactive-miner cutoff: unpaid shares belonging to miners whose
        // last_seen is older than ONE YEAR are reclaimed into the node pool
        // (via disappearance) so a permanently-abandoned miner's ledger does
        // not pin rows forever. Active miners — and even miners dark for up
        // to a year — keep every unpaid share regardless of age.
        const INACTIVE_SECS: i64 = 365 * 24 * 3600;
        let inactive_cutoff = now_s - INACTIVE_SECS;

        self.with_connection(|conn| {
            // 1. Paid shares: plain age-based prune. Keeps an audit tail
            //    of one retention window for paid history without bloat.
            let paid_deleted = conn
                .execute(
                    "DELETE FROM shares
                     WHERE timestamp < ?1
                       AND paid_in_proposal_hash IS NOT NULL",
                    params![paid_cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            // 2. Unpaid shares: drop only if the miner has been dark for
            //    1+ year. Active miners keep their full unpaid ledger.
            let unpaid_deleted = conn
                .execute(
                    "DELETE FROM shares
                     WHERE paid_in_proposal_hash IS NULL
                       AND miner_id IN (
                           SELECT miner_id FROM miners
                           WHERE last_seen < ?1
                       )",
                    params![inactive_cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(paid_deleted + unpaid_deleted)
        })
    }

    /// Minimum query length for miner search (DB-H1)
    /// Prevents expensive full-table scans with very short queries
    pub const MIN_MINER_SEARCH_LENGTH: usize = 3;

    /// Search miners by ID/address (partial match) and get their stats
    ///
    /// Returns empty results if query is too short (DB-H1 protection).
    pub fn search_miners(&self, query: &str) -> GhostResult<Vec<MinerSearchResult>> {
        // DB-H1: Require minimum query length to prevent expensive LIKE operations
        // Returns empty result instead of error for API convenience
        if query.len() < Self::MIN_MINER_SEARCH_LENGTH {
            tracing::debug!(
                query_len = query.len(),
                min_len = Self::MIN_MINER_SEARCH_LENGTH,
                "Miner search query too short, returning empty results"
            );
            return Ok(vec![]);
        }

        self.with_connection(|conn| {
            // M-STOR-1: Escape SQL LIKE wildcards to prevent injection
            // LOW-STOR-3: SQLite LIKE escaping behavior
            // - We use backslash (\) as the escape character via ESCAPE '\\'
            // - First replace \ with \\ to escape existing backslashes
            // - Then replace % with \% and _ with \_ to escape wildcards
            // - The ESCAPE clause in the SQL tells SQLite to treat \ as escape char
            let escaped_query = query
                .replace('\\', "\\\\") // Escape backslash first
                .replace('%', "\\%")
                .replace('_', "\\_");
            let search_pattern = format!("%{}%", escaped_query);
            let mut stmt = conn
                .prepare(
                    "SELECT
                        miner_id,
                        COUNT(*) as total_shares,
                        SUM(work) as total_work,
                        SUM(CASE WHEN valid = 1 THEN 1 ELSE 0 END) as valid_shares,
                        MIN(timestamp) as first_seen,
                        MAX(timestamp) as last_seen,
                        AVG(difficulty) as avg_difficulty
                     FROM shares_all
                     WHERE miner_id LIKE ?1 ESCAPE '\\'
                     GROUP BY miner_id
                     ORDER BY total_work DESC
                     LIMIT 50",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let results = stmt
                .query_map([&search_pattern], |row| {
                    Ok(MinerSearchResult {
                        miner_id: row.get(0)?,
                        total_shares: row.get(1)?,
                        total_work: row.get(2)?,
                        valid_shares: row.get(3)?,
                        first_seen: row.get(4)?,
                        last_seen: row.get(5)?,
                        avg_difficulty: row.get(6)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(results)
        })
    }

    /// Get detailed stats for a specific miner
    pub fn get_miner_stats(&self, miner_id: &str) -> GhostResult<Option<MinerDetailedStats>> {
        self.with_connection(|conn| {
            // Get aggregate stats
            let stats: Option<MinerDetailedStats> = conn
                .query_row(
                    "SELECT
                        miner_id,
                        COUNT(*) as total_shares,
                        SUM(work) as total_work,
                        SUM(CASE WHEN valid = 1 THEN 1 ELSE 0 END) as valid_shares,
                        SUM(CASE WHEN valid = 0 THEN 1 ELSE 0 END) as invalid_shares,
                        MIN(timestamp) as first_seen,
                        MAX(timestamp) as last_seen,
                        AVG(difficulty) as avg_difficulty,
                        COUNT(DISTINCT round_id) as rounds_participated
                     FROM shares_all
                     WHERE miner_id = ?1
                     GROUP BY miner_id",
                    params![miner_id],
                    |row| {
                        Ok(MinerDetailedStats {
                            miner_id: row.get(0)?,
                            total_shares: row.get(1)?,
                            total_work: row.get(2)?,
                            valid_shares: row.get(3)?,
                            invalid_shares: row.get(4)?,
                            first_seen: row.get(5)?,
                            last_seen: row.get(6)?,
                            avg_difficulty: row.get(7)?,
                            rounds_participated: row.get(8)?,
                            recent_shares: vec![],
                        })
                    },
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            // Get recent shares if miner exists
            if let Some(mut stats) = stats {
                let mut stmt = conn
                    .prepare(
                        "SELECT round_id, difficulty, work, timestamp, valid
                         FROM shares_all WHERE miner_id = ?1
                         ORDER BY timestamp DESC LIMIT 10",
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                let recent = stmt
                    .query_map([miner_id], |row| {
                        Ok(RecentShare {
                            round_id: row.get(0)?,
                            difficulty: row.get(1)?,
                            work: row.get(2)?,
                            timestamp: row.get(3)?,
                            valid: row.get(4)?,
                        })
                    })
                    .map_err(|e| GhostError::Database(e.to_string()))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                stats.recent_shares = recent;
                Ok(Some(stats))
            } else {
                Ok(None)
            }
        })
    }
}

// =============================================================================
// ROUND QUERIES
// =============================================================================

impl Database {
    /// Create a new round
    pub fn create_round(&self, round: &RoundRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO rounds (round_id, block_height, start_time, payout_status)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    round.round_id,
                    round.block_height,
                    round.start_time,
                    round.payout_status.as_str(),
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Create a round if it doesn't already exist (INSERT OR IGNORE).
    ///
    /// Used by payout recording to ensure the FK-referenced round exists
    /// before inserting payout entries. Idempotent — safe to call multiple times.
    pub fn create_round_if_not_exists(&self, round: &RoundRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO rounds (round_id, block_height, block_hash, start_time,
                                               found_by_node, payout_status, subsidy_sats, tx_fees_sats)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    round.round_id,
                    round.block_height,
                    round.block_hash,
                    round.start_time,
                    round.found_by_node,
                    round.payout_status.as_str(),
                    round.subsidy_sats,
                    round.tx_fees_sats,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Insert or update a round, always writing the block-outcome columns.
    ///
    /// Unlike `create_round_if_not_exists`, this overwrites `block_hash`,
    /// `found_by_node`, `payout_status`, `subsidy_sats` and `tx_fees_sats` on
    /// conflict, so the payout path can fill in block details on a round row
    /// that was already persisted at round start (with only `block_height`).
    /// `start_time` and share totals are preserved from the existing row.
    pub fn upsert_round(&self, round: &RoundRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO rounds (round_id, block_height, block_hash, start_time,
                                     found_by_node, payout_status, subsidy_sats, tx_fees_sats)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(round_id) DO UPDATE SET
                     block_height  = excluded.block_height,
                     block_hash    = excluded.block_hash,
                     found_by_node = excluded.found_by_node,
                     payout_status = excluded.payout_status,
                     subsidy_sats  = excluded.subsidy_sats,
                     tx_fees_sats  = excluded.tx_fees_sats",
                params![
                    round.round_id,
                    round.block_height,
                    round.block_hash,
                    round.start_time,
                    round.found_by_node,
                    round.payout_status.as_str(),
                    round.subsidy_sats,
                    round.tx_fees_sats,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a round by ID
    pub fn get_round(&self, round_id: u64) -> GhostResult<Option<RoundRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT round_id, block_height, block_hash, start_time, end_time,
                            total_shares, total_work, winning_miner, found_by_node,
                            payout_status, subsidy_sats, tx_fees_sats
                     FROM rounds WHERE round_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let round = stmt
                .query_row([round_id], |row| {
                    let status_str: String = row.get(9)?;
                    Ok(RoundRecord {
                        round_id: row.get(0)?,
                        block_height: row.get(1)?,
                        block_hash: row.get(2)?,
                        start_time: row.get(3)?,
                        end_time: row.get(4)?,
                        total_shares: row.get(5)?,
                        total_work: row.get(6)?,
                        winning_miner: row.get(7)?,
                        found_by_node: row.get(8)?,
                        payout_status: parse_payout_status_strict(&status_str, "get_round")?,
                        subsidy_sats: row.get(10)?,
                        tx_fees_sats: row.get(11)?,
                    })
                })
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(round)
        })
    }

    /// Update round with block found
    pub fn update_round_block_found(
        &self,
        round_id: u64,
        block_hash: &str,
        winning_miner: &str,
        found_by_node: &str,
        subsidy_sats: u64,
        tx_fees_sats: u64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE rounds SET
                    block_hash = ?1, winning_miner = ?2, found_by_node = ?3,
                    subsidy_sats = ?4, tx_fees_sats = ?5, payout_status = 'pending'
                 WHERE round_id = ?6",
                params![
                    block_hash,
                    winning_miner,
                    found_by_node,
                    subsidy_sats,
                    tx_fees_sats,
                    round_id
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// End a round
    pub fn end_round(&self, round_id: u64, end_time: i64) -> GhostResult<()> {
        self.with_connection(|conn| {
            // Update round totals
            conn.execute(
                "UPDATE rounds SET
                    end_time = ?1,
                    total_shares = (SELECT COUNT(*) FROM shares_all WHERE round_id = ?2 AND valid = 1),
                    total_work = (SELECT COALESCE(SUM(work), 0) FROM shares_all WHERE round_id = ?2 AND valid = 1)
                 WHERE round_id = ?2",
                params![end_time, round_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update round payout status
    pub fn update_round_status(&self, round_id: u64, status: PayoutStatus) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE rounds SET payout_status = ?1 WHERE round_id = ?2",
                params![status.as_str(), round_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Mark rounds as orphaned by block hash (called on reorg)
    ///
    /// Returns the number of rounds affected.
    /// Only affects rounds that haven't been confirmed yet.
    pub fn mark_rounds_orphaned_by_hash(&self, block_hash: &str) -> GhostResult<usize> {
        self.with_connection(|conn| {
            // Only orphan rounds that are pending/approved/broadcast - not already confirmed
            let affected = conn
                .execute(
                    "UPDATE rounds SET payout_status = 'orphaned'
                 WHERE block_hash = ?1
                   AND payout_status IN ('pending', 'approved', 'broadcast')",
                    params![block_hash],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(affected)
        })
    }

    /// Get rounds by block hash
    pub fn get_rounds_by_block_hash(&self, block_hash: &str) -> GhostResult<Vec<RoundRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT round_id, block_height, block_hash, start_time, end_time,
                            total_shares, total_work, winning_miner, found_by_node,
                            payout_status, subsidy_sats, tx_fees_sats
                     FROM rounds WHERE block_hash = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rounds = stmt
                .query_map([block_hash], |row| {
                    let status_str: String = row.get(9)?;
                    Ok(RoundRecord {
                        round_id: row.get(0)?,
                        block_height: row.get(1)?,
                        block_hash: row.get(2)?,
                        start_time: row.get(3)?,
                        end_time: row.get(4)?,
                        total_shares: row.get(5)?,
                        total_work: row.get(6)?,
                        winning_miner: row.get(7)?,
                        found_by_node: row.get(8)?,
                        payout_status: parse_payout_status_strict(
                            &status_str,
                            "get_rounds_by_block_hash",
                        )?,
                        subsidy_sats: row.get(10)?,
                        tx_fees_sats: row.get(11)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rounds)
        })
    }

    /// Get recent rounds
    pub fn get_recent_rounds(&self, limit: u32) -> GhostResult<Vec<RoundRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT round_id, block_height, block_hash, start_time, end_time,
                            total_shares, total_work, winning_miner, found_by_node,
                            payout_status, subsidy_sats, tx_fees_sats
                     FROM rounds ORDER BY round_id DESC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rounds = stmt
                .query_map([limit], |row| {
                    let status_str: String = row.get(9)?;
                    Ok(RoundRecord {
                        round_id: row.get(0)?,
                        block_height: row.get(1)?,
                        block_hash: row.get(2)?,
                        start_time: row.get(3)?,
                        end_time: row.get(4)?,
                        total_shares: row.get(5)?,
                        total_work: row.get(6)?,
                        winning_miner: row.get(7)?,
                        found_by_node: row.get(8)?,
                        payout_status: parse_payout_status_strict(
                            &status_str,
                            "get_recent_rounds",
                        )?,
                        subsidy_sats: row.get(10)?,
                        tx_fees_sats: row.get(11)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rounds)
        })
    }
}

// =============================================================================
// NODE QUERIES
// =============================================================================

impl Database {
    /// Upsert a node record
    ///
    /// L-1 FIX: Validates display_name (128 chars max) and public_address (256 chars max).
    /// L-4 FIX: Validates capabilities JSON structure and size (4 KB max).
    pub fn upsert_node(&self, node: &NodeRecord) -> GhostResult<()> {
        // L-1 FIX: Validate display_name length
        if let Some(ref name) = node.display_name {
            if name.len() > MAX_DISPLAY_NAME_LEN {
                return Err(GhostError::Database(format!(
                    "L-1: display_name too long: {} > {} chars",
                    name.len(),
                    MAX_DISPLAY_NAME_LEN
                )));
            }
        }

        // L-1 FIX: Validate public_address length
        if let Some(ref addr) = node.public_address {
            if addr.len() > MAX_PUBLIC_ADDRESS_LEN {
                return Err(GhostError::Database(format!(
                    "L-1: public_address too long: {} > {} chars",
                    addr.len(),
                    MAX_PUBLIC_ADDRESS_LEN
                )));
            }
        }

        // L-4 FIX: Validate capabilities JSON size
        if node.capabilities.len() > MAX_CAPABILITIES_JSON_SIZE {
            return Err(GhostError::Database(format!(
                "L-4: capabilities JSON too large: {} > {} bytes",
                node.capabilities.len(),
                MAX_CAPABILITIES_JSON_SIZE
            )));
        }

        // L-4 FIX: Validate capabilities is valid JSON
        if serde_json::from_str::<serde_json::Value>(&node.capabilities).is_err() {
            return Err(GhostError::Database(
                "L-4: capabilities is not valid JSON".into(),
            ));
        }

        // P-4: Encrypt payout address before storing
        let encrypted_payout = match &node.payout_address {
            Some(addr) if !addr.is_empty() => Some(self.encrypt_address(addr)?),
            other => other.clone(),
        };

        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO nodes (node_id, public_address, display_name, first_seen, last_seen,
                                   is_elder, elder_order, capabilities, payout_address)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(node_id) DO UPDATE SET
                    public_address = COALESCE(?2, public_address),
                    display_name = COALESCE(?3, display_name),
                    last_seen = ?5,
                    is_elder = ?6,
                    elder_order = ?7,
                    capabilities = ?8,
                    payout_address = COALESCE(?9, payout_address)",
                params![
                    node.node_id,
                    node.public_address,
                    node.display_name,
                    node.first_seen,
                    node.last_seen,
                    node.is_elder,
                    node.elder_order,
                    node.capabilities,
                    encrypted_payout,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a node by ID
    ///
    /// P-4: Decrypts the payout_address if encryption is configured.
    pub fn get_node(&self, node_id: &str) -> GhostResult<Option<NodeRecord>> {
        let node = self.with_connection(|conn| get_node_internal(conn, node_id))?;
        self.decrypt_node_record(node)
    }

    /// P-4: Decrypt payout_address in an optional NodeRecord
    fn decrypt_node_record(&self, node: Option<NodeRecord>) -> GhostResult<Option<NodeRecord>> {
        match node {
            Some(mut n) => {
                if let Some(ref addr) = n.payout_address {
                    if !addr.is_empty() {
                        n.payout_address = Some(self.decrypt_address(addr)?);
                    }
                }
                Ok(Some(n))
            }
            None => Ok(None),
        }
    }

    /// P-4: Decrypt payout_address in a vec of NodeRecords
    fn decrypt_node_records(&self, nodes: Vec<NodeRecord>) -> GhostResult<Vec<NodeRecord>> {
        nodes
            .into_iter()
            .map(|mut n| {
                if let Some(ref addr) = n.payout_address {
                    if !addr.is_empty() {
                        n.payout_address = Some(self.decrypt_address(addr)?);
                    }
                }
                Ok(n)
            })
            .collect()
    }

    /// Get all elders (ordered by registration)
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    /// Note: Protocol limits elders to 101, but we add LIMIT for defense in depth
    /// P-4: Decrypts payout addresses.
    pub fn get_elders(&self) -> GhostResult<Vec<NodeRecord>> {
        let nodes = self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT node_id, public_address, display_name, first_seen, last_seen,
                            is_elder, elder_order, capabilities, total_uptime_secs,
                            uptime_7d_percent, verification_pass_rate, total_shares_received,
                            total_blocks_found, payout_address
                     FROM nodes WHERE is_elder = 1 ORDER BY elder_order LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let nodes = stmt
                .query_map([Self::MAX_QUERY_RESULTS], node_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(nodes)
        })?;
        self.decrypt_node_records(nodes)
    }

    /// Get top N nodes by shares received
    ///
    /// P-4: Decrypts payout addresses.
    pub fn get_top_nodes_by_shares(&self, limit: u32) -> GhostResult<Vec<NodeRecord>> {
        let nodes = self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT node_id, public_address, display_name, first_seen, last_seen,
                            is_elder, elder_order, capabilities, total_uptime_secs,
                            uptime_7d_percent, verification_pass_rate, total_shares_received,
                            total_blocks_found, payout_address
                     FROM nodes ORDER BY total_shares_received DESC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let nodes = stmt
                .query_map([limit], node_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(nodes)
        })?;
        self.decrypt_node_records(nodes)
    }

    /// Update node last seen timestamp
    pub fn update_node_last_seen(&self, node_id: &str, timestamp: i64) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE nodes SET last_seen = ?1 WHERE node_id = ?2",
                params![timestamp, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Register this node (or refresh it): insert if absent, else bump `last_seen` and keep the
    /// stored public address unless a new one is given.
    pub fn register_node(
        &self,
        node_id: &str,
        public_address: Option<&str>,
        display_name: Option<&str>,
    ) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO nodes (node_id, public_address, display_name, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(node_id) DO UPDATE SET
                     last_seen = excluded.last_seen,
                     public_address = COALESCE(excluded.public_address, nodes.public_address),
                     display_name = COALESCE(excluded.display_name, nodes.display_name)",
                params![node_id, public_address, display_name, now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    // =========================================================================
    // ELDER REVOCATION (Offline >7 days → BFT vote → burned slot)
    // =========================================================================

    /// Get elder count
    pub fn get_elder_count(&self) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let count: u32 = conn
                .query_row("SELECT COUNT(*) FROM nodes WHERE is_elder = 1", [], |row| {
                    row.get(0)
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count)
        })
    }

    /// Increment node share count
    pub fn increment_node_shares(&self, node_id: &str, count: u64) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE nodes SET total_shares_received = total_shares_received + ?1 WHERE node_id = ?2",
                params![count, node_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

// =============================================================================
// MINER QUERIES
// =============================================================================

impl Database {
    /// Get a miner by ID
    ///
    /// P-4: Decrypts the payout_address if encryption is configured.
    pub fn get_miner(&self, miner_id: &str) -> GhostResult<Option<MinerRecord>> {
        let miner = self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT miner_id, payout_address, first_seen, last_seen,
                            connected_node, total_shares, total_work, blocks_won,
                            total_payouts_sats, avg_hashrate_ths
                     FROM miners WHERE miner_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let miner = stmt
                .query_row([miner_id], |row| {
                    Ok(MinerRecord {
                        miner_id: row.get(0)?,
                        payout_address: row.get(1)?,
                        first_seen: row.get(2)?,
                        last_seen: row.get(3)?,
                        connected_node: row.get(4)?,
                        total_shares: row.get(5)?,
                        total_work: row.get(6)?,
                        blocks_won: row.get(7)?,
                        total_payouts_sats: row.get(8)?,
                        avg_hashrate_ths: row.get(9)?,
                    })
                })
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(miner)
        })?;
        // P-4: Decrypt the payout address
        match miner {
            Some(mut m) => {
                if !m.payout_address.is_empty() {
                    m.payout_address = self.decrypt_address(&m.payout_address)?;
                }
                Ok(Some(m))
            }
            None => Ok(None),
        }
    }

    /// Return every miner whose `miner_id` is of the form `<address>.<worker>`
    /// for the given address. Uses the `miner_id` primary-key index with a
    /// prefix-LIKE match, so we never have to decrypt the stored (encrypted)
    /// payout_address column. Anchored with `.%` so `bc1qabc` can't match
    /// `bc1qabcdef.worker` by accident. Results are ordered by `last_seen`
    /// so the most-recently-active worker comes first.
    pub fn get_miners_by_address(
        &self,
        address: &str,
        limit: u32,
    ) -> GhostResult<Vec<MinerRecord>> {
        // Guard: require a plausible full address. Prefix matches on very
        // short strings can return thousands of rows and leak enumeration.
        if address.len() < 20 {
            return Ok(Vec::new());
        }
        let pattern = format!("{}.%", address);
        let miners = self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT miner_id, payout_address, first_seen, last_seen,
                            connected_node, total_shares, total_work, blocks_won,
                            total_payouts_sats, avg_hashrate_ths
                     FROM miners
                     WHERE miner_id LIKE ?1
                     ORDER BY last_seen DESC
                     LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![pattern, limit], |row| {
                    Ok(MinerRecord {
                        miner_id: row.get(0)?,
                        payout_address: row.get(1)?,
                        first_seen: row.get(2)?,
                        last_seen: row.get(3)?,
                        connected_node: row.get(4)?,
                        total_shares: row.get(5)?,
                        total_work: row.get(6)?,
                        blocks_won: row.get(7)?,
                        total_payouts_sats: row.get(8)?,
                        avg_hashrate_ths: row.get(9)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rows)
        })?;

        // Decrypt each payout_address column (matches get_miner's behaviour)
        miners
            .into_iter()
            .map(|mut m| {
                if !m.payout_address.is_empty() {
                    m.payout_address = self.decrypt_address(&m.payout_address)?;
                }
                Ok(m)
            })
            .collect()
    }

    /// Truncated SHA-256 of each miner_id whose `last_seen` is within the
    /// window. 16 bytes is enough for ~2^64 entries before birthday collisions
    /// become a concern — comfortable for a mining pool. Used to share a
    /// privacy-preserving fingerprint with mesh peers so a deduplicated active
    /// miner count can be computed without leaking miner_ids.
    pub fn active_miner_id_hashes(&self, window_secs: i64) -> GhostResult<Vec<[u8; 16]>> {
        use sha2::{Digest, Sha256};
        self.with_connection(|conn| {
            let cutoff: i64 = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64)
                - window_secs;
            // Only LOCALLY-CONNECTED miners — those whose miner_id is a real SV1
            // identity `payout_address.worker` (always contains '.'). The `miners`
            // table also accumulates the converged cross-node share ledger, where
            // a replicated share-proof records the miner under `hex(SHA256(id)[..8])`
            // (16 bare hex chars, no '.'). Counting those would double-count every
            // miner: once as its full id on its home node, once as the gossip hash
            // on every node — so 5 real miners read as 10. Each miner connects to
            // exactly one node, so the mesh union of per-node LOCAL sets is the
            // true distinct count. (Mirrors the `received_by` scoping in
            // `local_hashrate_th` that keeps the mesh hashrate from double-counting.)
            let mut stmt = conn
                .prepare(
                    "SELECT miner_id FROM miners WHERE last_seen > ?1 AND instr(miner_id, '.') > 0",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let rows = stmt
                .query_map(params![cutoff], |row| row.get::<_, String>(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let mut out: Vec<[u8; 16]> = Vec::new();
            for row in rows {
                let miner_id = row.map_err(|e| GhostError::Database(e.to_string()))?;
                let digest = Sha256::digest(miner_id.as_bytes());
                let mut h = [0u8; 16];
                h.copy_from_slice(&digest[..16]);
                out.push(h);
            }
            Ok(out)
        })
    }

    /// This node's own realized hashrate (TH/s) over a trailing `window_secs`,
    /// as a windowed rate: `SUM(work) * 2^32 / window_secs / 1e12`.
    ///
    /// Scoped to shares THIS node received directly via `received_by` — local
    /// shares store `received_by = hex(node_id[..8])` (16 hex chars), whereas
    /// replicated peer share-proofs store the 8-char `hex(origin[..4])`, so the
    /// filter excludes replicated rows. This is essential: each node sums only
    /// its own work, and the mesh total (sum of these across nodes) therefore
    /// counts every share exactly once. A fixed `window_secs` denominator (not
    /// `now - first_seen`) keeps the value stable and additive across nodes —
    /// a miner present for only part of the window contributes proportionally,
    /// which is correct for a fleet rate and avoids the per-miner elapsed-clamp
    /// that over-reported bursty/transient miners under load-balancer churn.
    /// Windowed hashrate for ONE miner, in TH/s.
    ///
    /// ⛔ Use this rather than open-coding the arithmetic. The two miner-facing API routes each
    /// computed their own version as `total_work * avg_difficulty / (last_seen - first_seen)`, which
    /// is wrong twice over (#981):
    ///
    ///   * `work == difficulty` in this codebase (`bins/ghost-pool/src/convergence.rs:815`, "the
    ///     ABSOLUTE model: work == difficulty"), so a share of difficulty D is D × 2³² hashes. The
    ///     correct factor is 2³², not the difficulty again — multiplying by `avg_difficulty`
    ///     double-counts it AND omits 2³². MEASURED: at avg_difficulty 57,929 that understates by
    ///     ~74,100x — 1,653 TH/s reported as 0.0223 TH/s.
    ///   * `last_seen - first_seen` is the miner's whole LIFETIME, so even with the right constant
    ///     it answers a question nobody asked: a miner who mined hard last month and lightly today
    ///     sees a figure describing neither.
    ///
    /// Three copies of one calculation is how two of them came to disagree with the third, which is
    /// why this exists alongside [`Self::local_hashrate_th`] rather than beside it in a route.
    pub fn miner_hashrate_th(&self, miner_id: &str, window_secs: i64) -> GhostResult<f64> {
        self.with_connection(|conn| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let cutoff = now - window_secs;
            let total_work: f64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(work), 0.0)
                     FROM shares_all
                     WHERE timestamp >= ?1 AND valid = 1 AND miner_id = ?2",
                    params![cutoff, miner_id],
                    |row| row.get::<_, f64>(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let window = window_secs.max(1) as f64;
            Ok(total_work * 4294967296.0 / window / 1e12)
        })
    }

    pub fn local_hashrate_th(&self, window_secs: i64, received_by: &str) -> GhostResult<f64> {
        self.with_connection(|conn| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let cutoff = now - window_secs;
            let total_work: f64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(work), 0.0)
                     FROM shares_all
                     WHERE timestamp >= ?1 AND valid = 1 AND received_by = ?2",
                    params![cutoff, received_by],
                    |row| row.get::<_, f64>(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let window = window_secs.max(1) as f64;
            Ok(total_work * 4294967296.0 / window / 1e12)
        })
    }

    /// Count miners whose `last_seen` is within the given window (seconds).
    ///
    /// Used for stable "active miners" reporting that's independent of round
    /// rotation. The legacy `round_stats(current_round).miner_count` resets to
    /// zero every time a round rolls and only fills back in as miners submit
    /// fresh shares — fine for round-scoped accounting, misleading on a
    /// dashboard where operators expect "how many miners are currently mining".
    pub fn count_active_miners(&self, window_secs: i64) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let cutoff: i64 = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64)
                - window_secs;
            // Count only locally-connected miners (real `address.worker` ids).
            // The `miners` table also holds the converged cross-node share ledger,
            // where replicated proofs are keyed by `hex(SHA256(id)[..8])` (no '.');
            // counting those double-counts each miner (see `active_miner_id_hashes`).
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM miners WHERE last_seen > ?1 AND instr(miner_id, '.') > 0",
                    params![cutoff],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count.max(0) as u32)
        })
    }

    /// Get miner's payout address by ID
    ///
    /// P-4: Decrypts the address if encryption is configured.
    pub fn get_miner_payout_address(&self, miner_id: &str) -> GhostResult<Option<String>> {
        let stored: Option<String> = self.with_connection(|conn| {
            conn.query_row(
                "SELECT payout_address FROM miners WHERE miner_id = ?1",
                [miner_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| GhostError::Database(e.to_string()))
        })?;
        // P-4: Decrypt the address if present
        match stored {
            Some(addr) if !addr.is_empty() => Ok(Some(self.decrypt_address(&addr)?)),
            other => Ok(other),
        }
    }

    /// Upsert a miner (insert or update)
    ///
    /// P-4: Encrypts the payout_address before storing if encryption is configured.
    pub fn upsert_miner(&self, miner: &MinerRecord) -> GhostResult<()> {
        // P-4: Encrypt the payout address before storing
        let encrypted_address = if miner.payout_address.is_empty() {
            miner.payout_address.clone()
        } else {
            self.encrypt_address(&miner.payout_address)?
        };
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO miners (
                    miner_id, payout_address, first_seen, last_seen,
                    connected_node, total_shares, total_work, blocks_won,
                    total_payouts_sats, avg_hashrate_ths
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(miner_id) DO UPDATE SET
                    payout_address = ?2,
                    last_seen = ?4,
                    connected_node = ?5,
                    total_shares = ?6,
                    total_work = ?7,
                    blocks_won = ?8,
                    total_payouts_sats = ?9,
                    avg_hashrate_ths = ?10",
                params![
                    miner.miner_id,
                    encrypted_address,
                    miner.first_seen,
                    miner.last_seen,
                    miner.connected_node,
                    miner.total_shares,
                    miner.total_work,
                    miner.blocks_won,
                    miner.total_payouts_sats,
                    miner.avg_hashrate_ths,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update miner's payout address
    ///
    /// Uses INSERT OR REPLACE (UPSERT) to atomically insert or update the miner,
    /// preventing TOCTOU race conditions that could occur with separate
    /// UPDATE-then-INSERT logic.
    ///
    /// P-4: Encrypts the address before storing if encryption is configured.
    pub fn update_miner_address(&self, miner_id: &str, payout_address: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        // P-4: Encrypt the address before storing
        let encrypted_address = self.encrypt_address(payout_address)?;

        self.with_connection(|conn| {
            // Use INSERT ... ON CONFLICT for atomic upsert (SQLite 3.24+)
            // This prevents TOCTOU race between checking if row exists and inserting
            conn.execute(
                "INSERT INTO miners (miner_id, payout_address, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(miner_id) DO UPDATE SET
                     payout_address = excluded.payout_address,
                     last_seen = excluded.last_seen",
                params![miner_id, encrypted_address, now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(())
        })
    }

    /// Increment miner share count and work
    ///
    /// MED-STOR-1: Uses saturating arithmetic to prevent overflow. If values would overflow,
    /// they saturate at their maximum instead of wrapping.
    pub fn increment_miner_stats(&self, miner_id: &str, shares: u64, work: f64) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            // MED-STOR-1: Use MIN(current + new, max_value) to implement saturating arithmetic
            // SQLite's integer max is i64::MAX (9223372036854775807)
            // For total_shares, we use saturating add via CASE statement
            conn.execute(
                "UPDATE miners SET
                    total_shares = CASE
                        WHEN total_shares > 9223372036854775807 - ?1 THEN 9223372036854775807
                        ELSE total_shares + ?1
                    END,
                    total_work = CASE
                        WHEN total_work + ?2 > 1.7976931348623157e+308 THEN total_work
                        ELSE total_work + ?2
                    END,
                    last_seen = ?3
                 WHERE miner_id = ?4",
                params![shares, work, now, miner_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

fn get_node_internal(conn: &Connection, node_id: &str) -> GhostResult<Option<NodeRecord>> {
    let mut stmt = conn
        .prepare(
            "SELECT node_id, public_address, display_name, first_seen, last_seen,
                    is_elder, elder_order, capabilities, total_uptime_secs,
                    uptime_7d_percent, verification_pass_rate, total_shares_received,
                    total_blocks_found, payout_address
             FROM nodes WHERE node_id = ?1",
        )
        .map_err(|e| GhostError::Database(e.to_string()))?;

    let node = stmt
        .query_row([node_id], node_from_row)
        .optional()
        .map_err(|e| GhostError::Database(e.to_string()))?;

    Ok(node)
}

fn node_from_row(row: &rusqlite::Row) -> rusqlite::Result<NodeRecord> {
    Ok(NodeRecord {
        node_id: row.get(0)?,
        public_address: row.get(1)?,
        display_name: row.get(2)?,
        first_seen: row.get(3)?,
        last_seen: row.get(4)?,
        is_elder: row.get(5)?,
        elder_order: row.get(6)?,
        capabilities: row.get(7)?,
        total_uptime_secs: row.get(8)?,
        uptime_7d_percent: row.get(9)?,
        verification_pass_rate: row.get(10)?,
        total_shares_received: row.get(11)?,
        total_blocks_found: row.get(12)?,
        payout_address: row.get(13)?,
    })
}

// =============================================================================
// NODE REWARD LEDGER QUERIES
// =============================================================================

impl Database {}

// =============================================================================
// KEY-VALUE STORE
// =============================================================================

impl Database {
    /// Get a value from the key-value store
    pub fn kv_get(&self, key: &str) -> GhostResult<Option<String>> {
        self.with_connection(|conn| {
            let value: Option<String> = conn
                .query_row("SELECT value FROM kv_store WHERE key = ?1", [key], |row| {
                    row.get(0)
                })
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(value)
        })
    }

    /// Set a value in the key-value store
    ///
    /// M-2 FIX: Validates value size to prevent storage exhaustion attacks.
    /// Maximum value size is 1 MB (MAX_KV_VALUE_SIZE).
    pub fn kv_set(&self, key: &str, value: &str) -> GhostResult<()> {
        // M-2 FIX: Validate value size before storing
        if value.len() > MAX_KV_VALUE_SIZE {
            return Err(GhostError::Database(format!(
                "M-2: KV value exceeds maximum size: {} > {} bytes",
                value.len(),
                MAX_KV_VALUE_SIZE
            )));
        }

        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO kv_store (key, value, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
                params![key, value, now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Delete a key from the key-value store
    pub fn kv_delete(&self, key: &str) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute("DELETE FROM kv_store WHERE key = ?1", [key])
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

// =============================================================================
// PEER QUERIES
// =============================================================================

impl Database {
    /// Upsert a peer record
    pub fn upsert_peer(&self, peer: &PeerRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO peers (
                    peer_id, address, port, node_id, first_seen, last_seen,
                    last_success, last_failure, connection_count, failure_count,
                    is_banned, ban_until, capabilities, protocol_version
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                ON CONFLICT(peer_id) DO UPDATE SET
                    address = COALESCE(NULLIF(?2, ''), address),
                    last_seen = ?6,
                    last_success = COALESCE(?7, last_success),
                    last_failure = COALESCE(?8, last_failure),
                    connection_count = ?9,
                    failure_count = ?10,
                    is_banned = ?11,
                    ban_until = ?12,
                    capabilities = COALESCE(?13, capabilities),
                    protocol_version = COALESCE(?14, protocol_version)",
                params![
                    peer.peer_id,
                    peer.address,
                    peer.port,
                    peer.node_id,
                    peer.first_seen,
                    peer.last_seen,
                    peer.last_success,
                    peer.last_failure,
                    peer.connection_count,
                    peer.failure_count,
                    peer.is_banned,
                    peer.ban_until,
                    peer.capabilities,
                    peer.protocol_version,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a peer by ID
    pub fn get_peer(&self, peer_id: &str) -> GhostResult<Option<PeerRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT peer_id, address, port, node_id, first_seen, last_seen,
                            last_success, last_failure, connection_count, failure_count,
                            is_banned, ban_until, capabilities, protocol_version
                     FROM peers WHERE peer_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let peer = stmt
                .query_row([peer_id], peer_from_row)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(peer)
        })
    }

    /// Get active (non-banned) peers
    pub fn get_active_peers(&self, limit: u32) -> GhostResult<Vec<PeerRecord>> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT peer_id, address, port, node_id, first_seen, last_seen,
                            last_success, last_failure, connection_count, failure_count,
                            is_banned, ban_until, capabilities, protocol_version
                     FROM peers
                     WHERE is_banned = 0 OR ban_until < ?1
                     ORDER BY last_success DESC NULLS LAST
                     LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let peers = stmt
                .query_map(params![now, limit], peer_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(peers)
        })
    }
}

fn peer_from_row(row: &rusqlite::Row) -> rusqlite::Result<PeerRecord> {
    Ok(PeerRecord {
        peer_id: row.get(0)?,
        address: row.get(1)?,
        port: row.get(2)?,
        node_id: row.get(3)?,
        first_seen: row.get(4)?,
        last_seen: row.get(5)?,
        last_success: row.get(6)?,
        last_failure: row.get(7)?,
        connection_count: row.get(8)?,
        failure_count: row.get(9)?,
        is_banned: row.get(10)?,
        ban_until: row.get(11)?,
        capabilities: row.get(12)?,
        protocol_version: row.get(13)?,
    })
}

impl Database {
    // ========================================================================
    // Verification API Queries
    // ========================================================================

    /// Get recent shares across all rounds (for verification API)
    pub fn get_recent_shares(&self, limit: u32) -> GhostResult<Vec<ShareRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid
                     FROM shares_all ORDER BY timestamp DESC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let shares = stmt
                .query_map([limit], |row| {
                    Ok(ShareRecord {
                        id: Some(row.get(0)?),
                        round_id: row.get(1)?,
                        miner_id: row.get(2)?,
                        difficulty: row.get(3)?,
                        work: row.get(4)?,
                        share_hash: row.get(5)?,
                        timestamp: row.get(6)?,
                        received_by: row.get(7)?,
                        valid: row.get(8)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(shares)
        })
    }

    /// Get total blocks found (distinct block heights from payout proposals)
    /// Aggregate node metrics for the Core page. Intentionally
    /// returns only pool-wide counts and a median — never per-node
    /// data — so Tor operators (and anyone else) aren't individually
    /// identifiable in the response.
    ///
    /// `median_uptime_pct` is None when there are fewer than 3 nodes
    /// with non-zero uptime — below that the median gives away too much
    /// about individual operators.
    pub fn get_node_stats(&self) -> GhostResult<(u64, u64, u64, Option<f64>)> {
        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let cutoff_7d = now_s - 7 * 24 * 3600;

        self.with_connection(|conn| {
            let total: u64 = conn
                .query_row("SELECT COUNT(*) FROM nodes", [], |r| r.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let active_7d: u64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM nodes WHERE last_seen >= ?1",
                    [cutoff_7d],
                    |r| r.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let new_7d: u64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM nodes WHERE first_seen >= ?1",
                    [cutoff_7d],
                    |r| r.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            // Median uptime across nodes with any uptime data. SQLite
            // doesn't have a MEDIAN aggregate so we fetch the values
            // and compute in Rust. Sample size is small (≤ node count).
            let mut stmt = conn
                .prepare("SELECT uptime_7d_percent FROM nodes WHERE uptime_7d_percent > 0 ORDER BY uptime_7d_percent ASC")
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let values: Vec<f64> = stmt
                .query_map([], |r| r.get::<_, f64>(0))
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let median = if values.len() < 3 {
                None
            } else if values.len() % 2 == 1 {
                Some(values[values.len() / 2])
            } else {
                let a = values[values.len() / 2 - 1];
                let b = values[values.len() / 2];
                Some((a + b) / 2.0)
            };

            Ok((total, active_7d, new_7d, median))
        })
    }

    /// Number of blocks the pool has actually WON and settled.
    ///
    /// Counts `won_blocks` (recorded by `settle_paid_block` only when the coins exist), NOT
    /// rows in `payout_proposals` — a proposal is created for EVERY block's tip-change/attempt,
    /// so the old `COUNT(DISTINCT block_height) FROM payout_proposals` inflated the count by
    /// every proposed (incl. rejected) block, not just wins.
    pub fn get_blocks_found_count(&self) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM won_blocks", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;
            i64_to_u64(count, "blocks_found").map_err(|e| GhostError::Database(e.to_string()))
        })
    }

    // =========================================================================
    // KEY ROTATION WITH ELDER STATUS TRANSFER
    // =========================================================================
}

// =============================================================================
// TREASURY STATE QUERIES
// =============================================================================

impl Database {}

// =============================================================================
// CAPABILITY VERIFICATION CHALLENGES
// =============================================================================

impl Database {}

impl Database {
    // =========================================================================
    // UNIQUE CHALLENGER COUNT QUERIES (C-2 Sybil Prevention)
    // =========================================================================

    // =========================================================================
    // PER-CHALLENGER MAJORITY QUERIES (anti-griefing for liveness probes)
    //
    // CONSENSUS SECURITY: Stratum and GhostPay are liveness checks with NO
    // chain ground truth, so a stored verdict cannot be re-derived the way
    // Archive/Policy now are. A colluding minority that is merely >5% of a
    // target's challengers could otherwise sign `passed=0` and drag an honest
    // node under the per-challenge percentage gate to deny its rewards.
    //
    // These queries collapse the verdict to ONE VOTE PER DISTINCT CHALLENGER:
    // each challenger's vote is the majority of THAT challenger's own results,
    // then we count how many distinct challengers voted pass vs total. The
    // caller (`get_qualified_capabilities_with_rates`) then requires a STRICT
    // majority of distinct challengers. This makes a <50% colluding minority
    // unable to grief OR inflate, and is flood-resistant: a single challenger
    // spamming thousands of rows still contributes exactly one vote.
    // =========================================================================

    // =========================================================================
    // DETERMINISTIC QUALIFICATION over the converged verification_ledger (v42)
    //
    // These read ONLY the reconciled ledger over a bounded, cutoff-anchored
    // window `[since, until]`, so every node that has converged its ledger
    // computes identical tallies for the same (target, window) — the
    // foundation for an independently-verifiable node-reward split. They mirror
    // the live `*_challenges` gate semantics: archive/policy use a per-row pass
    // rate (their verdicts are re-derived at ingest), stratum/ghostpay use a
    // per-distinct-challenger majority. `capability` is one of
    // "archive"/"policy"/"stratum"/"ghostpay" (see `CapabilityType::as_str`).
    // =========================================================================

    /// Record an uptime sample for a node
    pub fn record_uptime_sample(
        &self,
        node_id: &str,
        sample_time: i64,
        was_online: bool,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO uptime_samples (node_id, sample_time, was_online)
                 VALUES (?1, ?2, ?3)",
                params![node_id, sample_time, was_online],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Record that THIS node is alive at `now`: an uptime sample plus a fresh `last_seen` on its
    /// own `nodes` row.
    ///
    /// A peer's row is refreshed by every health ping received from it, but a node never
    /// receives its own ping, so without this its own row keeps the `last_seen` written at
    /// startup. Every reader that filters on recency then drops the node from its own view once
    /// that timestamp ages out — `get_node_stats` reported 7 of 8 nodes active on a healthy
    /// fleet a week after a restart (#1004).
    pub fn record_self_liveness(&self, node_id: &str, now: i64) -> GhostResult<()> {
        self.record_uptime_sample(node_id, now, true)?;
        self.update_node_last_seen(node_id, now)
    }

    /// GHOST-10: online fraction (0.0..=1.0) for the trailing window.
    ///
    /// Downtime manifests as MISSING `uptime_samples` rows (gaps), not
    /// `was_online = 0` rows — only `true` is ever recorded — so the old
    /// `online / total` was always ~1.0 and the 95% gatekeeper meant nothing.
    /// Measure liveness instead as online samples vs the number EXPECTED at the
    /// 10s sampling cadence (the self-uptime task and the health-ping interval
    /// are both 10s) over the window, capped at 1.0. A node down 10% of the
    /// window thus shows ~0.9 and fails the gatekeeper.
    fn uptime_ratio(online: i64, since: i64) -> f64 {
        const UPTIME_SAMPLE_INTERVAL_SECS: i64 = 10;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(since);
        let expected = ((now - since) / UPTIME_SAMPLE_INTERVAL_SECS).max(1);
        (online as f64 / expected as f64).clamp(0.0, 1.0)
    }

    /// Get uptime percentage for a node over trailing period
    /// Returns percentage (0.0 to 1.0)
    pub fn get_uptime_percent(&self, node_id: &str, since: i64) -> GhostResult<f64> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        SUM(CASE WHEN was_online = 1 THEN 1 ELSE 0 END) as online,
                        COUNT(*) as total
                     FROM uptime_samples
                     WHERE node_id = ?1 AND sample_time >= ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = stmt
                .query_row(params![node_id, since], |row| {
                    let online: Option<i64> = row.get(0)?;
                    let total: i64 = row.get(1)?;
                    Ok((online.unwrap_or(0), total))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let (online, _total) = result;
            // GHOST-10: time-based expected denominator, not online/total.
            Ok(Self::uptime_ratio(online, since))
        })
    }

    // =========================================================================
    // EQUIVOCATION PROOF QUERIES (P2P4-L7)
    // =========================================================================
}

// =============================================================================
// MPC CEREMONY QUERIES
// =============================================================================

impl Database {
    // =========================================================================
    // ELDER STATUS (MPC-BASED)
    // =========================================================================
    // Elder status is determined by MPC contribution.
    // If a node contributed to the MPC ceremony (position 1-101), they are an elder.
    // This replaces the complex canonical elder list system.

    /// Get all MPC elders (contributors)
    ///
    /// Returns list of (node_id, position) for all MPC contributors.
    pub fn get_all_mpc_elders(&self) -> GhostResult<Vec<(String, u32)>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT contributor_node_id, elder_position FROM mpc_contributions
                     ORDER BY elder_position ASC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map([], |row| {
                    let node_id: String = row.get(0)?;
                    let position: i64 = row.get(1)?;
                    Ok((node_id, position))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut elders = Vec::new();
            for row in rows {
                let (node_id, pos) = row.map_err(|e| GhostError::Database(e.to_string()))?;
                let position = i64_to_u32_count(pos, "elder_position")
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                elders.push((node_id, position));
            }
            Ok(elders)
        })
    }
}

impl Database {
    // =========================================================================
    // PAYOUT PROPOSAL PERSISTENCE
    // =========================================================================
}

// =============================================================================
// CHECKPOINT RECORDS
// =============================================================================

impl Database {
    // =========================================================================
    // PAYOUT-LEDGER AND MESH NODE-LIST CHECKPOINTS
    // =========================================================================
}

impl Database {
    // =========================================================================
    // L2 Epoch Fee Tracking
    // =========================================================================
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #1004: a node counts itself as active for as long as it is running, not only for the
    /// 7 days after it last started. The row is aged the way a long-running node's own row is
    /// (stamped once at registration, never refreshed by a peer ping).
    #[test]
    fn a_running_node_stays_in_its_own_active_count() {
        let db = Database::in_memory().expect("in-memory db");
        let node_id = "aa".repeat(32);
        db.register_node(&node_id, None, None)
            .expect("register self");

        let now = chrono::Utc::now().timestamp();
        let eight_days_ago = now - 8 * 24 * 3600;
        db.update_node_last_seen(&node_id, eight_days_ago)
            .expect("age the row");
        let (total, active_7d, _, _) = db.get_node_stats().expect("stats");
        assert_eq!(
            (total, active_7d),
            (1, 0),
            "fixture: a row last seen 8 days ago must be outside the window"
        );

        db.record_self_liveness(&node_id, now).expect("liveness");

        let (total, active_7d, _, _) = db.get_node_stats().expect("stats");
        assert_eq!(
            (total, active_7d),
            (1, 1),
            "a node that just recorded its own liveness must count as active"
        );
        let samples: i64 = db
            .with_connection(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM uptime_samples WHERE node_id = ?1 AND sample_time = ?2",
                    params![node_id, now],
                    |r| r.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))
            })
            .expect("count samples");
        assert_eq!(samples, 1, "the uptime sample must still be recorded");
    }

    #[test]
    fn test_share_insert_and_query() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");

        let share = ShareRecord {
            id: None,
            round_id: 1,
            miner_id: "abc123".to_string(),
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: "def456".to_string(),
            timestamp: 1234567890,
            received_by: "node1".to_string(),
            valid: true,
        };

        let id = db
            .insert_share(&share)
            .expect("LOW-STOR-8: Failed to insert share");
        assert!(id > 0);

        let shares = db
            .get_shares_by_round(1)
            .expect("LOW-STOR-8: Failed to get shares by round");
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].miner_id, "abc123");
    }

    #[test]
    fn test_reverse_hex_sql_function() {
        let db = Database::in_memory().expect("create in-memory db");
        // Byte-wise reverse of 00 11 22 33 -> 33 22 11 00.
        let out: String = db
            .with_connection(|conn| {
                conn.query_row("SELECT reverse_hex(?1)", params!["00112233"], |r| r.get(0))
                    .map_err(|e| GhostError::Database(e.to_string()))
            })
            .expect("reverse_hex query");
        assert_eq!(out, "33221100");

        // Non-hex / odd-length input is returned unchanged (never aborts a query).
        let bad: String = db
            .with_connection(|conn| {
                conn.query_row("SELECT reverse_hex(?1)", params!["xyz"], |r| r.get(0))
                    .map_err(|e| GhostError::Database(e.to_string()))
            })
            .expect("reverse_hex query");
        assert_eq!(bad, "xyz");
    }

    #[test]
    fn test_get_best_share_since_ranks_by_display_order() {
        // `share_hash` is stored INTERNAL byte order (schema v41: PoW zeros at the
        // BACK). Rarity = the DISPLAY-order value (zeros at the front). The best
        // share must be the one with the most DISPLAY leading zeros, NOT the raw
        // internal-lexicographic minimum.
        let db = Database::in_memory().expect("create in-memory db");

        // Build the INTERNAL-order 64-hex storage form from a readable DISPLAY
        // (big-endian) hash by reversing the 32 bytes.
        let to_internal = |display_hex: &str| -> String {
            let mut bytes = hex::decode(display_hex).expect("32-byte display hex");
            assert_eq!(bytes.len(), 32);
            bytes.reverse();
            hex::encode(bytes)
        };

        // DISPLAY value 1 (all zeros but the last byte) — the genuinely rarest.
        let winner_display = "0000000000000000000000000000000000000000000000000000000000000001";
        // DISPLAY value with a high leading byte — common.
        let common_display = "ff00000000000000000000000000000000000000000000000000000000000000";
        // DISPLAY value with a mid leading byte — common.
        let mid_display = "0000ff0000000000000000000000000000000000000000000000000000000000";

        let mk = |hash: String, miner: &str| ShareRecord {
            id: None,
            round_id: 1,
            miner_id: miner.to_string(),
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: hash,
            timestamp: 1_000,
            received_by: "node1".to_string(),
            valid: true,
        };

        db.insert_share(&mk(to_internal(common_display), "addr1.w"))
            .unwrap();
        db.insert_share(&mk(to_internal(winner_display), "addr2.w"))
            .unwrap();
        db.insert_share(&mk(to_internal(mid_display), "addr3.w"))
            .unwrap();

        let best = db
            .get_best_share_since(0)
            .expect("query best share")
            .expect("a best share exists");

        // The rarest DISPLAY value (1) wins, stored in its INTERNAL form.
        assert_eq!(best.share_hash, to_internal(winner_display));
        assert_eq!(best.miner_id, "addr2.w");

        // Sanity: a naive raw-lexicographic MIN(share_hash) does NOT pick the
        // winner — its internal form starts with "01" while the common/mid shares'
        // internal forms start with "00", so they sort first. This is exactly the
        // bug reverse_hex fixes.
        let naive_min: String = db
            .with_connection(|conn| {
                conn.query_row(
                    "SELECT MIN(share_hash) FROM shares WHERE valid = 1 AND instr(miner_id,'.') > 0",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))
            })
            .unwrap();
        assert_ne!(
            naive_min,
            to_internal(winner_display),
            "internal-lex MIN must differ from the true rarest — proves the fix matters"
        );
    }

    /// #981: the per-miner figure must use 2^32 and a BOUNDED window.
    ///
    /// Two miner-facing routes computed `total_work * avg_difficulty / (last_seen - first_seen)`.
    /// `work == difficulty` here, so that double-counts difficulty and omits 2^32 — MEASURED at
    /// ~74,100x understatement on live data (1,653 TH/s shown as 0.0223 TH/s). A miner comparing
    /// that to their own rig's display reads it as "this pool is not counting my work".
    ///
    /// The magnitude assertion is the point: a formula that is merely *a* number passes any
    /// equality test written against itself, which is how three copies of this calculation came to
    /// disagree. This pins the order of magnitude against an independent hand computation.
    #[test]
    fn miner_hashrate_uses_pow_scaling_and_a_bounded_window() {
        let db = Database::in_memory().expect("create in-memory db");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mk = |hash: &str, miner: &str, work: f64, age: i64| ShareRecord {
            id: None,
            round_id: 1,
            miner_id: miner.to_string(),
            difficulty: work,
            work,
            share_hash: hash.to_string(),
            timestamp: now - age,
            received_by: "fb71fee87bb05169".to_string(),
            valid: true,
        };
        let window = 600i64;

        // Inside the window, ours.
        db.insert_share(&mk("a", "mine", 30_000.0, 60)).unwrap();
        db.insert_share(&mk("b", "mine", 30_000.0, 120)).unwrap();
        // Another miner — must not be counted.
        db.insert_share(&mk("c", "theirs", 900_000.0, 60)).unwrap();
        // Ours but OUTSIDE the window — must not be counted. This is the half that the
        // lifetime-denominator version could never get right.
        db.insert_share(&mk("d", "mine", 900_000.0, window + 300))
            .unwrap();

        let hr = db.miner_hashrate_th("mine", window).unwrap();
        let expected = 60_000.0 * 4294967296.0 / window as f64 / 1e12;
        assert!(
            (hr - expected).abs() < 1e-9,
            "per-miner hashrate wrong: {hr} vs {expected}"
        );

        // Independent sanity on the SCALE, not just the formula agreeing with itself:
        // 60,000 difficulty-units of work in 600s is 60000*2^32/600 ≈ 4.295e8 H/s ≈ 0.4295 TH/s.
        assert!(
            (0.42..0.44).contains(&hr),
            "expected ~0.43 TH/s by hand, got {hr} — the old work×avg_difficulty form gave ~74,000x less"
        );

        // And the defect itself: the pre-fix formula must NOT reproduce this.
        let lifetime_secs = (window + 300) as f64;
        let wrong = (960_000.0 * 30_000.0) / lifetime_secs / 1e12;
        assert!(
            (hr / wrong) > 1_000.0,
            "the corrected value must differ from the old formula by orders of magnitude, \
             got ratio {}",
            hr / wrong
        );
    }

    #[test]
    fn test_local_hashrate_th_excludes_replicated_peer_shares() {
        // The mesh-wide pool hashrate sums each node's local_hashrate_th. For
        // that sum to count every share exactly once, each node must count ONLY
        // shares it received directly — NOT replicated peer share-proofs (which
        // the origin node already counts). Local shares store the 16-hex
        // received_by; replicated ones store the 8-hex origin id. This guards
        // the double-count bug the earlier per-miner design missed.
        let db = Database::in_memory().expect("create in-memory db");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        const SELF_ID: &str = "fb71fee87bb05169"; // hex(node_id[..8]) — local
        let mk = |hash: &str, work: f64, rx: &str| ShareRecord {
            id: None,
            round_id: 1,
            miner_id: "m".to_string(),
            difficulty: work,
            work,
            share_hash: hash.to_string(),
            timestamp: now - 60,
            received_by: rx.to_string(),
            valid: true,
        };
        db.insert_share(&mk("a", 1000.0, SELF_ID)).unwrap();
        db.insert_share(&mk("b", 1000.0, SELF_ID)).unwrap();
        db.insert_share(&mk("c", 5000.0, "849bcece")).unwrap(); // replicated peer

        let window = 600i64;
        let hr = db.local_hashrate_th(window, SELF_ID).unwrap();
        let expected = 2000.0 * 4294967296.0 / window as f64 / 1e12; // local work only
        assert!(
            (hr - expected).abs() < 1e-12,
            "local-only hashrate wrong: {hr} vs {expected}"
        );
        let with_peer = 7000.0 * 4294967296.0 / window as f64 / 1e12;
        assert!(
            (hr - with_peer).abs() > 1e-12,
            "must NOT include replicated peer shares"
        );
        // Unknown received_by (no local shares) reports 0.
        assert_eq!(
            db.local_hashrate_th(window, "deadbeefdeadbeef").unwrap(),
            0.0
        );
    }

    #[test]
    fn test_round_operations() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");

        let round = RoundRecord {
            round_id: 1,
            block_height: 100,
            block_hash: None,
            start_time: 1234567890,
            end_time: None,
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: None,
            payout_status: PayoutStatus::Active,
            subsidy_sats: None,
            tx_fees_sats: None,
        };

        db.create_round(&round)
            .expect("LOW-STOR-8: Failed to create round");

        let fetched = db
            .get_round(1)
            .expect("LOW-STOR-8: Failed to get round")
            .expect("LOW-STOR-8: Round should exist");
        assert_eq!(fetched.block_height, 100);
    }

    #[test]
    fn test_kv_store() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");

        db.kv_set("test_key", "test_value")
            .expect("LOW-STOR-8: Failed to set key-value");
        let value = db
            .kv_get("test_key")
            .expect("LOW-STOR-8: Failed to get key");
        assert_eq!(value, Some("test_value".to_string()));

        db.kv_delete("test_key")
            .expect("LOW-STOR-8: Failed to delete key");
        let value = db
            .kv_get("test_key")
            .expect("LOW-STOR-8: Failed to get deleted key");
        assert_eq!(value, None);
    }

    #[test]
    fn test_kv_store_size_limit() {
        // M-2: Test that oversized values are rejected
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");

        // Value at the limit should succeed
        let max_value = "x".repeat(super::MAX_KV_VALUE_SIZE);
        db.kv_set("max_key", &max_value)
            .expect("LOW-STOR-8: Max size value should succeed");

        // Value over the limit should fail
        let oversized_value = "x".repeat(super::MAX_KV_VALUE_SIZE + 1);
        let result = db.kv_set("oversized_key", &oversized_value);
        assert!(result.is_err());
        let err_msg = result
            .expect_err("LOW-STOR-8: Oversized value should fail")
            .to_string();
        assert!(
            err_msg.contains("M-2"),
            "Expected M-2 error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_peer_operations() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");
        let now = chrono::Utc::now().timestamp();

        let peer = PeerRecord {
            peer_id: "peer123".to_string(),
            address: "192.168.1.1".to_string(),
            port: 8333,
            node_id: Some("node456".to_string()),
            first_seen: now,
            last_seen: now,
            last_success: Some(now),
            last_failure: None,
            connection_count: 5,
            failure_count: 0,
            is_banned: false,
            ban_until: None,
            capabilities: Some("{}".to_string()),
            protocol_version: Some(1),
        };

        db.upsert_peer(&peer)
            .expect("LOW-STOR-8: Failed to upsert peer");

        let fetched = db
            .get_peer("peer123")
            .expect("LOW-STOR-8: Failed to get peer")
            .expect("LOW-STOR-8: Peer should exist");
        assert_eq!(fetched.address, "192.168.1.1");
        assert_eq!(fetched.connection_count, 5);

        let active = db
            .get_active_peers(10)
            .expect("LOW-STOR-8: Failed to get active peers");
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_node_validation() {
        // L-1 and L-4: Test validation on node fields
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");
        let now = chrono::Utc::now().timestamp();

        // Valid node should succeed
        let valid_node = NodeRecord {
            node_id: "node123".to_string(),
            public_address: Some("192.168.1.1:8555".to_string()),
            display_name: Some("Test Node".to_string()),
            first_seen: now,
            last_seen: now,
            is_elder: false,
            elder_order: None,
            capabilities: "{}".to_string(),
            total_uptime_secs: 0,
            uptime_7d_percent: 0.0,
            verification_pass_rate: 0.0,
            total_shares_received: 0,
            total_blocks_found: 0,
            payout_address: None,
        };
        db.upsert_node(&valid_node)
            .expect("LOW-STOR-8: Failed to upsert valid node");

        // L-1: display_name too long
        let long_name_node = NodeRecord {
            display_name: Some("x".repeat(super::MAX_DISPLAY_NAME_LEN + 1)),
            ..valid_node.clone()
        };
        let result = db.upsert_node(&long_name_node);
        assert!(result.is_err());
        assert!(result
            .expect_err("LOW-STOR-8: Long display name should fail")
            .to_string()
            .contains("L-1"));

        // L-1: public_address too long
        let long_addr_node = NodeRecord {
            node_id: "node456".to_string(),
            public_address: Some("x".repeat(super::MAX_PUBLIC_ADDRESS_LEN + 1)),
            display_name: None,
            ..valid_node.clone()
        };
        let result = db.upsert_node(&long_addr_node);
        assert!(result.is_err());
        assert!(result
            .expect_err("LOW-STOR-8: Long public address should fail")
            .to_string()
            .contains("L-1"));

        // L-4: capabilities too large
        let large_caps_node = NodeRecord {
            node_id: "node789".to_string(),
            capabilities: "x".repeat(super::MAX_CAPABILITIES_JSON_SIZE + 1),
            display_name: None,
            ..valid_node.clone()
        };
        let result = db.upsert_node(&large_caps_node);
        assert!(result.is_err());
        assert!(result
            .expect_err("LOW-STOR-8: Large capabilities should fail")
            .to_string()
            .contains("L-4"));

        // L-4: capabilities invalid JSON
        let invalid_json_node = NodeRecord {
            node_id: "node_abc".to_string(),
            capabilities: "not valid json".to_string(),
            display_name: None,
            ..valid_node.clone()
        };
        let result = db.upsert_node(&invalid_json_node);
        assert!(result.is_err());
        assert!(result
            .expect_err("LOW-STOR-8: Invalid JSON capabilities should fail")
            .to_string()
            .contains("L-4"));
    }

    // =========================================================================
    // L-24 FIX TESTS: Instant Payment Reservation Persistence
    // =========================================================================

    #[test]
    fn test_active_miner_count_excludes_gossiped_ledger_rows() {
        // Regression: 5 miners read as 10. Each miner is stored under its full SV1
        // id `address.worker` on its home node AND under `hex(SHA256(id)[..8])` in
        // the converged cross-node share ledger on every node. Counting both
        // double-counts every miner. Active-miner counting must include only the
        // locally-connected `address.worker` rows (which contain '.').
        let db = Database::in_memory().expect("create in-memory db");
        let now_s = chrono::Utc::now().timestamp();

        let mk = |miner_id: &str| MinerRecord {
            miner_id: miner_id.to_string(),
            payout_address: String::new(),
            first_seen: now_s - 100,
            last_seen: now_s - 10, // well within a 300s window
            connected_node: None,
            total_shares: 1,
            total_work: 1000.0,
            blocks_won: 0,
            total_payouts_sats: 0,
            avg_hashrate_ths: 0.0,
        };

        // One real locally-connected miner...
        db.upsert_miner(&mk("bc1qexampleaddr.bitaxe1"))
            .expect("insert local miner");
        // ...and its gossip-ledger twin (hex(SHA256(full_id)[..8]), no '.').
        db.upsert_miner(&mk("67eb564b74d01ed4"))
            .expect("insert gossiped row");

        assert_eq!(
            db.count_active_miners(300).expect("count"),
            1,
            "only the locally-connected miner counts; the gossip-ledger row must not double it"
        );
        assert_eq!(
            db.active_miner_id_hashes(300).expect("hashes").len(),
            1,
            "the mesh-union hash set must contain only the locally-connected miner"
        );
    }

    #[test]
    fn test_leaderboard_excludes_gossiped_ledger_rows() {
        // The shares table holds both real local shares (miner_id `address.worker`)
        // and replicated cross-node proofs keyed by the bare hex(SHA256(id)) ledger
        // id. The leaderboard must list only real miners — otherwise the same miner
        // appears twice (once under its hex gossip twin).
        let db = Database::in_memory().expect("create in-memory db");
        let now_s = chrono::Utc::now().timestamp();

        let share = |miner_id: &str, hash: &str, work: f64| ShareRecord {
            id: None,
            round_id: 1,
            miner_id: miner_id.to_string(),
            difficulty: work,
            work,
            share_hash: hash.to_string(),
            timestamp: now_s - 60,
            received_by: "node1".to_string(),
            valid: true,
        };
        // Real miner with a strong best hash...
        db.insert_share(&share(
            "bc1qexampleaddr.bitaxe3",
            "000000000000000732a94aee7325d02fd49adbe4f89f9cfcb11ebf0bd33bc26b",
            2000.0,
        ))
        .expect("insert real share");
        // ...and its gossip-ledger twin (bare hex id, no '.').
        db.insert_share(&share(
            "30bcad707233de9d",
            "0001a496881607bf16a91a3fbada1bcd0fa6e3e2b7d4c5a6978899aabbccddee",
            2000.0,
        ))
        .expect("insert gossiped share");

        let best = db
            .get_leaderboard_best_hash(now_s - 3600, 10)
            .expect("best");
        assert_eq!(best.len(), 1, "leaderboard must list only the real miner");
        assert_eq!(best[0].0, "bc1qexampleaddr.bitaxe3");

        let shares = db.get_leaderboard_shares(now_s - 3600, 10).expect("shares");
        assert_eq!(
            shares.len(),
            1,
            "shares-contributed must exclude the gossip twin"
        );
        assert_eq!(shares[0].0, "bc1qexampleaddr.bitaxe3");

        // The single best share is attributed to the real miner, not the hex twin.
        let single = db
            .get_best_share_since(now_s - 3600)
            .expect("single")
            .unwrap();
        assert_eq!(single.miner_id, "bc1qexampleaddr.bitaxe3");

        // The quasar feed must likewise exclude the gossip twin — its share_hash
        // is stored internal-order (no leading zeros) and would render as a
        // dead-center 0-bit dot, and it's a duplicate of the real share anyway.
        let recent = db
            .get_recent_valid_shares(now_s - 3600, 100)
            .expect("recent");
        assert_eq!(recent.len(), 1, "quasar feed must exclude the gossip twin");
        assert_eq!(recent[0].0, "bc1qexampleaddr.bitaxe3");
    }

    #[test]
    fn test_best_share_per_window_and_round_scoping() {
        // Backs the /api/v1/mining/best-hash per-window records. Each window
        // must resolve the rarest real-miner share within it (not the chain
        // tip), attach the round's block height, and scope "current round"
        // strictly by round_id.
        let db = Database::in_memory().expect("create in-memory db");
        let now_s = chrono::Utc::now().timestamp();

        let round = |round_id: u64, block_height: u64| RoundRecord {
            round_id,
            block_height,
            block_hash: None,
            start_time: now_s - 100_000,
            end_time: None,
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: None,
            payout_status: PayoutStatus::Active,
            subsidy_sats: None,
            tx_fees_sats: None,
        };
        db.create_round(&round(1, 500)).expect("round 1");
        db.create_round(&round(2, 501)).expect("round 2");

        let share = |round_id: u64, miner_id: &str, hash: &str, ts: i64| ShareRecord {
            id: None,
            round_id,
            miner_id: miner_id.to_string(),
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: hash.to_string(),
            timestamp: ts,
            received_by: "node1".to_string(),
            valid: true,
        };

        // Round 1 (old): a very rare all-time-best share, ~30h ago so it falls
        // OUTSIDE the last-24h and last-hour windows.
        db.insert_share(&share(
            1,
            "bc1qminerA.w1",
            "0000000000000000000000000000000000000000000000000000000000000abc",
            now_s - 108_000,
        ))
        .expect("insert old best");
        // Round 2 (current): a weaker share within the last hour.
        db.insert_share(&share(
            2,
            "bc1qminerB.w1",
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            now_s - 600,
        ))
        .expect("insert recent");
        // A gossip-ledger twin (bare hex id, no '.') that is numerically the
        // rarest of all — it must be excluded from every window.
        db.insert_share(&share(
            2,
            "deadbeefcafef00d",
            "0000000000000000000000000000000000000000000000000000000000000001",
            now_s - 600,
        ))
        .expect("insert gossip twin");

        // All-time picks the rarest real share (round 1) and resolves its
        // block height via the round join.
        let all_time = db.get_best_share_since(0).expect("all-time").unwrap();
        assert_eq!(all_time.miner_id, "bc1qminerA.w1");
        assert_eq!(all_time.block_height, Some(500));

        // Last hour excludes the 30h-old round-1 share, so miner B wins.
        let last_hour = db
            .get_best_share_since(now_s - 3_600)
            .expect("last-hour")
            .unwrap();
        assert_eq!(last_hour.miner_id, "bc1qminerB.w1");
        assert_eq!(last_hour.block_height, Some(501));

        // Current round is scoped by round_id: round 2 sees only miner B, and
        // round 1 sees only miner A — neither leaks across, and the gossip
        // twin never appears.
        let cur2 = db.get_best_share_in_round(2).expect("round 2").unwrap();
        assert_eq!(cur2.miner_id, "bc1qminerB.w1");
        let cur1 = db.get_best_share_in_round(1).expect("round 1").unwrap();
        assert_eq!(cur1.miner_id, "bc1qminerA.w1");

        // A round with no shares yields None (frontend renders "No data yet").
        assert!(db.get_best_share_in_round(99).expect("empty").is_none());
    }

    #[test]
    fn test_best_share_block_height_from_round_start_persistence() {
        // Regression: the per-window best-hash join resolves a share's block
        // height from the `rounds` table. In production, rounds were only
        // written by the payout (block-found) path, which almost never fires,
        // so the table was empty and every per-window best share reported a
        // null block height. Persisting the round at start — with only its
        // block height and an Active status — must make the join resolve, and
        // a later payout upsert must fill the block-outcome columns without
        // disturbing the height.
        let db = Database::in_memory().expect("create in-memory db");
        let now_s = chrono::Utc::now().timestamp();

        // Round persisted at start: block height known, no block outcome yet.
        let start_record = RoundRecord {
            round_id: 7,
            block_height: 956_695,
            block_hash: None,
            start_time: now_s - 600,
            end_time: None,
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: None,
            payout_status: PayoutStatus::Active,
            subsidy_sats: None,
            tx_fees_sats: None,
        };
        db.create_round_if_not_exists(&start_record)
            .expect("persist round at start");

        db.insert_share(&ShareRecord {
            id: None,
            round_id: 7,
            miner_id: "bc1qminerA.w1".to_string(),
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: "0000000000000000000000000000000000000000000000000000000000000abc"
                .to_string(),
            timestamp: now_s - 300,
            received_by: "node1".to_string(),
            valid: true,
        })
        .expect("insert share");

        // Every window (time-based and round-scoped) now carries the real
        // block height resolved from the round persisted at start.
        for best in [
            db.get_best_share_since(0).expect("all-time").unwrap(),
            db.get_best_share_since(now_s - 3_600)
                .expect("last-hour")
                .unwrap(),
            db.get_best_share_in_round(7).expect("round 7").unwrap(),
        ] {
            assert_eq!(best.miner_id, "bc1qminerA.w1");
            assert_eq!(best.block_height, Some(956_695));
        }

        // A later payout upserts the block-outcome columns onto the same row.
        let payout_record = RoundRecord {
            round_id: 7,
            block_height: 956_695,
            block_hash: Some("deadbeef".to_string()),
            start_time: now_s, // ignored on conflict — start_time is preserved
            end_time: None,
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: Some("node1".to_string()),
            payout_status: PayoutStatus::Approved,
            subsidy_sats: Some(312_500_000),
            tx_fees_sats: Some(1_234),
        };
        db.upsert_round(&payout_record)
            .expect("upsert payout details");

        let round = db.get_round(7).expect("get round").unwrap();
        assert_eq!(round.block_height, 956_695);
        assert_eq!(round.block_hash.as_deref(), Some("deadbeef"));
        assert_eq!(round.payout_status, PayoutStatus::Approved);
        assert_eq!(round.subsidy_sats, Some(312_500_000));
        assert_eq!(round.tx_fees_sats, Some(1_234));
        // start_time from the original (start-time) insert is preserved.
        assert_eq!(round.start_time, now_s - 600);

        // Best share still resolves the height after the upsert.
        let best = db.get_best_share_in_round(7).expect("round 7").unwrap();
        assert_eq!(best.block_height, Some(956_695));
    }

    #[test]
    fn test_share_pruning_and_max_round_id() {
        let db = Database::in_memory().expect("Failed to create in-memory database");

        // Empty table: max round_id should be 0
        let max = db.get_max_round_id().expect("Failed to get max round id");
        assert_eq!(max, 0);

        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Insert old share (48 hours ago) belonging to a miner that has
        // been dark for >1 year. delete_old_shares only prunes unpaid
        // shares of inactive miners (last_seen older than 1 year), so the
        // miner row is required for the inactive-cutoff JOIN to match.
        let old_share = ShareRecord {
            id: None,
            round_id: 1,
            miner_id: "miner_old".to_string(),
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: "hash_old".to_string(),
            timestamp: now_s - (48 * 3600),
            received_by: "node1".to_string(),
            valid: true,
        };
        db.upsert_miner(&MinerRecord {
            miner_id: "miner_old".to_string(),
            payout_address: String::new(),
            first_seen: now_s - (400 * 24 * 3600),
            last_seen: now_s - (400 * 24 * 3600),
            connected_node: None,
            total_shares: 1,
            total_work: 1000.0,
            blocks_won: 0,
            total_payouts_sats: 0,
            avg_hashrate_ths: 0.0,
        })
        .expect("Failed to insert inactive miner");
        db.insert_share(&old_share)
            .expect("Failed to insert old share");

        // Insert recent share (30 minutes ago — well within the 1h minimum retention)
        let recent_share = ShareRecord {
            id: None,
            round_id: 5,
            miner_id: "miner_recent".to_string(),
            difficulty: 2000.0,
            work: 2000.0,
            share_hash: "hash_recent".to_string(),
            timestamp: now_s - (30 * 60),
            received_by: "node1".to_string(),
            valid: true,
        };
        db.insert_share(&recent_share)
            .expect("Failed to insert recent share");

        // Max round_id should be 5
        let max = db.get_max_round_id().expect("Failed to get max round id");
        assert_eq!(max, 5);

        // Prune with 24h retention — should delete only the old share
        let deleted = db
            .delete_old_shares(24 * 3600)
            .expect("Failed to delete old shares");
        assert_eq!(deleted, 1);

        // Recent share should remain
        let remaining = db
            .get_shares_by_round(5)
            .expect("Failed to get shares by round");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].miner_id, "miner_recent");

        // Old share should be gone
        let old = db.get_shares_by_round(1).expect("Failed to get old shares");
        assert_eq!(old.len(), 0);

        // Minimum retention guard: even with 0 seconds, enforces 1 hour minimum
        // The recent share (30 min old) should survive
        let deleted = db
            .delete_old_shares(0)
            .expect("Failed to prune with minimum guard");
        assert_eq!(
            deleted, 0,
            "Recent share should survive minimum retention guard"
        );
    }

    /// The round counter must not rewind when folded or pruned shares leave `rounds` ahead of
    /// `shares`.
    ///
    /// This is the restart path. `RoundManager::reload_from_db` sets the counter from this value
    /// and `start_round()` issues the next id, so a value taken from `shares` alone re-issues ids
    /// that already exist in `rounds` at the height they were created — and because
    /// `shard_epoch_shares` bins a share by `rounds.block_height`, the new work is filed under an
    /// epoch that is already folded and is credited to nobody, silently.
    ///
    /// Observed live before the fix: `rounds` at 668, `shares` at 450 after the shard's fold
    /// deleted what it had folded, and eight real mined shares bound to height 338.
    #[test]
    fn max_round_id_does_not_rewind_when_shares_lag_rounds() {
        let db = Database::in_memory().expect("Failed to create in-memory database");

        let round = |round_id: u64, block_height: u64| RoundRecord {
            round_id,
            block_height,
            block_hash: None,
            start_time: 1_700_000_000,
            end_time: None,
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: None,
            payout_status: PayoutStatus::Active,
            subsidy_sats: None,
            tx_fees_sats: None,
        };

        // An old round, and a much newer one — as a running pool accumulates.
        db.create_round(&round(450, 338)).expect("create round 450");
        db.create_round(&round(668, 370)).expect("create round 668");

        // The only surviving share belongs to the OLD round: everything newer has been folded
        // away by the shard or pruned by retention. This is the ordinary steady state, not a
        // corrupted database.
        db.insert_share(&ShareRecord {
            id: None,
            round_id: 450,
            miner_id: "miner".to_string(),
            difficulty: 1.0,
            work: 1.0,
            share_hash: "surviving_share".to_string(),
            timestamp: 1_700_000_001,
            received_by: "node1".to_string(),
            valid: true,
        })
        .expect("insert share");

        assert_eq!(
            db.get_max_round_id().expect("max round id"),
            668,
            "the counter must come from the highest round ever ISSUED (668), not the highest \
             round that still has a share (450) — restoring 450 re-issues 451.. over rounds that \
             already exist at a stale height, and the shares filed against them are folded into a \
             closed epoch and never credited"
        );
    }

    // =========================================================================
    // SHARE-LIFECYCLE / PAYOUT-LEDGER PROTECTION TESTS
    //
    // These guard the miners' earned-but-unpaid balances against the two
    // hourly prune paths. `delete_old_shares` (Path A) is the SINGLE authority
    // for share-row deletion; `run_maintenance`/`prune_old_rounds` (Path B)
    // must never touch a still-needed share.
    // =========================================================================

    fn ledger_now_s() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn ledger_miner(id: &str, last_seen: i64) -> MinerRecord {
        MinerRecord {
            miner_id: id.to_string(),
            payout_address: id.split('.').next().unwrap_or(id).to_string(),
            first_seen: last_seen - 24 * 3600,
            last_seen,
            connected_node: None,
            total_shares: 1,
            total_work: 1500.0,
            blocks_won: 0,
            total_payouts_sats: 0,
            avg_hashrate_ths: 0.0,
        }
    }

    fn ledger_share(round_id: u64, miner_id: &str, hash: &str, timestamp: i64) -> ShareRecord {
        ShareRecord {
            id: None,
            round_id,
            miner_id: miner_id.to_string(),
            difficulty: 1500.0,
            work: 1500.0,
            share_hash: hash.to_string(),
            timestamp,
            received_by: "node1".to_string(),
            valid: true,
        }
    }

    /// A miner dark for 400 days (> 1 year) has its abandoned unpaid share
    /// reclaimed by `delete_old_shares`.
    #[test]
    fn test_dark_miner_over_one_year_unpaid_share_reclaimed() {
        let db = Database::in_memory().unwrap();
        let now_s = ledger_now_s();
        let miner = "bc1qdark400d.worker";

        db.upsert_miner(&ledger_miner(miner, now_s - 400 * 24 * 3600))
            .unwrap();
        db.insert_share(&ledger_share(
            1,
            miner,
            "dark400d_unpaid",
            now_s - 400 * 24 * 3600,
        ))
        .unwrap();

        let deleted = db.delete_old_shares(24 * 3600).unwrap();
        assert_eq!(
            deleted, 1,
            "share of a >1-year-dark miner must be reclaimed"
        );
        assert!(db.get_shares_by_round(1).unwrap().is_empty());
    }

    // =========================================================================
    // FK Payout Recording Tests
    // =========================================================================

    fn test_round_record(round_id: u64, block_height: u64) -> RoundRecord {
        RoundRecord {
            round_id,
            block_height,
            block_hash: Some("abc123".to_string()),
            start_time: 1700000000,
            end_time: None,
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: Some("node1".to_string()),
            payout_status: PayoutStatus::Approved,
            subsidy_sats: Some(312_500_000),
            tx_fees_sats: Some(100_000),
        }
    }

    #[test]
    fn test_create_round_if_not_exists_idempotent() {
        let db = Database::in_memory().expect("Failed to create in-memory database");
        let round = test_round_record(1, 850_000);
        db.create_round_if_not_exists(&round)
            .expect("First create should succeed");
        db.create_round_if_not_exists(&round)
            .expect("Second create should also succeed (idempotent)");
        // Verify only one round exists
        let fetched = db.get_round(1).expect("Failed to get round");
        assert!(fetched.is_some());
    }

    // =========================================================================
    // PER-CHALLENGER MAJORITY (anti-griefing for stratum / ghostpay)
    // =========================================================================

    // ---- v56: the archive/live split, through the public API --------------------------------

    /// Seed a share into a specific table. `shares_archive` is what every row looked like the
    /// instant before the cutover; `shares` is what ingest writes after it.
    fn seed_into(db: &Database, table: &str, miner: &str, hash: &str, ts: i64, work: f64) {
        let sql = format!(
            "INSERT INTO {table}
                (round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid)
             VALUES (1, ?1, 1.0, ?2, ?3, ?4, 'node0000', 1)"
        );
        db.with_connection(|c| {
            c.execute(&sql, params![miner, work, hash, ts])
                .map_err(|e| GhostError::Database(e.to_string()))
        })
        .expect("seed");
    }

    /// The best-hash leaderboard must pick the rarest share across BOTH tables, and must return
    /// the row that actually owns that hash.
    ///
    /// This pins two things a faster query could silently break. `get_leaderboard_best_hash`
    /// replaced `ROW_NUMBER() OVER (PARTITION BY …)` with `MIN(reverse_hex(share_hash))` for a
    /// 13x speedup, which leans on SQLite's "bare columns take their value from the MIN row"
    /// rule — so `timestamp` and `difficulty` must still belong to the winning share, not to an
    /// arbitrary one. And the winner must be found whichever side of the cutover it is on.
    ///
    /// `share_hash` is stored INTERNAL byte order, so rarity is `reverse_hex(share_hash)`
    /// ascending: zeros at the FRONT once reversed. The fixtures below are built so the rare one
    /// is unambiguous under that ordering and NOT under raw lexicographic order — otherwise the
    /// test would pass against a query that forgot to reverse.
    #[test]
    fn best_hash_leaderboard_spans_both_tables_and_keeps_the_winning_row() {
        let db = Database::in_memory().expect("in-memory db");

        // Internal order: rarity lives at the BACK. Reversed, "…0000" becomes "0000…".
        let rare_hash = format!("{}{}", "ff".repeat(24), "00".repeat(8)); // reverses to 0000…
        let dull_hash = format!("{}{}", "00".repeat(24), "ff".repeat(8)); // reverses to ffff…

        // The RARE one is archived; the dull one is live. A query that only reads the live table,
        // or that drops the archive arm, returns the dull hash and fails here.
        seed_into(
            &db,
            "shares_archive",
            "bc1qminer.rig",
            &rare_hash,
            1_000,
            1.0,
        );
        seed_into(&db, "shares", "bc1qminer.rig", &dull_hash, 2_000, 1.0);

        let board = db.get_leaderboard_best_hash(0, 10).expect("best hash");
        assert_eq!(board.len(), 1, "one miner, one best share");
        let (miner, hash, ts, _diff) = &board[0];
        assert_eq!(miner, "bc1qminer.rig");
        assert_eq!(
            hash, &rare_hash,
            "the rarest share is the ARCHIVED one; picking the live share means the archive arm \
             was dropped, and picking by raw order means reverse_hex was lost"
        );
        assert_eq!(
            *ts, 1_000,
            "timestamp must come from the winning row — this is the SQLite bare-column guarantee \
             the MIN() rewrite depends on"
        );

        // Now put an even rarer share on the LIVE side; it must take over.
        let rarer_hash = format!("{}{}", "ee".repeat(24), "00".repeat(8));
        seed_into(&db, "shares", "bc1qminer.rig", &rarer_hash, 3_000, 1.0);
        let board = db.get_leaderboard_best_hash(0, 10).expect("best hash");
        assert_eq!(
            board[0].1, rarer_hash,
            "a rarer LIVE share must beat the archived one — the merge is not archive-preferring"
        );
        assert_eq!(board[0].2, 3_000, "and its own timestamp travels with it");
    }
}

#[cfg(test)]
mod ledger_reconciliation_tests {}
