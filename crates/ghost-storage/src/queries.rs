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

/// L-22 FIX: Parse RecipientType, returning error on invalid value.
fn parse_recipient_type_strict(
    type_str: &str,
    context: &str,
) -> Result<RecipientType, rusqlite::Error> {
    RecipientType::parse(type_str).ok_or_else(|| {
        warn!(
            type_str = type_str,
            context = context,
            "L-22: Invalid RecipientType value in database"
        );
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid RecipientType '{}' in context '{}'",
                    type_str, context
                ),
            )),
        )
    })
}

/// LOW-STOR-8 FIX: Parse GhostLockState, returning error on invalid value.
fn parse_ghost_lock_state_strict(
    state_str: &str,
    context: &str,
) -> Result<GhostLockState, rusqlite::Error> {
    GhostLockState::parse(state_str).ok_or_else(|| {
        warn!(
            state_str = state_str,
            context = context,
            "LOW-STOR-8: Invalid GhostLockState value in database"
        );
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid GhostLockState '{}' in context '{}'",
                    state_str, context
                ),
            )),
        )
    })
}

/// LOW-STOR-8 FIX: Parse WraithPhase, returning error on invalid value.
fn parse_wraith_phase_strict(
    phase_str: &str,
    context: &str,
) -> Result<WraithPhase, rusqlite::Error> {
    WraithPhase::parse(phase_str).ok_or_else(|| {
        warn!(
            phase_str = phase_str,
            context = context,
            "LOW-STOR-8: Invalid WraithPhase value in database"
        );
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid WraithPhase '{}' in context '{}'",
                    phase_str, context
                ),
            )),
        )
    })
}

/// LOW-STOR-8 FIX: Parse WraithStatus, returning error on invalid value.
fn parse_wraith_status_strict(
    status_str: &str,
    context: &str,
) -> Result<WraithStatus, rusqlite::Error> {
    WraithStatus::parse(status_str).ok_or_else(|| {
        warn!(
            status_str = status_str,
            context = context,
            "LOW-STOR-8: Invalid WraithStatus value in database"
        );
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid WraithStatus '{}' in context '{}'",
                    status_str, context
                ),
            )),
        )
    })
}

/// LOW-STOR-8 FIX: Parse ReconciliationStatus, returning error on invalid value.
fn parse_reconciliation_status_strict(
    status_str: &str,
    context: &str,
) -> Result<ReconciliationStatus, rusqlite::Error> {
    ReconciliationStatus::parse(status_str).ok_or_else(|| {
        warn!(
            status_str = status_str,
            context = context,
            "LOW-STOR-8: Invalid ReconciliationStatus value in database"
        );
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid ReconciliationStatus '{}' in context '{}'",
                    status_str, context
                ),
            )),
        )
    })
}

/// LOW-STOR-8 FIX: Parse WithdrawalStatus, returning error on invalid value.
fn parse_withdrawal_status_strict(
    status_str: &str,
    context: &str,
) -> Result<WithdrawalStatus, rusqlite::Error> {
    WithdrawalStatus::parse(status_str).ok_or_else(|| {
        warn!(
            status_str = status_str,
            context = context,
            "LOW-STOR-8: Invalid WithdrawalStatus value in database"
        );
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid WithdrawalStatus '{}' in context '{}'",
                    status_str, context
                ),
            )),
        )
    })
}

/// Type alias for node rotation data: (is_elder, elder_order, pow_proof, capabilities, first_seen)
type NodeRotationData = (
    bool,
    Option<u32>,
    Option<String>,
    Option<String>,
    Option<i64>,
);

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

/// LOW-STOR-4: Maximum signature size (hex-encoded Ed25519 signature: 128 hex chars = 64 bytes)
/// Ed25519 signatures are exactly 64 bytes (128 hex characters).
/// Set to 128 to match the actual Ed25519 signature size.
pub const MAX_SIGNATURE_SIZE: usize = 128;

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

/// SEC-DATA-1: Safely convert i64 from SQLite to u64, rejecting negative values
///
/// SQLite stores integers as signed, but satoshi values should never be negative.
/// This helper validates the conversion to catch database corruption.
fn i64_to_u64_sats(value: i64, field_name: &str) -> Result<u64, rusqlite::Error> {
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
                     FROM shares WHERE round_id = ?1 ORDER BY timestamp LIMIT ?2",
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
                     FROM shares WHERE round_id = ?1 AND miner_id = ?2 ORDER BY timestamp LIMIT ?3",
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
                    "SELECT COALESCE(SUM(work), 0) FROM shares WHERE round_id = ?1 AND miner_id = ?2 AND valid = 1",
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
                     FROM shares WHERE round_id = ?1 AND valid = 1
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
                     FROM shares WHERE round_id = ?1
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
                     FROM shares
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

    /// Find the best (lowest-value hex, most-leading-zeros) valid share
    /// submitted at or after `since_ts` (Unix seconds). Returns `None` if
    /// no shares match. Used to power public pool records (best hash per
    /// window).
    ///
    /// Correctness: SHA256 hashes rendered as zero-padded 64-char hex
    /// sort lexicographically in the same order as the underlying integer
    /// value, so `ORDER BY share_hash ASC LIMIT 1` gives the share closest
    /// to the all-zero target.
    pub fn get_best_share_since(
        &self,
        since_ts: i64,
    ) -> GhostResult<Option<crate::models::BestShare>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT share_hash, miner_id, timestamp, difficulty
                     FROM shares
                     WHERE timestamp >= ?1 AND valid = 1
                     ORDER BY share_hash ASC
                     LIMIT 1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let row = stmt
                .query_row(params![since_ts], |row| {
                    Ok(crate::models::BestShare {
                        share_hash: row.get(0)?,
                        miner_id: row.get(1)?,
                        timestamp: row.get(2)?,
                        difficulty: row.get(3)?,
                    })
                })
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(row)
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
        // Finding each miner's MIN(share_hash) then re-sorting is cheap
        // at our volume; if this becomes hot we can keep a materialised
        // per-miner-per-day rollup.
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT s.miner_id, s.share_hash, s.timestamp, s.difficulty
                     FROM shares s
                     INNER JOIN (
                         SELECT miner_id, MIN(share_hash) AS best_hash
                         FROM shares
                         WHERE timestamp >= ?1 AND valid = 1
                         GROUP BY miner_id
                     ) b ON s.miner_id = b.miner_id AND s.share_hash = b.best_hash
                     WHERE s.timestamp >= ?1 AND s.valid = 1
                     ORDER BY s.share_hash ASC
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
                    "SELECT miner_id, COUNT(*) AS share_count, SUM(work) AS total_work
                     FROM shares
                     WHERE timestamp >= ?1 AND valid = 1
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

    /// Unpaid-ledger snapshot: the top N miners by accumulated work that
    /// has NOT yet been committed to a payout proposal. Backs the ledger
    /// payout path — when a block is found the winning node calls this
    /// with cutoff = block_timestamp, dust-filters the result, and
    /// commits the survivors into the next template's coinbase.
    ///
    /// `cutoff_ts` keeps shares submitted *after* block-find out of the
    /// current payout: those belong to the next round's ledger.
    ///
    /// Returns `(miner_id, unpaid_work)` ordered by unpaid_work desc.
    pub fn get_top_unpaid_miners(
        &self,
        cutoff_ts: i64,
        limit: u32,
    ) -> GhostResult<Vec<(String, f64)>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT miner_id, SUM(work) AS unpaid_work
                     FROM shares
                     WHERE paid_in_proposal_hash IS NULL
                       AND timestamp <= ?1
                       AND valid = 1
                     GROUP BY miner_id
                     ORDER BY unpaid_work DESC
                     LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![cutoff_ts, limit], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rows)
        })
    }

    /// Address-grouped variant of [`Self::get_top_unpaid_miners`]. Sums
    /// unpaid work across all of a payout address's workers so a user
    /// running N rigs under one BTC address takes ONE coinbase slot
    /// instead of N. Backs the post-`PAYOUT_ADDRESS_GROUPING_HEIGHT`
    /// payout path; the legacy per-miner_id query stays around for the
    /// pre-gate path so a mixed-version mesh keeps producing identical
    /// proposals during the rollout window.
    ///
    /// Tie-break: lex order on the (decrypted) address. Deterministic
    /// across every node so the BFT supermajority computes identical
    /// proposal hashes.
    ///
    /// `payout_address` is encrypted at rest, so we can't `GROUP BY`
    /// in SQL — fetch the unpaid set, decrypt addresses in-process, then
    /// fold into a HashMap. At ledger sizes (low thousands of unpaid
    /// miners) the decrypt loop is negligible; if it ever shows up in
    /// flame graphs, add a `payout_address_hash` column + migration.
    ///
    /// Returns `Vec<(address, unpaid_work, miner_ids_in_group)>` ordered
    /// by unpaid_work desc, address asc. The `miner_ids_in_group` field
    /// lets the caller pass the flattened list straight to
    /// [`Self::mark_miners_paid`] without a follow-up resolve query.
    pub fn get_top_unpaid_addresses(
        &self,
        cutoff_ts: i64,
        limit: u32,
    ) -> GhostResult<Vec<(String, f64, Vec<String>)>> {
        // 1. Pull every unpaid (miner_id, work, encrypted_address) row.
        //    No GROUP BY in SQL because the address is encrypted.
        let raw: Vec<(String, f64, String)> = self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT s.miner_id, SUM(s.work) AS unpaid_work, m.payout_address
                     FROM shares s
                     INNER JOIN miners m ON m.miner_id = s.miner_id
                     WHERE s.paid_in_proposal_hash IS NULL
                       AND s.timestamp <= ?1
                       AND s.valid = 1
                     GROUP BY s.miner_id",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![cutoff_ts], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, f64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rows)
        })?;

        // 2. Decrypt + group by plaintext address. Skip rows whose
        //    payout_address is empty or fails to decrypt — they have no
        //    valid output target and should be excluded from payout
        //    rather than crashing the whole proposal.
        use std::collections::HashMap;
        let mut acc: HashMap<String, (f64, Vec<String>)> = HashMap::new();
        for (miner_id, work, enc_addr) in raw {
            if enc_addr.is_empty() {
                continue;
            }
            let plain = match self.decrypt_address(&enc_addr) {
                Ok(s) if !s.is_empty() => s,
                _ => continue,
            };
            let entry = acc.entry(plain).or_insert((0.0, Vec::new()));
            entry.0 += work;
            entry.1.push(miner_id);
        }

        // 3. Sort by (unpaid_work desc, address asc) — deterministic
        //    tie-break for cross-node BFT consensus.
        let mut sorted: Vec<(String, f64, Vec<String>)> = acc
            .into_iter()
            .map(|(addr, (work, ids))| (addr, work, ids))
            .collect();
        sorted.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        sorted.truncate(limit as usize);

        // 4. Each group's miner_ids list also gets a stable order so
        //    downstream callers that hash / serialise it converge.
        for entry in sorted.iter_mut() {
            entry.2.sort();
        }

        Ok(sorted)
    }

    /// Resolve a list of decrypted payout addresses to every `miner_id`
    /// currently bound to one of them. Used by the mark-paid handler
    /// post-`PAYOUT_ADDRESS_GROUPING_HEIGHT`: the proposal lists hashed
    /// ADDRESSES, but `mark_miners_paid` works on miner_ids, so we need
    /// to fan out before the UPDATE.
    ///
    /// Decrypts every miner's stored address in-process and matches in
    /// memory — same trade-off as [`Self::get_top_unpaid_addresses`].
    /// The input set is bounded by `LEDGER_CAP` (1000) so the cost is
    /// always trivially small.
    pub fn miner_ids_for_addresses(&self, addresses: &[String]) -> GhostResult<Vec<String>> {
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        use std::collections::HashSet;
        let wanted: HashSet<&str> = addresses.iter().map(|s| s.as_str()).collect();

        let pairs: Vec<(String, String)> = self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT miner_id, payout_address
                     FROM miners
                     WHERE payout_address IS NOT NULL AND payout_address != ''",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rows)
        })?;

        let mut out: Vec<String> = Vec::new();
        for (miner_id, enc_addr) in pairs {
            let plain = match self.decrypt_address(&enc_addr) {
                Ok(s) if !s.is_empty() => s,
                _ => continue,
            };
            if wanted.contains(plain.as_str()) {
                out.push(miner_id);
            }
        }
        out.sort();
        Ok(out)
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
            let mut stmt = conn
                .prepare(
                    "SELECT miner_id, share_hash, timestamp, work
                     FROM shares
                     WHERE timestamp > ?1 AND valid = 1
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

    /// Per-miner unpaid summary: how many shares and how much work a
    /// single miner currently has on their ledger. Used by the lookup
    /// endpoint so the miner stats page can display unpaid shares next
    /// to the lifetime figure.
    pub fn get_miner_unpaid_stats(&self, miner_id: &str) -> GhostResult<(u64, f64)> {
        self.with_connection(|conn| {
            let (count, work): (u64, f64) = conn
                .query_row(
                    "SELECT COUNT(*), COALESCE(SUM(work), 0)
                     FROM shares
                     WHERE miner_id = ?1
                       AND paid_in_proposal_hash IS NULL
                       AND valid = 1",
                    params![miner_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok((count, work))
        })
    }

    /// Distinct miner_ids with at least one unpaid share up to `cutoff_ts`.
    /// Used by the proposal-accepted hook: each consensus-approving node
    /// hashes these strings and matches against the `PayoutEntry.recipient_id`
    /// hashes in the accepted proposal to learn which shares to mark paid.
    /// The reverse lookup lives in Rust (SHA-256 of bytes) so we don't
    /// need a custom SQLite function.
    pub fn get_distinct_unpaid_miner_ids(&self, cutoff_ts: i64) -> GhostResult<Vec<String>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT DISTINCT miner_id FROM shares
                     WHERE paid_in_proposal_hash IS NULL
                       AND timestamp <= ?1
                       AND valid = 1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![cutoff_ts], |row| row.get::<_, String>(0))
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rows)
        })
    }

    /// Count of distinct miners currently carrying unpaid shares. Useful
    /// for the payout endpoint's "miners waiting" tile so the frontend
    /// can show how many miners are in the ledger vs how many get paid
    /// in a single block.
    pub fn count_unpaid_miners(&self, cutoff_ts: i64) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: u64 = conn
                .query_row(
                    "SELECT COUNT(DISTINCT miner_id) FROM shares
                     WHERE paid_in_proposal_hash IS NULL
                       AND timestamp <= ?1
                       AND valid = 1",
                    params![cutoff_ts],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count)
        })
    }

    /// Commit a block's payout: mark every unpaid share belonging to the
    /// paid miners (up to `cutoff_ts`) with this proposal's hash. Shares
    /// submitted after the cutoff stay NULL and roll into the next block's
    /// ledger.
    ///
    /// Batched in chunks to avoid SQLite's ~999 host-parameter limit on
    /// large IN-lists (1000 miners exceeds it by 1).
    pub fn mark_miners_paid(
        &self,
        proposal_hash: &[u8; 32],
        miner_ids: &[String],
        cutoff_ts: i64,
    ) -> GhostResult<usize> {
        if miner_ids.is_empty() {
            return Ok(0);
        }
        // SQLite default SQLITE_MAX_VARIABLE_NUMBER is 32766 on modern
        // builds but historically 999. Chunk at 500 to be safe and to
        // keep each UPDATE's lock hold-time short.
        const CHUNK: usize = 500;

        self.with_connection(|conn| {
            let mut updated_total: usize = 0;
            for batch in miner_ids.chunks(CHUNK) {
                let placeholders: Vec<&str> = batch.iter().map(|_| "?").collect();
                let sql = format!(
                    "UPDATE shares
                     SET paid_in_proposal_hash = ?1
                     WHERE paid_in_proposal_hash IS NULL
                       AND timestamp <= ?2
                       AND miner_id IN ({})",
                    placeholders.join(",")
                );

                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                let mut bind: Vec<Box<dyn rusqlite::ToSql>> = Vec::with_capacity(batch.len() + 2);
                bind.push(Box::new(proposal_hash.to_vec()));
                bind.push(Box::new(cutoff_ts));
                for id in batch {
                    bind.push(Box::new(id.clone()));
                }
                let params_ref: Vec<&dyn rusqlite::ToSql> =
                    bind.iter().map(|b| b.as_ref()).collect();

                let updated = stmt
                    .execute(params_ref.as_slice())
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                updated_total += updated;
            }
            Ok(updated_total)
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
                     FROM shares s
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
                    "SELECT miner_id, total_shares, total_work
                     FROM miners
                     WHERE total_shares > 0 AND last_seen >= ?2
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
                     FROM shares WHERE round_id = ?1 AND valid = 1
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
                     FROM shares
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

    /// Get the highest round_id from the shares table
    ///
    /// Returns 0 if no shares exist (fresh install).
    pub fn get_max_round_id(&self) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let max_id: u64 = conn
                .query_row("SELECT COALESCE(MAX(round_id), 0) FROM shares", [], |row| {
                    row.get(0)
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(max_id)
        })
    }

    /// Delete shares older than `retention_secs` seconds
    ///
    /// Uses the existing `idx_shares_timestamp` index for efficient deletion.
    /// Returns the number of deleted rows.
    /// Enforces a minimum retention of 1 hour to prevent accidental wipe.
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
        // last_seen is older than 7 days are dropped into the node pool
        // (via disappearance) so they don't sit on the ledger forever.
        // Active miners keep every unpaid share regardless of age.
        const INACTIVE_SECS: i64 = 7 * 24 * 3600;
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
            //    7+ days. Active miners keep their full unpaid ledger.
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
                     FROM shares
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
                     FROM shares
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
                         FROM shares WHERE miner_id = ?1
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
                    total_shares = (SELECT COUNT(*) FROM shares WHERE round_id = ?2 AND valid = 1),
                    total_work = (SELECT COALESCE(SUM(work), 0) FROM shares WHERE round_id = ?2 AND valid = 1)
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

    /// Get all node IDs with payout addresses
    ///
    /// Returns node IDs from the nodes table that have a payout address configured.
    /// Used for payout calculations to include all registered nodes.
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_all_node_ids_with_payout(&self) -> GhostResult<Vec<String>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT node_id FROM nodes WHERE payout_address IS NOT NULL AND payout_address != '' LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let node_ids = stmt
                .query_map([Self::MAX_QUERY_RESULTS], |row| row.get::<_, String>(0))
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(node_ids)
        })
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

    /// Register a node and check if it should be an elder
    /// Returns (is_elder, elder_order) - elder_order is Some(n) if node is elder
    ///
    /// Uses deterministic elder selection: lowest node_id (lexicographically) wins ties.
    /// This prevents race conditions at genesis where multiple nodes register simultaneously.
    ///
    /// **Sybil Resistance**: Nodes must provide valid PoW proof to be eligible for elder status.
    /// Call `register_node_with_elder_check_and_pow` for the full-featured version.
    ///
    /// The algorithm:
    /// 1. Insert the node if it doesn't exist (IGNORE on conflict)
    /// 2. Within an IMMEDIATE transaction (exclusive write lock):
    ///    - Count current elders
    ///    - If < MAX_ELDERS, promote eligible non-elder nodes by node_id order
    /// 3. Return the node's final elder status
    pub fn register_node_with_elder_check(
        &self,
        node_id: &str,
        public_address: Option<&str>,
        display_name: Option<&str>,
        capabilities: &str,
    ) -> GhostResult<(bool, Option<u32>)> {
        // Delegate to the version with PoW (using None for backwards compatibility)
        self.register_node_with_elder_check_and_pow(
            node_id,
            public_address,
            display_name,
            capabilities,
            None,
        )
    }

    /// Register a node with PoW proof for Sybil-resistant elder eligibility
    ///
    /// **IMPORTANT**: Nodes without valid PoW proofs will NOT be eligible for elder status.
    /// This prevents Sybil attacks where attackers generate many node_ids to capture elder slots.
    ///
    /// Uses deterministic elder selection: lowest node_id (lexicographically) wins ties.
    /// This prevents race conditions at genesis where multiple nodes register simultaneously.
    ///
    /// This is safe because:
    /// - IMMEDIATE transaction takes write lock before reading
    /// - Elder promotion is deterministic (by node_id)
    /// - Same result regardless of registration order
    pub fn register_node_with_elder_check_and_pow(
        &self,
        node_id: &str,
        public_address: Option<&str>,
        display_name: Option<&str>,
        capabilities: &str,
        pow_proof: Option<&str>,
    ) -> GhostResult<(bool, Option<u32>)> {
        use ghost_common::identity::{verify_node_id_pow_hex, NODE_ID_POW_DIFFICULTY};

        let now = chrono::Utc::now().timestamp();
        let max_elders = ghost_common::constants::MAX_ELDERS;

        // Verify PoW if provided
        let has_valid_pow = if let Some(proof) = pow_proof {
            verify_node_id_pow_hex(node_id, proof, NODE_ID_POW_DIFFICULTY)
        } else {
            false
        };

        self.with_connection(|conn| {
            // DB-C2: BEGIN IMMEDIATE transaction FIRST to prevent TOCTOU race conditions
            // This acquires a write lock before ANY reads or writes, ensuring atomicity
            // of the entire node registration + elder promotion operation.
            conn.execute("BEGIN IMMEDIATE", [])
                .map_err(|e| GhostError::Database(format!("Failed to begin transaction: {}", e)))?;

            let result = (|| -> GhostResult<(bool, Option<u32>)> {
                // Step 1: Insert node if not exists (now inside transaction)
                conn.execute(
                    "INSERT OR IGNORE INTO nodes (node_id, public_address, display_name, first_seen, last_seen,
                                                  is_elder, elder_order, capabilities, pow_proof)
                     VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL, ?6, ?7)",
                    params![
                        node_id,
                        public_address,
                        display_name,
                        now,
                        now,
                        capabilities,
                        pow_proof,
                    ],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                // Update last_seen, capabilities, and pow_proof if node already existed
                conn.execute(
                    "UPDATE nodes SET last_seen = ?1, public_address = COALESCE(?2, public_address),
                                      capabilities = ?3, pow_proof = COALESCE(?4, pow_proof)
                     WHERE node_id = ?5",
                    params![now, public_address, capabilities, pow_proof, node_id],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                // Step 2: Atomic elder promotion (deterministic)
                // Count current elders
                let elder_count: u32 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM nodes WHERE is_elder = 1",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                // If we have room for more elders, promote by node_id order (deterministic)
                // SYBIL RESISTANCE: Only nodes with valid PoW are eligible for elder status
                if elder_count < max_elders {
                    let slots_available = max_elders - elder_count;

                    // Promote non-elder nodes with lowest node_ids first
                    // BUT only if they have a valid PoW proof!
                    // (pow_proof IS NOT NULL means they submitted a proof - validated on insert)
                    conn.execute(
                        "UPDATE nodes SET is_elder = 1, elder_order = (
                            SELECT COUNT(*) + 1 FROM nodes n2 WHERE n2.is_elder = 1
                        )
                        WHERE node_id IN (
                            SELECT node_id FROM nodes
                            WHERE is_elder = 0 AND pow_proof IS NOT NULL
                            ORDER BY node_id ASC
                            LIMIT ?1
                        )",
                        params![slots_available],
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                }

                // Fetch final status for this node
                let (is_elder, elder_order): (bool, Option<u32>) = conn
                    .query_row(
                        "SELECT is_elder, elder_order FROM nodes WHERE node_id = ?1",
                        [node_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                // Log warning if node could have been elder but lacks PoW
                if !is_elder && !has_valid_pow && elder_count < max_elders {
                    tracing::debug!(
                        node_id = %&node_id[..8.min(node_id.len())],
                        "Node not eligible for elder status: missing or invalid proof-of-work"
                    );
                }

                Ok((is_elder, elder_order))
            })();

            // Commit or rollback based on result
            match &result {
                Ok(_) => {
                    conn.execute("COMMIT", [])
                        .map_err(|e| GhostError::Database(format!("Failed to commit: {}", e)))?;
                }
                Err(_) => {
                    let _ = conn.execute("ROLLBACK", []);
                }
            }

            result
        })
    }

    /// Get elder status for a node (queries database)
    /// Returns (is_elder, elder_order)
    pub fn get_node_elder_status(&self, node_id: &str) -> GhostResult<(bool, Option<u32>)> {
        self.with_connection(|conn| {
            let result: Option<(bool, Option<u32>)> = conn
                .query_row(
                    "SELECT is_elder, elder_order FROM nodes WHERE node_id = ?1",
                    [node_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result.unwrap_or((false, None)))
        })
    }

    // =========================================================================
    // ELDER REVOCATION (Offline >7 days → BFT vote → burned slot)
    // =========================================================================

    /// Record a burned elder position after successful revocation vote
    pub fn burn_elder_position(
        &self,
        position: u32,
        node_id: &str,
        reason: &str,
    ) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO burned_elder_numbers (elder_position, revoked_node_id, reason, revoked_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![position, node_id, reason, now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            tracing::warn!(
                position,
                node_id = %&node_id[..8.min(node_id.len())],
                reason,
                "Elder position burned (revoked)"
            );
            Ok(())
        })
    }

    /// Check if an elder position has been burned
    pub fn is_position_burned(&self, position: u32) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM burned_elder_numbers WHERE elder_position = ?1)",
                    [position],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(exists)
        })
    }

    /// Get all burned elder positions
    pub fn get_burned_positions(&self) -> GhostResult<Vec<(u32, String, String, i64)>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT elder_position, revoked_node_id, reason, revoked_at
                     FROM burned_elder_numbers ORDER BY elder_position ASC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut results = Vec::new();
            for row in rows {
                results.push(row.map_err(|e| GhostError::Database(e.to_string()))?);
            }
            Ok(results)
        })
    }

    /// Remove an elder from mpc_contributions after revocation.
    /// Returns the position that was revoked, or None if not found.
    pub fn revoke_mpc_elder(&self, node_id: &str) -> GhostResult<Option<u32>> {
        self.with_connection(|conn| {
            let position: Option<i64> = conn
                .query_row(
                    "SELECT elder_position FROM mpc_contributions WHERE contributor_node_id = ?1",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if let Some(pos) = position {
                conn.execute(
                    "DELETE FROM mpc_contributions WHERE contributor_node_id = ?1",
                    [node_id],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                tracing::warn!(
                    node_id = %&node_id[..8.min(node_id.len())],
                    position = pos,
                    "Revoked MPC elder from contributions"
                );
                Ok(Some(pos as u32))
            } else {
                Ok(None)
            }
        })
    }

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
                     FROM shares
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

    /// GHOST-02 / Option A: adopt a miner's payout address from a GHOST-09-signed
    /// share proof, FIRST-WRITER-WINS. The address is set only if the miner has
    /// none yet; an established address is never overwritten by a later (possibly
    /// conflicting) signed proof. This is what lets payout addresses converge
    /// across nodes — so validators can reproduce the proposer's address-grouped
    /// split (GHOST-02) — without reintroducing the M-06 address-hijack vector.
    pub fn adopt_miner_address(&self, miner_id: &str, payout_address: &str) -> GhostResult<()> {
        if payout_address.is_empty() {
            return Ok(());
        }
        let now = chrono::Utc::now().timestamp();
        let encrypted_address = self.encrypt_address(payout_address)?;
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO miners (miner_id, payout_address, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(miner_id) DO UPDATE SET
                     payout_address = CASE
                         WHEN miners.payout_address IS NULL OR miners.payout_address = ''
                         THEN excluded.payout_address
                         ELSE miners.payout_address
                     END,
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

    /// Increment miner's blocks_won counter
    pub fn increment_miner_blocks_won(&self, miner_id: &str) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE miners SET blocks_won = blocks_won + 1, last_seen = ?1 WHERE miner_id = ?2",
                params![chrono::Utc::now().timestamp(), miner_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get node's payout address by ID
    ///
    /// P-4: Decrypts the address if encryption is configured.
    pub fn get_node_payout_address(&self, node_id: &str) -> GhostResult<Option<String>> {
        let stored: Option<String> = self
            .with_connection(|conn| {
                conn.query_row(
                    "SELECT payout_address FROM nodes WHERE node_id = ?1",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))
            })?
            .flatten();
        // P-4: Decrypt the address if present
        match stored {
            Some(addr) if !addr.is_empty() => Ok(Some(self.decrypt_address(&addr)?)),
            other => Ok(other),
        }
    }

    /// Update node's payout address
    ///
    /// P-4: Encrypts the address before storing if encryption is configured.
    pub fn update_node_payout_address(
        &self,
        node_id: &str,
        payout_address: &str,
    ) -> GhostResult<()> {
        // P-4: Encrypt the address before storing
        let encrypted_address = self.encrypt_address(payout_address)?;
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE nodes SET payout_address = ?1 WHERE node_id = ?2",
                params![encrypted_address, node_id],
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

impl Database {
    /// Get or create node reward entry
    ///
    /// 4.18 SECURITY: Uses INSERT OR IGNORE to prevent race conditions when
    /// multiple concurrent calls try to create the same entry.
    pub fn get_or_create_node_reward(&self, node_id: &str) -> GhostResult<NodeRewardEntry> {
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            // 4.18: Try to insert first with IGNORE to handle race conditions
            // If entry already exists, this does nothing
            conn.execute(
                "INSERT OR IGNORE INTO node_rewards (node_id, balance_sats, created_at, updated_at)
                 VALUES (?1, 0, ?2, ?2)",
                params![node_id, now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Now we can safely SELECT - the entry definitely exists
            let mut stmt = conn
                .prepare(
                    "SELECT node_id, balance_sats, last_credited_round, total_credits_sats,
                            total_withdrawals_sats, created_at, updated_at
                     FROM node_rewards WHERE node_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let entry = stmt
                .query_row([node_id], |row| {
                    Ok(NodeRewardEntry {
                        node_id: row.get(0)?,
                        balance_sats: row.get(1)?,
                        last_credited_round: row.get(2)?,
                        total_credits_sats: row.get(3)?,
                        total_withdrawals_sats: row.get(4)?,
                        created_at: row.get(5)?,
                        updated_at: row.get(6)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(entry)
        })
    }

    /// Credit node reward
    ///
    /// DB-H2: Uses explicit transaction for atomicity and validates the node exists.
    /// H-DB-3 FIX: Uses transaction_retry for automatic retry on transient errors
    /// (e.g., SQLITE_BUSY), while still properly failing on "node not found".
    ///
    /// Returns error if the node doesn't exist in node_rewards table.
    pub fn credit_node_reward(&self, node_id: &str, amount: u64, round_id: u64) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        let node_id_owned = node_id.to_string();

        // H-DB-3 FIX: Use transaction_retry for automatic retry on transient errors
        self.transaction_retry("credit_node_reward", |tx| {
            let rows_affected = tx
                .execute(
                    "UPDATE node_rewards SET
                        balance_sats = balance_sats + ?1,
                        last_credited_round = ?2,
                        total_credits_sats = total_credits_sats + ?1,
                        updated_at = ?3
                     WHERE node_id = ?4",
                    params![amount, round_id, now, &node_id_owned],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if rows_affected == 0 {
                // Node doesn't exist - this is a non-retryable error
                // The transaction will be rolled back by the Drop impl
                return Err(GhostError::RecordNotFound {
                    table: "node_rewards".to_string(),
                    key: node_id_owned.clone(),
                });
            }

            Ok(())
        })
    }

    /// Get nodes with balance above threshold
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_nodes_with_balance(&self, min_balance: u64) -> GhostResult<Vec<NodeRewardEntry>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT node_id, balance_sats, last_credited_round, total_credits_sats,
                            total_withdrawals_sats, created_at, updated_at
                     FROM node_rewards WHERE balance_sats >= ?1 ORDER BY balance_sats DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let entries = stmt
                .query_map(params![min_balance, Self::MAX_QUERY_RESULTS], |row| {
                    Ok(NodeRewardEntry {
                        node_id: row.get(0)?,
                        balance_sats: row.get(1)?,
                        last_credited_round: row.get(2)?,
                        total_credits_sats: row.get(3)?,
                        total_withdrawals_sats: row.get(4)?,
                        created_at: row.get(5)?,
                        updated_at: row.get(6)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(entries)
        })
    }
}

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
// GHOST LOCK QUERIES
// =============================================================================

impl Database {
    /// Insert a new Ghost Lock
    pub fn insert_ghost_lock(&self, lock: &GhostLockRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO ghost_locks (
                    lock_id, owner_ghost_id, lock_pubkey, recovery_pubkey,
                    denomination, amount_sats, timelock_tier, creation_height,
                    recovery_height, state, funding_txid, funding_vout,
                    spend_txid, output_script, jump_risk_tier, next_jump_height,
                    created_at, updated_at, source, wraith_fee_sats, key_index
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
                params![
                    lock.lock_id,
                    lock.owner_ghost_id,
                    lock.lock_pubkey,
                    lock.recovery_pubkey,
                    lock.denomination,
                    lock.amount_sats,
                    lock.timelock_tier,
                    lock.creation_height,
                    lock.recovery_height,
                    lock.state.as_str(),
                    lock.funding_txid,
                    lock.funding_vout,
                    lock.spend_txid,
                    lock.output_script,
                    lock.jump_risk_tier,
                    lock.next_jump_height,
                    lock.created_at,
                    lock.updated_at,
                    lock.source,
                    lock.wraith_fee_sats,
                    lock.key_index,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a Ghost Lock by ID
    pub fn get_ghost_lock(&self, lock_id: &str) -> GhostResult<Option<GhostLockRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT lock_id, owner_ghost_id, lock_pubkey, recovery_pubkey,
                            denomination, amount_sats, timelock_tier, creation_height,
                            recovery_height, state, funding_txid, funding_vout,
                            spend_txid, output_script, jump_risk_tier, next_jump_height,
                            created_at, updated_at, source, wraith_fee_sats, key_index
                     FROM ghost_locks WHERE lock_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let lock = stmt
                .query_row([lock_id], ghost_lock_from_row)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(lock)
        })
    }

    /// Get all Ghost Locks for an owner
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_ghost_locks_by_owner(
        &self,
        owner_ghost_id: &str,
    ) -> GhostResult<Vec<GhostLockRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT lock_id, owner_ghost_id, lock_pubkey, recovery_pubkey,
                            denomination, amount_sats, timelock_tier, creation_height,
                            recovery_height, state, funding_txid, funding_vout,
                            spend_txid, output_script, jump_risk_tier, next_jump_height,
                            created_at, updated_at, source, wraith_fee_sats, key_index
                     FROM ghost_locks WHERE owner_ghost_id = ?1 ORDER BY created_at DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let locks = stmt
                .query_map(
                    params![owner_ghost_id, Self::MAX_QUERY_RESULTS],
                    ghost_lock_from_row,
                )
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(locks)
        })
    }

    /// Get active Ghost Locks for an owner
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_active_ghost_locks(
        &self,
        owner_ghost_id: &str,
    ) -> GhostResult<Vec<GhostLockRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT lock_id, owner_ghost_id, lock_pubkey, recovery_pubkey,
                            denomination, amount_sats, timelock_tier, creation_height,
                            recovery_height, state, funding_txid, funding_vout,
                            spend_txid, output_script, jump_risk_tier, next_jump_height,
                            created_at, updated_at, source, wraith_fee_sats, key_index
                     FROM ghost_locks
                     WHERE owner_ghost_id = ?1 AND state = 'active'
                     ORDER BY created_at DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let locks = stmt
                .query_map(
                    params![owner_ghost_id, Self::MAX_QUERY_RESULTS],
                    ghost_lock_from_row,
                )
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(locks)
        })
    }

    /// Get Ghost Locks that need to jump by a certain height
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_locks_needing_jump(&self, current_height: u32) -> GhostResult<Vec<GhostLockRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT lock_id, owner_ghost_id, lock_pubkey, recovery_pubkey,
                            denomination, amount_sats, timelock_tier, creation_height,
                            recovery_height, state, funding_txid, funding_vout,
                            spend_txid, output_script, jump_risk_tier, next_jump_height,
                            created_at, updated_at, source, wraith_fee_sats, key_index
                     FROM ghost_locks
                     WHERE state = 'active' AND next_jump_height IS NOT NULL AND next_jump_height <= ?1
                     ORDER BY next_jump_height ASC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let locks = stmt
                .query_map(params![current_height, Self::MAX_QUERY_RESULTS], ghost_lock_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(locks)
        })
    }

    /// Update Ghost Lock state
    pub fn update_ghost_lock_state(&self, lock_id: &str, state: GhostLockState) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE ghost_locks SET state = ?1, updated_at = ?2 WHERE lock_id = ?3",
                params![state.as_str(), now, lock_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get the derivation index for a lock (count of locks created before it by the same owner).
    ///
    /// This corresponds to the key derivation index used in `GhostKeys::derive_lock_secret()`.
    /// Locks are created sequentially, so the creation order matches the derivation order.
    pub fn get_lock_index_for_owner(
        &self,
        owner_ghost_id: &str,
        lock_id: &str,
    ) -> GhostResult<u32> {
        self.with_connection(|conn| {
            // Prefer stored key_index (stable across lock insertions/deletions)
            let stored: Option<i64> = conn
                .query_row(
                    "SELECT key_index FROM ghost_locks WHERE lock_id = ?1",
                    [lock_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
                .flatten();

            if let Some(idx) = stored {
                return Ok(idx as u32);
            }

            // Fallback: compute dynamically (for locks created before v34 migration)
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM ghost_locks \
                     WHERE owner_ghost_id = ?1 \
                     AND created_at < (SELECT created_at FROM ghost_locks WHERE lock_id = ?2)",
                    params![owner_ghost_id, lock_id],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u32)
        })
    }

    /// Get the next available key_index for lock derivation.
    ///
    /// Returns `MAX(key_index) + 1` from all locks owned by this ghost_id,
    /// or 0 if no locks exist. This is stable across restarts — unlike
    /// the in-memory `ghost_locks.len()` which resets to 0.
    pub fn get_next_lock_key_index(&self, owner_ghost_id: &str) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let max_index: Option<i64> = conn
                .query_row(
                    "SELECT MAX(key_index) FROM ghost_locks WHERE owner_ghost_id = ?1",
                    [owner_ghost_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
                .flatten();

            Ok(max_index.map(|i| (i + 1) as u32).unwrap_or(0))
        })
    }

    /// Update Ghost Lock funding info
    pub fn update_ghost_lock_funding(
        &self,
        lock_id: &str,
        txid: &str,
        vout: u32,
    ) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE ghost_locks SET
                    funding_txid = ?1, funding_vout = ?2, state = 'active', updated_at = ?3
                 WHERE lock_id = ?4",
                params![txid, vout, now, lock_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update Ghost Lock spend info
    pub fn update_ghost_lock_spent(&self, lock_id: &str, spend_txid: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE ghost_locks SET
                    spend_txid = ?1, state = 'spent', updated_at = ?2
                 WHERE lock_id = ?3",
                params![spend_txid, now, lock_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update Ghost Lock next jump height
    pub fn update_ghost_lock_jump_height(
        &self,
        lock_id: &str,
        next_jump_height: u32,
    ) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE ghost_locks SET next_jump_height = ?1, updated_at = ?2 WHERE lock_id = ?3",
                params![next_jump_height, now, lock_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get total balance in active Ghost Locks for an owner
    pub fn get_ghost_lock_balance(&self, owner_ghost_id: &str) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let balance: u64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(amount_sats), 0) FROM ghost_locks
                     WHERE owner_ghost_id = ?1 AND state = 'active'",
                    [owner_ghost_id],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(balance)
        })
    }
}

fn ghost_lock_from_row(row: &rusqlite::Row) -> rusqlite::Result<GhostLockRecord> {
    let state_str: String = row.get(9)?;
    Ok(GhostLockRecord {
        lock_id: row.get(0)?,
        owner_ghost_id: row.get(1)?,
        lock_pubkey: row.get(2)?,
        recovery_pubkey: row.get(3)?,
        denomination: row.get(4)?,
        amount_sats: row.get(5)?,
        timelock_tier: row.get(6)?,
        creation_height: row.get(7)?,
        recovery_height: row.get(8)?,
        state: parse_ghost_lock_state_strict(&state_str, "ghost_lock_from_row")?,
        funding_txid: row.get(10)?,
        funding_vout: row.get(11)?,
        spend_txid: row.get(12)?,
        output_script: row.get(13)?,
        jump_risk_tier: row.get(14)?,
        next_jump_height: row.get(15)?,
        created_at: row.get(16)?,
        updated_at: row.get(17)?,
        source: row.get(18)?,
        wraith_fee_sats: row.get(19)?,
        key_index: row.get(20).ok(),
    })
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

    /// Ban a peer
    pub fn ban_peer(&self, peer_id: &str, ban_until: i64) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE peers SET is_banned = 1, ban_until = ?1 WHERE peer_id = ?2",
                params![ban_until, peer_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
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

// =============================================================================
// WRAITH ROUND QUERIES
// =============================================================================

impl Database {
    /// Insert a new Wraith round
    pub fn insert_wraith_round(&self, round: &WraithRoundRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO wraith_rounds (
                    round_id, coordinator_id, denomination, amount_sats, phase,
                    participant_count, min_participants, max_participants,
                    registration_deadline, execution_deadline, split_txid, merge_txid,
                    status, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    round.round_id,
                    round.coordinator_id,
                    round.denomination,
                    round.amount_sats,
                    round.phase.as_str(),
                    round.participant_count,
                    round.min_participants,
                    round.max_participants,
                    round.registration_deadline,
                    round.execution_deadline,
                    round.split_txid,
                    round.merge_txid,
                    round.status.as_str(),
                    round.created_at,
                    round.updated_at,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a Wraith round by ID
    pub fn get_wraith_round(&self, round_id: &str) -> GhostResult<Option<WraithRoundRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT round_id, coordinator_id, denomination, amount_sats, phase,
                            participant_count, min_participants, max_participants,
                            registration_deadline, execution_deadline, split_txid, merge_txid,
                            status, created_at, updated_at
                     FROM wraith_rounds WHERE round_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let round = stmt
                .query_row([round_id], wraith_round_from_row)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(round)
        })
    }

    /// Get active Wraith rounds
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_active_wraith_rounds(&self) -> GhostResult<Vec<WraithRoundRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT round_id, coordinator_id, denomination, amount_sats, phase,
                            participant_count, min_participants, max_participants,
                            registration_deadline, execution_deadline, split_txid, merge_txid,
                            status, created_at, updated_at
                     FROM wraith_rounds WHERE status = 'active'
                     ORDER BY registration_deadline ASC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rounds = stmt
                .query_map([Self::MAX_QUERY_RESULTS], wraith_round_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(rounds)
        })
    }

    /// Update Wraith round phase
    pub fn update_wraith_round_phase(&self, round_id: &str, phase: WraithPhase) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE wraith_rounds SET phase = ?1, updated_at = ?2 WHERE round_id = ?3",
                params![phase.as_str(), now, round_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update Wraith round status
    pub fn update_wraith_round_status(
        &self,
        round_id: &str,
        status: WraithStatus,
    ) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE wraith_rounds SET status = ?1, updated_at = ?2 WHERE round_id = ?3",
                params![status.as_str(), now, round_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

fn wraith_round_from_row(row: &rusqlite::Row) -> rusqlite::Result<WraithRoundRecord> {
    let phase_str: String = row.get(4)?;
    let status_str: String = row.get(12)?;
    Ok(WraithRoundRecord {
        round_id: row.get(0)?,
        coordinator_id: row.get(1)?,
        denomination: row.get(2)?,
        amount_sats: row.get(3)?,
        phase: parse_wraith_phase_strict(&phase_str, "wraith_round_from_row")?,
        participant_count: row.get(5)?,
        min_participants: row.get(6)?,
        max_participants: row.get(7)?,
        registration_deadline: row.get(8)?,
        execution_deadline: row.get(9)?,
        split_txid: row.get(10)?,
        merge_txid: row.get(11)?,
        status: parse_wraith_status_strict(&status_str, "wraith_round_from_row")?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
    })
}

// =============================================================================
// RECONCILIATION QUERIES
// =============================================================================

impl Database {
    /// Insert a reconciliation batch
    pub fn insert_reconciliation_batch(&self, batch: &ReconciliationRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO reconciliation_state (
                    batch_id, settlement_class, participant_count, total_amount_sats,
                    merkle_root, l1_txid, l1_block_height, dispute_deadline,
                    status, created_at, finalized_at, l2_node_rewards_sats
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    batch.batch_id,
                    batch.settlement_class,
                    batch.participant_count,
                    batch.total_amount_sats,
                    batch.merkle_root,
                    batch.l1_txid,
                    batch.l1_block_height,
                    batch.dispute_deadline,
                    batch.status.as_str(),
                    batch.created_at,
                    batch.finalized_at,
                    batch.l2_node_rewards_sats,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get a reconciliation batch by ID
    pub fn get_reconciliation_batch(
        &self,
        batch_id: &str,
    ) -> GhostResult<Option<ReconciliationRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT batch_id, settlement_class, participant_count, total_amount_sats,
                            merkle_root, l1_txid, l1_block_height, dispute_deadline,
                            status, created_at, finalized_at, l2_node_rewards_sats
                     FROM reconciliation_state WHERE batch_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let batch = stmt
                .query_row([batch_id], reconciliation_from_row)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(batch)
        })
    }

    /// Get pending reconciliation batches
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_pending_reconciliation_batches(&self) -> GhostResult<Vec<ReconciliationRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT batch_id, settlement_class, participant_count, total_amount_sats,
                            merkle_root, l1_txid, l1_block_height, dispute_deadline,
                            status, created_at, finalized_at, l2_node_rewards_sats
                     FROM reconciliation_state WHERE status IN ('pending', 'submitted')
                     ORDER BY created_at ASC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let batches = stmt
                .query_map([Self::MAX_QUERY_RESULTS], reconciliation_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(batches)
        })
    }

    /// Update reconciliation batch L1 submission
    pub fn update_reconciliation_l1_submitted(
        &self,
        batch_id: &str,
        txid: &str,
        block_height: u64,
        dispute_deadline: u64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE reconciliation_state SET
                    l1_txid = ?1, l1_block_height = ?2, dispute_deadline = ?3, status = 'submitted'
                 WHERE batch_id = ?4",
                params![txid, block_height, dispute_deadline, batch_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Finalize reconciliation batch
    pub fn finalize_reconciliation_batch(&self, batch_id: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE reconciliation_state SET status = 'finalized', finalized_at = ?1 WHERE batch_id = ?2",
                params![now, batch_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }
}

fn reconciliation_from_row(row: &rusqlite::Row) -> rusqlite::Result<ReconciliationRecord> {
    let status_str: String = row.get(8)?;
    Ok(ReconciliationRecord {
        batch_id: row.get(0)?,
        settlement_class: row.get(1)?,
        participant_count: row.get(2)?,
        total_amount_sats: row.get(3)?,
        merkle_root: row.get(4)?,
        l1_txid: row.get(5)?,
        l1_block_height: row.get(6)?,
        dispute_deadline: row.get(7)?,
        status: parse_reconciliation_status_strict(&status_str, "reconciliation_from_row")?,
        created_at: row.get(9)?,
        finalized_at: row.get(10)?,
        // Column 11 = l2_node_rewards_sats, added in v36. Callers that
        // still project 11 columns (older SELECTs) get a default 0 via
        // the optional column read.
        l2_node_rewards_sats: row.get::<_, i64>(11).unwrap_or(0) as u64,
    })
}

// =============================================================================
// WITHDRAWAL REQUEST QUERIES
// =============================================================================

impl Database {
    /// Insert a new withdrawal request
    pub fn insert_withdrawal_request(&self, request: &WithdrawalRequest) -> GhostResult<i64> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO withdrawal_requests (
                    ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                    status, batch_id, l1_txid, settlement_class, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    request.ghost_id,
                    request.lock_id,
                    request.destination_address,
                    request.amount_sats,
                    request.fee_sats,
                    request.status.as_str(),
                    request.batch_id,
                    request.l1_txid,
                    request.settlement_class,
                    request.created_at,
                    request.updated_at,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid())
        })
    }

    /// Atomically insert a withdrawal request if no pending/batched withdrawal exists for the lock
    ///
    /// This prevents double-spend race conditions (C-PAY-3) by:
    /// 1. Using a transaction to ensure atomicity
    /// 2. Checking for existing pending/batched withdrawals within the transaction
    /// 3. Relying solely on the database partial unique index for atomicity
    ///
    /// DB-C3: Removed application-level check to eliminate TOCTOU race window.
    /// The partial unique index `idx_withdrawals_pending_lock` on (lock_id)
    /// WHERE status IN ('pending', 'batched') enforces the constraint atomically.
    ///
    /// Returns:
    /// - Ok(Some(id)) - Successfully inserted, returns the new withdrawal ID
    /// - Ok(None) - A pending/batched withdrawal already exists for this lock
    /// - Err(_) - Database error
    pub fn insert_withdrawal_request_atomic(
        &self,
        request: &WithdrawalRequest,
    ) -> GhostResult<Option<i64>> {
        self.with_connection(|conn| {
            // DB-C3: Directly attempt INSERT and rely on unique constraint
            // The partial unique index ensures atomic double-spend prevention
            // without the TOCTOU race window of check-then-insert
            let result = conn.execute(
                "INSERT INTO withdrawal_requests (
                    ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                    status, batch_id, l1_txid, settlement_class, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    request.ghost_id,
                    request.lock_id,
                    request.destination_address,
                    request.amount_sats,
                    request.fee_sats,
                    request.status.as_str(),
                    request.batch_id,
                    request.l1_txid,
                    request.settlement_class,
                    request.created_at,
                    request.updated_at,
                ],
            );

            match result {
                Ok(_) => Ok(Some(conn.last_insert_rowid())),
                Err(e) => {
                    // Check if this is a unique constraint violation
                    // This means a pending/batched withdrawal already exists for this lock
                    let err_str = e.to_string();
                    if err_str.contains("UNIQUE constraint failed")
                        || err_str.contains("idx_withdrawals_pending_lock")
                    {
                        // Duplicate withdrawal attempt - return None (not an error)
                        tracing::debug!(
                            lock_id = %request.lock_id,
                            "Withdrawal request rejected: pending/batched withdrawal exists"
                        );
                        Ok(None)
                    } else {
                        Err(GhostError::Database(err_str))
                    }
                }
            }
        })
    }

    /// Get a withdrawal request by ID
    pub fn get_withdrawal_request(&self, id: i64) -> GhostResult<Option<WithdrawalRequest>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                            status, batch_id, l1_txid, settlement_class, created_at, updated_at
                     FROM withdrawal_requests WHERE id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let request = stmt
                .query_row([id], withdrawal_from_row)
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(request)
        })
    }

    /// Get pending withdrawal requests for a ghost_id
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_pending_withdrawals(&self, ghost_id: &str) -> GhostResult<Vec<WithdrawalRequest>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                            status, batch_id, l1_txid, settlement_class, created_at, updated_at
                     FROM withdrawal_requests
                     WHERE ghost_id = ?1 AND status = 'pending'
                     ORDER BY created_at ASC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let requests = stmt
                .query_map(
                    params![ghost_id, Self::MAX_QUERY_RESULTS],
                    withdrawal_from_row,
                )
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(requests)
        })
    }

    /// Get all pending withdrawal requests (for batch processing)
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_all_pending_withdrawals(&self) -> GhostResult<Vec<WithdrawalRequest>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                            status, batch_id, l1_txid, settlement_class, created_at, updated_at
                     FROM withdrawal_requests
                     WHERE status = 'pending'
                     ORDER BY created_at ASC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let requests = stmt
                .query_map([Self::MAX_QUERY_RESULTS], withdrawal_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(requests)
        })
    }

    /// Get withdrawal requests by lock ID
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_withdrawals_by_lock(&self, lock_id: &str) -> GhostResult<Vec<WithdrawalRequest>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                            status, batch_id, l1_txid, settlement_class, created_at, updated_at
                     FROM withdrawal_requests
                     WHERE lock_id = ?1
                     ORDER BY created_at DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let requests = stmt
                .query_map(
                    params![lock_id, Self::MAX_QUERY_RESULTS],
                    withdrawal_from_row,
                )
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(requests)
        })
    }

    /// Get pending withdrawals filtered by settlement class
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_pending_withdrawals_by_class(
        &self,
        settlement_class: &str,
    ) -> GhostResult<Vec<WithdrawalRequest>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                            status, batch_id, l1_txid, settlement_class, created_at, updated_at
                     FROM withdrawal_requests
                     WHERE status = 'pending' AND settlement_class = ?1
                     ORDER BY created_at ASC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let requests = stmt
                .query_map(
                    params![settlement_class, Self::MAX_QUERY_RESULTS],
                    withdrawal_from_row,
                )
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(requests)
        })
    }

    /// Get submitted-but-unconfirmed withdrawals (for confirmation monitoring)
    ///
    /// Returns withdrawals that have been broadcast to L1 but not yet confirmed.
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_submitted_withdrawals(&self) -> GhostResult<Vec<WithdrawalRequest>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, ghost_id, lock_id, destination_address, amount_sats, fee_sats,
                            status, batch_id, l1_txid, settlement_class, created_at, updated_at
                     FROM withdrawal_requests
                     WHERE status = 'submitted'
                     ORDER BY updated_at ASC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let requests = stmt
                .query_map([Self::MAX_QUERY_RESULTS], withdrawal_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(requests)
        })
    }

    /// Update withdrawal request status
    pub fn update_withdrawal_status(&self, id: i64, status: WithdrawalStatus) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE withdrawal_requests SET status = ?1, updated_at = ?2 WHERE id = ?3",
                params![status.as_str(), now, id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update withdrawal request with batch info
    ///
    /// Validates status transition: only pending withdrawals can be batched.
    /// Returns error if the withdrawal is not in 'pending' status.
    pub fn update_withdrawal_batched(&self, id: i64, batch_id: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            let updated = conn.execute(
                "UPDATE withdrawal_requests SET status = 'batched', batch_id = ?1, updated_at = ?2
                 WHERE id = ?3 AND status = 'pending'",
                params![batch_id, now, id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            if updated == 0 {
                return Err(GhostError::InvalidState(format!(
                    "Cannot batch withdrawal {}: not in 'pending' status or does not exist",
                    id
                )));
            }
            Ok(())
        })
    }

    /// Update withdrawal request with L1 txid
    ///
    /// Validates status transition: only batched withdrawals can be submitted.
    /// Returns error if the withdrawal is not in 'batched' status.
    pub fn update_withdrawal_submitted(&self, id: i64, l1_txid: &str) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            let updated = conn.execute(
                "UPDATE withdrawal_requests SET status = 'submitted', l1_txid = ?1, updated_at = ?2
                 WHERE id = ?3 AND status = 'batched'",
                params![l1_txid, now, id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            if updated == 0 {
                return Err(GhostError::InvalidState(format!(
                    "Cannot submit withdrawal {}: not in 'batched' status or does not exist",
                    id
                )));
            }
            Ok(())
        })
    }

    /// Mark withdrawal as confirmed
    ///
    /// Validates status transition: only submitted withdrawals can be confirmed.
    /// Returns error if the withdrawal is not in 'submitted' status.
    pub fn update_withdrawal_confirmed(&self, id: i64) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            let updated = conn
                .execute(
                    "UPDATE withdrawal_requests SET status = 'confirmed', updated_at = ?1
                 WHERE id = ?2 AND status = 'submitted'",
                    params![now, id],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if updated == 0 {
                return Err(GhostError::InvalidState(format!(
                    "Cannot confirm withdrawal {}: not in 'submitted' status or does not exist",
                    id
                )));
            }
            Ok(())
        })
    }

    /// Cancel a pending withdrawal
    ///
    /// Validates status transition: only pending withdrawals can be cancelled.
    /// Returns error if the withdrawal is not in 'pending' status.
    pub fn cancel_withdrawal(&self, id: i64) -> GhostResult<()> {
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            let updated = conn
                .execute(
                    "UPDATE withdrawal_requests SET status = 'cancelled', updated_at = ?1
                 WHERE id = ?2 AND status = 'pending'",
                    params![now, id],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if updated == 0 {
                return Err(GhostError::InvalidState(format!(
                    "Cannot cancel withdrawal {}: not in 'pending' status or does not exist",
                    id
                )));
            }
            Ok(())
        })
    }

    // ========================================================================
    // Verification API Queries
    // ========================================================================

    /// Get recent shares across all rounds (for verification API)
    pub fn get_recent_shares(&self, limit: u32) -> GhostResult<Vec<ShareRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid
                     FROM shares ORDER BY timestamp DESC LIMIT ?1",
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

    /// Get payouts for a specific round
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_payouts_by_round(&self, round_id: u64) -> GhostResult<Vec<PayoutRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, recipient_id, recipient_type, address, amount_sats,
                            txid, vout, status, created_at, confirmed_at
                     FROM payouts WHERE round_id = ?1 ORDER BY created_at DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let payouts = stmt
                .query_map(params![round_id, Self::MAX_QUERY_RESULTS], payout_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(payouts)
        })
    }

    /// Get recent payouts across all rounds
    pub fn get_recent_payouts(&self, limit: u32) -> GhostResult<Vec<PayoutRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, round_id, recipient_id, recipient_type, address, amount_sats,
                            txid, vout, status, created_at, confirmed_at
                     FROM payouts ORDER BY created_at DESC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let payouts = stmt
                .query_map([limit], payout_from_row)
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(payouts)
        })
    }

    /// Insert a payout record
    pub fn insert_payout(&self, payout: &PayoutRecord) -> GhostResult<i64> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO payouts (round_id, recipient_id, recipient_type, address, amount_sats,
                                     txid, vout, status, created_at, confirmed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    payout.round_id,
                    payout.recipient_id,
                    payout.recipient_type.as_str(),
                    payout.address,
                    payout.amount_sats,
                    payout.txid,
                    payout.vout,
                    payout.status.as_str(),
                    payout.created_at,
                    payout.confirmed_at,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Get total payout count
    pub fn get_payout_count(&self) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM payouts", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;
            // 4.19 SECURITY: Use safe conversion to detect database corruption
            i64_to_u64(count, "payout_count").map_err(|e| GhostError::Database(e.to_string()))
        })
    }

    /// Query paginated payout history
    ///
    /// Returns round payout summaries ordered by block height descending.
    /// Results are grouped by round and include aggregated payout information.
    ///
    /// The query joins the rounds and payouts tables to provide a complete
    /// picture of each round's payout distribution.
    pub fn query_payout_history(
        &self,
        query: PayoutHistoryQuery,
    ) -> GhostResult<Vec<RoundPayoutSummary>> {
        self.with_connection(|conn| {
            // Build the SQL query with optional height filters
            // We join rounds with payouts to get complete information
            // and aggregate payout counts and amounts by recipient type
            let sql = "
                SELECT
                    r.round_id,
                    r.block_height,
                    r.block_hash,
                    COALESCE(SUM(CASE WHEN p.recipient_type = 'miner' THEN 1 ELSE 0 END), 0) as miner_count,
                    COALESCE(SUM(CASE WHEN p.recipient_type = 'node' OR p.recipient_type = 'tx_fees' THEN 1 ELSE 0 END), 0) as node_count,
                    COALESCE(SUM(CASE WHEN p.recipient_type = 'miner' THEN p.amount_sats ELSE 0 END), 0) as total_miner_sats,
                    COALESCE(SUM(CASE WHEN p.recipient_type = 'node' THEN p.amount_sats ELSE 0 END), 0) as total_node_sats,
                    COALESCE(SUM(CASE WHEN p.recipient_type = 'treasury' THEN p.amount_sats ELSE 0 END), 0) as treasury_sats,
                    COALESCE(r.tx_fees_sats, 0) as tx_fees_sats,
                    r.payout_status,
                    COALESCE(MIN(p.created_at), r.start_time) as created_at
                FROM rounds r
                LEFT JOIN payouts p ON r.round_id = p.round_id
                WHERE r.payout_status IN ('pending', 'approved', 'broadcast', 'confirmed')
                    AND (?1 IS NULL OR r.block_height >= ?1)
                    AND (?2 IS NULL OR r.block_height <= ?2)
                GROUP BY r.round_id
                ORDER BY r.block_height DESC
                LIMIT ?3 OFFSET ?4
            ";

            let mut stmt = conn
                .prepare(sql)
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let summaries = stmt
                .query_map(
                    params![
                        query.min_height,
                        query.max_height,
                        query.limit,
                        query.offset
                    ],
                    |row| {
                        // SEC-DATA-3: Use safe conversions to catch database corruption
                        Ok(RoundPayoutSummary {
                            round_id: row.get(0)?,
                            block_height: row.get(1)?,
                            block_hash: row.get(2)?,
                            miner_count: i64_to_u32_count(row.get::<_, i64>(3)?, "miner_count")?,
                            node_count: i64_to_u32_count(row.get::<_, i64>(4)?, "node_count")?,
                            total_miner_sats: i64_to_u64_sats(row.get::<_, i64>(5)?, "total_miner_sats")?,
                            total_node_sats: i64_to_u64_sats(row.get::<_, i64>(6)?, "total_node_sats")?,
                            treasury_sats: i64_to_u64_sats(row.get::<_, i64>(7)?, "treasury_sats")?,
                            tx_fees_sats: i64_to_u64_sats(row.get::<_, i64>(8)?, "tx_fees_sats")?,
                            status: row.get(9)?,
                            created_at: row.get(10)?,
                        })
                    },
                )
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(summaries)
        })
    }

    /// Get total count of rounds with payouts (for pagination metadata)
    pub fn get_payout_round_count(
        &self,
        min_height: Option<u64>,
        max_height: Option<u64>,
    ) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(DISTINCT round_id) FROM rounds
                     WHERE payout_status IN ('pending', 'approved', 'broadcast', 'confirmed')
                       AND (?1 IS NULL OR block_height >= ?1)
                       AND (?2 IS NULL OR block_height <= ?2)",
                    params![min_height, max_height],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            // 4.19 SECURITY: Use safe conversion to detect database corruption
            i64_to_u64(count, "round_count").map_err(|e| GhostError::Database(e.to_string()))
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

    /// Cumulative sats paid into the node reward pool via coinbase
    /// across every block Ghost has ever found. Each approved payout
    /// proposal carries a `node_payouts: Vec<PayoutEntry>` in its
    /// serialized JSON; we deserialize and sum.
    ///
    /// Returns 0 until the pool finds its first block. This number is
    /// the L1 side of "total paid to node reward pool"; L2 Ghost Pay
    /// fees are tracked separately.
    pub fn get_total_node_rewards_paid(&self) -> GhostResult<u64> {
        use ghost_common::types::{PayoutProposal, PayoutType};

        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare("SELECT proposal_json FROM payout_proposals WHERE is_approved = 1")
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut total: u64 = 0;
            for r in rows {
                let json = match r {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "Skipping malformed payout_proposals row");
                        continue;
                    }
                };
                match serde_json::from_str::<PayoutProposal>(&json) {
                    Ok(p) => {
                        for entry in p.node_payouts.iter() {
                            if matches!(entry.payout_type, PayoutType::NodeReward) {
                                total = total.saturating_add(entry.amount);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to deserialize proposal_json");
                    }
                }
            }
            Ok(total)
        })
    }

    pub fn get_blocks_found_count(&self) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(DISTINCT block_height) FROM payout_proposals",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            i64_to_u64(count, "blocks_found").map_err(|e| GhostError::Database(e.to_string()))
        })
    }

    // =========================================================================
    // KEY ROTATION WITH ELDER STATUS TRANSFER
    // =========================================================================

    /// Check if a node_id has been retired (rotated away from)
    ///
    /// Returns the new node_id if the node was rotated, None if still active.
    pub fn is_node_retired(&self, node_id: &str) -> GhostResult<Option<String>> {
        self.with_connection(|conn| {
            let result: Option<String> = conn
                .query_row(
                    "SELECT new_node_id FROM retired_nodes WHERE old_node_id = ?1",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(result)
        })
    }

    /// Check if a rotation proof has been used (prevent replay)
    fn is_rotation_proof_used(
        &self,
        conn: &Connection,
        old_node_id: &str,
        new_node_id: &str,
    ) -> GhostResult<bool> {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM rotation_history
                 WHERE old_node_id = ?1 AND new_node_id = ?2 AND status = 'completed'",
                params![old_node_id, new_node_id],
                |row| row.get(0),
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
        Ok(count > 0)
    }

    /// Transfer elder status from old node_id to new node_id using a rotation proof
    ///
    /// This is the ONLY way to preserve elder status during key rotation.
    ///
    /// Security checks performed:
    /// 1. Rotation proof is cryptographically valid (both signatures)
    /// 2. Old node_id is not already retired
    /// 3. New node_id is not already in use as someone else's identity
    /// 4. The rotation proof hasn't been used before (prevent replay)
    /// 5. The rotation proof is recent (not expired)
    ///
    /// Returns (success, elder_transferred)
    ///
    /// # L-16 Size Limit
    /// The serialized rotation_proof must not exceed MAX_ROTATION_PROOF_SIZE (10 KB).
    /// Returns an error if the proof is too large.
    pub fn transfer_elder_with_rotation(
        &self,
        rotation_proof: &ghost_common::key_rotation::KeyRotationProof,
    ) -> GhostResult<(bool, bool)> {
        // Step 1: Verify the rotation proof cryptographically (includes expiration check)
        rotation_proof.verify().map_err(|e| {
            GhostError::SignatureVerification(format!("Invalid rotation proof: {}", e))
        })?;

        let old_node_id = hex::encode(rotation_proof.old_node_id);
        let new_node_id = hex::encode(rotation_proof.new_node_id);
        let now = chrono::Utc::now().timestamp();
        let proof_bytes = rotation_proof.to_bytes();

        // L-16: Validate rotation proof size before INSERT to prevent storage DoS
        if proof_bytes.len() > MAX_ROTATION_PROOF_SIZE {
            return Err(GhostError::InvalidInput(format!(
                "Rotation proof too large: {} bytes (max {} bytes)",
                proof_bytes.len(),
                MAX_ROTATION_PROOF_SIZE
            )));
        }

        self.with_connection(|conn| {
            // Step 2: Check if old node is already retired
            let already_retired: Option<String> = conn
                .query_row(
                    "SELECT new_node_id FROM retired_nodes WHERE old_node_id = ?1",
                    [&old_node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if already_retired.is_some() {
                return Err(GhostError::SignatureVerification(format!(
                    "Node {} is already retired",
                    &old_node_id[..16]
                )));
            }

            // Step 3: Check if this rotation proof was already used
            if self.is_rotation_proof_used(conn, &old_node_id, &new_node_id)? {
                return Err(GhostError::SignatureVerification(
                    "Rotation proof has already been used".to_string()
                ));
            }

            // Step 4: Check if new_node_id is already in use by someone else
            let existing_new: Option<String> = conn
                .query_row(
                    "SELECT node_id FROM nodes WHERE node_id = ?1 AND rotated_from IS NULL",
                    [&new_node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if existing_new.is_some() {
                // New node_id exists and wasn't from a rotation - could be hijack attempt
                return Err(GhostError::SignatureVerification(format!(
                    "New node_id {} is already registered by another identity",
                    &new_node_id[..16]
                )));
            }

            // Step 5: Start transaction for atomic elder transfer
            conn.execute("BEGIN IMMEDIATE", [])
                .map_err(|e| GhostError::Database(format!("Failed to start transaction: {}", e)))?;

            let result: GhostResult<(bool, bool)> = (|| {
                // Get old node's elder status and other transferable attributes
                let old_node: Option<NodeRotationData> = conn
                    .query_row(
                        "SELECT is_elder, elder_order, pow_proof, capabilities, first_seen
                         FROM nodes WHERE node_id = ?1",
                        [&old_node_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                    )
                    .optional()
                    .map_err(|e| GhostError::Database(e.to_string()))?;

                let (is_elder, elder_order, pow_proof, capabilities, first_seen) = match old_node {
                    Some(data) => data,
                    None => {
                        return Err(GhostError::SignatureVerification(format!(
                            "Old node {} not found in database",
                            &old_node_id[..16]
                        )));
                    }
                };

                // Insert new node (or update if it exists from a previous incomplete rotation)
                conn.execute(
                    "INSERT INTO nodes (node_id, first_seen, last_seen, is_elder, elder_order,
                                       pow_proof, capabilities, rotated_from)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                     ON CONFLICT(node_id) DO UPDATE SET
                         is_elder = excluded.is_elder,
                         elder_order = excluded.elder_order,
                         pow_proof = COALESCE(excluded.pow_proof, pow_proof),
                         capabilities = COALESCE(excluded.capabilities, capabilities),
                         rotated_from = excluded.rotated_from,
                         last_seen = excluded.last_seen",
                    params![
                        &new_node_id,
                        first_seen.unwrap_or(now),  // Preserve original first_seen
                        now,
                        is_elder,
                        elder_order,
                        pow_proof,
                        capabilities,
                        &old_node_id,
                    ],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                // Mark old node as retired (remove elder status)
                conn.execute(
                    "UPDATE nodes SET is_elder = 0, elder_order = NULL, rotated_to = ?1
                     WHERE node_id = ?2",
                    params![&new_node_id, &old_node_id],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                // Add to retired_nodes table (permanent record)
                conn.execute(
                    "INSERT INTO retired_nodes (old_node_id, new_node_id, rotation_timestamp, rotation_proof)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![&old_node_id, &new_node_id, now, &proof_bytes],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                // Add to rotation history
                conn.execute(
                    "INSERT INTO rotation_history (old_node_id, new_node_id, rotation_timestamp,
                                                   finalized_timestamp, status, rotation_proof, elder_transferred)
                     VALUES (?1, ?2, ?3, ?4, 'completed', ?5, ?6)",
                    params![
                        &old_node_id,
                        &new_node_id,
                        rotation_proof.timestamp as i64,
                        now,
                        &proof_bytes,
                        if is_elder { 1 } else { 0 },
                    ],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                Ok((true, is_elder))
            })();

            // Commit or rollback
            match &result {
                Ok(_) => {
                    conn.execute("COMMIT", [])
                        .map_err(|e| GhostError::Database(format!("Failed to commit: {}", e)))?;
                }
                Err(_) => {
                    let _ = conn.execute("ROLLBACK", []);
                }
            }

            result
        })
    }

    /// Get the rotation history for a node (follows the chain of rotations)
    ///
    /// L-12 FIX: Limited to MAX_QUERY_RESULTS total rows (combined from both queries).
    /// Previously each query had its own limit, allowing up to 2x MAX_QUERY_RESULTS total.
    pub fn get_rotation_chain(&self, node_id: &str) -> GhostResult<Vec<(String, String, i64)>> {
        self.with_connection(|conn| {
            // L-12 FIX: Pre-allocate with max capacity to enforce combined limit
            let mut chain = Vec::with_capacity(Self::MAX_QUERY_RESULTS as usize);

            // First, find all rotations FROM this node
            // L-12 FIX: Use full limit for first query
            let mut stmt = conn
                .prepare(
                    "SELECT old_node_id, new_node_id, finalized_timestamp
                     FROM rotation_history
                     WHERE old_node_id = ?1 AND status = 'completed'
                     ORDER BY finalized_timestamp DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rotations = stmt
                .query_map(params![node_id, Self::MAX_QUERY_RESULTS], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            chain.extend(rotations);

            // L-12 FIX: Calculate remaining capacity for second query
            let remaining = (Self::MAX_QUERY_RESULTS as usize).saturating_sub(chain.len());
            if remaining == 0 {
                // Already at limit, skip second query
                return Ok(chain);
            }

            // Also find rotations TO this node (to build full chain)
            // L-12 FIX: Only fetch up to remaining capacity
            let mut stmt = conn
                .prepare(
                    "SELECT old_node_id, new_node_id, finalized_timestamp
                     FROM rotation_history
                     WHERE new_node_id = ?1 AND status = 'completed'
                     ORDER BY finalized_timestamp DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rotations = stmt
                .query_map(params![node_id, remaining as u32], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            chain.extend(rotations);

            Ok(chain)
        })
    }

    /// Store a pending rotation (before finalization)
    /// This allows for grace period revocation
    pub fn store_pending_rotation(
        &self,
        rotation_proof: &ghost_common::key_rotation::KeyRotationProof,
    ) -> GhostResult<i64> {
        let old_node_id = hex::encode(rotation_proof.old_node_id);
        let new_node_id = hex::encode(rotation_proof.new_node_id);
        let proof_bytes = rotation_proof.to_bytes();

        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO rotation_history (old_node_id, new_node_id, rotation_timestamp,
                                               status, rotation_proof, elder_transferred)
                 VALUES (?1, ?2, ?3, 'pending', ?4, 0)",
                params![
                    &old_node_id,
                    &new_node_id,
                    rotation_proof.timestamp as i64,
                    &proof_bytes,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid())
        })
    }

    /// Revoke a pending rotation (during grace period)
    pub fn revoke_pending_rotation(
        &self,
        rotation_id: i64,
        revocation_proof: &ghost_common::key_rotation::RotationRevocation,
    ) -> GhostResult<()> {
        // Serialize revocation proof to JSON
        let revocation_bytes = serde_json::to_vec(revocation_proof)
            .map_err(|e| GhostError::Database(format!("Failed to serialize revocation: {}", e)))?;
        let now = chrono::Utc::now().timestamp();

        self.with_connection(|conn| {
            let rows_affected = conn
                .execute(
                    "UPDATE rotation_history
                     SET status = 'revoked', finalized_timestamp = ?1, revocation_proof = ?2
                     WHERE id = ?3 AND status = 'pending'",
                    params![now, &revocation_bytes, rotation_id],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if rows_affected == 0 {
                return Err(GhostError::Database(
                    "Rotation not found or already finalized".to_string(),
                ));
            }

            Ok(())
        })
    }
}

fn withdrawal_from_row(row: &rusqlite::Row) -> rusqlite::Result<WithdrawalRequest> {
    let status_str: String = row.get(6)?;
    Ok(WithdrawalRequest {
        id: Some(row.get(0)?),
        ghost_id: row.get(1)?,
        lock_id: row.get(2)?,
        destination_address: row.get(3)?,
        amount_sats: row.get(4)?,
        fee_sats: row.get(5)?,
        status: parse_withdrawal_status_strict(&status_str, "withdrawal_from_row")?,
        batch_id: row.get(7)?,
        l1_txid: row.get(8)?,
        settlement_class: row
            .get::<_, String>(9)
            .unwrap_or_else(|_| "standard".to_string()),
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn payout_from_row(row: &rusqlite::Row) -> rusqlite::Result<PayoutRecord> {
    let recipient_type_str: String = row.get(3)?;
    let status_str: String = row.get(8)?;
    Ok(PayoutRecord {
        id: Some(row.get(0)?),
        round_id: row.get(1)?,
        recipient_id: row.get(2)?,
        recipient_type: parse_recipient_type_strict(&recipient_type_str, "payout_from_row")?,
        address: row.get(4)?,
        amount_sats: row.get(5)?,
        txid: row.get(6)?,
        vout: row.get(7)?,
        status: parse_payout_status_strict(&status_str, "payout_from_row")?,
        created_at: row.get(9)?,
        confirmed_at: row.get(10)?,
    })
}

// =============================================================================
// TREASURY STATE QUERIES
// =============================================================================

/// Treasury state storage keys
const TREASURY_BALANCE_KEY: &str = "treasury_balance_sats";
const TREASURY_THRESHOLD_REACHED_KEY: &str = "treasury_threshold_reached_at";
const L2_NODE_REWARDS_PAID_KEY: &str = "l2_node_rewards_paid_sats";

impl Database {
    /// Cumulative sats paid into the node reward pool via L2 Ghost Pay
    /// settlement fees. Incremented atomically by `add_l2_node_rewards_paid`
    /// when a reconciliation batch finalises on L1.
    pub fn get_l2_node_rewards_paid(&self) -> GhostResult<u64> {
        match self.kv_get(L2_NODE_REWARDS_PAID_KEY)? {
            Some(s) => s.parse().map_err(|e| {
                GhostError::Database(format!("Failed to parse L2 node rewards total: {}", e))
            }),
            None => Ok(0),
        }
    }

    /// Atomically add `amount` to the L2 node-rewards-paid running total.
    /// Uses the same SELECT-FOR-UPDATE-style transaction pattern as
    /// `add_treasury_funds` so concurrent settlements don't race.
    pub fn add_l2_node_rewards_paid(&self, amount: u64) -> GhostResult<u64> {
        if amount == 0 {
            return self.get_l2_node_rewards_paid();
        }
        let now = chrono::Utc::now().timestamp();
        self.with_connection(|conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let current: u64 = tx
                .query_row(
                    "SELECT COALESCE(value, '0') FROM kv_store WHERE key = ?1",
                    [L2_NODE_REWARDS_PAID_KEY],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            let new_total = current.saturating_add(amount);

            tx.execute(
                "INSERT INTO kv_store (key, value, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                params![L2_NODE_REWARDS_PAID_KEY, new_total.to_string(), now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            tx.commit()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(new_total)
        })
    }

    /// Get the current treasury balance in satoshis
    pub fn get_treasury_balance(&self) -> GhostResult<u64> {
        match self.kv_get(TREASURY_BALANCE_KEY)? {
            Some(s) => s.parse().map_err(|e| {
                GhostError::Database(format!("Failed to parse treasury balance: {}", e))
            }),
            None => Ok(0),
        }
    }

    /// Set the current treasury balance in satoshis
    pub fn set_treasury_balance(&self, balance: u64) -> GhostResult<()> {
        self.kv_set(TREASURY_BALANCE_KEY, &balance.to_string())
    }

    /// Get the timestamp when treasury threshold was reached (if ever)
    pub fn get_treasury_threshold_reached(&self) -> GhostResult<Option<i64>> {
        match self.kv_get(TREASURY_THRESHOLD_REACHED_KEY)? {
            Some(s) => {
                let ts: i64 = s.parse().map_err(|e| {
                    GhostError::Database(format!(
                        "Failed to parse treasury threshold timestamp: {}",
                        e
                    ))
                })?;
                Ok(Some(ts))
            }
            None => Ok(None),
        }
    }

    /// Set the timestamp when treasury threshold was reached
    pub fn set_treasury_threshold_reached(&self, timestamp: i64) -> GhostResult<()> {
        self.kv_set(TREASURY_THRESHOLD_REACHED_KEY, &timestamp.to_string())
    }

    /// Add funds to treasury and check if threshold was crossed
    /// Returns true if threshold was just crossed
    ///
    /// # M-10: Atomic Treasury Balance Update
    ///
    /// This method uses a transaction to ensure atomic read-modify-write.
    /// Without this, concurrent calls could result in lost updates.
    pub fn add_treasury_funds(&self, amount: u64, threshold: u64) -> GhostResult<bool> {
        let now = chrono::Utc::now().timestamp();

        // M-10: Use transaction for atomic balance update
        self.transaction(|tx| {
            // Read current balance within transaction
            let current: u64 = tx
                .query_row(
                    "SELECT value FROM kv_store WHERE key = ?1",
                    [TREASURY_BALANCE_KEY],
                    |row| {
                        let s: String = row.get(0)?;
                        Ok(s.parse::<u64>().unwrap_or(0))
                    },
                )
                .unwrap_or(0);

            let new_balance = current.saturating_add(amount);

            // Update balance within same transaction
            tx.execute(
                "INSERT INTO kv_store (key, value, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
                params![TREASURY_BALANCE_KEY, new_balance.to_string(), now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Check if we just crossed threshold
            if current < threshold && new_balance >= threshold {
                tx.execute(
                    "INSERT INTO kv_store (key, value, updated_at) VALUES (?1, ?2, ?3)
                     ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
                    params![TREASURY_THRESHOLD_REACHED_KEY, now.to_string(), now],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                tracing::info!(
                    balance = new_balance,
                    threshold,
                    "Treasury threshold reached - decay begins"
                );
                return Ok(true);
            }

            Ok(false)
        })
    }
}

// =============================================================================
// CAPABILITY VERIFICATION CHALLENGES
// =============================================================================

impl Database {
    /// Insert an archive challenge result
    ///
    /// L-3 FIX: Uses INSERT OR REPLACE to enforce rate limiting. The unique index
    /// on (node_id, challenger_id, date(timestamp)) prevents duplicate challenges
    /// from the same challenger for the same node on the same day.
    ///
    /// LOW-STOR-5: Validates all string field sizes before INSERT.
    pub fn insert_archive_challenge(
        &self,
        node_id: &str,
        challenger_id: &str,
        block_height: u64,
        expected_hash: &str,
        response_hash: Option<&str>,
        passed: bool,
    ) -> GhostResult<i64> {
        // LOW-STOR-5: Validate field sizes before INSERT
        if node_id.len() > MAX_CHALLENGE_ID_SIZE {
            return Err(GhostError::InvalidInput(format!(
                "LOW-STOR-5: node_id too large: {} bytes (max {})",
                node_id.len(),
                MAX_CHALLENGE_ID_SIZE
            )));
        }
        if challenger_id.len() > MAX_CHALLENGE_ID_SIZE {
            return Err(GhostError::InvalidInput(format!(
                "LOW-STOR-5: challenger_id too large: {} bytes (max {})",
                challenger_id.len(),
                MAX_CHALLENGE_ID_SIZE
            )));
        }
        if expected_hash.len() > MAX_CHALLENGE_FIELD_SIZE {
            return Err(GhostError::InvalidInput(format!(
                "LOW-STOR-5: expected_hash too large: {} bytes (max {})",
                expected_hash.len(),
                MAX_CHALLENGE_FIELD_SIZE
            )));
        }
        if let Some(hash) = response_hash {
            if hash.len() > MAX_CHALLENGE_FIELD_SIZE {
                return Err(GhostError::InvalidInput(format!(
                    "LOW-STOR-5: response_hash too large: {} bytes (max {})",
                    hash.len(),
                    MAX_CHALLENGE_FIELD_SIZE
                )));
            }
        }

        self.with_connection(|conn| {
            let timestamp = chrono::Utc::now().timestamp();
            // L-3 FIX: INSERT OR REPLACE updates if same (node, challenger, day) exists
            conn.execute(
                "INSERT OR REPLACE INTO archive_challenges
                 (node_id, challenger_id, block_height, expected_hash, response_hash, passed, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    node_id,
                    challenger_id,
                    block_height,
                    expected_hash,
                    response_hash,
                    passed,
                    timestamp,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Insert a policy challenge result
    ///
    /// L-3 FIX: Uses INSERT OR REPLACE to enforce rate limiting. The unique index
    /// on (node_id, challenger_id, date(timestamp)) prevents duplicate challenges
    /// from the same challenger for the same node on the same day.
    ///
    /// LOW-STOR-5: Validates all string field sizes before INSERT.
    pub fn insert_policy_challenge(
        &self,
        node_id: &str,
        challenger_id: &str,
        txid: &str,
        expected_tier: i32,
        response_tier: Option<i32>,
        passed: bool,
    ) -> GhostResult<i64> {
        // LOW-STOR-5: Validate field sizes before INSERT
        if node_id.len() > MAX_CHALLENGE_ID_SIZE {
            return Err(GhostError::InvalidInput(format!(
                "LOW-STOR-5: node_id too large: {} bytes (max {})",
                node_id.len(),
                MAX_CHALLENGE_ID_SIZE
            )));
        }
        if challenger_id.len() > MAX_CHALLENGE_ID_SIZE {
            return Err(GhostError::InvalidInput(format!(
                "LOW-STOR-5: challenger_id too large: {} bytes (max {})",
                challenger_id.len(),
                MAX_CHALLENGE_ID_SIZE
            )));
        }
        if txid.len() > MAX_CHALLENGE_FIELD_SIZE {
            return Err(GhostError::InvalidInput(format!(
                "LOW-STOR-5: txid too large: {} bytes (max {})",
                txid.len(),
                MAX_CHALLENGE_FIELD_SIZE
            )));
        }

        self.with_connection(|conn| {
            let timestamp = chrono::Utc::now().timestamp();
            // L-3 FIX: INSERT OR REPLACE updates if same (node, challenger, day) exists
            conn.execute(
                "INSERT OR REPLACE INTO policy_challenges
                 (node_id, challenger_id, txid, expected_tier, response_tier, passed, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    node_id,
                    challenger_id,
                    txid,
                    expected_tier,
                    response_tier,
                    passed,
                    timestamp,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Insert a stratum challenge result
    ///
    /// L-3 FIX: Uses INSERT OR REPLACE to enforce rate limiting. The unique index
    /// on (node_id, challenger_id, date(timestamp)) prevents duplicate challenges
    /// from the same challenger for the same node on the same day.
    ///
    /// LOW-STOR-5: Validates all string field sizes before INSERT.
    pub fn insert_stratum_challenge(
        &self,
        node_id: &str,
        challenger_id: &str,
        connected: bool,
        latency_ms: Option<u32>,
        passed: bool,
    ) -> GhostResult<i64> {
        // LOW-STOR-5: Validate field sizes before INSERT
        if node_id.len() > MAX_CHALLENGE_ID_SIZE {
            return Err(GhostError::InvalidInput(format!(
                "LOW-STOR-5: node_id too large: {} bytes (max {})",
                node_id.len(),
                MAX_CHALLENGE_ID_SIZE
            )));
        }
        if challenger_id.len() > MAX_CHALLENGE_ID_SIZE {
            return Err(GhostError::InvalidInput(format!(
                "LOW-STOR-5: challenger_id too large: {} bytes (max {})",
                challenger_id.len(),
                MAX_CHALLENGE_ID_SIZE
            )));
        }

        self.with_connection(|conn| {
            let timestamp = chrono::Utc::now().timestamp();
            // L-3 FIX: INSERT OR REPLACE updates if same (node, challenger, day) exists
            conn.execute(
                "INSERT OR REPLACE INTO stratum_challenges
                 (node_id, challenger_id, connected, latency_ms, passed, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    node_id,
                    challenger_id,
                    connected,
                    latency_ms,
                    passed,
                    timestamp,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Insert a Ghost Pay challenge result
    ///
    /// L-3 FIX: Uses INSERT OR REPLACE to enforce rate limiting. The unique index
    /// on (node_id, challenger_id, date(timestamp)) prevents duplicate challenges
    /// from the same challenger for the same node on the same day.
    ///
    /// LOW-STOR-5: Validates all string field sizes before INSERT.
    pub fn insert_ghostpay_challenge(
        &self,
        node_id: &str,
        challenger_id: &str,
        endpoint: &str,
        response_valid: bool,
        passed: bool,
    ) -> GhostResult<i64> {
        // LOW-STOR-5: Validate field sizes before INSERT
        if node_id.len() > MAX_CHALLENGE_ID_SIZE {
            return Err(GhostError::InvalidInput(format!(
                "LOW-STOR-5: node_id too large: {} bytes (max {})",
                node_id.len(),
                MAX_CHALLENGE_ID_SIZE
            )));
        }
        if challenger_id.len() > MAX_CHALLENGE_ID_SIZE {
            return Err(GhostError::InvalidInput(format!(
                "LOW-STOR-5: challenger_id too large: {} bytes (max {})",
                challenger_id.len(),
                MAX_CHALLENGE_ID_SIZE
            )));
        }
        if endpoint.len() > MAX_CHALLENGE_FIELD_SIZE {
            return Err(GhostError::InvalidInput(format!(
                "LOW-STOR-5: endpoint too large: {} bytes (max {})",
                endpoint.len(),
                MAX_CHALLENGE_FIELD_SIZE
            )));
        }

        self.with_connection(|conn| {
            let timestamp = chrono::Utc::now().timestamp();
            // L-3 FIX: INSERT OR REPLACE updates if same (node, challenger, day) exists
            conn.execute(
                "INSERT OR REPLACE INTO ghostpay_challenges
                 (node_id, challenger_id, endpoint, response_valid, passed, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    node_id,
                    challenger_id,
                    endpoint,
                    response_valid,
                    passed,
                    timestamp,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// Get archive capability pass rate for a node
    /// Returns (passed_count, total_count)
    pub fn get_archive_pass_rate(&self, node_id: &str, since: i64) -> GhostResult<(u32, u32)> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
                        COUNT(*) as total
                     FROM archive_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            // M-10 FIX: Use safe conversions instead of direct `as u32` casts
            let result = stmt
                .query_row(params![node_id, since], |row| {
                    let passed: Option<i64> = row.get(0)?;
                    let total: i64 = row.get(1)?;
                    Ok((
                        i64_to_u32_count(passed.unwrap_or(0), "archive_passed")?,
                        i64_to_u32_count(total, "archive_total")?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result)
        })
    }

    /// Get policy capability pass rate for a node
    /// Returns (passed_count, total_count)
    pub fn get_policy_pass_rate(&self, node_id: &str, since: i64) -> GhostResult<(u32, u32)> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
                        COUNT(*) as total
                     FROM policy_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            // M-10 FIX: Use safe conversions instead of direct `as u32` casts
            let result = stmt
                .query_row(params![node_id, since], |row| {
                    let passed: Option<i64> = row.get(0)?;
                    let total: i64 = row.get(1)?;
                    Ok((
                        i64_to_u32_count(passed.unwrap_or(0), "policy_passed")?,
                        i64_to_u32_count(total, "policy_total")?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result)
        })
    }

    /// Get stratum capability pass rate for a node
    /// Returns (passed_count, total_count)
    pub fn get_stratum_pass_rate(&self, node_id: &str, since: i64) -> GhostResult<(u32, u32)> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
                        COUNT(*) as total
                     FROM stratum_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            // M-10 FIX: Use safe conversions instead of direct `as u32` casts
            let result = stmt
                .query_row(params![node_id, since], |row| {
                    let passed: Option<i64> = row.get(0)?;
                    let total: i64 = row.get(1)?;
                    Ok((
                        i64_to_u32_count(passed.unwrap_or(0), "stratum_passed")?,
                        i64_to_u32_count(total, "stratum_total")?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result)
        })
    }

    /// Get Ghost Pay capability pass rate for a node
    /// Returns (passed_count, total_count)
    pub fn get_ghostpay_pass_rate(&self, node_id: &str, since: i64) -> GhostResult<(u32, u32)> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT
                        SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed,
                        COUNT(*) as total
                     FROM ghostpay_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            // M-10 FIX: Use safe conversions instead of direct `as u32` casts
            let result = stmt
                .query_row(params![node_id, since], |row| {
                    let passed: Option<i64> = row.get(0)?;
                    let total: i64 = row.get(1)?;
                    Ok((
                        i64_to_u32_count(passed.unwrap_or(0), "ghostpay_passed")?,
                        i64_to_u32_count(total, "ghostpay_total")?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result)
        })
    }

    // =========================================================================
    // UNIQUE CHALLENGER COUNT QUERIES (C-2 Sybil Prevention)
    // =========================================================================

    /// Get the count of unique challengers for archive capability
    /// C-2: Prevents Sybil attacks by requiring verification from multiple independent nodes
    pub fn get_archive_unique_challengers(&self, node_id: &str, since: i64) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    // M-18 FIX: Only count unique challengers where passed = 1
                    // This prevents inflation via colluding nodes sending failing challenges
                    "SELECT COUNT(DISTINCT challenger_id)
                     FROM archive_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2 AND passed = 1",
                    params![node_id, since],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            // M-10 FIX: Use safe conversion
            i64_to_u32_count(count, "archive_unique_challengers")
                .map_err(|e| GhostError::Database(e.to_string()))
        })
    }

    /// Get the count of unique challengers for policy capability
    /// C-2: Prevents Sybil attacks by requiring verification from multiple independent nodes
    pub fn get_policy_unique_challengers(&self, node_id: &str, since: i64) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    // M-18 FIX: Only count unique challengers where passed = 1
                    // This prevents inflation via colluding nodes sending failing challenges
                    "SELECT COUNT(DISTINCT challenger_id)
                     FROM policy_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2 AND passed = 1",
                    params![node_id, since],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            // M-10 FIX: Use safe conversion
            i64_to_u32_count(count, "policy_unique_challengers")
                .map_err(|e| GhostError::Database(e.to_string()))
        })
    }

    /// Get the count of unique challengers for stratum capability
    /// C-2: Prevents Sybil attacks by requiring verification from multiple independent nodes
    pub fn get_stratum_unique_challengers(&self, node_id: &str, since: i64) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    // M-18 FIX: Only count unique challengers where passed = 1
                    // This prevents inflation via colluding nodes sending failing challenges
                    "SELECT COUNT(DISTINCT challenger_id)
                     FROM stratum_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2 AND passed = 1",
                    params![node_id, since],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            // M-10 FIX: Use safe conversion
            i64_to_u32_count(count, "stratum_unique_challengers")
                .map_err(|e| GhostError::Database(e.to_string()))
        })
    }

    /// Get the count of unique challengers for ghostpay capability
    /// C-2: Prevents Sybil attacks by requiring verification from multiple independent nodes
    pub fn get_ghostpay_unique_challengers(&self, node_id: &str, since: i64) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    // M-18 FIX: Only count unique challengers where passed = 1
                    // This prevents inflation via colluding nodes sending failing challenges
                    "SELECT COUNT(DISTINCT challenger_id)
                     FROM ghostpay_challenges
                     WHERE node_id = ?1 AND timestamp >= ?2 AND passed = 1",
                    params![node_id, since],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            // M-10 FIX: Use safe conversion
            i64_to_u32_count(count, "ghostpay_unique_challengers")
                .map_err(|e| GhostError::Database(e.to_string()))
        })
    }

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

    /// H-2 SECURITY: Get uptime percentage as integer (0-100)
    ///
    /// Returns the uptime as a percentage (0-100), or None if no samples exist.
    /// This is used for elder registration verification where we compare against
    /// claimed uptime values.
    pub fn get_node_uptime_percent(&self, node_id: &str, since: i64) -> GhostResult<Option<u32>> {
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

            let (online, total) = result;
            if total == 0 {
                return Ok(None);
            }
            // GHOST-10: time-based expected denominator, not online/total.
            let percent = (Self::uptime_ratio(online, since) * 100.0).round() as u32;
            Ok(Some(percent.min(100)))
        })
    }

    /// H-2 SECURITY: Get first seen timestamp for a node
    ///
    /// Returns the earliest timestamp when this node was first observed.
    /// Used to verify elder registration uptime claims.
    pub fn get_node_first_seen(&self, node_id: &str) -> GhostResult<Option<i64>> {
        self.with_connection(|conn| {
            // First check the nodes table
            let from_nodes: Option<i64> = conn
                .query_row(
                    "SELECT first_seen FROM nodes WHERE node_id = ?1",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
                .flatten();

            // Also check uptime_samples for earliest sample
            let from_samples: Option<i64> = conn
                .query_row(
                    "SELECT MIN(sample_time) FROM uptime_samples WHERE node_id = ?1",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
                .flatten();

            // Return the earliest of the two
            match (from_nodes, from_samples) {
                (Some(n), Some(s)) => Ok(Some(n.min(s))),
                (Some(n), None) => Ok(Some(n)),
                (None, Some(s)) => Ok(Some(s)),
                (None, None) => Ok(None),
            }
        })
    }

    /// Check if a node has elder status
    ///
    /// Elder status is granted to the first 101 registered nodes.
    /// This is tracked by the is_elder flag in the nodes table.
    pub fn is_node_elder(&self, node_id: &str) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let is_elder: bool = conn
                .query_row(
                    "SELECT COALESCE(is_elder, 0) FROM nodes WHERE node_id = ?1",
                    [node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
                .unwrap_or(false);
            Ok(is_elder)
        })
    }

    /// Get qualified capabilities for a node
    ///
    /// A capability is qualified if:
    /// 1. Node passes uptime gatekeeper (95% over lookback period)
    /// 2. Capability has min_challenges or more challenges
    /// 3. Pass rate is >= min_pass_rate
    ///
    /// H-4: This function safely handles division by zero by checking total > 0
    /// before computing pass rate. If total is 0, the capability is not qualified.
    pub fn get_qualified_capabilities(
        &self,
        node_id: &str,
        since: i64,
        min_challenges: u32,
        min_pass_rate: f64,
    ) -> GhostResult<ghost_common::types::NodeCapabilities> {
        // Legacy function - uses same pass rate for all capabilities
        // Call the new per-capability function with uniform rates
        self.get_qualified_capabilities_with_rates(
            node_id,
            since,
            min_challenges,
            min_pass_rate,
            min_pass_rate,
            min_pass_rate,
            min_pass_rate,
        )
    }

    /// M-16 FIX: Get qualified capabilities with per-capability pass rates
    ///
    /// A capability is qualified if:
    /// 1. Node passes uptime gatekeeper (95% over lookback period)
    /// 2. Capability has min_challenges or more challenges
    /// 3. Pass rate is >= the capability-specific threshold
    ///
    /// H-4: This function safely handles division by zero by checking total > 0
    /// before computing pass rate. If total is 0, the capability is not qualified.
    #[allow(clippy::too_many_arguments)]
    pub fn get_qualified_capabilities_with_rates(
        &self,
        node_id: &str,
        since: i64,
        min_challenges: u32,
        archive_pass_rate: f64,
        ghostpay_pass_rate: f64,
        stratum_pass_rate: f64,
        policy_pass_rate: f64,
    ) -> GhostResult<ghost_common::types::NodeCapabilities> {
        use ghost_common::types::NodeCapabilities;

        // H-4: Helper function to safely compute qualification without division by zero
        // Returns true only if total >= min_challenges AND total > 0 AND pass_rate >= threshold
        let is_qualified = |passed: u32, total: u32, min_rate: f64| -> bool {
            // Explicit check for total > 0 to prevent any division by zero
            total > 0 && total >= min_challenges && (passed as f64 / total as f64) >= min_rate
        };

        // M-16 FIX: Check each capability with its own pass rate threshold
        let archive_qualified = {
            let (passed, total) = self.get_archive_pass_rate(node_id, since)?;
            is_qualified(passed, total, archive_pass_rate)
        };

        let policy_qualified = {
            let (passed, total) = self.get_policy_pass_rate(node_id, since)?;
            is_qualified(passed, total, policy_pass_rate)
        };

        let stratum_qualified = {
            let (passed, total) = self.get_stratum_pass_rate(node_id, since)?;
            is_qualified(passed, total, stratum_pass_rate)
        };

        let ghostpay_qualified = {
            let (passed, total) = self.get_ghostpay_pass_rate(node_id, since)?;
            is_qualified(passed, total, ghostpay_pass_rate)
        };

        // Elder status is based on is_elder flag in the nodes table
        // First 101 registered nodes are elders (registration order tracked by elder_order)
        let elder_qualified = self.is_node_elder(node_id)?;

        Ok(NodeCapabilities {
            archive_mode: archive_qualified,
            ghost_pay: ghostpay_qualified,
            public_mining: stratum_qualified,
            reaper: policy_qualified,
            elder_status: elder_qualified,
        })
    }

    // =========================================================================
    // EQUIVOCATION PROOF QUERIES (P2P4-L7)
    // =========================================================================

    /// Store an equivocation proof for a Byzantine node
    ///
    /// P2P4-L7: Persists cryptographic proof when a node is caught signing
    /// conflicting votes. This evidence is used for:
    /// - Forensic analysis
    /// - Future slashing implementation
    /// - Audit trail
    ///
    /// # Arguments
    /// * `node_id` - The node that committed equivocation (32-byte NodeId)
    /// * `proof_data` - Serialized equivocation proof (both conflicting votes)
    /// * `round_number` - Optional round number where equivocation occurred
    /// * `vote_type` - Optional description of the vote type (e.g., "payout", "block")
    ///
    /// # L-16 Size Limit
    /// proof_data must not exceed MAX_EQUIVOCATION_PROOF_SIZE (100 KB).
    /// Returns an error if the proof is too large.
    pub fn store_equivocation_proof(
        &self,
        node_id: &[u8; 32],
        proof_data: &[u8],
        round_number: Option<u64>,
        vote_type: Option<&str>,
    ) -> GhostResult<i64> {
        // L-16: Validate proof size before INSERT to prevent storage DoS
        if proof_data.len() > MAX_EQUIVOCATION_PROOF_SIZE {
            return Err(GhostError::InvalidInput(format!(
                "Equivocation proof too large: {} bytes (max {} bytes)",
                proof_data.len(),
                MAX_EQUIVOCATION_PROOF_SIZE
            )));
        }

        self.with_connection(|conn| {
            let now = chrono::Utc::now().timestamp();
            conn.execute(
                "INSERT INTO equivocation_proofs (node_id, proof_data, detected_at, round_number, vote_type)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    node_id.as_slice(),
                    proof_data,
                    now,
                    round_number.map(|r| r as i64),
                    vote_type,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(conn.last_insert_rowid())
        })
    }

    /// GHOST-11: distinct equivocators with a proof detected at/after
    /// `since_unix`, and their latest detection time. Used to re-apply
    /// equivocation bans on startup — bans are otherwise in-memory and silently
    /// lost on restart, letting an equivocator vote again within its ban window.
    pub fn get_recent_equivocators(&self, since_unix: i64) -> GhostResult<Vec<([u8; 32], i64)>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT node_id, MAX(detected_at) FROM equivocation_proofs
                     WHERE detected_at >= ?1 GROUP BY node_id",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let rows = stmt
                .query_map(params![since_unix], |row| {
                    let blob: Vec<u8> = row.get(0)?;
                    let detected: i64 = row.get(1)?;
                    Ok((blob, detected))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let mut out = Vec::new();
            for r in rows {
                let (blob, detected) = r.map_err(|e| GhostError::Database(e.to_string()))?;
                if blob.len() == 32 {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&blob);
                    out.push((id, detected));
                }
            }
            Ok(out)
        })
    }

    /// Get equivocation proofs for a node
    ///
    /// Returns all stored equivocation proofs for forensic analysis.
    /// H-7: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub fn get_equivocation_proofs(
        &self,
        node_id: &[u8; 32],
    ) -> GhostResult<Vec<EquivocationProofRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, node_id, proof_data, detected_at, round_number, vote_type, created_at
                     FROM equivocation_proofs WHERE node_id = ?1 ORDER BY detected_at DESC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let proofs = stmt
                .query_map(params![node_id.as_slice(), Self::MAX_QUERY_RESULTS], |row| {
                    Ok(EquivocationProofRecord {
                        id: row.get(0)?,
                        node_id: row.get(1)?,
                        proof_data: row.get(2)?,
                        detected_at: row.get(3)?,
                        round_number: row.get(4)?,
                        vote_type: row.get(5)?,
                        created_at: row.get(6)?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(proofs)
        })
    }

    /// Count equivocation events for a node
    ///
    /// Useful for tracking repeat offenders.
    pub fn count_equivocation_events(&self, node_id: &[u8; 32]) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM equivocation_proofs WHERE node_id = ?1",
                    [node_id.as_slice()],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            // M-10 FIX: Use safe conversion
            i64_to_u32_count(count, "equivocation_count")
                .map_err(|e| GhostError::Database(e.to_string()))
        })
    }
}

// =============================================================================
// L2 STATE QUERIES (ZK-CONSENSUS)
// =============================================================================

impl Database {
    /// Get current L2 state (height and state root)
    ///
    /// Returns (height, state_root) or (0, [0u8; 32]) if not initialized.
    pub fn get_l2_state(&self) -> GhostResult<(u64, [u8; 32])> {
        self.with_connection(|conn| {
            let result: Option<(i64, Vec<u8>)> = conn
                .query_row(
                    "SELECT height, state_root FROM l2_state WHERE id = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some((height_i64, root_bytes)) => {
                    // M-10 FIX: Use safe conversion
                    let height = i64_to_u64(height_i64, "l2_height")
                        .map_err(|e| GhostError::Database(e.to_string()))?;
                    let mut state_root = [0u8; 32];
                    if root_bytes.len() == 32 {
                        state_root.copy_from_slice(&root_bytes);
                    }
                    Ok((height, state_root))
                }
                None => Ok((0, [0u8; 32])),
            }
        })
    }

    /// Save block proposer record for L2 block tracking
    pub fn save_block_proposer(
        &self,
        height: u64,
        proposer_id: &str,
        state_root: &str,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            let now = chrono::Utc::now().timestamp();
            conn.execute(
                "INSERT OR REPLACE INTO block_proposers (height, proposer_id, state_root, timestamp) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![height as i64, proposer_id, state_root, now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Save current L2 state
    pub fn save_l2_state(&self, height: u64, state_root: [u8; 32]) -> GhostResult<()> {
        self.with_connection(|conn| {
            let now = chrono::Utc::now().timestamp_millis();
            conn.execute(
                "INSERT OR REPLACE INTO l2_state (id, height, state_root, updated_at)
                 VALUES (1, ?1, ?2, ?3)",
                params![height as i64, state_root.as_slice(), now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Save L2 state snapshot for reorg recovery
    pub fn save_l2_snapshot(&self, height: u64, state_root: [u8; 32]) -> GhostResult<()> {
        self.with_connection(|conn| {
            let now = chrono::Utc::now().timestamp_millis();
            conn.execute(
                "INSERT OR REPLACE INTO l2_snapshots (height, state_root, created_at)
                 VALUES (?1, ?2, ?3)",
                params![height as i64, state_root.as_slice(), now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get L2 snapshot at or before a given height (for reorg recovery)
    pub fn get_l2_snapshot_at_or_before(
        &self,
        height: u64,
    ) -> GhostResult<Option<(u64, [u8; 32])>> {
        self.with_connection(|conn| {
            let result: Option<(i64, Vec<u8>)> = conn
                .query_row(
                    "SELECT height, state_root FROM l2_snapshots
                     WHERE height <= ?1 ORDER BY height DESC LIMIT 1",
                    params![height as i64],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some((snap_height, root_bytes)) => {
                    let mut state_root = [0u8; 32];
                    if root_bytes.len() == 32 {
                        state_root.copy_from_slice(&root_bytes);
                    }
                    // 4.19 SECURITY: Use safe conversion
                    let height = i64_to_u64(snap_height, "snapshot_height")
                        .map_err(|e| GhostError::Database(e.to_string()))?;
                    Ok(Some((height, state_root)))
                }
                None => Ok(None),
            }
        })
    }

    /// Prune old L2 snapshots, keeping the most recent N
    pub fn prune_l2_snapshots(&self, keep_count: usize) -> GhostResult<u64> {
        self.with_connection(|conn| {
            // First count how many we have
            let total: i64 = conn
                .query_row("SELECT COUNT(*) FROM l2_snapshots", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if total <= keep_count as i64 {
                return Ok(0);
            }

            // Delete oldest snapshots beyond keep_count
            let delete_count = total - keep_count as i64;
            conn.execute(
                "DELETE FROM l2_snapshots WHERE height IN (
                    SELECT height FROM l2_snapshots ORDER BY height ASC LIMIT ?1
                )",
                params![delete_count],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // 4.19 SECURITY: Use safe conversion (defensive, should never fail given the guard above)
            i64_to_u64(delete_count, "delete_count")
                .map_err(|e| GhostError::Database(e.to_string()))
        })
    }
}

// =============================================================================
// MPC CEREMONY QUERIES
// =============================================================================

/// MPC ceremony state record (singleton)
#[derive(Debug, Clone)]
pub struct MpcCeremonyState {
    pub contribution_count: u32,
    pub current_params_hash: [u8; 32],
    pub is_ossified: bool,
    pub ossified_at: Option<u64>,
    pub block_vk_hash: Option<[u8; 32]>,
    pub payout_vk_hash: Option<[u8; 32]>,
    pub updated_at: u64,
}

/// MPC contribution record
#[derive(Debug, Clone)]
pub struct MpcContributionRecord {
    pub elder_position: u32,
    pub contributor_node_id: String,
    pub prev_params_hash: [u8; 32],
    pub new_params_hash: [u8; 32],
    pub contribution_proof: Vec<u8>,
    pub epoch: u64,
    pub created_at: u64,
}

/// MPC verification vote record
#[derive(Debug, Clone)]
pub struct MpcVerificationVote {
    pub contribution_position: u32,
    pub voter_node_id: String,
    pub approve: bool,
    pub signature: Vec<u8>,
    pub voted_at: u64,
}

/// MPC parameter file metadata
#[derive(Debug, Clone)]
pub struct MpcParamsFile {
    pub params_hash: [u8; 32],
    pub file_path: String,
    pub size_bytes: u64,
    pub contribution_count: u32,
    pub created_at: u64,
}

impl Database {
    /// Get the MPC ceremony state
    ///
    /// Returns None if the ceremony hasn't been initialized yet.
    #[allow(clippy::type_complexity)]
    pub fn get_mpc_ceremony_state(&self) -> GhostResult<Option<MpcCeremonyState>> {
        self.with_connection(|conn| {
            let result: Option<(
                i64,
                Vec<u8>,
                i64,
                Option<i64>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
                i64,
            )> = conn
                .query_row(
                    "SELECT contribution_count, current_params_hash, is_ossified, ossified_at,
                            block_vk_hash, payout_vk_hash, updated_at
                     FROM mpc_ceremony WHERE id = 1",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some((count, hash_bytes, ossified, ossified_at, block_vk, payout_vk, updated)) => {
                    let mut params_hash = [0u8; 32];
                    if hash_bytes.len() == 32 {
                        params_hash.copy_from_slice(&hash_bytes);
                    }

                    let block_vk_hash = block_vk.and_then(|v| {
                        if v.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&v);
                            Some(arr)
                        } else {
                            None
                        }
                    });

                    let payout_vk_hash = payout_vk.and_then(|v| {
                        if v.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&v);
                            Some(arr)
                        } else {
                            None
                        }
                    });

                    // M-10 FIX: Use safe conversions
                    Ok(Some(MpcCeremonyState {
                        contribution_count: i64_to_u32_count(count, "contribution_count")
                            .map_err(|e| GhostError::Database(e.to_string()))?,
                        current_params_hash: params_hash,
                        is_ossified: ossified != 0,
                        ossified_at: match ossified_at {
                            Some(v) => Some(
                                i64_to_u64(v, "ossified_at")
                                    .map_err(|e| GhostError::Database(e.to_string()))?,
                            ),
                            None => None,
                        },
                        block_vk_hash,
                        payout_vk_hash,
                        updated_at: i64_to_u64(updated, "updated_at")
                            .map_err(|e| GhostError::Database(e.to_string()))?,
                    }))
                }
                None => Ok(None),
            }
        })
    }

    /// Save or update MPC ceremony state
    pub fn save_mpc_ceremony_state(&self, state: &MpcCeremonyState) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO mpc_ceremony (id, contribution_count, current_params_hash, is_ossified,
                                          ossified_at, block_vk_hash, payout_vk_hash, updated_at)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(id) DO UPDATE SET
                    contribution_count = excluded.contribution_count,
                    current_params_hash = excluded.current_params_hash,
                    is_ossified = excluded.is_ossified,
                    ossified_at = excluded.ossified_at,
                    block_vk_hash = excluded.block_vk_hash,
                    payout_vk_hash = excluded.payout_vk_hash,
                    updated_at = excluded.updated_at",
                params![
                    state.contribution_count as i64,
                    &state.current_params_hash[..],
                    if state.is_ossified { 1i64 } else { 0i64 },
                    state.ossified_at.map(|v| v as i64),
                    state.block_vk_hash.as_ref().map(|v| &v[..]),
                    state.payout_vk_hash.as_ref().map(|v| &v[..]),
                    state.updated_at as i64,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Save an MPC contribution
    pub fn save_mpc_contribution(&self, contribution: &MpcContributionRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO mpc_contributions (elder_position, contributor_node_id, prev_params_hash,
                                                new_params_hash, contribution_proof, epoch, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    contribution.elder_position as i64,
                    contribution.contributor_node_id,
                    &contribution.prev_params_hash[..],
                    &contribution.new_params_hash[..],
                    &contribution.contribution_proof,
                    contribution.epoch as i64,
                    contribution.created_at as i64,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get an MPC contribution by position
    #[allow(clippy::type_complexity)]
    pub fn get_mpc_contribution(
        &self,
        position: u32,
    ) -> GhostResult<Option<MpcContributionRecord>> {
        self.with_connection(|conn| {
            let result: Option<(String, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64)> = conn
                .query_row(
                    "SELECT contributor_node_id, prev_params_hash, new_params_hash,
                            contribution_proof, epoch, created_at
                     FROM mpc_contributions WHERE elder_position = ?1",
                    params![position as i64],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some((node_id, prev_hash, new_hash, proof, epoch, created_at)) => {
                    let mut prev_params_hash = [0u8; 32];
                    let mut new_params_hash = [0u8; 32];
                    if prev_hash.len() == 32 {
                        prev_params_hash.copy_from_slice(&prev_hash);
                    }
                    if new_hash.len() == 32 {
                        new_params_hash.copy_from_slice(&new_hash);
                    }

                    // M-10 FIX: Use safe conversions
                    Ok(Some(MpcContributionRecord {
                        elder_position: position,
                        contributor_node_id: node_id,
                        prev_params_hash,
                        new_params_hash,
                        contribution_proof: proof,
                        epoch: i64_to_u64(epoch, "mpc_epoch")
                            .map_err(|e| GhostError::Database(e.to_string()))?,
                        created_at: i64_to_u64(created_at, "mpc_created_at")
                            .map_err(|e| GhostError::Database(e.to_string()))?,
                    }))
                }
                None => Ok(None),
            }
        })
    }

    /// Save an MPC verification vote
    pub fn save_mpc_vote(&self, vote: &MpcVerificationVote) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO mpc_verification_votes (contribution_position, voter_node_id, approve,
                                                      signature, voted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(contribution_position, voter_node_id) DO UPDATE SET
                    approve = excluded.approve,
                    signature = excluded.signature,
                    voted_at = excluded.voted_at",
                params![
                    vote.contribution_position as i64,
                    vote.voter_node_id,
                    if vote.approve { 1i64 } else { 0i64 },
                    &vote.signature,
                    vote.voted_at as i64,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Count MPC approvals for a contribution
    pub fn count_mpc_approvals(&self, contribution_position: u32) -> GhostResult<(u32, u32)> {
        self.with_connection(|conn| {
            let (approve_count, reject_count): (i64, i64) = conn
                .query_row(
                    "SELECT
                        SUM(CASE WHEN approve = 1 THEN 1 ELSE 0 END),
                        SUM(CASE WHEN approve = 0 THEN 1 ELSE 0 END)
                     FROM mpc_verification_votes WHERE contribution_position = ?1",
                    params![contribution_position as i64],
                    |row| {
                        let approves: Option<i64> = row.get(0)?;
                        let rejects: Option<i64> = row.get(1)?;
                        Ok((approves.unwrap_or(0), rejects.unwrap_or(0)))
                    },
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            // M-10 FIX: Use safe conversions
            Ok((
                i64_to_u32_count(approve_count, "mpc_approve_count")
                    .map_err(|e| GhostError::Database(e.to_string()))?,
                i64_to_u32_count(reject_count, "mpc_reject_count")
                    .map_err(|e| GhostError::Database(e.to_string()))?,
            ))
        })
    }

    /// Get all votes for a contribution
    pub fn get_mpc_votes(
        &self,
        contribution_position: u32,
    ) -> GhostResult<Vec<MpcVerificationVote>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT voter_node_id, approve, signature, voted_at
                     FROM mpc_verification_votes WHERE contribution_position = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![contribution_position as i64], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut votes = Vec::new();
            for row in rows {
                let (voter_id, approve, sig, voted_at) =
                    row.map_err(|e| GhostError::Database(e.to_string()))?;
                // M-10 FIX: Use safe conversion
                let voted_at_u64 = i64_to_u64(voted_at, "mpc_voted_at")
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                votes.push(MpcVerificationVote {
                    contribution_position,
                    voter_node_id: voter_id,
                    approve: approve != 0,
                    signature: sig,
                    voted_at: voted_at_u64,
                });
            }
            Ok(votes)
        })
    }

    /// Mark ceremony as ossified
    pub fn set_ceremony_ossified(&self, ossified_at: u64) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE mpc_ceremony SET is_ossified = 1, ossified_at = ?1 WHERE id = 1",
                params![ossified_at as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Save MPC parameter file metadata
    pub fn save_mpc_params_file(&self, params_file: &MpcParamsFile) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO mpc_params_files (params_hash, file_path, size_bytes, contribution_count, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(params_hash) DO UPDATE SET
                    file_path = excluded.file_path,
                    size_bytes = excluded.size_bytes",
                params![
                    &params_file.params_hash[..],
                    params_file.file_path,
                    params_file.size_bytes as i64,
                    params_file.contribution_count as i64,
                    params_file.created_at as i64,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get MPC parameter file by hash
    pub fn get_mpc_params_file(
        &self,
        params_hash: &[u8; 32],
    ) -> GhostResult<Option<MpcParamsFile>> {
        self.with_connection(|conn| {
            let result: Option<(String, i64, i64, i64)> = conn
                .query_row(
                    "SELECT file_path, size_bytes, contribution_count, created_at
                     FROM mpc_params_files WHERE params_hash = ?1",
                    params![&params_hash[..]],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some((path, size, count, created)) => {
                    // M-10 FIX: Use safe conversions
                    Ok(Some(MpcParamsFile {
                        params_hash: *params_hash,
                        file_path: path,
                        size_bytes: i64_to_u64(size, "mpc_size_bytes")
                            .map_err(|e| GhostError::Database(e.to_string()))?,
                        contribution_count: i64_to_u32_count(count, "mpc_contribution_count")
                            .map_err(|e| GhostError::Database(e.to_string()))?,
                        created_at: i64_to_u64(created, "mpc_created_at")
                            .map_err(|e| GhostError::Database(e.to_string()))?,
                    }))
                }
                None => Ok(None),
            }
        })
    }

    /// Get the latest MPC parameter file (highest contribution count)
    pub fn get_latest_mpc_params_file(&self) -> GhostResult<Option<MpcParamsFile>> {
        self.with_connection(|conn| {
            let result: Option<(Vec<u8>, String, i64, i64, i64)> = conn
                .query_row(
                    "SELECT params_hash, file_path, size_bytes, contribution_count, created_at
                     FROM mpc_params_files ORDER BY contribution_count DESC LIMIT 1",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some((hash_bytes, path, size, count, created)) => {
                    let mut params_hash = [0u8; 32];
                    if hash_bytes.len() == 32 {
                        params_hash.copy_from_slice(&hash_bytes);
                    }
                    // M-10 FIX: Use safe conversions
                    Ok(Some(MpcParamsFile {
                        params_hash,
                        file_path: path,
                        size_bytes: i64_to_u64(size, "mpc_size_bytes")
                            .map_err(|e| GhostError::Database(e.to_string()))?,
                        contribution_count: i64_to_u32_count(count, "mpc_contribution_count")
                            .map_err(|e| GhostError::Database(e.to_string()))?,
                        created_at: i64_to_u64(created, "mpc_created_at")
                            .map_err(|e| GhostError::Database(e.to_string()))?,
                    }))
                }
                None => Ok(None),
            }
        })
    }

    // =========================================================================
    // ELDER STATUS (MPC-BASED)
    // =========================================================================
    // Elder status is determined by MPC contribution.
    // If a node contributed to the MPC ceremony (position 1-101), they are an elder.
    // This replaces the complex canonical elder list system.

    /// Check if a node is an elder (MPC contributor)
    ///
    /// A node is an elder if they have contributed to the MPC ceremony.
    /// Elder status grants +1 share in node rewards (if 95% uptime met).
    pub fn is_mpc_elder(&self, node_id: &str) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM mpc_contributions WHERE contributor_node_id = ?1",
                    params![node_id],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count > 0)
        })
    }

    /// Get a node's elder position (MPC contribution position)
    ///
    /// Returns the position (1-101) if the node is an elder, None otherwise.
    pub fn get_mpc_elder_position(&self, node_id: &str) -> GhostResult<Option<u32>> {
        self.with_connection(|conn| {
            let result: Option<i64> = conn
                .query_row(
                    "SELECT elder_position FROM mpc_contributions WHERE contributor_node_id = ?1",
                    params![node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some(pos) => {
                    let position = i64_to_u32_count(pos, "elder_position")
                        .map_err(|e| GhostError::Database(e.to_string()))?;
                    Ok(Some(position))
                }
                None => Ok(None),
            }
        })
    }

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

    /// Get count of MPC elders
    pub fn get_mpc_elder_count(&self) -> GhostResult<u32> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM mpc_contributions", [], |row| {
                    row.get(0)
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;
            i64_to_u32_count(count, "mpc_elder_count")
                .map_err(|e| GhostError::Database(e.to_string()))
        })
    }

    /// Get all MPC elder node IDs as parsed 32-byte arrays
    ///
    /// Returns a HashSet of NodeId bytes for all MPC contributors.
    /// Used by VoteHandler to determine eligible voters for BFT consensus.
    pub fn get_mpc_elder_node_ids(&self) -> GhostResult<std::collections::HashSet<[u8; 32]>> {
        let elders = self.get_all_mpc_elders()?;
        let mut node_ids = std::collections::HashSet::new();
        for (node_id_hex, _position) in &elders {
            if let Ok(bytes) = hex::decode(node_id_hex) {
                if let Ok(id) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    node_ids.insert(id);
                }
            }
        }
        Ok(node_ids)
    }
}

// =============================================================================
// L-24 FIX: INSTANT PAYMENT RESERVATION QUERIES
// =============================================================================

/// Record for persisted instant payment reservation
#[derive(Debug, Clone)]
pub struct InstantReservationRecord {
    /// Payment ID (32 bytes)
    pub payment_id: [u8; 32],
    /// Lock ID this reservation is for
    pub lock_id: String,
    /// Amount reserved in satoshis
    pub amount_sats: u64,
    /// When created (Unix millis)
    pub created_at: u64,
    /// When expires (Unix millis)
    pub expires_at: u64,
}

impl Database {
    /// Save an instant payment reservation
    ///
    /// L-24 FIX: Persists reservations so they survive restarts
    pub fn save_instant_reservation(
        &self,
        reservation: &InstantReservationRecord,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO instant_payment_reservations
                 (payment_id, lock_id, amount_sats, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    reservation.payment_id.as_slice(),
                    reservation.lock_id,
                    reservation.amount_sats as i64,
                    reservation.created_at as i64,
                    reservation.expires_at as i64,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get all active reservations for a lock
    ///
    /// L-24 FIX: Returns reservations that haven't expired yet
    pub fn get_active_reservations_for_lock(
        &self,
        lock_id: &str,
        current_time_millis: u64,
    ) -> GhostResult<Vec<InstantReservationRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT payment_id, lock_id, amount_sats, created_at, expires_at
                     FROM instant_payment_reservations
                     WHERE lock_id = ?1 AND expires_at > ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let reservations = stmt
                .query_map(params![lock_id, current_time_millis as i64], |row| {
                    let payment_id_bytes: Vec<u8> = row.get(0)?;
                    let mut payment_id = [0u8; 32];
                    if payment_id_bytes.len() == 32 {
                        payment_id.copy_from_slice(&payment_id_bytes);
                    }
                    Ok(InstantReservationRecord {
                        payment_id,
                        lock_id: row.get(1)?,
                        amount_sats: i64_to_u64_sats(row.get::<_, i64>(2)?, "amount_sats")?,
                        created_at: i64_to_u64(row.get::<_, i64>(3)?, "created_at")?,
                        expires_at: i64_to_u64(row.get::<_, i64>(4)?, "expires_at")?,
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(reservations)
        })
    }

    /// Get total reserved amount for a lock
    ///
    /// L-24 FIX: Efficiently sums all active reservations
    pub fn get_total_reserved_for_lock(
        &self,
        lock_id: &str,
        current_time_millis: u64,
    ) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let total: Option<i64> = conn
                .query_row(
                    "SELECT SUM(amount_sats) FROM instant_payment_reservations
                     WHERE lock_id = ?1 AND expires_at > ?2",
                    params![lock_id, current_time_millis as i64],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match total {
                Some(sats) => i64_to_u64_sats(sats, "total_reserved")
                    .map_err(|e| GhostError::Database(e.to_string())),
                None => Ok(0),
            }
        })
    }

    /// Delete a reservation (e.g., when settled or cancelled)
    ///
    /// L-24 FIX: Removes reservation after it's no longer needed
    pub fn delete_instant_reservation(&self, payment_id: &[u8; 32]) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let affected = conn
                .execute(
                    "DELETE FROM instant_payment_reservations WHERE payment_id = ?1",
                    [payment_id.as_slice()],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(affected > 0)
        })
    }

    /// Prune expired reservations
    ///
    /// L-24 FIX: Clean up expired reservations to prevent unbounded growth
    pub fn prune_expired_reservations(&self, current_time_millis: u64) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let deleted = conn
                .execute(
                    "DELETE FROM instant_payment_reservations WHERE expires_at <= ?1",
                    [current_time_millis as i64],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(deleted as u64)
        })
    }

    /// Check if a reservation exists
    ///
    /// L-24 FIX: Quick check without loading full record
    pub fn has_instant_reservation(&self, payment_id: &[u8; 32]) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM instant_payment_reservations WHERE payment_id = ?1",
                    [payment_id.as_slice()],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count > 0)
        })
    }
}

// =============================================================================
// L2 STATE QUERIES (GhostPay Verification)
// =============================================================================

/// L2 state summary for verification
#[derive(Debug, Clone)]
pub struct L2StateInfo {
    /// Current L2 block height
    pub height: u64,
    /// Current epoch (height / 2160)
    pub epoch: u64,
    /// State root hash at current height (hex)
    pub state_root: String,
    /// Timestamp of latest block
    pub timestamp: i64,
}

impl Database {
    /// Get the latest L2 state from block_proposers table
    ///
    /// Returns the most recent block proposer record which contains:
    /// - L2 block height
    /// - State root hash
    /// - Timestamp
    ///
    /// Used by GhostPay verification to prove L2 capability.
    pub fn get_latest_l2_state(&self) -> GhostResult<Option<L2StateInfo>> {
        self.with_connection(|conn| {
            let result = conn.query_row(
                "SELECT height, state_root, timestamp FROM block_proposers
                 ORDER BY height DESC LIMIT 1",
                [],
                |row| {
                    let h: i64 = row.get(0)?;
                    let state_root: String = row.get(1)?;
                    let timestamp: i64 = row.get(2)?;
                    Ok((h, state_root, timestamp))
                },
            );

            match result {
                Ok((h, state_root, timestamp)) => {
                    // Validate height is non-negative
                    if h < 0 {
                        return Err(GhostError::Database(format!(
                            "Invalid negative L2 height: {}",
                            h
                        )));
                    }
                    let height = h as u64;
                    // Epoch = height / 2160 (L2 blocks per epoch)
                    let epoch = height / 2160;
                    Ok(Some(L2StateInfo {
                        height,
                        epoch,
                        state_root,
                        timestamp,
                    }))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(GhostError::Database(e.to_string())),
            }
        })
    }

    /// Get L2 state at a specific epoch
    ///
    /// Returns the block proposer record at the last block of the specified epoch.
    /// Epoch N ends at block height ((N + 1) * 2160 - 1).
    pub fn get_l2_state_at_epoch(&self, epoch: u64) -> GhostResult<Option<L2StateInfo>> {
        // Find the highest block in this epoch
        // Epoch N contains blocks [N * 2160, (N+1) * 2160 - 1]
        let epoch_start = epoch.saturating_mul(2160);
        let epoch_end = epoch
            .saturating_add(1)
            .saturating_mul(2160)
            .saturating_sub(1);

        self.with_connection(|conn| {
            let result = conn.query_row(
                "SELECT height, state_root, timestamp FROM block_proposers
                 WHERE height >= ?1 AND height <= ?2
                 ORDER BY height DESC LIMIT 1",
                params![epoch_start as i64, epoch_end as i64],
                |row| {
                    let h: i64 = row.get(0)?;
                    let state_root: String = row.get(1)?;
                    let timestamp: i64 = row.get(2)?;
                    Ok((h, state_root, timestamp))
                },
            );

            match result {
                Ok((h, state_root, timestamp)) => {
                    if h < 0 {
                        return Err(GhostError::Database(format!(
                            "Invalid negative L2 height: {}",
                            h
                        )));
                    }
                    Ok(Some(L2StateInfo {
                        height: h as u64,
                        epoch,
                        state_root,
                        timestamp,
                    }))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(GhostError::Database(e.to_string())),
            }
        })
    }

    // =========================================================================
    // PAYOUT PROPOSAL PERSISTENCE
    // =========================================================================

    /// Store a payout proposal in the database
    ///
    /// Uses INSERT OR REPLACE so re-storing the same proposal (e.g., from P2P)
    /// is idempotent and won't fail.
    pub fn store_payout_proposal(
        &self,
        hash: &[u8],
        round_id: u64,
        height: u64,
        json: &str,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO payout_proposals (proposal_hash, round_id, block_height, proposal_json)
                 VALUES (?1, ?2, ?3, ?4)",
                params![hash, round_id as i64, height as i64, json],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Mark a proposal as approved and clear any other approvals
    ///
    /// Only one proposal can be approved at a time. This atomically
    /// clears all other approvals and sets the specified one.
    pub fn mark_payout_approved(&self, hash: &[u8]) -> GhostResult<()> {
        self.with_connection(|conn| {
            // Clear all existing approvals first
            conn.execute(
                "UPDATE payout_proposals SET is_approved = 0 WHERE is_approved = 1",
                [],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Mark the target as approved
            let updated = conn
                .execute(
                    "UPDATE payout_proposals SET is_approved = 1 WHERE proposal_hash = ?1",
                    params![hash],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if updated == 0 {
                warn!(
                    hash = %hex::encode(&hash[..hash.len().min(8)]),
                    "mark_payout_approved: proposal not found in database"
                );
            }

            Ok(())
        })
    }

    /// Clear the approved payout (e.g., after a block is found)
    pub fn clear_approved_payout(&self) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE payout_proposals SET is_approved = 0 WHERE is_approved = 1",
                [],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get the currently approved payout proposal
    ///
    /// Returns the proposal hash and JSON if an approved proposal exists.
    pub fn get_approved_payout_proposal(&self) -> GhostResult<Option<(Vec<u8>, String)>> {
        self.with_connection(|conn| {
            let result = conn
                .query_row(
                    "SELECT proposal_hash, proposal_json FROM payout_proposals WHERE is_approved = 1",
                    [],
                    |row| {
                        let hash: Vec<u8> = row.get(0)?;
                        let json: String = row.get(1)?;
                        Ok((hash, json))
                    },
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(result)
        })
    }

    /// Clean up old unapproved proposals, keeping at most `keep_count`
    ///
    /// Prevents unbounded growth of the payout_proposals table.
    /// Approved proposals are never deleted by this method.
    pub fn cleanup_old_proposals(&self, keep_count: u32) -> GhostResult<usize> {
        self.with_connection(|conn| {
            let deleted = conn
                .execute(
                    "DELETE FROM payout_proposals WHERE is_approved = 0 AND rowid NOT IN (
                        SELECT rowid FROM payout_proposals WHERE is_approved = 0
                        ORDER BY created_at DESC LIMIT ?1
                    )",
                    params![keep_count],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(deleted)
        })
    }
}

// =============================================================================
// CONFIDENTIAL TRANSFER QUERIES
// =============================================================================

/// Maximum proof size: Groth16 proofs are exactly 192 bytes
pub const MAX_CONFIDENTIAL_PROOF_SIZE: usize = 192;

/// Maximum commitment/nullifier size: 32 bytes (BLS12-381 scalar field element)
pub const MAX_COMMITMENT_SIZE: usize = 32;

/// Confidential note record for query results
#[derive(Debug, Clone)]
pub struct ConfidentialNoteRecord {
    pub tree_index: u64,
    pub commitment: [u8; 32],
    pub owner_pubkey: [u8; 32],
    pub created_at_height: u64,
    pub spent_at_height: Option<u64>,
}

/// Confidential transfer record for persistence
#[derive(Debug, Clone)]
pub struct ConfidentialTransferRecord {
    pub transfer_id: String,
    pub block_height: Option<u64>,
    pub nullifier: [u8; 32],
    pub sender_new_commitment: [u8; 32],
    pub recipient_new_commitment: [u8; 32],
    pub old_commitment_root: [u8; 32],
    pub new_commitment_root: [u8; 32],
    pub proof: Vec<u8>,
    pub sender_index: u64,
    pub recipient_index: u64,
    pub status: String,
    pub encrypted_change: Option<Vec<u8>>,
    pub encrypted_recipient: Option<Vec<u8>>,
    pub epoch: u64,
}

impl Database {
    // =========================================================================
    // CONFIDENTIAL NOTES
    // =========================================================================

    /// Insert a confidential note (commitment tree leaf)
    pub fn insert_confidential_note(
        &self,
        index: u64,
        commitment: &[u8; 32],
        owner_pubkey: &[u8; 32],
        height: u64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO confidential_notes (tree_index, commitment, owner_pubkey, created_at_height)
                 VALUES (?1, ?2, ?3, ?4)",
                params![index as i64, commitment.as_slice(), owner_pubkey.as_slice(), height as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Mark a confidential note as spent at a given height
    pub fn mark_note_spent(&self, index: u64, height: u64) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE confidential_notes SET spent_at_height = ?1 WHERE tree_index = ?2",
                params![height as i64, index as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get all notes owned by a specific pubkey
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS to prevent OOM.
    pub fn get_notes_for_owner(
        &self,
        owner_pubkey: &[u8; 32],
    ) -> GhostResult<Vec<ConfidentialNoteRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT tree_index, commitment, owner_pubkey, created_at_height, spent_at_height
                     FROM confidential_notes WHERE owner_pubkey = ?1
                     ORDER BY tree_index ASC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(
                    params![owner_pubkey.as_slice(), Self::MAX_QUERY_RESULTS],
                    |row| {
                        let idx: i64 = row.get(0)?;
                        let commitment: Vec<u8> = row.get(1)?;
                        let owner: Vec<u8> = row.get(2)?;
                        let created_h: i64 = row.get(3)?;
                        let spent_h: Option<i64> = row.get(4)?;
                        Ok((idx, commitment, owner, created_h, spent_h))
                    },
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut notes = Vec::new();
            for row in rows {
                let (idx, commitment, owner, created_h, spent_h) =
                    row.map_err(|e| GhostError::Database(e.to_string()))?;

                let commitment: [u8; 32] = commitment.try_into().map_err(|_| {
                    GhostError::Database("Invalid commitment size in DB".to_string())
                })?;
                let owner_pk: [u8; 32] = owner.try_into().map_err(|_| {
                    GhostError::Database("Invalid owner pubkey size in DB".to_string())
                })?;

                notes.push(ConfidentialNoteRecord {
                    tree_index: i64_to_u64_sats(idx, "tree_index")
                        .map_err(|e| GhostError::Database(e.to_string()))?,
                    commitment,
                    owner_pubkey: owner_pk,
                    created_at_height: i64_to_u64_sats(created_h, "created_at_height")
                        .map_err(|e| GhostError::Database(e.to_string()))?,
                    spent_at_height: spent_h
                        .map(|h| {
                            i64_to_u64_sats(h, "spent_at_height")
                                .map_err(|e| GhostError::Database(e.to_string()))
                        })
                        .transpose()?,
                });
            }
            Ok(notes)
        })
    }

    /// Load all confidential notes for tree reconstruction
    ///
    /// Returns (tree_index, commitment) pairs ordered by index.
    pub fn load_all_confidential_notes(&self) -> GhostResult<Vec<(u64, [u8; 32])>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT tree_index, commitment FROM confidential_notes ORDER BY tree_index ASC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map([], |row| {
                    let idx: i64 = row.get(0)?;
                    let commitment: Vec<u8> = row.get(1)?;
                    Ok((idx, commitment))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut notes = Vec::new();
            for row in rows {
                let (idx, commitment) = row.map_err(|e| GhostError::Database(e.to_string()))?;
                let commitment: [u8; 32] = commitment.try_into().map_err(|_| {
                    GhostError::Database("Invalid commitment size in DB".to_string())
                })?;
                notes.push((
                    i64_to_u64_sats(idx, "tree_index")
                        .map_err(|e| GhostError::Database(e.to_string()))?,
                    commitment,
                ));
            }
            Ok(notes)
        })
    }

    /// Get the next available tree index (one past the highest existing)
    pub fn get_next_confidential_note_index(&self) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let result: Option<i64> = conn
                .query_row(
                    "SELECT MAX(tree_index) FROM confidential_notes",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
                .flatten();

            match result {
                Some(max_idx) => Ok(i64_to_u64_sats(max_idx, "max_tree_index")
                    .map_err(|e| GhostError::Database(e.to_string()))?
                    + 1),
                None => Ok(0),
            }
        })
    }

    // =========================================================================
    // NULLIFIERS
    // =========================================================================

    /// Insert a nullifier (marks a note as spent)
    pub fn insert_nullifier(
        &self,
        nullifier: &[u8; 32],
        height: u64,
        transfer_id: &str,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO nullifiers (nullifier, block_height, transfer_id) VALUES (?1, ?2, ?3)",
                params![nullifier.as_slice(), height as i64, transfer_id],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Check if a nullifier has already been spent
    pub fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM nullifiers WHERE nullifier = ?1",
                    params![nullifier.as_slice()],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count > 0)
        })
    }

    /// Load all nullifiers for in-memory set reconstruction
    pub fn load_all_nullifiers(&self) -> GhostResult<Vec<[u8; 32]>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare("SELECT nullifier FROM nullifiers")
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map([], |row| {
                    let nullifier: Vec<u8> = row.get(0)?;
                    Ok(nullifier)
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut nullifiers = Vec::new();
            for row in rows {
                let nullifier = row.map_err(|e| GhostError::Database(e.to_string()))?;
                let nullifier: [u8; 32] = nullifier.try_into().map_err(|_| {
                    GhostError::Database("Invalid nullifier size in DB".to_string())
                })?;
                nullifiers.push(nullifier);
            }
            Ok(nullifiers)
        })
    }

    /// Get count of nullifiers (for tree state reporting)
    pub fn get_nullifier_count(&self) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM nullifiers", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u64)
        })
    }

    /// Get nullifiers in a block height range (for settlement batch merkle root)
    pub fn get_nullifiers_in_range(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> GhostResult<Vec<[u8; 32]>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT nullifier FROM nullifiers
                     WHERE block_height >= ?1 AND block_height <= ?2
                     ORDER BY block_height ASC, created_at ASC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![start_height as i64, end_height as i64], |row| {
                    let nullifier: Vec<u8> = row.get(0)?;
                    Ok(nullifier)
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut nullifiers = Vec::new();
            for row in rows {
                let nullifier = row.map_err(|e| GhostError::Database(e.to_string()))?;
                let nullifier: [u8; 32] = nullifier.try_into().map_err(|_| {
                    GhostError::Database("Invalid nullifier size in DB".to_string())
                })?;
                nullifiers.push(nullifier);
            }
            Ok(nullifiers)
        })
    }

    // =========================================================================
    // CONFIDENTIAL TRANSFERS
    // =========================================================================

    /// Insert a confidential transfer record
    pub fn insert_confidential_transfer(
        &self,
        record: &ConfidentialTransferRecord,
    ) -> GhostResult<()> {
        if record.proof.len() > MAX_CONFIDENTIAL_PROOF_SIZE {
            return Err(GhostError::Database(format!(
                "Proof size {} exceeds maximum {}",
                record.proof.len(),
                MAX_CONFIDENTIAL_PROOF_SIZE
            )));
        }

        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO confidential_transfers
                 (transfer_id, block_height, nullifier, sender_new_commitment,
                  recipient_new_commitment, old_commitment_root, new_commitment_root,
                  proof, sender_index, recipient_index, status,
                  encrypted_change, encrypted_recipient, epoch)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                params![
                    record.transfer_id,
                    record.block_height.map(|h| h as i64),
                    record.nullifier.as_slice(),
                    record.sender_new_commitment.as_slice(),
                    record.recipient_new_commitment.as_slice(),
                    record.old_commitment_root.as_slice(),
                    record.new_commitment_root.as_slice(),
                    record.proof.as_slice(),
                    record.sender_index as i64,
                    record.recipient_index as i64,
                    record.status,
                    record.encrypted_change.as_deref(),
                    record.encrypted_recipient.as_deref(),
                    record.epoch as i64,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update confidential transfer status and optionally set block height
    pub fn update_confidential_transfer_status(
        &self,
        transfer_id: &str,
        status: &str,
        block_height: Option<u64>,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            match block_height {
                Some(h) => conn.execute(
                    "UPDATE confidential_transfers SET status = ?1, block_height = ?2
                         WHERE transfer_id = ?3",
                    params![status, h as i64, transfer_id],
                ),
                None => conn.execute(
                    "UPDATE confidential_transfers SET status = ?1 WHERE transfer_id = ?2",
                    params![status, transfer_id],
                ),
            }
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get recent confidential transfers with encrypted fields for wallet scanning.
    ///
    /// Returns transfers at block_height > since_height, capped at 1000 results.
    pub fn get_recent_confidential_transfers(
        &self,
        since_height: u64,
    ) -> GhostResult<Vec<ConfidentialTransferRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT transfer_id, block_height, nullifier, sender_new_commitment,
                            recipient_new_commitment, old_commitment_root, new_commitment_root,
                            proof, sender_index, recipient_index, status,
                            encrypted_change, encrypted_recipient, epoch
                     FROM confidential_transfers
                     WHERE block_height > ?1 AND status = 'confirmed'
                     ORDER BY block_height ASC
                     LIMIT 1000",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![since_height as i64], |row| {
                    let transfer_id: String = row.get(0)?;
                    let block_height: Option<i64> = row.get(1)?;
                    let nullifier: Vec<u8> = row.get(2)?;
                    let sender_new: Vec<u8> = row.get(3)?;
                    let recipient_new: Vec<u8> = row.get(4)?;
                    let old_root: Vec<u8> = row.get(5)?;
                    let new_root: Vec<u8> = row.get(6)?;
                    let proof: Vec<u8> = row.get(7)?;
                    let sender_idx: i64 = row.get(8)?;
                    let recipient_idx: i64 = row.get(9)?;
                    let status: String = row.get(10)?;
                    let encrypted_change: Option<Vec<u8>> = row.get(11)?;
                    let encrypted_recipient: Option<Vec<u8>> = row.get(12)?;
                    let epoch: i64 = row.get::<_, Option<i64>>(13)?.unwrap_or(0);
                    Ok((
                        transfer_id,
                        block_height,
                        nullifier,
                        sender_new,
                        recipient_new,
                        old_root,
                        new_root,
                        proof,
                        sender_idx,
                        recipient_idx,
                        status,
                        encrypted_change,
                        encrypted_recipient,
                        epoch,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut transfers = Vec::new();
            for row in rows {
                let (
                    transfer_id,
                    block_height,
                    nullifier,
                    sender_new,
                    recipient_new,
                    old_root,
                    new_root,
                    proof,
                    sender_idx,
                    recipient_idx,
                    status,
                    encrypted_change,
                    encrypted_recipient,
                    epoch,
                ) = row.map_err(|e| GhostError::Database(e.to_string()))?;

                let to_32 = |v: Vec<u8>, name: &str| -> GhostResult<[u8; 32]> {
                    v.try_into()
                        .map_err(|_| GhostError::Database(format!("Invalid {} size in DB", name)))
                };

                transfers.push(ConfidentialTransferRecord {
                    transfer_id,
                    block_height: block_height.map(|h| h as u64),
                    nullifier: to_32(nullifier, "nullifier")?,
                    sender_new_commitment: to_32(sender_new, "sender_commitment")?,
                    recipient_new_commitment: to_32(recipient_new, "recipient_commitment")?,
                    old_commitment_root: to_32(old_root, "old_root")?,
                    new_commitment_root: to_32(new_root, "new_root")?,
                    proof,
                    sender_index: sender_idx as u64,
                    recipient_index: recipient_idx as u64,
                    status,
                    encrypted_change,
                    encrypted_recipient,
                    epoch: epoch as u64,
                });
            }
            Ok(transfers)
        })
    }

    /// Get count of confidential notes (for tree state reporting)
    pub fn get_confidential_note_count(&self) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM confidential_notes", [], |row| {
                    row.get(0)
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u64)
        })
    }
}

// =============================================================================
// L2 NOTE/UTXO MODEL — Record Types
// =============================================================================

/// L2 note record (commitment tree leaf, epoch-scoped)
#[derive(Debug, Clone)]
pub struct L2NoteRecord {
    pub note_index: u64,
    pub epoch: u64,
    pub commitment: [u8; 32],
    pub block_height: u64,
    pub spent: bool,
}

/// L2 nullifier record (epoch-scoped double-spend prevention)
#[derive(Debug, Clone)]
pub struct L2NullifierRecord {
    pub nullifier: [u8; 32],
    pub epoch: u64,
    pub block_height: u64,
}

/// L2 checkpoint block record
#[derive(Debug, Clone)]
pub struct L2CheckpointRecord {
    pub height: u64,
    pub epoch: u64,
    pub commitment_root: [u8; 32],
    pub tx_count: u32,
    pub proposer_id: String,
    pub active_node_count: u32,
    pub block_data: Vec<u8>,
}

/// L2 epoch record (lifecycle and compaction state)
#[derive(Debug, Clone)]
pub struct L2EpochRecord {
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: Option<u64>,
    pub initial_root: [u8; 32],
    pub final_root: Option<[u8; 32]>,
    pub notes_migrated: u64,
    pub status: String,
}

/// L2 valid root record (recent finalized roots for proof validation)
#[derive(Debug, Clone)]
pub struct L2ValidRootRecord {
    pub height: u64,
    pub epoch: u64,
    pub commitment_root: [u8; 32],
}

impl Database {
    // =========================================================================
    // L2 NOTES (EPOCH-SCOPED COMMITMENT TREE)
    // =========================================================================

    /// Insert an L2 note (commitment tree leaf)
    pub fn insert_l2_note(
        &self,
        epoch: u64,
        note_index: u64,
        commitment: &[u8; 32],
        block_height: u64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO l2_notes (note_index, epoch, commitment, block_height)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    note_index as i64,
                    epoch as i64,
                    commitment.as_slice(),
                    block_height as i64
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Mark an L2 note as spent
    pub fn mark_l2_note_spent(&self, epoch: u64, note_index: u64) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE l2_notes SET spent = 1 WHERE epoch = ?1 AND note_index = ?2",
                params![epoch as i64, note_index as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Load all unspent notes for an epoch (for tree compaction)
    ///
    /// H-7: Limited to MAX_QUERY_RESULTS to prevent OOM.
    pub fn load_unspent_l2_notes(&self, epoch: u64) -> GhostResult<Vec<L2NoteRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT note_index, epoch, commitment, block_height
                     FROM l2_notes WHERE epoch = ?1 AND spent = 0
                     ORDER BY note_index ASC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![epoch as i64, Self::MAX_QUERY_RESULTS], |row| {
                    let idx: i64 = row.get(0)?;
                    let ep: i64 = row.get(1)?;
                    let commitment: Vec<u8> = row.get(2)?;
                    let height: i64 = row.get(3)?;
                    Ok((idx, ep, commitment, height))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut notes = Vec::new();
            for row in rows {
                let (idx, ep, commitment, height) =
                    row.map_err(|e| GhostError::Database(e.to_string()))?;
                let commitment: [u8; 32] = commitment.try_into().map_err(|_| {
                    GhostError::Database("Invalid commitment size in l2_notes".to_string())
                })?;
                notes.push(L2NoteRecord {
                    note_index: i64_to_u64_sats(idx, "note_index")
                        .map_err(|e| GhostError::Database(e.to_string()))?,
                    epoch: i64_to_u64_sats(ep, "epoch")
                        .map_err(|e| GhostError::Database(e.to_string()))?,
                    commitment,
                    block_height: i64_to_u64_sats(height, "block_height")
                        .map_err(|e| GhostError::Database(e.to_string()))?,
                    spent: false,
                });
            }
            Ok(notes)
        })
    }

    /// Load all notes for an epoch (for tree reconstruction)
    ///
    /// Returns (note_index, commitment) pairs ordered by index.
    pub fn load_all_l2_notes_for_epoch(&self, epoch: u64) -> GhostResult<Vec<(u64, [u8; 32])>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT note_index, commitment FROM l2_notes
                     WHERE epoch = ?1 ORDER BY note_index ASC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![epoch as i64], |row| {
                    let idx: i64 = row.get(0)?;
                    let commitment: Vec<u8> = row.get(1)?;
                    Ok((idx, commitment))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut notes = Vec::new();
            for row in rows {
                let (idx, commitment) = row.map_err(|e| GhostError::Database(e.to_string()))?;
                let commitment: [u8; 32] = commitment.try_into().map_err(|_| {
                    GhostError::Database("Invalid commitment size in l2_notes".to_string())
                })?;
                notes.push((
                    i64_to_u64_sats(idx, "note_index")
                        .map_err(|e| GhostError::Database(e.to_string()))?,
                    commitment,
                ));
            }
            Ok(notes)
        })
    }

    /// Get the next available note index for an epoch
    pub fn get_next_l2_note_index(&self, epoch: u64) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let result: Option<i64> = conn
                .query_row(
                    "SELECT MAX(note_index) FROM l2_notes WHERE epoch = ?1",
                    params![epoch as i64],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?
                .flatten();

            match result {
                Some(max_idx) => Ok(i64_to_u64_sats(max_idx, "max_note_index")
                    .map_err(|e| GhostError::Database(e.to_string()))?
                    + 1),
                None => Ok(0),
            }
        })
    }

    /// Get count of L2 notes for an epoch
    pub fn get_l2_note_count(&self, epoch: u64) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM l2_notes WHERE epoch = ?1",
                    params![epoch as i64],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u64)
        })
    }

    /// Delete L2 notes with note_index above a threshold for a given epoch.
    /// Used during phantom note pruning to remove notes not included in any checkpoint.
    pub fn delete_l2_notes_above_index(&self, epoch: u64, max_index: u64) -> GhostResult<usize> {
        self.with_connection(|conn| {
            let deleted = conn
                .execute(
                    "DELETE FROM l2_notes WHERE epoch = ?1 AND note_index > ?2",
                    params![epoch as i64, max_index as i64],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(deleted)
        })
    }

    /// Delete pending shields that have already been finalized in l2_notes.
    /// Once a shield's note_index appears in l2_notes, it's been included in a
    /// checkpoint and no longer needs to be in the staging table.
    pub fn delete_stale_pending_shields(&self) -> GhostResult<usize> {
        self.with_connection(|conn| {
            let deleted = conn
                .execute(
                    "DELETE FROM pending_l2_shields WHERE note_index IN (SELECT note_index FROM l2_notes)",
                    [],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(deleted)
        })
    }

    // =========================================================================
    // L2 NULLIFIERS (EPOCH-SCOPED)
    // =========================================================================

    /// Insert an L2 nullifier (marks a note as spent within an epoch)
    pub fn insert_l2_nullifier(
        &self,
        nullifier: &[u8; 32],
        epoch: u64,
        block_height: u64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO l2_nullifiers (nullifier, epoch, block_height) VALUES (?1, ?2, ?3)",
                params![nullifier.as_slice(), epoch as i64, block_height as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Check if an L2 nullifier has been spent in a given epoch
    pub fn is_l2_nullifier_spent(&self, nullifier: &[u8; 32], epoch: u64) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM l2_nullifiers WHERE nullifier = ?1 AND epoch = ?2",
                    params![nullifier.as_slice(), epoch as i64],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count > 0)
        })
    }

    /// Load all L2 nullifiers for an epoch (for in-memory set reconstruction)
    pub fn load_l2_nullifiers_for_epoch(&self, epoch: u64) -> GhostResult<Vec<[u8; 32]>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare("SELECT nullifier FROM l2_nullifiers WHERE epoch = ?1")
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![epoch as i64], |row| {
                    let nullifier: Vec<u8> = row.get(0)?;
                    Ok(nullifier)
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut nullifiers = Vec::new();
            for row in rows {
                let nullifier = row.map_err(|e| GhostError::Database(e.to_string()))?;
                let nullifier: [u8; 32] = nullifier.try_into().map_err(|_| {
                    GhostError::Database("Invalid nullifier size in l2_nullifiers".to_string())
                })?;
                nullifiers.push(nullifier);
            }
            Ok(nullifiers)
        })
    }

    /// Get count of L2 nullifiers for an epoch
    pub fn get_l2_nullifier_count(&self, epoch: u64) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM l2_nullifiers WHERE epoch = ?1",
                    params![epoch as i64],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u64)
        })
    }

    /// Delete all L2 nullifiers for an epoch (during epoch compaction)
    pub fn delete_l2_nullifiers_for_epoch(&self, epoch: u64) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let deleted = conn
                .execute(
                    "DELETE FROM l2_nullifiers WHERE epoch = ?1",
                    params![epoch as i64],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(deleted as u64)
        })
    }

    // =========================================================================
    // PENDING NULLIFIERS (WRITE-AHEAD LOG)
    // =========================================================================

    /// Insert a pending nullifier (write-ahead for crash recovery)
    pub fn insert_pending_nullifier(
        &self,
        nullifier: &[u8; 32],
        epoch: u64,
        block_height: u64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO pending_nullifiers (nullifier, epoch, spent_at) VALUES (?1, ?2, ?3)",
                params![nullifier.as_slice(), epoch as i64, block_height as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Load all pending nullifiers (for crash recovery at startup)
    pub fn load_pending_nullifiers(&self) -> GhostResult<Vec<([u8; 32], u64, u64)>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare("SELECT nullifier, epoch, spent_at FROM pending_nullifiers")
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map([], |row| {
                    let nullifier: Vec<u8> = row.get(0)?;
                    let epoch: i64 = row.get(1)?;
                    let spent_at: i64 = row.get(2)?;
                    Ok((nullifier, epoch as u64, spent_at as u64))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut result = Vec::new();
            for row in rows {
                let (nullifier_vec, epoch, spent_at) =
                    row.map_err(|e| GhostError::Database(e.to_string()))?;
                let nullifier: [u8; 32] = nullifier_vec.try_into().map_err(|_| {
                    GhostError::Database("Invalid nullifier size in pending_nullifiers".to_string())
                })?;
                result.push((nullifier, epoch, spent_at));
            }
            Ok(result)
        })
    }

    /// Confirm pending nullifiers: move to l2_nullifiers and clear pending table.
    /// Called during checkpoint finalization.
    pub fn confirm_pending_nullifiers(&self) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM pending_nullifiers", [], |row| {
                    row.get(0)
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if count == 0 {
                return Ok(0);
            }

            conn.execute_batch(
                "BEGIN;
                 INSERT OR IGNORE INTO l2_nullifiers (nullifier, epoch, block_height)
                 SELECT nullifier, epoch, spent_at FROM pending_nullifiers;
                 DELETE FROM pending_nullifiers;
                 COMMIT;",
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(count as u64)
        })
    }

    // =========================================================================
    // PENDING L2 SHIELDS (staging for checkpoint inclusion)
    // =========================================================================

    /// Insert a pending shield commitment into the staging table.
    /// Called by sync_commitment() so shields survive restarts.
    pub fn insert_pending_shield(
        &self,
        note_index: u64,
        commitment: &[u8; 32],
        block_height: u64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO pending_l2_shields (note_index, commitment, block_height)
                 VALUES (?1, ?2, ?3)",
                params![
                    note_index as i64,
                    commitment.as_slice(),
                    block_height as i64
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Load all pending shield commitments (for restart recovery).
    pub fn load_pending_shields(&self) -> GhostResult<Vec<(u64, [u8; 32], u64)>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT note_index, commitment, block_height FROM pending_l2_shields
                     ORDER BY note_index ASC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map([], |row| {
                    let idx: i64 = row.get(0)?;
                    let commitment: Vec<u8> = row.get(1)?;
                    let height: i64 = row.get(2)?;
                    Ok((idx, commitment, height))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut result = Vec::new();
            for row in rows {
                let (idx, commitment_vec, height) =
                    row.map_err(|e| GhostError::Database(e.to_string()))?;
                let commitment: [u8; 32] = commitment_vec.try_into().map_err(|_| {
                    GhostError::Database(
                        "Invalid commitment size in pending_l2_shields".to_string(),
                    )
                })?;
                result.push((idx as u64, commitment, height as u64));
            }
            Ok(result)
        })
    }

    /// Delete finalized shield commitments from the staging table.
    /// Called during finalize_checkpoint() after shields are BFT-confirmed.
    pub fn delete_pending_shields(&self, note_indices: &[u64]) -> GhostResult<()> {
        if note_indices.is_empty() {
            return Ok(());
        }
        self.with_connection(|conn| {
            let placeholders: Vec<String> = note_indices.iter().map(|_| "?".to_string()).collect();
            let sql = format!(
                "DELETE FROM pending_l2_shields WHERE note_index IN ({})",
                placeholders.join(",")
            );
            let params: Vec<Box<dyn rusqlite::types::ToSql>> = note_indices
                .iter()
                .map(|idx| Box::new(*idx as i64) as Box<dyn rusqlite::types::ToSql>)
                .collect();
            conn.execute(
                &sql,
                rusqlite::params_from_iter(params.iter().map(|b| b.as_ref())),
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    // =========================================================================
    // CONFIRMED POOL STAGING (crash recovery for verified L2 transactions)
    // =========================================================================

    /// Insert a confirmed transaction into the staging table.
    /// Called when a ZK-verified transaction is added to the confirmed pool.
    pub fn insert_confirmed_pool_tx(
        &self,
        nullifier: &[u8; 32],
        tx_data: &[u8],
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO confirmed_pool_staging (nullifier, tx_data, added_at)
                 VALUES (?1, ?2, ?3)",
                params![
                    nullifier.as_slice(),
                    tx_data,
                    chrono::Utc::now().timestamp()
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Load all confirmed pool transactions from staging (for restart recovery).
    pub fn load_confirmed_pool_staging(&self) -> GhostResult<Vec<(Vec<u8>, Vec<u8>)>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT nullifier, tx_data FROM confirmed_pool_staging
                     ORDER BY added_at ASC",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map([], |row| {
                    let nullifier: Vec<u8> = row.get(0)?;
                    let tx_data: Vec<u8> = row.get(1)?;
                    Ok((nullifier, tx_data))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| GhostError::Database(e.to_string()))?);
            }
            Ok(result)
        })
    }

    /// Delete finalized transactions from the confirmed pool staging table.
    /// Called during finalize_checkpoint() after transactions are BFT-confirmed.
    pub fn delete_confirmed_pool_txs(&self, nullifiers: &[[u8; 32]]) -> GhostResult<()> {
        if nullifiers.is_empty() {
            return Ok(());
        }
        self.with_connection(|conn| {
            let placeholders: Vec<String> = nullifiers.iter().map(|_| "?".to_string()).collect();
            let sql = format!(
                "DELETE FROM confirmed_pool_staging WHERE nullifier IN ({})",
                placeholders.join(",")
            );
            let params: Vec<Box<dyn rusqlite::types::ToSql>> = nullifiers
                .iter()
                .map(|n| Box::new(n.to_vec()) as Box<dyn rusqlite::types::ToSql>)
                .collect();
            conn.execute(
                &sql,
                rusqlite::params_from_iter(params.iter().map(|b| b.as_ref())),
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Clear the entire confirmed pool staging table.
    pub fn clear_confirmed_pool_staging(&self) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute("DELETE FROM confirmed_pool_staging", [])
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    // =========================================================================
    // L2 CHECKPOINTS
    // =========================================================================

    /// Insert an L2 checkpoint block
    pub fn insert_l2_checkpoint(&self, record: &L2CheckpointRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO l2_checkpoints
                 (height, epoch, commitment_root, tx_count, proposer_id, active_node_count, block_data)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    record.height as i64,
                    record.epoch as i64,
                    record.commitment_root.as_slice(),
                    record.tx_count as i64,
                    record.proposer_id,
                    record.active_node_count as i64,
                    record.block_data.as_slice(),
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Atomically persist checkpoint data: nullifiers + checkpoint record in a single transaction.
    ///
    /// If the process crashes mid-write, the entire checkpoint is rolled back (no partial state).
    /// On restart, in-memory state can be re-derived from last persisted checkpoint.
    pub fn persist_l2_checkpoint_atomic(
        &self,
        record: &L2CheckpointRecord,
        nullifiers: &[([u8; 32], u64, u64)], // (nullifier, epoch, block_height)
    ) -> GhostResult<()> {
        self.transaction(|tx| {
            // Persist all nullifiers from this checkpoint's transactions
            for (nullifier, epoch, block_height) in nullifiers {
                tx.execute(
                    "INSERT OR IGNORE INTO l2_nullifiers (nullifier, epoch, block_height) VALUES (?1, ?2, ?3)",
                    params![nullifier.as_slice(), *epoch as i64, *block_height as i64],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            }

            // Persist checkpoint record
            tx.execute(
                "INSERT INTO l2_checkpoints
                 (height, epoch, commitment_root, tx_count, proposer_id, active_node_count, block_data)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    record.height as i64,
                    record.epoch as i64,
                    record.commitment_root.as_slice(),
                    record.tx_count as i64,
                    record.proposer_id,
                    record.active_node_count as i64,
                    record.block_data.as_slice(),
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(())
        })
    }

    /// Upsert an L2 checkpoint (idempotent via INSERT OR REPLACE).
    ///
    /// Used by tree sync to persist replayed checkpoints without failing on
    /// duplicate heights (unlike `persist_l2_checkpoint_atomic` which uses INSERT).
    pub fn upsert_l2_checkpoint(&self, record: &L2CheckpointRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO l2_checkpoints
                 (height, epoch, commitment_root, tx_count, proposer_id, active_node_count, block_data)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    record.height as i64,
                    record.epoch as i64,
                    record.commitment_root.as_slice(),
                    record.tx_count as i64,
                    record.proposer_id,
                    record.active_node_count as i64,
                    record.block_data.as_slice(),
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get the latest L2 checkpoint
    pub fn get_latest_l2_checkpoint(&self) -> GhostResult<Option<L2CheckpointRecord>> {
        self.with_connection(|conn| {
            let result = conn
                .query_row(
                    "SELECT height, epoch, commitment_root, tx_count, proposer_id,
                            active_node_count, block_data
                     FROM l2_checkpoints ORDER BY height DESC LIMIT 1",
                    [],
                    |row| {
                        let height: i64 = row.get(0)?;
                        let epoch: i64 = row.get(1)?;
                        let commitment_root: Vec<u8> = row.get(2)?;
                        let tx_count: i64 = row.get(3)?;
                        let proposer_id: String = row.get(4)?;
                        let active_node_count: i64 = row.get(5)?;
                        let block_data: Vec<u8> = row.get(6)?;
                        Ok((
                            height,
                            epoch,
                            commitment_root,
                            tx_count,
                            proposer_id,
                            active_node_count,
                            block_data,
                        ))
                    },
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some((
                    height,
                    epoch,
                    commitment_root,
                    tx_count,
                    proposer_id,
                    active_node_count,
                    block_data,
                )) => {
                    let commitment_root: [u8; 32] = commitment_root.try_into().map_err(|_| {
                        GhostError::Database(
                            "Invalid commitment_root size in l2_checkpoints".to_string(),
                        )
                    })?;
                    Ok(Some(L2CheckpointRecord {
                        height: i64_to_u64_sats(height, "height")
                            .map_err(|e| GhostError::Database(e.to_string()))?,
                        epoch: i64_to_u64_sats(epoch, "epoch")
                            .map_err(|e| GhostError::Database(e.to_string()))?,
                        commitment_root,
                        tx_count: tx_count as u32,
                        proposer_id,
                        active_node_count: active_node_count as u32,
                        block_data,
                    }))
                }
                None => Ok(None),
            }
        })
    }

    /// Get L2 checkpoint at a specific height
    pub fn get_l2_checkpoint(&self, height: u64) -> GhostResult<Option<L2CheckpointRecord>> {
        self.with_connection(|conn| {
            let result = conn
                .query_row(
                    "SELECT height, epoch, commitment_root, tx_count, proposer_id,
                            active_node_count, block_data
                     FROM l2_checkpoints WHERE height = ?1",
                    params![height as i64],
                    |row| {
                        let h: i64 = row.get(0)?;
                        let epoch: i64 = row.get(1)?;
                        let commitment_root: Vec<u8> = row.get(2)?;
                        let tx_count: i64 = row.get(3)?;
                        let proposer_id: String = row.get(4)?;
                        let active_node_count: i64 = row.get(5)?;
                        let block_data: Vec<u8> = row.get(6)?;
                        Ok((
                            h,
                            epoch,
                            commitment_root,
                            tx_count,
                            proposer_id,
                            active_node_count,
                            block_data,
                        ))
                    },
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some((
                    h,
                    epoch,
                    commitment_root,
                    tx_count,
                    proposer_id,
                    active_node_count,
                    block_data,
                )) => {
                    let commitment_root: [u8; 32] = commitment_root.try_into().map_err(|_| {
                        GhostError::Database(
                            "Invalid commitment_root size in l2_checkpoints".to_string(),
                        )
                    })?;
                    Ok(Some(L2CheckpointRecord {
                        height: i64_to_u64_sats(h, "height")
                            .map_err(|e| GhostError::Database(e.to_string()))?,
                        epoch: i64_to_u64_sats(epoch, "epoch")
                            .map_err(|e| GhostError::Database(e.to_string()))?,
                        commitment_root,
                        tx_count: tx_count as u32,
                        proposer_id,
                        active_node_count: active_node_count as u32,
                        block_data,
                    }))
                }
                None => Ok(None),
            }
        })
    }

    /// Count L2 notes in a given epoch
    pub fn count_l2_notes_in_epoch(&self, epoch: u64) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM l2_notes WHERE epoch = ?1",
                    params![epoch as i64],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u64)
        })
    }

    /// Count all recent L2 checkpoints (consensus rounds finalized).
    /// Looks back `lookback` checkpoints from the maximum height.
    pub fn count_recent_l2_finalizations(&self, lookback: u64) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM l2_checkpoints
                     WHERE height > (SELECT COALESCE(MAX(height), 0) - ?1 FROM l2_checkpoints)",
                    params![lookback as i64],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u64)
        })
    }

    /// Count recent L2 checkpoints with tx_count > 0 (active finalizations with L2 activity).
    /// Looks back `lookback` checkpoints from the maximum height.
    pub fn count_recent_active_l2_finalizations(&self, lookback: u64) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM l2_checkpoints
                     WHERE tx_count > 0
                     AND height > (SELECT COALESCE(MAX(height), 0) - ?1 FROM l2_checkpoints)",
                    params![lookback as i64],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count as u64)
        })
    }

    /// Get L2 checkpoints starting from a given height (for tree sync)
    pub fn get_l2_checkpoints_from_height(
        &self,
        from_height: u64,
        limit: u64,
    ) -> GhostResult<Vec<L2CheckpointRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT height, epoch, commitment_root, tx_count, proposer_id,
                            active_node_count, block_data
                     FROM l2_checkpoints WHERE height >= ?1
                     ORDER BY height ASC LIMIT ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![from_height as i64, limit as i64], |row| {
                    let h: i64 = row.get(0)?;
                    let epoch: i64 = row.get(1)?;
                    let commitment_root: Vec<u8> = row.get(2)?;
                    let tx_count: i64 = row.get(3)?;
                    let proposer_id: String = row.get(4)?;
                    let active_node_count: i64 = row.get(5)?;
                    let block_data: Vec<u8> = row.get(6)?;
                    Ok((
                        h,
                        epoch,
                        commitment_root,
                        tx_count,
                        proposer_id,
                        active_node_count,
                        block_data,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut records = Vec::new();
            for row in rows {
                let (
                    h,
                    epoch,
                    commitment_root,
                    tx_count,
                    proposer_id,
                    active_node_count,
                    block_data,
                ) = row.map_err(|e| GhostError::Database(e.to_string()))?;
                let commitment_root: [u8; 32] = commitment_root.try_into().map_err(|_| {
                    GhostError::Database(
                        "Invalid commitment_root size in l2_checkpoints".to_string(),
                    )
                })?;
                records.push(L2CheckpointRecord {
                    height: i64_to_u64_sats(h, "height")
                        .map_err(|e| GhostError::Database(e.to_string()))?,
                    epoch: i64_to_u64_sats(epoch, "epoch")
                        .map_err(|e| GhostError::Database(e.to_string()))?,
                    commitment_root,
                    tx_count: tx_count as u32,
                    proposer_id,
                    active_node_count: active_node_count as u32,
                    block_data,
                });
            }
            Ok(records)
        })
    }

    // =========================================================================
    // L2 EPOCHS
    // =========================================================================

    /// Insert a new L2 epoch
    pub fn insert_l2_epoch(&self, record: &L2EpochRecord) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO l2_epochs (epoch, start_height, end_height, initial_root, final_root, notes_migrated, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    record.epoch as i64,
                    record.start_height as i64,
                    record.end_height.map(|h| h as i64),
                    record.initial_root.as_slice(),
                    record.final_root.as_ref().map(|r| r.as_slice()),
                    record.notes_migrated as i64,
                    record.status,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get the current (active) L2 epoch
    pub fn get_active_l2_epoch(&self) -> GhostResult<Option<L2EpochRecord>> {
        self.with_connection(|conn| {
            let result = conn
                .query_row(
                    "SELECT epoch, start_height, end_height, initial_root, final_root,
                            notes_migrated, status
                     FROM l2_epochs WHERE status = 'active' ORDER BY epoch DESC LIMIT 1",
                    [],
                    l2_epoch_from_row,
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some(tuple) => l2_epoch_record_from_tuple(tuple).map(Some),
                None => Ok(None),
            }
        })
    }

    /// Get an L2 epoch by number
    pub fn get_l2_epoch(&self, epoch: u64) -> GhostResult<Option<L2EpochRecord>> {
        self.with_connection(|conn| {
            let result = conn
                .query_row(
                    "SELECT epoch, start_height, end_height, initial_root, final_root,
                            notes_migrated, status
                     FROM l2_epochs WHERE epoch = ?1",
                    params![epoch as i64],
                    l2_epoch_from_row,
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match result {
                Some(tuple) => l2_epoch_record_from_tuple(tuple).map(Some),
                None => Ok(None),
            }
        })
    }

    /// Finalize an L2 epoch (set end_height, final_root, notes_migrated, status)
    pub fn finalize_l2_epoch(
        &self,
        epoch: u64,
        end_height: u64,
        final_root: &[u8; 32],
        notes_migrated: u64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE l2_epochs SET end_height = ?1, final_root = ?2, notes_migrated = ?3, status = 'archived'
                 WHERE epoch = ?4",
                params![
                    end_height as i64,
                    final_root.as_slice(),
                    notes_migrated as i64,
                    epoch as i64,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Update the initial_root of an L2 epoch (used during epoch transition
    /// when the epoch record is created before the tree is fully built)
    pub fn update_l2_epoch_initial_root(
        &self,
        epoch: u64,
        initial_root: &[u8; 32],
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE l2_epochs SET initial_root = ?1 WHERE epoch = ?2",
                params![initial_root.as_slice(), epoch as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    // =========================================================================
    // L2 VALID ROOTS
    // =========================================================================

    /// Insert a valid commitment root at a given checkpoint height
    pub fn insert_l2_valid_root(
        &self,
        height: u64,
        epoch: u64,
        commitment_root: &[u8; 32],
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO l2_valid_roots (height, epoch, commitment_root)
                 VALUES (?1, ?2, ?3)",
                params![height as i64, epoch as i64, commitment_root.as_slice()],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Check if a commitment root is valid (exists in recent valid roots)
    pub fn is_l2_root_valid(&self, commitment_root: &[u8; 32]) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM l2_valid_roots WHERE commitment_root = ?1",
                    params![commitment_root.as_slice()],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count > 0)
        })
    }

    /// Get all valid roots (for both epochs during transition window)
    pub fn get_l2_valid_roots(&self) -> GhostResult<Vec<L2ValidRootRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT height, epoch, commitment_root FROM l2_valid_roots
                     ORDER BY height DESC LIMIT ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map(params![Self::MAX_QUERY_RESULTS], |row| {
                    let height: i64 = row.get(0)?;
                    let epoch: i64 = row.get(1)?;
                    let commitment_root: Vec<u8> = row.get(2)?;
                    Ok((height, epoch, commitment_root))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut roots = Vec::new();
            for row in rows {
                let (height, epoch, commitment_root) =
                    row.map_err(|e| GhostError::Database(e.to_string()))?;
                let commitment_root: [u8; 32] = commitment_root.try_into().map_err(|_| {
                    GhostError::Database(
                        "Invalid commitment_root size in l2_valid_roots".to_string(),
                    )
                })?;
                roots.push(L2ValidRootRecord {
                    height: i64_to_u64_sats(height, "height")
                        .map_err(|e| GhostError::Database(e.to_string()))?,
                    epoch: i64_to_u64_sats(epoch, "epoch")
                        .map_err(|e| GhostError::Database(e.to_string()))?,
                    commitment_root,
                });
            }
            Ok(roots)
        })
    }

    /// Prune old valid roots, keeping only the most recent N
    pub fn prune_l2_valid_roots(&self, keep_count: u64) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let deleted = conn
                .execute(
                    "DELETE FROM l2_valid_roots WHERE height NOT IN (
                         SELECT height FROM l2_valid_roots ORDER BY height DESC LIMIT ?1
                     )",
                    params![keep_count as i64],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(deleted as u64)
        })
    }
}

/// Raw row data from l2_epochs table before conversion to L2EpochRecord
type L2EpochRowTuple = (i64, i64, Option<i64>, Vec<u8>, Option<Vec<u8>>, i64, String);

/// Helper: parse an l2_epochs row into a tuple
fn l2_epoch_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<L2EpochRowTuple> {
    let epoch: i64 = row.get(0)?;
    let start_height: i64 = row.get(1)?;
    let end_height: Option<i64> = row.get(2)?;
    let initial_root: Vec<u8> = row.get(3)?;
    let final_root: Option<Vec<u8>> = row.get(4)?;
    let notes_migrated: i64 = row.get(5)?;
    let status: String = row.get(6)?;
    Ok((
        epoch,
        start_height,
        end_height,
        initial_root,
        final_root,
        notes_migrated,
        status,
    ))
}

/// Helper: convert l2_epochs tuple to L2EpochRecord
fn l2_epoch_record_from_tuple(tuple: L2EpochRowTuple) -> GhostResult<L2EpochRecord> {
    let (epoch, start_height, end_height, initial_root, final_root, notes_migrated, status) = tuple;

    let initial_root: [u8; 32] = initial_root
        .try_into()
        .map_err(|_| GhostError::Database("Invalid initial_root size in l2_epochs".to_string()))?;

    let final_root = final_root
        .map(|r| {
            r.try_into().map_err(|_| {
                GhostError::Database("Invalid final_root size in l2_epochs".to_string())
            })
        })
        .transpose()?;

    Ok(L2EpochRecord {
        epoch: i64_to_u64_sats(epoch, "epoch").map_err(|e| GhostError::Database(e.to_string()))?,
        start_height: i64_to_u64_sats(start_height, "start_height")
            .map_err(|e| GhostError::Database(e.to_string()))?,
        end_height: end_height
            .map(|h| {
                i64_to_u64_sats(h, "end_height").map_err(|e| GhostError::Database(e.to_string()))
            })
            .transpose()?,
        initial_root,
        final_root,
        notes_migrated: i64_to_u64_sats(notes_migrated, "notes_migrated")
            .map_err(|e| GhostError::Database(e.to_string()))?,
        status,
    })
}

// =============================================================================
// GhostGlyph Registry Queries
// =============================================================================

/// A glyph record from the ghost_glyph_registry table
#[derive(Debug, Clone)]
pub struct GlyphRecord {
    pub ghost_id: String,
    pub pixels: Vec<u8>,
    pub bitmap_hash: Vec<u8>,
    pub commitment: Vec<u8>,
    pub funding_txid: Option<String>,
    pub registered_at: Option<u64>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

impl Database {
    /// Insert a pending glyph claim.
    ///
    /// Returns error if ghost_id already claimed or bitmap_hash already taken.
    /// Claim expiry: 24 hours from creation.
    const GLYPH_CLAIM_TTL_SECS: u64 = 86400;

    pub fn insert_glyph_claim(
        &self,
        ghost_id: &str,
        pixels: &[u8],
        bitmap_hash: &[u8],
        commitment: &[u8],
        created_at: u64,
    ) -> GhostResult<()> {
        // L-4: Exact size validation for glyph blobs
        if pixels.len() != 256 {
            return Err(GhostError::Database(format!(
                "glyph pixels must be exactly 256 bytes, got {}",
                pixels.len()
            )));
        }
        if bitmap_hash.len() != 32 {
            return Err(GhostError::Database(format!(
                "glyph bitmap_hash must be exactly 32 bytes, got {}",
                bitmap_hash.len()
            )));
        }
        if commitment.len() != 32 {
            return Err(GhostError::Database(format!(
                "glyph commitment must be exactly 32 bytes, got {}",
                commitment.len()
            )));
        }

        let expires_at = created_at + Self::GLYPH_CLAIM_TTL_SECS;

        self.with_connection_retry("insert_glyph_claim", |conn| {
            conn.execute(
                "INSERT INTO ghost_glyph_registry (ghost_id, pixels, bitmap_hash, commitment, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![ghost_id, pixels, bitmap_hash, commitment, created_at as i64, expires_at as i64],
            )
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("UNIQUE") {
                    if msg.contains("bitmap_hash") {
                        GhostError::Database("Bitmap already registered by another ghost ID".to_string())
                    } else {
                        GhostError::Database("Ghost ID already has a registered glyph".to_string())
                    }
                } else {
                    GhostError::Database(msg)
                }
            })?;
            Ok(())
        })
    }

    /// Complete a glyph registration by setting the funding txid and timestamp.
    ///
    /// M-5: Only completes if the claim has not expired. Expired claims must be
    /// re-submitted before funding.
    pub fn complete_glyph_registration(
        &self,
        ghost_id: &str,
        funding_txid: &str,
        registered_at: u64,
    ) -> GhostResult<()> {
        self.with_connection_retry("complete_glyph_registration", |conn| {
            let updated = conn
                .execute(
                    "UPDATE ghost_glyph_registry SET funding_txid = ?1, registered_at = ?2, expires_at = NULL
                     WHERE ghost_id = ?3 AND funding_txid IS NULL
                     AND (expires_at IS NULL OR expires_at >= ?4)",
                    params![funding_txid, registered_at as i64, ghost_id, registered_at as i64],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if updated == 0 {
                return Err(GhostError::Database(
                    "No pending (non-expired) glyph claim found for this ghost ID".to_string(),
                ));
            }
            Ok(())
        })
    }

    /// Look up a glyph by ghost ID.
    pub fn get_glyph_by_ghost_id(&self, ghost_id: &str) -> GhostResult<Option<GlyphRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT ghost_id, pixels, bitmap_hash, commitment, funding_txid, registered_at, created_at, expires_at
                     FROM ghost_glyph_registry WHERE ghost_id = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            stmt.query_row(params![ghost_id], |row| {
                Ok(GlyphRecord {
                    ghost_id: row.get(0)?,
                    pixels: row.get(1)?,
                    bitmap_hash: row.get(2)?,
                    commitment: row.get(3)?,
                    funding_txid: row.get(4)?,
                    registered_at: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
                    created_at: row.get::<_, i64>(6)? as u64,
                    expires_at: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
                })
            })
            .optional()
            .map_err(|e| GhostError::Database(e.to_string()))
        })
    }

    /// Look up a glyph by bitmap hash.
    pub fn get_glyph_by_bitmap_hash(&self, bitmap_hash: &[u8]) -> GhostResult<Option<GlyphRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT ghost_id, pixels, bitmap_hash, commitment, funding_txid, registered_at, created_at, expires_at
                     FROM ghost_glyph_registry WHERE bitmap_hash = ?1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            stmt.query_row(params![bitmap_hash], |row| {
                Ok(GlyphRecord {
                    ghost_id: row.get(0)?,
                    pixels: row.get(1)?,
                    bitmap_hash: row.get(2)?,
                    commitment: row.get(3)?,
                    funding_txid: row.get(4)?,
                    registered_at: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
                    created_at: row.get::<_, i64>(6)? as u64,
                    expires_at: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
                })
            })
            .optional()
            .map_err(|e| GhostError::Database(e.to_string()))
        })
    }

    /// Check if a bitmap hash is available (not yet claimed by an active record).
    ///
    /// M-3: Expired unfunded claims do not block availability — they will be
    /// cleaned up by the hourly expiration task, but we treat them as available
    /// immediately so users don't have to wait.
    pub fn is_bitmap_available(&self, bitmap_hash: &[u8]) -> GhostResult<bool> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.with_connection(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM ghost_glyph_registry
                     WHERE bitmap_hash = ?1
                     AND (funding_txid IS NOT NULL OR expires_at IS NULL OR expires_at >= ?2)",
                    params![bitmap_hash, now],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(count == 0)
        })
    }

    /// List registered glyphs (those with funding_txid set), newest first.
    pub fn list_registered_glyphs(&self, offset: u64, limit: u64) -> GhostResult<Vec<GlyphRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT ghost_id, pixels, bitmap_hash, commitment, funding_txid, registered_at, created_at, expires_at
                     FROM ghost_glyph_registry
                     WHERE registered_at IS NOT NULL
                     ORDER BY registered_at DESC
                     LIMIT ?1 OFFSET ?2",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let records = stmt
                .query_map(params![limit as i64, offset as i64], |row| {
                    Ok(GlyphRecord {
                        ghost_id: row.get(0)?,
                        pixels: row.get(1)?,
                        bitmap_hash: row.get(2)?,
                        commitment: row.get(3)?,
                        funding_txid: row.get(4)?,
                        registered_at: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
                        created_at: row.get::<_, i64>(6)? as u64,
                        expires_at: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
                    })
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(records)
        })
    }

    /// Delete expired unfunded glyph claims. Returns the number of rows deleted.
    pub fn cleanup_expired_glyph_claims(&self, now: u64) -> GhostResult<usize> {
        self.with_connection_retry("cleanup_expired_glyph_claims", |conn| {
            let deleted = conn
                .execute(
                    "DELETE FROM ghost_glyph_registry WHERE expires_at < ?1 AND funding_txid IS NULL",
                    params![now as i64],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(deleted)
        })
    }

    // =========================================================================
    // L2 Epoch Fee Tracking
    // =========================================================================

    /// Atomically increment the fee counter for an epoch.
    /// `transfer_count` is the number of NoteSpend transfers in this checkpoint.
    pub fn increment_epoch_fee(&self, epoch: u64, transfer_count: u64) -> GhostResult<()> {
        use ghost_common::constants::L2_TRANSFER_FEE_SATS;
        let fee_sats = transfer_count * L2_TRANSFER_FEE_SATS;
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO l2_epoch_fees (epoch, transfer_count, fee_total_sats, updated_at)
                 VALUES (?1, ?2, ?3, datetime('now'))
                 ON CONFLICT(epoch) DO UPDATE SET
                     transfer_count = transfer_count + excluded.transfer_count,
                     fee_total_sats = fee_total_sats + excluded.fee_total_sats,
                     updated_at = datetime('now')",
                params![epoch as i64, transfer_count as i64, fee_sats as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Aggregate Pay-activity counters for the public stats endpoint.
    /// Returns a struct instead of individual functions so the website
    /// gets a consistent snapshot in one DB hit — avoids the tiny drift
    /// that comes from four sequential count queries over a moving
    /// `now` anchor.
    ///
    /// Privacy note: none of these expose per-row data (no payment ids,
    /// no participants, no addresses) — only counts and one sum.
    pub fn get_pay_stats(&self, since_ts: i64) -> GhostResult<PayStats> {
        self.with_connection(|conn| {
            // L2 payments — accepted_at is a unix timestamp, indexed.
            let payments_24h: u64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM accepted_instant_payments WHERE accepted_at >= ?1",
                    [since_ts],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            let payments_total: u64 = conn
                .query_row("SELECT COUNT(*) FROM accepted_instant_payments", [], |r| r.get(0))
                .unwrap_or(0);

            // Wraith rounds — created_at is unix seconds.
            let wraith_rounds_24h: u64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM wraith_rounds WHERE created_at >= ?1",
                    [since_ts],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            let wraith_rounds_total: u64 = conn
                .query_row("SELECT COUNT(*) FROM wraith_rounds", [], |r| r.get(0))
                .unwrap_or(0);
            let wraith_rounds_active: u64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM wraith_rounds WHERE status = 'active'",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);

            // Settlement batches — created_at is unix seconds.
            let settlements_24h: u64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM reconciliation_state WHERE created_at >= ?1",
                    [since_ts],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            let settlements_total: u64 = conn
                .query_row("SELECT COUNT(*) FROM reconciliation_state", [], |r| r.get(0))
                .unwrap_or(0);

            // Undistributed L2 fee pool — sum across all epochs that
            // haven't been distributed yet. Represents pending fees
            // queued for the next settlement.
            let epoch_fee_pool: u64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(fee_total_sats), 0) FROM l2_epoch_fees WHERE distributed = 0",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .map(|v| v.max(0) as u64)
                .unwrap_or(0);

            // Unspent shielded notes — proxy for "currently shielded" activity.
            let unspent_notes: u64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM l2_notes WHERE spent = 0",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);

            Ok(PayStats {
                payments_24h,
                payments_total,
                wraith_rounds_24h,
                wraith_rounds_total,
                wraith_rounds_active,
                settlements_24h,
                settlements_total,
                epoch_fee_pool_sats: epoch_fee_pool,
                unspent_notes,
            })
        })
    }

    /// Get the accumulated fee total for an epoch.
    pub fn get_epoch_fee_total(&self, epoch: u64) -> GhostResult<u64> {
        self.with_connection(|conn| {
            let result: Option<i64> = conn
                .query_row(
                    "SELECT fee_total_sats FROM l2_epoch_fees WHERE epoch = ?1",
                    params![epoch as i64],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(result.unwrap_or(0) as u64)
        })
    }

    /// Mark an epoch's fees as distributed (after reconciliation payout).
    pub fn mark_epoch_fees_distributed(&self, epoch: u64) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "UPDATE l2_epoch_fees SET distributed = 1, updated_at = datetime('now') WHERE epoch = ?1",
                params![epoch as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Increment wraith service fees for an epoch (variable amount per denomination).
    /// Unlike `increment_epoch_fee()` which computes fees from transfer count,
    /// wraith fees are passed directly since they vary per denomination tier.
    pub fn increment_wraith_fee(&self, epoch: u64, fee_sats: u64) -> GhostResult<()> {
        if fee_sats == 0 {
            return Ok(());
        }
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO l2_epoch_fees (epoch, transfer_count, fee_total_sats, updated_at)
                 VALUES (?1, 0, ?2, datetime('now'))
                 ON CONFLICT(epoch) DO UPDATE SET
                     fee_total_sats = fee_total_sats + excluded.fee_total_sats,
                     updated_at = datetime('now')",
                params![epoch as i64, fee_sats as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get all undistributed epoch fees (for reconciliation batch formation).
    pub fn get_undistributed_fees(&self) -> GhostResult<Vec<(u64, u64)>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT epoch, fee_total_sats FROM l2_epoch_fees
                     WHERE distributed = 0 AND fee_total_sats > 0
                     ORDER BY epoch",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let rows = stmt
                .query_map([], |row| {
                    let epoch: i64 = row.get(0)?;
                    let fee_total: i64 = row.get(1)?;
                    Ok((epoch as u64, fee_total as u64))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| GhostError::Database(e.to_string()))?);
            }
            Ok(result)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_node_reward_ledger() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");

        let entry = db
            .get_or_create_node_reward("node123")
            .expect("LOW-STOR-8: Failed to get or create node reward");
        assert_eq!(entry.balance_sats, 0);

        db.credit_node_reward("node123", 1000, 1)
            .expect("LOW-STOR-8: Failed to credit node reward");

        let entry = db
            .get_or_create_node_reward("node123")
            .expect("LOW-STOR-8: Failed to get node reward after credit");
        assert_eq!(entry.balance_sats, 1000);
        assert_eq!(entry.last_credited_round, 1);
    }

    #[test]
    fn test_ghost_lock_operations() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");
        let now = chrono::Utc::now().timestamp();

        let lock = GhostLockRecord {
            lock_id: "lock123".to_string(),
            owner_ghost_id: "ghost1abc".to_string(),
            lock_pubkey: "02abc123".to_string(),
            recovery_pubkey: "02def456".to_string(),
            denomination: "Medium".to_string(),
            amount_sats: 10_000_000,
            timelock_tier: "Standard".to_string(),
            creation_height: 800000,
            recovery_height: 807200,
            state: GhostLockState::Pending,
            funding_txid: None,
            funding_vout: None,
            spend_txid: None,
            output_script: "5120abcd".to_string(),
            jump_risk_tier: "Medium".to_string(),
            next_jump_height: Some(802016),
            created_at: now,
            updated_at: now,
            source: "manual".to_string(),
            wraith_fee_sats: 0,
            key_index: None,
        };

        db.insert_ghost_lock(&lock)
            .expect("LOW-STOR-8: Failed to insert ghost lock");

        let fetched = db
            .get_ghost_lock("lock123")
            .expect("LOW-STOR-8: Failed to get ghost lock")
            .expect("LOW-STOR-8: Ghost lock should exist");
        assert_eq!(fetched.amount_sats, 10_000_000);
        assert_eq!(fetched.state, GhostLockState::Pending);

        // Update funding
        db.update_ghost_lock_funding("lock123", "txid123", 0)
            .expect("LOW-STOR-8: Failed to update ghost lock funding");
        let fetched = db
            .get_ghost_lock("lock123")
            .expect("LOW-STOR-8: Failed to get ghost lock after funding")
            .expect("LOW-STOR-8: Ghost lock should exist");
        assert_eq!(fetched.state, GhostLockState::Active);
        assert_eq!(fetched.funding_txid, Some("txid123".to_string()));

        // Get by owner
        let locks = db
            .get_ghost_locks_by_owner("ghost1abc")
            .expect("LOW-STOR-8: Failed to get locks by owner");
        assert_eq!(locks.len(), 1);

        // Get balance
        let balance = db
            .get_ghost_lock_balance("ghost1abc")
            .expect("LOW-STOR-8: Failed to get lock balance");
        assert_eq!(balance, 10_000_000);
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

    #[test]
    fn test_wraith_round_operations() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");
        let now = chrono::Utc::now().timestamp();

        let round = WraithRoundRecord {
            round_id: "wraith123".to_string(),
            coordinator_id: "coord456".to_string(),
            denomination: "Medium".to_string(),
            amount_sats: 10_000_000,
            phase: WraithPhase::Registration,
            participant_count: 0,
            min_participants: 5,
            max_participants: 50,
            registration_deadline: now + 3600,
            execution_deadline: None,
            split_txid: None,
            merge_txid: None,
            status: WraithStatus::Active,
            created_at: now,
            updated_at: now,
        };

        db.insert_wraith_round(&round)
            .expect("LOW-STOR-8: Failed to insert wraith round");

        let fetched = db
            .get_wraith_round("wraith123")
            .expect("LOW-STOR-8: Failed to get wraith round")
            .expect("LOW-STOR-8: Wraith round should exist");
        assert_eq!(fetched.phase, WraithPhase::Registration);

        db.update_wraith_round_phase("wraith123", WraithPhase::Split)
            .expect("LOW-STOR-8: Failed to update wraith round phase");
        let fetched = db
            .get_wraith_round("wraith123")
            .expect("LOW-STOR-8: Failed to get wraith round after update")
            .expect("LOW-STOR-8: Wraith round should exist");
        assert_eq!(fetched.phase, WraithPhase::Split);

        let active = db
            .get_active_wraith_rounds()
            .expect("LOW-STOR-8: Failed to get active wraith rounds");
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_reconciliation_operations() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");
        let now = chrono::Utc::now().timestamp();

        let batch = ReconciliationRecord {
            batch_id: "batch123".to_string(),
            settlement_class: "Standard".to_string(),
            participant_count: 10,
            total_amount_sats: 100_000_000,
            merkle_root: "abc123".to_string(),
            l1_txid: None,
            l1_block_height: None,
            dispute_deadline: None,
            status: ReconciliationStatus::Pending,
            created_at: now,
            finalized_at: None,
            l2_node_rewards_sats: 0,
        };

        db.insert_reconciliation_batch(&batch)
            .expect("LOW-STOR-8: Failed to insert reconciliation batch");

        let fetched = db
            .get_reconciliation_batch("batch123")
            .expect("LOW-STOR-8: Failed to get reconciliation batch")
            .expect("LOW-STOR-8: Reconciliation batch should exist");
        assert_eq!(fetched.participant_count, 10);

        db.update_reconciliation_l1_submitted("batch123", "txid456", 800100, 800244)
            .expect("LOW-STOR-8: Failed to update reconciliation L1 submitted");
        let fetched = db
            .get_reconciliation_batch("batch123")
            .expect("LOW-STOR-8: Failed to get reconciliation batch after update")
            .expect("LOW-STOR-8: Reconciliation batch should exist");
        assert_eq!(fetched.status, ReconciliationStatus::Submitted);
        assert_eq!(fetched.l1_txid, Some("txid456".to_string()));

        let pending = db
            .get_pending_reconciliation_batches()
            .expect("LOW-STOR-8: Failed to get pending reconciliation batches");
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_payout_history_pagination() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");
        let now = chrono::Utc::now().timestamp();

        // Create test rounds with payouts
        for i in 0..5 {
            let round = RoundRecord {
                round_id: i as u64,
                block_height: 800000 + i as u64,
                block_hash: Some(format!("hash{}", i)),
                start_time: now - (5 - i) as i64 * 100,
                end_time: Some(now - (4 - i) as i64 * 100),
                total_shares: 100,
                total_work: 1000.0,
                winning_miner: Some("miner1".to_string()),
                found_by_node: Some("node1".to_string()),
                payout_status: PayoutStatus::Confirmed,
                subsidy_sats: Some(312500000),
                tx_fees_sats: Some(1000000),
            };
            db.create_round(&round)
                .expect("LOW-STOR-8: Failed to create round");

            // Add some payouts for each round
            let miner_payout = PayoutRecord {
                id: None,
                round_id: i as u64,
                recipient_id: "miner1".to_string(),
                recipient_type: RecipientType::Miner,
                address: "bc1qminer".to_string(),
                amount_sats: 309000000,
                txid: None,
                vout: None,
                status: PayoutStatus::Confirmed,
                created_at: now,
                confirmed_at: Some(now),
            };
            db.insert_payout(&miner_payout)
                .expect("LOW-STOR-8: Failed to insert miner payout");

            let node_payout = PayoutRecord {
                id: None,
                round_id: i as u64,
                recipient_id: "node1".to_string(),
                recipient_type: RecipientType::Node,
                address: "bc1qnode".to_string(),
                amount_sats: 2000000,
                txid: None,
                vout: None,
                status: PayoutStatus::Confirmed,
                created_at: now,
                confirmed_at: Some(now),
            };
            db.insert_payout(&node_payout)
                .expect("LOW-STOR-8: Failed to insert node payout");
        }

        // Test basic pagination
        let query = PayoutHistoryQuery::with_limit(3);
        let history = db
            .query_payout_history(query)
            .expect("LOW-STOR-8: Failed to query payout history");
        assert_eq!(history.len(), 3);
        // Results should be ordered by height descending
        assert!(history[0].block_height >= history[1].block_height);

        // Test offset
        let query = PayoutHistoryQuery::with_limit(2).with_offset(2);
        let history = db
            .query_payout_history(query)
            .expect("LOW-STOR-8: Failed to query payout history with offset");
        assert_eq!(history.len(), 2);

        // Test height filters
        let query = PayoutHistoryQuery::with_limit(10)
            .with_min_height(800002)
            .with_max_height(800003);
        let history = db
            .query_payout_history(query)
            .expect("LOW-STOR-8: Failed to query payout history with height filters");
        assert_eq!(history.len(), 2);
        for summary in &history {
            assert!(summary.block_height >= 800002);
            assert!(summary.block_height <= 800003);
        }

        // Test aggregation
        let query = PayoutHistoryQuery::with_limit(1);
        let history = db
            .query_payout_history(query)
            .expect("LOW-STOR-8: Failed to query payout history for aggregation");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].miner_count, 1);
        assert_eq!(history[0].node_count, 1);
        assert_eq!(history[0].total_miner_sats, 309000000);
        assert_eq!(history[0].total_node_sats, 2000000);

        // Test round count
        let count = db
            .get_payout_round_count(None, None)
            .expect("LOW-STOR-8: Failed to get payout round count");
        assert_eq!(count, 5);

        let count = db
            .get_payout_round_count(Some(800002), Some(800003))
            .expect("LOW-STOR-8: Failed to get payout round count with filters");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_withdrawal_atomic_insert_prevents_duplicates() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");
        let now = chrono::Utc::now().timestamp();

        // First, create a ghost lock that we can withdraw from
        let lock = GhostLockRecord {
            lock_id: "lock_atomic_test".to_string(),
            owner_ghost_id: "ghost_atomic".to_string(),
            lock_pubkey: "02abc123".to_string(),
            recovery_pubkey: "02def456".to_string(),
            denomination: "Medium".to_string(),
            amount_sats: 10_000_000,
            timelock_tier: "Standard".to_string(),
            creation_height: 800000,
            recovery_height: 807200,
            state: GhostLockState::Active,
            funding_txid: Some("abc123".to_string()),
            funding_vout: Some(0),
            spend_txid: None,
            output_script: "script".to_string(),
            jump_risk_tier: "Low".to_string(),
            next_jump_height: None,
            created_at: now,
            updated_at: now,
            source: "manual".to_string(),
            wraith_fee_sats: 0,
            key_index: None,
        };
        db.insert_ghost_lock(&lock)
            .expect("LOW-STOR-8: Failed to insert ghost lock");

        // First withdrawal request should succeed
        let withdrawal1 = WithdrawalRequest {
            id: None,
            ghost_id: "ghost_atomic".to_string(),
            lock_id: "lock_atomic_test".to_string(),
            destination_address: "bc1qtest1".to_string(),
            amount_sats: 1_000_000,
            fee_sats: 1000,
            status: WithdrawalStatus::Pending,
            batch_id: None,
            l1_txid: None,
            settlement_class: "standard".to_string(),
            created_at: now,
            updated_at: now,
        };

        let result = db
            .insert_withdrawal_request_atomic(&withdrawal1)
            .expect("LOW-STOR-8: Failed to insert first withdrawal request");
        assert!(result.is_some(), "First withdrawal should succeed");
        let first_id = result.expect("LOW-STOR-8: First withdrawal should return ID");
        assert!(first_id > 0);

        // Second withdrawal for the same lock should be rejected
        let withdrawal2 = WithdrawalRequest {
            id: None,
            ghost_id: "ghost_atomic".to_string(),
            lock_id: "lock_atomic_test".to_string(),
            destination_address: "bc1qtest2".to_string(),
            amount_sats: 2_000_000,
            fee_sats: 1000,
            status: WithdrawalStatus::Pending,
            batch_id: None,
            l1_txid: None,
            settlement_class: "standard".to_string(),
            created_at: now + 1,
            updated_at: now + 1,
        };

        let result = db
            .insert_withdrawal_request_atomic(&withdrawal2)
            .expect("LOW-STOR-8: Failed to attempt second withdrawal request");
        assert!(result.is_none(), "Second withdrawal should be rejected");

        // Verify only one withdrawal exists
        let withdrawals = db
            .get_withdrawals_by_lock("lock_atomic_test")
            .expect("LOW-STOR-8: Failed to get withdrawals by lock");
        assert_eq!(withdrawals.len(), 1);
        assert_eq!(withdrawals[0].destination_address, "bc1qtest1");
    }

    #[test]
    fn test_withdrawal_atomic_allows_after_completion() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");
        let now = chrono::Utc::now().timestamp();

        // Create a ghost lock
        let lock = GhostLockRecord {
            lock_id: "lock_complete_test".to_string(),
            owner_ghost_id: "ghost_complete".to_string(),
            lock_pubkey: "02abc123".to_string(),
            recovery_pubkey: "02def456".to_string(),
            denomination: "Medium".to_string(),
            amount_sats: 10_000_000,
            timelock_tier: "Standard".to_string(),
            creation_height: 800000,
            recovery_height: 807200,
            state: GhostLockState::Active,
            funding_txid: Some("abc123".to_string()),
            funding_vout: Some(0),
            spend_txid: None,
            output_script: "script".to_string(),
            jump_risk_tier: "Low".to_string(),
            next_jump_height: None,
            created_at: now,
            updated_at: now,
            source: "manual".to_string(),
            wraith_fee_sats: 0,
            key_index: None,
        };
        db.insert_ghost_lock(&lock)
            .expect("LOW-STOR-8: Failed to insert ghost lock");

        // First withdrawal
        let withdrawal1 = WithdrawalRequest {
            id: None,
            ghost_id: "ghost_complete".to_string(),
            lock_id: "lock_complete_test".to_string(),
            destination_address: "bc1qtest1".to_string(),
            amount_sats: 1_000_000,
            fee_sats: 1000,
            status: WithdrawalStatus::Pending,
            batch_id: None,
            l1_txid: None,
            settlement_class: "standard".to_string(),
            created_at: now,
            updated_at: now,
        };

        let result = db
            .insert_withdrawal_request_atomic(&withdrawal1)
            .expect("LOW-STOR-8: Failed to insert first withdrawal");
        let first_id = result.expect("LOW-STOR-8: First withdrawal should return ID");

        // Mark the first withdrawal as completed
        db.update_withdrawal_status(first_id, WithdrawalStatus::Confirmed)
            .expect("LOW-STOR-8: Failed to update withdrawal status");

        // Now a second withdrawal should succeed (since the first is confirmed)
        let withdrawal2 = WithdrawalRequest {
            id: None,
            ghost_id: "ghost_complete".to_string(),
            lock_id: "lock_complete_test".to_string(),
            destination_address: "bc1qtest2".to_string(),
            amount_sats: 2_000_000,
            fee_sats: 1000,
            status: WithdrawalStatus::Pending,
            batch_id: None,
            l1_txid: None,
            settlement_class: "standard".to_string(),
            created_at: now + 1,
            updated_at: now + 1,
        };

        let result = db
            .insert_withdrawal_request_atomic(&withdrawal2)
            .expect("LOW-STOR-8: Failed to attempt second withdrawal");
        assert!(
            result.is_some(),
            "Second withdrawal should succeed after first is confirmed"
        );
    }

    #[test]
    fn test_withdrawal_atomic_blocks_batched() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");
        let now = chrono::Utc::now().timestamp();

        // Create a ghost lock
        let lock = GhostLockRecord {
            lock_id: "lock_batched_test".to_string(),
            owner_ghost_id: "ghost_batched".to_string(),
            lock_pubkey: "02abc123".to_string(),
            recovery_pubkey: "02def456".to_string(),
            denomination: "Medium".to_string(),
            amount_sats: 10_000_000,
            timelock_tier: "Standard".to_string(),
            creation_height: 800000,
            recovery_height: 807200,
            state: GhostLockState::Active,
            funding_txid: Some("abc123".to_string()),
            funding_vout: Some(0),
            spend_txid: None,
            output_script: "script".to_string(),
            jump_risk_tier: "Low".to_string(),
            next_jump_height: None,
            created_at: now,
            updated_at: now,
            source: "manual".to_string(),
            wraith_fee_sats: 0,
            key_index: None,
        };
        db.insert_ghost_lock(&lock)
            .expect("LOW-STOR-8: Failed to insert ghost lock");

        // First withdrawal with pending status
        let withdrawal1 = WithdrawalRequest {
            id: None,
            ghost_id: "ghost_batched".to_string(),
            lock_id: "lock_batched_test".to_string(),
            destination_address: "bc1qtest1".to_string(),
            amount_sats: 1_000_000,
            fee_sats: 1000,
            status: WithdrawalStatus::Pending,
            batch_id: None,
            l1_txid: None,
            settlement_class: "standard".to_string(),
            created_at: now,
            updated_at: now,
        };

        let result = db
            .insert_withdrawal_request_atomic(&withdrawal1)
            .expect("LOW-STOR-8: Failed to insert first withdrawal");
        let first_id = result.expect("LOW-STOR-8: First withdrawal should return ID");

        // Mark the first withdrawal as batched
        db.update_withdrawal_batched(first_id, "batch123")
            .expect("LOW-STOR-8: Failed to update withdrawal batched");

        // Second withdrawal should still be rejected (batched also blocks)
        let withdrawal2 = WithdrawalRequest {
            id: None,
            ghost_id: "ghost_batched".to_string(),
            lock_id: "lock_batched_test".to_string(),
            destination_address: "bc1qtest2".to_string(),
            amount_sats: 2_000_000,
            fee_sats: 1000,
            status: WithdrawalStatus::Pending,
            batch_id: None,
            l1_txid: None,
            settlement_class: "standard".to_string(),
            created_at: now + 1,
            updated_at: now + 1,
        };

        let result = db
            .insert_withdrawal_request_atomic(&withdrawal2)
            .expect("LOW-STOR-8: Failed to attempt second withdrawal");
        assert!(
            result.is_none(),
            "Second withdrawal should be rejected when first is batched"
        );
    }

    /// SEC-DATA-TEST-1: Verify that negative satoshi values are properly rejected
    #[test]
    fn test_negative_satoshi_rejected() {
        // Positive values should succeed
        let result = i64_to_u64_sats(100, "test_field");
        assert!(result.is_ok());
        assert_eq!(result.expect("LOW-STOR-8: 100 should convert"), 100u64);

        // Zero should succeed
        let result = i64_to_u64_sats(0, "test_field");
        assert!(result.is_ok());
        assert_eq!(result.expect("LOW-STOR-8: 0 should convert"), 0u64);

        // Large positive value should succeed
        let result = i64_to_u64_sats(i64::MAX, "test_field");
        assert!(result.is_ok());
        assert_eq!(
            result.expect("LOW-STOR-8: i64::MAX should convert"),
            i64::MAX as u64
        );

        // Negative value should fail
        let result = i64_to_u64_sats(-1, "test_field");
        assert!(result.is_err(), "Negative satoshi value should be rejected");

        // Large negative value should fail
        let result = i64_to_u64_sats(-1_000_000, "total_miner_sats");
        assert!(
            result.is_err(),
            "Large negative satoshi value should be rejected"
        );
    }

    // =========================================================================
    // L-24 FIX TESTS: Instant Payment Reservation Persistence
    // =========================================================================

    #[test]
    fn test_instant_reservation_persistence() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");
        let current_time = 1700000000000u64;

        let reservation = InstantReservationRecord {
            payment_id: [1u8; 32],
            lock_id: "lock123".to_string(),
            amount_sats: 50_000,
            created_at: current_time,
            expires_at: current_time + 30_000, // 30 seconds
        };

        // Save reservation
        db.save_instant_reservation(&reservation)
            .expect("LOW-STOR-8: Failed to save instant reservation");

        // Verify it exists
        assert!(db
            .has_instant_reservation(&[1u8; 32])
            .expect("LOW-STOR-8: Failed to check reservation existence"));

        // Get active reservations
        let active = db
            .get_active_reservations_for_lock("lock123", current_time)
            .expect("LOW-STOR-8: Failed to get active reservations");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].amount_sats, 50_000);

        // Get total reserved
        let total = db
            .get_total_reserved_for_lock("lock123", current_time)
            .expect("LOW-STOR-8: Failed to get total reserved");
        assert_eq!(total, 50_000);
    }

    #[test]
    fn test_instant_reservation_expiry() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");
        let start_time = 1700000000000u64;

        let reservation = InstantReservationRecord {
            payment_id: [2u8; 32],
            lock_id: "lock456".to_string(),
            amount_sats: 25_000,
            created_at: start_time,
            expires_at: start_time + 30_000,
        };

        db.save_instant_reservation(&reservation)
            .expect("LOW-STOR-8: Failed to save instant reservation");

        // Before expiry - should be active
        let active = db
            .get_active_reservations_for_lock("lock456", start_time + 15_000)
            .expect("LOW-STOR-8: Failed to get active reservations before expiry");
        assert_eq!(active.len(), 1);

        // After expiry - should not be returned
        let active = db
            .get_active_reservations_for_lock("lock456", start_time + 31_000)
            .expect("LOW-STOR-8: Failed to get active reservations after expiry");
        assert_eq!(active.len(), 0);

        // Prune expired
        let pruned = db
            .prune_expired_reservations(start_time + 31_000)
            .expect("LOW-STOR-8: Failed to prune expired reservations");
        assert_eq!(pruned, 1);

        // Should no longer exist
        assert!(!db
            .has_instant_reservation(&[2u8; 32])
            .expect("LOW-STOR-8: Failed to check reservation existence"));
    }

    #[test]
    fn test_instant_reservation_multiple_locks() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");
        let current_time = 1700000000000u64;

        // Create reservations for different locks
        for i in 0..3 {
            let reservation = InstantReservationRecord {
                payment_id: [i as u8; 32],
                lock_id: format!("lock{}", i),
                amount_sats: 10_000 * (i as u64 + 1),
                created_at: current_time,
                expires_at: current_time + 30_000,
            };
            db.save_instant_reservation(&reservation)
                .expect("LOW-STOR-8: Failed to save instant reservation");
        }

        // Verify each lock has correct total
        assert_eq!(
            db.get_total_reserved_for_lock("lock0", current_time)
                .expect("LOW-STOR-8: Failed to get reserved for lock0"),
            10_000
        );
        assert_eq!(
            db.get_total_reserved_for_lock("lock1", current_time)
                .expect("LOW-STOR-8: Failed to get reserved for lock1"),
            20_000
        );
        assert_eq!(
            db.get_total_reserved_for_lock("lock2", current_time)
                .expect("LOW-STOR-8: Failed to get reserved for lock2"),
            30_000
        );

        // Delete one reservation
        db.delete_instant_reservation(&[1u8; 32])
            .expect("LOW-STOR-8: Failed to delete reservation");

        // lock1 should now have 0 reserved
        assert_eq!(
            db.get_total_reserved_for_lock("lock1", current_time)
                .expect("LOW-STOR-8: Failed to get reserved for lock1 after delete"),
            0
        );
    }

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
        // been dark for >7 days. delete_old_shares only prunes unpaid
        // shares of inactive miners, so the miner row is required for
        // the inactive-cutoff JOIN to match.
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
            first_seen: now_s - (10 * 24 * 3600),
            last_seen: now_s - (8 * 24 * 3600),
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

    // =========================================================================
    // CONFIDENTIAL TRANSFER TESTS
    // =========================================================================

    #[test]
    fn test_confidential_note_insert_and_query() {
        let db = Database::in_memory().expect("Failed to create in-memory database");

        let commitment = [0xABu8; 32];
        let owner = [0xCDu8; 32];

        db.insert_confidential_note(0, &commitment, &owner, 100)
            .expect("Failed to insert note");

        let notes = db.get_notes_for_owner(&owner).expect("Failed to get notes");
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].tree_index, 0);
        assert_eq!(notes[0].commitment, commitment);
        assert_eq!(notes[0].owner_pubkey, owner);
        assert_eq!(notes[0].created_at_height, 100);
        assert!(notes[0].spent_at_height.is_none());

        // Mark spent
        db.mark_note_spent(0, 200).expect("Failed to mark spent");
        let notes = db.get_notes_for_owner(&owner).expect("Failed to get notes");
        assert_eq!(notes[0].spent_at_height, Some(200));
    }

    #[test]
    fn test_confidential_note_load_all() {
        let db = Database::in_memory().expect("Failed to create in-memory database");

        let owner = [0x01u8; 32];
        for i in 0u64..5 {
            let mut commitment = [0u8; 32];
            commitment[0] = i as u8;
            db.insert_confidential_note(i, &commitment, &owner, i * 10)
                .expect("Failed to insert note");
        }

        let all = db
            .load_all_confidential_notes()
            .expect("Failed to load all");
        assert_eq!(all.len(), 5);
        assert_eq!(all[0].0, 0);
        assert_eq!(all[4].0, 4);

        let next = db
            .get_next_confidential_note_index()
            .expect("Failed to get next");
        assert_eq!(next, 5);
    }

    #[test]
    fn test_nullifier_insert_and_check() {
        let db = Database::in_memory().expect("Failed to create in-memory database");

        let nullifier = [0xFFu8; 32];
        assert!(!db
            .is_nullifier_spent(&nullifier)
            .expect("Failed to check nullifier"));

        db.insert_nullifier(&nullifier, 100, "tx-001")
            .expect("Failed to insert nullifier");

        assert!(db
            .is_nullifier_spent(&nullifier)
            .expect("Failed to check nullifier"));

        // Duplicate insert should fail (PRIMARY KEY constraint)
        assert!(db.insert_nullifier(&nullifier, 101, "tx-002").is_err());
    }

    #[test]
    fn test_nullifier_load_all_and_count() {
        let db = Database::in_memory().expect("Failed to create in-memory database");

        for i in 0u8..3 {
            let mut nullifier = [0u8; 32];
            nullifier[0] = i;
            db.insert_nullifier(&nullifier, i as u64, &format!("tx-{}", i))
                .expect("Failed to insert nullifier");
        }

        let all = db.load_all_nullifiers().expect("Failed to load all");
        assert_eq!(all.len(), 3);

        let count = db.get_nullifier_count().expect("Failed to get count");
        assert_eq!(count, 3);
    }

    #[test]
    fn test_nullifiers_in_range() {
        let db = Database::in_memory().expect("Failed to create in-memory database");

        for i in 0u8..10 {
            let mut nullifier = [0u8; 32];
            nullifier[0] = i;
            db.insert_nullifier(&nullifier, (i as u64) * 10, &format!("tx-{}", i))
                .expect("Failed to insert nullifier");
        }

        // Get nullifiers in range [30, 60]
        let range = db
            .get_nullifiers_in_range(30, 60)
            .expect("Failed to get range");
        assert_eq!(range.len(), 4); // heights 30, 40, 50, 60
    }

    #[test]
    fn test_confidential_transfer_insert_and_update() {
        let db = Database::in_memory().expect("Failed to create in-memory database");

        let record = ConfidentialTransferRecord {
            transfer_id: "ct-001".to_string(),
            block_height: None,
            nullifier: [0xAAu8; 32],
            sender_new_commitment: [0xBBu8; 32],
            recipient_new_commitment: [0xCCu8; 32],
            old_commitment_root: [0xDDu8; 32],
            new_commitment_root: [0xEEu8; 32],
            proof: vec![0u8; 192],
            sender_index: 0,
            recipient_index: 1,
            status: "pending".to_string(),
            encrypted_change: Some(vec![0xFFu8; 64]),
            encrypted_recipient: Some(vec![0xFEu8; 64]),
            epoch: 1,
        };

        db.insert_confidential_transfer(&record)
            .expect("Failed to insert transfer");

        // Update status with height
        db.update_confidential_transfer_status("ct-001", "confirmed", Some(500))
            .expect("Failed to update status");

        // Verify note count
        let count = db
            .get_confidential_note_count()
            .expect("Failed to get count");
        assert_eq!(count, 0); // No notes inserted directly, only transfer record
    }

    #[test]
    fn test_confidential_transfer_rejects_oversized_proof() {
        let db = Database::in_memory().expect("Failed to create in-memory database");

        let record = ConfidentialTransferRecord {
            transfer_id: "ct-oversized".to_string(),
            block_height: None,
            nullifier: [0u8; 32],
            sender_new_commitment: [0u8; 32],
            recipient_new_commitment: [0u8; 32],
            old_commitment_root: [0u8; 32],
            new_commitment_root: [0u8; 32],
            proof: vec![0u8; 256], // Too large
            sender_index: 0,
            recipient_index: 1,
            status: "pending".to_string(),
            encrypted_change: None,
            encrypted_recipient: None,
            epoch: 0,
        };

        assert!(db.insert_confidential_transfer(&record).is_err());
    }

    #[test]
    fn test_next_index_empty_table() {
        let db = Database::in_memory().expect("Failed to create in-memory database");
        let next = db
            .get_next_confidential_note_index()
            .expect("Failed to get next");
        assert_eq!(next, 0);
    }

    // =========================================================================
    // FK Payout Recording Tests
    // =========================================================================

    fn test_payout_record(round_id: u64) -> PayoutRecord {
        PayoutRecord {
            id: None,
            round_id,
            recipient_id: "abc123".to_string(),
            recipient_type: RecipientType::Miner,
            address: "bc1qtest".to_string(),
            amount_sats: 50_000,
            txid: None,
            vout: None,
            status: PayoutStatus::Approved,
            created_at: 1700000000,
            confirmed_at: None,
        }
    }

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
    fn test_payout_insert_requires_round() {
        let db = Database::in_memory().expect("Failed to create in-memory database");
        let record = test_payout_record(999);
        // Insert payout without creating round first → FK constraint violation
        assert!(db.insert_payout(&record).is_err());
    }

    #[test]
    fn test_payout_insert_with_round_succeeds() {
        let db = Database::in_memory().expect("Failed to create in-memory database");
        db.create_round(&test_round_record(1, 850_000))
            .expect("Failed to create round");
        let record = test_payout_record(1);
        assert!(db.insert_payout(&record).is_ok());
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

    #[test]
    fn test_create_round_if_not_exists_then_payout() {
        let db = Database::in_memory().expect("Failed to create in-memory database");
        // Use the new idempotent method (mimics what template.rs now does)
        db.create_round_if_not_exists(&test_round_record(42, 900_000))
            .expect("Failed to create round");
        let record = test_payout_record(42);
        let id = db
            .insert_payout(&record)
            .expect("Payout insert should succeed after round creation");
        assert!(id > 0);

        // Verify payout is queryable
        let count = db.get_payout_count().expect("Failed to get payout count");
        assert_eq!(count, 1);
    }

    // =========================================================================
    // GhostGlyph Storage Tests
    // =========================================================================

    fn test_glyph_pixels() -> Vec<u8> {
        let mut pixels = vec![0u8; 256];
        for i in 0..256 {
            pixels[i] = (i % 26) as u8;
        }
        pixels
    }

    fn test_bitmap_hash(pixels: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"GhostGlyphBitmap/v1");
        hasher.update(pixels);
        hasher.finalize().to_vec()
    }

    fn test_commitment(pixels: &[u8], ghost_id: &str) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"GhostGlyph/v1");
        hasher.update(pixels);
        hasher.update(ghost_id.as_bytes());
        hasher.finalize().to_vec()
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn test_glyph_claim_insert() {
        let db = Database::in_memory().expect("Failed to create DB");
        let pixels = test_glyph_pixels();
        let bh = test_bitmap_hash(&pixels);
        let cm = test_commitment(&pixels, "ghost1alice");

        db.insert_glyph_claim("ghost1alice", &pixels, &bh, &cm, 1000)
            .expect("Insert should succeed");

        let record = db
            .get_glyph_by_ghost_id("ghost1alice")
            .expect("Query should succeed")
            .expect("Record should exist");

        assert_eq!(record.ghost_id, "ghost1alice");
        assert_eq!(record.pixels, pixels);
        assert_eq!(record.bitmap_hash, bh);
        assert_eq!(record.commitment, cm);
        assert!(record.funding_txid.is_none());
        assert!(record.registered_at.is_none());
        assert_eq!(record.created_at, 1000);
    }

    #[test]
    fn test_glyph_duplicate_bitmap_rejected() {
        let db = Database::in_memory().expect("Failed to create DB");
        let pixels = test_glyph_pixels();
        let bh = test_bitmap_hash(&pixels);

        let cm1 = test_commitment(&pixels, "ghost1alice");
        db.insert_glyph_claim("ghost1alice", &pixels, &bh, &cm1, 1000)
            .expect("First insert should succeed");

        // Same bitmap_hash, different ghost_id
        let cm2 = test_commitment(&pixels, "ghost1bob");
        let result = db.insert_glyph_claim("ghost1bob", &pixels, &bh, &cm2, 1001);
        assert!(result.is_err(), "Duplicate bitmap should be rejected");
    }

    #[test]
    fn test_glyph_duplicate_ghost_id_rejected() {
        let db = Database::in_memory().expect("Failed to create DB");
        let pixels1 = test_glyph_pixels();
        let bh1 = test_bitmap_hash(&pixels1);
        let cm1 = test_commitment(&pixels1, "ghost1alice");

        db.insert_glyph_claim("ghost1alice", &pixels1, &bh1, &cm1, 1000)
            .expect("First insert should succeed");

        // Same ghost_id, different bitmap
        let mut pixels2 = vec![1u8; 256];
        pixels2[0] = 0; // Slightly different
        let bh2 = test_bitmap_hash(&pixels2);
        let cm2 = test_commitment(&pixels2, "ghost1alice");
        let result = db.insert_glyph_claim("ghost1alice", &pixels2, &bh2, &cm2, 1001);
        assert!(result.is_err(), "Duplicate ghost_id should be rejected");
    }

    #[test]
    fn test_glyph_complete_registration() {
        let db = Database::in_memory().expect("Failed to create DB");
        let pixels = test_glyph_pixels();
        let bh = test_bitmap_hash(&pixels);
        let cm = test_commitment(&pixels, "ghost1alice");

        db.insert_glyph_claim("ghost1alice", &pixels, &bh, &cm, 1000)
            .expect("Insert should succeed");

        db.complete_glyph_registration("ghost1alice", "txid123", 2000)
            .expect("Registration should succeed");

        let record = db
            .get_glyph_by_ghost_id("ghost1alice")
            .expect("Query should succeed")
            .expect("Record should exist");

        assert_eq!(record.funding_txid.as_deref(), Some("txid123"));
        assert_eq!(record.registered_at, Some(2000));
    }

    #[test]
    fn test_glyph_bitmap_availability() {
        let db = Database::in_memory().expect("Failed to create DB");
        let pixels = test_glyph_pixels();
        let bh = test_bitmap_hash(&pixels);
        let cm = test_commitment(&pixels, "ghost1alice");
        let now = now_secs();

        // Should be available before any claim
        assert!(db.is_bitmap_available(&bh).expect("Query should succeed"));

        db.insert_glyph_claim("ghost1alice", &pixels, &bh, &cm, now)
            .expect("Insert should succeed");

        // Should NOT be available after claim (not expired yet)
        assert!(!db.is_bitmap_available(&bh).expect("Query should succeed"));
    }

    #[test]
    fn test_glyph_get_by_bitmap_hash() {
        let db = Database::in_memory().expect("Failed to create DB");
        let pixels = test_glyph_pixels();
        let bh = test_bitmap_hash(&pixels);
        let cm = test_commitment(&pixels, "ghost1alice");

        db.insert_glyph_claim("ghost1alice", &pixels, &bh, &cm, 1000)
            .expect("Insert should succeed");

        let record = db
            .get_glyph_by_bitmap_hash(&bh)
            .expect("Query should succeed")
            .expect("Record should exist");

        assert_eq!(record.ghost_id, "ghost1alice");
    }

    #[test]
    fn test_glyph_list_registered() {
        let db = Database::in_memory().expect("Failed to create DB");

        // Insert two claims
        let pixels1 = test_glyph_pixels();
        let bh1 = test_bitmap_hash(&pixels1);
        let cm1 = test_commitment(&pixels1, "ghost1alice");
        db.insert_glyph_claim("ghost1alice", &pixels1, &bh1, &cm1, 1000)
            .expect("Insert should succeed");

        let mut pixels2 = vec![1u8; 256];
        for i in 0..256 {
            pixels2[i] = ((i + 1) % 26) as u8;
        }
        let bh2 = test_bitmap_hash(&pixels2);
        let cm2 = test_commitment(&pixels2, "ghost1bob");
        db.insert_glyph_claim("ghost1bob", &pixels2, &bh2, &cm2, 1001)
            .expect("Insert should succeed");

        // Neither registered yet
        let registered = db
            .list_registered_glyphs(0, 10)
            .expect("Query should succeed");
        assert_eq!(registered.len(), 0);

        // Register one
        db.complete_glyph_registration("ghost1alice", "txid123", 2000)
            .expect("Registration should succeed");

        let registered = db
            .list_registered_glyphs(0, 10)
            .expect("Query should succeed");
        assert_eq!(registered.len(), 1);
        assert_eq!(registered[0].ghost_id, "ghost1alice");
    }

    #[test]
    fn test_glyph_claim_has_expires_at() {
        let db = Database::in_memory().expect("Failed to create DB");
        let pixels = test_glyph_pixels();
        let bh = test_bitmap_hash(&pixels);
        let cm = test_commitment(&pixels, "ghost1alice");

        db.insert_glyph_claim("ghost1alice", &pixels, &bh, &cm, 1000)
            .expect("Insert should succeed");

        let record = db
            .get_glyph_by_ghost_id("ghost1alice")
            .expect("Query should succeed")
            .expect("Record should exist");

        // expires_at = created_at + 86400 (24h)
        assert_eq!(record.expires_at, Some(1000 + 86400));
    }

    #[test]
    fn test_glyph_registration_clears_expires_at() {
        let db = Database::in_memory().expect("Failed to create DB");
        let pixels = test_glyph_pixels();
        let bh = test_bitmap_hash(&pixels);
        let cm = test_commitment(&pixels, "ghost1alice");

        db.insert_glyph_claim("ghost1alice", &pixels, &bh, &cm, 1000)
            .expect("Insert should succeed");

        db.complete_glyph_registration("ghost1alice", "txid123", 2000)
            .expect("Registration should succeed");

        let record = db
            .get_glyph_by_ghost_id("ghost1alice")
            .expect("Query should succeed")
            .expect("Record should exist");

        // expires_at should be NULL after registration
        assert!(record.expires_at.is_none());
    }

    #[test]
    fn test_glyph_cleanup_expired_claims() {
        let db = Database::in_memory().expect("Failed to create DB");

        // Insert two claims: one at t=1000 (expires t=87400), one at t=100000 (expires t=186400)
        let pixels1 = test_glyph_pixels();
        let bh1 = test_bitmap_hash(&pixels1);
        let cm1 = test_commitment(&pixels1, "ghost1alice");
        db.insert_glyph_claim("ghost1alice", &pixels1, &bh1, &cm1, 1000)
            .expect("Insert should succeed");

        let mut pixels2 = vec![1u8; 256];
        for i in 0..256 {
            pixels2[i] = ((i + 1) % 26) as u8;
        }
        let bh2 = test_bitmap_hash(&pixels2);
        let cm2 = test_commitment(&pixels2, "ghost1bob");
        db.insert_glyph_claim("ghost1bob", &pixels2, &bh2, &cm2, 100000)
            .expect("Insert should succeed");

        // At t=90000: alice's claim expired (87400 < 90000), bob's hasn't (186400 > 90000)
        let deleted = db
            .cleanup_expired_glyph_claims(90000)
            .expect("Cleanup should succeed");
        assert_eq!(deleted, 1);

        // Alice should be gone
        assert!(db
            .get_glyph_by_ghost_id("ghost1alice")
            .expect("Query ok")
            .is_none());
        // Bob should still exist
        assert!(db
            .get_glyph_by_ghost_id("ghost1bob")
            .expect("Query ok")
            .is_some());
    }

    #[test]
    fn test_glyph_cleanup_skips_registered() {
        let db = Database::in_memory().expect("Failed to create DB");
        let pixels = test_glyph_pixels();
        let bh = test_bitmap_hash(&pixels);
        let cm = test_commitment(&pixels, "ghost1alice");

        db.insert_glyph_claim("ghost1alice", &pixels, &bh, &cm, 1000)
            .expect("Insert should succeed");

        // Complete registration — sets funding_txid and clears expires_at
        db.complete_glyph_registration("ghost1alice", "txid123", 2000)
            .expect("Registration should succeed");

        // Cleanup far in the future — should NOT delete registered claims
        let deleted = db
            .cleanup_expired_glyph_claims(999999999)
            .expect("Cleanup should succeed");
        assert_eq!(deleted, 0);

        // Record should still exist
        assert!(db
            .get_glyph_by_ghost_id("ghost1alice")
            .expect("Query ok")
            .is_some());
    }

    #[test]
    fn test_glyph_cleanup_frees_bitmap_for_reuse() {
        let db = Database::in_memory().expect("Failed to create DB");
        let pixels = test_glyph_pixels();
        let bh = test_bitmap_hash(&pixels);
        let cm = test_commitment(&pixels, "ghost1alice");
        let now = now_secs();

        db.insert_glyph_claim("ghost1alice", &pixels, &bh, &cm, now)
            .expect("Insert should succeed");

        // Bitmap should be taken (claim is still fresh)
        assert!(!db.is_bitmap_available(&bh).expect("Query ok"));

        // Expire the claim (cleanup with time far in the future)
        db.cleanup_expired_glyph_claims(now + 90000)
            .expect("Cleanup should succeed");

        // Bitmap should be available again (row deleted)
        assert!(db.is_bitmap_available(&bh).expect("Query ok"));

        // A new claim with the same bitmap should succeed
        let cm2 = test_commitment(&pixels, "ghost1bob");
        db.insert_glyph_claim("ghost1bob", &pixels, &bh, &cm2, now + 90001)
            .expect("Re-claim should succeed after expiry");
    }
}
