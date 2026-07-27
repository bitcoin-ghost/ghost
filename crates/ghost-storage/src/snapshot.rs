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
//| FILE: snapshot.rs                                                                                                    |
//|======================================================================================================================|

//! State snapshot management for ZK-BFT rollback capability
//!
//! Provides the ability to:
//! - Create snapshots of L2 state at block heights
//! - Rollback to a previous snapshot during reorg recovery
//! - Prune old snapshots beyond retention limit

use std::collections::HashMap;

/// L-STOR-1: Maximum allowed JSON size for deserialization from database (10 MB)
/// Prevents OOM attacks from maliciously large data
const MAX_JSON_SIZE: usize = 10 * 1024 * 1024;

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::params;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use ghost_common::error::{GhostError, GhostResult};

use crate::Database;

// =============================================================================
// L-17: SAFE HEIGHT CONVERSION
// =============================================================================

/// L-17: Safely convert i64 height from SQLite to u64, rejecting negative values.
/// Block heights should never be negative; a negative value indicates data corruption.
fn i64_to_u64_height(value: i64, context: &str) -> Result<u64, GhostError> {
    if value < 0 {
        Err(GhostError::Database(format!(
            "Invalid negative {} height: {}",
            context, value
        )))
    } else {
        Ok(value as u64)
    }
}

/// State snapshot record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Auto-increment ID
    pub id: Option<i64>,
    /// L2 block height
    pub height: u64,
    /// State root hash (hex)
    pub state_root: String,
    /// Account balances: ghost_id -> balance_sats
    pub balances: HashMap<String, u64>,
    /// Account nonces: ghost_id -> nonce (optional)
    pub nonces: Option<HashMap<String, u64>>,
    /// Creation timestamp
    pub created_at: i64,
}

/// Block proposer record for epoch tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProposerRecord {
    /// L2 block height
    pub height: u64,
    /// Proposer node ID (hex)
    pub proposer_id: String,
    /// State root at this height (hex)
    pub state_root: String,
    /// Timestamp when block was proposed
    pub timestamp: i64,
}

/// Manages state snapshots for ZK-BFT rollback
pub struct SnapshotManager {
    db: Database,
    /// Snapshot interval (every N blocks)
    snapshot_interval: u64,
    /// Maximum snapshots to retain
    max_snapshots: usize,
}

impl SnapshotManager {
    /// Create a new snapshot manager
    pub fn new(db: Database, snapshot_interval: u64, max_snapshots: usize) -> Self {
        Self {
            db,
            snapshot_interval,
            max_snapshots,
        }
    }

    /// Check if a snapshot should be created at this height
    pub fn should_snapshot(&self, height: u64) -> bool {
        height > 0 && height.is_multiple_of(self.snapshot_interval)
    }

    /// Create a snapshot at the given height
    pub fn create_snapshot(
        &self,
        height: u64,
        state_root: &[u8; 32],
        balances: &HashMap<String, u64>,
    ) -> GhostResult<()> {
        let state_root_hex = hex::encode(state_root);
        let balances_json = serde_json::to_string(balances)
            .map_err(|e| GhostError::Serialization(e.to_string()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.db.with_connection(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO state_snapshots (height, state_root, balances_json, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![height as i64, state_root_hex, balances_json, now],
            ).map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })?;

        debug!(height, "Created state snapshot");

        // Prune old snapshots if over limit
        self.prune_old_snapshots()?;

        Ok(())
    }

    /// Get the snapshot at or before the given height
    pub fn get_snapshot_at_or_before(&self, height: u64) -> GhostResult<Option<StateSnapshot>> {
        self.db.with_connection(|conn| {
            let result = conn.query_row(
                "SELECT id, height, state_root, balances_json, nonces_json, created_at
                 FROM state_snapshots
                 WHERE height <= ?1
                 ORDER BY height DESC
                 LIMIT 1",
                params![height as i64],
                |row| {
                    let id: i64 = row.get(0)?;
                    let h: i64 = row.get(1)?;
                    let state_root: String = row.get(2)?;
                    let balances_json: String = row.get(3)?;
                    let nonces_json: Option<String> = row.get(4)?;
                    let created_at: i64 = row.get(5)?;

                    Ok((id, h, state_root, balances_json, nonces_json, created_at))
                },
            );

            match result {
                Ok((id, h, state_root, balances_json, nonces_json, created_at)) => {
                    // L-17: Safely convert height, rejecting negative values
                    let snapshot_height = i64_to_u64_height(h, "snapshot_at_or_before")?;

                    // L-STOR-1: Check size before deserializing to prevent OOM
                    if balances_json.len() > MAX_JSON_SIZE {
                        return Err(GhostError::Database(format!(
                            "Snapshot balances JSON too large: {} bytes (max {})",
                            balances_json.len(),
                            MAX_JSON_SIZE
                        )));
                    }
                    if let Some(ref nonces) = nonces_json {
                        if nonces.len() > MAX_JSON_SIZE {
                            return Err(GhostError::Database(format!(
                                "Snapshot nonces JSON too large: {} bytes (max {})",
                                nonces.len(),
                                MAX_JSON_SIZE
                            )));
                        }
                    }

                    let balances: HashMap<String, u64> = serde_json::from_str(&balances_json)
                        .map_err(|e| GhostError::Serialization(e.to_string()))?;
                    let nonces: Option<HashMap<String, u64>> = nonces_json
                        .map(|json| serde_json::from_str(&json))
                        .transpose()
                        .map_err(|e| GhostError::Serialization(e.to_string()))?;

                    Ok(Some(StateSnapshot {
                        id: Some(id),
                        height: snapshot_height,
                        state_root,
                        balances,
                        nonces,
                        created_at,
                    }))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(GhostError::Database(e.to_string())),
            }
        })
    }

    /// Get the exact snapshot at a height
    pub fn get_snapshot_at(&self, height: u64) -> GhostResult<Option<StateSnapshot>> {
        self.db.with_connection(|conn| {
            let result = conn.query_row(
                "SELECT id, height, state_root, balances_json, nonces_json, created_at
                 FROM state_snapshots
                 WHERE height = ?1",
                params![height as i64],
                |row| {
                    let id: i64 = row.get(0)?;
                    let h: i64 = row.get(1)?;
                    let state_root: String = row.get(2)?;
                    let balances_json: String = row.get(3)?;
                    let nonces_json: Option<String> = row.get(4)?;
                    let created_at: i64 = row.get(5)?;

                    Ok((id, h, state_root, balances_json, nonces_json, created_at))
                },
            );

            match result {
                Ok((id, h, state_root, balances_json, nonces_json, created_at)) => {
                    // L-17: Safely convert height, rejecting negative values
                    let snapshot_height = i64_to_u64_height(h, "snapshot_at")?;

                    // L-STOR-1: Check size before deserializing to prevent OOM
                    if balances_json.len() > MAX_JSON_SIZE {
                        return Err(GhostError::Database(format!(
                            "Snapshot balances JSON too large: {} bytes (max {})",
                            balances_json.len(),
                            MAX_JSON_SIZE
                        )));
                    }
                    if let Some(ref nonces) = nonces_json {
                        if nonces.len() > MAX_JSON_SIZE {
                            return Err(GhostError::Database(format!(
                                "Snapshot nonces JSON too large: {} bytes (max {})",
                                nonces.len(),
                                MAX_JSON_SIZE
                            )));
                        }
                    }

                    let balances: HashMap<String, u64> = serde_json::from_str(&balances_json)
                        .map_err(|e| GhostError::Serialization(e.to_string()))?;
                    let nonces: Option<HashMap<String, u64>> = nonces_json
                        .map(|json| serde_json::from_str(&json))
                        .transpose()
                        .map_err(|e| GhostError::Serialization(e.to_string()))?;

                    Ok(Some(StateSnapshot {
                        id: Some(id),
                        height: snapshot_height,
                        state_root,
                        balances,
                        nonces,
                        created_at,
                    }))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(GhostError::Database(e.to_string())),
            }
        })
    }

    /// Rollback to a previous height by returning the closest snapshot
    ///
    /// Returns the snapshot to restore from and the target height.
    /// Caller is responsible for replaying blocks from snapshot height to target.
    ///
    /// M-13 FIX: Uses transaction to ensure atomic rollback. Both DELETE operations
    /// must succeed together or be rolled back together to prevent inconsistent state.
    pub fn rollback_to(&self, target_height: u64) -> GhostResult<Option<StateSnapshot>> {
        let snapshot = self.get_snapshot_at_or_before(target_height)?;

        if let Some(ref s) = snapshot {
            info!(
                target_height,
                snapshot_height = s.height,
                "Rolling back to snapshot"
            );

            // M-13 FIX: Use transaction for atomic deletion of both tables
            self.db.transaction(|tx| {
                // Delete any snapshots above target height
                tx.execute(
                    "DELETE FROM state_snapshots WHERE height > ?1",
                    params![target_height as i64],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                // Delete block proposers above target height
                tx.execute(
                    "DELETE FROM block_proposers WHERE height > ?1",
                    params![target_height as i64],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

                Ok(())
            })?;
        } else {
            warn!(target_height, "No snapshot found for rollback");
        }

        Ok(snapshot)
    }

    /// Prune old snapshots beyond retention limit
    ///
    /// M-1 FIX: Uses saturating_sub and validates count to prevent integer underflow.
    /// Even though COUNT(*) should never be negative in SQLite, we defensively
    /// reject negative values to catch database corruption.
    pub fn prune_old_snapshots(&self) -> GhostResult<usize> {
        self.db.with_connection(|conn| {
            // Count current snapshots
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM state_snapshots", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            // M-1 FIX: Validate count is non-negative (catches database corruption)
            if count < 0 {
                return Err(GhostError::Database(format!(
                    "M-1: Invalid negative snapshot count: {}",
                    count
                )));
            }

            let count_usize = count as usize;
            if count_usize <= self.max_snapshots {
                return Ok(0);
            }

            // M-1 FIX: Use saturating_sub for defense in depth
            let to_delete = count_usize.saturating_sub(self.max_snapshots);
            if to_delete == 0 {
                return Ok(0);
            }

            // Delete oldest snapshots
            conn.execute(
                "DELETE FROM state_snapshots WHERE id IN (
                    SELECT id FROM state_snapshots ORDER BY height ASC LIMIT ?1
                )",
                params![to_delete as i64],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            debug!(deleted = to_delete, "Pruned old snapshots");
            Ok(to_delete)
        })
    }

    /// Record a block proposer
    pub fn record_proposer(
        &self,
        height: u64,
        proposer_id: &[u8; 32],
        state_root: &[u8; 32],
    ) -> GhostResult<()> {
        let proposer_hex = hex::encode(proposer_id);
        let state_root_hex = hex::encode(state_root);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.db.with_connection(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO block_proposers (height, proposer_id, state_root, timestamp)
                 VALUES (?1, ?2, ?3, ?4)",
                params![height as i64, proposer_hex, state_root_hex, now],
            ).map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Get the proposer at a specific height
    pub fn get_proposer_at(&self, height: u64) -> GhostResult<Option<BlockProposerRecord>> {
        self.db.with_connection(|conn| {
            let result = conn.query_row(
                "SELECT height, proposer_id, state_root, timestamp
                 FROM block_proposers WHERE height = ?1",
                params![height as i64],
                |row| {
                    let h: i64 = row.get(0)?;
                    let proposer_id: String = row.get(1)?;
                    let state_root: String = row.get(2)?;
                    let timestamp: i64 = row.get(3)?;
                    Ok((h, proposer_id, state_root, timestamp))
                },
            );

            match result {
                Ok((h, proposer_id, state_root, timestamp)) => {
                    // L-17: Safely convert height, rejecting negative values
                    let proposer_height = i64_to_u64_height(h, "proposer")?;
                    Ok(Some(BlockProposerRecord {
                        height: proposer_height,
                        proposer_id,
                        state_root,
                        timestamp,
                    }))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(GhostError::Database(e.to_string())),
            }
        })
    }

    /// Get the latest snapshot height
    pub fn latest_snapshot_height(&self) -> GhostResult<Option<u64>> {
        self.db.with_connection(|conn| {
            let result: Result<Option<i64>, _> =
                conn.query_row("SELECT MAX(height) FROM state_snapshots", [], |row| {
                    row.get(0)
                });

            match result {
                // L-17: Safely convert height, rejecting negative values
                Ok(Some(h)) => Ok(Some(i64_to_u64_height(h, "latest_snapshot")?)),
                Ok(None) => Ok(None),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(GhostError::Database(e.to_string())),
            }
        })
    }

    /// Get snapshot count
    ///
    /// LOW-STOR-2: Validates count is non-negative before conversion
    pub fn snapshot_count(&self) -> GhostResult<usize> {
        self.db.with_connection(|conn| {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM state_snapshots", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            // LOW-STOR-2: Validate non-negative (same as other count functions)
            if count < 0 {
                return Err(GhostError::Database(format!(
                    "Invalid negative snapshot count: {}",
                    count
                )));
            }

            Ok(count as usize)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_test_db() -> Database {
        Database::in_memory().expect("MEDIUM-STOR-2: Failed to create in-memory test database")
    }

    #[test]
    fn test_should_snapshot() {
        let db = setup_test_db();
        let mgr = SnapshotManager::new(db, 100, 50);

        assert!(!mgr.should_snapshot(0));
        assert!(!mgr.should_snapshot(50));
        assert!(mgr.should_snapshot(100));
        assert!(!mgr.should_snapshot(150));
        assert!(mgr.should_snapshot(200));
    }

    #[test]
    fn test_create_and_get_snapshot() {
        let db = setup_test_db();
        let mgr = SnapshotManager::new(db, 100, 50);

        let state_root = [1u8; 32];
        let mut balances = HashMap::new();
        balances.insert("alice".to_string(), 1000);
        balances.insert("bob".to_string(), 2000);

        mgr.create_snapshot(100, &state_root, &balances)
            .expect("MEDIUM-STOR-2: Failed to create snapshot");

        let snapshot = mgr
            .get_snapshot_at(100)
            .expect("MEDIUM-STOR-2: Failed to get snapshot")
            .expect("MEDIUM-STOR-2: Snapshot should exist at height 100");
        assert_eq!(snapshot.height, 100);
        assert_eq!(snapshot.state_root, hex::encode(state_root));
        assert_eq!(snapshot.balances.get("alice"), Some(&1000));
        assert_eq!(snapshot.balances.get("bob"), Some(&2000));
    }

    #[test]
    fn test_get_snapshot_at_or_before() {
        let db = setup_test_db();
        let mgr = SnapshotManager::new(db, 100, 50);

        let state_root = [1u8; 32];
        let balances = HashMap::new();

        mgr.create_snapshot(100, &state_root, &balances)
            .expect("LOW-STOR-8: Failed to create snapshot at height 100");
        mgr.create_snapshot(200, &[2u8; 32], &balances)
            .expect("LOW-STOR-8: Failed to create snapshot at height 200");

        // Exact match
        let snapshot = mgr
            .get_snapshot_at_or_before(100)
            .expect("LOW-STOR-8: Failed to query snapshot")
            .expect("LOW-STOR-8: Snapshot should exist at height 100");
        assert_eq!(snapshot.height, 100);

        // Before
        let snapshot = mgr
            .get_snapshot_at_or_before(150)
            .expect("LOW-STOR-8: Failed to query snapshot")
            .expect("LOW-STOR-8: Snapshot should exist at or before height 150");
        assert_eq!(snapshot.height, 100);

        // Latest
        let snapshot = mgr
            .get_snapshot_at_or_before(250)
            .expect("LOW-STOR-8: Failed to query snapshot")
            .expect("LOW-STOR-8: Snapshot should exist at or before height 250");
        assert_eq!(snapshot.height, 200);

        // None before
        let snapshot = mgr
            .get_snapshot_at_or_before(50)
            .expect("LOW-STOR-8: Failed to query snapshot");
        assert!(snapshot.is_none());
    }

    #[test]
    fn test_rollback() {
        let db = setup_test_db();
        let mgr = SnapshotManager::new(db, 100, 50);

        let balances = HashMap::new();
        mgr.create_snapshot(100, &[1u8; 32], &balances)
            .expect("LOW-STOR-8: Failed to create snapshot at height 100");
        mgr.create_snapshot(200, &[2u8; 32], &balances)
            .expect("LOW-STOR-8: Failed to create snapshot at height 200");
        mgr.create_snapshot(300, &[3u8; 32], &balances)
            .expect("LOW-STOR-8: Failed to create snapshot at height 300");

        // Rollback to 150 should return snapshot at 100
        let snapshot = mgr
            .rollback_to(150)
            .expect("LOW-STOR-8: Failed to rollback")
            .expect("LOW-STOR-8: Rollback should return snapshot at height 100");
        assert_eq!(snapshot.height, 100);

        // Snapshots at 200 and 300 should be deleted
        assert!(mgr
            .get_snapshot_at(200)
            .expect("LOW-STOR-8: Failed to query snapshot")
            .is_none());
        assert!(mgr
            .get_snapshot_at(300)
            .expect("LOW-STOR-8: Failed to query snapshot")
            .is_none());
        assert!(mgr
            .get_snapshot_at(100)
            .expect("LOW-STOR-8: Failed to query snapshot")
            .is_some());
    }

    #[test]
    fn test_prune_old_snapshots() {
        let db = setup_test_db();
        let mgr = SnapshotManager::new(db, 10, 3); // Keep only 3

        let balances = HashMap::new();
        for i in 1..=5 {
            mgr.create_snapshot(i * 10, &[i as u8; 32], &balances)
                .expect("LOW-STOR-8: Failed to create snapshot");
        }

        // Should have pruned to 3
        assert_eq!(
            mgr.snapshot_count()
                .expect("LOW-STOR-8: Failed to count snapshots"),
            3
        );

        // Should have kept the latest 3 (30, 40, 50)
        assert!(mgr
            .get_snapshot_at(10)
            .expect("LOW-STOR-8: Failed to query snapshot")
            .is_none());
        assert!(mgr
            .get_snapshot_at(20)
            .expect("LOW-STOR-8: Failed to query snapshot")
            .is_none());
        assert!(mgr
            .get_snapshot_at(30)
            .expect("LOW-STOR-8: Failed to query snapshot")
            .is_some());
        assert!(mgr
            .get_snapshot_at(40)
            .expect("LOW-STOR-8: Failed to query snapshot")
            .is_some());
        assert!(mgr
            .get_snapshot_at(50)
            .expect("LOW-STOR-8: Failed to query snapshot")
            .is_some());
    }

    #[test]
    fn test_record_and_get_proposer() {
        let db = setup_test_db();
        let mgr = SnapshotManager::new(db, 100, 50);

        let proposer = [0xABu8; 32];
        let state_root = [0xCDu8; 32];

        mgr.record_proposer(100, &proposer, &state_root)
            .expect("LOW-STOR-8: Failed to record proposer");

        let record = mgr
            .get_proposer_at(100)
            .expect("LOW-STOR-8: Failed to get proposer")
            .expect("LOW-STOR-8: Proposer should exist at height 100");
        assert_eq!(record.height, 100);
        assert_eq!(record.proposer_id, hex::encode(proposer));
        assert_eq!(record.state_root, hex::encode(state_root));

        // Non-existent
        assert!(mgr
            .get_proposer_at(50)
            .expect("LOW-STOR-8: Failed to query proposer")
            .is_none());
    }

    #[test]
    fn test_json_size_limit_enforced() {
        // L-STOR-1: Test that oversized JSON is rejected
        let db = setup_test_db();

        // Insert a snapshot with oversized balances_json directly via SQL
        db.with_connection(|conn| {
            let oversized_json = "x".repeat(super::MAX_JSON_SIZE + 1);
            conn.execute(
                "INSERT INTO state_snapshots (height, state_root, balances_json, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![100i64, "abc", oversized_json, 12345i64],
            )
            .expect("LOW-STOR-8: Failed to insert oversized snapshot");
            Ok(())
        })
        .expect("LOW-STOR-8: Failed to execute with_connection");

        let mgr = SnapshotManager::new(db, 100, 50);

        // Should fail with size limit error
        let result = mgr.get_snapshot_at(100);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("too large"),
            "Expected size limit error, got: {}",
            err_msg
        );
    }
}
