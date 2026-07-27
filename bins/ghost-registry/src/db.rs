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
//| FILE: db.rs                                                                                                          |
//|======================================================================================================================|

//! SQLite database for node storage

use chrono::{DateTime, Utc};
use ghost_common::config::Region;
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

/// Database errors
#[derive(Debug, Error)]
pub(crate) enum DbError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("Node not found: {0}")]
    NodeNotFound(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

/// Pool node record stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PoolNode {
    /// Unique node identifier (secp256k1 public key hex)
    pub node_id: String,
    /// Public IP address or hostname
    pub host: String,
    /// Stratum V1 port
    pub sv1_port: u16,
    /// Stratum V2 port
    pub sv2_port: u16,
    /// Geographic region
    pub region: Region,
    /// Latitude (optional)
    pub latitude: Option<f64>,
    /// Longitude (optional)
    pub longitude: Option<f64>,
    /// Maximum miners capacity
    pub max_miners: u32,
    /// Current miner count
    pub miner_count: u32,
    /// Current load percentage (0-100)
    pub load_percent: u8,
    /// CPU usage percentage
    pub cpu_percent: u8,
    /// Memory usage percentage
    pub memory_percent: u8,
    /// Is node healthy
    pub healthy: bool,
    /// Is accepting new miners
    pub accepting_miners: bool,
    /// Excluded from DNS due to high load (hysteresis flag)
    pub excluded_for_load: bool,
    /// First registration timestamp
    pub registered_at: DateTime<Utc>,
    /// Last heartbeat timestamp
    pub last_heartbeat: DateTime<Utc>,
}

impl PoolNode {
    /// Calculate a score for load balancing (lower is better)
    pub(crate) fn load_score(&self) -> f64 {
        if !self.healthy || !self.accepting_miners {
            return f64::MAX;
        }

        // Base score from load percentage
        let mut score = self.load_percent as f64;

        // Add penalty for CPU usage
        score += (self.cpu_percent as f64) * 0.3;

        // Add penalty for memory usage
        score += (self.memory_percent as f64) * 0.2;

        // Add penalty for approaching capacity
        if self.max_miners > 0 {
            let capacity_ratio = self.miner_count as f64 / self.max_miners as f64;
            if capacity_ratio > 0.9 {
                score += 50.0;
            } else if capacity_ratio > 0.75 {
                score += 20.0;
            }
        }

        score
    }
}

// =============================================================================
// H-17: RAII UMASK GUARD FOR PERMISSION HARDENING
// =============================================================================

/// H-17: RAII guard that restores the original umask on drop.
/// Ensures umask is restored even if a panic occurs during file creation.
#[cfg(unix)]
struct UmaskGuard {
    old_umask: libc::mode_t,
}

#[cfg(unix)]
impl UmaskGuard {
    /// Set a restrictive umask and return a guard that restores the original on drop.
    /// umask 0o077 means: remove all permissions for group and others.
    fn new_restrictive() -> Self {
        // SAFETY: libc::umask is a POSIX standard function that:
        // 1. Atomically sets the process umask to the specified value
        // 2. Returns the previous umask value (which we store for restoration)
        // 3. Has no failure mode - it always succeeds
        // 4. Only affects file creation permissions, not existing files
        let old_umask = unsafe { libc::umask(0o077) };
        Self { old_umask }
    }
}

#[cfg(unix)]
impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: libc::umask is a POSIX standard function that:
        // 1. Atomically restores the process umask to the original value
        // 2. Has no failure mode - it always succeeds
        // 3. old_umask was obtained from a previous umask call, so it's valid
        unsafe {
            libc::umask(self.old_umask);
        }
    }
}

/// Database handle
pub(crate) struct RegistryDb {
    conn: Arc<Mutex<Connection>>,
}

impl RegistryDb {
    /// Maximum rows returned by unbounded queries (M-23: OOM prevention)
    pub(crate) const MAX_QUERY_RESULTS: u32 = 10000;

    /// Open or create database at path
    ///
    /// H-17 FIX: Uses UmaskGuard to create files with restrictive permissions (0o600).
    pub(crate) fn open(path: &Path) -> Result<Self, DbError> {
        // H-17 FIX: Set restrictive umask before creating any files.
        // Uses RAII guard to ensure umask is restored even on panic.
        // umask 0o077 means: remove all permissions for group and others
        // Directory 0o777 & !0o077 = 0o700
        // File 0o666 & !0o077 = 0o600
        #[cfg(unix)]
        let _umask_guard = UmaskGuard::new_restrictive();

        // Ensure parent directory exists (now created with 0o700 due to umask)
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                DbError::InvalidData(format!("Failed to create db directory: {}", e))
            })?;
        }

        // Open database (file created with 0o600 due to umask)
        let conn = Connection::open(path)?;

        // H-17: UmaskGuard is dropped here automatically when going out of scope,
        // restoring original umask. This happens even if an error occurred above
        // due to the RAII pattern.
        #[cfg(unix)]
        drop(_umask_guard);

        // Enable WAL mode for better concurrent access
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        // H-17 FIX: Verify permissions are correct and fix if needed
        // This handles cases where the file existed before with wrong permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            if let Ok(metadata) = std::fs::metadata(path) {
                let perms = metadata.permissions();
                if perms.mode() & 0o077 != 0 {
                    tracing::warn!(
                        path = %path.display(),
                        mode = format!("{:o}", perms.mode()),
                        "H-17: Registry database file has weak permissions, fixing..."
                    );
                    let mut new_perms = perms;
                    new_perms.set_mode(0o600);
                    std::fs::set_permissions(path, new_perms).map_err(|e| {
                        DbError::InvalidData(format!(
                            "Failed to secure database file permissions: {}",
                            e
                        ))
                    })?;
                }
            }
        }

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        db.init_schema()?;

        Ok(db)
    }

    /// Initialize database schema
    fn init_schema(&self) -> Result<(), DbError> {
        let conn = self.conn.lock();

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                sv1_port INTEGER NOT NULL,
                sv2_port INTEGER NOT NULL,
                region TEXT NOT NULL,
                latitude REAL,
                longitude REAL,
                max_miners INTEGER NOT NULL DEFAULT 1000,
                miner_count INTEGER NOT NULL DEFAULT 0,
                load_percent INTEGER NOT NULL DEFAULT 0,
                cpu_percent INTEGER NOT NULL DEFAULT 0,
                memory_percent INTEGER NOT NULL DEFAULT 0,
                healthy INTEGER NOT NULL DEFAULT 1,
                accepting_miners INTEGER NOT NULL DEFAULT 1,
                excluded_for_load INTEGER NOT NULL DEFAULT 0,
                registered_at TEXT NOT NULL,
                last_heartbeat TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_nodes_region ON nodes(region);
            CREATE INDEX IF NOT EXISTS idx_nodes_healthy ON nodes(healthy);
            CREATE INDEX IF NOT EXISTS idx_nodes_last_heartbeat ON nodes(last_heartbeat);
            "#,
        )?;

        // Migration: add excluded_for_load column if missing (ignore error if exists)
        let _ = conn.execute(
            "ALTER TABLE nodes ADD COLUMN excluded_for_load INTEGER NOT NULL DEFAULT 0",
            [],
        );

        Ok(())
    }

    /// Register or update a node
    pub(crate) fn upsert_node(&self, node: &PoolNode) -> Result<(), DbError> {
        let conn = self.conn.lock();

        conn.execute(
            r#"
            INSERT INTO nodes (
                node_id, host, sv1_port, sv2_port, region,
                latitude, longitude, max_miners, miner_count,
                load_percent, cpu_percent, memory_percent,
                healthy, accepting_miners, registered_at, last_heartbeat
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            ON CONFLICT(node_id) DO UPDATE SET
                host = excluded.host,
                sv1_port = excluded.sv1_port,
                sv2_port = excluded.sv2_port,
                region = excluded.region,
                latitude = excluded.latitude,
                longitude = excluded.longitude,
                max_miners = excluded.max_miners,
                last_heartbeat = excluded.last_heartbeat
            "#,
            params![
                node.node_id,
                node.host,
                node.sv1_port,
                node.sv2_port,
                region_to_string(node.region),
                node.latitude,
                node.longitude,
                node.max_miners,
                node.miner_count,
                node.load_percent,
                node.cpu_percent,
                node.memory_percent,
                node.healthy,
                node.accepting_miners,
                node.registered_at.to_rfc3339(),
                node.last_heartbeat.to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    /// Update node heartbeat data
    pub(crate) fn update_heartbeat(
        &self,
        node_id: &str,
        miner_count: u32,
        load_percent: u8,
        cpu_percent: u8,
        memory_percent: u8,
        accepting_miners: bool,
    ) -> Result<(), DbError> {
        let conn = self.conn.lock();

        let rows = conn.execute(
            r#"
            UPDATE nodes SET
                miner_count = ?2,
                load_percent = ?3,
                cpu_percent = ?4,
                memory_percent = ?5,
                accepting_miners = ?6,
                healthy = 1,
                last_heartbeat = ?7
            WHERE node_id = ?1
            "#,
            params![
                node_id,
                miner_count,
                load_percent,
                cpu_percent,
                memory_percent,
                accepting_miners,
                Utc::now().to_rfc3339(),
            ],
        )?;

        if rows == 0 {
            return Err(DbError::NodeNotFound(node_id.to_string()));
        }

        Ok(())
    }

    /// Get a node by ID
    pub(crate) fn get_node(&self, node_id: &str) -> Result<Option<PoolNode>, DbError> {
        let conn = self.conn.lock();

        let mut stmt = conn.prepare(
            r#"
            SELECT node_id, host, sv1_port, sv2_port, region,
                   latitude, longitude, max_miners, miner_count,
                   load_percent, cpu_percent, memory_percent,
                   healthy, accepting_miners, excluded_for_load,
                   registered_at, last_heartbeat
            FROM nodes WHERE node_id = ?1
            "#,
        )?;

        let node = stmt
            .query_row(params![node_id], |row| {
                Ok(PoolNode {
                    node_id: row.get(0)?,
                    host: row.get(1)?,
                    sv1_port: row.get(2)?,
                    sv2_port: row.get(3)?,
                    region: string_to_region(&row.get::<_, String>(4)?),
                    latitude: row.get(5)?,
                    longitude: row.get(6)?,
                    max_miners: row.get(7)?,
                    miner_count: row.get(8)?,
                    load_percent: row.get(9)?,
                    cpu_percent: row.get(10)?,
                    memory_percent: row.get(11)?,
                    healthy: row.get(12)?,
                    accepting_miners: row.get(13)?,
                    excluded_for_load: row.get(14)?,
                    registered_at: parse_datetime(&row.get::<_, String>(15)?),
                    last_heartbeat: parse_datetime(&row.get::<_, String>(16)?),
                })
            })
            .optional()?;

        Ok(node)
    }

    /// Get all nodes
    ///
    /// M-23 FIX: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub(crate) fn get_all_nodes(&self) -> Result<Vec<PoolNode>, DbError> {
        let conn = self.conn.lock();

        let mut stmt = conn.prepare(
            r#"
            SELECT node_id, host, sv1_port, sv2_port, region,
                   latitude, longitude, max_miners, miner_count,
                   load_percent, cpu_percent, memory_percent,
                   healthy, accepting_miners, excluded_for_load,
                   registered_at, last_heartbeat
            FROM nodes ORDER BY region, load_percent LIMIT ?1
            "#,
        )?;

        let nodes = stmt
            .query_map(params![Self::MAX_QUERY_RESULTS], |row| {
                Ok(PoolNode {
                    node_id: row.get(0)?,
                    host: row.get(1)?,
                    sv1_port: row.get(2)?,
                    sv2_port: row.get(3)?,
                    region: string_to_region(&row.get::<_, String>(4)?),
                    latitude: row.get(5)?,
                    longitude: row.get(6)?,
                    max_miners: row.get(7)?,
                    miner_count: row.get(8)?,
                    load_percent: row.get(9)?,
                    cpu_percent: row.get(10)?,
                    memory_percent: row.get(11)?,
                    healthy: row.get(12)?,
                    accepting_miners: row.get(13)?,
                    excluded_for_load: row.get(14)?,
                    registered_at: parse_datetime(&row.get::<_, String>(15)?),
                    last_heartbeat: parse_datetime(&row.get::<_, String>(16)?),
                })
            })?
            .collect::<SqliteResult<Vec<_>>>()?;

        Ok(nodes)
    }

    /// Get healthy nodes by region, sorted by load score
    /// Excludes nodes that are marked as excluded_for_load (hysteresis)
    ///
    /// M-23 FIX: Limited to MAX_QUERY_RESULTS rows to prevent OOM attacks
    pub(crate) fn get_healthy_nodes_by_region(
        &self,
        region: Region,
    ) -> Result<Vec<PoolNode>, DbError> {
        let conn = self.conn.lock();

        let mut stmt = conn.prepare(
            r#"
            SELECT node_id, host, sv1_port, sv2_port, region,
                   latitude, longitude, max_miners, miner_count,
                   load_percent, cpu_percent, memory_percent,
                   healthy, accepting_miners, excluded_for_load,
                   registered_at, last_heartbeat
            FROM nodes
            WHERE region = ?1 AND healthy = 1 AND accepting_miners = 1 AND excluded_for_load = 0
            ORDER BY load_percent ASC, miner_count ASC
            LIMIT ?2
            "#,
        )?;

        let nodes = stmt
            .query_map(
                params![region_to_string(region), Self::MAX_QUERY_RESULTS],
                |row| {
                    Ok(PoolNode {
                        node_id: row.get(0)?,
                        host: row.get(1)?,
                        sv1_port: row.get(2)?,
                        sv2_port: row.get(3)?,
                        region: string_to_region(&row.get::<_, String>(4)?),
                        latitude: row.get(5)?,
                        longitude: row.get(6)?,
                        max_miners: row.get(7)?,
                        miner_count: row.get(8)?,
                        load_percent: row.get(9)?,
                        cpu_percent: row.get(10)?,
                        memory_percent: row.get(11)?,
                        healthy: row.get(12)?,
                        accepting_miners: row.get(13)?,
                        excluded_for_load: row.get(14)?,
                        registered_at: parse_datetime(&row.get::<_, String>(15)?),
                        last_heartbeat: parse_datetime(&row.get::<_, String>(16)?),
                    })
                },
            )?
            .collect::<SqliteResult<Vec<_>>>()?;

        Ok(nodes)
    }

    /// Update load exclusion flags based on hysteresis thresholds
    /// Sets excluded_for_load = 1 when load >= max_load_percent
    /// Sets excluded_for_load = 0 when load < resume_load_percent
    ///
    /// M-24 FIX: Wrapped in transaction for atomicity. Both updates succeed
    /// or both fail together, preventing inconsistent state.
    pub(crate) fn update_load_exclusions(
        &self,
        max_load_percent: u8,
        resume_load_percent: u8,
    ) -> Result<(usize, usize), DbError> {
        let mut conn = self.conn.lock();

        // M-24 FIX: Use transaction for atomic update
        let tx = conn.transaction()?;

        // Exclude nodes that exceed max load
        let excluded = tx.execute(
            "UPDATE nodes SET excluded_for_load = 1 WHERE load_percent >= ?1 AND excluded_for_load = 0",
            params![max_load_percent],
        )?;

        // Re-include nodes that dropped below resume threshold
        let included = tx.execute(
            "UPDATE nodes SET excluded_for_load = 0 WHERE load_percent < ?1 AND excluded_for_load = 1",
            params![resume_load_percent],
        )?;

        // M-24: Commit transaction - both updates succeed or both fail
        tx.commit()?;

        Ok((excluded, included))
    }

    /// Mark stale nodes as unhealthy
    pub(crate) fn mark_stale_nodes_unhealthy(&self, timeout_secs: i64) -> Result<usize, DbError> {
        let conn = self.conn.lock();
        let cutoff = Utc::now() - chrono::Duration::seconds(timeout_secs);

        let rows = conn.execute(
            r#"
            UPDATE nodes SET healthy = 0
            WHERE healthy = 1 AND last_heartbeat < ?1
            "#,
            params![cutoff.to_rfc3339()],
        )?;

        Ok(rows)
    }

    /// Delete a node
    pub(crate) fn delete_node(&self, node_id: &str) -> Result<bool, DbError> {
        let conn = self.conn.lock();

        let rows = conn.execute("DELETE FROM nodes WHERE node_id = ?1", params![node_id])?;

        Ok(rows > 0)
    }

    /// Get region statistics
    pub(crate) fn get_region_stats(&self) -> Result<Vec<RegionStats>, DbError> {
        let conn = self.conn.lock();

        let mut stmt = conn.prepare(
            r#"
            SELECT region,
                   COUNT(*) as total_nodes,
                   SUM(CASE WHEN healthy = 1 THEN 1 ELSE 0 END) as healthy_nodes,
                   SUM(miner_count) as total_miners,
                   AVG(load_percent) as avg_load
            FROM nodes
            GROUP BY region
            "#,
        )?;

        let stats = stmt
            .query_map([], |row| {
                Ok(RegionStats {
                    region: string_to_region(&row.get::<_, String>(0)?),
                    total_nodes: row.get(1)?,
                    healthy_nodes: row.get(2)?,
                    total_miners: row.get(3)?,
                    avg_load: row.get(4)?,
                })
            })?
            .collect::<SqliteResult<Vec<_>>>()?;

        Ok(stats)
    }

    /// Get count of all nodes
    ///
    /// L-25 FIX: Validates count is non-negative before converting to usize.
    pub(crate) fn get_node_count(&self) -> Result<usize, DbError> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM nodes", [], |row| row.get(0))?;
        // L-25 FIX: Validate non-negative before usize cast
        if count < 0 {
            return Err(DbError::InvalidData(format!(
                "Invalid negative node count: {}",
                count
            )));
        }
        Ok(count as usize)
    }

    /// Get count of healthy nodes
    ///
    /// L-25 FIX: Validates count is non-negative before converting to usize.
    pub(crate) fn get_healthy_node_count(&self) -> Result<usize, DbError> {
        let conn = self.conn.lock();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM nodes WHERE healthy = 1", [], |row| {
                row.get(0)
            })?;
        // L-25 FIX: Validate non-negative before usize cast
        if count < 0 {
            return Err(DbError::InvalidData(format!(
                "Invalid negative healthy node count: {}",
                count
            )));
        }
        Ok(count as usize)
    }

    /// Get node status with rank information
    pub(crate) fn get_node_status(&self, node_id: &str) -> Result<Option<NodeStatus>, DbError> {
        let conn = self.conn.lock();

        // Get the node first
        let node: Option<(String, u8, bool, bool, bool, String, String)> = conn
            .query_row(
                r#"
                SELECT region, load_percent, healthy, accepting_miners, excluded_for_load,
                       registered_at, last_heartbeat
                FROM nodes WHERE node_id = ?1
                "#,
                params![node_id],
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
            .optional()?;

        let Some((
            region_str,
            load_percent,
            healthy,
            accepting_miners,
            excluded_for_load,
            registered_at,
            last_heartbeat,
        )) = node
        else {
            return Ok(None);
        };

        let region = string_to_region(&region_str);

        // Get rank in region (by load, lower is better)
        let rank: i64 = conn.query_row(
            r#"
            SELECT COUNT(*) + 1 FROM nodes
            WHERE region = ?1 AND load_percent < ?2 AND healthy = 1
            "#,
            params![region_str, load_percent],
            |row| row.get(0),
        )?;

        // Get total nodes in region
        let total_in_region: i64 = conn.query_row(
            "SELECT COUNT(*) FROM nodes WHERE region = ?1",
            params![region_str],
            |row| row.get(0),
        )?;

        // Get healthy nodes in region
        let healthy_in_region: i64 = conn.query_row(
            "SELECT COUNT(*) FROM nodes WHERE region = ?1 AND healthy = 1",
            params![region_str],
            |row| row.get(0),
        )?;

        // Node is in DNS if healthy, accepting miners, and not excluded for load
        let in_dns = healthy && accepting_miners && !excluded_for_load;

        Ok(Some(NodeStatus {
            registered: true,
            in_dns,
            healthy,
            accepting_miners,
            excluded_for_load,
            load_percent,
            rank_in_region: rank as u32,
            total_in_region: total_in_region as u32,
            healthy_in_region: healthy_in_region as u32,
            region,
            registered_at: parse_datetime(&registered_at),
            last_heartbeat: parse_datetime(&last_heartbeat),
        }))
    }
}

/// Node status with rank information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct NodeStatus {
    pub registered: bool,
    pub in_dns: bool,
    pub healthy: bool,
    pub accepting_miners: bool,
    pub excluded_for_load: bool,
    pub load_percent: u8,
    pub rank_in_region: u32,
    pub total_in_region: u32,
    pub healthy_in_region: u32,
    pub region: Region,
    pub registered_at: DateTime<Utc>,
    pub last_heartbeat: DateTime<Utc>,
}

/// Region statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RegionStats {
    pub region: Region,
    pub total_nodes: u32,
    pub healthy_nodes: u32,
    pub total_miners: u32,
    pub avg_load: f64,
}

// Helper functions for Region conversion
fn region_to_string(region: Region) -> String {
    match region {
        Region::UsEast => "us_east".to_string(),
        Region::UsWest => "us_west".to_string(),
        Region::EuWest => "eu_west".to_string(),
        Region::EuCentral => "eu_central".to_string(),
        Region::AsiaSoutheast => "asia_southeast".to_string(),
        Region::AsiaNortheast => "asia_northeast".to_string(),
        Region::Oceania => "oceania".to_string(),
        Region::SouthAmerica => "south_america".to_string(),
        Region::Africa => "africa".to_string(),
        Region::Unknown => "unknown".to_string(),
    }
}

fn string_to_region(s: &str) -> Region {
    match s {
        "us_east" => Region::UsEast,
        "us_west" => Region::UsWest,
        "eu_west" => Region::EuWest,
        "eu_central" => Region::EuCentral,
        "asia_southeast" => Region::AsiaSoutheast,
        "asia_northeast" => Region::AsiaNortheast,
        "oceania" => Region::Oceania,
        "south_america" => Region::SouthAmerica,
        "africa" => Region::Africa,
        _ => Region::Unknown,
    }
}

fn parse_datetime(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_node(node_id: &str, region: Region) -> PoolNode {
        PoolNode {
            node_id: node_id.to_string(),
            host: "192.168.1.1".to_string(),
            sv1_port: 3333,
            sv2_port: 34255,
            region,
            latitude: None,
            longitude: None,
            max_miners: 1000,
            miner_count: 100,
            load_percent: 10,
            cpu_percent: 20,
            memory_percent: 30,
            healthy: true,
            accepting_miners: true,
            excluded_for_load: false,
            registered_at: Utc::now(),
            last_heartbeat: Utc::now(),
        }
    }

    #[test]
    fn test_db_open_and_schema() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = RegistryDb::open(&db_path).unwrap();

        assert_eq!(db.get_node_count().unwrap(), 0);
    }

    #[test]
    fn test_node_upsert_and_get() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = RegistryDb::open(&db_path).unwrap();

        let node = create_test_node("test_node_1", Region::EuWest);
        db.upsert_node(&node).unwrap();

        let retrieved = db.get_node("test_node_1").unwrap().unwrap();
        assert_eq!(retrieved.node_id, "test_node_1");
        assert_eq!(retrieved.host, "192.168.1.1");
        assert!(matches!(retrieved.region, Region::EuWest));
    }

    #[test]
    fn test_heartbeat_update() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = RegistryDb::open(&db_path).unwrap();

        let node = create_test_node("test_node_2", Region::UsEast);
        db.upsert_node(&node).unwrap();

        db.update_heartbeat("test_node_2", 500, 75, 60, 50, true)
            .unwrap();

        let retrieved = db.get_node("test_node_2").unwrap().unwrap();
        assert_eq!(retrieved.miner_count, 500);
        assert_eq!(retrieved.load_percent, 75);
    }

    #[test]
    fn test_region_query() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = RegistryDb::open(&db_path).unwrap();

        db.upsert_node(&create_test_node("eu1", Region::EuWest))
            .unwrap();
        db.upsert_node(&create_test_node("eu2", Region::EuWest))
            .unwrap();
        db.upsert_node(&create_test_node("us1", Region::UsEast))
            .unwrap();

        let eu_nodes = db.get_healthy_nodes_by_region(Region::EuWest).unwrap();
        assert_eq!(eu_nodes.len(), 2);

        let us_nodes = db.get_healthy_nodes_by_region(Region::UsEast).unwrap();
        assert_eq!(us_nodes.len(), 1);
    }

    #[test]
    fn test_load_score() {
        let mut node = create_test_node("score_test", Region::EuWest);
        node.load_percent = 50;
        node.cpu_percent = 40;
        node.memory_percent = 30;

        let score = node.load_score();
        assert!(score > 50.0); // Base load + CPU + memory penalties
    }

    #[test]
    fn test_load_exclusion_hysteresis() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = RegistryDb::open(&db_path).unwrap();

        // Create node at 75% load (between resume=70 and max=80)
        let mut node = create_test_node("test1", Region::EuWest);
        node.load_percent = 75;
        db.upsert_node(&node).unwrap();

        // Should be in DNS (not excluded)
        let nodes = db.get_healthy_nodes_by_region(Region::EuWest).unwrap();
        assert_eq!(nodes.len(), 1);

        // Simulate load spike to 85% - should get excluded
        db.update_heartbeat("test1", 0, 85, 0, 0, true).unwrap();
        let (excluded, _) = db.update_load_exclusions(80, 70).unwrap();
        assert_eq!(excluded, 1);

        // Should not be in DNS
        let nodes = db.get_healthy_nodes_by_region(Region::EuWest).unwrap();
        assert_eq!(nodes.len(), 0);

        // Load drops to 75% - still excluded (hysteresis)
        db.update_heartbeat("test1", 0, 75, 0, 0, true).unwrap();
        let (_, included) = db.update_load_exclusions(80, 70).unwrap();
        assert_eq!(included, 0); // Still above 70%, not re-included

        let nodes = db.get_healthy_nodes_by_region(Region::EuWest).unwrap();
        assert_eq!(nodes.len(), 0);

        // Load drops to 65% - now re-included
        db.update_heartbeat("test1", 0, 65, 0, 0, true).unwrap();
        let (_, included) = db.update_load_exclusions(80, 70).unwrap();
        assert_eq!(included, 1);

        let nodes = db.get_healthy_nodes_by_region(Region::EuWest).unwrap();
        assert_eq!(nodes.len(), 1);
    }
}
