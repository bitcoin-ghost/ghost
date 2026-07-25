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
//| FILE: database.rs                                                                                                    |
//|======================================================================================================================|

//! Database connection and management

use parking_lot::{Mutex, RwLock};
use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{debug, info, warn};

use ghost_common::error::{GhostError, GhostResult};

// =============================================================================
// L-14: RAII UMASK GUARD
// =============================================================================

/// L-14: RAII guard that restores the original umask on drop.
/// Ensures umask is restored even if a panic occurs during file creation.
#[cfg(unix)]
pub struct UmaskGuard {
    old_umask: libc::mode_t,
}

#[cfg(unix)]
impl UmaskGuard {
    /// Set a restrictive umask and return a guard that restores the original on drop.
    /// umask 0o077 means: remove all permissions for group and others.
    pub fn new_restrictive() -> Self {
        // SAFETY: libc::umask is a POSIX standard function that:
        // 1. Atomically sets the process umask to the specified value
        // 2. Returns the previous umask value (which we store for restoration)
        // 3. Has no failure mode - it always succeeds
        // 4. Only affects file creation permissions, not existing files
        // The returned old_umask is always valid as umask cannot fail.
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
        // This restoration is critical for RAII: we must restore the umask
        // even if a panic occurs, which Drop guarantees.
        unsafe {
            libc::umask(self.old_umask);
        }
    }
}

/// Configuration for database retry behavior
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial backoff delay in milliseconds
    pub initial_backoff_ms: u64,
    /// Maximum backoff delay in milliseconds
    pub max_backoff_ms: u64,
    /// Backoff multiplier (exponential factor)
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_backoff_ms: 10,
            max_backoff_ms: 1000,
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    /// Create a config for aggressive retries (more attempts, longer waits)
    pub fn aggressive() -> Self {
        Self {
            max_retries: 10,
            initial_backoff_ms: 50,
            max_backoff_ms: 5000,
            backoff_multiplier: 2.0,
        }
    }

    /// Create a config for quick operations (fewer retries, shorter waits)
    pub fn quick() -> Self {
        Self {
            max_retries: 3,
            initial_backoff_ms: 5,
            max_backoff_ms: 100,
            backoff_multiplier: 2.0,
        }
    }
}

/// Check if a database error is transient and should be retried
fn is_transient_error(error: &GhostError) -> bool {
    match error {
        GhostError::Database(msg) => {
            // SQLite error codes that are transient
            let transient_patterns = [
                "database is locked",
                "SQLITE_BUSY",
                "SQLITE_LOCKED",
                "database table is locked",
                "cannot start a transaction within a transaction",
                "disk I/O error",
            ];
            transient_patterns
                .iter()
                .any(|pattern| msg.contains(pattern))
        }
        _ => false,
    }
}

/// Execute a fallible operation with retry logic
fn retry_with_backoff<F, T>(config: &RetryConfig, operation_name: &str, mut f: F) -> GhostResult<T>
where
    F: FnMut() -> GhostResult<T>,
{
    let mut attempt = 0;
    let mut backoff_ms = config.initial_backoff_ms;

    loop {
        match f() {
            Ok(result) => return Ok(result),
            Err(e) if is_transient_error(&e) && attempt < config.max_retries => {
                attempt += 1;
                warn!(
                    operation = operation_name,
                    attempt,
                    max_retries = config.max_retries,
                    backoff_ms,
                    error = %e,
                    "Transient database error, retrying"
                );
                thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = ((backoff_ms as f64 * config.backoff_multiplier) as u64)
                    .min(config.max_backoff_ms);
            }
            Err(e) => {
                if attempt > 0 {
                    warn!(
                        operation = operation_name,
                        attempts = attempt + 1,
                        "Database operation failed after retries"
                    );
                }
                return Err(e);
            }
        }
    }
}

use crate::migrations::run_migrations;

/// Database handle with connection pooling
#[derive(Clone)]
pub struct Database {
    inner: Arc<DatabaseInner>,
}

struct DatabaseInner {
    /// Primary connection (write)
    write_conn: Mutex<Connection>,
    /// Database path
    path: String,
    /// Whether this is an in-memory database
    in_memory: bool,
    /// P-4: Encryption key for payout addresses (at-rest encryption)
    encryption_key: RwLock<Option<[u8; 32]>>,
}

/// Tables a valid Ghost pool-database backup MUST contain. Used by
/// [`Database::verify_backup_file`] to reject a file that opens as SQLite but
/// isn't actually a Ghost pool database.
pub const REQUIRED_BACKUP_TABLES: &[&str] = &["miners", "shares", "rounds"];

/// Outcome of [`Database::verify_backup_file`]. Purely informational — reading
/// it never touches the live database or the artifact.
#[derive(Debug, Clone)]
pub struct BackupVerification {
    /// Overall verdict: integrity check passed AND all required tables present.
    pub valid: bool,
    /// `PRAGMA integrity_check` returned `ok`.
    pub integrity_ok: bool,
    /// The artifact was opened as a SQLCipher-encrypted file (`true`) using the
    /// node key, or as plain SQLite (`false`).
    pub encrypted: bool,
    /// `PRAGMA user_version` (schema version) read from the artifact.
    pub schema_version: u32,
    /// Required Ghost tables that were found.
    pub tables_present: Vec<String>,
    /// Required Ghost tables that were missing (empty when `valid`).
    pub missing_tables: Vec<String>,
    /// Total number of tables in the artifact.
    pub table_count: u64,
    /// Row count of the `miners` table (0 when absent).
    pub miner_count: u64,
    /// Size of the artifact on disk, in bytes.
    pub size_bytes: u64,
    /// Human-readable reason when not `valid`.
    pub detail: Option<String>,
}

impl BackupVerification {
    /// Construct a failed verification that never opened as a database.
    fn failed(size_bytes: u64, detail: &str) -> Self {
        Self {
            valid: false,
            integrity_ok: false,
            encrypted: false,
            schema_version: 0,
            tables_present: Vec::new(),
            missing_tables: REQUIRED_BACKUP_TABLES
                .iter()
                .map(|t| t.to_string())
                .collect(),
            table_count: 0,
            miner_count: 0,
            size_bytes,
            detail: Some(detail.to_string()),
        }
    }
}

/// Path where a validated restore artifact is staged, adjacent to the live DB.
/// The suffix is appended (not an extension replacement) so the file sits next
/// to `ghost.db` as `ghost.db.restore-pending` on the same filesystem, making
/// the final swap in [`apply_pending_restore`] an atomic rename.
pub fn pending_restore_path(db_path: &Path) -> std::path::PathBuf {
    let mut os = db_path.as_os_str().to_os_string();
    os.push(".restore-pending");
    std::path::PathBuf::from(os)
}

/// Apply a pending database restore, if one is staged next to `db_path`.
///
/// MUST be called at startup, BEFORE the database is opened, so the swap happens
/// while the DB file is closed (never corrupting a running database). When a
/// staged artifact exists it:
///   1. confirms the staged file at least opens (defence-in-depth; the API
///      fully verified it before staging),
///   2. copies the CURRENT live DB (if any) to a timestamped
///      `<db>.pre-restore-<unix>.db` safety backup,
///   3. removes the live DB's stale `-wal`/`-shm` sidecars,
///   4. atomically renames the staged file into `db_path`.
///
/// Returns `Ok(true)` when a restore was applied, `Ok(false)` when nothing was
/// staged. The only destructive step (the final rename) is atomic, so a failure
/// leaves the existing live DB intact.
pub fn apply_pending_restore(db_path: &Path) -> GhostResult<bool> {
    let staged = pending_restore_path(db_path);
    if !staged.exists() {
        return Ok(false);
    }
    info!(staged = %staged.display(), "Pending database restore detected; applying before open");

    // Defence in depth: the staged file must at least open. A SQLCipher artifact
    // won't read sqlite_master without a key, so only hard-fail on an OPEN error
    // (accepts both plain and encrypted staged files — the API already verified
    // the contents against the node key before staging).
    {
        Connection::open_with_flags(
            &staged,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )
        .map_err(|e| GhostError::Database(format!("staged restore not openable: {}", e)))?;
    }

    // Safety-copy the current live DB. ghost-pool checkpoints the WAL on shutdown
    // before exiting for a restart, so a plain file copy here is consistent.
    if db_path.exists() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut os = db_path.as_os_str().to_os_string();
        os.push(format!(".pre-restore-{}.db", ts));
        let safety = std::path::PathBuf::from(os);
        std::fs::copy(db_path, &safety)
            .map_err(|e| GhostError::Database(format!("safety backup of live DB failed: {}", e)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&safety, std::fs::Permissions::from_mode(0o600));
        }
        info!(backup = %safety.display(), "Live database copied to safety backup before restore");
    }

    // Drop stale WAL/SHM sidecars so the restored DB isn't reconciled against the
    // previous database's journal. For `ghost.db` these are `ghost.db-wal` /
    // `ghost.db-shm`, which `with_extension` produces exactly.
    for ext in ["db-wal", "db-shm"] {
        let side = db_path.with_extension(ext);
        if side.exists() {
            let _ = std::fs::remove_file(&side);
        }
    }

    // Atomic swap (staged is adjacent to db_path → same filesystem).
    std::fs::rename(&staged, db_path).map_err(|e| {
        GhostError::Database(format!("failed to move staged restore into place: {}", e))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(db_path, std::fs::Permissions::from_mode(0o600));
    }
    info!(db = %db_path.display(), "Pending database restore applied");
    Ok(true)
}

impl Database {
    /// Open a database at the given path
    ///
    /// H-DB-1/H-DB-2 FIX: Uses umask to create files with restricted permissions atomically,
    /// eliminating the race condition between file creation and chmod.
    ///
    /// L-14: Uses RAII UmaskGuard to ensure umask is restored even on panic.
    pub fn open<P: AsRef<Path>>(path: P) -> GhostResult<Self> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy().to_string();

        info!(path = %path_str, "Opening database");

        // H-DB-1 FIX: Set restrictive umask before creating any files.
        // L-14 FIX: Use RAII guard to ensure umask is restored even on panic.
        // umask 0o077 means: remove all permissions for group and others
        // Directory 0o777 & !0o077 = 0o700
        // File 0o666 & !0o077 = 0o600
        #[cfg(unix)]
        let _umask_guard = UmaskGuard::new_restrictive();

        // Create parent directory if needed (now created with 0o700 due to umask)
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Open database (file created with 0o600 due to umask)
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )
        .map_err(|e| GhostError::Database(e.to_string()))?;

        // L-14: UmaskGuard is dropped here automatically when going out of scope,
        // restoring original umask. This happens even if an error occurred above
        // due to the RAII pattern. We explicitly drop it here to be clear about
        // when the umask is restored.
        #[cfg(unix)]
        drop(_umask_guard);

        Self::initialize_connection(&conn)?;

        #[cfg(unix)]
        Self::verify_file_permissions(path)?;

        let db = Self {
            inner: Arc::new(DatabaseInner {
                write_conn: Mutex::new(conn),
                path: path_str,
                in_memory: false,
                encryption_key: RwLock::new(None),
            }),
        };

        // Run migrations
        db.with_connection(run_migrations)?;

        Ok(db)
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> GhostResult<Self> {
        debug!("Creating in-memory database");

        let conn = Connection::open_in_memory().map_err(|e| GhostError::Database(e.to_string()))?;

        Self::initialize_connection(&conn)?;

        let db = Self {
            inner: Arc::new(DatabaseInner {
                write_conn: Mutex::new(conn),
                path: ":memory:".to_string(),
                in_memory: true,
                encryption_key: RwLock::new(None),
            }),
        };

        // Run migrations
        db.with_connection(run_migrations)?;

        Ok(db)
    }

    /// Open an encrypted database using SQLCipher.
    ///
    /// The key must be 32 bytes. PRAGMA key is issued before any other operations.
    /// Existing unencrypted databases will fail — use `migrate_to_encrypted()` first.
    pub fn open_encrypted<P: AsRef<Path>>(path: P, key: &[u8; 32]) -> GhostResult<Self> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy().to_string();
        info!(path = %path_str, "Opening encrypted database");

        #[cfg(unix)]
        let _umask_guard = UmaskGuard::new_restrictive();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )
        .map_err(|e| GhostError::Database(e.to_string()))?;

        #[cfg(unix)]
        drop(_umask_guard);

        // PRAGMA key MUST be the first statement after opening
        let key_hex = hex::encode(key);
        conn.pragma_update(None, "key", format!("x'{}'", key_hex))
            .map_err(|e| GhostError::Database(format!("SQLCipher PRAGMA key: {}", e)))?;

        // Verify key by reading sqlite_master
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(|_| {
                GhostError::Database(
                    "SQLCipher key verification failed — wrong key or unencrypted database".into(),
                )
            })?;

        Self::initialize_connection(&conn)?;

        #[cfg(unix)]
        Self::verify_file_permissions(path)?;

        let db = Self {
            inner: Arc::new(DatabaseInner {
                write_conn: Mutex::new(conn),
                path: path_str,
                in_memory: false,
                encryption_key: RwLock::new(Some(*key)),
            }),
        };

        db.with_connection(run_migrations)?;
        Ok(db)
    }

    /// Migrate an existing unencrypted database to SQLCipher encryption.
    /// Creates an encrypted copy, then atomically swaps files.
    pub fn migrate_to_encrypted<P: AsRef<Path>>(path: P, key: &[u8; 32]) -> GhostResult<()> {
        let path = path.as_ref();
        let conn = Connection::open(path).map_err(|e| GhostError::Database(e.to_string()))?;

        // Verify it's readable as unencrypted
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(|e| GhostError::Database(format!("Cannot read DB: {}", e)))?;

        // Read schema version before export (PRAGMA user_version is not copied by sqlcipher_export)
        let schema_version: u32 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .map_err(|e| GhostError::Database(format!("Read user_version: {}", e)))?;

        let encrypted_path = path.with_extension("db.encrypted");
        let key_hex = hex::encode(key);

        conn.execute_batch(&format!(
            "ATTACH DATABASE '{}' AS encrypted KEY \"x'{}'\"; \
             SELECT sqlcipher_export('encrypted'); \
             DETACH DATABASE encrypted;",
            encrypted_path.display(),
            key_hex
        ))
        .map_err(|e| GhostError::Database(format!("SQLCipher export: {}", e)))?;

        drop(conn);

        // Set user_version on the encrypted database so migrations don't re-run
        {
            let enc_conn = Connection::open(&encrypted_path)
                .map_err(|e| GhostError::Database(e.to_string()))?;
            enc_conn
                .pragma_update(None, "key", format!("x'{}'", key_hex))
                .map_err(|e| GhostError::Database(format!("SQLCipher PRAGMA key: {}", e)))?;
            enc_conn
                .execute_batch(&format!("PRAGMA user_version = {};", schema_version))
                .map_err(|e| {
                    GhostError::Database(format!("Set user_version on encrypted DB: {}", e))
                })?;
        }

        // Atomic swap
        let backup = path.with_extension("db.unencrypted.bak");
        std::fs::rename(path, &backup)?;
        std::fs::rename(&encrypted_path, path)?;

        info!(
            schema_version,
            "Migrated to SQLCipher. Backup: {}",
            backup.display()
        );
        Ok(())
    }

    /// H-DB-2: Verify and fix file permissions on database and auxiliary files.
    #[cfg(unix)]
    fn verify_file_permissions(path: &Path) -> GhostResult<()> {
        use std::os::unix::fs::PermissionsExt;

        // Verify/fix main database file permissions
        if let Ok(metadata) = std::fs::metadata(path) {
            let perms = metadata.permissions();
            if perms.mode() & 0o077 != 0 {
                warn!(
                    path = %path.display(),
                    mode = format!("{:o}", perms.mode()),
                    "H-DB-2: Database file has weak permissions, fixing..."
                );
                let mut new_perms = perms;
                new_perms.set_mode(0o600);
                if let Err(e) = std::fs::set_permissions(path, new_perms) {
                    return Err(GhostError::Database(format!(
                        "Failed to secure database file permissions: {}",
                        e
                    )));
                }
            }
        }

        // Also secure WAL and SHM files if they exist
        for ext in ["db-wal", "db-shm"] {
            let aux_path = path.with_extension(ext);
            if aux_path.exists() {
                if let Ok(metadata) = std::fs::metadata(&aux_path) {
                    let perms = metadata.permissions();
                    if perms.mode() & 0o077 != 0 {
                        warn!(
                            path = %aux_path.display(),
                            mode = format!("{:o}", perms.mode()),
                            "H-DB-2: WAL/SHM file has weak permissions, fixing..."
                        );
                        let mut new_perms = perms;
                        new_perms.set_mode(0o600);
                        if let Err(e) = std::fs::set_permissions(&aux_path, new_perms) {
                            return Err(GhostError::Database(format!(
                                "Failed to secure auxiliary file permissions: {}",
                                e
                            )));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Initialize connection settings
    fn initialize_connection(conn: &Connection) -> GhostResult<()> {
        // Enable WAL mode for better concurrency
        // Auto-checkpoint when WAL reaches 1000 pages (~4MB with 4KB pages)
        //
        // H-5: Security hardening:
        // - synchronous = FULL: Ensures durability even on power loss (vs NORMAL)
        // - secure_delete = ON: Overwrites deleted data to prevent forensic recovery
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;
            PRAGMA cache_size = -16000;
            PRAGMA wal_autocheckpoint = 1000;
            PRAGMA secure_delete = ON;
            ",
        )
        .map_err(|e| GhostError::Database(format!("Failed to initialize connection: {}", e)))?;

        Self::register_functions(conn)?;

        Ok(())
    }

    /// Register custom SQL scalar functions on a connection.
    ///
    /// `reverse_hex(TEXT) -> TEXT` reverses a hex string byte-wise (decode hex,
    /// reverse the bytes, re-encode). `share_hash` is stored in INTERNAL byte
    /// order (schema v41 `normalise_legacy_share_hash_byte_order` — PoW zeros at
    /// the back), so `ORDER BY reverse_hex(share_hash)` ranks shares by their
    /// DISPLAY-order value (zeros at the front), i.e. genuine rarity. Non-hex or
    /// odd-length input is returned unchanged.
    ///
    /// Called from `initialize_connection`, so every query connection (the single
    /// `write_conn` per `Database`) has it before any query runs.
    fn register_functions(conn: &Connection) -> GhostResult<()> {
        conn.create_scalar_function(
            "reverse_hex",
            1,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            |ctx| {
                let input: String = ctx.get(0)?;
                let reversed = match hex::decode(&input) {
                    Ok(mut bytes) => {
                        bytes.reverse();
                        hex::encode(bytes)
                    }
                    // Non-hex / odd-length: return unchanged so a malformed row
                    // never aborts the query.
                    Err(_) => input,
                };
                Ok(reversed)
            },
        )
        .map_err(|e| {
            GhostError::Database(format!("Failed to register reverse_hex function: {}", e))
        })?;
        Ok(())
    }

    /// Execute a function with the database connection
    pub fn with_connection<F, T>(&self, f: F) -> GhostResult<T>
    where
        F: FnOnce(&Connection) -> GhostResult<T>,
    {
        let conn = self.inner.write_conn.lock();
        f(&conn)
    }

    /// Execute a function with the database connection, with retry logic for transient errors
    ///
    /// This is the preferred method for operations that may encounter SQLITE_BUSY
    /// or similar transient errors. Uses the default retry configuration.
    pub fn with_connection_retry<F, T>(&self, operation_name: &str, f: F) -> GhostResult<T>
    where
        F: Fn(&Connection) -> GhostResult<T>,
    {
        self.with_connection_retry_config(operation_name, &RetryConfig::default(), f)
    }

    /// Execute a function with the database connection, with custom retry configuration
    pub fn with_connection_retry_config<F, T>(
        &self,
        operation_name: &str,
        config: &RetryConfig,
        f: F,
    ) -> GhostResult<T>
    where
        F: Fn(&Connection) -> GhostResult<T>,
    {
        retry_with_backoff(config, operation_name, || {
            let conn = self.inner.write_conn.lock();
            f(&conn)
        })
    }

    /// Execute a function with a mutable connection reference
    pub fn with_connection_mut<F, T>(&self, f: F) -> GhostResult<T>
    where
        F: FnOnce(&mut Connection) -> GhostResult<T>,
    {
        let mut conn = self.inner.write_conn.lock();
        f(&mut conn)
    }

    /// Execute a transaction
    pub fn transaction<F, T>(&self, f: F) -> GhostResult<T>
    where
        F: FnOnce(&rusqlite::Transaction) -> GhostResult<T>,
    {
        let mut conn = self.inner.write_conn.lock();
        let tx = conn
            .transaction()
            .map_err(|e| GhostError::Database(e.to_string()))?;

        let result = f(&tx)?;

        tx.commit()
            .map_err(|e| GhostError::Database(e.to_string()))?;

        Ok(result)
    }

    /// Execute a transaction with retry logic for transient errors
    ///
    /// This retries the entire transaction if a transient error occurs.
    /// Uses the default retry configuration.
    pub fn transaction_retry<F, T>(&self, operation_name: &str, f: F) -> GhostResult<T>
    where
        F: Fn(&rusqlite::Transaction) -> GhostResult<T>,
    {
        self.transaction_retry_config(operation_name, &RetryConfig::default(), f)
    }

    /// Execute a transaction with custom retry configuration
    pub fn transaction_retry_config<F, T>(
        &self,
        operation_name: &str,
        config: &RetryConfig,
        f: F,
    ) -> GhostResult<T>
    where
        F: Fn(&rusqlite::Transaction) -> GhostResult<T>,
    {
        retry_with_backoff(config, operation_name, || {
            let mut conn = self.inner.write_conn.lock();
            let tx = conn
                .transaction()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = f(&tx)?;

            tx.commit()
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(result)
        })
    }

    /// Get the database path
    pub fn path(&self) -> &str {
        &self.inner.path
    }

    /// Check if this is an in-memory database
    pub fn is_in_memory(&self) -> bool {
        self.inner.in_memory
    }

    // =========================================================================
    // P-4: DATABASE ENCRYPTION FOR PAYOUT ADDRESSES
    // =========================================================================

    /// P-4: Set the encryption key for at-rest encryption of payout addresses.
    ///
    /// Must be called after Database::open() and before any address read/write
    /// operations. Uses the existing ChaCha20-Poly1305 encryption from
    /// `crate::encryption`.
    pub fn set_encryption_key(&self, key: [u8; 32]) {
        *self.inner.encryption_key.write() = Some(key);
        info!("P-4: Database encryption key configured for payout addresses");
    }

    /// P-4: Check if an encryption key is configured
    pub fn has_encryption_key(&self) -> bool {
        self.inner.encryption_key.read().is_some()
    }

    /// P-4: Encrypt a payout address before storing in the database.
    ///
    /// If no encryption key is configured, returns the plaintext unchanged
    /// (backward compatible). Encrypted values are prefixed with "enc:" to
    /// distinguish them from plaintext during migration.
    pub fn encrypt_address(&self, plaintext: &str) -> GhostResult<String> {
        let key_guard = self.inner.encryption_key.read();
        match *key_guard {
            None => Ok(plaintext.to_string()),
            Some(ref key) => {
                let encrypted = crate::encryption::encrypt_sensitive(plaintext, key)?;
                Ok(format!("enc:{}", encrypted))
            }
        }
    }

    /// P-4: Decrypt a payout address retrieved from the database.
    ///
    /// Handles both plaintext (pre-migration) and encrypted values gracefully:
    /// - Plaintext values are returned as-is (will be encrypted on next write)
    /// - Encrypted values (prefixed with "enc:") are decrypted
    /// - If encrypted data is found but no key is configured, returns an error
    pub fn decrypt_address(&self, stored: &str) -> GhostResult<String> {
        if !stored.starts_with("enc:") {
            // Plaintext (pre-migration data) — return as-is
            return Ok(stored.to_string());
        }

        let key_guard = self.inner.encryption_key.read();
        match *key_guard {
            None => {
                warn!("P-4: Encrypted address found but no encryption key configured");
                Err(GhostError::Crypto(
                    "Encrypted address found but no encryption key configured".into(),
                ))
            }
            Some(ref key) => {
                let base64_data = &stored[4..]; // Skip "enc:" prefix
                crate::encryption::decrypt_sensitive(base64_data, key)
            }
        }
    }

    /// L-15: Verify and fix auxiliary file (WAL/SHM) permissions.
    ///
    /// SQLite may create WAL and SHM files after the initial database open,
    /// potentially with weaker permissions than intended. This method should
    /// be called periodically (e.g., during maintenance or after checkpoints)
    /// to ensure these files maintain restrictive permissions.
    ///
    /// Note: There is an inherent race condition window between when SQLite
    /// creates these files and when this check runs. For maximum security,
    /// call this method frequently or use system-level protections like
    /// restrictive directory permissions (which we already set to 0o700).
    ///
    /// Returns the number of files that had permissions fixed.
    #[cfg(unix)]
    pub fn verify_aux_permissions(&self) -> GhostResult<usize> {
        use std::os::unix::fs::PermissionsExt;

        if self.inner.in_memory {
            return Ok(0);
        }

        let path = Path::new(&self.inner.path);
        let mut fixed_count = 0;

        for ext in ["db-wal", "db-shm"] {
            let aux_path = path.with_extension(ext);
            if aux_path.exists() {
                if let Ok(metadata) = std::fs::metadata(&aux_path) {
                    let perms = metadata.permissions();
                    // Check if group or others have any permissions
                    if perms.mode() & 0o077 != 0 {
                        warn!(
                            path = %aux_path.display(),
                            mode = format!("{:o}", perms.mode()),
                            "L-15: Auxiliary file has weak permissions, fixing..."
                        );
                        let mut new_perms = perms;
                        new_perms.set_mode(0o600);
                        std::fs::set_permissions(&aux_path, new_perms).map_err(|e| {
                            GhostError::Database(format!(
                                "Failed to secure auxiliary file permissions: {}",
                                e
                            ))
                        })?;
                        fixed_count += 1;
                    }
                }
            }
        }

        if fixed_count > 0 {
            info!(fixed_count, "L-15: Fixed auxiliary file permissions");
        }

        Ok(fixed_count)
    }

    /// L-15: Non-Unix stub for verify_aux_permissions
    #[cfg(not(unix))]
    pub fn verify_aux_permissions(&self) -> GhostResult<usize> {
        Ok(0)
    }

    /// Checkpoint WAL (force writes to main database)
    pub fn checkpoint(&self) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .map_err(|e| GhostError::Database(e.to_string()))
        })
    }

    /// Graceful shutdown: checkpoint WAL and remove WAL/SHM files
    pub fn shutdown(&self) -> GhostResult<()> {
        info!("Database shutdown: checkpointing WAL...");
        match self.checkpoint() {
            Ok(()) => info!("Database WAL checkpoint complete"),
            Err(e) => warn!("Database WAL checkpoint failed during shutdown: {}", e),
        }
        // Switch from WAL to DELETE mode — removes WAL/SHM files
        match self.with_connection(|conn| {
            conn.execute_batch("PRAGMA journal_mode = DELETE;")
                .map_err(|e| GhostError::Database(e.to_string()))
        }) {
            Ok(()) => info!("Database journal mode switched to DELETE"),
            Err(e) => warn!("Failed to switch journal mode during shutdown: {}", e),
        }
        Ok(())
    }

    /// L-13 FIX: Check database health by executing a simple query
    ///
    /// This verifies that the database connection is operational and can
    /// execute queries. Used by health check endpoints to provide accurate
    /// service status.
    pub fn health_check(&self) -> GhostResult<()> {
        self.with_connection(|conn| {
            // Execute a simple query to verify the connection is working
            let _: i64 = conn
                .query_row("SELECT 1", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(format!("Health check failed: {}", e)))?;
            Ok(())
        })
    }

    /// Get database statistics
    ///
    /// M-12 FIX: Uses safe i64 to u64 conversion with error handling for negative values.
    /// SQLite PRAGMA values should never be negative, but we validate to catch corruption.
    pub fn stats(&self) -> GhostResult<DatabaseStats> {
        self.with_connection(|conn| {
            let page_count: i64 = conn
                .query_row("PRAGMA page_count;", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let page_size: i64 = conn
                .query_row("PRAGMA page_size;", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let freelist_count: i64 = conn
                .query_row("PRAGMA freelist_count;", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            // M-12 FIX: Safely convert i64 to u64, rejecting negative values
            // Database page counts and sizes should never be negative
            if page_count < 0 {
                return Err(GhostError::Database(format!(
                    "Invalid negative page_count: {}",
                    page_count
                )));
            }
            if page_size < 0 {
                return Err(GhostError::Database(format!(
                    "Invalid negative page_size: {}",
                    page_size
                )));
            }
            if freelist_count < 0 {
                return Err(GhostError::Database(format!(
                    "Invalid negative freelist_count: {}",
                    freelist_count
                )));
            }

            Ok(DatabaseStats {
                size_bytes: page_count * page_size,
                page_count: page_count as u64,
                page_size: page_size as u64,
                freelist_pages: freelist_count as u64,
            })
        })
    }

    /// Minimum reclaimable free space before a full `VACUUM` is worth doing.
    ///
    /// `VACUUM` rebuilds the entire database through SQLite's page cache, so its peak memory is
    /// proportional to database size, not to the amount being reclaimed. Rebuilding 2.1GB to
    /// recover a few MB of pruned rows is what OOM-killed ghost-pool hourly on 3.87GB nodes.
    ///
    /// 256MB means a rebuild only happens when it would actually recover a meaningful amount of
    /// disk, at which point paying the memory cost once is reasonable.
    const VACUUM_MIN_RECLAIMABLE_BYTES: u64 = 256 * 1024 * 1024;

    /// Optimize the database.
    ///
    /// Always runs `ANALYZE` (cheap, and it is what actually helps the query planner) and a
    /// WAL checkpoint. Only runs `VACUUM` when there is enough reclaimable space to justify
    /// it — see `VACUUM_MIN_RECLAIMABLE_BYTES`.
    ///
    /// This used to run `VACUUM; ANALYZE;` unconditionally, and `run_maintenance` calls it
    /// whenever a maintenance pass deletes more than 1000 rows — which pruning health pings,
    /// challenges and verifications clears most hours. `VACUUM` rebuilds the ENTIRE database
    /// by streaming it through SQLite's page cache, so on a 2.1GB SQLCipher file it took
    /// ~2.8GB resident, every hour, to reclaim a few MB of freed rows.
    ///
    /// On 3.87GB nodes that was fatal: the kernel OOM-killed ghost-pool on the hour, every
    /// hour. Because an OOM kill is SIGKILL, it also never got to checkpoint, so the WAL grew
    /// to the size of the database and stayed there. Heap profiling attributed 96.9% of all
    /// allocation in the process to this one call.
    ///
    /// The checkpoint here is deliberate too: `VACUUM` holds a long transaction across the
    /// whole database, which blocks `wal_checkpoint(TRUNCATE)` (it returned busy with only
    /// ~4MB live inside a 2GB WAL). Checkpointing before any VACUUM lets the WAL actually
    /// shrink.
    pub fn optimize(&self) -> GhostResult<()> {
        self.with_connection(|conn| {
            // Truncating checkpoint first: cheap, and bounds WAL growth. Without this the WAL
            // file never shrinks (`journal_size_limit` is -1 by default).
            if let Err(e) = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);") {
                warn!("WAL checkpoint during maintenance failed: {e}");
            }

            // ANALYZE is the part that pays for itself — it refreshes planner statistics and
            // costs orders of magnitude less than a rebuild.
            conn.execute_batch("ANALYZE;")
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let page_size: i64 = conn
                .query_row("PRAGMA page_size", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let freelist_pages: i64 = conn
                .query_row("PRAGMA freelist_count", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let reclaimable =
                (freelist_pages.max(0) as u64).saturating_mul(page_size.max(0) as u64);

            if reclaimable < Self::VACUUM_MIN_RECLAIMABLE_BYTES {
                debug!(
                    reclaimable_bytes = reclaimable,
                    threshold = Self::VACUUM_MIN_RECLAIMABLE_BYTES,
                    "Skipping VACUUM — not enough reclaimable space to justify a full rebuild"
                );
                return Ok(());
            }

            info!(
                reclaimable_bytes = reclaimable,
                "Running VACUUM — reclaimable space exceeds threshold"
            );
            conn.execute_batch("VACUUM;")
                .map_err(|e| GhostError::Database(e.to_string()))
        })
    }

    /// Create a backup of the database using VACUUM INTO.
    ///
    /// This creates a consistent, compact copy of the database at the given path.
    /// The backup is atomic — either the full backup completes or nothing is written.
    /// Old backups at the same path are overwritten.
    pub fn backup(&self, backup_path: &std::path::Path) -> GhostResult<()> {
        // Remove existing backup file if present (VACUUM INTO fails if target exists)
        if backup_path.exists() {
            std::fs::remove_file(backup_path)
                .map_err(|e| GhostError::Database(format!("Failed to remove old backup: {}", e)))?;
        }

        let path_str = backup_path.to_string_lossy();
        info!(path = %path_str, "Creating database backup");

        self.with_connection(|conn| {
            conn.execute(
                &format!("VACUUM INTO '{}'", path_str.replace('\'', "''")),
                [],
            )
            .map_err(|e| GhostError::Database(format!("VACUUM INTO failed: {}", e)))?;
            Ok(())
        })?;

        // Set restrictive permissions on backup file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(backup_path, std::fs::Permissions::from_mode(0o600));
        }

        let size = std::fs::metadata(backup_path).map(|m| m.len()).unwrap_or(0);
        info!(path = %path_str, size_mb = size / (1024 * 1024), "Database backup complete");

        Ok(())
    }

    /// Verify a backup artifact produced by [`Database::backup`] WITHOUT mutating
    /// it or the live database.
    ///
    /// Opens the file read-only and, in order:
    ///   1. Confirms it is a readable SQLite database. If a plain open cannot
    ///      read `sqlite_master` and this database has an encryption key
    ///      configured, it retries once with the same SQLCipher key so an
    ///      encrypted artifact verifies with the node's own key.
    ///   2. Runs `PRAGMA integrity_check`.
    ///   3. Confirms every table in [`REQUIRED_BACKUP_TABLES`] is present, so a
    ///      random SQLite file that isn't a Ghost pool database is rejected.
    ///   4. Reads `PRAGMA user_version` and a `miners` row count for reporting.
    ///
    /// A file that opens but fails the checks yields `Ok(v)` with `v.valid ==
    /// false` (with `detail` explaining why); only an I/O-level failure to open
    /// the path at all is an `Err`. Never logs key material.
    pub fn verify_backup_file(&self, path: &Path) -> GhostResult<BackupVerification> {
        let size_bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

        let open_ro = || {
            Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
            )
        };

        // First attempt: plain (unencrypted) SQLite.
        let conn = open_ro()
            .map_err(|e| GhostError::Database(format!("cannot open backup file: {}", e)))?;
        let (conn, encrypted) = if conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .is_ok()
        {
            (conn, false)
        } else {
            drop(conn);
            // Not readable as plain SQLite. If we hold an encryption key, the
            // artifact may be SQLCipher-encrypted under it — retry once.
            let key = *self.inner.encryption_key.read();
            match key {
                Some(k) => {
                    let conn = open_ro().map_err(|e| {
                        GhostError::Database(format!("cannot open backup file: {}", e))
                    })?;
                    conn.pragma_update(None, "key", format!("x'{}'", hex::encode(k)))
                        .map_err(|e| {
                            GhostError::Database(format!("SQLCipher PRAGMA key: {}", e))
                        })?;
                    if conn
                        .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
                        .is_ok()
                    {
                        (conn, true)
                    } else {
                        return Ok(BackupVerification::failed(
                            size_bytes,
                            "file is not a readable SQLite/SQLCipher database (wrong key or corrupt)",
                        ));
                    }
                }
                None => {
                    return Ok(BackupVerification::failed(
                        size_bytes,
                        "file is not a readable SQLite database (corrupt or encrypted)",
                    ));
                }
            }
        };

        // Structural integrity.
        let integrity: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap_or_else(|e| format!("integrity_check error: {}", e));
        let integrity_ok = integrity == "ok";

        // Required Ghost tables.
        let mut tables_present = Vec::new();
        let mut missing_tables = Vec::new();
        for t in REQUIRED_BACKUP_TABLES {
            let exists = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [t],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap_or(0)
                > 0;
            if exists {
                tables_present.push((*t).to_string());
            } else {
                missing_tables.push((*t).to_string());
            }
        }

        let table_count = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0) as u64;

        let miner_count = if tables_present.iter().any(|t| t == "miners") {
            conn.query_row("SELECT count(*) FROM miners", [], |r| r.get::<_, i64>(0))
                .unwrap_or(0) as u64
        } else {
            0
        };

        let schema_version: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap_or(0);

        let valid = integrity_ok && missing_tables.is_empty();
        let detail = if valid {
            None
        } else if !integrity_ok {
            Some(format!("integrity check failed: {}", integrity))
        } else {
            Some(format!(
                "missing required Ghost tables: {}",
                missing_tables.join(", ")
            ))
        };

        Ok(BackupVerification {
            valid,
            integrity_ok,
            encrypted,
            schema_version,
            tables_present,
            missing_tables,
            table_count,
            miner_count,
            size_bytes,
            detail,
        })
    }

    /// Prune old, fully-settled rounds from the database.
    ///
    /// A `rounds` row is deleted ONLY when all three hold:
    ///   1. it is past the retention window (`round_id < MAX - keep_rounds`),
    ///   2. its `payout_status` is terminal (`confirmed`/`orphaned`/`failed`),
    ///   3. it has **zero remaining shares** referencing it.
    ///
    /// This function NEVER deletes from the `shares` table. Share-row lifecycle
    /// is owned solely by [`Database::delete_old_shares`] (Path A), which keeps
    /// an active or recently-dark miner's unpaid ledger intact. Because an
    /// unpaid share pins its round via the `NOT EXISTS` guard, a round is only
    /// reclaimed once `delete_old_shares` has legitimately removed its last
    /// share (after payout, or after the miner has been dark for over a year).
    ///
    /// Note: `shares.round_id` has NO foreign key / `ON DELETE CASCADE` to
    /// `rounds` (see the `shares` schema in migrations.rs), so deleting a round
    /// can never cascade into a live unpaid share. The `NOT EXISTS` guard is a
    /// belt-and-braces invariant that keeps round cleanup honest regardless.
    ///
    /// 4.17 SECURITY: Wrapped in transaction for atomicity.
    pub fn prune_old_rounds(&self, keep_rounds: u64) -> GhostResult<usize> {
        self.transaction(|tx| {
            // Find the minimum round ID to keep
            let current_round: Option<u64> = tx
                .query_row("SELECT MAX(round_id) FROM rounds", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let Some(current) = current_round else {
                return Ok(0);
            };

            let min_round_to_keep = current.saturating_sub(keep_rounds);

            // Delete only terminal-status rounds past the window that have NO
            // remaining shares. Shares are NOT touched here — an unpaid share
            // keeps its round alive until Path A prunes that share.
            let deleted = tx
                .execute(
                    "DELETE FROM rounds
                     WHERE round_id < ?1
                       AND payout_status IN ('confirmed', 'orphaned', 'failed')
                       AND NOT EXISTS (
                           SELECT 1 FROM shares s WHERE s.round_id = rounds.round_id
                       )",
                    [min_round_to_keep],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if deleted > 0 {
                info!(
                    rounds_deleted = deleted,
                    min_round = min_round_to_keep,
                    "Pruned old empty rounds"
                );
            }

            Ok(deleted)
        })
    }

    /// Prune old health pings
    ///
    /// Deletes health pings older than the specified number of days.
    ///
    /// L-2 FIX: Uses transaction for atomicity and consistent read visibility.
    /// Ensures the DELETE is rolled back on any failure.
    pub fn prune_old_health_pings(&self, keep_days: u32) -> GhostResult<usize> {
        self.transaction(|tx| {
            let cutoff = chrono::Utc::now().timestamp() - (keep_days as i64 * 86400);

            let deleted = tx
                .execute("DELETE FROM health_pings WHERE timestamp < ?1", [cutoff])
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if deleted > 0 {
                info!(deleted, keep_days, "Pruned old health pings");
            }

            Ok(deleted)
        })
    }

    /// Prune old vote records
    ///
    /// Deletes vote records for rounds older than the specified number.
    ///
    /// L-2 FIX: Uses transaction to ensure atomicity between reading the max round
    /// and deleting votes. This prevents race conditions where votes could be
    /// incorrectly pruned if a new round is created between the SELECT and DELETE.
    pub fn prune_old_votes(&self, keep_rounds: u64) -> GhostResult<usize> {
        self.transaction(|tx| {
            let current_round: Option<u64> = tx
                .query_row("SELECT MAX(round_id) FROM rounds", [], |row| row.get(0))
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let Some(current) = current_round else {
                return Ok(0);
            };

            let min_round_to_keep = current.saturating_sub(keep_rounds);

            let deleted = tx
                .execute("DELETE FROM votes WHERE round_id < ?1", [min_round_to_keep])
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if deleted > 0 {
                info!(deleted, min_round = min_round_to_keep, "Pruned old votes");
            }

            Ok(deleted)
        })
    }

    /// Prune old uptime samples
    ///
    /// Deletes uptime samples older than the specified number of days.
    /// STOR-1: uptime_samples grows ~8,640/day/node without cleanup.
    ///
    /// LOW FIX: Uses transaction for consistency with other prune operations.
    pub fn prune_old_uptime_samples(&self, keep_days: u32) -> GhostResult<usize> {
        self.transaction(|tx| {
            let cutoff = chrono::Utc::now().timestamp() - (keep_days as i64 * 86400);

            let deleted = tx
                .execute(
                    "DELETE FROM uptime_samples WHERE sample_time < ?1",
                    [cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if deleted > 0 {
                info!(deleted, keep_days, "Pruned old uptime samples");
            }

            Ok(deleted)
        })
    }

    /// Prune old challenge results
    ///
    /// Deletes challenge records older than the specified number of days from all
    /// challenge tables: archive_challenges, policy_challenges, stratum_challenges,
    /// and ghostpay_challenges.
    /// STOR-2/3/4/5: Each table grows ~864/day without cleanup.
    ///
    /// M-11: Wraps all DELETEs in a single transaction for atomicity.
    /// If any DELETE fails, all changes are rolled back to prevent inconsistent state.
    pub fn prune_old_challenges(&self, keep_days: u32) -> GhostResult<ChallengesPruneResult> {
        // M-11: Use transaction() for atomic multi-table pruning
        self.transaction(|tx| {
            let cutoff = chrono::Utc::now().timestamp() - (keep_days as i64 * 86400);

            let archive = tx
                .execute(
                    "DELETE FROM archive_challenges WHERE timestamp < ?1",
                    [cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let policy = tx
                .execute(
                    "DELETE FROM policy_challenges WHERE timestamp < ?1",
                    [cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let stratum = tx
                .execute(
                    "DELETE FROM stratum_challenges WHERE timestamp < ?1",
                    [cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let ghostpay = tx
                .execute(
                    "DELETE FROM ghostpay_challenges WHERE timestamp < ?1",
                    [cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let total = archive + policy + stratum + ghostpay;
            if total > 0 {
                info!(
                    archive,
                    policy, stratum, ghostpay, keep_days, "Pruned old challenges"
                );
            }

            Ok(ChallengesPruneResult {
                archive,
                policy,
                stratum,
                ghostpay,
            })
        })
    }

    /// Prune old verification records
    ///
    /// Deletes verification records older than the specified number of days.
    /// STOR-6: verifications grows ~864/day without cleanup.
    ///
    /// LOW FIX: Uses transaction for consistency with other prune operations.
    pub fn prune_old_verifications(&self, keep_days: u32) -> GhostResult<usize> {
        self.transaction(|tx| {
            let cutoff = chrono::Utc::now().timestamp() - (keep_days as i64 * 86400);

            let deleted = tx
                .execute(
                    "DELETE FROM verifications WHERE completed_at < ?1 OR (completed_at IS NULL AND started_at < ?1)",
                    [cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if deleted > 0 {
                info!(deleted, keep_days, "Pruned old verifications");
            }

            Ok(deleted)
        })
    }

    /// Prune old rows from the converged `verification_ledger` (v42).
    ///
    /// The ledger accrues one signed proof per (challenger, target, capability,
    /// timestamp) and otherwise grows without bound. `keep_days` MUST stay well
    /// above the challenge-convergence window (7 days) and the qualification
    /// window, so that (a) qualification never reads a pruned row and (b)
    /// convergence — which only reconciles the last 7 days — never re-fetches a
    /// pruned row from a peer that hasn't pruned it yet. The default retention
    /// (`keep_challenge_days` = 30) leaves ample margin.
    pub fn prune_old_verification_ledger(&self, keep_days: u32) -> GhostResult<usize> {
        self.transaction(|tx| {
            let cutoff = chrono::Utc::now().timestamp() - (keep_days as i64 * 86400);
            let deleted = tx
                .execute(
                    "DELETE FROM verification_ledger WHERE timestamp < ?1",
                    [cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            if deleted > 0 {
                info!(deleted, keep_days, "Pruned old verification ledger rows");
            }
            Ok(deleted)
        })
    }

    /// Run full maintenance (prune + checkpoint + optimize)
    ///
    /// This should be called periodically (e.g., once per hour).
    pub fn run_maintenance(&self, config: MaintenanceConfig) -> GhostResult<MaintenanceResult> {
        info!("Running database maintenance");

        // NOTE: `shares` rows are NOT pruned here. The share-row lifecycle is
        // owned solely by `delete_old_shares` (Path A, run by the dedicated
        // share-pruning task), which protects active and recently-dark miners'
        // unpaid ledgers. `prune_old_rounds` only removes already-empty rounds.
        let rounds_deleted = self.prune_old_rounds(config.keep_rounds)?;
        let pings_deleted = self.prune_old_health_pings(config.keep_health_ping_days)?;
        let votes_deleted = self.prune_old_votes(config.keep_rounds)?;
        let uptime_deleted = self.prune_old_uptime_samples(config.keep_uptime_sample_days)?;
        let challenges_deleted = self.prune_old_challenges(config.keep_challenge_days)?;
        let verification_ledger_deleted =
            self.prune_old_verification_ledger(config.keep_challenge_days)?;
        let verifications_deleted = self.prune_old_verifications(config.keep_verification_days)?;
        let checkpoints_pruned = self.prune_old_l2_checkpoints(config.keep_checkpoint_days)?;
        let pending_shields_cleaned = match self.delete_stale_pending_shields() {
            Ok(n) => n,
            Err(e) => {
                warn!(error = %e, "Failed to clean stale pending shields");
                0
            }
        };

        // Checkpoint WAL
        self.checkpoint()?;

        // Optimize if significant data was deleted
        let total_deleted = rounds_deleted
            + pings_deleted
            + votes_deleted
            + uptime_deleted
            + challenges_deleted.total()
            + verification_ledger_deleted
            + verifications_deleted
            + checkpoints_pruned
            + pending_shields_cleaned;
        if total_deleted > 1000 || config.force_optimize {
            self.optimize()?;
        }

        let stats = self.stats()?;

        info!(
            rounds_deleted,
            pings_deleted,
            votes_deleted,
            uptime_deleted,
            challenges_deleted = challenges_deleted.total(),
            verification_ledger_deleted,
            verifications_deleted,
            checkpoints_pruned,
            pending_shields_cleaned,
            db_size_mb = stats.size_mb(),
            "Database maintenance complete"
        );

        Ok(MaintenanceResult {
            rounds_deleted,
            pings_deleted,
            votes_deleted,
            uptime_deleted,
            challenges_deleted,
            verification_ledger_deleted,
            verifications_deleted,
            checkpoints_pruned,
            pending_shields_cleaned,
            db_size_bytes: stats.size_bytes,
        })
    }

    /// Prune old L2 checkpoint block_data beyond the retention window.
    ///
    /// Clears the block_data blob (which contains the full serialized checkpoint)
    /// for checkpoints older than keep_days, keeping the height/epoch/root metadata
    /// intact for historical reference. This prevents unbounded DB growth from
    /// accumulated checkpoint payloads.
    pub fn prune_old_l2_checkpoints(&self, keep_days: u32) -> GhostResult<usize> {
        self.transaction(|tx| {
            let cutoff = chrono::Utc::now()
                .checked_sub_signed(chrono::Duration::days(keep_days as i64))
                .unwrap_or_else(chrono::Utc::now)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string();

            let pruned = tx
                .execute(
                    "UPDATE l2_checkpoints SET block_data = X'' WHERE created_at < ?1 AND length(block_data) > 0",
                    [&cutoff],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            if pruned > 0 {
                info!(pruned, keep_days, "Pruned old L2 checkpoint block_data");
            }

            Ok(pruned)
        })
    }
}

/// Configuration for database maintenance
#[derive(Debug, Clone)]
pub struct MaintenanceConfig {
    /// Number of rounds to keep
    pub keep_rounds: u64,
    /// Number of days to keep health pings
    pub keep_health_ping_days: u32,
    /// Number of days to keep uptime samples (STOR-1)
    pub keep_uptime_sample_days: u32,
    /// Number of days to keep challenge results (STOR-2/3/4/5)
    pub keep_challenge_days: u32,
    /// Number of days to keep verification records (STOR-6)
    pub keep_verification_days: u32,
    /// Number of days to keep L2 checkpoint block_data
    pub keep_checkpoint_days: u32,
    /// Force optimize even if little was deleted
    pub force_optimize: bool,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            keep_rounds: 1000,          // Keep ~1000 rounds of data
            keep_health_ping_days: 7,   // 7 days of health pings
            keep_uptime_sample_days: 7, // 7 days of uptime samples (STOR-1)
            keep_challenge_days: 30,    // 30 days of challenge results (STOR-2/3/4/5)
            keep_verification_days: 30, // 30 days of verification records (STOR-6)
            keep_checkpoint_days: 90,   // 90 days of L2 checkpoint block_data
            force_optimize: false,
        }
    }
}

/// Result of database maintenance
#[derive(Debug, Clone)]
pub struct MaintenanceResult {
    pub rounds_deleted: usize,
    pub pings_deleted: usize,
    pub votes_deleted: usize,
    pub uptime_deleted: usize,
    pub challenges_deleted: ChallengesPruneResult,
    pub verification_ledger_deleted: usize,
    pub verifications_deleted: usize,
    pub checkpoints_pruned: usize,
    pub pending_shields_cleaned: usize,
    pub db_size_bytes: i64,
}

/// Result of pruning challenge tables
#[derive(Debug, Clone, Default)]
pub struct ChallengesPruneResult {
    pub archive: usize,
    pub policy: usize,
    pub stratum: usize,
    pub ghostpay: usize,
}

impl ChallengesPruneResult {
    /// Get total challenges deleted across all tables
    pub fn total(&self) -> usize {
        self.archive + self.policy + self.stratum + self.ghostpay
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub size_bytes: i64,
    pub page_count: u64,
    pub page_size: u64,
    pub freelist_pages: u64,
}

impl DatabaseStats {
    pub fn size_mb(&self) -> f64 {
        self.size_bytes as f64 / (1024.0 * 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// `optimize()` must not run a full VACUUM when there is nothing worth reclaiming.
    ///
    /// Regression guard for the hourly OOM: `optimize()` ran `VACUUM; ANALYZE;`
    /// unconditionally, and `run_maintenance` calls it whenever a pass deletes >1000 rows —
    /// most hours. VACUUM rebuilds the whole database through SQLite's page cache, so on a
    /// 2.1GB file it needed ~2.8GB resident and the kernel OOM-killed the process on the
    /// hour. Heap profiling attributed 96.9% of all allocation to that one call.
    ///
    /// A fresh database has an empty freelist, so this asserts the cheap path is taken and
    /// the database is still usable afterwards.
    #[test]
    fn optimize_skips_vacuum_when_nothing_to_reclaim() {
        let db = Database::in_memory().expect("create in-memory database");

        let freelist_before: i64 = db
            .with_connection(|conn| {
                conn.query_row("PRAGMA freelist_count", [], |row| row.get(0))
                    .map_err(|e| GhostError::Database(e.to_string()))
            })
            .expect("read freelist");
        assert_eq!(
            freelist_before, 0,
            "a fresh database should have no free pages"
        );

        db.optimize().expect("optimize must succeed");

        // Still usable, and ANALYZE ran without a rebuild.
        let stats = db.stats().expect("stats after optimize");
        assert!(stats.page_count > 0);
    }

    #[test]
    fn vacuum_threshold_is_large_enough_to_matter() {
        // The threshold exists so a rebuild only happens when it recovers meaningful disk.
        // Anything small here reintroduces the hourly rebuild this was written to stop.
        assert!(
            Database::VACUUM_MIN_RECLAIMABLE_BYTES >= 64 * 1024 * 1024,
            "threshold too low — VACUUM would run routinely again"
        );
    }

    #[test]
    fn test_in_memory_database() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");
        assert!(db.is_in_memory());
    }

    #[test]
    fn test_database_stats() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");
        let stats = db
            .stats()
            .expect("LOW-STOR-8: Failed to get database stats");
        assert!(stats.page_count > 0);
    }

    #[test]
    fn test_transaction() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");

        let result = db.transaction(|tx| {
            // Use a statement that doesn't return results
            tx.execute(
                "CREATE TABLE IF NOT EXISTS test_tx (id INTEGER PRIMARY KEY)",
                [],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(42)
        });

        assert_eq!(result.expect("LOW-STOR-8: Transaction should succeed"), 42);
    }

    #[test]
    fn test_is_transient_error() {
        // Test transient errors
        assert!(is_transient_error(&GhostError::Database(
            "database is locked".to_string()
        )));
        assert!(is_transient_error(&GhostError::Database(
            "SQLITE_BUSY (5)".to_string()
        )));
        assert!(is_transient_error(&GhostError::Database(
            "SQLITE_LOCKED".to_string()
        )));
        assert!(is_transient_error(&GhostError::Database(
            "database table is locked".to_string()
        )));

        // Test non-transient errors
        assert!(!is_transient_error(&GhostError::Database(
            "syntax error".to_string()
        )));
        assert!(!is_transient_error(&GhostError::Database(
            "no such table".to_string()
        )));
        assert!(!is_transient_error(&GhostError::Internal(
            "some error".to_string()
        )));
    }

    #[test]
    fn test_retry_succeeds_after_transient_errors() {
        let attempt_count = AtomicU32::new(0);
        let config = RetryConfig {
            max_retries: 3,
            initial_backoff_ms: 1,
            max_backoff_ms: 10,
            backoff_multiplier: 2.0,
        };

        let result = retry_with_backoff(&config, "test_op", || {
            let count = attempt_count.fetch_add(1, Ordering::SeqCst);
            if count < 2 {
                Err(GhostError::Database("database is locked".to_string()))
            } else {
                Ok(42)
            }
        });

        assert_eq!(
            result.expect("LOW-STOR-8: Retry should eventually succeed"),
            42
        );
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_retry_fails_after_max_retries() {
        let attempt_count = AtomicU32::new(0);
        let config = RetryConfig {
            max_retries: 2,
            initial_backoff_ms: 1,
            max_backoff_ms: 10,
            backoff_multiplier: 2.0,
        };

        let result: GhostResult<i32> = retry_with_backoff(&config, "test_op", || {
            attempt_count.fetch_add(1, Ordering::SeqCst);
            Err(GhostError::Database("database is locked".to_string()))
        });

        assert!(result.is_err());
        // Initial attempt + 2 retries = 3 total
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_retry_does_not_retry_non_transient_errors() {
        let attempt_count = AtomicU32::new(0);
        let config = RetryConfig::default();

        let result: GhostResult<i32> = retry_with_backoff(&config, "test_op", || {
            attempt_count.fetch_add(1, Ordering::SeqCst);
            Err(GhostError::Database("syntax error".to_string()))
        });

        assert!(result.is_err());
        // Should not retry, only 1 attempt
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_with_connection_retry() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");

        // Create a test table
        db.with_connection(|conn| {
            conn.execute(
                "CREATE TABLE IF NOT EXISTS retry_test (id INTEGER PRIMARY KEY, val INTEGER)",
                [],
            )
            .map_err(|e| GhostError::Database(e.to_string()))
        })
        .expect("LOW-STOR-8: Failed to create test table");

        // Test retry method works for normal operations
        let result = db.with_connection_retry("insert_test", |conn| {
            conn.execute("INSERT INTO retry_test (val) VALUES (42)", [])
                .map_err(|e| GhostError::Database(e.to_string()))
        });

        assert!(result.is_ok());
    }

    #[test]
    fn test_transaction_retry() {
        let db = Database::in_memory().expect("MED-STOR-2: Failed to create in-memory database");

        // Create a test table
        db.with_connection(|conn| {
            conn.execute(
                "CREATE TABLE IF NOT EXISTS tx_retry_test (id INTEGER PRIMARY KEY, val INTEGER)",
                [],
            )
            .map_err(|e| GhostError::Database(e.to_string()))
        })
        .expect("LOW-STOR-8: Failed to create test table");

        // Test retry method works for transactions
        let result = db.transaction_retry("tx_test", |tx| {
            tx.execute("INSERT INTO tx_retry_test (val) VALUES (1)", [])
                .map_err(|e| GhostError::Database(e.to_string()))?;
            tx.execute("INSERT INTO tx_retry_test (val) VALUES (2)", [])
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        });

        assert!(result.is_ok());

        // Verify both inserts happened
        let count: i64 = db
            .with_connection(|conn| {
                conn.query_row("SELECT COUNT(*) FROM tx_retry_test", [], |row| row.get(0))
                    .map_err(|e| GhostError::Database(e.to_string()))
            })
            .expect("LOW-STOR-8: Failed to count rows");

        assert_eq!(count, 2);
    }

    #[test]
    fn test_retry_config_presets() {
        let default = RetryConfig::default();
        assert_eq!(default.max_retries, 5);

        let aggressive = RetryConfig::aggressive();
        assert_eq!(aggressive.max_retries, 10);
        assert!(aggressive.max_backoff_ms > default.max_backoff_ms);

        let quick = RetryConfig::quick();
        assert_eq!(quick.max_retries, 3);
        assert!(quick.max_backoff_ms < default.max_backoff_ms);
    }

    // =========================================================================
    // P-4: DATABASE ENCRYPTION TESTS
    // =========================================================================

    fn test_encryption_key() -> [u8; 32] {
        [
            0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7,
            0xf8, 0x09, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5,
            0xc6, 0xd7, 0xe8, 0xf9,
        ]
    }

    #[test]
    fn test_encrypt_decrypt_address_roundtrip() {
        let db = Database::in_memory().expect("Failed to create in-memory database");
        db.set_encryption_key(test_encryption_key());

        let address = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let encrypted = db
            .encrypt_address(address)
            .expect("Failed to encrypt address");

        // Encrypted value should be prefixed with "enc:"
        assert!(encrypted.starts_with("enc:"));
        assert_ne!(encrypted, address);

        let decrypted = db
            .decrypt_address(&encrypted)
            .expect("Failed to decrypt address");
        assert_eq!(decrypted, address);
    }

    #[test]
    fn test_no_key_returns_plaintext() {
        let db = Database::in_memory().expect("Failed to create in-memory database");
        // No encryption key set

        let address = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let result = db
            .encrypt_address(address)
            .expect("Failed to encrypt address");

        // Without key, should return plaintext
        assert_eq!(result, address);
        assert!(!result.starts_with("enc:"));
    }

    #[test]
    fn test_decrypt_plaintext_passthrough() {
        let db = Database::in_memory().expect("Failed to create in-memory database");
        db.set_encryption_key(test_encryption_key());

        // Pre-migration plaintext should pass through unchanged
        let plaintext = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let result = db
            .decrypt_address(plaintext)
            .expect("Failed to decrypt plaintext address");
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_decrypt_encrypted_without_key_fails() {
        let db = Database::in_memory().expect("Failed to create in-memory database");
        db.set_encryption_key(test_encryption_key());

        let address = "bc1qtest";
        let encrypted = db
            .encrypt_address(address)
            .expect("Failed to encrypt address");

        // Create a new DB without key
        let db2 = Database::in_memory().expect("Failed to create in-memory database");
        let result = db2.decrypt_address(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_has_encryption_key() {
        let db = Database::in_memory().expect("Failed to create in-memory database");
        assert!(!db.has_encryption_key());

        db.set_encryption_key(test_encryption_key());
        assert!(db.has_encryption_key());
    }

    #[test]
    fn test_miner_address_encryption_roundtrip() {
        let db = Database::in_memory().expect("Failed to create in-memory database");
        db.set_encryption_key(test_encryption_key());

        let miner_id = "test_miner_001";
        let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

        // Store encrypted
        db.update_miner_address(miner_id, address)
            .expect("Failed to update miner address");

        // Retrieve and verify it's decrypted
        let retrieved = db
            .get_miner_payout_address(miner_id)
            .expect("Failed to get miner address");
        assert_eq!(retrieved, Some(address.to_string()));
    }

    #[test]
    fn test_node_address_encryption_roundtrip() {
        let db = Database::in_memory().expect("Failed to create in-memory database");
        db.set_encryption_key(test_encryption_key());

        let node_id = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

        // First register the node so it exists
        db.upsert_node(&crate::models::NodeRecord {
            node_id: node_id.to_string(),
            public_address: Some("127.0.0.1:8555".to_string()),
            display_name: None,
            first_seen: 1000,
            last_seen: 1000,
            is_elder: false,
            elder_order: None,
            capabilities: "{}".to_string(),
            total_uptime_secs: 0,
            uptime_7d_percent: 0.0,
            verification_pass_rate: 0.0,
            total_shares_received: 0,
            total_blocks_found: 0,
            payout_address: Some(address.to_string()),
        })
        .expect("Failed to upsert node");

        // Retrieve and verify it's decrypted
        let retrieved = db
            .get_node_payout_address(node_id)
            .expect("Failed to get node address");
        assert_eq!(retrieved, Some(address.to_string()));
    }

    /// Unique scratch path under the system temp dir for a file-based test DB.
    fn temp_db_path(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "ghost-verify-test-{}-{}-{}.db",
            std::process::id(),
            tag,
            nanos
        ))
    }

    #[test]
    fn test_backup_and_verify_roundtrip() {
        let src = temp_db_path("src");
        let backup = temp_db_path("backup");
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&backup);

        let db = Database::open(&src).expect("open source db");
        // Produce a real backup with VACUUM INTO (same path the API uses).
        db.backup(&backup).expect("backup");

        // A readable, encrypted-key-free copy that verifies as a Ghost DB.
        let v = db.verify_backup_file(&backup).expect("verify");
        assert!(v.valid, "expected valid backup, detail={:?}", v.detail);
        assert!(v.integrity_ok);
        assert!(!v.encrypted);
        assert!(v.missing_tables.is_empty());
        for required in REQUIRED_BACKUP_TABLES {
            assert!(
                v.tables_present.iter().any(|t| t == required),
                "missing required table {required}"
            );
        }
        assert!(v.size_bytes > 0);
        assert!(v.table_count >= REQUIRED_BACKUP_TABLES.len() as u64);

        let _ = db.shutdown();
        drop(db);
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&backup);
        for ext in ["db-wal", "db-shm"] {
            let _ = std::fs::remove_file(src.with_extension(ext));
        }
    }

    #[test]
    fn test_verify_rejects_corrupt_artifact() {
        let corrupt = temp_db_path("corrupt");
        std::fs::write(
            &corrupt,
            b"this is definitely not a sqlite database\x00\x01\x02",
        )
        .expect("write corrupt file");

        // A key-less handle (in-memory) cannot open garbage as SQLite.
        let db = Database::in_memory().expect("in-memory db");
        let v = db.verify_backup_file(&corrupt).expect("verify runs");
        assert!(!v.valid);
        assert!(!v.integrity_ok);
        assert!(v.detail.is_some());

        let _ = std::fs::remove_file(&corrupt);
    }

    #[test]
    fn test_verify_rejects_non_ghost_sqlite() {
        let other = temp_db_path("other");
        let _ = std::fs::remove_file(&other);
        {
            // A valid SQLite DB, but NOT a Ghost pool database.
            let conn = Connection::open(&other).expect("open plain sqlite");
            conn.execute("CREATE TABLE unrelated (id INTEGER)", [])
                .expect("create table");
        }

        let db = Database::in_memory().expect("in-memory db");
        let v = db.verify_backup_file(&other).expect("verify runs");
        assert!(!v.valid, "a non-Ghost sqlite file must not verify");
        // It IS structurally sound — it just lacks the Ghost schema.
        assert!(v.integrity_ok);
        assert!(!v.missing_tables.is_empty());

        let _ = std::fs::remove_file(&other);
    }
}
