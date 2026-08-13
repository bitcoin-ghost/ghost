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
//| FILE: migrations.rs                                                                                                  |
//|======================================================================================================================|

//! Database migrations

use rusqlite::{params, Connection};
use tracing::{debug, info, warn};

use ghost_common::error::{GhostError, GhostResult};

/// Current schema version
const SCHEMA_VERSION: u32 = 53;

/// Run all pending migrations
pub fn run_migrations(conn: &Connection) -> GhostResult<()> {
    let current_version = get_schema_version(conn)?;

    // A database AHEAD of the binary is always a mistake, and it used to be completely silent.
    //
    // It happens when a node runs an unreleased build: its migrations apply irreversibly, and
    // rolling the binary back does not roll the schema back. vm6 and vm8 sit at 47 against a
    // binary at 46 for exactly that reason, from a branch test (#523).
    //
    // The danger is not today. It is that the check below is `>=`, so when THIS binary later
    // gains its own migration 47 — almost certainly a different one — those nodes skip it while
    // reporting themselves up to date. The defect then surfaces far from its cause, as a missing
    // table on two nodes only, and those two are the canaries we deploy to first.
    if current_version > SCHEMA_VERSION {
        warn!(
            database_version = current_version,
            binary_version = SCHEMA_VERSION,
            "Database schema is AHEAD of this binary — it has run a newer build. Migration \
             {SCHEMA_VERSION}..={current_version} will be SKIPPED if this binary later defines \
             one, because the version number cannot tell them apart"
        );
        return Ok(());
    }

    if current_version == SCHEMA_VERSION {
        debug!(version = current_version, "Database schema up to date");
        return Ok(());
    }

    info!(
        from = current_version,
        to = SCHEMA_VERSION,
        "Running database migrations"
    );

    // Run migrations sequentially, each wrapped in a transaction.
    // This ensures that if a migration succeeds but the version update fails,
    // both are rolled back atomically — preventing stuck partial migrations.
    //
    // v10 is a special case: it uses PRAGMA foreign_keys ON/OFF which cannot run
    // inside a transaction, so it manages its own transaction internally.
    #[allow(clippy::type_complexity)]
    let pre_v10: &[(u32, fn(&Connection) -> GhostResult<()>)] = &[
        (1, migrate_v1),
        (2, migrate_v2),
        (3, migrate_v3),
        (4, migrate_v4),
        (5, migrate_v5),
        (6, migrate_v6),
        (7, migrate_v7),
        (8, migrate_v8),
        (9, migrate_v9),
    ];

    #[allow(clippy::type_complexity)]
    let post_v10: &[(u32, fn(&Connection) -> GhostResult<()>)] = &[
        (11, migrate_v11),
        (12, migrate_v12),
        (13, migrate_v13),
        (14, migrate_v14),
        (15, migrate_v15),
        (16, migrate_v16),
        (17, migrate_v17),
        (18, migrate_v18),
        (19, migrate_v19),
        (20, migrate_v20),
        (21, migrate_v21),
        (22, migrate_v22),
        (23, migrate_v23),
        (24, migrate_v24),
        (25, migrate_v25),
        (26, migrate_v26),
        (27, migrate_v27),
        (28, migrate_v28),
        (29, migrate_v29),
        (30, migrate_v30),
        (31, migrate_v31),
        (32, migrate_v32),
        (33, migrate_v33),
        (34, migrate_v34),
        (35, migrate_v35),
        (36, migrate_v36),
        (37, migrate_v37),
        (38, migrate_v38),
        (39, migrate_v39),
        (40, migrate_v40),
        (41, migrate_v41),
        (42, migrate_v42),
        (43, migrate_v43),
        (44, migrate_v44),
        (45, migrate_v45),
        (46, migrate_v46),
        (47, migrate_v47),
        (48, migrate_v48),
        (49, migrate_v49),
        (50, migrate_v50),
        (51, migrate_v51),
        (52, migrate_v52),
        (53, migrate_v53),
    ];

    for &(version, migrate_fn) in pre_v10 {
        if current_version < version {
            run_migration_tx(conn, version, migrate_fn)?;
        }
    }

    // v10 manages its own PRAGMA foreign_keys ON/OFF and cannot be wrapped
    if current_version < 10 {
        migrate_v10(conn)?;
        set_schema_version(conn, 10)?;
    }

    for &(version, migrate_fn) in post_v10 {
        if current_version < version {
            run_migration_tx(conn, version, migrate_fn)?;
        }
    }

    info!("Database migrations complete");
    Ok(())
}

/// Get current schema version
fn get_schema_version(conn: &Connection) -> GhostResult<u32> {
    let version: u32 = conn
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .map_err(|e| GhostError::Database(e.to_string()))?;
    Ok(version)
}

/// Set schema version
///
/// DB-C1 SECURITY NOTE: This uses format! because SQLite PRAGMA statements do not
/// support parameterized queries. This is safe because:
/// 1. `version` is a u32, which can only contain decimal digits
/// 2. The Rust type system guarantees version cannot contain SQL injection payloads
/// 3. The function is only called internally with the SCHEMA_VERSION constant
///
/// SECURITY: While format! is used, u32 cannot produce SQL injection.
/// The version number is bounded by u32::MAX and only contains digits.
fn set_schema_version(conn: &Connection, version: u32) -> GhostResult<()> {
    // PRAGMA does not support ? parameters
    // SECURITY: Use Display formatting for u32 which produces only ASCII digits 0-9
    // This is SQL injection safe because u32.to_string() cannot contain ', ", ;, or --
    let sql = format!("PRAGMA user_version = {}", version);
    conn.execute(&sql, [])
        .map_err(|e| GhostError::Database(e.to_string()))?;
    Ok(())
}

/// Run a single migration within a transaction.
///
/// Wraps the migration function + version update in BEGIN IMMEDIATE / COMMIT
/// so that if the migration succeeds but the version update fails (e.g. disk full),
/// both are rolled back atomically. This prevents the node from getting stuck with
/// a partially-applied migration that can't be re-run.
fn run_migration_tx(
    conn: &Connection,
    version: u32,
    migrate_fn: fn(&Connection) -> GhostResult<()>,
) -> GhostResult<()> {
    conn.execute("BEGIN IMMEDIATE", []).map_err(|e| {
        GhostError::Migration(format!("Failed to begin migration v{}: {}", version, e))
    })?;

    if let Err(e) = migrate_fn(conn) {
        let _ = conn.execute("ROLLBACK", []);
        return Err(e);
    }

    if let Err(e) = set_schema_version(conn, version) {
        let _ = conn.execute("ROLLBACK", []);
        return Err(e);
    }

    conn.execute("COMMIT", []).map_err(|e| {
        GhostError::Migration(format!("Failed to commit migration v{}: {}", version, e))
    })?;

    Ok(())
}

/// Migration to v1: Initial schema
fn migrate_v1(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v1");

    conn.execute_batch(
        r#"
        -- Shares table
        CREATE TABLE IF NOT EXISTS shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id INTEGER NOT NULL,
            miner_id TEXT NOT NULL,
            difficulty REAL NOT NULL,
            work REAL NOT NULL,
            share_hash TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            received_by TEXT NOT NULL,
            valid INTEGER NOT NULL DEFAULT 1,
            UNIQUE(share_hash)
        );
        CREATE INDEX IF NOT EXISTS idx_shares_round ON shares(round_id);
        CREATE INDEX IF NOT EXISTS idx_shares_miner ON shares(miner_id);
        CREATE INDEX IF NOT EXISTS idx_shares_timestamp ON shares(timestamp);

        -- Rounds table
        CREATE TABLE IF NOT EXISTS rounds (
            round_id INTEGER PRIMARY KEY,
            block_height INTEGER NOT NULL,
            block_hash TEXT,
            start_time INTEGER NOT NULL,
            end_time INTEGER,
            total_shares INTEGER NOT NULL DEFAULT 0,
            total_work REAL NOT NULL DEFAULT 0,
            winning_miner TEXT,
            found_by_node TEXT,
            payout_status TEXT NOT NULL DEFAULT 'active',
            subsidy_sats INTEGER,
            tx_fees_sats INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_rounds_height ON rounds(block_height);
        CREATE INDEX IF NOT EXISTS idx_rounds_status ON rounds(payout_status);

        -- Nodes table
        CREATE TABLE IF NOT EXISTS nodes (
            node_id TEXT PRIMARY KEY,
            public_address TEXT,
            display_name TEXT,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            is_elder INTEGER NOT NULL DEFAULT 0,
            elder_order INTEGER,
            capabilities TEXT NOT NULL DEFAULT '{}',
            total_uptime_secs INTEGER NOT NULL DEFAULT 0,
            uptime_7d_percent REAL NOT NULL DEFAULT 0,
            verification_pass_rate REAL NOT NULL DEFAULT 0,
            total_shares_received INTEGER NOT NULL DEFAULT 0,
            total_blocks_found INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_nodes_elder ON nodes(is_elder, elder_order);
        CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen);

        -- Miners table
        CREATE TABLE IF NOT EXISTS miners (
            miner_id TEXT PRIMARY KEY,
            payout_address TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            connected_node TEXT,
            total_shares INTEGER NOT NULL DEFAULT 0,
            total_work REAL NOT NULL DEFAULT 0,
            blocks_won INTEGER NOT NULL DEFAULT 0,
            total_payouts_sats INTEGER NOT NULL DEFAULT 0,
            avg_hashrate_ths REAL NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_miners_last_seen ON miners(last_seen);

        -- Payouts table
        CREATE TABLE IF NOT EXISTS payouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id INTEGER NOT NULL,
            recipient_id TEXT NOT NULL,
            recipient_type TEXT NOT NULL,
            address TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            txid TEXT,
            vout INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            confirmed_at INTEGER,
            FOREIGN KEY (round_id) REFERENCES rounds(round_id)
        );
        CREATE INDEX IF NOT EXISTS idx_payouts_round ON payouts(round_id);
        CREATE INDEX IF NOT EXISTS idx_payouts_recipient ON payouts(recipient_id);
        CREATE INDEX IF NOT EXISTS idx_payouts_status ON payouts(status);

        -- Node reward ledger
        CREATE TABLE IF NOT EXISTS node_rewards (
            node_id TEXT PRIMARY KEY,
            balance_sats INTEGER NOT NULL DEFAULT 0,
            last_credited_round INTEGER NOT NULL DEFAULT 0,
            total_credits_sats INTEGER NOT NULL DEFAULT 0,
            total_withdrawals_sats INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        -- Verifications table
        CREATE TABLE IF NOT EXISTS verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            challenger_id TEXT NOT NULL,
            capability TEXT NOT NULL,
            challenge_type TEXT NOT NULL,
            challenge_data TEXT NOT NULL,
            response_data TEXT,
            result TEXT NOT NULL DEFAULT 'pending',
            started_at INTEGER NOT NULL,
            completed_at INTEGER,
            FOREIGN KEY (node_id) REFERENCES nodes(node_id)
        );
        CREATE INDEX IF NOT EXISTS idx_verifications_node ON verifications(node_id);
        CREATE INDEX IF NOT EXISTS idx_verifications_result ON verifications(result);

        -- Health pings table
        CREATE TABLE IF NOT EXISTS health_pings (
            node_id TEXT NOT NULL,
            block_height INTEGER NOT NULL,
            round_id INTEGER NOT NULL,
            miner_count INTEGER NOT NULL,
            capabilities TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            PRIMARY KEY (node_id, timestamp)
        );
        CREATE INDEX IF NOT EXISTS idx_health_pings_timestamp ON health_pings(timestamp);

        -- Votes table
        CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id INTEGER NOT NULL,
            proposal_hash TEXT NOT NULL,
            voter_id TEXT NOT NULL,
            vote INTEGER NOT NULL,
            signature TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            UNIQUE(round_id, proposal_hash, voter_id)
        );
        CREATE INDEX IF NOT EXISTS idx_votes_round ON votes(round_id, proposal_hash);

        -- Key-value store for misc data
        CREATE TABLE IF NOT EXISTS kv_store (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v2: Ghost Pay L2 tables (locks, wraith, reconciliation, peers)
fn migrate_v2(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v2");

    conn.execute_batch(
        r#"
        -- Ghost Locks table for P2TR timelocked UTXOs
        CREATE TABLE IF NOT EXISTS ghost_locks (
            lock_id TEXT PRIMARY KEY,
            owner_ghost_id TEXT NOT NULL,
            lock_pubkey TEXT NOT NULL,
            recovery_pubkey TEXT NOT NULL,
            denomination TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            timelock_tier TEXT NOT NULL,
            creation_height INTEGER NOT NULL,
            recovery_height INTEGER NOT NULL,
            state TEXT NOT NULL DEFAULT 'pending',
            funding_txid TEXT,
            funding_vout INTEGER,
            spend_txid TEXT,
            output_script TEXT NOT NULL,
            jump_risk_tier TEXT NOT NULL,
            next_jump_height INTEGER,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ghost_locks_owner ON ghost_locks(owner_ghost_id);
        CREATE INDEX IF NOT EXISTS idx_ghost_locks_state ON ghost_locks(state);
        CREATE INDEX IF NOT EXISTS idx_ghost_locks_recovery ON ghost_locks(recovery_height);
        CREATE INDEX IF NOT EXISTS idx_ghost_locks_jump ON ghost_locks(next_jump_height);

        -- Peers table for P2P network tracking
        CREATE TABLE IF NOT EXISTS peers (
            peer_id TEXT PRIMARY KEY,
            address TEXT NOT NULL,
            port INTEGER NOT NULL,
            node_id TEXT,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            last_success INTEGER,
            last_failure INTEGER,
            connection_count INTEGER NOT NULL DEFAULT 0,
            failure_count INTEGER NOT NULL DEFAULT 0,
            is_banned INTEGER NOT NULL DEFAULT 0,
            ban_until INTEGER,
            capabilities TEXT,
            protocol_version INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_peers_last_seen ON peers(last_seen);
        CREATE INDEX IF NOT EXISTS idx_peers_node ON peers(node_id);

        -- Peer reputation tracking
        CREATE TABLE IF NOT EXISTS peer_reputation (
            peer_id TEXT PRIMARY KEY,
            reputation_score REAL NOT NULL DEFAULT 100.0,
            shares_relayed INTEGER NOT NULL DEFAULT 0,
            shares_invalid INTEGER NOT NULL DEFAULT 0,
            blocks_relayed INTEGER NOT NULL DEFAULT 0,
            latency_avg_ms REAL NOT NULL DEFAULT 0,
            uptime_percent REAL NOT NULL DEFAULT 0,
            last_calculated INTEGER NOT NULL,
            FOREIGN KEY (peer_id) REFERENCES peers(peer_id)
        );

        -- Wraith mixing rounds
        CREATE TABLE IF NOT EXISTS wraith_rounds (
            round_id TEXT PRIMARY KEY,
            coordinator_id TEXT NOT NULL,
            denomination TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            phase TEXT NOT NULL DEFAULT 'registration',
            participant_count INTEGER NOT NULL DEFAULT 0,
            min_participants INTEGER NOT NULL,
            max_participants INTEGER NOT NULL,
            registration_deadline INTEGER NOT NULL,
            execution_deadline INTEGER,
            split_txid TEXT,
            merge_txid TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_wraith_rounds_status ON wraith_rounds(status);
        CREATE INDEX IF NOT EXISTS idx_wraith_rounds_phase ON wraith_rounds(phase);
        CREATE INDEX IF NOT EXISTS idx_wraith_rounds_deadline ON wraith_rounds(registration_deadline);

        -- Wraith round participants
        CREATE TABLE IF NOT EXISTS wraith_participants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id TEXT NOT NULL,
            ghost_id TEXT NOT NULL,
            blinded_output TEXT NOT NULL,
            unblinded_output TEXT,
            input_txid TEXT,
            input_vout INTEGER,
            status TEXT NOT NULL DEFAULT 'registered',
            joined_at INTEGER NOT NULL,
            FOREIGN KEY (round_id) REFERENCES wraith_rounds(round_id),
            UNIQUE(round_id, ghost_id)
        );
        CREATE INDEX IF NOT EXISTS idx_wraith_participants_round ON wraith_participants(round_id);

        -- L2 reconciliation state
        CREATE TABLE IF NOT EXISTS reconciliation_state (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL UNIQUE,
            settlement_class TEXT NOT NULL,
            participant_count INTEGER NOT NULL,
            total_amount_sats INTEGER NOT NULL,
            merkle_root TEXT NOT NULL,
            l1_txid TEXT,
            l1_block_height INTEGER,
            dispute_deadline INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            finalized_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_reconciliation_status ON reconciliation_state(status);
        CREATE INDEX IF NOT EXISTS idx_reconciliation_deadline ON reconciliation_state(dispute_deadline);

        -- Reconciliation participants (individual settlements in a batch)
        CREATE TABLE IF NOT EXISTS reconciliation_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            ghost_id TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            direction TEXT NOT NULL,
            merkle_proof TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            FOREIGN KEY (batch_id) REFERENCES reconciliation_state(batch_id)
        );
        CREATE INDEX IF NOT EXISTS idx_reconciliation_entries_batch ON reconciliation_entries(batch_id);
        CREATE INDEX IF NOT EXISTS idx_reconciliation_entries_ghost ON reconciliation_entries(ghost_id);

        -- Uptime samples for 7-day tracking (moved from v1 if not exists)
        CREATE TABLE IF NOT EXISTS uptime_samples (
            node_id TEXT NOT NULL,
            sample_time INTEGER NOT NULL,
            was_online INTEGER NOT NULL,
            PRIMARY KEY (node_id, sample_time)
        );

        -- Archive challenge results
        CREATE TABLE IF NOT EXISTS archive_challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            challenger_id TEXT NOT NULL,
            block_height INTEGER NOT NULL,
            expected_hash TEXT NOT NULL,
            response_hash TEXT,
            passed INTEGER,
            timestamp INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_archive_challenges_node ON archive_challenges(node_id);

        -- Policy challenge results
        CREATE TABLE IF NOT EXISTS policy_challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            challenger_id TEXT NOT NULL,
            txid TEXT NOT NULL,
            expected_tier INTEGER NOT NULL,
            response_tier INTEGER,
            passed INTEGER,
            timestamp INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_policy_challenges_node ON policy_challenges(node_id);

        -- Stratum challenge results
        CREATE TABLE IF NOT EXISTS stratum_challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            challenger_id TEXT NOT NULL,
            connected INTEGER,
            latency_ms INTEGER,
            passed INTEGER,
            timestamp INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_stratum_challenges_node ON stratum_challenges(node_id);

        -- Ghost Pay challenge results
        CREATE TABLE IF NOT EXISTS ghostpay_challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            challenger_id TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            response_valid INTEGER,
            passed INTEGER,
            timestamp INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ghostpay_challenges_node ON ghostpay_challenges(node_id);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v3: Withdrawal requests table
fn migrate_v3(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v3");

    conn.execute_batch(
        r#"
        -- Withdrawal requests for L1 settlement
        CREATE TABLE IF NOT EXISTS withdrawal_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ghost_id TEXT NOT NULL,
            lock_id TEXT NOT NULL,
            destination_address TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            fee_sats INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            batch_id TEXT,
            l1_txid TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (lock_id) REFERENCES ghost_locks(lock_id)
        );
        CREATE INDEX IF NOT EXISTS idx_withdrawal_ghost ON withdrawal_requests(ghost_id);
        CREATE INDEX IF NOT EXISTS idx_withdrawal_lock ON withdrawal_requests(lock_id);
        CREATE INDEX IF NOT EXISTS idx_withdrawal_status ON withdrawal_requests(status);
        CREATE INDEX IF NOT EXISTS idx_withdrawal_batch ON withdrawal_requests(batch_id);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v4: Add Sybil resistance (PoW proof) and elder bond columns
fn migrate_v4(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v4: Adding Sybil resistance and elder bond columns");

    conn.execute_batch(
        r#"
        -- Add proof-of-work column for Sybil resistance
        -- The pow_proof is a hex-encoded 12-byte value: 8-byte nonce + 4-byte difficulty
        ALTER TABLE nodes ADD COLUMN pow_proof TEXT;

        -- Add elder bond column for nothing-at-stake prevention
        -- Elder candidates must demonstrate economic commitment
        ALTER TABLE nodes ADD COLUMN elder_bond_sats INTEGER NOT NULL DEFAULT 0;

        -- Add column to track if elder bond has been verified on-chain
        ALTER TABLE nodes ADD COLUMN elder_bond_txid TEXT;

        -- Add column to track slashing events
        ALTER TABLE nodes ADD COLUMN slashed_at INTEGER;

        -- Create table for tracking elder bond UTXOs
        CREATE TABLE IF NOT EXISTS elder_bonds (
            node_id TEXT PRIMARY KEY,
            txid TEXT NOT NULL,
            vout INTEGER NOT NULL,
            amount_sats INTEGER NOT NULL,
            script_pubkey TEXT NOT NULL,
            confirmation_height INTEGER,
            spent_txid TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (node_id) REFERENCES nodes(node_id)
        );
        CREATE INDEX IF NOT EXISTS idx_elder_bonds_status ON elder_bonds(status);
        CREATE INDEX IF NOT EXISTS idx_elder_bonds_txid ON elder_bonds(txid);

        -- Create table for tracking slashing events
        CREATE TABLE IF NOT EXISTS elder_slashing (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            evidence_hash TEXT NOT NULL,
            slashed_amount_sats INTEGER NOT NULL,
            slashing_txid TEXT,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (node_id) REFERENCES nodes(node_id)
        );
        CREATE INDEX IF NOT EXISTS idx_elder_slashing_node ON elder_slashing(node_id);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v5: Add payout_address to nodes for mainnet payouts
fn migrate_v5(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v5: Adding node payout_address");

    conn.execute_batch(
        r#"
        -- Add payout_address column for node operator rewards
        -- This is the Bitcoin address where nodes receive their 5% share reward
        ALTER TABLE nodes ADD COLUMN payout_address TEXT;

        -- Create index for efficient payout lookups
        CREATE INDEX IF NOT EXISTS idx_nodes_payout ON nodes(payout_address) WHERE payout_address IS NOT NULL;
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v6: ZK-BFT state management tables
fn migrate_v6(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v6: Adding ZK-BFT state management tables");

    conn.execute_batch(
        r#"
        -- State snapshots for L2 rollback capability
        -- Snapshots are taken at intervals (every N blocks) and pruned to keep last M
        CREATE TABLE IF NOT EXISTS state_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            height INTEGER NOT NULL UNIQUE,
            state_root TEXT NOT NULL,
            balances_json TEXT NOT NULL,
            nonces_json TEXT,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_snapshots_height ON state_snapshots(height);

        -- Block proposers for epoch settler selection
        -- The proposer of the last block in an epoch becomes the settler
        CREATE TABLE IF NOT EXISTS block_proposers (
            height INTEGER PRIMARY KEY,
            proposer_id TEXT NOT NULL,
            state_root TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_proposers_epoch ON block_proposers((height / 2160));

        -- Epoch settlement tracking
        -- Tracks which node is responsible for settling each epoch
        CREATE TABLE IF NOT EXISTS epoch_settlements (
            epoch_id INTEGER PRIMARY KEY,
            settler_id TEXT NOT NULL,
            fallback_settler_id TEXT,
            batch_id TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            settlement_deadline INTEGER NOT NULL,
            started_at INTEGER,
            completed_at INTEGER,
            failure_reason TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_epoch_status ON epoch_settlements(status);
        CREATE INDEX IF NOT EXISTS idx_epoch_deadline ON epoch_settlements(settlement_deadline);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v7: Key rotation with elder status transfer
///
/// Adds tables to securely track node identity rotations, preventing:
/// - Reuse of retired node_ids
/// - Unauthorized elder status claims
/// - Replay of old rotation proofs
fn migrate_v7(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v7: Adding key rotation tables");

    conn.execute_batch(
        r#"
        -- Retired node_ids table
        -- Once a node_id is retired (rotated away from), it can never be reused.
        -- This prevents replay attacks and identity resurrection.
        CREATE TABLE IF NOT EXISTS retired_nodes (
            old_node_id TEXT PRIMARY KEY,
            new_node_id TEXT NOT NULL,
            rotation_timestamp INTEGER NOT NULL,
            rotation_proof BLOB NOT NULL,
            FOREIGN KEY (new_node_id) REFERENCES nodes(node_id)
        );
        CREATE INDEX IF NOT EXISTS idx_retired_new ON retired_nodes(new_node_id);

        -- Rotation history for audit trail
        -- Tracks all rotations including revoked ones for forensic analysis.
        CREATE TABLE IF NOT EXISTS rotation_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            old_node_id TEXT NOT NULL,
            new_node_id TEXT NOT NULL,
            rotation_timestamp INTEGER NOT NULL,
            finalized_timestamp INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            rotation_proof BLOB NOT NULL,
            revocation_proof BLOB,
            elder_transferred INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_rotation_old ON rotation_history(old_node_id);
        CREATE INDEX IF NOT EXISTS idx_rotation_new ON rotation_history(new_node_id);
        CREATE INDEX IF NOT EXISTS idx_rotation_status ON rotation_history(status);

        -- Add rotation tracking column to nodes
        -- Points to the new node_id if this identity was rotated
        -- NULL means active identity, non-NULL means retired
        ALTER TABLE nodes ADD COLUMN rotated_to TEXT;

        -- Add rotation source column to nodes
        -- Points to the old node_id if this identity was rotated from another
        -- Allows tracing the full identity chain
        ALTER TABLE nodes ADD COLUMN rotated_from TEXT;
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v8: Equivocation proof persistence (P2P4-L7)
///
/// Stores equivocation proofs when Byzantine behavior is detected.
/// These proofs serve as evidence for slashing and forensic analysis.
fn migrate_v8(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v8: Adding equivocation proofs table");

    conn.execute_batch(
        r#"
        -- Equivocation proofs for Byzantine behavior evidence (P2P4-L7)
        -- Stores cryptographic proof when a node signs conflicting votes
        CREATE TABLE IF NOT EXISTS equivocation_proofs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id BLOB NOT NULL,
            proof_data BLOB NOT NULL,
            detected_at INTEGER NOT NULL,
            round_number INTEGER,
            vote_type TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_equivocation_proofs_node ON equivocation_proofs(node_id);
        CREATE INDEX IF NOT EXISTS idx_equivocation_proofs_round ON equivocation_proofs(round_number);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v9: Prevent double-spend race condition on withdrawals (C-PAY-3)
///
/// Adds a partial unique index to prevent concurrent withdrawal requests for the same lock.
/// Only one pending or batched withdrawal can exist per lock at any time.
fn migrate_v9(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v9: Adding partial unique index for withdrawal race condition prevention");

    conn.execute_batch(
        r#"
        -- Partial unique index to prevent double-withdrawal race condition (C-PAY-3)
        -- Ensures only one pending/batched withdrawal can exist per lock_id
        -- This provides defense-in-depth at the database level
        CREATE UNIQUE INDEX IF NOT EXISTS idx_withdrawals_pending_lock
        ON withdrawal_requests(lock_id)
        WHERE status IN ('pending', 'batched');
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    Ok(())
}

/// Migration to v10: Add ON DELETE CASCADE to foreign keys (DB-C4)
///
/// This ensures that when parent records are deleted, orphaned child records
/// are automatically cleaned up. Without CASCADE, deleting a parent could leave
/// orphaned child records that could cause constraint violations or data inconsistency.
///
/// Tables modified:
/// - payouts: cascade from rounds
/// - verifications: cascade from nodes
/// - peer_reputation: cascade from peers
/// - wraith_participants: cascade from wraith_rounds
/// - reconciliation_entries: cascade from reconciliation_state
/// - withdrawal_requests: cascade from ghost_locks
/// - elder_bonds: cascade from nodes
/// - elder_slashing: cascade from nodes
fn migrate_v10(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v10: Adding ON DELETE CASCADE to foreign keys (DB-C4)");

    // SQLite doesn't support ALTER TABLE to modify foreign key constraints,
    // so we need to recreate each table with the CASCADE option.
    // We use a safe pattern: create new table, copy data, drop old, rename new.

    // M-22 FIX: Disable foreign keys first, then wrap migration in a closure
    // to ensure we ALWAYS re-enable foreign keys, even on error.
    conn.execute("PRAGMA foreign_keys = OFF", [])
        .map_err(|e| GhostError::Migration(e.to_string()))?;

    // M-22: Run migration, capturing any error.
    //
    // M-10: BEGIN/COMMIT inside the batch. The runner deliberately skips `run_migration_tx` for
    // v10 because `PRAGMA foreign_keys` cannot be changed inside a transaction — but the comment
    // there claimed v10 "manages its own transaction internally" and it did not, so the whole
    // create/copy/drop/rename ran in autocommit. A crash partway left scratch `*_new` tables and,
    // worse, a table dropped and never renamed back: the re-run then dies on
    // `INSERT INTO x_new SELECT * FROM x` — no such table — and the node never starts again.
    //
    // The pragma stays outside the transaction, where SQLite requires it; only the DDL is wrapped.
    let migration_result = conn.execute_batch(
        r#"
        BEGIN;

        -- 1. payouts table: cascade from rounds
        CREATE TABLE IF NOT EXISTS payouts_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id INTEGER NOT NULL,
            recipient_id TEXT NOT NULL,
            recipient_type TEXT NOT NULL,
            address TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            txid TEXT,
            vout INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            confirmed_at INTEGER,
            FOREIGN KEY (round_id) REFERENCES rounds(round_id) ON DELETE CASCADE
        );
        INSERT INTO payouts_new SELECT * FROM payouts;
        DROP TABLE payouts;
        ALTER TABLE payouts_new RENAME TO payouts;
        CREATE INDEX IF NOT EXISTS idx_payouts_round ON payouts(round_id);
        CREATE INDEX IF NOT EXISTS idx_payouts_recipient ON payouts(recipient_id);
        CREATE INDEX IF NOT EXISTS idx_payouts_status ON payouts(status);

        -- 2. verifications table: cascade from nodes
        CREATE TABLE IF NOT EXISTS verifications_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            challenger_id TEXT NOT NULL,
            capability TEXT NOT NULL,
            challenge_type TEXT NOT NULL,
            challenge_data TEXT NOT NULL,
            response_data TEXT,
            result TEXT NOT NULL DEFAULT 'pending',
            started_at INTEGER NOT NULL,
            completed_at INTEGER,
            FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
        );
        INSERT INTO verifications_new SELECT * FROM verifications;
        DROP TABLE verifications;
        ALTER TABLE verifications_new RENAME TO verifications;
        CREATE INDEX IF NOT EXISTS idx_verifications_node ON verifications(node_id);
        CREATE INDEX IF NOT EXISTS idx_verifications_result ON verifications(result);

        -- 3. peer_reputation table: cascade from peers
        CREATE TABLE IF NOT EXISTS peer_reputation_new (
            peer_id TEXT PRIMARY KEY,
            reputation_score REAL NOT NULL DEFAULT 100.0,
            shares_relayed INTEGER NOT NULL DEFAULT 0,
            shares_invalid INTEGER NOT NULL DEFAULT 0,
            blocks_relayed INTEGER NOT NULL DEFAULT 0,
            latency_avg_ms REAL NOT NULL DEFAULT 0,
            uptime_percent REAL NOT NULL DEFAULT 0,
            last_calculated INTEGER NOT NULL,
            FOREIGN KEY (peer_id) REFERENCES peers(peer_id) ON DELETE CASCADE
        );
        INSERT INTO peer_reputation_new SELECT * FROM peer_reputation;
        DROP TABLE peer_reputation;
        ALTER TABLE peer_reputation_new RENAME TO peer_reputation;

        -- 4. wraith_participants table: cascade from wraith_rounds
        CREATE TABLE IF NOT EXISTS wraith_participants_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id TEXT NOT NULL,
            ghost_id TEXT NOT NULL,
            blinded_output TEXT NOT NULL,
            unblinded_output TEXT,
            input_txid TEXT,
            input_vout INTEGER,
            status TEXT NOT NULL DEFAULT 'registered',
            joined_at INTEGER NOT NULL,
            FOREIGN KEY (round_id) REFERENCES wraith_rounds(round_id) ON DELETE CASCADE,
            UNIQUE(round_id, ghost_id)
        );
        INSERT INTO wraith_participants_new SELECT * FROM wraith_participants;
        DROP TABLE wraith_participants;
        ALTER TABLE wraith_participants_new RENAME TO wraith_participants;
        CREATE INDEX IF NOT EXISTS idx_wraith_participants_round ON wraith_participants(round_id);

        -- 5. reconciliation_entries table: cascade from reconciliation_state
        CREATE TABLE IF NOT EXISTS reconciliation_entries_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            ghost_id TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            direction TEXT NOT NULL,
            merkle_proof TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            FOREIGN KEY (batch_id) REFERENCES reconciliation_state(batch_id) ON DELETE CASCADE
        );
        INSERT INTO reconciliation_entries_new SELECT * FROM reconciliation_entries;
        DROP TABLE reconciliation_entries;
        ALTER TABLE reconciliation_entries_new RENAME TO reconciliation_entries;
        CREATE INDEX IF NOT EXISTS idx_reconciliation_entries_batch ON reconciliation_entries(batch_id);
        CREATE INDEX IF NOT EXISTS idx_reconciliation_entries_ghost ON reconciliation_entries(ghost_id);

        -- 6. withdrawal_requests table: cascade from ghost_locks
        -- Note: Also recreate the partial unique index for double-spend prevention
        CREATE TABLE IF NOT EXISTS withdrawal_requests_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ghost_id TEXT NOT NULL,
            lock_id TEXT NOT NULL,
            destination_address TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            fee_sats INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            batch_id TEXT,
            l1_txid TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (lock_id) REFERENCES ghost_locks(lock_id) ON DELETE CASCADE
        );
        INSERT INTO withdrawal_requests_new SELECT * FROM withdrawal_requests;
        DROP TABLE withdrawal_requests;
        ALTER TABLE withdrawal_requests_new RENAME TO withdrawal_requests;
        CREATE INDEX IF NOT EXISTS idx_withdrawal_ghost ON withdrawal_requests(ghost_id);
        CREATE INDEX IF NOT EXISTS idx_withdrawal_lock ON withdrawal_requests(lock_id);
        CREATE INDEX IF NOT EXISTS idx_withdrawal_status ON withdrawal_requests(status);
        CREATE INDEX IF NOT EXISTS idx_withdrawal_batch ON withdrawal_requests(batch_id);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_withdrawals_pending_lock
        ON withdrawal_requests(lock_id)
        WHERE status IN ('pending', 'batched');

        -- 7. elder_bonds table: cascade from nodes
        CREATE TABLE IF NOT EXISTS elder_bonds_new (
            node_id TEXT PRIMARY KEY,
            txid TEXT NOT NULL,
            vout INTEGER NOT NULL,
            amount_sats INTEGER NOT NULL,
            script_pubkey TEXT NOT NULL,
            confirmation_height INTEGER,
            spent_txid TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
        );
        INSERT INTO elder_bonds_new SELECT * FROM elder_bonds;
        DROP TABLE elder_bonds;
        ALTER TABLE elder_bonds_new RENAME TO elder_bonds;
        CREATE INDEX IF NOT EXISTS idx_elder_bonds_status ON elder_bonds(status);
        CREATE INDEX IF NOT EXISTS idx_elder_bonds_txid ON elder_bonds(txid);

        -- 8. elder_slashing table: cascade from nodes
        CREATE TABLE IF NOT EXISTS elder_slashing_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            evidence_hash TEXT NOT NULL,
            slashed_amount_sats INTEGER NOT NULL,
            slashing_txid TEXT,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
        );
        INSERT INTO elder_slashing_new SELECT * FROM elder_slashing;
        DROP TABLE elder_slashing;
        ALTER TABLE elder_slashing_new RENAME TO elder_slashing;
        CREATE INDEX IF NOT EXISTS idx_elder_slashing_node ON elder_slashing(node_id);

        COMMIT;
        "#,
    );

    // M-10: `execute_batch` stops at the failing statement and leaves the transaction OPEN —
    // it does not roll back for us. Without this the scratch tables stay visible on this
    // connection and the DDL is neither applied nor undone, which is the half-migrated state the
    // transaction was added to prevent.
    if migration_result.is_err() {
        if let Err(e) = conn.execute_batch("ROLLBACK;") {
            warn!(error = %e, "v10 rollback failed after a failed migration");
        }
    }

    // M-22 FIX: ALWAYS re-enable foreign keys, even if migration failed
    // This ensures we don't leave the connection in a bad state.
    conn.execute("PRAGMA foreign_keys = ON", [])
        .map_err(|e| GhostError::Migration(format!("Failed to re-enable foreign keys: {}", e)))?;

    // Now check if migration succeeded
    migration_result.map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("DB-C4: Added ON DELETE CASCADE to all foreign keys");
    Ok(())
}

/// Migration to v11: Canonical elder list tables (P2P-C1/C2/C3)
fn migrate_v11(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v11: Adding canonical elder list tables (P2P-C1/C2/C3)");

    conn.execute_batch(
        r#"
        -- Canonical elder lists by epoch
        -- Stores the agreed-upon elder list for each epoch
        CREATE TABLE IF NOT EXISTS canonical_elder_lists (
            epoch INTEGER PRIMARY KEY,
            merkle_root TEXT NOT NULL,
            elder_count INTEGER NOT NULL,
            activated_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
        );
        CREATE INDEX IF NOT EXISTS idx_elder_lists_activated ON canonical_elder_lists(activated_at);

        -- Elder entries (members of each epoch's canonical list)
        CREATE TABLE IF NOT EXISTS elder_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            epoch INTEGER NOT NULL,
            node_id TEXT NOT NULL,
            registered_epoch INTEGER NOT NULL,
            pow_nonce INTEGER NOT NULL,
            pow_difficulty INTEGER NOT NULL,
            first_seen INTEGER NOT NULL,
            uptime_at_registration REAL NOT NULL,
            position INTEGER NOT NULL,
            FOREIGN KEY (epoch) REFERENCES canonical_elder_lists(epoch) ON DELETE CASCADE,
            UNIQUE(epoch, node_id)
        );
        CREATE INDEX IF NOT EXISTS idx_elder_entries_epoch ON elder_entries(epoch);
        CREATE INDEX IF NOT EXISTS idx_elder_entries_node ON elder_entries(node_id);

        -- Elder approvals (BFT signatures for elder list transitions)
        CREATE TABLE IF NOT EXISTS elder_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            epoch INTEGER NOT NULL,
            approver_node_id TEXT NOT NULL,
            signature TEXT NOT NULL,
            approved_at INTEGER NOT NULL,
            FOREIGN KEY (epoch) REFERENCES canonical_elder_lists(epoch) ON DELETE CASCADE,
            UNIQUE(epoch, approver_node_id)
        );
        CREATE INDEX IF NOT EXISTS idx_elder_approvals_epoch ON elder_approvals(epoch);

        -- Pending elder registration requests
        CREATE TABLE IF NOT EXISTS elder_registration_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            candidate_node_id TEXT NOT NULL UNIQUE,
            pow_nonce INTEGER NOT NULL,
            pow_difficulty INTEGER NOT NULL,
            first_seen INTEGER NOT NULL,
            uptime_percent REAL NOT NULL,
            target_epoch INTEGER NOT NULL,
            requested_at INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
        );
        CREATE INDEX IF NOT EXISTS idx_elder_reg_status ON elder_registration_requests(status);

        -- Elder registration votes (BFT votes on registration requests)
        CREATE TABLE IF NOT EXISTS elder_registration_votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            voter_node_id TEXT NOT NULL,
            approve INTEGER NOT NULL,
            rejection_reason TEXT,
            signature TEXT NOT NULL,
            voted_at INTEGER NOT NULL,
            FOREIGN KEY (request_id) REFERENCES elder_registration_requests(id) ON DELETE CASCADE,
            UNIQUE(request_id, voter_node_id)
        );
        CREATE INDEX IF NOT EXISTS idx_elder_reg_votes_request ON elder_registration_votes(request_id);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("P2P-C1/C2/C3: Added canonical elder list tables");
    Ok(())
}

/// Migration to v12: L2 state tracking for ZK consensus
fn migrate_v12(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v12: Adding L2 state tracking for ZK consensus");

    conn.execute_batch(
        r#"
        -- L2 state tracking for Ghost Pay ZK consensus
        -- Stores the current L2 state root and height for recovery after restart
        CREATE TABLE IF NOT EXISTS l2_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            height INTEGER NOT NULL DEFAULT 0,
            state_root BLOB NOT NULL,
            updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
        );

        -- L2 state snapshots for reorg recovery
        -- Stores periodic snapshots that can be rolled back to
        CREATE TABLE IF NOT EXISTS l2_snapshots (
            height INTEGER PRIMARY KEY,
            state_root BLOB NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
        );
        CREATE INDEX IF NOT EXISTS idx_l2_snapshots_created ON l2_snapshots(created_at);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("ZK-CONSENSUS: Added L2 state tracking tables");
    Ok(())
}

/// Migration to v13: MPC ceremony tables for rolling trusted setup
fn migrate_v13(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v13: Adding MPC ceremony tables");

    conn.execute_batch(
        r#"
        -- MPC ceremony state (singleton)
        -- Tracks the global state of the rolling MPC ceremony
        CREATE TABLE IF NOT EXISTS mpc_ceremony (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            contribution_count INTEGER NOT NULL DEFAULT 0,
            current_params_hash BLOB NOT NULL,
            is_ossified INTEGER NOT NULL DEFAULT 0,
            ossified_at INTEGER,
            block_vk_hash BLOB,
            payout_vk_hash BLOB,
            updated_at INTEGER NOT NULL
        );

        -- MPC contribution history (one per elder, 1-101)
        -- Each elder contributes exactly once during registration
        CREATE TABLE IF NOT EXISTS mpc_contributions (
            elder_position INTEGER PRIMARY KEY,
            contributor_node_id TEXT NOT NULL,
            prev_params_hash BLOB NOT NULL,
            new_params_hash BLOB NOT NULL,
            contribution_proof BLOB NOT NULL,
            epoch INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_mpc_contributions_node ON mpc_contributions(contributor_node_id);
        CREATE INDEX IF NOT EXISTS idx_mpc_contributions_epoch ON mpc_contributions(epoch);

        -- MPC verification votes for contributions
        -- Current elders vote to approve each contribution
        -- NOTE: No FK constraint because votes are saved before contribution is applied
        -- (pending contributions are tracked in memory until BFT approval)
        CREATE TABLE IF NOT EXISTS mpc_verification_votes (
            contribution_position INTEGER NOT NULL,
            voter_node_id TEXT NOT NULL,
            approve INTEGER NOT NULL,
            signature BLOB NOT NULL,
            voted_at INTEGER NOT NULL,
            PRIMARY KEY (contribution_position, voter_node_id)
        );
        CREATE INDEX IF NOT EXISTS idx_mpc_votes_position ON mpc_verification_votes(contribution_position);

        -- MPC parameter file metadata
        -- Tracks the actual parameter files on disk
        CREATE TABLE IF NOT EXISTS mpc_params_files (
            params_hash BLOB PRIMARY KEY,
            file_path TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            contribution_count INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_mpc_params_count ON mpc_params_files(contribution_count);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("MPC-CEREMONY: Added rolling MPC ceremony tables");
    Ok(())
}

/// Migration v14: Add instant payment reservations table (L-24 fix)
///
/// Persists fund reservations for instant payments to survive restarts.
/// This prevents double-spending when the node restarts with pending payments.
fn migrate_v14(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v14: Adding instant payment reservations table");

    conn.execute_batch(
        r#"
        -- L-24 FIX: Instant payment fund reservations
        -- Persists reservations to survive restarts and prevent double-spend
        CREATE TABLE IF NOT EXISTS instant_payment_reservations (
            payment_id BLOB PRIMARY KEY,
            lock_id TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_reservations_lock ON instant_payment_reservations(lock_id);
        CREATE INDEX IF NOT EXISTS idx_reservations_expires ON instant_payment_reservations(expires_at);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("L-24 FIX: Added instant payment reservations table");
    Ok(())
}

/// Migration v15: Add rate limiting indexes for challenge tables (L-3 fix)
///
/// Creates unique indexes on (node_id, challenger_id, date(timestamp)) for each challenge
/// table to prevent spam attacks where the same challenger floods the database with
/// challenges for the same node on the same day.
fn migrate_v15(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v15: Adding rate limiting indexes for challenge tables");

    conn.execute_batch(
        r#"
        -- L-3 FIX: Rate limiting indexes for challenge tables
        -- Prevents the same challenger from inserting multiple challenges for the same
        -- node on the same day. Uses date(timestamp, 'unixepoch') to extract the date.

        -- Archive challenges: one challenge per (node, challenger) pair per day
        CREATE UNIQUE INDEX IF NOT EXISTS idx_archive_challenges_daily
        ON archive_challenges(node_id, challenger_id, date(timestamp, 'unixepoch'));

        -- Policy challenges: one challenge per (node, challenger) pair per day
        CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_challenges_daily
        ON policy_challenges(node_id, challenger_id, date(timestamp, 'unixepoch'));

        -- Stratum challenges: one challenge per (node, challenger) pair per day
        CREATE UNIQUE INDEX IF NOT EXISTS idx_stratum_challenges_daily
        ON stratum_challenges(node_id, challenger_id, date(timestamp, 'unixepoch'));

        -- GhostPay challenges: one challenge per (node, challenger) pair per day
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ghostpay_challenges_daily
        ON ghostpay_challenges(node_id, challenger_id, date(timestamp, 'unixepoch'));
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("L-3 FIX: Added rate limiting indexes for challenge tables");
    Ok(())
}

/// Migration v16: Add accepted instant payments table (HIGH-RACE-1 fix)
///
/// Prevents double-acceptance of instant payments by tracking accepted payments
/// with a unique constraint on (sender_lock_id, payment_id, merchant_wallet_id).
/// This eliminates the TOCTOU race condition where the same instant payment could
/// be accepted multiple times by the same or different merchants.
fn migrate_v16(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v16: Adding accepted instant payments table (HIGH-RACE-1 fix)");

    conn.execute_batch(
        r#"
        -- HIGH-RACE-1 FIX: Accepted instant payments tracking
        -- Prevents double-acceptance of the same instant payment
        CREATE TABLE IF NOT EXISTS accepted_instant_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payment_id BLOB NOT NULL,
            sender_lock_id TEXT NOT NULL,
            merchant_wallet_id TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            accepted_at INTEGER NOT NULL,
            settlement_block INTEGER NOT NULL,
            confidence REAL NOT NULL,
            sender_pubkey BLOB NOT NULL,
            signature BLOB NOT NULL,
            -- UNIQUE constraint prevents double-acceptance atomically
            UNIQUE(sender_lock_id, payment_id, merchant_wallet_id)
        );
        CREATE INDEX IF NOT EXISTS idx_instant_payments_sender_lock ON accepted_instant_payments(sender_lock_id);
        CREATE INDEX IF NOT EXISTS idx_instant_payments_merchant ON accepted_instant_payments(merchant_wallet_id);
        CREATE INDEX IF NOT EXISTS idx_instant_payments_settlement ON accepted_instant_payments(settlement_block);
        CREATE INDEX IF NOT EXISTS idx_instant_payments_accepted_at ON accepted_instant_payments(accepted_at);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("HIGH-RACE-1 FIX: Added accepted instant payments table with atomic double-spend prevention");
    Ok(())
}

/// Migration v17: Add prev_merkle_root column to elder_approvals
///
/// Chain binding for elder list approvals - prevents replay attacks by
/// binding each approval to the previous epoch's merkle root.
fn migrate_v17(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v17: Adding prev_merkle_root to elder_approvals");

    conn.execute_batch(
        r#"
        -- Add prev_merkle_root column for chain binding (C-1 security)
        ALTER TABLE elder_approvals ADD COLUMN prev_merkle_root TEXT;
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added prev_merkle_root column to elder_approvals for chain binding");
    Ok(())
}

/// Migration v18: Remove FK constraint from mpc_verification_votes
///
/// The FK constraint causes a chicken-and-egg problem: votes can't be saved
/// until the contribution is in the DB, but contributions aren't saved until
/// they receive enough votes. Recreate the table without the FK.
fn migrate_v18(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v18: Removing FK from mpc_verification_votes");

    // SQLite doesn't support DROP CONSTRAINT, so we recreate the table
    conn.execute_batch(
        r#"
        -- Backup existing data
        CREATE TABLE IF NOT EXISTS mpc_verification_votes_backup AS
        SELECT * FROM mpc_verification_votes;

        -- Drop old table
        DROP TABLE IF EXISTS mpc_verification_votes;

        -- Recreate without FK constraint
        CREATE TABLE mpc_verification_votes (
            contribution_position INTEGER NOT NULL,
            voter_node_id TEXT NOT NULL,
            approve INTEGER NOT NULL,
            signature BLOB NOT NULL,
            voted_at INTEGER NOT NULL,
            PRIMARY KEY (contribution_position, voter_node_id)
        );
        CREATE INDEX IF NOT EXISTS idx_mpc_votes_position ON mpc_verification_votes(contribution_position);

        -- Restore data
        INSERT OR IGNORE INTO mpc_verification_votes
        SELECT * FROM mpc_verification_votes_backup;

        -- Drop backup
        DROP TABLE IF EXISTS mpc_verification_votes_backup;
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Removed FK constraint from mpc_verification_votes table");
    Ok(())
}

/// Migration v19: Add payout_proposals table for persistence across restarts
///
/// Stores BFT-approved payout proposals in SQLite so they survive node restarts.
/// Without this, approved payouts are lost on restart and the next block uses
/// fallback coinbase outputs instead of the BFT-approved payout distribution.
fn migrate_v19(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v19: Adding payout_proposals table");

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS payout_proposals (
            proposal_hash BLOB PRIMARY KEY NOT NULL,
            round_id INTEGER NOT NULL,
            block_height INTEGER NOT NULL,
            is_approved INTEGER NOT NULL DEFAULT 0,
            proposal_json TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        );
        CREATE INDEX IF NOT EXISTS idx_payout_proposals_approved ON payout_proposals(is_approved);
        CREATE INDEX IF NOT EXISTS idx_payout_proposals_round ON payout_proposals(round_id);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added payout_proposals table for restart persistence");
    Ok(())
}

/// Migration v20: Add confidential transfer tables for ZK privacy layer
///
/// Three tables for the MiMC commitment tree and Groth16 confidential transfers:
/// - confidential_notes: Commitment tree leaves with owner tracking
/// - nullifiers: Spent nullifier registry (prevents double-spend)
/// - confidential_transfers: Transfer records with Groth16 proofs
fn migrate_v20(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v20: Adding confidential transfer tables");

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS confidential_notes (
            tree_index INTEGER PRIMARY KEY,
            commitment BLOB NOT NULL,
            owner_pubkey BLOB NOT NULL,
            created_at_height INTEGER NOT NULL,
            spent_at_height INTEGER,
            created_at INTEGER NOT NULL DEFAULT (unixepoch())
        );

        CREATE TABLE IF NOT EXISTS nullifiers (
            nullifier BLOB PRIMARY KEY,
            block_height INTEGER NOT NULL,
            transfer_id TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (unixepoch())
        );

        CREATE TABLE IF NOT EXISTS confidential_transfers (
            transfer_id TEXT PRIMARY KEY,
            block_height INTEGER,
            nullifier BLOB NOT NULL,
            sender_new_commitment BLOB NOT NULL,
            recipient_new_commitment BLOB NOT NULL,
            old_commitment_root BLOB NOT NULL,
            new_commitment_root BLOB NOT NULL,
            proof BLOB NOT NULL,
            sender_index INTEGER NOT NULL,
            recipient_index INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL DEFAULT (unixepoch())
        );

        CREATE INDEX IF NOT EXISTS idx_ct_status ON confidential_transfers(status);
        CREATE INDEX IF NOT EXISTS idx_ct_height ON confidential_transfers(block_height);
        CREATE INDEX IF NOT EXISTS idx_cn_owner ON confidential_notes(owner_pubkey);
        CREATE INDEX IF NOT EXISTS idx_null_height ON nullifiers(block_height);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added confidential transfer tables (notes, nullifiers, transfers)");
    Ok(())
}

/// Migration v21: L2 note/UTXO model tables for sender-side proofs
///
/// Replaces the account-based L2 model with an append-only note commitment tree.
/// Senders generate Groth16 proofs; validators verify per-tx (~5ms).
/// Checkpoint blocks provide consistency via all-node BFT every 10 seconds.
///
/// Tables:
/// - l2_notes: Commitment tree leaves (epoch-scoped)
/// - l2_nullifiers: Spent nullifier registry (epoch-scoped, prevents double-spend)
/// - l2_checkpoints: Checkpoint blocks with BFT consensus
/// - l2_epochs: Epoch lifecycle and tree compaction state
/// - l2_valid_roots: Recent finalized commitment roots for proof validation
fn migrate_v21(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v21: Adding L2 note/UTXO model tables");

    conn.execute_batch(
        r#"
        -- Epoch-scoped commitment tree leaves
        -- Each note is a Pedersen commitment appended to the tree
        CREATE TABLE IF NOT EXISTS l2_notes (
            note_index INTEGER NOT NULL,
            epoch INTEGER NOT NULL,
            commitment BLOB NOT NULL,
            block_height INTEGER NOT NULL,
            spent INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (epoch, note_index)
        );
        CREATE INDEX IF NOT EXISTS idx_l2_notes_height ON l2_notes(block_height);
        CREATE INDEX IF NOT EXISTS idx_l2_notes_unspent ON l2_notes(epoch, spent) WHERE spent = 0;

        -- Epoch-scoped nullifier registry (prevents double-spend)
        -- Reset at each epoch boundary during tree compaction
        CREATE TABLE IF NOT EXISTS l2_nullifiers (
            nullifier BLOB NOT NULL,
            epoch INTEGER NOT NULL,
            block_height INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (epoch, nullifier)
        );
        CREATE INDEX IF NOT EXISTS idx_l2_nullifiers_height ON l2_nullifiers(block_height);

        -- Checkpoint blocks (assembled by proposer every 10s, no proof generation)
        CREATE TABLE IF NOT EXISTS l2_checkpoints (
            height INTEGER PRIMARY KEY,
            epoch INTEGER NOT NULL,
            commitment_root BLOB NOT NULL,
            tx_count INTEGER NOT NULL,
            proposer_id TEXT NOT NULL,
            active_node_count INTEGER NOT NULL,
            block_data BLOB NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_l2_checkpoints_epoch ON l2_checkpoints(epoch);

        -- Epoch lifecycle and tree compaction state
        CREATE TABLE IF NOT EXISTS l2_epochs (
            epoch INTEGER PRIMARY KEY,
            start_height INTEGER NOT NULL,
            end_height INTEGER,
            initial_root BLOB NOT NULL,
            final_root BLOB,
            notes_migrated INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'active'
        );
        CREATE INDEX IF NOT EXISTS idx_l2_epochs_status ON l2_epochs(status);

        -- Recent finalized commitment roots for proof validation
        -- Validators check that a tx's commitment_root is in this set
        CREATE TABLE IF NOT EXISTS l2_valid_roots (
            height INTEGER PRIMARY KEY,
            epoch INTEGER NOT NULL,
            commitment_root BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_l2_valid_roots_epoch ON l2_valid_roots(epoch);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added L2 note/UTXO model tables (notes, nullifiers, checkpoints, epochs, valid_roots)");
    Ok(())
}

/// H-12 / M-16: Add composite indexes and cascade constraints
fn migrate_v22(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v22: Composite indexes and cascade constraints");

    conn.execute_batch(
        r#"
        -- H-12: Composite indexes on frequently-queried columns
        CREATE INDEX IF NOT EXISTS idx_payouts_round_type
            ON payouts(round_id, recipient_type);
        CREATE INDEX IF NOT EXISTS idx_shares_miner_round
            ON shares(miner_id, round_id);
        CREATE INDEX IF NOT EXISTS idx_rounds_status_height
            ON rounds(payout_status, block_height);

        -- M-16: Composite index on l2_valid_roots for epoch + height queries
        CREATE INDEX IF NOT EXISTS idx_l2_valid_roots_epoch_height
            ON l2_valid_roots(epoch, height);

        -- H-12: Composite index on l2_nullifiers for epoch + nullifier lookups
        CREATE INDEX IF NOT EXISTS idx_l2_nullifiers_epoch_nullifier
            ON l2_nullifiers(epoch, nullifier);

        -- H-12: Composite index on l2_notes for epoch + spent status queries
        CREATE INDEX IF NOT EXISTS idx_l2_notes_epoch_spent
            ON l2_notes(epoch, spent);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added composite indexes (H-12, M-16)");
    Ok(())
}

/// L-10: Add foreign key references for L2 tables
/// L-11: Add partial index on l2_notes(spent) WHERE spent = 1
fn migrate_v23(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v23: L2 foreign keys and spent notes index");

    // SQLite does not support ALTER TABLE ADD CONSTRAINT for foreign keys.
    // Foreign keys must be defined at table creation time. Since we cannot
    // retroactively add FK constraints to existing tables without recreating
    // them (which risks data loss), we add a trigger-based equivalent that
    // enforces referential integrity for new inserts.
    //
    // These triggers ensure that:
    // - l2_checkpoints.epoch must reference an existing l2_epochs.epoch
    // - l2_valid_roots.epoch must reference an existing l2_epochs.epoch
    // - l2_notes.epoch must reference an existing l2_epochs.epoch
    // - l2_nullifiers.epoch must reference an existing l2_epochs.epoch
    conn.execute_batch(
        r#"
        -- L-10: Trigger-based FK enforcement for l2_checkpoints.epoch -> l2_epochs.epoch
        CREATE TRIGGER IF NOT EXISTS fk_l2_checkpoints_epoch
        BEFORE INSERT ON l2_checkpoints
        BEGIN
            SELECT RAISE(ABORT, 'FK violation: l2_checkpoints.epoch references nonexistent l2_epochs.epoch')
            WHERE NOT EXISTS (SELECT 1 FROM l2_epochs WHERE epoch = NEW.epoch);
        END;

        -- L-10: Trigger-based FK enforcement for l2_valid_roots.epoch -> l2_epochs.epoch
        CREATE TRIGGER IF NOT EXISTS fk_l2_valid_roots_epoch
        BEFORE INSERT ON l2_valid_roots
        BEGIN
            SELECT RAISE(ABORT, 'FK violation: l2_valid_roots.epoch references nonexistent l2_epochs.epoch')
            WHERE NOT EXISTS (SELECT 1 FROM l2_epochs WHERE epoch = NEW.epoch);
        END;

        -- L-10: Trigger-based FK enforcement for l2_notes.epoch -> l2_epochs.epoch
        CREATE TRIGGER IF NOT EXISTS fk_l2_notes_epoch
        BEFORE INSERT ON l2_notes
        BEGIN
            SELECT RAISE(ABORT, 'FK violation: l2_notes.epoch references nonexistent l2_epochs.epoch')
            WHERE NOT EXISTS (SELECT 1 FROM l2_epochs WHERE epoch = NEW.epoch);
        END;

        -- L-10: Trigger-based FK enforcement for l2_nullifiers.epoch -> l2_epochs.epoch
        CREATE TRIGGER IF NOT EXISTS fk_l2_nullifiers_epoch
        BEFORE INSERT ON l2_nullifiers
        BEGIN
            SELECT RAISE(ABORT, 'FK violation: l2_nullifiers.epoch references nonexistent l2_epochs.epoch')
            WHERE NOT EXISTS (SELECT 1 FROM l2_epochs WHERE epoch = NEW.epoch);
        END;

        -- L-11: Partial index for spent notes to optimize queries filtering spent = 1.
        -- The existing idx_l2_notes_unspent covers spent = 0; this covers spent = 1
        -- for settlement reconciliation queries that look up spent notes.
        CREATE INDEX IF NOT EXISTS idx_l2_notes_spent ON l2_notes(spent) WHERE spent = 1;
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added L2 foreign key triggers (L-10) and spent notes index (L-11)");
    Ok(())
}

/// v24: Drop unused elder_bonds/elder_slashing tables, add burned_elder_numbers
fn migrate_v24(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v24: Drop elder bonding tables, add burned elder positions");

    conn.execute_batch(
        r#"
        -- Remove invented bonding/slashing tables (not in spec, zero callers)
        DROP TABLE IF EXISTS elder_bonds;
        DROP TABLE IF EXISTS elder_slashing;

        -- Burned elder positions: revoked slots are never reassigned
        CREATE TABLE IF NOT EXISTS burned_elder_numbers (
            elder_position INTEGER PRIMARY KEY,
            revoked_node_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            revoked_at INTEGER NOT NULL
        );
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Dropped elder_bonds/elder_slashing, added burned_elder_numbers table");
    Ok(())
}

/// v25: Add encrypted fields to confidential_transfers for wallet scanning
fn migrate_v25(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v25: Add encrypted fields to confidential_transfers");

    conn.execute_batch(
        r#"
        ALTER TABLE confidential_transfers ADD COLUMN encrypted_change BLOB;
        ALTER TABLE confidential_transfers ADD COLUMN encrypted_recipient BLOB;
        ALTER TABLE confidential_transfers ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0;
        CREATE INDEX IF NOT EXISTS idx_ct_block_height ON confidential_transfers(block_height);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added encrypted_change, encrypted_recipient, epoch to confidential_transfers");
    Ok(())
}

/// v26: Add GhostGlyph registry table
fn migrate_v26(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v26: Add ghost_glyph_registry table");

    conn.execute_batch(
        r#"
        CREATE TABLE ghost_glyph_registry (
            ghost_id       TEXT PRIMARY KEY,
            pixels         BLOB NOT NULL,
            bitmap_hash    BLOB NOT NULL,
            commitment     BLOB NOT NULL,
            funding_txid   TEXT,
            registered_at  INTEGER,
            created_at     INTEGER NOT NULL,
            UNIQUE(bitmap_hash)
        );

        CREATE INDEX idx_glyph_bitmap_hash ON ghost_glyph_registry(bitmap_hash);
        CREATE INDEX idx_glyph_registered ON ghost_glyph_registry(registered_at);
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Created ghost_glyph_registry table");
    Ok(())
}

fn migrate_v27(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v27: Add expires_at to ghost_glyph_registry");

    conn.execute_batch(
        r#"
        ALTER TABLE ghost_glyph_registry ADD COLUMN expires_at INTEGER;
        CREATE INDEX idx_glyph_expires ON ghost_glyph_registry(expires_at)
            WHERE funding_txid IS NULL;
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    // Set expiry on existing unfunded claims (24 hours from creation)
    conn.execute(
        "UPDATE ghost_glyph_registry SET expires_at = created_at + 86400 WHERE funding_txid IS NULL",
        [],
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added expires_at to ghost_glyph_registry");
    Ok(())
}

fn migrate_v28(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v28: Add l2_epoch_fees table for L2 transfer fee tracking");

    conn.execute_batch(
        r#"
        CREATE TABLE l2_epoch_fees (
            epoch INTEGER PRIMARY KEY,
            transfer_count INTEGER NOT NULL DEFAULT 0,
            fee_total_sats INTEGER NOT NULL DEFAULT 0,
            distributed INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added l2_epoch_fees table");
    Ok(())
}

/// Migration to v29: Add wraith fee tracking columns to ghost_locks
fn migrate_v29(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v29: Add source and wraith_fee_sats to ghost_locks");

    conn.execute_batch(
        r#"
        ALTER TABLE ghost_locks ADD COLUMN source TEXT NOT NULL DEFAULT 'manual';
        ALTER TABLE ghost_locks ADD COLUMN wraith_fee_sats INTEGER NOT NULL DEFAULT 0;
        "#,
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added source and wraith_fee_sats columns to ghost_locks");
    Ok(())
}

/// Migration to v30: Add pending_nullifiers write-ahead table for crash recovery
fn migrate_v30(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v30: Add pending_nullifiers write-ahead table");

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pending_nullifiers (
            nullifier BLOB PRIMARY KEY,
            epoch INTEGER NOT NULL,
            spent_at INTEGER NOT NULL
        );",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added pending_nullifiers write-ahead table for crash recovery");
    Ok(())
}

/// Migration to v31: Add pending_l2_shields staging table for restart recovery
fn migrate_v31(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v31: Add pending_l2_shields staging table");

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pending_l2_shields (
            note_index INTEGER PRIMARY KEY,
            commitment BLOB NOT NULL,
            block_height INTEGER NOT NULL
        );",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added pending_l2_shields staging table for checkpoint divergence fix");
    Ok(())
}

/// v32: Add confirmed_pool_staging table for crash recovery of verified transactions.
/// Without this, the confirmed_pool (verified ZK transactions awaiting checkpoint inclusion)
/// is lost on restart, causing fund-freeze until the sender resubmits.
fn migrate_v32(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v32: Add confirmed_pool_staging table");

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS confirmed_pool_staging (
            nullifier BLOB PRIMARY KEY,
            tx_data BLOB NOT NULL,
            added_at INTEGER NOT NULL
        );",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added confirmed_pool_staging table for crash recovery of verified transactions");
    Ok(())
}

fn migrate_v33(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v33: Add settlement_class to withdrawal_requests");

    conn.execute_batch(
        "ALTER TABLE withdrawal_requests ADD COLUMN settlement_class TEXT NOT NULL DEFAULT 'standard';
         CREATE INDEX IF NOT EXISTS idx_withdrawal_class ON withdrawal_requests(settlement_class);",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added settlement_class column and index to withdrawal_requests");
    Ok(())
}

fn migrate_v34(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v34: Add key_index to ghost_locks");

    conn.execute_batch("ALTER TABLE ghost_locks ADD COLUMN key_index INTEGER;")
        .map_err(|e| GhostError::Migration(e.to_string()))?;

    // Backfill existing locks with their current computed index
    // This uses the same logic as get_lock_index_for_owner: count of locks created before each lock
    conn.execute_batch(
        "UPDATE ghost_locks SET key_index = (
            SELECT COUNT(*) FROM ghost_locks AS g2
            WHERE g2.owner_ghost_id = ghost_locks.owner_ghost_id
            AND g2.created_at < ghost_locks.created_at
        );",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added key_index column to ghost_locks with backfill");
    Ok(())
}

/// v35: ledger-style payouts
///
/// Adds `paid_in_proposal_hash BLOB NULL` to `shares`. Null means "unpaid,
/// counts toward the next block's coinbase"; non-null is a 32-byte payout
/// proposal hash that committed this share to a specific coinbase.
///
/// Backfill: every existing share is stamped with a sentinel hash (32 zero
/// bytes) so the first post-upgrade payout doesn't sweep legacy data into
/// a single gigantic ledger reset. After migration, the unpaid ledger
/// starts fresh and accumulates from live hashing activity going forward.
///
/// The partial index on `WHERE paid_in_proposal_hash IS NULL` is what
/// keeps the ledger query hot regardless of how many historical paid
/// shares sit in the table.
fn migrate_v35(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v35: Add paid_in_proposal_hash to shares");

    conn.execute_batch("ALTER TABLE shares ADD COLUMN paid_in_proposal_hash BLOB;")
        .map_err(|e| GhostError::Migration(e.to_string()))?;

    // Stamp every existing share as already-paid with an all-zero sentinel.
    // Fresh start: the ledger is empty on first boot after this migration.
    conn.execute_batch("UPDATE shares SET paid_in_proposal_hash = zeroblob(32);")
        .map_err(|e| GhostError::Migration(e.to_string()))?;

    // Partial index keeps the unpaid-ledger query O(log N_unpaid), not
    // O(log N_all_shares). Without this, every payout lookup would scan
    // millions of paid rows.
    conn.execute_batch(
        "CREATE INDEX idx_shares_unpaid ON shares(miner_id)
         WHERE paid_in_proposal_hash IS NULL;",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    // Lookup by proposal hash for audit / reversal on reorg.
    conn.execute_batch(
        "CREATE INDEX idx_shares_paid_proposal ON shares(paid_in_proposal_hash)
         WHERE paid_in_proposal_hash IS NOT NULL;",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added paid_in_proposal_hash column + partial indexes to shares");
    Ok(())
}

/// v36: track L2 node reward payouts per batch
///
/// Each L2 settlement batch splits its fee pool between treasury and the
/// node reward pool. Pre-v36 the node-side amount was computed at batch
/// build but never persisted — we could only report it live, not run
/// a cumulative total. This column captures the amount so the
/// finalize path can increment a global `l2_node_rewards_paid_sats`
/// kv_store accumulator once the batch's L1 transaction confirms.
///
/// Existing rows default to 0 (we have no retroactive data). The
/// accumulator starts from the moment nodes upgrade.
fn migrate_v36(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v36: Add l2_node_rewards_sats to reconciliation_state");

    conn.execute_batch(
        "ALTER TABLE reconciliation_state ADD COLUMN l2_node_rewards_sats INTEGER NOT NULL DEFAULT 0;",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added l2_node_rewards_sats column to reconciliation_state");
    Ok(())
}

/// v37: Add `sender_ghost_id` to accepted_instant_payments so the transactions
/// route can find an L2 payment by either the sender's or the recipient's
/// ghost_id. Existing rows have NULL — historic payments simply won't show up
/// on the sender's side until they're re-issued.
fn migrate_v37(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v37: Add sender_ghost_id to accepted_instant_payments");

    conn.execute_batch(
        "ALTER TABLE accepted_instant_payments ADD COLUMN sender_ghost_id TEXT;
         CREATE INDEX IF NOT EXISTS idx_instant_payments_sender_ghost_id ON accepted_instant_payments(sender_ghost_id);",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Added sender_ghost_id column + index to accepted_instant_payments");
    Ok(())
}

/// v38: Wraith bond escrow ledger. Each row is a participant's L2 bond
/// for a Wraith mix round. `status` is one of `'escrowed'` (sats are
/// held), `'refunded'` (released back to the participant), or
/// `'slashed'` (forfeit). The partial unique index permits at most one
/// live (escrowed) bond per `(ghost_id, session_id)` while still
/// allowing a fresh bond after a prior one has been refunded or
/// slashed.
fn migrate_v38(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v38: Add wraith_bonds escrow ledger");

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS wraith_bonds (
            bond_id TEXT PRIMARY KEY,
            ghost_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            amount_sats INTEGER NOT NULL,
            status TEXT NOT NULL,
            resolution TEXT,
            created_at INTEGER NOT NULL,
            resolved_at INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_wraith_bonds_live
            ON wraith_bonds(ghost_id, session_id) WHERE status='escrowed';
        CREATE INDEX IF NOT EXISTS idx_wraith_bonds_lookup
            ON wraith_bonds(ghost_id, session_id);",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("Created wraith_bonds table + indexes");
    Ok(())
}

/// v39: MPC ceremony state foundation.
///
/// Two changes, both idempotent and safe on the live 5-contribution DBs as
/// well as a fresh genesis DB.
///
/// Change 1 — add a stable `ceremony_id BLOB` column to the `mpc_ceremony`
/// singleton. `ceremony_id` is the genesis-derived constant Schnorr proofs bind
/// to (= position-1 `prev_params_hash`, the genesis lineage hash). It is
/// nullable: legacy/pre-genesis rows carry NULL, which the reader treats as
/// "not yet established" and the load path re-derives from position-1.
///
/// Change 2 — backfill the `mpc_ceremony` singleton (id=1) from existing
/// contribution history when it is ABSENT but `mpc_contributions` has rows (the
/// exact state of the live fleet: 5 contributions, empty singleton). The
/// singleton then becomes the authoritative source of truth for progression,
/// set as follows:
///
/// ```text
/// contribution_count = MAX(elder_position)
/// current_params_hash = mpc_contributions[MAX].new_params_hash  (lineage hash)
/// is_ossified         = 0
/// ceremony_id         = mpc_contributions[1].prev_params_hash
/// updated_at          = now
/// ```
///
/// An existing singleton is NEVER overwritten. If `mpc_contributions` is also
/// empty (fresh genesis), the singleton is left for genesis init to create.
fn migrate_v39(conn: &Connection) -> GhostResult<()> {
    use rusqlite::OptionalExtension;

    debug!("Running migration v39: Add mpc_ceremony.ceremony_id + backfill singleton");

    // 1. Add the stable ceremony_id column.
    conn.execute_batch("ALTER TABLE mpc_ceremony ADD COLUMN ceremony_id BLOB;")
        .map_err(|e| GhostError::Migration(e.to_string()))?;

    // 2. Idempotent backfill — never overwrite an existing singleton.
    let singleton_exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM mpc_ceremony WHERE id = 1)",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map_err(|e| GhostError::Migration(e.to_string()))?
        != 0;

    if singleton_exists {
        info!("v39: mpc_ceremony singleton already present — leaving it untouched");
        return Ok(());
    }

    let max_position: Option<i64> = conn
        .query_row(
            "SELECT MAX(elder_position) FROM mpc_contributions",
            [],
            |r| r.get(0),
        )
        .map_err(|e| GhostError::Migration(e.to_string()))?;

    let Some(max_position) = max_position else {
        // No contributions — fresh genesis DB. Genesis init will create the row.
        info!("v39: no mpc_contributions rows — leaving singleton empty for genesis init");
        return Ok(());
    };

    // Lineage head: current_params_hash = new_params_hash at the highest position.
    let current_params_hash: Vec<u8> = conn
        .query_row(
            "SELECT new_params_hash FROM mpc_contributions WHERE elder_position = ?1",
            [max_position],
            |r| r.get(0),
        )
        .map_err(|e| GhostError::Migration(e.to_string()))?;

    // ceremony_id = genesis lineage hash = position-1 prev_params_hash.
    // Defensive: if position 1 is somehow absent, store NULL (reader re-derives).
    let ceremony_id: Option<Vec<u8>> = conn
        .query_row(
            "SELECT prev_params_hash FROM mpc_contributions WHERE elder_position = 1",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| GhostError::Migration(e.to_string()))?;

    if ceremony_id.is_none() {
        warn!(
            "v39: contribution position 1 missing — backfilling singleton with NULL ceremony_id \
             (load path will re-derive once position 1 is available)"
        );
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    conn.execute(
        "INSERT INTO mpc_ceremony
            (id, contribution_count, current_params_hash, is_ossified, ossified_at,
             block_vk_hash, payout_vk_hash, updated_at, ceremony_id)
         VALUES (1, ?1, ?2, 0, NULL, NULL, NULL, ?3, ?4)",
        rusqlite::params![max_position, current_params_hash, now, ceremony_id],
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!(
        contribution_count = max_position,
        "v39: Backfilled mpc_ceremony singleton from existing contribution history"
    );
    Ok(())
}

/// Migration v40: autonomous-ossification pin.
///
/// Adds a nullable `ossified_file_hash BLOB` column to the `mpc_ceremony`
/// singleton. When the ceremony reaches `MAX_CEREMONY_CONTRIBUTORS` this column
/// records the raw-file SHA-256 of the final `note_spend_params_current.bin`
/// (the SAME digest a `ZK_PARAMS_HASH` static pin holds). Its presence makes a
/// node self-select the `OssifiedPinned` startup mode with no operator action —
/// no env re-pin, surviving restarts and fresh joins forever.
///
/// Additive and idempotent: no existing row is rewritten (a live ceremony that
/// has not yet ossified simply gets a NULL column, which reads as "not ossified
/// yet"). The one-way latch in `save_mpc_ceremony_state` / `latch_mpc_ossification`
/// is what later populates it, deterministically, on every node.
fn migrate_v40(conn: &Connection) -> GhostResult<()> {
    debug!(
        "Running migration v40: Add mpc_ceremony.ossified_file_hash (autonomous ossification pin)"
    );

    conn.execute_batch("ALTER TABLE mpc_ceremony ADD COLUMN ossified_file_hash BLOB;")
        .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("v40: Added mpc_ceremony.ossified_file_hash column");
    Ok(())
}

/// Migration v41: persist the signed `ShareProof` alongside each share.
///
/// The payout ledger is computed from the `shares` table, and every node must sum an
/// IDENTICAL share set or the GHOST-02 exact-equality recompute rejects the payout. Share
/// gossip is fire-and-forget, so drops happen; GHOST-03 anti-entropy exists to repair them.
///
/// But a node can only serve a backfill if it can hand over the *signed proof* — and the
/// proof was only ever held in `RoundManager::recent_proofs`, pruned after 10 rounds. The
/// `shares` table could not stand in for it: `miner_id` and `received_by` are stored TRUNCATED
/// (8- and 4-byte hex prefixes), and `template_id`, `payout_address` and the GHOST-09 signature
/// are not stored at all. So beyond a ~15 minute window there was nothing to reconcile from,
/// and divergence became permanent.
///
/// This column stores the canonical JSON of the full `ShareProof`, so any node can serve — and
/// any node can signature-verify — a backfill for a share of any age.
///
/// Additive and idempotent. Existing rows get NULL: those shares predate the column and their
/// proofs are gone for good, so they cannot be served or verified. Reconciling that backlog is
/// a one-time operation, not something this migration can do.
fn migrate_v41(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v41: Add shares.proof (signed ShareProof for ledger convergence)");

    // A real pool DB always has `shares` (v1). Some partial-schema fixtures do not, and a
    // ledger-less database has nothing to migrate.
    let has_shares: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='shares'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if !has_shares {
        debug!("v41: no `shares` table — nothing to migrate");
        return Ok(());
    }

    conn.execute_batch("ALTER TABLE shares ADD COLUMN proof BLOB;")
        .map_err(|e| GhostError::Migration(e.to_string()))?;

    // Convergence serves by (round, share) and backfills by share_hash; the existing
    // idx_shares_round / UNIQUE(share_hash) cover both, so no new index is needed.
    info!("v41: Added shares.proof column");

    normalise_legacy_share_hash_byte_order(conn)?;
    Ok(())
}

/// Migration v42: the verification ledger — one table of signed
/// `VerificationResultMessage` records across all capabilities, the challenge
/// equivalent of `shares.proof`. It is the source of truth for challenge
/// convergence (GHOST-03-style backfill) and, later, deterministic node-reward
/// qualification. The signed record is UNIFORM across capabilities even though
/// the four raw `*_challenges` tables are not, so it lives in one table (the
/// shares model, applied to a uniform signed record). The PRIMARY KEY makes
/// gossip re-delivery and backfill idempotent — the dedup the `*_challenges`
/// tables never had. See `ghost-web/docs/node-reward-convergence.md`.
fn migrate_v42(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v42: verification_ledger (signed challenge records)");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS verification_ledger (
            challenger_id  TEXT    NOT NULL,
            target_node_id TEXT    NOT NULL,
            capability     TEXT    NOT NULL,
            passed         INTEGER NOT NULL,
            timestamp      INTEGER NOT NULL,
            proof          BLOB    NOT NULL,
            PRIMARY KEY (challenger_id, target_node_id, capability, timestamp)
        );
         CREATE INDEX IF NOT EXISTS idx_vled_target_cap_ts
             ON verification_ledger(target_node_id, capability, timestamp);
         CREATE INDEX IF NOT EXISTS idx_vled_ts
             ON verification_ledger(timestamp);",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;
    info!("v42: created verification_ledger");
    Ok(())
}

/// Migration v43: the payout-ledger checkpoint store. Each row is a BFT-finalised
/// snapshot `{height, cutoff_ts, ledger_root}` that the fleet agreed on — the
/// object the coinbase becomes a pure function of. Keyed by `height` (one finalised
/// checkpoint per anchor height), so re-delivery/replay is idempotent. Additive:
/// a fresh table, no change to existing data. See `tasks/design_payout_finalization.md`.
fn migrate_v43(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v43: payout_ledger_checkpoints");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS payout_ledger_checkpoints (
            height            INTEGER PRIMARY KEY,
            cutoff_ts         INTEGER NOT NULL,
            ledger_root       BLOB    NOT NULL,
            proposer_id       TEXT    NOT NULL,
            active_node_count INTEGER NOT NULL,
            created_at        TEXT    NOT NULL DEFAULT (datetime('now'))
        );",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;
    info!("v43: created payout_ledger_checkpoints");
    Ok(())
}

/// v44: option (c) adopt-on-finalise — store the CANONICAL payout the fleet ratified
/// (miner + node lists) so the coinbase builds from the agreed checkpoint, not the local
/// (divergent) share ledger. One JSON blob column; NULL on pre-(c) rows.
fn migrate_v44(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v44: payout_ledger_checkpoints.canonical_payout");
    conn.execute_batch("ALTER TABLE payout_ledger_checkpoints ADD COLUMN canonical_payout BLOB;")
        .map_err(|e| GhostError::Migration(e.to_string()))?;
    info!("v44: added payout_ledger_checkpoints.canonical_payout");
    Ok(())
}

/// v45: Surface A-2b — record the ROUND a verification verdict was issued in, so
/// qualification can recompute the consensus-drawn challenger assignment for that
/// round (seeded by the buried block hash) and count the verdict only if the
/// challenger was actually assigned to the target. Additive nullable column;
/// NULL on pre-A-2b rows (they predate assignment and are only ever counted below
/// the CHALLENGER_ASSIGNMENT_HEIGHT gate, where the filter is inactive).
fn migrate_v45(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v45: verification_ledger.round_height");
    conn.execute_batch("ALTER TABLE verification_ledger ADD COLUMN round_height INTEGER;")
        .map_err(|e| GhostError::Migration(e.to_string()))?;
    info!("v45: added verification_ledger.round_height");
    Ok(())
}

/// Migration v46: an isolated record of blocks the pool actually WON and settled, so the
/// "blocks found" count reflects real wins rather than every proposed (incl. rejected)
/// block in `payout_proposals`. Written only by `settle_paid_block` (coins exist). Kept
/// separate from `rounds.payout_status` so round pruning / payout-history queries are
/// unaffected. Additive: a fresh table, no change to existing data.
fn migrate_v46(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v46: won_blocks");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS won_blocks (
            block_height INTEGER PRIMARY KEY,
            settled_at   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;
    info!("v46: created won_blocks");
    Ok(())
}

/// v47: storage for the signed mesh node-list checkpoint (#402, #467).
///
/// Cherry-picked verbatim from `pool-hardening`, which is where this migration was written and
/// where vm6 and vm8 already ran it. Their live table is byte-identical to this statement, so
/// landing it here converges them rather than leaving two nodes claiming version 47 for a
/// migration `main` never had (#523).
///
/// The checkpoint gate is dormant, so this creates the table and nothing writes to it yet.
fn migrate_v47(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v47: mesh_node_list_checkpoints");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS mesh_node_list_checkpoints (
            height             INTEGER PRIMARY KEY,
            cutoff_ts          INTEGER NOT NULL,
            list_root          BLOB    NOT NULL,
            signer_set_root    BLOB    NOT NULL,
            proposer_id        TEXT    NOT NULL,
            active_node_count  INTEGER NOT NULL,
            proposer_signature BLOB    NOT NULL,
            detail             BLOB    NOT NULL,
            created_at         TEXT    NOT NULL DEFAULT (datetime('now'))
        );",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;
    info!("v47: created mesh_node_list_checkpoints");
    Ok(())
}

/// v48: covering index for the unpaid-ledger scan (#554, #556).
///
/// `get_top_unpaid_addresses` is the hot query in the whole system — `compute_root` runs it on
/// every payout-checkpoint propose AND every vote, on a 30 s cadence. It aggregates every unpaid
/// share, and with payouts stalled since 2026-07-25 that is 2.66M rows reaching back to 06-02.
///
/// The existing `idx_shares_unpaid` covers only `(miner_id)`, so the planner walked the index and
/// then did a **random row fetch per entry** to read `timestamp`, `valid` and `work`. That is 2.66M
/// scattered reads against a 1.4 GB table, which only works while the table is in page cache.
///
/// Measured on vm5 (4 GB RAM, 2.5 GB database — i.e. it does NOT fit):
///
/// ```text
///   before: 55.57 s wall,  3.42 s user   <- 52 s of pure I/O wait
///   after:   4.04 s wall,  1.92 s user   <- 13.8x faster
/// ```
///
/// The query runs every 30 s and took 55 s, so vm5 could never keep up: calls overlapped, the
/// process read 4.35 TB from a 2.6 GB database in 15 h, and one tokio worker sat pinned in
/// uninterruptible disk wait while `/health` timed out. After the index, `/health` on vm5 went
/// from a 45 s timeout to 1.9 ms.
///
/// The index is ~126 MB against a ~1.4 GB table, so the scan's working set now fits in RAM on a
/// 4 GB node, which is the whole point.
///
/// This was applied by hand to all eight nodes on 2026-07-29 to clear the live outage; this
/// migration is what makes it survive a reinstall or a fresh node. `IF NOT EXISTS` means it is a
/// no-op on those nodes.
///
/// NOTE this does not fix the underlying design: the query is still O(unpaid shares) and still
/// costs ~2-4 s of CPU per call. Bounding that needs either memoisation by `(cutoff_ts, height)`
/// or a maintained per-miner totals table — see #554.
fn migrate_v48(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v48: covering index for the unpaid-ledger scan");

    // Same guard as v41: a real pool DB always has `shares` (v1), but partial-schema
    // fixtures do not, and a ledger-less database has no scan to accelerate.
    let has_shares: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='shares'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if !has_shares {
        debug!("v48: no `shares` table — nothing to index");
        return Ok(());
    }

    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_shares_unpaid_cover
             ON shares(miner_id, timestamp, valid, work)
             WHERE paid_in_proposal_hash IS NULL;",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;
    info!("v48: created idx_shares_unpaid_cover");
    Ok(())
}

/// v41: rewrite legacy locally-received shares into canonical INTERNAL byte order.
///
/// The SV1/SV2 layer reports `share_hash` in big-endian DISPLAY order (PoW zeros at the front).
/// The locally-received path stored that verbatim, while every GOSSIPED copy of the same share
/// was stored in INTERNAL order (zeros at the high-index end), matching the signed `ShareProof`.
/// So one physical share carried two different `share_hash` spellings depending on which node
/// wrote it, and `share_hash` was useless as a cross-node identity.
///
/// That was survivable only because a node skips gossip of its own shares, so nothing ever
/// re-inserted the other spelling. The moment ledger convergence reconciles on `share_hash`, a
/// peer would serve a node its OWN shares back under the internal spelling, the UNIQUE
/// constraint would not recognise them, and the work would be counted TWICE.
///
/// Detection is unambiguous in practice: a share meets a difficulty target, so its display form
/// begins with a run of zeros and its internal form ends with one. We rewrite only rows that
/// look display-shaped and NOT internal-shaped, so an ambiguous hash is left alone rather than
/// guessed at.
///
/// A UNIQUE collision during the rewrite means the node genuinely held BOTH spellings of one
/// share — a real double-count — so the duplicate is deleted rather than kept.
fn normalise_legacy_share_hash_byte_order(conn: &Connection) -> GhostResult<()> {
    let mut stmt = conn
        .prepare(
            "SELECT id, share_hash FROM shares
             WHERE share_hash LIKE '00000000%' AND share_hash NOT LIKE '%00000000'",
        )
        .map_err(|e| GhostError::Migration(e.to_string()))?;

    let rows: Vec<(i64, String)> = stmt
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
        .map_err(|e| GhostError::Migration(e.to_string()))?
        .collect::<Result<_, _>>()
        .map_err(|e| GhostError::Migration(e.to_string()))?;
    drop(stmt);

    let (mut rewritten, mut deduped, mut skipped) = (0usize, 0usize, 0usize);
    for (id, display_hex) in rows {
        let Ok(bytes) = hex::decode(&display_hex) else {
            skipped += 1;
            continue;
        };
        if bytes.len() != 32 {
            skipped += 1;
            continue;
        }
        let internal: Vec<u8> = bytes.iter().rev().copied().collect();
        let internal_hex = hex::encode(internal);

        match conn.execute(
            "UPDATE shares SET share_hash = ?1 WHERE id = ?2",
            params![internal_hex, id],
        ) {
            Ok(_) => rewritten += 1,
            Err(e) if e.to_string().contains("UNIQUE") => {
                // Both spellings of the same share were present — a genuine double-count.
                conn.execute("DELETE FROM shares WHERE id = ?1", params![id])
                    .map_err(|e| GhostError::Migration(e.to_string()))?;
                deduped += 1;
            }
            Err(e) => return Err(GhostError::Migration(e.to_string())),
        }
    }

    info!(
        rewritten,
        deduped, skipped, "v41: normalised legacy share_hash byte order to internal"
    );
    Ok(())
}

/// v49: chain-derived settlement — `payout_proposals.outputs_hash` + `settled_blocks`.
///
/// Settlement is what marks a miner's shares paid so the next payout does not pay the same work
/// twice. Until now it ran in exactly one place: `payout::settle_paid_block`, called only from the
/// `block_submitted` consumer, i.e. **only on the node that submitted the winning block**. The
/// other seven never marked anything paid, so after a win their ledgers still owed the whole paid
/// set. Whichever of them proposed next would pay it again, and — because they are the majority —
/// their view is the one that reaches quorum. That is a double-payment path, and it also explains
/// why the unpaid ledger only ever grows: nothing has settled since 2026-06-02.
///
/// The fix is to stop *announcing* settlement and start *observing* it. A won block's coinbase is
/// already on-chain and already commits to exactly who was paid, so every node can settle from its
/// own view of the chain with no gossip, no new consensus object, and no agreement step. Hashing
/// the observed coinbase outputs under `CoinbaseOutputs/v1` yields the same `outputs_hash` the
/// proposal committed to, which is what makes the match trustworthy: the chain is the anchor, so a
/// forged proposal cannot hash to an observed coinbase.
///
/// Two changes, because two things were missing — and, deliberately, no new proposal table.
///
/// `payout_proposals.outputs_hash` — proposals are **already** persisted with their full JSON
/// (`payout_proposals`, added in v18; written by `store_payout_proposal` on every proposal, and
/// never pruned). What was missing is only the lookup key: settlement starts from a coinbase seen
/// on-chain, so it needs to find a proposal by the hash of that coinbase's outputs. Adding the
/// column and its index to the existing table keeps one source of truth for "what proposals exist";
/// an earlier draft of this migration created a parallel `ratified_proposals` table, which would
/// have duplicated the JSON and left two places to disagree about proposal history.
///
/// Nullable, because rows written before this migration have no hash. They are backfilled lazily:
/// `store_payout_proposal` computes it going forward, and a proposal that predates the column
/// simply will not match a coinbase until it is rewritten. That is the correct failure — it means
/// "I cannot prove this block is mine", not "this block is not mine".
///
/// `coinbase_skeletons` — the invariant parts of a job's coinbase, either side of the extranonce.
/// Persisted rather than held in memory because a restart would otherwise leave every share of the
/// job in flight unverifiable: the skeleton had already been delivered, so `pool_sv2` will not
/// offer it again, and nothing would ask. Retention is the reorg-floor rule in `skeleton_store`.
///
/// `unverified_bindings` — shares whose skeleton had not arrived when they did. Recording them is
/// what makes the gap close: without this the share is judged once, on the one occasion the
/// evidence happened to be missing, and never revisited. Indexed by `skeleton_id` so a skeleton
/// arriving late can find exactly the shares waiting on it. Cleared on success; retried on the
/// same reconcile tick that retries deferred settlements.
///
/// `deferred_settlements` — a block that carries our payout tag but whose proposal this node never
/// received. It cannot be settled yet, and forgetting it would be a silent hole: the forward scan
/// is cursor-driven, so once the cursor passes that height the block is never looked at again, and
/// the proposal fetched from a peer a second later would arrive with nothing left to apply it to.
/// Recording the block instead lets reconciliation retry exactly those, bounded, and survive a
/// restart — the cursor keeps advancing and the unresolved set stays small.
///
/// `settled_blocks` — records exactly what each settlement applied (`shares_marked`,
/// `treasury_bumped`) so a reorg reversal is an exact inversion of recorded amounts rather than a
/// recomputation, and so re-settling is idempotent. `reversed` is a flag rather than a deletion:
/// an orphaned block that later returns to the main chain must re-settle through the same row.
///
/// Additive throughout. The column add is guarded so re-running is a no-op.
fn migrate_v49(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v49: payout_proposals.outputs_hash + settled_blocks");

    // Same guard as v41 and v48: a real pool DB always has `payout_proposals` (v18), but
    // partial-schema test fixtures do not, and there is nothing to extend on those.
    let has_proposals: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='payout_proposals'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| GhostError::Migration(e.to_string()))?;

    if has_proposals > 0 {
        // ALTER TABLE ADD COLUMN is not idempotent in SQLite, so check for the column first.
        let has_outputs_hash: bool = {
            let mut stmt = conn
                .prepare("PRAGMA table_info(payout_proposals)")
                .map_err(|e| GhostError::Migration(e.to_string()))?;
            let cols: Vec<String> = stmt
                .query_map([], |r| r.get::<_, String>(1))
                .map_err(|e| GhostError::Migration(e.to_string()))?
                .filter_map(|c| c.ok())
                .collect();
            cols.iter().any(|c| c == "outputs_hash")
        };
        if !has_outputs_hash {
            conn.execute_batch("ALTER TABLE payout_proposals ADD COLUMN outputs_hash BLOB;")
                .map_err(|e| GhostError::Migration(e.to_string()))?;
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_payout_proposals_outputs
                 ON payout_proposals(outputs_hash);",
        )
        .map_err(|e| GhostError::Migration(e.to_string()))?;
    }

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS settled_blocks (
            block_hash      TEXT    PRIMARY KEY,
            block_height    INTEGER NOT NULL,
            proposal_hash   BLOB    NOT NULL,
            outputs_hash    BLOB    NOT NULL,
            shares_marked   INTEGER NOT NULL,
            treasury_bumped INTEGER NOT NULL,
            settled_ts      INTEGER NOT NULL,
            reversed        INTEGER NOT NULL DEFAULT 0
        );
         CREATE INDEX IF NOT EXISTS idx_settled_blocks_unreversed
             ON settled_blocks(reversed, block_height);",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS coinbase_skeletons (
            skeleton_id     BLOB    PRIMARY KEY,
            coinbase_prefix BLOB    NOT NULL,
            coinbase_suffix BLOB    NOT NULL,
            merkle_path     BLOB    NOT NULL,
            stored_at       INTEGER NOT NULL,
            floor_from      INTEGER NOT NULL,
            last_seq        INTEGER
        );
         CREATE TABLE IF NOT EXISTS unverified_bindings (
            share_hash  TEXT    PRIMARY KEY,
            skeleton_id BLOB    NOT NULL,
            extranonce  BLOB    NOT NULL,
            header      BLOB    NOT NULL,
            expected_node BLOB  NOT NULL,
            first_seen  INTEGER NOT NULL,
            attempts    INTEGER NOT NULL DEFAULT 0
        );
         CREATE INDEX IF NOT EXISTS idx_unverified_bindings_skeleton
             ON unverified_bindings(skeleton_id);",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS deferred_settlements (
            block_hash    TEXT    PRIMARY KEY,
            block_height  INTEGER NOT NULL,
            payout_id     BLOB    NOT NULL,
            first_seen_ts INTEGER NOT NULL,
            attempts      INTEGER NOT NULL DEFAULT 0
        );",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("v49: added payout_proposals.outputs_hash, settled_blocks and deferred_settlements");
    Ok(())
}

/// v53: the network shard's persistent state (`SHARE_SHARD.md` §4.3/§4.4, build Stage 1).
///
/// Strictly additive and dormant: nothing reads these tables until the shard is wired behind
/// `pool.share_shard`, so a node on the old path is unaffected and a rollback to the previous
/// binary simply ignores them. Every `sbc_*` table is left untouched — the SBC layer is deleted
/// in a later release, not this one, and this migration must not depend on it either way.
///
/// Three tables, mirroring `ghost_common::share_shard::ShardTable`:
///
/// - `shard_counters` — one row per `accrued[node][address]` cell. Grow-only in merged state;
///   this node's own column is the only one written additively, remote columns land here after
///   a verified max-merge.
/// - `shard_settled` — `settled[address]`, read off the chain at coinbase maturity. Never
///   gossiped, so there is no stale copy anywhere to resurrect (§4.4).
/// - `shard_epochs` — this node's own signed per-epoch summaries, kept so a syncing peer can be
///   answered and so a folded epoch is durably marked as folded.
///
/// KEYED BY `H(plaintext address)`, NEVER THE CIPHERTEXT — the `sbc_balances` rationale holds
/// unchanged: `encrypt_sensitive` draws a fresh random nonce per call, so the same address
/// encrypts differently every time and a ciphertext key could never be looked up. Every write
/// would insert a new row and one miner's balance would scatter across duplicates. The hash is
/// deterministic, and portable between nodes where the per-node ciphertext is not. Never
/// `GROUP BY` the encrypted column.
///
/// `*_micro` columns are INTEGER because the in-memory type is `i64` micro-work
/// (`share_batch::fold_shares`); storing TEXT would let the persisted type drift from the type
/// the table root is computed over, and the root is what nodes compare.
///
/// No VACUUM here or in any accessor: it needs 2× the database size free, and vm1 does not
/// have it.
fn migrate_v53(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v53: shard_counters, shard_settled, shard_epochs");

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS shard_counters (
            node_id       BLOB    NOT NULL,
            address_hash  BLOB    NOT NULL,
            -- Encrypted plaintext, decrypted on load: the table root commits to PLAINTEXT
            -- addresses, so plaintext is what has to reach the in-memory table.
            address_enc   TEXT    NOT NULL,
            total_micro   INTEGER NOT NULL,
            -- Which epoch last wrote this cell. Advisory, for diagnosis — never a decision
            -- input (the close_ts/finalised_at lesson).
            updated_epoch INTEGER NOT NULL,
            PRIMARY KEY (node_id, address_hash)
         );
         CREATE INDEX IF NOT EXISTS idx_shard_counters_epoch
             ON shard_counters(updated_epoch);

         CREATE TABLE IF NOT EXISTS shard_settled (
            address_hash  BLOB    PRIMARY KEY,
            address_enc   TEXT    NOT NULL,
            settled_micro INTEGER NOT NULL,
            -- The highest block height whose settlement touched this row. Advisory.
            last_height   INTEGER NOT NULL
         );

         -- One row per epoch: this node's OWN summary (each node writes only its own column,
         -- §4.4, so it only ever signs its own). The full summary is kept — root alone cannot
         -- reconstruct one — encrypted at rest because the deltas are keyed by plaintext payout
         -- address. Unlike sbc_batches' verbatim JSON, re-serialisation is harmless here: the
         -- signature covers the canonical signing bytes, not the JSON encoding.
         CREATE TABLE IF NOT EXISTS shard_epochs (
            epoch        INTEGER PRIMARY KEY,
            node_id      BLOB    NOT NULL,
            share_root   BLOB    NOT NULL,
            share_count  INTEGER NOT NULL,
            summary_enc  TEXT    NOT NULL,
            published    INTEGER NOT NULL DEFAULT 0
         );",
    )
    .map_err(|e| GhostError::Database(e.to_string()))?;

    Ok(())
}

/// v50: share-batch chain persistence (WP-5 shadow run).
///
/// See `docs/archive/SHARE_BATCH_CHAIN.md`. The defect being replaced is stated there in one line:
/// **"payable state is O(shares), not O(addresses)"**. Today the payable state is 1.5M unpaid
/// share rows that every node rescans to produce ~68 numbers. Here it is the ~68 numbers.
///
/// So this deliberately does NOT archive shares. Shares travel *inside* a batch so new work can
/// enter the chain, but once a batch is folded the balance carries the value forward and the share
/// rows are no longer payable state. Persisting every batch's shares would rebuild the same
/// O(shares) problem one layer down.
///
/// What must survive a restart, and why:
///
/// - **balances** — the payable state itself.
/// - **the adopted chain, bounded** — enough to judge the next batch's parent and to serve sync to
///   a node that fell behind. Not history for its own sake.
/// - **quarantine** — release is operator-only by design (an automatic timer lets a Byzantine node
///   misbehave, wait, and repeat), so it cannot live in memory.
///
/// Additive and dormant: nothing reads these until the shadow run is wired, so a node on the old
/// path is unaffected and a downgrade ignores them.
/// v51: persist share-batch COMMIT CERTIFICATES.
///
/// A certificate is the quorum of signed precommits that decided a sequence. It is the only thing
/// that lets a node which missed a sequence's consensus adopt it later — the receiver cannot
/// establish "was this committed?" from local state, so the peer that watched it close supplies
/// the proof.
///
/// Held only in memory, that proof evaporated on restart. A rolling fleet restart — the ordinary
/// deploy — left NO node holding a certificate for any committed sequence, so any node that was
/// behind at that moment could never adopt those sequences from anyone, permanently. Catch-up was
/// correctly gated on a verifiable certificate, which turned "lost proof" into "wedged node".
///
/// Small and immutable: one row per committed sequence, a few hundred bytes of signatures, written
/// once and never updated. Bounded by the same retention as the batch window.
/// v52: `sbc_watermarks` — the share-batch chain's per-proposer replay guard.
///
/// One row per proposer: the canonical position `(ts, share_hash)` of the last share that
/// proposer has had adopted. `verify_batch` requires a batch's shares to sort strictly after this
/// mark, which is what stops the same share being credited in two batches — WITHOUT a per-share
/// index, which this schema deliberately does not have (payable state is O(addresses), and the
/// guard is O(proposers): 8 rows).
///
/// Written in the same transaction as `sbc_balances` because both are the fold's running state:
/// a watermark ahead of the balances would fault honest proposers for shares never actually
/// credited, and one behind would re-credit what already was.
fn migrate_v52(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v52: sbc_watermarks");

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sbc_watermarks (
            proposer    BLOB    PRIMARY KEY,
            ts          INTEGER NOT NULL,
            share_hash  BLOB    NOT NULL,
            updated_seq INTEGER NOT NULL
         );",
    )
    .map_err(|e| GhostError::Database(e.to_string()))?;

    Ok(())
}

fn migrate_v51(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v51: sbc_certs");

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sbc_certs (
            seq             INTEGER PRIMARY KEY,
            round           INTEGER NOT NULL,
            batch_hash      BLOB    NOT NULL,
            voter_set_hash  BLOB    NOT NULL,
            -- The signatures, as the JSON the wire type carries. Stored verbatim so what is
            -- served is byte-identical to what was verified when it was minted.
            cert_json       TEXT    NOT NULL,
            minted_at       INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_sbc_certs_hash ON sbc_certs(batch_hash);",
    )
    .map_err(|e| GhostError::Database(e.to_string()))?;

    Ok(())
}

fn migrate_v50(conn: &Connection) -> GhostResult<()> {
    debug!("Running migration v50: sbc_balances, sbc_batches, sbc_quarantine");

    conn.execute_batch(
        // The payable state. ~68 rows, bounded by miner count rather than by history.
        //
        // `micro_work` is INTEGER because the fold is `BTreeMap<String, i64>` with
        // `saturating_add` (share_batch::fold_shares). Storing it as TEXT would invite a
        // conversion at every read and let the stored type drift from the type the state root is
        // actually computed over — and the root is what nodes compare.
        //
        // KEYED BY HASH, NOT CIPHERTEXT. `encrypt_sensitive` draws a fresh random nonce per call,
        // so the same address encrypts differently every time and a ciphertext key could never be
        // looked up: every fold would insert a new row and a miner's balance would scatter across
        // duplicates. The hash is deterministic, so it can. It also happens to be portable between
        // nodes, whereas the ciphertext is not — the encryption key is per-node.
        //
        // `address_enc` holds the encrypted plaintext, decrypted into the fold's map on load. The
        // state root commits to PLAINTEXT addresses, so plaintext is what has to reach the fold;
        // at ~68 rows the decrypt cost is immaterial.
        "CREATE TABLE IF NOT EXISTS sbc_balances (
            address_hash BLOB    PRIMARY KEY,
            address_enc  TEXT    NOT NULL,
            micro_work   INTEGER NOT NULL,
            updated_seq  INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_sbc_balances_seq ON sbc_balances(updated_seq);

        -- The adopted chain, retained as a BOUNDED WINDOW rather than forever.
        --
        -- Two jobs: `MAX(seq)` is the head a new batch is judged against, and the recent entries
        -- are what a lagging node's ShareBatchSync is answered from. Neither needs deep history.
        --
        -- `batch_json` is the full adopted batch, so a sync response is served verbatim rather
        -- than reconstructed — a reconstruction that differs by one byte is a batch hash that no
        -- longer verifies. It is the one place shares are held, and only inside the window.
        --
        -- `state_root` is duplicated out of the JSON deliberately: it is the value the trust gate
        -- compares across all 8 nodes, and it should be readable without parsing a blob.
        CREATE TABLE IF NOT EXISTS sbc_batches (
            seq          INTEGER PRIMARY KEY,
            batch_hash   BLOB    NOT NULL,
            prev_hash    BLOB    NOT NULL,
            proposer     BLOB    NOT NULL,
            close_ts     INTEGER NOT NULL,
            state_root   BLOB    NOT NULL,
            share_count  INTEGER NOT NULL,
            batch_json   TEXT    NOT NULL,
            finalised_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_sbc_batches_hash ON sbc_batches(batch_hash);

        -- Quarantined peers. Release is OPERATOR-ONLY: an automatic timer would let a Byzantine
        -- node misbehave, wait it out, and repeat forever. So this outlives the process.
        CREATE TABLE IF NOT EXISTS sbc_quarantine (
            node_id        BLOB    PRIMARY KEY,
            reason         TEXT    NOT NULL,
            batch_seq      INTEGER,
            quarantined_at INTEGER NOT NULL
        );",
    )
    .map_err(|e| GhostError::Migration(e.to_string()))?;

    info!("v50: created sbc_balances, sbc_batches and sbc_quarantine (share-batch chain, dormant)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// v47 creates the mesh node-list checkpoint table, and doing so must be idempotent —
    /// vm6 and vm8 already have it from a `pool-hardening` build, so this migration meets an
    /// existing table on those nodes (#523).
    #[test]
    fn v47_creates_the_checkpoint_table_and_tolerates_an_existing_one() {
        let conn = Connection::open_in_memory().expect("conn");
        run_migrations(&conn).expect("migrate");
        // Bind to the constant, not a literal: this test is about v47's table being
        // idempotent, so pinning the version number here just breaks it on every
        // subsequent migration (it did, on v48).
        assert_eq!(get_schema_version(&conn).unwrap(), SCHEMA_VERSION);

        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = 'mesh_node_list_checkpoints'",
                [],
                |r| r.get(0),
            )
            .expect("table must exist after migrating");
        // The columns the checkpoint blob is stored under. Pinned because vm6/vm8 already hold
        // this exact shape; a divergence here would split the fleet's schema silently.
        for col in [
            "height",
            "cutoff_ts",
            "list_root",
            "signer_set_root",
            "proposer_id",
            "active_node_count",
            "proposer_signature",
            "detail",
            "created_at",
        ] {
            assert!(sql.contains(col), "v47 table is missing `{col}`: {sql}");
        }

        // Running it again against the existing table must not error.
        migrate_v47(&conn).expect("v47 must be idempotent");
    }

    /// The v48 index is only worth its ~126 MB if the planner actually chooses it for the
    /// unpaid-ledger aggregate. Assert the plan, not just that the index exists — an index
    /// the optimiser ignores is pure cost, and this one exists to stop a 55 s query.
    #[test]
    fn v48_covering_index_is_used_by_the_unpaid_ledger_scan() {
        let conn = Connection::open_in_memory().expect("conn");
        run_migrations(&conn).expect("migrate");

        let plan: String = conn
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT s.miner_id, SUM(CAST(ROUND(s.work * 1000000) AS INTEGER)), m.payout_address
                 FROM shares s INNER JOIN miners m ON m.miner_id = s.miner_id
                 WHERE s.paid_in_proposal_hash IS NULL AND s.timestamp <= 1 AND s.valid = 1
                 GROUP BY s.miner_id",
            )
            .expect("prepare")
            .query_map([], |r| r.get::<_, String>(3))
            .expect("plan")
            .collect::<Result<Vec<_>, _>>()
            .expect("rows")
            .join(" | ");

        assert!(
            plan.contains("idx_shares_unpaid_cover"),
            "planner did not choose the covering index; plan was: {plan}"
        );
    }

    /// Re-running v48 must be a no-op — it was applied by hand to all eight nodes before this
    /// migration existed, so every one of them runs it against an index that is already there.
    #[test]
    fn v48_is_idempotent() {
        let conn = Connection::open_in_memory().expect("conn");
        run_migrations(&conn).expect("migrate");
        migrate_v48(&conn).expect("v48 must be idempotent");
        migrate_v48(&conn).expect("v48 must be idempotent twice");
    }

    /// v49 must be idempotent: a node that has already taken the settlement tables (a canary on an
    /// earlier build, or a hand-applied fix) runs this against tables that already exist.
    #[test]
    fn v49_is_idempotent() {
        let conn = Connection::open_in_memory().expect("conn");
        run_migrations(&conn).expect("migrate");
        migrate_v49(&conn).expect("v49 must be idempotent");
        migrate_v49(&conn).expect("v49 must be idempotent twice");
    }

    /// The settlement tables must carry every column the reversal path reads back. Reversal is an
    /// exact inversion of what settlement applied, so `shares_marked` and `treasury_bumped` are
    /// load-bearing: without them a reorg could only re-derive, and re-deriving after the ledger
    /// has moved on is how you double-credit.
    #[test]
    fn v49_settlement_tables_have_the_reversal_columns() {
        let conn = Connection::open_in_memory().expect("conn");
        run_migrations(&conn).expect("migrate");

        for (table, required) in [
            (
                "settled_blocks",
                vec![
                    "block_hash",
                    "block_height",
                    "proposal_hash",
                    "outputs_hash",
                    "shares_marked",
                    "treasury_bumped",
                    "settled_ts",
                    "reversed",
                ],
            ),
            // Extended, not duplicated: proposals already live here with their full JSON.
            (
                "payout_proposals",
                vec!["proposal_hash", "proposal_json", "outputs_hash"],
            ),
        ] {
            let mut stmt = conn
                .prepare(&format!("PRAGMA table_info({table})"))
                .expect("prepare");
            let columns: Vec<String> = stmt
                .query_map([], |r| r.get::<_, String>(1))
                .expect("query")
                .map(|c| c.expect("column"))
                .collect();
            for column in required {
                assert!(
                    columns.contains(&column.to_string()),
                    "{table} missing '{column}'. Found: {columns:?}"
                );
            }
        }
    }

    /// The lookup that drives settlement is "given a coinbase I just saw on-chain, which proposal
    /// does it pay?" — an `outputs_hash` probe. It must not degrade into a table scan, because it
    /// runs on every block the node sees, including every block mined by everyone else.
    #[test]
    fn v49_outputs_hash_lookup_uses_the_index() {
        let conn = Connection::open_in_memory().expect("conn");
        run_migrations(&conn).expect("migrate");

        let plan: String = conn
            .query_row(
                "EXPLAIN QUERY PLAN SELECT proposal_hash FROM payout_proposals \
                 WHERE outputs_hash = ?1",
                [vec![0u8; 32]],
                |r| r.get(3),
            )
            .expect("explain");

        assert!(
            plan.contains("idx_payout_proposals_outputs"),
            "planner did not choose the outputs_hash index; plan was: {plan}"
        );
    }

    /// The column add is not idempotent in SQLite, so it is guarded. A node that already took v49
    /// (a canary on an earlier build) must not fail its next start with "duplicate column name".
    #[test]
    fn v49_column_add_is_guarded() {
        let conn = Connection::open_in_memory().expect("conn");
        run_migrations(&conn).expect("migrate");
        migrate_v49(&conn).expect("v49 must tolerate an existing outputs_hash column");
        migrate_v49(&conn).expect("and again");
    }

    /// A database from a NEWER build must be left alone, and must not be mistaken for one
    /// that is up to date.
    ///
    /// vm6 and vm8 are in this state: 47 against a binary at 46, from a branch test whose
    /// migration applied irreversibly. The risk is not present-tense — it is that this binary
    /// will one day define its own 47, and a `>=` check cannot tell the two apart.
    #[test]
    fn a_database_ahead_of_the_binary_is_not_treated_as_up_to_date() {
        let conn = Connection::open_in_memory().expect("conn");
        run_migrations(&conn).expect("migrate to current");
        assert_eq!(get_schema_version(&conn).unwrap(), SCHEMA_VERSION);

        // Simulate the node having run a newer build.
        set_schema_version(&conn, SCHEMA_VERSION + 1).unwrap();

        // Running again must succeed and must NOT rewind the version — a binary that
        // "corrected" a newer database down to its own number would destroy the record of
        // what had actually been applied.
        run_migrations(&conn).expect("must not fail on a newer database");
        assert_eq!(
            get_schema_version(&conn).unwrap(),
            SCHEMA_VERSION + 1,
            "an older binary must not rewind a newer database's version"
        );
    }

    /// The ordinary case: a database already at this binary's version is a no-op.
    #[test]
    fn a_database_at_the_binary_version_is_a_no_op() {
        let conn = Connection::open_in_memory().expect("conn");
        run_migrations(&conn).expect("first");
        let after_first = get_schema_version(&conn).unwrap();
        run_migrations(&conn).expect("second");
        assert_eq!(get_schema_version(&conn).unwrap(), after_first);
        assert_eq!(after_first, SCHEMA_VERSION);
    }

    /// v41 must rewrite display-order share hashes into canonical internal order, leave
    /// already-internal rows alone, and delete a row that collides (a genuine double-count).
    #[test]
    fn v41_normalises_share_hash_byte_order() {
        let conn = Connection::open_in_memory().expect("conn");
        run_migrations(&conn).expect("migrate");

        // A share as the LOCAL path used to write it: display order, zeros at the front.
        let display =
            "000000000000001625f43a1854a8cf2237e634e76068ffaf1eaf2c8e23c534e5".to_string();
        let internal: String = {
            let b = hex::decode(&display).expect("hex");
            hex::encode(b.iter().rev().copied().collect::<Vec<u8>>())
        };

        // A share as the GOSSIP path writes it: already internal, zeros at the end.
        let already_internal =
            "7b0ad875c4e9bc1301680b41a5bf47fdb69996795b56ede5fc280d0000000000".to_string();

        let insert = |hash: &str, node: &str| {
            conn.execute(
                "INSERT INTO shares (round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid)
                 VALUES (1, 'm', 1.0, 1.0, ?1, 100, ?2, 1)",
                params![hash, node],
            )
            .expect("insert");
        };
        insert(&display, "self");
        insert(&already_internal, "peer");

        normalise_legacy_share_hash_byte_order(&conn).expect("normalise");

        let hashes: Vec<String> = conn
            .prepare("SELECT share_hash FROM shares ORDER BY share_hash")
            .expect("prep")
            .query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows");

        assert!(
            hashes.contains(&internal),
            "the display-order row must be rewritten to internal order"
        );
        assert!(
            !hashes.contains(&display),
            "no display-order row may survive — share_hash must be a cross-node identity"
        );
        assert!(
            hashes.contains(&already_internal),
            "an already-internal row must be left untouched"
        );
        assert_eq!(hashes.len(), 2, "no rows invented or lost");
    }

    /// If a node holds BOTH spellings of one share, that is a live double-count: the same work
    /// summed twice into the payout ledger. The rewrite must collapse it, not preserve it.
    #[test]
    fn v41_deletes_a_double_counted_share() {
        let conn = Connection::open_in_memory().expect("conn");
        run_migrations(&conn).expect("migrate");

        let display = "000000000000001625f43a1854a8cf2237e634e76068ffaf1eaf2c8e23c534e5";
        let internal: String = {
            let b = hex::decode(display).expect("hex");
            hex::encode(b.iter().rev().copied().collect::<Vec<u8>>())
        };

        for (hash, node) in [(display, "self"), (internal.as_str(), "peer")] {
            conn.execute(
                "INSERT INTO shares (round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid)
                 VALUES (1, 'm', 1.0, 1.0, ?1, 100, ?2, 1)",
                params![hash, node],
            )
            .expect("insert");
        }

        normalise_legacy_share_hash_byte_order(&conn).expect("normalise");

        let (count, work): (i64, f64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(work),0) FROM shares",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("count");
        assert_eq!(count, 1, "the duplicate spelling must be deleted");
        assert_eq!(work, 1.0, "the work must be counted once, not twice");
    }

    #[test]
    fn test_migrations() {
        let conn = Connection::open_in_memory()
            .expect("MEDIUM-STOR-2: Failed to create in-memory connection for migration test");
        run_migrations(&conn).expect("MEDIUM-STOR-2: Failed to run migrations");

        let version = get_schema_version(&conn)
            .expect("MEDIUM-STOR-2: Failed to get schema version after migrations");
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn test_idempotent_migrations() {
        let conn = Connection::open_in_memory()
            .expect("MEDIUM-STOR-2: Failed to create in-memory connection for idempotency test");

        // Run migrations twice
        run_migrations(&conn).expect("MEDIUM-STOR-2: Failed to run migrations first time");
        run_migrations(&conn)
            .expect("MEDIUM-STOR-2: Failed to run migrations second time (idempotency)");

        let version = get_schema_version(&conn)
            .expect("MEDIUM-STOR-2: Failed to get schema version after idempotent migrations");
        assert_eq!(version, SCHEMA_VERSION);
    }

    // ========================================================================
    // v39: mpc_ceremony.ceremony_id + singleton backfill (Stage A task 3)
    // ========================================================================

    /// Create the `mpc_ceremony` + `mpc_contributions` tables in their pre-v39
    /// (v13) shape — i.e. WITHOUT the `ceremony_id` column — and stamp the DB at
    /// schema version 38 so `run_migrations` runs only v39.
    fn setup_pre_v39_mpc(conn: &Connection) {
        conn.execute_batch(
            r#"
            CREATE TABLE mpc_ceremony (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                contribution_count INTEGER NOT NULL DEFAULT 0,
                current_params_hash BLOB NOT NULL,
                is_ossified INTEGER NOT NULL DEFAULT 0,
                ossified_at INTEGER,
                block_vk_hash BLOB,
                payout_vk_hash BLOB,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE mpc_contributions (
                elder_position INTEGER PRIMARY KEY,
                contributor_node_id TEXT NOT NULL,
                prev_params_hash BLOB NOT NULL,
                new_params_hash BLOB NOT NULL,
                contribution_proof BLOB NOT NULL,
                epoch INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            "#,
        )
        .unwrap();
        set_schema_version(conn, 38).unwrap();
    }

    /// Insert `n` synthetic contributions chaining lineage hashes:
    /// pos 1 prev=[200;32] new=[1;32]; pos i prev=[i-1;32] new=[i;32].
    fn insert_synthetic_contributions(conn: &Connection, n: u8) {
        for pos in 1..=n {
            let prev = if pos == 1 { [200u8; 32] } else { [pos - 1; 32] };
            let new = [pos; 32];
            conn.execute(
                "INSERT INTO mpc_contributions
                    (elder_position, contributor_node_id, prev_params_hash, new_params_hash,
                     contribution_proof, epoch, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, 0)",
                rusqlite::params![
                    pos as i64,
                    format!("node{pos}"),
                    &prev[..],
                    &new[..],
                    &[1u8, 2, 3][..]
                ],
            )
            .unwrap();
        }
    }

    /// contribution_count, current_params_hash, is_ossified, ceremony_id
    type CeremonySingleton = (i64, Vec<u8>, i64, Option<Vec<u8>>);

    fn read_singleton(conn: &Connection) -> Option<CeremonySingleton> {
        conn.query_row(
            "SELECT contribution_count, current_params_hash, is_ossified, ceremony_id
             FROM mpc_ceremony WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .ok()
    }

    #[test]
    fn test_v39_adds_ceremony_id_column() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        let cols = get_column_names(&conn, "mpc_ceremony");
        assert!(
            cols.contains(&"ceremony_id".to_string()),
            "v39 must add ceremony_id column; got {cols:?}"
        );
    }

    #[test]
    fn test_v39_backfills_singleton_from_five_contributions() {
        let conn = Connection::open_in_memory().unwrap();
        setup_pre_v39_mpc(&conn);
        insert_synthetic_contributions(&conn, 5);

        run_migrations(&conn).unwrap();

        let (count, cph, ossified, cid) =
            read_singleton(&conn).expect("singleton must be backfilled");
        assert_eq!(count, 5, "contribution_count = MAX(elder_position)");
        assert_eq!(
            cph,
            vec![5u8; 32],
            "current_params_hash = contributions[5].new_params_hash"
        );
        assert_eq!(ossified, 0, "backfilled ceremony is not ossified");
        assert_eq!(
            cid,
            Some(vec![200u8; 32]),
            "ceremony_id = contributions[1].prev_params_hash"
        );
    }

    #[test]
    fn test_v39_backfill_is_idempotent_no_op_on_rerun() {
        let conn = Connection::open_in_memory().unwrap();
        setup_pre_v39_mpc(&conn);
        insert_synthetic_contributions(&conn, 5);

        run_migrations(&conn).unwrap();
        // Re-running is version-gated and must not change the singleton.
        run_migrations(&conn).unwrap();

        let (count, cph, _ossified, cid) = read_singleton(&conn).unwrap();
        assert_eq!(count, 5);
        assert_eq!(cph, vec![5u8; 32]);
        assert_eq!(cid, Some(vec![200u8; 32]));
    }

    #[test]
    fn test_v39_never_overwrites_existing_singleton() {
        let conn = Connection::open_in_memory().unwrap();
        setup_pre_v39_mpc(&conn);
        insert_synthetic_contributions(&conn, 5);
        // A singleton already exists with a DIFFERENT count — must be preserved.
        conn.execute(
            "INSERT INTO mpc_ceremony
                (id, contribution_count, current_params_hash, is_ossified, updated_at)
             VALUES (1, 2, ?1, 0, 123)",
            rusqlite::params![&[2u8; 32][..]],
        )
        .unwrap();

        run_migrations(&conn).unwrap();

        let (count, cph, _ossified, cid) = read_singleton(&conn).unwrap();
        assert_eq!(count, 2, "existing singleton count must NOT be overwritten");
        assert_eq!(cph, vec![2u8; 32], "existing current_params_hash preserved");
        assert_eq!(
            cid, None,
            "existing row's ceremony_id left as NULL (not backfilled)"
        );
    }

    #[test]
    fn test_v39_empty_contributions_writes_no_singleton() {
        let conn = Connection::open_in_memory().unwrap();
        setup_pre_v39_mpc(&conn);
        // No contributions at all (fresh genesis DB).

        run_migrations(&conn).unwrap();

        assert!(
            read_singleton(&conn).is_none(),
            "no singleton must be written when mpc_contributions is empty"
        );
    }

    // ========================================================================
    // v40: mpc_ceremony.ossified_file_hash (autonomous ossification pin)
    // ========================================================================

    #[test]
    fn test_v40_adds_ossified_file_hash_column() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        let cols = get_column_names(&conn, "mpc_ceremony");
        assert!(
            cols.contains(&"ossified_file_hash".to_string()),
            "v40 must add ossified_file_hash column; got {cols:?}"
        );
    }

    #[test]
    fn test_v40_applies_on_existing_db_without_data_loss() {
        // Start at the pre-v39 shape with a populated singleton, then run the
        // full migration chain (v39 + v40). The column is added and the existing
        // singleton data is untouched (additive migration).
        let conn = Connection::open_in_memory().unwrap();
        setup_pre_v39_mpc(&conn);
        insert_synthetic_contributions(&conn, 3);
        conn.execute(
            "INSERT INTO mpc_ceremony
                (id, contribution_count, current_params_hash, is_ossified, updated_at)
             VALUES (1, 3, ?1, 0, 77)",
            rusqlite::params![&[3u8; 32][..]],
        )
        .unwrap();

        run_migrations(&conn).unwrap();

        assert_eq!(get_schema_version(&conn).unwrap(), SCHEMA_VERSION);
        let cols = get_column_names(&conn, "mpc_ceremony");
        assert!(cols.contains(&"ossified_file_hash".to_string()));
        // Existing data preserved; new column defaults to NULL.
        let (count, ofh): (i64, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT contribution_count, ossified_file_hash FROM mpc_ceremony WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(count, 3, "existing singleton preserved across v40");
        assert_eq!(
            ofh, None,
            "ossified_file_hash defaults to NULL (not ossified)"
        );
    }

    /// Helper: returns all table names from sqlite_master
    fn get_table_names(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    /// Helper: returns column names for a given table via PRAGMA table_info
    fn get_column_names(conn: &Connection, table: &str) -> Vec<String> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({})", table))
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    #[test]
    fn test_v1_core_tables_exist() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        let tables = get_table_names(&conn);
        for expected in &["shares", "rounds", "miners", "nodes"] {
            assert!(
                tables.contains(&expected.to_string()),
                "v1 core table '{}' missing from schema. Found tables: {:?}",
                expected,
                tables
            );
        }
    }

    #[test]
    fn test_v2_challenge_tables_exist() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        let tables = get_table_names(&conn);
        for expected in &[
            "archive_challenges",
            "policy_challenges",
            "stratum_challenges",
            "ghostpay_challenges",
        ] {
            assert!(
                tables.contains(&expected.to_string()),
                "v2 challenge table '{}' missing from schema. Found tables: {:?}",
                expected,
                tables
            );
        }
    }

    #[test]
    fn test_v10_foreign_key_cascades() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        // Check that tables recreated in v10 have ON DELETE CASCADE.
        // PRAGMA foreign_key_list returns rows with columns:
        //   id, seq, table, from, to, on_update, on_delete, match
        let tables_with_cascade = [
            "payouts",
            "verifications",
            "peer_reputation",
            "wraith_participants",
            "reconciliation_entries",
            "withdrawal_requests",
        ];

        for table in &tables_with_cascade {
            let mut stmt = conn
                .prepare(&format!("PRAGMA foreign_key_list({})", table))
                .unwrap();
            let fk_rows: Vec<(String, String)> = stmt
                .query_map([], |row| {
                    // column 2 = referenced table, column 6 = on_delete action
                    Ok((row.get::<_, String>(2)?, row.get::<_, String>(6)?))
                })
                .unwrap()
                .map(|r| r.unwrap())
                .collect();

            assert!(
                !fk_rows.is_empty(),
                "Table '{}' has no foreign keys after v10 migration",
                table
            );

            for (ref_table, on_delete) in &fk_rows {
                assert_eq!(
                    on_delete, "CASCADE",
                    "Table '{}' FK to '{}' has on_delete='{}', expected 'CASCADE'",
                    table, ref_table, on_delete
                );
            }
        }
    }

    #[test]
    fn test_v13_mpc_tables_exist() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        let tables = get_table_names(&conn);
        for expected in &["mpc_contributions", "mpc_verification_votes"] {
            assert!(
                tables.contains(&expected.to_string()),
                "v13 MPC table '{}' missing from schema. Found tables: {:?}",
                expected,
                tables
            );
        }
    }

    #[test]
    fn test_v21_l2_tables_exist() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        let tables = get_table_names(&conn);
        // v21 creates l2_notes and l2_nullifiers (the nullifier set)
        for expected in &["l2_notes", "l2_nullifiers"] {
            assert!(
                tables.contains(&expected.to_string()),
                "v21 L2 table '{}' missing from schema. Found tables: {:?}",
                expected,
                tables
            );
        }
    }

    #[test]
    fn test_v23_triggers_exist() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='trigger' ORDER BY name")
            .unwrap();
        let trigger_names: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        let expected_triggers = [
            "fk_l2_checkpoints_epoch",
            "fk_l2_valid_roots_epoch",
            "fk_l2_notes_epoch",
            "fk_l2_nullifiers_epoch",
        ];

        for expected in &expected_triggers {
            assert!(
                trigger_names.contains(&expected.to_string()),
                "v23 trigger '{}' missing. Found triggers: {:?}",
                expected,
                trigger_names
            );
        }
    }

    #[test]
    fn test_schema_version_is_latest() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        // Verify via get_schema_version helper
        let version = get_schema_version(&conn).unwrap();
        assert_eq!(
            version, SCHEMA_VERSION,
            "Schema version {} does not match SCHEMA_VERSION constant {}",
            version, SCHEMA_VERSION
        );

        // Also verify directly via PRAGMA user_version
        let pragma_version: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(pragma_version, SCHEMA_VERSION);
    }

    #[test]
    fn test_v38_wraith_bonds_table_and_partial_unique_index() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        // Table exists.
        let tables = get_table_names(&conn);
        assert!(
            tables.contains(&"wraith_bonds".to_string()),
            "v38 wraith_bonds table missing. Found: {:?}",
            tables
        );

        // The partial unique index exists.
        let index_names: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='wraith_bonds'",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(
            index_names.contains(&"idx_wraith_bonds_live".to_string()),
            "v38 partial unique index missing. Found: {:?}",
            index_names
        );

        // First escrowed bond for (alice, sess-1) inserts fine.
        conn.execute(
            "INSERT INTO wraith_bonds
                (bond_id, ghost_id, session_id, amount_sats, status, resolution, created_at, resolved_at)
             VALUES ('b1', 'alice', 'sess-1', 500, 'escrowed', NULL, 100, NULL)",
            [],
        )
        .unwrap();

        // A SECOND escrowed bond for the same (ghost_id, session_id) is
        // rejected by the partial unique index.
        let dup = conn.execute(
            "INSERT INTO wraith_bonds
                (bond_id, ghost_id, session_id, amount_sats, status, resolution, created_at, resolved_at)
             VALUES ('b2', 'alice', 'sess-1', 500, 'escrowed', NULL, 101, NULL)",
            [],
        );
        assert!(
            dup.is_err(),
            "second escrowed bond for the same (ghost_id, session_id) must be rejected"
        );

        // Resolve the first bond (refund) — frees the partial-unique slot.
        conn.execute(
            "UPDATE wraith_bonds SET status='refunded', resolved_at=200 WHERE bond_id='b1'",
            [],
        )
        .unwrap();

        // Now a fresh escrowed bond for the same pair is allowed.
        conn.execute(
            "INSERT INTO wraith_bonds
                (bond_id, ghost_id, session_id, amount_sats, status, resolution, created_at, resolved_at)
             VALUES ('b3', 'alice', 'sess-1', 500, 'escrowed', NULL, 201, NULL)",
            [],
        )
        .expect("a new escrowed bond must be allowed once the prior one is refunded");

        // A slashed prior bond likewise frees the slot for one more escrow.
        conn.execute(
            "UPDATE wraith_bonds SET status='slashed', resolution='x', resolved_at=300 WHERE bond_id='b3'",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO wraith_bonds
                (bond_id, ghost_id, session_id, amount_sats, status, resolution, created_at, resolved_at)
             VALUES ('b4', 'alice', 'sess-1', 500, 'escrowed', NULL, 301, NULL)",
            [],
        )
        .expect("a new escrowed bond must be allowed once the prior one is slashed");
    }

    #[test]
    fn test_v24_burned_elder_positions() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        let tables = get_table_names(&conn);
        assert!(
            tables.contains(&"burned_elder_numbers".to_string()),
            "v24 burned_elder_numbers table missing. Found: {:?}",
            tables
        );

        // elder_bonds and elder_slashing should be gone
        assert!(
            !tables.contains(&"elder_bonds".to_string()),
            "elder_bonds table should have been dropped by v24"
        );
        assert!(
            !tables.contains(&"elder_slashing".to_string()),
            "elder_slashing table should have been dropped by v24"
        );

        // Verify burned_elder_numbers is functional
        conn.execute(
            "INSERT INTO burned_elder_numbers (elder_position, revoked_node_id, reason, revoked_at)
             VALUES (3, 'abc123', 'ExtendedOffline(10d)', 1709312400)",
            [],
        )
        .unwrap();

        let count: u32 = conn
            .query_row("SELECT COUNT(*) FROM burned_elder_numbers", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);

        // Position is PK — duplicate should fail
        let result = conn.execute(
            "INSERT INTO burned_elder_numbers (elder_position, revoked_node_id, reason, revoked_at)
             VALUES (3, 'def456', 'duplicate', 1709312500)",
            [],
        );
        assert!(result.is_err(), "Duplicate elder_position should fail");
    }

    /// Audit M-10. v10 rebuilds eight tables with create/copy/drop/rename, and the runner skips
    /// `run_migration_tx` for it — the comment there claims v10 "manages its own transaction
    /// internally", which it did not. The batch ran in autocommit, so a crash between
    /// `DROP TABLE payouts` and `ALTER TABLE payouts_new RENAME TO payouts` left the database with
    /// no `payouts` table and a stranded `payouts_new`. The re-run then dies on
    /// `INSERT INTO payouts_new SELECT * FROM payouts` — no such table — for ever.
    ///
    /// Drives it by giving v10 a database where a LATER table it rebuilds is missing, so the batch
    /// fails partway, then asserts the EARLIER table it had already rebuilt is untouched.
    #[test]
    fn migrate_v10_is_atomic_when_it_fails_partway() {
        let conn = Connection::open_in_memory().expect("conn");
        // Only the first table v10 rebuilds. Every later one is absent, so the batch must fail
        // after it has already dropped/renamed this one in the non-atomic version.
        conn.execute_batch(
            "CREATE TABLE payouts (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 round_id INTEGER NOT NULL,
                 recipient_id TEXT NOT NULL,
                 recipient_type TEXT NOT NULL,
                 address TEXT NOT NULL,
                 amount_sats INTEGER NOT NULL,
                 txid TEXT,
                 paid_at INTEGER,
                 created_at INTEGER NOT NULL
             );
             INSERT INTO payouts (round_id, recipient_id, recipient_type, address, amount_sats, created_at)
             VALUES (1, 'miner', 'miner', 'bc1qtest', 5000, 1);",
        )
        .expect("seed");

        let before: i64 = conn
            .query_row("SELECT COUNT(*) FROM payouts", [], |r| r.get(0))
            .expect("payouts readable before");
        assert_eq!(before, 1);

        // Expected to fail: the later tables do not exist.
        let result = migrate_v10(&conn);
        assert!(
            result.is_err(),
            "the batch must fail for this test to mean anything"
        );

        // The database must be exactly as it was — not half-migrated. The tell is a stranded
        // `*_new` table: without a transaction the batch gets partway through, leaving scratch
        // tables behind and the schema in a shape the re-run cannot recover from.
        let stranded = get_table_names(&conn)
            .into_iter()
            .filter(|t| t.ends_with("_new"))
            .collect::<Vec<_>>();
        assert!(
            stranded.is_empty(),
            "a failed v10 must roll back completely, leaving no scratch tables; found {stranded:?}"
        );
        let after: Result<i64, _> =
            conn.query_row("SELECT COUNT(*) FROM payouts", [], |r| r.get(0));
        assert_eq!(
            after.ok(),
            Some(1),
            "payouts must survive a failed migration"
        );
    }

    /// v50 exists to make payable state O(addresses), not O(shares) — so it must NOT provide a
    /// place to archive every share.
    ///
    /// `docs/archive/SHARE_BATCH_CHAIN.md` names the defect being replaced: today the payable state is
    /// 1.5M unpaid share rows rescanned to produce ~68 numbers. If a future change adds a
    /// share-per-row table here, that problem is rebuilt one layer down and the reason for the
    /// whole programme is quietly lost. Shares live inside a batch, inside a bounded window.
    #[test]
    fn v50_stores_balances_and_a_bounded_chain_but_not_a_share_archive() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        let tables = get_table_names(&conn);
        for t in ["sbc_balances", "sbc_batches", "sbc_quarantine"] {
            assert!(tables.contains(&t.to_string()), "{t} missing from schema");
        }

        // The chain is keyed by seq — one row per adopted batch, prunable to a window — rather
        // than by share. A share-keyed table here would be the regression this test guards.
        let batch_cols = get_column_names(&conn, "sbc_batches");
        assert!(
            batch_cols.contains(&"seq".to_string()),
            "sbc_batches must be keyed by seq, found: {batch_cols:?}"
        );
        assert!(
            !batch_cols
                .iter()
                .any(|c| c == "share_hash" || c == "miner_id"),
            "sbc_batches must not hold per-share columns — payable state is O(addresses); \
             found: {batch_cols:?}"
        );

        // Balances hold i64 micro-work, matching `fold_shares`'s BTreeMap<String, i64> exactly.
        // A different stored type means a conversion at every read, and the value the state root
        // is computed over is the one that must round-trip.
        let mut stmt = conn.prepare("PRAGMA table_info(sbc_balances)").unwrap();
        let ty = stmt
            .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
            .unwrap()
            .filter_map(|c| c.ok())
            .find(|(n, _)| n == "micro_work")
            .map(|(_, t)| t)
            .expect("micro_work column");
        assert_eq!(ty, "INTEGER", "micro_work must match the i64 fold type");

        // A balance must survive a round trip, including a negative one — settlement reversal on
        // a reorg subtracts, and a column that cannot hold the result would corrupt the root.
        conn.execute(
            "INSERT INTO sbc_balances (address_hash, address_enc, micro_work, updated_seq) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![vec![1u8; 32], "enc", -42i64, 7i64],
        )
        .expect("insert");
        let back: i64 = conn
            .query_row(
                "SELECT micro_work FROM sbc_balances WHERE address_hash = ?1",
                rusqlite::params![vec![1u8; 32]],
                |r| r.get(0),
            )
            .expect("read back");
        assert_eq!(back, -42);
    }

    #[test]
    fn test_kv_store_table_exists() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        let tables = get_table_names(&conn);
        assert!(
            tables.contains(&"kv_store".to_string()),
            "kv_store table missing from schema. Found tables: {:?}",
            tables
        );

        // Verify the expected columns exist
        let columns = get_column_names(&conn, "kv_store");
        assert!(
            columns.contains(&"key".to_string()),
            "kv_store missing 'key' column. Found columns: {:?}",
            columns
        );
        assert!(
            columns.contains(&"value".to_string()),
            "kv_store missing 'value' column. Found columns: {:?}",
            columns
        );
    }

    /// v53 must apply cleanly on a v52 database, be idempotent against tables that already
    /// exist (the vm6/vm8 drifted-node case: a branch build ran, the binary rolled back, and
    /// the tables outlived it), and be strictly additive — every `sbc_*` table survives.
    #[test]
    fn v53_applies_on_v52_and_is_idempotent() {
        let conn = Connection::open_in_memory().expect("conn");
        run_migrations(&conn).expect("migrate");
        assert_eq!(get_schema_version(&conn).unwrap(), SCHEMA_VERSION);

        let expected: &[(&str, &[&str])] = &[
            (
                "shard_counters",
                &[
                    "node_id",
                    "address_hash",
                    "address_enc",
                    "total_micro",
                    "updated_epoch",
                ],
            ),
            (
                "shard_settled",
                &[
                    "address_hash",
                    "address_enc",
                    "settled_micro",
                    "last_height",
                ],
            ),
            (
                "shard_epochs",
                &[
                    "epoch",
                    "node_id",
                    "share_root",
                    "share_count",
                    "summary_enc",
                    "published",
                ],
            ),
        ];
        let check_shape = |conn: &Connection, when: &str| {
            let tables = get_table_names(conn);
            for (table, cols) in expected {
                assert!(
                    tables.contains(&table.to_string()),
                    "{table} missing {when}. Found tables: {tables:?}"
                );
                let have = get_column_names(conn, table);
                for col in *cols {
                    assert!(
                        have.contains(&col.to_string()),
                        "{table} missing `{col}` {when}. Found columns: {have:?}"
                    );
                }
            }
        };
        check_shape(&conn, "after a clean migration");

        // Additive: the sbc_* tables this release explicitly does NOT touch are all present.
        let tables = get_table_names(&conn);
        for sbc in [
            "sbc_balances",
            "sbc_batches",
            "sbc_certs",
            "sbc_quarantine",
            "sbc_watermarks",
        ] {
            assert!(
                tables.contains(&sbc.to_string()),
                "v53 must leave `{sbc}` alone. Found tables: {tables:?}"
            );
        }

        // Drifted-node case: the DB claims v52 but the shard tables already exist. Re-running
        // must not error and must land back on the current version.
        conn.execute("PRAGMA user_version = 52", [])
            .expect("rewind");
        run_migrations(&conn).expect("v53 must tolerate existing tables");
        assert_eq!(get_schema_version(&conn).unwrap(), SCHEMA_VERSION);

        // Clean v52 case: no shard tables at all, exactly what the fleet's databases hold today.
        conn.execute_batch(
            "DROP TABLE shard_counters; DROP TABLE shard_settled; DROP TABLE shard_epochs;",
        )
        .expect("drop");
        conn.execute("PRAGMA user_version = 52", [])
            .expect("rewind");
        run_migrations(&conn).expect("v53 must apply on a v52 database");
        assert_eq!(get_schema_version(&conn).unwrap(), SCHEMA_VERSION);
        check_shape(&conn, "after migrating a v52 database");
    }
}
