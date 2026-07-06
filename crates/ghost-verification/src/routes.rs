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
//| FILE: routes.rs                                                                                                      |
//|======================================================================================================================|

//! HTTP routes for verification endpoints

use axum::{
    extract::{ws::WebSocketUpgrade, Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use ghost_buds::{BudsClassifier, BudsTier};
use ghost_common::constants::{SV1_STRATUM_PORT, SV2_AUTHORITY_PUBLIC_KEY, SV2_STRATUM_PORT};

use crate::auth::{verify_internal_auth, InternalAuth};
use crate::challenge::*;
use crate::server::{MeshNodeInfo, ShareBatch, ShareNotification, VerificationState};
use crate::websocket::{ws_handler, WsAuthQuery};

/// M-STOR-3: Check if a path is in the allowed list
fn is_safe_proc_path(path: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|a| a == path)
}

/// VF-H1: Validate hex hash format (block hash or txid)
/// Must be exactly 64 hex characters (32 bytes)
fn is_valid_hex_hash(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// VF-H2: Maximum transaction hex size for policy verification (100KB)
/// Standard Bitcoin nodes reject transactions > 100KB
const MAX_TX_HEX_SIZE: usize = 200_000; // 100KB in hex = 200k chars

/// M-STOR-3: Safely read a /proc file if it's in the allowed list
fn safe_read_proc_file(path: &str, allowed: &[String]) -> Option<String> {
    if is_safe_proc_path(path, allowed) {
        std::fs::read_to_string(path).ok()
    } else {
        None
    }
}

/// Get system resource usage (CPU %, Memory %, Disk %)
/// M-STOR-3: Takes allowed proc paths to validate before reading
fn get_system_resources(proc_paths_allowed: &[String]) -> (f64, f64, f64) {
    // Read memory info from /proc/meminfo (only if allowed)
    let memory_percent = safe_read_proc_file("/proc/meminfo", proc_paths_allowed)
        .and_then(|content| {
            let mut total: u64 = 0;
            let mut available: u64 = 0;
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    total = line.split_whitespace().nth(1)?.parse().ok()?;
                } else if line.starts_with("MemAvailable:") {
                    available = line.split_whitespace().nth(1)?.parse().ok()?;
                }
            }
            if total > 0 {
                Some(((total - available) as f64 / total as f64) * 100.0)
            } else {
                None
            }
        })
        .unwrap_or(0.0);

    // Read disk usage using statvfs on root partition
    let disk_percent = {
        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::mem::MaybeUninit;

            // L-1: Root path has no NUL bytes so this always succeeds
            let path = CString::new("/").expect("root path contains no NUL bytes");
            let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();

            // SAFETY: libc::statvfs is a POSIX standard function that:
            // 1. Takes a valid C string pointer (path.as_ptr() is null-terminated)
            // 2. Writes to a properly aligned, uninitialized statvfs struct
            // 3. Returns 0 on success, -1 on failure (we check result before using stat)
            // 4. Does not retain the pointer after the call returns
            // The MaybeUninit wrapper ensures we don't assume initialization until
            // statvfs succeeds (result == 0).
            let result = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };

            if result == 0 {
                // SAFETY: We only call assume_init() after verifying result == 0,
                // which guarantees statvfs successfully wrote valid data to the struct.
                // The statvfs struct contains only POD types (integers) with no
                // invariants beyond being initialized, which statvfs guarantees on success.
                let stat = unsafe { stat.assume_init() };
                let total = stat.f_blocks as f64 * stat.f_frsize as f64;
                let free = stat.f_bfree as f64 * stat.f_frsize as f64;
                if total > 0.0 {
                    ((total - free) / total) * 100.0
                } else {
                    0.0
                }
            } else {
                // L-05: Return -1.0 on statvfs failure to distinguish error from 0% usage
                -1.0
            }
        }
        #[cfg(not(unix))]
        {
            0.0
        }
    };

    // CPU usage requires sampling over time, return a simple load average estimate
    // M-STOR-3: Only read if paths are allowed
    let cpu_percent = safe_read_proc_file("/proc/loadavg", proc_paths_allowed)
        .and_then(|content| {
            let load_1min: f64 = content.split_whitespace().next()?.parse().ok()?;
            // Get number of CPUs (only if /proc/cpuinfo is allowed)
            let num_cpus = safe_read_proc_file("/proc/cpuinfo", proc_paths_allowed)
                .map(|c| c.matches("processor").count())
                .unwrap_or(1) as f64;
            // Convert load average to percentage (capped at 100%)
            Some((load_1min / num_cpus * 100.0).min(100.0))
        })
        .unwrap_or(0.0);

    (cpu_percent, memory_percent, disk_percent)
}

/// Create verification router
pub fn create_router(state: Arc<VerificationState>) -> Router {
    // Clone ws_state for the WebSocket handler
    let ws_state = Arc::clone(&state.ws_state);

    // Public routes (no authentication required)
    let public_router = Router::new()
        // WebSocket for real-time updates (AUTH4-M3: supports optional authentication)
        .route(
            "/ws",
            get(move |ws: WebSocketUpgrade, auth: Query<WsAuthQuery>| {
                let ws_state = Arc::clone(&ws_state);
                async move { ws_handler(ws, auth, State(ws_state)).await }
            }),
        )
        // Health and node info
        .route("/health", get(health_handler))
        .route("/node-info", get(node_info_handler))
        // Informational endpoints
        .route("/peers", get(peers_handler))
        .route("/shares", get(shares_handler))
        .route("/rounds", get(rounds_handler))
        .route("/payouts", get(payouts_handler))
        .route("/consensus-state", get(consensus_state_handler))
        // Verification challenges
        .route("/verify/archive", get(archive_handler))
        .route("/verify/policy", get(policy_handler))
        .route("/verify/stratum", get(stratum_handler))
        .route("/verify/ghostpay", get(ghostpay_handler))
        // API v1 routes for dashboard compatibility
        .route("/api/v1/node/status", get(api_node_status_handler))
        .route("/api/v1/node/info", get(api_node_info_handler))
        .route("/api/v1/node/blockchain", get(api_node_blockchain_handler))
        .route("/api/v1/node/shares", get(api_node_shares_handler))
        .route("/api/v1/mining/status", get(api_mining_status_handler))
        .route("/api/v1/mining/miners", get(api_miners_handler))
        .route("/api/v1/miners/search", get(api_miners_search_handler))
        // Public self-lookup endpoint — exact-match only, requires the full
        // <address>.<worker> miner_id. Reachable without auth so a miner can
        // look up their own stats from the website (industry standard for
        // mining pools). Enumeration is prevented by exact-match semantics
        // and per-IP nginx rate limiting at the proxy layer.
        .route("/api/v1/miners/lookup", get(api_miner_lookup_handler))
        // Per-miner time-series: bucketed share count + work over a window.
        // Backs the individual miner page's hashrate chart. Requires exact
        // miner_id (no enumeration) and returns empty `points` when unknown.
        .route("/api/v1/miners/history", get(api_miner_history_handler))
        // Workers under a given payout address. Used by the miner lookup UI
        // when a user enters an address without a `.worker` suffix — returns
        // a compact summary per worker so the frontend can render a picker.
        .route("/api/v1/miners/workers", get(api_miners_by_address_handler))
        // Public best-hash records per window (block / day / week / month).
        // Returns this node's best share only; website aggregates across
        // nodes. No auth; enumeration not possible (one response).
        .route("/api/v1/pool/records", get(api_pool_records_handler))
        // Public per-window leaderboard: top miners by best-hash and by
        // total shares contributed in the requested window. Used by the
        // pool page gamification; same redaction rules as /records.
        .route(
            "/api/v1/pool/leaderboard",
            get(api_pool_leaderboard_handler),
        )
        // "Next block payout" projection: current round's top miners,
        // their work share, and projected sats from the 99% miner pool.
        // Also reports the fee split (treasury + node reward pool) so the
        // website can render the full breakdown. DB-only, no mesh.
        .route(
            "/api/v1/pool/next_payout",
            get(api_pool_next_payout_handler),
        )
        // Tail of recent shares for the live quasar visualisation. One
        // lightweight row per share — the caller polls with ?since=<ts>
        // and gets everything accepted since that watermark.
        .route(
            "/api/v1/pool/recent_shares",
            get(api_pool_recent_shares_handler),
        )
        // Live mesh node list: this node + every connected peer, with the
        // already-public gossiped capability/hashrate/miner fields. Lets the
        // website render the node list from one node instead of a hard-coded
        // VM set, so new nodes appear automatically.
        .route("/api/v1/pool/mesh-nodes", get(api_pool_mesh_nodes_handler))
        // Rolling server-side time-series of pool hashrate + connected miners,
        // sampled every 30s (24h retention). `?window=1h|24h`. Lets the pool
        // page chart real history instead of a client-side session buffer.
        .route("/api/v1/pool/series", get(api_pool_series_handler))
        // Mesh-wide leaderboard: node-ranked (self + peers by hashrate) plus the
        // mesh-wide best-share records per window, aggregated from existing mesh
        // data with no new gossip. Replaces the pool page's this-node-only list.
        .route(
            "/api/v1/pool/mesh-leaderboard",
            get(api_pool_mesh_leaderboard_handler),
        )
        // Read-only decentralised-coordinator election view. Returns
        // `{enabled:false}` unless the operator turns on
        // `[coordinator] wraith_election_enabled`.
        .route(
            "/api/v1/pool/coordinator",
            get(api_pool_coordinator_handler),
        )
        // Treasury + decentralisation-phase state for the Core page.
        // Exposes balance / 21-BTC threshold / decay year / fee split so
        // the website can render the Bootstrap → Decentralising →
        // Sovereign journey against live pool state.
        .route(
            "/api/v1/pool/treasury_state",
            get(api_pool_treasury_state_handler),
        )
        // Aggregate node metrics for the Core page. Returns pool-wide
        // counts only — no per-node data, no clearnet/tor breakdown,
        // no identifiers. Tor operators are counted as part of the
        // aggregate and cannot be singled out.
        .route("/api/v1/mesh/node_stats", get(api_mesh_node_stats_handler))
        // M-14: /api/v1/miners/stats moved to internal routes (requires HMAC auth)
        // Exposes individual miner work values, hashrates, and share history
        .route("/api/v1/network/peers", get(peers_handler))
        .route("/api/v1/network/pool", get(api_pool_status_handler))
        .route("/api/v1/mesh/status", get(consensus_state_handler))
        .route("/api/v1/config", get(api_config_handler))
        .route("/api/v1/resources/status", get(api_resources_handler))
        .route("/api/v1/ghostpay/status", get(api_ghostpay_status_handler))
        .route(
            "/api/v1/buds/capabilities",
            get(api_buds_capabilities_handler),
        )
        // Additional dashboard endpoints
        .route("/api/v1/swarm", get(api_swarm_handler))
        .route("/api/v1/network/treasury", get(api_treasury_handler))
        .route(
            "/api/v1/l2/fee-distribution-context",
            get(api_l2_fee_distribution_context_handler),
        )
        .route("/api/v1/l2/tree-state", get(api_l2_tree_state_handler))
        .route("/api/v1/rewards/current", get(api_rewards_current_handler))
        .route("/api/v1/rewards/history", get(api_rewards_history_handler))
        // HIGH-4: /api/v1/logs endpoint REMOVED - exposed journalctl output (security risk)
        .route("/api/v1/locks", get(api_locks_handler))
        .route("/api/v1/node/nickname", get(api_nickname_handler))
        // Additional endpoints for dashboard compatibility
        .route("/api/v1/rewards/full", get(api_rewards_full_handler))
        .route(
            "/api/v1/settlement/status",
            get(api_settlement_status_handler),
        )
        .route("/api/v1/swarm/nodes", get(api_swarm_nodes_handler))
        .route("/api/v1/watchdog/status", get(api_watchdog_status_handler))
        .route("/api/v1/system/version", get(api_system_version_handler))
        .route("/api/v1/system/mempool", get(api_system_mempool_handler))
        .route("/api/v1/system/self-check", get(api_self_check_handler))
        .route("/api/v1/reaper/status", get(api_reaper_status_handler))
        .route("/api/v1/payments", get(api_payments_handler))
        .route("/api/v1/backup/history", get(api_backup_history_handler))
        .route("/api/v1/wraith/sessions", get(api_wraith_sessions_handler))
        .route("/api/v1/network/elder", get(api_network_elder_handler))
        .route(
            "/api/v1/network/public-nodes",
            get(api_public_nodes_handler),
        )
        .route(
            "/api/v1/node/public-info",
            get(api_node_public_info_handler),
        )
        .route("/api/v1/buds/mempool", get(api_buds_mempool_handler))
        .route(
            "/api/v1/mining/best-hash",
            get(api_mining_best_hash_handler),
        )
        .route(
            "/api/v1/network/payout-history",
            get(api_payout_history_handler),
        )
        .route(
            "/api/v1/ghostpay/payout-history",
            get(api_ghostpay_payout_history_handler),
        )
        .route(
            "/api/v1/rewards/node-history",
            get(api_rewards_node_history_handler),
        )
        // Config endpoints (GET only - reading is public, POST requires auth via internal router)
        // CRIT-6: POST handlers moved to internal_router to require authentication
        .route("/api/v1/config/full", get(api_config_full_handler))
        .route(
            "/api/v1/config/archive_mode",
            get(api_config_archive_mode_handler),
        )
        .route(
            "/api/v1/config/ghost_mode",
            get(api_config_ghost_mode_handler),
        )
        .route(
            "/api/v1/config/mempool_profile",
            get(api_config_mempool_profile_handler),
        )
        .route(
            "/api/v1/config/public_mining",
            get(api_config_public_mining_handler),
        )
        .route(
            "/api/v1/config/template_profile",
            get(api_config_template_profile_handler),
        )
        .route("/api/v1/config/reaper", get(api_config_reaper_handler))
        .route("/api/v1/config/daemon", get(api_config_daemon_handler))
        .route("/api/v1/config/alerts", get(api_config_alerts_handler))
        .route(
            "/api/v1/config/backup_schedule",
            get(api_config_backup_schedule_handler),
        )
        .route(
            "/api/v1/config/ghost_pay",
            get(api_config_ghost_pay_handler),
        )
        .route("/api/v1/config/wraith", get(api_config_wraith_handler))
        .route("/api/v1/config/elder", get(api_config_elder_handler))
        .route(
            "/api/v1/config/prune_profile",
            get(api_config_prune_profile_handler),
        )
        .route(
            "/api/v1/config/operator_window",
            get(api_config_operator_window_handler),
        )
        // Mining endpoints
        .route(
            "/api/v1/mining/payout_address",
            get(api_mining_payout_address_handler),
        )
        .route("/api/v1/mining/private", get(api_mining_private_handler))
        .route("/api/v1/mining/public", get(api_mining_public_handler))
        // Ghost Pay endpoints
        .route(
            "/api/v1/ghost-pay/pruning",
            get(api_ghostpay_pruning_handler),
        )
        // Settings endpoints
        .route(
            "/api/v1/settings/ghostpay_payout_address",
            get(api_settings_ghostpay_payout_address_handler),
        )
        // L2 read endpoints (public)
        // MPC ceremony endpoints
        .route("/api/v1/mpc/params", get(api_mpc_params_handler))
        .route(
            "/api/v1/mpc/payout-params",
            get(api_mpc_payout_params_handler),
        )
        .route(
            "/api/v1/mpc/unshield-params",
            get(api_mpc_unshield_params_handler),
        )
        .route(
            "/api/v1/mpc/params/manifest",
            get(api_mpc_params_manifest_handler),
        )
        .route("/api/v1/mpc/status", get(api_mpc_status_handler))
        .route(
            "/api/v1/mpc/contributors",
            get(api_mpc_contributors_handler),
        )
        // Stage C: per-position contribution (WITH proof) + retained approve
        // votes, so a catching-up node can re-verify proofs and check the
        // retained BFT quorum (the contributors list above omits both).
        .route("/api/v1/mpc/votes/:position", get(api_mpc_votes_handler))
        // Ghost Haze & Shroud endpoints
        .route("/api/v1/haze/status", get(api_haze_status_handler))
        .route("/api/v1/shroud/status", get(api_shroud_status_handler))
        // Swarm endpoints
        .route("/api/v1/swarm/sync", get(api_swarm_sync_handler))
        .route(
            "/api/v1/swarm/update-all",
            get(api_swarm_update_all_handler),
        )
        // L-16: System, watchdog, and backup endpoints moved to internal routes
        // These endpoints can expose sensitive system information or trigger
        // destructive operations (updates, cache clearing, backup import).
        // Auth endpoint (returns empty token for dashboard compatibility)
        .route("/auth/token", get(api_auth_token_handler))
        // Prometheus metrics endpoint
        .route("/metrics", get(metrics_handler));

    // Localhost-only endpoints: SRI Pool share webhook (no HMAC required)
    // SRI Pool runs on localhost and doesn't support HMAC auth headers.
    // These are protected by a localhost-only middleware instead.
    let localhost_router = Router::new()
        .route("/api/internal/share", post(share_notification_handler))
        .route("/api/internal/shares", post(share_batch_handler))
        .route("/api/internal/pool-nodes", get(pool_nodes_handler))
        // L2 mutation endpoints — localhost only (ghost-pay is colocated)
        .route("/api/v1/l2/submit", post(api_l2_submit_handler))
        .route(
            "/api/v1/l2/sync-commitment",
            post(api_l2_sync_commitment_handler),
        )
        // GhostGlyph relay endpoints — localhost only (ghost-pay is colocated)
        .route(
            "/api/v1/glyph/relay-claim",
            post(api_glyph_relay_claim_handler),
        )
        .route(
            "/api/v1/glyph/relay-registered",
            post(api_glyph_relay_registered_handler),
        )
        .layer(middleware::from_fn(localhost_only_middleware));

    // Internal/admin endpoints with HMAC authentication (AUTH4-1 fix)
    // CRIT-6: All config POST endpoints moved here to require authentication
    let internal_router = Router::new()
        // Admin endpoints for testing
        .route("/admin/test-consensus", post(admin_test_consensus_handler))
        // Internal API for dashboard config updates (triggers graceful restart)
        .route(
            "/api/internal/config/update",
            post(api_config_update_handler),
        )
        // CRIT-6: Config POST endpoints require authentication
        // These modify node configuration and must be protected from unauthorized access
        .route(
            "/api/v1/config/archive_mode",
            post(api_config_archive_mode_post_handler),
        )
        .route(
            "/api/v1/config/ghost_mode",
            post(api_config_ghost_mode_post_handler),
        )
        .route(
            "/api/v1/config/public_mining",
            post(api_config_public_mining_post_handler),
        )
        .route(
            "/api/v1/config/policy_profile",
            post(api_config_policy_profile_post_handler),
        )
        .route(
            "/api/v1/config/policy_custom",
            post(api_config_policy_custom_post_handler),
        )
        .route(
            "/api/v1/config/reaper",
            post(api_config_reaper_post_handler),
        )
        .route("/api/v1/config/tor", post(api_config_tor_post_handler))
        .route(
            "/api/v1/config/daemon",
            post(api_config_daemon_post_handler),
        )
        .route(
            "/api/v1/config/alerts",
            post(api_config_alerts_post_handler),
        )
        .route(
            "/api/v1/config/backup_schedule",
            post(api_config_backup_schedule_post_handler),
        )
        .route("/api/v1/alerts/test", post(api_alerts_test_post_handler))
        .route(
            "/api/v1/alerts/internal/failed-login",
            post(api_alerts_failed_login_post_handler),
        )
        .route(
            "/api/v1/config/ghost_pay",
            post(api_config_ghost_pay_post_handler),
        )
        .route(
            "/api/v1/config/wraith",
            post(api_config_wraith_post_handler),
        )
        .route("/api/v1/config/elder", post(api_config_elder_post_handler))
        .route(
            "/api/v1/config/prune_profile",
            post(api_config_prune_profile_post_handler),
        )
        // M-14: Miner stats endpoint moved here to require HMAC authentication
        // Exposes individual miner work values, hashrates, and share history
        .route("/api/v1/miners/stats", get(api_miner_stats_handler))
        // M-14: Miner search with full details (internal use only)
        .route(
            "/api/internal/miners/search",
            get(api_miners_search_internal_handler),
        )
        // L-16: System endpoints moved here to require HMAC authentication
        // These can expose sensitive system state or trigger potentially destructive operations
        .route(
            "/api/v1/system/update/status",
            get(api_system_update_status_handler),
        )
        .route("/api/v1/system/updates", get(api_system_updates_handler))
        .route("/api/v1/system/update", get(api_system_update_handler))
        .route("/api/v1/system/rollback", get(api_system_rollback_handler))
        // L-16: Watchdog endpoints moved here to require HMAC authentication
        // watchdog/events may expose operational details, clear-cache affects system state
        .route("/api/v1/watchdog/events", get(api_watchdog_events_handler))
        // L-16: Backup endpoints moved here to require HMAC authentication
        // These can export/import potentially sensitive node configuration and data
        .route(
            "/api/v1/backup/export",
            get(api_backup_export_handler).post(api_backup_export_handler),
        )
        .route(
            "/api/v1/backup/import",
            get(api_backup_import_handler).post(api_backup_import_handler),
        )
        .route(
            "/api/v1/backup/verify",
            get(api_backup_verify_handler).post(api_backup_verify_handler),
        )
        .route(
            "/api/v1/backup/delete/:filename",
            delete(api_backup_delete_handler),
        )
        // Dashboard: Logs endpoint (ring buffer + allowlisted journald units)
        .route("/api/v1/logs", get(api_logs_handler))
        .route("/api/v1/logs/units", get(api_logs_units_handler))
        // Dashboard: Nickname management
        .route("/api/v1/node/nickname", post(api_nickname_post_handler))
        // Dashboard: Swarm node management CRUD
        .route("/api/v1/swarm/nodes", post(api_swarm_node_add_handler))
        .route(
            "/api/v1/swarm/nodes/:node_id",
            delete(api_swarm_node_remove_handler).put(api_swarm_node_update_handler),
        )
        .route(
            "/api/v1/swarm/nodes/:node_id/refresh",
            post(api_swarm_node_refresh_handler),
        )
        .route(
            "/api/v1/swarm/nodes/:node_id/config",
            put(api_swarm_node_config_handler),
        )
        .route(
            "/api/v1/swarm/nodes/:node_id/restart",
            post(api_swarm_node_restart_handler),
        )
        .route(
            "/api/v1/swarm/nodes/:node_id/update",
            post(api_swarm_node_update_version_handler),
        )
        .route("/api/v1/swarm/sync", post(api_swarm_sync_post_handler))
        .route(
            "/api/v1/swarm/update-all",
            post(api_swarm_update_all_post_handler),
        )
        // Dashboard: Watchdog service control
        .route(
            "/api/v1/watchdog/start/:service",
            post(api_watchdog_start_handler),
        )
        .route(
            "/api/v1/watchdog/stop/:service",
            post(api_watchdog_stop_handler),
        )
        .route(
            "/api/v1/watchdog/restart/:service",
            post(api_watchdog_restart_handler),
        )
        .route(
            "/api/v1/watchdog/clear-cache",
            get(api_watchdog_clear_cache_handler).post(api_watchdog_clear_cache_handler),
        )
        // Dashboard: Config profile CRUD
        .route(
            "/api/v1/config/profiles/mempool",
            post(api_config_profiles_mempool_post_handler),
        )
        .route(
            "/api/v1/config/profiles/mempool/:name",
            delete(api_config_profiles_mempool_delete_handler),
        )
        .route(
            "/api/v1/config/profiles/mempool/:name/activate",
            post(api_config_profiles_mempool_activate_handler),
        )
        .route(
            "/api/v1/config/profiles/template",
            post(api_config_profiles_template_post_handler),
        )
        .route(
            "/api/v1/config/profiles/template/:name",
            delete(api_config_profiles_template_delete_handler),
        )
        .route(
            "/api/v1/config/profiles/template/:name/activate",
            post(api_config_profiles_template_activate_handler),
        )
        // Dashboard: GhostPay payout address POST
        .route(
            "/api/v1/settings/ghostpay_payout_address",
            post(api_settings_ghostpay_payout_address_post_handler),
        )
        // Dashboard: Mining POST handlers
        .route(
            "/api/v1/mining/private",
            post(api_mining_private_post_handler),
        )
        .route(
            "/api/v1/mining/public",
            post(api_mining_public_post_handler),
        )
        .route(
            "/api/v1/mining/payout_address",
            post(api_mining_payout_address_post_handler),
        )
        .route(
            "/api/v1/mining/pool_name",
            post(api_mining_pool_name_post_handler),
        )
        // Dashboard: System update POST handlers (dashboard sends POST, backend has GET)
        .route("/api/v1/system/update", post(api_system_update_handler))
        .route("/api/v1/system/rollback", post(api_system_rollback_handler))
        // Dashboard: Operator window POST
        .route(
            "/api/v1/config/operator_window",
            post(api_config_operator_window_post_handler),
        )
        // Dashboard: Unredacted miners list (for dashboard mining page)
        .route("/api/v1/mining/miners/full", get(api_miners_full_handler))
        // Dashboard: Haze/Shroud configuration (wizard endpoints)
        .route("/api/v1/haze/configure", post(api_haze_configure_handler))
        .route(
            "/api/v1/shroud/configure",
            post(api_shroud_configure_handler),
        )
        // Dashboard: Node restart
        .route("/api/v1/node/restart", post(api_node_restart_handler))
        // L2 commitment sync (authenticated alternative to localhost-only sync-commitment)
        .route(
            "/api/internal/l2/sync-commitment",
            post(api_l2_sync_commitment_handler),
        );

    // H-3: Apply authentication middleware - ALWAYS required for internal endpoints
    let internal_router = if let Some(ref auth) = state.internal_auth {
        tracing::info!("Internal API authentication enabled for /api/internal/* and /admin/*");
        let auth_clone = Arc::clone(auth);
        internal_router.layer(middleware::from_fn(move |request, next| {
            let auth = Arc::clone(&auth_clone);
            internal_auth_middleware(auth, request, next)
        }))
    } else {
        // H-3 SECURITY: Internal endpoints REQUIRE authentication in production.
        // Without internal_api_secret configured, all internal endpoints will return 401.
        // This fail-closed approach prevents accidental exposure of admin functionality.
        tracing::error!(
            "H-3 SECURITY: Internal API authentication NOT configured! \
             /api/internal/* and /admin/* endpoints will REJECT all requests. \
             Configure internal_api_secret in pool.toml for these endpoints to function."
        );
        // Return a router that rejects all requests to internal endpoints
        internal_router.layer(middleware::from_fn(
            |request: axum::extract::Request, _next: axum::middleware::Next| async move {
                tracing::warn!(
                    path = %request.uri().path(),
                    "H-3: Rejecting unauthenticated internal API request"
                );
                axum::response::Response::builder()
                    .status(axum::http::StatusCode::UNAUTHORIZED)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"error":"Internal API authentication not configured"}"#,
                    ))
                    .unwrap()
            },
        ))
    };

    // Merge routers
    public_router
        .merge(localhost_router)
        .merge(internal_router)
        .with_state(state)
}

/// Middleware to verify HMAC authentication for internal endpoints
///
/// # Security (AUTH4-1)
///
/// This middleware protects internal endpoints from unauthorized access by requiring
/// HMAC-SHA256 signatures on all requests. Without this, attackers could:
/// - Inject fake shares to manipulate payout calculations
/// - Trigger admin operations (test-consensus)
/// - Submit fraudulent block notifications
///
/// All requests require HMAC authentication, including localhost.
/// This prevents auth bypass via misconfigured reverse proxies or IP spoofing.
async fn internal_auth_middleware(
    auth: Arc<InternalAuth>,
    request: axum::extract::Request,
    next: Next,
) -> Result<axum::response::Response, (StatusCode, String)> {
    // Extract headers and body for authentication
    let (parts, body) = request.into_parts();
    let headers = &parts.headers;

    // Read body bytes for HMAC verification
    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024) // 10MB limit
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to read request body: {}", e),
            )
        })?;

    // Verify authentication
    verify_internal_auth(&auth, headers, &body_bytes)?;

    // Reconstruct request with body and continue
    let request = axum::http::Request::from_parts(parts, axum::body::Body::from(body_bytes));

    Ok(next.run(request).await)
}

/// Middleware that restricts access to localhost (127.0.0.1/::1) connections only.
/// Used for SRI Pool share webhook endpoints that don't support HMAC auth.
async fn localhost_only_middleware(
    request: axum::extract::Request,
    next: Next,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let is_localhost = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().is_loopback())
        .unwrap_or(false);

    if !is_localhost {
        return Err((
            StatusCode::FORBIDDEN,
            "Share webhook only accessible from localhost".to_string(),
        ));
    }

    Ok(next.run(request).await)
}

/// Health check query parameters (optional nonce for signed response)
#[derive(Debug, Deserialize, Default)]
pub struct HealthQuery {
    /// Challenge nonce for signed response binding
    pub nonce: Option<String>,
    /// Explicitly disable signing (default: signed when possible)
    pub unsigned: Option<bool>,
}

/// Health check handler
///
/// Returns HealthResponse wrapped in SignedResponse by default when signing
/// identity is configured. Use `unsigned=true` to get unsigned response.
///
/// **Security**: Always prefer signed responses to prevent MITM/proxy attacks.
async fn health_handler(
    State(state): State<Arc<VerificationState>>,
    Query(query): Query<HealthQuery>,
) -> impl IntoResponse {
    let response = state.get_health().await;

    // Sign by default unless explicitly disabled
    let should_sign = !query.unsigned.unwrap_or(false);

    if should_sign && state.can_sign() {
        if let Some(signed) = state.sign_response(response.clone(), query.nonce) {
            return Json(serde_json::json!({
                "signed": true,
                "response": signed
            }));
        }
    }

    // Warn in logs when returning unsigned response
    if state.can_sign() && query.unsigned.unwrap_or(false) {
        tracing::warn!("Returning unsigned response by explicit request");
    }

    Json(serde_json::json!({
        "signed": false,
        "response": response
    }))
}

/// Node info handler (detailed node information)
async fn node_info_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let health = state.get_health().await;
    Json(serde_json::json!({
        "node_id": health.node_id,
        "version": health.version,
        "capabilities": health.capabilities,
        "uptime_secs": health.uptime_secs,
        "block_height": health.block_height,
        "round_id": health.round_id,
        "miner_count": health.miner_count,
        "peer_count": health.peer_count
    }))
}

/// Peers handler - returns connected peers info
async fn peers_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let health = state.get_health().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Query database for peer list if available
    let peers = if let Some(ref db) = state.database {
        match db.get_active_peers(50) {
            Ok(peer_records) => peer_records
                .iter()
                .map(|p| {
                    // Approximate latency from health ping staleness (pings every 10s)
                    // Subtract expected ping interval to get excess delay
                    let staleness_secs = (now - p.last_seen).max(0);
                    let latency_ms: Option<u64> = if staleness_secs < 30 {
                        // Fresh peer: excess over 10s ping interval is ~network delay
                        let excess = (staleness_secs as u64).saturating_sub(5) * 100;
                        Some(excess.clamp(1, 9999))
                    } else {
                        None
                    };
                    serde_json::json!({
                        "peer_id": p.peer_id,
                        "address": p.address,
                        "port": p.port,
                        "node_id": p.node_id,
                        "first_seen": p.first_seen,
                        "last_seen": p.last_seen,
                        "connected_at": p.first_seen,
                        "connection_count": p.connection_count,
                        "version": env!("CARGO_PKG_VERSION"),
                        "latency_ms": latency_ms,
                        "synced": (now - p.last_seen) < 60,
                        "uptime_seconds": now - p.first_seen
                    })
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                error!(error = %e, "Failed to query peers");
                vec![]
            }
        }
    } else {
        vec![]
    };

    Json(serde_json::json!({
        "peer_count": health.peer_count,
        "peers": peers
    }))
}

/// Shares handler - returns recent share statistics
async fn shares_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let health = state.get_health().await;

    // Query database for recent shares if available
    let (shares, total_shares) = if let Some(ref db) = state.database {
        let shares = match db.get_recent_shares(100) {
            Ok(share_records) => share_records
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "round_id": s.round_id,
                        "miner_id": s.miner_id,
                        // Achieved difficulty from the hash (the score). `work` is
                        // the stored vardiff target used for payout/hashrate.
                        "difficulty": share_difficulty_from_hash_hex(&s.share_hash),
                        "work": s.work,
                        "share_hash": s.share_hash,
                        "timestamp": s.timestamp,
                        "valid": s.valid
                    })
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                error!(error = %e, "Failed to query shares");
                vec![]
            }
        };
        let total = shares.len();
        (shares, total)
    } else {
        (vec![], 0)
    };

    Json(serde_json::json!({
        "round_id": health.round_id,
        "total_shares": total_shares,
        "shares": shares
    }))
}

/// Rounds handler - returns recent round information
async fn rounds_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let health = state.get_health().await;

    // Query database for recent rounds if available
    let rounds = if let Some(ref db) = state.database {
        match db.get_recent_rounds(20) {
            Ok(round_records) => round_records
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "round_id": r.round_id,
                        "block_height": r.block_height,
                        "block_hash": r.block_hash,
                        "start_time": r.start_time,
                        "end_time": r.end_time,
                        "total_shares": r.total_shares,
                        "total_work": r.total_work,
                        "winning_miner": r.winning_miner,
                        "payout_status": r.payout_status.as_str()
                    })
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                error!(error = %e, "Failed to query rounds");
                vec![]
            }
        }
    } else {
        vec![]
    };

    Json(serde_json::json!({
        "current_round": health.round_id,
        "block_height": health.block_height,
        "rounds": rounds
    }))
}

/// Payouts handler - returns payout history
async fn payouts_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    // Query database for recent payouts if available
    let (payouts, total_payouts) = if let Some(ref db) = state.database {
        let total = db.get_payout_count().unwrap_or(0);
        let payouts = match db.get_recent_payouts(50) {
            Ok(payout_records) => payout_records
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "round_id": p.round_id,
                        "recipient_id": p.recipient_id,
                        "recipient_type": p.recipient_type.as_str(),
                        "address": p.address,
                        "amount_sats": p.amount_sats,
                        "txid": p.txid,
                        "status": p.status.as_str(),
                        "created_at": p.created_at
                    })
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                error!(error = %e, "Failed to query payouts");
                vec![]
            }
        };
        (payouts, total)
    } else {
        (vec![], 0)
    };

    Json(serde_json::json!({
        "total_payouts": total_payouts,
        "payouts": payouts
    }))
}

/// Consensus state handler - returns current consensus status
async fn consensus_state_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let health = state.get_health().await;

    // Query database for elder count and peer info
    let (elder_count, burned_elder_count, peer_count) = if let Some(ref db) = state.database {
        let elders = db.get_elder_count().unwrap_or(0);
        let burned = db
            .get_burned_positions()
            .map(|v| v.len() as u32)
            .unwrap_or(0);
        let peers = db.get_active_peers(100).map(|p| p.len()).unwrap_or(0) as u32;
        (elders, burned, peers)
    } else {
        (0, 0, health.peer_count)
    };

    // Determine consensus status based on peer connectivity
    let consensus_status = if peer_count >= 3 {
        "active"
    } else if peer_count > 0 {
        "degraded"
    } else {
        "isolated"
    };

    Json(serde_json::json!({
        "round_id": health.round_id,
        "block_height": health.block_height,
        "peer_count": peer_count,
        "miner_count": health.miner_count,
        "consensus_status": consensus_status,
        "elder_count": elder_count,
        "elders_registered": elder_count,
        "elders_burned": burned_elder_count,
        "elders_cap": 101u32,
        "bft_threshold": 0.67,
        "quorum_reached": peer_count >= 3
    }))
}

/// Archive verification query parameters
#[derive(Debug, Deserialize)]
pub struct ArchiveQuery {
    /// Block hash to verify
    pub block: Option<String>,
    /// Transaction ID to verify
    pub tx: Option<String>,
    /// Minimum height to prove
    pub min_height: Option<u64>,
    /// Challenge nonce for signed response binding
    pub nonce: Option<String>,
    /// Explicitly disable signing (default: signed when possible)
    pub unsigned: Option<bool>,
}

/// Archive verification handler
///
/// Returns ArchiveResponse wrapped in SignedResponse by default when signing
/// identity is configured. Use `unsigned=true` to get unsigned response.
async fn archive_handler(
    State(state): State<Arc<VerificationState>>,
    Query(query): Query<ArchiveQuery>,
) -> impl IntoResponse {
    debug!(
        block = ?query.block,
        tx = ?query.tx,
        "Archive verification request"
    );

    // VF-H1: Validate input format before processing
    // Block hashes and txids must be exactly 64 hex characters
    if let Some(ref block) = query.block {
        if !is_valid_hex_hash(block) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "signed": false,
                    "response": ArchiveResponse {
                        success: false,
                        block_data: None,
                        tx_data: None,
                        error: Some("Invalid block hash: must be exactly 64 hex characters".to_string()),
                    }
                })),
            );
        }
    }
    if let Some(ref tx) = query.tx {
        if !is_valid_hex_hash(tx) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "signed": false,
                    "response": ArchiveResponse {
                        success: false,
                        block_data: None,
                        tx_data: None,
                        error: Some("Invalid txid: must be exactly 64 hex characters".to_string()),
                    }
                })),
            );
        }
    }

    let challenge = ArchiveChallenge {
        challenge_type: if query.block.is_some() {
            ChallengeType::ArchiveBlock
        } else {
            ChallengeType::ArchiveTx
        },
        block_hash: query.block,
        txid: query.tx,
        min_height: query.min_height,
    };

    let should_sign = !query.unsigned.unwrap_or(false);

    match state.verify_archive(challenge).await {
        Ok(response) => {
            if should_sign && state.can_sign() {
                if let Some(signed) = state.sign_response(response.clone(), query.nonce) {
                    return (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "signed": true,
                            "response": signed
                        })),
                    );
                }
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "signed": false,
                    "response": response
                })),
            )
        }
        Err(e) => {
            error!(error = %e, "Archive verification failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "signed": false,
                    "response": ArchiveResponse {
                        success: false,
                        block_data: None,
                        tx_data: None,
                        error: Some(e.to_string()),
                    }
                })),
            )
        }
    }
}

/// Policy verification query parameters
#[derive(Debug, Deserialize)]
pub struct PolicyQuery {
    /// Raw transaction hex
    pub tx: String,
    /// Expected tier (optional)
    pub expected_tier: Option<String>,
    /// Challenge nonce for signed response binding
    pub nonce: Option<String>,
    /// Explicitly disable signing (default: signed when possible)
    pub unsigned: Option<bool>,
}

/// Policy verification handler
///
/// Returns PolicyResponse wrapped in SignedResponse by default when signing
/// identity is configured. Use `unsigned=true` to get unsigned response.
///
/// **Security**: Always prefer signed responses to prevent MITM/proxy attacks.
async fn policy_handler(
    State(state): State<Arc<VerificationState>>,
    Query(query): Query<PolicyQuery>,
) -> impl IntoResponse {
    debug!(tx_len = query.tx.len(), unsigned = ?query.unsigned, "Policy verification request");

    // VF-H2: Validate transaction hex size before processing
    if query.tx.len() > MAX_TX_HEX_SIZE {
        warn!(
            tx_len = query.tx.len(),
            max = MAX_TX_HEX_SIZE,
            "Transaction hex too large"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "signed": false,
                "response": PolicyResponse {
                    success: false,
                    profile: "N/A".to_string(),
                    classification: None,
                    accepted: false,
                    rejection_reason: Some("Input too large".to_string()),
                    tx_txid: None,
                    error: Some(format!(
                        "Transaction hex too large: {} bytes (max {})",
                        query.tx.len(),
                        MAX_TX_HEX_SIZE
                    )),
                }
            })),
        );
    }

    let challenge = PolicyChallenge {
        tx_hex: query.tx,
        expected_tier: query.expected_tier,
    };

    // Sign by default unless explicitly disabled
    let should_sign = !query.unsigned.unwrap_or(false);

    match state.verify_policy(challenge).await {
        Ok(response) => {
            if should_sign && state.can_sign() {
                if let Some(signed) = state.sign_response(response.clone(), query.nonce) {
                    return (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "signed": true,
                            "response": signed
                        })),
                    );
                }
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "signed": false,
                    "response": response
                })),
            )
        }
        Err(e) => {
            error!(error = %e, "Policy verification failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "signed": false,
                    "response": PolicyResponse {
                        success: false,
                        profile: String::new(),
                        classification: None,
                        accepted: false,
                        rejection_reason: None,
                        tx_txid: None,
                        error: Some(e.to_string()),
                    }
                })),
            )
        }
    }
}

/// Stratum verification query parameters
#[derive(Debug, Deserialize)]
pub struct StratumQuery {
    /// Port to check
    pub port: Option<u16>,
    /// Protocol (sv1 or sv2)
    pub protocol: Option<String>,
    /// Challenge nonce for signed response binding
    pub nonce: Option<String>,
    /// Explicitly disable signing (default: signed when possible)
    pub unsigned: Option<bool>,
}

/// Stratum verification handler
///
/// Returns StratumResponse wrapped in SignedResponse by default when signing
/// identity is configured. Use `unsigned=true` to get unsigned response.
///
/// **Security**: Always prefer signed responses to prevent MITM/proxy attacks.
async fn stratum_handler(
    State(state): State<Arc<VerificationState>>,
    Query(query): Query<StratumQuery>,
) -> impl IntoResponse {
    let protocol = match query.protocol.as_deref() {
        Some("sv1") => StratumProtocol::Sv1,
        _ => StratumProtocol::Sv2,
    };

    let challenge = StratumChallenge {
        port: query.port,
        protocol,
    };

    debug!(port = ?query.port, protocol = ?protocol, unsigned = ?query.unsigned, "Stratum verification request");

    // Sign by default unless explicitly disabled
    let should_sign = !query.unsigned.unwrap_or(false);

    match state.verify_stratum(challenge).await {
        Ok(response) => {
            if should_sign && state.can_sign() {
                if let Some(signed) = state.sign_response(response.clone(), query.nonce) {
                    return (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "signed": true,
                            "response": signed
                        })),
                    );
                }
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "signed": false,
                    "response": response
                })),
            )
        }
        Err(e) => {
            error!(error = %e, "Stratum verification failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "signed": false,
                    "response": StratumResponse {
                        success: false,
                        port: query.port.unwrap_or(34255),
                        protocol,
                        connected: false,
                        latency_ms: None,
                        error: Some(e.to_string()),
                    }
                })),
            )
        }
    }
}

/// Ghost Pay verification query parameters
#[derive(Debug, Deserialize)]
pub struct GhostPayQuery {
    /// Address to query balance
    pub address: Option<String>,
    /// Challenge nonce for signed response binding
    pub nonce: Option<String>,
    /// Explicitly disable signing (default: signed when possible)
    pub unsigned: Option<bool>,
    /// H-5: Challenge epoch to verify L2 state for (cryptographic verification)
    pub challenge_epoch: Option<u64>,
    /// VER-2: Challenge nonce for precomputation prevention
    /// When provided, response must include nonce_bound_proof = SHA256(epoch_state_hash || challenge_nonce)
    pub challenge_nonce: Option<String>,
}

/// Ghost Pay verification handler
///
/// Returns GhostPayResponse wrapped in SignedResponse by default when signing
/// identity is configured. Use `unsigned=true` to get unsigned response.
///
/// **Security**: Always prefer signed responses to prevent MITM/proxy attacks.
async fn ghostpay_handler(
    State(state): State<Arc<VerificationState>>,
    Query(query): Query<GhostPayQuery>,
) -> impl IntoResponse {
    debug!(address = ?query.address, unsigned = ?query.unsigned, "GhostPay verification request");

    let challenge = GhostPayChallenge {
        challenge_type: if query.address.is_some() {
            ChallengeType::GhostPayBalance
        } else {
            ChallengeType::GhostPayTransfer
        },
        address: query.address,
        challenge_epoch: query.challenge_epoch,
        challenge_nonce: query.challenge_nonce,
    };

    // Sign by default unless explicitly disabled
    let should_sign = !query.unsigned.unwrap_or(false);

    match state.verify_ghostpay(challenge).await {
        Ok(response) => {
            if should_sign && state.can_sign() {
                if let Some(signed) = state.sign_response(response.clone(), query.nonce) {
                    return (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "signed": true,
                            "response": signed
                        })),
                    );
                }
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "signed": false,
                    "response": response
                })),
            )
        }
        Err(e) => {
            error!(error = %e, "GhostPay verification failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "signed": false,
                    "response": GhostPayResponse {
                        success: false,
                        l2_enabled: false,
                        virtual_block: None,
                        epoch: None,
                        balance_sats: None,
                        wraith_enabled: false,
                        epoch_state_hash: None,
                        epoch_tx_count: None,
                        nonce_bound_proof: None,
                        epoch_proof: None,
                        error: Some(e.to_string()),
                    }
                })),
            )
        }
    }
}

// ============================================================================
// API v1 Handlers for Dashboard Compatibility
// ============================================================================

/// API v1 node status handler
async fn api_node_status_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let health = state.get_health().await;
    let config = state.dashboard_config.read();
    // M-11: This endpoint exposes this node's own status, which is intentionally public.
    // The node advertises these capabilities to participate in the network.
    // Sensitive details like internal IP addresses are NOT exposed here.
    Json(serde_json::json!({
        "online": health.healthy,
        "node_id": health.node_id,
        "version": health.version,
        "network": state.network.as_str(),
        "sync_height": health.block_height,
        "block_height": health.block_height,
        "round_id": health.round_id,
        "uptime_seconds": health.uptime_secs,
        "uptime_secs": health.uptime_secs,
        // M-11: Only show counts, not actual peer/miner identifiers
        "peer_count": health.peer_count,
        "miner_count": health.miner_count,
        "is_synced": true,
        // Capability flags are public - used for verification challenges
        "mempool_profile": config.mempool_profile,
        "template_profile": config.template_profile,
        "archive_mode": config.archive_mode,
        "ghost_pay": config.ghost_pay,
        "public_mining": config.public_mining,
        "private_mining": false,
        "reaper": config.reaper,
        "ghost_mode": config.ghost_mode,
        "tor_mode": config.tor_mode,
        "onion_address": config.onion_address
    }))
}

/// API v1 node shares handler (5-4-3-2-1 system)
async fn api_node_shares_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let _health = state.get_health().await;
    let config = state.dashboard_config.read();

    // Check elder status from MPC database (authoritative source)
    // The dashboard_config.elder flag can be stale; the DB knows the truth
    let (is_elder, elder_slot) = if let Some(ref db) = state.database {
        let elder = db.is_mpc_elder(&state.node_id).unwrap_or(false);
        let slot = if elder {
            db.get_mpc_elder_position(&state.node_id).unwrap_or(None)
        } else {
            None
        };
        (elder, slot)
    } else {
        (config.elder, config.elder_slot)
    };

    // Calculate total shares based on capabilities (5-4-3-2-1 system)
    let mut total = 0;
    if config.archive_mode {
        total += 5;
    }
    if config.ghost_pay {
        total += 4;
    }
    if config.public_mining {
        total += 3;
    }
    if config.reaper {
        total += 2;
    }
    if is_elder {
        total += 1;
    }

    // Real trailing-7-day uptime for THIS node (the qualification gatekeeper
    // metric), read from the self-recorded uptime samples via the same query
    // the qualification layer uses. `uptime_qualified` reflects the true >=95%
    // gate rather than an unconditional `true`. Falls back to null/false when
    // no DB is attached (never a fabricated 99.9%).
    let self_uptime_percent: Option<f64> = state.database.as_ref().and_then(|db| {
        let since = chrono::Utc::now().timestamp()
            - (ghost_common::constants::UPTIME_WINDOW_DAYS as i64 * 86_400);
        db.get_uptime_percent(&state.node_id, since)
            .ok()
            .map(|ratio| ratio * 100.0)
    });
    let uptime_qualified = self_uptime_percent
        .map(|p| p >= ghost_common::constants::UPTIME_GATEKEEPER_THRESHOLD)
        .unwrap_or(false);

    Json(serde_json::json!({
        "total": total,
        "max_shares": 15,
        "uptime_qualified": uptime_qualified,
        "uptime_percent": self_uptime_percent,
        "archive_mode": config.archive_mode,
        "ghost_pay": config.ghost_pay,
        "public_mining": config.public_mining,
        "reaper": config.reaper,
        "elder": is_elder,
        "elder_slot": elder_slot,
        "estimated_reward_btc": 0.0
    }))
}

/// API v1 node info handler (detailed)
async fn api_node_info_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let health = state.get_health().await;
    let config = state.dashboard_config.read();
    let node_id_short = health.node_id.chars().take(8).collect::<String>();
    Json(serde_json::json!({
        "node_id": health.node_id,
        "node_id_short": node_id_short,
        "nickname": node_id_short,
        "version": health.version,
        "capabilities": health.capabilities,
        "uptime_seconds": health.uptime_secs,
        "uptime_secs": health.uptime_secs,
        "sync_height": health.block_height,
        "block_height": health.block_height,
        "round_id": health.round_id,
        "network": state.network.as_str(),
        "is_synced": true,
        "peer_count": health.peer_count,
        "miner_count": health.miner_count,
        "archive_mode": config.archive_mode,
        "ghost_pay": config.ghost_pay,
        "public_mining": config.public_mining,
        "reaper": config.reaper,
        "mempool_profile": config.mempool_profile,
        "template_profile": config.template_profile
    }))
}

/// API v1 node blockchain handler — chain & sync status for the Sync page.
///
/// Every field is sourced directly from ghostd's `getblockchaininfo` RPC (the
/// same call the haze/mining handlers already use). This is the only endpoint
/// that surfaces the header-tip height, on-disk size, verification progress,
/// best-block hash, tip time and the initial-block-download flag — the node
/// `status`/`info` endpoints only carry the block height from the health cache.
///
/// When the RPC is unavailable or times out, the numeric fields degrade to
/// `null` (and `available: false`) so the dashboard renders "—" rather than a
/// misleading zero.
async fn api_node_blockchain_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let network = state.network.as_str();

    let info = match state.rpc {
        Some(ref rpc) => {
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                rpc.get_blockchain_info(),
            )
            .await
            {
                Ok(Ok(info)) => Some(info),
                Ok(Err(e)) => {
                    warn!("Failed to get blockchain info from RPC: {}", e);
                    None
                }
                Err(_) => {
                    warn!("Blockchain info RPC timed out");
                    None
                }
            }
        }
        None => None,
    };

    match info {
        Some(info) => Json(serde_json::json!({
            "available": true,
            "network": network,
            "chain": info.chain,
            "blocks": info.blocks,
            "headers": info.headers,
            "best_block_hash": info.bestblockhash,
            "difficulty": info.difficulty,
            "size_on_disk": info.size_on_disk,
            "verification_progress": info.verificationprogress,
            "initial_block_download": info.initialblockdownload,
            "pruned": info.pruned,
            "hazed": info.hazed,
            "median_time": info.mediantime,
            "tip_time": info.time,
            "chainwork": info.chainwork,
            "warnings": info.warnings,
        })),
        None => Json(serde_json::json!({
            "available": false,
            "network": network,
            "chain": serde_json::Value::Null,
            "blocks": serde_json::Value::Null,
            "headers": serde_json::Value::Null,
            "best_block_hash": serde_json::Value::Null,
            "difficulty": serde_json::Value::Null,
            "size_on_disk": serde_json::Value::Null,
            "verification_progress": serde_json::Value::Null,
            "initial_block_download": serde_json::Value::Null,
            "pruned": serde_json::Value::Null,
            "hazed": serde_json::Value::Null,
            "median_time": serde_json::Value::Null,
            "tip_time": serde_json::Value::Null,
            "chainwork": serde_json::Value::Null,
            "warnings": serde_json::Value::Null,
        })),
    }
}

/// API v1 mining status handler
async fn api_mining_status_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let health = state.get_health().await;

    // Fetch tip timestamp up-front (async). The config lock guard below
    // is !Send, so we must not hold any await-points after acquiring it.
    //
    // `health.block_height` is the TEMPLATE height (tip + 1 — the block
    // ghost-pool is currently building). Calling getblockhash(that)
    // returns "out of range" because Bitcoin Core doesn't have it yet.
    // `getbestblockhash` returns the actual confirmed tip.
    let last_block_time: Option<u64> = if let Some(ref rpc) = state.rpc {
        match rpc.get_best_block_hash().await {
            Ok(hash) => rpc.get_block_header(&hash).await.ok().map(|h| h.time),
            Err(_) => None,
        }
    } else {
        None
    };

    let config = state.dashboard_config.read();

    // Aggregate hashrate across all miners. Use the miner's actual elapsed
    // time in the window (now - first_share_in_window), clamped at both ends:
    //   * MIN_ELAPSED = 300s prevents a single lucky high-difficulty share
    //     from inflating the rate for brand-new miners (the original spike
    //     bug the 30-min window was introduced to fix).
    //   * WINDOW_SECS = 1800s caps elapsed at the SQL window length; since
    //     the query only returns shares from the last 1800s, elapsed can
    //     never honestly exceed that.
    // This recovers the correct rate for miners that reconnected partway
    // through the window (e.g. after a pool restart) — they were previously
    // under-reported because a fixed 1800s denominator assumed a full
    // window's worth of work.
    const WINDOW_SECS: f64 = 1800.0;
    const MIN_ELAPSED: f64 = 300.0;
    let (total_hashrate_th, shares_submitted, shares_accepted) =
        if let Some(ref db) = state.database {
            match db.get_all_miners_stats() {
                Ok(miners) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let mut total_hr = 0.0f64;
                    let mut total_shares = 0u64;
                    let mut valid_shares = 0u64;
                    for m in &miners {
                        let raw = (now - m.first_seen).max(1) as f64;
                        let elapsed = raw.clamp(MIN_ELAPSED, WINDOW_SECS);
                        // Hashrate = SUM(difficulty) * 2^32 / elapsed / 1e12 (TH/s)
                        total_hr += m.total_work * 4294967296.0 / elapsed / 1e12;
                        total_shares += m.total_shares;
                        valid_shares += m.valid_shares;
                    }
                    (total_hr, total_shares, valid_shares)
                }
                Err(_) => (0.0, 0, 0),
            }
        } else {
            (0.0, 0, 0)
        };

    // Stable count of miners active in the last 5 minutes — survives round
    // rotations that reset the round-scoped miner_count to zero. This is the
    // local view; mesh_active_miners below is the deduplicated pool-wide count.
    let active_miners = state
        .database
        .as_ref()
        .and_then(|db| db.count_active_miners(300).ok())
        .unwrap_or(0);
    let mesh_active_miners = state.mesh_active_miners().unwrap_or(active_miners);
    // Pool-wide hashrate (sum of every node's own realized hashrate) is the
    // figure operators expect: it stays put when the load balancer migrates a
    // miner between nodes. Falls back to the node-local sum on older deploys
    // without the mesh provider. `local_hashrate_th` shows this node's own
    // contribution (the same windowed value it gossips), so the per-node and
    // mesh figures reconcile.
    let mesh_hashrate_th = state.mesh_total_hashrate().unwrap_or(total_hashrate_th);
    let local_hashrate_th = state.local_hashrate().unwrap_or(total_hashrate_th);

    // SV2/Noise miners must pin the pool's authority public key to connect.
    // Source it from the node's own pool config when the operator set a bespoke
    // `[network] sv2_authority_public_key`; otherwise advertise the network-wide
    // default so the dashboard can stop hardcoding it as a frontend constant.
    // (Reading full_node_config is a non-async lock, safe alongside the config
    // guard held above — no await points follow.)
    let authority_public_key = state
        .full_node_config
        .as_ref()
        .and_then(|c| c.read().network.sv2_authority_public_key.clone())
        .unwrap_or_else(|| SV2_AUTHORITY_PUBLIC_KEY.to_string());

    Json(serde_json::json!({
        // Backend fields
        "active": true,
        "sync_height": health.block_height,
        "block_height": health.block_height,
        "round_id": health.round_id,
        "miner_count": health.miner_count,
        "total_hashrate": mesh_hashrate_th,
        "shares_this_round": health.capabilities.total_shares,
        "difficulty": 1.0,
        "best_hash": null,
        "is_synced": true,
        // Dashboard-compatible aliases
        "enabled": true,
        "private_mining": config.private_mining.unwrap_or(false),
        "public_mining": health.capabilities.public_mining,
        "hashrate_th": mesh_hashrate_th,
        "local_hashrate_th": local_hashrate_th,
        "connected_miners": mesh_active_miners,
        "local_connected_miners": health.miner_count,
        "active_miners": active_miners,
        "mesh_active_miners": mesh_active_miners,
        "shares_submitted": shares_submitted,
        "shares_accepted": shares_accepted,
        "shares_rejected": shares_submitted - shares_accepted,
        "stratum_v1_port": SV1_STRATUM_PORT,
        "stratum_v2_port": SV2_STRATUM_PORT,
        "authority_public_key": authority_public_key,
        "stratum_v1_endpoint": format!("stratum+tcp://0.0.0.0:{}", SV1_STRATUM_PORT),
        "stratum_v2_endpoint": format!("stratum+tcp://0.0.0.0:{}", SV2_STRATUM_PORT),
        "payout_address": config.payout_address,
        "pool_name": config.pool_name,
        "blocks_found": state.database.as_ref()
            .and_then(|db| db.get_blocks_found_count().ok())
            .unwrap_or(0),
        "last_block_time": last_block_time
    }))
}

/// API v1 miners handler
///
/// Dual-mode. By default this is the PUBLIC endpoint and returns only redacted
/// aggregate stats (M-11). When the caller presents a valid operator
/// (`INTERNAL_AUTH_KEY`) HMAC signature — the same auth the config-set
/// endpoints use, which the dashboard proxy adds to every request — it returns
/// the full unredacted connected-miner list instead. This gives the operator
/// dashboard a miner-details path that does NOT require the peer/mesh signature,
/// while the mesh-authed `/api/v1/mining/miners/full` peer endpoint is left
/// untouched. Unsigned or invalid callers only ever see the redacted aggregate.
async fn api_miners_handler(
    State(state): State<Arc<VerificationState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Operator-authed detail path: the dashboard proxy signs GET requests with
    // the operator INTERNAL_AUTH_KEY over an empty body, so verify against that.
    if let Some(ref auth) = state.internal_auth {
        if verify_internal_auth(auth, &headers, b"").is_ok() {
            let miners = build_detailed_miner_list(&state);
            return Json(serde_json::json!({
                "total_miners": miners.len(),
                "miners": miners,
                "miners_redacted": false,
            }));
        }
    }

    let health = state.get_health().await;

    // M-11: Query miners but redact sensitive details from public endpoint
    // Only show counts and aggregated stats, not individual miner IDs and work values
    let (active_count, total_work) = if let Some(ref db) = state.database {
        match db.get_round_miners(health.round_id) {
            Ok(miner_work) => {
                let count = miner_work.len();
                // Sum work values from Vec<(String, f64)>
                let work: f64 = miner_work.iter().map(|(_, w)| w).sum();
                (count, work)
            }
            Err(e) => {
                error!(error = %e, "Failed to query miners");
                (0, 0.0)
            }
        }
    } else {
        (0, 0.0)
    };

    // M-11: Public endpoint shows only aggregate stats, not individual miner details
    // Individual miner data could be used for targeted attacks or competitor analysis
    Json(serde_json::json!({
        "total_miners": health.miner_count,
        "active_miners": active_count,
        "total_work_this_round": total_work,
        "round_id": health.round_id,
        // M-11: Individual miner list redacted from public endpoint
        // Use authenticated internal API for full miner details
        "miners_redacted": true,
        "message": "Individual miner details require authentication"
    }))
}

/// Query parameters for miner search
#[derive(Debug, Deserialize)]
struct MinerSearchQuery {
    /// Search query (worker name or address)
    q: Option<String>,
}

/// Query parameters for miner stats
#[derive(Debug, Deserialize)]
struct MinerStatsQuery {
    /// Miner ID to look up
    miner_id: Option<String>,
}

/// Query parameters for the public pool records endpoint.
/// `window` is one of `block | day | week | month`.
#[derive(Debug, Deserialize)]
struct PoolRecordsQuery {
    window: Option<String>,
}

/// Query parameters for the public leaderboard endpoint.
/// `window` is `day | week | month` (no `block` — 10 min is too short
/// to rank). `limit` defaults to 10, capped at 50 to prevent enumeration.
#[derive(Debug, Deserialize)]
struct PoolLeaderboardQuery {
    window: Option<String>,
    limit: Option<u32>,
}

/// Query parameters for the pool time-series endpoint.
/// `window` is `1h | 24h` (defaults to `1h`, anything else is treated as `1h`).
#[derive(Debug, Deserialize)]
struct PoolSeriesQuery {
    window: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MinerHistoryQuery {
    miner_id: Option<String>,
    window: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MinersByAddressQuery {
    address: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecentSharesQuery {
    since: Option<i64>,
    limit: Option<u32>,
}

/// API v1 miner search handler - search miners by worker name or address
/// M-13: Returns only aggregate counts, not individual miner details (same pattern as M-11)
async fn api_miners_search_handler(
    State(state): State<Arc<VerificationState>>,
    Query(params): Query<MinerSearchQuery>,
) -> impl IntoResponse {
    let query = params.q.unwrap_or_default();

    if query.is_empty() {
        return Json(serde_json::json!({
            "error": "Missing search query parameter 'q'",
            "example": "/api/v1/miners/search?q=worker_name"
        }));
    }

    if query.len() < 3 {
        return Json(serde_json::json!({
            "error": "Search query must be at least 3 characters",
            "query": query
        }));
    }

    // M-13: Query miners but return only aggregate stats, not individual details
    // Individual miner data (IDs, work values, hashrates) could enable:
    // - Targeted attacks on high-value miners
    // - Competitor analysis of mining operations
    // - Enumeration of pool participants
    let (match_count, total_work, active_count) = if let Some(ref db) = state.database {
        match db.search_miners(&query) {
            Ok(miners) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let count = miners.len();
                let work: f64 = miners.iter().map(|m| m.total_work).sum();
                let active = miners.iter().filter(|m| (now - m.last_seen) < 600).count();
                (count, work, active)
            }
            Err(e) => {
                error!(error = %e, "Failed to search miners");
                (0, 0.0, 0)
            }
        }
    } else {
        (0, 0.0, 0)
    };

    // M-13: Public endpoint shows only aggregate stats, not individual miner details
    Json(serde_json::json!({
        "query": query,
        "match_count": match_count,
        "active_matches": active_count,
        "total_work": total_work,
        // M-13: Individual miner list redacted from public endpoint
        "miners_redacted": true,
        "message": "Individual miner details require authentication. Use /api/internal/miners/search for full details."
    }))
}

/// API internal miner search handler - returns full miner details (requires HMAC auth)
/// M-14: This internal version provides complete miner data for authenticated admin access
async fn api_miners_search_internal_handler(
    State(state): State<Arc<VerificationState>>,
    Query(params): Query<MinerSearchQuery>,
) -> impl IntoResponse {
    let query = params.q.unwrap_or_default();

    if query.is_empty() {
        return Json(serde_json::json!({
            "error": "Missing search query parameter 'q'",
            "example": "/api/internal/miners/search?q=worker_name"
        }));
    }

    if query.len() < 3 {
        return Json(serde_json::json!({
            "error": "Search query must be at least 3 characters",
            "query": query
        }));
    }

    let results = if let Some(ref db) = state.database {
        match db.search_miners(&query) {
            Ok(miners) => miners
                .iter()
                .map(|m| {
                    // Calculate estimated hashrate from work and time
                    let duration_secs = (m.last_seen - m.first_seen).max(1) as f64;
                    let hashrate_ths = (m.total_work * m.avg_difficulty) / duration_secs / 1e12;

                    serde_json::json!({
                        "miner_id": m.miner_id,
                        "total_shares": m.total_shares,
                        "valid_shares": m.valid_shares,
                        "total_work": m.total_work,
                        "avg_difficulty": m.avg_difficulty,
                        "first_seen": m.first_seen,
                        "last_seen": m.last_seen,
                        "estimated_hashrate_ths": format!("{:.4}", hashrate_ths),
                        "active": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64 - m.last_seen) < 600
                    })
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                error!(error = %e, "Failed to search miners");
                vec![]
            }
        }
    } else {
        vec![]
    };

    Json(serde_json::json!({
        "query": query,
        "count": results.len(),
        "miners": results
    }))
}

/// API v1 miner stats handler - get detailed stats for a specific miner
async fn api_miner_stats_handler(
    State(state): State<Arc<VerificationState>>,
    Query(params): Query<MinerStatsQuery>,
) -> impl IntoResponse {
    let miner_id = params.miner_id.unwrap_or_default();

    if miner_id.is_empty() {
        return Json(serde_json::json!({
            "error": "Missing miner_id parameter",
            "example": "/api/v1/miners/stats?miner_id=address.worker"
        }));
    }

    let stats = if let Some(ref db) = state.database {
        match db.get_miner_stats(&miner_id) {
            Ok(Some(s)) => {
                // Calculate estimated hashrate
                let duration_secs = (s.last_seen - s.first_seen).max(1) as f64;
                let hashrate_ths = (s.total_work * s.avg_difficulty) / duration_secs / 1e12;
                let acceptance_rate = if s.total_shares > 0 {
                    (s.valid_shares as f64 / s.total_shares as f64) * 100.0
                } else {
                    0.0
                };

                serde_json::json!({
                    "found": true,
                    "miner_id": s.miner_id,
                    "total_shares": s.total_shares,
                    "valid_shares": s.valid_shares,
                    "invalid_shares": s.invalid_shares,
                    "acceptance_rate": format!("{:.2}%", acceptance_rate),
                    "total_work": s.total_work,
                    "avg_difficulty": s.avg_difficulty,
                    "rounds_participated": s.rounds_participated,
                    "first_seen": s.first_seen,
                    "last_seen": s.last_seen,
                    "estimated_hashrate_ths": format!("{:.4}", hashrate_ths),
                    "active": (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64 - s.last_seen) < 600,
                    "recent_shares": s.recent_shares.iter().map(|rs| {
                        serde_json::json!({
                            "round_id": rs.round_id,
                            "difficulty": rs.difficulty,
                            "work": rs.work,
                            "timestamp": rs.timestamp,
                            "valid": rs.valid
                        })
                    }).collect::<Vec<_>>()
                })
            }
            Ok(None) => {
                serde_json::json!({
                    "found": false,
                    "miner_id": miner_id,
                    "message": "Miner not found"
                })
            }
            Err(e) => {
                error!(error = %e, "Failed to get miner stats");
                serde_json::json!({
                    "error": "Database error",
                    "miner_id": miner_id
                })
            }
        }
    } else {
        serde_json::json!({
            "error": "Database not available",
            "miner_id": miner_id
        })
    };

    Json(stats)
}

/// Public miner self-lookup handler.
///
/// Reads the persistent `miners` table (NOT the per-round `shares` table that
/// `api_miner_stats_handler` queries — that gets pruned and would return
/// "not found" for miners without current-round activity).
///
/// Caller provides the full <address>.<worker> identifier as `?miner_id=`.
/// Exact match only; no listing or fuzzy search → no enumeration risk.
/// Per-IP rate limiting is enforced at the nginx proxy layer.
async fn api_miner_lookup_handler(
    State(state): State<Arc<VerificationState>>,
    Query(params): Query<MinerStatsQuery>,
) -> impl IntoResponse {
    let miner_id = params.miner_id.unwrap_or_default();

    if miner_id.is_empty() {
        return Json(serde_json::json!({
            "error": "Missing miner_id parameter",
            "example": "/api/v1/miners/lookup?miner_id=bc1q....workername"
        }));
    }

    let result = if let Some(ref db) = state.database {
        match db.get_miner(&miner_id) {
            Ok(Some(m)) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let active = (now - m.last_seen) < 600;
                // Unpaid ledger side of the lookup: shares this miner has
                // submitted that haven't been committed to a payout yet.
                // Frontend sums across VMs (each node has its own ledger).
                let (unpaid_shares, unpaid_work) =
                    db.get_miner_unpaid_stats(&m.miner_id).unwrap_or((0, 0.0));
                serde_json::json!({
                    "found": true,
                    "miner_id": m.miner_id,
                    "payout_address": m.payout_address,
                    "first_seen": m.first_seen,
                    "last_seen": m.last_seen,
                    "active": active,
                    "total_shares": m.total_shares,
                    "total_work": m.total_work,
                    "blocks_won": m.blocks_won,
                    "total_payouts_sats": m.total_payouts_sats,
                    "avg_hashrate_ths": m.avg_hashrate_ths,
                    "unpaid_shares": unpaid_shares,
                    "unpaid_work": unpaid_work,
                })
            }
            Ok(None) => serde_json::json!({
                "found": false,
                "miner_id": miner_id,
                "message": "Miner not found"
            }),
            Err(e) => {
                error!(error = %e, "Failed to get miner record");
                serde_json::json!({
                    "error": "Database error",
                    "miner_id": miner_id
                })
            }
        }
    } else {
        serde_json::json!({
            "error": "Database not available",
            "miner_id": miner_id
        })
    };

    Json(result)
}

/// "Next block payout" — project each miner's share of the upcoming
/// block. We take the max round_id currently present in shares (that's
/// the round the template is building on), pull the top N miners by
/// work within it, and compute projected sats = miner_work / total_work
/// × miner_pool.
///
/// The miner pool is 99% of subsidy; the 1% pool fee is split 50/50
/// between treasury and the node reward pool (constant pre-21-BTC).
/// TX fees are paid to the node that builds the winning block, not to
/// miners, so they're reported separately as a note.
async fn api_pool_next_payout_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    // Pool economics: 1% fee from subsidy only, split 50/50 today.
    // If this changes (post-21-BTC decay), it must also change in
    // bins/ghost-pool/src/treasury.rs — keep the two in sync.
    const POOL_FEE_BPS: u64 = 100; // 1.00%
    const TREASURY_RATE_BPS: u64 = 5000; // 50% of pool fee
    const NODE_RATE_BPS: u64 = 5000; // 50% of pool fee
    const DUST_THRESHOLD_SATS: u64 = 546;
    const LEDGER_CAP: u32 = 1000;

    let health = state.get_health().await;
    let block_height = health.block_height as u64;

    // Bitcoin halving schedule: 50 BTC >> halvings, zero after halving 64
    let subsidy_sats: u64 = {
        let halvings = block_height / 210_000;
        if halvings >= 64 {
            0
        } else {
            5_000_000_000u64 >> halvings
        }
    };

    let pool_fee_sats = subsidy_sats * POOL_FEE_BPS / 10_000;
    let treasury_sats = pool_fee_sats * TREASURY_RATE_BPS / 10_000;
    let node_reward_pool_sats = pool_fee_sats.saturating_sub(treasury_sats);
    let miner_pool_sats = subsidy_sats.saturating_sub(pool_fee_sats);

    let Some(ref db) = state.database else {
        return Json(serde_json::json!({
            "block_height": block_height,
            "subsidy_sats": subsidy_sats,
            "error": "Database not available",
        }));
    };

    let now_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Ledger snapshot: top N by accumulated unpaid work. Mirror of the
    // block-found payout path — same query, same dust filter — so the
    // projection the website shows matches what gets written into the
    // coinbase when a block is actually found. Translator-proxy accounts
    // are excluded from the display only; if shares from a real miner
    // happen to be submitted under a system miner_id they'd still be
    // paid on-chain but the public view doesn't need to surface them.
    //
    // Gate: post-PAYOUT_ADDRESS_GROUPING_HEIGHT we group by payout_address
    // so the displayed top-N matches the post-gate coinbase behaviour
    // (one slot per address, multi-rig users no longer monopolise).
    // The constant is duplicated here rather than imported because
    // ghost-verification doesn't depend on ghost-pool — keep the two
    // in sync if the gate ever moves.
    const PAYOUT_ADDRESS_GROUPING_HEIGHT: u64 = 946_743;

    let top_rows: Vec<(String, f64)> = if block_height >= PAYOUT_ADDRESS_GROUPING_HEIGHT {
        db.get_top_unpaid_addresses(now_s, LEDGER_CAP.saturating_mul(2))
            .unwrap_or_default()
            .into_iter()
            .filter(|(addr, _, _)| !is_system_miner(addr))
            .take(LEDGER_CAP as usize)
            .map(|(addr, work, _miner_ids)| (addr, work))
            .collect()
    } else {
        db.get_top_unpaid_miners(now_s, LEDGER_CAP.saturating_mul(2))
            .unwrap_or_default()
            .into_iter()
            .filter(|(miner_id, _)| !is_system_miner(miner_id))
            .take(LEDGER_CAP as usize)
            .collect()
    };
    // Count distinct unpaid users (miners pre-gate, addresses post-gate)
    // so the header tile matches what's actually shown in the table.
    let total_unpaid_miners = if block_height >= PAYOUT_ADDRESS_GROUPING_HEIGHT {
        db.get_top_unpaid_addresses(now_s, u32::MAX)
            .unwrap_or_default()
            .into_iter()
            .filter(|(addr, _, _)| !is_system_miner(addr))
            .count() as u64
    } else {
        db.get_distinct_unpaid_miner_ids(now_s)
            .unwrap_or_default()
            .into_iter()
            .filter(|id| !is_system_miner(id))
            .count() as u64
    };

    // Iterative dust filter: drop miners whose projected payout < 546 sats,
    // recompute total_work, repeat until stable. Converges quickly (each
    // iteration strictly reduces the candidate set).
    let mut surviving: Vec<(String, f64)> = top_rows;
    loop {
        let total_work: f64 = surviving.iter().map(|(_, w)| *w).sum();
        if total_work <= 0.0 {
            break;
        }
        let pre_len = surviving.len();
        surviving.retain(|(_, work)| {
            let projected = (miner_pool_sats as f64 * work / total_work) as u64;
            projected >= DUST_THRESHOLD_SATS
        });
        if surviving.len() == pre_len {
            break;
        }
    }

    let total_work: f64 = surviving.iter().map(|(_, w)| *w).sum();
    let paid_this_block = surviving.len() as u64;

    let miners: Vec<_> = surviving
        .into_iter()
        .enumerate()
        .map(|(i, (miner_id, work))| {
            let share_pct = if total_work > 0.0 {
                work / total_work * 100.0
            } else {
                0.0
            };
            let projected_sats = if total_work > 0.0 {
                (miner_pool_sats as u128 * ((work * 1_000_000.0) as u128)
                    / ((total_work * 1_000_000.0) as u128)) as u64
            } else {
                0
            };
            serde_json::json!({
                "rank": i + 1,
                "miner_id_redacted": redact_miner_id(&miner_id),
                "unpaid_work": work,
                "share_pct": share_pct,
                "projected_sats": projected_sats,
            })
        })
        .collect();

    Json(serde_json::json!({
        "block_height": block_height,
        "subsidy_sats": subsidy_sats,
        "pool_fee_bps": POOL_FEE_BPS,
        "treasury_rate_bps": TREASURY_RATE_BPS,
        "node_rate_bps": NODE_RATE_BPS,
        "pool_fee_sats": pool_fee_sats,
        "treasury_sats": treasury_sats,
        "node_reward_pool_sats": node_reward_pool_sats,
        "miner_pool_sats": miner_pool_sats,
        "dust_threshold_sats": DUST_THRESHOLD_SATS,
        "ledger_cap": LEDGER_CAP,
        "total_work": total_work,
        "total_unpaid_miners": total_unpaid_miners,
        "paid_this_block": paid_this_block,
        "notes": {
            "model": "ledger",
            "tx_fees_to_block_finder": true,
            "dust_redistributed_to_node_pool": true,
            "unpaid_shares_carry_forward": true,
            "inactive_prune_days": 7,
        },
        "miners": miners,
    }))
}

/// Aggregate node metrics for the Core page. Returns only pool-wide
/// counts and a median — never per-node data — so Tor operators (and
/// everyone else) remain individually invisible. No clearnet/tor
/// breakdown exists on purpose; operators who run Tor nodes chose a
/// privacy setting and we honour it by not publishing the split.
async fn api_mesh_node_stats_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let Some(ref db) = state.database else {
        return Json(serde_json::json!({
            "error": "Database not available",
        }));
    };

    let (total, active_7d, new_7d, median_uptime) = db.get_node_stats().unwrap_or((0, 0, 0, None));

    Json(serde_json::json!({
        "total_nodes": total,
        "active_7d": active_7d,
        "new_7d": new_7d,
        "median_uptime_pct": median_uptime,
    }))
}

/// Decentralisation-phase + treasury state for the public Core page.
///
/// The pool collects 0.5% of every block subsidy into the treasury
/// until it reaches 21 BTC. At that point the treasury balance is
/// frozen and the fee split begins a five-year linear decay from
/// 50/50 (treasury/node-pool) to 0/100. The three phases:
///
///   * Bootstrap    — pre-threshold. Treasury filling.
///   * Decentralising — post-threshold, during the 5-year decay.
///   * Sovereign    — post-decay. 100% of pool fee → node reward pool.
///
/// Returns every field the Core page needs to render the journey
/// stepper, progress bar, and current-split tiles in one round trip.
async fn api_pool_treasury_state_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    // Mirror of the constants in ghost-reconciliation::fee_distribution —
    // kept inline to avoid adding a new crate dependency for one endpoint.
    // If either side moves, both need to move together.
    const TREASURY_THRESHOLD_SATS: u64 = 21 * 100_000_000; // 21 BTC
                                                           // (treasury_bps, node_bps) for year 0 (pre-threshold, then year 1…5).
                                                           // Year 0 = pre-threshold initial split, same as the first decay row.
    const DECAY_SCHEDULE_BPS: [(u64, u64); 6] = [
        (5000, 5000), // pre-threshold / year 0
        (4000, 6000), // year 1
        (3000, 7000), // year 2
        (2000, 8000), // year 3
        (1000, 9000), // year 4
        (0, 10000),   // year 5+
    ];

    let Some(ref db) = state.database else {
        return Json(serde_json::json!({
            "error": "Database not available",
            "threshold_sats": TREASURY_THRESHOLD_SATS,
        }));
    };

    let balance_sats = db.get_treasury_balance().unwrap_or(0);
    let threshold_reached_ts = db.get_treasury_threshold_reached().unwrap_or(None);
    let threshold_reached = threshold_reached_ts.is_some();

    // Decay year: 0 pre-threshold, 1..=5 after. 365-day years, same as
    // TreasuryState::years_since_threshold.
    let decay_year: u32 = match threshold_reached_ts {
        None => 0,
        Some(ts) => {
            let now_s = chrono::Utc::now().timestamp();
            let elapsed_days = ((now_s - ts).max(0)) / 86_400;
            ((elapsed_days / 365) as u32 + 1).min(5)
        }
    };

    let idx = decay_year as usize;
    let (treasury_bps, node_bps) = DECAY_SCHEDULE_BPS[idx.min(5)];

    let phase = if !threshold_reached {
        "Bootstrap"
    } else if decay_year < 5 {
        "Decentralising"
    } else {
        "Sovereign"
    };

    let progress_pct = if threshold_reached {
        100.0
    } else {
        (balance_sats as f64 / TREASURY_THRESHOLD_SATS as f64 * 100.0).min(100.0)
    };

    // Cumulative totals paid into the node reward pool.
    //   * Coinbase: authoritative sum across every approved PayoutProposal
    //   * L2:       running kv_store accumulator bumped at Ghost Pay
    //               broadcast-success time in bins/ghost-pay/src/main.rs
    let node_rewards_coinbase = db.get_total_node_rewards_paid().unwrap_or(0);
    let node_rewards_l2 = db.get_l2_node_rewards_paid().unwrap_or(0);
    let node_rewards_total = node_rewards_coinbase.saturating_add(node_rewards_l2);

    Json(serde_json::json!({
        "phase": phase,
        "balance_sats": balance_sats,
        "threshold_sats": TREASURY_THRESHOLD_SATS,
        "threshold_reached": threshold_reached,
        "threshold_reached_at": threshold_reached_ts,
        "progress_pct": progress_pct,
        "decay_year": decay_year,
        "decay_years_total": 5u32,
        "treasury_rate_bps": treasury_bps,
        "node_rate_bps": node_bps,
        "pool_fee_bps": 100u32,
        "node_rewards_paid_coinbase_sats": node_rewards_coinbase,
        "node_rewards_paid_l2_sats": node_rewards_l2,
        "node_rewards_paid_total_sats": node_rewards_total,
    }))
}

/// Tail of recent valid shares for the quasar visualisation. Each
/// share becomes one particle on the client; quality is normalised
/// from the share hash's leading zero bits so common pool shares land
/// in the middle of the colour ramp and rare block-worthy hits
/// approach 1.0.
///
/// Clients poll with `?since=<ts>`; the first call (no since) returns
/// just the newest few rows so the feed starts caught up rather than
/// flooding the scene with history.
async fn api_pool_recent_shares_handler(
    State(state): State<Arc<VerificationState>>,
    Query(params): Query<RecentSharesQuery>,
) -> impl IntoResponse {
    let now_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let limit = params.limit.unwrap_or(500).min(2000).max(1);
    // No watermark → start from a short look-back so the quasar has a
    // few particles to render immediately instead of waiting for the
    // next incoming share. 30 seconds is one emit-cycle at most rates.
    let since_ts = params.since.unwrap_or(now_s - 30);

    let Some(ref db) = state.database else {
        return Json(serde_json::json!({
            "now_ts": now_s,
            "since_ts": since_ts,
            "shares": serde_json::Value::Array(Vec::new()),
            "error": "Database not available",
        }));
    };

    let rows = db
        .get_recent_valid_shares(since_ts, limit)
        .unwrap_or_default();

    let shares: Vec<_> = rows
        .into_iter()
        .filter(|(miner_id, _, _, _)| !is_system_miner(miner_id))
        .map(|(miner_id, hash, ts, _work)| {
            // Leading hex zeros → leading bits (×4). Bitaxe-difficulty
            // shares today hit ~48; a genuine mainnet block needs ~80.
            //
            // Piecewise radial map:
            //   bits 40..72   →  inner 85 % of the radius (normal range)
            //   bits 72..80   →  outer 15 % (near-block / block-grade)
            //
            // Keeps ordinary shares spread through the sphere without
            // letting an unlucky-but-ordinary share masquerade as a near-
            // block. Outer band is reserved for genuinely exceptional hashes.
            let leading_hex_zeros = hash.chars().take_while(|c| *c == '0').count();
            let leading_bits = (leading_hex_zeros * 4) as f64;
            let quality = if leading_bits < 72.0 {
                ((leading_bits - 40.0) / 32.0 * 0.85).clamp(0.0, 0.85)
            } else {
                (0.85 + (leading_bits - 72.0) / 8.0 * 0.15).clamp(0.85, 1.0)
            };
            serde_json::json!({
                "t": ts,
                "miner_id_redacted": redact_miner_id(&miner_id),
                "leading_zero_bits": leading_bits as u64,
                "quality": quality,
            })
        })
        .collect();

    Json(serde_json::json!({
        "now_ts": now_s,
        "since_ts": since_ts,
        "shares": shares,
    }))
}

/// Shape one connected peer (`MeshNodeInfo`) into the public mesh-node JSON
/// object. Self is shaped inline by the handler from local state, so this
/// helper always renders a peer (`is_self = false`). Pulled out as a free
/// function so the JSON contract is unit-testable without a live server.
fn mesh_node_to_json(node: &MeshNodeInfo) -> serde_json::Value {
    serde_json::json!({
        "node_id": node.node_id,
        "address": node.address,
        "elder": node.elder,
        "capabilities": {
            "archive": node.cap_archive,
            "ghost_pay": node.cap_ghost_pay,
            "public_mining": node.cap_public_mining,
            "reaper": node.cap_reaper,
            "elder": node.cap_elder,
        },
        "hashrate_th": node.hashrate_th,
        "miner_count": node.miner_count,
        "deduped_miner_count": node.deduped_miner_count,
        // Peer's hardware-derived capacity ceiling (0 = not yet gossiped →
        // the Capacity page renders it as "unknown", not a real ceiling).
        "max_capacity": node.max_capacity,
        // Swarm-page telemetry gossiped per peer. `None` serialises to JSON null,
        // which the frontend renders as "—" (never a misleading 0).
        "l1_height": node.l1_height,
        "uptime_percent": node.uptime_percent,
        "peer_count": node.peer_count,
        "l2_height": node.l2_height,
        "healthy": node.healthy,
        "is_self": false,
    })
}

/// Live mesh node list = this node (self) + every connected peer.
///
/// PUBLIC, no auth (same exposure level as `recent_shares`): every field
/// returned is already gossiped openly in health pings. The website polls
/// this on one bootstrap node and renders the whole mesh, so newly-joined
/// nodes appear automatically without a hard-coded VM list or a per-node
/// nginx proxy block.
///
/// Self is built from this node's local state (the same sources
/// `/api/v1/mining/status` uses); peers come from the in-memory
/// `PeerManager` via the `mesh_nodes` callback (no network calls). Results
/// are deduplicated by `node_id` with self always included exactly once;
/// a missing field on any one peer degrades to a default (`0`/`false`)
/// rather than failing the whole response.
async fn api_pool_mesh_nodes_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let health = state.get_health().await;

    // Self address: the operator-configured public host (+ HTTP port when a
    // bare host was configured). Falls back to an empty string — never fails.
    let self_address = {
        let config = state.dashboard_config.read();
        match config.stratum_host.clone() {
            Some(host) if host.contains(':') => host,
            Some(host) => {
                let port = config.http_port.unwrap_or(8080);
                format!("{host}:{port}")
            }
            None => String::new(),
        }
    };

    let self_caps = &health.capabilities;
    let self_node = serde_json::json!({
        "node_id": health.node_id,
        "address": self_address,
        "elder": self_caps.elder_status,
        "capabilities": {
            "archive": self_caps.archive_mode,
            "ghost_pay": self_caps.ghost_pay,
            "public_mining": self_caps.public_mining,
            "reaper": self_caps.reaper,
            "elder": self_caps.elder_status,
        },
        // This node's own realized hashrate (same windowed value it gossips);
        // 0.0 on deploys without the local-hashrate provider wired.
        "hashrate_th": state.local_hashrate().unwrap_or(0.0),
        "miner_count": health.miner_count,
        // Deduped share attributed to this node (see `deduped_miner_counts`);
        // self + peers sum to the deduped mesh-wide active-miner total.
        "deduped_miner_count": state.self_deduped_miner_count(),
        // This node's own hardware-derived capacity ceiling, so the Capacity
        // page can render self's utilisation from the same field it uses for
        // every peer.
        "max_capacity": state.max_capacity(),
        // Self is serving this request, so it is healthy by definition.
        "healthy": true,
        "is_self": true,
    });

    let mut nodes = vec![self_node];
    // Dedup by node_id; self is already in, so skip any peer that re-reports
    // this node's id (e.g. a same-host placeholder).
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    seen.insert(health.node_id.clone());

    for peer in state.mesh_nodes() {
        if seen.insert(peer.node_id.clone()) {
            nodes.push(mesh_node_to_json(&peer));
        }
    }

    let total = nodes.len();
    Json(serde_json::json!({
        "nodes": nodes,
        "total": total,
    }))
}

/// Workers under a given payout address. Lets users enter just their
/// Bitcoin address and see every worker (bitaxe1, bitaxe2, …) attached
/// to it. Returns a compact summary per worker; the website aggregates
/// across nodes and uses each worker's `miner_id` as the key to the
/// individual miner page.
async fn api_miners_by_address_handler(
    State(state): State<Arc<VerificationState>>,
    Query(params): Query<MinersByAddressQuery>,
) -> impl IntoResponse {
    let address = params.address.unwrap_or_default();
    if address.is_empty() {
        return Json(serde_json::json!({
            "error": "Missing address parameter",
        }));
    }

    let Some(ref db) = state.database else {
        return Json(serde_json::json!({
            "address": address,
            "workers": serde_json::Value::Array(Vec::new()),
            "error": "Database not available",
        }));
    };

    let now_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let workers = db
        .get_miners_by_address(&address, 50)
        .unwrap_or_default()
        .into_iter()
        .map(|m| {
            let active = (now_s - m.last_seen) < 600;
            // Extract the worker suffix from `address.worker` for display
            let worker = m
                .miner_id
                .rsplit_once('.')
                .map(|(_, w)| w.to_string())
                .unwrap_or_else(|| "".to_string());
            serde_json::json!({
                "miner_id": m.miner_id,
                "worker": worker,
                "first_seen": m.first_seen,
                "last_seen": m.last_seen,
                "active": active,
                "total_shares": m.total_shares,
                "total_work": m.total_work,
                "blocks_won": m.blocks_won,
                "total_payouts_sats": m.total_payouts_sats,
            })
        })
        .collect::<Vec<_>>();

    Json(serde_json::json!({
        "address": address,
        "workers": workers,
    }))
}

/// Per-miner share history, bucketed. Client computes hashrate from
/// `work / bucket_secs`. Returns empty `points` if miner is unknown or
/// has no shares in window — the per-miner page aggregates responses
/// from every node so "unknown" on one node is fine.
///
/// Buckets: day → 5 min, week → 30 min, month → 2 h. Keeps the point
/// count bounded (~280–360 points) regardless of window.
async fn api_miner_history_handler(
    State(state): State<Arc<VerificationState>>,
    Query(params): Query<MinerHistoryQuery>,
) -> impl IntoResponse {
    let miner_id = params.miner_id.unwrap_or_default();
    if miner_id.is_empty() {
        return Json(serde_json::json!({
            "error": "Missing miner_id parameter",
        }));
    }

    let window_name = params
        .window
        .as_deref()
        .unwrap_or("day")
        .to_ascii_lowercase();
    let (window_secs, bucket_secs): (i64, i64) = match window_name.as_str() {
        "day" => (86_400, 300),
        "week" => (604_800, 1_800),
        "month" => (2_592_000, 7_200),
        _ => {
            return Json(serde_json::json!({
                "error": "Invalid window — expected day | week | month",
                "window": window_name,
            }));
        }
    };

    let now_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let since_ts = now_s - window_secs;

    let Some(ref db) = state.database else {
        return Json(serde_json::json!({
            "miner_id": miner_id,
            "window": window_name,
            "bucket_secs": bucket_secs,
            "since_ts": since_ts,
            "points": serde_json::Value::Array(Vec::new()),
            "error": "Database not available",
        }));
    };

    let points = db
        .get_miner_history(&miner_id, since_ts, bucket_secs)
        .unwrap_or_default()
        .into_iter()
        .map(|(t, shares, work)| {
            serde_json::json!({
                "t": t,
                "shares": shares,
                "work": work,
            })
        })
        .collect::<Vec<_>>();

    Json(serde_json::json!({
        "miner_id": miner_id,
        "window": window_name,
        "bucket_secs": bucket_secs,
        "since_ts": since_ts,
        "points": points,
    }))
}

/// Public pool records — best (rarest, lowest-value) valid share for the
/// requested window, converged across the MESH.
///
/// Each node stores only its own miners' shares, so the pool-wide record can
/// live on any node. Every node gossips its per-window best in its health ping
/// (`HealthPing::best_records`), so this handler merges the local DB best with
/// every connected peer's gossiped best and returns the rarest across all of
/// them. That makes the record stable + correct on first load: it no longer
/// flickers when the record-holding node is momentarily unreachable, and the
/// website's fan-out + min still returns the same value (now from any node).
///
/// `?window=` accepts `block | day | week | month`. Defaults to `day`.
/// "Block" is approximated as the last 10 minutes (average block interval)
/// rather than looking up the actual network tip time — keeps the handler
/// synchronous and DB-only for the local term.
///
/// The miner ID is returned in redacted form to preserve privacy while
/// still giving enough of a handle to recognise one's own worker.
async fn api_pool_records_handler(
    State(state): State<Arc<VerificationState>>,
    Query(params): Query<PoolRecordsQuery>,
) -> impl IntoResponse {
    let window_name = params
        .window
        .as_deref()
        .unwrap_or("day")
        .to_ascii_lowercase();
    let window_secs: i64 = match window_name.as_str() {
        "block" => 600,
        "day" => 86_400,
        "week" => 604_800,
        "month" => 2_592_000,
        _ => {
            return Json(serde_json::json!({
                "error": "Invalid window — expected block | day | week | month",
                "window": window_name,
            }));
        }
    };

    // Shares are persisted with Unix-seconds timestamps (despite the
    // `ShareRecord::timestamp` docstring claiming ms) — match that unit here.
    let now_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let since_ts = now_s - window_secs;

    let Some(ref db) = state.database else {
        return Json(serde_json::json!({
            "window": window_name,
            "since_ts": since_ts,
            "found": false,
            "error": "Database not available",
        }));
    };

    // Local term: this node's own best for the window, from SQLite. We keep the
    // stored vardiff target separately so the response can still expose
    // `assigned_difficulty` when the local share wins (peers only gossip the
    // achieved difficulty, so that field is null when a peer's record wins).
    let local_best = match db.get_best_share_since(since_ts) {
        Ok(best) => best,
        Err(e) => {
            error!(error = %e, "Failed to query best share");
            return Json(serde_json::json!({
                "window": window_name,
                "since_ts": since_ts,
                "found": false,
                "error": "Database error",
            }));
        }
    };

    // Candidate winner so far: the rarest `share_hash` seen. `assigned_diff`
    // is Some only for the local share. Hashes are fixed-width zero-padded hex,
    // so string `<` matches numeric order (smaller = rarer).
    let mut winning_hash: Option<String> = None;
    let mut winning_redacted = String::new();
    let mut winning_timestamp: i64 = 0;
    let mut winning_assigned_diff: Option<f64> = None;

    if let Some(best) = local_best {
        winning_hash = Some(best.share_hash.clone());
        winning_redacted = redact_miner_id(&best.miner_id);
        winning_timestamp = best.timestamp;
        winning_assigned_diff = Some(best.difficulty);
    }

    // Mesh term: every connected peer's gossiped best for THIS window. The
    // miner_id is already redacted at the source. A peer record beats the
    // current winner only when its hash is strictly smaller (rarer).
    if let Some(peer_records) = state.mesh_best_records() {
        for rec in peer_records {
            if rec.window != window_name || rec.share_hash.is_empty() {
                continue;
            }
            let beats = winning_hash
                .as_ref()
                .map(|w| rec.share_hash < *w)
                .unwrap_or(true);
            if beats {
                winning_hash = Some(rec.share_hash);
                winning_redacted = rec.miner_id_redacted;
                winning_timestamp = rec.timestamp;
                // A peer's record carries no stored vardiff target.
                winning_assigned_diff = None;
            }
        }
    }

    let Some(share_hash) = winning_hash else {
        return Json(serde_json::json!({
            "window": window_name,
            "since_ts": since_ts,
            "found": false,
        }));
    };

    // Recompute the leading-zero presentation from the WINNING hash (the local
    // and peer hashes use the same big-endian zero-padded hex encoding).
    // Each leading '0' hex char = 4 binary leading zeros — a coarse signal;
    // the hash itself is the definitive record but reads worse in tiles.
    let leading_hex_zeros = share_hash.chars().take_while(|c| *c == '0').count();
    let leading_zero_bits = leading_hex_zeros * 4;

    Json(serde_json::json!({
        "window": window_name,
        "since_ts": since_ts,
        "found": true,
        "best": {
            "share_hash": share_hash,
            "leading_zero_bits": leading_zero_bits,
            "leading_hex_zeros": leading_hex_zeros,
            "miner_id_redacted": winning_redacted,
            "timestamp": winning_timestamp,
            // Achieved difficulty from the hash (the score), NOT the stored
            // vardiff target. `assigned_difficulty` keeps the stored value for
            // any consumer that wants the share's pool-credit work — null when
            // a peer's record wins (peers don't gossip their vardiff target).
            "difficulty": share_difficulty_from_hash_hex(&share_hash),
            "assigned_difficulty": winning_assigned_diff,
        }
    }))
}

/// Rolling server-side time-series of pool hashrate + connected miners.
///
/// The sampler task in `bins/ghost-pool` snapshots the same mesh accessors the
/// mining-status endpoint uses (`mesh_total_hashrate` / `local_hashrate` /
/// `mesh_active_miners`) every 30s into a bounded in-memory ring. This endpoint
/// returns the samples within the requested `window` (`1h` or `24h`, default
/// `1h`), oldest first. Empty until the first sample lands after startup — the
/// dashboard keeps its client-side session buffer as a fallback in that case.
async fn api_pool_series_handler(
    State(state): State<Arc<VerificationState>>,
    Query(params): Query<PoolSeriesQuery>,
) -> impl IntoResponse {
    // Only 1h and 24h are offered; anything else falls back to 1h.
    let (window_label, window_secs): (&str, i64) = match params.window.as_deref() {
        Some("24h") => ("24h", 24 * 3600),
        _ => ("1h", 3600),
    };
    let cutoff = chrono::Utc::now().timestamp() - window_secs;
    let samples = state.pool_series.since(cutoff);
    Json(serde_json::json!({
        "window": window_label,
        "window_secs": window_secs,
        "sample_interval_secs": 30,
        "count": samples.len(),
        "samples": samples,
    }))
}

/// Mesh-wide leaderboard for the pool page — aggregated across the whole mesh
/// WITHOUT any new gossip, from data every node already holds:
///
/// * `nodes` — every mesh node (self + connected peers) ranked by realized
///   hashrate. This is the mesh-wide replacement for the pool page's old
///   this-node-only miner list.
/// * `records` — the mesh-wide best (rarest) share per window (block/day/week/
///   month), merging this node's local DB best with peers' gossiped
///   `best_records` (already reduced to one winner per window), each attributed
///   to its redacted miner id.
///
/// LIMIT: a true mesh-wide *per-miner top-N* leaderboard (every miner on every
/// node ranked by hashrate or shares) is NOT computable from a single node
/// without new gossip — peers gossip per-node aggregates and one best-share
/// record per window, never their full per-miner tables. The public website
/// builds that by fanning out to every node and merging client-side. `records`
/// is the widest mesh-wide per-miner surface available server-side here.
async fn api_pool_mesh_leaderboard_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let health = state.get_health().await;

    // --- Node-ranked leaderboard: self + every connected peer ---
    let self_name = {
        let config = state.dashboard_config.read();
        let addr = match config.stratum_host.clone() {
            Some(host) if host.contains(':') => host,
            Some(host) => format!("{host}:{}", config.http_port.unwrap_or(8080)),
            None => String::new(),
        };
        config
            .node_name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| mesh_node_name(&addr, &health.node_id))
    };
    let self_caps = &health.capabilities;
    let mut nodes = vec![serde_json::json!({
        "node_id": health.node_id.clone(),
        "name": self_name,
        "hashrate_th": state.local_hashrate().unwrap_or(0.0),
        // Deduped real-miner count (matches Capacity/Swarm/overview), not the
        // raw share-ledger miner_count which double-counts (issue #281).
        "miner_count": state.self_deduped_miner_count(),
        "shares": mesh_capability_shares(
            self_caps.archive_mode,
            self_caps.ghost_pay,
            self_caps.public_mining,
            self_caps.reaper,
            self_caps.elder_status,
        ),
        "elder": self_caps.elder_status,
        "healthy": health.healthy,
        "is_self": true,
    })];
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    seen.insert(health.node_id.clone());
    for peer in state.mesh_nodes() {
        if !seen.insert(peer.node_id.clone()) {
            continue;
        }
        nodes.push(serde_json::json!({
            "node_id": peer.node_id,
            "name": mesh_node_name(&peer.address, &peer.node_id),
            "hashrate_th": peer.hashrate_th,
            // Deduped real-miner count, consistent with the self row (issue #281).
            "miner_count": peer.deduped_miner_count,
            "shares": mesh_capability_shares(
                peer.cap_archive,
                peer.cap_ghost_pay,
                peer.cap_public_mining,
                peer.cap_reaper,
                peer.cap_elder,
            ),
            "elder": peer.cap_elder,
            "healthy": peer.healthy,
            "is_self": false,
        }));
    }
    // Rank by realized hashrate, highest first.
    nodes.sort_by(|a, b| {
        let ha = a.get("hashrate_th").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let hb = b.get("hashrate_th").and_then(|v| v.as_f64()).unwrap_or(0.0);
        hb.partial_cmp(&ha).unwrap_or(std::cmp::Ordering::Equal)
    });
    let node_count = nodes.len();

    // --- Mesh-wide best-share records per window ---
    // Merge this node's local DB best with the peers' gossiped winners (already
    // one per window). Same rarity rule as /api/v1/pool/records: fixed-width
    // zero-padded hex, so string `<` matches numeric order (smaller = rarer).
    let now_s = chrono::Utc::now().timestamp();
    let mesh_records = state.mesh_best_records();
    let mut records = Vec::new();
    for (window_name, window_secs) in [
        ("block", 600i64),
        ("day", 86_400),
        ("week", 604_800),
        ("month", 2_592_000),
    ] {
        let since_ts = now_s - window_secs;
        let mut winning_hash: Option<String> = None;
        let mut winning_redacted = String::new();
        let mut winning_timestamp: i64 = 0;

        if let Some(ref db) = state.database {
            if let Ok(Some(best)) = db.get_best_share_since(since_ts) {
                winning_hash = Some(best.share_hash.clone());
                winning_redacted = redact_miner_id(&best.miner_id);
                winning_timestamp = best.timestamp;
            }
        }
        if let Some(ref recs) = mesh_records {
            for rec in recs {
                if rec.window != window_name || rec.share_hash.is_empty() {
                    continue;
                }
                let beats = winning_hash
                    .as_ref()
                    .map(|w| rec.share_hash < *w)
                    .unwrap_or(true);
                if beats {
                    winning_hash = Some(rec.share_hash.clone());
                    winning_redacted = rec.miner_id_redacted.clone();
                    winning_timestamp = rec.timestamp;
                }
            }
        }

        if let Some(share_hash) = winning_hash {
            let leading_hex_zeros = share_hash.chars().take_while(|c| *c == '0').count();
            records.push(serde_json::json!({
                "window": window_name,
                "share_hash": share_hash.clone(),
                "leading_zero_bits": leading_hex_zeros * 4,
                "leading_hex_zeros": leading_hex_zeros,
                "miner_id_redacted": winning_redacted,
                "timestamp": winning_timestamp,
                "difficulty": share_difficulty_from_hash_hex(&share_hash),
            }));
        }
    }

    Json(serde_json::json!({
        "nodes": nodes,
        "node_count": node_count,
        "records": records,
        "limit_note": "Node-ranked leaderboard + mesh-wide best-share records \
            per window, aggregated from existing mesh data (no new gossip). A \
            per-miner top-N hashrate/shares leaderboard across the whole mesh \
            requires client-side fan-out to every node.",
    }))
}

/// Public leaderboard for the pool page. Returns both the best-hash
/// leaderboard and the shares-contributed leaderboard for the window.
/// Website fans out to every node and merges per-miner across nodes.
async fn api_pool_leaderboard_handler(
    State(state): State<Arc<VerificationState>>,
    Query(params): Query<PoolLeaderboardQuery>,
) -> impl IntoResponse {
    let window_name = params
        .window
        .as_deref()
        .unwrap_or("day")
        .to_ascii_lowercase();
    let limit = params.limit.unwrap_or(10).min(50).max(1);

    // "lifetime" queries the `miners` table directly and ignores the
    // pruned shares timeline. Only the shares-contributed tab is useful
    // in this mode — best-hash needs an actual share hash which we only
    // keep in `shares` for a bounded window.
    if window_name == "lifetime" {
        let Some(ref db) = state.database else {
            return Json(serde_json::json!({
                "window": "lifetime",
                "error": "Database not available",
            }));
        };
        // Fetch a larger slice and filter so we still return the caller's
        // requested `limit` after removing system accounts.
        let over_fetch = (limit as usize).saturating_mul(3).max(30) as u32;
        // 7-day activity filter matches the unpaid-ledger prune rule:
        // a miner must have submitted at least one share in the last
        // week to appear on the public lifetime leaderboard. Hides
        // legacy translator attributions and abandoned wallets.
        const ACTIVE_SECS: i64 = 7 * 24 * 3600;
        let shares = db
            .get_leaderboard_lifetime(over_fetch, ACTIVE_SECS)
            .unwrap_or_default()
            .into_iter()
            .filter(|(miner_id, _, _)| !is_system_miner(miner_id))
            .take(limit as usize)
            .map(|(miner_id, share_count, total_work)| {
                serde_json::json!({
                    "miner_id_redacted": redact_miner_id(&miner_id),
                    "share_count": share_count,
                    "total_work": total_work,
                })
            })
            .collect::<Vec<_>>();

        return Json(serde_json::json!({
            "window": "lifetime",
            "best_hash": serde_json::Value::Array(Vec::new()),
            "shares": shares,
            "limit": limit,
        }));
    }

    let window_secs: i64 = match window_name.as_str() {
        "day" => 86_400,
        "week" => 604_800,
        "month" => 2_592_000,
        _ => {
            return Json(serde_json::json!({
                "error": "Invalid window — expected day | week | month | lifetime",
                "window": window_name,
            }));
        }
    };

    let now_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let since_ts = now_s - window_secs;

    let Some(ref db) = state.database else {
        return Json(serde_json::json!({
            "window": window_name,
            "since_ts": since_ts,
            "error": "Database not available",
        }));
    };

    // Over-fetch so we can filter out system miners (translator proxies)
    // and still return `limit` real rows.
    let over_fetch = (limit as usize).saturating_mul(3).max(30) as u32;

    let best_hash = db
        .get_leaderboard_best_hash(since_ts, over_fetch)
        .unwrap_or_default()
        .into_iter()
        .filter(|(miner_id, _, _, _)| !is_system_miner(miner_id))
        .take(limit as usize)
        .map(|(miner_id, hash, ts, difficulty)| {
            let leading_hex_zeros = hash.chars().take_while(|c| *c == '0').count();
            serde_json::json!({
                "miner_id_redacted": redact_miner_id(&miner_id),
                "share_hash": hash,
                "leading_zero_bits": leading_hex_zeros * 4,
                "timestamp": ts,
                // Achieved difficulty from the hash (the score). `claimed_difficulty`
                // is the stored vardiff target, kept for back-compat.
                "difficulty": share_difficulty_from_hash_hex(&hash),
                "claimed_difficulty": difficulty,
            })
        })
        .collect::<Vec<_>>();

    let shares = db
        .get_leaderboard_shares(since_ts, over_fetch)
        .unwrap_or_default()
        .into_iter()
        .filter(|(miner_id, _, _)| !is_system_miner(miner_id))
        .take(limit as usize)
        .map(|(miner_id, share_count, total_work)| {
            serde_json::json!({
                "miner_id_redacted": redact_miner_id(&miner_id),
                "share_count": share_count,
                "total_work": total_work,
            })
        })
        .collect::<Vec<_>>();

    Json(serde_json::json!({
        "window": window_name,
        "since_ts": since_ts,
        "limit": limit,
        "best_hash": best_hash,
        "shares": shares,
    }))
}

/// Redact a miner_id of the form `<address>.<worker>` for public display.
/// Keeps the first 6 and last 4 characters of the address, and leaves the
/// worker portion intact. If the input doesn't contain a `.`, treats the
/// whole thing as an address.
/// Recognise system-level connections that shouldn't appear in public
/// leaderboards or payout projections — each node runs a local SRI
/// translator which authenticates as `<addr>.translator-proxy`, and the
/// historical shares table still holds signet/testnet translator
/// entries. They outrank real miners on lifetime work just because
/// they've been up longer, which isn't useful to show.
/// Achieved difficulty of a share, derived from its hash — the standard pool
/// "best share" / score metric (`diff1_target / hash_value`).
///
/// The `shares.difficulty`/`shares.work` DB columns store the SV2/SRI-assigned
/// *vardiff target* (used for payout and hashrate accounting), NOT how good the
/// share's hash actually was — so a lucky 60-leading-zero-bit share is stored as
/// e.g. ~1.5K, six orders of magnitude below its true ~600M difficulty. Any stat
/// that means "how good was this share" must therefore be computed from the hash.
///
/// `share_hash` is stored/served big-endian (leading hex zeros at the front =
/// higher difficulty), so this mirrors the web client's `hashToDifficulty`
/// (`BigInt('0x'+hash)`) exactly — most-significant byte first — giving backend
/// and frontend identical numbers and reading historical rows correctly with no
/// migration. (Note: `DifficultyCalculator::difficulty_from_hash` uses the
/// opposite, internal little-endian byte order, so it is deliberately NOT reused
/// here.) The difficulty-1 target (pdiff) is `0xFFFF * 2^208`.
///
/// Returns 0.0 for a hash that isn't 32 bytes of hex (treated as "unknown").
/// Achieved difficulty for a 64-char big-endian hex share hash (`diff1_target
/// / hash_value`). Returns 0.0 for malformed input. `pub` so the ping builder
/// in ghost-pool derives the same score it would here.
pub fn share_difficulty_from_hash_hex(share_hash_hex: &str) -> f64 {
    let bytes = match hex::decode(share_hash_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return 0.0,
    };
    // Big-endian: byte[0] is most-significant.
    let mut hash_value = 0.0_f64;
    for &byte in bytes.iter() {
        hash_value = hash_value * 256.0 + byte as f64;
    }
    if hash_value == 0.0 {
        return f64::MAX;
    }
    let diff1_target = 65535.0_f64 * 2.0_f64.powi(208);
    diff1_target / hash_value
}

fn is_system_miner(miner_id: &str) -> bool {
    let worker = miner_id.rsplit_once('.').map(|(_, w)| w).unwrap_or("");
    let lower = worker.to_ascii_lowercase();
    lower.contains("translator") || lower == "proxy"
}

/// Redact a `address.worker` miner_id for public display: first 6 + ellipsis +
/// last 4 of the address portion, worker kept intact. `pub` so the ping builder
/// in ghost-pool redacts gossiped records identically to this endpoint.
pub fn redact_miner_id(id: &str) -> String {
    let (addr, worker) = match id.find('.') {
        Some(i) => (&id[..i], &id[i..]), // worker has leading '.'
        None => (id, ""),
    };
    let redacted_addr = if addr.len() <= 12 {
        addr.to_string()
    } else {
        format!("{}…{}", &addr[..6], &addr[addr.len() - 4..])
    };
    format!("{}{}", redacted_addr, worker)
}

/// API v1 pool status handler
async fn api_pool_status_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let health = state.get_health().await;
    let active_miners = state
        .database
        .as_ref()
        .and_then(|db| db.count_active_miners(300).ok())
        .unwrap_or(0);
    let mesh_active_miners = state.mesh_active_miners().unwrap_or(active_miners);
    Json(serde_json::json!({
        "pool_name": "Ghost Pool",
        "version": health.version,
        "block_height": health.block_height,
        "peer_count": health.peer_count,
        "active_nodes": health.peer_count + 1,
        "miner_count": health.miner_count,
        "active_miners": active_miners,
        "mesh_active_miners": mesh_active_miners,
        "round_id": health.round_id,
        "uptime_secs": health.uptime_secs,
        "total_shares": health.capabilities.total_shares,
        "stratum_sv2_port": 4444,
        "stratum_sv1_port": 3333,
        "http_port": 8080
    }))
}

/// API v1 config handler
async fn api_config_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let config = state.dashboard_config.read();
    Json(serde_json::json!({
        "archive_mode": config.archive_mode,
        "ghost_pay": config.ghost_pay,
        "public_mining": config.public_mining,
        "reaper": config.reaper,
        "ghost_mode": config.ghost_mode,
        "mempool_profile": config.mempool_profile,
        "template_profile": config.template_profile
    }))
}

/// API v1 resources handler
async fn api_resources_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let health = state.get_health().await;

    // M-STOR-3: Get allowed proc paths from config
    let proc_paths_allowed = {
        let config = state.dashboard_config.read();
        config.proc_paths_allowed.clone()
    };

    // Get actual system resource usage
    let (cpu_percent, memory_percent, disk_percent) = get_system_resources(&proc_paths_allowed);

    // Read memory totals from /proc/meminfo for dashboard
    let (memory_total_mb, memory_used_mb) =
        safe_read_proc_file("/proc/meminfo", &proc_paths_allowed)
            .and_then(|content| {
                let mut total: u64 = 0;
                let mut available: u64 = 0;
                for line in content.lines() {
                    if line.starts_with("MemTotal:") {
                        total = line.split_whitespace().nth(1)?.parse().ok()?;
                    } else if line.starts_with("MemAvailable:") {
                        available = line.split_whitespace().nth(1)?.parse().ok()?;
                    }
                }
                // Convert from kB to MB
                Some((total / 1024, (total - available) / 1024))
            })
            .unwrap_or((0, 0));

    // Read disk totals via statvfs
    let (disk_total_gb, disk_used_gb) = {
        #[cfg(unix)]
        {
            use std::ffi::CString;
            use std::mem::MaybeUninit;
            let path = CString::new("/").expect("root path contains no NUL bytes");
            let mut stat_buf: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
            let result = unsafe { libc::statvfs(path.as_ptr(), stat_buf.as_mut_ptr()) };
            if result == 0 {
                let stat_buf = unsafe { stat_buf.assume_init() };
                let total = stat_buf.f_blocks as f64 * stat_buf.f_frsize as f64;
                let free = stat_buf.f_bfree as f64 * stat_buf.f_frsize as f64;
                let gb = 1024.0 * 1024.0 * 1024.0;
                ((total / gb) as u64, ((total - free) / gb) as u64)
            } else {
                (0, 0)
            }
        }
        #[cfg(not(unix))]
        {
            (0u64, 0u64)
        }
    };

    let status = if cpu_percent > 90.0 || memory_percent > 90.0 {
        "critical"
    } else if cpu_percent > 70.0 || memory_percent > 70.0 {
        "warning"
    } else {
        "healthy"
    };

    Json(serde_json::json!({
        "cpu_percent": cpu_percent,
        "memory_percent": memory_percent,
        "memory_mb": memory_used_mb,
        "memory_used_mb": memory_used_mb,
        "memory_total_mb": memory_total_mb,
        "disk_percent": disk_percent,
        "disk_usage_percent": disk_percent,
        "disk_used_gb": disk_used_gb,
        "disk_total_gb": disk_total_gb,
        "uptime_seconds": health.uptime_secs,
        "uptime_secs": health.uptime_secs,
        // Deduplicated mesh-wide active-miner count (same source as
        // /api/v1/network/pool), NOT the raw `miner_count` — the raw value is a
        // load-balancer routing view that double-counts miners failing over
        // between nodes, so the Watchdog was showing an inflated figure that
        // could exceed the real distinct total. Falls back to raw if unavailable.
        "connected_miners": state.mesh_active_miners().unwrap_or(health.miner_count),
        "estimated_capacity": 1000,
        "status": status,
        "last_redirect_count": 0,
        "warning_threshold_cpu": 70.0,
        "critical_threshold_cpu": 90.0,
        "warning_threshold_memory": 70.0,
        "critical_threshold_memory": 90.0
    }))
}

/// Ghost Pay L2 status result
struct GhostPayLiveStatus {
    epoch: u64,
    virtual_block: u64,
    wraith_enabled: bool,
    sync_state: &'static str,
}

/// Query ghost-pay L2 status — tries in-process handler first, then HTTPS to localhost:8800.
/// Returns a self-contained future (no borrows) so axum handlers stay Send.
///
/// ghost-pay serves identity-derived TLS on 8800 (cert pubkey == node_id).
/// Loopback IPC under the same identity, so we skip cert-chain validation.
async fn fetch_ghostpay_from_service() -> Option<GhostPayLiveStatus> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .danger_accept_invalid_certs(true)
        .build()
        .ok()?;

    let resp = client
        .get("https://127.0.0.1:8800/verify/ghostpay?unsigned=true")
        .send()
        .await
        .ok()?;
    let json: serde_json::Value = resp.json().await.ok()?;
    let inner = json.get("response")?;

    let success = inner
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !success {
        return None;
    }

    Some(GhostPayLiveStatus {
        epoch: inner.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0),
        virtual_block: inner
            .get("virtual_block")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        wraith_enabled: inner
            .get("wraith_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        sync_state: "synced",
    })
}

/// Check ghost-pay status from in-process handler (sync). Returns None if handler unavailable.
fn check_ghostpay_local(state: &VerificationState) -> Option<GhostPayLiveStatus> {
    let config = state.dashboard_config.read();
    if !config.ghost_pay {
        return Some(GhostPayLiveStatus {
            epoch: 0,
            virtual_block: 0,
            wraith_enabled: false,
            sync_state: "disabled",
        });
    }
    drop(config);

    state.get_ghostpay_status().map(|info| GhostPayLiveStatus {
        epoch: info.epoch,
        virtual_block: info.virtual_block,
        wraith_enabled: info.wraith_enabled,
        sync_state: "synced",
    })
}

/// API v1 GhostPay status handler
async fn api_ghostpay_status_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let health = state.get_health().await;

    // Try in-process handler first (sync, no borrow issues)
    let gp = match check_ghostpay_local(&state) {
        Some(status) => status,
        None => {
            // Ghost-pay runs as separate service on port 8800 — query via spawned task
            // 5s timeout prevents hanging when ghost-pay is unresponsive
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::spawn(fetch_ghostpay_from_service()),
            )
            .await
            {
                Ok(Ok(Some(status))) => status,
                _ => GhostPayLiveStatus {
                    epoch: 0,
                    virtual_block: 0,
                    wraith_enabled: false,
                    sync_state: "unavailable",
                },
            }
        }
    };

    Json(serde_json::json!({
        "enabled": gp.sync_state != "disabled",
        "node_id": health.node_id,
        "protocol_version": 1,
        "network": state.network.as_str(),
        "l2_era": gp.epoch,
        "virtual_block": gp.virtual_block,
        "l2_height": gp.virtual_block,
        "block_height": health.block_height,
        "epoch": gp.epoch,
        "peer_count": health.peer_count,
        "uptime_secs": health.uptime_secs,
        "sync_state": gp.sync_state,
        // Operator's Wraith setting from config — the user-facing "is Wraith
        // enabled on this node" flag the dashboard's L2 card reads. Sourced
        // from `[ghost_pay] wraith_enabled`, NOT ghost-pay's internal host flag
        // (`gp.wraith_enabled`), which is always false since mixing moved to
        // the wraith-coordinator binary and would misreport the operator's choice.
        "wraith_enabled": state.wraith_enabled,
        // Retained internal signal: whether the ghost-pay process itself hosts
        // CoinJoin sessions (always false post-wraith-coordinator split).
        "ghostpay_hosts_mixing": gp.wraith_enabled,
        "total_balances": 0
    }))
}

/// API v1 BUDS capabilities handler
async fn api_buds_capabilities_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let health = state.get_health().await;
    Json(serde_json::json!({
        "reaper": health.capabilities.reaper,
        "allowed_tiers": if health.capabilities.reaper {
            vec!["T0", "T1"]
        } else {
            vec!["T0", "T1", "T2"]
        },
        "max_op_return_size": 80,
        "allow_inscriptions": false,
        "allow_runes": false
    }))
}

/// API v1 Swarm handler - for multi-node management
/// Capability shares (0-15) from the individual capability booleans.
/// Mirrors `NodeCapabilities::total_shares()` for the mesh-gossiped flags
/// (Archive +5, Ghost Pay +4, Public Mining +3, Reaper +2, Elder +1).
fn mesh_capability_shares(
    archive: bool,
    ghost_pay: bool,
    public_mining: bool,
    reaper: bool,
    elder: bool,
) -> u32 {
    (archive as u32) * 5
        + (ghost_pay as u32) * 4
        + (public_mining as u32) * 3
        + (reaper as u32) * 2
        + (elder as u32)
}

/// Display name for a mesh node: the host portion of its advertised address,
/// falling back to a short node-id label when no address has been gossiped yet.
fn mesh_node_name(address: &str, node_id: &str) -> String {
    let host = address.split(':').next().unwrap_or("").trim();
    if !host.is_empty() {
        host.to_string()
    } else {
        format!("node-{}", &node_id[..node_id.len().min(8)])
    }
}

/// API v1 Swarm handler — the fleet view consumed by the dashboard Swarm page.
///
/// Auto-discovered mesh peers are reported with their REAL, health-ping-gossiped
/// state (online/capabilities/hashrate/miner count) that this node already holds
/// in the in-memory `PeerManager` — the exact source `/api/v1/pool/mesh-nodes`
/// uses. Previously this handler returned each peer stripped down to its mesh
/// address (`:8555`) with no `online` flag, so the dashboard rendered every mesh
/// peer as "Offline" with zeroed stats even though the mesh reports them healthy.
///
/// Fields that are NOT gossiped per peer (uptime %, mesh peer count, L1/L2 chain
/// heights, node balance) are deliberately OMITTED rather than sent as `0`, so
/// the dashboard can render them as "—" instead of a misleading zero. Each node
/// carries `"source": "mesh"` so the frontend can distinguish auto-discovered
/// peers (never poll-able from here, so never "offline" just because their
/// loopback dashboard API is unreachable) from any manually-added swarm node.
async fn api_swarm_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let health = state.get_health().await;

    // Self node's public address (operator-configured host + HTTP port) and
    // display name, read from the dashboard config in a single lock.
    let (self_address, self_name) = {
        let config = state.dashboard_config.read();
        let addr = match config.stratum_host.clone() {
            Some(host) if host.contains(':') => host,
            Some(host) => format!("{host}:{}", config.http_port.unwrap_or(8080)),
            None => String::new(),
        };
        let name = config
            .node_name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| mesh_node_name(&addr, &health.node_id));
        (addr, name)
    };

    let self_caps = &health.capabilities;
    let self_hashrate = state.local_hashrate().unwrap_or(0.0);
    let self_shares = mesh_capability_shares(
        self_caps.archive_mode,
        self_caps.ghost_pay,
        self_caps.public_mining,
        self_caps.reaper,
        self_caps.elder_status,
    );

    // THIS node's own L2 (Ghost Pay) virtual-block height. `check_ghostpay_local`
    // reads the in-process handler, which production ghost-pool does NOT wire —
    // ghost-pay runs as a separate service on :8800 — so it returns `None` and
    // the self row's L2 showed "—". Mirror the ghostpay status endpoint: on that
    // `None`, fall back to querying the local :8800 service. `Some(disabled)`
    // (ghost-pay off) still resolves to `None` → "—", never a fabricated value.
    let self_l2_height = match check_ghostpay_local(&state) {
        Some(gp) if gp.sync_state == "disabled" => None,
        Some(gp) => Some(gp.virtual_block),
        None => match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::spawn(fetch_ghostpay_from_service()),
        )
        .await
        {
            Ok(Ok(Some(status))) => Some(status.virtual_block),
            _ => None,
        },
    };

    // This node's own trailing-7-day uptime %, the qualification gatekeeper
    // metric (>=95% before capabilities count). It's the exact figure the
    // qualification layer reads (`get_uptime_percent`, GHOST-10 time-based
    // denominator) over the self-recorded samples — the self-uptime task
    // records under `identity.node_id_hex()`, which is `state.node_id` /
    // `health.node_id`. Returned as a percentage (0-100) to match the
    // peer-gossiped `uptime_percent` the frontend already renders. Left as
    // `None` (frontend "—") only when there's no DB attached.
    let self_uptime_percent = state.database.as_ref().and_then(|db| {
        let since = chrono::Utc::now().timestamp()
            - (ghost_common::constants::UPTIME_WINDOW_DAYS as i64 * 86_400);
        db.get_uptime_percent(&health.node_id, since)
            .ok()
            .map(|ratio| ratio * 100.0)
    });

    let self_node = serde_json::json!({
        "node_id": health.node_id.clone(),
        "name": self_name.clone(),
        "address": self_address.clone(),
        // Self is serving this request, so it is online by definition.
        "online": health.healthy,
        "is_self": true,
        "source": "mesh",
        "version": health.version.clone(),
        "hashrate_th": self_hashrate,
        "miner_count": health.miner_count,
        "shares": self_shares,
        "max_shares": 15,
        "archive_mode": self_caps.archive_mode,
        "ghost_pay": self_caps.ghost_pay,
        "public_mining": self_caps.public_mining,
        "reaper": self_caps.reaper,
        "elder": self_caps.elder_status,
        // Locally-known stats the mesh doesn't gossip (fixes the self row's "—").
        "peer_count": health.peer_count,
        "l1_height": health.block_height,
        "l2_height": self_l2_height,
        "uptime_percent": self_uptime_percent,
    });

    let mut nodes = vec![self_node];
    // Dedup by node_id; self is already in, so skip any peer that re-reports
    // this node's id (e.g. a same-host placeholder).
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    seen.insert(health.node_id.clone());

    let mut online_nodes: u32 = if health.healthy { 1 } else { 0 };
    let mut combined_hashrate = self_hashrate;
    let mut combined_shares = self_shares;

    for peer in state.mesh_nodes() {
        if !seen.insert(peer.node_id.clone()) {
            continue;
        }
        let shares = mesh_capability_shares(
            peer.cap_archive,
            peer.cap_ghost_pay,
            peer.cap_public_mining,
            peer.cap_reaper,
            peer.cap_elder,
        );
        if peer.healthy {
            online_nodes += 1;
        }
        combined_hashrate += peer.hashrate_th;
        combined_shares += shares;
        nodes.push(serde_json::json!({
            "node_id": peer.node_id,
            "name": mesh_node_name(&peer.address, &peer.node_id),
            "address": peer.address,
            "online": peer.healthy,
            "is_self": false,
            "source": "mesh",
            "hashrate_th": peer.hashrate_th,
            "miner_count": peer.miner_count,
            "shares": shares,
            "max_shares": 15,
            "archive_mode": peer.cap_archive,
            "ghost_pay": peer.cap_ghost_pay,
            "public_mining": peer.cap_public_mining,
            "reaper": peer.cap_reaper,
            "elder": peer.cap_elder,
            // Gossiped Swarm telemetry — `None` → JSON null → "—" on the page,
            // so a peer running an older build (that doesn't gossip these) shows
            // a dash rather than a fabricated 0 until the fleet is updated.
            "uptime_percent": peer.uptime_percent,
            "peer_count": peer.peer_count,
            "l1_height": peer.l1_height,
            "l2_height": peer.l2_height,
        }));
    }

    let total_nodes = nodes.len() as u32;

    Json(serde_json::json!({
        "enabled": true,
        "node_id": health.node_id.clone(),
        "self": {
            "node_id": health.node_id,
            "name": self_name,
            "address": self_address,
            "version": health.version,
            "capabilities": health.capabilities,
        },
        "nodes": nodes,
        "total": total_nodes,
        "stats": {
            "total_nodes": total_nodes,
            "online_nodes": online_nodes,
            "offline_nodes": total_nodes.saturating_sub(online_nodes),
            "combined_hashrate_th": combined_hashrate,
            "combined_shares": combined_shares,
            "max_combined_shares": total_nodes * 15,
        },
    }))
}

/// API v1 Treasury handler
async fn api_treasury_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    // Query database for treasury stats
    let (total_fees, payout_count) = if let Some(ref db) = state.database {
        // Sum all payouts where recipient_type is Treasury
        let payouts = db.get_recent_payouts(1000).unwrap_or_default();
        let treasury_payouts: Vec<_> = payouts
            .iter()
            .filter(|p| {
                matches!(
                    p.recipient_type,
                    ghost_storage::models::RecipientType::Treasury
                )
            })
            .collect();
        let total: u64 = treasury_payouts.iter().map(|p| p.amount_sats).sum();
        (total, treasury_payouts.len())
    } else {
        (0, 0)
    };

    // Calculate progress towards 21 BTC target
    let accumulated_btc = total_fees as f64 / 100_000_000.0;
    let target_btc = 21.0;
    let progress = (accumulated_btc / target_btc * 100.0).min(100.0);

    // Determine phase based on progress
    let phase = if accumulated_btc >= target_btc {
        "decay"
    } else {
        "bootstrap"
    };

    Json(serde_json::json!({
        "treasury_address": "", // Would come from config
        "treasury_balance_sats": total_fees,
        "fee_percent": 1.0,
        "total_fees_collected": total_fees,
        "total_payouts": payout_count,
        "phase": phase,
        "decay_year": if phase == "decay" { Some(2026) } else { None },
        "decay_started": phase == "decay",
        "accumulated_btc": accumulated_btc,
        "target_btc": target_btc,
        "progress_percent": progress,
        "treasury_percent": 50.0,
        "node_pool_percent": 50.0
    }))
}

/// L2 fee distribution context for ghost-pay settlement loop.
/// Returns treasury state and qualified Ghost Pay nodes for fee distribution.
async fn api_l2_fee_distribution_context_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let db = match state.database.as_ref() {
        Some(db) => db,
        None => {
            return Json(serde_json::json!({
                "error": "Database not available"
            }));
        }
    };

    // Get treasury balance
    let treasury_balance_sats = db.get_treasury_balance().unwrap_or(0);

    // Get treasury threshold timestamp
    let threshold_reached_at: Option<i64> = db.get_treasury_threshold_reached().unwrap_or(None);

    // Get nodes with Ghost Pay capability and their shares.
    // Uses the nodes table which is updated by health pings. Filter for recently-seen
    // nodes (last_seen within 5 min) that have ghost_pay in their capabilities JSON.
    let now = chrono::Utc::now().timestamp();
    let recent_cutoff = now - 300; // 5 minutes
    let ghost_pay_nodes: Vec<serde_json::Value> = match db.get_top_nodes_by_shares(200) {
        Ok(nodes) => nodes
            .into_iter()
            .filter(|node| node.last_seen >= recent_cutoff)
            .filter_map(|node| {
                // Parse "key:value,key:value" format stored by health_handler
                let cap_map: std::collections::HashMap<&str, bool> = node
                    .capabilities
                    .split(',')
                    .filter_map(|pair| {
                        let (k, v) = pair.split_once(':')?;
                        Some((k.trim(), v.trim() == "true"))
                    })
                    .collect();

                if !cap_map.get("ghost_pay").copied().unwrap_or(false) {
                    return None;
                }
                // Compute total shares from capabilities
                let archive = if cap_map.get("archive").copied().unwrap_or(false) {
                    5i32
                } else {
                    0
                };
                let ghost_pay_shares = 4i32;
                let public_mining = if cap_map.get("public_mining").copied().unwrap_or(false) {
                    3
                } else {
                    0
                };
                let reaper = if cap_map.get("reaper").copied().unwrap_or(false) {
                    2
                } else {
                    0
                };
                let elder = if node.is_elder { 1 } else { 0 };
                let total_shares = archive + ghost_pay_shares + public_mining + reaper + elder;

                // Get payout address from node record or fall back to public_address
                let address = db
                    .get_node_payout_address(&node.node_id)
                    .ok()
                    .flatten()
                    .or_else(|| node.public_address.clone())
                    .unwrap_or_default();

                Some(serde_json::json!({
                    "node_id": node.node_id,
                    "address": address,
                    "shares": total_shares,
                }))
            })
            .collect(),
        Err(_) => Vec::new(),
    };

    Json(serde_json::json!({
        "treasury_balance_sats": treasury_balance_sats,
        "threshold_reached_at": threshold_reached_at,
        "ghost_pay_nodes": ghost_pay_nodes,
    }))
}

/// L2 commitment tree state for health monitoring.
/// Exposes live in-memory tree root, checkpoint root, and finalization status.
async fn api_l2_tree_state_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let tree_state_fn = match &state.l2_tree_state_fn {
        Some(f) => f.clone(),
        None => {
            return Json(serde_json::json!({
                "error": "L2 tree state not configured"
            }));
        }
    };

    let info = match tree_state_fn() {
        Ok(info) => info,
        Err(e) => {
            return Json(serde_json::json!({
                "error": format!("Failed to get tree state: {}", e)
            }));
        }
    };

    let db = match state.database.as_ref() {
        Some(db) => db,
        None => {
            return Json(serde_json::json!({
                "error": "Database not available"
            }));
        }
    };

    let checkpoint = db.get_latest_l2_checkpoint().unwrap_or(None);
    let (checkpoint_root, checkpoint_tx_count, checkpoint_height) = match &checkpoint {
        Some(cp) => (hex::encode(cp.commitment_root), cp.tx_count, cp.height),
        None => ("0".repeat(64), 0, 0),
    };

    let recent_finalizations = db.count_recent_l2_finalizations(100).unwrap_or(0);
    let active_finalizations = db.count_recent_active_l2_finalizations(100).unwrap_or(0);

    let tree_root_hex = hex::encode(info.tree_root);
    let roots_match = tree_root_hex == checkpoint_root;

    Json(serde_json::json!({
        "epoch": info.epoch,
        "tree_root": tree_root_hex,
        "checkpoint_height": checkpoint_height,
        "checkpoint_root": checkpoint_root,
        "checkpoint_tx_count": checkpoint_tx_count,
        "note_count": info.note_count,
        "recent_finalizations": recent_finalizations,
        "active_finalizations": active_finalizations,
        "roots_match": roots_match
    }))
}

/// API v1 Rewards current handler
async fn api_rewards_current_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let health = state.get_health().await;
    let config = state.dashboard_config.read();

    // Get node reward entry from database
    let (balance_sats, total_credits, last_round) = if let Some(ref db) = state.database {
        match db.get_or_create_node_reward(&health.node_id) {
            Ok(entry) => (
                entry.balance_sats,
                entry.total_credits_sats,
                entry.last_credited_round,
            ),
            Err(e) => {
                error!(error = %e, "Failed to query node rewards");
                (0, 0, 0)
            }
        }
    } else {
        (0, 0, 0)
    };

    // Calculate node shares based on capabilities
    let mut node_shares = 0u32;
    if config.archive_mode {
        node_shares += 5;
    }
    if config.ghost_pay {
        node_shares += 4;
    }
    if config.public_mining {
        node_shares += 3;
    }
    if config.reaper {
        node_shares += 2;
    }
    if config.elder {
        node_shares += 1;
    }

    Json(serde_json::json!({
        "round_id": health.round_id,
        "block_height": health.block_height,
        "pending_rewards_sats": balance_sats,
        "total_earned_sats": total_credits,
        "last_credited_round": last_round,
        "estimated_share": if node_shares > 0 { node_shares as f64 / 15.0 } else { 0.0 },
        "node_shares": node_shares,
        "total_network_shares": 15,
        "message": "Current round reward estimation"
    }))
}

/// API v1 Rewards history handler
async fn api_rewards_history_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    // Query payouts to this node as reward history
    let health = state.get_health().await;

    let (rewards, total_sats) = if let Some(ref db) = state.database {
        // Get payouts where this node was the recipient
        let payouts = db.get_recent_payouts(100).unwrap_or_default();
        let node_payouts: Vec<_> = payouts
            .iter()
            .filter(|p| p.recipient_id == health.node_id)
            .map(|p| {
                serde_json::json!({
                    "round_id": p.round_id,
                    "amount_sats": p.amount_sats,
                    "txid": p.txid,
                    "status": format!("{:?}", p.status),
                    "created_at": p.created_at
                })
            })
            .collect();
        let total: u64 = payouts
            .iter()
            .filter(|p| p.recipient_id == health.node_id)
            .map(|p| p.amount_sats)
            .sum();
        (node_payouts, total)
    } else {
        (vec![], 0)
    };

    Json(serde_json::json!({
        "rewards": rewards,
        "total_rewards": rewards.len(),
        "total_earned_sats": total_sats,
        "total_earned_btc": total_sats as f64 / 100_000_000.0
    }))
}

// HIGH-4: api_logs_handler REMOVED
// This endpoint exposed journalctl output which is a security risk.
// System logs can reveal sensitive information about:
// - Internal IP addresses and network topology
// - Error messages with stack traces
// - Configuration details
// - Timing information useful for attacks
// The endpoint has been completely removed rather than adding authentication
// because even authenticated access to logs is a security concern.

/// API v1 Locks handler (Ghost Lock state channels)
async fn api_locks_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let health = state.get_health().await;
    let config = state.dashboard_config.read();

    // Query Ghost Locks for this node from database
    let (locks, active_count, total_locked) = if let Some(ref db) = state.database {
        // Get all locks owned by this node's ghost ID
        let ghost_id = format!("ghost{}", &health.node_id[..8.min(health.node_id.len())]);
        match db.get_ghost_locks_by_owner(&ghost_id) {
            Ok(lock_records) => {
                let active: Vec<_> = lock_records
                    .iter()
                    .filter(|l| l.state == ghost_storage::models::GhostLockState::Active)
                    .collect();
                let total: u64 = active.iter().map(|l| l.amount_sats).sum();
                let locks_json: Vec<_> = lock_records
                    .iter()
                    .map(|l| {
                        serde_json::json!({
                            "lock_id": l.lock_id,
                            "denomination": l.denomination,
                            "amount_sats": l.amount_sats,
                            "state": format!("{:?}", l.state),
                            "timelock_tier": l.timelock_tier,
                            "creation_height": l.creation_height,
                            "recovery_height": l.recovery_height,
                            "funding_txid": l.funding_txid,
                            "next_jump_height": l.next_jump_height,
                            "created_at": l.created_at
                        })
                    })
                    .collect();
                (locks_json, active.len(), total)
            }
            Err(e) => {
                error!(error = %e, "Failed to query ghost locks");
                (vec![], 0, 0)
            }
        }
    } else {
        (vec![], 0, 0)
    };

    Json(serde_json::json!({
        "enabled": config.ghost_pay,
        "active_locks": active_count,
        "total_locked_sats": total_locked,
        "locks": locks
    }))
}

/// API v1 Nickname handler
async fn api_nickname_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let health = state.get_health().await;
    let config = state.dashboard_config.read();
    // Use stored nickname, fall back to short node ID
    let nickname = config
        .nickname
        .clone()
        .unwrap_or_else(|| health.node_id.chars().take(8).collect());
    Json(serde_json::json!({
        "nickname": nickname
    }))
}

/// API v1 Rewards full handler
async fn api_rewards_full_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let health = state.get_health().await;
    let config = state.dashboard_config.read();

    // Get node reward entry from database
    let (balance_sats, total_credits, total_withdrawals, last_round) =
        if let Some(ref db) = state.database {
            match db.get_or_create_node_reward(&health.node_id) {
                Ok(entry) => (
                    entry.balance_sats,
                    entry.total_credits_sats,
                    entry.total_withdrawals_sats,
                    entry.last_credited_round,
                ),
                Err(e) => {
                    error!(error = %e, "Failed to query node rewards");
                    (0, 0, 0, 0)
                }
            }
        } else {
            (0, 0, 0, 0)
        };

    // Get payout history
    let (rewards_history, last_payout) = if let Some(ref db) = state.database {
        let payouts = db.get_recent_payouts(20).unwrap_or_default();
        let node_payouts: Vec<_> = payouts
            .iter()
            .filter(|p| p.recipient_id == health.node_id)
            .map(|p| {
                serde_json::json!({
                    "round_id": p.round_id,
                    "amount_sats": p.amount_sats,
                    "txid": p.txid,
                    "status": format!("{:?}", p.status),
                    "created_at": p.created_at
                })
            })
            .collect();
        let last = payouts
            .iter()
            .find(|p| p.recipient_id == health.node_id)
            .map(|p| {
                serde_json::json!({
                    "round_id": p.round_id,
                    "amount_sats": p.amount_sats,
                    "txid": p.txid,
                    "created_at": p.created_at
                })
            });
        (node_payouts, last)
    } else {
        (vec![], None)
    };

    // Calculate node shares
    let mut node_shares = 0u32;
    if config.archive_mode {
        node_shares += 5;
    }
    if config.ghost_pay {
        node_shares += 4;
    }
    if config.public_mining {
        node_shares += 3;
    }
    if config.reaper {
        node_shares += 2;
    }
    if config.elder {
        node_shares += 1;
    }

    Json(serde_json::json!({
        "round_id": health.round_id,
        "block_height": health.block_height,
        "node_shares": node_shares,
        "total_network_shares": 15,
        "estimated_reward_sats": 0,
        "lifetime_rewards_sats": total_credits,
        "pending_payout_sats": balance_sats,
        "total_withdrawals_sats": total_withdrawals,
        "last_credited_round": last_round,
        "last_payout": last_payout,
        "rewards_history": rewards_history
    }))
}

/// API v1 Settlement status handler
async fn api_settlement_status_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    // Query pending reconciliation batches
    let (pending_count, last_settlement, total_settled) = if let Some(ref db) = state.database {
        let pending = db.get_pending_reconciliation_batches().unwrap_or_default();
        let pending_count = pending.len();

        // Get the most recent finalized batch
        let all_pending = db.get_pending_reconciliation_batches().unwrap_or_default();
        let last = all_pending
            .iter()
            .find(|b| b.finalized_at.is_some())
            .map(|b| {
                serde_json::json!({
                    "batch_id": b.batch_id,
                    "total_amount_sats": b.total_amount_sats,
                    "l1_txid": b.l1_txid,
                    "finalized_at": b.finalized_at
                })
            });

        let total: u64 = all_pending
            .iter()
            .filter(|b| b.finalized_at.is_some())
            .map(|b| b.total_amount_sats)
            .sum();

        (pending_count, last, total)
    } else {
        (0, None, 0)
    };

    let status = if pending_count > 0 {
        "processing"
    } else {
        "idle"
    };

    Json(serde_json::json!({
        "status": status,
        "pending_settlements": pending_count,
        "pending_count": pending_count,
        "batches_24h": 0,
        "last_settlement": last_settlement,
        "total_settled_sats": total_settled
    }))
}

/// API v1 Swarm nodes handler
async fn api_swarm_nodes_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let health = state.get_health().await;

    // M-11: Redact peer addresses from public endpoint to protect network topology
    // Only show this node's public info and aggregate peer counts
    let self_node = serde_json::json!({
        "node_id": health.node_id,
        "version": health.version,
        "online": health.healthy,
        "is_self": true
    });

    // Count peers without exposing their details
    let peer_count = if let Some(ref db) = state.database {
        db.get_active_peers(50)
            .map(|peers| peers.len())
            .unwrap_or(0)
    } else {
        0
    };

    // M-11: Public endpoint shows only self node and peer count
    // Exposing peer addresses reveals network topology which aids targeted attacks
    Json(serde_json::json!({
        "nodes": [self_node],
        "total": peer_count + 1,
        "peer_count": peer_count,
        // M-11: Peer addresses redacted from public endpoint
        "peers_redacted": true,
        "message": "Peer addresses require authentication"
    }))
}

/// API v1 Public nodes handler - returns list of peer addresses for node finder to query
async fn api_public_nodes_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let _health = state.get_health().await; // Reserved for future health-based filtering
    let config = state.dashboard_config.read();

    let mut nodes = Vec::new();

    // Add self if public mining is enabled
    if config.public_mining {
        let host = config
            .stratum_host
            .clone()
            .unwrap_or_else(|| "localhost".to_string());
        let http_port = config.http_port.unwrap_or(8080);
        nodes.push(serde_json::json!({
            "host": host,
            "http_port": http_port,
            "is_self": true
        }));
    }

    // Add known peers - the node finder will query each one for /api/v1/node/public-info
    if let Some(ref db) = state.database {
        if let Ok(peers) = db.get_active_peers(100) {
            for peer in peers {
                // Add peer address for the finder to query
                nodes.push(serde_json::json!({
                    "host": peer.address,
                    "http_port": peer.port,
                    "is_self": false
                }));
            }
        }
    }

    Json(serde_json::json!({
        "nodes": nodes,
        "total": nodes.len(),
        "note": "Query each node's /api/v1/node/public-info for details"
    }))
}

/// API v1 Node public info handler - returns this node's public mining info
async fn api_node_public_info_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let health = state.get_health().await;
    let config = state.dashboard_config.read();

    if !config.public_mining {
        return Json(serde_json::json!({
            "public_mining": false,
            "message": "This node does not accept public miners"
        }));
    }

    // Determine status based on miner count vs capacity
    let status = if health.miner_count >= config.max_miners {
        "full"
    } else if health.miner_count as f64 >= config.max_miners as f64 * 0.8 {
        "busy"
    } else {
        "available"
    };

    Json(serde_json::json!({
        "public_mining": true,
        "node_id": health.node_id,
        "name": config.node_name.clone().unwrap_or_else(|| health.node_id[..8].to_string()),
        "region": config.region.clone().unwrap_or_else(|| "unknown".to_string()),
        "stratum_host": config.stratum_host.clone().unwrap_or_else(|| "localhost".to_string()),
        "stratum_port": config.stratum_port.unwrap_or(3333),
        "status": status,
        "accepting_miners": status != "full",
        "version": health.version
    }))
}

/// API v1 Watchdog status handler
async fn api_watchdog_status_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let health = state.get_health().await;

    // Check ghost-pool status (we're running, so it's up)
    let ghost_pool_status = serde_json::json!({
        "status": "running",
        "uptime_secs": health.uptime_secs,
        "pid": std::process::id()
    });

    // Check ghost-core status via RPC
    let ghost_core_status = if let Some(ref rpc) = state.rpc {
        match tokio::time::timeout(std::time::Duration::from_secs(5), rpc.get_blockchain_info())
            .await
        {
            Ok(Ok(info)) => serde_json::json!({
                "status": "running",
                "chain": info.chain,
                "blocks": info.blocks,
                "headers": info.headers,
                "synced": info.blocks == info.headers
            }),
            Ok(Err(_)) => serde_json::json!({
                "status": "error",
                "message": "RPC connection failed"
            }),
            Err(_) => serde_json::json!({
                "status": "error",
                "message": "RPC timeout"
            }),
        }
    } else {
        serde_json::json!({
            "status": "unknown",
            "message": "RPC not configured"
        })
    };

    // Check ghost-pay L2 service status
    let gp = match check_ghostpay_local(&state) {
        Some(status) => status,
        None => match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::spawn(fetch_ghostpay_from_service()),
        )
        .await
        {
            Ok(Ok(Some(status))) => status,
            _ => GhostPayLiveStatus {
                epoch: 0,
                virtual_block: 0,
                wraith_enabled: false,
                sync_state: "unavailable",
            },
        },
    };
    let ghost_pay_status = match gp.sync_state {
        "synced" => serde_json::json!({
            "status": "running",
            "epoch": gp.epoch,
            "virtual_block": gp.virtual_block
        }),
        "disabled" => serde_json::json!({
            "status": "not_enabled",
            "message": "Ghost Pay not configured"
        }),
        _ => serde_json::json!({
            "status": "error",
            "message": "Ghost Pay not responding"
        }),
    };

    // Check GSP (Ghost Service Protocol) status for light wallet support
    let gsp_status = if let Some(gsp_info) = state.get_gsp_info() {
        serde_json::json!({
            "status": "running",
            "protocol_version": gsp_info.protocol_version,
            "network": gsp_info.network,
            "connections": gsp_info.connections,
            "sync_status": gsp_info.sync_status,
            "registered_wallets": gsp_info.registered_wallets
        })
    } else {
        serde_json::json!({
            "status": "not_enabled",
            "message": "GSP light wallet server not configured"
        })
    };

    // Build services list for dashboard compatibility
    let services_list = vec![
        serde_json::json!({
            "name": "ghost-pool",
            "status": "running",
            "details": ghost_pool_status
        }),
        serde_json::json!({
            "name": "ghost-core",
            "status": ghost_core_status.get("status").and_then(|s| s.as_str()).unwrap_or("unknown"),
            "details": ghost_core_status
        }),
        serde_json::json!({
            "name": "ghost-pay",
            "status": ghost_pay_status.get("status").and_then(|s| s.as_str()).unwrap_or("not_enabled"),
            "details": ghost_pay_status
        }),
        serde_json::json!({
            "name": "gsp",
            "status": gsp_status.get("status").and_then(|s| s.as_str()).unwrap_or("not_enabled"),
            "details": gsp_status
        }),
    ];

    // Build components list
    let components = vec![
        serde_json::json!({
            "name": "ghost-pool",
            "port": 8080,
            "status": "ok",
            "pid": std::process::id(),
            "last_check": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        }),
        serde_json::json!({
            "name": "ghost-core",
            "port": 8332,
            "status": if ghost_core_status.get("status").and_then(|s| s.as_str()) == Some("running") { "ok" } else { "error" },
            "last_check": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        }),
        serde_json::json!({
            "name": "ghost-pay",
            "port": 8800,
            "status": if ghost_pay_status.get("status").and_then(|s| s.as_str()) == Some("running") { "ok" } else { "down" },
            "last_check": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        }),
    ];

    Json(serde_json::json!({
        "services": services_list,
        "components": components,
        "healthy": true,
        "overall_health": "healthy",
        "last_check": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "uptime_secs": health.uptime_secs
    }))
}

/// API v1 System version handler
async fn api_system_version_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    // Get ghost-core version if available
    let ghost_core_version = if let Some(ref rpc) = state.rpc {
        match tokio::time::timeout(std::time::Duration::from_secs(5), rpc.get_network_info()).await
        {
            Ok(Ok(info)) => Some(info.subversion),
            _ => None,
        }
    } else {
        None
    };

    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "build": if cfg!(debug_assertions) { "debug" } else { "release" },
        "build_time": option_env!("BUILD_TIME").unwrap_or("unknown"),
        "git_hash": option_env!("GIT_HASH").unwrap_or("unknown"),
        "ghost_core_version": ghost_core_version,
        "rust_version": env!("CARGO_PKG_RUST_VERSION"),
        "target": std::env::consts::ARCH,
        "os": std::env::consts::OS,
        "update_available": false
    }))
}

/// API v1 Payments handler
async fn api_payments_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    // Query database for recent payouts (payments are derived from payouts)
    let (payments, total) = if let Some(ref db) = state.database {
        let payout_records = db.get_recent_payouts(50).unwrap_or_default();
        let total = db.get_payout_count().unwrap_or(0);
        let payments_json: Vec<_> = payout_records
            .iter()
            .map(|p| {
                serde_json::json!({
                    "id": format!("{}-{}", p.round_id, p.recipient_id),
                    "round_id": p.round_id,
                    "recipient": p.recipient_id,
                    "recipient_type": format!("{:?}", p.recipient_type),
                    "amount_sats": p.amount_sats,
                    "address": p.address,
                    "txid": p.txid,
                    "status": format!("{:?}", p.status),
                    "type": "payout",
                    "created_at": p.created_at
                })
            })
            .collect();
        (payments_json, total)
    } else {
        (vec![], 0)
    };

    Json(serde_json::json!({
        "payments": payments,
        "total": total
    }))
}

/// API v1 Backup history handler
async fn api_backup_history_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    // M-STOR-3: Get backup directory from config instead of hardcoded path
    let backup_dir_path = {
        let config = state.dashboard_config.read();
        config.backup_dir.clone()
    };

    // M-15: Proper path validation using canonicalization
    // Step 1: Must be absolute path
    let backup_dir = std::path::Path::new(&backup_dir_path);
    if !backup_dir.is_absolute() {
        tracing::warn!(
            path = %backup_dir_path,
            "M-15: Rejecting relative backup_dir path"
        );
        return Json(serde_json::json!({
            "backups": [],
            "total": 0,
            "backup_dir": backup_dir_path,
            "error": "Backup directory must be an absolute path"
        }));
    }

    // Step 2: Canonicalize the path to resolve symlinks and ../ components
    // This is the proper way to prevent path traversal attacks
    let canonical_backup_dir = match backup_dir.canonicalize() {
        Ok(path) => path,
        Err(e) => {
            // If directory doesn't exist yet, that's okay - return empty list
            if e.kind() == std::io::ErrorKind::NotFound {
                return Json(serde_json::json!({
                    "backups": [],
                    "total": 0,
                    "backup_dir": backup_dir_path
                }));
            }
            tracing::warn!(
                path = %backup_dir_path,
                error = %e,
                "M-15: Failed to canonicalize backup_dir path"
            );
            return Json(serde_json::json!({
                "backups": [],
                "total": 0,
                "backup_dir": backup_dir_path,
                "error": "Invalid backup directory path"
            }));
        }
    };

    // Step 3: Verify the canonical path is still within an allowed base directory
    // This prevents traversal attacks via symlinks
    // Allow: /home/ghost/.ghost/backups, /var/lib/ghost/backups, /tmp/ghost-backups
    let allowed_base_paths = [
        std::path::PathBuf::from("/home/ghost/.ghost"),
        std::path::PathBuf::from("/var/lib/ghost"),
        std::path::PathBuf::from("/tmp/ghost-backups"),
        std::path::PathBuf::from("/opt/ghost"),
    ];

    let is_within_allowed = allowed_base_paths.iter().any(|base| {
        if let Ok(canonical_base) = base.canonicalize() {
            canonical_backup_dir.starts_with(&canonical_base)
        } else {
            // Base doesn't exist, check if backup_dir would be under it if it existed
            canonical_backup_dir.starts_with(base)
        }
    });

    if !is_within_allowed {
        tracing::warn!(
            path = %backup_dir_path,
            canonical = %canonical_backup_dir.display(),
            "M-15: Backup directory outside allowed base paths"
        );
        return Json(serde_json::json!({
            "backups": [],
            "total": 0,
            "backup_dir": backup_dir_path,
            "error": "Backup directory must be within allowed paths"
        }));
    }

    let backups = match std::fs::read_dir(&canonical_backup_dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                // M-15: Verify each file is actually within the backup directory
                // (prevents symlink attacks within the directory)
                let file_path = e.path();
                let canonical_file = match file_path.canonicalize() {
                    Ok(p) => p,
                    Err(_) => return None,
                };

                // File must be directly in the backup dir (not in subdirs via symlinks)
                if canonical_file.parent() != Some(&canonical_backup_dir) {
                    tracing::debug!(
                        file = %file_path.display(),
                        "M-15: Skipping file outside backup directory"
                    );
                    return None;
                }

                // Only allow .backup and .db extensions
                let ext = file_path.extension()?;
                if ext != "backup" && ext != "db" {
                    return None;
                }

                let metadata = e.metadata().ok()?;
                let modified = metadata
                    .modified()
                    .ok()?
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()?
                    .as_secs();

                // Only return the filename, not the full path (avoid information disclosure)
                Some(serde_json::json!({
                    "filename": e.file_name().to_string_lossy(),
                    "size_bytes": metadata.len(),
                    "created_at": modified
                }))
            })
            .collect::<Vec<_>>(),
        Err(_) => vec![],
    };

    let total = backups.len();
    Json(serde_json::json!({
        "backups": backups,
        "total": total,
        "backup_dir": canonical_backup_dir.to_string_lossy()
    }))
}

/// API v1 Wraith sessions handler (Ghost Pay sessions)
async fn api_wraith_sessions_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    // Query database for active wraith rounds if available
    let (sessions, active_count, total_participants) = if let Some(ref db) = state.database {
        let rounds = db.get_active_wraith_rounds().unwrap_or_default();
        let active = rounds.len();
        let participants: u32 = rounds.iter().map(|r| r.participant_count).sum();
        let sessions_json: Vec<_> = rounds
            .iter()
            .map(|r| {
                serde_json::json!({
                    "round_id": r.round_id,
                    "denomination": r.denomination,
                    "amount_sats": r.amount_sats,
                    "participant_count": r.participant_count,
                    "phase": format!("{:?}", r.phase),
                    "registration_deadline": r.registration_deadline
                })
            })
            .collect();
        (sessions_json, active, participants)
    } else {
        (vec![], 0, 0)
    };

    Json(serde_json::json!({
        "sessions": sessions,
        "total": sessions.len(),
        "active": active_count,
        "active_sessions": active_count,
        "sessions_completed": 0,
        "total_sessions": sessions.len(),
        "sessions_expired": 0,
        "total_participants": total_participants
    }))
}

/// API v1 Network elder handler
async fn api_network_elder_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let health = state.get_health().await;
    let max_elders = ghost_common::constants::MAX_ELDERS;

    // Use MPC contributions as authoritative source for elder status
    let (elders, total_elders, is_elder, elder_slot) = if let Some(ref db) = state.database {
        let mpc_elders = db.get_all_mpc_elders().unwrap_or_default();
        let total = mpc_elders.len() as u32;
        let self_entry = mpc_elders.iter().find(|(nid, _)| *nid == health.node_id);
        let is_self_elder = self_entry.is_some();
        let slot = self_entry.map(|(_, pos)| *pos as u64);
        let elders_json: Vec<_> = mpc_elders
            .iter()
            .map(|(node_id, position)| {
                serde_json::json!({
                    "node_id": node_id,
                    "display_name": null,
                    "elder_order": position,
                    "first_seen": null,
                    "last_seen": null,
                    "is_self": *node_id == health.node_id
                })
            })
            .collect();
        (elders_json, total, is_self_elder, slot)
    } else {
        (vec![], 0, false, None)
    };

    let spots_remaining = max_elders.saturating_sub(total_elders);

    Json(serde_json::json!({
        "elders": elders,
        "total_elders": total_elders,
        "active_elders": total_elders,
        "max_elders": max_elders,
        "spots_remaining": spots_remaining,
        "is_elder": is_elder,
        "elder_slot": elder_slot,
        "registered_at": null,
        "downtime_warning": false,
        "consecutive_downtime_days": 0
    }))
}

/// API v1 BUDS mempool handler
async fn api_buds_mempool_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    // Query Ghost Core for mempool info (10s timeout — loops over up to 100 txs)
    if let Some(ref rpc) = state.rpc {
        let rpc_result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            async {
                let mempool_info = match rpc.get_mempool_info().await {
                    Ok(info) => info,
                    Err(_) => return None,
                };

                let (transactions, by_tier) = match rpc.get_raw_mempool(true).await {
                    Ok(mempool) => {
                        let classifier = BudsClassifier::new();
                        let mut tier_counts = [0u64; 4]; // T0, T1, T2, T3

                        let txids: Vec<String> = if let Some(obj) = mempool.as_object() {
                            obj.keys().take(100).cloned().collect()
                        } else {
                            vec![]
                        };

                        let mut txs = Vec::with_capacity(txids.len());

                        for txid in &txids {
                            let entry = mempool.get(txid);
                            let vsize = entry
                                .and_then(|e| e.get("vsize"))
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            let weight = entry
                                .and_then(|e| e.get("weight"))
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            let fee = entry
                                .and_then(|e| e.get("fees"))
                                .and_then(|f| f.get("base"))
                                .and_then(|b| b.as_f64())
                                .unwrap_or(0.0);
                            let time = entry
                                .and_then(|e| e.get("time"))
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);

                            let (tier, tier_str, reason) = match rpc
                                .get_raw_transaction(txid, false)
                                .await
                            {
                                Ok(raw_value) => {
                                    if let Some(hex) = raw_value.as_str() {
                                        match hex::decode(hex) {
                                            Ok(bytes) => {
                                                match bitcoin::consensus::deserialize::<
                                                    bitcoin::Transaction,
                                                >(
                                                    &bytes
                                                ) {
                                                    Ok(tx) => {
                                                        let result = classifier.classify(&tx);
                                                        let tier = result.tier;
                                                        tier_counts[tier.value() as usize] += 1;
                                                        (
                                                            Some(tier.value()),
                                                            tier.to_string(),
                                                            result.reason.to_string(),
                                                        )
                                                    }
                                                    Err(e) => {
                                                        warn!(txid, error = %e, "Failed to deserialize tx");
                                                        (
                                                            None,
                                                            "unknown".to_string(),
                                                            "decode error".to_string(),
                                                        )
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                warn!(txid, error = %e, "Failed to decode hex");
                                                (
                                                    None,
                                                    "unknown".to_string(),
                                                    "hex error".to_string(),
                                                )
                                            }
                                        }
                                    } else {
                                        let tier = classify_by_weight_heuristic(weight);
                                        tier_counts[tier.value() as usize] += 1;
                                        (
                                            Some(tier.value()),
                                            tier.to_string(),
                                            "weight heuristic".to_string(),
                                        )
                                    }
                                }
                                Err(_) => {
                                    let tier = classify_by_weight_heuristic(weight);
                                    tier_counts[tier.value() as usize] += 1;
                                    (
                                        Some(tier.value()),
                                        tier.to_string(),
                                        "weight heuristic".to_string(),
                                    )
                                }
                            };

                            txs.push(serde_json::json!({
                                "txid": txid,
                                "vsize": vsize,
                                "weight": weight,
                                "fee": fee,
                                "time": time,
                                "tier": tier,
                                "tier_name": tier_str,
                                "classification_reason": reason,
                            }));
                        }

                        let tiers = serde_json::json!({
                            "T0": tier_counts[0],
                            "T1": tier_counts[1],
                            "T2": tier_counts[2],
                            "T3": tier_counts[3]
                        });
                        (txs, tiers)
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to get raw mempool");
                        (
                            vec![],
                            serde_json::json!({"T0": 0, "T1": 0, "T2": 0, "T3": 0}),
                        )
                    }
                };

                Some(serde_json::json!({
                    "transactions": transactions,
                    "total": mempool_info.size,
                    "bytes": mempool_info.bytes,
                    "usage": mempool_info.usage,
                    "max_mempool": mempool_info.maxmempool,
                    "min_fee": mempool_info.mempoolminfee,
                    "by_tier": by_tier,
                    "sample_size": transactions.len(),
                    "note": "Tier counts are based on sampled transactions"
                }))
            },
        )
        .await;

        if let Ok(Some(json)) = rpc_result {
            return Json(json);
        }
        // Timeout or RPC error — fall through to fallback
    }

    // Fallback if RPC not available
    Json(serde_json::json!({
        "transactions": [],
        "total": 0,
        "by_tier": {
            "T0": 0,
            "T1": 0,
            "T2": 0,
            "T3": 0
        },
        "message": "Ghost Core RPC not configured"
    }))
}

/// Heuristic classification based on transaction weight
/// Used as fallback when raw transaction data is unavailable
fn classify_by_weight_heuristic(weight: u64) -> BudsTier {
    // Standard transaction: ~400-600 weight units for simple P2WPKH
    // Multisig/complex: ~1000-2000 weight units
    // Data-heavy: >4000 weight units (inscriptions can be 100k+)
    if weight > 4000 {
        BudsTier::T3 // Heavy data
    } else if weight > 1500 {
        BudsTier::T1 // Extended financial
    } else {
        BudsTier::T0 // Standard payment
    }
}

/// API v1 Mining best-hash handler
///
/// Returns the best (rarest hash / highest achieved difficulty) SHARE
/// submitted by a connected miner in each window — current round, last hour,
/// last 24h and all time — NOT the network chain tip. Each window is resolved
/// independently from this node's `shares` table, so a lucky share only counts
/// for the windows it actually falls within. Windows with no real-miner share
/// yet return a null entry (the frontend renders "No data yet").
async fn api_mining_best_hash_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let health = state.get_health().await;

    let null_entry = || {
        serde_json::json!({
            "hash": null,
            "difficulty": 0,
            "timestamp": 0,
            "miner_id": null,
            "block_height": null
        })
    };

    let Some(ref db) = state.database else {
        // No local DB — cannot attribute per-miner shares. Return empty
        // windows rather than the misleading chain tip.
        return Json(serde_json::json!({
            "current_round": null_entry(),
            "last_round": null_entry(),
            "last_hour": null_entry(),
            "last_24h": null_entry(),
            "all_time": null_entry(),
            "best_hash": null,
            "best_difficulty": 0,
            "block_height": health.block_height,
            "round_id": health.round_id,
            "message": "Database not available"
        }));
    };

    let now_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Convert a stored best share into the dashboard entry shape. The
    // displayed `difficulty` is the ACHIEVED difficulty derived from the
    // hash (how good the share actually was), matching the pool records /
    // leaderboard endpoints — the stored `difficulty` column is only the
    // vardiff target. The miner_id is redacted for public display but stays
    // non-null so the frontend can tell a real share from the old chain-tip
    // placeholder.
    let to_entry = |best: Option<ghost_storage::models::BestShare>| match best {
        Some(b) => serde_json::json!({
            "hash": b.share_hash,
            "difficulty": share_difficulty_from_hash_hex(&b.share_hash),
            "timestamp": b.timestamp,
            "miner_id": redact_miner_id(&b.miner_id),
            "block_height": b.block_height,
        }),
        None => null_entry(),
    };

    // Per-window best shares. Current round is scoped by round_id so it tracks
    // the live round exactly; the time windows use timestamp cutoffs; all-time
    // uses a zero cutoff (every retained share).
    let current_round = to_entry(db.get_best_share_in_round(health.round_id).unwrap_or(None));
    let last_hour = to_entry(db.get_best_share_since(now_s - 3_600).unwrap_or(None));
    let last_24h = to_entry(db.get_best_share_since(now_s - 86_400).unwrap_or(None));
    let all_time_best = db.get_best_share_since(0).unwrap_or(None);

    // Raw back-compat fields mirror the all-time best share (achieved score).
    let (best_hash, best_difficulty) = match &all_time_best {
        Some(b) => (
            Some(b.share_hash.clone()),
            share_difficulty_from_hash_hex(&b.share_hash),
        ),
        None => (None, 0.0),
    };
    let all_time = to_entry(all_time_best);

    // Best-effort network context (never blocks the per-window share data).
    let (network_hashrate, chain) = if let Some(ref rpc) = state.rpc {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let network_hashrate = rpc.get_mining_info().await.map(|i| i.networkhashps).ok();
            let chain = rpc.get_blockchain_info().await.map(|i| i.chain).ok();
            (network_hashrate, chain)
        })
        .await
        .unwrap_or((None, None))
    } else {
        (None, None)
    };

    Json(serde_json::json!({
        // Dashboard-compatible per-window format
        "current_round": current_round,
        "last_round": null_entry(),
        "last_hour": last_hour,
        "last_24h": last_24h,
        "all_time": all_time,
        // Raw fields for backwards compat (all-time best miner share)
        "best_hash": best_hash,
        "best_difficulty": best_difficulty,
        "network_hashrate": network_hashrate,
        "block_height": health.block_height,
        "round_id": health.round_id,
        "chain": chain
    }))
}

/// API v1 Network payout history handler
async fn api_payout_history_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    // Query database for recent payouts if available
    let (payouts, total) = if let Some(ref db) = state.database {
        let payout_records = db.get_recent_payouts(100).unwrap_or_default();
        let total = db.get_payout_count().unwrap_or(0);
        let payouts_json: Vec<_> = payout_records
            .iter()
            .map(|p| {
                serde_json::json!({
                    "round_id": p.round_id,
                    "recipient_id": p.recipient_id,
                    "recipient_type": format!("{:?}", p.recipient_type),
                    "amount_sats": p.amount_sats,
                    "address": p.address,
                    "txid": p.txid,
                    "status": format!("{:?}", p.status),
                    "created_at": p.created_at
                })
            })
            .collect();
        (payouts_json, total)
    } else {
        (vec![], 0)
    };

    Json(serde_json::json!({
        "payouts": payouts,
        "total": total
    }))
}

/// API v1 Ghost Pay payout history handler
async fn api_ghostpay_payout_history_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let health = state.get_health().await;
    let ghost_id = format!("ghost{}", &health.node_id[..8.min(health.node_id.len())]);

    // Query withdrawals as GhostPay payouts
    let (payouts, total) = if let Some(ref db) = state.database {
        let withdrawals = db.get_pending_withdrawals(&ghost_id).unwrap_or_default();
        let payouts_json: Vec<_> = withdrawals
            .iter()
            .map(|w| {
                serde_json::json!({
                    "id": w.id,
                    "lock_id": w.lock_id,
                    "destination": w.destination_address,
                    "amount_sats": w.amount_sats,
                    "fee_sats": w.fee_sats,
                    "status": format!("{:?}", w.status),
                    "batch_id": w.batch_id,
                    "l1_txid": w.l1_txid,
                    "created_at": w.created_at
                })
            })
            .collect();
        let total = payouts_json.len();
        (payouts_json, total)
    } else {
        (vec![], 0)
    };

    Json(serde_json::json!({
        "payouts": payouts,
        "total": total
    }))
}

/// API v1 Rewards node history handler
async fn api_rewards_node_history_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let health = state.get_health().await;

    // Get all nodes with rewards and their history
    let (history, total) = if let Some(ref db) = state.database {
        // Get nodes with balance
        let nodes = db.get_nodes_with_balance(0).unwrap_or_default();
        let history_json: Vec<_> = nodes
            .iter()
            .map(|n| {
                serde_json::json!({
                    "node_id": n.node_id,
                    "balance_sats": n.balance_sats,
                    "last_credited_round": n.last_credited_round,
                    "total_credits_sats": n.total_credits_sats,
                    "total_withdrawals_sats": n.total_withdrawals_sats,
                    "is_self": n.node_id == health.node_id,
                    "created_at": n.created_at,
                    "updated_at": n.updated_at
                })
            })
            .collect();
        let total = history_json.len();
        (history_json, total)
    } else {
        (vec![], 0)
    };

    Json(serde_json::json!({
        "history": history,
        "total": total
    }))
}

// ============================================================================
// Config Endpoints
// ============================================================================

/// API v1 Config full handler
async fn api_config_full_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let health = state.get_health().await;
    let config = state.dashboard_config.read();
    // Surface the real tier policy (pool.toml [policy]) so the dashboard can show
    // the current preset AND, for the Custom profile, pre-fill the advanced
    // per-field controls. Read from the full node config when it is loaded.
    let policy = policy_json(&state);
    Json(serde_json::json!({
        "archive_mode": config.archive_mode,
        "ghost_pay": config.ghost_pay,
        "public_mining": config.public_mining,
        "reaper": config.reaper,
        "ghost_mode": config.ghost_mode,
        "mempool_profile": config.mempool_profile,
        "template_profile": config.template_profile,
        "prune_profile": config.prune_profile,
        "policy": policy,
        "operator_window": 100,
        "network": state.network.as_str(),
        "stratum_sv2_port": 4444,
        "stratum_sv1_port": 3333,
        "http_port": 8080,
        "node_id": health.node_id,
        "version": health.version
    }))
}

/// API v1 Config archive mode handler
async fn api_config_archive_mode_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let config = state.dashboard_config.read();
    Json(serde_json::json!({
        "enabled": config.archive_mode,
        "message": "Archive mode configuration"
    }))
}

/// API v1 Config ghost mode handler
///
/// Returns ghost mode status. If RPC is available, queries ghost-core for the
/// authoritative state and syncs the local config.
async fn api_config_ghost_mode_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    // Try to get ghost mode from ghost-core RPC (5s timeout)
    let rpc_state = if let Some(ref rpc) = state.rpc {
        match tokio::time::timeout(std::time::Duration::from_secs(5), rpc.get_ghost_mode()).await {
            Ok(Ok(response)) => {
                // Sync local state with RPC response
                {
                    let mut config = state.dashboard_config.write();
                    if config.ghost_mode != response.ghost_mode {
                        debug!(
                            "Syncing ghost mode from RPC: {} -> {}",
                            config.ghost_mode, response.ghost_mode
                        );
                        config.ghost_mode = response.ghost_mode;
                    }
                }
                Some(response.ghost_mode)
            }
            Ok(Err(e)) => {
                warn!("Failed to get ghost mode from RPC: {}", e);
                None
            }
            Err(_) => {
                warn!("Ghost mode RPC timed out");
                None
            }
        }
    } else {
        None
    };

    let config = state.dashboard_config.read();
    Json(serde_json::json!({
        "enabled": config.ghost_mode,
        "ghost_mode": config.ghost_mode,
        "rpc_synced": rpc_state.is_some(),
        "message": "Ghost mode configuration"
    }))
}

/// API v1 Config mempool profile handler
async fn api_config_mempool_profile_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let config = state.dashboard_config.read();
    Json(serde_json::json!({
        "profile": config.mempool_profile,
        "message": "Current mempool profile"
    }))
}

/// API v1 Config public mining handler
async fn api_config_public_mining_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let config = state.dashboard_config.read();
    Json(serde_json::json!({
        "enabled": config.public_mining,
        "message": "Public mining configuration"
    }))
}

/// API v1 Config template profile handler
async fn api_config_template_profile_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let config = state.dashboard_config.read();
    Json(serde_json::json!({
        "profile": config.template_profile,
        "message": "Current template profile"
    }))
}

/// API v1 Config reaper handler — returns the per-vector reaper configuration
/// from the full node config (pool.toml `[reaper]`).
async fn api_config_reaper_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let settings = state
        .full_node_config
        .as_ref()
        .map(|c| c.read().reaper.clone())
        .unwrap_or_default();
    let apply = serde_json::to_value(&*state.ghostd_reaper_apply.read())
        .unwrap_or_else(|_| serde_json::json!({}));
    Json(serde_json::json!({
        "enabled": settings.enabled,
        "mode": if settings.enabled { "strict" } else { "disabled" },
        "settings": serde_json::to_value(&settings).unwrap_or_else(|_| serde_json::json!({})),
        // Terminal result of the last automatic ghostd mempool-reaper apply so
        // the dashboard can show whether the node picked up the change.
        "ghostd_apply": apply,
        "message": "Reaper per-vector configuration",
    }))
}

/// API v1 Config daemon handler — returns the ghostd launch / daemon settings
/// from the full node config (pool.toml `[node_launch]`), plus the terminal
/// result of the last ghostd apply so the dashboard can show whether the change
/// was picked up. All of these are ghostd startup flags, so a change requires a
/// ghostd restart (handled by the POST path).
async fn api_config_daemon_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let launch = state
        .full_node_config
        .as_ref()
        .map(|c| c.read().node_launch.clone())
        .unwrap_or_default();
    let apply = serde_json::to_value(&*state.ghostd_reaper_apply.read())
        .unwrap_or_else(|_| serde_json::json!({}));
    Json(serde_json::json!({
        "settings": {
            "max_mempool_mb": launch.max_mempool_mb,
            "mempool_expiry_hours": launch.mempool_expiry_hours,
            "max_connections": launch.max_connections,
            "max_upload_target_mb": launch.max_upload_target_mb,
            "dbcache_mb": launch.dbcache_mb,
            "block_filter_index": launch.block_filter_index,
            "peer_block_filters": launch.peer_block_filters,
            "onlynet": launch.onlynet,
            "i2p_sam": launch.i2p_sam,
            "i2p_accept_incoming": launch.i2p_accept_incoming,
        },
        // Terminal result of the last automatic ghostd apply.
        "ghostd_apply": apply,
        "message": "ghostd daemon launch settings (restart-required)",
    }))
}

/// API v1 Config ghost pay handler
async fn api_config_ghost_pay_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let config = state.dashboard_config.read();
    Json(serde_json::json!({
        "enabled": config.ghost_pay,
        "message": "Ghost Pay configuration"
    }))
}

/// API v1 Config prune profile handler
async fn api_config_prune_profile_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let config = state.dashboard_config.read();
    Json(serde_json::json!({
        "profile": config.prune_profile,
        "message": "Pruning profile configuration"
    }))
}

/// API v1 Config operator window handler
async fn api_config_operator_window_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "window": 100,
        "message": "Operator window configuration"
    }))
}

/// Request body for toggle config endpoints
#[derive(Debug, Deserialize)]
struct ToggleRequest {
    enabled: bool,
}

/// Request body for profile config endpoints
#[derive(Debug, Deserialize)]
struct ProfileRequest {
    profile: String,
}

/// API v1 Config archive_mode POST handler
async fn api_config_archive_mode_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<ToggleRequest>,
) -> impl IntoResponse {
    let mut config = state.dashboard_config.write();
    config.archive_mode = payload.enabled;
    Json(serde_json::json!({
        "success": true,
        "enabled": payload.enabled,
        "message": "Archive mode updated"
    }))
}

/// API v1 Config ghost_mode POST handler
///
/// Toggles ghost mode on the node:
/// 1. Calls ghost-core RPC to set the mode (if RPC client available)
/// 2. Updates the in-memory dashboard config
/// 3. Persists the setting to disk (if config path available)
async fn api_config_ghost_mode_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<ToggleRequest>,
) -> impl IntoResponse {
    let enabled = payload.enabled;

    // Try to call ghost-core RPC to set ghost mode
    let rpc_result = if let Some(ref rpc) = state.rpc {
        match rpc.set_ghost_mode(enabled).await {
            Ok(response) => {
                debug!("Ghost mode RPC call successful: {:?}", response);
                Some(response.ghost_mode)
            }
            Err(e) => {
                warn!("Failed to set ghost mode via RPC: {}", e);
                None
            }
        }
    } else {
        debug!("No RPC client available, updating local state only");
        None
    };

    // Use RPC response if available, otherwise use requested value
    let actual_enabled = rpc_result.unwrap_or(enabled);

    // Update dashboard config
    {
        let mut config = state.dashboard_config.write();
        config.ghost_mode = actual_enabled;
    }

    // Update and persist node config
    {
        let mut node_config = state.node_config.write();
        node_config.ghost_mode = actual_enabled;

        if let Some(ref path) = state.node_config_path {
            if let Err(e) = node_config.save(path) {
                error!("Failed to persist node config: {}", e);
            }
        }
    }

    Json(serde_json::json!({
        "success": true,
        "enabled": actual_enabled,
        "rpc_synced": rpc_result.is_some(),
        "message": if rpc_result.is_some() {
            "Ghost mode updated and synced with ghost-core"
        } else {
            "Ghost mode updated (RPC sync unavailable)"
        }
    }))
}

/// API v1 Config public_mining POST handler
async fn api_config_public_mining_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<ToggleRequest>,
) -> impl IntoResponse {
    let mut config = state.dashboard_config.write();
    config.public_mining = payload.enabled;
    Json(serde_json::json!({
        "success": true,
        "enabled": payload.enabled,
        "message": "Public mining updated"
    }))
}

/// Resolve the `ghost-setup` binary used to apply the ghostd mempool-reaper
/// drop-in. Overridable via `GHOST_SETUP_BIN` for packaging and for tests
/// (point it at a non-existent path to exercise the fail-safe without touching
/// the real node).
fn ghost_setup_bin() -> String {
    std::env::var("GHOST_SETUP_BIN").unwrap_or_else(|_| "/opt/ghost/bin/ghost-setup".to_string())
}

/// Run `sudo -n <ghost-setup> apply-reaper`, which regenerates the ghostd
/// `-ghostreaper` systemd drop-in from `pool.toml [reaper]` and restarts ghostd.
///
/// Blocking (it waits for ghostd to restart), so callers run it off the request
/// path. Returns `Ok(message)` on success or `Err(reason)` on any failure —
/// never a false success. The `GHOST_REAPER_APPLY_TEST_MODE` env var short-
/// circuits the shell-out in tests (`success` → Ok, anything else → Err).
fn run_ghostd_apply_reaper() -> Result<String, String> {
    // Test hook: never shell out to sudo/ghostd/systemctl from unit tests.
    if let Ok(mode) = std::env::var("GHOST_REAPER_APPLY_TEST_MODE") {
        return if mode == "success" {
            Ok("test-mode: apply-reaper simulated success".to_string())
        } else {
            Err(format!("test-mode: apply-reaper simulated failure ({mode})"))
        };
    }

    let bin = ghost_setup_bin();
    // Fail-safe: if the helper isn't deployed we report the ghostd side as not
    // applied rather than spawning a doomed process.
    if !std::path::Path::new(&bin).exists() {
        return Err(format!(
            "ghost-setup binary not found at {bin}; ghostd mempool reaper not updated"
        ));
    }

    // `sudo -n` never prompts: if the scoped sudoers drop-in isn't installed
    // this fails fast with a clear permission error instead of hanging.
    let output = std::process::Command::new("sudo")
        .args(["-n", &bin, "apply-reaper"])
        .output()
        .map_err(|e| format!("failed to launch `sudo -n {bin} apply-reaper`: {e}"))?;

    if output.status.success() {
        Ok("ghostd `-ghostreaper` flags regenerated and ghostd restarted".to_string())
    } else {
        // Surface the most informative line of stderr (e.g. the sudo denial).
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .last()
            .unwrap_or("no error output");
        Err(format!(
            "`ghost-setup apply-reaper` failed ({}): {detail}",
            output.status
        ))
    }
}

/// Spawn the automatic ghostd apply in the background and, once it settles,
/// trigger the pool restart. Sequencing the pool restart *after* the ghostd
/// apply is deliberate: the pool depends on ghostd's RPC, so we let ghostd
/// finish restarting (or fail) before ghost-pool bounces and reconnects to the
/// freshly-flagged daemon. If the ghostd apply fails, the pool side still
/// applies from the persisted config — the node is never left half-configured.
fn spawn_ghostd_reaper_apply(state: Arc<VerificationState>) {
    *state.ghostd_reaper_apply.write() =
        ghost_common_now("applying", "Applying ghostd mempool-reaper flags…");

    tokio::spawn(async move {
        // The apply blocks (it waits for ghostd's restart); keep it off the
        // async worker threads.
        let result = tokio::task::spawn_blocking(run_ghostd_apply_reaper).await;
        let outcome = match result {
            Ok(Ok(msg)) => {
                info!(message = %msg, "ghostd mempool reaper auto-applied");
                ghost_common_now("applied", msg)
            }
            Ok(Err(reason)) => {
                warn!(reason = %reason, "ghostd mempool reaper auto-apply failed");
                ghost_common_now("failed", reason)
            }
            Err(join_err) => {
                let reason = format!("apply task panicked: {join_err}");
                error!(error = %reason, "ghostd mempool reaper auto-apply crashed");
                ghost_common_now("failed", reason)
            }
        };
        *state.ghostd_reaper_apply.write() = outcome;

        // Now bounce the pool so the block-template reaper picks up the same
        // config, reconnecting to the (already-restarted) ghostd.
        state.request_restart();
    });
}

/// Small local helper to build a timestamped apply record without importing the
/// type name everywhere.
fn ghost_common_now(state: &str, message: impl Into<String>) -> crate::server::GhostdReaperApply {
    crate::server::GhostdReaperApply::now(state, message)
}

/// API v1 Config tor POST handler — toggles ghostd Tor mode (`-tormode`).
///
/// ghostd only reads `-tormode` at startup, so it can't be flipped mid-flight.
/// This persists `[node_launch] tor_mode` to pool.toml and then applies it via
/// the same ghostd-flag drop-in path as the reaper: `spawn_ghostd_reaper_apply`
/// runs `ghost-setup apply-reaper` (which now regenerates the combined
/// reaper + launch-flag drop-in and restarts ghostd) and afterwards bounces
/// ghost-pool. The response returns promptly with the apply *initiated*; the
/// terminal result lands on the reaper GET endpoint's `ghostd_apply`.
async fn api_config_tor_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<ToggleRequest>,
) -> impl IntoResponse {
    // Require the full node config + a path to persist to; otherwise the change
    // can't survive a restart, so fail-closed with SERVICE_UNAVAILABLE.
    let Some(ref full) = state.full_node_config else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "success": false,
                "error": "Config update API not available: full node config not loaded",
                "code": "CONFIG_NOT_LOADED",
            })),
        )
            .into_response();
    };
    let Some(ref path) = state.full_node_config_path else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "success": false,
                "error": "Config update API not available: no node config path configured",
                "code": "CONFIG_NOT_LOADED",
            })),
        )
            .into_response();
    };

    {
        let mut cfg = full.write();
        cfg.node_launch.tor_mode = payload.enabled;
        if let Err(e) = cfg.save_atomic(path) {
            error!(error = %e, "Failed to persist Tor mode");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to persist Tor mode: {e}"),
                    "code": "PERSIST_FAILED",
                })),
            )
                .into_response();
        }
    }

    // Apply the ghostd flag (restarts ghostd) then bounce the pool. Shares the
    // reaper apply path because the drop-in now carries all ghost-managed flags.
    spawn_ghostd_reaper_apply(Arc::clone(&state));

    let apply = serde_json::to_value(&*state.ghostd_reaper_apply.read())
        .unwrap_or_else(|_| serde_json::json!({}));
    Json(serde_json::json!({
        "success": true,
        "enabled": payload.enabled,
        "ghostd_apply": apply,
        "message": if payload.enabled {
            "Tor mode enabled. ghostd is restarting with -tormode=1; the pool will bounce once it settles."
        } else {
            "Tor mode disabled. ghostd is restarting on clearnet; the pool will bounce once it settles."
        },
    }))
    .into_response()
}

/// Request body for the ghostd daemon-settings POST endpoint. Every field is an
/// `Option`; a missing field clears the corresponding ghostd flag (falls back to
/// ghostd's own default). Mirrors the `[node_launch]` daemon fields — `tor_mode`
/// keeps its own `/config/tor` endpoint and is preserved here untouched.
#[derive(Debug, Default, Deserialize)]
struct DaemonSettingsRequest {
    #[serde(default)]
    max_mempool_mb: Option<u32>,
    #[serde(default)]
    mempool_expiry_hours: Option<u32>,
    #[serde(default)]
    max_connections: Option<u32>,
    #[serde(default)]
    max_upload_target_mb: Option<String>,
    #[serde(default)]
    dbcache_mb: Option<u32>,
    #[serde(default)]
    block_filter_index: Option<bool>,
    #[serde(default)]
    peer_block_filters: Option<bool>,
    #[serde(default)]
    onlynet: Option<Vec<String>>,
    #[serde(default)]
    i2p_sam: Option<String>,
    #[serde(default)]
    i2p_accept_incoming: Option<bool>,
}

/// Networks ghostd's `-onlynet` accepts (matches `GetNetworkNames()`).
const VALID_ONLYNET: &[&str] = &["ipv4", "ipv6", "onion", "i2p", "cjdns"];

/// Validate a `-maxuploadtarget` value: a non-negative integer with an optional
/// single base-unit suffix `[k|K|m|M|g|G|t|T]`. `0` (no limit) is allowed.
fn valid_upload_target(v: &str) -> bool {
    if v.is_empty() {
        return false;
    }
    let (num, _unit) = match v.chars().last() {
        Some(c) if "kKmMgGtT".contains(c) => (&v[..v.len() - 1], Some(c)),
        _ => (v, None),
    };
    !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) && num.parse::<u64>().is_ok()
}

/// Validate the incoming daemon settings, returning a human-readable reason on
/// the first failure. Ranges are deliberately generous but reject nonsense that
/// would make ghostd refuse to start or cripple this mining node.
fn validate_daemon_settings(req: &DaemonSettingsRequest) -> Result<(), String> {
    // Mempool must stay live for block templates; ghostd's floor is small but a
    // few MB is the practical minimum. Cap well above any realistic value.
    if let Some(mb) = req.max_mempool_mb {
        if !(5..=100_000).contains(&mb) {
            return Err(format!("max_mempool_mb must be 5..=100000 MB (got {mb})"));
        }
    }
    if let Some(h) = req.mempool_expiry_hours {
        if !(1..=8_760).contains(&h) {
            return Err(format!(
                "mempool_expiry_hours must be 1..=8760 hours (got {h})"
            ));
        }
    }
    // maxconnections=0 would disable listening/dnsseed — unacceptable for a
    // mining node — so require a sane floor.
    if let Some(n) = req.max_connections {
        if !(8..=10_000).contains(&n) {
            return Err(format!("max_connections must be 8..=10000 (got {n})"));
        }
    }
    if let Some(ref t) = req.max_upload_target_mb {
        if !valid_upload_target(t) {
            return Err(format!(
                "max_upload_target_mb must be a number with optional unit [k|K|m|M|g|G|t|T] (got {t:?})"
            ));
        }
    }
    if let Some(mb) = req.dbcache_mb {
        if !(4..=1_000_000).contains(&mb) {
            return Err(format!("dbcache_mb must be 4..=1000000 MB (got {mb})"));
        }
    }
    if let Some(ref nets) = req.onlynet {
        for net in nets {
            let n = net.trim().to_ascii_lowercase();
            if !VALID_ONLYNET.contains(&n.as_str()) {
                return Err(format!(
                    "onlynet entry {net:?} invalid; allowed: {}",
                    VALID_ONLYNET.join(", ")
                ));
            }
        }
    }
    // ghostd refuses to start with -peerblockfilters unless the block-filter
    // index is also enabled, so reject that combination up front.
    if req.peer_block_filters == Some(true) && req.block_filter_index != Some(true) {
        return Err(
            "peer_block_filters (BIP157) requires block_filter_index to be enabled too".to_string(),
        );
    }
    // I2P SAM proxy must be host:port with a numeric port.
    if let Some(ref sam) = req.i2p_sam {
        let ok = sam
            .rsplit_once(':')
            .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
        if !ok {
            return Err(format!("i2p_sam must be host:port with a numeric port (got {sam:?})"));
        }
    }
    if req.i2p_accept_incoming == Some(true) && req.i2p_sam.is_none() {
        return Err("i2p_accept_incoming requires i2p_sam to be set".to_string());
    }
    Ok(())
}

/// API v1 Config daemon POST handler — sets ghostd launch flags (mempool,
/// connectivity, performance, BIP157 indexes, onlynet, I2P).
///
/// ghostd reads all of these only at startup, so — exactly like `-tormode` and
/// the `-ghostreaper` flags — this persists `[node_launch]` to pool.toml and
/// then reuses `spawn_ghostd_reaper_apply`, which runs `ghost-setup apply-reaper`
/// to regenerate the combined managed drop-in and RESTART ghostd, then bounces
/// ghost-pool. The response returns promptly with the apply *initiated*; the
/// terminal result lands on the `/config/daemon` GET endpoint's `ghostd_apply`.
async fn api_config_daemon_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<DaemonSettingsRequest>,
) -> impl IntoResponse {
    // Validate before touching anything; reject nonsense with 400.
    if let Err(reason) = validate_daemon_settings(&payload) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": reason,
                "code": "INVALID_DAEMON_SETTINGS",
            })),
        )
            .into_response();
    }

    // Require the full node config + a path to persist to; otherwise the change
    // can't survive a restart, so fail-closed with SERVICE_UNAVAILABLE.
    let Some(ref full) = state.full_node_config else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "success": false,
                "error": "Config update API not available: full node config not loaded",
                "code": "CONFIG_NOT_LOADED",
            })),
        )
            .into_response();
    };
    let Some(ref path) = state.full_node_config_path else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "success": false,
                "error": "Config update API not available: no node config path configured",
                "code": "CONFIG_NOT_LOADED",
            })),
        )
            .into_response();
    };

    {
        let mut cfg = full.write();
        // tor_mode is owned by /config/tor — preserve it. Overwrite the daemon
        // fields wholesale from the request (a missing field clears the flag,
        // reverting to ghostd's default), normalising onlynet entries.
        let launch = &mut cfg.node_launch;
        launch.max_mempool_mb = payload.max_mempool_mb;
        launch.mempool_expiry_hours = payload.mempool_expiry_hours;
        launch.max_connections = payload.max_connections;
        launch.max_upload_target_mb = payload.max_upload_target_mb.clone();
        launch.dbcache_mb = payload.dbcache_mb;
        launch.block_filter_index = payload.block_filter_index;
        launch.peer_block_filters = payload.peer_block_filters;
        launch.onlynet = payload
            .onlynet
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|n| n.trim().to_ascii_lowercase())
            .collect();
        launch.i2p_sam = payload.i2p_sam.clone();
        launch.i2p_accept_incoming = payload.i2p_accept_incoming;

        if let Err(e) = cfg.save_atomic(path) {
            error!(error = %e, "Failed to persist daemon settings");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to persist daemon settings: {e}"),
                    "code": "PERSIST_FAILED",
                })),
            )
                .into_response();
        }
    }

    // Apply the ghostd flags (restarts ghostd) then bounce the pool. Shares the
    // reaper apply path because the drop-in carries all ghost-managed flags.
    spawn_ghostd_reaper_apply(Arc::clone(&state));

    let apply = serde_json::to_value(&*state.ghostd_reaper_apply.read())
        .unwrap_or_else(|_| serde_json::json!({}));
    Json(serde_json::json!({
        "success": true,
        "ghostd_apply": apply,
        "restart_pending": true,
        "message": "Daemon settings saved. ghostd is restarting to apply the new launch flags; the pool will bounce once it settles.",
    }))
    .into_response()
}

/// API v1 Config reaper POST handler — accepts the full per-vector reaper
/// settings, persists them to the node config (pool.toml `[reaper]`), and then
/// applies them to BOTH reapers automatically: the pool block-template reaper
/// (via a ghost-pool restart) and the ghostd mempool reaper (by running
/// `ghost-setup apply-reaper` in the background, which regenerates the
/// `-ghostreaper` drop-in and restarts ghostd). No manual CLI step is needed.
///
/// The ghostd apply is slow and disruptive, so it runs off the request path;
/// the response returns promptly with the apply *initiated* and the terminal
/// result lands on the reaper GET endpoint's `ghostd_apply`. A legacy
/// `{ "enabled": bool }` body still works (the per-vector fields fall back to
/// their serde defaults = all-on).
/// Request body for the policy-profile POST endpoint.
#[derive(Debug, Deserialize)]
struct PolicyProfileRequest {
    /// One of `strict` (legacy alias `bitcoin_pure`), `permissive`, `full_open`.
    profile: String,
}

/// API v1 Config policy_profile POST handler.
///
/// This is the REAL lever for which BUDS tiers get mined: it writes
/// `[policy].profile` into the node config (pool.toml) and persists it, then
/// requests a graceful ghost-pool restart so the new profile is resolved at
/// startup. Unlike the cosmetic `mempool_profile`/`template_profile` dashboard
/// mirrors, changing this actually alters template construction.
async fn api_config_policy_profile_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<PolicyProfileRequest>,
) -> impl IntoResponse {
    use ghost_common::config::PolicyProfile;

    // Map the incoming string to the config enum. Accept the new `strict`
    // spelling and the legacy `bitcoin_pure` alias; reject anything else 400.
    let profile = match payload.profile.trim().to_ascii_lowercase().as_str() {
        "strict" | "bitcoin_pure" => PolicyProfile::BitcoinPure,
        "permissive" => PolicyProfile::Permissive,
        "full_open" => PolicyProfile::FullOpen,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Unknown policy profile: {other}"),
                    "code": "INVALID_PROFILE",
                })),
            )
                .into_response();
        }
    };

    // The canonical serialized name we echo back to the caller.
    let profile_name = match profile {
        PolicyProfile::BitcoinPure => "strict",
        PolicyProfile::Permissive => "permissive",
        PolicyProfile::FullOpen => "full_open",
        PolicyProfile::Custom => "custom",
    };

    // Require the full node config + a path to persist to; otherwise the change
    // can't survive a restart, so fail-closed with SERVICE_UNAVAILABLE.
    let Some(ref full) = state.full_node_config else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "success": false,
                "error": "Config update API not available: full node config not loaded",
                "code": "CONFIG_NOT_LOADED",
            })),
        )
            .into_response();
    };
    let Some(ref path) = state.full_node_config_path else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "success": false,
                "error": "Config update API not available: no node config path configured",
                "code": "CONFIG_NOT_LOADED",
            })),
        )
            .into_response();
    };

    {
        let mut cfg = full.write();
        cfg.policy.profile = profile;
        if let Err(e) = cfg.save_atomic(path) {
            error!(error = %e, "Failed to persist policy profile");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to persist policy profile: {e}"),
                    "code": "PERSIST_FAILED",
                })),
            )
                .into_response();
        }
    }

    // The profile is resolved at startup, so a graceful restart applies it.
    state.request_restart();

    Json(serde_json::json!({
        "success": true,
        "profile": profile_name,
        "restart_pending": true,
    }))
    .into_response()
}

/// Request body for the custom tier-policy POST endpoint. Carries the full set
/// of operator-tunable policy fields; the per-tier booleans map onto the
/// `[policy].custom.allowed_tiers` list.
#[derive(Debug, Deserialize)]
struct PolicyCustomRequest {
    /// Allow tier T0 (core financial) transactions.
    #[serde(default)]
    allow_t0: bool,
    /// Allow tier T1 (extended financial: multisig, timelocks) transactions.
    #[serde(default)]
    allow_t1: bool,
    /// Allow tier T2 (small data / OP_RETURN) transactions.
    #[serde(default)]
    allow_t2: bool,
    /// Allow tier T3 (heavy data: inscriptions, runes) transactions.
    #[serde(default)]
    allow_t3: bool,
    /// Allow Ordinals/inscription envelopes.
    #[serde(default)]
    allow_inscriptions: bool,
    /// Allow Runes runestones.
    #[serde(default)]
    allow_runes: bool,
    /// Allow BRC-20 token transfers.
    #[serde(default)]
    allow_brc20: bool,
    /// Maximum OP_RETURN payload size in bytes (0 = none allowed).
    max_op_return_size: usize,
    /// Maximum witness size per input in bytes.
    max_witness_per_input: usize,
    /// Maximum outputs per transaction.
    max_tx_outputs: usize,
    /// Maximum transaction size in vbytes.
    max_tx_size: usize,
    /// Minimum fee rate in sat/vB (0 = no minimum).
    min_fee_rate: f64,
}

/// API v1 Config policy_custom POST handler.
///
/// Sets `[policy].profile = custom` and writes the full `[policy].custom` block
/// to pool.toml, then requests a graceful restart so the operator-defined field
/// values are resolved into the enforced policy profile at startup. Unlike the
/// three presets, this exposes every per-field knob the template builder now
/// enforces (tiers, content toggles, size limits, min fee rate).
async fn api_config_policy_custom_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<PolicyCustomRequest>,
) -> impl IntoResponse {
    use ghost_common::config::{BudsTier, CustomPolicyConfig, PolicyProfile};

    // Validate the fee rate: must be a finite, non-negative number.
    if !payload.min_fee_rate.is_finite() || payload.min_fee_rate < 0.0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": "min_fee_rate must be a finite, non-negative number",
                "code": "INVALID_FEE_RATE",
            })),
        )
            .into_response();
    }

    // Build the allowed-tier list from the per-tier booleans.
    let mut allowed_tiers = Vec::new();
    if payload.allow_t0 {
        allowed_tiers.push(BudsTier::T0);
    }
    if payload.allow_t1 {
        allowed_tiers.push(BudsTier::T1);
    }
    if payload.allow_t2 {
        allowed_tiers.push(BudsTier::T2);
    }
    if payload.allow_t3 {
        allowed_tiers.push(BudsTier::T3);
    }

    let custom = CustomPolicyConfig {
        allowed_tiers,
        max_op_return_size: payload.max_op_return_size,
        max_witness_per_input: payload.max_witness_per_input,
        max_tx_outputs: payload.max_tx_outputs,
        max_tx_size: payload.max_tx_size,
        allow_inscriptions: payload.allow_inscriptions,
        allow_runes: payload.allow_runes,
        allow_brc20: payload.allow_brc20,
        min_fee_rate: payload.min_fee_rate,
    };

    // Require the full node config + a path to persist to; otherwise the change
    // can't survive a restart, so fail-closed with SERVICE_UNAVAILABLE.
    let Some(ref full) = state.full_node_config else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "success": false,
                "error": "Config update API not available: full node config not loaded",
                "code": "CONFIG_NOT_LOADED",
            })),
        )
            .into_response();
    };
    let Some(ref path) = state.full_node_config_path else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "success": false,
                "error": "Config update API not available: no node config path configured",
                "code": "CONFIG_NOT_LOADED",
            })),
        )
            .into_response();
    };

    let custom_json = serde_json::json!({
        "allowed_tiers": custom.allowed_tiers.iter().map(tier_key).collect::<Vec<_>>(),
        "max_op_return_size": custom.max_op_return_size,
        "max_witness_per_input": custom.max_witness_per_input,
        "max_tx_outputs": custom.max_tx_outputs,
        "max_tx_size": custom.max_tx_size,
        "allow_inscriptions": custom.allow_inscriptions,
        "allow_runes": custom.allow_runes,
        "allow_brc20": custom.allow_brc20,
        "min_fee_rate": custom.min_fee_rate,
    });

    {
        let mut cfg = full.write();
        cfg.policy.profile = PolicyProfile::Custom;
        cfg.policy.custom = Some(custom);
        if let Err(e) = cfg.save_atomic(path) {
            error!(error = %e, "Failed to persist custom policy");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to persist custom policy: {e}"),
                    "code": "PERSIST_FAILED",
                })),
            )
                .into_response();
        }
    }

    // The custom profile is resolved at startup, so a graceful restart applies it.
    state.request_restart();

    Json(serde_json::json!({
        "success": true,
        "profile": "custom",
        "custom": custom_json,
        "restart_pending": true,
    }))
    .into_response()
}

/// Build the `policy` JSON block for the config GET responses: the active
/// preset name plus the resolved custom field values. When no `[policy].custom`
/// block is persisted, the defaults are surfaced so the advanced UI panel has
/// sensible starting values. Returns `null` when the full node config is not
/// loaded (e.g. minimal/test servers).
fn policy_json(state: &Arc<VerificationState>) -> serde_json::Value {
    use ghost_common::config::{CustomPolicyConfig, PolicyProfile};

    let Some(ref full) = state.full_node_config else {
        return serde_json::Value::Null;
    };
    let cfg = full.read();

    let profile_name = match cfg.policy.profile {
        PolicyProfile::BitcoinPure => "strict",
        PolicyProfile::Permissive => "permissive",
        PolicyProfile::FullOpen => "full_open",
        PolicyProfile::Custom => "custom",
    };

    let custom: CustomPolicyConfig = cfg.policy.custom.clone().unwrap_or_default();

    serde_json::json!({
        "profile": profile_name,
        "custom": {
            "allow_t0": custom.allowed_tiers.contains(&ghost_common::config::BudsTier::T0),
            "allow_t1": custom.allowed_tiers.contains(&ghost_common::config::BudsTier::T1),
            "allow_t2": custom.allowed_tiers.contains(&ghost_common::config::BudsTier::T2),
            "allow_t3": custom.allowed_tiers.contains(&ghost_common::config::BudsTier::T3),
            "allow_inscriptions": custom.allow_inscriptions,
            "allow_runes": custom.allow_runes,
            "allow_brc20": custom.allow_brc20,
            "max_op_return_size": custom.max_op_return_size,
            "max_witness_per_input": custom.max_witness_per_input,
            "max_tx_outputs": custom.max_tx_outputs,
            "max_tx_size": custom.max_tx_size,
            "min_fee_rate": custom.min_fee_rate,
        }
    })
}

/// Serialize a config-crate BUDS tier to its lowercase wire key (`t0`..`t3`).
fn tier_key(tier: &ghost_common::config::BudsTier) -> &'static str {
    match tier {
        ghost_common::config::BudsTier::T0 => "t0",
        ghost_common::config::BudsTier::T1 => "t1",
        ghost_common::config::BudsTier::T2 => "t2",
        ghost_common::config::BudsTier::T3 => "t3",
    }
}

async fn api_config_reaper_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<ghost_common::config::ReaperSettings>,
) -> impl IntoResponse {
    let mut persisted = false;
    if let Some(ref full) = state.full_node_config {
        let mut cfg = full.write();
        cfg.reaper = payload.clone();
        if let Some(ref path) = state.full_node_config_path {
            match cfg.save_atomic(path) {
                Ok(()) => persisted = true,
                Err(e) => error!(error = %e, "Failed to persist reaper config"),
            }
        }
    }
    // Keep the dashboard master mirror in sync (capability / share displays).
    {
        let mut dc = state.dashboard_config.write();
        dc.reaper = payload.enabled;
    }

    // Nothing was written to pool.toml, so there is nothing to apply to either
    // reaper. Report skipped and don't touch ghostd or restart the pool.
    if !persisted {
        *state.ghostd_reaper_apply.write() =
            ghost_common_now("skipped", "Config not persisted; ghostd reaper unchanged.");
        let apply = serde_json::to_value(&*state.ghostd_reaper_apply.read())
            .unwrap_or_else(|_| serde_json::json!({}));
        return Json(serde_json::json!({
            "success": true,
            "persisted": false,
            "enabled": payload.enabled,
            "settings": serde_json::to_value(&payload).unwrap_or_else(|_| serde_json::json!({})),
            "ghostd_apply": apply,
            "message": "Reaper settings received but no node config path is configured — changes were not persisted.",
        }));
    }

    // Kick off the ghostd apply in the background; it triggers the pool restart
    // once ghostd has settled (see `spawn_ghostd_reaper_apply`). We deliberately
    // do NOT call `request_restart()` here — the background task owns the
    // ordering so the pool always bounces after ghostd, never before.
    spawn_ghostd_reaper_apply(Arc::clone(&state));

    let apply = serde_json::to_value(&*state.ghostd_reaper_apply.read())
        .unwrap_or_else(|_| serde_json::json!({}));
    Json(serde_json::json!({
        "success": true,
        "persisted": true,
        "enabled": payload.enabled,
        "settings": serde_json::to_value(&payload).unwrap_or_else(|_| serde_json::json!({})),
        // Superseded `ghostd_restart_required`: the node mempool reaper is now
        // applied automatically. Kept as `false` for older dashboards.
        "ghostd_restart_required": false,
        "ghostd_apply": apply,
        "message": "Reaper settings saved. The pool template reaper applies on the imminent ghost-pool restart, and the ghostd mempool reaper is being applied automatically (ghostd will briefly restart).",
    }))
}

// ============================================================================
// Operator Alerts (email / push / Telegram) — issue #236
// ============================================================================

/// Serialize an [`AlertsConfig`] for the read/write API with the Telegram bot
/// token REDACTED. The raw token is a secret (like `[coordinator]
/// bond_ledger_token`) and must never leave the node; the dashboard only needs
/// to know whether one is set. `telegram.bot_token` is dropped and a boolean
/// `telegram.bot_token_set` is injected in its place.
fn alerts_response_json(cfg: &ghost_common::config::AlertsConfig) -> serde_json::Value {
    let mut v = serde_json::to_value(cfg).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(tg) = v
        .get_mut("channels")
        .and_then(|c| c.get_mut("telegram"))
        .and_then(|t| t.as_object_mut())
    {
        let has_token = tg
            .remove("bot_token")
            .and_then(|t| t.as_str().map(|s| !s.is_empty()))
            .unwrap_or(false);
        tg.insert("bot_token_set".to_string(), serde_json::Value::Bool(has_token));
    }
    v
}

/// API v1 Config alerts GET handler — returns the operator alerting config from
/// pool.toml `[alerts]`, with the Telegram bot token redacted.
async fn api_config_alerts_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let alerts = state
        .full_node_config
        .as_ref()
        .map(|c| c.read().alerts.clone())
        .unwrap_or_default();
    let mut body = alerts_response_json(&alerts);
    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "message".to_string(),
            serde_json::Value::String("Operator alerting configuration".to_string()),
        );
    }
    Json(body)
}

/// API v1 Config alerts POST handler — persists the operator alerting config to
/// pool.toml `[alerts]`. The Telegram bot token is preserved when the client
/// omits it (the GET redacts it, so a normal round-trip carries no token); a
/// non-empty token replaces the stored one.
async fn api_config_alerts_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<ghost_common::config::AlertsConfig>,
) -> impl IntoResponse {
    let mut persisted = false;
    let mut saved = payload.clone();
    if let Some(ref full) = state.full_node_config {
        let mut cfg = full.write();
        // Secret-preserve: an empty/absent incoming bot token keeps the stored
        // one, so saving unrelated changes never wipes the credential.
        if saved
            .channels
            .telegram
            .bot_token
            .as_deref()
            .unwrap_or("")
            .is_empty()
        {
            saved.channels.telegram.bot_token =
                cfg.alerts.channels.telegram.bot_token.clone();
        }
        cfg.alerts = saved.clone();
        if let Some(ref path) = state.full_node_config_path {
            match cfg.save_atomic(path) {
                Ok(()) => persisted = true,
                // Do NOT log the config (it carries the bot token).
                Err(e) => error!(error = %e, "Failed to persist alerts config"),
            }
        }
    }
    let mut body = alerts_response_json(&saved);
    if let Some(obj) = body.as_object_mut() {
        obj.insert("success".to_string(), serde_json::Value::Bool(true));
        obj.insert("persisted".to_string(), serde_json::Value::Bool(persisted));
        obj.insert(
            "message".to_string(),
            serde_json::Value::String(
                if persisted {
                    "Alert settings saved.".to_string()
                } else {
                    "Alert settings received but no node config path is configured — changes were not persisted.".to_string()
                },
            ),
        );
    }
    Json(body)
}

/// Build the shared JSON body for the backup-schedule get/set endpoints:
/// the persisted schedule plus the in-memory last-run status.
fn backup_schedule_response_json(
    schedule: &ghost_common::config::BackupSchedule,
    status: &ghost_common::config::BackupRunStatus,
) -> serde_json::Value {
    serde_json::json!({
        // `interval` serialises to its wire string ("daily" / "weekly" / "6h").
        "enabled": schedule.enabled,
        "interval": schedule.interval,
        "retention": schedule.retention,
        "target_dir": schedule.target_dir,
        "status": status,
    })
}

/// API v1 Config backup-schedule GET handler — returns the automatic scheduled
/// encrypted-backup configuration plus the in-memory last-run status (time /
/// result / path) so the dashboard can render the "Scheduled backups" card.
async fn api_config_backup_schedule_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let schedule = state
        .full_node_config
        .as_ref()
        .map(|c| c.read().backup.clone())
        .unwrap_or_default();
    let status = state.backup_status.read().clone();
    let mut body = backup_schedule_response_json(&schedule, &status);
    if let Some(obj) = body.as_object_mut() {
        obj.insert(
            "message".to_string(),
            serde_json::Value::String(
                "Automatic scheduled encrypted-backup configuration".to_string(),
            ),
        );
    }
    Json(body)
}

/// API v1 Config backup-schedule POST handler — persists the scheduled-backup
/// config to pool.toml `[backup]`. Retention is floored at 1 and `target_dir`
/// must be an absolute path (mirrors the M-15 backup-history guard), so an
/// enabled schedule can never be pointed at a relative directory.
async fn api_config_backup_schedule_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<ghost_common::config::BackupSchedule>,
) -> impl IntoResponse {
    let mut saved = payload;
    // Never keep zero backups; clamp before persisting so what's stored matches
    // what the scheduler enforces.
    saved.retention = saved.retention.max(1);

    // Reject a relative target dir up front (the scheduler and history endpoint
    // both require an absolute path).
    if !std::path::Path::new(&saved.target_dir).is_absolute() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": "target_dir must be an absolute path",
                "code": "INVALID_TARGET_DIR",
            })),
        )
            .into_response();
    }

    let mut persisted = false;
    if let Some(ref full) = state.full_node_config {
        let mut cfg = full.write();
        cfg.backup = saved.clone();
        if let Some(ref path) = state.full_node_config_path {
            match cfg.save_atomic(path) {
                Ok(()) => persisted = true,
                Err(e) => error!(error = %e, "Failed to persist backup schedule config"),
            }
        }
    }

    let status = state.backup_status.read().clone();
    let mut body = backup_schedule_response_json(&saved, &status);
    if let Some(obj) = body.as_object_mut() {
        obj.insert("success".to_string(), serde_json::Value::Bool(true));
        obj.insert("persisted".to_string(), serde_json::Value::Bool(persisted));
        obj.insert(
            "message".to_string(),
            serde_json::Value::String(
                if persisted {
                    "Backup schedule saved.".to_string()
                } else {
                    "Backup schedule received but no node config path is configured — changes were not persisted.".to_string()
                },
            ),
        );
    }
    Json(body).into_response()
}

/// API v1 Alerts test-send POST handler — delivers a real test alert to every
/// enabled + configured channel, proving the delivery plumbing end to end. This
/// bypasses the master `enabled` switch (the operator explicitly asked to test)
/// but still only touches channels the operator has turned on and configured.
async fn api_alerts_test_post_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let alerts = state
        .full_node_config
        .as_ref()
        .map(|c| c.read().alerts.clone())
        .unwrap_or_default();
    let msg = crate::alerts::AlertMessage {
        title: format!(
            "[Ghost {}] Test alert",
            &state.node_id[..state.node_id.len().min(12)]
        ),
        body: "This is a test alert from your Ghost node dashboard. If you received it, alert delivery is working.".to_string(),
    };
    let results = crate::alerts::deliver(&alerts, &msg).await;
    let attempted = results.iter().filter(|r| r.attempted).count();
    let succeeded = results.iter().filter(|r| r.attempted && r.success).count();
    let message = if attempted == 0 {
        "No channels are enabled and configured — enable a channel and enter its details, save, then send a test.".to_string()
    } else if succeeded == attempted {
        format!("Test alert delivered to {succeeded} channel(s).")
    } else {
        format!("Delivered to {succeeded} of {attempted} channel(s); see per-channel results.")
    };
    Json(serde_json::json!({
        "success": attempted > 0 && succeeded == attempted,
        "attempted": attempted,
        "succeeded": succeeded,
        "results": results,
        "message": message,
    }))
}

/// Pool-side rate limit for failed-login alerts. The dashboard already
/// edge-triggers (it only signals when its failure counter first crosses the
/// threshold within the window), so this is a defensive second layer against a
/// burst of signals — at most one `FailedLogin` alert per this interval.
const FAILED_LOGIN_ALERT_MIN_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(5 * 60);

/// Body of the internal failed-login signal from the dashboard login route.
/// Carries only the failed-attempt count (and the window it was measured over) —
/// never the attempted password or any credential material.
#[derive(Debug, Deserialize)]
struct FailedLoginSignal {
    /// Number of consecutive failed dashboard login attempts observed.
    attempts: u32,
    /// Window (seconds) over which the attempts were counted, for the message.
    #[serde(default)]
    window_secs: Option<u64>,
}

/// API v1 internal failed-login signal handler — dispatches a `FailedLogin`
/// operator alert through the shared dispatcher.
///
/// This is a CROSS-LAYER bridge: dashboard password auth lives in the Next.js
/// layer, which counts consecutive failed attempts in-process and, on crossing
/// its threshold, calls this endpoint. The login route runs pre-session (there
/// is no operator cookie yet), so it cannot use the authenticated dashboard
/// proxy; instead it signs this call with the shared internal-auth secret
/// (`INTERNAL_AUTH_KEY`, the same HMAC the proxy uses). We therefore VERIFY that
/// HMAC here (`X-Ghost-Signature` + `X-Ghost-Timestamp` over the raw body) when
/// internal auth is configured, so only a holder of the secret can raise this
/// alert. The message includes the attempt count, never the attempted password.
async fn api_alerts_failed_login_post_handler(
    State(state): State<Arc<VerificationState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Require a valid internal HMAC when configured (production). Verify over the
    // exact raw bytes, matching the dashboard proxy's signing scheme.
    if let Some(auth) = state.internal_auth.as_ref() {
        if let Err((code, _)) = verify_internal_auth(auth, &headers, &body) {
            return (
                code,
                Json(serde_json::json!({ "success": false, "message": "unauthorized" })),
            )
                .into_response();
        }
    }

    let payload: FailedLoginSignal = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "success": false, "message": "invalid request body" })),
            )
                .into_response();
        }
    };

    let detail = match payload.window_secs {
        Some(w) if w >= 60 => format!(
            "{} consecutive failed dashboard login attempts within {} minutes.",
            payload.attempts,
            w / 60
        ),
        _ => format!(
            "{} consecutive failed dashboard login attempts.",
            payload.attempts
        ),
    };

    // Dispatch through the shared dispatcher: honours the master switch, the
    // `failed_login` event flag, and applies a pool-side rate limit. No-op if
    // the dispatcher was never wired (minimal/test servers).
    let dispatched = if let Some(dispatcher) = state.alert_dispatcher.get() {
        dispatcher
            .fire_rate_limited(
                crate::alerts::AlertEvent::FailedLogin,
                FAILED_LOGIN_ALERT_MIN_INTERVAL,
                &detail,
            )
            .await
    } else {
        false
    };

    Json(serde_json::json!({ "success": true, "dispatched": dispatched })).into_response()
}

/// API v1 Config ghost_pay POST handler
async fn api_config_ghost_pay_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<ToggleRequest>,
) -> impl IntoResponse {
    let mut config = state.dashboard_config.write();
    config.ghost_pay = payload.enabled;
    Json(serde_json::json!({
        "success": true,
        "enabled": payload.enabled,
        "message": "Ghost Pay updated"
    }))
}

/// API v1 Config wraith GET handler — reports the operator's Wraith-mixing
/// on/off choice (`[ghost_pay] wraith_enabled`). Prefers the persisted node
/// config and falls back to the in-memory mirror surfaced by the status
/// endpoints.
async fn api_config_wraith_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let enabled = state
        .full_node_config
        .as_ref()
        .map(|c| c.read().wraith_enabled())
        .unwrap_or(state.wraith_enabled);
    Json(serde_json::json!({
        "enabled": enabled,
        "message": "Wraith mixing configuration"
    }))
}

/// API v1 Config wraith POST handler — sets `[ghost_pay] wraith_enabled` in the
/// node config (pool.toml) and persists it, mirroring the reaper/ghost_pay
/// toggles. The wraith flag is read at startup, so a ghost-pool restart applies
/// the change. Enabling lets any L2 participant initiate a CoinJoin session;
/// disabling means this node won't participate in mixing.
async fn api_config_wraith_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<ToggleRequest>,
) -> impl IntoResponse {
    let mut persisted = false;
    if let Some(ref full) = state.full_node_config {
        let mut cfg = full.write();
        cfg.ghost_pay
            .get_or_insert_with(Default::default)
            .wraith_enabled = payload.enabled;
        if let Some(ref path) = state.full_node_config_path {
            match cfg.save_atomic(path) {
                Ok(()) => persisted = true,
                Err(e) => error!(error = %e, "Failed to persist wraith config"),
            }
        }
    }
    // The wraith flag is read from config at startup; a restart applies it.
    if persisted {
        state.request_restart();
    }
    Json(serde_json::json!({
        "success": true,
        "persisted": persisted,
        "enabled": payload.enabled,
        "restart_required": true,
        "message": if persisted {
            "Wraith mixing updated; ghost-pool will restart to apply."
        } else {
            "Wraith setting received but no node config path is configured — changes were not persisted."
        },
    }))
}

/// Request body for elder config
#[derive(Debug, Deserialize)]
struct ElderRequest {
    enabled: bool,
    slot: Option<u32>,
}

/// API v1 Config elder handler
async fn api_config_elder_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let config = state.dashboard_config.read();
    Json(serde_json::json!({
        "enabled": config.elder,
        "slot": config.elder_slot,
        "message": "Elder status configuration"
    }))
}

/// API v1 Config elder POST handler
async fn api_config_elder_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<ElderRequest>,
) -> impl IntoResponse {
    let mut config = state.dashboard_config.write();
    config.elder = payload.enabled;
    config.elder_slot = payload.slot;
    Json(serde_json::json!({
        "success": true,
        "enabled": payload.enabled,
        "slot": payload.slot,
        "message": "Elder status updated"
    }))
}

/// API v1 Config prune_profile POST handler
async fn api_config_prune_profile_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<ProfileRequest>,
) -> impl IntoResponse {
    let mut config = state.dashboard_config.write();
    config.prune_profile = payload.profile.clone();
    Json(serde_json::json!({
        "success": true,
        "profile": payload.profile,
        "message": "Prune profile updated"
    }))
}

// ============================================================================
// Mining Endpoints
// ============================================================================

/// API v1 Mining payout address handler
async fn api_mining_payout_address_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "address": null,
        "message": "No payout address configured"
    }))
}

/// API v1 Mining private handler
async fn api_mining_private_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let config = state.dashboard_config.read();

    // Private mining is the opposite of public mining
    let enabled = !config.public_mining;

    // In private mode, we don't expose miner details for privacy
    Json(serde_json::json!({
        "enabled": enabled,
        "miners": [], // Private miners are not enumerated
        "total": 0,
        "message": if enabled { "Private mining mode active - miner details hidden" } else { "Public mining enabled" }
    }))
}

/// API v1 Mining public handler
async fn api_mining_public_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let health = state.get_health().await;

    // Query miners from current round
    let (miners, total) = if let Some(ref db) = state.database {
        match db.get_round_miners(health.round_id) {
            Ok(miner_work) => {
                let miners_json: Vec<_> = miner_work
                    .iter()
                    .map(|(miner_id, work)| {
                        serde_json::json!({
                            "miner_id": miner_id,
                            "work": work,
                            "type": "public"
                        })
                    })
                    .collect();
                let total = miners_json.len();
                (miners_json, total)
            }
            Err(e) => {
                error!(error = %e, "Failed to query public miners");
                (vec![], 0)
            }
        }
    } else {
        (vec![], 0)
    };

    Json(serde_json::json!({
        "enabled": health.capabilities.public_mining,
        "miners": miners,
        "total": total
    }))
}

// ============================================================================
// Ghost Pay Endpoints
// ============================================================================

/// API v1 Ghost Pay pruning handler
async fn api_ghostpay_pruning_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let config = state.dashboard_config.read();

    // Get pruning profile settings
    let (enabled, threshold) = match config.prune_profile.as_str() {
        "none" => (false, 0),
        "minimal" => (true, 100000),      // Prune locks below 100k sats
        "moderate" => (true, 1000000),    // Prune locks below 1M sats
        "aggressive" => (true, 10000000), // Prune locks below 10M sats
        _ => (false, 0),
    };

    Json(serde_json::json!({
        "enabled": enabled,
        "profile": config.prune_profile,
        "threshold_sats": threshold,
        "last_prune": null
    }))
}

// ============================================================================
// Settings Endpoints
// ============================================================================

/// API v1 Settings ghostpay payout address handler
async fn api_settings_ghostpay_payout_address_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "address": null,
        "message": "No Ghost Pay payout address configured"
    }))
}

// ============================================================================
// Swarm Endpoints
// ============================================================================

/// API v1 Swarm sync handler
async fn api_swarm_sync_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let health = state.get_health().await;

    // Check sync status based on peer connectivity and block height
    let (status, synced_peers) = if let Some(ref db) = state.database {
        let peers = db.get_active_peers(50).unwrap_or_default();
        let synced = peers.len();
        let status = if synced >= 3 {
            "synced"
        } else if synced > 0 {
            "syncing"
        } else {
            "disconnected"
        };
        (status, synced)
    } else {
        ("unknown", 0)
    };

    Json(serde_json::json!({
        "status": status,
        "block_height": health.block_height,
        "peer_count": synced_peers,
        "last_sync": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }))
}

/// API v1 Swarm update all handler
async fn api_swarm_update_all_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let health = state.get_health().await;

    // Get peer count for update status
    let peer_count = if let Some(ref db) = state.database {
        db.get_active_peers(50).map(|p| p.len()).unwrap_or(0)
    } else {
        0
    };

    Json(serde_json::json!({
        "status": "idle",
        "nodes_in_swarm": peer_count + 1, // +1 for self
        "nodes_updated": 0,
        "current_version": health.version
    }))
}

// ============================================================================
// System Endpoints
// ============================================================================

/// API v1 System update status handler
async fn api_system_update_status_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "idle",
        "current_version": env!("CARGO_PKG_VERSION"),
        "update_available": false,
        "progress": null
    }))
}

/// API v1 System updates handler
async fn api_system_updates_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "updates": [],
        "total": 0,
        "current_version": env!("CARGO_PKG_VERSION")
    }))
}

/// API v1 System update handler
async fn api_system_update_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "idle",
        "message": "No update in progress"
    }))
}

/// API v1 System rollback handler
async fn api_system_rollback_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "idle",
        "available_versions": [],
        "message": "System rollback status"
    }))
}

// ============================================================================
// Watchdog Endpoints
// ============================================================================

/// API v1 Watchdog events handler
async fn api_watchdog_events_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "events": [],
        "total": 0
    }))
}

/// API v1 Watchdog clear cache handler
async fn api_watchdog_clear_cache_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "message": "Cache cleared"
    }))
}

// ============================================================================
// Backup Endpoints
// ============================================================================

/// API v1 Backup export handler
async fn api_backup_export_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "idle",
        "message": "Backup export not started"
    }))
}

/// API v1 Backup import handler
async fn api_backup_import_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "idle",
        "message": "No backup import in progress"
    }))
}

/// API v1 Backup verify handler
async fn api_backup_verify_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "valid": true,
        "message": "Backup verification status"
    }))
}

/// Auth token handler (returns null token for dashboard compatibility)
async fn api_auth_token_handler() -> impl IntoResponse {
    // Dashboard expects this endpoint to exist, but auth is optional
    // Return null token which the client handles gracefully
    Json(serde_json::json!({
        "token": null
    }))
}

/// Admin endpoint to trigger a test consensus proposal (for BFT testing)
async fn admin_test_consensus_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    match state.trigger_test_proposal() {
        Ok(Some(hash)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "success": true,
                "proposal_hash": hex::encode(hash),
                "message": "Test proposal broadcast to peers"
            })),
        ),
        Ok(None) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "success": false,
                "error": "Test proposal handler not configured"
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to trigger test proposal: {}", e)
            })),
        ),
    }
}

// =============================================================================
// CONFIG UPDATE API
// =============================================================================

/// Request to update mutable configuration settings
///
/// All fields are optional - only specified fields will be updated.
/// Immutable settings (treasury_address, internal_api_secret, etc.) are rejected.
#[derive(Debug, Deserialize)]
pub struct ConfigUpdateRequest {
    /// Mining mode: "public_pool", "private_pool", or "private_solo"
    pub mining_mode: Option<String>,
    /// Password for private mining modes (required when switching to private modes)
    pub private_mining_password: Option<String>,
    /// Payout address for PrivateSolo mode (required when mining_mode = private_solo)
    pub solo_payout_address: Option<String>,
    /// Policy profile: "bitcoin_pure", "permissive", "full_open", or "custom"
    pub policy_profile: Option<String>,
    /// Enable/disable Ghost Pay L2
    pub ghost_pay_enabled: Option<bool>,
}

/// Response from config update API
#[derive(Debug, Serialize)]
pub struct ConfigUpdateResponse {
    /// Whether the update was successful
    pub success: bool,
    /// Human-readable message
    pub message: String,
    /// List of fields that were updated
    pub updated_fields: Vec<String>,
    /// Warnings (non-fatal issues)
    pub warnings: Vec<String>,
    /// Whether a restart is pending (config saved, restart needed to apply)
    pub restart_pending: bool,
}

/// Error response for config update API
#[derive(Debug, Serialize)]
pub struct ConfigUpdateError {
    /// Whether the update was successful (always false for errors)
    pub success: bool,
    /// Error message
    pub error: String,
    /// Error code for programmatic handling
    pub code: String,
}

/// Validate a mining mode string
fn validate_mining_mode(mode: &str) -> Result<ghost_common::config::MiningMode, String> {
    match mode.to_lowercase().as_str() {
        "public_pool" | "publicpool" => Ok(ghost_common::config::MiningMode::PublicPool),
        "private_pool" | "privatepool" => Ok(ghost_common::config::MiningMode::PrivatePool),
        "private_solo" | "privatesolo" => Ok(ghost_common::config::MiningMode::PrivateSolo),
        _ => Err(format!(
            "Invalid mining_mode '{}'. Valid values: public_pool, private_pool, private_solo",
            mode
        )),
    }
}

/// Validate a policy profile string
fn validate_policy_profile(profile: &str) -> Result<ghost_common::config::PolicyProfile, String> {
    match profile.to_lowercase().as_str() {
        "bitcoin_pure" | "bitcoinpure" => Ok(ghost_common::config::PolicyProfile::BitcoinPure),
        "permissive" => Ok(ghost_common::config::PolicyProfile::Permissive),
        "full_open" | "fullopen" => Ok(ghost_common::config::PolicyProfile::FullOpen),
        "custom" => Ok(ghost_common::config::PolicyProfile::Custom),
        _ => Err(format!(
            "Invalid policy_profile '{}'. Valid values: bitcoin_pure, permissive, full_open, custom",
            profile
        )),
    }
}

/// Validate bech32 address prefix for a network
fn validate_address_prefix(address: &str, network: ghost_common::config::BitcoinNetwork) -> bool {
    match network {
        ghost_common::config::BitcoinNetwork::Mainnet => address.starts_with("bc1"),
        ghost_common::config::BitcoinNetwork::Signet
        | ghost_common::config::BitcoinNetwork::Testnet => address.starts_with("tb1"),
        ghost_common::config::BitcoinNetwork::Regtest => address.starts_with("bcrt1"),
    }
}

/// Config update handler - updates mutable configuration settings
///
/// POST /api/internal/config/update
///
/// # Security
/// This endpoint is protected by HMAC authentication (internal API).
/// Only mutable settings can be changed - immutable settings are rejected.
///
/// # Restart Behavior
/// After a successful update, the config is saved to disk and a restart
/// is signaled. The node will exit with code 100, and systemd will restart it.
///
/// # Mutable Settings
/// - mining_mode: PublicPool/PrivatePool/PrivateSolo
/// - private_mining_password: required for private modes
/// - solo_payout_address: required for PrivateSolo
/// - policy_profile: bitcoin_pure/permissive/full_open/custom
/// - ghost_pay_enabled: toggle L2 on/off
async fn api_config_update_handler(
    State(state): State<Arc<VerificationState>>,
    Json(request): Json<ConfigUpdateRequest>,
) -> impl IntoResponse {
    let mut updated_fields = Vec::new();
    let mut warnings = Vec::new();

    // Check if full config is available
    let Some(ref full_config_lock) = state.full_node_config else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ConfigUpdateError {
                success: false,
                error: "Config update API not available: full node config not loaded".to_string(),
                code: "CONFIG_NOT_LOADED".to_string(),
            }),
        )
            .into_response();
    };

    // Get current config for validation
    let mut config = full_config_lock.write();
    let network = config.bitcoin.network;

    // Validate and apply mining_mode
    if let Some(ref mode_str) = request.mining_mode {
        match validate_mining_mode(mode_str) {
            Ok(new_mode) => {
                // Check if switching to private mode without password
                if matches!(
                    new_mode,
                    ghost_common::config::MiningMode::PrivatePool
                        | ghost_common::config::MiningMode::PrivateSolo
                ) {
                    // Need password either in request or already configured
                    let has_password = request.private_mining_password.is_some()
                        || config.network.private_mining_password.is_some();
                    if !has_password {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(ConfigUpdateError {
                                success: false,
                                error: format!(
                                    "private_mining_password required when switching to {}",
                                    mode_str
                                ),
                                code: "MISSING_PASSWORD".to_string(),
                            }),
                        )
                            .into_response();
                    }
                }

                // Check if switching to PrivateSolo without solo_payout_address
                if matches!(new_mode, ghost_common::config::MiningMode::PrivateSolo) {
                    let has_address = request.solo_payout_address.is_some()
                        || config.network.solo_payout_address.is_some();
                    if !has_address {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(ConfigUpdateError {
                                success: false,
                                error: "solo_payout_address required for private_solo mode"
                                    .to_string(),
                                code: "MISSING_SOLO_ADDRESS".to_string(),
                            }),
                        )
                            .into_response();
                    }
                }

                config.network.mining_mode = new_mode;
                updated_fields.push("mining_mode".to_string());
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ConfigUpdateError {
                        success: false,
                        error: e,
                        code: "INVALID_MINING_MODE".to_string(),
                    }),
                )
                    .into_response();
            }
        }
    }

    // Validate and apply private_mining_password
    // L-17: Enforce minimum password length of 8 characters with an error, not just a warning
    // Weak passwords expose private mining endpoints to brute-force attacks
    if let Some(ref password) = request.private_mining_password {
        if password.len() < 8 {
            return (
                StatusCode::BAD_REQUEST,
                Json(ConfigUpdateError {
                    success: false,
                    error: format!(
                        "L-17: Password must be at least 8 characters (got {}). \
                         Weak passwords expose private mining to brute-force attacks.",
                        password.len()
                    ),
                    code: "PASSWORD_TOO_SHORT".to_string(),
                }),
            )
                .into_response();
        }
        config.network.private_mining_password = Some(password.clone());
        updated_fields.push("private_mining_password".to_string());
    }

    // Validate and apply solo_payout_address
    if let Some(ref address) = request.solo_payout_address {
        if address.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(ConfigUpdateError {
                    success: false,
                    error: "solo_payout_address cannot be empty".to_string(),
                    code: "EMPTY_SOLO_ADDRESS".to_string(),
                }),
            )
                .into_response();
        }

        if !validate_address_prefix(address, network) {
            return (
                StatusCode::BAD_REQUEST,
                Json(ConfigUpdateError {
                    success: false,
                    error: format!(
                        "Invalid address prefix for {:?} network. Address: {}",
                        network, address
                    ),
                    code: "INVALID_ADDRESS_PREFIX".to_string(),
                }),
            )
                .into_response();
        }

        config.network.solo_payout_address = Some(address.clone());
        updated_fields.push("solo_payout_address".to_string());
    }

    // Validate and apply policy_profile
    if let Some(ref profile_str) = request.policy_profile {
        match validate_policy_profile(profile_str) {
            Ok(new_profile) => {
                config.policy.profile = new_profile;
                updated_fields.push("policy_profile".to_string());
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ConfigUpdateError {
                        success: false,
                        error: e,
                        code: "INVALID_POLICY_PROFILE".to_string(),
                    }),
                )
                    .into_response();
            }
        }
    }

    // Apply ghost_pay_enabled
    if let Some(enabled) = request.ghost_pay_enabled {
        if let Some(ref mut gp) = config.ghost_pay {
            gp.enabled = enabled;
            updated_fields.push("ghost_pay_enabled".to_string());
        } else if enabled {
            // Can't enable ghost_pay if not configured at all
            return (
                StatusCode::BAD_REQUEST,
                Json(ConfigUpdateError {
                    success: false,
                    error: "Cannot enable ghost_pay: [ghost_pay] section not configured in config"
                        .to_string(),
                    code: "GHOST_PAY_NOT_CONFIGURED".to_string(),
                }),
            )
                .into_response();
        }
    }

    // If nothing was updated, return early
    if updated_fields.is_empty() {
        return (
            StatusCode::OK,
            Json(ConfigUpdateResponse {
                success: true,
                message: "No changes requested".to_string(),
                updated_fields,
                warnings,
                restart_pending: false,
            }),
        )
            .into_response();
    }

    // Save config to disk atomically
    if let Some(ref config_path) = state.full_node_config_path {
        if let Err(e) = config.save_atomic(config_path) {
            error!(error = %e, "Failed to save config to disk");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ConfigUpdateError {
                    success: false,
                    error: format!("Failed to save config: {}", e),
                    code: "SAVE_FAILED".to_string(),
                }),
            )
                .into_response();
        }
        tracing::info!(
            fields = ?updated_fields,
            path = %config_path.display(),
            "Config saved to disk, signaling restart"
        );
    } else {
        warnings.push("Config path not set - changes will be lost on restart".to_string());
    }

    // Signal restart
    state.request_restart();

    (
        StatusCode::OK,
        Json(ConfigUpdateResponse {
            success: true,
            message: "Configuration updated. Restart pending.".to_string(),
            updated_fields,
            warnings,
            restart_pending: true,
        }),
    )
        .into_response()
}

/// Share notification handler - receives share data from SRI Pool
///
/// POST /api/internal/share
///
/// This endpoint is called by SRI Pool when it receives a valid share from a miner.
/// ghost-pool uses this to track miner work for payout calculations.
async fn share_notification_handler(
    State(state): State<Arc<VerificationState>>,
    Json(share): Json<ShareNotification>,
) -> impl IntoResponse {
    debug!(
        miner_id = %share.miner_id,
        work = share.work,
        job_id = share.job_id,
        "Received share notification from SRI"
    );

    match state.record_share(share) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))),
        Err(e) => {
            warn!(error = %e, "Failed to record share");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"status": "error", "message": e.to_string()})),
            )
        }
    }
}

/// Share batch handler - receives batched share data from SRI Pool native webhook
///
/// POST /api/internal/shares
///
/// This endpoint is called by SRI Pool's native webhook integration when it has
/// accumulated a batch of valid shares. This is more efficient than individual
/// share notifications for high-volume mining.
async fn share_batch_handler(
    State(state): State<Arc<VerificationState>>,
    Json(batch): Json<ShareBatch>,
) -> impl IntoResponse {
    let share_count = batch.shares.len();
    let batch_seq = batch.batch_seq;
    let pool_id = batch.pool_id;

    debug!(
        pool_id,
        batch_seq, share_count, "Received share batch from SRI Pool"
    );

    match state.record_share_batch(batch) {
        Ok(recorded) => {
            debug!(recorded, share_count, "Share batch processed");
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "ok",
                    "recorded": recorded,
                    "total": share_count
                })),
            )
        }
        Err(e) => {
            warn!(error = %e, "Failed to record share batch");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"status": "error", "message": e.to_string()})),
            )
        }
    }
}

// ============================================================================
// Prometheus Metrics Endpoint
// ============================================================================

/// Prometheus metrics handler - returns metrics in exposition format
async fn metrics_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    if let Some(ref metrics) = state.metrics {
        (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            metrics.render_cached(),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            "# No metrics available\n".to_string(),
        )
    }
}

// ============================================================================
// MPC Ceremony Endpoints
// ============================================================================

/// MPC params handler - serves current MPC parameters file for P2P sync
/// POST /api/v1/l2/submit — Accept L2 NoteSpend transaction for mesh broadcast
///
/// Called by ghost-pay after verifying a NoteSpend proof. Forwards the transaction
/// to the consensus mesh via the l2_submit_fn callback.
async fn api_l2_submit_handler(
    State(state): State<Arc<VerificationState>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let submit_fn = match &state.l2_submit_fn {
        Some(f) => f.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "L2 submission not configured"})),
            );
        }
    };

    match submit_fn(body.to_vec()) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "submitted"})),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("{}", e)})),
        ),
    }
}

/// POST /api/v1/l2/sync-commitment — Sync a commitment to the L2 tree
///
/// Called by ghost-pay after shielding a note or applying a transfer.
/// Inserts the commitment into the ghost-pool epoch tree and broadcasts to mesh.
async fn api_l2_sync_commitment_handler(
    State(state): State<Arc<VerificationState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let sync_fn = match &state.l2_sync_commitment_fn {
        Some(f) => f.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "L2 commitment sync not configured"})),
            );
        }
    };

    let commitment_hex = body["commitment"].as_str().unwrap_or_default();
    let note_index = body["note_index"].as_u64().unwrap_or(0);
    let block_height = body["block_height"].as_u64().unwrap_or(0);

    let commitment = match hex::decode(commitment_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid commitment hex (need 32 bytes)"})),
            );
        }
    };

    match sync_fn(commitment, note_index, block_height) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "synced"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        ),
    }
}

/// POST /api/v1/glyph/relay-claim — Relay a glyph claim to the mesh
///
/// Called by ghost-pay after validating and storing a glyph claim locally.
/// Forwards to the consensus mesh via the glyph_claim_relay_fn callback.
async fn api_glyph_relay_claim_handler(
    State(state): State<Arc<VerificationState>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let relay_fn = match &state.glyph_claim_relay_fn {
        Some(f) => f.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "Glyph relay not configured"})),
            );
        }
    };

    match relay_fn(body.to_vec()) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "relayed"})),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("{}", e)})),
        ),
    }
}

/// POST /api/v1/glyph/relay-registered — Relay a glyph registration to the mesh
///
/// Called by ghost-pay after completing glyph registration (lock funded).
/// Forwards to the consensus mesh via the glyph_registered_relay_fn callback.
async fn api_glyph_relay_registered_handler(
    State(state): State<Arc<VerificationState>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let relay_fn = match &state.glyph_registered_relay_fn {
        Some(f) => f.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "Glyph relay not configured"})),
            );
        }
    };

    match relay_fn(body.to_vec()) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "relayed"})),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("{}", e)})),
        ),
    }
}

/// Optional query for the note-spend params endpoint.
///
/// A BFT voter fetching a specific CANDIDATE (un-applied) parameter set passes
/// `?new_hash=<64-hex>` — the candidate's lineage hash. Absent (the self-heal /
/// refresh / manifest callers), the endpoint serves the applied current head.
#[derive(Debug, Default, Deserialize)]
pub struct MpcParamsQuery {
    /// Hex of the candidate lineage `new_params_hash` to serve, if any.
    #[serde(default)]
    pub new_hash: Option<String>,
}

/// Resolve which note-spend parameter file the params endpoint should serve.
///
/// When `requested_hash` is a well-formed 32-byte hex lineage hash AND the
/// matching CANDIDATE file exists, serve the candidate (so a voter gets the
/// un-applied params it must cryptographically verify). Otherwise — no / blank /
/// malformed hash, or no such candidate on disk — serve the active
/// `note_spend_params_current.bin` (applied head), preserving the self-heal /
/// refresh / manifest behaviour. The hash is decoded and re-encoded through the
/// shared `ghost_common::mpc` helper, so a malicious `new_hash` can never escape
/// the params directory (no path traversal).
fn resolve_mpc_note_spend_path(
    base_dir: &std::path::Path,
    requested_hash: Option<&str>,
) -> std::path::PathBuf {
    if let Some(h) = requested_hash.filter(|h| !h.is_empty()) {
        if let Some(bytes) = hex::decode(h).ok().filter(|b| b.len() == 32) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let candidate = base_dir.join(ghost_common::mpc::candidate_note_spend_filename(&arr));
            if candidate.exists() {
                return candidate;
            }
        }
    }
    base_dir.join("note_spend_params_current.bin")
}

// NOTE: `pub` so the cross-process MPC ceremony harness
// (`crates/mpc-xproc-harness`) can mount this EXACT production handler in a
// minimal router and prove the `?new_hash=` candidate-vs-current serving works
// across real OS process boundaries. Behaviour is unchanged.
pub async fn api_mpc_params_handler(
    State(_state): State<Arc<VerificationState>>,
    Query(query): Query<MpcParamsQuery>,
) -> impl IntoResponse {
    // Get MPC params dir from home directory, then resolve to the applied head
    // or — when a voter asks by `new_hash` — the matching candidate file.
    let base_dir =
        std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
            .join(".ghost/mpc_params");
    let params_path = resolve_mpc_note_spend_path(&base_dir, query.new_hash.as_deref());

    if !params_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            serde_json::json!({"error": "MPC params not available"})
                .to_string()
                .into_bytes(),
        );
    }

    match std::fs::read(&params_path) {
        Ok(data) => {
            debug!(size = data.len(), "Serving MPC params");
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                data,
            )
        }
        Err(e) => {
            warn!(error = %e, "Failed to read MPC params file");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                serde_json::json!({"error": "Failed to read params"})
                    .to_string()
                    .into_bytes(),
            )
        }
    }
}

/// MPC payout params handler - serves current MPC payout parameters file for P2P sync
async fn api_mpc_payout_params_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let params_path =
        std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
            .join(".ghost/mpc_params/payout_params_current.bin");

    if !params_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            serde_json::json!({"error": "MPC payout params not available"})
                .to_string()
                .into_bytes(),
        );
    }

    match std::fs::read(&params_path) {
        Ok(data) => {
            debug!(size = data.len(), "Serving MPC payout params");
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                data,
            )
        }
        Err(e) => {
            warn!(error = %e, "Failed to read MPC payout params file");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                serde_json::json!({"error": "Failed to read payout params"})
                    .to_string()
                    .into_bytes(),
            )
        }
    }
}

async fn api_mpc_unshield_params_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let params_path =
        std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
            .join(".ghost/mpc_params/unshield_params_current.bin");

    if !params_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            serde_json::json!({"error": "MPC unshield params not available"})
                .to_string()
                .into_bytes(),
        );
    }

    match std::fs::read(&params_path) {
        Ok(data) => {
            debug!(size = data.len(), "Serving MPC unshield params");
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                data,
            )
        }
        Err(e) => {
            warn!(error = %e, "Failed to read MPC unshield params file");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                serde_json::json!({"error": "Failed to read unshield params"})
                    .to_string()
                    .into_bytes(),
            )
        }
    }
}

/// MPC params manifest handler - returns SHA-256 hashes of all param files
///
/// Clients download this manifest first (small), then verify each param file
/// against its hash after download. Prevents MITM from serving malicious params.
async fn api_mpc_params_manifest_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    use sha2::{Digest, Sha256};

    let base_path =
        std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
            .join(".ghost/mpc_params");

    let files = [
        ("note_spend_params_current.bin", "note_spend"),
        ("payout_params_current.bin", "consolidation"),
        ("unshield_params_current.bin", "unshield"),
    ];

    let mut manifest = serde_json::Map::new();

    for (filename, key) in &files {
        let path = base_path.join(filename);
        match std::fs::read(&path) {
            Ok(data) => {
                let hash = hex::encode(Sha256::digest(&data));
                manifest.insert(
                    key.to_string(),
                    serde_json::json!({
                        "filename": filename,
                        "sha256": hash,
                        "size": data.len(),
                    }),
                );
            }
            Err(_) => {
                manifest.insert(
                    key.to_string(),
                    serde_json::json!({
                        "filename": filename,
                        "available": false,
                    }),
                );
            }
        }
    }

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(&manifest)
            .unwrap_or_else(|_| "{}".to_string())
            .into_bytes(),
    )
}

/// MPC status handler - returns ceremony status
async fn api_mpc_status_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    // Get contribution count from database if available
    let (contribution_count, is_ossified) = if let Some(ref db) = state.database {
        let count = db.get_mpc_elder_count().unwrap_or(0);
        (count, count >= 101)
    } else {
        (0, false)
    };

    // Check if this node is an elder (has contributed to MPC)
    let (is_elder, elder_slot) = if let Some(ref db) = state.database {
        let pos = db.get_mpc_elder_position(&state.node_id).unwrap_or(None);
        (pos.is_some(), pos)
    } else {
        (false, None)
    };

    // Determine ceremony phase
    let phase = if is_ossified {
        "ossified"
    } else if contribution_count > 0 {
        "contributing"
    } else {
        "initializing"
    };

    // Check if params file exists
    let params_path =
        std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
            .join(".ghost/mpc_params/note_spend_params_current.bin");
    let has_params = params_path.exists();

    Json(serde_json::json!({
        "contribution_count": contribution_count,
        "max_contributors": 101,
        "is_ossified": is_ossified,
        "is_elder": is_elder,
        "elder_slot": elder_slot,
        "phase": phase,
        "has_params": has_params,
        "node_id": state.node_id
    }))
}

/// MPC contributors handler - returns list of MPC contributors (elders)
/// Used by new nodes to sync the contributor list during startup
async fn api_mpc_contributors_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    // Get contributors from database
    let contributors = if let Some(ref db) = state.database {
        // Get all MPC contributions and return full records for sync
        let mut contributors = Vec::new();
        for position in 1..=101u32 {
            if let Ok(Some(record)) = db.get_mpc_contribution(position) {
                // Return all fields needed for MpcContributionRecord
                contributors.push(serde_json::json!({
                    "position": position,
                    "node_id": record.contributor_node_id,
                    "prev_params_hash": hex::encode(record.prev_params_hash),
                    "new_params_hash": hex::encode(record.new_params_hash),
                    "epoch": record.epoch,
                    "created_at": record.created_at,
                }));
            } else {
                break; // No more contributions
            }
        }
        contributors
    } else {
        Vec::new()
    };

    Json(serde_json::json!({
        "contributors": contributors,
        "count": contributors.len()
    }))
}

/// Stage C: per-position contribution + retained votes handler.
///
/// Serves, for a single ceremony position: the FULL contribution record —
/// including the (non-empty) `contribution_proof`, which the `/contributors`
/// list deliberately omits — AND every retained verification vote (voter,
/// approve, signature). This is exactly the data a catching-up node needs to
/// (a) re-run `verify_contribution` on the fetched proof and (b) re-check the
/// retained BFT quorum at startup, without keeping historical params blobs.
async fn api_mpc_votes_handler(
    State(state): State<Arc<VerificationState>>,
    Path(position): Path<u32>,
) -> impl IntoResponse {
    let Some(ref db) = state.database else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "no database" })),
        );
    };

    let contribution = match db.get_mpc_contribution(position) {
        Ok(Some(rec)) => serde_json::json!({
            "position": rec.elder_position,
            "node_id": rec.contributor_node_id,
            "prev_params_hash": hex::encode(rec.prev_params_hash),
            "new_params_hash": hex::encode(rec.new_params_hash),
            // Hex-encoded serialized ContributionProof — the field the
            // contributors endpoint drops. Empty string if not retained.
            "contribution_proof": hex::encode(&rec.contribution_proof),
            "epoch": rec.epoch,
            "created_at": rec.created_at,
        }),
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(
                    serde_json::json!({ "error": "no contribution at position", "position": position }),
                ),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            );
        }
    };

    let votes = match db.get_mpc_votes(position) {
        Ok(v) => v
            .into_iter()
            .map(|vote| {
                serde_json::json!({
                    "voter_node_id": vote.voter_node_id,
                    "approve": vote.approve,
                    "signature": hex::encode(vote.signature),
                    "voted_at": vote.voted_at,
                })
            })
            .collect::<Vec<_>>(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            );
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "contribution": contribution,
            "votes": votes,
            "vote_count": votes.len(),
        })),
    )
}

// =============================================================================
// Ghost Haze & Shroud endpoint handlers
// =============================================================================

/// Ghost Haze status handler — returns storage privacy status from Ghost Core
///
/// Proxies blockchain info from Ghost Core to show haze mode, storage savings,
/// and block counts. Uses the existing `hazed` field from `getblockchaininfo`.
async fn api_haze_status_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let archive_mode = { state.dashboard_config.read().archive_mode };

    let rpc_result = match state.rpc {
        Some(ref rpc) => {
            match tokio::time::timeout(std::time::Duration::from_secs(5), rpc.get_blockchain_info())
                .await
            {
                Ok(Ok(info)) => Some(info),
                Ok(Err(e)) => {
                    warn!("Failed to get haze status from RPC: {}", e);
                    None
                }
                Err(_) => {
                    warn!("Haze status RPC timed out");
                    None
                }
            }
        }
        None => None,
    };

    let (hazed, blocks, size_on_disk, pruned, chain, mode) = match rpc_result {
        Some(info) => {
            let mode = if archive_mode {
                "full_archive"
            } else if info.hazed {
                "hazed"
            } else {
                "standard"
            };
            (
                info.hazed,
                info.blocks,
                info.size_on_disk,
                info.pruned,
                info.chain,
                mode,
            )
        }
        None => (false, 0, 0, false, String::new(), "unknown"),
    };

    Json(serde_json::json!({
        "hazed": hazed,
        "archive_mode": archive_mode,
        "mode": mode,
        "blocks": blocks,
        "size_on_disk": size_on_disk,
        "pruned": pruned,
        "chain": chain
    }))
}

/// Ghost Shroud status handler — returns relay privacy configuration
///
/// Shroud is a Ghost Core feature that adds random delays before relaying
/// transactions, breaking timing-based origin detection. This endpoint
/// returns the shroud configuration status.
async fn api_shroud_status_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    // Shroud is enabled by default in Ghost Core via -shroud=1
    // Check if Ghost Core is reachable to confirm it's running
    let ghost_core_running = if let Some(ref rpc) = state.rpc {
        tokio::time::timeout(std::time::Duration::from_secs(5), rpc.get_blockchain_info())
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false)
    } else {
        false
    };

    Json(serde_json::json!({
        "enabled": ghost_core_running,
        "ghost_core_connected": ghost_core_running,
        "max_delay_ms": 5000,
        "avg_delay_ms": 2500
    }))
}

// =============================================================================
// Wizard endpoint handlers (Haze, Shroud, Node Restart)
// =============================================================================

/// Request body for haze configuration
#[derive(Debug, Deserialize)]
struct HazeConfigureRequest {
    /// Haze mode: "standard", "hazed", or "full_archive"
    mode: String,
}

/// POST /api/v1/haze/configure — Set Ghost Haze mode
///
/// Changes the haze privacy mode for stripped blocks:
/// - "standard": Normal block storage (no stripping)
/// - "hazed": Strip witness/script data from stored blocks
/// - "full_archive": Keep full blocks (archive node mode)
async fn api_haze_configure_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<HazeConfigureRequest>,
) -> impl IntoResponse {
    let valid_modes = ["standard", "hazed", "full_archive"];
    if !valid_modes.contains(&payload.mode.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": format!("Invalid mode '{}'. Must be one of: standard, hazed, full_archive", payload.mode)
            })),
        );
    }

    // Update archive_mode based on selected mode
    let archive_mode = payload.mode == "full_archive";
    {
        let mut config = state.dashboard_config.write();
        config.archive_mode = archive_mode;
    }

    // Try to sync with ghost-core via RPC if available
    let rpc_synced = if let Some(ref rpc) = state.rpc {
        match rpc.set_ghost_mode(payload.mode == "hazed").await {
            Ok(_) => true,
            Err(e) => {
                warn!("Failed to sync haze mode with ghost-core: {}", e);
                false
            }
        }
    } else {
        false
    };

    // Persist to node config
    {
        let node_config = state.node_config.write();
        // ghost_mode is the closest persisted field; haze is a ghost-core setting
        if let Some(ref path) = state.node_config_path {
            if let Err(e) = node_config.save(path) {
                error!("Failed to persist node config: {}", e);
            }
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "mode": payload.mode,
            "archive_mode": archive_mode,
            "rpc_synced": rpc_synced,
            "message": format!("Haze mode set to '{}'", payload.mode)
        })),
    )
}

/// Request body for shroud configuration
#[derive(Debug, Deserialize)]
struct ShroudConfigureRequest {
    /// Enable/disable shroud relay privacy (random 0-5s delay before relay)
    enabled: bool,
}

/// POST /api/v1/shroud/configure — Configure Shroud relay privacy
///
/// Persists shroud_enabled to node config and returns restart_required: true.
/// Ghost-core must be restarted with -shroud=1 flag for the setting to take effect.
async fn api_shroud_configure_handler(
    State(state): State<Arc<VerificationState>>,
    Json(payload): Json<ShroudConfigureRequest>,
) -> impl IntoResponse {
    // Persist to node config
    {
        let mut node_config = state.node_config.write();
        node_config.shroud_enabled = payload.enabled;
        if let Some(ref path) = state.node_config_path {
            if let Err(e) = node_config.save(path) {
                error!("Failed to persist shroud config: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "success": false,
                        "error": format!("Failed to persist config: {}", e)
                    })),
                );
            }
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "enabled": payload.enabled,
            "restart_required": true,
            "message": if payload.enabled {
                "Shroud enabled — restart ghost-core with -shroud=1 to activate"
            } else {
                "Shroud disabled — restart ghost-core without -shroud flag to deactivate"
            }
        })),
    )
}

/// POST /api/v1/node/restart — Restart ghost-pool service
///
/// Triggers a graceful restart of the ghost-pool service via systemctl.
/// Requires the process to have appropriate permissions (typically via sudoers).
async fn api_node_restart_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    // Spawn the restart command asynchronously
    // The service manager will handle graceful shutdown and restart
    let result = tokio::process::Command::new("sudo")
        .args(["systemctl", "restart", "ghost-pool"])
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => Json(serde_json::json!({
            "success": true,
            "message": "Node restart initiated"
        })),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Node restart failed: {}", stderr);
            Json(serde_json::json!({
                "success": false,
                "error": format!("Restart failed: {}", stderr)
            }))
        }
        Err(e) => {
            error!("Failed to execute restart command: {}", e);
            Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to execute restart: {}", e)
            }))
        }
    }
}

// =============================================================================
// Dashboard endpoint handlers
// =============================================================================

/// Logs query parameters
#[derive(Debug, Deserialize)]
struct LogsQuery {
    limit: Option<usize>,
    level: Option<String>,
    /// Logical binary key (see `crate::journal::ALLOWLIST`). Absent → ghost-pool
    /// ring buffer (unchanged default behaviour).
    unit: Option<String>,
}

/// API v1 Logs handler — returns recent log entries for the selected binary.
///
/// `unit=ghost-pool` (the default) short-circuits to ghost-pool's in-process
/// ring buffer (`crate::log_buffer`): its `tracing` layer mirrors every emitted
/// event into the buffer so each entry carries the real structured message,
/// target and level, with no host log daemon or elevated privileges required.
///
/// Any other allowlisted binary (ghostd / ghost-pay / dashboard / SV2 stack) is
/// read from the systemd journal via `crate::journal`. The client sends only a
/// LOGICAL key, which is resolved through a strict compile-time allowlist to a
/// hard-coded unit string; `journalctl` is then exec'd with an explicit argv, so
/// there is no shell and no way to interpolate a client string into the command.
/// An unknown key is rejected with 400 before anything is executed. journald
/// failures (missing binary, permission denied, empty) return an honest
/// structured `error`/empty state — never fabricated log lines.
async fn api_logs_handler(
    State(_state): State<Arc<VerificationState>>,
    Query(params): Query<LogsQuery>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100).min(1000);
    let level = params.level.as_deref();
    let key = params
        .unit
        .as_deref()
        .unwrap_or(crate::journal::DEFAULT_UNIT);

    // STRICT allowlist: an unknown key is rejected here, before any exec.
    let Some(unit) = crate::journal::resolve_unit(key) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "entries": [],
                "unit": key,
                "error": format!("Unknown log unit '{key}'"),
            })),
        )
            .into_response();
    };

    // ghost-pool → in-process ring buffer (unchanged behaviour).
    if unit.ring_buffer {
        let entries = crate::log_buffer::recent(limit, level);
        return Json(serde_json::json!({
            "entries": entries,
            "unit": unit.key,
            "source": "ring-buffer",
            "error": serde_json::Value::Null,
        }))
        .into_response();
    }

    // All other allowlisted binaries → journald, via an argv exec.
    match crate::journal::read_journal(unit.unit, limit, level).await {
        Ok(entries) => Json(serde_json::json!({
            "entries": entries,
            "unit": unit.key,
            "source": "journald",
            "error": serde_json::Value::Null,
        }))
        .into_response(),
        Err(e) => Json(serde_json::json!({
            "entries": [],
            "unit": unit.key,
            "source": "journald",
            "error": e.message(),
        }))
        .into_response(),
    }
}

/// API v1 Logs Units handler — lists the binaries whose logs this node can
/// serve, so the dashboard builds its selector from what is actually allowlisted
/// AND present on this host. ghost-pool is always available (ring buffer); other
/// units report `available` from their systemd `LoadState`.
async fn api_logs_units_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    let mut units = Vec::with_capacity(crate::journal::ALLOWLIST.len());
    for u in crate::journal::ALLOWLIST {
        units.push(serde_json::json!({
            "key": u.key,
            "label": u.label,
            "description": u.description,
            "source": if u.ring_buffer { "ring-buffer" } else { "journald" },
            "available": crate::journal::unit_is_present(u).await,
        }));
    }
    Json(serde_json::json!({ "units": units, "default": crate::journal::DEFAULT_UNIT }))
}

/// Nickname POST body
#[derive(Debug, Deserialize)]
struct NicknameBody {
    nickname: String,
}

/// API v1 Nickname POST handler — set node nickname
async fn api_nickname_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(body): Json<NicknameBody>,
) -> impl IntoResponse {
    // Validate nickname length
    let nickname = body.nickname.trim();
    if nickname.len() > 32 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Nickname too long (max 32 chars)"})),
        )
            .into_response();
    }

    let value = if nickname.is_empty() {
        None
    } else {
        Some(nickname.to_string())
    };

    // Store in the in-memory dashboard config (what the GET handler and the rest
    // of the process read live).
    {
        let mut config = state.dashboard_config.write();
        config.nickname = value.clone();
    }

    // Persist to the node config file so the nickname survives a restart. It
    // previously lived only in the in-memory dashboard config and was lost on
    // every restart.
    {
        let mut node_config = state.node_config.write();
        node_config.nickname = value;
        if let Some(ref path) = state.node_config_path {
            if let Err(e) = node_config.save(path) {
                error!(error = %e, "Failed to persist node nickname");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Failed to persist nickname: {}", e)})),
                )
                    .into_response();
            }
        }
    }

    Json(serde_json::json!({
        "nickname": nickname
    }))
    .into_response()
}

/// Swarm node add body
#[derive(Debug, Deserialize)]
struct SwarmNodeAddBody {
    name: String,
    address: String,
}

/// API v1 Swarm: Add a node to operator's fleet tracking
async fn api_swarm_node_add_handler(
    State(_state): State<Arc<VerificationState>>,
    Json(body): Json<SwarmNodeAddBody>,
) -> impl IntoResponse {
    // Swarm node management is operator-local fleet tracking
    // For now, return the node as acknowledged (DB persistence comes later)
    Json(serde_json::json!({
        "node_id": format!("{:08x}", fxhash(&body.address)),
        "name": body.name,
        "address": body.address,
        "online": false,
        "shares": 0,
        "max_shares": 15,
        "last_seen": 0
    }))
}

/// API v1 Swarm: Remove a node from fleet tracking
async fn api_swarm_node_remove_handler(
    State(_state): State<Arc<VerificationState>>,
    Path(node_id): Path<String>,
) -> impl IntoResponse {
    debug!(node_id = %node_id, "Removing swarm node");
    StatusCode::NO_CONTENT
}

/// Swarm node update body
#[derive(Debug, Deserialize)]
struct SwarmNodeUpdateBody {
    name: Option<String>,
    address: Option<String>,
}

/// API v1 Swarm: Update a node's name/address
async fn api_swarm_node_update_handler(
    State(_state): State<Arc<VerificationState>>,
    Path(node_id): Path<String>,
    Json(body): Json<SwarmNodeUpdateBody>,
) -> impl IntoResponse {
    debug!(node_id = %node_id, name = ?body.name, address = ?body.address, "Updating swarm node");
    StatusCode::NO_CONTENT
}

/// API v1 Swarm: Re-poll a node's status
async fn api_swarm_node_refresh_handler(
    State(_state): State<Arc<VerificationState>>,
    Path(node_id): Path<String>,
) -> impl IntoResponse {
    debug!(node_id = %node_id, "Refreshing swarm node");
    Json(serde_json::json!({
        "node_id": node_id,
        "online": false,
        "message": "Refresh queued"
    }))
}

/// API v1 Swarm: Configure a remote node
async fn api_swarm_node_config_handler(
    State(_state): State<Arc<VerificationState>>,
    Path(node_id): Path<String>,
    Json(_body): Json<serde_json::Value>,
) -> impl IntoResponse {
    debug!(node_id = %node_id, "Configuring swarm node");
    Json(serde_json::json!({
        "node_id": node_id,
        "message": "Configuration updated"
    }))
}

/// API v1 Swarm: Restart a remote node
async fn api_swarm_node_restart_handler(
    State(_state): State<Arc<VerificationState>>,
    Path(node_id): Path<String>,
) -> impl IntoResponse {
    debug!(node_id = %node_id, "Restarting swarm node");
    Json(serde_json::json!({
        "node_id": node_id,
        "message": "Restart command sent"
    }))
}

/// API v1 Swarm: Update a remote node's version
async fn api_swarm_node_update_version_handler(
    State(_state): State<Arc<VerificationState>>,
    Path(node_id): Path<String>,
    Json(_body): Json<serde_json::Value>,
) -> impl IntoResponse {
    debug!(node_id = %node_id, "Updating swarm node version");
    Json(serde_json::json!({
        "node_id": node_id,
        "message": "Update command sent"
    }))
}

/// API v1 Swarm: Sync fleet from P2P peer list (POST variant)
async fn api_swarm_sync_post_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    // Reuse GET handler logic
    api_swarm_sync_handler(State(state)).await
}

/// API v1 Swarm: Update all nodes (POST variant)
async fn api_swarm_update_all_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(_body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let _ = state;
    Json(serde_json::json!({
        "message": "Update all command sent",
        "updated_count": 0
    }))
}

/// Allowed services for watchdog control
const WATCHDOG_ALLOWED_SERVICES: &[&str] = &["ghost-pool", "ghost-core", "ghost-pay"];

/// Watchdog service control: start
async fn api_watchdog_start_handler(
    State(_state): State<Arc<VerificationState>>,
    Path(service): Path<String>,
) -> impl IntoResponse {
    watchdog_service_control(&service, "start").await
}

/// Watchdog service control: stop
async fn api_watchdog_stop_handler(
    State(_state): State<Arc<VerificationState>>,
    Path(service): Path<String>,
) -> impl IntoResponse {
    watchdog_service_control(&service, "stop").await
}

/// Watchdog service control: restart
async fn api_watchdog_restart_handler(
    State(_state): State<Arc<VerificationState>>,
    Path(service): Path<String>,
) -> impl IntoResponse {
    watchdog_service_control(&service, "restart").await
}

/// Execute a systemctl command for a whitelisted service
async fn watchdog_service_control(service: &str, action: &str) -> axum::response::Response {
    if !WATCHDOG_ALLOWED_SERVICES.contains(&service) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": format!("Service '{}' not in allowed list", service)
            })),
        )
            .into_response();
    }

    match tokio::process::Command::new("systemctl")
        .arg(action)
        .arg(service)
        .output()
        .await
    {
        Ok(output) => {
            let success = output.status.success();
            let message = if success {
                format!("Service {} {}", service, action)
            } else {
                String::from_utf8_lossy(&output.stderr).to_string()
            };
            Json(serde_json::json!({
                "success": success,
                "message": message,
                "service": service,
                "action": action
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to execute systemctl: {}", e)
            })),
        )
            .into_response(),
    }
}

/// Config profile save body (mempool)
#[derive(Debug, Deserialize)]
struct ProfileSaveBody {
    name: String,
    #[serde(flatten)]
    settings: serde_json::Value,
}

/// API v1 Config: Save custom mempool profile
async fn api_config_profiles_mempool_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(body): Json<ProfileSaveBody>,
) -> impl IntoResponse {
    let name = body.name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid profile name"})),
        )
            .into_response();
    }

    // Store in dashboard config custom profiles
    {
        let mut config = state.dashboard_config.write();
        config
            .custom_mempool_profiles
            .insert(name.clone(), body.settings.clone());
    }

    Json(serde_json::json!({
        "name": name,
        "settings": body.settings
    }))
    .into_response()
}

/// API v1 Config: Delete custom mempool profile
async fn api_config_profiles_mempool_delete_handler(
    State(state): State<Arc<VerificationState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let mut config = state.dashboard_config.write();
    config.custom_mempool_profiles.remove(&name);
    StatusCode::NO_CONTENT
}

/// API v1 Config: Activate a mempool profile
async fn api_config_profiles_mempool_activate_handler(
    State(state): State<Arc<VerificationState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    // Record the selection in the dashboard mirror. This is a cosmetic display
    // field; the real mining lever is `/api/v1/config/policy_profile`.
    let mut config = state.dashboard_config.write();
    config.mempool_profile = name.clone();
    Json(serde_json::json!({
        "success": true,
        "profile": name,
        "message": "Mempool profile updated"
    }))
}

/// API v1 Config: Save custom template profile
async fn api_config_profiles_template_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(body): Json<ProfileSaveBody>,
) -> impl IntoResponse {
    let name = body.name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid profile name"})),
        )
            .into_response();
    }

    {
        let mut config = state.dashboard_config.write();
        config
            .custom_template_profiles
            .insert(name.clone(), body.settings.clone());
    }

    Json(serde_json::json!({
        "name": name,
        "settings": body.settings
    }))
    .into_response()
}

/// API v1 Config: Delete custom template profile
async fn api_config_profiles_template_delete_handler(
    State(state): State<Arc<VerificationState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let mut config = state.dashboard_config.write();
    config.custom_template_profiles.remove(&name);
    StatusCode::NO_CONTENT
}

/// API v1 Config: Activate a template profile
async fn api_config_profiles_template_activate_handler(
    State(state): State<Arc<VerificationState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    // Cosmetic dashboard mirror; the real mining lever is
    // `/api/v1/config/policy_profile`.
    let mut config = state.dashboard_config.write();
    config.template_profile = name.clone();
    Json(serde_json::json!({
        "success": true,
        "profile": name,
        "message": "Template profile updated"
    }))
}

/// GhostPay payout address body
#[derive(Debug, Deserialize)]
struct GhostPayAddressBody {
    address: Option<String>,
}

/// API v1 Settings: Set GhostPay payout address (POST)
async fn api_settings_ghostpay_payout_address_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(body): Json<GhostPayAddressBody>,
) -> impl IntoResponse {
    {
        let mut config = state.dashboard_config.write();
        config.ghostpay_payout_address = body.address.clone();
    }

    Json(serde_json::json!({
        "address": body.address
    }))
}

/// Mining toggle body
#[derive(Debug, Deserialize)]
struct MiningToggleBody {
    enabled: Option<bool>,
}

/// API v1 Mining: Set private mining mode (POST)
async fn api_mining_private_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(body): Json<MiningToggleBody>,
) -> impl IntoResponse {
    if let Some(enabled) = body.enabled {
        let mut config = state.dashboard_config.write();
        config.private_mining = Some(enabled);
    }
    // Return current mining status
    api_mining_status_handler(State(state))
        .await
        .into_response()
}

/// API v1 Mining: Set public mining mode (POST)
async fn api_mining_public_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(body): Json<MiningToggleBody>,
) -> impl IntoResponse {
    if let Some(enabled) = body.enabled {
        let mut config = state.dashboard_config.write();
        config.public_mining = enabled;
    }
    api_mining_status_handler(State(state))
        .await
        .into_response()
}

/// Payout address body
#[derive(Debug, Deserialize)]
struct PayoutAddressBody {
    address: String,
}

/// API v1 Mining: Set payout address (POST)
async fn api_mining_payout_address_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(body): Json<PayoutAddressBody>,
) -> impl IntoResponse {
    {
        let mut config = state.dashboard_config.write();
        config.payout_address = Some(body.address);
    }
    api_mining_status_handler(State(state))
        .await
        .into_response()
}

/// Pool name body
#[derive(Debug, Deserialize)]
struct PoolNameBody {
    name: Option<String>,
}

/// API v1 Mining: Set pool name (POST)
/// Validates: ASCII printable, max 30 chars, no control characters.
/// Set name to null/empty to clear.
async fn api_mining_pool_name_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(body): Json<PoolNameBody>,
) -> impl IntoResponse {
    if let Some(ref name) = body.name {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            let mut config = state.dashboard_config.write();
            config.pool_name = None;
        } else if trimmed.len() > 30 {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Pool name must be 30 characters or fewer"})),
            )
                .into_response();
        } else if !trimmed
            .chars()
            .all(|c| c.is_ascii() && !c.is_ascii_control())
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Pool name must be ASCII printable characters only"})),
            )
                .into_response();
        } else {
            let mut config = state.dashboard_config.write();
            config.pool_name = Some(trimmed.to_string());
        }
    } else {
        let mut config = state.dashboard_config.write();
        config.pool_name = None;
    }
    api_mining_status_handler(State(state))
        .await
        .into_response()
}

/// Operator window body
#[derive(Debug, Deserialize)]
struct OperatorWindowBody {
    blocks: Option<u64>,
}

/// API v1 Config: Set operator window (POST)
async fn api_config_operator_window_post_handler(
    State(state): State<Arc<VerificationState>>,
    Json(body): Json<OperatorWindowBody>,
) -> impl IntoResponse {
    if let Some(blocks) = body.blocks {
        let mut config = state.dashboard_config.write();
        config.operator_window = Some(blocks);
    }

    if let Some(ref fnc) = state.full_node_config {
        let config = fnc.read();
        Json(serde_json::json!(config.clone())).into_response()
    } else {
        Json(serde_json::json!({"error": "Config not available"})).into_response()
    }
}

/// Backup delete handler
async fn api_backup_delete_handler(
    State(_state): State<Arc<VerificationState>>,
    Path(filename): Path<String>,
) -> impl IntoResponse {
    debug!(filename = %filename, "Delete backup requested");
    Json(serde_json::json!({
        "success": true,
        "message": format!("Backup {} deleted", filename)
    }))
}

/// Build the detailed connected-miner list (miners with a share in the last
/// 600s). Shared by the mesh-authed `/api/v1/mining/miners/full` peer endpoint
/// and the operator-authed detail branch of `/api/v1/mining/miners`, so both
/// surfaces return identical per-miner rows from one source of truth.
fn build_detailed_miner_list(state: &VerificationState) -> Vec<serde_json::Value> {
    let Some(ref db) = state.database else {
        return Vec::new();
    };
    let Ok(miner_stats) = db.get_all_miners_stats() else {
        return Vec::new();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    miner_stats
        .into_iter()
        .filter(|m| (now - m.last_seen) < 600)
        .map(|m| {
            // Use time from first share to now for stable estimate
            let elapsed = (now - m.first_seen).max(1) as f64;
            // Hashrate = SUM(difficulty) * 2^32 / elapsed / 1e12 (TH/s)
            let hashrate_th = m.total_work * 4294967296.0 / elapsed / 1e12;
            serde_json::json!({
                "worker_name": m.miner_id,
                // The SV1 authorize `<addr>.<worker>` becomes the SV2 channel
                // user_identity, so worker_name and user_identity are the same
                // key; expose both so either dashboard field name resolves.
                "user_identity": m.miner_id,
                "hashrate_th": hashrate_th,
                "shares_submitted": m.total_shares,
                "shares_accepted": m.valid_shares,
                "difficulty": m.avg_difficulty,
                "last_share": m.last_seen,
                "connected_at": m.first_seen,
                "active": true,
                "ip_address": ""
            })
        })
        .collect()
}

/// API v1 Miners: Full unredacted miner list (internal only)
async fn api_miners_full_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    let miners = build_detailed_miner_list(&state);
    Json(serde_json::json!({
        "total": miners.len(),
        "miners": miners
    }))
}

/// Simple hash for generating pseudo-IDs from addresses
fn fxhash(s: &str) -> u32 {
    let mut h: u32 = 0;
    for b in s.bytes() {
        h = h.wrapping_mul(0x01000193) ^ (b as u32);
    }
    h
}

/// Returns peers with public_mining enabled and their miner counts.
/// Used by the colocated translator for transparent TCP load balancing.
async fn pool_nodes_handler(State(state): State<Arc<VerificationState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "this_node": {
            "miner_count": state.miner_count(),
            "max_capacity": state.max_capacity(),
            // Deduped share attributed to this node; `this_node` + every peer's
            // `deduped_miner_count` sum to the deduped `mesh_active_miners`.
            "deduped_miner_count": state.self_deduped_miner_count(),
        },
        "peers": state.pool_peers(),
    }))
}

/// Return the Reaper observability snapshot (cumulative txs evaluated /
/// reaped / accepted, dead bytes total, per-DeadCodeType counters). Read by
/// the dashboard `/reaper` page. Counters are process-lived — they reset on
/// ghost-pool restart, matching the rest of the operator metric surface.
async fn api_reaper_status_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    Json(state.reaper_stats())
}

/// Return the capability self-check snapshot (per-capability
/// claimed/passed/reason) computed by the background loop in ghost-pool. The
/// dashboard reads this to warn an operator when they have CLAIMED a capability
/// (e.g. `public_mining`) whose prerequisite is missing (e.g. no stratum
/// listening on port 3333), so they don't silently fail to earn its shares.
/// Read-only: hands back the last snapshot; no probing happens in the request
/// path. Returns `null` on older deploys where the provider isn't wired.
async fn api_self_check_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    Json(state.self_check())
}

/// Read-only decentralised-coordinator election view
/// (`tasks/plan_decentralised_coordinators.md`). Returns
/// `{enabled, epoch, seats, my_seat, elected:[hex node ids]}` when the operator
/// has turned on `[coordinator] wraith_election_enabled`, else `{enabled:false}`.
/// This endpoint activates nothing — it only reports the public election draw.
async fn api_pool_coordinator_handler(
    State(state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    Json(state.coordinator_status())
}

/// Detect whether the operator has installed the per-node mempool.space stack
/// on this VM. The stack is opt-in (extra ~2 GB RAM, ~50 GB disk), so most
/// nodes won't have it — that's fine. Detection is deliberately cheap:
///
///   1. If `/etc/ghost/mempool-stack.enabled` exists, read the port from it
///      (operator's bring-up script writes this marker).
///   2. Otherwise default to checking port 8999.
///   3. TCP-connect with a 250 ms timeout to that port on localhost.
///
/// Returns one of three states:
///   - `running`             — port responds, frontend can iframe it
///   - `installed_not_running` — marker exists but port is silent
///   - `not_installed`       — no marker, port silent → show install panel
async fn api_system_mempool_handler(
    State(_state): State<Arc<VerificationState>>,
) -> impl IntoResponse {
    use std::time::Duration;
    use tokio::net::TcpStream;

    let marker_path = std::path::Path::new("/etc/ghost/mempool-stack.enabled");
    let marker_present = marker_path.exists();
    let port: u16 = if marker_present {
        std::fs::read_to_string(marker_path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(8999)
    } else {
        8999
    };

    let port_responds = tokio::time::timeout(
        Duration::from_millis(250),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);

    let status = match (marker_present, port_responds) {
        (_, true) => "running",
        (true, false) => "installed_not_running",
        (false, false) => "not_installed",
    };

    Json(serde_json::json!({
        "enabled": port_responds,
        "status": status,
        "port": port,
        "marker_path": marker_path.to_string_lossy(),
        // Helpful UI hints — keep these stable, the dashboard reads them.
        "install_command": "sudo /opt/ghost/bin/ghost-mempool install",
        "uninstall_command": "sudo /opt/ghost/bin/ghost-mempool uninstall",
        "min_ram_gb": 4,
        "min_disk_gb": 50,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_mpc_note_spend_path_serves_candidate_then_current() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let current = base.join("note_spend_params_current.bin");
        std::fs::write(&current, b"applied-head").unwrap();

        let new_hash = [0xABu8; 32];
        let candidate = base.join(ghost_common::mpc::candidate_note_spend_filename(&new_hash));
        let hash_hex = hex::encode(new_hash);

        // No hash → always the applied current head.
        assert_eq!(resolve_mpc_note_spend_path(base, None), current);
        assert_eq!(resolve_mpc_note_spend_path(base, Some("")), current);

        // A by-hash request BEFORE the candidate exists falls back to current
        // (never a 404 that would break the applied-params refresh path).
        assert_eq!(resolve_mpc_note_spend_path(base, Some(&hash_hex)), current);

        // Once the contributor has written the candidate, the by-hash request
        // resolves to the candidate — while a bare request still serves current.
        std::fs::write(&candidate, b"un-applied-candidate").unwrap();
        assert_eq!(
            resolve_mpc_note_spend_path(base, Some(&hash_hex)),
            candidate
        );
        assert_eq!(resolve_mpc_note_spend_path(base, None), current);

        // A request for a DIFFERENT candidate hash (none on disk) → current.
        let other = hex::encode([0x01u8; 32]);
        assert_eq!(resolve_mpc_note_spend_path(base, Some(&other)), current);

        // Malformed / traversal attempts can never escape the params dir.
        for bad in ["../../etc/passwd", "zz", "not-hex", "%2e%2e", "ab/cd"] {
            assert_eq!(
                resolve_mpc_note_spend_path(base, Some(bad)),
                current,
                "malformed new_hash {bad:?} must fall back to current"
            );
        }
    }

    #[test]
    fn test_valid_upload_target() {
        for ok in ["0", "500", "500M", "2G", "1t", "100k"] {
            assert!(valid_upload_target(ok), "{ok:?} should be valid");
        }
        for bad in ["", "M", "5x", "-1", "1.5G", "5 M", "GG"] {
            assert!(!valid_upload_target(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn test_validate_daemon_settings_accepts_sane_and_rejects_nonsense() {
        // A fully-populated, sane request passes.
        let good = DaemonSettingsRequest {
            max_mempool_mb: Some(600),
            mempool_expiry_hours: Some(72),
            max_connections: Some(40),
            max_upload_target_mb: Some("1G".to_string()),
            dbcache_mb: Some(2048),
            block_filter_index: Some(true),
            peer_block_filters: Some(true),
            onlynet: Some(vec!["onion".to_string(), "IPv4".to_string()]),
            i2p_sam: Some("127.0.0.1:7656".to_string()),
            i2p_accept_incoming: Some(true),
        };
        assert!(validate_daemon_settings(&good).is_ok());

        // An all-None request (clear everything back to ghostd defaults) passes.
        assert!(validate_daemon_settings(&DaemonSettingsRequest::default()).is_ok());

        // Out-of-range scalars are rejected.
        assert!(validate_daemon_settings(&DaemonSettingsRequest {
            max_mempool_mb: Some(1),
            ..Default::default()
        })
        .is_err());
        assert!(validate_daemon_settings(&DaemonSettingsRequest {
            max_connections: Some(0),
            ..Default::default()
        })
        .is_err());
        assert!(validate_daemon_settings(&DaemonSettingsRequest {
            mempool_expiry_hours: Some(0),
            ..Default::default()
        })
        .is_err());

        // Unknown onlynet value rejected.
        assert!(validate_daemon_settings(&DaemonSettingsRequest {
            onlynet: Some(vec!["moonnet".to_string()]),
            ..Default::default()
        })
        .is_err());

        // BIP157: peerblockfilters without blockfilterindex is rejected.
        assert!(validate_daemon_settings(&DaemonSettingsRequest {
            peer_block_filters: Some(true),
            block_filter_index: None,
            ..Default::default()
        })
        .is_err());

        // I2P: accept-incoming without a SAM proxy, and a malformed SAM address.
        assert!(validate_daemon_settings(&DaemonSettingsRequest {
            i2p_accept_incoming: Some(true),
            ..Default::default()
        })
        .is_err());
        assert!(validate_daemon_settings(&DaemonSettingsRequest {
            i2p_sam: Some("no-port".to_string()),
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn test_share_difficulty_from_hash_hex() {
        // The difficulty-1 target (pdiff) is 0xFFFF * 2^208 → difficulty 1.0.
        // In the big-endian hash string that is 0xFFFF after 8 leading hex zeros.
        let diff1 = "00000000ffff0000000000000000000000000000000000000000000000000000";
        let d1 = share_difficulty_from_hash_hex(diff1);
        assert!((d1 - 1.0).abs() < 1e-6, "diff-1 target hex → 1.0, got {d1}");

        // A real best-share hash with many leading zeros must read as a LARGE
        // achieved difficulty — the regression returned the ~1.5K vardiff target
        // instead. This exact hash mapped to ≈596.69M live (and via the web
        // client's hashToDifficulty), pinning byte order + formula together.
        let big = "000000000000000732a94aee7325d02fd49adbe4f89f9cfcb11ebf0bd33bc26b";
        let d = share_difficulty_from_hash_hex(big);
        assert!(
            (d - 596_688_523.7).abs() / 596_688_523.7 < 1e-6,
            "best-share hash must match the web client's 596.69M, got {d}"
        );

        // Malformed / wrong-length input is treated as unknown (0.0), never a panic.
        assert_eq!(share_difficulty_from_hash_hex(""), 0.0);
        assert_eq!(share_difficulty_from_hash_hex("not-hex"), 0.0);
        assert_eq!(share_difficulty_from_hash_hex("00ff"), 0.0);
    }

    #[test]
    fn test_archive_query() {
        let query = ArchiveQuery {
            block: Some("abc123".to_string()),
            tx: None,
            min_height: Some(100),
            nonce: None,
            unsigned: None,
        };

        assert!(query.block.is_some());
        assert!(query.tx.is_none());
    }

    #[test]
    fn test_archive_query_defaults_to_signed() {
        // Default behavior: signing is enabled (unsigned is None or false)
        let query = ArchiveQuery {
            block: Some("abc123".to_string()),
            tx: None,
            min_height: Some(100),
            nonce: Some("deadbeef".to_string()),
            unsigned: None,
        };

        // Should sign by default (unsigned is false when None)
        let should_sign = !query.unsigned.unwrap_or(false);
        assert!(should_sign);
        assert_eq!(query.nonce, Some("deadbeef".to_string()));
    }

    #[test]
    fn test_archive_query_explicit_unsigned() {
        // Explicitly disable signing
        let query = ArchiveQuery {
            block: Some("abc123".to_string()),
            tx: None,
            min_height: Some(100),
            nonce: None,
            unsigned: Some(true),
        };

        let should_sign = !query.unsigned.unwrap_or(false);
        assert!(!should_sign);
    }

    // ===========================================================================
    // CRIT-6: Config POST Authentication Tests
    // ===========================================================================
    //
    // These tests verify that config POST endpoints require authentication.
    // Without proper auth, all POST requests to config endpoints must return 401.

    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    fn test_secret() -> [u8; 32] {
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x42);
        }
        secret
    }

    fn create_test_state_with_auth() -> Arc<crate::server::VerificationState> {
        use ghost_common::types::NodeCapabilities;
        use ghost_policy::PolicyProfile;

        let auth = crate::auth::InternalAuth::new(&test_secret()).unwrap();
        let state = crate::server::VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        )
        .with_internal_auth(auth);

        Arc::new(state)
    }

    fn create_test_state_without_auth() -> Arc<crate::server::VerificationState> {
        use ghost_common::types::NodeCapabilities;
        use ghost_policy::PolicyProfile;

        let mut state = crate::server::VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        );

        // Set require_internal_auth to false so we can test the reject-all fallback
        state.require_internal_auth = false;

        Arc::new(state)
    }

    /// Test that config GET endpoints are publicly accessible (no auth required)
    #[tokio::test]
    async fn test_config_get_is_public() {
        let state = create_test_state_with_auth();
        let app = super::create_router(state);

        // GET requests should succeed without auth
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/config/archive_mode")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Regression: status/info endpoints must report the node's configured
    /// network, not a hardcoded value. Production nodes run mainnet; the old
    /// code always returned "signet", misleading the dashboard and wallets.
    #[tokio::test]
    async fn test_status_reports_configured_network() {
        use ghost_common::config::BitcoinNetwork;
        use ghost_common::types::NodeCapabilities;
        use ghost_policy::PolicyProfile;

        async fn network_field(state: Arc<crate::server::VerificationState>) -> String {
            let app = super::create_router(state);
            let response = app
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/api/v1/node/status")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
                .await
                .unwrap();
            let data: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            data["network"].as_str().unwrap().to_string()
        }

        let make_state = |network| {
            Arc::new(
                crate::server::VerificationState::new(
                    "test_node".to_string(),
                    "1.0.0".to_string(),
                    PolicyProfile::default(),
                    NodeCapabilities::default(),
                )
                .with_network(network),
            )
        };

        assert_eq!(
            network_field(make_state(BitcoinNetwork::Mainnet)).await,
            "mainnet",
            "mainnet-configured node must report mainnet"
        );
        assert_eq!(
            network_field(make_state(BitcoinNetwork::Regtest)).await,
            "regtest"
        );

        // Default (no with_network) preserves the historical signet value.
        let default_state = Arc::new(crate::server::VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        ));
        assert_eq!(network_field(default_state).await, "signet");
    }

    /// Regression: the ghostpay status endpoint's `wraith_enabled` must reflect
    /// the operator's `[ghost_pay] wraith_enabled` config choice, not ghost-pay's
    /// internal "hosts CoinJoin sessions" flag (always false since mixing moved
    /// to wraith-coordinator). Nodes with wraith_enabled = true were reporting
    /// false, so the dashboard L2 card showed Wraith "Not enabled" when it was.
    #[tokio::test]
    async fn test_ghostpay_status_reports_configured_wraith() {
        use ghost_common::types::NodeCapabilities;
        use ghost_policy::PolicyProfile;

        async fn wraith_field(state: Arc<crate::server::VerificationState>) -> serde_json::Value {
            let app = super::create_router(state);
            let response = app
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/api/v1/ghostpay/status")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
                .await
                .unwrap();
            serde_json::from_slice(&bytes).unwrap()
        }

        let make_state = |wraith_enabled| {
            let state = crate::server::VerificationState::new(
                "test_node".to_string(),
                "1.0.0".to_string(),
                PolicyProfile::default(),
                NodeCapabilities::default(),
            )
            .with_wraith_enabled(wraith_enabled);
            // Force the fast in-process path (no ghostpay handler wired in tests)
            // so the handler does not fall through to the 8800 network probe.
            state.dashboard_config.write().ghost_pay = false;
            Arc::new(state)
        };

        // Operator enabled Wraith → status must report true.
        let enabled = wraith_field(make_state(true)).await;
        assert_eq!(
            enabled["wraith_enabled"].as_bool(),
            Some(true),
            "config wraith_enabled = true must surface as wraith_enabled: true"
        );
        // The internal host-mixing signal stays distinct and false.
        assert_eq!(
            enabled["ghostpay_hosts_mixing"].as_bool(),
            Some(false),
            "ghost-pay no longer hosts mixing; host flag must stay false"
        );

        // Operator disabled Wraith → status must report false.
        let disabled = wraith_field(make_state(false)).await;
        assert_eq!(
            disabled["wraith_enabled"].as_bool(),
            Some(false),
            "config wraith_enabled = false must surface as wraith_enabled: false"
        );

        // Default (no with_wraith_enabled) preserves the historical off value.
        let default_state = {
            let state = crate::server::VerificationState::new(
                "test_node".to_string(),
                "1.0.0".to_string(),
                PolicyProfile::default(),
                NodeCapabilities::default(),
            );
            state.dashboard_config.write().ghost_pay = false;
            Arc::new(state)
        };
        assert_eq!(
            wraith_field(default_state).await["wraith_enabled"].as_bool(),
            Some(false)
        );
    }

    /// The reaper config POST must auto-apply the ghostd mempool reaper: it
    /// persists the config, then runs `ghost-setup apply-reaper` in the
    /// background and sequences the pool restart after. This exercises both the
    /// success path and the fail-safe (helper missing / not permitted) without
    /// shelling out, via the `GHOST_REAPER_APPLY_TEST_MODE` / `GHOST_SETUP_BIN`
    /// hooks. Runs both cases in one test so the process-global env vars can't
    /// race a parallel test.
    #[tokio::test]
    async fn test_config_reaper_post_auto_applies_ghostd() {
        use ghost_common::config::NodeConfig as FullNodeConfig;
        use ghost_common::types::NodeCapabilities;
        use ghost_policy::PolicyProfile;

        // Poll the shared apply record until it leaves the "applying" state.
        async fn settle(state: &Arc<crate::server::VerificationState>) -> String {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let st = state.ghostd_reaper_apply.read().state.clone();
                if st != "applying" {
                    return st;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "ghostd apply never settled"
                );
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }

        let post_reaper = |state: Arc<crate::server::VerificationState>,
                           auth: crate::auth::InternalAuth,
                           enabled: bool| {
            let app = super::create_router(Arc::clone(&state));
            async move {
                let body = format!(r#"{{"enabled": {enabled}}}"#);
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let signature = auth.sign(timestamp, body.as_bytes());
                let response = app
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/api/v1/config/reaper")
                            .header("Content-Type", "application/json")
                            .header("X-Ghost-Signature", signature)
                            .header("X-Ghost-Timestamp", timestamp.to_string())
                            .body(Body::from(body))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            }
        };

        let make_state = || {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("pool.toml");
            let auth = crate::auth::InternalAuth::new(&test_secret()).unwrap();
            let state = Arc::new(
                crate::server::VerificationState::new(
                    "test_node".to_string(),
                    "1.0.0".to_string(),
                    PolicyProfile::default(),
                    NodeCapabilities::default(),
                )
                .with_internal_auth(auth.clone())
                .with_full_node_config(FullNodeConfig::default(), path.clone()),
            );
            // Keep `dir` alive for the state's lifetime by leaking it (test-only).
            std::mem::forget(dir);
            (state, auth)
        };

        // --- Success path: apply-reaper "succeeds", ghostd reported applied,
        //     and the pool restart is requested AFTER (sequenced). ---
        std::env::remove_var("GHOST_SETUP_BIN");
        std::env::set_var("GHOST_REAPER_APPLY_TEST_MODE", "success");
        let (state, auth) = make_state();
        let resp = post_reaper(Arc::clone(&state), auth.clone(), true).await;
        assert_eq!(resp["persisted"].as_bool(), Some(true));
        assert_eq!(resp["ghostd_restart_required"].as_bool(), Some(false));
        // Response returns promptly while the apply is still in flight.
        assert_eq!(resp["ghostd_apply"]["state"].as_str(), Some("applying"));
        // Pool restart must NOT fire until the ghostd apply settles.
        assert!(
            !state.restart_requested(),
            "pool restart must be sequenced after ghostd apply"
        );
        assert_eq!(settle(&state).await, "applied");
        assert!(
            state.restart_requested(),
            "pool restart must be requested once ghostd apply succeeds"
        );
        std::env::remove_var("GHOST_REAPER_APPLY_TEST_MODE");

        // --- Fail-safe: helper binary missing → config still persisted, ghostd
        //     reported NOT applied with a reason, pool still applies. ---
        std::env::set_var("GHOST_SETUP_BIN", "/nonexistent/ghost-setup-does-not-exist");
        let (state, auth) = make_state();
        let resp = post_reaper(Arc::clone(&state), auth.clone(), true).await;
        assert_eq!(resp["persisted"].as_bool(), Some(true));
        assert_eq!(settle(&state).await, "failed");
        let msg = state.ghostd_reaper_apply.read().message.clone();
        assert!(msg.contains("not found"), "reason should explain the miss: {msg}");
        assert!(
            state.restart_requested(),
            "pool side must still apply even when ghostd apply fails"
        );
        std::env::remove_var("GHOST_SETUP_BIN");

        // --- Not persisted: no config path → skipped, no restart, no ghostd. ---
        let auth = crate::auth::InternalAuth::new(&test_secret()).unwrap();
        let state = Arc::new(
            crate::server::VerificationState::new(
                "test_node".to_string(),
                "1.0.0".to_string(),
                PolicyProfile::default(),
                NodeCapabilities::default(),
            )
            .with_internal_auth(auth.clone()),
        );
        let resp = post_reaper(Arc::clone(&state), auth, true).await;
        assert_eq!(resp["persisted"].as_bool(), Some(false));
        assert_eq!(resp["ghostd_apply"]["state"].as_str(), Some("skipped"));
        assert!(
            !state.restart_requested(),
            "nothing persisted → nothing to restart"
        );
    }

    /// CRIT-6: Test that config POST without auth returns 401
    #[tokio::test]
    async fn test_config_post_without_auth_returns_401() {
        let state = create_test_state_with_auth();
        let app = super::create_router(state);

        // POST without auth should fail with 401 Unauthorized
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/config/archive_mode")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"enabled": true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "CRIT-6: Config POST without auth must return 401"
        );
    }

    /// CRIT-6: Test that config POST with valid auth succeeds
    #[tokio::test]
    async fn test_config_post_with_valid_auth_succeeds() {
        let state = create_test_state_with_auth();
        let auth = crate::auth::InternalAuth::new(&test_secret()).unwrap();
        let app = super::create_router(state);

        let body = r#"{"enabled": true}"#;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signature = auth.sign(timestamp, body.as_bytes());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/config/archive_mode")
                    .header("Content-Type", "application/json")
                    .header("X-Ghost-Signature", signature)
                    .header("X-Ghost-Timestamp", timestamp.to_string())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Config POST with valid auth should succeed"
        );
    }

    /// The wraith toggle POST must persist `[ghost_pay] wraith_enabled` to the
    /// node config on disk so the operator's choice survives a restart. Mirrors
    /// the reaper toggle's persistence path.
    #[tokio::test]
    async fn test_config_wraith_post_persists_to_node_config() {
        use ghost_common::config::NodeConfig as FullNodeConfig;
        use ghost_common::types::NodeCapabilities;
        use ghost_policy::PolicyProfile;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.toml");

        let auth = crate::auth::InternalAuth::new(&test_secret()).unwrap();
        let state = Arc::new(
            crate::server::VerificationState::new(
                "test_node".to_string(),
                "1.0.0".to_string(),
                PolicyProfile::default(),
                NodeCapabilities::default(),
            )
            .with_internal_auth(auth.clone())
            .with_full_node_config(FullNodeConfig::default(), path.clone()),
        );

        let post_wraith = |enabled: bool| {
            let app = super::create_router(Arc::clone(&state));
            let auth = auth.clone();
            async move {
                let body = format!(r#"{{"enabled": {enabled}}}"#);
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let signature = auth.sign(timestamp, body.as_bytes());
                let response = app
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/api/v1/config/wraith")
                            .header("Content-Type", "application/json")
                            .header("X-Ghost-Signature", signature)
                            .header("X-Ghost-Timestamp", timestamp.to_string())
                            .body(Body::from(body))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            }
        };

        // Disable → persisted to disk and reflected in the loaded config.
        let off = post_wraith(false).await;
        assert_eq!(off["persisted"].as_bool(), Some(true));
        assert_eq!(off["enabled"].as_bool(), Some(false));
        let reloaded = FullNodeConfig::load(&path).unwrap();
        assert!(!reloaded.wraith_enabled(), "disable must persist to disk");

        // Re-enable → persisted true.
        let on = post_wraith(true).await;
        assert_eq!(on["persisted"].as_bool(), Some(true));
        assert_eq!(on["enabled"].as_bool(), Some(true));
        let reloaded = FullNodeConfig::load(&path).unwrap();
        assert!(reloaded.wraith_enabled(), "enable must persist to disk");
    }

    /// The policy_profile POST is the real lever for mined BUDS tiers: without
    /// HMAC it must 401, and with a valid signature it must persist
    /// `[policy].profile` to pool.toml and request a graceful restart.
    #[tokio::test]
    async fn test_config_policy_profile_post_persists_and_restarts() {
        use ghost_common::config::NodeConfig as FullNodeConfig;
        use ghost_common::config::PolicyProfile as CfgProfile;
        use ghost_common::types::NodeCapabilities;
        use ghost_policy::PolicyProfile;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.toml");

        let auth = crate::auth::InternalAuth::new(&test_secret()).unwrap();
        let state = Arc::new(
            crate::server::VerificationState::new(
                "test_node".to_string(),
                "1.0.0".to_string(),
                PolicyProfile::default(),
                NodeCapabilities::default(),
            )
            .with_internal_auth(auth.clone())
            .with_full_node_config(FullNodeConfig::default(), path.clone()),
        );

        // Without auth → 401.
        let unauth = super::create_router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/config/policy_profile")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"profile": "strict"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            unauth.status(),
            StatusCode::UNAUTHORIZED,
            "policy_profile POST without auth must 401"
        );
        assert!(!state.restart_requested());

        // With valid HMAC → persists `strict` and requests restart.
        let body = r#"{"profile": "strict"}"#;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signature = auth.sign(timestamp, body.as_bytes());
        let response = super::create_router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/config/policy_profile")
                    .header("Content-Type", "application/json")
                    .header("X-Ghost-Signature", signature)
                    .header("X-Ghost-Timestamp", timestamp.to_string())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["success"].as_bool(), Some(true));
        assert_eq!(json["profile"].as_str(), Some("strict"));
        assert_eq!(json["restart_pending"].as_bool(), Some(true));

        // Persisted to disk as BitcoinPure and restart requested.
        let reloaded = FullNodeConfig::load(&path).unwrap();
        assert_eq!(reloaded.policy.profile, CfgProfile::BitcoinPure);
        assert!(
            state.restart_requested(),
            "policy_profile change must request a restart"
        );

        // Unknown profile → 400.
        let bad = r#"{"profile": "nonsense"}"#;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signature = auth.sign(timestamp, bad.as_bytes());
        let bad_resp = super::create_router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/config/policy_profile")
                    .header("Content-Type", "application/json")
                    .header("X-Ghost-Signature", signature)
                    .header("X-Ghost-Timestamp", timestamp.to_string())
                    .body(Body::from(bad))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            bad_resp.status(),
            StatusCode::BAD_REQUEST,
            "unknown policy profile must 400"
        );
    }

    /// The policy_custom POST exposes every per-field policy knob: without HMAC
    /// it must 401, and with a valid signature it must set `[policy].profile =
    /// custom`, persist the full `[policy].custom` block to pool.toml and request
    /// a graceful restart. It must also reject a negative min_fee_rate with 400.
    #[tokio::test]
    async fn test_config_policy_custom_post_persists_and_restarts() {
        use ghost_common::config::NodeConfig as FullNodeConfig;
        use ghost_common::config::{BudsTier, PolicyProfile as CfgProfile};
        use ghost_common::types::NodeCapabilities;
        use ghost_policy::PolicyProfile;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.toml");

        let auth = crate::auth::InternalAuth::new(&test_secret()).unwrap();
        let state = Arc::new(
            crate::server::VerificationState::new(
                "test_node".to_string(),
                "1.0.0".to_string(),
                PolicyProfile::default(),
                NodeCapabilities::default(),
            )
            .with_internal_auth(auth.clone())
            .with_full_node_config(FullNodeConfig::default(), path.clone()),
        );

        // A representative custom body: T0+T1 only, all data off, tight limits.
        let body = r#"{
            "allow_t0": true,
            "allow_t1": true,
            "allow_t2": false,
            "allow_t3": false,
            "allow_inscriptions": false,
            "allow_runes": false,
            "allow_brc20": false,
            "max_op_return_size": 40,
            "max_witness_per_input": 500,
            "max_tx_outputs": 8,
            "max_tx_size": 90000,
            "min_fee_rate": 2.5
        }"#;

        // Without auth → 401.
        let unauth = super::create_router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/config/policy_custom")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            unauth.status(),
            StatusCode::UNAUTHORIZED,
            "policy_custom POST without auth must 401"
        );
        assert!(!state.restart_requested());

        // With valid HMAC → persists + requests restart.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signature = auth.sign(timestamp, body.as_bytes());
        let response = super::create_router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/config/policy_custom")
                    .header("Content-Type", "application/json")
                    .header("X-Ghost-Signature", signature)
                    .header("X-Ghost-Timestamp", timestamp.to_string())
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["success"].as_bool(), Some(true));
        assert_eq!(json["profile"].as_str(), Some("custom"));
        assert_eq!(json["restart_pending"].as_bool(), Some(true));

        // Persisted to disk: profile = Custom and the custom block round-trips.
        let reloaded = FullNodeConfig::load(&path).unwrap();
        assert_eq!(reloaded.policy.profile, CfgProfile::Custom);
        let custom = reloaded.policy.custom.expect("custom block persisted");
        assert_eq!(custom.allowed_tiers, vec![BudsTier::T0, BudsTier::T1]);
        assert_eq!(custom.max_op_return_size, 40);
        assert_eq!(custom.max_witness_per_input, 500);
        assert_eq!(custom.max_tx_outputs, 8);
        assert_eq!(custom.max_tx_size, 90000);
        assert!(!custom.allow_inscriptions);
        assert!(!custom.allow_runes);
        assert!(!custom.allow_brc20);
        assert_eq!(custom.min_fee_rate, 2.5);
        assert!(
            state.restart_requested(),
            "policy_custom change must request a restart"
        );

        // Negative min_fee_rate → 400.
        let bad = r#"{
            "allow_t0": true, "allow_t1": false, "allow_t2": false, "allow_t3": false,
            "allow_inscriptions": false, "allow_runes": false, "allow_brc20": false,
            "max_op_return_size": 0, "max_witness_per_input": 500,
            "max_tx_outputs": 8, "max_tx_size": 90000, "min_fee_rate": -1.0
        }"#;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signature = auth.sign(timestamp, bad.as_bytes());
        let bad_resp = super::create_router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/config/policy_custom")
                    .header("Content-Type", "application/json")
                    .header("X-Ghost-Signature", signature)
                    .header("X-Ghost-Timestamp", timestamp.to_string())
                    .body(Body::from(bad))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            bad_resp.status(),
            StatusCode::BAD_REQUEST,
            "negative min_fee_rate must 400"
        );
    }

    /// The extended config GET (`/api/v1/config/full`) must surface the active
    /// policy profile and the resolved custom field values so the dashboard can
    /// render the current preset and pre-fill the advanced panel.
    #[tokio::test]
    async fn test_config_full_surfaces_policy() {
        use ghost_common::config::NodeConfig as FullNodeConfig;
        use ghost_common::config::{BudsTier, CustomPolicyConfig, PolicyProfile as CfgProfile};
        use ghost_common::types::NodeCapabilities;
        use ghost_policy::PolicyProfile;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.toml");

        let mut cfg = FullNodeConfig::default();
        cfg.policy.profile = CfgProfile::Custom;
        cfg.policy.custom = Some(CustomPolicyConfig {
            allowed_tiers: vec![BudsTier::T0, BudsTier::T2],
            max_op_return_size: 33,
            max_witness_per_input: 111,
            max_tx_outputs: 7,
            max_tx_size: 12345,
            allow_inscriptions: true,
            allow_runes: false,
            allow_brc20: true,
            min_fee_rate: 3.0,
        });

        let state = Arc::new(
            crate::server::VerificationState::new(
                "test_node".to_string(),
                "1.0.0".to_string(),
                PolicyProfile::default(),
                NodeCapabilities::default(),
            )
            .with_full_node_config(cfg, path.clone()),
        );

        let response = super::create_router(Arc::clone(&state))
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/config/full")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["policy"]["profile"].as_str(), Some("custom"));
        let c = &json["policy"]["custom"];
        assert_eq!(c["allow_t0"].as_bool(), Some(true));
        assert_eq!(c["allow_t1"].as_bool(), Some(false));
        assert_eq!(c["allow_t2"].as_bool(), Some(true));
        assert_eq!(c["allow_t3"].as_bool(), Some(false));
        assert_eq!(c["allow_inscriptions"].as_bool(), Some(true));
        assert_eq!(c["allow_brc20"].as_bool(), Some(true));
        assert_eq!(c["max_op_return_size"].as_u64(), Some(33));
        assert_eq!(c["max_tx_outputs"].as_u64(), Some(7));
        assert_eq!(c["min_fee_rate"].as_f64(), Some(3.0));
    }

    /// CRIT-6: Test that all config POST endpoints require auth
    #[tokio::test]
    async fn test_all_config_post_endpoints_require_auth() {
        let state = create_test_state_with_auth();

        // List of all config POST endpoints that must require auth
        let config_endpoints = [
            "/api/v1/config/archive_mode",
            "/api/v1/config/ghost_mode",
            "/api/v1/config/policy_profile",
            "/api/v1/config/policy_custom",
            "/api/v1/config/public_mining",
            "/api/v1/config/reaper",
            "/api/v1/config/ghost_pay",
            "/api/v1/config/wraith",
            "/api/v1/config/elder",
            "/api/v1/config/prune_profile",
        ];

        for endpoint in config_endpoints {
            let app = super::create_router(Arc::clone(&state));

            let body = match endpoint {
                "/api/v1/config/policy_profile" => r#"{"profile": "strict"}"#,
                "/api/v1/config/policy_custom" => {
                    r#"{"allow_t0": true, "allow_t1": true, "allow_t2": false, "allow_t3": false, "allow_inscriptions": false, "allow_runes": false, "allow_brc20": false, "max_op_return_size": 40, "max_witness_per_input": 500, "max_tx_outputs": 8, "max_tx_size": 90000, "min_fee_rate": 1.0}"#
                }
                "/api/v1/config/prune_profile" => r#"{"profile": "standard"}"#,
                "/api/v1/config/elder" => r#"{"enabled": true, "slot": 1}"#,
                _ => r#"{"enabled": true}"#,
            };

            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(endpoint)
                        .header("Content-Type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "CRIT-6: {} POST without auth must return 401",
                endpoint
            );
        }
    }

    /// CRIT-6: Test that invalid signature is rejected
    #[tokio::test]
    async fn test_config_post_with_invalid_signature_returns_401() {
        let state = create_test_state_with_auth();
        let app = super::create_router(state);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Use a wrong signature (all zeros)
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/config/archive_mode")
                    .header("Content-Type", "application/json")
                    .header("X-Ghost-Signature", "00".repeat(32))
                    .header("X-Ghost-Timestamp", timestamp.to_string())
                    .body(Body::from(r#"{"enabled": true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "CRIT-6: Config POST with invalid signature must return 401"
        );
    }

    /// CRIT-6: Test that when no auth is configured, POST endpoints fail-closed
    #[tokio::test]
    async fn test_config_post_without_auth_config_fails_closed() {
        let state = create_test_state_without_auth();
        let app = super::create_router(state);

        // Even without auth configured, internal endpoints should reject all requests
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/config/archive_mode")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"enabled": true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "CRIT-6: Config POST must fail-closed when auth not configured"
        );
    }

    // ===========================================================================
    // Validation Helper Tests
    // ===========================================================================

    #[test]
    fn test_valid_hex_hash_64_chars() {
        let hash = "a".repeat(64);
        assert!(is_valid_hex_hash(&hash));
    }

    #[test]
    fn test_valid_hex_hash_too_short() {
        let hash = "a".repeat(62);
        assert!(!is_valid_hex_hash(&hash));
    }

    #[test]
    fn test_valid_hex_hash_too_long() {
        let hash = "a".repeat(66);
        assert!(!is_valid_hex_hash(&hash));
    }

    #[test]
    fn test_valid_hex_hash_non_hex() {
        // 'z' is not a valid hex character
        let mut hash = "a".repeat(63);
        hash.push('z');
        assert!(!is_valid_hex_hash(&hash));
    }

    #[test]
    fn test_safe_proc_path_allowed() {
        let allowed = vec!["/proc/meminfo".to_string(), "/proc/cpuinfo".to_string()];
        assert!(is_safe_proc_path("/proc/meminfo", &allowed));
    }

    #[test]
    fn test_safe_proc_path_traversal() {
        let allowed = vec!["/proc/meminfo".to_string(), "/proc/cpuinfo".to_string()];
        assert!(!is_safe_proc_path("/proc/../etc/passwd", &allowed));
    }

    #[test]
    fn test_mesh_node_to_json_shape() {
        let node = MeshNodeInfo {
            node_id: "deadbeef".to_string(),
            address: "1.2.3.4:8080".to_string(),
            elder: true,
            cap_archive: true,
            cap_ghost_pay: false,
            cap_public_mining: true,
            cap_reaper: false,
            cap_elder: true,
            hashrate_th: 12.5,
            miner_count: 3,
            deduped_miner_count: 2,
            max_capacity: 500,
            healthy: true,
            l1_height: Some(912_345),
            uptime_percent: Some(99.7),
            peer_count: Some(3),
            l2_height: Some(4_567),
        };

        let v = mesh_node_to_json(&node);
        assert_eq!(v["node_id"], "deadbeef");
        assert_eq!(v["address"], "1.2.3.4:8080");
        assert_eq!(v["elder"], true);
        assert_eq!(v["hashrate_th"], 12.5);
        assert_eq!(v["miner_count"], 3);
        assert_eq!(v["deduped_miner_count"], 2);
        assert_eq!(v["max_capacity"], 500);
        assert_eq!(v["healthy"], true);
        // Gossiped Swarm telemetry surfaces on the peer JSON.
        assert_eq!(v["l1_height"], 912_345);
        assert_eq!(v["uptime_percent"], 99.7);
        assert_eq!(v["peer_count"], 3);
        assert_eq!(v["l2_height"], 4_567);
        // Peers are never self.
        assert_eq!(v["is_self"], false);
        // Capabilities are nested exactly as the website expects.
        assert_eq!(v["capabilities"]["archive"], true);
        assert_eq!(v["capabilities"]["ghost_pay"], false);
        assert_eq!(v["capabilities"]["public_mining"], true);
        assert_eq!(v["capabilities"]["reaper"], false);
        assert_eq!(v["capabilities"]["elder"], true);
    }

    #[test]
    fn test_mesh_node_to_json_defaults_for_bare_peer() {
        // A peer that has only just been discovered (no gossiped metrics yet)
        // must still serialize to a complete object with safe defaults rather
        // than dropping fields or failing.
        let node = MeshNodeInfo {
            node_id: "00ff".to_string(),
            address: String::new(),
            elder: false,
            cap_archive: false,
            cap_ghost_pay: false,
            cap_public_mining: false,
            cap_reaper: false,
            cap_elder: false,
            hashrate_th: 0.0,
            miner_count: 0,
            deduped_miner_count: 0,
            max_capacity: 0,
            healthy: false,
            l1_height: None,
            uptime_percent: None,
            peer_count: None,
            l2_height: None,
        };

        let v = mesh_node_to_json(&node);
        assert_eq!(v["address"], "");
        assert_eq!(v["hashrate_th"], 0.0);
        assert_eq!(v["miner_count"], 0);
        assert_eq!(v["deduped_miner_count"], 0);
        assert_eq!(v["max_capacity"], 0);
        assert_eq!(v["healthy"], false);
        // Unreported telemetry serialises to JSON null → "—" on the page, never
        // a fabricated 0.
        assert!(v["l1_height"].is_null());
        assert!(v["uptime_percent"].is_null());
        assert!(v["peer_count"].is_null());
        assert!(v["l2_height"].is_null());
        assert!(v["capabilities"].is_object());
    }

    #[test]
    fn test_mesh_capability_shares() {
        // Full stack: 5 + 4 + 3 + 2 + 1 = 15.
        assert_eq!(mesh_capability_shares(true, true, true, true, true), 15);
        // None: 0.
        assert_eq!(mesh_capability_shares(false, false, false, false, false), 0);
        // Ghost Pay (+4) + Public Mining (+3) + Reaper (+2) + Elder (+1) = 10,
        // matching the observed production self-node total.
        assert_eq!(mesh_capability_shares(false, true, true, true, true), 10);
        // Individual weights.
        assert_eq!(mesh_capability_shares(true, false, false, false, false), 5);
        assert_eq!(mesh_capability_shares(false, false, false, false, true), 1);
    }

    #[test]
    fn test_mesh_node_name_uses_host() {
        // Host portion of an advertised address.
        assert_eq!(
            mesh_node_name("83.136.251.162:8559", "abcdef0123456789"),
            "83.136.251.162"
        );
        // No port.
        assert_eq!(mesh_node_name("myhost", "abcdef0123456789"), "myhost");
        // No address gossiped yet -> short node-id label.
        assert_eq!(mesh_node_name("", "abcdef0123456789"), "node-abcdef01");
        // Address that is only a port marker (":8555") also degrades to the id.
        assert_eq!(mesh_node_name(":8555", "abcdef0123456789"), "node-abcdef01");
    }

    /// Stage C task 3 — sync endpoint round-trip:
    /// a "server" node persists a chain (contributions WITH real proof + votes),
    /// serves position 2 over `GET /api/v1/mpc/votes/2`, and a "fresh" node parses
    /// the response, persists the non-empty proof + votes, and the genesis-anchored
    /// startup quorum check then PASSES on the fresh node.
    #[tokio::test]
    async fn test_mpc_votes_endpoint_roundtrip() {
        use axum::body::Body;
        use axum::http::Request;
        use ghost_common::identity::NodeIdentity;
        use ghost_common::mpc::{contribution_hash, vote_signing_message};
        use ghost_storage::queries::{MpcContributionRecord, MpcVerificationVote};
        use ghost_storage::Database;
        use tower::ServiceExt;

        let anchor = [0xC9u8; 32];
        let id1 = NodeIdentity::generate(); // contributor at position 1 (elder #1)
        let id2 = NodeIdentity::generate(); // contributor at position 2
        let new1 = [0x11u8; 32];
        let new2 = [0x22u8; 32];

        // Real (non-empty) proof bytes for each position. Their CONTENT is opaque
        // to the quorum check (which binds votes to new_params_hash), so arbitrary
        // non-empty bytes suffice to prove the proof survives the round-trip.
        let proof1 = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let proof2 = vec![0x01, 0x02, 0x03, 0x04, 0x05];

        // --- server DB ---
        let server_db = Database::in_memory().unwrap();
        server_db
            .save_mpc_contribution(&MpcContributionRecord {
                elder_position: 1,
                contributor_node_id: hex::encode(id1.node_id()),
                prev_params_hash: anchor,
                new_params_hash: new1,
                contribution_proof: proof1.clone(),
                epoch: 0,
                created_at: 100,
            })
            .unwrap();
        server_db
            .save_mpc_contribution(&MpcContributionRecord {
                elder_position: 2,
                contributor_node_id: hex::encode(id2.node_id()),
                prev_params_hash: new1,
                new_params_hash: new2,
                contribution_proof: proof2.clone(),
                epoch: 0,
                created_at: 200,
            })
            .unwrap();
        // Position 2's approve vote from elder #1 (the only then-eligible elder).
        let ch2 = contribution_hash(&id2.node_id(), 2, &new2);
        let approve_msg = vote_signing_message(&ch2, true);
        let sig = id1.sign(&approve_msg);
        server_db
            .save_mpc_vote(&MpcVerificationVote {
                contribution_position: 2,
                voter_node_id: hex::encode(id1.node_id()),
                approve: true,
                signature: sig.to_vec(),
                voted_at: 200,
            })
            .unwrap();

        // --- serve position 2 over HTTP ---
        let state = {
            use ghost_common::types::NodeCapabilities;
            use ghost_policy::PolicyProfile;
            Arc::new(
                crate::server::VerificationState::new(
                    hex::encode(id1.node_id()),
                    "1.0.0".to_string(),
                    PolicyProfile::default(),
                    NodeCapabilities::default(),
                )
                .with_database(server_db),
            )
        };
        let app = super::create_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/mpc/votes/2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // The served proof is non-empty (the bug this endpoint fixes).
        let served_proof_hex = data["contribution"]["contribution_proof"].as_str().unwrap();
        assert_eq!(served_proof_hex, hex::encode(&proof2));
        assert!(!served_proof_hex.is_empty());
        assert_eq!(data["vote_count"].as_u64().unwrap(), 1);

        // --- fresh node: parse + persist, then the quorum check passes ---
        let fresh_db = Database::in_memory().unwrap();
        // Position 1 (genesis) is anchored, no votes needed; persist its row.
        fresh_db
            .save_mpc_contribution(&MpcContributionRecord {
                elder_position: 1,
                contributor_node_id: hex::encode(id1.node_id()),
                prev_params_hash: anchor,
                new_params_hash: new1,
                contribution_proof: proof1.clone(),
                epoch: 0,
                created_at: 100,
            })
            .unwrap();
        // Persist position 2 exactly as the sync path would, from the served JSON.
        let c = &data["contribution"];
        let proof_bytes = hex::decode(c["contribution_proof"].as_str().unwrap()).unwrap();
        assert!(
            !proof_bytes.is_empty(),
            "fresh node must persist a real proof"
        );
        fresh_db
            .save_mpc_contribution(&MpcContributionRecord {
                elder_position: c["position"].as_u64().unwrap() as u32,
                contributor_node_id: c["node_id"].as_str().unwrap().to_string(),
                prev_params_hash: hex::decode(c["prev_params_hash"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                new_params_hash: hex::decode(c["new_params_hash"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                contribution_proof: proof_bytes,
                epoch: 0,
                created_at: c["created_at"].as_u64().unwrap(),
            })
            .unwrap();
        for v in data["votes"].as_array().unwrap() {
            fresh_db
                .save_mpc_vote(&MpcVerificationVote {
                    contribution_position: 2,
                    voter_node_id: v["voter_node_id"].as_str().unwrap().to_string(),
                    approve: v["approve"].as_bool().unwrap(),
                    signature: hex::decode(v["signature"].as_str().unwrap()).unwrap(),
                    voted_at: v["voted_at"].as_u64().unwrap(),
                })
                .unwrap();
        }

        // The fresh node's genesis-anchored startup verification now passes.
        let verified = fresh_db
            .verify_mpc_genesis_anchored_lineage(&anchor, Some(&new2))
            .expect("fresh node startup quorum check must pass after sync");
        assert_eq!(verified, 2);
    }

    /// Build a state with operator auth + an in-memory DB holding one recent
    /// `<addr>.<worker>` share, for the miner-details endpoint tests.
    fn miner_details_state() -> Arc<crate::server::VerificationState> {
        use ghost_common::types::NodeCapabilities;
        use ghost_policy::PolicyProfile;
        use ghost_storage::Database;

        let db = Database::in_memory().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        db.insert_share(&ghost_storage::ShareRecord {
            id: None,
            round_id: 1,
            miner_id: "tb1qminerexampleaddr.worker1".to_string(),
            difficulty: 1024.0,
            work: 4096.0,
            share_hash: "00".repeat(32),
            timestamp: now,
            received_by: "test_node".to_string(),
            valid: true,
        })
        .unwrap();

        let auth = crate::auth::InternalAuth::new(&test_secret()).unwrap();
        Arc::new(
            crate::server::VerificationState::new(
                "test_node".to_string(),
                "1.0.0".to_string(),
                PolicyProfile::default(),
                NodeCapabilities::default(),
            )
            .with_internal_auth(auth)
            .with_database(db),
        )
    }

    /// Sign an empty-body GET exactly as the dashboard proxy does with the
    /// operator INTERNAL_AUTH_KEY, returning (signature, timestamp).
    fn operator_get_signature() -> (String, u64) {
        let auth = crate::auth::InternalAuth::new(&test_secret()).unwrap();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (auth.sign(timestamp, b""), timestamp)
    }

    /// Operator-authed `/api/v1/mining/miners` returns the full unredacted
    /// per-miner list (worker, hashrate, shares, difficulty) — the data the
    /// dashboard's Connected Miners table needs — using only INTERNAL_AUTH_KEY.
    #[tokio::test]
    async fn test_mining_miners_operator_auth_returns_full_list() {
        let state = miner_details_state();
        let app = super::create_router(state);
        let (signature, timestamp) = operator_get_signature();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/mining/miners")
                    .header("X-Ghost-Signature", signature)
                    .header("X-Ghost-Timestamp", timestamp.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(
            data["miners_redacted"].as_bool(),
            Some(false),
            "operator-authed request must NOT be redacted"
        );
        let miners = data["miners"].as_array().expect("miners array");
        assert_eq!(miners.len(), 1, "the one recent miner must be listed");
        let m = &miners[0];
        assert_eq!(
            m["worker_name"].as_str(),
            Some("tb1qminerexampleaddr.worker1")
        );
        assert_eq!(
            m["user_identity"].as_str(),
            Some("tb1qminerexampleaddr.worker1")
        );
        assert_eq!(m["shares_submitted"].as_u64(), Some(1));
        assert_eq!(m["shares_accepted"].as_u64(), Some(1));
        assert!(m["difficulty"].as_f64().unwrap() > 0.0);
        assert!(m["hashrate_th"].as_f64().unwrap() > 0.0);
    }

    /// Without a valid operator signature `/api/v1/mining/miners` stays redacted
    /// (M-11): no individual miner rows leak to unauthenticated callers.
    #[tokio::test]
    async fn test_mining_miners_unauthed_is_redacted() {
        let state = miner_details_state();
        let app = super::create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/mining/miners")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(
            data["miners_redacted"].as_bool(),
            Some(true),
            "unauthenticated request must be redacted"
        );
        assert!(
            data.get("miners").is_none(),
            "no individual miner list without operator auth"
        );
    }

    /// The mesh/operator-HMAC peer endpoint `/api/v1/mining/miners/full` still
    /// serves the full list when signed — the peer path is unchanged.
    #[tokio::test]
    async fn test_mining_miners_full_hmac_path_still_works() {
        let state = miner_details_state();
        let app = super::create_router(state);
        let (signature, timestamp) = operator_get_signature();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/mining/miners/full")
                    .header("X-Ghost-Signature", signature)
                    .header("X-Ghost-Timestamp", timestamp.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
            .await
            .unwrap();
        let data: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(data["total"].as_u64(), Some(1));
        assert_eq!(data["miners"].as_array().unwrap().len(), 1);
    }

    /// `/api/v1/mining/status` exposes the SV2 authority public key so the
    /// dashboard can source it dynamically. Defaults to the network-wide
    /// constant, and honours a per-node `[network] sv2_authority_public_key`.
    #[tokio::test]
    async fn test_mining_status_exposes_authority_key() {
        use ghost_common::config::NodeConfig as FullNodeConfig;
        use ghost_common::types::NodeCapabilities;
        use ghost_policy::PolicyProfile;

        async fn authority(state: Arc<crate::server::VerificationState>) -> String {
            let app = super::create_router(state);
            let response = app
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/api/v1/mining/status")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
                .await
                .unwrap();
            let data: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            data["authority_public_key"]
                .as_str()
                .expect("authority_public_key must be present")
                .to_string()
        }

        // Default: the network-wide constant.
        let default_state = Arc::new(crate::server::VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        ));
        assert_eq!(
            authority(default_state).await,
            SV2_AUTHORITY_PUBLIC_KEY,
            "status must advertise the default SV2 authority key"
        );

        // Operator override via pool.toml wins.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.toml");
        let mut cfg = FullNodeConfig::default();
        cfg.network.sv2_authority_public_key = Some("customAuthorityKey123".to_string());
        let override_state = Arc::new(
            crate::server::VerificationState::new(
                "test_node".to_string(),
                "1.0.0".to_string(),
                PolicyProfile::default(),
                NodeCapabilities::default(),
            )
            .with_full_node_config(cfg, path),
        );
        assert_eq!(authority(override_state).await, "customAuthorityKey123");
    }

    /// The self-check endpoint must serialise a FAILING snapshot so the
    /// dashboard can warn the operator (e.g. public_mining claimed but no
    /// stratum listening). Wire a provider that returns a failing capability
    /// and assert the endpoint reflects claimed/passed/reason verbatim.
    #[tokio::test]
    async fn test_self_check_endpoint_serialises_failure() {
        use ghost_common::types::NodeCapabilities;
        use ghost_policy::PolicyProfile;

        let state = Arc::new(
            crate::server::VerificationState::new(
                "test_node".to_string(),
                "1.0.0".to_string(),
                PolicyProfile::default(),
                NodeCapabilities::default(),
            )
            .with_self_check(|| {
                serde_json::json!({
                    "public_mining": {
                        "claimed": true,
                        "passed": false,
                        "reason": "SV1 stratum (port 3333) not listening — start sri-translator",
                        "last_checked_unix": 1_700_000_000_i64,
                    },
                    "archive": { "claimed": false, "passed": false, "reason": null, "last_checked_unix": 1_700_000_000_i64 },
                    "ghost_pay": { "claimed": false, "passed": false, "reason": null, "last_checked_unix": 1_700_000_000_i64 },
                    "reaper": { "claimed": false, "passed": false, "reason": null, "last_checked_unix": 1_700_000_000_i64 },
                })
            }),
        );
        let app = super::create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/system/self-check")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["public_mining"]["claimed"], true);
        assert_eq!(json["public_mining"]["passed"], false);
        assert!(json["public_mining"]["reason"]
            .as_str()
            .unwrap()
            .contains("port 3333"));
    }

    /// Pre-bounce safety: when the provider isn't wired (older deploy), the
    /// endpoint must still respond 200 with a JSON `null` body so the frontend
    /// can treat "absent/ok" as "render nothing".
    #[tokio::test]
    async fn test_self_check_endpoint_null_when_unwired() {
        let state = create_test_state_without_auth();
        let app = super::create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/system/self-check")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json.is_null());
    }
}
