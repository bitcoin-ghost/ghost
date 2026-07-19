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
//| FILE: main.rs                                                                                                        |
//|======================================================================================================================|

//! Ghost Pool - Bitcoin Ghost Mining Pool Node
//!
//! Main entry point for the Ghost Pool node. This is a complete mining pool
//! implementation featuring:
//!
//! - Stratum V2 server for miner connections
//! - BUDS-based transaction filtering
//! - Pre-consensus coinbase construction
//! - P2P mesh network for share propagation
//! - 67% BFT consensus for payouts
//!
//! Run with: ghost-pool --config ghost.toml

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::prelude::*;

use ghost_common::config::{MiningMode, NodeConfig, ReaperSettings};
use ghost_common::identity::NodeIdentity;
use ghost_common::metrics::Metrics;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::signer::SignerConfig;
use ghost_common::types::{ConsensusResult, NodeCapabilities};
use ghost_common::zmq::{ZmqConfig, ZmqSubscriber};
use ghost_consensus::ban_manager::BanManager;
use ghost_consensus::health_handler::HealthPingHandler;
use ghost_consensus::mesh::{MeshConfig, MeshNetwork};
use ghost_consensus::message::MessageType;
use ghost_consensus::verification_handler::VerificationResultHandler;
use ghost_consensus::vote_handler::{
    BroadcastFn, ExecuteFn, ProposalStoreFn, VoteHandler, VoteHandlerConfig,
};
use ghost_consensus::voting::VotingManager;
use ghost_policy::PolicyProfile;
use ghost_reaper::ReaperConfig;
use ghost_storage::Database;
use ghost_verification::{
    start_server, GspHandler, PeerProvider, QualifiedCapabilityProvider, RpcArchiveHandler,
    VerifiablePeer, VerificationState, VerificationTask,
};

use ghost_pool::capacity;
use ghost_pool::payout::{BlockFoundData, PayoutConfig, PayoutHandler, SoloBlockFoundData};
use ghost_pool::registry::RegistryClient;
use ghost_pool::reorg::{ReorgConfig, ReorgHandler};
use ghost_pool::round::{RoundConfig, RoundEvent, RoundManager};
use ghost_pool::self_check::SelfCheck;
use ghost_pool::share_handler::ShareProofHandler;
use ghost_pool::template::{TemplateConfig, TemplateEvent, TemplateProcessor};
use ghost_pool::template_provider::{TdpConfig, TemplateDistributionServer};
use ghost_pool::treasury::TreasuryState;

/// Exit code that signals systemd to restart the service
/// Used when config is updated via API and requires restart to apply
const EXIT_CODE_RESTART: i32 = 100;

/// Block height at which the payout proposal switches from per-`miner_id` grouping to
/// per-`payout_address` grouping.
///
/// Below this height: a user running N workers under one address takes N coinbase output
/// slots. At/above this height: their unpaid work is summed across workers and they take
/// ONE slot — freeing the rest for other miners.
///
/// This is a BFT-voted payout calculation. If any node uses a different algorithm than its
/// peers, its proposal diverges and never reaches the 67 % supermajority. Baking the
/// activation as a block-height gate (not a feature flag) means every node makes the same
/// decision at the same block. See `tasks/plan_payout_address_grouping.md` for the rollout.
///
/// Defined in the library so that the proposer and the GHOST-02 validator — which must
/// group the ledger identically — cannot drift apart. Re-exported here for the binary.
use ghost_pool::PAYOUT_ADDRESS_GROUPING_HEIGHT;

/// Trailing window for the per-node realized hashrate gossiped in health pings
/// and summed into the mesh-wide pool total. 10 minutes smooths small-miner
/// share variance while still tracking real changes within a few minutes.
const MESH_HASHRATE_WINDOW_SECS: i64 = 600;

/// Records windows gossiped in health pings: `(name, cutoff_secs)`. MUST match
/// the windows the `/api/v1/pool/records` endpoint serves so the gossiped best
/// merges 1:1 with the local DB best per window.
const RECORD_WINDOWS: [(&str, i64); 4] = [
    ("block", 600),
    ("day", 86_400),
    ("week", 604_800),
    ("month", 2_592_000),
];

/// MPC contribution retry window (a joining node broadcasting its candidate).
///
/// A joining node broadcasts a signed contribution candidate and then waits for
/// the existing elders to fetch its (~2.8 MB) parameters, run the heavy Groth16
/// `verify_contribution` pairing check, gossip votes, reach BFT quorum, apply
/// the contribution and propagate the new head back. On release builds that full
/// round trip routinely takes well over a minute per candidate. The window must
/// therefore be generous: we rebroadcast the SAME stable candidate on every
/// attempt (see `cached_contribution_still_valid`) so votes accumulate for one
/// `new_hash`, and give voters ~15-20 min total to converge instead of giving up
/// after ~5 minutes (the old 5-attempt / 10-100s loop that let the candidate
/// hash keep changing faster than voters could verify — the "moving target").
///
/// 15 attempts with a randomised 60-90s delay ⇒ 14 sleeps × ~75s ≈ 17.5 min.
/// These are consensus-affecting timings and are deliberately NOT env-tunable.
///
/// This is NO LONGER a terminal cap: a node that genuinely wants to be an elder
/// keeps retrying indefinitely (with escalating backoff) rather than declaring
/// "Node will not be an elder" after this many rounds. This constant now only
/// marks the boundary between the fast converge window (fixed 60-90s delay) and
/// the slow long-tail (exponential backoff up to `MPC_CONTRIBUTION_BACKOFF_MAX_SECS`).
const MPC_CONTRIBUTION_MAX_ATTEMPTS: u32 = 15;
/// Minimum per-attempt retry delay — enough for a voter to fetch the candidate,
/// run the Groth16 verify, gossip its vote, reach quorum, apply and propagate
/// back on a release build before we rebroadcast.
const MPC_CONTRIBUTION_RETRY_DELAY_MIN_SECS: u64 = 60;
/// Maximum per-attempt retry delay. The delay is randomised in
/// `[MIN, MAX]` to avoid a thundering herd when several nodes retry at once.
const MPC_CONTRIBUTION_RETRY_DELAY_MAX_SECS: u64 = 90;
/// Upper bound (seconds) on the escalating inter-round backoff once a node has
/// spent its initial `MPC_CONTRIBUTION_MAX_ATTEMPTS` fast rounds without being
/// voted in. A node that wants to be an elder NEVER permanently gives up (the
/// node7/node8 onboarding bug that needed a manual restart); it keeps retrying
/// and re-checking mesh readiness, but throttles to at most one round every few
/// minutes so it does not hammer the mesh forever.
#[cfg(feature = "mpc-ceremony")]
const MPC_CONTRIBUTION_BACKOFF_MAX_SECS: u64 = 300;

/// Freshness window (seconds) for counting an elder peer as "connected" in the
/// MPC mesh-registration readiness gate. Health pings arrive every ~10s, so 60s
/// tolerates a few missed pings without admitting long-dead peers.
#[cfg(feature = "mpc-ceremony")]
const MPC_READINESS_ELDER_FRESHNESS_SECS: u64 = 60;
/// Poll interval (seconds) while waiting for mesh registration before the first
/// contribution attempt. The gate sleeps between polls — it never busy-loops.
#[cfg(feature = "mpc-ceremony")]
const MPC_READINESS_POLL_SECS: u64 = 10;
/// Overall ceiling (seconds) on the pre-contribution mesh-registration wait.
/// Fail-safe: after this the node proceeds to attempt anyway. The contribution
/// loop itself re-checks readiness every round, so a node that is still not
/// meshed simply keeps retrying (with backoff) rather than blocking here forever.
#[cfg(feature = "mpc-ceremony")]
const MPC_READINESS_MAX_WAIT_SECS: u64 = 600;

/// Decide whether a cached MPC contribution candidate is still valid to
/// rebroadcast unchanged on the next retry.
///
/// A candidate is generated for ceremony position `cached_count + 1`, chained
/// onto the applied head at authoritative count `cached_count`. It stays valid
/// for as long as the authoritative contribution count has NOT advanced: no new
/// contribution has been applied, so our candidate still targets the correct
/// position and chains onto the correct head. In that case we rebroadcast the
/// SAME candidate (identical `new_hash`) so voters accumulate votes toward
/// quorum instead of chasing a fresh hash every attempt.
///
/// If the count has ADVANCED (`current_count != cached_count`, i.e. another
/// contribution was applied while we waited), our candidate is built on a stale
/// head and MUST be regenerated (rebased) onto the new head — its
/// `prev_params_hash` would otherwise fail hash-chain validation.
fn cached_contribution_still_valid(cached_count: u32, current_count: u32) -> bool {
    current_count == cached_count
}

/// Decide whether to advertise the Archive capability (+5 shares).
///
/// The claim must reflect Ghost Core's REAL archive state, not merely the
/// operator's `storage.archive_mode` config flag. Archive is only advertised when
/// the operator asked for it AND ghostd is genuinely serving a full block store:
/// - `hazed` nodes strip witness/scriptSig/OP_RETURN data, so they cannot return
///   whole historical blocks, and
/// - `pruned` nodes have discarded old blocks entirely, so they cannot serve the
///   arbitrary historical block the Archive challenge asks for.
///
/// Claiming Archive in either state always fails qualification and wastes every
/// peer's verification challenges, so we drop the claim up front. The `hazed` and
/// `pruned` inputs come straight from `getblockchaininfo`; the caller only reaches
/// this with a real response (the pool hard-exits if ghostd's RPC is unreachable),
/// so an unknown ghostd state never newly-claims Archive — fail-safe by design.
fn should_claim_archive(config_archive_mode: bool, hazed: bool, pruned: bool) -> bool {
    config_archive_mode && !hazed && !pruned
}

/// Local ghost-pay endpoint that accepts L2 checkpoint finalization notices.
/// ghost-pay serves identity-derived TLS on 8800; the caller uses a client with
/// `danger_accept_invalid_certs(true)` since this is loopback-only IPC.
const GHOST_PAY_FINALIZE_URL: &str = "https://127.0.0.1:8800/api/v1/l2/finalize";

/// Notify the local ghost-pay daemon that an L2 checkpoint finalized at `height`.
///
/// Retries up to 3 times with exponential backoff (500ms, then 1000ms). On
/// success returns the zero-based index of the attempt that succeeded (so the
/// caller can log a plain success vs. a succeeded-after-retry); on total failure
/// returns the last error string. This is only ever invoked when
/// [`NodeConfig::ghost_pay_enabled`] is true, so a returned `Err` always means a
/// genuine problem reaching a ghost-pay that is supposed to be running locally —
/// worth logging as an error — rather than the "ghost-pay isn't installed" case,
/// which is now gated out entirely at the call site.
async fn notify_ghost_pay_finalize(
    client: &reqwest::Client,
    endpoint: &str,
    height: u64,
    state_root: [u8; 32],
    nullifiers: &[[u8; 32]],
) -> Result<u32, String> {
    let body = serde_json::json!({
        "height": height,
        "state_root": hex::encode(state_root),
        "attestation_count": nullifiers.len(),
        "included_tx_ids": nullifiers.iter().map(hex::encode).collect::<Vec<_>>(),
    });
    let mut last_err = String::new();
    for attempt in 0..3u32 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(
                500 * 2u64.pow(attempt - 1),
            ))
            .await;
        }
        match client.post(endpoint).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(attempt),
            Ok(resp) => last_err = format!("HTTP {}", resp.status()),
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(last_err)
}

/// Local ghost-pay L2 status endpoint (unsigned, loopback IPC). Same service as
/// [`GHOST_PAY_FINALIZE_URL`]; returns this node's L2 virtual-block height.
const GHOST_PAY_STATUS_URL: &str = "https://127.0.0.1:8800/verify/ghostpay?unsigned=true";

/// Lightweight cache of the local ghost-pay L2 virtual-block height, refreshed
/// by a background poller and read (a cheap atomic load) on the health-ping hot
/// path so gossiping this node's L2 tip never blocks on a cross-process call.
/// `known` stays false until the first successful poll; once set it retains the
/// last good value across a failed poll, so peers see "—" only while we
/// genuinely have no L2 height to report.
#[derive(Default)]
struct L2HeightCache {
    height: std::sync::atomic::AtomicU64,
    known: std::sync::atomic::AtomicBool,
}

impl L2HeightCache {
    fn set(&self, height: u64) {
        self.height
            .store(height, std::sync::atomic::Ordering::Relaxed);
        self.known.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn get(&self) -> Option<u64> {
        self.known
            .load(std::sync::atomic::Ordering::Relaxed)
            .then(|| self.height.load(std::sync::atomic::Ordering::Relaxed))
    }
}

/// Query the local ghost-pay service for its current L2 virtual-block height.
/// ghost-pay serves identity-derived TLS on :8800, so this loopback IPC skips
/// cert-chain validation (same rationale as [`notify_ghost_pay_finalize`]).
/// Returns `None` when ghost-pay is unreachable or reports failure.
async fn fetch_ghostpay_virtual_block(client: &reqwest::Client) -> Option<u64> {
    let resp = client.get(GHOST_PAY_STATUS_URL).send().await.ok()?;
    let json: serde_json::Value = resp.json().await.ok()?;
    let inner = json.get("response")?;
    if !inner
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return None;
    }
    inner.get("virtual_block").and_then(|v| v.as_u64())
}

/// The ceremony position this node should target next, accounting for a node
/// whose adopted head lags the recorded chain tip.
///
/// * `authoritative_count` — the `mpc_ceremony` singleton count. This is advanced
///   ONLY when a position is actually ADOPTED (params applied + singleton
///   persisted).
/// * `max_position` — the `mpc_contributions` MAX. This is advanced whenever an
///   applied-contribution ROW arrives (startup contributor sync OR live gossip),
///   even before this node has adopted the corresponding params.
///
/// A node that joined / un-pinned while the ceremony had already advanced sees
/// its `max_position` climb via gossip while its `authoritative_count` stays put,
/// because merely receiving the row never drives the on-disk head forward. If it
/// naïvely targeted `authoritative_count + 1` it would try to contribute an
/// ALREADY-FILLED position forever (the node6→stuck-at-5 incident). The correct
/// target is one past the recorded chain tip, so the node contributes the next
/// FREE position — after first catching its head up to that tip. Returning
/// `max(count, tip) + 1` makes the target robust whether or not the catch-up has
/// completed this instant, and reduces to the normal `count + 1` when the head is
/// already at the tip (`count == tip`).
#[cfg(feature = "mpc-ceremony")]
fn mpc_next_contribution_position(authoritative_count: u32, max_position: u32) -> u32 {
    authoritative_count.max(max_position) + 1
}

/// Pure readiness predicate for the MPC mesh-registration gate.
///
/// A freshly joined node must NOT start broadcasting its ceremony candidate
/// until enough elders have DISCOVERED it (learned its address via mesh
/// discovery + health-ping propagation) that they can actually fetch its
/// candidate parameters and vote on them. Start too early and the voters cannot
/// resolve the new node's address, every vote abstains, and — under the old
/// fixed 15-attempt cap — the node wrongly concluded it "will not be an elder"
/// and needed a manual `ghost-pool` restart to re-trigger the loop once the mesh
/// had caught up (the node7/node8 onboarding bug this gate eliminates).
///
/// "Ready" iff BOTH hold:
///   * our own candidate-serving HTTP endpoint is up (`endpoint_up`) — voters
///     fetch `/api/v1/mpc/params?new_hash=…` from it, so it must be listening; and
///   * we have live (recent health-ping) connectivity with at least
///     `quorum` elders — the same BFT quorum the voters need to APPROVE the
///     contribution. Receiving their pings proves they have discovered us and
///     know our address, i.e. the reverse fetch path can succeed.
#[cfg(feature = "mpc-ceremony")]
fn mpc_contribution_ready(connected_elders: u32, quorum: u32, endpoint_up: bool) -> bool {
    endpoint_up && connected_elders >= quorum
}

/// Inter-round backoff (seconds) for the indefinite MPC contribution retry loop.
///
/// For the first `MPC_CONTRIBUTION_MAX_ATTEMPTS` rounds the ceremony is still in
/// its fast converge window, so this returns the upper bound of the tuned 60-90s
/// delay (`MPC_CONTRIBUTION_RETRY_DELAY_MAX_SECS`) — the post-attempt delay site
/// applies its own random jitter within `[MIN, MAX]`, while the readiness-wait
/// site uses this value directly. Beyond the fast window the delay escalates
/// exponentially and SATURATES at `MPC_CONTRIBUTION_BACKOFF_MAX_SECS`, so a node
/// that cannot yet get voted in keeps retrying forever (never the old permanent
/// "will not be an elder" giveup) without hammering the mesh.
#[cfg(feature = "mpc-ceremony")]
fn mpc_retry_backoff_secs(attempt: u32) -> u64 {
    if attempt <= MPC_CONTRIBUTION_MAX_ATTEMPTS {
        MPC_CONTRIBUTION_RETRY_DELAY_MAX_SECS
    } else {
        // over ∈ {1,2,…}; cap the shift so 1<<over cannot overflow.
        let over = (attempt - MPC_CONTRIBUTION_MAX_ATTEMPTS).min(6);
        MPC_CONTRIBUTION_RETRY_DELAY_MAX_SECS
            .saturating_mul(1u64 << over)
            .min(MPC_CONTRIBUTION_BACKOFF_MAX_SECS)
    }
}

/// Count peers that are currently LIVE elders: they advertised `elder_status`
/// in their most recent health ping AND that ping arrived within
/// `freshness_secs` of `now`. `now` is passed explicitly so the count is
/// deterministic under test.
///
/// NOTE: this reads `capabilities.elder_status` (refreshed on every health ping
/// via `PeerManager::update_health_metrics`), NOT the `Peer::is_elder` field —
/// the latter is only ever set true in unit tests and stays false in production,
/// so counting it would always yield zero on a real mesh.
#[cfg(feature = "mpc-ceremony")]
fn count_connected_elders(
    peers: &[ghost_consensus::peer::Peer],
    now: u64,
    freshness_secs: u64,
) -> u32 {
    let cutoff = now.saturating_sub(freshness_secs);
    peers
        .iter()
        .filter(|p| p.capabilities.elder_status && p.last_seen >= cutoff)
        .count() as u32
}

/// Probe our own candidate-serving HTTP endpoint — the same `:{http_port}` from
/// which voters fetch `/api/v1/mpc/params`. Returns true once it answers, so the
/// readiness gate never lets us advertise a candidate the voters could not
/// actually fetch back from us. Binds to loopback (the listener is `0.0.0.0`).
#[cfg(feature = "mpc-ceremony")]
async fn local_mpc_endpoint_up(http_port: u16) -> bool {
    let url = format!("http://127.0.0.1:{}/api/v1/mpc/status", http_port);
    matches!(
        reqwest::Client::new()
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await,
        Ok(resp) if resp.status().is_success()
    )
}

/// Build this node's best (rarest) valid share per records window from the
/// local DB, shaped exactly like the `/api/v1/pool/records` response (redacted
/// miner_id, achieved difficulty from the hash). Gossiped in health pings so
/// the mesh converges on the pool-wide rarest record per window. Windows with
/// no local share are omitted (a receiving node just won't get a term from us).
fn build_local_best_records(
    db: &ghost_storage::Database,
) -> Vec<ghost_common::types::WindowBestRecord> {
    let now_s = chrono::Utc::now().timestamp();
    let mut out = Vec::with_capacity(RECORD_WINDOWS.len());
    for (window, cutoff) in RECORD_WINDOWS {
        if let Ok(Some(best)) = db.get_best_share_since(now_s - cutoff) {
            out.push(ghost_common::types::WindowBestRecord {
                window: window.to_string(),
                // `best.share_hash` is INTERNAL order: feed it to the difficulty
                // fn as-is, but gossip the DISPLAY form so receiving nodes rank
                // it by rarity (string `<`) and serve it consistently with their
                // own display-order endpoint output.
                difficulty: ghost_verification::share_difficulty_from_hash_hex(&best.share_hash),
                miner_id_redacted: ghost_verification::redact_miner_id(&best.miner_id),
                share_hash: ghost_verification::internal_hex_to_display_hex(&best.share_hash),
                timestamp: best.timestamp,
            });
        }
    }
    out
}

/// H-8 SECURITY: Static storage for ZMQ subscriber to prevent memory leak.
/// Previously used std::mem::forget which intentionally leaked memory.
/// Using OnceLock ensures the subscriber lives for the program lifetime
/// without leaking, and can be properly dropped on program exit.
static ZMQ_SUBSCRIBER: OnceLock<ZmqSubscriber> = OnceLock::new();

/// GSP handler that caches status from periodic HTTP polls to the GSP service
struct CachedGspHandler {
    cache: Arc<parking_lot::RwLock<GspCachedState>>,
}

#[derive(Default)]
struct GspCachedState {
    enabled: bool,
    protocol_version: String,
    network: String,
    connections: u32,
    registered_wallets: u32,
    sync_status: String,
}

impl CachedGspHandler {
    fn new(gsp_url: String) -> Self {
        let cache = Arc::new(parking_lot::RwLock::new(GspCachedState::default()));
        let poll_cache = Arc::clone(&cache);

        // C-04: Validate GSP URL is a loopback address to prevent MITM on health checks
        let is_loopback = is_loopback_url(&gsp_url);

        if !is_loopback {
            tracing::warn!(
                url = %gsp_url,
                "C-04: GSP URL is not a loopback address — TLS verification enforced. \
                 Use 127.0.0.1 or localhost for local GSP connections."
            );
        }

        // Background task polls GSP info every 30s
        tokio::spawn(async move {
            let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5));
            // H-4: No TLS cert bypass — loopback should use plain HTTP, not HTTPS with invalid certs
            let client = client;
            let client = client.build().unwrap_or_default();
            loop {
                match client.get(format!("{}/api/v1/info", gsp_url)).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(info) = resp.json::<serde_json::Value>().await {
                            let mut state = poll_cache.write();
                            state.enabled = true;
                            state.protocol_version = info
                                .get("protocol_version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            state.network = info
                                .get("network")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            state.connections =
                                info.get("connections")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0) as u32;
                            state.sync_status = info
                                .get("sync_status")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                        }
                    }
                    _ => {
                        poll_cache.write().enabled = false;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });

        Self { cache }
    }
}

impl GspHandler for CachedGspHandler {
    fn is_enabled(&self) -> bool {
        self.cache.read().enabled
    }
    fn get_protocol_version(&self) -> String {
        self.cache.read().protocol_version.clone()
    }
    fn get_network(&self) -> String {
        self.cache.read().network.clone()
    }
    fn get_connection_count(&self) -> u32 {
        self.cache.read().connections
    }
    fn get_registered_wallets(&self) -> u32 {
        self.cache.read().registered_wallets
    }
    fn get_sync_status(&self) -> String {
        self.cache.read().sync_status.clone()
    }
    fn health_check(&self) -> ghost_common::GhostResult<bool> {
        Ok(self.cache.read().enabled)
    }
}

/// Adapter to provide peers for verification from PeerManager
struct PeerProviderAdapter {
    peers: Arc<ghost_consensus::peer::PeerManager>,
    http_port: u16,
}

impl PeerProviderAdapter {
    fn new(peers: Arc<ghost_consensus::peer::PeerManager>, http_port: u16) -> Self {
        Self { peers, http_port }
    }
}

impl PeerProvider for PeerProviderAdapter {
    fn get_random_peers(
        &self,
        exclude: &ghost_common::types::NodeId,
        count: usize,
    ) -> Vec<VerifiablePeer> {
        use rand::seq::SliceRandom;

        // Get connected peers (seen in last 60 seconds)
        let connected = self.peers.get_connected_peers(60);

        // Filter out the excluded node (ourselves) and peers without valid addresses
        let mut candidates: Vec<_> = connected
            .into_iter()
            .filter(|p| &p.node_id != exclude && !p.public_address.is_empty())
            .map(|p| {
                // Derive HTTP address from public_address + http_port
                let host = extract_peer_host(&p.public_address);

                // CRIT-VER-1: Extract IP address for Sybil resistance
                let ip_address = Some(host.to_string());

                // CRIT-VER-1: Uptime info for reputation weighting
                // Default to None, will be filled by verification task from DB
                let uptime = None;

                VerifiablePeer {
                    node_id: p.node_id,
                    http_address: format!("{}:{}", host, self.http_port),
                    uptime,
                    ip_address,
                }
            })
            .collect();

        // Shuffle and take up to count
        let mut rng = rand::thread_rng();
        candidates.shuffle(&mut rng);
        candidates.truncate(count);
        candidates
    }
}

/// Ghost Pool - Decentralized Bitcoin Mining Pool
#[derive(Parser, Debug)]
#[command(name = "ghost-pool")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "ghost.toml")]
    config: PathBuf,

    /// Data directory
    #[arg(short, long, default_value = "~/.ghost")]
    data_dir: PathBuf,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Generate new node identity
    #[arg(long)]
    generate_identity: bool,

    /// Show node identity and exit
    #[arg(long)]
    show_identity: bool,

    /// Initialize MPC genesis (only use on first node in network)
    #[arg(long)]
    genesis: bool,

    /// Password for genesis initialization (must match genesis_password in pool config)
    #[arg(long)]
    genesis_password: Option<String>,

    /// Show node status in load balancer and exit
    #[arg(long)]
    status: bool,

    /// Watch node status continuously (refresh every N seconds)
    #[arg(long, value_name = "SECS")]
    watch: Option<u64>,

    /// Bitcoin RPC host override
    #[arg(long)]
    rpc_host: Option<String>,

    /// Bitcoin RPC port override
    #[arg(long)]
    rpc_port: Option<u16>,

    /// Stratum listen port override
    #[arg(long)]
    stratum_port: Option<u16>,

    /// Enable Template Distribution Protocol server (for SRI pool)
    #[arg(long)]
    tdp_enabled: bool,

    /// TDP server port (default: 8442)
    #[arg(long, default_value = "8442")]
    tdp_port: u16,

    /// Disable native stratum server (use when running with SRI pool via TDP)
    #[arg(long)]
    no_stratum: bool,

    /// ONE-TIME LEDGER RECONCILIATION: export this node's unpaid shares to a JSON file.
    ///
    /// Shares predating schema v41 carry no signed proof, so no node can serve or verify them
    /// and GHOST-03 convergence cannot repair the divergence they cause. The fleet can only be
    /// made to agree on that backlog by taking the UNION across the operator's own nodes.
    #[arg(long, value_name = "FILE")]
    ledger_export: Option<PathBuf>,

    /// ONE-TIME LEDGER RECONCILIATION: import unpaid shares this node is missing.
    ///
    /// Never deletes and never overwrites — dedup is UNIQUE(share_hash) and a miner row is only
    /// created if absent, so it is safe to re-run. Each miner's payout address is re-encrypted
    /// with THIS node's key (the DB key is per-node), without which the payout query's
    /// INNER JOIN would drop the share and the miner would silently lose the work.
    #[arg(long, value_name = "FILE")]
    ledger_import: Option<PathBuf>,

    /// With --ledger-import: report what WOULD change and write nothing.
    #[arg(long)]
    dry_run: bool,
}

/// Pool state shared across components
pub struct PoolState {
    /// Node identity
    pub identity: Arc<NodeIdentity>,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Policy profile
    pub policy: PolicyProfile,
    /// Bitcoin RPC client
    pub rpc: Arc<BitcoinRpc>,
    /// Database
    pub db: Arc<Database>,
    /// Round manager
    pub round_manager: Arc<RoundManager>,
    /// Template processor
    pub template_processor: Arc<TemplateProcessor>,
    /// P2P mesh network
    pub mesh: Arc<MeshNetwork>,
    /// Vote handler for consensus
    pub vote_handler: Arc<VoteHandler>,
    /// Shutdown signal
    pub shutdown_tx: broadcast::Sender<()>,
}

/// Handle --status command: query and display node status from registry
async fn handle_status_command(
    config: &NodeConfig,
    identity: &NodeIdentity,
    watch_interval: Option<u64>,
) -> Result<()> {
    use ghost_pool::registry::NodeStatusResponse;

    let Some(ref registry_config) = config.registry else {
        println!("Registry not configured in config file.");
        println!("Add [registry] section with url and region to enable load balancing.");
        return Ok(());
    };

    // Create a simple HTTP client to query status
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let node_id = identity.node_id_hex();
    let url = format!("{}/api/v1/nodes/{}/status", registry_config.url, node_id);

    loop {
        // Clear screen in watch mode
        if watch_interval.is_some() {
            print!("\x1B[2J\x1B[1;1H");
        }

        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║                    Ghost Pool Status                          ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();

        println!("Registry:    {}", registry_config.url);
        println!("Node ID:     {} ({})", identity.node_id_short(), node_id);
        println!();

        match client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let api_resp: serde_json::Value = response.json().await?;

                    if let Some(data) = api_resp.get("data") {
                        let status: NodeStatusResponse = serde_json::from_value(data.clone())?;
                        print_status(&status);
                    } else if let Some(error) = api_resp.get("error") {
                        println!("Error: {}", error);
                    }
                } else if response.status().as_u16() == 404 {
                    println!("Status:      NOT REGISTERED");
                    println!();
                    println!("This node is not registered with the registry.");
                    println!("Start the pool service to register automatically.");
                } else {
                    println!("Error: Registry returned status {}", response.status());
                }
            }
            Err(e) => {
                println!("Error:       Could not connect to registry");
                println!("             {}", e);
                println!();
                println!("Check that the registry is running and accessible.");
            }
        }

        // Exit if not in watch mode
        let Some(interval) = watch_interval else {
            break;
        };

        println!();
        println!("─────────────────────────────────────────────────────────────────");
        println!("Refreshing every {}s. Press Ctrl+C to exit.", interval);

        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
    }

    Ok(())
}

/// Print formatted status output
fn print_status(status: &ghost_pool::registry::NodeStatusResponse) {
    // Status indicator
    let status_icon = if status.in_dns { "●" } else { "○" };
    let status_text = if status.in_dns {
        "IN DNS (receiving miners)"
    } else {
        "NOT IN DNS"
    };

    println!("Status:      {} {}", status_icon, status_text);
    println!();

    // Details
    println!("┌─ Load Balancer Status ─────────────────────────────────────┐");
    println!(
        "│ Registered:        {:<39} │",
        if status.registered { "Yes" } else { "No" }
    );
    println!(
        "│ In DNS:            {:<39} │",
        if status.in_dns { "Yes" } else { "No" }
    );
    println!(
        "│ Healthy:           {:<39} │",
        if status.healthy { "Yes" } else { "No" }
    );
    println!(
        "│ Accepting Miners:  {:<39} │",
        if status.accepting_miners { "Yes" } else { "No" }
    );
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    println!("┌─ Load & Ranking ────────────────────────────────────────────┐");
    println!(
        "│ Current Load:      {:<39} │",
        format!("{}%", status.load_percent)
    );
    println!("│ Region:            {:<39} │", status.region);
    println!(
        "│ Rank in Region:    {:<39} │",
        format!(
            "{} of {} (by load)",
            status.rank_in_region, status.healthy_in_region
        )
    );
    println!(
        "│ Total in Region:   {:<39} │",
        format!(
            "{} nodes ({} healthy)",
            status.total_in_region, status.healthy_in_region
        )
    );
    println!(
        "│ Last Heartbeat:    {:<39} │",
        format!("{}s ago", status.last_heartbeat_ago_secs)
    );
    println!("└─────────────────────────────────────────────────────────────┘");

    // Exclusion reason if any
    if let Some(ref reason) = status.exclusion_reason {
        println!();
        println!("┌─ Exclusion Reason ─────────────────────────────────────────┐");
        println!("│ {:<59} │", reason);
        println!("└─────────────────────────────────────────────────────────────┘");
    }

    // Tips
    if !status.in_dns {
        println!();
        println!("Tip: Node is not receiving miners because it's excluded from DNS.");
        if status.excluded_for_load {
            println!("     Load is ≥80%. Will resume when load drops below 70%.");
        } else if !status.healthy {
            println!("     Node marked unhealthy. Check heartbeat connectivity.");
        } else if !status.accepting_miners {
            println!("     Node is not accepting miners. Check configuration.");
        }
    }
}

// ============================================================================
// MPC / ZK trusted-setup parameter self-heal
//
// A fresh node that has the `zk-production` binary but no MPC ceremony output on
// disk used to crash-loop: `ghost_zkp::load_trusted_params()` failed at startup
// and the process exited BEFORE the background MPC task could fetch the params
// from a seed. The helpers below fetch (and SECURITY-verify) the ceremony output
// from seeds so the node self-heals instead. They are the single shared
// implementation used by BOTH the startup self-heal and the runtime MPC task.
// ============================================================================

/// Name of the environment variable holding the pinned ceremony parameter
/// hashes (`BLOCK:sha256hex,PAYOUT:sha256hex,...`).
///
/// Resolves to the canonical `ghost_zkp` constant whenever ZK consensus is
/// compiled in (always, in practice); falls back to the literal otherwise so
/// the fetch helpers compile even in an `mpc-ceremony`-only build.
#[cfg(feature = "mpc-ceremony")]
fn zk_params_hash_env_name() -> &'static str {
    #[cfg(feature = "zk-consensus")]
    {
        ghost_zkp::ZK_PARAMS_HASH_ENV
    }
    #[cfg(not(feature = "zk-consensus"))]
    {
        "ZK_PARAMS_HASH"
    }
}

/// Parse the pinned ceremony parameter hashes from `ZK_PARAMS_HASH`.
///
/// Format: `TYPE:sha256hex` pairs separated by commas, e.g.
/// `BLOCK:fa9d...,PAYOUT:1234...`. Mirrors `ghost_zkp::parse_expected_hashes`
/// (which is private) so the fetch path can verify a downloaded blob against
/// the same pinned digest that `load_trusted_params` enforces. Malformed
/// entries are skipped. Returns an empty map when the variable is unset, in
/// which case no hash is pinned and verification is not enforced (test nets).
#[cfg(feature = "mpc-ceremony")]
fn expected_param_hashes() -> std::collections::HashMap<String, [u8; 32]> {
    match std::env::var(zk_params_hash_env_name()) {
        Ok(env_val) => parse_param_hashes(&env_val),
        Err(_) => std::collections::HashMap::new(),
    }
}

/// Pure parser for the `ZK_PARAMS_HASH` value (split out for testability).
///
/// Accepts comma-separated `TYPE:sha256hex` pairs; malformed entries (wrong
/// length, non-hex) are skipped rather than aborting, so a single bad entry
/// cannot mask the others. Types are upper-cased so lookups are case-insensitive.
#[cfg(feature = "mpc-ceremony")]
fn parse_param_hashes(env_val: &str) -> std::collections::HashMap<String, [u8; 32]> {
    let mut map = std::collections::HashMap::new();
    for pair in env_val.split(',') {
        let mut it = pair.splitn(2, ':');
        if let (Some(ty), Some(hash_hex)) = (it.next(), it.next()) {
            let hash_hex = hash_hex.trim();
            if hash_hex.len() != 64 {
                continue;
            }
            if let Ok(bytes) = hex::decode(hash_hex) {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                    map.insert(ty.trim().to_uppercase(), arr);
                }
            }
        }
    }
    map
}

/// SECURITY: decide whether a freshly-fetched parameter blob may be trusted and
/// written to disk as part of the trusted set.
///
/// A blob is accepted only when it is non-trivial in size AND — when a hash is
/// pinned for this parameter type via `ZK_PARAMS_HASH` — its SHA-256 matches
/// that pinned digest. This is the trusted-setup gate: a malicious seed cannot
/// inject forged parameters, because a mismatched blob is rejected here BEFORE
/// it is ever written. When no hash is pinned (test nets), only the size check
/// applies, preserving the historical behaviour.
#[cfg(feature = "mpc-ceremony")]
fn params_blob_is_trusted(data: &[u8], expected_hash: Option<&[u8; 32]>) -> bool {
    if data.len() <= 1000 {
        return false;
    }
    match expected_hash {
        Some(expected) => {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(data);
            let actual: [u8; 32] = hasher.finalize().into();
            &actual == expected
        }
        None => true,
    }
}

/// Process-wide serialisation for trusted-setup parameter writes.
///
/// BOTH the ceremony-task fetch path ([`fetch_one_param`]) and the
/// BFT-apply params-update callback write the SAME on-disk files
/// (`note_spend_params_*.bin` and friends). If two of those writes interleaved,
/// the next startup's `load_trusted_params` (or a live reader) could observe a
/// half-written, right-sized but wrong-hash file — exactly the node6
/// crash-loop signature. Holding this async mutex across the write +
/// verify-after-write critical section makes every parameter write atomic with
/// respect to every other, so no torn/raced file is ever produced.
#[cfg(feature = "mpc-ceremony")]
fn param_write_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// SHA-256 of a file's raw bytes.
///
/// Matches `ghost_zkp::compute_params_file_hash` and [`params_blob_is_trusted`]
/// (the pinned `ZK_PARAMS_HASH` BLOCK digest is the SHA-256 of the params file
/// bytes), so this is the canonical way to validate params already on disk.
#[cfg(feature = "mpc-ceremony")]
fn sha256_file(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Persist a freshly generated note-spend CANDIDATE (un-applied) parameter set
/// for serving to voters, keyed by its lineage `new_params_hash`.
///
/// SECURITY (Bug-1 fix): the candidate is written to a SEPARATE serving file
/// (`note_spend_params_candidate_<hash>.bin`) and NEVER to the active
/// `note_spend_params_current.bin`. The node's `current.bin` must remain the
/// last BFT-APPLIED params until a contribution is actually applied through
/// `CeremonyManager::apply_contribution_multi` (the sole legitimate writer of
/// `current.bin`). Writing the un-applied candidate over `current.bin` is what
/// crash-looped node5: on restart the genesis-anchored cross-check saw on-disk
/// candidate ≠ chain head and failed closed.
///
/// Stale candidates from superseded positions are purged best-effort so the
/// serving directory does not accumulate multi-hundred-megabyte blobs. Returns
/// the candidate file path on success.
#[cfg(feature = "mpc-ceremony")]
fn write_candidate_note_spend_params(
    params_dir: &std::path::Path,
    new_params_hash: &[u8; 32],
    serialized: &[u8],
) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(params_dir)?;

    // Drop candidate files for other (superseded) positions. Keep only the one
    // we are about to (re)write so a long retry loop never bloats the dir.
    let keep = ghost_common::mpc::candidate_note_spend_filename(new_params_hash);
    if let Ok(entries) = std::fs::read_dir(params_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(ghost_common::mpc::CANDIDATE_NOTE_SPEND_PREFIX)
                && name.ends_with(".bin")
                && name != keep
            {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    let candidate_path = params_dir.join(&keep);
    std::fs::write(&candidate_path, serialized)?;
    Ok(candidate_path)
}

/// True iff `note_spend_params_current.bin` exists in `params_dir` and — when a
/// hash is pinned — its SHA-256 matches.
///
/// Mirrors the gate `load_trusted_params` applies at startup, so a node that
/// already holds valid trusted-setup params on disk is recognised WITHOUT
/// re-fetching them (a re-fetch would overwrite the good file). With no pinned
/// hash (test nets) only presence is required, matching historical behaviour.
#[cfg(feature = "mpc-ceremony")]
fn ondisk_note_spend_valid(params_dir: &std::path::Path, expected_hash: Option<&[u8; 32]>) -> bool {
    let current = params_dir.join("note_spend_params_current.bin");
    if !current.exists() {
        return false;
    }
    match expected_hash {
        Some(pinned) => matches!(sha256_file(&current), Ok(actual) if &actual == pinned),
        None => true,
    }
}

/// Atomically write `data` to `final_path`: write a unique temp file in the same
/// directory, `fsync` it, then `rename` it over the destination.
///
/// `rename(2)` is atomic on a single filesystem, so a concurrent reader or a
/// crash mid-write never observes a partially written params file (the node6
/// right-sized/wrong-hash corruption). The temp name is unique per write so two
/// concurrent writers cannot scribble over each other's in-progress file.
#[cfg(feature = "mpc-ceremony")]
fn write_params_atomic(final_path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let dir = final_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let file_name = final_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "params.bin".to_string());
    let nonce = NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp_path = dir.join(format!(
        ".{}.tmp.{}.{}",
        file_name,
        std::process::id(),
        nonce
    ));

    let res = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp_path, final_path)?;
        Ok(())
    })();

    if res.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    res
}

/// Install `data` as the trusted `<base>_v0.bin`, repoint `<base>_current.bin`
/// at it, then VERIFY-AFTER-WRITE.
///
/// The write is atomic ([`write_params_atomic`]). After repointing `current`,
/// the file `load_trusted_params` will actually read is re-read from disk and
/// re-hashed against `expected_hash`. If a torn/raced write (or any I/O fault)
/// left a wrong file in place, both the `current` pointer and the `v0` file are
/// removed and `false` is returned — a corrupt trusted-setup file is NEVER left
/// behind to crash-loop the node. With no pinned hash (test nets) no post-write
/// hash check is possible; the caller's size gate still applies.
///
/// Callers MUST hold [`param_write_lock`] across this call so the verify-after
/// read cannot be swapped by a concurrent writer.
#[cfg(feature = "mpc-ceremony")]
fn install_and_verify_param(
    params_dir: &std::path::Path,
    base: &str,
    data: &[u8],
    expected_hash: Option<&[u8; 32]>,
) -> bool {
    let params_path = params_dir.join(format!("{}_v0.bin", base));
    let current_path = params_dir.join(format!("{}_current.bin", base));

    if let Err(e) = write_params_atomic(&params_path, data) {
        warn!(error = %e, base, "MPC: failed to save fetched params");
        return false;
    }

    // Point `<base>_current.bin` at the version we just wrote.
    let _ = std::fs::remove_file(&current_path);
    if let Err(e) = std::os::unix::fs::symlink(&params_path, &current_path) {
        warn!(error = %e, base, "MPC: failed to create params symlink");
    }

    // SECURITY: verify-after-write. Re-read the exact file the next startup's
    // `load_trusted_params` will read and re-check its hash against the pinned
    // digest. Leaving a corrupt file here is what crash-loops a node.
    if let Some(expected) = expected_hash {
        match sha256_file(&current_path) {
            Ok(actual) if &actual == expected => {}
            Ok(_) => {
                warn!(
                    base,
                    "MPC: SECURITY: params failed verify-after-write (on-disk hash != pinned) — removing corrupt file"
                );
                let _ = std::fs::remove_file(&current_path);
                let _ = std::fs::remove_file(&params_path);
                return false;
            }
            Err(e) => {
                warn!(error = %e, base, "MPC: failed verify-after-write re-read — removing");
                let _ = std::fs::remove_file(&current_path);
                let _ = std::fs::remove_file(&params_path);
                return false;
            }
        }
    }

    true
}

/// Move an existing-but-corrupt `note_spend_params_current.bin` aside for
/// forensics (suffixed `.corrupt.<unixsecs>`) and drop the live `current`
/// pointer so a fresh fetch recreates it. Best-effort: if the rename fails the
/// backing file is removed so it can never be re-read as trusted.
#[cfg(all(feature = "zk-consensus", feature = "mpc-ceremony"))]
fn quarantine_corrupt_note_spend(params_dir: &std::path::Path) {
    let current = params_dir.join("note_spend_params_current.bin");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Resolve the real backing file (`current` is usually a symlink to *_v0.bin).
    let real = std::fs::canonicalize(&current).unwrap_or_else(|_| current.clone());
    let mut quarantined = real.clone().into_os_string();
    quarantined.push(format!(".corrupt.{}", ts));
    let quarantined = std::path::PathBuf::from(quarantined);
    if let Err(e) = std::fs::rename(&real, &quarantined) {
        warn!(error = %e, path = %real.display(), "MPC: failed to quarantine corrupt params; removing instead");
        let _ = std::fs::remove_file(&real);
    } else {
        warn!(from = %real.display(), to = %quarantined.display(), "MPC: quarantined corrupt trusted-setup params");
    }
    // Drop the (now possibly dangling) `current` pointer so the re-fetch recreates it.
    let _ = std::fs::remove_file(&current);
}

/// Fetch a single MPC parameter set from one seed, verify it, and write it to
/// `params_dir` (as `<base>_v0.bin`, the `<base>_current.bin` symlink, and the
/// extracted `<vk_name>` verifying key).
///
/// Returns `true` only when the blob was fetched, passed
/// [`params_blob_is_trusted`], was written atomically, and passed
/// verify-after-write. A hash mismatch is rejected (returns `false`) so the
/// caller moves on to the next seed.
#[cfg(feature = "mpc-ceremony")]
async fn fetch_one_param(
    host: &str,
    endpoint: &str,
    params_dir: &std::path::Path,
    base: &str,
    vk_name: &str,
    expected_hash: Option<&[u8; 32]>,
) -> bool {
    let url = format!("http://{}:8080/api/v1/mpc/{}", host, endpoint);
    debug!(url = %url, "MPC: fetching params from peer");

    let response = match reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => resp,
        Ok(resp) => {
            debug!(status = %resp.status(), peer = %host, endpoint, "MPC: peer returned non-success status");
            return false;
        }
        Err(e) => {
            debug!(error = %e, peer = %host, endpoint, "MPC: failed to fetch from peer");
            return false;
        }
    };

    let data = match response.bytes().await {
        Ok(data) => data,
        Err(e) => {
            debug!(error = %e, peer = %host, endpoint, "MPC: failed to read response body");
            return false;
        }
    };

    if !params_blob_is_trusted(&data, expected_hash) {
        if expected_hash.is_some() && data.len() > 1000 {
            // Size was fine but the pinned hash did not match: this is a forged
            // or corrupt trusted-setup blob. Refuse it and try the next seed.
            warn!(
                peer = %host,
                endpoint,
                size = data.len(),
                "MPC: SECURITY: fetched params failed hash verification against ZK_PARAMS_HASH — rejecting and trying next seed"
            );
        } else {
            debug!(size = data.len(), peer = %host, endpoint, "MPC: response too small, peer may not have params");
        }
        return false;
    }

    let _ = std::fs::create_dir_all(params_dir);
    let params_path = params_dir.join(format!("{}_v0.bin", base));

    // Serialise the write + verify-after-write against every other parameter
    // write (the BFT-apply callback, other fetch tasks) so a concurrent writer
    // can neither tear this file nor swap it between our write and our re-read.
    let installed = {
        let _write_guard = param_write_lock().lock().await;
        if !install_and_verify_param(params_dir, base, &data, expected_hash) {
            false
        } else {
            // Extract and persist the verifying key while STILL holding the lock,
            // so the file we read is exactly the one we just verified.
            if let Ok(params) = ghost_mpc::params::load_parameters(&params_path) {
                let vk_path = params_dir.join(vk_name);
                if let Err(e) = ghost_mpc::params::save_verifying_key(&vk_path, &params.vk) {
                    warn!(error = %e, endpoint, "MPC: failed to save verifying key");
                }
            }
            true
        }
    };
    if !installed {
        return false;
    }

    info!(size = data.len(), peer = %host, endpoint, "MPC: fetched + verified params from peer");
    true
}

/// Fetch the full ceremony parameter set (note_spend, payout, unshield) from a
/// single seed. `note_spend` is the primary, hash-pinned trusted-setup file:
/// the function returns `true` only when it was fetched and verified. `payout`
/// and `unshield` are fetched best-effort afterwards (verified against their
/// own pinned hashes when present). This is the one shared fetch implementation.
#[cfg(feature = "mpc-ceremony")]
async fn try_fetch_params_from_seed(
    host: &str,
    params_dir: &std::path::Path,
    expected: &std::collections::HashMap<String, [u8; 32]>,
) -> bool {
    if !fetch_one_param(
        host,
        "params",
        params_dir,
        "note_spend_params",
        "note_spend_vk.bin",
        expected.get("BLOCK"),
    )
    .await
    {
        return false;
    }

    let _ = fetch_one_param(
        host,
        "payout-params",
        params_dir,
        "payout_params",
        "payout_vk.bin",
        expected.get("PAYOUT"),
    )
    .await;
    let _ = fetch_one_param(
        host,
        "unshield-params",
        params_dir,
        "unshield_params",
        "unshield_vk.bin",
        expected.get("UNSHIELD"),
    )
    .await;

    true
}

/// Fetch + parse one circuit's parameters from a peer entirely IN MEMORY.
///
/// Used by the BFT voter / params-adoption path to obtain a candidate parameter
/// set for cryptographic verification without touching the on-disk parameter
/// files (only the post-approval apply persists parameters). When
/// `expected_hash` is set, the parsed parameters' `hash_parameters()` (the
/// structured LINEAGE hash) must match or `None` is returned. The heavy
/// parse/hash runs on a blocking thread so the async runtime is never stalled.
#[cfg(feature = "mpc-ceremony")]
async fn fetch_and_parse_params(
    host: &str,
    endpoint: &str,
    expected_hash: Option<[u8; 32]>,
) -> Option<ghost_mpc::Groth16Params> {
    // When we are after a specific (candidate) lineage hash, ask the peer to
    // serve THAT candidate by hash. The contributor stores its un-applied
    // candidate in a separate serving file keyed by `new_hash` (its active
    // current.bin stays at the applied head), so a bare GET would return the
    // applied params and the hash filter below would reject every peer. With
    // `?new_hash=` the contributor serves the candidate; peers without it fall
    // back to their current.bin (which won't match, so we skip them).
    let url = match expected_hash {
        Some(h) => format!(
            "http://{}:8080/api/v1/mpc/{}?new_hash={}",
            host,
            endpoint,
            hex::encode(h)
        ),
        None => format!("http://{}:8080/api/v1/mpc/{}", host, endpoint),
    };
    let resp = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let data = resp.bytes().await.ok()?;
    if data.len() <= 1000 {
        return None;
    }
    tokio::task::spawn_blocking(move || {
        let params = ghost_mpc::params::read_parameters_from_bytes(&data).ok()?;
        if let Some(expected) = expected_hash {
            let h = ghost_mpc::contribution::hash_parameters(&params).ok()?;
            if h != expected {
                tracing::debug!(
                    expected = %hex::encode(&expected[..8]),
                    got = %hex::encode(&h[..8]),
                    "MPC fetch: parsed params hash != expected lineage hash"
                );
                return None;
            }
        }
        Some(params)
    })
    .await
    .ok()?
}

/// Host portion of an `address` that may be a bare host, `host:port`,
/// `[ipv6]:port`, or carry a `scheme://` prefix. Mirrors the mesh's own
/// `extract_host_from_address` so a contributor's advertised mesh address
/// (`ip:8559`) reduces to just the host we then hit on the fetch port (`:8080`).
#[cfg(feature = "mpc-ceremony")]
fn fetch_host_of(address: &str) -> String {
    let s = match address.find("://") {
        Some(i) => &address[i + 3..],
        None => address,
    };
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }
    match s.rfind(':') {
        Some(i) if !s[i + 1..].is_empty() && s[i + 1..].chars().all(|c| c.is_ascii_digit()) => {
            s[..i].to_string()
        }
        _ => s.to_string(),
    }
}

/// Resolve a contributor node id to its reachable address: the live mesh peer
/// registry FIRST (freshest — the same registry the mesh uses for Noise/health),
/// then the persisted `nodes` table. Empty strings are treated as unresolved.
/// `None` means we could not find an address and must fall back to seeds only.
#[cfg(feature = "mpc-ceremony")]
fn resolve_contributor_addr(
    peers: &ghost_consensus::peer::PeerManager,
    db: &ghost_storage::Database,
    contributor: &ghost_common::types::NodeId,
) -> Option<String> {
    peers
        .get_peer(contributor)
        .map(|p| p.public_address)
        .filter(|a| !a.is_empty())
        .or_else(|| {
            db.get_node(&hex::encode(contributor))
                .ok()
                .flatten()
                .and_then(|n| n.public_address)
        })
        .filter(|a| !a.is_empty())
}

/// Build the ordered list of fetch hosts for a candidate parameter bundle: the
/// CONTRIBUTOR first (the only node serving its un-applied candidate), then the
/// configured seeds. Entries are reduced to host-only and de-duplicated by host
/// so the contributor is never retried as a seed and duplicate seeds are dropped.
/// When `contributor_addr` is `None` (address unresolved) the result is exactly
/// the seed hosts — preserving the prior seeds-only behaviour as a fallback.
#[cfg(feature = "mpc-ceremony")]
fn ordered_fetch_sources(contributor_addr: Option<&str>, seeds: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(seeds.len() + 1);
    if let Some(addr) = contributor_addr {
        let h = fetch_host_of(addr);
        if !h.is_empty() {
            out.push(h);
        }
    }
    for seed in seeds {
        let h = fetch_host_of(seed);
        if h.is_empty() || out.iter().any(|existing| existing == &h) {
            continue;
        }
        out.push(h);
    }
    out
}

/// Fetch a full candidate parameter bundle (note-spend + payout + unshield) from
/// the network for one contribution.
///
/// The primary note-spend parameters MUST hash-match `expected_note_spend_hash`
/// (the contribution's claimed lineage head) — only then is a bundle returned.
/// `payout`/`unshield` ride along best-effort (they share the same toxic waste).
/// Returns `None` if no source can supply matching note-spend parameters, which
/// forces the voter to ABSTAIN rather than approve blind. Sources are tried in
/// the given order (contributor-first per [`ordered_fetch_sources`]).
#[cfg(feature = "mpc-ceremony")]
async fn fetch_ceremony_params_bundle(
    sources: &[String],
    expected_note_spend_hash: [u8; 32],
) -> Option<ghost_consensus::mpc_handler::FetchedCeremonyParams> {
    for source in sources {
        let host = source.split(':').next().unwrap_or(source);
        let note_spend =
            match fetch_and_parse_params(host, "params", Some(expected_note_spend_hash)).await {
                Some(p) => p,
                None => continue,
            };
        let payout = fetch_and_parse_params(host, "payout-params", None).await;
        let unshield = fetch_and_parse_params(host, "unshield-params", None).await;
        return Some(ghost_consensus::mpc_handler::FetchedCeremonyParams {
            note_spend: std::sync::Arc::new(note_spend),
            payout: payout.map(std::sync::Arc::new),
            unshield: unshield.map(std::sync::Arc::new),
        });
    }
    None
}

/// Load a note-spend CANDIDATE parameter set from THIS node's local serving
/// directory, keyed by its lineage `new_params_hash`, and verify the parsed
/// params hash to that head before returning.
///
/// This is the fast, network-free source for a contributor adopting its OWN
/// applied contribution: the candidate it generated + wrote (never `current.bin`)
/// hashes to exactly the `new_params_hash` the voters BFT-approved. Returns
/// `None` when the file is absent, unreadable, unparsable, or the parsed hash
/// does not match (a corrupt/stale candidate) — the caller then falls back to
/// the network.
#[cfg(feature = "mpc-ceremony")]
fn load_local_candidate_note_spend(
    params_dir: &std::path::Path,
    new_params_hash: &[u8; 32],
) -> Option<ghost_mpc::Groth16Params> {
    let path = params_dir.join(ghost_common::mpc::candidate_note_spend_filename(
        new_params_hash,
    ));
    let bytes = std::fs::read(&path).ok()?;
    let params = ghost_mpc::params::read_parameters_from_bytes(&bytes).ok()?;
    let h = ghost_mpc::contribution::hash_parameters(&params).ok()?;
    if &h != new_params_hash {
        tracing::warn!(
            expected = %hex::encode(&new_params_hash[..8]),
            got = %hex::encode(&h[..8]),
            "MPC adopt: local candidate hash != recorded lineage head — ignoring (will try network)"
        );
        return None;
    }
    Some(params)
}

/// Reconstruct an [`ghost_mpc::MpcContribution`] from a persisted contribution
/// row. The proof is parsed from the stored bytes when present; when it is empty
/// or malformed (e.g. a row synced from `/contributors` before the real proof
/// was back-filled) an all-empty proof is substituted. This is safe for the
/// adopt/apply path because `apply_contribution_multi` reads only the position,
/// hashes and timestamp — never the proof. Callers that adopt params they did
/// NOT author still run [`ghost_mpc::CeremonyManager::verify_contribution_catchup`]
/// separately, which requires a real proof.
#[cfg(feature = "mpc-ceremony")]
fn contribution_from_row(
    row: &ghost_storage::queries::MpcContributionRecord,
) -> ghost_mpc::MpcContribution {
    let proof = serde_json::from_slice::<ghost_mpc::ContributionProof>(&row.contribution_proof)
        .unwrap_or_else(|_| {
            let empty_pok = || ghost_mpc::contribution::ProofOfKnowledge {
                commitment_g1: Vec::new(),
                challenge: [0u8; 32],
                response: Vec::new(),
            };
            ghost_mpc::ContributionProof {
                tau_g1: Vec::new(),
                tau_g2: Vec::new(),
                alpha_g1: Vec::new(),
                beta_g1: Vec::new(),
                beta_g2: Vec::new(),
                tau_pok: empty_pok(),
                alpha_pok: empty_pok(),
                beta_pok: empty_pok(),
            }
        });
    ghost_mpc::MpcContribution {
        position: row.elder_position,
        prev_params_hash: row.prev_params_hash,
        new_params_hash: row.new_params_hash,
        proof,
        contributor: row.contributor_node_id.clone(),
        timestamp: row.created_at,
        commitment_hash: None,
    }
}

/// Persist the `mpc_ceremony` singleton from the ceremony manager's AUTHORITATIVE
/// post-apply state (count, current-params hash, ossification, vk hashes,
/// ceremony_id). Mirrors the persistence the BFT `params_update_callback` does
/// after it applies. Returns `false` on a DB error so callers never declare a
/// consistent head while the singleton write failed.
#[cfg(feature = "mpc-ceremony")]
fn persist_singleton_from_manager(
    ceremony_mgr: &ghost_mpc::CeremonyManager,
    db: &ghost_storage::Database,
) -> bool {
    let s = ceremony_mgr.state();
    let db_state = ghost_storage::queries::MpcCeremonyState {
        contribution_count: s.contribution_count,
        current_params_hash: s.current_params_hash,
        is_ossified: s.is_ossified,
        ossified_at: s.ossified_at,
        block_vk_hash: s.note_spend_vk_hash,
        payout_vk_hash: s.payout_vk_hash,
        updated_at: s.updated_at,
        ceremony_id: s.ceremony_id,
        ossified_file_hash: s.ossified_file_hash,
    };
    if let Err(e) = db.save_mpc_ceremony_state(&db_state) {
        tracing::warn!(error = %e, "MPC adopt: failed to persist ceremony singleton");
        return false;
    }
    true
}

/// Apply an already-obtained, hash-matched note-spend parameter set for
/// `contribution` through the ONLY legitimate `current.bin` writer
/// ([`ghost_mpc::CeremonyManager::apply_contribution_multi`]), then persist the
/// `mpc_ceremony` singleton from the manager's authoritative state.
///
/// Returns `true` ONLY when the post-conditions hold: manager count ==
/// `contribution.position` AND manager current-params hash ==
/// `contribution.new_params_hash` (so `note_spend_params_current.bin` is the
/// applied head) AND the singleton was persisted. A `false` return means the
/// adopt did NOT complete cleanly and the caller MUST NOT declare success.
///
/// Payout/unshield ride the note-spend lineage (same toxic waste) and are
/// intentionally left as `None` here: the note-spend hash is the BFT-chained
/// trusted-setup head, and the contributor holds only its note-spend candidate.
/// `update_current_params` copies only the versions that exist on disk, so the
/// payout/unshield current pointers are left untouched (byte-identical to the
/// applied head).
#[cfg(feature = "mpc-ceremony")]
fn apply_and_persist_adopted_note_spend(
    ceremony_mgr: &ghost_mpc::CeremonyManager,
    db: &ghost_storage::Database,
    note_spend: ghost_mpc::Groth16Params,
    contribution: &ghost_mpc::MpcContribution,
) -> bool {
    if let Err(e) = ceremony_mgr.apply_contribution_multi(note_spend, None, None, contribution) {
        tracing::warn!(
            error = %e,
            position = contribution.position,
            "MPC adopt: apply_contribution_multi failed"
        );
        return false;
    }
    if !persist_singleton_from_manager(ceremony_mgr, db) {
        return false;
    }
    // Lineage invariant: the on-disk head + singleton now sit at our applied
    // position. Verified against the recorded `new_params_hash`, so an adopted
    // `current.bin` that failed to advance can never masquerade as success.
    let ok = ceremony_mgr.contribution_count() == contribution.position
        && ceremony_mgr.current_params_hash() == contribution.new_params_hash;
    if !ok {
        tracing::error!(
            position = contribution.position,
            count = ceremony_mgr.contribution_count(),
            "MPC adopt: post-apply invariant violated (count/hash != applied position)"
        );
    }
    ok
}

/// Adopt the BFT-applied contribution recorded at `position` into THIS node's
/// on-disk `note_spend_params_current.bin` + `mpc_ceremony` singleton, advancing
/// the ceremony manager from `position - 1` to `position`.
///
/// This closes the contributor self-adopt gap. A node that GENERATED a
/// contribution never applies it through its own [`ghost_consensus::MpcHandler`]:
/// the handler only applies contributions it RECEIVED into its
/// `pending_contributions` map, and a node's own broadcast is never in that map.
/// So once the voters reach quorum and BFT-apply, and the row gossips back into
/// `mpc_contributions`, the contributor is recorded as an elder at `position`
/// while its own `current.bin` + singleton stay at `position - 1` — a fail-closed
/// crash-loop on restart (on-disk head < recorded chain tip). This drives the
/// canonical adopt so the head catches up.
///
/// Params source, in order: (1) the node's OWN local candidate serving file
/// (`note_spend_params_candidate_<new_hash>.bin`, hash-checked); (2) the network
/// (a voter's applied head, hash-checked). For a position this node did NOT
/// contribute, the fetched params are additionally run through the SAME catch-up
/// crypto verification (Schnorr + pairing transform against OUR prev) a
/// voter/callback runs — never adopt a foreign lineage on hash-match alone. An
/// OWN contribution is self-authored (we produced `new_params_hash`) so the
/// hash-match to our own BFT-approved row is the gate.
///
/// Returns `true` ONLY when the post-adopt invariant holds. `false` means the
/// node did NOT reach a consistent applied head and the caller MUST NOT declare
/// elder success.
#[cfg(feature = "mpc-ceremony")]
async fn adopt_applied_position(
    ceremony_mgr: &Arc<ghost_mpc::CeremonyManager>,
    db: &Arc<ghost_storage::Database>,
    peers: &ghost_consensus::peer::PeerManager,
    seeds: &[String],
    our_node_id_hex: &str,
    position: u32,
) -> bool {
    // The recorded (BFT-approved) row is the authority for what to adopt.
    let row = match db.get_mpc_contribution(position) {
        Ok(Some(r)) => r,
        Ok(None) => {
            tracing::warn!(
                position,
                "MPC adopt: no contribution row for position — cannot adopt"
            );
            return false;
        }
        Err(e) => {
            tracing::warn!(error = %e, position, "MPC adopt: contribution row lookup failed");
            return false;
        }
    };

    // Fast path: already at this applied head — just make sure the singleton
    // reflects it (a lagged singleton on an otherwise-consistent head).
    if ceremony_mgr.contribution_count() == position
        && ceremony_mgr.current_params_hash() == row.new_params_hash
    {
        return persist_singleton_from_manager(ceremony_mgr, db);
    }

    // apply_contribution_multi only accepts the IMMEDIATE next position
    // (position == count + 1). Callers advance positions in order, so this holds.
    if ceremony_mgr.contribution_count() + 1 != position {
        tracing::warn!(
            position,
            count = ceremony_mgr.contribution_count(),
            "MPC adopt: manager not positioned at position-1 — cannot apply out of order"
        );
        return false;
    }

    let is_own = row.contributor_node_id == our_node_id_hex;
    let params_dir = ceremony_mgr.params_dir().clone();
    let new_hash = row.new_params_hash;

    // Serialise param writes against the other writers (startup fetch, BFT apply,
    // params_callback) on the shared parameter files.
    let _param_write_guard = param_write_lock().lock().await;

    // (1) Local candidate serving file first (parse off the async thread).
    let local = {
        let dir = params_dir.clone();
        tokio::task::spawn_blocking(move || load_local_candidate_note_spend(&dir, &new_hash))
            .await
            .ok()
            .flatten()
    };

    let note_spend = match local {
        Some(p) => {
            tracing::info!(position, is_own, "MPC adopt: using local candidate params");
            p
        }
        None => {
            // (2) Network fallback: a voter serves the applied head by hash. A
            // contributor adopting its OWN lost candidate resolves nothing for
            // itself (it is not its own peer) → seeds-only, and any voter's
            // current.bin now hashes to `new_hash`.
            let contributor_addr = if is_own {
                None
            } else {
                hex::decode(&row.contributor_node_id)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                    .and_then(|c| resolve_contributor_addr(peers, db, &c))
            };
            let sources = ordered_fetch_sources(contributor_addr.as_deref(), seeds);
            match fetch_ceremony_params_bundle(&sources, new_hash).await {
                Some(b) => {
                    tracing::info!(
                        position,
                        is_own,
                        "MPC adopt: fetched applied params from network"
                    );
                    (*b.note_spend).clone()
                }
                None => {
                    tracing::warn!(
                        position,
                        "MPC adopt: no local candidate and no network source served matching params"
                    );
                    return false;
                }
            }
        }
    };

    let contribution = contribution_from_row(&row);

    // Never adopt a FOREIGN lineage on hash-match alone: run the same catch-up
    // crypto verification (Schnorr proof bound to ceremony_id + h/l pairing
    // transform against OUR prev) a voter/callback runs. OWN contributions are
    // self-authored and gated by the hash-match to our own approved row (their
    // proof may not even be locally present yet).
    if !is_own && position >= 2 && ceremony_mgr.has_current_params() {
        let prev = match ceremony_mgr.note_spend_params() {
            Some(p) => p,
            None => {
                tracing::warn!(
                    position,
                    "MPC adopt: no current params to verify a non-own contribution against"
                );
                return false;
            }
        };
        let mgr = Arc::clone(ceremony_mgr);
        let ns = note_spend.clone();
        let c = contribution.clone();
        let verified =
            tokio::task::spawn_blocking(move || mgr.verify_contribution_catchup(&prev, &ns, &c))
                .await;
        if !matches!(verified, Ok(Ok(true))) {
            tracing::warn!(
                position,
                result = ?verified,
                "MPC adopt: non-own candidate FAILED catch-up verification — refusing"
            );
            return false;
        }
    }

    // Apply through the manager + persist the singleton, off the async thread.
    let mgr = Arc::clone(ceremony_mgr);
    let db2 = Arc::clone(db);
    let applied = tokio::task::spawn_blocking(move || {
        apply_and_persist_adopted_note_spend(&mgr, &db2, note_spend, &contribution)
    })
    .await;
    matches!(applied, Ok(true))
}

/// Catch THIS node's on-disk head + singleton up to the recorded chain tip by
/// adopting every un-adopted applied position in order. Used both when a
/// contributor first learns (via gossip) that its contribution was BFT-applied
/// and at startup for a contributor whose head lags the chain (the restart
/// self-heal). Returns `true` only when the manager count reaches the recorded
/// max position (`get_mpc_max_contribution_position`) with each step's invariant
/// satisfied; `false` if any position could not be adopted (caller then avoids
/// declaring elder success and lets a later retry / restart heal it).
#[cfg(feature = "mpc-ceremony")]
async fn adopt_all_applied_positions(
    ceremony_mgr: &Arc<ghost_mpc::CeremonyManager>,
    db: &Arc<ghost_storage::Database>,
    peers: &ghost_consensus::peer::PeerManager,
    seeds: &[String],
    our_node_id_hex: &str,
) -> bool {
    let max_pos = db
        .get_mpc_max_contribution_position()
        .ok()
        .flatten()
        .unwrap_or(0);
    while ceremony_mgr.contribution_count() < max_pos {
        let next = ceremony_mgr.contribution_count() + 1;
        // Before adopting, make sure this position's FULL data is present locally.
        // A row that arrived via lightweight gossip (or the proof-less
        // `/contributors` sync) carries an EMPTY proof and NO retained votes, so:
        //   * a FOREIGN lineage could not be re-verified (`verify_contribution_catchup`
        //     needs the real Schnorr/pairing proof), and
        //   * a later restart's genesis-anchored check would fail closed (it
        //     requires the retained ≥quorum BFT votes for every position 2..N).
        // Pull the real proof + retained votes from a peer's
        // `/api/v1/mpc/votes/{pos}` endpoint (best-effort; safe proof-fill upsert
        // preserves an applied row). If no seed serves it we still attempt the
        // adopt with whatever is local — an OWN position needs neither, and a
        // FOREIGN one without a valid proof simply fails the crypto verify below
        // and we stop (fail-safe), never adopting on hash-match alone.
        sync_mpc_proof_and_votes(seeds, next, db).await;
        if !adopt_applied_position(ceremony_mgr, db, peers, seeds, our_node_id_hex, next).await {
            return false;
        }
    }
    true
}

/// Reconcile the `mpc_ceremony` singleton to the recorded contribution-chain
/// head. The SINGLE source of the "singleton count == chain tip == head lineage
/// hash" invariant shared by the fresh-join SYNC path (Part A) and the startup
/// self-heal guard (Part B).
///
/// * ZERO contribution rows → returns `Ok(None)` and writes NOTHING: the node
///   is legitimately pre-genesis (a brand-new genesis node) and must stay so.
/// * `n > 0` rows AND singleton absent-or-BEHIND → creates / advances the
///   singleton to `contribution_count = n` with
///   `current_params_hash = mpc_contributions[n].new_params_hash` (the lineage
///   head) and `ceremony_id = position-1.prev_params_hash` (the genesis anchor).
/// * `n > 0` rows AND singleton already at/ahead of `n` → no-op, `Ok(Some(n))`.
///
/// Fail-CLOSED + honest: it reconciles ONLY to contributions that actually
/// exist, never fabricates a genesis or invents a head, and NEVER lowers an
/// already-ahead singleton (that would be a rollback).
#[cfg(feature = "mpc-ceremony")]
fn reconcile_singleton_to_recorded_head(
    db: &ghost_storage::Database,
) -> anyhow::Result<Option<u32>> {
    let max_pos = match db.get_mpc_max_contribution_position()? {
        Some(n) if n > 0 => n,
        // No contribution rows: genuinely pre-genesis — leave the DB untouched.
        _ => return Ok(None),
    };

    // Only create-if-absent or advance-if-behind; never lower an ahead singleton.
    if let Some(state) = db.get_mpc_ceremony_state()? {
        if state.contribution_count >= max_pos {
            return Ok(Some(max_pos));
        }
    }

    let head = db.get_mpc_contribution(max_pos)?.ok_or_else(|| {
        anyhow::anyhow!("MPC: chain tip position {max_pos} has no contribution row")
    })?;
    // Canonical ceremony anchor = position-1's prev_params_hash (genesis lineage).
    let anchor = db.mpc_genesis_ceremony_id()?.unwrap_or([0u8; 32]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    db.reconcile_mpc_singleton_to_head(max_pos, &head.new_params_hash, &anchor, now)?;
    Ok(Some(max_pos))
}

/// Ensure the on-disk `note_spend_params_current.bin` IS the recorded
/// contribution-chain head (`mpc_contributions[MAX].new_params_hash`).
///
/// If the manager already holds head parameters whose lineage
/// [`hash_parameters`] equals the recorded head, this is a no-op (`Ok(true)`) —
/// the common case for both a fresh join (the generic params fetch already
/// installed the head) and a node7-style restart (the head is on disk, only the
/// singleton was missing). Otherwise the head is fetched BY ITS LINEAGE HASH
/// (contributor-first, then seeds; hash-checked inside
/// [`fetch_ceremony_params_bundle`]) and installed through the manager's atomic
/// params writer ([`ghost_mpc::CeremonyManager::install_synced_head`]), then the
/// on-disk head is guaranteed to match.
///
/// Returns `Ok(false)` when there is no recorded head (zero contributions —
/// pre-genesis). Returns `Err` (fail-safe) when a head is recorded but no source
/// can supply matching parameters, so the caller does NOT persist a singleton it
/// cannot back with on-disk params.
#[cfg(feature = "mpc-ceremony")]
async fn ensure_recorded_head_installed(
    ceremony_mgr: &Arc<ghost_mpc::CeremonyManager>,
    db: &ghost_storage::Database,
    peers: &ghost_consensus::peer::PeerManager,
    seeds: &[String],
) -> anyhow::Result<bool> {
    let max_pos = match db.get_mpc_max_contribution_position()? {
        Some(n) if n > 0 => n,
        _ => return Ok(false),
    };
    let head = db.get_mpc_contribution(max_pos)?.ok_or_else(|| {
        anyhow::anyhow!("MPC: chain tip position {max_pos} has no contribution row")
    })?;

    // Already at the recorded head on disk (loaded into the manager)?
    let on_disk_ok = ceremony_mgr
        .note_spend_params()
        .and_then(|p| ghost_mpc::contribution::hash_parameters(&p).ok())
        .map(|h| h == head.new_params_hash)
        .unwrap_or(false);
    if on_disk_ok {
        return Ok(true);
    }

    // current.bin is missing / stale: fetch the exact head by its lineage hash
    // and install it through the atomic params writer. Serialise against the
    // other trusted-setup writers on the shared parameter files.
    let _guard = param_write_lock().lock().await;
    let contributor_addr = hex::decode(&head.contributor_node_id)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .and_then(|c| resolve_contributor_addr(peers, db, &c));
    let sources = ordered_fetch_sources(contributor_addr.as_deref(), seeds);
    let bundle = fetch_ceremony_params_bundle(&sources, head.new_params_hash)
        .await
        .ok_or_else(|| {
            anyhow::anyhow!(
                "MPC: no source served head params matching recorded lineage at position {max_pos}"
            )
        })?;
    let note_spend = (*bundle.note_spend).clone();
    let new_hash = head.new_params_hash;
    // `install_synced_head` is CPU-heavy (serialise + hash hundreds of MB); run it
    // off the async runtime on a blocking thread (mirrors the adopt path).
    let mgr = Arc::clone(ceremony_mgr);
    let installed = tokio::task::spawn_blocking(move || {
        mgr.install_synced_head(max_pos, &note_spend, new_hash)
    })
    .await;
    match installed {
        Ok(Ok(())) => Ok(true),
        Ok(Err(e)) => Err(anyhow::anyhow!("MPC: install_synced_head failed: {e}")),
        Err(e) => Err(anyhow::anyhow!(
            "MPC: install_synced_head task join failed: {e}"
        )),
    }
}

/// Stage C task 3: fetch a single position's FULL contribution (with the real
/// `contribution_proof`) AND its retained approve/reject votes from a peer's
/// `/api/v1/mpc/votes/{position}` endpoint, and persist BOTH locally.
///
/// This is what makes catch-up autonomous: the old `/contributors` sync saved
/// rows with an EMPTY proof and NO votes, so a fresh node could neither re-run
/// `verify_contribution` nor check the retained BFT quorum. After this call the
/// local DB holds the real proof (filled via the safe proof-fill upsert in
/// `save_mpc_contribution`) and every retained vote, so the genesis-anchored
/// startup verification has the data it needs. Returns `true` if at least the
/// proof or some votes were persisted from some seed.
#[cfg(feature = "mpc-ceremony")]
async fn sync_mpc_proof_and_votes(
    seeds: &[String],
    position: u32,
    db: &ghost_storage::Database,
) -> bool {
    for seed in seeds {
        let host = seed.split(':').next().unwrap_or(seed);
        let url = format!("http://{}:8080/api/v1/mpc/votes/{}", host, position);
        let resp = match reqwest::Client::new()
            .get(&url)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };
        let data: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => continue,
        };

        let mut persisted = false;

        // 1. Persist the real proof (proof-fill upsert preserves an applied row).
        if let Some(c) = data.get("contribution") {
            let proof_hex = c
                .get("contribution_proof")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let node_id = c.get("node_id").and_then(|v| v.as_str()).unwrap_or("");
            let prev = c
                .get("prev_params_hash")
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
            let new = c
                .get("new_params_hash")
                .and_then(|v| v.as_str())
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
            let created_at = c.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
            let epoch = c.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0);

            if let (false, Ok(proof_bytes), Some(prev), Some(new)) = (
                proof_hex.is_empty() || node_id.is_empty(),
                hex::decode(proof_hex),
                prev,
                new,
            ) {
                let record = ghost_storage::queries::MpcContributionRecord {
                    elder_position: position,
                    contributor_node_id: node_id.to_string(),
                    prev_params_hash: prev,
                    new_params_hash: new,
                    contribution_proof: proof_bytes,
                    epoch,
                    created_at,
                };
                if db.save_mpc_contribution(&record).is_ok() {
                    persisted = true;
                }
            }
        }

        // 2. Persist every retained vote (save_mpc_vote upserts by (pos, voter)).
        if let Some(votes) = data.get("votes").and_then(|v| v.as_array()) {
            for v in votes {
                let voter = v.get("voter_node_id").and_then(|x| x.as_str());
                let approve = v.get("approve").and_then(|x| x.as_bool());
                let sig = v
                    .get("signature")
                    .and_then(|x| x.as_str())
                    .and_then(|h| hex::decode(h).ok());
                let voted_at = v.get("voted_at").and_then(|x| x.as_u64()).unwrap_or(0);
                if let (Some(voter), Some(approve), Some(sig)) = (voter, approve, sig) {
                    let vote = ghost_storage::queries::MpcVerificationVote {
                        contribution_position: position,
                        voter_node_id: voter.to_string(),
                        approve,
                        signature: sig,
                        voted_at,
                    };
                    if db.save_mpc_vote(&vote).is_ok() {
                        persisted = true;
                    }
                }
            }
        }

        if persisted {
            return true;
        }
    }
    false
}

/// Startup self-heal: ensure the trusted-setup parameters exist on disk before
/// the hard `load_trusted_params` check, fetching them from seeds if missing.
///
/// Idempotent: returns immediately when `note_spend_params_current.bin` (the
/// file `load_trusted_params` verifies) is already present. Otherwise it tries
/// each seed for a bounded number of rounds with a short backoff. On total
/// failure it returns an error so the process exits — systemd restarts it and
/// it retries, recovering automatically the moment a seed becomes reachable.
/// It NEVER loops forever inside one process and NEVER continues without params.
///
/// The `expected` pinned hashes gate every fetched/present blob. Normally this is
/// `expected_param_hashes()` (from `ZK_PARAMS_HASH`), but the autonomous-ossified
/// path passes `{ "BLOCK": ossified_file_hash }` sourced from the DB latch so a
/// fresh joiner self-heals the FINAL params with no env pin at all.
#[cfg(all(feature = "zk-consensus", feature = "mpc-ceremony"))]
async fn ensure_mpc_params_present(
    seed_nodes: &[String],
    params_dir: &std::path::Path,
    expected: &std::collections::HashMap<String, [u8; 32]>,
) -> Result<()> {
    let current = params_dir.join("note_spend_params_current.bin");
    let expected = expected.clone();

    if current.exists() {
        // Present — but DON'T blindly trust it. Validate against the pinned
        // ZK_PARAMS_HASH (the same gate `load_trusted_params` enforces on the
        // next line). A present-but-CORRUPT file (the node6 crash-loop) must
        // SELF-HEAL: quarantine the bad file and fall through to re-fetch,
        // rather than returning Ok and letting the hard hash check kill the
        // process. NEVER continue with unverified params.
        match expected.get("BLOCK") {
            Some(pinned) => match sha256_file(&current) {
                Ok(actual) if &actual == pinned => return Ok(()),
                Ok(actual) => {
                    warn!(
                        expected = %hex::encode(pinned),
                        got = %hex::encode(actual),
                        path = %current.display(),
                        "MPC params present but hash MISMATCHES the pinned ZK_PARAMS_HASH — quarantining and re-fetching from seeds (self-heal)"
                    );
                    quarantine_corrupt_note_spend(params_dir);
                }
                Err(e) => {
                    warn!(error = %e, path = %current.display(), "MPC params present but unreadable — quarantining and re-fetching");
                    quarantine_corrupt_note_spend(params_dir);
                }
            },
            // No pinned hash (test nets): preserve historical behaviour — a
            // present file is accepted as-is (nothing to verify it against).
            None => return Ok(()),
        }
    }

    if seed_nodes.is_empty() {
        return Err(anyhow::anyhow!(
            "MPC params missing or quarantined at {} and no seed nodes are configured to fetch \
             them from. Add at least one reachable seed to network.seed_nodes, or run the genesis \
             node with --genesis to create the ceremony.",
            params_dir.display()
        ));
    }

    warn!(
        path = %params_dir.display(),
        seeds = seed_nodes.len(),
        verified = expected.contains_key("BLOCK"),
        "MPC params missing — fetching trusted-setup parameters from seeds before ZK startup check…"
    );

    const MAX_ROUNDS: u32 = 20;
    for round in 1..=MAX_ROUNDS {
        for seed in seed_nodes {
            let host = seed.split(':').next().unwrap_or(seed);
            if try_fetch_params_from_seed(host, params_dir, &expected).await && current.exists() {
                info!(peer = %host, path = %params_dir.display(), "MPC params self-heal succeeded — trusted-setup parameters fetched and verified");
                return Ok(());
            }
        }

        if round % 4 == 0 {
            info!(
                round,
                "MPC params self-heal: still fetching from seeds (round {}/{})…", round, MAX_ROUNDS
            );
        }
        if round < MAX_ROUNDS {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        }
    }

    Err(anyhow::anyhow!(
        "MPC params self-heal: exhausted all {} seed(s) over {} rounds — trusted-setup parameters \
         still missing at {}. Exiting so the service manager restarts and retries; the node will \
         recover automatically once a seed serving verified ceremony params is reachable.",
        seed_nodes.len(),
        MAX_ROUNDS,
        params_dir.display()
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    let level = parse_log_level(&args.log_level);

    // Console layer (stdout → journald under systemd). ANSI is gated on an
    // interactive terminal so journald stores clean UTF-8, not colour escapes.
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false);

    // Ring-buffer layer feeds the dashboard `/logs` endpoint with ghost-pool's
    // own structured log tail (real message + target + level per event).
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::from_level(level))
        .with(fmt_layer)
        .with(ghost_pool::log_ring::LogRingLayer);

    // HIGH-8: Use fallible initialization - if subscriber is already set, that's fine
    if tracing::subscriber::set_global_default(subscriber).is_err() {
        // A subscriber is already registered (e.g., from test harness). Continue with existing one.
        eprintln!("Note: Tracing subscriber already initialized, using existing configuration");
    }

    // Install the rustls process-level CryptoProvider exactly once, before
    // any code path constructs a `rustls::ClientConfig::builder()` or similar.
    // The verification client's identity-pinned TLS path triggers this otherwise.
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        // Already installed (test harness / re-init); nothing to do.
    }

    // Expand data directory
    let data_dir = expand_path(&args.data_dir)?;
    std::fs::create_dir_all(&data_dir)?;

    // Default key path in data directory (used for --generate-identity and fallback)
    let default_key_path = data_dir.join("node.key");

    // Handle --generate-identity command (doesn't need config)
    if args.generate_identity {
        info!("Generating new node identity...");
        let identity = NodeIdentity::generate();
        identity.save(&default_key_path)?;
        info!("Node ID: {}", identity.node_id_hex());
        info!("Key saved to: {}", default_key_path.display());
        return Ok(());
    }

    // Load configuration first (needed for signer config)
    let config = load_config(&args.config)?;

    // Policy master/slave reconciliation. `pool.toml [policy] profile` is the single
    // MASTER the operator edits (directly or via the dashboard); ghostd's
    // `-ghostpolicy-allowtiers` is a derived SLAVE. If they have drifted — e.g. the
    // dashboard shows `strict` while ghostd is still accepting T2 — bring ghostd back
    // in line with pool.toml here, before anything else, so the two can never silently
    // disagree. No-op when already in sync; only restarts ghostd when it must.
    ghost_verification::routes::reconcile_ghostd_policy_to_config(config.policy.profile.as_str());

    // Determine the effective signer configuration
    // Priority: config.identity.signer > config.identity.key_path > data_dir/node.key
    let signer_config = resolve_signer_path(
        &config.identity.signer,
        &config.identity.key_path,
        &default_key_path,
    )?;

    // Load or create identity using signer config
    let identity = match &signer_config {
        SignerConfig::Local { key_path } => {
            if key_path.exists() {
                NodeIdentity::load(key_path)?
            } else {
                info!(
                    "No identity found at {}, generating new one...",
                    key_path.display()
                );
                let identity = NodeIdentity::generate();
                identity.save(key_path)?;
                info!("Generated new identity, saved to: {}", key_path.display());
                identity
            }
        }
        SignerConfig::Hsm { .. } | SignerConfig::Kms { .. } => {
            // HSM/KMS signers require the key to already exist
            NodeIdentity::from_config(&signer_config).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to initialize {} signer: {}",
                    match &signer_config {
                        SignerConfig::Hsm { .. } => "HSM",
                        SignerConfig::Kms { .. } => "KMS",
                        _ => "unknown",
                    },
                    e
                )
            })?
        }
    };

    // Handle --show-identity command
    if args.show_identity {
        println!("Node ID: {}", identity.node_id_hex());
        println!("Short ID: {}", identity.node_id_short());
        println!("Signer: {}", identity.signer_type());
        return Ok(());
    }

    // Handle --status command
    if args.status {
        return handle_status_command(&config, &identity, None).await;
    }

    // Handle --watch command
    if let Some(interval) = args.watch {
        return handle_status_command(&config, &identity, Some(interval.max(1))).await;
    }

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!(
        "║              Ghost Pool v{}                           ║",
        env!("CARGO_PKG_VERSION")
    );
    info!("║          Decentralized Bitcoin Mining Pool                   ║");
    info!("╚══════════════════════════════════════════════════════════════╝");
    info!(
        "Node ID: {} ({})",
        identity.node_id_short(),
        identity.signer_type()
    );

    // Validate configuration
    let validation = config.validate();

    // Log warnings
    for warning in &validation.warnings {
        warn!("{}", warning);
    }

    // Check for errors
    if !validation.is_valid() {
        error!("Configuration validation failed:");
        for err in &validation.errors {
            error!("  {}", err);
        }
        return Err(anyhow::anyhow!(
            "Configuration validation failed with {} error(s)",
            validation.errors.len()
        ));
    }

    info!(
        "Configuration validated ({} warning(s))",
        validation.warnings.len()
    );

    // Override config with CLI args
    let rpc_host = args.rpc_host.as_ref().unwrap_or(&config.bitcoin.rpc_host);
    let rpc_port = args.rpc_port.unwrap_or(config.bitcoin.rpc_port);

    // Initialize Bitcoin RPC
    info!("Connecting to Ghost Core at {}:{}", rpc_host, rpc_port);
    let mut rpc = BitcoinRpc::new(
        rpc_host,
        rpc_port,
        &config.bitcoin.rpc_user,
        &config.bitcoin.rpc_password,
    )?;
    rpc.set_network(config.bitcoin.network);
    let rpc = Arc::new(rpc);

    // Test RPC connection
    let blockchain_info = match rpc.get_blockchain_info().await {
        Ok(info) => {
            info!(
                chain = %info.chain,
                height = info.blocks,
                difficulty = info.difficulty,
                "Connected to Ghost Core"
            );
            info
        }
        Err(e) => {
            error!(error = %e, "Failed to connect to Ghost Core");
            return Err(anyhow::anyhow!("Bitcoin RPC connection failed: {}", e));
        }
    };

    // Query Tor mode status from Ghost Core
    let tor_status = match rpc.get_tor_mode().await {
        Ok(status) => {
            if status.enabled {
                info!(
                    onion_address = status.onion_address.as_deref().unwrap_or("pending"),
                    embedded = status.embedded_tor,
                    "Tor mode active on Ghost Core"
                );
            }
            Some(status)
        }
        Err(e) => {
            // gettormode may not exist on older Ghost Core versions
            debug!(error = %e, "Could not query Tor mode (older ghostd?)");
            None
        }
    };

    // Initialize database
    let db_path = data_dir.join("ghost.db");

    // Apply a pending restore staged by the dashboard Backup & Restore import,
    // if any. This MUST run before the DB is opened so the swap happens while the
    // file is closed (never corrupting a running DB). It first copies the current
    // DB to a timestamped `.pre-restore-*.db` safety backup. A failure here is
    // non-fatal — the existing DB is left intact and we start from it.
    match ghost_storage::database::apply_pending_restore(&db_path) {
        Ok(true) => info!("Applied pending database restore from dashboard import"),
        Ok(false) => {}
        Err(e) => error!(
            error = %e,
            "Pending database restore failed; starting with the existing database"
        ),
    }

    // Resolve the activation gates for this run BEFORE anything reads them. On mainnet these are
    // the compiled-in constants and nothing can move them; elsewhere they may be pulled down from
    // the environment so a regtest cluster exercises the POST-gate paths using the real shipping
    // binary, rather than a specially-patched one that is not what gets deployed.
    ghost_pool::init_activation_heights(&config.bitcoin.network);

    let db = Arc::new(Database::open(&db_path)?);
    info!("Database opened: {}", db_path.display());

    // P-4: Configure database encryption for payout addresses.
    // Derive a deterministic encryption key from the node identity by signing
    // a domain-separated message. This works with any Signer backend (local, HSM, KMS)
    // and produces a node-specific key without exposing the private key directly.
    // Falls back to GHOST_ENCRYPTION_KEY env var if identity-based derivation fails.
    {
        use sha2::{Digest, Sha256};
        let signature = identity.signer().sign(b"ghost/db-encryption/v1");
        let mut hasher = Sha256::new();
        hasher.update(b"ghost/db-encryption-key/v1");
        hasher.update(signature);
        let key_material = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_material);
        db.set_encryption_key(key);
        // Zeroize local copies
        key.fill(0);
    }

    // ONE-TIME LEDGER RECONCILIATION (runs after DB encryption is configured, and exits).
    //
    // Shares predating schema v41 carry no signed proof — their GHOST-09 signatures exist
    // nowhere — so no node can serve or verify them, and GHOST-03 convergence cannot repair the
    // divergence they cause. Every node sums a different unpaid ledger, so every node computes a
    // different miner split, so GHOST-02's exact-equality check rejects every payout.
    //
    // The only way to make the fleet agree on that backlog is to take the UNION across the
    // operator's own nodes. That is sound because the divergence is nodes MISSING shares, never
    // nodes holding fabricated ones — each node's set is a subset of the truth. It is trusted
    // rather than verified, and it is only defensible because every node in the mesh belongs to
    // the same operator. New shares (v41 onward) carry their proof and converge verifiably.
    if let Some(path) = &args.ledger_export {
        let shares = db.export_unpaid_shares()?;
        let total_work: f64 = shares.iter().map(|s| s.work).sum();
        let no_address = shares.iter().filter(|s| s.payout_address.is_none()).count();
        std::fs::write(path, serde_json::to_vec(&shares)?)?;
        info!(
            shares = shares.len(),
            total_work,
            no_address,
            file = %path.display(),
            "Ledger export complete"
        );
        if no_address > 0 {
            warn!(
                no_address,
                "Shares with no resolvable payout address will be dropped by the payout query's \
                 INNER JOIN on `miners` — they cannot be credited to anyone"
            );
        }
        return Ok(());
    }

    if let Some(path) = &args.ledger_import {
        let raw = std::fs::read(path)?;
        let shares: Vec<ghost_storage::queries::UnpaidShareExport> = serde_json::from_slice(&raw)?;
        let (inserted, miners) = db.import_unpaid_shares(&shares, args.dry_run)?;
        info!(
            offered = shares.len(),
            inserted,
            miners_created = miners,
            dry_run = args.dry_run,
            "Ledger import complete"
        );
        return Ok(());
    }

    // Setup policy profile
    let policy = match config.policy.profile {
        ghost_common::config::PolicyProfile::BitcoinPure => PolicyProfile::bitcoin_pure(),
        ghost_common::config::PolicyProfile::Permissive => PolicyProfile::permissive(),
        ghost_common::config::PolicyProfile::FullOpen => PolicyProfile::full_open(),
        // Custom: build the enforced profile from the operator's `[policy].custom`
        // fields so the finer knobs (tiers, content toggles, size limits, min fee)
        // actually bite at block-build time. Falls back to the default custom
        // block when none is persisted.
        ghost_common::config::PolicyProfile::Custom => {
            let custom = config.policy.custom.clone().unwrap_or_default();
            policy_profile_from_custom(&custom)
        }
    };
    info!(
        "Policy profile: {} (allows up to T{})",
        policy.name,
        policy.highest_allowed_tier().map(|t| t as u8).unwrap_or(0)
    );

    // Setup reaper config for dead code detection, honouring the operator's
    // per-vector detector selection (not just the master on/off).
    let reaper_config = reaper_config_from_settings(&config.reaper);
    if let Err(e) = reaper_config.validate() {
        warn!("Reaper config invalid ({e}); falling back to all-on defaults");
    }
    info!(
        "Reaper: {} (inscription={} dropstuffing={} fakepubkey={} annex={} unreachable={} excess_witness={} legacy={})",
        if reaper_config.enabled { "enabled" } else { "disabled" },
        reaper_config.reject_inscription_envelope,
        reaper_config.reject_drop_stuffing,
        reaper_config.reject_fake_pubkeys,
        reaper_config.reject_annex,
        reaper_config.reject_unreachable_code,
        reaper_config.reject_excess_witness,
        reaper_config.reject_legacy_data_stuffing,
    );

    // Determine effective public_mining from mining_mode
    // PublicPool = public mining enabled, other modes = private
    let mining_mode = config.network.mining_mode;
    let is_public_mining = matches!(mining_mode, MiningMode::PublicPool);

    info!(
        "Mining mode: {:?} (public_mining={})",
        mining_mode, is_public_mining
    );

    // Setup capabilities - initially with elder_status = false
    // We'll update after registering with the database
    let mut capabilities = NodeCapabilities {
        archive_mode: config.storage.archive_mode,
        // Advertise GhostPay only when it is actually enabled — NOT on mere
        // presence of a `[ghost_pay]` block. Pool-only nodes carry a default
        // (disabled) block; advertising `is_some()` made them claim GhostPay,
        // so every peer port-probed their (absent) ghost-pay API and logged a
        // `GhostPay verification failed: Verification timeout` warning. Gating on
        // `ghost_pay_enabled()` stops the false claim (verification still
        // correctly denied them the +4 share, but silently now).
        ghost_pay: config.ghost_pay_enabled(),
        public_mining: is_public_mining, // Derived from mining_mode
        reaper: config.reaper.enabled,
        elder_status: false,
        coordinator: config.coordinator.coordinator_enabled, // opt-in Wraith coordinator role
    };

    // Register node with database
    let node_id_hex = identity.node_id_hex();
    let public_address = config.network.public_address.as_deref();
    let display_name = config.identity.display_name.as_deref();
    let capabilities_str = format!(
        "archive:{},ghost_pay:{},public_mining:{},reaper:{}",
        capabilities.archive_mode,
        capabilities.ghost_pay,
        capabilities.public_mining,
        capabilities.reaper
    );

    // Register node in database (for tracking/discovery purposes).
    // The PoW proof is mandatory for elder-slot eligibility — the
    // promotion SQL filters `WHERE pow_proof IS NOT NULL`, so a nil
    // proof leaves the node permanently ineligible. Always pass our
    // locally-computed proof (generated by NodeIdentity::generate).
    let pow_proof_hex = identity.pow_proof_hex();
    if let Err(e) = db.register_node_with_elder_check_and_pow(
        &node_id_hex,
        public_address,
        display_name,
        &capabilities_str,
        pow_proof_hex.as_deref(),
    ) {
        warn!("Failed to register node: {} - continuing anyway", e);
    }

    // Set local node's payout address for node reward distribution
    if let Some(ref addr) = config.pool.node_payout_address {
        if let Err(e) = db.update_node_payout_address(&node_id_hex, addr) {
            warn!(
                "Failed to set node payout address: {} - continuing anyway",
                e
            );
        } else {
            let redacted = if addr.len() > 10 {
                format!("{}...{}", &addr[..6], &addr[addr.len() - 4..])
            } else {
                "***".to_string()
            };
            debug!(address = %redacted, "Node payout address configured");
        }
    }

    // Check MPC-based elder status
    // Elder = MPC contributor (position 1-101 in the ceremony)
    match db.get_mpc_elder_position(&node_id_hex) {
        Ok(Some(position)) => {
            capabilities.elder_status = true;
            info!("Node is MPC Elder #{}", position);
        }
        Ok(None) => {
            info!(
                "Node is not an MPC elder ({} MPC contributors exist)",
                db.get_mpc_elder_count().unwrap_or(0)
            );
        }
        Err(e) => {
            warn!(
                "Failed to check MPC elder status: {} - defaulting to non-elder",
                e
            );
        }
    }

    // Only advertise Archive when Ghost Core is genuinely keeping a full archive.
    // `storage.archive_mode = true` alone is not enough: a hazed ghostd strips
    // block data and a pruned ghostd has discarded old blocks, so neither can
    // serve the arbitrary historical block the Archive challenge asks for, and
    // claiming it just burns every peer's verification challenges on a guaranteed
    // failure. `blockchain_info` came from `getblockchaininfo` above (the pool
    // hard-exits if that RPC is unreachable), so we never newly-claim Archive on an
    // unknown state — fail-safe: prefer not claiming over falsely claiming.
    if capabilities.archive_mode
        && !should_claim_archive(
            capabilities.archive_mode,
            blockchain_info.hazed,
            blockchain_info.pruned,
        )
    {
        if blockchain_info.hazed {
            warn!("Ghost Core is running in haze mode — disabling archive_mode capability (+5 shares)");
        } else {
            warn!("storage.archive_mode is set but Ghost Core is pruned (not keeping a full archive) — disabling archive_mode capability (+5 shares)");
        }
        capabilities.archive_mode = false;
    }

    info!("Capability shares: {}/15", capabilities.total_shares());

    // Create identity Arc
    let identity = Arc::new(identity);

    // Prometheus metrics
    let metrics = Metrics::default_metrics();

    // Initialize round manager with mining mode
    let is_mainnet_round = config.bitcoin.network == ghost_common::config::BitcoinNetwork::Mainnet;
    let round_config = RoundConfig {
        mining_mode,
        ..Default::default()
    };
    let mut round_manager_inner = RoundManager::new(identity.node_id(), round_config);
    round_manager_inner.set_metrics(Arc::clone(&metrics));
    let round_manager = Arc::new(round_manager_inner);

    // Register our own node's capabilities so we're included in node reward calculations
    // This is critical - without this, our shares won't be counted for node rewards
    round_manager.register_node(identity.node_id(), capabilities);

    // Reload pre-restart share data from database so miners don't lose credit
    round_manager.reload_from_db(&db);

    // Resolve coinbase tag: coinbase_extra > pool_name formatted > mode default
    let coinbase_tag = config
        .pool
        .coinbase_extra
        .clone()
        .or_else(|| {
            config
                .pool
                .pool_name
                .as_ref()
                .map(|name| format!("- G H O S T - {}", name))
        })
        .unwrap_or_else(|| mining_mode.default_coinbase_tag().to_string());

    // Write tag file so SRI pool service can pick it up via ExecStartPre
    let tag_path = data_dir.join("coinbase_tag");
    if let Err(e) = std::fs::write(&tag_path, &coinbase_tag) {
        warn!(error = %e, "Failed to write coinbase tag file");
    }
    info!(tag = %coinbase_tag, "Coinbase tag: {}", coinbase_tag);

    // Initialize template processor with treasury and pool payout addresses from config
    // Per-field policy enforcement (max outputs / size / OP_RETURN / witness /
    // content) is the "Advanced" Custom profile only. The three "Basic" presets
    // stay tier-gate-only, so their baked-in field limits are NOT enforced at
    // block-build time — preserving the historical preset behaviour.
    let enforce_custom_policy_fields = matches!(
        config.policy.profile,
        ghost_common::config::PolicyProfile::Custom
    );

    // The template's minimum fee-rate floor. Presets keep the historical
    // TemplateConfig default (unchanged behaviour); the Custom profile lets the
    // operator set their own floor via `[policy].custom.min_fee_rate`.
    let template_min_fee_rate = if enforce_custom_policy_fields {
        policy.min_fee_rate
    } else {
        TemplateConfig::default().min_fee_rate
    };

    // Pool payout address defaults to treasury address if not explicitly configured separately
    let template_config = TemplateConfig {
        treasury_address: config.pool.treasury_address.clone(),
        pool_payout_address: config.pool.treasury_address.address().to_string(), // Use same as treasury for now
        network: config.bitcoin.network,
        mining_mode,
        solo_payout_address: config.network.solo_payout_address.clone(),
        coinbase_extra: coinbase_tag,
        min_fee_rate: template_min_fee_rate,
        enforce_custom_policy_fields,
        // Block-priority lever (max_fee default | payments_first). Resolved once
        // here at startup from pool.toml; the dashboard POST persists + restarts.
        block_priority: config.pool.block_priority,
        // Template refresh cadence (ms) from pool.toml, clamped to [10s,60s].
        // The dashboard retunes it live via the atomic handle (no restart).
        refresh_interval_ms: config.pool.template_refresh_ms(),
        ..Default::default()
    };
    let template_processor = Arc::new(
        TemplateProcessor::new(
            template_config,
            Arc::clone(&rpc),
            policy.clone(),
            reaper_config,
        )
        .with_database(Arc::clone(&db)),
    );
    // Restore any previously approved payout proposal from database
    template_processor.restore_from_db();

    // Note: Native stratum server removed - using SRI (Stratum Reference Implementation) via TDP
    // SRI pool connects to ghost-pool's TDP server for templates
    // SRI translator handles SV1 miners on port 3333

    // Initialize P2P mesh with actual node capabilities for health pings
    // C-1: Enable Noise Protocol encryption for sensitive P2P traffic
    let noise_keypair_path = data_dir.join("noise.key");
    let mesh_config = MeshConfig {
        public_address: config
            .network
            .public_address
            .clone()
            .unwrap_or_else(|| "127.0.0.1".to_string()),
        ports: config.network.p2p.clone(),
        capabilities,
        // Advertise a coordinator endpoint ONLY when opted in — otherwise a
        // stray config value would falsely mark us coordinator-reachable.
        advertised_coordinator_endpoint: if config.coordinator.coordinator_enabled {
            config.coordinator.advertised_endpoint.clone()
        } else {
            None
        },
        // C-1: Noise Protocol configuration for encrypted P2P
        // Read from config (mainnet validation ensures this is true on mainnet)
        noise_enabled: config.network.noise_enabled,
        noise_port: ghost_consensus::mesh::DEFAULT_NOISE_PORT,
        noise_keypair_path: Some(noise_keypair_path),
        noise_required: true,
        // Persist the outbound mesh sequence so a restart resumes above its
        // prior value instead of resetting to 0 (which peers reject as replays).
        sequence_persist_path: Some(data_dir.join("mesh_sequence")),
        ..Default::default()
    };
    // M-2: Use try_new() to properly handle Noise initialization failures
    let mut mesh_inner = MeshNetwork::try_new(Arc::clone(&identity), mesh_config)?;

    // Provide real miner count for health pings (replaces peer_count placeholder).
    // The round_manager tracks per-round miner stats from share submissions.
    let rm_for_miner_count = Arc::clone(&round_manager);
    mesh_inner.set_miner_count_provider(Arc::new(move || {
        rm_for_miner_count
            .round_stats(rm_for_miner_count.current_round_id())
            .map(|s| s.miner_count as u32)
            .unwrap_or(0)
    }));

    // Gossip the local active miner_id hashes (5-min window) so peers can
    // compute a deduplicated mesh-wide active count. Hashes are SHA-256
    // truncated to 16 bytes — privacy-preserving and small (~16 KB per ping
    // at 1k miners; negligible at our scale).
    let db_for_active_hashes = Arc::clone(&db);
    mesh_inner.set_active_miner_hashes_provider(Arc::new(move || {
        db_for_active_hashes
            .active_miner_id_hashes(300)
            .unwrap_or_default()
    }));

    // Gossip THIS node's own realized hashrate (10-min trailing window) so
    // peers can sum one term per node into a pool-wide total that's stable
    // under load-balancer migration. Scoped by `received_by = hex(node_id[..8])`
    // so only shares this node received directly count — replicated peer
    // share-proofs are excluded, which is what keeps the mesh sum from
    // double-counting (each share counted once, by its origin node).
    let self_received_by = hex::encode(&identity.node_id()[..8]);
    let db_for_local_hr = Arc::clone(&db);
    let self_rx_for_provider = self_received_by.clone();
    mesh_inner.set_local_hashrate_provider(Arc::new(move || {
        db_for_local_hr
            .local_hashrate_th(MESH_HASHRATE_WINDOW_SECS, &self_rx_for_provider)
            .unwrap_or(0.0)
    }));

    // Gossip THIS node's best (rarest) valid share per records window so every
    // node converges on the pool-wide rarest record per window. Without this,
    // the record lives on whichever node received it and the website's fan-out
    // flickers when that node is momentarily unreachable. Each entry mirrors the
    // shape the `/api/v1/pool/records` endpoint returns (redacted miner_id,
    // achieved difficulty) so a receiving node can serve it verbatim.
    let db_for_best_records = Arc::clone(&db);
    mesh_inner.set_best_records_provider(Arc::new(move || {
        build_local_best_records(&db_for_best_records)
    }));

    // Swarm-page telemetry gossiped so peers render each node's real state
    // instead of a dash. These mirror exactly what the swarm SELF row reports.

    // L1 (Bitcoin) block height — the same value the /health block_height uses.
    let rm_for_l1_height = Arc::clone(&round_manager);
    mesh_inner.set_l1_height_provider(Arc::new(move || rm_for_l1_height.current_height()));

    // This node's own trailing-7-day uptime %, the qualification gatekeeper
    // metric — the exact figure `get_uptime_percent` returns (GHOST-10
    // time-based denominator), keyed by our own hex node id and converted to a
    // percentage. `None` (→ "—") when there are no samples yet, never fabricated.
    let db_for_uptime = Arc::clone(&db);
    let uptime_node_id_hex = identity.node_id_hex();
    mesh_inner.set_uptime_percent_provider(Arc::new(move || {
        let since = chrono::Utc::now().timestamp()
            - (ghost_common::constants::UPTIME_WINDOW_DAYS as i64 * 86_400);
        db_for_uptime
            .get_uptime_percent(&uptime_node_id_hex, since)
            .ok()
            .map(|ratio| ratio * 100.0)
    }));

    // Ghost Pay L2 virtual-block height, read from a lightweight cache refreshed
    // by a background poller (below). Reading a cached atomic keeps the health-
    // ping hot path free of the cross-process ghost-pay call.
    let l2_height_cache = Arc::new(L2HeightCache::default());
    let l2_cache_for_ping = Arc::clone(&l2_height_cache);
    mesh_inner.set_l2_height_provider(Arc::new(move || l2_cache_for_ping.get()));

    // Poll the local ghost-pay service (:8800) for the L2 tip and cache it, so
    // both this node's gossiped L2 height and the cache stay warm. Only runs
    // when ghost-pay is enabled; on failure the last good value is retained.
    if config.ghost_pay_enabled() {
        let l2_cache_for_poll = Arc::clone(&l2_height_cache);
        tokio::spawn(async move {
            let client = match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .danger_accept_invalid_certs(true)
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "L2 height poller: failed to build client");
                    return;
                }
            };
            loop {
                if let Some(height) = fetch_ghostpay_virtual_block(&client).await {
                    l2_cache_for_poll.set(height);
                }
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            }
        });
    }

    let mesh = Arc::new(mesh_inner);

    // Hardware-derived miner capacity. Operator's `network.max_miners` is the
    // ceiling — `measure()` returns `min(calculated, declared)`. The mesh
    // broadcasts this in health pings so peers' load balancers can route by
    // utilisation % of declared capacity.
    let cap_breakdown = capacity::measure(Some(config.network.max_miners));
    mesh.set_max_capacity(cap_breakdown.effective_max);
    let effective_max_capacity = cap_breakdown.effective_max;

    // Initialize consensus voting
    let voting_manager = Arc::new(VotingManager::new(100)); // 100 max sessions

    // Create broadcast callback for vote propagation via Noise relay
    let (vote_tx, mut vote_rx) =
        tokio::sync::mpsc::channel::<(ghost_consensus::message::MessageType, Vec<u8>)>(64);
    let mesh_for_vote_relay = Arc::clone(&mesh);
    tokio::spawn(async move {
        while let Some((msg_type, payload)) = vote_rx.recv().await {
            match mesh_for_vote_relay.create_envelope_raw(msg_type, payload) {
                Ok(envelope) => {
                    if let Err(e) = mesh_for_vote_relay.broadcast(envelope).await {
                        tracing::warn!(error = %e, "Vote Noise broadcast failed");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Vote envelope creation failed");
                }
            }
        }
    });
    let broadcast_fn: BroadcastFn = Arc::new(move |msg_type, payload| {
        vote_tx.try_send((msg_type, payload)).map_err(|e| {
            ghost_common::error::GhostError::Internal(format!(
                "Vote broadcast channel error: {}",
                e
            ))
        })
    });

    // Create execute callback for consensus decisions
    let tp_for_execute = Arc::clone(&template_processor);
    let execute_fn: ExecuteFn = Arc::new(move |result: ConsensusResult| {
        match result {
            ConsensusResult::Approved {
                proposal_hash,
                approval_count,
                total_nodes,
            } => {
                info!(
                    hash = %hex::encode(&proposal_hash[..8]),
                    approvals = approval_count,
                    total = total_nodes,
                    "Payout consensus approved - executing"
                );
                // Store approved payout for coinbase construction
                tp_for_execute.set_approved_payout(proposal_hash);

                // NOTE: settling the ledger (mark-paid + treasury) deliberately does NOT
                // happen here. Approval only ARMS the coinbase — the coins do not exist until a
                // block carrying this snapshot is actually mined and accepted. Settling on
                // approval marked a miner's work paid before a satoshi had moved, and if the
                // pool never won again that work stayed marked paid and never paid.
                //
                // The ledger is settled in the block-accepted path, keyed on the winning block's
                // `payout_snapshot`, via `payout::settle_paid_block`.

                // Refresh template to include approved payout in coinbase
                // This is the "1 block behind" fix: when consensus approves the payout
                // from round N, refresh templates so block N+1 has correct outputs
                let tp = Arc::clone(&tp_for_execute);
                tokio::spawn(async move {
                    if let Err(e) = tp.refresh_template().await {
                        tracing::error!(error = %e, "Failed to refresh template after payout approval");
                    } else {
                        tracing::info!("Template refreshed with approved payout outputs");
                    }
                });
            }
            ConsensusResult::Rejected {
                proposal_hash,
                rejection_count,
                reason,
                ..
            } => {
                warn!(
                    hash = %hex::encode(&proposal_hash[..8]),
                    rejections = rejection_count,
                    reason = ?reason,
                    "Payout consensus rejected"
                );
            }
            ConsensusResult::Timeout {
                proposal_hash,
                approvals,
                rejections,
                ..
            } => {
                warn!(
                    hash = %hex::encode(&proposal_hash[..8]),
                    approvals = approvals,
                    rejections = rejections,
                    "Payout consensus timed out"
                );
            }
            ConsensusResult::Error(msg) => {
                error!(error = %msg, "Consensus error");
            }
        }
        Ok(())
    });

    // Create shared ban manager for cross-handler enforcement (C1 security fix)
    let ban_manager = Arc::new(BanManager::new());
    info!("Shared BanManager created for cross-handler ban enforcement");

    // GHOST-11: re-apply equivocation bans persisted before this restart, so a
    // restart doesn't silently un-ban an equivocator that is still inside its
    // ban window. (Bans are otherwise in-memory only.)
    {
        const EQUIVOCATION_BAN_WINDOW_SECS: i64 = 600;
        let now = chrono::Utc::now().timestamp();
        match db.get_recent_equivocators(now - EQUIVOCATION_BAN_WINDOW_SECS) {
            Ok(equivocators) => {
                let mut restored = 0usize;
                for (node_id, detected_at) in equivocators {
                    let remaining = (detected_at + EQUIVOCATION_BAN_WINDOW_SECS) - now;
                    if remaining > 0 {
                        ban_manager.ban_for_duration(
                            node_id,
                            ghost_consensus::ban_manager::BanReason::Equivocation,
                            std::time::Duration::from_secs(remaining as u64),
                        );
                        restored += 1;
                    }
                }
                if restored > 0 {
                    info!(
                        restored,
                        "GHOST-11: re-applied persisted equivocation bans on startup"
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, "GHOST-11: failed to load persisted equivocation bans")
            }
        }
    }

    // Create vote handler with callbacks and shared ban manager
    // 4.5 SECURITY: Rate limiter persistence is now enabled by default to prevent
    // attackers from bypassing rate limits by triggering node restarts.
    // GHOST-04: adapt the BFT voter floor to the registered elder set, clamped
    // to [4, 7]. At the bootstrap 4-elder set this is 4 (f=1, 3-of-4 quorum) so
    // payout consensus can actually FORM — a hard floor of 7 made mainnet payout
    // voting impossible below 7 elders. It rises to 7 (f=2) as the set grows,
    // capped at the long-term target; requiring the full registered set (up to
    // 7) keeps a small-N quorum from being unsafe. NOTE: computed once at start;
    // restart after the elder set changes materially.
    let rate_limiter_path = data_dir.join("rate_limiter.json");
    let vote_config = VoteHandlerConfig {
        min_voters_for_bft: if is_mainnet_round {
            (db.get_mpc_elder_count().unwrap_or(0) as usize).clamp(4, 7)
        } else {
            3
        },
        ..VoteHandlerConfig::default()
    };
    // Create proposal store callback so remote nodes store proposal data
    // in the template processor when proposals arrive via P2P
    let tp_for_proposal_store = Arc::clone(&template_processor);
    let proposal_store_fn: ProposalStoreFn = Arc::new(move |proposal| {
        tp_for_proposal_store.store_proposal(proposal);
    });

    let vote_handler = Arc::new(
        VoteHandler::with_config(
            Arc::clone(&identity),
            Arc::clone(&voting_manager),
            vote_config,
        )
        .with_broadcaster(broadcast_fn)
        .with_executor(execute_fn)
        .with_proposal_store(proposal_store_fn)
        .with_ban_manager(Arc::clone(&ban_manager))
        .with_database(Arc::clone(&db))
        .with_rate_limiter_persistence(rate_limiter_path)
        .with_revocation_executor({
            let db_for_revoke = Arc::clone(&db);
            Arc::new(move |node_id_hex: &str, _position: u32, reason: &str| {
                // 1. Remove from mpc_contributions and get position
                let pos = db_for_revoke.revoke_mpc_elder(node_id_hex)?;
                if let Some(position) = pos {
                    // 2. Burn the elder position
                    db_for_revoke.burn_elder_position(position, node_id_hex, reason)?;
                    tracing::warn!(
                        node_id = %&node_id_hex[..8.min(node_id_hex.len())],
                        position,
                        reason,
                        "Elder revoked and position burned"
                    );
                } else {
                    tracing::warn!(
                        node_id = %&node_id_hex[..8.min(node_id_hex.len())],
                        "Elder revocation: node not found in MPC contributions"
                    );
                }
                Ok(())
            })
        }),
    );
    // Start the background persistence task (persists every 60 seconds)
    vote_handler.start_persistence_task();

    // Populate elders from database for BFT voting
    match db.get_elders() {
        Ok(elders) => {
            for elder in &elders {
                // Parse node_id hex to bytes
                if let Ok(node_id_bytes) = hex::decode(&elder.node_id) {
                    if node_id_bytes.len() == 32 {
                        let mut node_id = [0u8; 32];
                        node_id.copy_from_slice(&node_id_bytes);
                        vote_handler.add_elder(node_id);
                    }
                }
            }
            info!(
                "Registered {} elders from database for BFT voting",
                elders.len()
            );
        }
        Err(e) => {
            warn!("Failed to load elders for voting: {}", e);
        }
    }

    // Register ourselves as a voter - ALL active nodes participate in BFT consensus
    // (elder_status is just a capability flag indicating uptime/reliability, not a voting requirement)
    vote_handler.add_elder(identity.node_id());
    info!("Registered self as BFT voter");
    info!(
        "Initial voters for BFT: {} (peer discovery will add more from HealthPing)",
        vote_handler.elder_count()
    );

    // Register vote handler with mesh for incoming vote messages
    mesh.register_handler(
        Arc::clone(&vote_handler) as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>
    );

    // Periodic timeout checker for payout proposals
    // Without this, voting sessions that don't get enough votes never expire,
    // which can cause stale proposals to accumulate and block new ones.
    {
        let vh_for_timeouts = Arc::clone(&vote_handler);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let timeouts = vh_for_timeouts.check_timeouts();
                for result in &timeouts {
                    if let ghost_common::types::ConsensusResult::Timeout {
                        proposal_hash,
                        approvals,
                        total_nodes,
                        ..
                    } = result
                    {
                        tracing::warn!(
                            hash = %hex::encode(&proposal_hash[..8]),
                            approvals,
                            total_nodes,
                            "Payout proposal timed out"
                        );
                    }
                }
                vh_for_timeouts.cleanup_rate_limiter();
            }
        });
    }

    // Create and register health ping handler for peer tracking and voter discovery
    // ALL active nodes participate in BFT consensus - the callback registers discovered nodes as voters
    let vh_for_callback = Arc::clone(&vote_handler);
    let voter_callback: ghost_consensus::health_handler::ElderCallback = Arc::new(move |node_id| {
        vh_for_callback.add_elder(node_id);
    });

    // Callback to register node capabilities for payout calculations
    let rm_for_callback = Arc::clone(&round_manager);
    let node_caps_callback: ghost_consensus::health_handler::NodeCapabilitiesCallback =
        Arc::new(move |node_id, capabilities| {
            rm_for_callback.register_node(node_id, capabilities);
        });

    // P2P4-M2: Create capability verifier to replace claimed capabilities with VERIFIED ones
    // This ensures health pings register nodes with their actual verified capabilities,
    // not just what they claim. The QualifiedCapabilityProvider checks challenge results.
    let qualification_provider_for_health =
        Arc::new(QualifiedCapabilityProvider::new(Arc::clone(&db)));
    let qp_for_verifier = Arc::clone(&qualification_provider_for_health);
    let capability_verifier: ghost_consensus::health_handler::CapabilityVerifierCallback =
        Arc::new(move |node_id| qp_for_verifier.get_qualified(node_id));

    let health_handler = Arc::new(
        HealthPingHandler::new(
            Arc::clone(mesh.peers()),
            Some(Arc::clone(&db)),
            Arc::clone(&ban_manager),
        )
        .with_elder_callback(voter_callback)
        .with_node_capabilities_callback(node_caps_callback)
        .with_capability_verifier(capability_verifier),
    );
    mesh.register_handler(
        Arc::clone(&health_handler) as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>
    );

    // Node-reward challenge convergence (Component A): reconcile the v42
    // verification_ledger across nodes so deterministic node-reward qualification
    // reads the same signed challenge history everywhere — the analogue of the
    // GHOST-03 share ledger sweep below. The handler's send is sync, so outbound
    // frames go through an mpsc channel drained by a task that wraps each in a
    // ChallengeConvergence envelope and broadcasts it.
    let (verify_conv_tx, mut verify_conv_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    {
        let mesh_for_vconv = Arc::clone(&mesh);
        tokio::spawn(async move {
            while let Some(bytes) = verify_conv_rx.recv().await {
                match mesh_for_vconv
                    .create_envelope_raw(ghost_consensus::MessageType::ChallengeConvergence, bytes)
                {
                    Ok(envelope) => {
                        if let Err(e) = mesh_for_vconv.broadcast(envelope).await {
                            tracing::debug!(error = %e, "challenge-convergence broadcast failed");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "challenge-convergence envelope failed"),
                }
            }
        });
    }
    let verify_conv_send: ghost_consensus::verification_handler::ChallengeSendFn = {
        let verify_conv_tx = verify_conv_tx.clone();
        Arc::new(move |bytes| {
            verify_conv_tx.try_send(bytes).map_err(|e| {
                ghost_common::error::GhostError::P2PMessage(format!(
                    "challenge-convergence channel: {e}"
                ))
            })
        })
    };

    // Create and register verification result handler for P2P verification results
    // HIGH-VER-4: Use with_peers to validate challengers are known nodes before recording
    // CONSENSUS SECURITY: re-derive peer-broadcast Archive verdicts against our
    // own Bitcoin Core + the target's signed response, so a colluding minority of
    // challengers cannot fabricate a FAIL (to grief an honest node under the 95%
    // gate) or a PASS. `rpc` is the node's Bitcoin Core RPC client (see above).
    let verification_result_handler = Arc::new(
        VerificationResultHandler::with_peers(Arc::clone(&db), Arc::clone(mesh.peers()))
            .with_rederivation(Arc::new(
                ghost_pool::verification_reverify::ChainReVerifier::new(
                    Arc::clone(&rpc),
                    policy.clone(),
                ),
            ))
            .with_challenge_send(verify_conv_send),
    );
    mesh.register_handler(Arc::clone(&verification_result_handler)
        as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

    // ── Payout-ledger checkpoint finalisation (payout-finalisation P1) ──
    // The fleet BFT-finalises a {height, cutoff_ts, ledger_root} snapshot at a
    // lagging height; the coinbase becomes a pure function of it (see
    // tasks/design_payout_finalization.md). Runs DARK here — nothing consumes the
    // finalised checkpoint yet; the coinbase wiring lands behind an activation gate.
    let (plchk_tx, mut plchk_rx) =
        tokio::sync::mpsc::channel::<(ghost_consensus::MessageType, Vec<u8>)>(256);
    {
        let mesh_c = Arc::clone(&mesh);
        tokio::spawn(async move {
            while let Some((ty, bytes)) = plchk_rx.recv().await {
                match mesh_c.create_envelope_raw(ty, bytes) {
                    Ok(env) => {
                        if let Err(e) = mesh_c.broadcast(env).await {
                            tracing::debug!(error = %e, "payout-checkpoint broadcast failed");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "payout-checkpoint envelope failed"),
                }
            }
        });
    }
    let plchk_send: ghost_pool::payout_checkpoint::BroadcastFn = {
        let tx = plchk_tx.clone();
        Arc::new(move |ty, bytes| {
            tx.try_send((ty, bytes)).map_err(|e| {
                ghost_common::error::GhostError::P2PMessage(format!("payout-checkpoint channel: {e}"))
            })
        })
    };
    // compute_root: the canonical ledger root from THIS node's converged view at a
    // fixed cutoff — miner set (unpaid ledger) + qualified-node set. Deterministic
    // subsidy via calculate_block_subsidy(height, None) so every node matches.
    let compute_ledger_root_fn: ghost_pool::payout_checkpoint::ComputeRootFn = {
        let db_c = Arc::clone(&db);
        Arc::new(move |cutoff_ts, height| {
            let subsidy = ghost_common::rpc::calculate_block_subsidy(height, None);
            let miners =
                ghost_pool::payout::select_ledger_miner_work(&db_c, cutoff_ts, height, subsidy)
                    .ok()?;
            let node_ids = db_c.get_all_node_ids_with_payout().ok()?;
            let qp = ghost_verification::QualifiedCapabilityProvider::new(Arc::clone(&db_c));
            let nodes = qp.get_all_qualified_nodes_at_cutoff(&node_ids, cutoff_ts);
            Some(ghost_pool::payout::compute_ledger_root(
                &miners, &nodes, cutoff_ts, height,
            ))
        })
    };
    let payout_checkpoint_mgr =
        Arc::new(ghost_pool::payout_checkpoint::PayoutCheckpointManager::new(
            Arc::clone(&identity),
            Arc::clone(&db),
            plchk_send,
            compute_ledger_root_fn,
        ));
    mesh.register_handler(Arc::clone(&payout_checkpoint_mgr)
        as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);
    // Propose cadence: every ~30s the deterministic proposer for (tip - LAG)
    // proposes that checkpoint. LAG keeps the anchor far enough behind the tip that
    // the share/qualification ledgers have converged there (else validators reject).
    {
        let mgr = Arc::clone(&payout_checkpoint_mgr);
        let rpc_c = Arc::clone(&rpc);
        tokio::spawn(async move {
            const LAG: u64 = 6;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let tip = match rpc_c.get_block_count().await {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                if tip <= LAG {
                    continue;
                }
                let height = tip - LAG;
                let cutoff_ts = match rpc_c.get_block_hash(height).await {
                    Ok(hash) => match rpc_c.get_block_header(&hash).await {
                        Ok(hdr) => hdr.time as i64,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                };
                mgr.maybe_propose(height, cutoff_ts).await;
            }
        });
    }

    // Component A sweep: rotate through bounded windows of the verification
    // ledger, advertising the keys we hold so peers backfill what we lack. Mirrors
    // the GHOST-03 ledger sweep. One 1-hour bucket per tick keeps each request a
    // sane size; the rotation covers the trailing 7 days that qualification reads.
    {
        let vconv_handler = Arc::clone(&verification_result_handler);
        tokio::spawn(async move {
            const VCONV_INTERVAL_SECS: u64 = 60;
            const VLEDGER_BUCKET_SECS: i64 = 3_600; // 1h per advertisement
            const VLEDGER_SWEEP_SPAN_SECS: i64 = 7 * 86_400; // trailing 7 days
            const VLEDGER_BUCKETS: i64 = VLEDGER_SWEEP_SPAN_SECS / VLEDGER_BUCKET_SECS;

            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(VCONV_INTERVAL_SECS));
            let mut bucket: i64 = 0;
            loop {
                ticker.tick().await;
                let now = chrono::Utc::now().timestamp();
                let until = now - bucket * VLEDGER_BUCKET_SECS;
                let since = until - VLEDGER_BUCKET_SECS;
                bucket = (bucket + 1) % VLEDGER_BUCKETS;
                if let Err(e) = vconv_handler.request_convergence(since, until) {
                    tracing::debug!(error = %e, "challenge-convergence request failed");
                }
            }
        });
    }

    // Create and register discovery handler for peer gossip
    // This enables nodes to discover peers beyond just seed nodes
    let public_address = config
        .network
        .public_address
        .clone()
        .unwrap_or_else(|| "".to_string());
    let mesh_for_connect = Arc::clone(&mesh);
    let connect_callback: ghost_consensus::discovery_handler::ConnectCallback = Arc::new(
        move |addr| {
            let mesh_clone = Arc::clone(&mesh_for_connect);
            tokio::spawn(async move {
                if let Err(e) = mesh_clone.connect_peer(&addr).await {
                    tracing::debug!(addr = %addr, error = %e, "Failed to connect to discovered peer");
                }
            });
        },
    );
    let discovery_handler = Arc::new(
        ghost_consensus::DiscoveryHandler::new(
            identity.node_id(),
            public_address.clone(),
            Arc::clone(mesh.peers()),
        )
        .with_connect_callback(connect_callback)
        // Mainnet keeps the SSRF/hijack guard (rejects private/loopback peers);
        // test networks allow them so a local/containerised cluster can mesh.
        .with_private_peers_allowed(!is_mainnet_round),
    );
    mesh.register_handler(Arc::clone(&discovery_handler)
        as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

    // Register share proof handler for cross-node share propagation
    let share_proof_handler = Arc::new(ShareProofHandler::new(
        Arc::clone(&round_manager),
        Arc::clone(&db),
        identity.node_id(),
    ));
    mesh.register_handler(Arc::clone(&share_proof_handler)
        as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

    // GHOST-03: ledger convergence. Periodically advertise the shares we hold for
    // the current round; peers reply with the signed proofs we were missing
    // (drop/partition) and we apply them (re-verifying the GHOST-09 signature).
    // `broadcast()` is async but the handler's send is sync, so outbound
    // convergence frames go through an mpsc channel drained by a spawned task.
    let (conv_tx, mut conv_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    {
        let mesh_for_conv = Arc::clone(&mesh);
        tokio::spawn(async move {
            while let Some(bytes) = conv_rx.recv().await {
                match mesh_for_conv
                    .create_envelope_raw(ghost_consensus::MessageType::ShareConvergence, bytes)
                {
                    Ok(envelope) => {
                        if let Err(e) = mesh_for_conv.broadcast(envelope).await {
                            tracing::debug!(error = %e, "GHOST-03: convergence broadcast failed");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "GHOST-03: convergence envelope failed"),
                }
            }
        });
    }
    let conv_send: ghost_pool::convergence::ConvergenceSendFn = {
        let conv_tx = conv_tx.clone();
        Arc::new(move |bytes| {
            conv_tx.try_send(bytes).map_err(|e| {
                ghost_common::error::GhostError::P2PMessage(format!("convergence channel: {e}"))
            })
        })
    };
    let convergence_handler = Arc::new(
        ghost_pool::convergence::ConvergenceHandler::new(Arc::clone(&round_manager))
            .with_send(conv_send)
            .with_db(Arc::clone(&db)),
    );
    mesh.register_handler(Arc::clone(&convergence_handler)
        as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);
    {
        let conv_handler = Arc::clone(&convergence_handler);
        let rm_for_conv = Arc::clone(&round_manager);
        let conv_tx = conv_tx.clone();
        tokio::spawn(async move {
            const CONVERGENCE_INTERVAL_SECS: u64 = 30;

            // GHOST-03 ledger sweep. The round-scoped exchange only ever repairs the round in
            // flight, and rounds rotate every ~90s with signed proofs pruned after 10 of them —
            // so anything dropped outside a ~15-minute window was unrecoverable and the ledgers
            // diverged permanently. Since the payout is computed from the unpaid ledger and
            // GHOST-02 compares the split for EXACT equality, that divergence means every node
            // rejects every payout with nothing able to repair it.
            //
            // So we also sweep the unpaid ledger in bounded windows, one bucket per tick,
            // rotating back through `LEDGER_SWEEP_SPAN_SECS`. Bucketing keeps each advertisement
            // a sane size; the rotation covers the whole span.
            const LEDGER_BUCKET_SECS: i64 = 1_800; // 30 min per advertisement
            const LEDGER_SWEEP_SPAN_SECS: i64 = 86_400; // sweep the last 24h
            const LEDGER_BUCKETS: i64 = LEDGER_SWEEP_SPAN_SECS / LEDGER_BUCKET_SECS;

            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(CONVERGENCE_INTERVAL_SECS));
            let mut bucket: i64 = 0;

            loop {
                ticker.tick().await;

                // Repair the round in flight (fast path for a share dropped seconds ago).
                let round_id = rm_for_conv.current_round_id();
                if let Ok(bytes) = conv_handler.request_bytes(round_id) {
                    let _ = conv_tx.send(bytes).await;
                }

                // Repair one window of the unpaid ledger (the slow path that actually keeps the
                // ledgers converged). A full sweep of the span takes LEDGER_BUCKETS ticks.
                let now = chrono::Utc::now().timestamp();
                let until = now - bucket * LEDGER_BUCKET_SECS;
                let since = until - LEDGER_BUCKET_SECS;
                bucket = (bucket + 1) % LEDGER_BUCKETS;

                if let Ok(bytes) = conv_handler.ledger_request_bytes(since, until) {
                    let _ = conv_tx.send(bytes).await;
                }
            }
        });
    }

    // Register GhostGlyph handler for visual identity P2P messages
    let glyph_handler = Arc::new(ghost_pool::glyph_handler::GlyphRegistrationHandler::new(
        Arc::clone(&db),
    ));
    mesh.register_handler(
        Arc::clone(&glyph_handler) as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>
    );

    // Create broadcast relay for GhostGlyph messages (Noise-encrypted)
    let (glyph_tx, mut glyph_rx) =
        tokio::sync::mpsc::channel::<(ghost_consensus::message::MessageType, Vec<u8>)>(64);
    let mesh_for_glyph_relay = Arc::clone(&mesh);
    tokio::spawn(async move {
        while let Some((msg_type, payload)) = glyph_rx.recv().await {
            match mesh_for_glyph_relay.create_envelope_raw(msg_type, payload) {
                Ok(envelope) => {
                    if let Err(e) = mesh_for_glyph_relay.broadcast(envelope).await {
                        tracing::warn!(error = %e, "Glyph Noise broadcast failed");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Glyph envelope creation failed");
                }
            }
        }
    });
    let glyph_broadcast: ghost_consensus::vote_handler::BroadcastFn =
        Arc::new(move |msg_type, payload| {
            glyph_tx.try_send((msg_type, payload)).map_err(|e| {
                ghost_common::error::GhostError::Internal(format!(
                    "Glyph broadcast channel error: {}",
                    e
                ))
            })
        });
    glyph_handler.set_broadcast_fn(glyph_broadcast);

    // Wire glyph relay callbacks for ghost-pay → ghost-pool localhost relay
    let gh_for_claim = Arc::clone(&glyph_handler);
    let glyph_claim_relay_fn: ghost_verification::GlyphClaimRelayFn =
        Arc::new(move |data: Vec<u8>| gh_for_claim.relay_claim(data));
    let gh_for_registered = Arc::clone(&glyph_handler);
    let glyph_registered_relay_fn: ghost_verification::GlyphRegisteredRelayFn =
        Arc::new(move |data: Vec<u8>| gh_for_registered.relay_registered(data));

    // ZK consensus handlers (optional feature)
    // DEFERRED INITIALIZATION: ZK parameter generation is memory-intensive and can take minutes.
    // We spawn it in a background task so the node can start serving immediately.
    #[allow(unused_assignments, unused_mut)]
    let mut l2_submit_fn_opt: Option<ghost_verification::L2SubmitFn> = None;
    #[allow(unused_assignments, unused_mut)]
    let mut l2_sync_commitment_fn_opt: Option<ghost_verification::L2SyncCommitmentFn> = None;
    #[allow(unused_assignments, unused_mut)]
    let mut l2_tree_state_fn_opt: Option<ghost_verification::L2TreeStateFn> = None;

    // Stage C: when the ZK startup mode is genesis-anchored ROLLING (the static
    // current-params pin `ZK_PARAMS_HASH` is absent but `ZK_GENESIS_PARAMS_HASH`
    // is set), this carries the immutable genesis lineage anchor from the
    // zk-consensus gate down to the MPC block, which runs the genesis-anchored
    // lineage + retained-quorum verification (fail-closed). `None` keeps the
    // legacy static-pin / test behaviour exactly.
    #[cfg_attr(
        not(all(feature = "zk-consensus", feature = "mpc-ceremony")),
        allow(unused_mut, unused_variables, unused_assignments)
    )]
    let mut zk_rolling_anchor: Option<[u8; 32]> = None;

    #[cfg(feature = "zk-consensus")]
    {
        use ghost_consensus::epoch_manager::{EpochManager, EpochManagerConfig};
        use ghost_consensus::nullifier_route_handler::NullifierRouteHandler;
        // Check production mode early (this is fast)
        let is_production = ghost_zkp::is_production_mode();
        let is_mainnet = config.bitcoin.network == ghost_common::config::BitcoinNetwork::Mainnet;

        // MAINNET SECURITY: ZK consensus on mainnet REQUIRES trusted setup
        if is_mainnet && !is_production {
            return Err(anyhow::anyhow!(
                "MAINNET SECURITY: ZK consensus on mainnet requires trusted setup parameters. \
                 Either:\n  \
                 1. Complete MPC ceremony and build with --features zk-production\n  \
                 2. Disable ZK consensus by building without --features zk-consensus\n\n\
                 Running ZK consensus with test parameters on mainnet would allow proof forgery."
            ));
        }

        if is_production {
            // Stage C: choose the trusted-setup verification mode explicitly.
            // StaticPin (`ZK_PARAMS_HASH` set) = the legacy frozen/pinned and
            // post-ossification path, bit-identical to prior releases.
            // GenesisAnchoredRolling (`ZK_PARAMS_HASH` absent, `ZK_GENESIS_PARAMS_HASH`
            // set) = the unpinned rolling path: the static current-params file
            // check is replaced by the genesis-anchored lineage + retained-quorum
            // verification run in the MPC block below. Neither set on a production
            // node → `select_startup_mode` errors and startup aborts (never
            // unverified).
            //
            // AUTONOMOUS OSSIFICATION takes ABSOLUTE precedence: if the DB
            // ceremony singleton has ossified (reached the 101 cap) and recorded
            // the final params file hash, the node self-selects `OssifiedPinned`
            // from that DB latch REGARDLESS of env vars — no operator re-pin. This
            // is read fresh from the DB here so it drives the very first decision.
            let ossified_pin: Option<[u8; 32]> = db
                .get_mpc_ceremony_state()
                .ok()
                .flatten()
                .filter(|s| s.is_ossified)
                .and_then(|s| s.ossified_file_hash);
            match ghost_zkp::select_startup_mode_with_ossification(ossified_pin)? {
                ghost_zkp::ZkStartupMode::OssifiedPinned { file_hash } => {
                    // The trusted setup is FINAL. Behaves like StaticPin but the
                    // pin comes from the DB latch, not an env var (which may be a
                    // stale intermediate hash). Self-heal missing/corrupt params
                    // from seeds — verified against the ossified pin — then apply
                    // the hard fail-closed file-hash check. A tampered or wrong
                    // params file MUST NOT run.
                    let params_dir = std::path::PathBuf::from(
                        std::env::var(ghost_zkp::ZK_PARAMS_PATH_ENV).map_err(|_| {
                            anyhow::anyhow!(
                                "OSSIFIED PIN: {} is not set — cannot locate the frozen \
                                 trusted-setup params directory. Refusing to start (fail-closed).",
                                ghost_zkp::ZK_PARAMS_PATH_ENV
                            )
                        })?,
                    );
                    #[cfg(feature = "mpc-ceremony")]
                    {
                        let mut expected = std::collections::HashMap::new();
                        expected.insert("BLOCK".to_string(), file_hash);
                        ensure_mpc_params_present(
                            &config.network.seed_nodes,
                            &params_dir,
                            &expected,
                        )
                        .await?;
                    }
                    // FATAL if the on-disk head does not match the ossified pin.
                    ghost_zkp::verify_ossified_current_params(&params_dir, &file_hash)?;
                    // Still run the genesis-anchored lineage + retained-quorum
                    // verification below so the frozen params stay cryptographically
                    // anchored to the genesis root, not merely file-hash-trusted.
                    // Anchor = DB-derived genesis lineage hash (position-1
                    // prev_params_hash); fall back to the env anchor if present.
                    let anchor = db
                        .mpc_genesis_ceremony_id()
                        .ok()
                        .flatten()
                        .or_else(|| ghost_zkp::genesis_params_hash().ok().flatten())
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "OSSIFIED PIN: cannot derive the genesis lineage anchor (no \
                                 position-1 contribution and {} unset) — refusing to start so the \
                                 ossified params are never left unanchored (fail-closed).",
                                ghost_zkp::ZK_GENESIS_PARAMS_HASH_ENV
                            )
                        })?;
                    zk_rolling_anchor = Some(anchor);
                    info!(
                        pin = %hex::encode(&file_hash[..8]),
                        anchor = %hex::encode(&anchor[..8]),
                        "ZK consensus in OSSIFIED mode: trusted setup is FINAL — verified against \
                         the permanent DB pin, still genesis-anchored (no operator action, no env \
                         re-pin)"
                    );
                }
                ghost_zkp::ZkStartupMode::StaticPin => {
                    // SELF-HEAL: a fresh production node may have the binary but no
                    // MPC ceremony output on disk yet. Fetch + verify the params
                    // from seeds BEFORE the hard `load_trusted_params` check,
                    // otherwise the process would exit here and the background MPC
                    // task that fetches params would never run — an unrecoverable
                    // crash-loop. The fetch path verifies every blob against the
                    // pinned ZK_PARAMS_HASH, so a malicious seed cannot inject
                    // forged trusted-setup parameters.
                    #[cfg(feature = "mpc-ceremony")]
                    if let Ok(zk_params_path) = std::env::var(ghost_zkp::ZK_PARAMS_PATH_ENV) {
                        let params_dir = std::path::PathBuf::from(&zk_params_path);
                        // ALWAYS run the self-heal: it validates present params
                        // against the pinned hash and quarantines + re-fetches a
                        // present-but-corrupt set (the node6 case), in addition to
                        // fetching a missing one. Gating this on `!current.exists()`
                        // would let a corrupt-but-present file slip straight into
                        // the hard `load_trusted_params` check below and crash-loop
                        // the node.
                        ensure_mpc_params_present(
                            &config.network.seed_nodes,
                            &params_dir,
                            &expected_param_hashes(),
                        )
                        .await?;
                    }
                    ghost_zkp::load_trusted_params()?;
                    info!(
                        "ZK consensus using PRODUCTION parameters from MPC ceremony (static pin)"
                    );
                }
                ghost_zkp::ZkStartupMode::GenesisAnchoredRolling { genesis_anchor } => {
                    // Rolling: do NOT run the static file-hash check (there is no
                    // current pin to check against). The genesis-anchored lineage
                    // + retained-quorum verification runs in the MPC block below
                    // and is FATAL on failure. Hand it the immutable anchor.
                    zk_rolling_anchor = Some(genesis_anchor);
                    info!(
                        anchor = %hex::encode(&genesis_anchor[..8]),
                        "ZK consensus in ROLLING mode: trusted setup verified by genesis anchor + \
                         lineage chain + retained BFT quorum (static current-params pin absent)"
                    );
                }
            }
        } else {
            warn!("ZK consensus using TEST parameters - NOT SECURE FOR MAINNET");
        }

        // Initialize epoch manager (commitment tree, nullifier set, proposer rotation)
        let epoch_config = EpochManagerConfig::default();
        let epoch_manager = Arc::new(EpochManager::new(Arc::clone(&db), epoch_config));

        // Recover epoch state from DB or initialize genesis
        epoch_manager.initialize()?;
        if db.get_active_l2_epoch()?.is_none() {
            epoch_manager.initialize_genesis()?;
            info!("L2 epoch genesis initialized (fresh database)");
        }

        info!(
            epoch = epoch_manager.current_epoch(),
            height = epoch_manager.current_height(),
            "Epoch manager initialized"
        );

        // Create broadcast relay for L2 messages (Noise-encrypted)
        let (l2_tx, mut l2_rx) =
            tokio::sync::mpsc::channel::<(ghost_consensus::message::MessageType, Vec<u8>)>(256);
        let mesh_for_l2_relay = Arc::clone(&mesh);
        tokio::spawn(async move {
            while let Some((msg_type, payload)) = l2_rx.recv().await {
                match mesh_for_l2_relay.create_envelope_raw(msg_type, payload) {
                    Ok(envelope) => {
                        if let Err(e) = mesh_for_l2_relay.broadcast(envelope).await {
                            tracing::warn!(error = %e, "L2 Noise broadcast failed");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "L2 envelope creation failed");
                    }
                }
            }
        });
        let l2_broadcast: ghost_consensus::vote_handler::BroadcastFn =
            Arc::new(move |msg_type, payload| {
                l2_tx.try_send((msg_type, payload)).map_err(|e| {
                    ghost_common::error::GhostError::Internal(format!(
                        "L2 broadcast channel error: {}",
                        e
                    ))
                })
            });

        // Create NullifierRouteHandler for L2 transaction validation
        let nullifier_handler = Arc::new(NullifierRouteHandler::with_defaults(
            identity.node_id(),
            Arc::clone(&epoch_manager),
            Arc::clone(&db),
        ));
        nullifier_handler.set_broadcast_fn(l2_broadcast);
        nullifier_handler.set_metrics(Arc::clone(&metrics));

        // Restore pending shields that survived a restart but weren't yet
        // included in a finalized checkpoint (prevents checkpoint divergence).
        if let Err(e) = nullifier_handler.restore_pending_shields() {
            warn!(error = %e, "Failed to restore pending shields from DB");
        }

        // Restore confirmed pool (ZK-verified transactions awaiting checkpoint).
        // Without this, transactions verified before the crash would be lost,
        // causing fund-freeze until the sender resubmits.
        if let Err(e) = nullifier_handler.restore_confirmed_pool() {
            warn!(error = %e, "Failed to restore confirmed pool from DB");
        }

        // Set checkpoint base root from latest persisted checkpoint
        if let Ok(Some(cp)) = db.get_latest_l2_checkpoint() {
            nullifier_handler.set_checkpoint_base_root(cp.commitment_root);
        }
        let identity_for_sign = Arc::clone(&identity);
        nullifier_handler.set_sign_fn(std::sync::Arc::new(move |msg: &[u8]| {
            identity_for_sign.sign(msg)
        }));

        // Wire L2 submit callback for ghost-pay relay
        let nh_for_l2 = Arc::clone(&nullifier_handler);
        l2_submit_fn_opt = Some(Arc::new(move |data: Vec<u8>| {
            let msg: ghost_consensus::message::L2ConfidentialTransferMessage =
                serde_json::from_slice(&data).map_err(|e| {
                    ghost_common::error::GhostError::Serialization(format!(
                        "Invalid L2ConfidentialTransferMessage: {}",
                        e
                    ))
                })?;
            nh_for_l2.submit_external_transfer(&msg)
        }));

        // Wire L2 commitment sync callback for ghost-pay tree sync
        let nh_for_sync = Arc::clone(&nullifier_handler);
        l2_sync_commitment_fn_opt = Some(Arc::new(
            move |commitment: [u8; 32], note_index: u64, block_height: u64| {
                nh_for_sync.sync_commitment(commitment, note_index, block_height)
            },
        ));

        // Wire L2 tree state callback for health monitoring
        let em_for_tree_state = Arc::clone(&epoch_manager);
        let db_for_tree_state = Arc::clone(&db);
        l2_tree_state_fn_opt = Some(Arc::new(move || {
            let epoch = em_for_tree_state.current_epoch();
            let tree_root = em_for_tree_state.current_root()?;
            let checkpoint_height = em_for_tree_state.current_height();
            let note_count = db_for_tree_state.count_l2_notes_in_epoch(epoch)?;
            Ok(ghost_verification::L2TreeStateInfo {
                epoch,
                tree_root,
                checkpoint_height,
                note_count,
            })
        }));

        // Wire finalization callback to notify ghost-pay when checkpoints are finalized.
        // ghost-pay serves identity-derived TLS on 8800 (cert pubkey == node_id).
        // Both daemons run on the same VM under the same identity, so the loopback
        // call doesn't need cert-chain validation — `danger_accept_invalid_certs`
        // is appropriate for localhost-only IPC. (Not the same code path as the
        // L-29-blocked verification client; that one talks to remote peers.)
        //
        // Gate on `ghost_pay_enabled()` — NOT on `ghost_pay.is_some()`. Pool-only
        // nodes carry a `[ghost_pay]` block (setup emits one with `enabled = false`)
        // but never run the ghost-pay daemon; wiring the notify there produced a
        // failed POST + 3 retries + an ERROR on every checkpoint finalization
        // (~7/min of pure noise). Nodes that DO run ghost-pay set `enabled = true`,
        // so they still get notified exactly as before, and a genuine notify
        // failure there still surfaces as an error (a real, log-worthy problem).
        if config.ghost_pay_enabled() {
            let finalize_client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .danger_accept_invalid_certs(true)
                .build()
                .expect("Failed to create HTTP client for ghost-pay finalize");
            let finalize_fn: ghost_consensus::nullifier_route_handler::FinalizeFn = Arc::new(
                move |height: u64, state_root: [u8; 32], nullifiers: Vec<[u8; 32]>| {
                    let client = finalize_client.clone();
                    tokio::spawn(async move {
                        match notify_ghost_pay_finalize(
                            &client,
                            GHOST_PAY_FINALIZE_URL,
                            height,
                            state_root,
                            &nullifiers,
                        )
                        .await
                        {
                            Ok(0) => {
                                tracing::debug!(height, "Ghost-pay finalization notified");
                            }
                            Ok(attempt) => {
                                tracing::info!(
                                    height,
                                    attempt = attempt + 1,
                                    "Ghost-pay finalization notified (after retry)"
                                );
                            }
                            Err(last_err) => {
                                tracing::error!(
                                    height,
                                    error = %last_err,
                                    "Failed to notify ghost-pay of finalization after 3 attempts"
                                );
                            }
                        }
                    });
                },
            );
            nullifier_handler.set_finalize_fn(finalize_fn);
        } else {
            // Pool-only node: participate in L2 checkpoint consensus/gossip as
            // normal, just don't try to hand finalizations to a local ghost-pay
            // that isn't there. Logged once here, never per-checkpoint.
            info!("ghost-pay not enabled — L2 finalization notifications disabled");
        }

        // Initialize validators from MPC elders in DB
        let validators = db.get_mpc_elder_node_ids().unwrap_or_default();
        epoch_manager.update_active_nodes(validators.iter().copied().collect());

        // Register handler with mesh
        mesh.register_handler(Arc::clone(&nullifier_handler)
            as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

        info!("L2 nullifier route handler registered (verifier initializing in background...)");

        // C-1: Request tree sync on startup after peers connect.
        // This ensures a restarted node catches up on any checkpoints it missed
        // while offline, rather than waiting for the next reactive tree sync trigger.
        let handler_for_startup_sync = Arc::clone(&nullifier_handler);
        tokio::spawn(async move {
            // Wait for mesh connections to establish
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            info!("Requesting startup tree sync from peers...");
            if let Err(e) = handler_for_startup_sync.request_tree_sync() {
                tracing::warn!(error = %e, "Startup tree sync request failed");
            }
        });

        // Spawn checkpoint proposal loop (every 10s)
        let handler_for_proposals = Arc::clone(&nullifier_handler);
        tokio::spawn(async move {
            // Wait for initial setup (25s to allow startup tree sync to complete first)
            tokio::time::sleep(std::time::Duration::from_secs(25)).await;
            info!("L2 checkpoint proposer starting (10s interval)");

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                if !handler_for_proposals.has_verifier() {
                    tracing::debug!(
                        "GhostNoteVerifier not ready yet, skipping checkpoint proposal"
                    );
                    continue;
                }

                // Self-healing: detect stale checkpoint pipeline and trigger tree sync.
                // This covers the case where votes arrived without proposal data and
                // the node couldn't finalize — without this, the pipeline stays stuck
                // until manual restart.
                handler_for_proposals.check_and_heal_stale_pipeline();

                match handler_for_proposals.propose_checkpoint() {
                    Ok(Some(proposal)) => {
                        if let Err(e) = handler_for_proposals.propose_and_broadcast(&proposal) {
                            tracing::warn!(error = %e, "Failed to broadcast checkpoint proposal");
                        }
                    }
                    Ok(None) => {
                        // Not our turn to propose
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Checkpoint proposal failed");
                    }
                }
            }
        });

        // Spawn background task to generate ZK parameters
        let nullifier_handler_for_init = Arc::clone(&nullifier_handler);
        tokio::spawn(async move {
            use ghost_zkp::{GhostNoteProver, GhostNoteVerifier};

            info!("ZK parameter generation starting in background...");
            let start = std::time::Instant::now();

            // Generate note prover/verifier - prefer MPC-generated params when available
            #[cfg(feature = "mpc-ceremony")]
            let note_prover_result: Result<GhostNoteProver, String> = {
                let mpc_dir = std::path::PathBuf::from(
                    std::env::var("MPC_PARAMS_PATH").unwrap_or_else(|_| {
                        format!(
                            "{}/.ghost/mpc_params",
                            std::env::var("HOME").unwrap_or_default()
                        )
                    }),
                );
                let note_spend_path = mpc_dir.join("note_spend_params_current.bin");
                if note_spend_path.exists() {
                    match ghost_mpc::params::load_parameters(&note_spend_path) {
                        Ok(params) => {
                            info!("Using MPC-generated note_spend parameters");
                            Ok(GhostNoteProver::new_with_params(Arc::new(params), 20))
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to load MPC note_spend params, falling back to random setup");
                            GhostNoteProver::new_with_setup(20).map_err(|e| format!("{}", e))
                        }
                    }
                } else {
                    warn!("No MPC note_spend params on disk, using random trusted setup");
                    GhostNoteProver::new_with_setup(20).map_err(|e| format!("{}", e))
                }
            };
            #[cfg(not(feature = "mpc-ceremony"))]
            let note_prover_result: Result<GhostNoteProver, String> =
                GhostNoteProver::new_with_setup(20).map_err(|e| format!("{}", e));

            match note_prover_result {
                Ok(note_prover) => {
                    // Extract prepared VK for the verifier
                    if let Some(pvk) = note_prover.prepared_verifying_key() {
                        let verifier =
                            Arc::new(GhostNoteVerifier::new(pvk, note_prover.prover_id()));
                        nullifier_handler_for_init.set_verifier(verifier);
                        info!(
                            elapsed_secs = start.elapsed().as_secs(),
                            "L2 note verifier initialized (depth=20)"
                        );
                    } else {
                        error!("GhostNoteProver has no prepared verifying key");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to generate note prover parameters");
                }
            }

            // Load consolidation VK from MPC params directory
            {
                let mpc_dir = std::path::PathBuf::from(
                    std::env::var("MPC_PARAMS_PATH").unwrap_or_else(|_| {
                        format!(
                            "{}/.ghost/mpc_params",
                            std::env::var("HOME").unwrap_or_default()
                        )
                    }),
                );
                let consolidation_vk_path = mpc_dir.join("payout_vk.bin");
                if consolidation_vk_path.exists() {
                    match ghost_zkp::load_consolidation_verifier(&consolidation_vk_path, 20) {
                        Ok(verifier) => {
                            nullifier_handler_for_init
                                .set_consolidation_verifier(Arc::new(verifier));
                            info!("L2 consolidation verifier initialized");
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to load consolidation verifier");
                        }
                    }
                } else {
                    info!(
                        path = %consolidation_vk_path.display(),
                        "Consolidation VK not found — consolidation not available"
                    );
                }

                // Load unshield VK
                let unshield_vk_path = mpc_dir.join("unshield_vk.bin");
                if unshield_vk_path.exists() {
                    match ghost_zkp::load_unshield_verifier(&unshield_vk_path, 20) {
                        Ok(verifier) => {
                            nullifier_handler_for_init.set_unshield_verifier(Arc::new(verifier));
                            info!("L2 unshield verifier initialized");
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to load unshield verifier");
                        }
                    }
                } else {
                    info!(
                        path = %unshield_vk_path.display(),
                        "Unshield VK not found — unshield not available"
                    );
                }
            }

            info!(
                total_secs = start.elapsed().as_secs(),
                "ZK parameter generation complete"
            );
        });
    }

    // MPC ceremony integration (optional feature)
    #[cfg(feature = "mpc-ceremony")]
    {
        use ghost_consensus::MpcHandler;
        use ghost_mpc::CeremonyManager;

        // Part B — defensive startup self-heal (node7 recovery).
        //
        // A node that SYNCED contribution rows (+ proofs/votes) but never
        // persisted the `mpc_ceremony` singleton (the fresh-join gap Part A fixes
        // at the source) would otherwise fall through `load_or_init(None)` into
        // the PRE-GENESIS branch and DISCARD its synced position-1..n state,
        // regenerating genesis. Detect that inconsistency BEFORE `load_or_init`
        // and reconcile the singleton to the recorded chain-tip head, so the
        // manager loads the synced position cleanly instead.
        //
        // "Inconsistent" = contribution rows EXIST (`max_pos > 0`) AND the
        // singleton is absent, or present but BEHIND the recorded chain tip
        // (`count < max_pos`). A node with ZERO contribution rows is left
        // untouched — it is legitimately pre-genesis (this is how a brand-new
        // genesis node starts). Fail-CLOSED + honest: reconcile only from
        // contributions that actually exist; never fabricate a genesis or head.
        {
            let singleton_count = db.get_mpc_ceremony_state()?.map(|s| s.contribution_count);
            let max_pos = db.get_mpc_max_contribution_position()?.unwrap_or(0);
            let inconsistent = max_pos > 0 && singleton_count.map(|c| c < max_pos).unwrap_or(true);
            if inconsistent {
                match reconcile_singleton_to_recorded_head(&db) {
                    Ok(Some(head)) => info!(
                        head,
                        had_singleton = singleton_count.is_some(),
                        prior_count = singleton_count.unwrap_or(0),
                        "MPC startup self-heal: reconciled mpc_ceremony singleton to the recorded \
                         contribution-chain head (contributions present but singleton absent/behind) \
                         — loading the synced position instead of re-initialising pre-genesis"
                    ),
                    Ok(None) => {}
                    Err(e) => warn!(
                        error = %e,
                        "MPC startup self-heal: singleton reconcile failed — startup verification \
                         will decide (fail-closed)"
                    ),
                }
            }
        }

        // Load MPC ceremony state from database (reconciled above if it was
        // absent/behind, so a synced node now passes `Some(state)` — with
        // `count == chain tip` — into `load_or_init` and loads current.bin,
        // rather than the pre-genesis `None` path).
        let mpc_state = db.get_mpc_ceremony_state()?;

        // Stage A task 2: derive the STABLE ceremony_id.
        //
        // ceremony_id binds every Schnorr proof, so it must be identical on
        // every node and unchanging for the life of the ceremony. The canonical
        // source is position-1's `prev_params_hash` (the genesis lineage hash);
        // the persisted `mpc_ceremony.ceremony_id` column is a backfilled cache
        // of the same value. Prefer the canonical derivation, fall back to the
        // cached column, then to zero (pre-genesis — genesis init then sets it).
        //
        // This deliberately REPLACES the old behaviour of using
        // `current_params_hash`, which changed every time a contribution was
        // applied and so could never be a stable ceremony binding.
        let persisted_ceremony_id = mpc_state
            .as_ref()
            .map(|s| s.ceremony_id)
            .filter(|cid| *cid != [0u8; 32]);
        let stable_ceremony_id = db
            .mpc_genesis_ceremony_id()?
            .or(persisted_ceremony_id)
            .unwrap_or([0u8; 32]);

        // Determine params directory (from config or default)
        let mpc_params_dir =
            std::path::PathBuf::from(std::env::var("MPC_PARAMS_PATH").unwrap_or_else(|_| {
                format!(
                    "{}/.ghost/mpc_params",
                    std::env::var("HOME").unwrap_or_default()
                )
            }));

        // Initialize ceremony manager
        let ceremony_manager = match CeremonyManager::load_or_init(
            mpc_params_dir.clone(),
            mpc_state.map(|s| ghost_mpc::CeremonyState {
                contribution_count: s.contribution_count,
                current_params_hash: s.current_params_hash,
                is_ossified: s.is_ossified,
                ossified_at: s.ossified_at,
                note_spend_vk_hash: s.block_vk_hash,
                payout_vk_hash: s.payout_vk_hash,
                updated_at: s.updated_at,
                // Stable genesis-derived ceremony_id (NOT current_params_hash).
                ceremony_id: stable_ceremony_id,
                pending_commitment_count: 0,
                // Round-trip the permanent ossification pin from the DB so the
                // manager stays ossified across restarts (irreversible latch).
                ossified_file_hash: s.ossified_file_hash,
            }),
        ) {
            Ok(manager) => Arc::new(manager),
            Err(e) => {
                warn!(error = %e, "Failed to initialize MPC ceremony manager, continuing without MPC");
                // Create a minimal ceremony manager that reports as ossified
                Arc::new(CeremonyManager::new(mpc_params_dir))
            }
        };

        // Part B — current.bin consistency for the reconciled head.
        //
        // The Part-B guard above ensured the singleton == chain tip, so
        // `load_or_init` above loaded whatever `note_spend_params_current.bin`
        // holds at that count. In the node7 case current.bin IS the synced head
        // (the fetch installed it), so this is a no-op. But if current.bin is
        // MISSING or STALE (e.g. a partial sync, or a head fetched under a
        // pre-reconcile count), a synced node has no sequential apply path to
        // rebuild it (`adopt_all_applied_positions` is a no-op once
        // count == chain tip). Re-install the recorded head by its lineage hash
        // through the atomic params writer so the genesis-anchored FATAL check
        // below passes on a genuinely-consistent head — rather than the node
        // silently proving against stale params or falsely advancing.
        // Fail-CLOSED: if the head can't be installed we leave current.bin as-is
        // and let the FATAL verification decide.
        if ceremony_manager.contribution_count() > 0 {
            match ensure_recorded_head_installed(
                &ceremony_manager,
                &db,
                mesh.peers(),
                &config.network.seed_nodes,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => {}
                Err(e) => warn!(
                    error = %e,
                    "MPC startup self-heal: could not (re)install the recorded head to current.bin \
                     — genesis-anchored verification will decide (fail-closed)"
                ),
            }
        }

        // Stage A task 3: startup lineage cross-check (fail-closed).
        //
        // After loading the current parameters, recompute their LINEAGE hash
        // (`hash_parameters` — structured VK + h + l vectors, NOT the raw-file
        // pin hash) and require it to equal BOTH:
        //   * the singleton's `current_params_hash`, and
        //   * `mpc_contributions[MAX].new_params_hash`.
        // A mismatch means the on-disk params are corrupt or out of step with
        // the recorded lineage; this node must NOT enter the rolling /
        // contribution path (it would poison the lineage). The result gates the
        // auto-contribute task below. The existing frozen/pinned behaviour is
        // untouched — pinned nodes still freeze via their own guard, and the
        // raw-file `ZK_PARAMS_HASH` check (a DIFFERENT digest) still runs.
        let mpc_lineage_ok: bool = {
            let count = ceremony_manager.contribution_count();
            if count == 0 {
                // Pre-genesis / genesis-forming: nothing applied to cross-check.
                true
            } else {
                match ceremony_manager.note_spend_params() {
                    None => {
                        error!(
                            count,
                            "MPC lineage cross-check FAILED: ceremony reports contributions but no \
                             parameters are loaded — refusing to enter rolling (fail-closed)"
                        );
                        false
                    }
                    Some(params) => match ghost_mpc::contribution::hash_parameters(&params) {
                        Err(e) => {
                            error!(error = %e, "MPC lineage cross-check FAILED: could not hash loaded params — refusing rolling");
                            false
                        }
                        Ok(file_lineage) => {
                            // contributions[MAX].new_params_hash (lineage head)
                            let contribution_head = db
                                .get_mpc_contribution(count)
                                .ok()
                                .flatten()
                                .map(|c| c.new_params_hash);
                            // mpc_ceremony.current_params_hash (loaded into state)
                            let singleton_head = ceremony_manager.current_params_hash();

                            let ok = ghost_mpc::lineage_head_matches(
                                &file_lineage,
                                &singleton_head,
                                contribution_head.as_ref(),
                            );
                            if ok {
                                info!(
                                    position = count,
                                    "MPC lineage cross-check passed: on-disk params match recorded lineage head"
                                );
                            } else {
                                error!(
                                    position = count,
                                    on_disk = %hex::encode(&file_lineage[..8]),
                                    contribution_head = contribution_head
                                        .map(|h| hex::encode(&h[..8]))
                                        .unwrap_or_else(|| "<missing>".to_string()),
                                    singleton_head = %hex::encode(&singleton_head[..8]),
                                    "MPC lineage cross-check FAILED: on-disk params do not match the \
                                     recorded lineage head — refusing rolling (fail-closed)"
                                );
                            }
                            ok
                        }
                    },
                }
            }
        };

        // Stage C task 2 + 5: genesis-anchored startup verification (ROLLING mode).
        //
        // When the node is UNPINNED (no static `ZK_PARAMS_HASH`, an immutable
        // `ZK_GENESIS_PARAMS_HASH` instead — `zk_rolling_anchor` is Some), the
        // static current-params file check was deliberately skipped at the ZK
        // gate. Here we validate the evolving setup the rolling way: genesis
        // anchor → lineage chain 1..N → retained BFT quorum per position →
        // on-disk head. This is FATAL on failure (same fail-closed posture the
        // static pin had — a mismatch means lineage/quorum is broken, not merely
        // "file != static hash"). On success we true-up the singleton (task 5) so
        // a node that abstained on some position is reconciled to the verified
        // head + chain length.
        if let Some(genesis_anchor) = zk_rolling_anchor {
            // 7th contribution-flow gap — CONTRIBUTOR restart self-heal (fail-safe,
            // runs BEFORE the FATAL verification below).
            //
            // A node that GENERATED a contribution never applies it through its own
            // MpcHandler (the handler applies only contributions it RECEIVED into
            // `pending_contributions`; a node's own broadcast is never there). So
            // after the voters BFT-apply it and the row gossips back into
            // `mpc_contributions`, the contributor is an elder at the new position
            // while its own `current.bin` + singleton stay at the previous head. On
            // restart the genesis-anchored verification below sees
            // `contributions[MAX].new != on-disk head` and fails closed → crash-loop
            // (the exact node5→position-5 incident).
            //
            // Catch the on-disk head + singleton up to the recorded chain tip by
            // adopting each un-adopted position from THIS node's own local candidate
            // (network fallback if the candidate is gone). This only advances
            // positions this node contributed (or ones it can fetch + crypto-verify),
            // and is a no-op once the head already equals the chain tip (voters, and
            // an already-healed contributor). If it cannot fully heal we do NOT force
            // it — the verification below stays authoritative and fail-closed.
            let our_node_id_hex = hex::encode(identity.node_id());
            let max_pos = db
                .get_mpc_max_contribution_position()
                .ok()
                .flatten()
                .unwrap_or(0);
            if ceremony_manager.contribution_count() < max_pos {
                if adopt_all_applied_positions(
                    &ceremony_manager,
                    &db,
                    mesh.peers(),
                    &config.network.seed_nodes,
                    &our_node_id_hex,
                )
                .await
                {
                    info!(
                        head = ceremony_manager.contribution_count(),
                        "MPC restart self-heal: adopted own applied contribution(s) into on-disk head \
                         before genesis-anchored verification"
                    );
                } else {
                    warn!(
                        head = ceremony_manager.contribution_count(),
                        max_pos,
                        "MPC restart self-heal: could not fully adopt applied position(s) — \
                         genesis-anchored verification may fail-close"
                    );
                }
            }

            // Head lineage hash of the on-disk current params (None if not loaded).
            let head_lineage: Option<[u8; 32]> = ceremony_manager
                .note_spend_params()
                .and_then(|p| ghost_mpc::contribution::hash_parameters(&p).ok());

            let verified_count = db
                .verify_mpc_genesis_anchored_lineage(&genesis_anchor, head_lineage.as_ref())
                .map_err(|e| {
                    anyhow::anyhow!(
                        "MAINNET SECURITY (rolling): genesis-anchored trusted-setup verification \
                         FAILED — refusing to start (fail-closed). {e}"
                    )
                })?;

            info!(
                count = verified_count,
                anchor = %hex::encode(&genesis_anchor[..8]),
                "MPC: genesis-anchored startup verification PASSED (anchor + lineage + retained \
                 BFT quorum + on-disk head)"
            );

            // Task 5: reconcile the singleton to the verified head + length.
            if let Some(head) = head_lineage {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                match db.reconcile_mpc_singleton_to_head(
                    verified_count,
                    &head,
                    &genesis_anchor,
                    now,
                ) {
                    Ok(true) => info!(
                        count = verified_count,
                        "MPC: trued-up mpc_ceremony singleton to the verified rolling head"
                    ),
                    Ok(false) => {}
                    Err(e) => {
                        warn!(error = %e, "MPC: singleton true-up after verification failed")
                    }
                }
            }

            // AUTONOMOUS OSSIFICATION LATCH (fresh-joiner + safety net).
            //
            // The genesis-anchored verification above just PROVED the on-disk head
            // is the cryptographically-valid chain tip. If that verified chain has
            // reached the cap, permanently record the ossified params FILE hash
            // from the on-disk head. This is the step that lets a fresh node which
            // just SYNCED an already-complete 1..MAX chain self-pin: on its NEXT
            // startup `ossified_pin` is Some and it auto-selects `OssifiedPinned`
            // with zero operator action. It is also a safety net for any node that
            // reached the cap without persisting the pin through the apply path.
            //
            // Idempotent + irreversible: `latch_mpc_ossification` never re-pins an
            // already-latched singleton and the storage layer refuses to clear it.
            // Non-fatal: a transient hash failure just defers self-pinning to the
            // next restart — the genesis-anchored verification still fully guards
            // this node in the meantime.
            if verified_count >= ghost_mpc::MAX_CEREMONY_CONTRIBUTORS {
                match ceremony_manager.current_params_file_hash() {
                    Ok(file_hash) => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        match db.latch_mpc_ossification(&file_hash, now) {
                            Ok(true) => info!(
                                count = verified_count,
                                file_hash = %hex::encode(&file_hash[..8]),
                                "MPC: autonomously OSSIFIED — recorded permanent params file-hash \
                                 pin; this node self-pins on next startup (no operator action)"
                            ),
                            Ok(false) => {
                                info!("MPC: ossified pin already latched (permanent) — leaving it")
                            }
                            Err(e) => warn!(
                                error = %e,
                                "MPC: reached cap but could not latch ossified pin — will retry on \
                                 next restart (genesis-anchored verification still guards this node)"
                            ),
                        }
                    }
                    Err(e) => warn!(
                        error = %e,
                        "MPC: reached cap but could not hash on-disk head to latch ossified pin — \
                         will retry on next restart"
                    ),
                }
            }
        }

        // Create broadcast callback for MPC handler
        // Uses async Noise relay: sync closure queues messages, background task
        // routes them through mesh.broadcast() which uses Noise encryption
        let (mpc_tx, mut mpc_rx) =
            tokio::sync::mpsc::channel::<(ghost_consensus::message::MessageType, Vec<u8>)>(64);
        let mesh_for_mpc_relay = Arc::clone(&mesh);
        tokio::spawn(async move {
            while let Some((msg_type, payload)) = mpc_rx.recv().await {
                match mesh_for_mpc_relay.create_envelope_raw(msg_type, payload) {
                    Ok(envelope) => {
                        if let Err(e) = mesh_for_mpc_relay.broadcast(envelope).await {
                            tracing::warn!(error = %e, "MPC Noise broadcast failed");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "MPC envelope creation failed");
                    }
                }
            }
        });
        let mpc_broadcast: ghost_consensus::mpc_handler::MpcBroadcastFn =
            Arc::new(move |msg_type, payload| {
                mpc_tx.try_send((msg_type, payload)).map_err(|e| {
                    ghost_common::error::GhostError::Internal(format!(
                        "MPC broadcast channel error: {}",
                        e
                    ))
                })
            });

        // Create MPC handler with params update callback.
        // When the handler applies a BFT-approved contribution from another node,
        // we need to fetch the actual params binary from the contributor so our
        // local params stay current. Without this, /api/v1/mpc/params serves stale
        // genesis params and new contributors can't build valid hash chains.
        let ceremony_mgr_for_callback = Arc::clone(&ceremony_manager);
        let seed_nodes_for_callback = config.network.seed_nodes.clone();
        let db_for_callback = Arc::clone(&db);
        let peers_for_callback = Arc::clone(mesh.peers());
        type ParamsUpdateFn = dyn Fn(&[u8; 32], &[u8; 32]) + Send + Sync;
        let params_update_callback: Arc<ParamsUpdateFn> = Arc::new(
            move |expected_hash: &[u8; 32], contributor: &[u8; 32]| {
                let ceremony_mgr = Arc::clone(&ceremony_mgr_for_callback);
                let seeds = seed_nodes_for_callback.clone();
                let db = Arc::clone(&db_for_callback);
                let peers = Arc::clone(&peers_for_callback);
                let expected = *expected_hash;
                let contributor = *contributor;
                tokio::spawn(async move {
                    // Small delay to let the contributing node finish writing.
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

                    // Fast path: we already hold these params (e.g. we voted and
                    // applied through the manager directly). Nothing to adopt.
                    if ceremony_mgr.current_params_hash() == expected {
                        return;
                    }

                    // SECURITY (params_callback trust-gap upgrade): a node adopting
                    // parameters it did not itself vote on must run the SAME
                    // cryptographic gate as a voter — never adopt on a bare hash
                    // match. Recover the full contribution (proof, prev, position)
                    // from the BFT-approved row that apply_contribution persisted.
                    let record = match db.get_mpc_contribution_by_new_hash(&expected) {
                        Ok(Some(r)) => r,
                        Ok(None) => {
                            tracing::warn!(
                                expected = %hex::encode(&expected[..8]),
                                "MPC params_callback: no approved contribution row for hash — refusing to adopt"
                            );
                            return;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "MPC params_callback: contribution lookup failed");
                            return;
                        }
                    };
                    let proof: ghost_mpc::ContributionProof = match serde_json::from_slice(
                        &record.contribution_proof,
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(error = %e, "MPC params_callback: malformed stored proof — refusing to adopt");
                            return;
                        }
                    };
                    let contribution = ghost_mpc::MpcContribution {
                        position: record.elder_position,
                        prev_params_hash: record.prev_params_hash,
                        new_params_hash: record.new_params_hash,
                        proof,
                        contributor: record.contributor_node_id.clone(),
                        timestamp: record.created_at,
                        commitment_hash: None,
                    };

                    // Serialise param writes against the other writers (startup
                    // fetch, BFT apply) on the shared parameter files.
                    let _param_write_guard = param_write_lock().lock().await;

                    // Fetch the candidate bundle (note-spend hash MUST match).
                    // Same root-cause fix as the voter path: the contributor is
                    // the only node serving its un-applied candidate, so resolve
                    // its address and try it FIRST, then the seeds (a peer that has
                    // already adopted the head can serve a historical catch-up).
                    let contributor_addr = resolve_contributor_addr(&peers, &db, &contributor);
                    if contributor_addr.is_none() {
                        tracing::info!(
                            contributor = %hex::encode(&contributor[..8]),
                            "MPC params_callback: contributor address unresolved — seeds only"
                        );
                    }
                    let sources = ordered_fetch_sources(contributor_addr.as_deref(), &seeds);
                    let bundle = match fetch_ceremony_params_bundle(&sources, expected).await {
                        Some(b) => b,
                        None => {
                            tracing::warn!(
                                expected = %hex::encode(&expected[..8]),
                                "MPC params_callback: no source had matching params"
                            );
                            return;
                        }
                    };

                    // CRYPTO GATE: verify the fetched params are a valid
                    // transformation of OUR current params (the prev) before
                    // hot-swapping. Genesis (position 1) / pre-genesis nodes have
                    // no prev to verify against and adopt the hash-pinned anchor.
                    //
                    // Stage C task 4: use the catch-up (no timestamp-skew) verify.
                    // This path adopts an ALREADY-BFT-APPROVED contribution that
                    // may be HISTORICAL (a node offline for days, or replaying the
                    // chain), whose timestamp is far outside the live ±1h window.
                    // Every cryptographic check (Schnorr bound to ceremony_id, hash
                    // chain, h/l pairing transform against OUR prev) is identical to
                    // the live path; only the freshness window — a replay defence
                    // for LIVE proposals, irrelevant once a contribution is part of
                    // the approved lineage — is dropped.
                    if contribution.position >= 2 && ceremony_mgr.has_current_params() {
                        let mgr = Arc::clone(&ceremony_mgr);
                        let note_spend = Arc::clone(&bundle.note_spend);
                        let contribution_for_verify = contribution.clone();
                        let prev_params = match mgr.note_spend_params() {
                            Some(p) => p,
                            None => {
                                tracing::warn!(
                                    "MPC params_callback: no current params to verify against — refusing to adopt"
                                );
                                return;
                            }
                        };
                        let verified = tokio::task::spawn_blocking(move || {
                            mgr.verify_contribution_catchup(
                                &prev_params,
                                &note_spend,
                                &contribution_for_verify,
                            )
                        })
                        .await;
                        match verified {
                            Ok(Ok(true)) => {}
                            other => {
                                tracing::warn!(
                                    position = contribution.position,
                                    result = ?other,
                                    "MPC params_callback: candidate params FAILED verification — refusing to adopt (never adopt on hash match alone)"
                                );
                                return;
                            }
                        }
                    }

                    // Adopt through the manager: disk write + symlink + in-memory
                    // hot-swap + count/current_params_hash + ossify check.
                    let note_spend = (*bundle.note_spend).clone();
                    let payout = bundle.payout.as_ref().map(|p| (**p).clone());
                    let unshield = bundle.unshield.as_ref().map(|p| (**p).clone());
                    let mgr = Arc::clone(&ceremony_mgr);
                    let contribution_for_apply = contribution.clone();
                    let applied = tokio::task::spawn_blocking(move || {
                        mgr.apply_contribution_multi(
                            note_spend,
                            payout,
                            unshield,
                            &contribution_for_apply,
                        )
                    })
                    .await;
                    match applied {
                        Ok(Ok(())) => {
                            // Persist the singleton from the manager's authoritative state.
                            let s = ceremony_mgr.state();
                            let db_state = ghost_storage::queries::MpcCeremonyState {
                                contribution_count: s.contribution_count,
                                current_params_hash: s.current_params_hash,
                                is_ossified: s.is_ossified,
                                ossified_at: s.ossified_at,
                                block_vk_hash: s.note_spend_vk_hash,
                                payout_vk_hash: s.payout_vk_hash,
                                updated_at: s.updated_at,
                                ceremony_id: s.ceremony_id,
                                ossified_file_hash: s.ossified_file_hash,
                            };
                            if let Err(e) = db.save_mpc_ceremony_state(&db_state) {
                                tracing::warn!(error = %e, "MPC params_callback: failed to persist ceremony singleton");
                            }
                            tracing::info!(
                                position = contribution.position,
                                hash = %hex::encode(&expected[..8]),
                                "MPC params_callback: verified and adopted contribution params"
                            );
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, position = contribution.position, "MPC params_callback: manager apply failed");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "MPC params_callback: apply task panicked");
                        }
                    }
                });
            },
        );

        // Stage 1a: the network fetcher the voter uses to obtain a candidate's
        // parameters before running real cryptographic verification. Fetches the
        // bundle in memory (no disk writes — verification is read-only).
        //
        // ROOT-CAUSE FIX: the contributor's freshly-generated candidate is served
        // ONLY by the contributor node (from a separate candidate file, never
        // `current.bin`), so the seeds return their own applied params whose hash
        // never matches and the voter abstained forever. The fetcher now resolves
        // the contributor's reachable address from the mesh peer registry (the
        // same registry the mesh uses for Noise/health) — falling back to the
        // persisted `nodes` table — and tries the CONTRIBUTOR FIRST, then the
        // seeds. If the address cannot be resolved we log and fall back to seeds
        // only (a peer that already adopted the candidate could still serve it),
        // preserving the fail-closed posture (no hash-match ⇒ abstain).
        let seed_nodes_for_fetch = config.network.seed_nodes.clone();
        let peers_for_fetch = Arc::clone(mesh.peers());
        let db_for_fetch = Arc::clone(&db);
        let params_fetcher: ghost_consensus::mpc_handler::MpcParamsFetchFn = Arc::new(
            move |expected: [u8; 32], contributor: ghost_common::types::NodeId| {
                let seeds = seed_nodes_for_fetch.clone();
                let peers = Arc::clone(&peers_for_fetch);
                let db = Arc::clone(&db_for_fetch);
                Box::pin(async move {
                    // Resolve the contributor's reachable host: live mesh peer
                    // registry first (freshest), then the persisted nodes table.
                    let contributor_addr = resolve_contributor_addr(&peers, &db, &contributor);
                    if contributor_addr.is_none() {
                        tracing::info!(
                            contributor = %hex::encode(&contributor[..8]),
                            "MPC fetch: contributor address unresolved from mesh/db — \
                             falling back to seeds only"
                        );
                    }
                    let sources = ordered_fetch_sources(contributor_addr.as_deref(), &seeds);
                    fetch_ceremony_params_bundle(&sources, expected).await
                })
            },
        );

        let mpc_handler = Arc::new(
            MpcHandler::new(Arc::clone(&identity), Arc::clone(&db))
                .with_broadcaster(mpc_broadcast)
                .with_params_callback(params_update_callback)
                // Stage 1a: wire the authoritative crypto backend + fetcher so the
                // voter verifies (Schnorr + pairing) before approving.
                .with_ceremony_manager(Arc::clone(&ceremony_manager))
                .with_params_fetcher(params_fetcher)
                .with_state(
                    ceremony_manager.contribution_count(),
                    ceremony_manager.is_ossified(),
                ),
        );
        // Install the self-reference so MPC message handling can offload heavy
        // fetch/verify/apply work off the single-threaded mesh message loop.
        mpc_handler.init_self_ref();

        // Register MPC handler with mesh
        mesh.register_handler(Arc::clone(&mpc_handler)
            as Arc<dyn ghost_consensus::mesh::MessageHandler + Send + Sync>);

        // Auto-contribute to MPC ceremony on startup
        // Any node can contribute - first 101 become elders
        // Only the genesis node (--genesis flag) can create initial parameters
        let ceremony_manager_for_startup = Arc::clone(&ceremony_manager);
        let mesh_for_mpc_startup = Arc::clone(&mesh);
        let identity_for_mpc = Arc::clone(&identity);
        let db_for_mpc = Arc::clone(&db);
        let round_manager_for_mpc = Arc::clone(&round_manager);
        let initial_capabilities = capabilities; // Copy for MPC task to update after elder promotion
        let is_genesis_node = args.genesis;
        let args_genesis_password = args.genesis_password.clone();
        let genesis_password = config.pool.genesis_password.clone();
        let seed_nodes_for_mpc = config.network.seed_nodes.clone();
        // Local HTTP port for the mesh-registration readiness probe (voters fetch
        // our candidate from `:{http_port}/api/v1/mpc/params`).
        let http_port_for_mpc = config.network.http_port;

        tokio::spawn(async move {
            // Wait a bit for network to stabilize
            tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;

            let node_id_hex = hex::encode(identity_for_mpc.node_id());

            // Check if ceremony is ossified
            if ceremony_manager_for_startup.is_ossified() {
                info!("MPC ceremony is ossified (101 contributors reached)");
                return;
            }

            // Check if we've already contributed
            if db_for_mpc.is_mpc_elder(&node_id_hex).unwrap_or(false) {
                let position = db_for_mpc
                    .get_mpc_elder_position(&node_id_hex)
                    .unwrap_or(None);
                // Self-heal (idempotent): a recorded elder whose own `current.bin`
                // + singleton lag its applied position must catch up (the restart
                // scenario). The synchronous restart self-heal above already ran in
                // rolling mode; this covers non-rolling starts and any residual lag.
                // A no-op when the head already equals the applied position.
                if !adopt_all_applied_positions(
                    &ceremony_manager_for_startup,
                    &db_for_mpc,
                    mesh_for_mpc_startup.peers(),
                    &seed_nodes_for_mpc,
                    &node_id_hex,
                )
                .await
                {
                    warn!(
                        position = ?position,
                        "MPC: elder on record but could not self-heal on-disk head to its applied \
                         position — will re-attempt on next restart"
                    );
                }
                info!(position = ?position, "Already an MPC contributor (elder)");
                return;
            }

            // ROOT-CAUSE GUARD (node6 crash-loop): in production the trusted
            // setup is PINNED via `ZK_PARAMS_HASH=BLOCK:<sha256>` and therefore
            // FROZEN — its on-disk SHA-256 must stay equal to that digest or the
            // next startup's `load_trusted_params` fails and the node crash-loops.
            // If we already hold params matching the pinned BLOCK hash, the
            // ceremony is complete for us: load them into memory and DO NOT enter
            // the contribution/fetch loop below. Either branch of that loop would
            // OVERWRITE the pinned file on disk — a network re-fetch, or (worse)
            // a freshly *generated* contribution whose random params hash to a
            // different value every time (exactly the observed "3 different wrong
            // hashes, same size"). This guard fires regardless of whether local
            // ceremony state happens to be flagged ossified. On test nets (no
            // pinned BLOCK hash) it does nothing, so an open ceremony still forms.
            {
                let pinned = expected_param_hashes();
                if pinned.contains_key("BLOCK") {
                    let params_dir_for_check = ceremony_manager_for_startup.params_dir().clone();
                    if ondisk_note_spend_valid(&params_dir_for_check, pinned.get("BLOCK")) {
                        if !ceremony_manager_for_startup.has_current_params() {
                            // Adopt the valid on-disk params into memory (so the
                            // params API can serve them) without re-fetching.
                            let _ = ceremony_manager_for_startup.load_current_params();
                        }
                        info!(
                            "MPC: trusted setup is pinned and valid on disk — ceremony is frozen; \
                             not fetching or contributing (prevents clobbering the pinned params)"
                        );
                        return;
                    }
                }
            }

            // Stage A task 3: fail-closed lineage gate. If the startup
            // cross-check found the on-disk params out of step with the recorded
            // lineage head, do NOT enter the rolling/contribution path — a
            // contribution built on top of mismatched params would poison the
            // lineage. The node keeps serving whatever it loaded; it just won't
            // fetch or contribute. (Pinned/frozen nodes already returned above.)
            if !mpc_lineage_ok {
                error!(
                    "MPC: startup lineage cross-check failed — refusing to enter the rolling \
                     ceremony (fail-closed). Investigate on-disk params vs recorded lineage."
                );
                return;
            }

            // === MESH-REGISTRATION READINESS GATE ===
            // Before starting (and counting) contribution attempts, WAIT until
            // the mesh has registered this node — i.e. enough elders have
            // discovered it that they can fetch its candidate and vote on it.
            // A fresh node that broadcast its candidate before the voters knew
            // its address had every vote abstain, exhausted the fixed attempt
            // cap, and wrongly gave up ("Node will not be an elder") — needing a
            // manual restart once the mesh had caught up (the node7/node8 bug).
            //
            // Skipped for the genesis-bootstrap case: a genesis node with an
            // empty ceremony creates position 1 itself and has no other elders to
            // connect to, so gating it would pointlessly stall ceremony formation.
            {
                let bootstrap_genesis = is_genesis_node
                    && db_for_mpc
                        .mpc_contribution_count_authoritative()
                        .unwrap_or(0)
                        == 0;
                if !bootstrap_genesis {
                    let deadline = std::time::Instant::now()
                        + std::time::Duration::from_secs(MPC_READINESS_MAX_WAIT_SECS);
                    loop {
                        // Already voted in while we waited: fall through to the
                        // loop below (its is_mpc_elder branch adopts + returns).
                        if db_for_mpc.is_mpc_elder(&node_id_hex).unwrap_or(false) {
                            break;
                        }
                        let contributor_count = db_for_mpc
                            .mpc_contribution_count_authoritative()
                            .unwrap_or(0);
                        let quorum = ghost_mpc::mpc_bft_threshold(contributor_count);
                        let now = chrono::Utc::now().timestamp() as u64;
                        let connected_elders = count_connected_elders(
                            &mesh_for_mpc_startup.peers().get_all_peers(),
                            now,
                            MPC_READINESS_ELDER_FRESHNESS_SECS,
                        );
                        let endpoint_up = local_mpc_endpoint_up(http_port_for_mpc).await;
                        if mpc_contribution_ready(connected_elders, quorum, endpoint_up) {
                            info!(
                                connected_elders,
                                quorum, "MPC: mesh registration complete — beginning contribution"
                            );
                            break;
                        }
                        if std::time::Instant::now() >= deadline {
                            warn!(
                                connected_elders,
                                quorum,
                                endpoint_up,
                                "MPC: mesh-registration wait ceiling reached — proceeding to \
                                 contribute anyway (the loop re-checks readiness every round)"
                            );
                            break;
                        }
                        info!(
                            connected_elders,
                            quorum,
                            endpoint_up,
                            "MPC: waiting for mesh registration before contributing — connected to \
                             {}/{} elders",
                            connected_elders,
                            quorum
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(MPC_READINESS_POLL_SECS))
                            .await;
                    }
                }
            }

            // Retry loop: attempt contribution up to MPC_CONTRIBUTION_MAX_ATTEMPTS
            // times with a randomised 60-90s interval (~15-20 min total window).
            // This handles race conditions where multiple nodes try the same position
            // simultaneously — the loser rebases onto the new head and retries at the
            // next position.
            // Between retries: sync contributors, and ONLY when the ceremony position
            // has actually advanced, re-fetch the latest applied params (prevents stale
            // prev_params_hash) and regenerate. When the position is UNCHANGED we keep
            // the cached candidate and rebroadcast the SAME signed message so voters
            // accumulate votes for one hash toward quorum (no "moving target").
            let mut cached_msg: Option<(ghost_consensus::message::MpcContributionMessage, u32)> =
                None;
            // INDEFINITE retry: a node that wants to be an elder never permanently
            // gives up. The first MPC_CONTRIBUTION_MAX_ATTEMPTS rounds use the tuned
            // 60-90s converge window; beyond that the inter-round delay backs off
            // (up to MPC_CONTRIBUTION_BACKOFF_MAX_SECS) so a still-unregistered node
            // keeps retrying without hammering the mesh. The ONLY exits are: voted
            // in (is_mpc_elder success → return) or the ceremony ossifies (clean
            // break). Each round re-checks mesh readiness so a node that lost its
            // elder connectivity waits rather than broadcasting into the void.
            let mut attempt: u32 = 0;
            loop {
                attempt += 1;

                // Clean exit if the ceremony ossified (101 contributors reached)
                // while we were retrying — nothing more to contribute.
                if ceremony_manager_for_startup.is_ossified() {
                    info!(
                        attempt,
                        "MPC: ceremony ossified while retrying — stopping contribution attempts"
                    );
                    break;
                }

                // Re-check if we became an elder (e.g., via P2P sync of our own contribution)
                if db_for_mpc.is_mpc_elder(&node_id_hex).unwrap_or(false) {
                    let position = db_for_mpc
                        .get_mpc_elder_position(&node_id_hex)
                        .unwrap_or(None);
                    // ADOPT our own BFT-applied contribution BEFORE declaring elder
                    // success. The handler never self-applied it (a node's own
                    // broadcast is not in its `pending_contributions`), so our
                    // `current.bin` + `mpc_ceremony` singleton still lag the applied
                    // position that gossiped back into `mpc_contributions`. Catch the
                    // head up (own local candidate first, network fallback) so it
                    // matches the chain tip — otherwise the next restart fails closed
                    // (on-disk head < chain tip) and crash-loops.
                    if adopt_all_applied_positions(
                        &ceremony_manager_for_startup,
                        &db_for_mpc,
                        mesh_for_mpc_startup.peers(),
                        &seed_nodes_for_mpc,
                        &node_id_hex,
                    )
                    .await
                    {
                        info!(position = ?position, "Now an MPC contributor (elder)");
                        // Update live capabilities so health pings reflect elder status
                        mesh_for_mpc_startup.update_elder_status(true);
                        let mut updated_caps = initial_capabilities;
                        updated_caps.elder_status = true;
                        round_manager_for_mpc
                            .update_node_capabilities(identity_for_mpc.node_id(), updated_caps);
                        return;
                    }
                    // Could not adopt yet (e.g. candidate gone AND seeds unreachable).
                    // Do NOT declare elder success on a lagging head; wait and re-check
                    // (the next iteration retries the adopt; a restart also self-heals).
                    warn!(
                        position = ?position,
                        "MPC: became an elder but could not adopt applied params yet — retrying \
                         (not declaring success on a lagging head)"
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                    continue;
                }

                // Re-check mesh registration each round (skipped for the
                // genesis-bootstrap case, which has no other elders). If we are no
                // longer connected to a BFT quorum of elders — or our own
                // candidate-serving endpoint went away — broadcasting a candidate
                // now would just abstain-vote into the void. Wait (with the same
                // escalating backoff as a failed attempt) and re-check instead of
                // burning a round. This is what stops a node from ever wrongly
                // concluding it "will not be an elder" while the mesh catches up.
                {
                    let bootstrap_genesis = is_genesis_node
                        && db_for_mpc
                            .mpc_contribution_count_authoritative()
                            .unwrap_or(0)
                            == 0;
                    if !bootstrap_genesis {
                        let contributor_count = db_for_mpc
                            .mpc_contribution_count_authoritative()
                            .unwrap_or(0);
                        let quorum = ghost_mpc::mpc_bft_threshold(contributor_count);
                        let now = chrono::Utc::now().timestamp() as u64;
                        let connected_elders = count_connected_elders(
                            &mesh_for_mpc_startup.peers().get_all_peers(),
                            now,
                            MPC_READINESS_ELDER_FRESHNESS_SECS,
                        );
                        let endpoint_up = local_mpc_endpoint_up(http_port_for_mpc).await;
                        if !mpc_contribution_ready(connected_elders, quorum, endpoint_up) {
                            let delay_secs = mpc_retry_backoff_secs(attempt);
                            warn!(
                                attempt,
                                connected_elders,
                                quorum,
                                endpoint_up,
                                delay_secs,
                                "MPC: not adequately meshed to contribute (connected to {}/{} \
                                 elders) — waiting before re-checking (no permanent giveup)",
                                connected_elders,
                                quorum
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
                            continue;
                        }
                    }
                }

                // Ensure we have parameters loaded.
                //
                // NOTE: a node holding VALID pinned trusted-setup params already
                // returned above (the frozen-ceremony guard), so reaching here in
                // production means params are genuinely missing/invalid on disk
                // and the fetch below heals them (and verifies against the pinned
                // hash). On test nets (no pinned hash) this is the normal forming
                // path. Either way the fetch can no longer clobber pinned params.
                if !ceremony_manager_for_startup.has_current_params() {
                    // Use DB to determine if this is truly genesis or if we need to fetch.
                    // Authoritative progression count = mpc_ceremony singleton (falls back to
                    // COUNT(mpc_contributions) when the singleton is absent, e.g. fresh genesis).
                    let db_count = db_for_mpc
                        .mpc_contribution_count_authoritative()
                        .unwrap_or(0);

                    if db_count == 0 && is_genesis_node {
                        // Genesis protection layer 1: Query seed peers for existing contributors
                        // If any peer already has MPC contributors, abort genesis to prevent dual-genesis
                        let mut network_has_contributors = false;
                        for seed in &seed_nodes_for_mpc {
                            let host = seed.split(':').next().unwrap_or(seed);
                            let url = format!("http://{}:8080/api/v1/mpc/contributors", host);
                            if let Ok(resp) = reqwest::Client::new()
                                .get(&url)
                                .timeout(std::time::Duration::from_secs(10))
                                .send()
                                .await
                            {
                                if let Ok(body) = resp.text().await {
                                    // If response is a non-empty JSON array, contributors exist
                                    let trimmed = body.trim();
                                    if trimmed.starts_with('[') && trimmed != "[]" {
                                        error!(
                                            seed = %seed,
                                            "Cannot init genesis: network already has MPC contributors (via {})",
                                            host
                                        );
                                        network_has_contributors = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if network_has_contributors {
                            warn!("MPC: Aborting genesis — existing contributors detected on network. Remove --genesis flag.");
                            return;
                        }

                        // Genesis protection layer 2: Password check
                        if let Some(ref required_pw) = genesis_password {
                            if args_genesis_password.as_deref() != Some(required_pw.as_str()) {
                                error!("MPC: genesis_password is configured but --genesis-password was not provided or does not match");
                                return;
                            }
                        }

                        // Truly the first node — no contributors exist anywhere, create genesis
                        info!("MPC: Genesis node with empty DB - creating initial parameters");
                        if let Err(e) = ceremony_manager_for_startup.ensure_genesis_initialized() {
                            warn!(error = %e, "Failed to initialize MPC genesis parameters");
                            return;
                        }
                    } else {
                        // Either DB already has contributors (synced from peers) or not genesis node
                        // In both cases, fetch params from network
                        if db_count > 0 {
                            info!(db_count, "MPC: DB has contributors but no local params, fetching from network...");
                        } else {
                            info!("MPC: No genesis parameters found, fetching from network...");
                        }

                        // Try to fetch params from seed nodes
                        let params_dir = ceremony_manager_for_startup.params_dir().clone();
                        let expected_hashes = expected_param_hashes();
                        let mut fetched = false;

                        for fetch_attempt in 1..=20 {
                            // Try each seed node (shared fetch + hash verification)
                            for seed in &seed_nodes_for_mpc {
                                let host = seed.split(':').next().unwrap_or(seed);
                                if try_fetch_params_from_seed(host, &params_dir, &expected_hashes)
                                    .await
                                {
                                    fetched = true;
                                    break;
                                }
                            }

                            if fetched {
                                // Also fetch MPC status to sync contribution count
                                for seed in &seed_nodes_for_mpc {
                                    let host = seed.split(':').next().unwrap_or(seed);
                                    let status_url =
                                        format!("http://{}:8080/api/v1/mpc/status", host);

                                    if let Ok(response) = reqwest::Client::new()
                                        .get(&status_url)
                                        .timeout(std::time::Duration::from_secs(10))
                                        .send()
                                        .await
                                    {
                                        if let Ok(status) =
                                            response.json::<serde_json::Value>().await
                                        {
                                            if let Some(count) = status
                                                .get("contribution_count")
                                                .and_then(|c| c.as_u64())
                                            {
                                                info!(
                                                    contribution_count = count,
                                                    "MPC: Synced contribution count from peer"
                                                );
                                                ceremony_manager_for_startup
                                                    .sync_contribution_count(count as u32);
                                            }
                                            break;
                                        }
                                    }
                                }

                                // Fetch and sync MPC contributors list (needed for vote validation)
                                for seed in &seed_nodes_for_mpc {
                                    let host = seed.split(':').next().unwrap_or(seed);
                                    let contributors_url =
                                        format!("http://{}:8080/api/v1/mpc/contributors", host);

                                    if let Ok(response) = reqwest::Client::new()
                                        .get(&contributors_url)
                                        .timeout(std::time::Duration::from_secs(10))
                                        .send()
                                        .await
                                    {
                                        if let Ok(data) = response.json::<serde_json::Value>().await
                                        {
                                            if let Some(contributors) =
                                                data.get("contributors").and_then(|c| c.as_array())
                                            {
                                                let mut synced_count = 0;
                                                for contrib in contributors {
                                                    let position = contrib
                                                        .get("position")
                                                        .and_then(|p| p.as_u64())
                                                        .unwrap_or(0)
                                                        as u32;
                                                    let node_id = contrib
                                                        .get("node_id")
                                                        .and_then(|n| n.as_str())
                                                        .unwrap_or("");
                                                    let prev_hash_hex = contrib
                                                        .get("prev_params_hash")
                                                        .and_then(|h| h.as_str())
                                                        .unwrap_or("");
                                                    let new_hash_hex = contrib
                                                        .get("new_params_hash")
                                                        .and_then(|h| h.as_str())
                                                        .unwrap_or("");
                                                    let epoch = contrib
                                                        .get("epoch")
                                                        .and_then(|e| e.as_u64())
                                                        .unwrap_or(0);
                                                    let created_at = contrib
                                                        .get("created_at")
                                                        .and_then(|c| c.as_u64())
                                                        .unwrap_or(0);

                                                    if position == 0 || node_id.is_empty() {
                                                        continue;
                                                    }

                                                    let prev_hash: [u8; 32] =
                                                        hex::decode(prev_hash_hex)
                                                            .ok()
                                                            .and_then(|b| b.try_into().ok())
                                                            .unwrap_or([0u8; 32]);
                                                    let new_hash: [u8; 32] =
                                                        hex::decode(new_hash_hex)
                                                            .ok()
                                                            .and_then(|b| b.try_into().ok())
                                                            .unwrap_or([0u8; 32]);

                                                    let record = ghost_storage::queries::MpcContributionRecord {
                                                        elder_position: position,
                                                        contributor_node_id: node_id.to_string(),
                                                        prev_params_hash: prev_hash,
                                                        new_params_hash: new_hash,
                                                        contribution_proof: Vec::new(),
                                                        epoch,
                                                        created_at,
                                                    };

                                                    if db_for_mpc
                                                        .save_mpc_contribution(&record)
                                                        .is_ok()
                                                    {
                                                        synced_count += 1;
                                                    }

                                                    // Stage C task 3: upgrade the
                                                    // proof-less placeholder with the
                                                    // REAL proof + retained votes so
                                                    // catch-up can re-verify + check
                                                    // the retained BFT quorum.
                                                    sync_mpc_proof_and_votes(
                                                        &seed_nodes_for_mpc,
                                                        position,
                                                        &db_for_mpc,
                                                    )
                                                    .await;
                                                }
                                                if synced_count > 0 {
                                                    info!(
                                                        count = synced_count,
                                                        "MPC: Synced contributor records (+ proofs/votes) from peer"
                                                    );
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }

                                // Load fetched params into ceremony manager
                                if let Err(e) = ceremony_manager_for_startup.load_current_params() {
                                    warn!(error = %e, "MPC: Failed to load fetched params");
                                    fetched = false;
                                } else {
                                    info!("MPC: Loaded fetched params into ceremony manager");
                                }
                                break;
                            }

                            if fetch_attempt % 4 == 0 {
                                info!(
                                    fetch_attempt,
                                    "MPC: Still trying to fetch params (attempt {}/20)...",
                                    fetch_attempt
                                );
                            }

                            tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
                        }

                        if !fetched || !ceremony_manager_for_startup.has_current_params() {
                            warn!("MPC: Failed to fetch genesis parameters from network. Use --genesis on the first node.");
                            return;
                        }

                        // Part A — persist a CONSISTENT synced head.
                        //
                        // The sync above populated `mpc_contributions` (+ proofs/
                        // votes) and fetched the head params into current.bin, but
                        // it never wrote the `mpc_ceremony` singleton. Left there,
                        // the next restart reads NO singleton, re-initialises
                        // PRE-GENESIS, and DISCARDS the synced position-1..n state
                        // (the node7 onboarding bug). Leave the node fully
                        // consistent at the synced head:
                        //   1. guarantee current.bin IS the recorded chain-tip head
                        //      (re-fetch by lineage hash + atomic install if the
                        //      generic fetch left it stale), then
                        //   2. persist the singleton (count == chain tip ==
                        //      on-disk head lineage hash).
                        // Fail-SAFE: if the head can't be made consistent we do NOT
                        // persist a singleton we cannot back with on-disk params —
                        // the next attempt / restart re-syncs.
                        match ensure_recorded_head_installed(
                            &ceremony_manager_for_startup,
                            &db_for_mpc,
                            mesh_for_mpc_startup.peers(),
                            &seed_nodes_for_mpc,
                        )
                        .await
                        {
                            Ok(true) => match reconcile_singleton_to_recorded_head(&db_for_mpc) {
                                Ok(Some(head)) => info!(
                                    head,
                                    "MPC: persisted synced ceremony head (current.bin + mpc_ceremony \
                                     singleton) — the node will load this position cleanly on restart"
                                ),
                                Ok(None) => {}
                                Err(e) => warn!(
                                    error = %e,
                                    "MPC: failed to persist synced ceremony singleton"
                                ),
                            },
                            Ok(false) => {}
                            Err(e) => warn!(
                                error = %e,
                                "MPC: could not install the synced head params to current.bin; \
                                 singleton NOT persisted — a restart will re-sync (fail-safe)"
                            ),
                        }
                    }
                }

                // DEFENCE IN DEPTH: never generate/apply a contribution once the
                // trusted setup is PINNED. A contribution transforms the params,
                // changing their hash — which would break the pinned
                // `ZK_PARAMS_HASH` check on every node. In production the only
                // legitimate actions are "load existing pinned params" or "fetch
                // the pinned params if missing" (both done above); contributing
                // is a test-net / ceremony-formation activity only. This also
                // closes the residual window where a production node that healed
                // missing params in the fetch step above would otherwise proceed
                // to overwrite them with a freshly generated contribution.
                if expected_param_hashes().contains_key("BLOCK") {
                    info!(
                        "MPC: trusted setup is pinned (ZK_PARAMS_HASH) — skipping contribution generation; params are frozen"
                    );
                    return;
                }

                // ── Attempt-start catch-up (behind-the-head rolling gap) ─────────
                // A node that joined / un-pinned while the ceremony had ALREADY
                // advanced receives the applied-contribution ROWS via gossip (its
                // `mpc_contributions` MAX climbs) but NOTHING drives its on-disk
                // head + `mpc_ceremony` singleton forward — so its authoritative
                // count lags the recorded chain tip. Left unhandled it computes
                // `next_position = count + 1` and keeps contributing an
                // ALREADY-FILLED position forever (the node6→stuck-at-5 incident)
                // instead of catching up and contributing the next FREE one.
                //
                // "Behind" = authoritative singleton count < recorded MAX position.
                // Catch the head up by adopting every un-adopted applied position in
                // order via the shared adopt driver: params are fetched
                // contributor-aware + hash-checked, FOREIGN lineages are additionally
                // crypto-verified (`verify_contribution_catchup`), and each
                // position's retained BFT quorum votes are synced so a later
                // restart's genesis-anchored check still passes. `next_position`
                // below is then recomputed from the advanced count.
                //
                // Idempotent + free when NOT behind: the inner while-loop is a no-op
                // (count == max_pos) and no fetch happens — the normal same-position
                // rolling path is untouched. Fail-safe: if catch-up can't complete
                // (peer unreachable / a position won't verify) we do NOT contribute a
                // stale position — wait and let the next attempt / a restart retry.
                {
                    let authoritative = db_for_mpc
                        .mpc_contribution_count_authoritative()
                        .unwrap_or(0);
                    let chain_tip = db_for_mpc
                        .get_mpc_max_contribution_position()
                        .ok()
                        .flatten()
                        .unwrap_or(0);
                    if authoritative < chain_tip {
                        info!(
                            authoritative,
                            chain_tip,
                            "MPC: adopted head lags the recorded chain tip — catching up before \
                             computing the next contribution position"
                        );
                        if adopt_all_applied_positions(
                            &ceremony_manager_for_startup,
                            &db_for_mpc,
                            mesh_for_mpc_startup.peers(),
                            &seed_nodes_for_mpc,
                            &node_id_hex,
                        )
                        .await
                        {
                            info!(
                                head = ceremony_manager_for_startup.contribution_count(),
                                "MPC: caught up to the recorded chain tip"
                            );
                        } else {
                            warn!(
                                head = ceremony_manager_for_startup.contribution_count(),
                                chain_tip,
                                "MPC: could not fully catch up to the chain tip this attempt — \
                                 NOT contributing a stale position; will retry"
                            );
                            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                            continue;
                        }
                    }
                }

                // Determine position from DB (authoritative source, not stale in-memory state).
                // Progression count comes from the mpc_ceremony singleton (falls back to
                // COUNT(mpc_contributions) when absent). Voter-set sizing still uses
                // get_mpc_elder_count() in the handler — these are deliberately distinct.
                // After the catch-up above, `db_count == chain_tip`, so targeting one
                // past the tip (via `mpc_next_contribution_position`) is the next FREE
                // position — never an already-filled one.
                let db_count = db_for_mpc
                    .mpc_contribution_count_authoritative()
                    .unwrap_or(0);
                let chain_tip = db_for_mpc
                    .get_mpc_max_contribution_position()
                    .ok()
                    .flatten()
                    .unwrap_or(0);
                let next_position = mpc_next_contribution_position(db_count, chain_tip);

                info!(
                    attempt,
                    db_count, next_position, "MPC: Attempting to contribute to ceremony"
                );

                // Cache the signed message so retries broadcast the same hash.
                // Regenerate only on first attempt or when db_count changes (position shifted).
                let need_generate = match &cached_msg {
                    Some((_, cached_db_count)) => *cached_db_count != db_count,
                    None => true,
                };

                if need_generate {
                    match ceremony_manager_for_startup
                        .generate_contribution_at_position(&node_id_hex, next_position)
                    {
                        Ok((new_params, contribution)) => {
                            let position = contribution.position;
                            info!(
                                position = position,
                                "MPC contribution generated for position {}", position,
                            );

                            // Genesis case: ONLY the genesis node auto-applies position 1.
                            // Non-genesis nodes must wait for BFT approval from existing elders.
                            // Without this guard, all nodes race to auto-apply their own position 1.
                            if db_count == 0 && is_genesis_node {
                                info!("MPC genesis: Auto-applying first contribution (no existing contributors to vote)");
                                if let Err(e) = ceremony_manager_for_startup
                                    .apply_contribution(new_params, &contribution)
                                {
                                    warn!(error = %e, "Failed to apply genesis contribution");
                                } else {
                                    let proof_bytes =
                                        serde_json::to_vec(&contribution.proof).unwrap_or_default();
                                    let record = ghost_storage::queries::MpcContributionRecord {
                                        elder_position: position,
                                        contributor_node_id: node_id_hex.clone(),
                                        prev_params_hash: contribution.prev_params_hash,
                                        new_params_hash: contribution.new_params_hash,
                                        contribution_proof: proof_bytes,
                                        epoch: 0,
                                        created_at: contribution.timestamp,
                                    };
                                    if let Err(e) = db_for_mpc.save_mpc_contribution(&record) {
                                        warn!(error = %e, "Failed to save genesis contribution to database");
                                    } else {
                                        info!("MPC genesis contribution applied - we are now Elder #1");
                                        // Update live capabilities so health pings reflect elder status
                                        mesh_for_mpc_startup.update_elder_status(true);
                                        let mut updated_caps = initial_capabilities;
                                        updated_caps.elder_status = true;
                                        round_manager_for_mpc.update_node_capabilities(
                                            identity_for_mpc.node_id(),
                                            updated_caps,
                                        );
                                    }
                                }
                            } else {
                                // Non-genesis: save the generated CANDIDATE to a
                                // SEPARATE serving file keyed by its lineage hash —
                                // NEVER the active note_spend_params_current.bin.
                                //
                                // We can't use apply_contribution here because it
                                // modifies internal state (contribution_count) which
                                // breaks retries if BFT rejects. And we must NOT
                                // overwrite current.bin (the last BFT-APPLIED head):
                                // doing so left node5 serving an un-applied candidate
                                // as its "current" params and crash-looped it on
                                // restart (on-disk candidate != chain head). Voters
                                // fetch this candidate by hash via
                                // GET /api/v1/mpc/params?new_hash=<hash>; our own
                                // current.bin only advances when (and if) the apply
                                // path runs after BFT approval.
                                let params_dir = ceremony_manager_for_startup.params_dir().clone();
                                let mut buf = Vec::new();
                                if new_params.write(&mut buf).is_ok() {
                                    match write_candidate_note_spend_params(
                                        &params_dir,
                                        &contribution.new_params_hash,
                                        &buf,
                                    ) {
                                        Ok(candidate_path) => {
                                            info!(
                                                position = position,
                                                size = buf.len(),
                                                new_hash = %hex::encode(&contribution.new_params_hash[..8]),
                                                path = %candidate_path.display(),
                                                "MPC: Saved generated CANDIDATE params for serving (active current.bin unchanged)"
                                            );
                                        }
                                        Err(e) => {
                                            warn!(error = %e, "MPC: Failed to save candidate params to disk");
                                        }
                                    }
                                }
                            }

                            // Build and sign the broadcast message
                            let proof_bytes =
                                serde_json::to_vec(&contribution.proof).unwrap_or_default();

                            let candidate: [u8; 32] = hex::decode(&contribution.contributor)
                                .ok()
                                .and_then(|b| b.try_into().ok())
                                .unwrap_or_else(|| identity_for_mpc.node_id());

                            let mut msg = ghost_consensus::message::MpcContributionMessage {
                                candidate,
                                elder_position: contribution.position,
                                prev_params_hash: contribution.prev_params_hash,
                                new_params_hash: contribution.new_params_hash,
                                contribution_proof: proof_bytes,
                                signature: [0u8; 64],
                                timestamp: contribution.timestamp,
                            };

                            let signing_message = msg.signing_message();
                            msg.signature = identity_for_mpc.sign(&signing_message);

                            cached_msg = Some((msg, db_count));

                            // If this was genesis (auto-applied), broadcast and we're done.
                            // Only genesis node returns early — non-genesis nodes must
                            // continue the retry loop to get BFT approval.
                            if db_count == 0 && is_genesis_node {
                                if let Some((ref cached, _)) = cached_msg {
                                    match mesh_for_mpc_startup
                                        .broadcast_message(
                                            ghost_consensus::message::MessageType::MpcContribution,
                                            cached,
                                        )
                                        .await
                                    {
                                        Ok(sent) => info!(
                                            sent = sent,
                                            "MPC genesis contribution broadcast via Noise"
                                        ),
                                        Err(e) => {
                                            warn!(error = %e, "Failed to broadcast MPC genesis contribution")
                                        }
                                    }
                                }
                                return;
                            }
                        }
                        Err(e) => {
                            info!(error = %e, attempt, "Could not generate MPC contribution, will retry");
                        }
                    }
                } else {
                    info!(
                        attempt,
                        db_count, "MPC: Rebroadcasting cached contribution (same position)"
                    );
                }

                // Broadcast (or rebroadcast) the cached message
                if let Some((ref cached, _)) = cached_msg {
                    match mesh_for_mpc_startup
                        .broadcast_message(
                            ghost_consensus::message::MessageType::MpcContribution,
                            cached,
                        )
                        .await
                    {
                        Ok(sent) => {
                            info!(sent = sent, attempt, "MPC contribution broadcast via Noise");
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to broadcast MPC contribution");
                        }
                    }
                }

                // Wait before the next round, then sync contributors + conditionally
                // refetch. ALWAYS runs now (the loop is indefinite): during the fast
                // converge window the delay is a randomised 60-90s — long enough for
                // voters to fetch + Groth16-verify + vote + reach quorum + apply +
                // propagate back, and randomised to prevent races where multiple
                // nodes fight for the same position simultaneously; beyond the fast
                // window it escalates to a capped backoff so a not-yet-voted-in node
                // keeps retrying without hammering the mesh.
                {
                    let delay_secs = if attempt < MPC_CONTRIBUTION_MAX_ATTEMPTS {
                        use rand::Rng;
                        rand::thread_rng().gen_range(
                            MPC_CONTRIBUTION_RETRY_DELAY_MIN_SECS
                                ..=MPC_CONTRIBUTION_RETRY_DELAY_MAX_SECS,
                        )
                    } else {
                        mpc_retry_backoff_secs(attempt)
                    };
                    info!(
                        attempt,
                        delay_secs, "MPC: Waiting before retry (randomized to prevent races)"
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;

                    // Sync contributors from peers to detect if our contribution was approved
                    for seed in &seed_nodes_for_mpc {
                        let host = seed.split(':').next().unwrap_or(seed);
                        let contributors_url =
                            format!("http://{}:8080/api/v1/mpc/contributors", host);

                        if let Ok(response) = reqwest::Client::new()
                            .get(&contributors_url)
                            .timeout(std::time::Duration::from_secs(10))
                            .send()
                            .await
                        {
                            if let Ok(data) = response.json::<serde_json::Value>().await {
                                if let Some(contributors) =
                                    data.get("contributors").and_then(|c| c.as_array())
                                {
                                    for contrib in contributors {
                                        let position = contrib
                                            .get("position")
                                            .and_then(|p| p.as_u64())
                                            .unwrap_or(0)
                                            as u32;
                                        let node_id = contrib
                                            .get("node_id")
                                            .and_then(|n| n.as_str())
                                            .unwrap_or("");
                                        let prev_hash_hex = contrib
                                            .get("prev_params_hash")
                                            .and_then(|h| h.as_str())
                                            .unwrap_or("");
                                        let new_hash_hex = contrib
                                            .get("new_params_hash")
                                            .and_then(|h| h.as_str())
                                            .unwrap_or("");
                                        let epoch = contrib
                                            .get("epoch")
                                            .and_then(|e| e.as_u64())
                                            .unwrap_or(0);
                                        let created_at = contrib
                                            .get("created_at")
                                            .and_then(|c| c.as_u64())
                                            .unwrap_or(0);

                                        if position == 0 || node_id.is_empty() {
                                            continue;
                                        }

                                        let prev_hash: [u8; 32] = hex::decode(prev_hash_hex)
                                            .ok()
                                            .and_then(|b| b.try_into().ok())
                                            .unwrap_or([0u8; 32]);
                                        let new_hash: [u8; 32] = hex::decode(new_hash_hex)
                                            .ok()
                                            .and_then(|b| b.try_into().ok())
                                            .unwrap_or([0u8; 32]);

                                        let record =
                                            ghost_storage::queries::MpcContributionRecord {
                                                elder_position: position,
                                                contributor_node_id: node_id.to_string(),
                                                prev_params_hash: prev_hash,
                                                new_params_hash: new_hash,
                                                contribution_proof: Vec::new(),
                                                epoch,
                                                created_at,
                                            };

                                        let _ = db_for_mpc.save_mpc_contribution(&record);

                                        // Stage C task 3: fill the real proof +
                                        // retained votes for catch-up re-verification
                                        // and the retained BFT quorum check.
                                        sync_mpc_proof_and_votes(
                                            &seed_nodes_for_mpc,
                                            position,
                                            &db_for_mpc,
                                        )
                                        .await;
                                    }
                                    break;
                                }
                            }
                        }
                    }

                    // Decide whether to re-fetch + regenerate, or keep our stable
                    // candidate. Read the authoritative count AFTER the contributor
                    // sync above: if a new contribution was applied while we waited,
                    // our candidate is chained onto a stale head and must be rebased
                    // (re-fetch the new applied head + regenerate). If the position is
                    // UNCHANGED, re-fetching would invalidate the cache and force the
                    // next attempt to regenerate a DIFFERENT candidate with fresh
                    // randomness (the "moving target" that stopped voters converging) —
                    // so we skip it and rebroadcast the SAME cached candidate next
                    // attempt, letting votes accumulate for one hash toward quorum.
                    let current_count = db_for_mpc
                        .mpc_contribution_count_authoritative()
                        .unwrap_or(db_count);
                    let position_advanced = match &cached_msg {
                        Some((_, cached_count)) => {
                            !cached_contribution_still_valid(*cached_count, current_count)
                        }
                        // No cached candidate (generation failed this attempt): re-fetch
                        // so the next attempt regenerates on the freshest head.
                        None => true,
                    };
                    if !position_advanced {
                        info!(
                            attempt,
                            db_count = current_count,
                            "MPC: ceremony position unchanged — keeping cached candidate, \
                             will rebroadcast the same hash next attempt"
                        );
                        continue;
                    }

                    // Position ADVANCED (or no cache): re-fetch the latest applied MPC
                    // params before the next attempt so we rebase onto the new head.
                    // Without this, the ceremony manager holds stale params and the
                    // regenerated contribution would fail hash-chain validation because
                    // prev_params_hash won't match the latest applied contribution. Note
                    // this writes the genuinely-newer APPLIED head to current.bin, which
                    // is correct — the candidate-serving rule only forbids writing our
                    // own UN-applied candidate to current.bin.
                    let params_dir = ceremony_manager_for_startup.params_dir().clone();
                    for seed in &seed_nodes_for_mpc {
                        let host = seed.split(':').next().unwrap_or(seed);
                        let url = format!("http://{}:8080/api/v1/mpc/params", host);

                        match reqwest::Client::new()
                            .get(&url)
                            .timeout(std::time::Duration::from_secs(60))
                            .send()
                            .await
                        {
                            Ok(response) if response.status().is_success() => {
                                match response.bytes().await {
                                    Ok(data) if data.len() > 1000 => {
                                        // Ensure params directory exists (may have been wiped)
                                        let _ = std::fs::create_dir_all(&params_dir);
                                        let params_path =
                                            params_dir.join("note_spend_params_current.bin");
                                        // Resolve symlink target or overwrite directly
                                        let write_path = std::fs::read_link(&params_path)
                                            .unwrap_or(params_path.clone());
                                        if let Err(e) = std::fs::write(&write_path, &data) {
                                            warn!(error = %e, "MPC: Failed to save refreshed params");
                                            continue;
                                        }
                                        // Extract and save note_spend VK
                                        if let Ok(ns_params) =
                                            ghost_mpc::params::load_parameters(&write_path)
                                        {
                                            let ns_vk_path = params_dir.join("note_spend_vk.bin");
                                            if let Err(e) = ghost_mpc::params::save_verifying_key(
                                                &ns_vk_path,
                                                &ns_params.vk,
                                            ) {
                                                warn!(error = %e, "MPC: Failed to save refreshed note_spend VK");
                                            }
                                        }
                                        // Reload into ceremony manager
                                        if let Err(e) =
                                            ceremony_manager_for_startup.load_current_params()
                                        {
                                            warn!(error = %e, "MPC: Failed to reload refreshed params");
                                        } else {
                                            info!(size = data.len(), peer = %host, "MPC: Refreshed note_spend params from network for retry");
                                            // Invalidate cached contribution since params changed
                                            cached_msg = None;
                                        }
                                        // Also refresh payout params from same peer (with VK extraction)
                                        let payout_url = format!(
                                            "http://{}:8080/api/v1/mpc/payout-params",
                                            host
                                        );
                                        if let Ok(payout_resp) = reqwest::Client::new()
                                            .get(&payout_url)
                                            .timeout(std::time::Duration::from_secs(60))
                                            .send()
                                            .await
                                        {
                                            if payout_resp.status().is_success() {
                                                if let Ok(payout_data) = payout_resp.bytes().await {
                                                    if payout_data.len() > 1000 {
                                                        let payout_current = params_dir
                                                            .join("payout_params_current.bin");
                                                        let payout_write =
                                                            std::fs::read_link(&payout_current)
                                                                .unwrap_or(payout_current.clone());
                                                        if let Err(e) = std::fs::write(
                                                            &payout_write,
                                                            &payout_data,
                                                        ) {
                                                            warn!(error = %e, "MPC: Failed to save refreshed payout params");
                                                        } else {
                                                            // Extract and save payout VK
                                                            if let Ok(payout_params) =
                                                                ghost_mpc::params::load_parameters(
                                                                    &payout_write,
                                                                )
                                                            {
                                                                let payout_vk_path = params_dir
                                                                    .join("payout_vk.bin");
                                                                if let Err(e) = ghost_mpc::params::save_verifying_key(&payout_vk_path, &payout_params.vk) {
                                                                    warn!(error = %e, "MPC: Failed to save refreshed payout VK");
                                                                }
                                                            }
                                                            info!(size = payout_data.len(), peer = %host, "MPC: Refreshed payout params from network");
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        // Also refresh unshield params from same peer (with VK extraction)
                                        let unshield_url = format!(
                                            "http://{}:8080/api/v1/mpc/unshield-params",
                                            host
                                        );
                                        if let Ok(unshield_resp) = reqwest::Client::new()
                                            .get(&unshield_url)
                                            .timeout(std::time::Duration::from_secs(60))
                                            .send()
                                            .await
                                        {
                                            if unshield_resp.status().is_success() {
                                                if let Ok(unshield_data) =
                                                    unshield_resp.bytes().await
                                                {
                                                    if unshield_data.len() > 1000 {
                                                        let unshield_current = params_dir
                                                            .join("unshield_params_current.bin");
                                                        let unshield_write =
                                                            std::fs::read_link(&unshield_current)
                                                                .unwrap_or(
                                                                    unshield_current.clone(),
                                                                );
                                                        if let Err(e) = std::fs::write(
                                                            &unshield_write,
                                                            &unshield_data,
                                                        ) {
                                                            warn!(error = %e, "MPC: Failed to save refreshed unshield params");
                                                        } else {
                                                            // Extract and save unshield VK
                                                            if let Ok(unshield_params) =
                                                                ghost_mpc::params::load_parameters(
                                                                    &unshield_write,
                                                                )
                                                            {
                                                                let unshield_vk_path = params_dir
                                                                    .join("unshield_vk.bin");
                                                                if let Err(e) = ghost_mpc::params::save_verifying_key(&unshield_vk_path, &unshield_params.vk) {
                                                                    warn!(error = %e, "MPC: Failed to save refreshed unshield VK");
                                                                }
                                                            }
                                                            info!(size = unshield_data.len(), peer = %host, "MPC: Refreshed unshield params from network");
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        break;
                                    }
                                    _ => continue,
                                }
                            }
                            _ => continue,
                        }
                    }
                }
            }

            // The loop only exits by BREAK (ceremony ossified) — the elder-success
            // path returns from inside it. So reaching here means the ceremony
            // ossified. If we were nonetheless voted in on the same tick we broke,
            // finalise elder state; otherwise the ceremony filled before we could
            // register. Either way this is a legitimate terminal state, NOT the old
            // misleading "gave up after N attempts / will not be an elder" — until
            // ossification a node that wants to be an elder retries indefinitely.
            if db_for_mpc.is_mpc_elder(&node_id_hex).unwrap_or(false) {
                let position = db_for_mpc
                    .get_mpc_elder_position(&node_id_hex)
                    .unwrap_or(None);
                info!(position = ?position, "MPC contribution succeeded after retries");
                // Update live capabilities so health pings reflect elder status
                mesh_for_mpc_startup.update_elder_status(true);
                let mut updated_caps = initial_capabilities;
                updated_caps.elder_status = true;
                round_manager_for_mpc
                    .update_node_capabilities(identity_for_mpc.node_id(), updated_caps);
            } else {
                info!(
                    "MPC: ceremony ossified before this node was voted in — it will not be an \
                     elder in this ceremony (retried until ossification; no premature giveup)"
                );
            }
        });
        info!("MPC auto-contribution task scheduled (15s delay)");

        info!(
            "MPC ceremony handler initialized (contributions={}, ossified={})",
            ceremony_manager.contribution_count(),
            ceremony_manager.is_ossified()
        );
    }

    // Create shutdown channel
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Create pool state (will be used for API handlers)
    let _pool_state = Arc::new(PoolState {
        identity: Arc::clone(&identity),
        capabilities,
        policy: policy.clone(),
        rpc: Arc::clone(&rpc),
        db: Arc::clone(&db),
        round_manager: Arc::clone(&round_manager),
        template_processor: Arc::clone(&template_processor),
        mesh: Arc::clone(&mesh),
        vote_handler: Arc::clone(&vote_handler),
        shutdown_tx: shutdown_tx.clone(),
    });

    // Create payout handler for block found events
    // This wires BlockFound -> PayoutProposal -> VoteHandler (BFT consensus)
    //
    // Convert treasury address from bech32 string to script pubkey bytes
    let treasury_script = if !config.pool.treasury_address.is_empty() {
        use bitcoin::address::NetworkUnchecked;
        use bitcoin::Address;
        use std::str::FromStr;

        let addr_str = config.pool.treasury_address.address();
        match Address::<NetworkUnchecked>::from_str(addr_str) {
            Ok(addr) => addr.assume_checked().script_pubkey().into_bytes(),
            Err(e) => {
                warn!(
                    address = %addr_str,
                    error = %e,
                    "Invalid treasury address, using empty (payouts will fail)"
                );
                Vec::new()
            }
        }
    } else {
        warn!("No treasury address configured, pool fee payouts will fail");
        Vec::new()
    };

    let payout_config = PayoutConfig {
        dust_threshold_sats: config.pool.min_payout_sats.max(546),
        max_miner_outputs: 200,
        max_node_outputs: 100,
        treasury_address: Some(treasury_script),
        network: config.bitcoin.network, // M-15/LOW: Enable mainnet-specific security checks
    };

    // H-MINE-1: PayoutHandler uses the same QualifiedCapabilityProvider as health_handler
    // This ensures consistent verified capability lookups across the system
    let payout_handler = Arc::new(PayoutHandler::new(
        Arc::clone(&identity),
        payout_config,
        Arc::clone(&db),
        Arc::clone(&vote_handler),
        Arc::clone(&template_processor),
        Arc::clone(&qualification_provider_for_health), // Reuse provider from health_handler
    )?);

    // GHOST-02: install the ledger-recompute validator on the vote handler now
    // that the PayoutHandler exists. A peer's payout proposal is vote-approved
    // only if its split matches what THIS node recomputes from its own converged
    // share ledger (GHOST-03) and converged payout addresses (Option A).
    {
        let validator = ghost_pool::payout::make_proposal_validator(
            Arc::clone(&payout_handler),
            Arc::clone(&db),
            ghost_pool::cluster_enforcement_height(),
        );
        vote_handler.set_proposal_validator(validator);
    }

    // Start verification HTTP server
    let rpc_for_verification = Arc::clone(&rpc);
    let rm_for_height = Arc::clone(&round_manager);
    let rm_for_round = Arc::clone(&round_manager);
    let rm_for_miners = Arc::clone(&round_manager);
    let rm_for_elapsed = Arc::clone(&round_manager);
    let mesh_for_verification = Arc::clone(&mesh);

    let mut verification_state = VerificationState::new(
        identity.node_id_hex(),
        env!("CARGO_PKG_VERSION").to_string(),
        policy.clone(),
        capabilities,
    );

    // Report the node's real configured chain on the status/info endpoints
    // (dashboard + wallets) instead of the historical hardcoded "signet".
    verification_state = verification_state.with_network(config.bitcoin.network);

    // Report the operator's Wraith-mixing choice from `[ghost_pay] wraith_enabled`
    // on the ghostpay status endpoint, so the dashboard's L2 card reflects the
    // node's actual setting rather than ghost-pay's internal "hosts mixing" flag.
    verification_state = verification_state.with_wraith_enabled(config.wraith_enabled());

    // VER-6: When a peer challenges this node's stratum capability, our
    // handler probes the stratum endpoint to confirm reachability. Without
    // this, the handler falls back to 127.0.0.1, which only proves loopback
    // listening (not external reachability) AND spams pool_sv2 with bogus
    // Noise NK handshakes that get logged as ERROR. Wiring the configured
    // public_address restores VER-6's intent.
    if let Some(public_address) = config.network.public_address.clone() {
        verification_state = verification_state.with_stratum_host(public_address);
    }
    verification_state =
        verification_state.with_stratum_ports(config.network.sv2_port, config.network.sv1_port);

    // Configure callbacks for health/status endpoints
    // Miner count now comes from share notifications via SRI forwarder
    verification_state = verification_state.with_callbacks(
        move || rm_for_height.current_height(),
        move || rm_for_round.current_round_id() as u64,
        move || {
            rm_for_miners
                .round_stats(rm_for_miners.current_round_id())
                .map(|s| s.miner_count as u32)
                .unwrap_or(0)
        },
        move || mesh_for_verification.peers().unique_peer_count() as u32,
    );

    // Wire pool-peers callback for the translator load-balancer endpoint.
    // `deduped_miner_count` is the per-node share of the mesh-wide active-miner
    // total (attributed over the same 300s window as `mesh_active_miners`), so
    // the Capacity page's per-node rows sum to the deduped grand total instead
    // of over-counting miners that fail over between nodes. The raw
    // `miner_count` is left untouched for the LB's utilisation routing.
    let mesh_for_pool_peers = Arc::clone(&mesh);
    verification_state = verification_state.with_pool_peers(move || {
        use ghost_verification::PoolPeerInfo;
        let deduped = mesh_for_pool_peers.deduped_miner_counts(300);
        mesh_for_pool_peers
            .peers()
            .get_connected_peers(30)
            .into_iter()
            .filter(|p| p.capabilities.public_mining && !p.public_address.is_empty())
            .map(|p| PoolPeerInfo {
                public_address: p.public_address.clone(),
                miner_count: p.miner_count,
                public_mining: true,
                last_seen: p.last_seen,
                max_capacity: p.max_capacity,
                deduped_miner_count: deduped.get(&p.node_id).copied().unwrap_or(0),
            })
            .collect()
    });

    // Live mesh node list for the public /api/v1/pool/mesh-nodes endpoint.
    // Maps every connected peer to MeshNodeInfo using only already-gossiped,
    // public fields (capabilities, hashrate, miner count). 120s freshness:
    // wide enough to tolerate a few missed ~10s health pings, narrow enough
    // that a genuinely gone node ages out. Self is added by the handler from
    // local state, so this returns peers only. No network calls.
    let mesh_for_node_list = Arc::clone(&mesh);
    verification_state = verification_state.with_mesh_nodes(move || {
        use ghost_verification::MeshNodeInfo;
        // Deduped per-node counts over the 300s active-miner window (matching
        // the mesh grand total) so the mesh-nodes list sums consistently.
        let deduped = mesh_for_node_list.deduped_miner_counts(300);
        mesh_for_node_list
            .peers()
            .get_connected_peers(120)
            .into_iter()
            .map(|p| MeshNodeInfo {
                node_id: p.node_id_hex(),
                address: p.public_address.clone(),
                elder: p.is_elder,
                cap_archive: p.capabilities.archive_mode,
                cap_ghost_pay: p.capabilities.ghost_pay,
                cap_public_mining: p.capabilities.public_mining,
                cap_reaper: p.capabilities.reaper,
                cap_elder: p.capabilities.elder_status,
                hashrate_th: p.local_hashrate_th,
                miner_count: p.miner_count,
                deduped_miner_count: deduped.get(&p.node_id).copied().unwrap_or(0),
                // Peer's gossiped hardware capacity ceiling (0 until reported),
                // so the Capacity page can show utilisation for every mesh node
                // — not just the public-mining peers the pool-nodes path lists.
                max_capacity: p.max_capacity,
                // get_connected_peers already filtered to Connected + fresh.
                healthy: true,
                // Swarm-page telemetry gossiped by each peer. L1 height 0 means
                // "not reported" (older build) → None so the page shows "—"
                // rather than a misleading 0; uptime/peer_count/L2 are already
                // Option (None = not reported / not applicable).
                l1_height: (p.block_height != 0).then_some(p.block_height),
                uptime_percent: p.uptime_percent,
                peer_count: p.peer_count,
                l2_height: p.l2_height,
            })
            .collect()
    });

    // Mesh-wide deduplicated active miner count. Unions local active miner_id
    // hashes with the most-recent set from each connected peer.
    //
    // The freshness window must match the 300s miner-activity window the local
    // and gossiped sets are computed over (`active_miner_id_hashes(300)`), NOT a
    // tight 60s. At 60s a peer that simply missed a few ~10s health pings (jitter,
    // GC, momentary load) was excluded entirely, dropping ALL of its active miners
    // from the union — so a node would report e.g. 4 of 5 miners, and since the
    // figure is gossip-derived the whole mesh could undercount at once. Dedup is by
    // miner_id hash, so a wider window cannot double-count, and a disconnected miner
    // still ages out at the source node's 300s `last_seen`, so the count stays
    // honest while becoming robust to transient ping loss.
    let mesh_for_active = Arc::clone(&mesh);
    verification_state = verification_state
        .with_mesh_active_miners(move || mesh_for_active.mesh_active_miner_count(300) as u32);

    // This node's (self) deduped share of that mesh-wide total, from the same
    // attribution that fills each peer's `deduped_miner_count`. Surfaced on the
    // self/`this_node` entries so `self + peers` sum to `mesh_active_miners`.
    let mesh_for_self_deduped = Arc::clone(&mesh);
    verification_state = verification_state.with_self_deduped_miner_count(move || {
        let counts = mesh_for_self_deduped.deduped_miner_counts(300);
        counts
            .get(&mesh_for_self_deduped.peers().our_node_id())
            .copied()
            .unwrap_or(0)
    });

    // Mesh-wide pool hashrate (TH/s) — sum of every node's own realized
    // hashrate (60s peer freshness). One term per node, scoped by received_by
    // at source, so it can't double-count and is identical on every node.
    let mesh_for_hashrate = Arc::clone(&mesh);
    verification_state = verification_state
        .with_mesh_total_hashrate(move || mesh_for_hashrate.mesh_total_hashrate(60));

    // This node's own contribution to that total, surfaced as `local_hashrate_th`
    // so the per-node and mesh figures reconcile (same windowed value it gossips).
    let db_for_local_hr_route = Arc::clone(&db);
    let self_rx_for_route = self_received_by.clone();
    verification_state = verification_state.with_local_hashrate(move || {
        db_for_local_hr_route
            .local_hashrate_th(MESH_HASHRATE_WINDOW_SECS, &self_rx_for_route)
            .unwrap_or(0.0)
    });
    // Scope the operator/peer detailed miner list to this node's own miners
    // (shares stored under our `received_by`), so "This Node's Miners" and the
    // /miners/full peer feed are local — not the mesh-wide gossiped set.
    verification_state = verification_state.with_local_received_by(self_received_by.clone());
    // Live handle to the template refresh cadence so the dashboard can retune it
    // (10–60s) without restarting the pool.
    verification_state =
        verification_state.with_template_refresh(template_processor.refresh_interval_handle());
    // Current-template snapshot provider for the dashboard visualiser (reads the
    // summary fields under the lock without cloning the full tx set).
    let tp_for_snapshot = Arc::clone(&template_processor);
    verification_state = verification_state
        .with_template_snapshot(move || tp_for_snapshot.current_template_summary());
    // Coinbase-payments breakdown provider: how the current block's coinbase
    // splits across miners / node rewards / treasury / finder fees, from the
    // approved payout proposal. `None` result until a payout is agreed.
    let tp_for_coinbase = Arc::clone(&template_processor);
    verification_state = verification_state
        .with_coinbase_snapshot(move || tp_for_coinbase.current_coinbase_breakdown());

    // Seconds elapsed working the current template, surfaced as
    // `current_round_duration_secs` on the pool-status endpoint so the
    // dashboard's round-progress readout reflects real round timing.
    verification_state = verification_state
        .with_round_elapsed_secs(move || rm_for_elapsed.current_round_elapsed_secs());

    // Mesh-wide best records per window — every connected peer's gossiped best,
    // reduced to one winner per window. The records endpoint merges this with
    // the local DB best so the pool-wide rarest record survives the
    // record-holding node being momentarily unreachable. 300s peer freshness
    // (matches the active-miner window) so a couple of missed ~10s pings don't
    // drop a peer's record from the merge.
    let mesh_for_best_records = Arc::clone(&mesh);
    verification_state = verification_state
        .with_mesh_best_records(move || mesh_for_best_records.mesh_best_records(300));

    // Advertise this node's hardware-derived capacity via /api/internal/pool-nodes
    // so the colocated translator's load balancer routes by utilisation %.
    verification_state.set_max_capacity(effective_max_capacity);

    // Wire Reaper observability counters through to /api/v1/reaper/status.
    // The processor owns the Arc<ReaperStats>; we hand the dashboard a closure
    // that snapshots it on demand.
    let reaper_stats_for_api = template_processor.reaper_stats();
    verification_state = verification_state.with_reaper_stats(move || {
        serde_json::to_value(reaper_stats_for_api.snapshot()).unwrap_or(serde_json::Value::Null)
    });

    // Capability self-check (Phase 3). Construct the coordinator here so its
    // last snapshot can be surfaced over HTTP at /api/v1/system/self-check;
    // the background probe loop is spawned later (after the HTTP listener is
    // up). The dashboard reads this to warn when a claimed capability's
    // prerequisite is missing (e.g. public_mining announced but no stratum
    // serving). Read-only: the handler reads the snapshot, it does not probe.
    let self_check = SelfCheck::new();
    {
        let self_check_for_api = self_check.clone();
        verification_state = verification_state.with_self_check(move || {
            serde_json::to_value(self_check_for_api.snapshot()).unwrap_or(serde_json::Value::Null)
        });
    }

    // Decentralised Wraith coordinator election (read-only, gated off by
    // default). Constructed ONLY when `[coordinator] wraith_election_enabled`
    // is true; otherwise `None` and the service is inert (zero effect on the
    // node). It computes/publishes the per-epoch draw — it activates NO
    // coordinator role and changes no consensus message.
    let coordinator_election = ghost_pool::coordinator_election::CoordinatorElection::maybe_new(
        config.coordinator.wraith_election_enabled,
        &identity,
        &capabilities,
        // Self's advertised endpoint enters the roster only when this node opted
        // in (capabilities.coordinator); harmless to pass through otherwise.
        config.coordinator.advertised_endpoint.clone(),
        Arc::clone(&mesh),
        Arc::clone(&rpc),
    );
    {
        let coord_for_api = coordinator_election.clone();
        verification_state = verification_state.with_coordinator_status(move || {
            coord_for_api
                .as_ref()
                .map(|c| c.status_json())
                .unwrap_or_else(ghost_pool::coordinator_election::disabled_status_json)
        });
    }

    // In-process coordinator activation (Inc 4). Off unless
    // `[coordinator] coordinator_role_enabled`; on mainnet it is refused unless a
    // real bond ledger is configured (secure-by-default). When elected, the node
    // runs the coordinator on `coordinator_port`; the supervisor is reconciled
    // against the election each epoch flip below.
    let coordinator_supervisor = {
        let coord_network = match config.bitcoin.network {
            ghost_common::config::BitcoinNetwork::Mainnet => bitcoin::Network::Bitcoin,
            ghost_common::config::BitcoinNetwork::Signet => bitcoin::Network::Signet,
            ghost_common::config::BitcoinNetwork::Testnet => bitcoin::Network::Testnet,
            ghost_common::config::BitcoinNetwork::Regtest => bitcoin::Network::Regtest,
        };
        let listen: std::net::SocketAddr =
            format!("0.0.0.0:{}", config.coordinator.coordinator_port)
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid coordinator listen addr: {e}"))?;
        let role_cfg = ghost_pool::coordinator_supervisor::CoordinatorRoleConfig {
            enabled: config.coordinator.coordinator_role_enabled,
            network: coord_network,
            listen,
            bond_ledger_url: config.coordinator.bond_ledger_url.clone(),
            bond_ledger_token: config.coordinator.bond_ledger_token.clone(),
            // The co-located ghost-pay serves its bond endpoints with an
            // identity cert derived from this SAME node identity, so the bond
            // ledger client pins against our own node_id.
            node_id: identity.node_id(),
            fee_address: config.coordinator.coordinator_fee_address.clone(),
            ghostd_rpc_url: format!(
                "http://{}:{}",
                config.bitcoin.rpc_host, config.bitcoin.rpc_port
            ),
            ghostd_rpc_user: config.bitcoin.rpc_user.clone(),
            ghostd_rpc_password: config.bitcoin.rpc_password.clone(),
        };
        ghost_pool::coordinator_supervisor::CoordinatorSupervisor::maybe_new(
            role_cfg,
            Arc::clone(&mesh),
        )
        .map_err(|e| anyhow::anyhow!(e))?
    };

    // Configure archive handler if archive mode enabled
    if capabilities.archive_mode {
        let archive_handler = RpcArchiveHandler::new(Arc::clone(&rpc_for_verification));
        verification_state = verification_state.with_archive_handler(archive_handler);
    }

    // Note: GhostPay verification is now handled directly by ghost-pay on port 8800.
    // The verification client routes GhostPay challenges to ghost-pay instead of ghost-pool,
    // so no stub handler is needed here. Ghost-pay queries its own L2 database for real state.

    // Wire GSP handler if GSP service URL is configured or default (port 8900)
    let gsp_handler = CachedGspHandler::new("https://127.0.0.1:8900".to_string());
    verification_state = verification_state.with_gsp_handler(gsp_handler);

    // Pass database and RPC to verification state for API endpoints
    verification_state = verification_state.with_database((*db).clone());
    verification_state = verification_state.with_rpc(Arc::clone(&rpc));

    // Wire node config path for persisting ghost_mode, shroud_enabled, etc.
    verification_state =
        verification_state.with_node_config_path(data_dir.join("node_config.json"));

    // Wire Tor mode status from Ghost Core RPC
    if let Some(ref ts) = tor_status {
        verification_state =
            verification_state.with_tor_status(ts.enabled, ts.onion_address.clone());
    }

    // Wire full node config for config update API
    // This allows the dashboard to modify settings via POST /api/internal/config/update
    verification_state =
        verification_state.with_full_node_config(config.clone(), args.config.clone());

    // Wire L2 submit callback if ZK consensus is enabled
    if let Some(l2_submit_fn) = l2_submit_fn_opt {
        verification_state = verification_state.with_l2_submit(l2_submit_fn);
    }

    // Wire L2 commitment sync callback if ZK consensus is enabled
    if let Some(l2_sync_fn) = l2_sync_commitment_fn_opt {
        verification_state = verification_state.with_l2_sync_commitment(l2_sync_fn);
    }

    // Wire L2 tree state callback if ZK consensus is enabled
    if let Some(l2_tree_state_fn) = l2_tree_state_fn_opt {
        verification_state = verification_state.with_l2_tree_state(l2_tree_state_fn);
    }

    // Wire GhostGlyph relay callbacks (always enabled — no feature gate)
    verification_state = verification_state
        .with_glyph_claim_relay(glyph_claim_relay_fn)
        .with_glyph_registered_relay(glyph_registered_relay_fn);

    // Configure internal API authentication (AUTH4-1 security fix)
    let is_mainnet_auth = config.bitcoin.network == ghost_common::config::BitcoinNetwork::Mainnet;
    if let Some(ref secret_hex) = config.network.internal_api_secret {
        match ghost_verification::InternalAuth::from_hex(secret_hex) {
            Ok(auth) => {
                info!("Internal API authentication configured for /api/internal/* and /admin/*");
                verification_state = verification_state.with_internal_auth(auth);
            }
            Err(e) => {
                // H-2: Malformed secret is always fatal — operator intended to configure auth
                return Err(anyhow::anyhow!(
                    "Invalid internal_api_secret: {} — fix or remove the config entry",
                    e
                ));
            }
        }
    } else if is_mainnet_auth {
        // C-1: Mainnet MUST have internal API authentication
        return Err(anyhow::anyhow!(
            "FATAL: network.internal_api_secret is required on mainnet. \
             Generate one with: openssl rand -hex 32"
        ));
    } else {
        warn!(
            "AUTH4-1 WARNING: network.internal_api_secret not configured! \
             Internal endpoints (/api/internal/*, /admin/*) are UNPROTECTED. \
             Generate a secret with: openssl rand -hex 32"
        );
        // Dev/test: on non-mainnet networks, allow the verification server to start
        // without an internal API secret so local rigs can POST to /api/internal/*.
        // Mainnet enforcement is still intact via the normal validator path.
        if !matches!(
            config.bitcoin.network,
            ghost_common::config::BitcoinNetwork::Mainnet
        ) {
            warn!(
                "Dev mode: network != mainnet and no internal_api_secret — allowing insecure internal API for local development only"
            );
            verification_state = verification_state.allow_insecure_internal_api(true);
        }
    }

    // Configure test proposal callback for BFT consensus testing
    let vh_for_test = Arc::clone(&vote_handler);
    let identity_for_test = Arc::clone(&identity);
    let rm_for_test = Arc::clone(&round_manager);
    let test_proposal_fn: ghost_verification::TestProposalFn = Arc::new(move || {
        use ghost_common::types::{PayoutEntry, PayoutProposal, PayoutType};

        // Create a test payout proposal
        let round_id = rm_for_test.current_round_id() as u64;
        let height = rm_for_test.current_height();
        let timestamp = chrono::Utc::now().timestamp() as u64;

        // Create minimal valid test proposal
        let proposal = PayoutProposal {
            proposal_hash: [0u8; 32], // Will be computed by handler
            round_id,
            block_hash: [0u8; 32],
            block_height: height.max(800_000), // Ensure valid height
            proposer: identity_for_test.node_id(),
            miner_payouts: vec![PayoutEntry {
                address: b"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_vec(), // Signet address
                amount: 100_000_000,                                             // 1 BTC test
                recipient_id: [1u8; 32],
                payout_type: PayoutType::Mining,
            }],
            node_payouts: vec![],
            treasury_amount: 1_000_000,                 // 0.01 BTC
            treasury_address: b"tb1qtreasury".to_vec(), // H-MINE-3: snapshot address (test)
            tx_fees: 500_000,
            subsidy: 312_500_000, // 3.125 BTC (signet subsidy)
            timestamp,
            tx_fees_unallocated: 0,
        };

        // Submit to vote handler (broadcasts to peers)
        vh_for_test.handle_proposal(proposal)
    });
    verification_state = verification_state.with_test_proposal_fn(test_proposal_fn);

    // Share broadcast relay: sync callback → async Noise broadcast
    // Follows the MPC relay pattern (main.rs:1107-1134)
    // Buffer cushion for share-relay bursts. The real throughput fix is the
    // concurrent per-peer fan-out in MeshNetwork::broadcast; this just absorbs
    // short bursts so try_send doesn't drop proofs under load.
    let (share_broadcast_tx, mut share_broadcast_rx) =
        tokio::sync::mpsc::channel::<ghost_common::types::ShareProof>(1024);
    let mesh_for_shares_relay = Arc::clone(&mesh);
    tokio::spawn(async move {
        while let Some(proof) = share_broadcast_rx.recv().await {
            let msg = ghost_consensus::message::ShareProofMessage { proof };
            match serde_json::to_vec(&msg) {
                Ok(payload) => {
                    match mesh_for_shares_relay
                        .create_envelope_raw(MessageType::ShareProof, payload)
                    {
                        Ok(envelope) => {
                            if let Err(e) = mesh_for_shares_relay.smart_broadcast(envelope).await {
                                tracing::warn!(error = %e, "Share proof broadcast failed");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Share proof envelope creation failed");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Share proof serialization failed");
                }
            }
        }
    });

    // Configure share recorder callback for SRI Pool share notifications
    let rm_for_shares = Arc::clone(&round_manager);
    let identity_for_shares = Arc::clone(&identity);
    let db_for_shares = Arc::clone(&db);
    verification_state = verification_state.with_share_recorder(move |share| {
        // Get current round ID for database record
        let round_id = rm_for_shares.current_round_id();

        // Record the share in the current round (in-memory tracking)
        rm_for_shares
            .record_share(&share.miner_id, share.work, identity_for_shares.node_id())
            .map_err(|e| ghost_common::GhostError::Internal(e.to_string()))?;

        // The SV2/SRI layer reports share_hash in big-endian DISPLAY order (PoW leading zeros
        // at the front). The pool's difficulty machinery and the ShareProof both use INTERNAL
        // (little-endian) order, zeros at the high-index end.
        //
        // CANONICAL STORAGE IS INTERNAL ORDER. This row used to be written in display order
        // while every gossiped copy of the SAME share was written internal, so one share had
        // two different `share_hash` strings depending on which node stored it. Nothing
        // double-counted only because a node skips gossip of its own shares — but it makes
        // share_hash useless as a cross-node identity, and any ledger reconciliation keyed on
        // it would serve a node its own shares back under the other spelling, where the UNIQUE
        // constraint would not recognise them and the work would be counted TWICE.
        let mut share_hash_bytes = [0u8; 32];
        if let Ok(decoded) = hex::decode(&share.share_hash) {
            if decoded.len() == 32 {
                for (i, b) in decoded.iter().rev().enumerate() {
                    share_hash_bytes[i] = *b; // display (big-endian) -> internal (little-endian)
                }
            } else {
                let len = decoded.len().min(32);
                share_hash_bytes[..len].copy_from_slice(&decoded[..len]);
            }
        }
        let canonical_share_hash = hex::encode(share_hash_bytes);

        // Uses SHA256(miner_id) as the 32-byte miner identifier for the proof.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(share.miner_id.as_bytes());
        let miner_hash: [u8; 32] = hasher.finalize().into();

        let mut proof = ghost_common::types::ShareProof {
            round_id,
            miner_id: miner_hash,
            difficulty: share.work,
            work: share.work,
            share_hash: share_hash_bytes,
            timestamp: share.timestamp,
            received_by: identity_for_shares.node_id(),
            template_id: rm_for_shares.current_template_id(),
            payout_address: share.payout_address.clone(),
            signature: None,
        };
        // GHOST-09: sign as the receiving node so peers can authenticate the
        // node-reward credit and reject relayed/forged `received_by`.
        proof.sign(identity_for_shares.as_ref());

        // GHOST-03 (schema v41): store the signed proof with the share so this node can serve a
        // backfill of it to any peer that dropped the broadcast, at any age.
        let proof_blob = serde_json::to_vec(&proof).unwrap_or_default();

        // Persist share to database for historical tracking and auditing
        let share_record = ghost_storage::models::ShareRecord {
            id: None,
            round_id,
            miner_id: share.miner_id.clone(),
            difficulty: share.work, // SRI reports work as difficulty-adjusted value
            work: share.work,
            share_hash: canonical_share_hash,
            timestamp: share.timestamp as i64,
            received_by: hex::encode(&identity_for_shares.node_id()[..8]),
            valid: true, // Already validated by SRI Pool
        };

        match db_for_shares.insert_share_with_proof(&share_record, &proof_blob) {
            Ok(_) => {
                // Share inserted successfully — update miner cumulative stats
                if let Err(e) = db_for_shares.increment_miner_stats(&share.miner_id, 1, share.work)
                {
                    tracing::warn!(
                        miner_id = %share.miner_id,
                        error = %e,
                        "Failed to increment miner stats"
                    );
                }
            }
            Err(e) => {
                // Log but don't fail - in-memory tracking is primary, DB is for auditing
                // UNIQUE constraint failures are expected (dedup) and don't increment stats
                tracing::warn!(
                    miner_id = %share.miner_id,
                    share_hash = %share.share_hash,
                    error = %e,
                    "Failed to persist share to database"
                );
            }
        }

        // Update miner's payout address in database if provided
        // The payout_address is extracted from user_identity (format: <address>.<worker>)
        if let Some(ref payout_address) = share.payout_address {
            if !payout_address.is_empty() {
                if let Err(e) = db_for_shares.update_miner_address(&share.miner_id, payout_address)
                {
                    tracing::warn!(
                        miner_id = %share.miner_id,
                        payout_address = %payout_address,
                        error = %e,
                        "Failed to update miner payout address"
                    );
                } else {
                    tracing::trace!(
                        miner_id = %share.miner_id,
                        payout_address = %payout_address,
                        "Updated miner payout address"
                    );
                }
            }
        }

        // Broadcast the signed share proof to other nodes via P2P.
        if let Err(e) = share_broadcast_tx.try_send(proof) {
            tracing::warn!(error = %e, "Share broadcast channel full or closed");
        }

        tracing::debug!(
            miner_id = %share.miner_id,
            work = share.work,
            round_id = round_id,
            "Share recorded from SRI notification"
        );
        Ok(())
    });

    // Shared slot for the operator-alert dispatcher. The block_found callback is
    // registered here (before `verification_state` is wrapped in an `Arc`, which
    // the dispatcher's live-config closure needs), so it can't capture the
    // dispatcher directly. Instead it captures this slot, which is populated
    // once the dispatcher is built (just after the `Arc::new` below). BlockFound
    // is the one trigger site on a pre-Arc, synchronous callback path.
    let alert_slot: Arc<std::sync::OnceLock<Arc<ghost_verification::alerts::AlertDispatcher>>> =
        Arc::new(std::sync::OnceLock::new());

    // Configure block_found callback: triggers payout proposal BEFORE block submission.
    // This breaks the bootstrap deadlock where:
    //   1. submitblock requires an approved coinbase commitment
    //   2. Coinbase commitment requires an approved payout proposal
    //   3. Payout proposals were only created from block_submitted_rx (AFTER submitblock)
    // By creating the proposal when a block-difficulty share is found (before submission),
    // the next template will include the committed coinbase and submitblock will succeed.
    {
        let rm_for_bf = Arc::clone(&round_manager);
        let tp_for_bf = Arc::clone(&template_processor);
        let payout_for_bf = Arc::clone(&payout_handler);
        let identity_for_bf = Arc::clone(&identity);
        let db_for_bf = Arc::clone(&db);
        let solo_payout_address_for_bf = config.network.solo_payout_address.clone();
        let metrics_for_bf = Arc::clone(&metrics);
        let alert_slot_for_bf = Arc::clone(&alert_slot);

        verification_state = verification_state.with_block_found_callback(move |block_info| {
            let round_id = rm_for_bf.current_round_id();
            let is_solo_mode = rm_for_bf.is_solo_mode();

            info!(
                round = round_id,
                share_hash = %block_info.share_hash,
                miner = %block_info.miner_id,
                solo_mode = is_solo_mode,
                "Block-difficulty share found, creating pre-submission payout proposal..."
            );

            // Fire the BlockFound operator alert (async, non-blocking — never
            // holds up the payout-proposal hot path). Enable-flag + delivery are
            // handled inside the dispatcher. Discrete event: no debounce needed.
            if let Some(dispatcher) = alert_slot_for_bf.get() {
                let dispatcher = Arc::clone(dispatcher);
                let detail = format!(
                    "Block-difficulty share found in round {round_id} (share {}, miner {}).",
                    block_info.share_hash, block_info.miner_id
                );
                tokio::spawn(async move {
                    dispatcher
                        .fire(ghost_verification::alerts::AlertEvent::BlockFound, &detail)
                        .await;
                });
            }

            // Use the share hash as block hash — the share met block difficulty,
            // so this IS the candidate block hash. Can't use [0u8;32] because
            // PO4-M1 validation rejects zero block hashes.
            let mut block_hash = [0u8; 32];
            if let Ok(decoded) = hex::decode(&block_info.share_hash) {
                let len = decoded.len().min(32);
                block_hash[..len].copy_from_slice(&decoded[..len]);
            }

            let node_shares = rm_for_bf.get_node_shares(round_id);
            let (subsidy, fees, height) = tp_for_bf.get_current_block_info();

            // Load treasury state from database
            let treasury_state = match db_for_bf.get_treasury_balance() {
                Ok(balance) => {
                    let threshold_ts = match db_for_bf.get_treasury_threshold_reached() {
                        Ok(ts_opt) => ts_opt
                            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
                            .map(|dt| dt.with_timezone(&chrono::Utc)),
                        Err(e) => {
                            warn!(error = %e, "Failed to load treasury threshold timestamp, using None");
                            None
                        }
                    };
                    TreasuryState::from_stored(balance, threshold_ts)
                }
                Err(e) => {
                    warn!(error = %e, "Failed to load treasury state, using default");
                    TreasuryState::new()
                }
            };

            let winning_node_id = identity_for_bf.node_id();

            if is_solo_mode {
                let solo_address = match &solo_payout_address_for_bf {
                    Some(addr) if !addr.is_empty() => addr.clone(),
                    _ => {
                        error!("Solo mode block found but solo_payout_address not configured!");
                        return;
                    }
                };

                let treasury_address_snapshot =
                    payout_for_bf.get_treasury_address_snapshot();

                let solo_data = SoloBlockFoundData {
                    round_id,
                    block_hash,
                    block_height: height,
                    block_timestamp: chrono::Utc::now(),
                    solo_payout_address: solo_address,
                    subsidy_sats: subsidy,
                    treasury_address_snapshot,
                    tx_fees_sats: fees,
                    node_shares,
                    treasury_state,
                };

                match payout_for_bf.handle_solo_block_found(solo_data) {
                    Ok(proposal_hash) => {
                        if proposal_hash != [0u8; 32] {
                            info!(
                                round = round_id,
                                hash = %hex::encode(&proposal_hash[..8]),
                                "Solo pre-submission payout proposal submitted for consensus"
                            );
                        }
                    }
                    Err(e) => {
                        error!(error = %e, round = round_id, "Failed to create solo pre-submission payout proposal");
                    }
                }
            } else {
                // Pool mode: ledger-style proportional distribution.
                //
                // Unpaid shares accumulate across rounds on each miner's
                // ledger. When a block is found we sweep the whole unpaid
                // ledger up to `cutoff_ts` — top 1000 contributors,
                // iteratively dust-filtered so every coinbase output is
                // ≥546 sats — and commit the survivors to the next block's
                // coinbase. Miners below the dust line (or outside the
                // 1000 cap) keep their ledger and compete again next block.
                //
                // GHOST-02: this MUST go through `select_ledger_miner_work`,
                // the same function every validator recomputes with. The
                // cutoff travels on the proposal (as its timestamp) so that
                // validators reproduce this exact window; a split either side
                // derives any other way is rejected on exact-equality.
                //
                // Shares arriving after this moment belong to the next
                // block's ledger and aren't swept.
                let cutoff_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                // No round-tracker fallback here, deliberately: a validator has no
                // way to know the proposer fell back, so it would recompute from the
                // ledger and reject the split. An empty ledger means nobody is owed —
                // `handle_block_found` then skips submission and the shares (if any
                // are merely late to persist) are swept by the next block instead.
                let miner_work = match ghost_pool::payout::select_ledger_miner_work(
                    &db_for_bf, cutoff_ts, height, subsidy,
                ) {
                    Ok(work) => work,
                    Err(e) => {
                        error!(
                            round = round_id,
                            cutoff_ts,
                            error = %e,
                            "Failed to read unpaid ledger at block-found; no miner payout \
                             this block — unpaid shares roll forward to the next"
                        );
                        Vec::new()
                    }
                };

                let treasury_address_snapshot =
                    payout_for_bf.get_treasury_address_snapshot();

                let block_data = BlockFoundData {
                    round_id,
                    ledger_cutoff_ts: cutoff_ts,
                    block_hash,
                    block_height: height,
                    block_timestamp: chrono::Utc::now(),
                    winning_miner_id: "pool".to_string(),
                    winning_miner_payout_address: Some(block_info.payout_address.clone()),
                    treasury_address_snapshot,
                    winning_node_id,
                    subsidy_sats: subsidy,
                    tx_fees_sats: fees,
                    miner_work,
                    node_shares,
                    treasury_state,
                };

                match payout_for_bf.handle_block_found(block_data) {
                    Ok(proposal_hash) => {
                        if proposal_hash != [0u8; 32] {
                            metrics_for_bf.payouts_total.inc();
                            info!(
                                round = round_id,
                                hash = %hex::encode(&proposal_hash[..8]),
                                "Pre-submission payout proposal submitted for consensus"
                            );
                        }
                    }
                    Err(e) => {
                        metrics_for_bf.payout_errors_total.inc();
                        error!(error = %e, round = round_id, "Failed to create pre-submission payout proposal");
                    }
                }
            }
        });
    }

    // Spawn async payout task: triggers payout proposal creation when a block is
    // submitted to Bitcoin Core via SubmitSolution (channel from TemplateProcessor).
    // This is the SECONDARY path — the primary path is now the block_found callback above.
    // This path handles the case where the block was successfully submitted and we need
    // to create a proposal for the NEXT block's coinbase.
    {
        let rm_for_block = Arc::clone(&round_manager);
        let tp_for_block = Arc::clone(&template_processor);
        let payout_for_block = Arc::clone(&payout_handler);
        let identity_for_block = Arc::clone(&identity);
        let db_for_block = Arc::clone(&db);
        let solo_payout_address_for_block = config.network.solo_payout_address.clone();
        let metrics_for_block = Arc::clone(&metrics);
        let mut block_rx = template_processor
            .take_block_submitted_rx()
            .expect("M-02: block_submitted_rx already taken — startup bug");

        tokio::spawn(async move {
            while let Some(info) = block_rx.recv().await {
                let round_id = rm_for_block.current_round_id();
                let is_solo_mode = rm_for_block.is_solo_mode();

                info!(
                    round = round_id,
                    hash = %hex::encode(&info.block_hash[..8]),
                    height = info.height,
                    solo_mode = is_solo_mode,
                    "Block submitted to Ghost Core, creating payout proposal..."
                );

                // SETTLE THE LEDGER — the coins now exist.
                //
                // This block's coinbase carries the payout named by the snapshot its template
                // was built against, so THIS is the moment the miners in that payout are
                // genuinely paid, and the only safe moment to mark their shares paid.
                //
                // Settling used to happen on consensus approval, which merely arms the coinbase
                // of some future block. A `None` snapshot means this block paid the fallback
                // coinbase and settles nothing.
                if let Some(snapshot) = info.payout_snapshot {
                    match tp_for_block.get_proposal(&snapshot) {
                        Some(paid) => {
                            if let Err(e) = ghost_pool::payout::settle_paid_block(
                                &db_for_block,
                                &paid,
                                PAYOUT_ADDRESS_GROUPING_HEIGHT,
                            ) {
                                error!(
                                    error = %e,
                                    hash = %hex::encode(&snapshot[..8]),
                                    "Failed to settle the ledger for a PAID block — its miners' \
                                     shares remain unpaid and will be swept again next block"
                                );
                            }
                        }
                        None => error!(
                            hash = %hex::encode(&snapshot[..8]),
                            "Block paid a payout proposal we no longer hold; cannot settle the \
                             ledger — those shares will be paid twice unless reconciled"
                        ),
                    }
                } else {
                    warn!(
                        height = info.height,
                        "Block carried the FALLBACK coinbase (no approved payout was armed when \
                         its template was built) — the miners were not paid from this block"
                    );
                }

                // Gather data for payout proposal
                let node_shares = rm_for_block.get_node_shares(round_id);
                let (subsidy, fees, height) = tp_for_block.get_current_block_info();

                // Load treasury state from database
                let treasury_state = match db_for_block.get_treasury_balance() {
                    Ok(balance) => {
                        let threshold_ts = match db_for_block.get_treasury_threshold_reached() {
                            Ok(ts_opt) => ts_opt
                                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
                                .map(|dt| dt.with_timezone(&chrono::Utc)),
                            Err(e) => {
                                warn!(error = %e, "Failed to load treasury threshold timestamp, using None");
                                None
                            }
                        };
                        TreasuryState::from_stored(balance, threshold_ts)
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to load treasury state, using default");
                        TreasuryState::new()
                    }
                };

                let winning_node_id = identity_for_block.node_id();

                if is_solo_mode {
                    let solo_address = match &solo_payout_address_for_block {
                        Some(addr) if !addr.is_empty() => addr.clone(),
                        _ => {
                            error!("Solo mode block found but solo_payout_address not configured!");
                            continue;
                        }
                    };

                    let treasury_address_snapshot =
                        payout_for_block.get_treasury_address_snapshot();

                    let solo_data = SoloBlockFoundData {
                        round_id,
                        block_hash: info.block_hash,
                        block_height: height,
                        block_timestamp: chrono::Utc::now(),
                        solo_payout_address: solo_address,
                        subsidy_sats: subsidy,
                        treasury_address_snapshot,
                        tx_fees_sats: fees,
                        node_shares,
                        treasury_state,
                    };

                    match payout_for_block.handle_solo_block_found(solo_data) {
                        Ok(proposal_hash) => {
                            if proposal_hash != [0u8; 32] {
                                info!(
                                    round = round_id,
                                    hash = %hex::encode(&proposal_hash[..8]),
                                    "Solo mode payout proposal submitted for consensus"
                                );
                            }
                        }
                        Err(e) => {
                            error!(error = %e, round = round_id, "Failed to create solo mode payout proposal");
                        }
                    }
                } else {
                    // Pool mode: ledger-style proportional distribution.
                    //
                    // GHOST-02: the unpaid ledger, NOT this round's work. Every proposal
                    // path must derive its split the same way the validators recompute it
                    // (`select_ledger_miner_work`), or the fleet rejects its own payout.
                    let cutoff_ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let miner_work = match ghost_pool::payout::select_ledger_miner_work(
                        &db_for_block,
                        cutoff_ts,
                        height,
                        subsidy,
                    ) {
                        Ok(work) => work,
                        Err(e) => {
                            error!(
                                round = round_id,
                                cutoff_ts,
                                error = %e,
                                "Failed to read unpaid ledger at block-found; no miner payout \
                                 this block — unpaid shares roll forward to the next"
                            );
                            Vec::new()
                        }
                    };

                    let treasury_address_snapshot =
                        payout_for_block.get_treasury_address_snapshot();

                    let block_data = BlockFoundData {
                        round_id,
                        ledger_cutoff_ts: cutoff_ts,
                        block_hash: info.block_hash,
                        block_height: height,
                        block_timestamp: chrono::Utc::now(),
                        winning_miner_id: "pool".to_string(),
                        winning_miner_payout_address: None,
                        treasury_address_snapshot,
                        winning_node_id,
                        subsidy_sats: subsidy,
                        tx_fees_sats: fees,
                        miner_work,
                        node_shares,
                        treasury_state,
                    };

                    match payout_for_block.handle_block_found(block_data) {
                        Ok(proposal_hash) => {
                            if proposal_hash != [0u8; 32] {
                                metrics_for_block.payouts_total.inc();
                                info!(
                                    round = round_id,
                                    hash = %hex::encode(&proposal_hash[..8]),
                                    "Payout proposal submitted for consensus"
                                );
                            }
                        }
                        Err(e) => {
                            metrics_for_block.payout_errors_total.inc();
                            error!(error = %e, round = round_id, "Failed to create payout proposal");
                        }
                    }
                }
            }
            warn!("Block submission channel closed, payout task exiting");
        });
    }

    // Wire Prometheus metrics to verification state
    verification_state = verification_state.with_metrics(Arc::clone(&metrics));

    let verification_state = Arc::new(verification_state);

    // Build the operator-alert dispatcher now that the state is an `Arc`. Its
    // config closure reads `full_node_config` on every dispatch, so live edits
    // to `[alerts]` via the config API apply without a restart. All async
    // trigger sites below clone this `Arc`; the block_found callback (registered
    // pre-Arc) reads it via `alert_slot`, populated here.
    let alert_dispatcher = {
        let state_for_alerts = Arc::clone(&verification_state);
        Arc::new(ghost_verification::alerts::AlertDispatcher::new(
            verification_state.node_id.clone(),
            move || {
                state_for_alerts
                    .full_node_config
                    .as_ref()
                    .map(|c| c.read().alerts.clone())
                    .unwrap_or_default()
            },
        ))
    };
    let _ = alert_slot.set(Arc::clone(&alert_dispatcher));

    // Register the dispatcher on the verification state so the internal
    // failed-login endpoint (signalled by the dashboard login route) can
    // dispatch the `FailedLogin` alert through the same debouncing dispatcher.
    verification_state.set_alert_dispatcher(Arc::clone(&alert_dispatcher));

    // Get restart signal for monitoring (config update API)
    let restart_signal = verification_state.restart_signal();

    // Start restart signal monitor task
    // When config is updated via API, this triggers graceful shutdown
    let restart_signal_for_monitor = Arc::clone(&restart_signal);
    let shutdown_tx_for_restart = shutdown_tx.clone();
    let alert_dispatcher_for_restart = Arc::clone(&alert_dispatcher);
    let restart_node_id = verification_state.node_id.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            if restart_signal_for_monitor.load(std::sync::atomic::Ordering::SeqCst) {
                info!("Restart signal received (config update). Initiating graceful shutdown...");
                // Fire the RestartNeeded alert BEFORE broadcasting shutdown so
                // the HTTPS delivery isn't cut short by the graceful-exit path.
                // Fires once (the loop breaks immediately after).
                alert_dispatcher_for_restart
                    .fire(
                        ghost_verification::alerts::AlertEvent::RestartNeeded,
                        &format!(
                            "Node {} is restarting to apply a configuration change.",
                            &restart_node_id[..8.min(restart_node_id.len())]
                        ),
                    )
                    .await;
                let _ = shutdown_tx_for_restart.send(());
                break;
            }
        }
    });
    info!("Restart signal monitor started (for config update API)");

    // Start WebSocket health broadcast task
    let ws_state = Arc::clone(&verification_state.ws_state);
    let rm_for_ws = Arc::clone(&round_manager);
    let mesh_for_ws = Arc::clone(&mesh);
    let start_time = std::time::Instant::now();
    let mut ws_shutdown = shutdown_tx.subscribe();
    let alert_dispatcher_for_ws = Arc::clone(&alert_dispatcher);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        // Track the previous peer count so we can alert on a DROP (a decrease),
        // not on every tick. `None` until the first observation.
        let mut last_peer_count: Option<u32> = None;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let miner_count = rm_for_ws
                        .round_stats(rm_for_ws.current_round_id())
                        .map(|s| s.miner_count as u32)
                        .unwrap_or(0);
                    let peer_count = mesh_for_ws.peers().unique_peer_count() as u32;
                    let event = ghost_verification::WsEvent::HealthUpdate {
                        block_height: rm_for_ws.current_height(),
                        round_id: rm_for_ws.current_round_id() as u64,
                        miner_count,
                        peer_count,
                        uptime_secs: start_time.elapsed().as_secs(),
                    };
                    ws_state.broadcast(event);

                    // PeerCountDrop alert: fire when the connected-peer count
                    // decreases. Rate-limited (at most once per 5 min) so a
                    // flapping mesh doesn't spam the operator; delivery + the
                    // enable flag are handled inside the dispatcher.
                    if let Some(prev) = last_peer_count {
                        if peer_count < prev {
                            let detail = format!(
                                "Connected peer count dropped from {prev} to {peer_count}."
                            );
                            alert_dispatcher_for_ws
                                .fire_rate_limited(
                                    ghost_verification::alerts::AlertEvent::PeerCountDrop,
                                    std::time::Duration::from_secs(300),
                                    &detail,
                                )
                                .await;
                        }
                    }
                    last_peer_count = Some(peer_count);
                }
                _ = ws_shutdown.recv() => break,
            }
        }
    });

    // Start the behind-tip monitor. Edge-triggered `BehindTip` alert when this
    // node's local height lags the best connected peer, or the tip stalls while
    // a peer is ahead. Uses the same height/peer plumbing the /health + swarm
    // views read; delivery + the enable flag are handled inside the dispatcher.
    {
        let rm_for_tip = Arc::clone(&round_manager);
        let mesh_for_tip = Arc::clone(&mesh);
        let alerts_for_tip = Arc::clone(&alert_dispatcher);
        ghost_pool::alert_monitors::spawn_behind_tip_monitor(
            alerts_for_tip,
            Arc::clone(&verification_state.chain_health),
            move || rm_for_tip.current_height(),
            move || {
                // Highest L1 height reported by a fresh, connected mesh peer
                // (0 when none is known → the monitor stays silent).
                mesh_for_tip
                    .peers()
                    .get_connected_peers(120)
                    .iter()
                    .map(|p| p.block_height)
                    .max()
                    .unwrap_or(0)
            },
            shutdown_tx.subscribe(),
        );
    }

    // Start the update-available monitor. Rate-limited `UpdateAvailable` alert
    // (at most once/day) when the updater's published latest version is newer
    // than the installed one — same version files the dashboard auto-update
    // view reads.
    ghost_pool::alert_monitors::spawn_update_available_monitor(
        Arc::clone(&alert_dispatcher),
        env!("CARGO_PKG_VERSION").to_string(),
        shutdown_tx.subscribe(),
    );

    // Start the mempool-congestion monitor. Edge-triggered `MempoolCongestion`
    // alert (with hysteresis) when ghostd's mempool `usage` nears `maxmempool`,
    // read via the pool's shared RPC client (`getmempoolinfo`).
    ghost_pool::alert_monitors::spawn_mempool_congestion_monitor(
        Arc::clone(&alert_dispatcher),
        Arc::clone(&rpc),
        shutdown_tx.subscribe(),
    );

    // Start the fee-spike monitor. Rate-limited `FeeSpike` alert when the
    // next-block fee rate (`estimatesmartfee`) crosses an absolute threshold or
    // jumps sharply versus a rolling baseline, read via the same RPC client.
    ghost_pool::alert_monitors::spawn_fee_spike_monitor(
        Arc::clone(&alert_dispatcher),
        Arc::clone(&rpc),
        shutdown_tx.subscribe(),
    );

    // Start pool time-series sampler task.
    // Snapshots the mesh-wide pool hashrate + connected-miner count (the same
    // accessors the /api/v1/mining/status handler reads) into the bounded
    // in-memory ring on VerificationState every 30s, so /api/v1/pool/series can
    // serve real server-side history instead of a client-side session buffer.
    {
        let state_for_series = Arc::clone(&verification_state);
        let rpc_for_series = Arc::clone(&rpc);
        let tp_for_series = Arc::clone(&template_processor);
        let mut series_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let mesh_hashrate_th = state_for_series
                            .mesh_total_hashrate()
                            .or_else(|| state_for_series.local_hashrate())
                            .unwrap_or(0.0);
                        // Local ghostd mempool tx count via the shared RPC client
                        // (0 if the RPC is briefly unavailable).
                        let mempool_txs = rpc_for_series
                            .get_mempool_info()
                            .await
                            .map(|i| i.size)
                            .unwrap_or(0);
                        // Current block template tx count (incl. coinbase); 0 before
                        // the first template is built.
                        let block_txs = tp_for_series
                            .current_work()
                            .map(|w| w.tx_count as u64)
                            .unwrap_or(0);
                        let sample = ghost_verification::pool_series::PoolSample {
                            t: chrono::Utc::now().timestamp(),
                            mesh_hashrate_th,
                            local_hashrate_th: state_for_series.local_hashrate().unwrap_or(0.0),
                            miners: state_for_series.mesh_active_miners().unwrap_or(0),
                            mempool_txs,
                            block_txs,
                        };
                        state_for_series.pool_series.push(sample);
                    }
                    _ = series_shutdown.recv() => break,
                }
            }
        });
        info!("Pool time-series sampler started (30s interval, 24h retention)");
    }

    // Start self-uptime recording task
    // Records our own uptime so we can be qualified for payouts
    // This is necessary because verification results are stored by OTHER nodes about us,
    // but we need our own uptime record for the gatekeeper calculation (95% over 7 days).
    // Without self-recording, this node would have no uptime data ABOUT itself.
    let db_for_uptime = Arc::clone(&db);
    let node_id_for_uptime = identity.node_id_hex();
    let mut uptime_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        let mut sample_count: u64 = 0;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = chrono::Utc::now().timestamp();
                    match db_for_uptime.record_uptime_sample(&node_id_for_uptime, now, true) {
                        Ok(_) => {
                            sample_count += 1;
                            // Log every 360 samples (~1 hour) to confirm it's working
                            if sample_count.is_multiple_of(360) {
                                tracing::debug!(
                                    samples = sample_count,
                                    node_id = %&node_id_for_uptime[..8],
                                    "Self-uptime recording checkpoint"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                node_id = %&node_id_for_uptime[..8],
                                "Failed to record self-uptime sample"
                            );
                        }
                    }
                }
                _ = uptime_shutdown.recv() => {
                    tracing::info!(
                        total_samples = sample_count,
                        "Self-uptime recording task shutting down"
                    );
                    break;
                }
            }
        }
    });
    info!(
        node_id = %&node_id_hex[..8],
        interval_secs = 10,
        "Self-uptime recording task started"
    );

    // Start ban manager cleanup task (C1 security fix)
    // Periodically cleans up expired bans to prevent memory growth
    let ban_manager_for_cleanup = Arc::clone(&ban_manager);
    let mut ban_cleanup_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let removed = ban_manager_for_cleanup.cleanup_expired();
                    if removed > 0 {
                        tracing::debug!(removed, "Cleaned up expired bans");
                    }
                }
                _ = ban_cleanup_shutdown.recv() => {
                    tracing::info!("Ban manager cleanup task shutting down");
                    break;
                }
            }
        }
    });
    info!("Ban manager cleanup task started (60s interval)");

    // Elder offline revocation checker — runs hourly, detects elders offline >7 days
    // and proposes BFT revocation votes (burned slots are never reassigned)
    {
        let db_for_revoke = Arc::clone(&db);
        let vh_for_revoke = Arc::clone(&vote_handler);
        let hh_for_revoke = Arc::clone(&health_handler);
        let mesh_for_revoke = Arc::clone(&mesh);
        let alert_dispatcher_for_revoke = Arc::clone(&alert_dispatcher);
        let mut revoke_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            // Skip immediate first tick
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // 1. Get all current MPC elders from DB
                        let elders = match db_for_revoke.get_all_mpc_elders() {
                            Ok(e) => e,
                            Err(e) => {
                                tracing::warn!(error = %e, "Failed to get elders for revocation check");
                                continue;
                            }
                        };

                        // Convert to NodeId array
                        let elder_ids: Vec<[u8; 32]> = elders.iter().filter_map(|(hex, _)| {
                            hex::decode(hex).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                        }).collect();

                        // 2. Detect which are offline > 7 days
                        let offline = hh_for_revoke.detect_offline_elders(&elder_ids);

                        // NodeOffline alerts: this is the node's only periodic
                        // peer-liveness signal (self can't alert while it's the
                        // one that's down). Edge-trigger per elder so an elder
                        // that stays offline doesn't re-alert every hour, and
                        // re-arm elders that are no longer offline so a later
                        // outage alerts again. Keyed by the offline peer's id.
                        {
                            use std::collections::HashSet;
                            let offline_ids: HashSet<[u8; 32]> =
                                offline.iter().map(|(id, _)| *id).collect();
                            for (elder_hex, _) in &elders {
                                let is_offline = hex::decode(elder_hex)
                                    .ok()
                                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                                    .map(|id| offline_ids.contains(&id))
                                    .unwrap_or(false);
                                let days = offline
                                    .iter()
                                    .find(|(id, _)| hex::encode(id) == *elder_hex)
                                    .map(|(_, d)| *d)
                                    .unwrap_or(0);
                                let detail = format!(
                                    "Elder node {} has been offline for {} day(s).",
                                    &elder_hex[..8.min(elder_hex.len())],
                                    days
                                );
                                alert_dispatcher_for_revoke
                                    .fire_edge(
                                        ghost_verification::alerts::AlertEvent::NodeOffline,
                                        elder_hex,
                                        is_offline,
                                        &detail,
                                    )
                                    .await;
                            }
                        }

                        // 3. For each offline elder, propose revocation vote
                        for (node_id, offline_days) in offline {
                            let node_id_hex = hex::encode(node_id);
                            tracing::info!(
                                target = %&node_id_hex[..8],
                                offline_days,
                                "Detected offline elder, proposing revocation"
                            );

                            match vh_for_revoke.propose_revocation(&node_id_hex, offline_days) {
                                Ok(Some(payload)) => {
                                    // Broadcast the vote
                                    if let Ok(envelope) = mesh_for_revoke.create_envelope_raw(
                                        ghost_consensus::message::MessageType::Vote,
                                        payload,
                                    ) {
                                        if let Err(e) = mesh_for_revoke.broadcast(envelope).await {
                                            tracing::warn!(error = %e, "Failed to broadcast revocation vote");
                                        }
                                    }
                                }
                                Ok(None) => {
                                    tracing::debug!("Revocation proposal skipped (session exists or not enough elders)");
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "Failed to propose elder revocation");
                                }
                            }
                        }
                    }
                    _ = revoke_shutdown.recv() => {
                        tracing::info!("Elder revocation checker shutting down");
                        break;
                    }
                }
            }
        });
        info!("Elder revocation checker started (hourly)");
    }

    // Stale glyph claim cleanup — runs hourly, deletes unfunded claims past their expires_at
    {
        let db_for_glyph_cleanup = Arc::clone(&db);
        let mut glyph_cleanup_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            // Skip immediate first tick
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        match db_for_glyph_cleanup.cleanup_expired_glyph_claims(now) {
                            Ok(0) => {}
                            Ok(n) => {
                                info!(deleted = n, "Cleaned up expired glyph claims");
                            }
                            Err(e) => {
                                warn!(error = %e, "Failed to cleanup expired glyph claims");
                            }
                        }
                    }
                    _ = glyph_cleanup_shutdown.recv() => {
                        break;
                    }
                }
            }
        });
        info!("Glyph claim cleanup task started (hourly)");
    }

    // M-MINE-2: Start rate limit cleanup task for RoundManager
    // Periodically cleans up old rate limit entries to prevent memory growth
    let rm_for_cleanup = Arc::clone(&round_manager);
    let mut rate_limit_cleanup_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    rm_for_cleanup.cleanup_rate_limits();
                }
                _ = rate_limit_cleanup_shutdown.recv() => {
                    tracing::info!("Rate limit cleanup task shutting down");
                    break;
                }
            }
        }
    });
    info!("Rate limit cleanup task started (60s interval)");

    // Dedup cache cleanup — evict expired seen messages every 60s
    let mesh_for_dedup_cleanup = Arc::clone(&mesh);
    let mut dedup_cleanup_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    mesh_for_dedup_cleanup.cleanup_seen_messages(300);
                }
                _ = dedup_cleanup_shutdown.recv() => {
                    tracing::info!("Dedup cache cleanup task shutting down");
                    break;
                }
            }
        }
    });
    info!("Dedup cache cleanup task started (60s interval, 5min TTL)");

    // Noise connection pool cleanup — evict stale connections every 60s
    if let Some(noise_pool) = mesh.noise_pool() {
        let pool_for_cleanup = Arc::clone(noise_pool);
        let mut noise_cleanup_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        pool_for_cleanup.cleanup_stale();
                    }
                    _ = noise_cleanup_shutdown.recv() => {
                        tracing::info!("Noise pool cleanup task shutting down");
                        break;
                    }
                }
            }
        });
        info!("Noise pool cleanup task started (60s interval)");
    }

    // Periodic share pruning — delete shares older than 24 hours, run every hour
    let db_for_pruning = Arc::clone(&db);
    let mut share_prune_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        const PRUNE_INTERVAL_SECS: u64 = 3600;
        const SHARE_RETENTION_SECS: i64 = 24 * 3600;

        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(PRUNE_INTERVAL_SECS));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match db_for_pruning.delete_old_shares(SHARE_RETENTION_SECS) {
                        Ok(0) => {}
                        Ok(count) => {
                            tracing::info!(deleted = count, "Pruned old shares from database");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to prune old shares");
                        }
                    }
                }
                _ = share_prune_shutdown.recv() => {
                    tracing::info!("Share pruning task shutting down");
                    break;
                }
            }
        }
    });
    info!("Share pruning task started (hourly, 24h retention)");

    // Periodic database maintenance — prune health_pings, uptime_samples, challenges,
    // verifications, votes + WAL checkpoint + VACUUM. Runs every hour.
    let db_for_maintenance = Arc::clone(&db);
    let mut maintenance_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        const MAINTENANCE_INTERVAL_SECS: u64 = 3600;

        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(MAINTENANCE_INTERVAL_SECS));
        // Skip the first immediate tick — let the node fully start up first
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let config = ghost_storage::database::MaintenanceConfig::default();
                    match db_for_maintenance.run_maintenance(config) {
                        Ok(result) => {
                            tracing::info!(
                                rounds = result.rounds_deleted,
                                pings = result.pings_deleted,
                                votes = result.votes_deleted,
                                uptime = result.uptime_deleted,
                                challenges = result.challenges_deleted.total(),
                                verifications = result.verifications_deleted,
                                checkpoints = result.checkpoints_pruned,
                                db_size_mb = result.db_size_bytes / (1024 * 1024),
                                "Database maintenance complete"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Database maintenance failed");
                        }
                    }
                }
                _ = maintenance_shutdown.recv() => {
                    tracing::info!("Database maintenance task shutting down");
                    break;
                }
            }
        }
    });
    info!("Database maintenance task started (hourly)");

    // M5: Daily database backup task
    let db_for_backup = Arc::clone(&db);
    let backup_dir = data_dir.clone();
    let mut backup_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        const BACKUP_INTERVAL_SECS: u64 = 86400; // 24 hours

        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(BACKUP_INTERVAL_SECS));
        // Skip first immediate tick — let node start fully first
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let backup_path = backup_dir.join("ghost_backup.db");
                    match db_for_backup.backup(&backup_path) {
                        Ok(()) => {
                            tracing::info!(path = ?backup_path, "Daily database backup complete");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Daily database backup failed");
                        }
                    }
                }
                _ = backup_shutdown.recv() => {
                    tracing::info!("Database backup task shutting down");
                    break;
                }
            }
        }
    });
    info!("Database backup task started (daily)");

    // Automatic scheduled encrypted-backup task. Secure-by-default: it idles and
    // writes nothing until an operator enables `[backup]` in pool.toml (or via
    // the dashboard). When enabled it reuses the SAME `Database::backup`
    // (VACUUM INTO) routine the manual backup uses — so the artifact inherits
    // the database's SQLCipher encryption — writing a timestamped file into the
    // configured target dir, pruning to `retention`, and recording last-run
    // status for the dashboard. The live schedule is re-read from the shared
    // full_node_config each tick, so enable/interval/retention/target_dir edits
    // take effect without a node restart.
    {
        let db_for_sched = Arc::clone(&db);
        let state_for_sched = Arc::clone(&verification_state);
        let mut sched_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            // Coarse poll cadence: the loop wakes on this fixed interval and only
            // runs a backup once the configured period has elapsed. 60s keeps the
            // task off any hot path while still honouring hourly custom periods.
            const CHECK_SECS: u64 = 60;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(CHECK_SECS));
            // Let the node finish starting before the first check/run.
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Snapshot the live schedule (may have changed via the API).
                        let schedule = match state_for_sched.full_node_config.as_ref() {
                            Some(cfg) => cfg.read().backup.clone(),
                            None => continue,
                        };
                        if !schedule.enabled {
                            continue;
                        }
                        let now_unix = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let last_run = state_for_sched.backup_status.read().last_run_unix;
                        if !ghost_common::config::backup_is_due(
                            last_run,
                            now_unix,
                            schedule.interval.period_secs(),
                        ) {
                            continue;
                        }

                        let target_dir = std::path::PathBuf::from(&schedule.target_dir);
                        let filename =
                            ghost_common::config::BackupSchedule::artifact_filename(now_unix);
                        let backup_path = target_dir.join(&filename);
                        let retention = schedule.effective_retention();

                        // Blocking DB + filesystem work off the async worker.
                        let db_run = Arc::clone(&db_for_sched);
                        let dir_run = target_dir.clone();
                        let path_run = backup_path.clone();
                        let result = tokio::task::spawn_blocking(
                            move || -> Result<(), String> {
                                std::fs::create_dir_all(&dir_run)
                                    .map_err(|e| format!("create target dir: {e}"))?;
                                db_run.backup(&path_run).map_err(|e| e.to_string())?;
                                // Prune old artifacts down to the retention window.
                                let mut names: Vec<String> = Vec::new();
                                if let Ok(entries) = std::fs::read_dir(&dir_run) {
                                    for entry in entries.flatten() {
                                        if let Some(name) = entry.file_name().to_str() {
                                            if name.starts_with("ghost-backup-")
                                                && name.ends_with(".db")
                                            {
                                                names.push(name.to_string());
                                            }
                                        }
                                    }
                                }
                                for stale in ghost_common::config::backups_to_prune(
                                    names, retention,
                                ) {
                                    let _ = std::fs::remove_file(dir_run.join(stale));
                                }
                                Ok(())
                            },
                        )
                        .await;

                        let finished_unix = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(now_unix);
                        let mut status = state_for_sched.backup_status.write();
                        status.last_run_unix = Some(finished_unix);
                        match result {
                            Ok(Ok(())) => {
                                status.last_success = Some(true);
                                status.last_path =
                                    Some(backup_path.to_string_lossy().to_string());
                                status.last_error = None;
                                tracing::info!(
                                    path = ?backup_path,
                                    "Scheduled encrypted backup complete"
                                );
                            }
                            Ok(Err(e)) => {
                                status.last_success = Some(false);
                                status.last_error = Some(e.clone());
                                tracing::warn!(error = %e, "Scheduled backup failed");
                            }
                            Err(e) => {
                                let msg = format!("backup task join error: {e}");
                                status.last_success = Some(false);
                                status.last_error = Some(msg.clone());
                                tracing::warn!(error = %msg, "Scheduled backup task failed");
                            }
                        }
                    }
                    _ = sched_shutdown.recv() => {
                        tracing::info!("Scheduled backup task shutting down");
                        break;
                    }
                }
            }
        });
        info!("Scheduled encrypted-backup task started (idle until enabled)");
    }

    // Clone ws_state for event handlers before moving verification_state
    let _verification_state_for_ws = Arc::clone(&verification_state);

    let http_port = config.network.http_port;
    let verification_https_port = config.network.verification_https_port;
    // Build TLS config for the verification HTTPS listener. Resolution order:
    //   1. Operator-managed PEM files (`tls.cert_path` + `tls.key_path`)
    //   2. Identity-derived cert (cert pubkey == node_id; mainnet-allowed)
    //   3. Random self-signed (testnet/dev only)
    //
    // Plain HTTP on `http_port` is ALWAYS bound — it serves SRI's share
    // webhook (loopback), nginx public-API upstream, and the local dashboard.
    // TLS is added on a SEPARATE listener (`verification_https_port`) used
    // only by cross-VM peer challenges, so SRI/nginx/dashboard never see TLS.
    let has_explicit_tls = config.network.tls.cert_path.is_some();
    let is_mainnet_tls = config.bitcoin.network == ghost_common::config::BitcoinNetwork::Mainnet;
    // Identity-derived TLS works only with LocalSigner; HSM/KMS need operator PEMs.
    let identity_secret_for_tls: Option<[u8; 32]> = identity
        .signer()
        .as_any()
        .downcast_ref::<ghost_common::signer::LocalSigner>()
        .map(|s| s.signing_key_bytes());

    let tls_server_config = if has_explicit_tls {
        match ghost_common::tls::build_server_config_for_network(
            &config.network.tls,
            is_mainnet_tls,
        ) {
            Ok(tls) => {
                info!(
                    "TLS configured (operator PEM) for verification server on port {}",
                    http_port
                );
                Some(tls)
            }
            Err(e) => {
                error!(
                    error = %e,
                    "Operator PEM TLS load failed; verification mesh will not start cleanly"
                );
                None
            }
        }
    } else if let Some(secret) = identity_secret_for_tls {
        match ghost_common::tls::build_server_config_with_identity(
            &config.network.tls,
            &secret,
            config.network.public_address.as_deref(),
        ) {
            Ok(tls) => {
                info!(
                    "TLS configured (identity-derived, cert pubkey = node_id) on port {}",
                    http_port
                );
                Some(tls)
            }
            Err(e) => {
                error!(
                    error = %e,
                    "Identity-derived TLS build failed; falling back to plain HTTP"
                );
                None
            }
        }
    } else if is_mainnet_tls {
        // HSM/KMS without operator PEMs is a misconfiguration on mainnet.
        match ghost_common::tls::build_server_config_for_network(
            &config.network.tls,
            is_mainnet_tls,
        ) {
            Ok(tls) => Some(tls),
            Err(e) => {
                error!(
                    error = %e,
                    "Mainnet TLS unavailable: HSM/KMS signers must supply tls.cert_path + tls.key_path"
                );
                None
            }
        }
    } else {
        info!("No TLS configured — verification HTTPS listener will not start");
        None
    };

    // Always bind plain HTTP on `http_port`. Loopback-only consumers (SRI
    // share webhook on 127.0.0.1, nginx public-API upstream, the local
    // dashboard) all expect plain HTTP and have no TLS-skip-verify escape
    // hatch. Cross-VM peer challenges use the HTTPS listener below instead.
    let state_for_http = Arc::clone(&verification_state);
    tokio::spawn(async move {
        if let Err(e) = start_server(state_for_http, http_port, None).await {
            error!(error = %e, "Verification HTTP server error (port {})", http_port);
        }
    });
    info!("HTTP API listening on port {} (plain HTTP)", http_port);

    // Additionally bind HTTPS on `verification_https_port` for the inter-peer
    // verification mesh — only the verification client uses this port. Cert
    // is identity-derived (pubkey == node_id), peers pin against the
    // registered node_id, no CA / DNS / Let's Encrypt required.
    let https_verification_listening = tls_server_config.is_some();
    if let Some(tls) = tls_server_config {
        let state_for_https = Arc::clone(&verification_state);
        tokio::spawn(async move {
            if let Err(e) = start_server(state_for_https, verification_https_port, Some(tls)).await
            {
                error!(
                    error = %e,
                    "Verification HTTPS server error (port {})",
                    verification_https_port
                );
            }
        });
        info!(
            "Verification HTTPS listening on port {} (identity-pinned TLS for peer mesh)",
            verification_https_port
        );
    }

    // Phase 3: capability self-check loop. Probes prerequisites for each
    // claimed capability (stratum ports, disk space, ghost-pay daemon,
    // reaper config) every 30s. Diagnostic only — surfaced via the dashboard
    // (`/api/v1/system/self-check`) and `/health/self_check`. Does not
    // auto-demote claims; the verification mesh catches false claims at the
    // consensus layer. `self_check` was constructed earlier so the HTTP
    // handler shares this exact snapshot; here we start its probe loop.
    // Pass the alert dispatcher so the self-check loop fires CapabilityDrift
    // (a claimed capability's prerequisite regressing pass→fail) and LowDisk
    // (data partition crossing the low-free threshold) as edge-triggered alerts.
    self_check.clone().spawn_loop(
        Arc::new(config.clone()),
        Some(Arc::clone(&alert_dispatcher)),
    );
    info!("Capability self-check loop started (30s interval)");

    // Subscribe to template events BEFORE starting the processor to avoid race condition
    // (the processor fires NewWork immediately on first refresh)
    let mut template_events_early = template_processor.subscribe();

    // Start template processor
    let tp = Arc::clone(&template_processor);
    let mut template_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            result = tp.start() => {
                if let Err(e) = result {
                    error!(error = %e, "Template processor error");
                }
            }
            _ = template_shutdown.recv() => {}
        }
    });
    info!("Template processor started");

    // Note: Native stratum server removed - SRI handles all miner connections via TDP

    // Start Template Distribution Protocol server (for SRI pool integration)
    if args.tdp_enabled {
        // Load node key bytes for TDP Noise authentication
        // The key file contains 32 bytes of private key (+ optional 12 bytes PoW proof)
        let key_path = data_dir.join("node.key");
        let key_bytes = std::fs::read(&key_path)
            .map_err(|e| anyhow::anyhow!("Failed to read node key for TDP: {}", e))?;

        // HIGH-6: Proper error handling instead of panic on short key file
        if key_bytes.len() < 32 {
            return Err(anyhow::anyhow!(
                "Node key file '{}' is too short: expected at least 32 bytes, got {}. \
                 Generate a new key with: ghost-pool --generate-identity",
                key_path.display(),
                key_bytes.len()
            ));
        }
        let tdp_secret_key: [u8; 32] = key_bytes[..32]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Node key slice conversion failed"))?;

        // L-26: Use proper error handling instead of expect()
        let mut tdp_config = TdpConfig::new(tdp_secret_key).map_err(|e| {
            anyhow::anyhow!(
                "L-26: Invalid TDP secret key from node key file '{}': {}. \
                 The key may be all zeros or outside the valid secp256k1 scalar range. \
                 Regenerate with: ghost-pool --generate-identity",
                key_path.display(),
                e
            )
        })?;
        tdp_config.port = args.tdp_port;
        tdp_config.max_connections = 10;
        tdp_config.timeout_secs = 30;

        info!(
            "TDP authority public key: {} (use this in SRI pool config)",
            tdp_config.authority_pubkey_base58()
        );

        let tdp_server = TemplateDistributionServer::new(
            tdp_config,
            Arc::clone(&template_processor),
            shutdown_tx.subscribe(),
        );

        tokio::spawn(async move {
            if let Err(e) = tdp_server.run().await {
                error!(error = %e, "TDP server error");
            }
        });

        info!(
            "TDP server listening on port {} (Template Distribution Protocol for SRI pool)",
            args.tdp_port
        );
    }

    // Start P2P mesh
    let m = Arc::clone(&mesh);
    tokio::spawn(async move {
        if let Err(e) = m.start().await {
            error!(error = %e, "Mesh network error");
        }
    });
    info!("P2P mesh network started");

    // C-1: Start the Noise Protocol RECEIVE listener for encrypted P2P.
    // The accept/handshake/dispatch loop now lives in MeshNetwork
    // (`run_noise_listener`) so the receive side of the Noise plane is owned and
    // tested alongside the send side, instead of being hand-rolled here.
    if mesh.noise_pool().is_some() {
        let mesh_for_noise = Arc::clone(&mesh);
        let noise_shutdown = shutdown_tx.subscribe();
        let noise_is_mainnet = is_mainnet_round;
        tokio::spawn(async move {
            mesh_for_noise
                .run_noise_listener(noise_is_mainnet, noise_shutdown)
                .await;
        });
    } else {
        warn!("Noise Protocol DISABLED - P2P traffic is unencrypted");
    }

    // Bootstrap peer connections from seed nodes
    if !config.network.seed_nodes.is_empty() {
        let mesh_bootstrap = Arc::clone(&mesh);
        let seed_nodes = config.network.seed_nodes.clone();
        let discovery_for_bootstrap = Arc::clone(&discovery_handler);
        tokio::spawn(async move {
            // Wait a moment for mesh to fully start
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            for seed in &seed_nodes {
                info!(seed = %seed, "Connecting to seed node");
                // Add seed to discovery handler's known peers
                discovery_for_bootstrap.add_known_peer([0u8; 32], seed.clone());
                if let Err(e) = mesh_bootstrap.connect_peer(seed).await {
                    warn!(seed = %seed, error = %e, "Failed to connect to seed node");
                }
            }
        });
    }

    // Start periodic discovery broadcast task
    // This gossips our known peers to other nodes every 30 seconds
    //
    // L-15 SECURITY NOTE: Discovery broadcasts are intentionally unauthenticated
    //
    // Discovery messages are sent over ZMQ PUB/SUB without encryption because:
    //
    // 1. **Bootstrap Problem**: Nodes need to discover peers before they can
    //    establish authenticated connections. Requiring authentication for
    //    discovery would create a chicken-and-egg problem.
    //
    // 2. **Defense in Depth via Noise Authentication**: After discovering a peer,
    //    all sensitive communication (shares, blocks, votes, payouts) is sent
    //    over Noise Protocol encrypted channels (port 8563). An attacker who
    //    injects false discovery messages cannot:
    //    - Receive shares or blocks (encrypted to real node's Noise key)
    //    - Cast votes (requires cryptographic identity proof)
    //    - Modify payouts (BFT consensus with signed votes)
    //
    // 3. **Address Validation**: Discovery handler validates that advertised
    //    addresses are valid IPs (not domains), non-reserved, and haven't been
    //    claimed by another node (H-P2P-4 address hijacking protection).
    //
    // 4. **Rate Limiting**: Discovery messages are rate-limited per sender to
    //    prevent flooding attacks (M-8).
    //
    // 5. **Signature Verification**: While broadcast is unauthenticated,
    //    discovery messages include the sender's signature. The handler verifies
    //    this signature before processing (M-3 defense-in-depth).
    //
    // The worst case for a discovery attacker is wasting CPU on connection
    // attempts to non-existent or malicious endpoints, which is mitigated by
    // the Noise handshake timeout and connection backoff.
    let mesh_for_discovery = Arc::clone(&mesh);
    let discovery_for_broadcast = Arc::clone(&discovery_handler);
    let mut discovery_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        // Wait for mesh to establish connections
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Get the discovery message with our known peers
                    let discovery_msg = discovery_for_broadcast.get_discovery_message();

                    // Broadcast it
                    match mesh_for_discovery
                        .broadcast_message(ghost_consensus::MessageType::Discovery, &discovery_msg)
                        .await
                    {
                        Ok(sent) => {
                            if sent > 0 {
                                tracing::debug!(
                                    sent = sent,
                                    known_peers = discovery_msg.known_peers.len(),
                                    "Broadcast discovery message"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "Failed to broadcast discovery");
                        }
                    }
                }
                _ = discovery_shutdown.recv() => {
                    tracing::info!("Discovery broadcast task shutting down");
                    break;
                }
            }
        }
    });

    // Start periodic verification task (verifies peer capabilities every 5 minutes)
    // This implements the spec: nodes verify each other, results stored in DB for payout calculation.
    //
    // The peer_provider's `http_port` becomes the port the verification client
    // connects to on each peer. When the local HTTPS listener bound, peers also
    // expose the same HTTPS listener (per protocol), so we target their
    // `verification_https_port`. Otherwise fall back to plain HTTP on
    // `http_port`.
    let peer_challenge_port = if https_verification_listening {
        config.network.verification_https_port
    } else {
        config.network.http_port
    };
    let peer_provider = Arc::new(PeerProviderAdapter::new(
        Arc::clone(mesh.peers()),
        peer_challenge_port,
    ));

    // Create broadcast channel for verification results
    let (verification_tx, mut verification_rx) =
        ghost_verification::task::verification_broadcast_channel(100);

    // C-3: Handle Result from VerificationTask::new() instead of panicking
    // Mainnet uses identity-pinned TLS (cert pubkey == node_id, no CA chain).
    // Signet/testnet falls back to plain HTTP for ease of dev iteration.
    let is_mainnet = config.bitcoin.network == ghost_common::config::BitcoinNetwork::Mainnet;
    let verification_result = if is_mainnet {
        // Build the pubkey allow list backed by the live peer registry. The
        // closure clones the Arc<PeerManager> so it can be consulted at every
        // TLS handshake without holding any lock outside the call.
        let peer_mgr_for_pinning = Arc::clone(mesh.peers());
        let pubkey_allow: ghost_common::tls::PubkeyAllowList =
            Arc::new(move |pubkey: &[u8; 32]| peer_mgr_for_pinning.get_peer(pubkey).is_some());
        VerificationTask::new_with_identity_pinned(
            Arc::clone(&db),
            &identity,
            peer_provider as Arc<dyn PeerProvider>,
            pubkey_allow,
        )
    } else {
        // Signet/testnet: Use HTTP since TLS is typically not configured
        VerificationTask::new_for_signet(
            Arc::clone(&db),
            &identity,
            peer_provider as Arc<dyn PeerProvider>,
        )
    };
    match verification_result {
        Ok(verification_task) => {
            let verification_task = verification_task
                .with_rpc(Arc::clone(&rpc))
                .with_policy(policy.clone())
                .with_broadcast(verification_tx);

            let mut verification_shutdown = shutdown_tx.subscribe();
            tokio::spawn(async move {
                // Wait for mesh to establish connections before starting verification
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                tokio::select! {
                    _ = verification_task.run() => {}
                    _ = verification_shutdown.recv() => {
                        tracing::info!("Verification task shutting down");
                    }
                }
            });
            info!("Verification task started (5 minute interval)");
        }
        Err(e) => {
            error!(error = %e, "Failed to create verification task - verification disabled");
        }
    }

    // Start verification result broadcaster (sends results to other nodes via P2P)
    let mesh_for_verification = Arc::clone(&mesh);
    let identity_for_verification = Arc::clone(&identity);
    let db_for_verification = Arc::clone(&db);
    tokio::spawn(async move {
        use ghost_consensus::message::{CapabilityType, MessageType, VerificationResultMessage};

        while let Some(broadcast) = verification_rx.recv().await {
            let target_short = hex::encode(&broadcast.target_node_id[..4]);
            let challenger_short = hex::encode(&broadcast.challenger_id[..4]);

            info!(
                target = %target_short,
                challenger = %challenger_short,
                capability = %broadcast.capability,
                passed = broadcast.passed,
                "DIAG: Broadcasting verification result to P2P mesh"
            );

            // Convert the capability to the message enum
            let capability = match broadcast.capability.as_str() {
                "archive" => CapabilityType::Archive,
                "policy" => CapabilityType::Policy,
                "stratum" => CapabilityType::Stratum,
                "ghostpay" => CapabilityType::GhostPay,
                other => {
                    warn!(capability = %other, "Unknown capability type, skipping broadcast");
                    continue;
                }
            };

            // Sign the verification result
            let mut signing_data = Vec::new();
            signing_data.extend_from_slice(&broadcast.target_node_id);
            signing_data.extend_from_slice(broadcast.capability.as_bytes());
            signing_data.push(if broadcast.passed { 1 } else { 0 });
            signing_data.extend_from_slice(&broadcast.timestamp.to_le_bytes());
            let signature = identity_for_verification.sign(&signing_data);

            let msg = VerificationResultMessage {
                target_node_id: broadcast.target_node_id,
                challenger_id: broadcast.challenger_id,
                capability,
                passed: broadcast.passed,
                timestamp: broadcast.timestamp,
                challenge_data: broadcast.challenge_data,
                response_data: broadcast.response_data,
                target_signed_response: broadcast.target_signed_response,
                signature,
            };

            // Retain OUR OWN signed verdict in the convergence ledger, so a node's own challenges
            // enter its ledger immediately rather than only via a convergence round-trip from a
            // peer that happened to receive this broadcast. Same authoritative source the receive
            // path stores (the signed message blob); the distinct-challenger majority at
            // qualification still governs the verdict.
            match serde_json::to_vec(&msg) {
                Ok(blob) => {
                    if let Err(e) = db_for_verification.insert_verification_proof(
                        &hex::encode(msg.challenger_id),
                        &hex::encode(msg.target_node_id),
                        broadcast.capability.as_str(),
                        msg.passed,
                        msg.timestamp,
                        &blob,
                    ) {
                        warn!(error = %e, "Failed to persist own verification proof to ledger");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to serialize own verification result for ledger")
                }
            }

            // Get peer count before broadcast for logging
            let peer_count = mesh_for_verification.peers().peer_count();
            let connected_count = mesh_for_verification.peers().connected_count();

            match mesh_for_verification
                .broadcast_message(MessageType::VerificationResult, &msg)
                .await
            {
                Ok(sent) => {
                    info!(
                        target = %target_short,
                        capability = %broadcast.capability,
                        passed = broadcast.passed,
                        sent_to = sent,
                        peer_entries = peer_count,
                        zmq_connections = connected_count,
                        "DIAG: Verification result broadcast complete"
                    );
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        target = %target_short,
                        capability = %broadcast.capability,
                        peer_count = peer_count,
                        connected_count = connected_count,
                        "DIAG: Failed to broadcast verification result"
                    );
                }
            }
        }
    });
    info!("Verification result broadcaster started");

    // Start ZMQ block watcher with reorg detection (if configured)
    if let Some(ref zmq_endpoint) = config.bitcoin.zmq_hashblock {
        let rm = Arc::clone(&round_manager);
        let tp = Arc::clone(&template_processor);

        // Use ZmqSubscriber for both block notifications and reorg detection
        // Derive sequence endpoint from hashblock (28332 -> 28334 typically)
        let sequence_endpoint = config.bitcoin.zmq_sequence.clone().or_else(|| {
            // Auto-derive sequence endpoint: tcp://127.0.0.1:28332 -> tcp://127.0.0.1:28334
            zmq_endpoint.replace(":28332", ":28334").into()
        });

        let zmq_config = ZmqConfig {
            hashblock_endpoint: Some(zmq_endpoint.clone()),
            hashtx_endpoint: None,
            rawblock_endpoint: None,
            rawtx_endpoint: None,
            sequence_endpoint: sequence_endpoint.clone(),
        };

        let zmq_subscriber = ZmqSubscriber::new(zmq_config).map_err(|e| {
            anyhow::anyhow!(
                "ZMQ security validation failed: {}. Only localhost endpoints are allowed.",
                e
            )
        })?;
        let mut block_rx = zmq_subscriber.subscribe_blocks();

        // Start block event handler for new blocks
        tokio::spawn(async move {
            while let Ok(block_hash) = block_rx.recv().await {
                info!(hash = %block_hash, "New block detected via ZMQ");

                // End current round
                if let Some(summary) = rm.end_round() {
                    info!(
                        round = summary.round_id,
                        miners = summary.miner_count,
                        work = summary.total_miner_work,
                        "Round ended"
                    );
                }

                // Fast changeover: publish a coinbase-only (empty) template for
                // the new tip immediately so SV1/SV2 miners start hashing the new
                // block with zero transaction-assembly latency, then build and
                // swap in the full template. A block found in the sub-second gap
                // is a valid empty block (subsidy only).
                if let Err(e) = tp.publish_empty_template().await {
                    warn!(error = %e, "Failed to publish empty template on new block");
                }
                // Full template (forced — the empty one already bumped the height).
                if let Err(e) = tp.refresh_template_forced().await {
                    error!(error = %e, "Failed to refresh full template on new block");
                }
            }
        });

        // Start reorg handler (subscribes to block disconnect events). Wire the
        // operator-alert dispatcher so the existing reorg-detection point also
        // fires a `ReorgDetected` alert (gated on the operator's event flag).
        let block_events = zmq_subscriber.subscribe_block_events();
        let rm_for_reorg = Arc::clone(&round_manager);
        let reorg_handler = ReorgHandler::new(Arc::clone(&db), ReorgConfig::default())
            .with_vote_handler(Arc::clone(&vote_handler))
            .with_alert_dispatcher(Arc::clone(&alert_dispatcher))
            // Record each detected reorg into the shared chain-health ring so the
            // Sync page's Chain Health view can display it (not just alert).
            .with_chain_health(Arc::clone(&verification_state.chain_health))
            .with_height_getter(move || rm_for_reorg.current_height());
        reorg_handler.start(block_events);

        info!("ZMQ block watcher connected to {}", zmq_endpoint);
        if let Some(seq_ep) = sequence_endpoint {
            info!("ZMQ reorg detection connected to {}", seq_ep);
        }

        // H-8 SECURITY: Store ZMQ subscriber in static OnceLock instead of leaking via mem::forget.
        // This keeps it alive for the program lifetime while allowing proper cleanup on exit.
        if ZMQ_SUBSCRIBER.set(zmq_subscriber).is_err() {
            warn!("ZMQ subscriber already initialized - this should not happen");
        }
    }

    // Handle template events for round management
    // (subscription was created earlier before template processor started)
    // Note: Job notifications to miners now handled by SRI via TDP
    let rm_notify = Arc::clone(&round_manager);
    let tp_for_template_events = Arc::clone(&template_processor);
    // Persist each round at start so the `rounds` table carries its block
    // height. The best-hash per-window queries LEFT JOIN rounds to resolve a
    // share's block height; previously rounds were only ever written by the
    // payout path (block-found), which almost never fires, so every per-window
    // best share reported a null block height.
    let db_for_rounds = Arc::clone(&db);
    // Coordinator-election recompute hook (read-only). `None` when the feature
    // is off → the recompute below is skipped entirely.
    let coord_for_events = coordinator_election.clone();
    // Activation supervisor — reconciled against the election so an elected node
    // runs the coordinator (and a node that lost its seat stops). `None` when
    // role activation is off.
    let supervisor_for_events = coordinator_supervisor.clone();
    // Tip-change payout proposal: arms the coinbase BEFORE a block is won.
    let payout_for_tips = Arc::clone(&payout_handler);
    let identity_for_tips = Arc::clone(&identity);
    // The vote handler validates a payout proposal's block height against the current tip
    // (a +/-1000 block window). It needs to be told the tip advances, or that check runs
    // against height 0 and falls back to a permissive default — see below.
    let vote_handler_for_tips = Arc::clone(&vote_handler);

    tokio::spawn(async move {
        // The last chain height we proposed a payout for. `NewWork` fires on every template
        // refresh (~30s), but the tip only moves on a new block, and a payout is per-block.
        let mut last_proposed_height: u64 = 0;

        while let Ok(event) = template_events_early.recv().await {
            match event {
                TemplateEvent::NewWork { job_id: _, height } => {
                    // Start new round (SRI gets jobs via TDP automatically)
                    let round_id = rm_notify.start_round(height);

                    // Tell the vote handler the chain has advanced — feeds the payout-proposal
                    // height window (`known_best_height +/- 1000`); it was never called, so the
                    // handler's height sat at 0 and the window check never constrained anything.
                    vote_handler_for_tips.update_block_height(height);

                    // TIP-CHANGE PAYOUT: propose and ratify the coinbase for the block being
                    // worked on, BEFORE anyone wins it.
                    //
                    // A block's coinbase is fixed when its template is built — the header
                    // commits to it — so it can only pay a payout that was already approved.
                    // Proposals were previously created ONLY on block-found, which means the
                    // approved payout always lagged one win behind. With `approved_payout`
                    // starting at None and the pool never yet having won, EVERY template carried
                    // the fallback coinbase: the first block Ghost ever won would have paid its
                    // entire subsidy to `pool_payout_address` and its miners nothing.
                    //
                    // Ratifying at each tip keeps a fresh, mesh-agreed split armed at all times,
                    // built from the unpaid ledger as of this tip. Safe only because the ledger
                    // is settled when a block PAYS (see `payout::settle_paid_block`), not when a
                    // proposal is approved — otherwise this would wipe the ledger every tip while
                    // paying nobody.
                    // Gated on FEE_TO_NODE_POOL_HEIGHT, and it must be: below that gate the
                    // coinbase still carries a TX-fee output addressed to the block FINDER, and
                    // at tip change nobody has found the block yet. A pre-gate tip proposal would
                    // have to name a finder it cannot know, handing that block's fees to whichever
                    // node's turn it happened to be. Routing fees to the node reward pool is what
                    // removes the last unknown from the coinbase and makes it ratifiable early.
                    if height >= ghost_pool::fee_to_node_pool_height()
                        && height > last_proposed_height
                    {
                        last_proposed_height = height;

                        // Deterministic proposer: every node computes the same answer from the
                        // MPC elder set with no coordination, and the load rotates. Without this,
                        // all 8 nodes would propose the same payout at every tip.
                        let mut elders: Vec<[u8; 32]> = db_for_rounds
                            .get_mpc_elder_node_ids()
                            .unwrap_or_default()
                            .into_iter()
                            .collect();
                        elders.sort_unstable();

                        let me = identity_for_tips.node_id();
                        let my_turn =
                            !elders.is_empty() && elders[(height as usize) % elders.len()] == me;

                        if my_turn {
                            // The tip we are building on. Every node agrees on it, and
                            // PO4-M1 rejects a zero block hash — there is no block hash yet
                            // because the block does not exist, so the tip identifies the
                            // payout instead.
                            match rm_notify.current_template_id() {
                                Some(tip) => {
                                    let cutoff_ts = chrono::Utc::now().timestamp();
                                    // `None` matches what `validate_block_data` uses to compute
                                    // the expected subsidy — pass anything else and the proposal
                                    // fails its own validation.
                                    let subsidy =
                                        ghost_common::rpc::calculate_block_subsidy(height, None);

                                    match ghost_pool::payout::select_ledger_miner_work(
                                        &db_for_rounds,
                                        cutoff_ts,
                                        height,
                                        subsidy,
                                    ) {
                                        Ok(miner_work) if !miner_work.is_empty() => {
                                            let (_, fees, _) =
                                                tp_for_template_events.get_current_block_info();
                                            let treasury_state = TreasuryState::from_stored(
                                                db_for_rounds
                                                    .get_treasury_balance()
                                                    .unwrap_or_default(),
                                                None,
                                            );
                                            let treasury_address_snapshot =
                                                payout_for_tips.get_treasury_address_snapshot();

                                            let data = BlockFoundData {
                                                round_id,
                                                ledger_cutoff_ts: cutoff_ts,
                                                block_hash: tip,
                                                block_height: height,
                                                block_timestamp: chrono::Utc::now(),
                                                winning_miner_id: "pool".to_string(),
                                                winning_miner_payout_address: None,
                                                treasury_address_snapshot,
                                                // Post-gate there is no block-finder fee output,
                                                // so this identifies the proposer for bookkeeping
                                                // only — it receives nothing on account of it.
                                                winning_node_id: me,
                                                subsidy_sats: subsidy,
                                                tx_fees_sats: fees,
                                                miner_work,
                                                node_shares: rm_notify.get_node_shares(round_id),
                                                treasury_state,
                                            };

                                            match payout_for_tips.handle_block_found(data) {
                                                Ok(hash) if hash != [0u8; 32] => info!(
                                                    height,
                                                    hash = %hex::encode(&hash[..8]),
                                                    "Tip-change payout proposed: arming the coinbase for this block"
                                                ),
                                                Ok(_) => debug!(
                                                    height,
                                                    "Tip-change payout produced no miner outputs"
                                                ),
                                                Err(e) => error!(
                                                    height,
                                                    error = %e,
                                                    "Tip-change payout proposal failed — this block's \
                                                     coinbase will fall back to the pool address and \
                                                     pay the miners nothing"
                                                ),
                                            }
                                        }
                                        Ok(_) => debug!(
                                            height,
                                            "No unpaid ledger at tip change; nothing to arm"
                                        ),
                                        Err(e) => error!(
                                            height,
                                            error = %e,
                                            "Failed to read the unpaid ledger at tip change"
                                        ),
                                    }
                                }
                                None => debug!(
                                    height,
                                    "No template id (tip) yet; cannot arm a payout this tip"
                                ),
                            }
                        }
                    }

                    // Persist the round (round_id → block_height) so the
                    // best-hash per-window join can resolve a share's block
                    // height. INSERT OR IGNORE: the payout path later upserts
                    // the block-outcome columns onto this row if a block is
                    // found for the round.
                    let round_record = ghost_storage::RoundRecord {
                        round_id,
                        block_height: height,
                        block_hash: None,
                        start_time: chrono::Utc::now().timestamp(),
                        end_time: None,
                        total_shares: 0,
                        total_work: 0.0,
                        winning_miner: None,
                        found_by_node: None,
                        payout_status: ghost_storage::PayoutStatus::Active,
                        subsidy_sats: None,
                        tx_fees_sats: None,
                    };
                    if let Err(e) = db_for_rounds.create_round_if_not_exists(&round_record) {
                        warn!(round_id = round_id, error = %e, "Failed to persist round at start");
                    }

                    // Refresh the coordinator-election view if the epoch has
                    // changed (cheap no-op within an epoch; a no-op entirely
                    // when the feature is off). Read-only — activates nothing.
                    if let Some(ref coord) = coord_for_events {
                        coord.refresh_for_height(height).await;
                        // Start/stop the in-process coordinator to match the
                        // freshly-recomputed election (no-op when role activation
                        // is off or the seat is unchanged).
                        if let Some(ref sup) = supervisor_for_events {
                            sup.reconcile(coord.am_i_coordinator()).await;
                        }
                    }

                    // M-MINE-1: Update template ID for share validation
                    // The template ID is the prev_block_hash which uniquely identifies the template
                    if let Some(work_state) = tp_for_template_events.current_work() {
                        // Parse prev_hash hex string to [u8; 32]
                        if let Ok(prev_hash_bytes) = hex::decode(&work_state.prev_hash) {
                            if prev_hash_bytes.len() == 32 {
                                let mut template_id = [0u8; 32];
                                template_id.copy_from_slice(&prev_hash_bytes);
                                rm_notify.set_template_id(template_id);
                            }
                        }
                    }
                }
                TemplateEvent::TransactionsFiltered {
                    original_count,
                    filtered_count,
                    removed_fees,
                } => {
                    info!(
                        original = original_count,
                        filtered = filtered_count,
                        removed_fees = removed_fees,
                        "BUDS filtering applied"
                    );
                }
                TemplateEvent::FetchFailed { error } => {
                    warn!(error = %error, "Template fetch failed");
                }
            }
        }
    });

    // Clone refs for the async round event handler
    let rm_for_events = Arc::clone(&round_manager);
    let tp_for_events = Arc::clone(&template_processor);
    let payout_for_events = Arc::clone(&payout_handler);
    let identity_for_events = Arc::clone(&identity);
    let db_for_events = Arc::clone(&db);
    let solo_payout_address_for_events = config.network.solo_payout_address.clone();

    // Subscribe to round events and handle block found
    let mut round_events = round_manager.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = round_events.recv().await {
            match event {
                RoundEvent::BlockFound {
                    round_id,
                    block_hash,
                    miner_id,
                } => {
                    let is_solo_mode = rm_for_events.is_solo_mode();
                    info!(
                        round = round_id,
                        hash = %hex::encode(&block_hash[..8]),
                        miner = %miner_id,
                        solo_mode = is_solo_mode,
                        "🎉 BLOCK FOUND! Creating payout proposal..."
                    );

                    // Gather data for payout proposal
                    let node_shares = rm_for_events.get_node_shares(round_id);

                    // Get block subsidy and fees from template processor
                    let (subsidy, fees, height) = tp_for_events.get_current_block_info();

                    // Load treasury state from database for decay calculation
                    // SEC-ERR-4: Log database errors instead of silently ignoring them
                    let treasury_state = match db_for_events.get_treasury_balance() {
                        Ok(balance) => {
                            let threshold_ts = match db_for_events.get_treasury_threshold_reached()
                            {
                                Ok(ts_opt) => ts_opt
                                    .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))
                                    .map(|dt| dt.with_timezone(&chrono::Utc)),
                                Err(e) => {
                                    warn!(error = %e, "Failed to load treasury threshold timestamp, using None");
                                    None
                                }
                            };
                            TreasuryState::from_stored(balance, threshold_ts)
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to load treasury state, using default");
                            TreasuryState::new()
                        }
                    };

                    // Dispatch based on mining mode
                    if is_solo_mode {
                        // Solo mode: 99% subsidy + ALL TX fees to solo_payout_address
                        let solo_address = match &solo_payout_address_for_events {
                            Some(addr) if !addr.is_empty() => addr.clone(),
                            _ => {
                                error!(
                                    "Solo mode block found but solo_payout_address not configured!"
                                );
                                continue;
                            }
                        };

                        // PO4-M2: Capture treasury address snapshot
                        let treasury_address_snapshot =
                            payout_for_events.get_treasury_address_snapshot();

                        let solo_data = SoloBlockFoundData {
                            round_id,
                            block_hash,
                            block_height: height,
                            block_timestamp: chrono::Utc::now(),
                            solo_payout_address: solo_address,
                            subsidy_sats: subsidy,
                            treasury_address_snapshot,
                            tx_fees_sats: fees,
                            node_shares,
                            treasury_state,
                        };

                        match payout_for_events.handle_solo_block_found(solo_data) {
                            Ok(proposal_hash) => {
                                if proposal_hash != [0u8; 32] {
                                    info!(
                                        round = round_id,
                                        hash = %hex::encode(&proposal_hash[..8]),
                                        "Solo mode payout proposal submitted for consensus"
                                    );
                                }
                            }
                            Err(e) => {
                                error!(error = %e, round = round_id, "Failed to create solo mode payout proposal");
                            }
                        }
                    } else {
                        // Pool mode: ledger-style proportional distribution.
                        // Shares arriving after this moment belong to the next block's ledger.
                        let cutoff_ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;
                        let miner_work = {
                            // GHOST-02: the unpaid ledger, NOT this round's work. Every
                            // proposal path must derive its split the same way validators
                            // recompute it, or the fleet rejects its own payout.
                            match ghost_pool::payout::select_ledger_miner_work(
                                &db_for_events,
                                cutoff_ts,
                                height,
                                subsidy,
                            ) {
                                Ok(work) => work,
                                Err(e) => {
                                    error!(
                                        round = round_id,
                                        cutoff_ts,
                                        error = %e,
                                        "Failed to read unpaid ledger at block-found; no miner \
                                         payout this block — unpaid shares roll forward"
                                    );
                                    Vec::new()
                                }
                            }
                        };
                        let winning_node_id = identity_for_events.node_id();

                        // PO4-M2: Capture treasury address snapshot
                        let treasury_address_snapshot =
                            payout_for_events.get_treasury_address_snapshot();

                        let block_data = BlockFoundData {
                            round_id,
                            ledger_cutoff_ts: cutoff_ts,
                            block_hash,
                            block_height: height,
                            block_timestamp: chrono::Utc::now(),
                            winning_miner_id: miner_id.clone(),
                            winning_miner_payout_address: None, // Address looked up from DB
                            treasury_address_snapshot,
                            winning_node_id,
                            subsidy_sats: subsidy,
                            tx_fees_sats: fees,
                            miner_work,
                            node_shares,
                            treasury_state,
                        };

                        match payout_for_events.handle_block_found(block_data) {
                            Ok(proposal_hash) => {
                                if proposal_hash != [0u8; 32] {
                                    info!(
                                        round = round_id,
                                        hash = %hex::encode(&proposal_hash[..8]),
                                        "Payout proposal submitted for consensus"
                                    );
                                }
                            }
                            Err(e) => {
                                error!(error = %e, round = round_id, "Failed to create payout proposal");
                            }
                        }
                    }
                }
                RoundEvent::ShareSubmitted {
                    round_id: _,
                    miner_id: _,
                    work: _,
                } => {
                    // Log periodically, not every share
                }
                _ => {}
            }
        }
    });

    // Note: Stratum events now come from SRI, not ghost-pool
    // WebSocket broadcast for miner events would need SRI integration

    // Start registry client for load balancer registration (only for PublicPool mode)
    // Private modes (PrivatePool, PrivateSolo) skip DNS registration
    // Store registry client for deregistration on shutdown
    let registry_client_for_shutdown: Option<Arc<RegistryClient>> = if !matches!(
        mining_mode,
        MiningMode::PublicPool
    ) {
        info!(
            "Mining mode {:?}: skipping DNS registration (private mode)",
            mining_mode
        );
        None
    } else if let Some(ref registry_config) = config.registry {
        if !registry_config.url.is_empty() {
            let host = config
                .network
                .public_address
                .clone()
                .unwrap_or_else(|| "".to_string());

            if host.is_empty() {
                warn!("Registry configured but network.public_address is not set - skipping registration");
                None
            } else if let Some(ref signing_key) = config.network.signing_key {
                match RegistryClient::new(
                    signing_key,
                    registry_config.clone(),
                    host,
                    config.network.sv1_port,
                    config.network.sv2_port,
                    config.network.max_miners,
                ) {
                    Ok(registry_client) => {
                        let registry_client = Arc::new(registry_client);
                        let registry_for_task = Arc::clone(&registry_client);
                        let registry_shutdown = shutdown_tx.subscribe();
                        tokio::spawn(async move {
                            registry_for_task
                                .start(
                                    move || 0_u32, // Miner count from SRI (not tracked here)
                                    registry_shutdown,
                                )
                                .await;
                        });

                        info!(
                            "Registry client started (heartbeat every {}s)",
                            registry_config.heartbeat_interval_secs
                        );
                        Some(registry_client)
                    }
                    Err(e) => {
                        error!("Failed to create registry client: {}", e);
                        None
                    }
                }
            } else {
                warn!("Registry configured but network.signing_key is not set - skipping registration");
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Print startup summary
    info!("════════════════════════════════════════════════════════════════");
    info!("Ghost Pool is ready!");
    info!("  Stratum:    via SRI (connect to TDP)");
    if args.tdp_enabled {
        info!("  TDP:        0.0.0.0:{}", args.tdp_port);
    }
    info!("  HTTP API:   0.0.0.0:{}", http_port);
    info!("  Policy:     {}", policy.name);
    info!("  Shares:     {}/15", capabilities.total_shares());
    if let Some(ref ts) = tor_status {
        if ts.enabled {
            info!(
                "  Tor:        active ({})",
                ts.onion_address.as_deref().unwrap_or("pending")
            );
        }
    }
    info!("════════════════════════════════════════════════════════════════");

    // Verify template processor has work (for TDP job delivery)
    {
        let tp_check = Arc::clone(&template_processor);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            match tp_check.current_work() {
                Some(work) => {
                    info!(
                        height = work.height,
                        job_id = %work.job_id,
                        "STARTUP CHECK: Template processor has work available"
                    );
                }
                None => {
                    error!("STARTUP CHECK: Template processor has NO work - SRI won't receive templates!");
                }
            }
        });
    }

    // Wait for shutdown signal (ctrl+c, SIGTERM, or restart signal from config update)
    let mut shutdown_rx = shutdown_tx.subscribe();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Failed to install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received SIGINT, shutting down Ghost Pool...");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM, shutting down Ghost Pool...");
        }
        _ = shutdown_rx.recv() => {
            // Shutdown triggered by restart signal monitor
            if restart_signal.load(std::sync::atomic::Ordering::SeqCst) {
                info!("Shutting down for restart (config update)...");
            } else {
                info!("Shutting down Ghost Pool...");
            }
        }
    }

    // Send shutdown signal to all tasks
    let _ = shutdown_tx.send(());

    // H-9 SECURITY: Allow graceful shutdown period for spawned tasks.
    // Tasks subscribe to shutdown_tx and exit when signaled. This gives them
    // time to complete in-flight operations (save state, close connections).
    // 5 seconds is sufficient for orderly cleanup without blocking restart.
    info!("Waiting up to 5 seconds for tasks to complete...");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Deregister from load balancer (if registered)
    if let Some(registry_client) = registry_client_for_shutdown {
        info!("Deregistering from load balancer...");
        if let Err(e) = registry_client.deregister().await {
            warn!("Failed to deregister from load balancer: {}", e);
        }
    }

    // Cleanup
    template_processor.stop();
    mesh.stop().await?;

    // Checkpoint WAL and clean up database files
    if let Err(e) = db.shutdown() {
        warn!("Database shutdown error (non-fatal): {}", e);
    }

    // Check if this was a restart request
    if restart_signal.load(std::sync::atomic::Ordering::SeqCst) {
        info!(
            "Ghost Pool shutdown complete. Exiting with code {} for systemd restart.",
            EXIT_CODE_RESTART
        );
        std::process::exit(EXIT_CODE_RESTART);
    }

    info!("Ghost Pool shutdown complete");
    Ok(())
}

/// Expand ~ in path
fn expand_path(path: &std::path::Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    if let Some(stripped) = path_str.strip_prefix("~/") {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| anyhow::anyhow!("Could not determine home directory"))?;
        Ok(PathBuf::from(home).join(stripped))
    } else {
        Ok(path.to_path_buf())
    }
}

/// Build the pool template-reaper config from the operator's per-vector
/// settings. When the master switch is off, every detector is disabled.
/// Otherwise each detector and threshold maps straight through to the
/// `ghost_reaper::ReaperConfig` field that enforces it. Node-only vectors
/// (`reject_opreturn`, `reject_runestone`) have no pool-side equivalent and are
/// intentionally not mapped here — the Rust reaper bounds OP_RETURN via the
/// `max_op_return_bytes` threshold and has no Runestone detector.
/// Build the enforced `ghost_policy::PolicyProfile` from an operator's
/// `[policy].custom` config block. This is the source of truth the template
/// builder enforces per-field (tiers, content toggles, size limits) when the
/// operator selects the `Custom` profile.
fn policy_profile_from_custom(custom: &ghost_common::config::CustomPolicyConfig) -> PolicyProfile {
    // Map the config-crate BudsTier enum onto the ghost_buds tier the policy
    // engine/classifier use.
    let allowed_tiers = custom
        .allowed_tiers
        .iter()
        .map(|t| match t {
            ghost_common::config::BudsTier::T0 => ghost_buds::BudsTier::T0,
            ghost_common::config::BudsTier::T1 => ghost_buds::BudsTier::T1,
            ghost_common::config::BudsTier::T2 => ghost_buds::BudsTier::T2,
            ghost_common::config::BudsTier::T3 => ghost_buds::BudsTier::T3,
        })
        .collect();

    PolicyProfile {
        name: "custom".to_string(),
        description: "Operator-defined custom policy".to_string(),
        allowed_tiers,
        max_op_return_size: custom.max_op_return_size,
        max_witness_per_input: custom.max_witness_per_input,
        max_tx_outputs: custom.max_tx_outputs,
        max_tx_size: custom.max_tx_size,
        allow_inscriptions: custom.allow_inscriptions,
        allow_runes: custom.allow_runes,
        allow_brc20: custom.allow_brc20,
        min_fee_rate: custom.min_fee_rate,
        t0_priority_boost: 1.0,
    }
}

fn reaper_config_from_settings(s: &ReaperSettings) -> ReaperConfig {
    if !s.enabled {
        return ReaperConfig::disabled();
    }
    ReaperConfig {
        enabled: true,
        reject_inscription_envelope: s.reject_inscription,
        reject_drop_stuffing: s.reject_dropstuffing,
        reject_fake_pubkeys: s.reject_fakepubkey,
        reject_annex: s.reject_annex,
        reject_unreachable_code: s.reject_unreachable_code,
        max_op_return_bytes: s.max_op_return_bytes,
        min_drop_data_size: s.min_drop_size,
        reject_excess_witness: s.reject_excess_witness,
        min_excess_witness_bytes: s.min_excess_witness_bytes,
        reject_legacy_data_stuffing: s.reject_legacy_data_stuffing,
        legacy_max_push_bytes: s.legacy_max_push_bytes,
        validate_pubkey_curve_point: s.validate_pubkey_curve_point,
    }
}

/// Load configuration from file
fn load_config(path: &std::path::Path) -> Result<NodeConfig> {
    let mut config = if path.exists() {
        let content = std::fs::read_to_string(path)?;

        // One-shot deprecation check: the legacy `public_mining` bool was
        // removed in favour of `mining_mode`. Old pool.toml files still parse
        // (serde silently ignores unknown fields) but operators should clean
        // up so the source of truth is unambiguous.
        if content
            .lines()
            .any(|l| l.trim_start().starts_with("public_mining"))
        {
            warn!(
                "DEPRECATED: `public_mining` in pool.toml is ignored. \
                 Use `mining_mode = \"PublicPool\" | \"PrivatePool\" | \"PrivateSolo\"` instead. \
                 Remove the `public_mining` line to silence this warning."
            );
        }

        let config: NodeConfig = toml::from_str(&content)?;

        // Check config file permissions — fails on mainnet if world-readable
        ghost_common::config::validate_config_permissions(path, Some(&config.bitcoin.network))
            .map_err(|e| anyhow::anyhow!(e))?;

        config
    } else {
        info!("No config file found at {}, using defaults", path.display());
        NodeConfig::default()
    };

    // Enforce the Ghost Mode / Public Mining mutual exclusion at load time. A
    // Ghost Mode node builds near-empty blocks and forfeits all transaction-fee
    // income, so it must never also run as a public miner. If a config file sets
    // both, Ghost Mode is disabled (Public Mining, the income-earning
    // capability, is left active) and the change is logged loudly rather than
    // silently allowed.
    if let Some(warning) = config.reconcile_ghost_mode_mining_exclusion() {
        warn!("{}", warning);
    }

    // Validate pool configuration
    if let Err(e) = config.pool.validate() {
        warn!("Pool configuration warning: {}", e);
    }

    Ok(config)
}

/// Parse a log level string into a tracing Level
fn parse_log_level(s: &str) -> Level {
    match s.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    }
}

/// Check if a URL points to a loopback address
fn is_loopback_url(url: &str) -> bool {
    url.contains("127.0.0.1") || url.contains("localhost") || url.contains("[::1]")
}

/// Extract the host portion from a peer address (strips port if present)
fn extract_peer_host(address: &str) -> &str {
    if address.contains(':') {
        address.split(':').next().unwrap_or(address)
    } else {
        address
    }
}

/// Resolve the effective signer configuration from config and defaults
fn resolve_signer_path(
    config_signer: &Option<SignerConfig>,
    config_key_path: &std::path::Path,
    default_key_path: &std::path::Path,
) -> Result<SignerConfig> {
    match config_signer {
        Some(cfg) => Ok(cfg.clone()),
        None => {
            let cfg_key_path = expand_path(config_key_path)?;
            if cfg_key_path.exists() {
                Ok(SignerConfig::Local {
                    key_path: cfg_key_path,
                })
            } else {
                Ok(SignerConfig::Local {
                    key_path: default_key_path.to_path_buf(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::config::GhostPayConfig;
    use std::path::Path;

    // ── ghost-pay finalization notify gate ───────────────────────────
    //
    // The finalize callback must be wired ONLY when ghost-pay is actually
    // enabled on this node. Pool-only nodes carry a `[ghost_pay]` block with
    // `enabled = false` and no local ghost-pay daemon; wiring the notify there
    // spammed an ERROR (+3 retries) on every checkpoint finalization.

    #[test]
    fn test_finalize_gate_disabled_without_ghost_pay() {
        // No [ghost_pay] block at all → no notify wiring.
        let mut config = NodeConfig::default();
        assert!(config.ghost_pay.is_none());
        assert!(!config.ghost_pay_enabled());

        // [ghost_pay] present but disabled (what `setup` writes on a pool-only
        // node) → still no notify wiring.
        config.ghost_pay = Some(GhostPayConfig::default());
        assert!(!config.ghost_pay.as_ref().unwrap().enabled);
        assert!(
            !config.ghost_pay_enabled(),
            "pool-only node must not attempt the ghost-pay finalize notify"
        );
    }

    #[test]
    fn test_finalize_gate_enabled_with_ghost_pay() {
        // A node running ghost-pay sets enabled = true → notify is wired.
        let mut config = NodeConfig::default();
        config.ghost_pay = Some(GhostPayConfig {
            enabled: true,
            ..GhostPayConfig::default()
        });
        assert!(
            config.ghost_pay_enabled(),
            "a ghost-pay node must attempt the finalize notify"
        );
    }

    #[tokio::test]
    async fn test_notify_ghost_pay_finalize_surfaces_genuine_failure() {
        // On a node WITH ghost-pay enabled but the daemon unreachable, the
        // notify must still fail loudly (return Err) so the caller logs an
        // error. 127.0.0.1:1 refuses connections fast, so this doesn't wait on
        // the full 5s HTTP timeout — only the two backoff sleeps (~1.5s total).
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build()
            .expect("build test client");
        let result = notify_ghost_pay_finalize(
            &client,
            "https://127.0.0.1:1/api/v1/l2/finalize",
            123,
            [0u8; 32],
            &[[1u8; 32], [2u8; 32]],
        )
        .await;
        assert!(
            result.is_err(),
            "an unreachable ghost-pay must surface as an error, not be swallowed"
        );
    }

    // ── ordered_fetch_sources (MPC candidate fetch ordering) ─────────
    //
    // These lock in the contributor-first-then-seeds ordering that lets a voter
    // reach the candidate parameters served ONLY by the contributor node.

    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn test_ordered_fetch_sources_contributor_first() {
        let seeds = vec!["seed1.example:8559".to_string(), "9.9.9.9:8559".to_string()];
        let got = ordered_fetch_sources(Some("1.2.3.4:8559"), &seeds);
        // Contributor host leads, then the seeds — all reduced to host-only.
        assert_eq!(got, vec!["1.2.3.4", "seed1.example", "9.9.9.9"]);
    }

    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn test_ordered_fetch_sources_dedups_contributor_that_is_also_a_seed() {
        let seeds = vec!["1.2.3.4:8559".to_string(), "9.9.9.9:8559".to_string()];
        // The contributor is also a configured seed → it must appear ONCE, first.
        let got = ordered_fetch_sources(Some("1.2.3.4:8559"), &seeds);
        assert_eq!(got, vec!["1.2.3.4", "9.9.9.9"]);
    }

    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn test_ordered_fetch_sources_unresolved_contributor_falls_back_to_seeds() {
        let seeds = vec!["seed1.example:8559".to_string(), "9.9.9.9:8559".to_string()];
        // Address unresolved → seeds-only (prior behaviour), never empty/hard-fail.
        let got = ordered_fetch_sources(None, &seeds);
        assert_eq!(got, vec!["seed1.example", "9.9.9.9"]);
    }

    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn test_fetch_host_of_variants() {
        assert_eq!(fetch_host_of("1.2.3.4:8559"), "1.2.3.4");
        assert_eq!(fetch_host_of("1.2.3.4"), "1.2.3.4");
        assert_eq!(fetch_host_of("host.example:8080"), "host.example");
        assert_eq!(fetch_host_of("tcp://1.2.3.4:8559"), "1.2.3.4");
        assert_eq!(fetch_host_of("[2001:db8::1]:8559"), "2001:db8::1");
    }

    // ── contributor self-adopt (7th contribution-flow gap) ───────────
    //
    // A node that GENERATES a contribution never applies it through its own
    // MpcHandler, so after the voters BFT-apply it and the row gossips back,
    // the contributor is an elder on record while its own `current.bin` +
    // singleton stay at the PREVIOUS position. These lock in the fix: the adopt
    // path advances the on-disk head + singleton to the applied position.

    /// Build a fresh in-memory DB + a genesis+position-1 ceremony manager in
    /// `dir`, returning the manager, the DB, the node id hex, and the position-1
    /// lineage hash. After this the manager is an applied-position-1 head.
    #[cfg(feature = "mpc-ceremony")]
    fn ceremony_at_position_1(
        dir: &Path,
    ) -> (
        std::sync::Arc<ghost_mpc::CeremonyManager>,
        std::sync::Arc<ghost_storage::Database>,
        String,
        [u8; 32],
    ) {
        use ghost_common::identity::NodeIdentity;

        let manager = std::sync::Arc::new(ghost_mpc::CeremonyManager::new(dir.to_path_buf()));
        manager.ensure_genesis_initialized().expect("genesis init");

        let id = NodeIdentity::generate();
        let id_hex = hex::encode(id.node_id());

        // Position 1 contributed + applied by this node → manager count 0 -> 1.
        let (p1, c1) = manager
            .generate_contribution(&id_hex)
            .expect("generate position 1");
        manager
            .apply_contribution(p1, &c1)
            .expect("apply position 1");

        let db = std::sync::Arc::new(ghost_storage::Database::in_memory().expect("in-memory db"));
        db.save_mpc_contribution(&ghost_storage::queries::MpcContributionRecord {
            elder_position: 1,
            contributor_node_id: id_hex.clone(),
            prev_params_hash: c1.prev_params_hash,
            new_params_hash: c1.new_params_hash,
            contribution_proof: serde_json::to_vec(&c1.proof).unwrap(),
            epoch: 0,
            created_at: c1.timestamp,
        })
        .expect("save position 1 row");
        // Singleton reflects the applied head (count 1).
        persist_singleton_from_manager(&manager, &db);

        (manager, db, id_hex, c1.new_params_hash)
    }

    /// The core self-adopt: a contributor whose own position-2 contribution was
    /// BFT-applied by the voters (row gossiped back) but whose manager +
    /// singleton still sit at position 1 must advance its `current.bin` +
    /// singleton to position 2 when it adopts its OWN local candidate.
    ///
    /// Pre-fix behaviour was to detect elder status and RETURN without adopting
    /// (the asserted PRE state below); the fix drives the candidate through
    /// `apply_contribution_multi` + persists the singleton (the asserted POST
    /// state). The POST assertions FAIL under the pre-fix "return without adopt".
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn contributor_adopts_own_applied_position_from_local_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, db, id_hex, p1_hash) = ceremony_at_position_1(dir.path());

        // Generate our position-2 candidate WITHOUT applying it (mirrors the
        // contributor: it writes a candidate serving file, never current.bin).
        let (p2, c2) = manager
            .generate_contribution_at_position(&id_hex, 2)
            .expect("generate position 2");
        let mut buf = Vec::new();
        p2.write(&mut buf).expect("serialize position 2 params");
        write_candidate_note_spend_params(dir.path(), &c2.new_params_hash, &buf)
            .expect("write candidate");

        // The voters applied position 2 and it gossiped back: our DB has the
        // position-2 row (contributed by US), but our manager/singleton lag at 1.
        db.save_mpc_contribution(&ghost_storage::queries::MpcContributionRecord {
            elder_position: 2,
            contributor_node_id: id_hex.clone(),
            prev_params_hash: c2.prev_params_hash,
            new_params_hash: c2.new_params_hash,
            contribution_proof: serde_json::to_vec(&c2.proof).unwrap(),
            epoch: 0,
            created_at: c2.timestamp,
        })
        .expect("save position 2 row");

        // ---- PRE (the bug state the pre-fix "return without adopt" leaves) ----
        assert_eq!(
            manager.contribution_count(),
            1,
            "pre-adopt: manager head lags at position 1"
        );
        assert_eq!(
            manager.current_params_hash(),
            p1_hash,
            "pre-adopt: current.bin is still the position-1 params"
        );
        assert_eq!(
            db.get_mpc_ceremony_state()
                .unwrap()
                .unwrap()
                .contribution_count,
            1,
            "pre-adopt: singleton lags at position 1"
        );

        // ---- ADOPT (the fix): load our own candidate + apply + persist --------
        let params = load_local_candidate_note_spend(dir.path(), &c2.new_params_hash)
            .expect("local candidate must load + hash-match the applied head");
        let row = db.get_mpc_contribution(2).unwrap().unwrap();
        let contribution = contribution_from_row(&row);
        assert!(
            apply_and_persist_adopted_note_spend(&manager, &db, params, &contribution),
            "adopt must satisfy the post-apply invariant"
        );

        // ---- POST (fails under pre-fix; passes after) -------------------------
        assert_eq!(
            manager.contribution_count(),
            2,
            "post-adopt: manager head advanced to position 2"
        );
        assert_eq!(
            manager.current_params_hash(),
            c2.new_params_hash,
            "post-adopt: current.bin is the position-2 applied head"
        );
        // On-disk current params re-hash to the applied head (lineage).
        let on_disk = ghost_mpc::contribution::hash_parameters(
            &manager.note_spend_params().expect("current params loaded"),
        )
        .expect("hash current params");
        assert_eq!(
            on_disk, c2.new_params_hash,
            "post-adopt: note_spend_params_current.bin is the applied head"
        );
        let singleton = db.get_mpc_ceremony_state().unwrap().unwrap();
        assert_eq!(
            singleton.contribution_count, 2,
            "post-adopt: singleton advanced to position 2"
        );
        assert_eq!(
            singleton.current_params_hash, c2.new_params_hash,
            "post-adopt: singleton head == applied head"
        );
    }

    /// Restart self-heal: a contributor restarts with its recorded chain AHEAD of
    /// its on-disk head (mpc_contributions has position 2, but current.bin +
    /// singleton are at position 1 — node5's exact restart state). Pre-fix, the
    /// genesis-anchored startup verification sees `contributions[MAX].new !=
    /// on-disk head` and fail-closes → crash-loop. This proves the self-heal
    /// advances the head so that mismatch is gone.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn restart_self_heal_advances_lagging_contributor_head() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, db, id_hex, _p1_hash) = ceremony_at_position_1(dir.path());

        let (p2, c2) = manager
            .generate_contribution_at_position(&id_hex, 2)
            .expect("generate position 2");
        let mut buf = Vec::new();
        p2.write(&mut buf).expect("serialize position 2 params");
        write_candidate_note_spend_params(dir.path(), &c2.new_params_hash, &buf)
            .expect("write candidate");
        db.save_mpc_contribution(&ghost_storage::queries::MpcContributionRecord {
            elder_position: 2,
            contributor_node_id: id_hex.clone(),
            prev_params_hash: c2.prev_params_hash,
            new_params_hash: c2.new_params_hash,
            contribution_proof: serde_json::to_vec(&c2.proof).unwrap(),
            epoch: 0,
            created_at: c2.timestamp,
        })
        .expect("save position 2 row");

        // The exact fail-closed condition: recorded chain tip != on-disk head.
        let chain_tip = db.get_mpc_max_contribution_position().unwrap().unwrap();
        let head_pre =
            ghost_mpc::contribution::hash_parameters(&manager.note_spend_params().unwrap())
                .unwrap();
        let tip_hash = db
            .get_mpc_contribution(chain_tip)
            .unwrap()
            .unwrap()
            .new_params_hash;
        assert_eq!(chain_tip, 2);
        assert_ne!(
            head_pre, tip_hash,
            "pre-heal: on-disk head lags the chain tip (the crash-loop condition)"
        );

        // Self-heal by adopting each un-adopted position in order (what the
        // startup restart self-heal / retry-loop drivers do, sans network).
        while manager.contribution_count() < chain_tip {
            let next = manager.contribution_count() + 1;
            let params = load_local_candidate_note_spend(dir.path(), &tip_hash)
                .expect("local candidate available for the lagging position");
            let row = db.get_mpc_contribution(next).unwrap().unwrap();
            let contribution = contribution_from_row(&row);
            assert!(apply_and_persist_adopted_note_spend(
                &manager,
                &db,
                params,
                &contribution
            ));
        }

        // Post-heal: on-disk head now equals the chain tip — verification passes.
        let head_post =
            ghost_mpc::contribution::hash_parameters(&manager.note_spend_params().unwrap())
                .unwrap();
        assert_eq!(
            head_post, tip_hash,
            "post-heal: on-disk head == chain tip (fail-closed mismatch resolved)"
        );
        assert_eq!(manager.contribution_count(), 2);
        assert_eq!(
            db.get_mpc_ceremony_state()
                .unwrap()
                .unwrap()
                .contribution_count,
            2
        );
    }

    // ── fresh-join singleton self-heal (node7 onboarding gap) ────────
    //
    // node7 joined genesis-anchored, synced the full lineage (contribution rows
    // + proofs + votes) and fetched the head params into current.bin, but the
    // sync NEVER wrote the `mpc_ceremony` singleton. On restart
    // `get_mpc_ceremony_state()` returned None, `load_or_init(None)`
    // re-initialised PRE-GENESIS, and the node DISCARDED its synced position-1..n
    // state. These lock in the fix: with contribution rows present but no
    // singleton, the startup reconcile creates the singleton at the chain tip
    // (current_params_hash == contributions[MAX].new_params_hash) so the node is
    // NOT pre-genesis; with ZERO contributions it stays pre-genesis.

    /// Build a node7-shaped state in `dir`: an in-memory DB with contribution
    /// rows 1..=n (+ proofs) and an on-disk head (`current.bin`) at position n,
    /// but DELIBERATELY no `mpc_ceremony` singleton (the fresh-join sync gap).
    #[cfg(feature = "mpc-ceremony")]
    fn synced_ceremony_no_singleton(
        dir: &Path,
        n: u32,
    ) -> (
        std::sync::Arc<ghost_mpc::CeremonyManager>,
        std::sync::Arc<ghost_storage::Database>,
        String,
    ) {
        use ghost_common::identity::NodeIdentity;

        let manager = std::sync::Arc::new(ghost_mpc::CeremonyManager::new(dir.to_path_buf()));
        manager.ensure_genesis_initialized().expect("genesis init");
        let id_hex = hex::encode(NodeIdentity::generate().node_id());
        let db = std::sync::Arc::new(ghost_storage::Database::in_memory().expect("in-memory db"));

        // Position 1 (genesis contribution), then 2..=n, applied in order so
        // current.bin ends at the position-n head; every position saved as a row.
        let (p1, c1) = manager
            .generate_contribution(&id_hex)
            .expect("generate position 1");
        manager
            .apply_contribution(p1, &c1)
            .expect("apply position 1");
        db.save_mpc_contribution(&foreign_row(1, &id_hex, &c1))
            .unwrap();
        for pos in 2..=n {
            let (p, c) = manager
                .generate_contribution_at_position(&id_hex, pos)
                .expect("generate position");
            manager.apply_contribution(p, &c).expect("apply position");
            db.save_mpc_contribution(&foreign_row(pos, &id_hex, &c))
                .unwrap();
        }
        // NODE7 GAP: deliberately do NOT persist the mpc_ceremony singleton.
        assert!(
            db.get_mpc_ceremony_state().unwrap().is_none(),
            "helper must reproduce the node7 state: rows present, NO singleton"
        );
        (manager, db, id_hex)
    }

    /// Storage/reconcile: N contribution rows (+ proofs) but NO singleton → the
    /// startup reconcile CREATES the singleton at count=N with
    /// `current_params_hash == contributions[N].new_params_hash` (NOT pre-genesis).
    /// Pre-fix this scenario stayed singleton-less → pre-genesis on restart.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn startup_reconcile_creates_singleton_from_synced_contributions() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, db, _id) = synced_ceremony_no_singleton(dir.path(), 3);

        assert_eq!(db.get_mpc_max_contribution_position().unwrap(), Some(3));
        let head_hash = db.get_mpc_contribution(3).unwrap().unwrap().new_params_hash;

        // ── the fix ─────────────────────────────────────────────────────────
        let n = reconcile_singleton_to_recorded_head(&db).unwrap();
        assert_eq!(n, Some(3));

        let singleton = db
            .get_mpc_ceremony_state()
            .unwrap()
            .expect("singleton created — node is NO LONGER pre-genesis");
        assert_eq!(
            singleton.contribution_count, 3,
            "singleton count == chain tip"
        );
        assert_eq!(
            singleton.current_params_hash, head_hash,
            "singleton head == recorded contributions[MAX].new_params_hash (lineage hash)"
        );
        // Invariant: singleton head == on-disk current.bin head lineage hash.
        let on_disk =
            ghost_mpc::contribution::hash_parameters(&manager.note_spend_params().unwrap())
                .unwrap();
        assert_eq!(
            on_disk, head_hash,
            "singleton head == on-disk current.bin head"
        );
    }

    /// The genuine pre-genesis path is preserved: ZERO contribution rows AND no
    /// singleton → the reconcile is a no-op and the node stays pre-genesis (this
    /// is how a brand-new genesis node starts). No singleton is fabricated.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn startup_reconcile_zero_contributions_stays_pregenesis() {
        let db = std::sync::Arc::new(ghost_storage::Database::in_memory().unwrap());
        assert!(db.get_mpc_ceremony_state().unwrap().is_none());
        assert_eq!(db.get_mpc_max_contribution_position().unwrap(), None);

        assert_eq!(
            reconcile_singleton_to_recorded_head(&db).unwrap(),
            None,
            "no contributions → pre-genesis, nothing to reconcile"
        );
        assert!(
            db.get_mpc_ceremony_state().unwrap().is_none(),
            "must NOT fabricate a singleton for a brand-new genesis node"
        );
    }

    /// Sync-path (Part A): after the finalize runs, the singleton is present at
    /// the synced count AND current.bin on disk hashes to the head lineage hash.
    /// (current.bin was already installed by the params fetch, so no network is
    /// needed — `ensure_recorded_head_installed` returns Ok(true) immediately.)
    #[cfg(feature = "mpc-ceremony")]
    #[tokio::test]
    async fn sync_path_persists_head_and_singleton() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, db, _id) = synced_ceremony_no_singleton(dir.path(), 2);
        let head_hash = db.get_mpc_contribution(2).unwrap().unwrap().new_params_hash;

        let peers = ghost_consensus::peer::PeerManager::new([0u8; 32], 100);
        assert!(
            ensure_recorded_head_installed(&manager, &db, &peers, &[])
                .await
                .unwrap(),
            "current.bin already at the recorded head — no re-fetch needed"
        );
        assert_eq!(reconcile_singleton_to_recorded_head(&db).unwrap(), Some(2));

        let singleton = db.get_mpc_ceremony_state().unwrap().unwrap();
        assert_eq!(singleton.contribution_count, 2);
        assert_eq!(singleton.current_params_hash, head_hash);

        // current.bin on disk hashes to the head lineage hash.
        let current = dir.path().join("note_spend_params_current.bin");
        let on_disk = ghost_mpc::contribution::hash_parameters(
            &ghost_mpc::params::load_parameters(&current).unwrap(),
        )
        .unwrap();
        assert_eq!(
            on_disk, head_hash,
            "on-disk current.bin == head lineage hash"
        );
    }

    /// Regression: the caller reconciles BEFORE `load_or_init`, so the ceremony
    /// state handed to `load_or_init` is `Some(state)` — never `None` — when
    /// contributions are present. `load_or_init(dir, None)` with contributions is
    /// the exact node7 crash-path and must be unreachable after the guard.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn load_or_init_receives_some_after_startup_reconcile() {
        let dir = tempfile::tempdir().unwrap();
        let (_manager, db, _id) = synced_ceremony_no_singleton(dir.path(), 2);

        // Pre-reconcile: state is None — load_or_init(None) would go PRE-GENESIS.
        assert!(db.get_mpc_ceremony_state().unwrap().is_none());

        // Part B guard runs the reconcile before load_or_init.
        reconcile_singleton_to_recorded_head(&db).unwrap();

        // The value load_or_init now receives is Some(state), count == chain tip.
        let state = db.get_mpc_ceremony_state().unwrap();
        assert!(
            state.is_some(),
            "caller must pass Some(state) to load_or_init after reconcile, never None"
        );
        assert_eq!(state.unwrap().contribution_count, 2);
    }

    // ── attempt-start catch-up (behind-the-head rolling gap) ─────────
    //
    // A node that joined / un-pinned while the ceremony had already advanced
    // receives applied-contribution ROWS via gossip (its `mpc_contributions` MAX
    // climbs) but nothing drives its adopted head + singleton forward. Pre-fix it
    // computed `next_position = singleton_count + 1` and contributed an
    // ALREADY-FILLED position forever (node6→stuck-at-5). These lock in the fix:
    // detect "behind", catch the head up by adopting every un-adopted position,
    // then target one past the recorded chain tip (the next FREE position).

    /// Directly write a note-spend candidate serving file WITHOUT the
    /// supersede-cleanup that `write_candidate_note_spend_params` performs, so a
    /// multi-step test can stage several positions' candidates simultaneously.
    #[cfg(feature = "mpc-ceremony")]
    fn stage_candidate(dir: &Path, new_hash: &[u8; 32], params: &ghost_mpc::Groth16Params) {
        let mut buf = Vec::new();
        params.write(&mut buf).expect("serialize candidate params");
        let name = ghost_common::mpc::candidate_note_spend_filename(new_hash);
        std::fs::write(dir.join(name), &buf).expect("write candidate file");
    }

    #[cfg(feature = "mpc-ceremony")]
    fn foreign_row(
        position: u32,
        contributor: &str,
        c: &ghost_mpc::MpcContribution,
    ) -> ghost_storage::queries::MpcContributionRecord {
        ghost_storage::queries::MpcContributionRecord {
            elder_position: position,
            contributor_node_id: contributor.to_string(),
            prev_params_hash: c.prev_params_hash,
            new_params_hash: c.new_params_hash,
            contribution_proof: serde_json::to_vec(&c.proof).unwrap(),
            epoch: 0,
            created_at: c.timestamp,
        }
    }

    /// The pure targeting decision, at the EXACT node6 numbers. Pre-fix targeted
    /// `count + 1` off a lagging singleton (an already-filled position); the fix
    /// targets one past the recorded chain tip (the next free position).
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn mpc_next_contribution_position_targets_next_free_after_catchup() {
        // node6: adopted head (singleton) lagged at 4 while the chain tip advanced
        // to 5. The PRE-FIX formula `count + 1` == 5 — ALREADY node5's position.
        assert_eq!(
            4 + 1,
            5,
            "pre-fix formula targets the FILLED position (bug)"
        );
        // The FIX targets one past the tip → 6 (next FREE), both before the
        // catch-up (count 4) and after it advances the head to the tip (count 5).
        assert_eq!(mpc_next_contribution_position(4, 5), 6);
        assert_eq!(mpc_next_contribution_position(5, 5), 6);
        // Behind by two (count 4, tip 6): target 7 (after adopting 5 then 6).
        assert_eq!(mpc_next_contribution_position(4, 6), 7);
        assert_eq!(mpc_next_contribution_position(6, 6), 7);
        // Not behind (fresh genesis / already caught up): normal count+1, and never
        // a phantom advance past the head.
        assert_eq!(mpc_next_contribution_position(0, 0), 1);
        assert_eq!(mpc_next_contribution_position(3, 3), 4);
    }

    /// Build a peer that advertises elder status with an explicit `last_seen`.
    #[cfg(feature = "mpc-ceremony")]
    fn elder_peer(tag: u8, last_seen: u64) -> ghost_consensus::peer::Peer {
        let mut p = ghost_consensus::peer::Peer::new([tag; 32], format!("10.0.0.{tag}:8555"));
        p.capabilities = NodeCapabilities {
            elder_status: true,
            ..NodeCapabilities::default()
        };
        p.last_seen = last_seen;
        p
    }

    /// The mesh-registration readiness predicate: ready iff our candidate-serving
    /// endpoint is up AND we are connected to at least a BFT quorum of elders.
    /// This is the gate that stops the node7/node8 "broadcast before the voters
    /// know my address → abstain → give up" bug.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn mpc_contribution_ready_below_at_and_above_threshold() {
        // Below quorum: NOT ready even with the endpoint up.
        assert!(!mpc_contribution_ready(2, 3, true));
        // Exactly at quorum with the endpoint up: ready.
        assert!(mpc_contribution_ready(3, 3, true));
        // Above quorum: ready.
        assert!(mpc_contribution_ready(4, 3, true));
        // Endpoint down is never ready, regardless of elder count.
        assert!(!mpc_contribution_ready(4, 3, false));
        // Bootstrap quorum of 1 needs exactly one connected elder.
        assert!(!mpc_contribution_ready(0, 1, true));
        assert!(mpc_contribution_ready(1, 1, true));
    }

    /// `count_connected_elders` counts only peers that BOTH advertise elder
    /// status AND were seen within the freshness window; a `now`-relative cutoff
    /// keeps it deterministic.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn count_connected_elders_filters_stale_and_non_elders() {
        let now = 10_000u64;
        let fresh = now - 30; // within a 60s window
        let stale = now - 120; // outside it

        let mut non_elder = ghost_consensus::peer::Peer::new([9u8; 32], "10.0.0.9:8555".into());
        non_elder.last_seen = fresh; // recent but NOT an elder
        non_elder.capabilities = NodeCapabilities::default();

        let peers = vec![
            elder_peer(1, fresh), // counts
            elder_peer(2, fresh), // counts
            elder_peer(3, stale), // too old — excluded
            non_elder,            // not an elder — excluded
        ];

        assert_eq!(count_connected_elders(&peers, now, 60), 2);
        // Widen the window and the stale elder is admitted too.
        assert_eq!(count_connected_elders(&peers, now, 300), 3);
        // No peers → zero (a fresh node that nobody has discovered yet).
        assert_eq!(count_connected_elders(&[], now, 60), 0);
    }

    /// The retry loop NEVER permanently gives up: for a node that is not yet
    /// registered (`connected_elders < quorum`) the readiness predicate stays
    /// false for every round, and the inter-round backoff stays a FINITE, bounded
    /// delay no matter how many rounds elapse — so the node keeps re-checking
    /// forever instead of hitting the old fixed 15-attempt "will not be an elder"
    /// terminal state.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn retry_backoff_is_indefinite_and_capped() {
        // Fast converge window: the tuned upper bound (jitter added at the call site).
        assert_eq!(
            mpc_retry_backoff_secs(1),
            MPC_CONTRIBUTION_RETRY_DELAY_MAX_SECS
        );
        assert_eq!(
            mpc_retry_backoff_secs(MPC_CONTRIBUTION_MAX_ATTEMPTS),
            MPC_CONTRIBUTION_RETRY_DELAY_MAX_SECS
        );

        // Beyond the fast window the delay escalates monotonically, then saturates
        // at the cap — and is ALWAYS finite (never a "stop" sentinel), even for an
        // absurd round count. This is the essence of "no permanent giveup".
        let first_over = mpc_retry_backoff_secs(MPC_CONTRIBUTION_MAX_ATTEMPTS + 1);
        assert!(first_over > MPC_CONTRIBUTION_RETRY_DELAY_MAX_SECS);
        assert!(first_over <= MPC_CONTRIBUTION_BACKOFF_MAX_SECS);
        for attempt in [MPC_CONTRIBUTION_MAX_ATTEMPTS + 5, 1_000, 100_000, u32::MAX] {
            let d = mpc_retry_backoff_secs(attempt);
            assert!(
                d >= first_over,
                "backoff must not shrink back below the first step"
            );
            assert_eq!(
                d, MPC_CONTRIBUTION_BACKOFF_MAX_SECS,
                "backoff must saturate at the cap, not overflow or reset"
            );
        }

        // A still-unregistered node is never "ready", for any round — contrast the
        // OLD behaviour, which stopped trying after MPC_CONTRIBUTION_MAX_ATTEMPTS.
        for attempt in [1u32, MPC_CONTRIBUTION_MAX_ATTEMPTS, 10_000] {
            assert!(
                !mpc_contribution_ready(1, 3, true),
                "unregistered node stays not-ready at round {attempt}, so the loop keeps retrying"
            );
        }
    }

    /// node6 reproduction: singleton at 1 while the chain tip advanced to a FOREIGN
    /// position 2 (received only as a row). The attempt-start catch-up must ADOPT
    /// position 2 (params + singleton advance to 2), after which the node targets
    /// position 3 — NOT the already-filled 2. Pre-fix (no catch-up) it stayed
    /// stuck targeting 2.
    #[cfg(feature = "mpc-ceremony")]
    #[tokio::test]
    async fn attempt_start_catchup_adopts_foreign_position_and_targets_next_free() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, db, our_id, _p1) = ceremony_at_position_1(dir.path());

        // A DIFFERENT node contributed position 2 (a VALID foreign lineage
        // transform of our position-1 head). We are the "behind" node: we received
        // the ROW + the contributor's candidate params but never adopted the head.
        let foreign_id = hex::encode(NodeIdentity::generate().node_id());
        let (p2, c2) = manager
            .generate_contribution_at_position(&foreign_id, 2)
            .expect("generate foreign position 2");
        stage_candidate(dir.path(), &c2.new_params_hash, &p2);
        db.save_mpc_contribution(&foreign_row(2, &foreign_id, &c2))
            .unwrap();

        // ── PRE (the node6 stuck state) ──────────────────────────────────────
        let pre_count = db.mpc_contribution_count_authoritative().unwrap();
        let tip = db.get_mpc_max_contribution_position().unwrap().unwrap();
        assert_eq!(pre_count, 1, "adopted head still lags at position 1");
        assert_eq!(tip, 2, "the chain tip advanced to position 2 via the row");
        // Pre-fix targeted `count + 1` == 2 — the position ALREADY filled by the
        // foreign contributor. That is the forever-stuck condition.
        assert_eq!(pre_count + 1, tip, "pre-fix targets the FILLED position");

        // ── CATCH UP (the fix) ───────────────────────────────────────────────
        let peers = ghost_consensus::peer::PeerManager::new([0u8; 32], 100);
        assert!(
            adopt_all_applied_positions(&manager, &db, &peers, &[], &our_id).await,
            "attempt-start catch-up must adopt the foreign applied position"
        );

        // ── POST (fails under pre-fix) ───────────────────────────────────────
        assert_eq!(manager.contribution_count(), 2, "head advanced to the tip");
        assert_eq!(
            manager.current_params_hash(),
            c2.new_params_hash,
            "current.bin is the position-2 applied head"
        );
        let post_count = db.mpc_contribution_count_authoritative().unwrap();
        assert_eq!(post_count, 2, "singleton advanced to the tip");
        // Now the node targets position 3 — the next FREE position, not the filled 2.
        assert_eq!(
            mpc_next_contribution_position(post_count, tip),
            3,
            "after catch-up the node targets the next FREE position (3), not 2"
        );
    }

    /// Multi-step catch-up: behind by two. The singleton sits at 1 while the chain
    /// tip advanced to position 3 (rows for 2 and 3 received). The catch-up must
    /// adopt 2 THEN 3 in order, after which the node targets 4.
    #[cfg(feature = "mpc-ceremony")]
    #[tokio::test]
    async fn attempt_start_catchup_multi_step_adopts_all_positions() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, db, our_id, _p1) = ceremony_at_position_1(dir.path());

        // Our own positions 2 and 3 were BFT-applied and gossiped back as rows; we
        // hold both candidate serving files but adopted neither (singleton at 1).
        let (p2, c2) = manager
            .generate_contribution_at_position(&our_id, 2)
            .expect("generate position 2");
        let (p3, c3) = manager
            .generate_contribution_at_position(&our_id, 3)
            .expect("generate position 3");
        stage_candidate(dir.path(), &c2.new_params_hash, &p2);
        stage_candidate(dir.path(), &c3.new_params_hash, &p3);
        db.save_mpc_contribution(&foreign_row(2, &our_id, &c2))
            .unwrap();
        db.save_mpc_contribution(&foreign_row(3, &our_id, &c3))
            .unwrap();

        let pre_count = db.mpc_contribution_count_authoritative().unwrap();
        let tip = db.get_mpc_max_contribution_position().unwrap().unwrap();
        assert_eq!(pre_count, 1);
        assert_eq!(tip, 3, "behind by two positions");

        let peers = ghost_consensus::peer::PeerManager::new([0u8; 32], 100);
        assert!(
            adopt_all_applied_positions(&manager, &db, &peers, &[], &our_id).await,
            "catch-up must adopt BOTH lagging positions in order"
        );

        assert_eq!(manager.contribution_count(), 3, "head advanced 1 -> 2 -> 3");
        assert_eq!(manager.current_params_hash(), c3.new_params_hash);
        let post_count = db.mpc_contribution_count_authoritative().unwrap();
        assert_eq!(post_count, 3);
        assert_eq!(
            mpc_next_contribution_position(post_count, tip),
            4,
            "after a two-step catch-up the node targets position 4"
        );
    }

    /// Fail-closed on FOREIGN lineage: a caught-up position this node did NOT
    /// author is adopted ONLY after cryptographic `verify_contribution_catchup`
    /// (Schnorr + pairing transform), never on hash-match alone. A forged
    /// candidate whose file hashes to the recorded head but whose params are not a
    /// valid transform must be REJECTED and must NOT advance the head.
    #[cfg(feature = "mpc-ceremony")]
    #[tokio::test]
    async fn catchup_rejects_forged_foreign_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, db, our_id, p1_hash) = ceremony_at_position_1(dir.path());

        // Borrow a foreign node's REAL position-2 proof (valid Schnorr bound to
        // this ceremony_id), so the forgery clears the proof checks and is caught
        // specifically by the pairing TRANSFORM check.
        let foreign_id = hex::encode(NodeIdentity::generate().node_id());
        let (_p2, c2) = manager
            .generate_contribution_at_position(&foreign_id, 2)
            .expect("generate foreign position 2 (for its valid proof)");

        // FORGERY: the "position-2 params" are actually the UNCHANGED position-1
        // params (an identity transform that applied no tau). The candidate file
        // hashes to the row's new_params_hash (hash-match PASSES), but
        // e(new_h, tau_G2) != e(old_h, G2) when new_h == old_h and tau != 1, so
        // `verify_contribution_catchup` MUST reject it.
        let prev = manager.note_spend_params().unwrap();
        let forged_hash = ghost_mpc::contribution::hash_parameters(&prev).unwrap();
        assert_eq!(
            forged_hash, p1_hash,
            "forged candidate == the position-1 head"
        );
        stage_candidate(dir.path(), &forged_hash, &prev);
        db.save_mpc_contribution(&ghost_storage::queries::MpcContributionRecord {
            elder_position: 2,
            contributor_node_id: foreign_id.clone(),
            prev_params_hash: p1_hash,
            new_params_hash: forged_hash,
            contribution_proof: serde_json::to_vec(&c2.proof).unwrap(),
            epoch: 0,
            created_at: c2.timestamp,
        })
        .unwrap();

        let peers = ghost_consensus::peer::PeerManager::new([0u8; 32], 100);
        let adopted = adopt_all_applied_positions(&manager, &db, &peers, &[], &our_id).await;

        assert!(!adopted, "a forged foreign candidate must NOT be adopted");
        assert_eq!(
            manager.contribution_count(),
            1,
            "head must stay at position 1 — no false advance on a rejected forgery"
        );
        assert_eq!(
            db.get_mpc_ceremony_state()
                .unwrap()
                .unwrap()
                .contribution_count,
            1,
            "singleton must not advance on a rejected forgery"
        );
    }

    /// Restart-safety of a caught-up position: after adopting position N the node
    /// must hold params AND the retained ≥quorum BFT votes for it, so a later
    /// restart's genesis-anchored startup check passes without manual backfill
    /// (the node6 votes I had to backfill by hand). The network vote sync runs
    /// against a peer's `/api/v1/mpc/votes/{pos}` endpoint (no HTTP server in a
    /// unit test); here the votes are seeded as that sync would deliver them, and
    /// we assert they SURVIVE the adopt and are queryable for the restart check.
    #[cfg(feature = "mpc-ceremony")]
    #[tokio::test]
    async fn catchup_retains_votes_for_restart_safety() {
        let dir = tempfile::tempdir().unwrap();
        let (manager, db, our_id, _p1) = ceremony_at_position_1(dir.path());

        let foreign_id = hex::encode(NodeIdentity::generate().node_id());
        let (p2, c2) = manager
            .generate_contribution_at_position(&foreign_id, 2)
            .expect("generate foreign position 2");
        stage_candidate(dir.path(), &c2.new_params_hash, &p2);
        db.save_mpc_contribution(&foreign_row(2, &foreign_id, &c2))
            .unwrap();

        // The retained BFT quorum votes for position 2 (as the votes endpoint
        // would serve them).
        for i in 0..3u8 {
            let voter = hex::encode(NodeIdentity::generate().node_id());
            db.save_mpc_vote(&ghost_storage::queries::MpcVerificationVote {
                contribution_position: 2,
                voter_node_id: voter,
                approve: true,
                signature: vec![i.wrapping_add(1); 64],
                voted_at: 1_700_000_000 + i as u64,
            })
            .unwrap();
        }

        let peers = ghost_consensus::peer::PeerManager::new([0u8; 32], 100);
        assert!(adopt_all_applied_positions(&manager, &db, &peers, &[], &our_id).await);

        // Params present at the adopted head …
        assert_eq!(manager.contribution_count(), 2);
        assert_eq!(manager.current_params_hash(), c2.new_params_hash);
        // … AND the retained quorum votes for the caught-up position survive, so
        // the genesis-anchored restart verification has what it needs.
        let votes = db.get_mpc_votes(2).unwrap();
        assert_eq!(
            votes.len(),
            3,
            "retained BFT votes for the caught-up position are present after catch-up"
        );
        assert!(votes.iter().all(|v| v.approve));
    }

    // ── reaper_config_from_settings ──────────────────────────────────

    #[test]
    fn test_reaper_config_master_off_disables_all() {
        let s = ReaperSettings {
            enabled: false,
            ..Default::default()
        };
        let cfg = reaper_config_from_settings(&s);
        assert!(!cfg.enabled);
    }

    #[test]
    fn test_reaper_config_maps_per_vector() {
        let s = ReaperSettings {
            enabled: true,
            reject_inscription: false,
            reject_annex: false,
            reject_legacy_data_stuffing: false,
            max_op_return_bytes: 40,
            min_drop_size: 64,
            ..Default::default()
        };
        let cfg = reaper_config_from_settings(&s);
        assert!(cfg.enabled);
        // disabled vectors map through
        assert!(!cfg.reject_inscription_envelope);
        assert!(!cfg.reject_annex);
        assert!(!cfg.reject_legacy_data_stuffing);
        // untouched vectors stay on
        assert!(cfg.reject_drop_stuffing);
        assert!(cfg.reject_fake_pubkeys);
        assert!(cfg.reject_unreachable_code);
        assert!(cfg.reject_excess_witness);
        // thresholds map (canonical min_drop_size -> min_drop_data_size)
        assert_eq!(cfg.max_op_return_bytes, 40);
        assert_eq!(cfg.min_drop_data_size, 64);
        // valid for the analyzer
        assert!(cfg.validate().is_ok());
    }

    // ── cached_contribution_still_valid (MPC retry loop) ─────────────

    #[test]
    fn cached_contribution_valid_when_position_unchanged() {
        // Candidate generated at authoritative count N (targets position N+1).
        // A retry where the count is STILL N must keep the cached candidate so
        // the SAME new_hash is rebroadcast and votes accumulate toward quorum
        // (the fix for the "moving target" that stalled node5 on mainnet).
        let cached_count = 6u32;
        let current_count = 6u32;
        assert!(
            cached_contribution_still_valid(cached_count, current_count),
            "unchanged position must NOT invalidate the cached candidate"
        );
    }

    #[test]
    fn cached_contribution_invalid_when_position_advanced() {
        // Another contribution was applied while we waited (count N -> N+1):
        // our candidate is chained onto a stale head and MUST be regenerated
        // (rebased) onto the new head, so it is no longer valid to rebroadcast.
        let cached_count = 6u32;
        let current_count = 7u32;
        assert!(
            !cached_contribution_still_valid(cached_count, current_count),
            "advanced position MUST invalidate the cached candidate (rebase)"
        );
    }

    #[test]
    fn cached_contribution_invalid_on_multi_step_advance() {
        // Robust to more than one applied contribution during a long wait.
        assert!(!cached_contribution_still_valid(6, 9));
    }

    // ── should_claim_archive ─────────────────────────────────────────

    #[test]
    fn archive_claimed_only_when_config_on_and_ghostd_full() {
        // Operator asked for archive AND ghostd is a full (non-pruned, non-hazed)
        // node — this is the only combination that may advertise Archive (+5).
        assert!(should_claim_archive(true, false, false));
    }

    #[test]
    fn archive_not_claimed_when_ghostd_pruned() {
        // storage.archive_mode = true but ghostd is pruned: a pruned node cannot
        // serve arbitrary historical blocks, so the claim must be dropped even
        // though the config asks for it. This is the operator-reported bug.
        assert!(!should_claim_archive(true, false, true));
    }

    #[test]
    fn archive_not_claimed_when_ghostd_hazed() {
        // Hazed ghostd strips block data, so it also cannot satisfy the Archive
        // challenge regardless of the config flag.
        assert!(!should_claim_archive(true, true, false));
    }

    #[test]
    fn archive_not_claimed_when_config_off() {
        // Operator did not enable archive mode — never claim, whatever ghostd's
        // real state is.
        assert!(!should_claim_archive(false, false, false));
        assert!(!should_claim_archive(false, false, true));
        assert!(!should_claim_archive(false, true, false));
    }

    // ── expand_path ──────────────────────────────────────────────────

    #[test]
    fn expand_path_tilde_prefix() {
        let home = std::env::var("HOME").unwrap();
        let result = expand_path(Path::new("~/foo")).unwrap();
        assert_eq!(result, PathBuf::from(home).join("foo"));
    }

    #[test]
    fn expand_path_absolute_unchanged() {
        let result = expand_path(Path::new("/absolute/path")).unwrap();
        assert_eq!(result, PathBuf::from("/absolute/path"));
    }

    #[test]
    fn expand_path_relative_unchanged() {
        let result = expand_path(Path::new("relative/path")).unwrap();
        assert_eq!(result, PathBuf::from("relative/path"));
    }

    #[test]
    fn expand_path_tilde_deeply_nested() {
        let home = std::env::var("HOME").unwrap();
        let result = expand_path(Path::new("~/deeply/nested/path")).unwrap();
        assert_eq!(result, PathBuf::from(home).join("deeply/nested/path"));
    }

    #[test]
    fn expand_path_tilde_alone() {
        // strip_prefix("~/") doesn't match bare "~", so returned unchanged
        let result = expand_path(Path::new("~")).unwrap();
        assert_eq!(result, PathBuf::from("~"));
    }

    // ── load_config ──────────────────────────────────────────────────

    #[test]
    fn load_config_missing_file_returns_defaults() {
        let result = load_config(Path::new("/nonexistent/ghost.toml")).unwrap();
        let default = NodeConfig::default();
        assert_eq!(result.pool.min_payout_sats, default.pool.min_payout_sats);
    }

    #[test]
    fn load_config_valid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ghost.toml");
        // Serialize the default config, then override a field
        let mut default = NodeConfig::default();
        default.bitcoin.rpc_host = "10.0.0.1".to_string();
        default.bitcoin.rpc_user = "testuser".to_string();
        let toml_str = toml::to_string(&default).unwrap();
        std::fs::write(&path, &toml_str).unwrap();
        let config = load_config(&path).unwrap();
        assert_eq!(config.bitcoin.rpc_host, "10.0.0.1");
        assert_eq!(config.bitcoin.rpc_user, "testuser");
    }

    #[test]
    fn load_config_invalid_toml_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is [[[not valid toml").unwrap();
        assert!(load_config(&path).is_err());
    }

    #[test]
    fn load_config_empty_file_is_err() {
        // Empty TOML is missing required fields (identity, bitcoin, etc.)
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.toml");
        std::fs::write(&path, "").unwrap();
        assert!(load_config(&path).is_err());
    }

    // ── parse_log_level ──────────────────────────────────────────────

    #[test]
    fn parse_log_level_all_valid() {
        assert_eq!(parse_log_level("trace"), Level::TRACE);
        assert_eq!(parse_log_level("debug"), Level::DEBUG);
        assert_eq!(parse_log_level("info"), Level::INFO);
        assert_eq!(parse_log_level("warn"), Level::WARN);
        assert_eq!(parse_log_level("error"), Level::ERROR);
    }

    #[test]
    fn parse_log_level_case_insensitive() {
        assert_eq!(parse_log_level("TRACE"), Level::TRACE);
        assert_eq!(parse_log_level("Trace"), Level::TRACE);
        assert_eq!(parse_log_level("DEBUG"), Level::DEBUG);
    }

    #[test]
    fn parse_log_level_unknown_defaults_to_info() {
        assert_eq!(parse_log_level("verbose"), Level::INFO);
        assert_eq!(parse_log_level("nonsense"), Level::INFO);
    }

    #[test]
    fn parse_log_level_empty_defaults_to_info() {
        assert_eq!(parse_log_level(""), Level::INFO);
    }

    // ── is_loopback_url ──────────────────────────────────────────────

    #[test]
    fn is_loopback_url_127() {
        assert!(is_loopback_url("http://127.0.0.1:8800/api"));
    }

    #[test]
    fn is_loopback_url_localhost() {
        assert!(is_loopback_url("http://localhost:8800"));
    }

    #[test]
    fn is_loopback_url_ipv6() {
        assert!(is_loopback_url("http://[::1]:8800"));
    }

    #[test]
    fn is_loopback_url_external_ip() {
        assert!(!is_loopback_url("http://10.0.0.1:8800"));
    }

    #[test]
    fn is_loopback_url_external_domain() {
        assert!(!is_loopback_url("http://example.com:8800"));
    }

    // ── extract_peer_host ────────────────────────────────────────────

    #[test]
    fn extract_peer_host_ip_with_port() {
        assert_eq!(extract_peer_host("192.168.1.1:8080"), "192.168.1.1");
    }

    #[test]
    fn extract_peer_host_ip_without_port() {
        assert_eq!(extract_peer_host("192.168.1.1"), "192.168.1.1");
    }

    #[test]
    fn extract_peer_host_hostname_with_port() {
        assert_eq!(extract_peer_host("host.com:8080"), "host.com");
    }

    #[test]
    fn extract_peer_host_empty() {
        assert_eq!(extract_peer_host(""), "");
    }

    // ── resolve_signer_path ──────────────────────────────────────────

    #[test]
    fn resolve_signer_explicit_config() {
        let explicit = SignerConfig::Local {
            key_path: PathBuf::from("/custom/key"),
        };
        let result = resolve_signer_path(
            &Some(explicit.clone()),
            Path::new("/ignored"),
            Path::new("/also_ignored"),
        )
        .unwrap();
        assert_eq!(result, explicit);
    }

    #[test]
    fn resolve_signer_config_key_exists() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("node.key");
        std::fs::write(&key_path, "key_data").unwrap();
        let default_path = dir.path().join("default.key");

        let result = resolve_signer_path(&None, &key_path, &default_path).unwrap();
        assert_eq!(
            result,
            SignerConfig::Local {
                key_path: key_path.clone()
            }
        );
    }

    #[test]
    fn resolve_signer_config_key_missing_uses_default() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.key");
        let default_path = dir.path().join("default.key");

        let result = resolve_signer_path(&None, &missing, &default_path).unwrap();
        assert_eq!(
            result,
            SignerConfig::Local {
                key_path: default_path.clone()
            }
        );
    }

    #[test]
    fn resolve_signer_neither_path_exists() {
        let dir = tempfile::tempdir().unwrap();
        let missing1 = dir.path().join("a.key");
        let missing2 = dir.path().join("b.key");

        let result = resolve_signer_path(&None, &missing1, &missing2).unwrap();
        assert_eq!(
            result,
            SignerConfig::Local {
                key_path: missing2.clone()
            }
        );
    }

    // ── MPC / ZK trusted-setup param self-heal ───────────────────────

    #[cfg(feature = "mpc-ceremony")]
    fn sha256(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }

    /// A blob whose hash matches the pinned digest is trusted.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn params_blob_trusted_when_hash_matches() {
        let blob = vec![7u8; 4096];
        let expected = sha256(&blob);
        assert!(params_blob_is_trusted(&blob, Some(&expected)));
    }

    /// SECURITY: a forged blob (wrong hash) is rejected even though it is large
    /// enough — a malicious seed cannot inject it as the trusted set.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn params_blob_rejected_when_hash_mismatches() {
        let good = vec![7u8; 4096];
        let expected = sha256(&good);
        let forged = vec![9u8; 4096]; // same size, different bytes
        assert!(!params_blob_is_trusted(&forged, Some(&expected)));
    }

    /// A tiny blob is rejected regardless of hash pinning.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn params_blob_rejected_when_too_small() {
        let tiny = vec![0u8; 16];
        assert!(!params_blob_is_trusted(&tiny, None));
        let h = sha256(&tiny);
        assert!(!params_blob_is_trusted(&tiny, Some(&h)));
    }

    /// With no pinned hash (test nets) only the size gate applies.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn params_blob_unverified_accepts_large_blob() {
        let blob = vec![1u8; 2048];
        assert!(params_blob_is_trusted(&blob, None));
    }

    /// `ZK_PARAMS_HASH` parsing extracts each pinned type, upper-cases the key,
    /// and skips malformed entries without dropping the valid ones.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn parse_param_hashes_extracts_and_skips_malformed() {
        let block = "fa9db2b7".repeat(8); // 64 hex chars
        let payout = "0123abcd".repeat(8);
        let env = format!("block:{},garbage,PAYOUT:{},BAD:xyz,SHORT:00", block, payout);
        let map = parse_param_hashes(&env);
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get("BLOCK"),
            Some(&<[u8; 32]>::try_from(hex::decode(&block).unwrap().as_slice()).unwrap())
        );
        assert!(map.contains_key("PAYOUT"));
        assert!(!map.contains_key("BAD"));
        assert!(!map.contains_key("SHORT"));
    }

    /// An empty / unset value yields no pinned hashes (verification not enforced).
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn parse_param_hashes_empty_is_empty() {
        assert!(parse_param_hashes("").is_empty());
    }

    // ── Atomic write + verify-after-write + self-heal ────────────────

    /// `write_params_atomic` lands a file whose re-read hash matches the input,
    /// and leaves no stray temp file behind.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn write_params_atomic_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("note_spend_params_v0.bin");
        let blob = vec![0x42u8; 4096];

        write_params_atomic(&target, &blob).unwrap();

        assert!(target.exists());
        assert_eq!(sha256_file(&target).unwrap(), sha256(&blob));
        // No leftover temp files in the directory.
        let leftover = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains(".tmp."));
        assert!(!leftover, "atomic write must not leave a temp file behind");
    }

    /// A correctly-hashed blob installs cleanly: `current` exists, points at the
    /// `v0` file, and its hash matches the pinned digest.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn install_and_verify_param_success() {
        let dir = tempfile::tempdir().unwrap();
        let blob = vec![0x07u8; 4096];
        let pinned = sha256(&blob);

        let ok = install_and_verify_param(dir.path(), "note_spend_params", &blob, Some(&pinned));
        assert!(ok);

        let current = dir.path().join("note_spend_params_current.bin");
        let v0 = dir.path().join("note_spend_params_v0.bin");
        assert!(current.exists());
        assert!(v0.exists());
        assert_eq!(sha256_file(&current).unwrap(), pinned);
    }

    /// Bug-1 regression: generating a candidate must write a SEPARATE serving
    /// file keyed by its lineage hash and must NEVER touch the active
    /// `note_spend_params_current.bin`. Writing the un-applied candidate over
    /// current.bin crash-looped node5 (on-disk candidate != BFT chain head).
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn write_candidate_does_not_touch_current() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-existing applied head — must remain byte-for-byte untouched.
        let current = dir.path().join("note_spend_params_current.bin");
        let applied = vec![0x11u8; 4096];
        std::fs::write(&current, &applied).unwrap();

        let new_hash = [0xCDu8; 32];
        let candidate_blob = vec![0x22u8; 2048];
        let path =
            write_candidate_note_spend_params(dir.path(), &new_hash, &candidate_blob).unwrap();

        // The candidate lives in its own hash-keyed file, distinct from current.
        assert_eq!(
            path.file_name().unwrap().to_string_lossy(),
            ghost_common::mpc::candidate_note_spend_filename(&new_hash)
        );
        assert_ne!(path, current);
        assert_eq!(std::fs::read(&path).unwrap(), candidate_blob);
        // The active current.bin is unchanged — only the apply path may move it.
        assert_eq!(std::fs::read(&current).unwrap(), applied);

        // Writing a candidate for a NEW position purges the stale one but keeps
        // current.bin intact (serving dir never accumulates blobs).
        let new_hash2 = [0xEFu8; 32];
        let path2 =
            write_candidate_note_spend_params(dir.path(), &new_hash2, &vec![0x33u8; 1024]).unwrap();
        assert!(path2.exists());
        assert!(
            !path.exists(),
            "stale candidate from old position must be purged"
        );
        assert_eq!(std::fs::read(&current).unwrap(), applied);
    }

    /// SECURITY: if the on-disk file does not match the pinned hash after the
    /// write (simulated here by passing a non-matching expected hash), the
    /// verify-after-write step removes BOTH the `current` pointer and the `v0`
    /// file — no corrupt trusted-setup file is left behind to crash-loop a node.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn install_and_verify_param_mismatch_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let blob = vec![0x07u8; 4096];
        // Pin the hash of DIFFERENT content so verify-after-write must fail.
        let wrong = sha256(&vec![0x09u8; 4096]);

        let ok = install_and_verify_param(dir.path(), "note_spend_params", &blob, Some(&wrong));
        assert!(!ok, "mismatched params must report failure");

        let current = dir.path().join("note_spend_params_current.bin");
        let v0 = dir.path().join("note_spend_params_v0.bin");
        assert!(!current.exists(), "corrupt current params must be removed");
        assert!(!v0.exists(), "corrupt v0 params must be removed");
    }

    /// With no pinned hash (test nets) the install succeeds and leaves the file
    /// in place — there is nothing to verify it against, so the size gate in the
    /// caller is the only check.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn install_and_verify_param_unpinned_keeps_file() {
        let dir = tempfile::tempdir().unwrap();
        let blob = vec![0x07u8; 4096];

        let ok = install_and_verify_param(dir.path(), "note_spend_params", &blob, None);
        assert!(ok);
        assert!(dir.path().join("note_spend_params_current.bin").exists());
    }

    /// `ondisk_note_spend_valid` recognises a valid on-disk set (so the ceremony
    /// task does not re-fetch/clobber), and rejects a missing or mismatching one.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn ondisk_note_spend_valid_matrix() {
        let dir = tempfile::tempdir().unwrap();
        let blob = vec![0x33u8; 4096];
        let pinned = sha256(&blob);

        // Missing → false regardless of pinning.
        assert!(!ondisk_note_spend_valid(dir.path(), Some(&pinned)));
        assert!(!ondisk_note_spend_valid(dir.path(), None));

        // Install a valid set.
        assert!(install_and_verify_param(
            dir.path(),
            "note_spend_params",
            &blob,
            Some(&pinned)
        ));

        // Present + correct pinned → true.
        assert!(ondisk_note_spend_valid(dir.path(), Some(&pinned)));
        // Present + no pin (test net) → true.
        assert!(ondisk_note_spend_valid(dir.path(), None));
        // Present + WRONG pin → false.
        let wrong = sha256(&vec![0x44u8; 4096]);
        assert!(!ondisk_note_spend_valid(dir.path(), Some(&wrong)));
    }

    /// Quarantine moves the corrupt file aside (`.corrupt.<ts>`) and drops the
    /// live `current` pointer so a re-fetch can recreate it.
    #[cfg(all(feature = "zk-consensus", feature = "mpc-ceremony"))]
    #[test]
    fn quarantine_moves_corrupt_aside() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("note_spend_params_current.bin");
        std::fs::File::create(&current)
            .unwrap()
            .write_all(&[0xABu8; 4096])
            .unwrap();

        quarantine_corrupt_note_spend(dir.path());

        assert!(!current.exists(), "live current pointer must be dropped");
        let has_corrupt = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains(".corrupt."));
        assert!(has_corrupt, "a .corrupt. forensic copy should remain");
    }

    /// SELF-HEAL: a PRESENT-but-WRONG note_spend file (right size, wrong bytes —
    /// the node6 signature) must NOT pass. With a pinned BLOCK hash and no seeds
    /// to heal from, `ensure_mpc_params_present` quarantines the bad file and
    /// returns Err — it never returns `Ok(())` with a hash-mismatching file at
    /// the live path. Env-mutating, so it is the ONLY test that touches
    /// `ZK_PARAMS_HASH` (avoids intra-suite races).
    #[cfg(all(feature = "zk-consensus", feature = "mpc-ceremony"))]
    #[tokio::test]
    async fn ensure_present_but_corrupt_self_heals_not_ok() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let current = dir.path().join("note_spend_params_current.bin");
        // Right-sized but WRONG content.
        std::fs::File::create(&current)
            .unwrap()
            .write_all(&[0xABu8; 4096])
            .unwrap();

        // Pin a BLOCK hash that does NOT match the garbage on disk.
        let pinned = sha256(&[0x11u8; 4096]);
        let prev = std::env::var("ZK_PARAMS_HASH").ok();
        std::env::set_var("ZK_PARAMS_HASH", format!("BLOCK:{}", hex::encode(pinned)));

        // No seeds → cannot heal → must NOT return Ok while the bad file sits there.
        let res = ensure_mpc_params_present(&[], dir.path(), &expected_param_hashes()).await;

        // Restore env before asserting (so a panic cannot leak the override).
        match prev {
            Some(v) => std::env::set_var("ZK_PARAMS_HASH", v),
            None => std::env::remove_var("ZK_PARAMS_HASH"),
        }

        assert!(
            res.is_err(),
            "must NOT return Ok with a hash-mismatching file present"
        );
        assert!(
            !current.exists(),
            "the corrupt file must be quarantined away from the live path"
        );
        let has_corrupt = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains(".corrupt."));
        assert!(has_corrupt, "a .corrupt. forensic copy should remain");
    }

    /// LOCK the documented `params_blob_is_trusted(None)` behaviour AND prove it
    /// cannot apply to note_spend: note_spend is fetched via
    /// `try_fetch_params_from_seed`, which passes `expected.get("BLOCK")`. When
    /// `ZK_PARAMS_HASH` pins BLOCK (production), that lookup is `Some`, so the
    /// permissive `None` branch is never taken for note_spend.
    #[cfg(feature = "mpc-ceremony")]
    #[test]
    fn note_spend_block_hash_is_some_when_pinned() {
        let block = "ab12cd34".repeat(8); // 64 hex chars
        let map = parse_param_hashes(&format!("BLOCK:{}", block));
        // This is the exact key `try_fetch_params_from_seed` passes for note_spend.
        assert!(
            map.get("BLOCK").is_some(),
            "note_spend must resolve a pinned BLOCK hash, never None, in production"
        );
        // And a non-trivial blob with the None branch IS accepted — proving the
        // permissive path exists, which is exactly why note_spend must use Some.
        assert!(params_blob_is_trusted(&vec![1u8; 2048], None));
        assert!(!params_blob_is_trusted(&vec![1u8; 2048], map.get("BLOCK")));
    }
}
