//! `wraithd` — Wraith Wallet daemon.
//!
//! Long-running process that holds module state and exposes a local IPC surface
//! to the CLI and GUI. Phase 0 (closed): IPC + lifecycle + multi-wallet keystore.
//! Phase 1 (in progress): chain (REST → ghost-pay), gsp (WebSocket → ghost-gsp).
//!
//! Wallet layout: `~/.wraith/wallets/<name>/keystore.bin`. The "active" wallet is
//! tracked in memory only — it is set on `WalletCreate`, `WalletUnlock`, or
//! `WalletSelect`, and lost when the daemon restarts. Wallet-scoped commands
//! (`WalletDerive`, `WalletAuthInfo`, `LightReceive`) target the active wallet.

/// Channel-agnostic picker for resolving an elected coordinator's endpoint
/// (fetch path lands with the GUI toggle; see the module docs).
mod coordinator_resolve;

fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(server::serve())
}

/// Daemon core. The IPC transport is a cross-platform local socket
/// (Unix-domain socket on unix, named pipe on Windows) via the
/// `interprocess` crate; everything else in here is platform-neutral.
mod server {
    use std::collections::HashMap;
    #[cfg_attr(not(unix), allow(unused_imports))]
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;
    use std::time::Instant;

    use ghost_gsp_proto::{PaymentMode, SessionToken};
    use interprocess::local_socket::traits::tokio::{Listener as _, Stream as _};
    use interprocess::local_socket::ListenerOptions;
    use secrecy::SecretString;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::sync::RwLock;

    /// Full-duplex IPC stream (splits into [`IpcRecvHalf`] + [`IpcSendHalf`]).
    type IpcStream = interprocess::local_socket::tokio::Stream;
    /// Read half of a connection — feeds the newline-delimited request reader.
    type IpcRecvHalf = interprocess::local_socket::tokio::RecvHalf;
    /// Write half of a connection — carries JSON responses / pushes.
    type IpcSendHalf = interprocess::local_socket::tokio::SendHalf;
    use wraith_wallet_core::auth;
    use wraith_wallet_core::chain::ChainClient;
    use wraith_wallet_core::gsp::GspClient;
    use wraith_wallet_core::gsp::{
        spawn_session_with_bech32, GspError, SessionHandle, SessionPhase, SessionStatus,
    };
    use wraith_wallet_core::keystore::{Keystore, KeystoreError};
    use wraith_wallet_core::light;
    use wraith_wallet_core::signer::{Signer, SoftwareSigner};
    use wraith_wallet_ipc::{
        AnonymitySetReport, ChainStatusResponse, CheckForUpdateResponse, ConnectionStatusResponse,
        DaemonEnvResponse, DetectedPaymentEntry, DoctorCheck, DoctorResponse, Envelope,
        ErrorResponse, GlyphClaimResult, GlyphInfo, GspAuthResponse, GspPingResponse,
        GspSessionStatusResponse, HealthResponse, LightBalanceResponse, LightDetectedResponse,
        LightHistoryEntry, LightHistoryResponse, LightL1UtxoEntry, LightL1UtxosResponse,
        LightReceiveResponse, LightSentResponse, LightUtxoEntry, LightUtxosResponse, LockEntry,
        LocksConfirmedResponse, LocksJumpedResponse, LocksListResponse, LocksPreparedResponse,
        LocksRecoveredResponse, NodeEndpointsResponse, PsbtBroadcastResponse, PsbtBumpFeeResponse,
        PsbtInputSummary, PsbtInspectResponse, PsbtOutputSummary, PsbtSignResponse,
        ReleaseManifest, Request, Response, SignerInfoIpc, WalletAuthInfoResponse,
        WalletCreateResponse, WalletDeriveResponse, WalletGhostIdResponse, WalletListEntry,
        WalletListResponse, WalletShowMnemonicResponse, WalletStatusResponse, WalletXpubResponse,
        WraithDiscoverResponse, WraithDiscoverTier, WraithMixCompletedResponse,
        WraithMixPreparedResponse, WraithMixRefusedResponse,
    };

    /// Bundled public preset — the Bitcoin Ghost fleet, reachable without
    /// running your own node. `pool.bitcoinghost.org` round-robins the four
    /// fleet IPs; ghost-pay serves TLS on :8800 and GSP on :8900. A brand-new
    /// install defaults here so the wallet works out of the box.
    const PUBLIC_GHOST_PAY: &str = "https://pool.bitcoinghost.org:8800";
    const PUBLIC_GSP: &str = "wss://pool.bitcoinghost.org:8900/ws/v1";
    /// Node-selection preset labels. Persisted in `node.json` and surfaced via
    /// `DaemonEnv.node_preset` so the settings UI knows which radio is active.
    const PRESET_PUBLIC: &str = "public";
    const PRESET_CUSTOM: &str = "custom";
    /// Optional override for the on-disk node-selection config path. Defaults
    /// to `<wallets_dir>/../node.json` (i.e. `~/.wraith/node.json`).
    const NODE_CONFIG_ENV: &str = "WRAITHD_NODE_CONFIG";
    const GHOST_PAY_ENV: &str = "WRAITHD_GHOST_PAY";
    /// Optional shared secret for ghost-pay's `X-Internal-Auth`
    /// bypass. When set, the wallet can call ghost-pay's
    /// authenticated routes (e.g. `/api/v1/utxos/scan`) without
    /// HMAC. Required for the L1 UTXO scanner; other routes work
    /// without it.
    const GHOST_PAY_INTERNAL_AUTH_ENV: &str = "WRAITHD_GHOST_PAY_INTERNAL_AUTH";
    /// Optional default wraith-coordinator URL. When set, the
    /// `Doctor` check probes its `/api/v1/pool/discover` endpoint
    /// for liveness. Mixes still use the per-call URL the wallet
    /// supplies — this is purely for diagnostic / dev-stack
    /// purposes.
    const WRAITH_COORDINATOR_ENV: &str = "WRAITHD_WRAITH_COORDINATOR";
    /// Kiosk mode flag (`1`/`true`). When set, the daemon refuses
    /// wallet-management operations (create, import, select, lock).
    /// The operator selects and unlocks one wallet before enabling
    /// kiosk mode; the daemon then locks that decision in until it
    /// restarts. Used for retail/POS deployments where untrusted
    /// staff at the till should only be able to take payments.
    const KIOSK_MODE_ENV: &str = "WRAITHD_KIOSK_MODE";
    const GSP_ENV: &str = "WRAITHD_GSP";
    const WALLETS_DIR_ENV: &str = "WRAITHD_WALLETS_DIR";
    const NETWORK_ENV: &str = "WRAITHD_NETWORK";
    /// Optional SOCKS5 proxy (e.g. `socks5h://127.0.0.1:9050` for Tor).
    /// When set, all REST traffic to ghost-pay and ghost-gsp goes through it.
    /// The persistent WebSocket session does **not** yet honour this proxy.
    const TOR_PROXY_ENV: &str = "WRAITHD_TOR_PROXY";
    /// Optional bitcoind RPC config for the LocksRecover unilateral
    /// exit path. None of these are required to boot — only LocksRecover
    /// fails without them.
    const GHOSTD_URL_ENV: &str = "WRAITHD_GHOSTD_URL";
    const GHOSTD_COOKIE_ENV: &str = "WRAITHD_GHOSTD_COOKIE";
    const GHOSTD_USER_ENV: &str = "WRAITHD_GHOSTD_USER";
    const GHOSTD_PASS_ENV: &str = "WRAITHD_GHOSTD_PASS";
    // Unix reads this here to locate the socket file for housekeeping; on
    // Windows the same override is honoured inside `wraith_wallet_ipc`'s
    // pipe-name derivation, so the daemon never references it directly.
    #[cfg(unix)]
    const SOCKET_ENV: &str = "WRAITHD_SOCKET";
    const IDLE_LOCK_ENV: &str = "WRAITHD_IDLE_LOCK_SECS";
    const DEFAULT_IDLE_LOCK_SECS: u64 = 900;
    /// Default outbound-broadcast shroud window in milliseconds. Matches the
    /// 0–5 s window ghost-core uses for its Shroud relay layer; the wallet's
    /// shroud sits one hop earlier in the path (wallet → ghost-pay) and
    /// shares the same constant for symmetry.
    const SHROUD_ENV: &str = "WRAITHD_SHROUD_MAX_MS";
    const DEFAULT_SHROUD_MAX_MS: u64 = 5000;
    /// Phase 15: URL the daemon's CheckForUpdate handler fetches by default.
    /// Unset → no auto-update channel is configured; per-call URLs still work.
    const UPDATE_MANIFEST_ENV: &str = "WRAITHD_UPDATE_MANIFEST_URL";

    /// A `SessionToken` paired with the wallet name that produced it AND a live
    /// `SessionHandle` running the persistent authenticated WebSocket. Dropping
    /// the `StoredSession` aborts the session task (via `SessionHandle::Drop`).
    struct StoredSession {
        wallet_name: String,
        token: SessionToken,
        handle: SessionHandle,
    }

    /// In-flight Wraith Lite mix between `WraithMixPrepare` and
    /// `WraithMixSubmit`. Holds the prepared round + the client that
    /// produced it (so /witness submission re-uses the same HTTP
    /// client / proxy config without rebuilding it). Caller is
    /// expected to submit promptly — the coordinator's no-sign
    /// deadline is ticking.
    /// Turn a refusal into something the wallet can render.
    ///
    /// A refusal shown as a sentence gives the user nothing to decide with. The
    /// figures are what they need: how many entities were actually there, what
    /// was discounted, and whether the coordinator's claim was the problem.
    fn refusal_response(
        session_id: String,
        min_entities: usize,
        e: &wraith_wallet_core::wraith::WraithClientError,
    ) -> Option<WraithMixRefusedResponse> {
        use wraith_protocol::pre_sign::RefuseToSign;
        use wraith_wallet_core::wraith::WraithClientError;

        let WraithClientError::RefusedRound { reasons, report } = e else {
            return None;
        };

        // An over-claim is not a size problem. The coordinator stated a figure
        // the chain does not support, and no floor makes that acceptable — so
        // the wallet must not offer to lower one.
        let over_claimed = reasons
            .iter()
            .any(|r| matches!(r, RefuseToSign::SetOverClaimed { .. }));

        Some(WraithMixRefusedResponse {
            session_id,
            report: AnonymitySetReport {
                seats: report.seats,
                entities: report.entities,
                discounted: report.discounted(),
                unverified: report.unverified,
                payers: report.payers,
            },
            reasons: reasons.iter().map(ToString::to_string).collect(),
            min_entities,
            lowering_the_floor_would_help: !over_claimed,
        })
    }

    /// Open the durable once-per-coin ledger.
    ///
    /// Lives beside `node.json` in the wallet's data directory. Opened per
    /// operation rather than held: the file is small, the write is the
    /// expensive part either way, and a fresh read means a second process
    /// touching the same wallet cannot be missed.
    fn signing_ledger_for(
        state: &Arc<DaemonState>,
    ) -> std::io::Result<
        wraith_protocol::signing_ledger::SigningLedger<
            wraith_wallet_core::signing_ledger_file::FileSignatureStore,
        >,
    > {
        let path = state
            .node_config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("wraith-signed-coins.json");
        Ok(wraith_protocol::signing_ledger::SigningLedger::new(
            wraith_wallet_core::signing_ledger_file::FileSignatureStore::open(path)?,
        ))
    }

    struct StoredWraithMix {
        /// The **inspected** round. Not a `PreparedMix`: `submit_witness` will
        /// not accept anything else, so a round cannot reach the wire without
        /// having been checked and its coin committed.
        inspected: wraith_wallet_core::wraith::InspectedMix,
        client: Arc<wraith_wallet_core::wraith::WraithSessionClient>,
    }

    /// Local metadata for a Ghost Lock the wallet has prepared.
    /// Keyed by lock_id in `DaemonState::prepared_locks`. Required for
    /// the `LocksRecover` (unilateral exit) path — the wallet must
    /// know its recovery_index (to derive the secret), the full lock
    /// script details (to reconstruct the witness program), and the
    /// funding outpoint (to spend the right UTXO).
    ///
    /// Persisted to `<wallets_dir>/<wallet>/locks.json` so a daemon
    /// restart between LocksPrepare and LocksRecover doesn't lose
    /// the recovery_index. Loaded on wallet unlock; written on
    /// every prepare / confirm / recover.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct PreparedLockMeta {
        wallet_name: String,
        recovery_index: u32,
        lock_pubkey_hex: String,
        recovery_pubkey_hex: String,
        recovery_blocks: u32,
        creation_height: u32,
        funding_address: String,
        capacity_sats: u64,
        /// Set once `LocksConfirm` lands.
        funding_txid: Option<String>,
    }

    /// The live node clients + their configured URLs, held together so a
    /// runtime endpoint change (`SetNodeEndpoints`) swaps all of them
    /// atomically under one write lock. Read paths clone the `Arc`s out and
    /// release the lock immediately, so a slow ghost-pay/GSP call never blocks
    /// a config change and vice-versa.
    struct NodeClients {
        chain: Arc<dyn ChainClient>,
        gsp: Arc<GspClient>,
        /// Ghost-pay base URLs in failover order — surfaced via DaemonEnv.
        ghost_pay_urls: Vec<String>,
        /// GSP WS URLs in failover order — passed to spawn_session at gsp_auth time.
        gsp_urls: Vec<String>,
        /// Which node preset is active: `public` or `custom`. Drives the
        /// settings UI's radio selection.
        preset: String,
    }

    struct DaemonState {
        started: Instant,
        /// The active node clients + endpoint config. Swapped wholesale by
        /// `SetNodeEndpoints` without a daemon restart.
        clients: RwLock<NodeClients>,
        /// True when `WRAITHD_GHOST_PAY` / `WRAITHD_GSP` pinned the endpoints at
        /// boot. While either is set the URLs are power-user-owned: the UI shows
        /// them read-only and `SetNodeEndpoints` refuses to change them.
        ghost_pay_env_override: bool,
        gsp_env_override: bool,
        /// Absolute path to the persisted node-selection config (`node.json`).
        node_config_path: PathBuf,
        /// Optional ghost-pay `X-Internal-Auth` secret, kept so a runtime
        /// endpoint swap can rebuild the chain client with the same auth.
        ghost_pay_internal_auth: Option<String>,
        /// Optional SOCKS5 proxy for both REST and WS (e.g. socks5h://127.0.0.1:9050).
        /// Threaded into spawn_session so the persistent WS routes through Tor too.
        tor_proxy: Option<String>,
        /// Optional default wraith-coordinator URL — used by Doctor
        /// to probe coordinator liveness in the dev stack. None
        /// when unset, in which case Doctor skips the coordinator
        /// check.
        wraith_coordinator_url: Option<String>,
        /// Kiosk mode lock. When true, wallet-management operations
        /// (create, import, select, lock) are refused. The operator
        /// must select + unlock the active wallet before enabling
        /// kiosk mode. Set via `WRAITHD_KIOSK_MODE` at boot.
        kiosk_mode: bool,
        wallets_dir: PathBuf,
        wallets: RwLock<HashMap<String, Keystore>>,
        active: RwLock<Option<String>>,
        session: RwLock<Option<StoredSession>>,
        network: bitcoin::Network,
        /// Human-readable IPC endpoint (Unix socket path, or Windows
        /// `\\.\pipe\...` name). Surfaced via DaemonEnv for diagnostics.
        endpoint_display: String,
        /// Unix-seconds timestamp of the last user-driven IPC request.
        /// Health/Doctor/DaemonEnv don't bump this; everything else does.
        last_activity: std::sync::atomic::AtomicU64,
        /// Idle threshold in seconds. If 0, auto-lock is disabled.
        idle_lock_secs: u64,
        /// Phase 9 shroud relay: max ms the wallet holds a signed payment
        /// before submitting to ghost-pay. Each send picks a uniform random
        /// delay in [0, this]. 0 = disabled (broadcast immediately).
        shroud_max_ms: u64,
        /// Phase 15: default URL for the release manifest used by
        /// CheckForUpdate. None = no default channel; per-call overrides
        /// still work.
        update_manifest_url: Option<String>,
        /// Phase 5b: in-flight Wraith Lite mix sessions, keyed by
        /// session_id. Populated by `WraithMixPrepare` and consumed
        /// by `WraithMixSubmit`. Each entry holds a
        /// `wraith_wallet_core::wraith::PreparedMix` plus the
        /// `WraithSessionClient` that produced it (so submit reuses
        /// the same HTTP client / proxy config).
        wraith_mixes: RwLock<HashMap<String, StoredWraithMix>>,
        /// Locks the wallet has prepared, keyed by lock_id. Populated
        /// by `LocksPrepare`, consumed by `LocksRecover` (and consulted
        /// by `LocksConfirm` to attach the funding txid).
        prepared_locks: RwLock<HashMap<String, PreparedLockMeta>>,
        /// Monotonic counter for the wallet's own recovery-key derivation
        /// indices. Independent of any operator-side index. On wallet unlock it
        /// is advanced past the highest `recovery_index` persisted in
        /// `locks.json` (via `fetch_max`), so it never re-issues an index an
        /// existing lock already uses across a daemon restart.
        next_recovery_index: AtomicU32,
        /// Optional bitcoind RPC URL. Required for the LocksRecover
        /// (unilateral exit) path — wallet talks directly to bitcoind,
        /// not through ghost-pay. None disables the path; the IPC
        /// returns a clear "no bitcoind configured" error.
        ghostd_url: Option<String>,
        /// Cookie file path (preferred) OR explicit user/pass for
        /// bitcoind RPC auth. At most one of these branches is set.
        ghostd_cookie_path: Option<PathBuf>,
        ghostd_user: Option<String>,
        ghostd_pass: Option<String>,
        /// HTTP client used for daemon-side fetches outside the GSP/ghost-pay
        /// stack (currently just the manifest fetch). Reuses rustls so we
        /// don't pull in a second TLS implementation.
        http: reqwest::Client,
    }

    fn default_wallets_dir() -> PathBuf {
        if let Ok(p) = std::env::var(WALLETS_DIR_ENV) {
            return PathBuf::from(p);
        }
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".wraith").join("wallets")
    }

    fn ghost_network_from_bitcoin(n: bitcoin::Network) -> ghost_keys::GhostNetwork {
        match n {
            bitcoin::Network::Bitcoin => ghost_keys::GhostNetwork::Mainnet,
            bitcoin::Network::Testnet => ghost_keys::GhostNetwork::Testnet,
            bitcoin::Network::Signet => ghost_keys::GhostNetwork::Signet,
            bitcoin::Network::Regtest => ghost_keys::GhostNetwork::Regtest,
            // bitcoin 0.32 has more variants in non_exhaustive — default to Mainnet.
            _ => ghost_keys::GhostNetwork::Mainnet,
        }
    }

    /// Construct a fresh concrete `GhostPayClient` for the glyph
    /// routes. `state.chain` is a `dyn ChainClient` trait object, so
    /// it can't expose the inherent glyph methods — rebuild from the
    /// daemon's configured ghost-pay URLs + proxy, attaching the
    /// internal-auth secret (claim is an authenticated route).
    async fn build_ghost_pay_client(
        state: &DaemonState,
    ) -> Result<wraith_wallet_core::chain::GhostPayClient, String> {
        let mut c = wraith_wallet_core::chain::GhostPayClient::with_urls_and_proxy(
            state.ghost_pay_urls().await,
            state.tor_proxy.as_deref(),
        )
        .map_err(|e| format!("ghost-pay client: {e}"))?;
        if let Some(secret) = state.ghost_pay_internal_auth.as_ref() {
            if !secret.is_empty() {
                c = c.with_internal_secret(secret.clone());
            }
        }
        Ok(c)
    }

    /// Node-selection config persisted to `node.json`. Loaded at boot and
    /// rewritten whenever the user picks a node via `SetNodeEndpoints`. Absent
    /// on a fresh install — the daemon then falls back to the public preset.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct NodeConfig {
        /// `public` or `custom`.
        preset: String,
        ghost_pay_urls: Vec<String>,
        gsp_urls: Vec<String>,
    }

    /// Resolve where the node-selection config lives. `WRAITHD_NODE_CONFIG`
    /// overrides; otherwise it sits next to the wallets dir at
    /// `<wallets_dir>/../node.json` (i.e. `~/.wraith/node.json`).
    fn node_config_path(wallets_dir: &std::path::Path) -> PathBuf {
        if let Ok(p) = std::env::var(NODE_CONFIG_ENV) {
            if !p.is_empty() {
                return PathBuf::from(p);
            }
        }
        let base = wallets_dir.parent().unwrap_or(wallets_dir);
        base.join("node.json")
    }

    /// Read `node.json`. Absent or malformed → `None` (a corrupt file must not
    /// wedge the daemon; it falls back to the public preset and the next save
    /// overwrites it).
    fn load_node_config(path: &std::path::Path) -> Option<NodeConfig> {
        let raw = fs::read_to_string(path).ok()?;
        match serde_json::from_str::<NodeConfig>(&raw) {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "ignoring malformed node.json");
                None
            }
        }
    }

    /// Persist `node.json` atomically (temp-file + rename) with 0600 perms on
    /// unix — the file only lists endpoint URLs, but it lives in the wallet
    /// data dir so we keep it user-private like the keystores.
    fn save_node_config(path: &std::path::Path, cfg: &NodeConfig) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(cfg).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Validate + parse a custom node's ghost-pay and GSP URL strings (each may
    /// be a comma-separated failover list). Rejects empty input and the wrong
    /// scheme so a typo can't silently leave the wallet pointed at nothing.
    fn validate_custom_endpoints(
        pay_raw: &str,
        gsp_raw: &str,
    ) -> Result<(Vec<String>, Vec<String>), String> {
        let pay = wraith_wallet_core::chain::GhostPayClient::parse_urls(pay_raw);
        let gsp = wraith_wallet_core::gsp::GspClient::parse_urls(gsp_raw);
        if pay.is_empty() {
            return Err("a ghost-pay URL is required for a custom node".to_string());
        }
        if gsp.is_empty() {
            return Err("a GSP URL is required for a custom node".to_string());
        }
        for u in &pay {
            if !(u.starts_with("http://") || u.starts_with("https://")) {
                return Err(format!(
                    "ghost-pay URL must start with http:// or https:// — got '{u}'"
                ));
            }
        }
        for u in &gsp {
            if !(u.starts_with("ws://") || u.starts_with("wss://")) {
                return Err(format!(
                    "GSP URL must start with ws:// or wss:// — got '{u}'"
                ));
            }
        }
        Ok((pay, gsp))
    }

    impl DaemonState {
        async fn chain(&self) -> Arc<dyn ChainClient> {
            self.clients.read().await.chain.clone()
        }
        async fn gsp(&self) -> Arc<GspClient> {
            self.clients.read().await.gsp.clone()
        }
        async fn ghost_pay_urls(&self) -> Vec<String> {
            self.clients.read().await.ghost_pay_urls.clone()
        }
        async fn gsp_urls(&self) -> Vec<String> {
            self.clients.read().await.gsp_urls.clone()
        }
        /// Build a fresh ghost-pay chain client for `urls`, reusing the daemon's
        /// tor proxy + internal-auth secret.
        fn build_chain(&self, urls: Vec<String>) -> Result<Arc<dyn ChainClient>, String> {
            let mut c = wraith_wallet_core::chain::GhostPayClient::with_urls_and_proxy(
                urls,
                self.tor_proxy.as_deref(),
            )
            .map_err(|e| format!("ghost-pay client: {e}"))?;
            if let Some(secret) = self.ghost_pay_internal_auth.as_ref() {
                if !secret.is_empty() {
                    c = c.with_internal_secret(secret.clone());
                }
            }
            Ok(Arc::new(c))
        }

        /// Apply a node selection at runtime: rebuild the ghost-pay + GSP
        /// clients, persist the choice to `node.json`, and drop any live GSP
        /// session so it re-authenticates against the new endpoint. Refuses
        /// while an env-var override pins the endpoints (power-user precedence).
        async fn set_node_endpoints(
            &self,
            preset: &str,
            ghost_pay_url: Option<String>,
            gsp_url: Option<String>,
        ) -> Result<NodeEndpointsResponse, String> {
            if self.ghost_pay_env_override || self.gsp_env_override {
                return Err("node endpoints are pinned by environment variables \
                     (WRAITHD_GHOST_PAY / WRAITHD_GSP); unset them to manage the \
                     node from the wallet"
                    .to_string());
            }
            let (ghost_pay_urls, gsp_urls, preset_label) = match preset {
                PRESET_PUBLIC => (
                    vec![PUBLIC_GHOST_PAY.to_string()],
                    vec![PUBLIC_GSP.to_string()],
                    PRESET_PUBLIC.to_string(),
                ),
                PRESET_CUSTOM => {
                    let (pay, gsp) = validate_custom_endpoints(
                        ghost_pay_url.as_deref().unwrap_or(""),
                        gsp_url.as_deref().unwrap_or(""),
                    )?;
                    (pay, gsp, PRESET_CUSTOM.to_string())
                }
                other => {
                    return Err(format!(
                        "unknown node preset '{other}' (expected 'public' or 'custom')"
                    ))
                }
            };
            // Build the replacements before touching anything — if either fails
            // we leave the running config untouched.
            let chain = self.build_chain(ghost_pay_urls.clone())?;
            let gsp = Arc::new(
                wraith_wallet_core::gsp::GspClient::with_urls_and_proxy(
                    gsp_urls.clone(),
                    self.tor_proxy.as_deref(),
                )
                .map_err(|e| format!("gsp client: {e}"))?,
            );
            // Persist first: if the disk write fails we refuse rather than run
            // on a config a restart would silently revert.
            let cfg = NodeConfig {
                preset: preset_label.clone(),
                ghost_pay_urls: ghost_pay_urls.clone(),
                gsp_urls: gsp_urls.clone(),
            };
            save_node_config(&self.node_config_path, &cfg)
                .map_err(|e| format!("persist node.json: {e}"))?;
            {
                let mut w = self.clients.write().await;
                w.chain = chain;
                w.gsp = gsp;
                w.ghost_pay_urls = ghost_pay_urls.clone();
                w.gsp_urls = gsp_urls.clone();
                w.preset = preset_label.clone();
            }
            // Old session points at the old GSP URL; drop it so the header's
            // auto-auth re-establishes one against the new endpoint.
            *self.session.write().await = None;
            tracing::info!(
                preset = %preset_label,
                ghost_pay = ?ghost_pay_urls,
                gsp = ?gsp_urls,
                "node endpoints updated at runtime",
            );
            Ok(NodeEndpointsResponse {
                preset: preset_label,
                ghost_pay_urls,
                gsp_urls,
            })
        }
    }

    /// Compute the glyph bitmap uniqueness hash exactly as
    /// ghost-glyph defines it: hex(SHA256("GhostGlyphBitmap/v1" ||
    /// pixels)). Must stay byte-for-byte identical to
    /// `GhostGlyph::compute_bitmap_hash` or `check` queries the
    /// wrong key.
    fn glyph_bitmap_hash_hex(pixels: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"GhostGlyphBitmap/v1");
        hasher.update(pixels);
        hex::encode(hasher.finalize())
    }

    fn parse_network(s: &str) -> Option<bitcoin::Network> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mainnet" | "bitcoin" => Some(bitcoin::Network::Bitcoin),
            "testnet" => Some(bitcoin::Network::Testnet),
            "signet" => Some(bitcoin::Network::Signet),
            "regtest" => Some(bitcoin::Network::Regtest),
            _ => None,
        }
    }

    /// Reject names that would let a caller traverse outside `wallets_dir` or
    /// produce ambiguous on-disk paths.
    /// Decode the hex user-entropy digest a front-end collected.
    ///
    /// Strict about the shape and indifferent to the content: any 32 bytes
    /// are acceptable because mixing is one-directional. What is refused is
    /// a value that is not a digest at all, which would be a caller bug
    /// worth surfacing rather than silently ignoring.
    fn decode_entropy_digest(hex_digest: &str) -> Result<[u8; 32], String> {
        let bytes = hex::decode(hex_digest.trim())
            .map_err(|e| format!("user_entropy_digest is not hex: {e}"))?;
        bytes
            .try_into()
            .map_err(|_| "user_entropy_digest must be exactly 32 bytes".to_string())
    }

    /// Re-derive the election's beacon from the wallet's own node.
    ///
    /// Returns `true` when the beacon matches the anchor block's hash, and
    /// also when this wallet has no node configured — in that case there is
    /// nothing to pin against, and the weaker guarantee (`election_is_honest`
    /// alone) is what the caller gets. Refusing outright would leave every
    /// node-less wallet unable to use an election at all, which is a worse
    /// answer than a stated-weaker check.
    ///
    /// A node that is configured but unreachable is also not a refusal: an
    /// operator's election is not made dishonest by the wallet's own bitcoind
    /// being down, and treating it as such would hand anyone who can knock
    /// out a wallet's node the power to force it onto a manual coordinator.
    fn beacon_pinned_to_chain(state: &DaemonState, election: &serde_json::Value) -> bool {
        use wraith_wallet_core::ghostd::GhostdRpc;

        let Some((anchor_height, _)) =
            crate::coordinator_resolve::beacon_anchor_expectation(election)
        else {
            // No beacon published at all — `election_is_honest` refuses this
            // on its own, so there is nothing to add here.
            return true;
        };
        let Some(url) = state.ghostd_url.as_deref() else {
            tracing::debug!("no bitcoind configured; election beacon not pinned to the chain");
            return true;
        };
        let rpc = match (
            state.ghostd_cookie_path.as_ref(),
            state.ghostd_user.as_deref(),
            state.ghostd_pass.as_deref(),
        ) {
            (Some(cookie), None, None) => match GhostdRpc::from_cookie(url, cookie.as_path()) {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(error = %e, "bitcoind auth unusable; beacon not pinned");
                    return true;
                }
            },
            (None, Some(u), Some(p)) => GhostdRpc::new(url, u, p),
            _ => return true,
        };
        match rpc.get_block_hash(anchor_height) {
            Ok(hash) => crate::coordinator_resolve::beacon_matches_chain(election, &hash),
            Err(e) => {
                tracing::debug!(error = %e, anchor_height, "anchor block unreachable; beacon not pinned");
                true
            }
        }
    }

    fn validate_wallet_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("wallet name must not be empty".into());
        }
        if name.len() > 64 {
            return Err("wallet name too long (max 64 chars)".into());
        }
        let allowed = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
        if !name.chars().all(allowed) {
            return Err("wallet name must be ascii alphanumeric, '-', or '_' only".into());
        }
        Ok(())
    }

    fn keystore_path(wallets_dir: &Path, name: &str) -> PathBuf {
        wallets_dir.join(name).join("keystore.bin")
    }

    /// Per-wallet directory for saved multisig descriptors. Each
    /// descriptor lives in its own file (`<name>.desc`) so adding /
    /// removing one doesn't risk corrupting the others.
    fn descriptors_dir(wallets_dir: &Path, wallet_name: &str) -> PathBuf {
        wallets_dir.join(wallet_name).join("descriptors")
    }

    fn descriptor_path(wallets_dir: &Path, wallet_name: &str, desc_name: &str) -> PathBuf {
        descriptors_dir(wallets_dir, wallet_name).join(format!("{desc_name}.desc"))
    }

    /// Same allow-list as `validate_wallet_name`. Re-used so a
    /// descriptor-name traversal can't be smuggled past
    /// `descriptor_path`.
    fn validate_descriptor_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("descriptor name must not be empty".into());
        }
        if name.len() > 64 {
            return Err("descriptor name too long (max 64 chars)".into());
        }
        let allowed = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
        if !name.chars().all(allowed) {
            return Err("descriptor name must be ascii alphanumeric, '-', or '_' only".into());
        }
        Ok(())
    }

    /// Per-wallet on-disk index of prepared Ghost Locks. Each entry
    /// carries everything `LocksRecover` needs to spend the recovery
    /// branch without operator cooperation: the recovery_index, the
    /// full lock script details, and the funding outpoint.
    ///
    /// Stored as plain JSON at `<wallets_dir>/<name>/locks.json`
    /// with file mode 0600. The data isn't a seed — losing the
    /// file means the wallet can't recover via this path, but the
    /// recovery_secret can still be re-derived from the keystore
    /// if the user remembers / can scan back through indices.
    /// Treating the file as plain (not encrypted) keeps the
    /// recovery flow accessible even if the keystore is locked at
    /// scan time. This is a deliberate trade-off; documented.
    fn locks_path(wallets_dir: &Path, name: &str) -> PathBuf {
        wallets_dir.join(name).join("locks.json")
    }

    /// Persist the subset of prepared_locks that belongs to
    /// `wallet_name`. Called from every dispatch arm that mutates
    /// the in-memory map (LocksPrepare, LocksConfirm, LocksRecover).
    /// Filtering by wallet_name keeps each wallet's locks file
    /// isolated even when multiple wallets are unlocked at once.
    async fn persist_prepared_locks(state: &Arc<DaemonState>, wallet_name: &str) {
        let snapshot: HashMap<String, PreparedLockMeta> = state
            .prepared_locks
            .read()
            .await
            .iter()
            .filter(|(_, m)| m.wallet_name == wallet_name)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if let Err(e) = save_locks_for_wallet(&state.wallets_dir, wallet_name, &snapshot) {
            tracing::warn!(wallet = %wallet_name, error = %e, "failed to persist locks");
        }
    }

    /// Atomic write to `path`: serialise `locks` as pretty JSON,
    /// write to a temp file, fsync, rename. Mode 0600.
    fn save_locks_for_wallet(
        wallets_dir: &Path,
        wallet_name: &str,
        locks: &HashMap<String, PreparedLockMeta>,
    ) -> std::io::Result<()> {
        let path = locks_path(wallets_dir, wallet_name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(locks).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            use std::io::Write;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        // mode 0600 on Unix; Windows inherits the user-profile ACL.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&tmp)?.permissions();
            perm.set_mode(0o600);
            std::fs::set_permissions(&tmp, perm)?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Load whatever's at `<wallets_dir>/<name>/locks.json`. Returns
    /// an empty map when the file doesn't exist. Logs and returns
    /// empty on parse error rather than refusing to unlock — a
    /// corrupt locks file shouldn't make the wallet unusable.
    fn load_locks_for_wallet(
        wallets_dir: &Path,
        wallet_name: &str,
    ) -> HashMap<String, PreparedLockMeta> {
        let path = locks_path(wallets_dir, wallet_name);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
            Err(e) => {
                tracing::warn!(?path, error = %e, "could not read locks file");
                return HashMap::new();
            }
        };
        match serde_json::from_slice::<HashMap<String, PreparedLockMeta>>(&bytes) {
            Ok(map) => map,
            Err(e) => {
                tracing::warn!(?path, error = %e, "locks file is corrupt — ignoring");
                HashMap::new()
            }
        }
    }

    /// Advance `counter` past the highest `recovery_index` present in `locks`,
    /// monotonically (`fetch_max` never lowers it). Called on every wallet
    /// unlock so a daemon restart never re-issues a recovery-derivation index an
    /// existing lock already uses — which would re-derive the same recovery key
    /// and break the lock's unilateral-exit guarantee. No-op when `locks` is
    /// empty.
    fn advance_recovery_index_past_locks(
        counter: &AtomicU32,
        locks: &HashMap<String, PreparedLockMeta>,
    ) {
        if let Some(max_idx) = locks.values().map(|m| m.recovery_index).max() {
            counter.fetch_max(max_idx + 1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Enumerate every directory under `wallets_dir` that contains a `keystore.bin`.
    fn list_on_disk(wallets_dir: &Path) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(wallets_dir) else {
            return Vec::new();
        };
        let mut names = Vec::new();
        for entry in entries.flatten() {
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if validate_wallet_name(&name).is_err() {
                continue;
            }
            if keystore_path(wallets_dir, &name).is_file() {
                names.push(name);
            }
        }
        names.sort();
        names
    }

    pub async fn serve() -> std::io::Result<()> {
        // WRAITHD_SOCKET override lets operators run multiple daemons (one
        // per wallet "profile") without endpoint collisions, and lets
        // integration tests bind their own ephemeral socket. Falls back to
        // the OS-default path so the common case is unchanged. On Unix the
        // concrete filesystem path is needed for stale-file removal and the
        // 0600 chmod; Windows named pipes have no filesystem presence.
        #[cfg(unix)]
        let socket_path = match std::env::var(SOCKET_ENV) {
            Ok(p) if !p.is_empty() => std::path::PathBuf::from(p),
            _ => wraith_wallet_ipc::default_socket_path(),
        };
        let endpoint_display = wraith_wallet_ipc::endpoint_display();
        let tor_proxy = std::env::var(TOR_PROXY_ENV).ok();
        let ghostd_url = std::env::var(GHOSTD_URL_ENV).ok();
        let ghostd_cookie_path = std::env::var(GHOSTD_COOKIE_ENV).ok().map(PathBuf::from);
        let ghostd_user = std::env::var(GHOSTD_USER_ENV).ok();
        let ghostd_pass = std::env::var(GHOSTD_PASS_ENV).ok();
        let ghost_pay_internal_auth = std::env::var(GHOST_PAY_INTERNAL_AUTH_ENV)
            .ok()
            .filter(|s| !s.is_empty());
        let wallets_dir = default_wallets_dir();
        let node_config_path = node_config_path(&wallets_dir);
        let network = std::env::var(NETWORK_ENV)
            .ok()
            .and_then(|s| parse_network(&s))
            .unwrap_or(bitcoin::Network::Bitcoin);

        // Endpoint resolution precedence, per field:
        //   1. WRAITHD_GHOST_PAY / WRAITHD_GSP env var (power-user override)
        //   2. persisted node.json (the choice made in the wallet UI)
        //   3. bundled public preset (so a fresh install works out of the box)
        // Both env vars still accept a comma-separated failover list.
        let persisted = load_node_config(&node_config_path);
        let ghost_pay_env = std::env::var(GHOST_PAY_ENV).ok().filter(|s| !s.is_empty());
        let gsp_env = std::env::var(GSP_ENV).ok().filter(|s| !s.is_empty());
        let ghost_pay_env_override = ghost_pay_env.is_some();
        let gsp_env_override = gsp_env.is_some();
        // A persisted `public` preset is symbolic — it always resolves to the
        // *current* bundled fleet URLs, so a client that once picked "public"
        // follows the fleet if these constants change in a later release.
        let persisted_is_public = persisted.as_ref().map(|c| c.preset == PRESET_PUBLIC);
        let ghost_pay_urls = if let Some(raw) = ghost_pay_env {
            wraith_wallet_core::chain::GhostPayClient::parse_urls(&raw)
        } else if persisted_is_public == Some(false) {
            persisted.as_ref().unwrap().ghost_pay_urls.clone()
        } else {
            vec![PUBLIC_GHOST_PAY.to_string()]
        };
        let gsp_urls = if let Some(raw) = gsp_env {
            wraith_wallet_core::gsp::GspClient::parse_urls(&raw)
        } else if persisted_is_public == Some(false) {
            persisted.as_ref().unwrap().gsp_urls.clone()
        } else {
            vec![PUBLIC_GSP.to_string()]
        };
        // Preset label for the settings UI: a persisted choice wins; otherwise
        // an env override reads as `custom`, and a clean fresh install reads as
        // `public` (the bundled default it just fell back to).
        let node_preset = if let Some(cfg) = persisted.as_ref() {
            cfg.preset.clone()
        } else if ghost_pay_env_override || gsp_env_override {
            PRESET_CUSTOM.to_string()
        } else {
            PRESET_PUBLIC.to_string()
        };
        tracing::info!(
            preset = %node_preset,
            ghost_pay = ?ghost_pay_urls,
            gsp = ?gsp_urls,
            wallets_dir = %wallets_dir.display(),
            network = ?network,
            tor_proxy = ?tor_proxy,
            ghost_pay_env_override,
            gsp_env_override,
            "node endpoints + wallets dir + network configured",
        );

        let chain: Arc<dyn ChainClient> = {
            let mut c = wraith_wallet_core::chain::GhostPayClient::with_urls_and_proxy(
                ghost_pay_urls.clone(),
                tor_proxy.as_deref(),
            )
            .map_err(|e| std::io::Error::other(format!("ghost-pay client: {e}")))?;
            if let Some(secret) = ghost_pay_internal_auth.as_ref() {
                if !secret.is_empty() {
                    c = c.with_internal_secret(secret.clone());
                }
            }
            Arc::new(c)
        };
        let gsp = Arc::new(
            wraith_wallet_core::gsp::GspClient::with_urls_and_proxy(
                gsp_urls.clone(),
                tor_proxy.as_deref(),
            )
            .map_err(|e| std::io::Error::other(format!("gsp client: {e}")))?,
        );

        let idle_lock_secs = std::env::var(IDLE_LOCK_ENV)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_IDLE_LOCK_SECS);
        let shroud_max_ms = std::env::var(SHROUD_ENV)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_SHROUD_MAX_MS);
        let update_manifest_url = std::env::var(UPDATE_MANIFEST_ENV)
            .ok()
            .filter(|s| !s.is_empty());

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent(concat!("wraithd/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| std::io::Error::other(format!("http client: {e}")))?;

        let wraith_coordinator_url = std::env::var(WRAITH_COORDINATOR_ENV)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let kiosk_mode = std::env::var(KIOSK_MODE_ENV)
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        if kiosk_mode {
            tracing::info!("kiosk mode enabled — wallet-management operations will be refused");
        }
        let state = Arc::new(DaemonState {
            started: Instant::now(),
            clients: RwLock::new(NodeClients {
                chain,
                gsp,
                ghost_pay_urls,
                gsp_urls,
                preset: node_preset,
            }),
            ghost_pay_env_override,
            gsp_env_override,
            node_config_path,
            ghost_pay_internal_auth,
            tor_proxy: tor_proxy.clone(),
            wraith_coordinator_url,
            kiosk_mode,
            wallets_dir,
            wallets: RwLock::new(HashMap::new()),
            active: RwLock::new(None),
            session: RwLock::new(None),
            network,
            endpoint_display: endpoint_display.clone(),
            last_activity: std::sync::atomic::AtomicU64::new(now_unix_secs()),
            idle_lock_secs,
            shroud_max_ms,
            update_manifest_url,
            http,
            wraith_mixes: RwLock::new(HashMap::new()),
            prepared_locks: RwLock::new(HashMap::new()),
            next_recovery_index: AtomicU32::new(0),
            ghostd_url,
            ghostd_cookie_path,
            ghostd_user,
            ghostd_pass,
        });

        // Auto-lock task. Wakes every 30 s. If idle_lock_secs is 0 the task
        // exits immediately — no overhead when the feature is disabled.
        if idle_lock_secs > 0 {
            tokio::spawn(idle_lock_task(state.clone()));
        }

        // Unix-domain sockets leave a filesystem entry; clear any stale one
        // and ensure the parent dir exists before binding. Windows named
        // pipes have no such artefact, so this housekeeping is unix-only.
        #[cfg(unix)]
        {
            if socket_path.exists() {
                tracing::warn!(
                    path = %socket_path.display(),
                    "stale socket file present, removing"
                );
                fs::remove_file(&socket_path)?;
            }
            if let Some(parent) = socket_path.parent() {
                fs::create_dir_all(parent)?;
            }
        }

        let name = wraith_wallet_ipc::endpoint_name()?;
        let listener = ListenerOptions::new().name(name).create_tokio()?;
        // Restrict the endpoint to the current user. On Unix we chmod the
        // socket to 0600; on Windows the default named-pipe ACL already
        // limits access to the pipe's creator plus SYSTEM/administrators,
        // which is equivalent for a per-user daemon.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        }
        tracing::info!(endpoint = %endpoint_display, "wraithd listening");

        // Watch for shutdown signals (SIGTERM / SIGINT on Unix, Ctrl-C on
        // Windows) so we can drop the listener, kill any active session
        // task, and clean up before exiting. Created once and polled each
        // loop iteration via `&mut`.
        let shutdown = shutdown_signal();
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    match accept {
                        Ok(stream) => {
                            let state = Arc::clone(&state);
                            tokio::spawn(handle_connection(stream, state));
                        }
                        Err(e) => {
                            tracing::warn!(?e, "accept failed");
                        }
                    }
                }
                _ = &mut shutdown => {
                    tracing::info!("shutdown signal received, shutting down");
                    break;
                }
            }
        }

        // Drop the active GSP session (SessionHandle::Drop aborts the task).
        *state.session.write().await = None;
        // Wallets clear on drop (zeroized).
        state.wallets.write().await.clear();
        // Remove the socket so the next startup doesn't see a stale file.
        // (Named pipes vanish with the listener; nothing to unlink on Windows.)
        #[cfg(unix)]
        let _ = fs::remove_file(&socket_path);
        tracing::info!("wraithd stopped");
        Ok(())
    }

    /// Resolve when the OS asks the daemon to shut down. Unix listens for
    /// SIGTERM and SIGINT; Windows listens for Ctrl-C (the portable
    /// `tokio::signal::ctrl_c`, which also fires on `CTRL_CLOSE`/logoff).
    #[cfg(unix)]
    async fn shutdown_signal() {
        use tokio::signal::unix::{signal, SignalKind};
        // If a handler can't be installed the daemon still runs; it just
        // won't get a graceful-shutdown notification for that signal.
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(?e, "could not install SIGTERM handler");
                return std::future::pending().await;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(?e, "could not install SIGINT handler");
                return std::future::pending().await;
            }
        };
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = sigint.recv() => {}
        }
    }

    /// See the Unix variant above.
    #[cfg(windows)]
    async fn shutdown_signal() {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(?e, "could not listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    }

    async fn handle_connection(stream: IpcStream, state: Arc<DaemonState>) {
        let (reader, mut writer) = stream.split();
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            // Streaming subscriptions short-circuit the request/response cycle:
            // we ack on the original id, then keep writing pushes (id=0) until
            // the client drops. After the stream ends the connection is done —
            // we don't try to read more requests on the same connection.
            if let Ok(env) = serde_json::from_str::<Envelope<Request>>(&line) {
                if matches!(env.payload, Request::WatchPayments) {
                    let ack: Envelope<Response> = Envelope::new(env.id, Response::Watching);
                    if !write_envelope(&mut writer, &ack).await {
                        return;
                    }
                    run_watch_payments(writer, lines, state.clone()).await;
                    return;
                }
            }
            let response = dispatch(&line, &state).await;
            if !write_envelope(&mut writer, &response).await {
                return;
            }
        }
    }

    async fn write_envelope(writer: &mut IpcSendHalf, env: &Envelope<Response>) -> bool {
        let mut out = match serde_json::to_string(env) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(?e, "failed to serialise response");
                return true; // Skip this one; keep the connection open.
            }
        };
        out.push('\n');
        if let Err(e) = writer.write_all(out.as_bytes()).await {
            tracing::warn!(?e, "client write failed");
            return false;
        }
        true
    }

    /// Streaming WatchPayments handler. Subscribes to the active session's
    /// payment-detection broadcast and forwards each event as a push envelope
    /// (id=0). Exits when the client disconnects, the active session is
    /// rotated out, or the broadcast channel is closed.
    async fn run_watch_payments(
        mut writer: IpcSendHalf,
        mut lines: tokio::io::Lines<BufReader<IpcRecvHalf>>,
        state: Arc<DaemonState>,
    ) {
        let mut rx = match state.session.read().await.as_ref() {
            Some(s) => s.handle.subscribe_payments(),
            None => {
                let err: Envelope<Response> = Envelope::new(
                    0,
                    Response::Error(ErrorResponse {
                        message: "no active session; call gsp_auth first".to_string(),
                    }),
                );
                let _ = write_envelope(&mut writer, &err).await;
                return;
            }
        };
        loop {
            tokio::select! {
                read = lines.next_line() => {
                    // The client closed (or sent another request — we don't accept
                    // anything else on a watch connection; just hang up).
                    match read {
                        Ok(Some(_)) => return,
                        _ => return,
                    }
                }
                event = rx.recv() => {
                    match event {
                        Ok(d) => {
                            let push: Envelope<Response> = Envelope::new(
                                0,
                                Response::PaymentDetected(DetectedPaymentEntry {
                                    txid: d.txid,
                                    block_height: d.block_height,
                                    vout: d.vout,
                                    amount_sats: d.amount_sats,
                                    k: d.k,
                                    received_at: d.received_at,
                                }),
                            );
                            if !write_envelope(&mut writer, &push).await {
                                return;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(missed = n, "watch_payments lagged; client should resync via light_detected");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            // Session was rotated out — close the watch.
                            return;
                        }
                    }
                }
            }
        }
    }

    /// `GspAuth` orchestration: register-if-needed + session. Stores the resulting
    /// `SessionToken` in `state.session` so subsequent commits can use it to open
    /// a persistent authenticated WebSocket.
    async fn gsp_auth(state: &Arc<DaemonState>) -> Result<GspAuthResponse, String> {
        // 1. Get the auth keypair + active wallet name.
        let (active_name, kp) = {
            let active = state
                .active
                .read()
                .await
                .clone()
                .ok_or_else(|| "no active wallet".to_string())?;
            let wallets = state.wallets.read().await;
            let ks = wallets
                .get(&active)
                .ok_or_else(|| format!("active wallet '{active}' is not unlocked"))?;
            let kp = auth::auth_keypair(ks).map_err(|e| format!("auth keypair: {e}"))?;
            (active, kp)
        };
        let wallet_id = auth::wallet_id_hex(&kp);

        // 2. Register (idempotent — treat "already registered" server errors as success).
        let gsp = state.gsp().await;
        let register_proof =
            auth::make_proof(&kp, "register").map_err(|e| format!("register proof: {e}"))?;
        let already_registered = match gsp.register(register_proof, None).await {
            Ok(_) => false,
            Err(GspError::Server(msg)) if msg.to_ascii_lowercase().contains("already") => true,
            Err(e) => return Err(format!("register: {e}")),
        };

        // 3. Generate session_nonce + sign session proof + create session.
        use rand::RngCore;
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let session_nonce = hex::encode(nonce_bytes);

        let session_proof =
            auth::make_proof(&kp, "session").map_err(|e| format!("session proof: {e}"))?;
        let token = gsp
            .create_session(session_proof, Some(session_nonce))
            .await
            .map_err(|e| format!("session: {e}"))?;

        let token_prefix: String = token.token.chars().take(12).collect();
        let expires_at = token.expires_at;
        let jwt_for_session = token.token.clone();

        // Derive ghost keys for client-side BIP-352 detection. Best-effort:
        // failure here just means the session won't auto-scan; auth still works.
        let scan_keys = {
            let wallets = state.wallets.read().await;
            wallets
                .get(&active_name)
                .and_then(|ks| ks.ghost_keys().ok())
        };

        // Compute the wallet's network-correct bech32 ghost-id once
        // up front. The session forwards it with each
        // GetTransactions so ghost-pay can match recipient-side
        // rows. `GhostKeys::ghost_id().to_string()` would emit the
        // mainnet HRP — wrong for regtest/signet/testnet.
        let ghost_id_bech32 = scan_keys.as_ref().and_then(|gk| {
            gk.ghost_id()
                .encode_for_network(ghost_network_from_bitcoin(state.network))
                .ok()
        });

        // 4. Stash the token + spawn a persistent authenticated session task.
        //    Replacing an existing slot drops the old SessionHandle, which aborts
        //    its task before the new one starts.
        let handle = spawn_session_with_bech32(
            state.gsp_urls().await,
            jwt_for_session,
            scan_keys,
            ghost_id_bech32,
            state.tor_proxy.clone(),
        );
        *state.session.write().await = Some(StoredSession {
            wallet_name: active_name,
            token,
            handle,
        });

        Ok(GspAuthResponse {
            wallet_id,
            already_registered,
            token_prefix,
            expires_at,
        })
    }

    /// Helpers shared by lock operations: pull the auth keypair from the session's wallet.
    /// Used so each lock op binds to the wallet that produced the session token.
    async fn auth_keypair_for_session(
        state: &Arc<DaemonState>,
    ) -> Result<bitcoin::secp256k1::Keypair, String> {
        let session = state.session.read().await;
        let session = session
            .as_ref()
            .ok_or_else(|| "no GSP session — run `wraith gsp auth` first".to_string())?;
        let wallets = state.wallets.read().await;
        let ks = wallets.get(&session.wallet_name).ok_or_else(|| {
            format!(
                "wallet '{}' (the session's wallet) is not unlocked",
                session.wallet_name
            )
        })?;
        wraith_wallet_core::auth::auth_keypair(ks).map_err(|e| format!("auth keypair: {e}"))
    }

    fn parse_jump_priority(s: &str) -> Result<String, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "normal" => Ok("normal".to_string()),
            "high" => Ok("high".to_string()),
            "urgent" => Ok("urgent".to_string()),
            other => Err(format!(
                "unknown jump priority '{other}' (try normal, high, urgent)"
            )),
        }
    }

    fn parse_payment_mode(s: &str) -> Result<PaymentMode, String> {
        // Send only exposes the instant L2 ledger transfer (`ghostpay`).
        // The `wraith` and `confidential` modes were retired here because
        // they never had a real code path in Send — both silently took the
        // plaintext L2 ledger route, so advertising them was a
        // truth-in-advertising defect. Unlinkable L1 spends live in the Mix
        // tab (Wraith CoinJoin); a shielded confidential L2 transfer needs
        // client-side ZK proving the wallet-core cannot yet produce, so it
        // is not offered rather than faked. Both are rejected below instead
        // of silently accepted — a rejected send can never leak as a
        // plaintext one.
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "ghostpay" | "ghost-pay" | "ghost_pay" => Ok(PaymentMode::GhostPay),
            "wraith" => Err(
                "payment mode 'wraith' is not available from Send — unlinkable L1 spends go \
                 through the Mix tab (Wraith CoinJoin)"
                    .to_string(),
            ),
            "confidential" => Err(
                "payment mode 'confidential' is not available: shielded L2 transfers require \
                 client-side ZK proving that is not yet supported"
                    .to_string(),
            ),
            other => Err(format!("unknown payment mode '{other}' (try ghostpay)")),
        }
    }

    /// `LightSend` orchestration: PreparePayment → sign sighash with auth key → SubmitSignedPayment.
    /// Mirrors `ghost-light-wallet::payments::send::sign_and_submit` so wire format matches.
    async fn light_send(
        state: &Arc<DaemonState>,
        recipient: String,
        amount_sats: u64,
        mode_str: String,
        memo: Option<String>,
        shroud_override_ms: Option<u64>,
    ) -> Result<LightSentResponse, String> {
        // The `mode` field on the IPC is parsed and validated. Only
        // `ghostpay` (the instant L2 ledger transfer) is accepted; the
        // retired `wraith`/`confidential` modes are rejected here so a
        // stale caller can never fall through to a plaintext send it
        // did not intend (see `parse_payment_mode`).
        let mode = parse_payment_mode(&mode_str)?;
        let mode_label = format!("{mode}");

        let session = state.session.read().await;
        let session = session
            .as_ref()
            .ok_or_else(|| "no GSP session — run `wraith gsp auth` first".to_string())?;

        // Auth keypair from the active wallet (must match session's wallet).
        let kp = {
            let wallets = state.wallets.read().await;
            let ks = wallets.get(&session.wallet_name).ok_or_else(|| {
                format!(
                    "wallet '{}' (the session's wallet) is not unlocked",
                    session.wallet_name
                )
            })?;
            wraith_wallet_core::auth::auth_keypair(ks).map_err(|e| format!("auth keypair: {e}"))?
        };

        // Phase 9 Shroud: hold the request for a uniform random delay
        // in [0, max] before sending. For L2 ledger ops there's no P2P
        // broadcast to correlate against, but a network observer with
        // both wallet→ghost-pay HTTP and ghost-pay→peer ledger update
        // vantage points could still correlate "user typed send" with
        // "ledger updated" — the shroud breaks that timing seam.
        let max_ms = shroud_override_ms.unwrap_or(state.shroud_max_ms);
        let shroud_delay_ms = shroud_pick_delay(max_ms);
        if let Some(chosen) = shroud_delay_ms {
            tracing::debug!(
                shroud_max_ms = max_ms,
                chosen_ms = chosen,
                "shroud relay: holding L2 send before submit"
            );
            tokio::time::sleep(std::time::Duration::from_millis(chosen)).await;
        }

        // Fresh per-call auth proof and a single SendL2Payment.
        // Replaces the prepare/sign/submit dance — L2 transfers are
        // session-authenticated ledger ops, not Bitcoin txs requiring
        // per-payment sighash signatures.
        let proof = wraith_wallet_core::auth::make_proof(&kp, "send_l2_payment")
            .map_err(|e| format!("send_l2_payment proof: {e}"))?;

        let result = session
            .handle
            .send_l2_payment(recipient.clone(), amount_sats, proof, memo.clone())
            .await
            .map_err(|e| format!("SendL2Payment: {e}"))?;

        Ok(LightSentResponse {
            payment_id: result.payment_id,
            // L2 transfers are off-chain ledger ops — there's no
            // bitcoin txid until the eventual settlement step
            // (reconciliation or confidential-transfer ZK proof).
            txid: None,
            recipient,
            amount_sats: result.amount_sats,
            // ghost-pay's L2 send doesn't currently expose a fee
            // breakdown in its response. v1 reports 0; the
            // operator-side fee accounting can surface later via
            // a separate query if/when needed.
            fee_sats: 0,
            mode: mode_label,
            shroud_delay_ms,
        })
    }

    /// Send `RegisterScanKey` over the persistent session: derives the wallet's
    /// BIP-352 scan pubkey, signs a `register_scan_key` proof, and delegates to
    /// the session task. Returns (wallet_id, scan_pubkey_hex) on success.
    async fn gsp_register_scan_key(state: &Arc<DaemonState>) -> Result<(String, String), String> {
        let session = state.session.read().await;
        let session = session
            .as_ref()
            .ok_or_else(|| "no GSP session — run `wraith gsp auth` first".to_string())?;

        // Derive scan pubkey + auth keypair from the session's wallet.
        let (scan_pubkey_hex, kp) = {
            let wallets = state.wallets.read().await;
            let ks = wallets.get(&session.wallet_name).ok_or_else(|| {
                format!(
                    "wallet '{}' (the session's wallet) is not unlocked",
                    session.wallet_name
                )
            })?;
            let gk = ks.ghost_keys().map_err(|e| format!("ghost-keys: {e}"))?;
            let scan_hex = hex::encode(gk.scan_pubkey().serialize());
            let kp = wraith_wallet_core::auth::auth_keypair(ks)
                .map_err(|e| format!("auth keypair: {e}"))?;
            (scan_hex, kp)
        };

        let proof = wraith_wallet_core::auth::make_proof(&kp, "register_scan_key")
            .map_err(|e| format!("register_scan_key proof: {e}"))?;
        let wallet_id = wraith_wallet_core::auth::wallet_id_hex(&kp);

        session
            .handle
            .register_scan_key(scan_pubkey_hex.clone(), proof)
            .await
            .map_err(|e| format!("RegisterScanKey: {e}"))?;

        Ok((wallet_id, scan_pubkey_hex))
    }

    /// Run all connectivity / liveness checks and return a summary.
    async fn doctor_run(state: &Arc<DaemonState>) -> DoctorResponse {
        let mut checks: Vec<DoctorCheck> = Vec::new();
        let mut all_pass = true;

        // 1. Daemon liveness — always passes if we got here.
        checks.push(DoctorCheck {
            name: "daemon".into(),
            status: "pass".into(),
            detail: format!(
                "v{} — uptime {}s",
                env!("CARGO_PKG_VERSION"),
                state.started.elapsed().as_secs()
            ),
        });

        // 2. ghost-pay /api/v1/status round-trip + latency.
        let t0 = std::time::Instant::now();
        match state.chain().await.status().await {
            Ok(s) => {
                let rtt = t0.elapsed().as_millis();
                checks.push(DoctorCheck {
                    name: "ghost-pay".into(),
                    status: "pass".into(),
                    detail: format!(
                        "v{} ({}) — locks={}, sessions={} — round-trip {rtt}ms",
                        s.backend_version, s.network, s.lock_count, s.active_sessions
                    ),
                });
            }
            Err(e) => {
                all_pass = false;
                let rtt = t0.elapsed().as_millis();
                checks.push(DoctorCheck {
                    name: "ghost-pay".into(),
                    status: "fail".into(),
                    detail: format!("{e} (after {rtt}ms)"),
                });
            }
        }

        // 3. GSP ping round-trip.
        match state.gsp().await.ping().await {
            Ok(p) => {
                let detail = match p.round_trip_ms {
                    Some(rtt) => format!("server_time {} — round-trip {}ms", p.server_time, rtt),
                    None => format!("server_time {}", p.server_time),
                };
                checks.push(DoctorCheck {
                    name: "ghost-gsp".into(),
                    status: "pass".into(),
                    detail,
                });
            }
            Err(e) => {
                all_pass = false;
                checks.push(DoctorCheck {
                    name: "ghost-gsp".into(),
                    status: "fail".into(),
                    detail: format!("{e}"),
                });
            }
        }

        // 4. Active wallet status.
        match state.active.read().await.clone() {
            Some(active) => checks.push(DoctorCheck {
                name: "active wallet".into(),
                status: "pass".into(),
                detail: format!("'{active}' unlocked"),
            }),
            None => {
                checks.push(DoctorCheck {
                    name: "active wallet".into(),
                    status: "skip".into(),
                    detail: "no wallet selected — `wraith wallet unlock <name>`".into(),
                });
            }
        }

        // 5. Session — present?
        match state.session.read().await.as_ref() {
            None => checks.push(DoctorCheck {
                name: "gsp session".into(),
                status: "skip".into(),
                detail: "no session — `wraith gsp auth`".into(),
            }),
            Some(s) => {
                let snap = s.handle.snapshot().await;
                let phase = phase_label(snap.phase);
                let status = if matches!(snap.phase, SessionPhase::Authenticated) {
                    "pass".to_string()
                } else {
                    all_pass = false;
                    "fail".to_string()
                };
                checks.push(DoctorCheck {
                    name: "gsp session".into(),
                    status,
                    detail: format!(
                        "{} (connects: {}, expires in {}s)",
                        phase,
                        snap.connect_count,
                        s.token.remaining_secs()
                    ),
                });
            }
        }

        // 6. wraith-coordinator probe (only when WRAITHD_WRAITH_COORDINATOR
        //    is set — mixes use a per-call URL from the wallet, so this is
        //    purely a dev-stack diagnostic).
        if let Some(url) = state.wraith_coordinator_url.as_deref() {
            use wraith_wallet_core::wraith::WraithSessionClient;
            let client = WraithSessionClient::new(url.to_string(), state.network);
            let t0 = std::time::Instant::now();
            match client.discover().await {
                Ok((_, payload)) => {
                    let rtt = t0.elapsed().as_millis();
                    checks.push(DoctorCheck {
                        name: "wraith-coordinator".into(),
                        status: "pass".into(),
                        detail: format!(
                            "{} ({}) — {} tier(s) — round-trip {rtt}ms",
                            payload.pool_id,
                            payload.network,
                            payload.tiers.len()
                        ),
                    });
                }
                Err(e) => {
                    all_pass = false;
                    let rtt = t0.elapsed().as_millis();
                    checks.push(DoctorCheck {
                        name: "wraith-coordinator".into(),
                        status: "fail".into(),
                        detail: format!("{url}: {e} (after {rtt}ms)"),
                    });
                }
            }
        }

        // Mainnet-readiness: only emitted when bound to real bitcoin. The
        // checks here aren't run on signet / testnet / regtest because the
        // privacy-and-integrity stakes don't apply to test networks.
        if state.network == bitcoin::Network::Bitcoin {
            let ghost_pay_urls = state.ghost_pay_urls().await;
            let gsp_urls = state.gsp_urls().await;
            mainnet_readiness_checks(
                &ghost_pay_urls,
                &gsp_urls,
                state.tor_proxy.as_deref(),
                &mut checks,
                &mut all_pass,
            );
        }

        DoctorResponse { checks, all_pass }
    }

    /// Returns true for URLs that bind to the local host (127.0.0.1, ::1,
    /// localhost). Plaintext is fine on these — the traffic never leaves
    /// the box and TLS-on-loopback is just CPU burned for no privacy gain.
    fn is_loopback_url(url: &str) -> bool {
        // Strip scheme. Anything past `://` up to the next `/` or `:` is
        // the host. Cheap parse — we don't need a full URL parser here.
        let after_scheme = url.split("://").nth(1).unwrap_or(url);
        let host = after_scheme
            .split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("");
        matches!(host, "127.0.0.1" | "::1" | "localhost")
    }

    /// Phase: mainnet-only doctor checks. Flags plaintext non-loopback
    /// URLs (real privacy hole on real bitcoin) and the absence of a Tor
    /// proxy (advisory — Tor is opt-in by design, but worth surfacing so
    /// the user knows they're publishing their IP to ghost-pay/GSP).
    fn mainnet_readiness_checks(
        ghost_pay_urls: &[String],
        gsp_urls: &[String],
        tor_proxy: Option<&str>,
        checks: &mut Vec<DoctorCheck>,
        all_pass: &mut bool,
    ) {
        let plaintext_pay: Vec<&String> = ghost_pay_urls
            .iter()
            .filter(|u| u.starts_with("http://") && !is_loopback_url(u))
            .collect();
        let plaintext_gsp: Vec<&String> = gsp_urls
            .iter()
            .filter(|u| u.starts_with("ws://") && !is_loopback_url(u))
            .collect();

        // Plaintext ghost-pay row. Fail = wallet→ghost-pay traffic is
        // visible to anyone on the path; an observer can correlate
        // submissions with broadcasts.
        if plaintext_pay.is_empty() {
            checks.push(DoctorCheck {
                name: "mainnet/ghost-pay tls".into(),
                status: "pass".into(),
                detail: "all ghost-pay endpoints use https or are loopback-bound".into(),
            });
        } else {
            *all_pass = false;
            checks.push(DoctorCheck {
                name: "mainnet/ghost-pay tls".into(),
                status: "fail".into(),
                detail: format!(
                    "{} non-TLS endpoint(s): {}. switch to https:// or run ghost-pay on \
                     loopback.",
                    plaintext_pay.len(),
                    plaintext_pay
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }

        // Plaintext GSP row. Same threat: ws:// leaks the wallet's
        // existence + auth identity to anyone on the path.
        if plaintext_gsp.is_empty() {
            checks.push(DoctorCheck {
                name: "mainnet/gsp tls".into(),
                status: "pass".into(),
                detail: "all gsp endpoints use wss or are loopback-bound".into(),
            });
        } else {
            *all_pass = false;
            checks.push(DoctorCheck {
                name: "mainnet/gsp tls".into(),
                status: "fail".into(),
                detail: format!(
                    "{} non-TLS endpoint(s): {}. switch to wss:// or run GSP on loopback.",
                    plaintext_gsp.len(),
                    plaintext_gsp
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }

        // Tor row. Advisory only — Tor is opt-in by design, and forcing
        // it would break legitimate setups (e.g. an operator running
        // their own ghost-pay on a private network). "skip" rather than
        // "fail" so all_pass isn't lowered.
        if tor_proxy.is_none() {
            checks.push(DoctorCheck {
                name: "mainnet/tor".into(),
                status: "skip".into(),
                detail: "WRAITHD_TOR_PROXY unset — your IP is visible to ghost-pay and GSP. \
                         set e.g. socks5h://127.0.0.1:9050 to route through Tor."
                    .into(),
            });
        } else {
            checks.push(DoctorCheck {
                name: "mainnet/tor".into(),
                status: "pass".into(),
                detail: format!("routing through {}", tor_proxy.unwrap_or("?")),
            });
        }
    }

    fn phase_label(p: SessionPhase) -> &'static str {
        match p {
            SessionPhase::Disconnected => "disconnected",
            SessionPhase::Connecting => "connecting",
            SessionPhase::Authenticating => "authenticating",
            SessionPhase::Authenticated => "authenticated",
            SessionPhase::Backoff => "backoff",
        }
    }

    /// Human-readable network label matching the strings the GUI expects
    /// ("mainnet"/"signet"/"testnet"/"regtest").
    fn network_label(n: bitcoin::Network) -> &'static str {
        match n {
            bitcoin::Network::Bitcoin => "mainnet",
            bitcoin::Network::Signet => "signet",
            bitcoin::Network::Testnet => "testnet",
            bitcoin::Network::Regtest => "regtest",
            _ => "unknown",
        }
    }

    /// Snapshot the active wallet's name + keystore for read-only use.
    /// Returns Err with a user-friendly message if no wallet is active.
    /// Reject the request if kiosk mode is active. Used by the
    /// wallet-management handlers (create/import/select/lock) to
    /// keep retail-floor staff from changing the active wallet.
    /// Read paths and Merchant-screen paths (Receive, light_l1_utxos,
    /// payment-detected) stay open.
    fn refuse_in_kiosk_mode(state: &DaemonState, op: &str) -> Option<Response> {
        if state.kiosk_mode {
            Some(Response::Error(ErrorResponse {
                message: format!(
                    "{op} is disabled in kiosk mode — restart wraithd without \
                     WRAITHD_KIOSK_MODE to make wallet changes"
                ),
            }))
        } else {
            None
        }
    }

    /// Build an unsigned PSBT spending the active wallet's L1
    /// UTXOs. Returns `Err` with a human-readable message; the
    /// dispatch arm wraps that into a `Response::Error`. Pulled
    /// out of the dispatch closure so error-paths can use `?` and
    /// the lock holds stay scoped.
    /// Default BIP86 index for a seat coin, chosen well clear of the
    /// everyday receive range so a prepared seat never collides with an
    /// address the wallet hands out for ordinary payments.
    const SEAT_RECEIVE_INDEX: u32 = 900;

    /// Build the split that turns an ordinary coin into exactly one seat.
    ///
    /// Asks the coordinator what a seat costs rather than deriving it — the
    /// coordinator, the round builder and the wallet computing that number
    /// separately is how it came to disagree with itself (#698). Stops at the
    /// unsigned PSBT: signing and broadcasting are existing verbs, and
    /// keeping them separate means this never moves money by itself.
    async fn wraith_prepare_coin_handler(
        state: &DaemonState,
        tier_id: &str,
        coordinator_url: String,
        coordinator_peers: Vec<String>,
        receive_index: Option<u32>,
        fee_rate_sats_per_vb: u64,
        bip86_scan_max: u32,
    ) -> Result<wraith_wallet_ipc::WraithCoinPreparedResponse, String> {
        use wraith_wallet_core::wraith::WraithSessionClient;

        let client =
            WraithSessionClient::with_peers(coordinator_url, coordinator_peers, state.network);
        let (_answered_by, discover) = client
            .discover()
            .await
            .map_err(|e| format!("could not ask the coordinator what a seat costs: {e}"))?;
        let tier = discover
            .tiers
            .iter()
            .find(|t| t.id == tier_id)
            .ok_or_else(|| {
                let known: Vec<&str> = discover.tiers.iter().map(|t| t.id.as_str()).collect();
                format!("coordinator does not offer tier '{tier_id}'; it offers {known:?}")
            })?;
        let seat_price_sats = tier.mix_seat_price_sats;

        let destination_index = receive_index.unwrap_or(SEAT_RECEIVE_INDEX);
        let network = state.network;
        let destination_address = with_active_wallet(state, move |_, ks| {
            wraith_wallet_core::light::receive_address(ks, destination_index, network)
                .map(|a| a.to_string())
                .map_err(|e| e.to_string())
        })
        .await?;

        let created = psbt_create_handler(
            state,
            &destination_address,
            seat_price_sats,
            fee_rate_sats_per_vb,
            None,
            bip86_scan_max,
            &[],
        )
        .await?;

        Ok(wraith_wallet_ipc::WraithCoinPreparedResponse {
            psbt: created.psbt,
            seat_price_sats,
            destination_address,
            destination_index,
            input_count: created.input_count,
            total_input_sats: created.total_input_sats,
            change_sats: created.change_sats,
            fee_sats: created.fee_sats,
        })
    }

    async fn psbt_create_handler(
        state: &DaemonState,
        recipient_address: &str,
        amount_sats: u64,
        fee_rate_sats_per_vb: u64,
        change_index: Option<u32>,
        bip86_scan_max: u32,
        selected_outpoints: &[wraith_wallet_ipc::OutpointRef],
    ) -> Result<wraith_wallet_ipc::PsbtCreateResponse, String> {
        use wraith_wallet_core::psbt as psbt_mod;
        let network = state.network;
        let scan_max = bip86_scan_max.max(1);

        // 1. Derive the wallet's BIP86 receive addresses 0..scan_max
        //    (used both for the UTXO scan and for picking the change
        //    address). We hold the keystore lock just long enough to
        //    derive — no async work happens inside the guard.
        let active_name = state
            .active
            .read()
            .await
            .clone()
            .ok_or_else(|| "no active wallet".to_string())?;
        let change_idx = change_index.unwrap_or(scan_max + 1);
        let (addr_strings, change_addr) = {
            let wallets = state.wallets.read().await;
            let ks = wallets
                .get(&active_name)
                .ok_or_else(|| format!("active wallet '{active_name}' is not unlocked"))?;
            let mut addrs = Vec::with_capacity(scan_max as usize + 1);
            for i in 0..=scan_max {
                let a = wraith_wallet_core::light::receive_address(ks, i, network)
                    .map_err(|e| format!("derive idx {i}: {e}"))?;
                addrs.push(a.to_string());
            }
            let change = wraith_wallet_core::light::receive_address(ks, change_idx, network)
                .map_err(|e| format!("derive change idx {change_idx}: {e}"))?;
            (addrs, change)
        };

        // 2. Ask ghost-pay for the UTXO set at those addresses.
        //    Confirmations gate at 1 — same default as
        //    light_l1_utxos.
        let scan = state
            .chain()
            .await
            .scan_utxos(&addr_strings, 1)
            .await
            .map_err(|e| format!("scan_utxos: {e}"))?;
        if scan.utxos.is_empty() {
            return Err(format!(
                "no spendable UTXOs at receive indices 0..{scan_max} on this wallet"
            ));
        }

        // 3. Map ScannedL1Utxo → AvailableUtxo for the builder.
        //    If the caller passed `selected_outpoints` (coin
        //    control), filter to that set; error if any selected
        //    outpoint isn't in the scan results — that means the
        //    GUI's UTXO list is stale or referencing a UTXO we
        //    don't own, both of which are fail-loud cases rather
        //    than fail-silent.
        let mut available: Vec<psbt_mod::AvailableUtxo> = Vec::new();
        let coin_control = !selected_outpoints.is_empty();
        let wanted: std::collections::HashSet<(String, u32)> = if coin_control {
            selected_outpoints
                .iter()
                .map(|o| (o.txid.clone(), o.vout))
                .collect()
        } else {
            std::collections::HashSet::new()
        };
        let mut matched: std::collections::HashSet<(String, u32)> =
            std::collections::HashSet::new();
        for u in &scan.utxos {
            if coin_control && !wanted.contains(&(u.txid.clone(), u.vout)) {
                continue;
            }
            let txid: bitcoin::Txid = u
                .txid
                .parse()
                .map_err(|e| format!("scan returned bad txid: {e}"))?;
            let spk_bytes = hex::decode(u.scriptpubkey_hex.trim())
                .map_err(|e| format!("scan returned bad spk hex: {e}"))?;
            available.push(psbt_mod::AvailableUtxo {
                txid,
                vout: u.vout,
                value_sats: u.amount_sats,
                script_pubkey: bitcoin::ScriptBuf::from_bytes(spk_bytes),
            });
            if coin_control {
                matched.insert((u.txid.clone(), u.vout));
            }
        }
        if coin_control {
            let missing: Vec<String> = wanted
                .iter()
                .filter(|p| !matched.contains(*p))
                .map(|(t, v)| format!("{t}:{v}"))
                .collect();
            if !missing.is_empty() {
                return Err(format!(
                    "selected outpoints not in this wallet's scanned UTXO set: {} \
                     — refresh the UTXO list and retry",
                    missing.join(", ")
                ));
            }
            if available.is_empty() {
                return Err("coin-control selection resolved to zero UTXOs".into());
            }
        }

        // 4. Build the unsigned PSBT.
        let (psbt, meta) = psbt_mod::create_psbt(
            &available,
            recipient_address,
            amount_sats,
            &change_addr,
            network,
            fee_rate_sats_per_vb,
        )
        .map_err(|e| format!("create_psbt: {e}"))?;

        let encoded = psbt_mod::encode_psbt(&psbt, psbt_mod::PsbtEncoding::Base64);
        Ok(wraith_wallet_ipc::PsbtCreateResponse {
            psbt: encoded,
            input_count: meta.selected_input_count as u32,
            total_input_sats: meta.total_input_sats,
            recipient_sats: meta.recipient_sats,
            change_sats: meta.change_sats,
            fee_sats: meta.fee_sats,
            change_bip86_index: if meta.change_sats > 0 {
                Some(change_idx)
            } else {
                None
            },
        })
    }

    /// Extract a finalized tx from a PSBT (or accept raw tx hex
    /// directly) and broadcast it via ghost-pay. Returns the
    /// txid bitcoind accepted.
    async fn psbt_broadcast_handler(
        state: &DaemonState,
        psbt_or_tx_hex: &str,
    ) -> Result<String, String> {
        use wraith_wallet_core::psbt as psbt_mod;
        let trimmed = psbt_or_tx_hex.trim();
        // PSBT magic in hex is 70736274ff; in base64 it's `cHNidP`.
        // Anything else, treat as raw consensus-encoded tx hex.
        let is_psbt =
            trimmed.to_lowercase().starts_with("70736274ff") || trimmed.starts_with("cHNidP");
        let tx_hex = if is_psbt {
            let (parsed, _) =
                psbt_mod::decode_psbt(trimmed).map_err(|e| format!("decode_psbt: {e}"))?;
            if !psbt_mod::is_complete(&parsed) {
                return Err(
                    "PSBT is not complete — every input must be finalized before broadcast".into(),
                );
            }
            let tx = parsed
                .extract_tx()
                .map_err(|e| format!("extract_tx: {e}"))?;
            bitcoin::consensus::encode::serialize_hex(&tx)
        } else {
            let bytes = hex::decode(trimmed).map_err(|e| format!("hex: {e}"))?;
            let _: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&bytes)
                .map_err(|e| format!("invalid raw tx: {e}"))?;
            trimmed.to_string()
        };
        state
            .chain()
            .await
            .broadcast_tx(&tx_hex)
            .await
            .map_err(|e| format!("broadcast: {e}"))
    }

    /// Inspect a multisig descriptor. Pure function: parse, derive
    /// the requested receive addresses, mark which cosigner is the
    /// active wallet (if any). No persistence — `MultisigDescriptorSave`
    /// is the explicit commit step.
    async fn multisig_inspect_handler(
        state: &DaemonState,
        descriptor: &str,
        address_count: u32,
    ) -> Result<wraith_wallet_ipc::MultisigDescriptorInspected, String> {
        use wraith_wallet_core::descriptor as desc;
        let parsed = desc::parse(descriptor).map_err(|e| format!("descriptor: {e}"))?;
        // Resolve our fingerprint (if a wallet is active) so the
        // GUI can label which row is us.
        let our_fp: Option<[u8; 4]> = match state.active.read().await.clone() {
            Some(name) => {
                let wallets = state.wallets.read().await;
                match wallets.get(&name) {
                    Some(ks) => Some(
                        ks.master_fingerprint_bytes()
                            .map_err(|e| format!("fingerprint: {e}"))?,
                    ),
                    None => None,
                }
            }
            None => None,
        };
        let cosigners: Vec<wraith_wallet_ipc::MultisigCosignerSummary> = parsed
            .keys
            .iter()
            .map(|k| wraith_wallet_ipc::MultisigCosignerSummary {
                fingerprint_hex: hex::encode(k.fingerprint),
                origin_path: k.origin_path.clone(),
                xpub: k.xpub.to_string(),
                is_us: our_fp == Some(k.fingerprint),
            })
            .collect();
        let contains_us = cosigners.iter().any(|c| c.is_us);
        let count = address_count.min(64); // hard cap so a typo can't DoS the daemon
        let mut addresses = Vec::with_capacity(count as usize);
        for i in 0..count {
            match parsed.derive_address(i, false, state.network) {
                Ok(a) => addresses.push(a.to_string()),
                Err(e) => {
                    // Fixed-child descriptor → only index 0 valid;
                    // bail with what we have rather than blocking
                    // the whole inspect.
                    if matches!(e, desc::DescriptorError::IndexOutOfRange { .. }) {
                        break;
                    }
                    return Err(format!("derive {i}: {e}"));
                }
            }
        }
        let kind = match parsed.kind {
            desc::DescriptorKind::WshSortedMulti => "wsh-sortedmulti",
        };
        Ok(wraith_wallet_ipc::MultisigDescriptorInspected {
            kind: kind.to_string(),
            k: parsed.k as u32,
            n: parsed.n() as u32,
            cosigners,
            contains_us,
            addresses,
            checksum: parsed.checksum,
        })
    }

    /// Persist a multisig descriptor for the active wallet. Refuses
    /// if our fingerprint isn't in the descriptor — we only model
    /// "we are a cosigner" today, not "watch-only".
    async fn multisig_save_handler(
        state: &DaemonState,
        name: &str,
        descriptor: &str,
    ) -> Result<wraith_wallet_ipc::MultisigDescriptorSaved, String> {
        use wraith_wallet_core::descriptor as desc;
        validate_descriptor_name(name)?;
        let parsed = desc::parse(descriptor).map_err(|e| format!("descriptor: {e}"))?;
        let active = state
            .active
            .read()
            .await
            .clone()
            .ok_or_else(|| "no active wallet".to_string())?;
        let our_fp = {
            let wallets = state.wallets.read().await;
            let ks = wallets
                .get(&active)
                .ok_or_else(|| format!("active wallet '{active}' is not unlocked"))?;
            ks.master_fingerprint_bytes()
                .map_err(|e| format!("fingerprint: {e}"))?
        };
        if !parsed.contains_fingerprint(&our_fp) {
            return Err(format!(
                "active wallet's fingerprint {} is not in this descriptor — refusing to save \
                 (watch-only multisig is not supported in this build)",
                hex::encode(our_fp)
            ));
        }
        let dir = descriptors_dir(&state.wallets_dir, &active);
        std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir descriptors: {e}"))?;
        // Refuse to overwrite an existing descriptor — saving over
        // a name silently is the kind of footgun we don't want.
        let path = descriptor_path(&state.wallets_dir, &active, name);
        if path.exists() {
            return Err(format!(
                "descriptor '{name}' already exists for wallet '{active}' — pick a different name or delete the old one"
            ));
        }
        std::fs::write(&path, descriptor.trim().as_bytes())
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        // 0600 like the keystore — descriptors carry every cosigner's
        // xpub, which is sensitive metadata even though it's "public".
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path)
                .map_err(|e| format!("stat: {e}"))?
                .permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&path, perms);
        }
        Ok(wraith_wallet_ipc::MultisigDescriptorSaved {
            name: name.to_string(),
            path: path.display().to_string(),
        })
    }

    /// List saved descriptors for the active wallet. Returns a
    /// summary per file; full contents fetched separately if the
    /// GUI needs them.
    async fn multisig_list_handler(
        state: &DaemonState,
    ) -> Result<wraith_wallet_ipc::MultisigDescriptorListResponse, String> {
        use wraith_wallet_core::descriptor as desc;
        let active = state
            .active
            .read()
            .await
            .clone()
            .ok_or_else(|| "no active wallet".to_string())?;
        let dir = descriptors_dir(&state.wallets_dir, &active);
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = match path.file_stem().and_then(|s| s.to_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                if path.extension().and_then(|s| s.to_str()) != Some("desc") {
                    continue;
                }
                let body = match std::fs::read_to_string(&path) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let parsed = match desc::parse(&body) {
                    Ok(p) => p,
                    // Skip un-parseable files rather than failing
                    // the whole list — they'll be visible on disk
                    // for the user to clean up.
                    Err(_) => continue,
                };
                let kind = match parsed.kind {
                    desc::DescriptorKind::WshSortedMulti => "wsh-sortedmulti",
                };
                out.push(wraith_wallet_ipc::MultisigDescriptorListEntry {
                    name,
                    kind: kind.to_string(),
                    k: parsed.k as u32,
                    n: parsed.n() as u32,
                    cosigner_fingerprints: parsed
                        .keys
                        .iter()
                        .map(|k| hex::encode(k.fingerprint))
                        .collect(),
                });
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(wraith_wallet_ipc::MultisigDescriptorListResponse { descriptors: out })
    }

    /// Derive `count` addresses starting at `start_index` for a
    /// saved descriptor.
    async fn multisig_addresses_handler(
        state: &DaemonState,
        name: &str,
        start_index: u32,
        count: u32,
        internal: bool,
    ) -> Result<wraith_wallet_ipc::MultisigDescriptorAddressesResponse, String> {
        use wraith_wallet_core::descriptor as desc;
        validate_descriptor_name(name)?;
        let active = state
            .active
            .read()
            .await
            .clone()
            .ok_or_else(|| "no active wallet".to_string())?;
        let path = descriptor_path(&state.wallets_dir, &active, name);
        let body =
            std::fs::read_to_string(&path).map_err(|e| format!("read descriptor '{name}': {e}"))?;
        let parsed = desc::parse(&body).map_err(|e| format!("descriptor: {e}"))?;
        let count = count.min(64);
        let mut addresses = Vec::with_capacity(count as usize);
        for offset in 0..count {
            let idx = start_index + offset;
            match parsed.derive_address(idx, internal, state.network) {
                Ok(a) => addresses.push(wraith_wallet_ipc::MultisigDescriptorAddressEntry {
                    index: idx,
                    address: a.to_string(),
                }),
                Err(e) => {
                    if matches!(e, desc::DescriptorError::IndexOutOfRange { .. }) {
                        break;
                    }
                    return Err(format!("derive {idx}: {e}"));
                }
            }
        }
        Ok(wraith_wallet_ipc::MultisigDescriptorAddressesResponse {
            name: name.to_string(),
            internal,
            addresses,
        })
    }

    /// Idempotent delete — no error if the descriptor doesn't
    /// exist. Returns whether a file was actually removed.
    async fn multisig_delete_handler(state: &DaemonState, name: &str) -> Result<bool, String> {
        validate_descriptor_name(name)?;
        let active = state
            .active
            .read()
            .await
            .clone()
            .ok_or_else(|| "no active wallet".to_string())?;
        let path = descriptor_path(&state.wallets_dir, &active, name);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("remove {}: {e}", path.display())),
        }
    }

    /// BIP-125 fee-bump on a PSBT. Resolves the active wallet,
    /// runs `psbt::bump_fee` (which reduces the wallet-owned change
    /// output to absorb the higher fee), and returns the new
    /// unsigned PSBT plus the old/new fee + change breakdown.
    async fn psbt_bump_fee_handler(
        state: &DaemonState,
        psbt: &str,
        new_fee_rate_sats_per_vb: u64,
        bip86_scan_max: u32,
    ) -> Result<PsbtBumpFeeResponse, String> {
        use wraith_wallet_core::psbt as psbt_mod;
        let (parsed, _encoding) =
            psbt_mod::decode_psbt(psbt).map_err(|e| format!("decode_psbt: {e}"))?;
        let network = state.network;
        let scan_max = bip86_scan_max.max(1);
        with_active_wallet(state, move |_, ks| {
            let mut p = parsed;
            let (bumped, meta) =
                psbt_mod::bump_fee(&p, ks, network, scan_max, new_fee_rate_sats_per_vb)
                    .map_err(|e| format!("bump_fee: {e}"))?;
            // Re-bind to satisfy the closure's move semantics — we
            // discard the old PSBT now that the bumped one is
            // built.
            let _ = std::mem::replace(&mut p, bumped.clone());
            let encoded = psbt_mod::encode_psbt(&bumped, psbt_mod::PsbtEncoding::Base64);
            Ok(PsbtBumpFeeResponse {
                psbt: encoded,
                old_fee_sats: meta.old_fee_sats,
                new_fee_sats: meta.new_fee_sats,
                old_change_sats: meta.old_change_sats,
                new_change_sats: meta.new_change_sats,
                input_count: meta.input_count as u32,
            })
        })
        .await
    }

    async fn with_active_wallet<F, R>(state: &DaemonState, f: F) -> Result<R, String>
    where
        F: FnOnce(&str, &Keystore) -> Result<R, String>,
    {
        let active = state.active.read().await.clone().ok_or_else(|| {
            "no active wallet; run `wraith wallet unlock <name>` or \
                 `wraith wallet select <name>` first"
                .to_string()
        })?;
        let wallets = state.wallets.read().await;
        let ks = wallets
            .get(&active)
            .ok_or_else(|| format!("active wallet '{active}' is not unlocked"))?;
        f(&active, ks)
    }

    /// Phase 13: lift a keystore's signer-info into the wire format. The
    /// daemon currently always wraps unlocked keystores in `SoftwareSigner`,
    /// so this is a constant; a future hardware-aware version of the daemon
    /// would dispatch on the keystore's tagged variant instead.
    fn signer_info_for_unlocked(ks: &Keystore) -> SignerInfoIpc {
        let signer = SoftwareSigner::new(ks);
        let info = signer.info();
        SignerInfoIpc {
            kind: info.kind,
            label: info.label,
            interactive: info.interactive,
        }
    }

    /// Phase 15 helper: fetch a release manifest, compare against the running
    /// version. Returns a structured response; bubbles fetch / parse failures
    /// up as `Err(String)` so the caller maps them to `Response::Error`.
    async fn check_for_update(
        state: &Arc<DaemonState>,
        override_url: Option<String>,
    ) -> Result<CheckForUpdateResponse, String> {
        let url = override_url
            .or_else(|| state.update_manifest_url.clone())
            .ok_or_else(|| {
                "no manifest URL — pass --manifest-url <url> or set \
                 WRAITHD_UPDATE_MANIFEST_URL"
                    .to_string()
            })?;
        let resp = state
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("fetch {url}: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("fetch {url}: HTTP {}", resp.status()));
        }
        let body = resp
            .text()
            .await
            .map_err(|e| format!("read manifest body: {e}"))?;
        let manifest: ReleaseManifest =
            serde_json::from_str(&body).map_err(|e| format!("parse manifest: {e}"))?;
        let current = env!("CARGO_PKG_VERSION").to_string();
        let up_to_date = manifest.version == current;
        Ok(CheckForUpdateResponse {
            current_version: current,
            latest_version: Some(manifest.version),
            up_to_date,
            manifest_url: url,
            tarball: Some(manifest.tarball),
            tarball_sha256: Some(manifest.tarball_sha256),
        })
    }

    /// Phase 9 Shroud helper: pick a uniform random delay in `[0, max_ms]`,
    /// or `None` when shroud is disabled (`max_ms == 0`).
    ///
    /// Pulled out of `light_send` so the bound + disabled-path semantics can
    /// be unit-tested without standing up a GSP mock.
    pub(crate) fn shroud_pick_delay(max_ms: u64) -> Option<u64> {
        if max_ms == 0 {
            None
        } else {
            use rand::Rng;
            // Inclusive on both ends — using `..=max_ms` lets a `max=1` config
            // still produce both 0 and 1, which matters for tests that want
            // to bound the delay from above.
            Some(rand::thread_rng().gen_range(0..=max_ms))
        }
    }

    /// Error text for `locks_recover` when we hold no local metadata for the
    /// requested lock. Prepared locks are persisted to `<wallet>/locks.json`
    /// and reloaded on `WalletUnlock`, so a miss means the entry belongs to a
    /// different wallet/daemon or its `locks.json` row is gone — not that the
    /// index was lost to a restart. Pulled out so the message is unit-testable.
    fn missing_lock_metadata_error(lock_id: &str) -> String {
        format!(
            "no local metadata for lock '{lock_id}' — either it was prepared \
            by a different wallet/daemon, or its locks.json entry is missing. \
            Unlock the wallet that prepared it and retry."
        )
    }

    /// Error text for `WraithMixSubmit` when the `session_id` is unknown. The
    /// `wraith_mixes` map is in-memory only by design (the coordinator's
    /// no-sign deadline is ticking), so a miss means the round expired or the
    /// daemon restarted mid-round. Pulled out so the message is unit-testable.
    fn unknown_mix_session_error(session_id: &str) -> String {
        format!(
            "mix session '{session_id}' not found — it expired or the daemon \
            restarted mid-round; start the mix again"
        )
    }

    fn now_unix_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Returns true iff this request counts as user-facing activity for the
    /// idle-lock timer. Diagnostics (Health, Doctor, DaemonEnv) and the watch
    /// stream itself don't reset the timer — they're either too quiet to
    /// indicate a present user, or they're held open continuously and would
    /// defeat the feature.
    fn is_activity(req: &Request) -> bool {
        !matches!(
            req,
            Request::Health | Request::Doctor | Request::DaemonEnv | Request::WatchPayments
        )
    }

    /// Background task that locks every unlocked wallet after
    /// `state.idle_lock_secs` of no user activity. Tick is
    /// `min(30s, idle_lock_secs/2)` so short thresholds (mostly used in
    /// tests) still fire roughly on time, while production-default 900s
    /// thresholds keep the cheap 30s cadence.
    async fn idle_lock_task(state: Arc<DaemonState>) {
        let tick_secs = (state.idle_lock_secs / 2).clamp(1, 30);
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(tick_secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let last = state
                .last_activity
                .load(std::sync::atomic::Ordering::Relaxed);
            let now = now_unix_secs();
            let idle = now.saturating_sub(last);
            if idle < state.idle_lock_secs {
                continue;
            }
            // Decide what to lock outside the write guard so we don't drop
            // active references while iterating. Then drain.
            let names: Vec<String> = {
                let map = state.wallets.read().await;
                map.keys().cloned().collect()
            };
            if names.is_empty() {
                continue;
            }
            tracing::info!(
                idle_secs = idle,
                wallets = names.len(),
                "idle threshold exceeded; auto-locking wallets"
            );
            let mut wallets = state.wallets.write().await;
            for n in &names {
                wallets.remove(n);
            }
            drop(wallets);
            *state.active.write().await = None;
            // Active GSP session belonged to one of those wallets; drop it.
            *state.session.write().await = None;
        }
    }

    async fn dispatch(line: &str, state: &Arc<DaemonState>) -> Envelope<Response> {
        let parsed: Result<Envelope<Request>, _> = serde_json::from_str(line);
        let (id, request) = match parsed {
            Ok(env) => (env.id, env.payload),
            Err(e) => {
                return Envelope::new(
                    0,
                    Response::Error(ErrorResponse {
                        message: format!("malformed request: {e}"),
                    }),
                );
            }
        };

        // Bump the idle-lock timer for user-facing requests. Diagnostics
        // (Health, Doctor, DaemonEnv) and WatchPayments don't count.
        if is_activity(&request) {
            state
                .last_activity
                .store(now_unix_secs(), std::sync::atomic::Ordering::Relaxed);
        }

        let response = match request {
            Request::Health => Response::Health(HealthResponse {
                daemon_version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_secs: state.started.elapsed().as_secs(),
            }),
            Request::Doctor => Response::Doctor(doctor_run(state).await),
            Request::ChainStatus => match state.chain().await.status().await {
                Ok(s) => Response::ChainStatus(ChainStatusResponse {
                    backend_version: s.backend_version,
                    network: s.network,
                    has_keys: s.has_keys,
                    lock_count: s.lock_count,
                    active_sessions: s.active_sessions,
                    chain_height: s.chain_height,
                    chain_headers: s.chain_headers,
                    chain_verification_progress: s.chain_verification_progress,
                    chain_initial_block_download: s.chain_initial_block_download,
                    l2_height: s.l2_height,
                    l2_epoch: s.l2_epoch,
                }),
                Err(e) => Response::Error(ErrorResponse {
                    message: format!("chain: {e}"),
                }),
            },
            Request::GspPing => match state.gsp().await.ping().await {
                Ok(p) => Response::GspPing(GspPingResponse {
                    server_time: p.server_time,
                    round_trip_ms: p.round_trip_ms,
                }),
                Err(e) => Response::Error(ErrorResponse {
                    message: format!("gsp: {e}"),
                }),
            },
            Request::GspAuth => match gsp_auth(state).await {
                Ok(r) => Response::GspAuth(r),
                Err(message) => Response::Error(ErrorResponse { message }),
            },
            Request::GspRegisterScanKey => match gsp_register_scan_key(state).await {
                Ok((wallet_id, scan_pubkey_hex)) => Response::GspScanKeyRegistered {
                    wallet_id,
                    scan_pubkey_hex,
                },
                Err(message) => Response::Error(ErrorResponse { message }),
            },
            Request::GspSessionStatus => {
                let guard = state.session.read().await;
                match guard.as_ref() {
                    Some(s) => {
                        let snap: SessionStatus = s.handle.snapshot().await;
                        Response::GspSessionStatus(GspSessionStatusResponse {
                            have_token: true,
                            wallet_name: Some(s.wallet_name.clone()),
                            wallet_id: Some(s.token.wallet_id.0.clone()),
                            expires_at: Some(s.token.expires_at),
                            remaining_secs: Some(s.token.remaining_secs()),
                            phase: Some(phase_label(snap.phase).to_string()),
                            connect_count: Some(snap.connect_count),
                            last_error: snap.last_error,
                        })
                    }
                    None => Response::GspSessionStatus(GspSessionStatusResponse {
                        have_token: false,
                        wallet_name: None,
                        wallet_id: None,
                        expires_at: None,
                        remaining_secs: None,
                        phase: None,
                        connect_count: None,
                        last_error: None,
                    }),
                }
            }
            Request::ConnectionStatus => {
                // One probe answers "is ghost-pay reachable" AND supplies the
                // chain fields. On error we report unreachable rather than
                // surfacing a Response::Error — the whole point is a header
                // that says "unreachable" instead of spinning forever.
                let (
                    ghost_pay_reachable,
                    ghost_pay_version,
                    ghost_pay_error,
                    chain_height,
                    chain_headers,
                    chain_ibd,
                    l2_height,
                ) = match state.chain().await.status().await {
                    Ok(s) => (
                        true,
                        Some(s.backend_version),
                        None,
                        s.chain_height,
                        s.chain_headers,
                        s.chain_initial_block_download,
                        s.l2_height,
                    ),
                    Err(e) => (false, None, Some(format!("{e}")), None, None, None, None),
                };
                // Same rule the GUI's SyncIndicator uses: verified height has
                // caught the header tip (or headers unknown) AND bitcoind is
                // out of initial block download.
                let chain_synced = ghost_pay_reachable
                    && chain_height.is_some()
                    && chain_headers.is_none_or(|h| chain_height.unwrap_or(0) >= h)
                    && chain_ibd == Some(false);
                let (gsp_have_token, gsp_phase) = {
                    let guard = state.session.read().await;
                    match guard.as_ref() {
                        Some(s) => {
                            let snap = s.handle.snapshot().await;
                            (true, Some(phase_label(snap.phase).to_string()))
                        }
                        None => (false, None),
                    }
                };
                let gsp_connected = gsp_phase.as_deref() == Some("authenticated");
                Response::ConnectionStatus(ConnectionStatusResponse {
                    network: network_label(state.network).to_string(),
                    ghost_pay_reachable,
                    ghost_pay_version,
                    ghost_pay_error,
                    gsp_have_token,
                    gsp_connected,
                    gsp_phase,
                    chain_height,
                    chain_headers,
                    chain_synced,
                    l2_height,
                })
            }
            Request::LightBalance => {
                let guard = state.session.read().await;
                match guard.as_ref() {
                    None => Response::Error(ErrorResponse {
                        message: "no GSP session — run `wraith gsp auth` first".to_string(),
                    }),
                    Some(s) => {
                        let snap = s.handle.snapshot().await;
                        match snap.last_balance {
                            None => Response::LightBalance(LightBalanceResponse {
                                confirmed_sats: None,
                                unconfirmed_sats: None,
                                locked_sats: None,
                                received_at: None,
                            }),
                            Some(b) => Response::LightBalance(LightBalanceResponse {
                                confirmed_sats: Some(b.confirmed_sats),
                                unconfirmed_sats: Some(b.unconfirmed_sats),
                                locked_sats: Some(b.locked_sats),
                                received_at: Some(b.received_at),
                            }),
                        }
                    }
                }
            }
            Request::LightUtxos { min_confirmations } => {
                let guard = state.session.read().await;
                match guard.as_ref() {
                    None => Response::Error(ErrorResponse {
                        message: "no GSP session — run `wraith gsp auth` first".to_string(),
                    }),
                    Some(s) => match s.handle.get_utxos(min_confirmations).await {
                        Ok(result) => {
                            let utxos = result
                                .utxos
                                .into_iter()
                                .map(|u| LightUtxoEntry {
                                    txid: u.txid,
                                    vout: u.vout,
                                    amount_sats: u.amount_sats,
                                    confirmations: u.confirmations,
                                    script_type: u.script_type,
                                    spendable: u.spendable,
                                })
                                .collect();
                            Response::LightUtxos(LightUtxosResponse {
                                utxos,
                                total_sats: result.total_sats,
                            })
                        }
                        Err(e) => Response::Error(ErrorResponse {
                            message: format!("light utxos: {e}"),
                        }),
                    },
                }
            }
            Request::LightL1Utxos {
                scan_max_index,
                min_confirmations,
            } => {
                use std::collections::HashMap;
                let scan_max = scan_max_index.min(1024);
                let network = state.network;
                // Derive 0..scan_max receive addresses from the active
                // keystore. We need both the address (to send to
                // ghost-pay) and the scriptPubKey (to attribute each
                // returned UTXO back to its derivation index).
                //
                // Why scriptPubKey, not address: bitcoind's
                // scantxoutset normalises `addr(<bech32>)` into
                // `rawtr(<spk-hex>)` (or `wpkh(<spk-hex>)`, etc.) in
                // its response — the address descriptor is not
                // round-tripped. Matching on the canonical
                // scriptPubKey instead avoids depending on which
                // descriptor format bitcoind chooses to echo back.
                #[derive(Clone)]
                struct DerivedAddr {
                    address: String,
                    scriptpubkey_hex: String,
                    index: u32,
                }
                let derived: Result<Vec<DerivedAddr>, String> =
                    with_active_wallet(state, |_, ks| {
                        let mut out = Vec::with_capacity(scan_max as usize);
                        for i in 0..scan_max {
                            let a = light::receive_address(ks, i, network)
                                .map_err(|e| format!("derive index {i}: {e}"))?;
                            let spk_hex = hex::encode(a.script_pubkey().as_bytes());
                            out.push(DerivedAddr {
                                address: a.to_string(),
                                scriptpubkey_hex: spk_hex,
                                index: i,
                            });
                        }
                        Ok(out)
                    })
                    .await;
                let pairs = match derived {
                    Ok(p) => p,
                    Err(e) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message: e }));
                    }
                };
                // scriptpubkey_hex → (bip86_index, address). The
                // canonical match key — see comment above.
                let spk_to_idx: HashMap<String, (u32, String)> = pairs
                    .iter()
                    .map(|d| (d.scriptpubkey_hex.clone(), (d.index, d.address.clone())))
                    .collect();
                let addresses: Vec<String> = pairs.into_iter().map(|d| d.address).collect();
                let scan = match state
                    .chain()
                    .await
                    .scan_utxos(&addresses, min_confirmations)
                    .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("ghost-pay scan: {e}"),
                            }),
                        );
                    }
                };
                let utxos: Vec<LightL1UtxoEntry> = scan
                    .utxos
                    .into_iter()
                    .filter_map(|u| {
                        // Match by scriptPubKey — independent of
                        // whether bitcoind echoed `addr(...)` or
                        // `rawtr(...)` in the response descriptor.
                        let (bip86_index, address) =
                            spk_to_idx.get(&u.scriptpubkey_hex).cloned()?;
                        Some(LightL1UtxoEntry {
                            txid: u.txid,
                            vout: u.vout,
                            amount_sats: u.amount_sats,
                            scriptpubkey_hex: u.scriptpubkey_hex,
                            bip86_index,
                            // Use the daemon-derived address — the
                            // ghost-pay-side parser may have lost it
                            // when the descriptor came back as
                            // rawtr(...).
                            address,
                            confirmations: u.confirmations,
                            height: u.height,
                        })
                    })
                    .collect();
                let total_sats = utxos.iter().map(|u| u.amount_sats).sum();
                Response::LightL1Utxos(LightL1UtxosResponse {
                    utxos,
                    total_sats,
                    chain_height: scan.chain_height,
                    scanned_max_index: scan_max,
                })
            }
            Request::LightDetected => {
                let guard = state.session.read().await;
                match guard.as_ref() {
                    None => Response::Error(ErrorResponse {
                        message: "no GSP session — run `wraith gsp auth` first".to_string(),
                    }),
                    Some(s) => {
                        let snap = s.handle.snapshot().await;
                        let detections = snap
                            .detections
                            .into_iter()
                            .map(|d| DetectedPaymentEntry {
                                txid: d.txid,
                                block_height: d.block_height,
                                vout: d.vout,
                                amount_sats: d.amount_sats,
                                k: d.k,
                                received_at: d.received_at,
                            })
                            .collect();
                        Response::LightDetected(LightDetectedResponse { detections })
                    }
                }
            }
            // Streaming subscription. handle_connection intercepts this before
            // dispatch; reaching the dispatcher means the connection wasn't
            // running our normal IPC loop. Fail loudly so misuse is obvious.
            Request::WatchPayments => Response::Error(ErrorResponse {
                message: "watch_payments must be sent on a fresh connection — \
                          handled in handle_connection, not dispatch"
                    .to_string(),
            }),
            Request::DaemonEnv => {
                let network = match state.network {
                    bitcoin::Network::Bitcoin => "mainnet",
                    bitcoin::Network::Signet => "signet",
                    bitcoin::Network::Testnet => "testnet",
                    bitcoin::Network::Regtest => "regtest",
                    _ => "unknown",
                }
                .to_string();
                let clients = state.clients.read().await;
                Response::DaemonEnv(DaemonEnvResponse {
                    ghost_pay_urls: clients.ghost_pay_urls.clone(),
                    gsp_urls: clients.gsp_urls.clone(),
                    node_preset: clients.preset.clone(),
                    ghost_pay_env_override: state.ghost_pay_env_override,
                    gsp_env_override: state.gsp_env_override,
                    network,
                    wallets_dir: state.wallets_dir.display().to_string(),
                    tor_proxy: state.tor_proxy.clone(),
                    socket_path: state.endpoint_display.clone(),
                    idle_lock_secs: state.idle_lock_secs,
                    shroud_max_ms: state.shroud_max_ms,
                    update_manifest_url: state.update_manifest_url.clone(),
                    kiosk_mode: state.kiosk_mode,
                })
            }
            Request::SetNodeEndpoints {
                preset,
                ghost_pay_url,
                gsp_url,
            } => match state
                .set_node_endpoints(&preset, ghost_pay_url, gsp_url)
                .await
            {
                Ok(applied) => Response::NodeEndpointsSet(applied),
                Err(message) => Response::Error(ErrorResponse { message }),
            },
            Request::CheckForUpdate { manifest_url } => {
                match check_for_update(state, manifest_url).await {
                    Ok(r) => Response::CheckForUpdate(r),
                    Err(message) => Response::Error(ErrorResponse { message }),
                }
            }
            Request::LightHistory { limit, offset } => {
                let guard = state.session.read().await;
                match guard.as_ref() {
                    None => Response::Error(ErrorResponse {
                        message: "no GSP session — run `wraith gsp auth` first".to_string(),
                    }),
                    Some(s) => match s.handle.get_transactions(limit, offset).await {
                        Ok(result) => {
                            let transactions = result
                                .transactions
                                .into_iter()
                                .map(|t| LightHistoryEntry {
                                    txid: t.txid,
                                    block_height: t.block_height,
                                    timestamp: t.timestamp,
                                    amount_sats: t.amount_sats,
                                    fee_sats: t.fee_sats,
                                    tx_type: t.tx_type,
                                    confirmations: t.confirmations,
                                    memo: t.memo,
                                })
                                .collect();
                            Response::LightHistory(LightHistoryResponse {
                                transactions,
                                total_count: result.total_count,
                            })
                        }
                        Err(e) => Response::Error(ErrorResponse {
                            message: format!("light history: {e}"),
                        }),
                    },
                }
            }
            Request::LightSend {
                recipient,
                amount_sats,
                mode,
                memo,
                shroud_max_ms,
            } => match light_send(state, recipient, amount_sats, mode, memo, shroud_max_ms).await {
                Ok(r) => Response::LightSent(r),
                Err(message) => Response::Error(ErrorResponse { message }),
            },
            Request::LocksPrepare { capacity_sats } => {
                let kp = match auth_keypair_for_session(state).await {
                    Ok(k) => k,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }));
                    }
                };
                let owner_pubkey = hex::encode(wraith_wallet_core::auth::xonly_pubkey_bytes(&kp));

                // Derive the wallet's recovery_pubkey at the next free
                // index. The matching recovery_secret stays in the
                // wallet's keystore, never crossing the wire. This is
                // what makes the timelock recovery branch a real
                // unilateral exit: the operator holds the lock_pubkey
                // (cooperative path), the user holds this
                // recovery_pubkey's matching secret.
                let recovery_index = state
                    .next_recovery_index
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let active_name = match state.active.read().await.clone() {
                    Some(n) => n,
                    None => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: "no active wallet".into(),
                            }),
                        );
                    }
                };
                let recovery_pubkey_hex = match with_active_wallet(state, |_, ks| {
                    let ghost_keys = ks.ghost_keys().map_err(|e| format!("ghost_keys: {e}"))?;
                    let pk_bytes = ghost_keys
                        .derive_recovery_pubkey(recovery_index)
                        .map_err(|e| format!("derive_recovery_pubkey: {e}"))?;
                    Ok::<String, String>(hex::encode(pk_bytes))
                })
                .await
                {
                    Ok(s) => s,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }));
                    }
                };

                let session = state.session.read().await;
                let session = session.as_ref().expect("just checked above");
                match session
                    .handle
                    .prepare_ghost_lock(
                        owner_pubkey,
                        capacity_sats,
                        recovery_pubkey_hex.clone(),
                        recovery_index,
                    )
                    .await
                {
                    Ok(r) => {
                        // Belt-and-braces: server MUST echo the same
                        // recovery_pubkey we sent. If it doesn't, the
                        // operator has substituted its own key and the
                        // recovery path is no longer ours. Refuse.
                        if r.recovery_pubkey != recovery_pubkey_hex
                            || r.recovery_index != recovery_index
                        {
                            return Envelope::new(
                                id,
                                Response::Error(ErrorResponse {
                                    message: format!(
                                        "operator returned mismatched recovery key \
                                         (sent {} idx={}, got {} idx={}); refusing lock — \
                                         possible operator substitution attack",
                                        recovery_pubkey_hex,
                                        recovery_index,
                                        r.recovery_pubkey,
                                        r.recovery_index,
                                    ),
                                }),
                            );
                        }

                        // Stash everything LocksRecover will need.
                        state.prepared_locks.write().await.insert(
                            r.lock_id.clone(),
                            PreparedLockMeta {
                                wallet_name: active_name.clone(),
                                recovery_index,
                                lock_pubkey_hex: r.lock_pubkey.clone(),
                                recovery_pubkey_hex: r.recovery_pubkey.clone(),
                                recovery_blocks: r.recovery_blocks,
                                creation_height: r.creation_height,
                                funding_address: r.funding_address.clone(),
                                capacity_sats: r.required_sats,
                                funding_txid: None,
                            },
                        );
                        persist_prepared_locks(state, &active_name).await;

                        Response::LocksPrepared(LocksPreparedResponse {
                            lock_id: r.lock_id,
                            funding_address: r.funding_address,
                            required_sats: r.required_sats,
                        })
                    }
                    Err(message) => Response::Error(ErrorResponse {
                        message: format!("locks prepare: {message}"),
                    }),
                }
            }
            Request::LocksConfirm {
                lock_id,
                funding_txid,
            } => {
                let kp = match auth_keypair_for_session(state).await {
                    Ok(k) => k,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }));
                    }
                };
                let proof = match wraith_wallet_core::auth::make_proof(&kp, "confirm_lock") {
                    Ok(p) => p,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("confirm_lock proof: {e}"),
                            }),
                        );
                    }
                };
                let session = state.session.read().await;
                let session = session.as_ref().expect("just checked above");
                match session
                    .handle
                    .confirm_ghost_lock_funding(lock_id, funding_txid, proof)
                    .await
                {
                    Ok(r) => {
                        // Attach the funding txid to our local lock
                        // metadata so LocksRecover can spend the right
                        // outpoint without going back to the operator.
                        // Capture the wallet_name out of the meta so we
                        // can persist after dropping the write guard.
                        let wallet_to_persist = {
                            let mut guard = state.prepared_locks.write().await;
                            guard.get_mut(&r.lock_id).map(|m| {
                                m.funding_txid = Some(r.txid.clone());
                                m.wallet_name.clone()
                            })
                        };
                        if let Some(wallet) = wallet_to_persist {
                            persist_prepared_locks(state, &wallet).await;
                        }
                        Response::LocksConfirmed(LocksConfirmedResponse {
                            lock_id: r.lock_id,
                            txid: r.txid,
                            block_height: r.block_height,
                        })
                    }
                    Err(message) => Response::Error(ErrorResponse {
                        message: format!("locks confirm: {message}"),
                    }),
                }
            }
            Request::LocksJump {
                lock_id,
                target_address,
                priority,
            } => {
                let priority = match parse_jump_priority(&priority) {
                    Ok(p) => p,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }));
                    }
                };
                let kp = match auth_keypair_for_session(state).await {
                    Ok(k) => k,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }));
                    }
                };
                let proof = match wraith_wallet_core::auth::make_proof(&kp, "request_jump") {
                    Ok(p) => p,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("request_jump proof: {e}"),
                            }),
                        );
                    }
                };
                let session = state.session.read().await;
                let session = session.as_ref().expect("just checked above");
                match session
                    .handle
                    .request_jump(lock_id, priority, target_address, proof)
                    .await
                {
                    Ok(r) => Response::LocksJumped(LocksJumpedResponse {
                        lock_id: r.lock_id,
                        jump_txid: r.jump_txid,
                    }),
                    Err(message) => Response::Error(ErrorResponse {
                        message: format!("locks jump: {message}"),
                    }),
                }
            }
            Request::LocksRecover {
                lock_id,
                destination_address,
                fee_sats,
            } => {
                use wraith_wallet_core::ghostd::GhostdRpc;
                use wraith_wallet_core::lock_recovery::{
                    build_recovery_spend, RecoverySpendInputs,
                };

                // 1. bitcoind must be configured. Without it the
                //    recovery path can't reach L1 — this is the only
                //    IPC method that talks straight to bitcoind.
                let url = match state.ghostd_url.as_deref() {
                    Some(u) => u,
                    None => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: "no bitcoind RPC configured \
                                    (set WRAITHD_GHOSTD_URL + WRAITHD_GHOSTD_COOKIE \
                                    or WRAITHD_GHOSTD_USER+PASS)"
                                    .into(),
                            }),
                        );
                    }
                };
                let rpc_result = match (
                    state.ghostd_cookie_path.as_ref(),
                    state.ghostd_user.as_deref(),
                    state.ghostd_pass.as_deref(),
                ) {
                    (Some(cookie), None, None) => GhostdRpc::from_cookie(url, cookie),
                    (None, Some(u), Some(p)) => Ok(GhostdRpc::new(url, u, p)),
                    _ => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: "bitcoind auth misconfigured: supply either \
                                    cookie path or user+pass, not both / neither"
                                    .into(),
                            }),
                        );
                    }
                };
                let rpc = match rpc_result {
                    Ok(r) => r,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("bitcoind init: {e}"),
                            }),
                        );
                    }
                };

                // 2. Pull the prepared-lock metadata from our local
                //    stash. Without it we can't reconstruct the
                //    witness script or know which recovery_secret to
                //    sign with.
                let meta = match state.prepared_locks.read().await.get(&lock_id).cloned() {
                    Some(m) => m,
                    None => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: missing_lock_metadata_error(&lock_id),
                            }),
                        );
                    }
                };
                let funding_txid = match meta.funding_txid.clone() {
                    Some(t) => t,
                    None => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!(
                                    "lock '{lock_id}' has no recorded funding txid \
                                    (call locks confirm first)"
                                ),
                            }),
                        );
                    }
                };

                // 3. Resolve the funding outpoint via bitcoind. Walk
                //    the tx vouts for one whose address matches our
                //    funding_address. (P2WSH addresses are unique
                //    per script so a single match is all we need.)
                let raw_tx = match rpc.get_raw_transaction_verbose(&funding_txid) {
                    Ok(t) => t,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("bitcoind getrawtransaction: {e}"),
                            }),
                        );
                    }
                };
                let matching_vout = raw_tx.vout.iter().find(|v| {
                    v.script_pubkey.first_address() == Some(meta.funding_address.as_str())
                });
                let vout = match matching_vout {
                    Some(v) => v,
                    None => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!(
                                    "funding tx {funding_txid} has no output \
                                    paying lock address {}",
                                    meta.funding_address
                                ),
                            }),
                        );
                    }
                };

                // 4. Maturity check.
                let current_height = match rpc.get_block_count() {
                    Ok(h) => h as u32,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("bitcoind getblockcount: {e}"),
                            }),
                        );
                    }
                };

                // 5. Build the recovery tx using the wallet's own
                //    recovery_secret. with_active_wallet locks the
                //    keystore briefly for the (sync) sighash + ECDSA
                //    sign step.
                let prev_value_sats = vout.value_sats();
                let funding_scriptpubkey_hex = vout.script_pubkey.hex.clone();
                let funding_vout_n = vout.n;
                let recovery_index = meta.recovery_index;
                let inputs = RecoverySpendInputs {
                    lock_pubkey_hex: meta.lock_pubkey_hex.clone(),
                    recovery_pubkey_hex: meta.recovery_pubkey_hex.clone(),
                    recovery_blocks: meta.recovery_blocks,
                    funding_txid: funding_txid.clone(),
                    funding_vout: funding_vout_n,
                    prev_value_sats,
                    funding_scriptpubkey_hex,
                    destination_address: destination_address.clone(),
                    fee_sats,
                    network: state.network,
                    current_height,
                    creation_height: meta.creation_height,
                };

                let built = match with_active_wallet(state, |_, ks| {
                    let ghost_keys = ks.ghost_keys().map_err(|e| format!("ghost_keys: {e}"))?;
                    let recovery_secret = ghost_keys
                        .derive_recovery_secret(recovery_index)
                        .map_err(|e| format!("derive_recovery_secret: {e}"))?;
                    build_recovery_spend(&inputs, &recovery_secret)
                        .map_err(|e| format!("build recovery: {e}"))
                })
                .await
                {
                    Ok(b) => b,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }));
                    }
                };

                // 6. Broadcast.
                match rpc.send_raw_transaction(&built.raw_hex) {
                    Ok(network_txid) => {
                        tracing::info!(
                            %lock_id,
                            broadcast_txid = %network_txid,
                            recovered_sats = prev_value_sats - fee_sats,
                            "lock recovery broadcast — unilateral exit complete",
                        );
                        // The lock is spent — drop it from the stash
                        // so subsequent recovery attempts on the same
                        // lock_id fail cleanly. Persist the change.
                        let wallet_to_persist = state
                            .prepared_locks
                            .write()
                            .await
                            .remove(&lock_id)
                            .map(|m| m.wallet_name);
                        if let Some(wallet) = wallet_to_persist {
                            persist_prepared_locks(state, &wallet).await;
                        }
                        Response::LocksRecovered(LocksRecoveredResponse {
                            lock_id,
                            broadcast_txid: network_txid,
                            destination_address,
                            recovered_sats: prev_value_sats - fee_sats,
                            fee_sats,
                        })
                    }
                    Err(e) => Response::Error(ErrorResponse {
                        message: format!("bitcoind sendrawtransaction: {e}"),
                    }),
                }
            }
            Request::LocksList => {
                let guard = state.session.read().await;
                match guard.as_ref() {
                    None => Response::Error(ErrorResponse {
                        message: "no GSP session — run `wraith gsp auth` first".to_string(),
                    }),
                    Some(s) => match s.handle.get_ghost_locks().await {
                        Ok(result) => {
                            let locks = result
                                .locks
                                .into_iter()
                                .map(|l| LockEntry {
                                    lock_id: l.lock_id,
                                    // Canonical lowercase via Display ("pending"/"active"/"in_use");
                                    // Debug formatting would render multi-word variants wrong (e.g. "inuse").
                                    status: l.status.to_string(),
                                    capacity_sats: l.capacity_sats,
                                    balance_sats: l.balance_sats,
                                    denomination: l.denomination,
                                    timelock_tier: l.timelock_tier,
                                    funding_address: l.funding_address,
                                    funding_txid: l.funding_txid,
                                    funding_vout: l.funding_vout,
                                    creation_height: l.creation_height,
                                    recovery_height: l.recovery_height,
                                })
                                .collect();
                            Response::LocksList(LocksListResponse {
                                locks,
                                total_locked_sats: result.total_locked_sats,
                            })
                        }
                        Err(e) => Response::Error(ErrorResponse {
                            message: format!("locks list: {e}"),
                        }),
                    },
                }
            }
            Request::WalletCreate {
                name,
                passphrase,
                user_entropy_digest,
            } => {
                if let Some(refused) = refuse_in_kiosk_mode(state, "wallet create") {
                    return Envelope::new(id, refused);
                }
                if let Err(e) = validate_wallet_name(&name) {
                    Response::Error(ErrorResponse { message: e })
                } else {
                    let path = keystore_path(&state.wallets_dir, &name);
                    if path.exists() {
                        Response::Error(ErrorResponse {
                            message: format!(
                                "wallet '{name}' already exists at {}; refusing to overwrite",
                                path.display()
                            ),
                        })
                    } else {
                        let pass = SecretString::new(passphrase);
                        // User entropy is mixed with the OS source, never
                        // substituted for it, so a malformed or hostile
                        // digest cannot weaken the seed below what the OS
                        // alone would have given.
                        let mixed = match user_entropy_digest.as_deref() {
                            None => None,
                            Some(hex_digest) => match decode_entropy_digest(hex_digest) {
                                Ok(d) => Some(d),
                                Err(message) => {
                                    return Envelope::new(
                                        id,
                                        Response::Error(ErrorResponse { message }),
                                    )
                                }
                            },
                        };
                        match Keystore::create_with_mixed_digest(mixed.as_ref()) {
                            Ok((ks, mnemonic)) => match ks.save(&path, &pass) {
                                Ok(()) => {
                                    state.wallets.write().await.insert(name.clone(), ks);
                                    *state.active.write().await = Some(name.clone());
                                    Response::WalletCreate(WalletCreateResponse {
                                        name,
                                        mnemonic,
                                        path: path.display().to_string(),
                                    })
                                }
                                Err(e) => Response::Error(ErrorResponse {
                                    message: format!("save: {e}"),
                                }),
                            },
                            Err(e) => Response::Error(ErrorResponse {
                                message: format!("create: {e}"),
                            }),
                        }
                    }
                }
            }
            Request::WalletImport {
                name,
                mnemonic,
                passphrase,
            } => {
                if let Some(refused) = refuse_in_kiosk_mode(state, "wallet import") {
                    return Envelope::new(id, refused);
                }
                if let Err(e) = validate_wallet_name(&name) {
                    Response::Error(ErrorResponse { message: e })
                } else if state.network == bitcoin::Network::Bitcoin
                    && wraith_wallet_core::mainnet_guard::is_known_weak_mnemonic(&mnemonic)
                {
                    // Mainnet-readiness guard: refuse canonical BIP-39 test vectors
                    // and other publicly-published seeds. Allowed on signet /
                    // testnet / regtest where the foot-gun isn't a foot-gun.
                    Response::Error(ErrorResponse {
                        message: "refusing to import a publicly-known mnemonic on mainnet — \
                                  this seed has been swept thousands of times. Generate a \
                                  fresh one with `wraith wallet create`."
                            .to_string(),
                    })
                } else {
                    let path = keystore_path(&state.wallets_dir, &name);
                    if path.exists() {
                        Response::Error(ErrorResponse {
                            message: format!(
                                "wallet '{name}' already exists at {}; refusing to overwrite",
                                path.display()
                            ),
                        })
                    } else {
                        let pass = SecretString::new(passphrase);
                        match Keystore::from_mnemonic(&mnemonic) {
                            Ok(ks) => match ks.save(&path, &pass) {
                                Ok(()) => {
                                    state.wallets.write().await.insert(name.clone(), ks);
                                    *state.active.write().await = Some(name.clone());
                                    Response::WalletImported {
                                        name,
                                        path: path.display().to_string(),
                                    }
                                }
                                Err(e) => Response::Error(ErrorResponse {
                                    message: format!("save: {e}"),
                                }),
                            },
                            Err(e) => Response::Error(ErrorResponse {
                                message: format!("mnemonic: {e}"),
                            }),
                        }
                    }
                }
            }
            Request::WalletUnlock { name, passphrase } => {
                if let Err(e) = validate_wallet_name(&name) {
                    Response::Error(ErrorResponse { message: e })
                } else {
                    let path = keystore_path(&state.wallets_dir, &name);
                    if !path.exists() {
                        Response::Error(ErrorResponse {
                            message: format!("no wallet '{name}' at {}", path.display()),
                        })
                    } else {
                        let pass = SecretString::new(passphrase);
                        match Keystore::load(&path, &pass) {
                            Ok(ks) => {
                                state.wallets.write().await.insert(name.clone(), ks);
                                *state.active.write().await = Some(name.clone());
                                // Restore the wallet's previously-prepared locks
                                // from disk. Merges into the in-memory map so
                                // multi-wallet setups don't clobber each other.
                                let restored = load_locks_for_wallet(&state.wallets_dir, &name);
                                if !restored.is_empty() {
                                    let mut guard = state.prepared_locks.write().await;
                                    for (k, v) in restored {
                                        guard.insert(k, v);
                                    }
                                    // Advance the recovery-index counter past every
                                    // index already committed to disk so a restart
                                    // never re-issues (and thus re-derives) a recovery
                                    // key an existing lock already uses.
                                    advance_recovery_index_past_locks(
                                        &state.next_recovery_index,
                                        &guard,
                                    );
                                    tracing::info!(wallet = %name, "restored prepared locks from disk");
                                }
                                Response::WalletUnlocked
                            }
                            Err(KeystoreError::Decrypt) => Response::Error(ErrorResponse {
                                message: "wrong passphrase".to_string(),
                            }),
                            Err(e) => Response::Error(ErrorResponse {
                                message: format!("unlock: {e}"),
                            }),
                        }
                    }
                }
            }
            Request::WalletLock { name } => {
                if let Some(refused) = refuse_in_kiosk_mode(state, "wallet lock") {
                    return Envelope::new(id, refused);
                }
                let target = match name {
                    Some(n) => n,
                    None => match state.active.read().await.clone() {
                        Some(n) => n,
                        None => {
                            return Envelope::new(
                                id,
                                Response::Error(ErrorResponse {
                                    message: "no active wallet to lock".to_string(),
                                }),
                            );
                        }
                    },
                };
                let removed = state.wallets.write().await.remove(&target).is_some();
                if !removed {
                    Response::Error(ErrorResponse {
                        message: format!("wallet '{target}' is not unlocked"),
                    })
                } else {
                    let mut active = state.active.write().await;
                    if active.as_deref() == Some(target.as_str()) {
                        *active = None;
                    }
                    // Drop any GSP session bound to the wallet we just locked.
                    let mut session = state.session.write().await;
                    if session.as_ref().is_some_and(|s| s.wallet_name == target) {
                        *session = None;
                    }
                    Response::WalletLocked { name: target }
                }
            }
            Request::WalletDelete { name } => {
                if let Some(refused) = refuse_in_kiosk_mode(state, "wallet delete") {
                    return Envelope::new(id, refused);
                }
                if let Err(e) = validate_wallet_name(&name) {
                    Response::Error(ErrorResponse { message: e })
                } else {
                    let keystore = keystore_path(&state.wallets_dir, &name);
                    // The per-wallet directory holds the keystore plus any
                    // saved descriptors; removing it wipes every on-disk
                    // trace of the wallet.
                    let wallet_dir = state.wallets_dir.join(&name);
                    if !keystore.is_file() {
                        Response::Error(ErrorResponse {
                            message: format!("no wallet '{name}' at {}", keystore.display()),
                        })
                    } else if let Err(e) = std::fs::remove_dir_all(&wallet_dir) {
                        Response::Error(ErrorResponse {
                            message: format!("delete '{name}': {e}"),
                        })
                    } else {
                        // Drop the in-memory keystore and clear the active
                        // pointer / bound GSP session so nothing keeps
                        // referencing a wallet whose backing is now gone.
                        state.wallets.write().await.remove(&name);
                        let mut active = state.active.write().await;
                        if active.as_deref() == Some(name.as_str()) {
                            *active = None;
                        }
                        let mut session = state.session.write().await;
                        if session.as_ref().is_some_and(|s| s.wallet_name == name) {
                            *session = None;
                        }
                        Response::WalletDeleted { name }
                    }
                }
            }
            Request::WalletList => {
                let on_disk = list_on_disk(&state.wallets_dir);
                let unlocked = state.wallets.read().await;
                let active = state.active.read().await.clone();
                let mut wallets: Vec<WalletListEntry> = on_disk
                    .into_iter()
                    .map(|name| {
                        let signer = unlocked.get(&name).map(signer_info_for_unlocked);
                        WalletListEntry {
                            path: keystore_path(&state.wallets_dir, &name)
                                .display()
                                .to_string(),
                            unlocked: unlocked.contains_key(&name),
                            active: active.as_deref() == Some(name.as_str()),
                            name,
                            signer,
                        }
                    })
                    .collect();
                // Surface unlocked-but-not-on-disk wallets too (shouldn't happen, but
                // defensive — eg if disk file was deleted under us).
                for (name, ks) in unlocked.iter() {
                    if !wallets.iter().any(|e| &e.name == name) {
                        wallets.push(WalletListEntry {
                            name: name.clone(),
                            path: keystore_path(&state.wallets_dir, name)
                                .display()
                                .to_string(),
                            unlocked: true,
                            active: active.as_deref() == Some(name.as_str()),
                            signer: Some(signer_info_for_unlocked(ks)),
                        });
                    }
                }
                Response::WalletList(WalletListResponse { wallets })
            }
            Request::WalletSelect { name } => {
                if let Some(refused) = refuse_in_kiosk_mode(state, "wallet select") {
                    return Envelope::new(id, refused);
                }
                if let Err(e) = validate_wallet_name(&name) {
                    Response::Error(ErrorResponse { message: e })
                } else if !state.wallets.read().await.contains_key(&name) {
                    Response::Error(ErrorResponse {
                        message: format!(
                            "wallet '{name}' is not unlocked; \
                             run `wraith wallet unlock {name}` first"
                        ),
                    })
                } else {
                    *state.active.write().await = Some(name.clone());
                    // Drop any GSP session that belongs to a different wallet.
                    let mut session = state.session.write().await;
                    if session.as_ref().is_some_and(|s| s.wallet_name != name) {
                        *session = None;
                    }
                    Response::WalletSelected { name }
                }
            }
            Request::WalletStatus => {
                let active = state.active.read().await.clone();
                let wallets = state.wallets.read().await;
                let unlocked = active
                    .as_deref()
                    .map(|n| wallets.contains_key(n))
                    .unwrap_or(false);
                let signer = active
                    .as_deref()
                    .and_then(|n| wallets.get(n))
                    .map(signer_info_for_unlocked);
                let path = active
                    .as_ref()
                    .map(|n| keystore_path(&state.wallets_dir, n).display().to_string());
                Response::WalletStatus(WalletStatusResponse {
                    active,
                    path,
                    unlocked,
                    signer,
                })
            }
            Request::WalletDerive { path } => {
                match with_active_wallet(state, |_, ks| {
                    ks.derive_xprv(&path)
                        .map(|x| hex::encode(x.public_key().to_bytes()))
                        .map_err(|e| format!("derive: {e}"))
                })
                .await
                {
                    Ok(public_key_hex) => Response::WalletDerive(WalletDeriveResponse {
                        path,
                        public_key_hex,
                    }),
                    Err(message) => Response::Error(ErrorResponse { message }),
                }
            }
            Request::WalletExportXpub { path, mainnet } => {
                let label = if mainnet { "mainnet" } else { "testnet" }.to_string();
                match with_active_wallet(state, move |_, ks| {
                    ks.export_xpub(&path, mainnet)
                        .map_err(|e| format!("export_xpub: {e}"))
                })
                .await
                {
                    Ok(exp) => Response::WalletXpub(WalletXpubResponse {
                        xpub: exp.xpub,
                        master_fingerprint_hex: exp.master_fingerprint_hex,
                        path: exp.path,
                        descriptor_key_fragment: exp.descriptor_key_fragment,
                        network_label: label,
                    }),
                    Err(message) => Response::Error(ErrorResponse { message }),
                }
            }
            Request::MultisigDescriptorInspect {
                descriptor,
                address_count,
            } => match multisig_inspect_handler(state, &descriptor, address_count).await {
                Ok(r) => Response::MultisigDescriptorInspected(r),
                Err(e) => Response::Error(ErrorResponse { message: e }),
            },
            Request::MultisigDescriptorSave { name, descriptor } => {
                match multisig_save_handler(state, &name, &descriptor).await {
                    Ok(r) => Response::MultisigDescriptorSaved(r),
                    Err(e) => Response::Error(ErrorResponse { message: e }),
                }
            }
            Request::MultisigDescriptorList => match multisig_list_handler(state).await {
                Ok(r) => Response::MultisigDescriptorList(r),
                Err(e) => Response::Error(ErrorResponse { message: e }),
            },
            Request::MultisigDescriptorAddresses {
                name,
                start_index,
                count,
                internal,
            } => match multisig_addresses_handler(state, &name, start_index, count, internal).await
            {
                Ok(r) => Response::MultisigDescriptorAddresses(r),
                Err(e) => Response::Error(ErrorResponse { message: e }),
            },
            Request::MultisigDescriptorDelete { name } => {
                match multisig_delete_handler(state, &name).await {
                    Ok(removed) => Response::MultisigDescriptorDeleted { removed },
                    Err(e) => Response::Error(ErrorResponse { message: e }),
                }
            }
            Request::WalletGhostId => {
                let net = state.network;
                let label = format!("{:?}", net).to_lowercase();
                match with_active_wallet(state, move |_, ks| {
                    let gk = ks.ghost_keys().map_err(|e| format!("ghost-keys: {e}"))?;
                    let id = gk
                        .ghost_id()
                        .encode_for_network(ghost_network_from_bitcoin(net))
                        .map_err(|e| format!("encode: {e}"))?;
                    let scan_hex = hex::encode(gk.scan_pubkey().serialize());
                    let spend_hex = hex::encode(gk.spend_pubkey().serialize());
                    Ok::<_, String>((id, scan_hex, spend_hex))
                })
                .await
                {
                    Ok((id, scan, spend)) => Response::WalletGhostId(WalletGhostIdResponse {
                        ghost_id: id,
                        network: label,
                        scan_public_key_hex: scan,
                        spend_public_key_hex: spend,
                    }),
                    Err(message) => Response::Error(ErrorResponse { message }),
                }
            }
            Request::WalletGlyph { ghost_id } => match build_ghost_pay_client(state).await {
                Ok(client) => match client.get_glyph(&ghost_id).await {
                    Ok(v) => match serde_json::from_value::<GlyphInfo>(v) {
                        Ok(info) => Response::WalletGlyph(info),
                        Err(e) => Response::Error(ErrorResponse {
                            message: format!("glyph parse: {e}"),
                        }),
                    },
                    Err(e) => Response::Error(ErrorResponse {
                        message: format!("glyph: {e}"),
                    }),
                },
                Err(message) => Response::Error(ErrorResponse { message }),
            },
            Request::WalletGlyphCheck { pixels } => match build_ghost_pay_client(state).await {
                Ok(client) => {
                    let bitmap_hash_hex = glyph_bitmap_hash_hex(&pixels);
                    match client.check_glyph(&bitmap_hash_hex).await {
                        Ok(v) => {
                            let available = v
                                .get("available")
                                .and_then(|b| b.as_bool())
                                .unwrap_or(false);
                            Response::WalletGlyphChecked { available }
                        }
                        Err(e) => Response::Error(ErrorResponse {
                            message: format!("glyph check: {e}"),
                        }),
                    }
                }
                Err(message) => Response::Error(ErrorResponse { message }),
            },
            Request::WalletGlyphClaim { ghost_id, pixels } => {
                match build_ghost_pay_client(state).await {
                    Ok(client) => match client.claim_glyph(&ghost_id, &pixels).await {
                        Ok(v) => match serde_json::from_value::<GlyphClaimResult>(v) {
                            Ok(r) => Response::WalletGlyphClaimed(r),
                            Err(e) => Response::Error(ErrorResponse {
                                message: format!("glyph claim parse: {e}"),
                            }),
                        },
                        Err(e) => Response::Error(ErrorResponse {
                            message: format!("glyph claim: {e}"),
                        }),
                    },
                    Err(message) => Response::Error(ErrorResponse { message }),
                }
            }
            Request::WalletAuthInfo => {
                match with_active_wallet(state, |_, ks| {
                    let kp = auth::auth_keypair(ks).map_err(|e| format!("auth-info: {e}"))?;
                    Ok::<_, String>((
                        auth::wallet_id_hex(&kp),
                        hex::encode(auth::xonly_pubkey_bytes(&kp)),
                    ))
                })
                .await
                {
                    Ok((wallet_id, auth_public_key_hex)) => {
                        Response::WalletAuthInfo(WalletAuthInfoResponse {
                            wallet_id,
                            auth_public_key_hex,
                            derivation_path: auth::AUTH_DERIVATION_PATH.to_string(),
                        })
                    }
                    Err(message) => Response::Error(ErrorResponse { message }),
                }
            }
            Request::WalletExport { name, to_path } => {
                if let Err(e) = validate_wallet_name(&name) {
                    Response::Error(ErrorResponse { message: e })
                } else {
                    let src = keystore_path(&state.wallets_dir, &name);
                    if !src.is_file() {
                        Response::Error(ErrorResponse {
                            message: format!("no wallet '{name}' at {}", src.display()),
                        })
                    } else {
                        let dst = std::path::PathBuf::from(&to_path);
                        if dst.exists() {
                            Response::Error(ErrorResponse {
                                message: format!(
                                    "refusing to overwrite existing file at {}",
                                    dst.display()
                                ),
                            })
                        } else {
                            if let Some(parent) = dst.parent() {
                                if let Err(e) = std::fs::create_dir_all(parent) {
                                    return Envelope::new(
                                        id,
                                        Response::Error(ErrorResponse {
                                            message: format!("create parent dir: {e}"),
                                        }),
                                    );
                                }
                            }
                            match std::fs::copy(&src, &dst) {
                                Ok(bytes) => {
                                    // Match the keystore's own owner-only permissions.
                                    // Windows inherits the user-profile ACL from the
                                    // parent directory, so no explicit chmod is needed.
                                    #[cfg(unix)]
                                    {
                                        use std::os::unix::fs::PermissionsExt;
                                        let _ = std::fs::set_permissions(
                                            &dst,
                                            std::fs::Permissions::from_mode(0o600),
                                        );
                                    }
                                    Response::WalletExported {
                                        name,
                                        path: dst.display().to_string(),
                                        bytes,
                                    }
                                }
                                Err(e) => Response::Error(ErrorResponse {
                                    message: format!("copy: {e}"),
                                }),
                            }
                        }
                    }
                }
            }
            Request::WalletRestore { name, from_path } => {
                if let Err(e) = validate_wallet_name(&name) {
                    Response::Error(ErrorResponse { message: e })
                } else {
                    let src = std::path::PathBuf::from(&from_path);
                    if !src.is_file() {
                        Response::Error(ErrorResponse {
                            message: format!("no file at {}", src.display()),
                        })
                    } else {
                        let dst = keystore_path(&state.wallets_dir, &name);
                        if dst.exists() {
                            Response::Error(ErrorResponse {
                                message: format!(
                                    "wallet '{name}' already exists at {}; refusing to overwrite",
                                    dst.display()
                                ),
                            })
                        } else {
                            if let Some(parent) = dst.parent() {
                                if let Err(e) = std::fs::create_dir_all(parent) {
                                    return Envelope::new(
                                        id,
                                        Response::Error(ErrorResponse {
                                            message: format!("create wallet dir: {e}"),
                                        }),
                                    );
                                }
                            }
                            match std::fs::copy(&src, &dst) {
                                Ok(bytes) => {
                                    #[cfg(unix)]
                                    {
                                        use std::os::unix::fs::PermissionsExt;
                                        let _ = std::fs::set_permissions(
                                            &dst,
                                            std::fs::Permissions::from_mode(0o600),
                                        );
                                    }
                                    Response::WalletRestored {
                                        name,
                                        path: dst.display().to_string(),
                                        bytes,
                                    }
                                }
                                Err(e) => Response::Error(ErrorResponse {
                                    message: format!("copy: {e}"),
                                }),
                            }
                        }
                    }
                }
            }
            Request::WalletShowMnemonic { name, passphrase } => {
                if let Err(e) = validate_wallet_name(&name) {
                    Response::Error(ErrorResponse { message: e })
                } else {
                    let path = keystore_path(&state.wallets_dir, &name);
                    if !path.exists() {
                        Response::Error(ErrorResponse {
                            message: format!("no wallet '{name}' at {}", path.display()),
                        })
                    } else {
                        let pass = SecretString::new(passphrase);
                        match Keystore::load(&path, &pass) {
                            Ok(ks) => Response::WalletShowMnemonic(WalletShowMnemonicResponse {
                                mnemonic: ks.expose_mnemonic().to_string(),
                            }),
                            Err(KeystoreError::Decrypt) => Response::Error(ErrorResponse {
                                message: "wrong passphrase".to_string(),
                            }),
                            Err(e) => Response::Error(ErrorResponse {
                                message: format!("show-mnemonic: {e}"),
                            }),
                        }
                    }
                }
            }
            Request::LightReceive { index } => {
                let network = state.network;
                match with_active_wallet(state, |_, ks| {
                    light::receive_address(ks, index, network)
                        .map(|a| a.to_string())
                        .map_err(|e| format!("light receive: {e}"))
                })
                .await
                {
                    Ok(address) => Response::LightReceive(LightReceiveResponse {
                        address,
                        index,
                        network: format!("{:?}", state.network).to_lowercase(),
                        derivation_path: format!(
                            "m/86'/{}'/0'/0/{}",
                            light::GHOST_COIN_TYPE,
                            index
                        ),
                    }),
                    Err(message) => Response::Error(ErrorResponse { message }),
                }
            }
            Request::WraithMixPrepare {
                coordinator_url,
                socks5_proxy,
                coordinator_peers,
                tier_id,
                ghost_id,
                utxo_txid,
                utxo_vout,
                utxo_value_sats,
                utxo_scriptpubkey_hex,
                mix_output_address,
                min_entities,
            } => {
                use wraith_wallet_core::wraith::{
                    MixRequest, ParticipantUtxo, WraithClientError, WraithSessionClient,
                };
                let client_result = match socks5_proxy.as_deref() {
                    Some(proxy) => WraithSessionClient::with_outputs_proxy(
                        coordinator_url.clone(),
                        state.network,
                        proxy,
                    ),
                    None if coordinator_peers.is_empty() => Ok(WraithSessionClient::new(
                        coordinator_url.clone(),
                        state.network,
                    )),
                    None => Ok(WraithSessionClient::with_peers(
                        coordinator_url.clone(),
                        coordinator_peers.clone(),
                        state.network,
                    )),
                };
                let client = match client_result {
                    Ok(c) => Arc::new(c),
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("wraith client: {e}"),
                            }),
                        );
                    }
                };
                // Same reason: `req` takes the scriptPubKey, and the
                // ownership proof needs it to find the key that owns it.
                let utxo_scriptpubkey_hex_for_proof = utxo_scriptpubkey_hex.clone();
                let network_for_proof = state.network;
                let scan_max_for_proof = wraith_wallet_core::wraith_signer::DEFAULT_SCAN_INDEX_MAX;
                let req = MixRequest {
                    tier_id,
                    ghost_id,
                    utxo: ParticipantUtxo {
                        txid: utxo_txid,
                        vout: utxo_vout,
                        value_sats: utxo_value_sats,
                        scriptpubkey_hex: utxo_scriptpubkey_hex,
                    },
                    mix_output_address,
                    min_entities: min_entities
                        .unwrap_or(wraith_wallet_core::wraith::DEFAULT_MIN_ENTITIES),
                };
                // Prove control of the input UTXO. The coordinator checks
                // this against the scriptPubKey the chain reports for the
                // outpoint, so it must come from the key that really owns
                // the coin (#699). Async because the keystore sits behind
                // the wallet lock.
                let proof_spk = utxo_scriptpubkey_hex_for_proof.clone();
                let prove_ownership = |challenge: &str| {
                    let challenge = challenge.to_string();
                    let spk = proof_spk.clone();
                    async move {
                        with_active_wallet(state, move |_, ks| {
                            wraith_wallet_core::wraith_signer::prove_ownership(
                                ks,
                                network_for_proof,
                                &spk,
                                &challenge,
                                scan_max_for_proof,
                            )
                            .map_err(|e| e.to_string())
                        })
                        .await
                        .map_err(WraithClientError::OwnershipProof)
                    }
                };
                match client.prepare_mix(req, prove_ownership).await {
                    Ok(prepared) => {
                        // Inspect here, at prepare time — before the caller is
                        // handed a transaction to sign. Checking later would
                        // mean the wallet had already produced a signature over
                        // a round it never verified.
                        match signing_ledger_for(state) {
                            Err(e) => Response::Error(ErrorResponse {
                                message: format!("signing ledger unavailable: {e}"),
                            }),
                            Ok(mut ledger) => match prepared.inspect(&mut ledger) {
                                Err(e) => match refusal_response(
                                    prepared.session_id.clone(),
                                    min_entities.unwrap_or(
                                        wraith_wallet_core::wraith::DEFAULT_MIN_ENTITIES,
                                    ),
                                    &e,
                                ) {
                                    Some(r) => Response::WraithMixRefused(r),
                                    None => Response::Error(ErrorResponse {
                                        message: format!("refused the round: {e}"),
                                    }),
                                },
                                Ok(inspected) => {
                                    let p = inspected.prepared();
                                    let resp = WraithMixPreparedResponse {
                                        session_id: p.session_id.clone(),
                                        unsigned_tx_hex: bitcoin::consensus::encode::serialize_hex(
                                            &p.unsigned_tx,
                                        ),
                                        input_index: p.input_index as u32,
                                        prev_amount_sats: p.prev_amount_sats,
                                        mixed_output_tx_index: p.mixed_output_tx_index as u32,
                                    };
                                    let sid = p.session_id.clone();
                                    state
                                        .wraith_mixes
                                        .write()
                                        .await
                                        .insert(sid, StoredWraithMix { inspected, client });
                                    Response::WraithMixPrepared(resp)
                                }
                            },
                        }
                    }
                    Err(e) => Response::Error(ErrorResponse {
                        message: format!("wraith prepare: {e}"),
                    }),
                }
            }
            Request::WraithMixSubmit {
                session_id,
                witness_hex,
            } => {
                let stored = state.wraith_mixes.write().await.remove(&session_id);
                let stored = match stored {
                    Some(s) => s,
                    None => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: unknown_mix_session_error(&session_id),
                            }),
                        );
                    }
                };
                let witness_bytes = match hex::decode(witness_hex.trim()) {
                    Ok(b) => b,
                    Err(e) => {
                        // Re-stash: caller can retry with corrected hex.
                        state
                            .wraith_mixes
                            .write()
                            .await
                            .insert(session_id.clone(), stored);
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("witness_hex not valid hex: {e}"),
                            }),
                        );
                    }
                };
                let witness: bitcoin::Witness =
                    match bitcoin::consensus::encode::deserialize(&witness_bytes) {
                        Ok(w) => w,
                        Err(e) => {
                            state
                                .wraith_mixes
                                .write()
                                .await
                                .insert(session_id.clone(), stored);
                            return Envelope::new(
                                id,
                                Response::Error(ErrorResponse {
                                    message: format!("witness consensus decode: {e}"),
                                }),
                            );
                        }
                    };
                match stored
                    .client
                    .submit_witness(&stored.inspected, witness)
                    .await
                {
                    Ok(outcome) => Response::WraithMixCompleted(WraithMixCompletedResponse {
                        session_id: outcome.session_id,
                        broadcast_txid: outcome.broadcast_txid.to_string(),
                        mixed_output_tx_index: outcome.mixed_output_tx_index as u32,
                    }),
                    Err(e) => Response::Error(ErrorResponse {
                        message: format!("wraith submit: {e}"),
                    }),
                }
            }
            Request::WraithCoordinatorDiscover {
                coordinator_url,
                coordinator_peers,
            } => {
                use wraith_wallet_core::wraith::WraithSessionClient;
                let client = WraithSessionClient::with_peers(
                    coordinator_url,
                    coordinator_peers,
                    state.network,
                );
                match client.discover().await {
                    Ok((answered_by, parsed)) => {
                        Response::WraithCoordinatorDiscover(WraithDiscoverResponse {
                            answered_by,
                            network: parsed.network,
                            pool_id: parsed.pool_id,
                            service_fee_bps: parsed.service_fee_bps,
                            fill_window_secs: parsed.fill_window_secs,
                            tiers: parsed
                                .tiers
                                .into_iter()
                                .map(|t| WraithDiscoverTier {
                                    id: t.id,
                                    denomination_sats: t.denomination_sats,
                                    min_participants: t.min_participants,
                                    max_participants: t.max_participants,
                                    service_fee_sats: t.service_fee_sats,
                                    mix_seat_price_sats: t.mix_seat_price_sats,
                                    jump_seat_price_sats: t.jump_seat_price_sats,
                                })
                                .collect(),
                        })
                    }
                    Err(e) => Response::Error(ErrorResponse {
                        message: format!("discover: {e}"),
                    }),
                }
            }
            Request::WraithResolveCoordinator { tier_id } => {
                // Fetch the node's election view THROUGH ghost-pay (wallet hard
                // rule: never the pool API directly), then resolve the seat that
                // owns this tier. Any failure → (None, None) so the caller falls
                // back to a manually-configured coordinator URL.
                let (endpoint, epoch) =
                    match wraith_wallet_core::chain::GhostPayClient::with_urls_and_proxy(
                        state.ghost_pay_urls().await,
                        None,
                    ) {
                        Ok(client) => match client.coordinator_election().await {
                            Ok(election) => {
                                // Pin the beacon to the chain if this wallet has
                                // its own node. Verifying the draw against the
                                // beacon published beside it only proves internal
                                // consistency; the block hash is a fact the
                                // operator does not get to state (#697).
                                if !beacon_pinned_to_chain(state, &election) {
                                    tracing::warn!(
                                        "resolve coordinator: published beacon does not match \
                                         the anchor block; refusing the election"
                                    );
                                    (None, election.get("epoch").and_then(|e| e.as_u64()))
                                } else {
                                    crate::coordinator_resolve::resolve_from_election(
                                        &election, &tier_id,
                                    )
                                }
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, "resolve coordinator: election fetch failed");
                                (None, None)
                            }
                        },
                        Err(e) => {
                            tracing::debug!(error = %e, "resolve coordinator: ghost-pay client build failed");
                            (None, None)
                        }
                    };
                Response::WraithCoordinatorResolved { endpoint, epoch }
            }
            Request::WraithMixOneShot {
                coordinator_url,
                socks5_proxy,
                coordinator_peers,
                tier_id,
                ghost_id,
                utxo_txid,
                utxo_vout,
                utxo_value_sats,
                utxo_scriptpubkey_hex,
                mix_output_address,
                bip86_index,
                bip86_scan_max,
                min_entities,
            } => {
                use wraith_wallet_core::wraith::{
                    MixRequest, ParticipantUtxo, WraithClientError, WraithSessionClient,
                };
                use wraith_wallet_core::wraith_signer::{
                    sign_taproot_key_path, sign_taproot_key_path_at_index, DEFAULT_SCAN_INDEX_MAX,
                };
                let client_result = match socks5_proxy.as_deref() {
                    Some(proxy) => WraithSessionClient::with_outputs_proxy(
                        coordinator_url.clone(),
                        state.network,
                        proxy,
                    ),
                    None if coordinator_peers.is_empty() => Ok(WraithSessionClient::new(
                        coordinator_url.clone(),
                        state.network,
                    )),
                    None => Ok(WraithSessionClient::with_peers(
                        coordinator_url.clone(),
                        coordinator_peers.clone(),
                        state.network,
                    )),
                };
                let client = match client_result {
                    Ok(c) => c,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("wraith client: {e}"),
                            }),
                        );
                    }
                };
                // Same reason: `req` takes the scriptPubKey, and the
                // ownership proof needs it to find the key that owns it.
                let utxo_scriptpubkey_hex_for_proof = utxo_scriptpubkey_hex.clone();
                let network_for_proof = state.network;
                let scan_max_for_proof = bip86_scan_max.unwrap_or(DEFAULT_SCAN_INDEX_MAX);
                let req = MixRequest {
                    tier_id,
                    ghost_id,
                    utxo: ParticipantUtxo {
                        txid: utxo_txid,
                        vout: utxo_vout,
                        value_sats: utxo_value_sats,
                        scriptpubkey_hex: utxo_scriptpubkey_hex,
                    },
                    mix_output_address,
                    min_entities: min_entities
                        .unwrap_or(wraith_wallet_core::wraith::DEFAULT_MIN_ENTITIES),
                };
                // Prove control of the input UTXO. The coordinator checks
                // this against the scriptPubKey the chain reports for the
                // outpoint, so it must come from the key that really owns
                // the coin (#699). Async because the keystore sits behind
                // the wallet lock.
                let proof_spk = utxo_scriptpubkey_hex_for_proof.clone();
                let prove_ownership = |challenge: &str| {
                    let challenge = challenge.to_string();
                    let spk = proof_spk.clone();
                    async move {
                        with_active_wallet(state, move |_, ks| {
                            wraith_wallet_core::wraith_signer::prove_ownership(
                                ks,
                                network_for_proof,
                                &spk,
                                &challenge,
                                scan_max_for_proof,
                            )
                            .map_err(|e| e.to_string())
                        })
                        .await
                        .map_err(WraithClientError::OwnershipProof)
                    }
                };
                let prepared = match client.prepare_mix(req, prove_ownership).await {
                    Ok(p) => p,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("wraith prepare: {e}"),
                            }),
                        );
                    }
                };

                // Inspect BEFORE signing. This path is the one-shot mix, and it
                // previously went from `/round-tx` straight to the keystore —
                // no check that the wallet's own input and output were in the
                // round, no anonymity floor, and no commitment of the coin.
                let mut ledger = match signing_ledger_for(state) {
                    Ok(l) => l,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("signing ledger unavailable: {e}"),
                            }),
                        );
                    }
                };
                let inspected = match prepared.inspect(&mut ledger) {
                    Ok(i) => i,
                    Err(e) => {
                        let resp = match refusal_response(
                            prepared.session_id.clone(),
                            min_entities
                                .unwrap_or(wraith_wallet_core::wraith::DEFAULT_MIN_ENTITIES),
                            &e,
                        ) {
                            Some(r) => Response::WraithMixRefused(r),
                            None => Response::Error(ErrorResponse {
                                message: format!("refused the round: {e}"),
                            }),
                        };
                        return Envelope::new(id, resp);
                    }
                };

                // Sign with the active wallet's keystore. `with_active_wallet`
                // is async and re-locks the keystore RwLock on each call;
                // we hold the lock just for the (sync) sighash + Schnorr step.
                let network = state.network;
                let scan_max = bip86_scan_max.unwrap_or(DEFAULT_SCAN_INDEX_MAX);
                let prepared_for_sign = prepared.clone();
                let witness_result = with_active_wallet(state, move |_, ks| {
                    let res = match bip86_index {
                        Some(idx) => sign_taproot_key_path_at_index(
                            ks,
                            network,
                            &prepared_for_sign.unsigned_tx,
                            prepared_for_sign.input_index,
                            &prepared_for_sign.prevouts,
                            idx,
                        ),
                        None => sign_taproot_key_path(
                            ks,
                            network,
                            &prepared_for_sign.unsigned_tx,
                            prepared_for_sign.input_index,
                            &prepared_for_sign.prevouts,
                            scan_max,
                        ),
                    };
                    res.map_err(|e| format!("wraith sign: {e}"))
                })
                .await;
                let witness = match witness_result {
                    Ok(w) => w,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }));
                    }
                };
                match client.submit_witness(&inspected, witness).await {
                    Ok(outcome) => Response::WraithMixCompleted(WraithMixCompletedResponse {
                        session_id: outcome.session_id,
                        broadcast_txid: outcome.broadcast_txid.to_string(),
                        mixed_output_tx_index: outcome.mixed_output_tx_index as u32,
                    }),
                    Err(e) => Response::Error(ErrorResponse {
                        message: format!("wraith submit: {e}"),
                    }),
                }
            }
            Request::PsbtInspect { psbt } => {
                use wraith_wallet_core::psbt as psbt_mod;
                match psbt_mod::decode_psbt(&psbt) {
                    Err(e) => Response::Error(ErrorResponse {
                        message: format!("psbt decode: {e}"),
                    }),
                    Ok((parsed, _encoding)) => {
                        let inspect = psbt_mod::inspect(&parsed);
                        let network = state.network;
                        // Resolve the active wallet (if any) to
                        // answer the per-input "is this signable
                        // by me?" question. Inspector still works
                        // without an active wallet — those flags
                        // just come back false.
                        let active = state.active.read().await.clone();
                        let scan_max = psbt_mod::DEFAULT_SCAN_INDEX_MAX;
                        let (input_signable, output_owned) = if let Some(name) = active {
                            let wallets = state.wallets.read().await;
                            if let Some(ks) = wallets.get(&name) {
                                let inputs_flags: Vec<bool> = inspect
                                    .inputs
                                    .iter()
                                    .map(|iv| match &iv.script_pubkey {
                                        Some(spk) if spk.is_p2tr() => {
                                            psbt_mod::find_bip86_index_for_script(
                                                ks, network, spk, scan_max,
                                            )
                                            .unwrap_or(None)
                                            .is_some()
                                        }
                                        _ => false,
                                    })
                                    .collect();
                                let outputs_flags: Vec<bool> = inspect
                                    .outputs
                                    .iter()
                                    .map(|ov| {
                                        if !ov.script_pubkey.is_p2tr() {
                                            return false;
                                        }
                                        psbt_mod::find_bip86_index_for_script(
                                            ks,
                                            network,
                                            &ov.script_pubkey,
                                            scan_max,
                                        )
                                        .unwrap_or(None)
                                        .is_some()
                                    })
                                    .collect();
                                (inputs_flags, outputs_flags)
                            } else {
                                (
                                    vec![false; inspect.inputs.len()],
                                    vec![false; inspect.outputs.len()],
                                )
                            }
                        } else {
                            (
                                vec![false; inspect.inputs.len()],
                                vec![false; inspect.outputs.len()],
                            )
                        };

                        let inputs: Vec<PsbtInputSummary> = inspect
                            .inputs
                            .iter()
                            .enumerate()
                            .map(|(i, iv)| PsbtInputSummary {
                                previous_txid: iv.previous_txid.to_string(),
                                previous_vout: iv.previous_vout,
                                value_sats: iv.value_sats,
                                script_pubkey_hex: iv
                                    .script_pubkey
                                    .as_ref()
                                    .map(|s| hex::encode(s.as_bytes())),
                                address: iv
                                    .script_pubkey
                                    .as_ref()
                                    .and_then(|s| psbt_mod::script_to_address(s, network)),
                                is_finalized: iv.is_finalized,
                                partial_signatures: iv.partial_signatures,
                                is_signable_by_active_wallet: input_signable[i] && !iv.is_finalized,
                            })
                            .collect();
                        let outputs: Vec<PsbtOutputSummary> = inspect
                            .outputs
                            .iter()
                            .enumerate()
                            .map(|(i, ov)| PsbtOutputSummary {
                                value_sats: ov.value_sats,
                                script_pubkey_hex: hex::encode(ov.script_pubkey.as_bytes()),
                                address: psbt_mod::script_to_address(&ov.script_pubkey, network),
                                is_owned_by_active_wallet: output_owned[i],
                            })
                            .collect();

                        let total_in_sats: Option<u64> =
                            if inputs.iter().all(|i| i.value_sats.is_some()) {
                                Some(inputs.iter().map(|i| i.value_sats.unwrap_or(0)).sum())
                            } else {
                                None
                            };
                        let total_out_sats: u64 = outputs.iter().map(|o| o.value_sats).sum();
                        let fee_sats = total_in_sats.and_then(|t| t.checked_sub(total_out_sats));
                        let is_complete = psbt_mod::is_complete(&parsed);
                        let has_signable_inputs =
                            inputs.iter().any(|i| i.is_signable_by_active_wallet);

                        let network_label = match state.network {
                            bitcoin::Network::Bitcoin => "mainnet",
                            bitcoin::Network::Signet => "signet",
                            bitcoin::Network::Testnet => "testnet",
                            bitcoin::Network::Regtest => "regtest",
                            _ => "unknown",
                        };

                        Response::PsbtInspected(PsbtInspectResponse {
                            network: network_label.to_string(),
                            unsigned_tx_hex: bitcoin::consensus::encode::serialize_hex(
                                &parsed.unsigned_tx,
                            ),
                            txid: inspect.txid.to_string(),
                            inputs,
                            outputs,
                            total_in_sats,
                            total_out_sats,
                            fee_sats,
                            is_complete,
                            has_signable_inputs,
                        })
                    }
                }
            }
            Request::PsbtCreate {
                recipient_address,
                amount_sats,
                fee_rate_sats_per_vb,
                change_index,
                bip86_scan_max,
                selected_outpoints,
            } => match psbt_create_handler(
                state,
                &recipient_address,
                amount_sats,
                fee_rate_sats_per_vb,
                change_index,
                bip86_scan_max,
                &selected_outpoints,
            )
            .await
            {
                Ok(r) => Response::PsbtCreated(r),
                Err(e) => Response::Error(ErrorResponse { message: e }),
            },
            Request::WraithPrepareCoin {
                tier_id,
                coordinator_url,
                coordinator_peers,
                receive_index,
                fee_rate_sats_per_vb,
                bip86_scan_max,
            } => match wraith_prepare_coin_handler(
                state,
                &tier_id,
                coordinator_url,
                coordinator_peers,
                receive_index,
                fee_rate_sats_per_vb,
                bip86_scan_max,
            )
            .await
            {
                Ok(r) => Response::WraithCoinPrepared(r),
                Err(e) => Response::Error(ErrorResponse { message: e }),
            },
            Request::PsbtBroadcast { psbt_or_tx_hex } => {
                match psbt_broadcast_handler(state, &psbt_or_tx_hex).await {
                    Ok(txid) => Response::PsbtBroadcast(PsbtBroadcastResponse { txid }),
                    Err(e) => Response::Error(ErrorResponse { message: e }),
                }
            }
            Request::PsbtBumpFee {
                psbt,
                new_fee_rate_sats_per_vb,
                bip86_scan_max,
            } => {
                match psbt_bump_fee_handler(state, &psbt, new_fee_rate_sats_per_vb, bip86_scan_max)
                    .await
                {
                    Ok(r) => Response::PsbtBumped(r),
                    Err(e) => Response::Error(ErrorResponse { message: e }),
                }
            }
            Request::PsbtSign {
                psbt,
                bip86_scan_max,
            } => {
                use wraith_wallet_core::psbt as psbt_mod;
                let scan_max = bip86_scan_max.unwrap_or(psbt_mod::DEFAULT_SCAN_INDEX_MAX);
                match psbt_mod::decode_psbt(&psbt) {
                    Err(e) => Response::Error(ErrorResponse {
                        message: format!("psbt decode: {e}"),
                    }),
                    Ok((mut parsed, encoding)) => {
                        let network = state.network;
                        let result = with_active_wallet(state, move |_, ks| {
                            psbt_mod::sign_owned_inputs(&mut parsed, ks, network, scan_max)
                                .map(|signed| (signed, parsed))
                                .map_err(|e| format!("psbt sign: {e}"))
                        })
                        .await;
                        match result {
                            Err(e) => Response::Error(ErrorResponse { message: e }),
                            Ok((signed, signed_psbt)) => {
                                let input_count = signed_psbt.unsigned_tx.input.len() as u32;
                                let is_complete = psbt_mod::is_complete(&signed_psbt);
                                let encoded = psbt_mod::encode_psbt(&signed_psbt, encoding);
                                Response::PsbtSigned(PsbtSignResponse {
                                    psbt: encoded,
                                    signed_inputs: signed,
                                    input_count,
                                    is_complete,
                                })
                            }
                        }
                    }
                }
            }
        };

        Envelope::new(id, response)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn fixture_meta(wallet: &str, lock_id: &str) -> PreparedLockMeta {
            PreparedLockMeta {
                wallet_name: wallet.into(),
                recovery_index: 7,
                lock_pubkey_hex: "02".to_string() + &"00".repeat(32),
                recovery_pubkey_hex: "03".to_string() + &"11".repeat(32),
                recovery_blocks: 1008,
                creation_height: 800_000,
                funding_address: format!("tb1q{lock_id}"),
                capacity_sats: 100_000,
                funding_txid: Some("aa".repeat(32)),
            }
        }

        #[test]
        fn round_trip_locks_to_disk_preserves_every_field() {
            let dir = tempfile::tempdir().unwrap();
            let mut map = HashMap::new();
            let meta = fixture_meta("alice", "lock-A");
            map.insert("lock-A".to_string(), meta.clone());
            super::save_locks_for_wallet(dir.path(), "alice", &map).unwrap();

            let restored = super::load_locks_for_wallet(dir.path(), "alice");
            assert_eq!(restored.len(), 1);
            let r = restored.get("lock-A").unwrap();
            assert_eq!(r.wallet_name, meta.wallet_name);
            assert_eq!(r.recovery_index, meta.recovery_index);
            assert_eq!(r.lock_pubkey_hex, meta.lock_pubkey_hex);
            assert_eq!(r.recovery_pubkey_hex, meta.recovery_pubkey_hex);
            assert_eq!(r.recovery_blocks, meta.recovery_blocks);
            assert_eq!(r.creation_height, meta.creation_height);
            assert_eq!(r.funding_address, meta.funding_address);
            assert_eq!(r.capacity_sats, meta.capacity_sats);
            assert_eq!(r.funding_txid, meta.funding_txid);
        }

        #[test]
        fn load_returns_empty_when_file_missing() {
            let dir = tempfile::tempdir().unwrap();
            let restored = super::load_locks_for_wallet(dir.path(), "missing");
            assert!(restored.is_empty());
        }

        #[test]
        fn recovery_index_advances_past_persisted_locks() {
            use std::sync::atomic::Ordering::SeqCst;

            // Regression: the counter reset to 0 each boot, so after a restart a
            // freshly-prepared lock re-issued an index an existing lock already
            // used — re-deriving the same recovery key.
            let counter = AtomicU32::new(0);
            let mut map = HashMap::new();
            let mut a = fixture_meta("alice", "lock-A");
            a.recovery_index = 4;
            let mut b = fixture_meta("alice", "lock-B");
            b.recovery_index = 9; // highest
            let mut c = fixture_meta("alice", "lock-C");
            c.recovery_index = 2;
            map.insert("lock-A".to_string(), a);
            map.insert("lock-B".to_string(), b);
            map.insert("lock-C".to_string(), c);

            super::advance_recovery_index_past_locks(&counter, &map);
            assert_eq!(
                counter.load(SeqCst),
                10,
                "counter must sit one past the highest persisted recovery_index"
            );

            // Monotonic: a second wallet with lower indices must not lower it.
            let mut map2 = HashMap::new();
            let mut d = fixture_meta("bob", "lock-D");
            d.recovery_index = 3;
            map2.insert("lock-D".to_string(), d);
            super::advance_recovery_index_past_locks(&counter, &map2);
            assert_eq!(
                counter.load(SeqCst),
                10,
                "fetch_max must never lower the counter"
            );

            // Empty set is a no-op.
            super::advance_recovery_index_past_locks(&counter, &HashMap::new());
            assert_eq!(counter.load(SeqCst), 10);
        }

        #[test]
        fn load_returns_empty_when_file_corrupt() {
            let dir = tempfile::tempdir().unwrap();
            let path = super::locks_path(dir.path(), "borked");
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"this is not json").unwrap();
            let restored = super::load_locks_for_wallet(dir.path(), "borked");
            assert!(
                restored.is_empty(),
                "corrupt file is logged + ignored, never bubbles"
            );
        }

        #[cfg(unix)]
        #[test]
        fn save_writes_with_mode_0600() {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let mut map = HashMap::new();
            map.insert("k".to_string(), fixture_meta("w", "k"));
            super::save_locks_for_wallet(dir.path(), "w", &map).unwrap();
            let path = super::locks_path(dir.path(), "w");
            let perm = std::fs::metadata(&path).unwrap().permissions();
            assert_eq!(
                perm.mode() & 0o777,
                0o600,
                "locks file must be wallet-owner-only readable",
            );
        }

        #[test]
        fn missing_lock_metadata_error_is_accurate() {
            let msg = super::missing_lock_metadata_error("lock-XYZ");
            // Names the offending lock so the operator can act on it.
            assert!(msg.contains("lock-XYZ"), "must name the lock: {msg}");
            // Points at the real recovery path now that locks persist to
            // locks.json and reload on WalletUnlock.
            assert!(msg.contains("locks.json"), "must mention locks.json: {msg}");
            assert!(
                msg.contains("different wallet/daemon"),
                "must explain the cross-wallet/daemon case: {msg}"
            );
            // Regression guard: the old message falsely claimed the index was
            // in-memory only and lost on restart. That is no longer true.
            assert!(
                !msg.contains("restarts lose the index"),
                "stale, now-false claim must be gone: {msg}"
            );
            assert!(
                !msg.contains("in-memory"),
                "stale in-memory claim must be gone: {msg}"
            );
        }

        #[test]
        fn unknown_mix_session_error_is_clear() {
            let msg = super::unknown_mix_session_error("sess-123");
            assert!(msg.contains("sess-123"), "must name the session: {msg}");
            assert!(msg.contains("not found"), "must say not found: {msg}");
            // Honest about why it's gone: expired or daemon restart mid-round.
            assert!(
                msg.contains("expired") && msg.contains("restarted"),
                "must explain expiry/restart cause: {msg}"
            );
            assert!(
                msg.contains("start the mix again"),
                "must tell the user how to recover: {msg}"
            );
        }

        use super::shroud_pick_delay;

        #[test]
        fn shroud_disabled_when_max_is_zero() {
            for _ in 0..100 {
                assert_eq!(shroud_pick_delay(0), None);
            }
        }

        #[test]
        fn shroud_delay_is_within_bounds() {
            // Sample across a few distributions to make sure the gen_range
            // semantics are inclusive on both ends and never overshoot.
            for max in [1u64, 10, 100, 5000, 60_000] {
                for _ in 0..256 {
                    let d = shroud_pick_delay(max).expect("non-zero max yields Some");
                    assert!(d <= max, "delay {d} must not exceed max {max}");
                }
            }
        }

        #[test]
        fn shroud_max_one_emits_both_zero_and_one() {
            // With max_ms=1 we sample {0, 1}; over 1000 picks both should
            // appear. Probability of all-zeros or all-ones is 2 * 2^-1000.
            let mut saw_zero = false;
            let mut saw_one = false;
            for _ in 0..1000 {
                match shroud_pick_delay(1) {
                    Some(0) => saw_zero = true,
                    Some(1) => saw_one = true,
                    other => panic!("unexpected delay: {other:?}"),
                }
                if saw_zero && saw_one {
                    return;
                }
            }
            panic!("did not see both 0 and 1 across 1000 samples");
        }

        // ---- payment-mode gating -------------------------------------
        //
        // Send exposes exactly one real mode (`ghostpay`). The former
        // `wraith`/`confidential` modes were cosmetic — they parsed into
        // a label but took the same plaintext L2 ledger path — so they
        // are now refused. These tests lock that in: a retired mode must
        // never resolve into an accepted send.

        #[test]
        fn parse_payment_mode_accepts_ghostpay_aliases_and_default() {
            for s in [
                "",
                "ghostpay",
                "GhostPay",
                "ghost-pay",
                "ghost_pay",
                "  ghostpay  ",
            ] {
                assert!(
                    matches!(super::parse_payment_mode(s), Ok(PaymentMode::GhostPay)),
                    "{s:?} should resolve to GhostPay"
                );
            }
        }

        #[test]
        fn parse_payment_mode_rejects_retired_modes() {
            for s in ["wraith", "Wraith", "confidential", "CONFIDENTIAL"] {
                let err = super::parse_payment_mode(s)
                    .expect_err(&format!("retired mode {s:?} must be rejected"));
                assert!(
                    err.contains("not available"),
                    "{s:?} rejection should explain it is unavailable; got: {err}"
                );
            }
        }

        #[test]
        fn parse_payment_mode_rejects_unknown() {
            let err =
                super::parse_payment_mode("banana").expect_err("an unknown mode must be rejected");
            assert!(
                err.contains("unknown payment mode"),
                "unexpected error text: {err}"
            );
        }

        /// Minimal `ChainClient` stub — `light_send` never touches the
        /// chain (its gating happens before any I/O), so a status-only
        /// error stub is all we need to satisfy the `DaemonState` field.
        struct RejectChain;

        #[async_trait::async_trait]
        impl ChainClient for RejectChain {
            async fn status(
                &self,
            ) -> Result<wraith_wallet_core::chain::ChainStatus, wraith_wallet_core::chain::ChainError>
            {
                Err(wraith_wallet_core::chain::ChainError::Backend(
                    "test stub".into(),
                ))
            }
        }

        /// A session-less `DaemonState` sufficient to exercise
        /// `light_send`'s mode gate. Everything past the gate needs a
        /// live GSP session, which the IPC integration tests cover; here
        /// we only care that the gate accepts/rejects the right modes.
        fn test_state() -> Arc<DaemonState> {
            test_state_in(std::env::temp_dir())
        }

        fn test_state_in(wallets_dir: std::path::PathBuf) -> Arc<DaemonState> {
            let node_config_path = wallets_dir.join("node.json");
            Arc::new(DaemonState {
                started: Instant::now(),
                clients: RwLock::new(NodeClients {
                    chain: Arc::new(RejectChain),
                    gsp: Arc::new(GspClient::new("ws://127.0.0.1:0")),
                    ghost_pay_urls: vec!["http://127.0.0.1:0".to_string()],
                    gsp_urls: vec!["ws://127.0.0.1:0".to_string()],
                    preset: PRESET_CUSTOM.to_string(),
                }),
                ghost_pay_env_override: false,
                gsp_env_override: false,
                node_config_path,
                ghost_pay_internal_auth: None,
                tor_proxy: None,
                wraith_coordinator_url: None,
                kiosk_mode: false,
                wallets_dir,
                wallets: RwLock::new(HashMap::new()),
                active: RwLock::new(None),
                session: RwLock::new(None),
                network: bitcoin::Network::Regtest,
                endpoint_display: std::env::temp_dir()
                    .join("wraithd-modegate-test.sock")
                    .display()
                    .to_string(),
                last_activity: std::sync::atomic::AtomicU64::new(0),
                idle_lock_secs: 0,
                shroud_max_ms: 0,
                update_manifest_url: None,
                http: reqwest::Client::new(),
                wraith_mixes: RwLock::new(HashMap::new()),
                prepared_locks: RwLock::new(HashMap::new()),
                next_recovery_index: AtomicU32::new(0),
                ghostd_url: None,
                ghostd_cookie_path: None,
                ghostd_user: None,
                ghostd_pass: None,
            })
        }

        #[tokio::test]
        async fn light_send_refuses_retired_modes_before_any_send() {
            let state = test_state();
            for mode in ["wraith", "confidential"] {
                let err = super::light_send(
                    &state,
                    "tghost1qexample".into(),
                    1000,
                    mode.into(),
                    None,
                    Some(0),
                )
                .await
                .expect_err("a retired mode must be refused, never silently sent");
                // Must fail at the mode gate — NOT by reaching the session
                // step. If it reached the session it would return the
                // "no GSP session" error, which would mean the mode was
                // (wrongly) accepted as sendable.
                assert!(
                    !err.contains("no GSP session"),
                    "mode `{mode}` must be rejected at the gate before the send path; got: {err}"
                );
                assert!(
                    err.contains("not available"),
                    "mode `{mode}` rejection should explain it is unavailable; got: {err}"
                );
            }
        }

        #[tokio::test]
        async fn light_send_accepts_ghostpay_past_the_mode_gate() {
            // ghostpay (and the empty default) must pass the mode gate.
            // With no session configured the send can't complete, but it
            // must advance to the session step — proven by the
            // "no GSP session" error rather than a mode-rejection error.
            let state = test_state();
            for mode in ["ghostpay", ""] {
                let err = super::light_send(
                    &state,
                    "tghost1qexample".into(),
                    1000,
                    mode.into(),
                    None,
                    Some(0),
                )
                .await
                .expect_err("no session is configured in this unit test");
                assert!(
                    err.contains("no GSP session"),
                    "ghostpay must clear the mode gate and reach the session step; got: {err}"
                );
            }
        }

        #[tokio::test]
        async fn wallet_delete_removes_keystore_and_forgets_active() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_in(dir.path().to_path_buf());

            // Create a wallet through the real dispatch path so the test
            // exercises the same code the GUI drives.
            let create = serde_json::to_string(&Envelope::new(
                1,
                Request::WalletCreate {
                    name: "doomed".into(),
                    passphrase: "hunter2hunter2".into(),
                    user_entropy_digest: None,
                },
            ))
            .unwrap();
            let resp = super::dispatch(&create, &state).await;
            assert!(
                matches!(resp.payload, Response::WalletCreate(_)),
                "create should succeed; got {:?}",
                resp.payload
            );
            let wallet_dir = dir.path().join("doomed");
            let keystore = wallet_dir.join("keystore.bin");
            assert!(keystore.is_file(), "keystore should exist after create");
            assert_eq!(state.active.read().await.as_deref(), Some("doomed"));

            // Delete it.
            let del = serde_json::to_string(&Envelope::new(
                2,
                Request::WalletDelete {
                    name: "doomed".into(),
                },
            ))
            .unwrap();
            let resp = super::dispatch(&del, &state).await;
            match resp.payload {
                Response::WalletDeleted { name } => assert_eq!(name, "doomed"),
                other => panic!("expected WalletDeleted, got {other:?}"),
            }

            // On-disk directory gone, in-memory state cleared.
            assert!(!keystore.exists(), "keystore file must be removed");
            assert!(!wallet_dir.exists(), "wallet dir must be removed");
            assert!(state.wallets.read().await.get("doomed").is_none());
            assert!(state.active.read().await.is_none());

            // No longer surfaced by WalletList.
            let list = serde_json::to_string(&Envelope::new(3, Request::WalletList)).unwrap();
            let resp = super::dispatch(&list, &state).await;
            match resp.payload {
                Response::WalletList(l) => assert!(
                    l.wallets.iter().all(|w| w.name != "doomed"),
                    "deleted wallet must not appear in the list"
                ),
                other => panic!("expected WalletList, got {other:?}"),
            }

            // Deleting a wallet that no longer exists is a clean error,
            // never a panic.
            let resp = super::dispatch(&del, &state).await;
            assert!(
                matches!(resp.payload, Response::Error(_)),
                "second delete should error; got {:?}",
                resp.payload
            );
        }

        #[tokio::test]
        async fn connection_status_reports_unreachable_without_erroring() {
            // With the RejectChain stub (ghost-pay unreachable) and no GSP
            // session, ConnectionStatus must still return a structured
            // snapshot — NOT a Response::Error. This is what lets the header
            // render a clear "unreachable" state instead of a perpetual
            // "connecting…" spinner on a laptop with no local endpoints.
            let state = test_state();
            let req = serde_json::to_string(&Envelope::new(1, Request::ConnectionStatus)).unwrap();
            let resp = super::dispatch(&req, &state).await;
            match resp.payload {
                Response::ConnectionStatus(s) => {
                    assert_eq!(
                        s.network, "regtest",
                        "network is read from config, not the backend"
                    );
                    assert!(
                        !s.ghost_pay_reachable,
                        "RejectChain stub must read as unreachable"
                    );
                    assert!(
                        s.ghost_pay_error.is_some(),
                        "an unreachable backend should carry an error hint"
                    );
                    assert!(s.ghost_pay_version.is_none());
                    assert!(!s.gsp_have_token, "no session configured in this test");
                    assert!(!s.gsp_connected);
                    assert!(s.gsp_phase.is_none());
                    assert!(
                        !s.chain_synced,
                        "cannot be synced while ghost-pay is unreachable"
                    );
                    assert!(s.chain_height.is_none());
                }
                other => panic!("expected ConnectionStatus, got {other:?}"),
            }
        }

        /// SetNodeEndpoints must: apply the new URLs at runtime, persist them to
        /// node.json, and have DaemonEnv reflect the change — all without a
        /// restart.
        #[tokio::test]
        async fn set_node_endpoints_applies_persists_and_surfaces() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_in(dir.path().to_path_buf());

            // Switch to a custom node.
            let req = serde_json::to_string(&Envelope::new(
                1,
                Request::SetNodeEndpoints {
                    preset: "custom".into(),
                    ghost_pay_url: Some("https://pay.example.com:8800".into()),
                    gsp_url: Some("wss://gsp.example.com:8900/ws/v1".into()),
                },
            ))
            .unwrap();
            match super::dispatch(&req, &state).await.payload {
                Response::NodeEndpointsSet(r) => {
                    assert_eq!(r.preset, "custom");
                    assert_eq!(r.ghost_pay_urls, vec!["https://pay.example.com:8800"]);
                    assert_eq!(r.gsp_urls, vec!["wss://gsp.example.com:8900/ws/v1"]);
                }
                other => panic!("expected NodeEndpointsSet, got {other:?}"),
            }

            // Persisted to node.json, and reloadable.
            let persisted =
                super::load_node_config(&state.node_config_path).expect("node.json written");
            assert_eq!(persisted.preset, "custom");
            assert_eq!(
                persisted.ghost_pay_urls,
                vec!["https://pay.example.com:8800"]
            );

            // Live state reflects it via the accessors + DaemonEnv.
            assert_eq!(
                state.ghost_pay_urls().await,
                vec!["https://pay.example.com:8800".to_string()]
            );
            let env = serde_json::to_string(&Envelope::new(2, Request::DaemonEnv)).unwrap();
            match super::dispatch(&env, &state).await.payload {
                Response::DaemonEnv(e) => {
                    assert_eq!(e.node_preset, "custom");
                    assert_eq!(e.gsp_urls, vec!["wss://gsp.example.com:8900/ws/v1"]);
                    assert!(!e.ghost_pay_env_override);
                }
                other => panic!("expected DaemonEnv, got {other:?}"),
            }

            // Switching to the public preset ignores the URL fields and applies
            // the bundled fleet endpoints.
            let pub_req = serde_json::to_string(&Envelope::new(
                3,
                Request::SetNodeEndpoints {
                    preset: "public".into(),
                    ghost_pay_url: None,
                    gsp_url: None,
                },
            ))
            .unwrap();
            match super::dispatch(&pub_req, &state).await.payload {
                Response::NodeEndpointsSet(r) => {
                    assert_eq!(r.preset, "public");
                    assert_eq!(r.ghost_pay_urls, vec![super::PUBLIC_GHOST_PAY.to_string()]);
                    assert_eq!(r.gsp_urls, vec![super::PUBLIC_GSP.to_string()]);
                }
                other => panic!("expected NodeEndpointsSet, got {other:?}"),
            }
        }

        /// A custom node with a wrong-scheme URL is rejected, and nothing is
        /// persisted — a typo must never silently point the wallet at nothing.
        #[tokio::test]
        async fn set_node_endpoints_rejects_bad_scheme() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_in(dir.path().to_path_buf());
            let req = serde_json::to_string(&Envelope::new(
                1,
                Request::SetNodeEndpoints {
                    preset: "custom".into(),
                    // ws:// where http(s):// is required for ghost-pay.
                    ghost_pay_url: Some("ws://pay.example.com:8800".into()),
                    gsp_url: Some("wss://gsp.example.com:8900/ws/v1".into()),
                },
            ))
            .unwrap();
            match super::dispatch(&req, &state).await.payload {
                Response::Error(e) => assert!(
                    e.message.contains("http"),
                    "error should explain the scheme requirement; got: {}",
                    e.message
                ),
                other => panic!("expected Error, got {other:?}"),
            }
            assert!(
                !state.node_config_path.exists(),
                "a rejected change must not write node.json"
            );
        }

        /// While an env-var override pins the endpoints, SetNodeEndpoints is
        /// refused — env vars keep power-user precedence.
        #[tokio::test]
        async fn set_node_endpoints_refused_under_env_override() {
            let dir = tempfile::tempdir().unwrap();
            let mut state = test_state_in(dir.path().to_path_buf());
            // Simulate a boot with WRAITHD_GHOST_PAY set.
            Arc::get_mut(&mut state).unwrap().ghost_pay_env_override = true;
            let err = state
                .set_node_endpoints("public", None, None)
                .await
                .expect_err("must refuse while env override is active");
            assert!(
                err.contains("environment"),
                "error should point at the env-var override; got: {err}"
            );
        }
    }
}
