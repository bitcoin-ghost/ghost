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
    use std::sync::Arc;
    use std::time::Instant;

    use interprocess::local_socket::traits::tokio::{Listener as _, Stream as _};
    use interprocess::local_socket::ListenerOptions;
    use secrecy::SecretString;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::sync::RwLock;

    /// Full-duplex IPC stream (splits into a read half and [`IpcSendHalf`]).
    type IpcStream = interprocess::local_socket::tokio::Stream;
    /// Write half of a connection — carries JSON responses / pushes.
    type IpcSendHalf = interprocess::local_socket::tokio::SendHalf;
    use wraith_wallet_core::auth;
    use wraith_wallet_core::chain::ChainClient;
    use wraith_wallet_core::keystore::{Keystore, KeystoreError};
    use wraith_wallet_core::light;
    use wraith_wallet_core::signer::{Signer, SoftwareSigner};
    use wraith_wallet_ipc::{
        AnonymitySetReport, ChainStatusResponse, CheckForUpdateResponse, ConnectionStatusResponse,
        DaemonEnvResponse, DetectedPaymentEntry, DoctorCheck, DoctorResponse, Envelope,
        ErrorResponse, EscapeCoin, GhostLockEscapePlanResponse, GhostLockEscapeSignedResponse,
        GhostLockForgottenResponse, GhostLockLane, GhostLockLanesResponse, GhostLockListResponse,
        GhostLockQuorumSignedResponse, GhostLockRecord, GhostLockRoundDestinationResponse,
        GhostLockSavedResponse, GhostLockSignBegunResponse, GhostLockSignNoncedResponse,
        GhostLockSignedResponse, HealthResponse, LightBalanceResponse, LightDetectedResponse,
        LightHistoryEntry, LightHistoryResponse, LightL1UtxoEntry, LightL1UtxosResponse,
        LightReceiveResponse, LightUtxoEntry, LightUtxosResponse, LockSpendOutput,
        LockSpendSummary, NodeResponse, PsbtBroadcastResponse, PsbtBumpFeeResponse,
        PsbtInputSummary, PsbtInspectResponse, PsbtOutputSummary, PsbtSignResponse,
        ReleaseManifest, Request, Response, SignerInfoIpc, WalletAuthInfoResponse,
        WalletCreateResponse, WalletDeriveResponse, WalletGhostIdResponse, WalletListEntry,
        WalletListResponse, WalletShowMnemonicResponse, WalletStatusResponse, WalletXpubResponse,
        WraithDiscoverResponse, WraithDiscoverTier, WraithMixCompletedResponse,
        WraithMixPreparedResponse, WraithMixRefusedResponse,
    };

    /// Optional override for the on-disk node config path. Defaults to
    /// `<wallets_dir>/../node.json` (i.e. `~/.wraith/node.json`).
    const NODE_CONFIG_ENV: &str = "WRAITHD_NODE_CONFIG";
    /// Optional pool node consulted for the coordinator election.
    const POOL_URL_ENV: &str = "WRAITHD_POOL_URL";
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

    /// Open the store of Ghost Lock definitions.
    ///
    /// Beside `node.json`, and beside the signing ledger — which is a different
    /// kind of file despite the neighbourhood. Losing *this* one costs
    /// convenience; the lanes rebuild from the same three keys and the keystore.
    /// Losing the ledger re-permits a double-sign.
    fn ghost_lock_store_for(
        state: &Arc<DaemonState>,
    ) -> std::io::Result<wraith_wallet_core::ghost_lock_store::GhostLockStore> {
        let path = state
            .node_config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("ghost-locks.json");
        wraith_wallet_core::ghost_lock_store::GhostLockStore::open(path)
    }

    /// Where one wallet's own records live: `<wallets_dir>/<name>/`.
    ///
    /// ⚠ Per wallet, not per daemon, and the distinction is load-bearing.
    /// These files answer "what happened to *this* wallet" — a history, a set
    /// of detected coins, a scan bookmark. Shared across wallets they are
    /// wrong in both directions at once: one wallet's payments appear in
    /// another's history, and the shared bookmark tells the scanner those
    /// blocks are already read, so a wallet switched to never gets a history
    /// at all. The keystore and its descriptors already live here, and
    /// `WalletDelete` removes the directory, so a deleted wallet takes its
    /// records with it.
    fn wallet_data_dir(state: &DaemonState, wallet: &str) -> PathBuf {
        state.wallets_dir.join(wallet)
    }

    /// The active wallet's name, or a message saying there isn't one.
    async fn active_wallet_name(state: &Arc<DaemonState>) -> Result<String, String> {
        state.active.read().await.clone().ok_or_else(|| {
            "no active wallet; run `wraith wallet unlock <name>` or \
             `wraith wallet select <name>` first"
                .to_string()
        })
    }

    /// Open the active wallet's record of what it has sent and received.
    ///
    /// This exists because transaction history used to come from the
    /// operator's GSP session: the wallet asked somebody else what it had
    /// done. With that gone, nothing remembers unless this does.
    async fn history_store_for(
        state: &Arc<DaemonState>,
    ) -> Result<wraith_wallet_core::history_store::HistoryStore, String> {
        let name = active_wallet_name(state).await?;
        wraith_wallet_core::history_store::HistoryStore::open(
            wallet_data_dir(state, &name).join("history.json"),
        )
        .map_err(|e| format!("history store: {e}"))
    }

    /// Open the active wallet's store of silent payments the scanner found.
    async fn detection_store_for(
        state: &Arc<DaemonState>,
    ) -> Result<wraith_wallet_core::detection_store::DetectionStore, String> {
        let name = active_wallet_name(state).await?;
        wraith_wallet_core::detection_store::DetectionStore::open(
            wallet_data_dir(state, &name).join("detections.json"),
        )
        .map_err(|e| format!("detections: {e}"))
    }

    /// Record the height a wallet came into being.
    ///
    /// Best-effort by design: a node that is unreachable at creation time must
    /// not stop a wallet being made. A missing birth height costs history
    /// depth on a later rescan, which is recoverable by setting one; refusing
    /// to create the wallet is not.
    async fn record_birth_height(state: &Arc<DaemonState>, wallet: &str, height: Option<u32>) {
        let path = wallet_data_dir(state, wallet).join("wallet-meta.json");
        let meta = wraith_wallet_core::wallet_meta::WalletMeta {
            birth_height: height,
        };
        if let Err(e) = wraith_wallet_core::wallet_meta::save(&path, &meta) {
            tracing::warn!(wallet, error = %e, "could not record the wallet's birth height");
        }
    }

    /// The current chain tip, if a node is reachable.
    async fn current_tip(state: &Arc<DaemonState>) -> Option<u32> {
        state
            .chain()
            .await
            .status()
            .await
            .ok()
            .and_then(|s| s.chain_height)
            .map(|h| h as u32)
    }

    /// Read the active wallet's metadata.
    async fn wallet_meta_for(
        state: &Arc<DaemonState>,
    ) -> Result<wraith_wallet_core::wallet_meta::WalletMeta, String> {
        let name = active_wallet_name(state).await?;
        Ok(wraith_wallet_core::wallet_meta::load(
            wallet_data_dir(state, &name).join("wallet-meta.json"),
        ))
    }

    /// Open the active wallet's block-scanner bookmark.
    async fn scan_state_for(
        state: &Arc<DaemonState>,
    ) -> Result<wraith_wallet_core::scan_state::ScanState, String> {
        let name = active_wallet_name(state).await?;
        wraith_wallet_core::scan_state::ScanState::open(
            wallet_data_dir(state, &name).join("scan-state.json"),
        )
        .map_err(|e| format!("scan state: {e}"))
    }

    fn lock_record(l: &wraith_wallet_core::ghost_lock_store::StoredLock) -> GhostLockRecord {
        GhostLockRecord {
            lock_id: l.lock_id.clone(),
            label: l.label.clone(),
            backup_pubkey: l.backup_pubkey.clone(),
            heir_pubkey: l.heir_pubkey.clone(),
            quorum_pubkey: l.quorum_pubkey.clone(),
            anchor_height: l.anchor_height,
            inherit_height: l.inherit_height,
            bip86_index: l.bip86_index,
        }
    }

    /// The wallet's own MuSig2 nonce ledger.
    ///
    /// Lives beside `node.json` in the wallet's data directory. Opened per
    /// operation rather than held: the file is small, the write is the
    /// expensive part either way, and a fresh read means a second process
    /// touching the same wallet cannot be missed.
    ///
    /// Separate file from the round signing ledger: they answer different
    /// questions (has this coin been signed for / has this nonce been used)
    /// and sharing a file would make one's corruption the other's outage.
    fn ghost_lock_nonce_ledger_for(
        state: &Arc<DaemonState>,
    ) -> std::io::Result<ghost_lock::nonce_ledger_file::FileNonceLedger> {
        let path = state
            .node_config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("ghost-lock-nonces.json");
        ghost_lock::nonce_ledger_file::FileNonceLedger::open(path)
    }

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

    /// One air-gapped Lock signing, between rounds.
    ///
    /// The `session` is `Some` only between round 1 and round 2. The owner's
    /// partial signature is produced as soon as both nonces are known, so no
    /// secret nonce is held while somebody carries the second payload to the
    /// device.
    struct PendingLockSign {
        keys: Vec<bitcoin::XOnlyPublicKey>,
        merkle_root: Option<bitcoin::TapNodeHash>,
        message: [u8; 32],
        psbt: String,
        input_index: u32,
        our_nonce: [u8; 66],
        /// Consumed at round 2.
        session: Option<ghost_lock::signing::SigningSession>,
        /// Set at round 2, with every party's nonce in the order they were
        /// aggregated.
        nonces: Vec<[u8; 66]>,
        our_partial: Option<[u8; 32]>,
    }

    /// In-flight Wraith Lite mix between `WraithMixPrepare` and
    /// `WraithMixSubmit`. Holds the prepared round + the client that produced
    /// it, so witness submission re-uses the same HTTP client and proxy config
    /// without rebuilding it. The caller is expected to submit promptly — the
    /// coordinator's no-sign deadline is ticking.
    struct StoredWraithMix {
        /// The **inspected** round. Not a `PreparedMix`: `submit_witness` will
        /// not accept anything else, so a round cannot reach the wire without
        /// having been checked and its coin committed.
        inspected: wraith_wallet_core::wraith::InspectedMix,
        client: Arc<wraith_wallet_core::wraith::WraithSessionClient>,
    }

    /// The live chain client, held behind a lock so a runtime endpoint change
    /// swaps it without a restart. Read paths clone the `Arc` out and release
    /// the lock immediately, so a slow node call never blocks a config change
    /// and vice-versa.
    struct NodeClients {
        chain: Arc<dyn ChainClient>,
    }

    struct DaemonState {
        started: Instant,
        /// The active node clients + endpoint config. Swapped wholesale by
        /// `SetNodeEndpoints` without a daemon restart.
        clients: RwLock<NodeClients>,
        /// Absolute path to the persisted node-selection config (`node.json`).
        node_config_path: PathBuf,
        /// Optional SOCKS5 proxy (e.g. socks5h://127.0.0.1:9050).
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
        /// Air-gapped Lock signings waiting on the backup device.
        ///
        /// In memory by design. A daemon restart loses the secret nonce, which
        /// is the safe direction: nothing can be reused, and the spend is
        /// retryable because the nonce ledger keys on the nonce rather than the
        /// message.
        lock_signings: RwLock<HashMap<String, PendingLockSign>>,
        /// Where the node is and how to reach it. Behind a lock so the
        /// settings screen can change it without a restart. Also pins the
        /// election beacon to the chain; with no node that check is skipped.
        ghostd: RwLock<GhostdSettings>,
        /// A Ghost pool node, consulted only for the coordinator election.
        pool_url: RwLock<Option<String>>,
        /// The last verified election, with the epoch it was drawn for.
        ///
        /// Cached for the whole epoch — 144 blocks, about a day — so the
        /// number of times the wallet asks a pool anything stops tracking the
        /// number of times it mixes. Without that, a pool watching request
        /// timing learns when its askers are about to mix even though it
        /// learns nothing from the request itself.
        election_cache: RwLock<Option<(u64, serde_json::Value)>>,
        /// True when the environment pinned the node at boot. While it is set
        /// the settings are power-user-owned and `SetNode` refuses.
        ghostd_env_override: bool,
        /// HTTP client used for daemon-side fetches (currently just the
        /// manifest fetch). Reuses rustls so we don't pull in a second TLS
        /// implementation.
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
    /// Where the wallet's node is, and how to authenticate to it.
    ///
    /// All four may be absent: a fresh install has no node, and the wallet
    /// says so rather than borrowing somebody else's.
    #[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct GhostdSettings {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        /// Path to the node's `.cookie`. Preferred over user/pass: it rotates
        /// with the node and is never typed anywhere.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cookie_path: Option<PathBuf>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pass: Option<String>,
    }

    impl GhostdSettings {
        /// How the wallet authenticates, as one word, for display.
        ///
        /// Never the credential itself — this is what goes back over the IPC
        /// and into the settings screen.
        fn auth_kind(&self) -> &'static str {
            if self.cookie_path.is_some() {
                "cookie"
            } else if self.user.is_some() || self.pass.is_some() {
                "userpass"
            } else {
                "none"
            }
        }
    }

    /// Node config persisted to `node.json`. Loaded at boot and rewritten
    /// whenever the user points the wallet at a node. Absent on a fresh
    /// install, in which case the wallet has no chain backend until one is
    /// configured.
    #[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
    struct NodeConfig {
        #[serde(default)]
        ghostd: GhostdSettings,
        /// A Ghost pool node, consulted only for the coordinator election.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pool_url: Option<String>,
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
    /// wedge the daemon; it starts with no node and the next save overwrites
    /// it).
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
    /// unix. It can hold an RPC password, so owner-only is not optional.
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

    impl DaemonState {
        async fn chain(&self) -> Arc<dyn ChainClient> {
            self.clients.read().await.chain.clone()
        }

        /// The node settings currently in force.
        async fn ghostd(&self) -> GhostdSettings {
            self.ghostd.read().await.clone()
        }

        /// Build the chain backend from the node settings.
        ///
        /// No node means `NoChain`, whose every call refuses with a sentence
        /// saying what to configure. Falling back to somebody else's server
        /// would be the alternative, and a self-custody wallet quietly asking
        /// a stranger what it owns is exactly what this is for.
        async fn build_chain(&self) -> Arc<dyn ChainClient> {
            match self.build_ghostd_rpc().await {
                Some(rpc) => {
                    tracing::info!("chain backend: the wallet's own node");
                    Arc::new(wraith_wallet_core::chain::GhostdChainClient::new(
                        rpc,
                        self.network.to_string(),
                    ))
                }
                None => {
                    tracing::warn!(
                        "chain backend: none — no node is configured, so balances, \
                         scans and broadcasts will all refuse until one is"
                    );
                    Arc::new(wraith_wallet_core::chain::NoChain)
                }
            }
        }

        /// An RPC connection to the owner's node, if one is configured.
        ///
        /// Shared with the election-beacon check rather than built twice: two
        /// constructions of the same connection drift, and the one that drifts
        /// is always the one nobody is looking at.
        async fn build_ghostd_rpc(&self) -> Option<wraith_wallet_core::ghostd::GhostdRpc> {
            use wraith_wallet_core::ghostd::GhostdRpc;
            let cfg = self.ghostd().await;
            let url = cfg.url.as_deref()?;
            match (
                cfg.cookie_path.as_ref(),
                cfg.user.as_deref(),
                cfg.pass.as_deref(),
            ) {
                (Some(cookie), _, _) => match GhostdRpc::from_cookie(url, cookie.as_path()) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        tracing::warn!(error = %e, "ghostd cookie unreadable; falling back");
                        None
                    }
                },
                (None, Some(u), Some(p)) => Some(GhostdRpc::new(url, u, p)),
                _ => None,
            }
        }

        /// Point the wallet at a node, at runtime.
        ///
        /// Persists first, then swaps: if the disk write fails the daemon
        /// keeps running on the old settings rather than on a config a
        /// restart would silently revert. Refuses while the environment pins
        /// the node — a power user who set `WRAITHD_GHOSTD_URL` did not mean
        /// for a settings screen to overrule it.
        async fn set_node(
            &self,
            next: GhostdSettings,
            pool_url: Option<String>,
        ) -> Result<NodeResponse, String> {
            if self.ghostd_env_override {
                return Err("the node is pinned by environment variables \
                     (WRAITHD_GHOSTD_URL and friends); unset them to manage the \
                     node from the wallet"
                    .to_string());
            }
            for (what, url) in [("node", next.url.as_deref()), ("pool", pool_url.as_deref())] {
                if let Some(url) = url {
                    if !(url.starts_with("http://") || url.starts_with("https://")) {
                        return Err(format!(
                            "{what} URL must start with http:// or https:// (got '{url}')"
                        ));
                    }
                }
            }
            save_node_config(
                &self.node_config_path,
                &NodeConfig {
                    ghostd: next.clone(),
                    pool_url: pool_url.clone(),
                },
            )
            .map_err(|e| format!("persist node.json: {e}"))?;
            *self.ghostd.write().await = next.clone();
            *self.pool_url.write().await = pool_url.clone();
            // A different pool, or none, invalidates what the last one said.
            *self.election_cache.write().await = None;
            let chain = self.build_chain().await;
            self.clients.write().await.chain = chain;
            tracing::info!(url = ?next.url, auth = next.auth_kind(), "node updated at runtime");
            let auth = next.auth_kind().to_string();
            Ok(NodeResponse {
                ghostd_url: next.url,
                pool_url,
                // The credential itself never crosses the IPC. Which *kind*
                // is in use is what a settings screen needs to show.
                auth,
                env_pinned: false,
            })
        }
    }

    /// Compute the glyph bitmap uniqueness hash exactly as
    /// ghost-glyph defines it: hex(SHA256("GhostGlyphBitmap/v1" ||
    /// pixels)). Must stay byte-for-byte identical to
    /// `GhostGlyph::compute_bitmap_hash` or `check` queries the
    /// wrong key.
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
        let ghostd_env = GhostdSettings {
            url: std::env::var(GHOSTD_URL_ENV).ok().filter(|s| !s.is_empty()),
            cookie_path: std::env::var(GHOSTD_COOKIE_ENV)
                .ok()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
            user: std::env::var(GHOSTD_USER_ENV)
                .ok()
                .filter(|s| !s.is_empty()),
            pass: std::env::var(GHOSTD_PASS_ENV)
                .ok()
                .filter(|s| !s.is_empty()),
        };
        let wallets_dir = default_wallets_dir();
        let node_config_path = node_config_path(&wallets_dir);
        let network = std::env::var(NETWORK_ENV)
            .ok()
            .and_then(|s| parse_network(&s))
            .unwrap_or(bitcoin::Network::Bitcoin);

        // Node resolution, in order:
        //   1. the environment (power-user override, pins the settings screen)
        //   2. persisted node.json (the choice made in the wallet UI)
        //   3. nothing — the wallet has no chain backend and says so
        //
        // There is deliberately no bundled default. A wallet that silently
        // points at somebody else's node on a fresh install is a wallet whose
        // owner never chose who gets to see their addresses.
        let ghostd_env_override = ghostd_env.url.is_some();
        let persisted = load_node_config(&node_config_path);
        let ghostd = if ghostd_env_override {
            ghostd_env
        } else {
            persisted.clone().map(|c| c.ghostd).unwrap_or_default()
        };
        let pool_url = std::env::var(POOL_URL_ENV)
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| persisted.and_then(|c| c.pool_url));
        tracing::info!(
            node = ?ghostd.url,
            auth = ghostd.auth_kind(),
            wallets_dir = %wallets_dir.display(),
            network = ?network,
            tor_proxy = ?tor_proxy,
            ghostd_env_override,
            "node + wallets dir + network configured",
        );
        if ghostd.url.is_none() {
            tracing::warn!(
                "no node configured — set one in Settings or via \
                 WRAITHD_GHOSTD_URL; until then the wallet cannot read or \
                 write the chain"
            );
        }

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
            // Placeholder: the real backend is built from `ghostd` just
            // below, once the state exists to build it from.
            clients: RwLock::new(NodeClients {
                chain: Arc::new(wraith_wallet_core::chain::NoChain),
            }),
            node_config_path,
            tor_proxy: tor_proxy.clone(),
            wraith_coordinator_url,
            kiosk_mode,
            wallets_dir,
            wallets: RwLock::new(HashMap::new()),
            active: RwLock::new(None),
            network,
            endpoint_display: endpoint_display.clone(),
            last_activity: std::sync::atomic::AtomicU64::new(now_unix_secs()),
            idle_lock_secs,
            shroud_max_ms,
            update_manifest_url,
            http,
            wraith_mixes: RwLock::new(HashMap::new()),
            lock_signings: RwLock::new(HashMap::new()),
            ghostd: RwLock::new(ghostd),
            ghostd_env_override,
            pool_url: RwLock::new(pool_url),
            election_cache: RwLock::new(None),
        });
        state.clients.write().await.chain = state.build_chain().await;

        // Auto-lock task. Wakes every 30 s. If idle_lock_secs is 0 the task
        // exits immediately — no overhead when the feature is disabled.
        // Watch the chain for money arriving. Cheap when there is nothing to
        // do: it returns immediately without an unlocked wallet or a node.
        tokio::spawn(block_scan_task(state.clone()));

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
    /// `GspAuth` orchestration: register-if-needed + session. Stores the resulting
    /// `SessionToken` in `state.session` so subsequent commits can use it to open
    /// a persistent authenticated WebSocket.
    /// `LightSend` orchestration: PreparePayment → sign sighash with auth key → SubmitSignedPayment.
    /// Mirrors `ghost-light-wallet::payments::send::sign_and_submit` so wire format matches.
    /// Send `RegisterScanKey` over the persistent session: derives the wallet's
    /// BIP-352 scan pubkey, signs a `register_scan_key` proof, and delegates to
    /// the session task. Returns (wallet_id, scan_pubkey_hex) on success.
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

        // 2. The node: reachability, sync, and round-trip.
        let t0 = std::time::Instant::now();
        let configured = state.ghostd().await.url.is_some();
        match state.chain().await.status().await {
            Ok(s) => {
                let rtt = t0.elapsed().as_millis();
                let height = match s.chain_height {
                    Some(h) => h.to_string(),
                    None => "unknown".into(),
                };
                checks.push(DoctorCheck {
                    name: "node".into(),
                    status: "pass".into(),
                    detail: format!(
                        "{} ({}) — height {height} — round-trip {rtt}ms",
                        s.backend_version, s.network
                    ),
                });
            }
            // No node configured is a setup step, not a failure: it does not
            // fail the run, because there is nothing broken to fix — only
            // something not yet chosen.
            Err(e) if !configured => checks.push(DoctorCheck {
                name: "node".into(),
                status: "skip".into(),
                detail: format!("{e}"),
            }),
            Err(e) => {
                all_pass = false;
                let rtt = t0.elapsed().as_millis();
                checks.push(DoctorCheck {
                    name: "node".into(),
                    status: "fail".into(),
                    detail: format!("{e} (after {rtt}ms)"),
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
            let node = state.ghostd().await;
            mainnet_readiness_checks(
                node.url.as_deref(),
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

    /// Extra rows emitted only on mainnet, where the stakes are real.
    ///
    /// Test networks are excluded deliberately: a plaintext regtest node is
    /// not a privacy problem, and failing on it would train people to ignore
    /// the row that matters.
    fn mainnet_readiness_checks(
        node_url: Option<&str>,
        tor_proxy: Option<&str>,
        checks: &mut Vec<DoctorCheck>,
        all_pass: &mut bool,
    ) {
        // Plaintext RPC row. The node connection carries the wallet's
        // addresses and its transactions before they are broadcast; in the
        // clear, anyone on the path learns both. Loopback is exempt — the
        // traffic never leaves the machine, and TLS there is CPU burned for
        // no privacy gain.
        match node_url {
            None => checks.push(DoctorCheck {
                name: "mainnet/node tls".into(),
                status: "skip".into(),
                detail: "no node configured".into(),
            }),
            Some(u) if u.starts_with("http://") && !is_loopback_url(u) => {
                *all_pass = false;
                checks.push(DoctorCheck {
                    name: "mainnet/node tls".into(),
                    status: "fail".into(),
                    detail: format!(
                        "{u} is plaintext and not loopback — your addresses and \
                         unbroadcast transactions are visible to anyone on the path. \
                         use https://, or reach the node over loopback or an SSH tunnel."
                    ),
                });
            }
            Some(_) => checks.push(DoctorCheck {
                name: "mainnet/node tls".into(),
                status: "pass".into(),
                detail: "the node is reached over https or loopback".into(),
            }),
        }

        // Tor row. Advisory only — Tor is opt-in by design, and forcing it
        // would break legitimate setups (a node on a private network, say).
        // "skip" rather than "fail" so all_pass isn't lowered.
        match tor_proxy {
            None => checks.push(DoctorCheck {
                name: "mainnet/tor".into(),
                status: "skip".into(),
                detail: "WRAITHD_TOR_PROXY unset — your IP is visible to anything the \
                         wallet talks to. set e.g. socks5h://127.0.0.1:9050 to route \
                         through Tor."
                    .into(),
            }),
            Some(p) => checks.push(DoctorCheck {
                name: "mainnet/tor".into(),
                status: "pass".into(),
                detail: format!("routing through {p}"),
            }),
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
        //
        // A Ghost ID is paid differently from an address: the money goes to a
        // taproot output derived per-payment, and an OP_RETURN alongside it
        // carries the ephemeral key the recipient needs to find it. Routed on
        // the recipient's form rather than on a flag, so the caller cannot ask
        // for one and get the other.
        let (psbt, meta) = if wraith_wallet_core::silent_payment::looks_like_ghost_id(
            recipient_address,
            network,
        ) {
            let pay = wraith_wallet_core::silent_payment::build(recipient_address, network, 0)
                .map_err(|e| format!("silent payment: {e}"))?;
            psbt_mod::create_psbt_to_scripts(
                &available,
                pay.output_script,
                amount_sats,
                std::slice::from_ref(&pay.announcement_script),
                &change_addr,
                fee_rate_sats_per_vb,
            )
            .map_err(|e| format!("create_psbt: {e}"))?
        } else {
            psbt_mod::create_psbt(
                &available,
                recipient_address,
                amount_sats,
                &change_addr,
                network,
                fee_rate_sats_per_vb,
            )
            .map_err(|e| format!("create_psbt: {e}"))?
        };

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

    /// What one on-chain payment needs to know.
    ///
    /// A struct rather than a long argument list: every field but the first
    /// two is optional in spirit, and eight positional arguments of mostly
    /// numbers is a place where two of them quietly swap.
    struct L1SendParams {
        recipient_address: String,
        amount_sats: u64,
        fee_rate_sats_per_vb: u64,
        change_index: Option<u32>,
        bip86_scan_max: u32,
        selected_outpoints: Vec<wraith_wallet_ipc::OutpointRef>,
        memo: Option<String>,
        shroud_override_ms: Option<u64>,
    }

    /// Build, sign and broadcast an ordinary on-chain payment.
    ///
    /// Composed from the three verbs that already exist rather than
    /// re-implementing any of them: `psbt_create_handler` selects coins and
    /// sets the change, `sign_owned_inputs` signs what the wallet owns, and
    /// `psbt_broadcast_handler` is the single place a transaction reaches the
    /// network and the single place history is written.
    ///
    /// It stops with a clear error rather than broadcasting a partly signed
    /// transaction. An incomplete PSBT here means a selected input was not
    /// ours to sign — which is worth saying, because the alternative is a
    /// rejection from the node whose message explains nothing.
    async fn l1_send(
        state: &Arc<DaemonState>,
        p: L1SendParams,
    ) -> Result<wraith_wallet_ipc::L1SendResponse, String> {
        use wraith_wallet_core::psbt as psbt_mod;

        let L1SendParams {
            recipient_address,
            amount_sats,
            fee_rate_sats_per_vb,
            change_index,
            bip86_scan_max,
            selected_outpoints,
            memo,
            shroud_override_ms,
        } = p;

        let built = psbt_create_handler(
            state,
            &recipient_address,
            amount_sats,
            fee_rate_sats_per_vb,
            change_index,
            bip86_scan_max,
            &selected_outpoints,
        )
        .await?;

        let network = state.network;
        let scan_max = bip86_scan_max.max(1);
        let (mut parsed, encoding) =
            psbt_mod::decode_psbt(&built.psbt).map_err(|e| format!("decode: {e}"))?;
        let signed_count = with_active_wallet(state, move |_, ks| {
            psbt_mod::sign_owned_inputs(&mut parsed, ks, network, scan_max)
                .map(|n| (n, parsed))
                .map_err(|e| format!("sign: {e}"))
        })
        .await?;
        let (signed, signed_psbt) = signed_count;
        if !psbt_mod::is_complete(&signed_psbt) {
            return Err(format!(
                "signed {} of {} inputs — the rest are not this wallet's to sign, \
                 so nothing was broadcast",
                signed.len(),
                signed_psbt.inputs.len()
            ));
        }

        // The same shroud as `LightSend`, and it means more here: this one
        // does reach the P2P network, where the moment of broadcast is what an
        // observer correlates against the user's keystrokes.
        let max_ms = shroud_override_ms.unwrap_or(state.shroud_max_ms);
        let shroud_delay_ms = shroud_pick_delay(max_ms);
        if let Some(chosen) = shroud_delay_ms {
            tracing::debug!(
                shroud_max_ms = max_ms,
                chosen_ms = chosen,
                "shroud relay: holding L1 payment before broadcast"
            );
            tokio::time::sleep(std::time::Duration::from_millis(chosen)).await;
        }

        let encoded = psbt_mod::encode_psbt(&signed_psbt, encoding);
        let txid = psbt_broadcast_handler(state, &encoded, "send", memo).await?;

        Ok(wraith_wallet_ipc::L1SendResponse {
            txid,
            recipient: recipient_address,
            // From the built transaction, not from the request: coin selection
            // decides what the fee ends up being.
            amount_sats: built.recipient_sats,
            fee_sats: built.fee_sats,
            change_sats: built.change_sats,
            input_count: built.input_count,
            shroud_delay_ms,
        })
    }

    /// Extract a finalized tx from a PSBT (or accept raw tx hex
    /// directly), broadcast it, and write it into the local history.
    /// Returns the txid the node accepted.
    ///
    /// This is the one place a transaction reaches the network, which is why
    /// it is also the one place history is written: a spend that never left
    /// is not something the wallet did, and one that left must not be
    /// forgotten.
    async fn psbt_broadcast_handler(
        state: &Arc<DaemonState>,
        psbt_or_tx_hex: &str,
        kind: &str,
        memo: Option<String>,
    ) -> Result<String, String> {
        use wraith_wallet_core::psbt as psbt_mod;
        let trimmed = psbt_or_tx_hex.trim();
        // PSBT magic in hex is 70736274ff; in base64 it's `cHNidP`.
        // Anything else, treat as raw consensus-encoded tx hex.
        let is_psbt =
            trimmed.to_lowercase().starts_with("70736274ff") || trimmed.starts_with("cHNidP");
        let mut source_psbt = None;
        let tx_hex = if is_psbt {
            let (parsed, _) =
                psbt_mod::decode_psbt(trimmed).map_err(|e| format!("decode_psbt: {e}"))?;
            if !psbt_mod::is_complete(&parsed) {
                return Err(
                    "PSBT is not complete — every input must be finalized before broadcast".into(),
                );
            }
            let tx = parsed
                .clone()
                .extract_tx()
                .map_err(|e| format!("extract_tx: {e}"))?;
            let hex = bitcoin::consensus::encode::serialize_hex(&tx);
            // Kept for the history entry: a PSBT carries the input values, so
            // it is the only form from which the fee and the true net change
            // can be worked out. A bare transaction does not carry them.
            source_psbt = Some(parsed);
            hex
        } else {
            let bytes = hex::decode(trimmed).map_err(|e| format!("hex: {e}"))?;
            let _: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&bytes)
                .map_err(|e| format!("invalid raw tx: {e}"))?;
            trimmed.to_string()
        };
        let txid = state
            .chain()
            .await
            .broadcast_tx(&tx_hex)
            .await
            .map_err(|e| format!("broadcast: {e}"))?;
        // Recorded after the node accepted it, because a transaction the node
        // rejected is not something the wallet did. A failure to record is
        // logged and not propagated: the money has already moved, and
        // reporting the broadcast as failed would be the more damaging lie.
        if let Err(e) = record_broadcast(state, &txid, source_psbt.as_ref(), kind, memo).await {
            tracing::warn!(
                txid = %txid,
                error = %e,
                "broadcast succeeded but could not be written to local history"
            );
        }
        Ok(txid)
    }

    /// Write one broadcast into the local history.
    ///
    /// Both figures come from the PSBT or from nowhere. A raw transaction does
    /// not carry its input values, so neither the fee nor the net change can
    /// be derived from one; the entry is then recorded with `None` for both
    /// rather than with a plausible-looking wrong number. `None` reads as "—"
    /// in the UI, where a `0` would read as "moved nothing".
    async fn record_broadcast(
        state: &Arc<DaemonState>,
        txid: &str,
        source_psbt: Option<&bitcoin::psbt::Psbt>,
        kind: &str,
        memo: Option<String>,
    ) -> Result<(), String> {
        let (amount_sats, fee_sats) = match source_psbt {
            Some(p) => match own_script_pubkeys(state).await {
                Some(ours) => psbt_ledger_effect(p, &ours),
                // Locked wallet: the fee is still inputs minus outputs and
                // needs no keys, but which coins were ours does.
                None => (None, psbt_ledger_effect_fee(p)),
            },
            None => (None, None),
        };
        let mut store = history_store_for(state).await?;
        store
            .record(wraith_wallet_core::history_store::HistoryEntry {
                txid: txid.to_string(),
                at: now_unix_secs() as i64,
                // Unconfirmed until the scanner sees it mined.
                block_height: None,
                amount_sats,
                fee_sats,
                kind: kind.to_string(),
                memo,
            })
            .map_err(|e| format!("history write: {e}"))
    }

    /// The value backing one PSBT input, from whichever UTXO field carries it.
    fn psbt_input_value(psbt: &bitcoin::psbt::Psbt, i: usize) -> Option<&bitcoin::TxOut> {
        let input = psbt.inputs.get(i)?;
        if let Some(txout) = input.witness_utxo.as_ref() {
            return Some(txout);
        }
        // Legacy inputs carry the whole previous transaction instead.
        let prev = input.non_witness_utxo.as_ref()?;
        let outpoint = psbt.unsigned_tx.input.get(i)?.previous_output;
        prev.output.get(outpoint.vout as usize)
    }

    /// Miner fee: every input value minus every output value.
    ///
    /// `None` if any input's value is missing — a fee computed from a subset
    /// of the inputs is not a smaller fee, it is a wrong one.
    fn psbt_ledger_effect_fee(psbt: &bitcoin::psbt::Psbt) -> Option<u64> {
        let mut inputs = 0u64;
        for i in 0..psbt.unsigned_tx.input.len() {
            inputs = inputs.saturating_add(psbt_input_value(psbt, i)?.value.to_sat());
        }
        let outputs: u64 = psbt
            .unsigned_tx
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .sum();
        Some(inputs.saturating_sub(outputs))
    }

    /// What this PSBT does to the wallet's balance, and what it pays in fee.
    ///
    /// The net is our outputs minus our inputs, so it accounts for change and
    /// for the fee without either being special-cased: a 50,000 sat payment
    /// costing 500 in fee nets −50,500, which is the number the balance will
    /// actually move by. Addresses beyond the scan window read as somebody
    /// else's and overstate what left — the safer direction to be wrong in for
    /// a record the user checks against their memory of the payment.
    fn psbt_ledger_effect(
        psbt: &bitcoin::psbt::Psbt,
        ours: &std::collections::HashSet<Vec<u8>>,
    ) -> (Option<i64>, Option<u64>) {
        let fee = psbt_ledger_effect_fee(psbt);
        let mut spent: i64 = 0;
        for i in 0..psbt.unsigned_tx.input.len() {
            let Some(txout) = psbt_input_value(psbt, i) else {
                // One unknown input value makes the net unknowable; the fee
                // is already `None` for the same reason.
                return (None, fee);
            };
            if ours.contains(txout.script_pubkey.as_bytes()) {
                spent = spent.saturating_add(txout.value.to_sat() as i64);
            }
        }
        let mut received: i64 = 0;
        for out in &psbt.unsigned_tx.output {
            if ours.contains(out.script_pubkey.as_bytes()) {
                received = received.saturating_add(out.value.to_sat() as i64);
            }
        }
        (Some(received.saturating_sub(spent)), fee)
    }

    /// The scripts this wallet can spend, over the scan window.
    ///
    /// `None` when the wallet is locked — deriving needs the keys. Change
    /// addresses beyond the window read as somebody else's, which overstates
    /// what left; that is the safer direction to be wrong in for a record the
    /// user checks against their own memory of the payment.
    async fn own_script_pubkeys(state: &DaemonState) -> Option<std::collections::HashSet<Vec<u8>>> {
        let network = state.network;
        with_active_wallet(state, move |_, ks| {
            let mut set = std::collections::HashSet::new();
            for i in 0..wraith_wallet_core::psbt::DEFAULT_SCAN_INDEX_MAX {
                let a = light::receive_address(ks, i, network)
                    .map_err(|e| format!("derive index {i}: {e}"))?;
                set.insert(a.script_pubkey().as_bytes().to_vec());
            }
            Ok(set)
        })
        .await
        .ok()
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
    /// idle-lock timer. Diagnostics (Health, Doctor, DaemonEnv) don't reset
    /// it — they are too quiet to indicate a present user, and a status bar
    /// polling every few seconds would defeat the feature outright.
    fn is_activity(req: &Request) -> bool {
        !matches!(req, Request::Health | Request::Doctor | Request::DaemonEnv)
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
        }
    }

    /// How many blocks one scan tick will read.
    ///
    /// A wallet that has been shut for a week has a lot to catch up on, and
    /// reading it in one go would hold the runtime and the node for minutes.
    /// Bounded work per tick means it catches up steadily and stays responsive
    /// while it does.
    const SCAN_BATCH_BLOCKS: u32 = 50;

    /// How far back a reorg is looked for before giving up.
    ///
    /// Deeper than any reorg this chain has seen. If the fork is further back
    /// than this the scanner says so rather than guessing — a bookmark that
    /// cannot be reconciled is a thing to report, not to paper over.
    const REORG_SEARCH_DEPTH: u32 = 100;

    /// Read new blocks and record what they did to the wallet.
    ///
    /// # What this replaces
    ///
    /// The operator's GSP watched the chain and pushed what it found, which
    /// meant giving somebody a scan key and believing the answer. This asks
    /// the wallet's own node instead. The cost is latency — a payment appears
    /// within a tick rather than the instant it is relayed — and the gain is
    /// that nobody else needs to know the wallet is watching.
    async fn block_scan_task(state: Arc<DaemonState>) {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(20));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            loop {
                match scan_new_blocks(&state).await {
                    Ok(0) => break,
                    // A full batch means there is more waiting. Go straight
                    // round again rather than sleeping: a wallet restored from
                    // a year ago has fifty thousand blocks to read, and doing
                    // that at one batch per tick would take most of a day.
                    // Idle, this still costs nothing — the first pass returns
                    // zero and the loop ends.
                    Ok(n) if n >= SCAN_BATCH_BLOCKS => continue,
                    Ok(n) => {
                        tracing::debug!(blocks = n, "block scan caught up");
                        break;
                    }
                    // A node that is down, syncing or mid-restart is the common
                    // case and not worth an error line every twenty seconds.
                    // The status header already says the node is unreachable.
                    Err(e) => {
                        tracing::debug!(error = %e, "block scan tick did not complete");
                        break;
                    }
                }
            }
        }
    }

    /// One pass of the scanner. Returns how many blocks it read.
    ///
    /// Does nothing at all without an unlocked wallet — deriving the scripts
    /// to match against needs the keys, and there is no useful work to do
    /// while the wallet is locked.
    async fn scan_new_blocks(state: &Arc<DaemonState>) -> Result<u32, String> {
        let Some(ours) = own_script_pubkeys(state).await else {
            return Ok(0);
        };
        // The Ghost ID's scan and spend keys. A silent payment lands on a key
        // derived from these rather than on any address the wallet published,
        // so `ours` above cannot find one.
        let ghost_keys = with_active_wallet(state, |_, ks| {
            ks.ghost_keys().map_err(|e| format!("ghost keys: {e}"))
        })
        .await
        .ok();
        let Some(rpc) = state.build_ghostd_rpc().await else {
            return Ok(0);
        };
        let rpc = Arc::new(rpc);

        let tip = {
            let rpc = rpc.clone();
            tokio::task::spawn_blocking(move || rpc.get_block_count())
                .await
                .map_err(|e| format!("join: {e}"))?
                .map_err(|e| format!("get_block_count: {e}"))? as u32
        };

        let mut bookmark = scan_state_for(state).await?;

        // Where a wallet that has never scanned begins.
        //
        // Its birth height when it has one: a wallet created here recorded the
        // tip, and a restored one recorded whatever its owner said. Reading
        // forward from there rebuilds the history.
        //
        // Otherwise the tip — not genesis. Reading the whole chain to find a
        // wallet that may have no history at all is hours of work for, usually,
        // nothing, and the wallet cannot tell the difference between "restored
        // from years ago" and "made this morning" unless it is told. Coins that
        // arrived before this point are not lost from view — the balance and
        // the UTXO list scan the entire UTXO set — they are absent from the
        // *history*, which is a narrower claim and a stated one.
        let Some(point) = bookmark.point().cloned() else {
            let birth = wallet_meta_for(state)
                .await
                .ok()
                .and_then(|m| m.birth_height);
            let start = birth.unwrap_or(tip).min(tip);
            // One before the start, because the loop below scans from
            // `from + 1`: the birth block itself can hold the first payment.
            let anchor = start.saturating_sub(1);
            let hash = block_hash_at(&rpc, anchor).await?;
            bookmark
                .set(anchor, hash)
                .map_err(|e| format!("scan state write: {e}"))?;
            match birth {
                Some(b) => tracing::info!(
                    birth_height = b,
                    tip,
                    behind = tip.saturating_sub(b),
                    "block scanner rebuilding history from the wallet's birth height"
                ),
                None => tracing::info!(
                    height = tip,
                    "block scanner started watching from the tip — this wallet has no \
                     recorded birth height, so nothing before now will appear in its history"
                ),
            }
            return Ok(0);
        };

        // Is the chain we read still the chain that exists?
        let mut from = point.height;
        if block_hash_at(&rpc, point.height).await? != point.hash {
            let mut fork = None;
            let floor = point.height.saturating_sub(REORG_SEARCH_DEPTH);
            for h in (floor..point.height).rev() {
                // Walking back to a height both chains agree on. The first
                // agreement is the fork point; everything above it was read
                // from blocks that are no longer in the chain.
                if let Some(known) = recorded_hash_at(state, h).await {
                    if block_hash_at(&rpc, h).await? == known {
                        fork = Some(h);
                        break;
                    }
                }
            }
            let restart = fork.unwrap_or(floor);
            let mut history = history_store_for(state).await?;
            let n = history
                .unconfirm_from(restart + 1)
                .map_err(|e| format!("history: {e}"))?;
            tracing::warn!(
                was = point.height,
                restart_from = restart,
                unconfirmed = n,
                "chain reorganised under the scanner; rescanning"
            );
            from = restart;
        }

        if from >= tip {
            return Ok(0);
        }
        let end = tip.min(from + SCAN_BATCH_BLOCKS);
        let mut history = history_store_for(state).await?;
        for height in (from + 1)..=end {
            let hash = block_hash_at(&rpc, height).await?;
            let block = {
                let rpc = rpc.clone();
                let h = hash.clone();
                tokio::task::spawn_blocking(move || rpc.get_block_with_prevouts(&h))
                    .await
                    .map_err(|e| format!("join: {e}"))?
                    .map_err(|e| format!("getblock {height}: {e}"))?
            };
            // Silent payments first: a detection is also money arriving, and
            // recording it as history below keeps one story rather than two.
            if let Some(keys) = ghost_keys.as_ref() {
                let mut found = Vec::new();
                for (txid, ephemeral, outputs) in
                    wraith_wallet_core::block_scan::candidates_in_block(&block)
                {
                    match wraith_wallet_core::candidate_scan::scan_candidate(
                        keys,
                        &ephemeral,
                        &outputs,
                        &txid,
                        Some(height),
                    ) {
                        Ok(hits) => found.extend(hits),
                        // A malformed announcement is somebody else's problem,
                        // not a reason to stop scanning the chain.
                        Err(e) => tracing::debug!(txid = %txid, error = %e, "candidate skipped"),
                    }
                }
                if !found.is_empty() {
                    let mut detections = detection_store_for(state).await?;
                    let credited: i64 = found
                        .iter()
                        .filter_map(|d| d.amount_sats)
                        .fold(0i64, |a, v| a.saturating_add(v as i64));
                    let txid = found[0].txid.clone();
                    let n = detections
                        .record_all(found)
                        .map_err(|e| format!("detections write: {e}"))?;
                    if n > 0 {
                        tracing::info!(height, coins = n, "silent payment detected");
                        history
                            .record(wraith_wallet_core::history_store::HistoryEntry {
                                txid,
                                at: block.time,
                                block_height: Some(height),
                                amount_sats: Some(credited),
                                // The sender paid the fee; the receiver of a
                                // silent payment has no way to know what it was
                                // and no reason to be charged for it on paper.
                                fee_sats: None,
                                kind: "receive".to_string(),
                                memo: None,
                            })
                            .map_err(|e| format!("history write: {e}"))?;
                    }
                }
            }

            for m in wraith_wallet_core::block_scan::scan_block(&block, &ours) {
                history
                    .record(wraith_wallet_core::history_store::HistoryEntry {
                        amount_sats: Some(m.net_sats()),
                        txid: m.txid,
                        at: m.time,
                        block_height: Some(m.height as u32),
                        fee_sats: m.fee_sats,
                        kind: if m.is_incoming { "receive" } else { "send" }.to_string(),
                        // The scanner cannot see a memo. `record` merges, so
                        // `None` here leaves any memo already recorded alone.
                        memo: None,
                    })
                    .map_err(|e| format!("history write: {e}"))?;
            }
            // Advanced per block, not per batch: an interrupted catch-up
            // resumes where it stopped instead of re-reading from the start.
            bookmark
                .set(height, hash)
                .map_err(|e| format!("scan state write: {e}"))?;
        }
        Ok(end - from)
    }

    /// The hash the node reports at `height`.
    async fn block_hash_at(
        rpc: &Arc<wraith_wallet_core::ghostd::GhostdRpc>,
        height: u32,
    ) -> Result<String, String> {
        let rpc = rpc.clone();
        tokio::task::spawn_blocking(move || rpc.get_block_hash(height as u64))
            .await
            .map_err(|e| format!("join: {e}"))?
            .map_err(|e| format!("get_block_hash {height}: {e}"))
    }

    /// The hash the bookmark holds for `height`, if it is the bookmarked one.
    ///
    /// Only one height is remembered, so the reorg walk can confirm agreement
    /// at exactly that point and otherwise falls back to rescanning the search
    /// depth — which is correct, just more work.
    async fn recorded_hash_at(state: &Arc<DaemonState>, height: u32) -> Option<String> {
        let bookmark = scan_state_for(state).await.ok()?;
        let p = bookmark.point()?;
        (p.height == height).then(|| p.hash.clone())
    }

    /// The coordinator election for the current epoch, verified.
    ///
    /// # Where it comes from, and what that costs
    ///
    /// A pool node publishes the draw at `/api/v1/pool/coordinator`. The
    /// wallet used to reach that through Ghost Pay, precisely so it never
    /// spoke to the pool itself; with the operator gone the choice is between
    /// asking a pool directly and not rotating coordinators at all. A single
    /// hard-coded coordinator URL defeats the point of the election, which
    /// exists so coordination moves across the qualified set instead of
    /// settling on whoever the wallet was shipped pointing at.
    ///
    /// So it asks, and pays for it in two ways that are worth naming:
    ///
    /// * The pool learns this IP asked. Route it through Tor if that matters —
    ///   the proxy is used when one is configured.
    /// * The pool could learn *when* somebody is about to mix, if the ask
    ///   happened per mix. It does not: the result is cached for the whole
    ///   epoch (144 blocks, about a day), so the number of asks stops tracking
    ///   the number of mixes.
    ///
    /// # What is checked
    ///
    /// The draw is recomputed from the beacon and roster published beside it,
    /// and the beacon is re-derived from the anchor block's hash **as the
    /// wallet's own node reports it**. A pool that names itself every seat is
    /// refused (#697).
    ///
    /// ⚠ The roster is still trusted. The published seat list must follow from
    /// the roster, but nothing here proves the roster is the real qualified
    /// set — a pool that omits honest candidates produces a self-consistent
    /// election over a subset it prefers. Closing that needs the qualified set
    /// to come from consensus, and it cannot come from the mesh node-list
    /// checkpoint: that one carries *public-mining* nodes and their stratum
    /// ports, while this draws from *coordinator*-opted-in nodes. ghost-pool
    /// builds the coordinator roster from live mesh state and says so —
    /// "the roster comes from live mesh state, which is the defect this value
    /// exposes rather than repairs" — so two nodes can legitimately disagree,
    /// and `roster_commitment` exists to make that visible. A trustless roster
    /// needs its own BFT-finalised checkpoint on the pool side, with a height
    /// gate and a fleet roll. Until then this is chain-anchored, not
    /// trustless, and the difference is the roster.
    async fn verified_election(state: &Arc<DaemonState>) -> Option<serde_json::Value> {
        let pool_url = state.pool_url.read().await.clone()?;

        // Which epoch we are in, from our own node. Asking the pool would let
        // it choose which epoch it answers for.
        let tip = current_tip(state).await?;
        let epoch = wraith_protocol::epoch_for_height(tip as u64);

        if let Some((cached_epoch, view)) = state.election_cache.read().await.as_ref() {
            if *cached_epoch == epoch {
                return Some(view.clone());
            }
        }

        let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(20));
        if let Some(proxy) = state.tor_proxy.as_deref() {
            match reqwest::Proxy::all(proxy) {
                Ok(p) => builder = builder.proxy(p),
                // Refusing rather than falling back to a direct request: the
                // user asked for Tor, and quietly revealing their IP instead
                // is the one outcome they were trying to avoid.
                Err(e) => {
                    tracing::warn!(error = %e, "tor proxy unusable; not asking the pool");
                    return None;
                }
            }
        }
        let client = builder.build().ok()?;
        let url = format!("{}/api/v1/pool/coordinator", pool_url.trim_end_matches('/'));
        let election: serde_json::Value = match client.get(&url).send().await {
            Ok(r) => match r.json().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(error = %e, "election view was not JSON");
                    return None;
                }
            },
            Err(e) => {
                tracing::debug!(error = %e, "could not reach the pool for the election");
                return None;
            }
        };

        if election.get("enabled").and_then(|v| v.as_bool()) != Some(true) {
            tracing::debug!("the pool has coordinator elections turned off");
            return None;
        }

        // Pin the beacon to the chain. Verifying the draw against the beacon
        // published beside it only proves internal consistency; the anchor
        // block's hash is a fact the pool does not get to state.
        let (anchor_height, _) = crate::coordinator_resolve::beacon_anchor_expectation(&election)?;
        let rpc = state.build_ghostd_rpc().await?;
        let anchor_hash = tokio::task::spawn_blocking(move || rpc.get_block_hash(anchor_height))
            .await
            .ok()?
            .ok()?;
        if !crate::coordinator_resolve::beacon_matches_chain(&election, &anchor_hash) {
            tracing::warn!(
                anchor_height,
                "the published election beacon does not follow from the anchor block — \
                 refusing the election"
            );
            return None;
        }

        // A draw over one candidate is not a draw. Said plainly, because a
        // wallet that mixes through a single-node "election" has the privacy
        // of not mixing at all and no way to tell (#708).
        if election.get("degraded").and_then(|v| v.as_bool()) == Some(true) {
            tracing::warn!(
                roster_size = election.get("roster_size").and_then(|v| v.as_u64()),
                "the coordinator election is degraded — too few candidates for the draw \
                 to mean anything"
            );
        }

        *state.election_cache.write().await = Some((epoch, election.clone()));
        Some(election)
    }

    /// Derive a Lock's four lanes from the supplied keys plus the active
    /// wallet's owner key.
    ///
    /// One definition, deliberately. `GhostLockLanes` and
    /// `GhostLockRoundDestination` must not be able to derive different
    /// addresses for the same Lock — a round paying into an address the
    /// balance view does not watch would look exactly like a lost deposit.
    async fn build_lock_account(
        state: &Arc<DaemonState>,
        backup_pubkey: &str,
        heir_pubkey: &str,
        quorum_pubkey: &str,
        inherit_height: u32,
        anchor_height: u32,
        bip86_index: Option<u32>,
    ) -> Result<wraith_wallet_core::ghost_lock_account::GhostLockAccount, String> {
        use bitcoin::secp256k1::Secp256k1;
        use bitcoin::XOnlyPublicKey;
        use std::str::FromStr;
        use wraith_wallet_core::ghost_lock_account::{GhostLockAccount, LockKeys};

        fn xonly(label: &str, hexstr: &str) -> Result<XOnlyPublicKey, String> {
            XOnlyPublicKey::from_str(hexstr.trim())
                .map_err(|e| format!("{label} is not an x-only public key: {e}"))
        }

        // The owner key comes from the active keystore; the backup, heir and
        // quorum keys are supplied. The two MuSig2 aggregates are DERIVED
        // below, not supplied — BIP-327 key aggregation is a deterministic
        // function of the public keys, so no ceremony and no other party
        // online is needed to CREATE a Lock. Interaction is only required to
        // SIGN a key-path spend.
        let idx = bip86_index.unwrap_or(0);
        let network = state.network;
        let owner = with_active_wallet(state, move |_, ks| {
            let path = format!(
                "m/86'/{}'/0'/0/{idx}",
                wraith_wallet_core::light::GHOST_COIN_TYPE
            );
            let xprv = ks.derive_xprv(&path).map_err(|e| format!("derive: {e}"))?;
            let secp = Secp256k1::new();
            let sk = bitcoin::secp256k1::SecretKey::from_slice(&xprv.private_key().to_bytes())
                .map_err(|e| format!("owner key: {e}"))?;
            Ok::<XOnlyPublicKey, String>(
                bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk)
                    .x_only_public_key()
                    .0,
            )
        })
        .await?;

        let backup = xonly("backup_pubkey", backup_pubkey)?;
        let quorum = xonly("quorum_pubkey", quorum_pubkey)?;

        // Derived here rather than accepted from the caller. BIP-327
        // aggregation is deterministic, so both sides reach the same answer
        // independently — and a pasted aggregate that did not match its parts
        // would build a Lock whose key path nobody can satisfy, with nothing
        // noticing until a spend failed.
        let owner_backup_aggregate = ghost_lock::aggregate(&[owner, backup])
            .map_err(|e| format!("owner+backup aggregate: {e}"))?;
        let owner_quorum_aggregate = ghost_lock::aggregate(&[owner, quorum])
            .map_err(|e| format!("owner+quorum aggregate: {e}"))?;

        let keys = LockKeys {
            owner,
            backup,
            heir: xonly("heir_pubkey", heir_pubkey)?,
            owner_backup_aggregate,
            owner_quorum_aggregate,
            quorum,
        };
        let secp = Secp256k1::verification_only();
        GhostLockAccount::build(&secp, &keys, network, anchor_height, inherit_height)
            .map_err(|e| format!("lock: {e}"))
    }

    fn unhex32(label: &str, s: &str) -> Result<[u8; 32], String> {
        let raw = hex::decode(s.trim()).map_err(|e| format!("{label} is not hex: {e}"))?;
        raw.try_into()
            .map_err(|_| format!("{label} must be 32 bytes"))
    }

    fn unhex66(label: &str, s: &str) -> Result<[u8; 66], String> {
        let raw = hex::decode(s.trim()).map_err(|e| format!("{label} is not hex: {e}"))?;
        raw.try_into()
            .map_err(|_| format!("{label} must be 66 bytes"))
    }

    fn lock_spend_summary(s: &ghost_lock::airgap::SpendSummary) -> LockSpendSummary {
        LockSpendSummary {
            input_index: s.input_index,
            input_sats: s.input_sats,
            input_address: s.input_address.clone(),
            outputs: s
                .outputs
                .iter()
                .map(|o| LockSpendOutput {
                    address: o.address.clone(),
                    sats: o.sats,
                })
                .collect(),
            fee_sats: s.fee_sats,
            input_count: s.input_count,
        }
    }

    /// Load a remembered Lock, derive its lanes, and resolve the named lane.
    ///
    /// Shares `build_lock_account` with the balance view and the round
    /// destination, so all three derive one Lock's addresses identically.
    async fn lock_lane_for(
        state: &Arc<DaemonState>,
        lock_id: &str,
        lane: &str,
    ) -> Result<
        (
            wraith_wallet_core::ghost_lock_account::GhostLockAccount,
            wraith_wallet_core::ghost_lock_account::LaneKind,
            wraith_wallet_core::ghost_lock_store::StoredLock,
        ),
        String,
    > {
        let kind = parse_lane(lane)?;
        let record = {
            let store = ghost_lock_store_for(state).map_err(|e| format!("lock store: {e}"))?;
            store
                .get(lock_id)
                .cloned()
                .ok_or_else(|| format!("no remembered Lock '{lock_id}'"))?
        };
        let account = build_lock_account(
            state,
            &record.backup_pubkey,
            &record.heir_pubkey,
            &record.quorum_pubkey,
            record.inherit_height,
            record.anchor_height,
            Some(record.bip86_index),
        )
        .await?;
        Ok((account, kind, record))
    }

    /// Every receive address the wallet would use, up to `scan_max`.
    ///
    /// Shared by the UTXO list and the balance, so the two cannot be computed
    /// over different address sets and disagree about how much money there is.
    async fn derived_receive_addresses(
        state: &Arc<DaemonState>,
        scan_max: u32,
    ) -> Result<Vec<(u32, String, String)>, String> {
        let network = state.network;
        with_active_wallet(state, move |_, ks| {
            let mut out = Vec::with_capacity(scan_max as usize);
            for i in 0..scan_max {
                let a = light::receive_address(ks, i, network)
                    .map_err(|e| format!("derive index {i}: {e}"))?;
                let spk = hex::encode(a.script_pubkey().as_bytes());
                out.push((i, a.to_string(), spk));
            }
            Ok(out)
        })
        .await
    }

    /// The wallet's on-chain balance, from the configured chain backend.
    ///
    /// Settled and unsettled are summed separately and never added together:
    /// money that can still vanish must not read as money you have. That is
    /// the same rule the Lock lanes follow, and for the same reason.
    async fn l1_balance(
        state: &Arc<DaemonState>,
        scan_max: u32,
    ) -> Result<(u64, u64, u32), String> {
        let pairs = derived_receive_addresses(state, scan_max).await?;
        let addresses: Vec<String> = pairs.into_iter().map(|(_, a, _)| a).collect();
        // Scanned at zero confirmations, then split here — one round trip
        // gives both figures, where two scans could disagree with each other.
        let scan = state
            .chain()
            .await
            .scan_utxos(&addresses, 0)
            .await
            .map_err(|e| format!("scan: {e}"))?;
        let mut confirmed = 0u64;
        let mut unconfirmed = 0u64;
        for u in &scan.utxos {
            if u.confirmations == 0 {
                unconfirmed = unconfirmed.saturating_add(u.amount_sats);
            } else {
                confirmed = confirmed.saturating_add(u.amount_sats);
            }
        }
        Ok((confirmed, unconfirmed, scan.chain_height))
    }

    /// The wallet's spendable outputs, from the node.
    ///
    /// Shares its derivation and scan with [`l1_balance`], so the balance and
    /// the coin list can never disagree about which coins exist — they are two
    /// readings of one answer, not two questions asked separately.
    async fn l1_utxo_entries(
        state: &Arc<DaemonState>,
        scan_max: u32,
        min_confirmations: u32,
    ) -> Result<(Vec<LightUtxoEntry>, u64), String> {
        let pairs = derived_receive_addresses(state, scan_max).await?;
        let addresses: Vec<String> = pairs.into_iter().map(|(_, a, _)| a).collect();
        let scan = state
            .chain()
            .await
            .scan_utxos(&addresses, min_confirmations)
            .await
            .map_err(|e| format!("scan: {e}"))?;
        let mut total = 0u64;
        let mut out = Vec::with_capacity(scan.utxos.len());
        for u in scan.utxos {
            total = total.saturating_add(u.amount_sats);
            out.push(LightUtxoEntry {
                txid: u.txid,
                vout: u.vout,
                amount_sats: u.amount_sats,
                confirmations: u.confirmations,
                // Every address the wallet derives is BIP86 taproot; the scan
                // only looked at those, so anything it returned is one.
                script_type: "p2tr".to_string(),
                // The scan filtered on confirmations already, and these are
                // the wallet's own single-key outputs.
                spendable: true,
            });
        }
        Ok((out, total))
    }

    /// Transaction history from the wallet's own record, confirmed against the
    /// node.
    ///
    /// # What this can and cannot show
    ///
    /// Both directions, now that the block scanner runs: what the wallet sent,
    /// recorded at broadcast, and what arrived, recorded when a block carrying
    /// it was read.
    ///
    /// The one gap is what happened before the scanner started watching. It
    /// begins at the tip on first run rather than reading the chain from
    /// genesis, so a restored wallet's older payments are absent from the
    /// history. They are not absent from the wallet: the balance and the UTXO
    /// list scan the whole UTXO set and see every coin. It is a narrower claim
    /// than it used to be, and a stated one.
    async fn l1_history(state: &Arc<DaemonState>, limit: u32, offset: u32) -> Response {
        let store = match history_store_for(state).await {
            Ok(s) => s,
            Err(message) => return Response::Error(ErrorResponse { message }),
        };
        let all = store.list();
        let total_count = all.len() as u32;
        let page: Vec<_> = all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();

        let chain = state.chain().await;
        // One tip read for the whole page. Confirmations are derived from the
        // height the scanner recorded, so a settled history costs a single
        // round trip rather than one per row.
        let tip = chain.status().await.ok().and_then(|s| s.chain_height);

        let mut transactions = Vec::with_capacity(page.len());
        for e in page {
            let confirmations = match (e.block_height, tip) {
                // Inclusive of the block it landed in: an entry in the tip
                // block has one confirmation, not zero. That off-by-one is the
                // difference between "spendable" and "invisible".
                (Some(h), Some(t)) if t >= h as u64 => Some((t - h as u64 + 1) as u32),
                // Mined deeper than the tip we just read means the tip moved
                // backwards under us — a reorg the scanner has not caught up
                // with yet. Unknown is the honest answer for one tick.
                (Some(_), Some(_)) => None,
                (Some(_), None) => None,
                // Never seen in a block. Ask the node whether it at least
                // holds the transaction, which distinguishes "in the mempool"
                // from "the node has never heard of this".
                (None, _) => chain.tx_confirmations(&e.txid).await.unwrap_or(None),
            };
            transactions.push(LightHistoryEntry {
                txid: e.txid,
                block_height: e.block_height,
                timestamp: e.at,
                amount_sats: e.amount_sats,
                fee_sats: e.fee_sats,
                tx_type: e.kind,
                confirmations,
                memo: e.memo,
            });
        }
        Response::LightHistory(LightHistoryResponse {
            transactions,
            total_count,
        })
    }

    /// One lane-name parser, so every caller accepts the same words.
    fn parse_lane(lane: &str) -> Result<wraith_wallet_core::ghost_lock_account::LaneKind, String> {
        use wraith_wallet_core::ghost_lock_account::LaneKind;
        match lane.trim().to_ascii_lowercase().as_str() {
            "savings" => Ok(LaneKind::Savings),
            "spending" => Ok(LaneKind::Spending),
            "cash" => Ok(LaneKind::Cash),
            "investments" => Ok(LaneKind::Investments),
            other => Err(format!(
                "unknown lane '{other}' (try savings, spending, cash, investments)"
            )),
        }
    }

    /// Resolve a lane and the escape its owner can take.
    ///
    /// Refuses the lanes with no owner escape by name. Cash has no leaves at
    /// all — it is the owner's key on the key path, so there is nothing to
    /// escape from.
    async fn lock_escape_for(
        state: &Arc<DaemonState>,
        lock_id: &str,
        lane: &str,
    ) -> Result<
        (
            wraith_wallet_core::ghost_lock_account::GhostLockAccount,
            wraith_wallet_core::ghost_lock_account::LaneKind,
            wraith_wallet_core::ghost_lock_store::StoredLock,
            ghost_lock::escape::OwnerEscape,
        ),
        String,
    > {
        use ghost_lock::escape::OwnerEscape;
        use wraith_wallet_core::ghost_lock_account::LaneKind;

        // Resolve the lane BEFORE loading the Lock. Both orders are correct;
        // only this one is useful. Asking about Cash with an unknown lock_id
        // should say Cash has no escape, not that the Lock is missing — the
        // second answer sends someone looking for the wrong problem.
        let kind = parse_lane(lane)?;
        let escape = match kind {
            LaneKind::Savings => OwnerEscape::SavingsRecovery,
            LaneKind::Spending => OwnerEscape::SpendingExit,
            LaneKind::Investments => OwnerEscape::InvestmentsRecall,
            LaneKind::Cash => {
                return Err(
                    "Cash has no escape leaf: it already spends with your key alone, so \
                     there is nothing to wait for"
                        .into(),
                )
            }
        };
        let (account, kind, record) = lock_lane_for(state, lock_id, lane).await?;
        Ok((account, kind, record, escape))
    }

    /// Decode a base64 PSBT and pull out every prevout.
    ///
    /// Every one, because a Taproot sighash commits to all of them. A missing
    /// prevout is refused rather than defaulted: the signature would be over a
    /// transaction different from the one presented.
    fn decode_psbt_with_prevouts(
        psbt_b64: &str,
    ) -> Result<(bitcoin::psbt::Psbt, Vec<bitcoin::TxOut>), String> {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(psbt_b64.trim())
            .map_err(|e| format!("psbt is not base64: {e}"))?;
        let psbt = bitcoin::psbt::Psbt::deserialize(&raw).map_err(|e| format!("psbt: {e}"))?;
        let mut prevouts = Vec::with_capacity(psbt.inputs.len());
        for (i, input) in psbt.inputs.iter().enumerate() {
            let utxo = input.witness_utxo.as_ref().ok_or_else(|| {
                format!(
                    "input {i} has no witness_utxo, so its value and script are unknown — \
                     the Taproot sighash commits to every input, so this cannot be signed \
                     correctly"
                )
            })?;
            prevouts.push(utxo.clone());
        }
        Ok((psbt, prevouts))
    }

    /// Which keys spend a lane by its key path.
    ///
    /// Not one answer for the whole Lock: each lane's Taproot internal key is a
    /// different thing, and signing under the wrong pair produces a signature
    /// that fails against the address with nothing to say why.
    ///
    ///   * **Savings** — MuSig2 of owner + backup. The air-gapped case.
    ///   * **Spending** — MuSig2 of owner + quorum. Networked.
    ///   * **Cash** — the owner's key alone. Ordinary single-sig; a MuSig2
    ///     ceremony here would be two rounds of theatre.
    ///   * **Investments** — the quorum's key alone. The owner cannot spend it
    ///     by the key path at all; the owner's route out is the recall leaf.
    fn lane_cosigners(
        kind: wraith_wallet_core::ghost_lock_account::LaneKind,
        owner: bitcoin::XOnlyPublicKey,
        record: &wraith_wallet_core::ghost_lock_store::StoredLock,
    ) -> Result<Vec<bitcoin::XOnlyPublicKey>, String> {
        use std::str::FromStr;
        use wraith_wallet_core::ghost_lock_account::LaneKind;
        let parse = |label: &str, hexstr: &str| {
            bitcoin::XOnlyPublicKey::from_str(hexstr.trim())
                .map_err(|e| format!("{label} is not an x-only public key: {e}"))
        };
        match kind {
            LaneKind::Savings => Ok(vec![owner, parse("backup_pubkey", &record.backup_pubkey)?]),
            LaneKind::Spending => Ok(vec![owner, parse("quorum_pubkey", &record.quorum_pubkey)?]),
            LaneKind::Cash => Err(
                "Cash spends with your key alone — sign it as an ordinary single-sig input, \
                 not through a MuSig2 ceremony"
                    .into(),
            ),
            LaneKind::Investments => Err(
                "Investments spends by the quorum's key alone, so there is no key path for \
                 you to co-sign; your route out is the recall leaf after its delay"
                    .into(),
            ),
        }
    }

    /// The owner's signing key for a Lock, from the active keystore.
    async fn lock_owner_seckey(
        state: &Arc<DaemonState>,
        bip86_index: u32,
    ) -> Result<bitcoin::secp256k1::SecretKey, String> {
        with_active_wallet(state, move |_, ks| {
            let path = format!(
                "m/86'/{}'/0'/0/{bip86_index}",
                wraith_wallet_core::light::GHOST_COIN_TYPE
            );
            let xprv = ks.derive_xprv(&path).map_err(|e| format!("derive: {e}"))?;
            bitcoin::secp256k1::SecretKey::from_slice(&xprv.private_key().to_bytes())
                .map_err(|e| format!("owner key: {e}"))
        })
        .await
    }

    /// Attach a finished key-path signature to the PSBT input.
    ///
    /// A key-path spend's witness is the signature and nothing else, so this is
    /// the whole of finalisation for that input.
    fn attach_key_path_signature(
        psbt_b64: &str,
        input_index: u32,
        sig: &bitcoin::secp256k1::schnorr::Signature,
    ) -> Result<String, String> {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(psbt_b64.trim())
            .map_err(|e| format!("psbt is not base64: {e}"))?;
        let mut psbt = bitcoin::psbt::Psbt::deserialize(&raw).map_err(|e| format!("psbt: {e}"))?;
        let idx = input_index as usize;
        let input = psbt
            .inputs
            .get_mut(idx)
            .ok_or_else(|| format!("input {idx} does not exist"))?;
        input.tap_key_sig = Some(bitcoin::taproot::Signature {
            signature: *sig,
            sighash_type: bitcoin::TapSighashType::Default,
        });
        let mut witness = bitcoin::Witness::new();
        witness.push(sig.serialize());
        input.final_script_witness = Some(witness);
        Ok(base64::engine::general_purpose::STANDARD.encode(psbt.serialize()))
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
                    chain_height: s.chain_height,
                    chain_headers: s.chain_headers,
                    chain_verification_progress: s.chain_verification_progress,
                    chain_initial_block_download: s.chain_initial_block_download,
                }),
                Err(e) => Response::Error(ErrorResponse {
                    message: format!("chain: {e}"),
                }),
            },
            Request::ConnectionStatus => {
                // One probe answers "is the node reachable" AND supplies the
                // chain fields. An unreachable node is reported as a field
                // rather than as an error: the point of this call is a header
                // that says "unreachable" instead of spinning forever.
                let node_configured = state.ghostd().await.url.is_some();
                let (node_reachable, node_version, node_error, chain_height, chain_headers, ibd) =
                    match state.chain().await.status().await {
                        Ok(s) => (
                            true,
                            Some(s.backend_version),
                            None,
                            s.chain_height,
                            s.chain_headers,
                            s.chain_initial_block_download,
                        ),
                        // With no node configured there is nothing to be
                        // unreachable, and `NoChain`'s refusal is a setup
                        // instruction rather than a probe failure — so it is
                        // not reported as one.
                        Err(e) => (
                            false,
                            None,
                            node_configured.then(|| format!("{e}")),
                            None,
                            None,
                            None,
                        ),
                    };
                // Same rule the GUI's SyncIndicator uses: verified height has
                // caught the header tip (or headers unknown) AND the node is
                // out of initial block download.
                let chain_synced = node_reachable
                    && chain_height.is_some()
                    && chain_headers.is_none_or(|h| chain_height.unwrap_or(0) >= h)
                    && ibd == Some(false);
                Response::ConnectionStatus(ConnectionStatusResponse {
                    network: network_label(state.network).to_string(),
                    node_configured,
                    node_reachable,
                    node_version,
                    node_error,
                    chain_height,
                    chain_headers,
                    chain_synced,
                })
            }
            Request::LightBalance => match l1_balance(state, 1024).await {
                Ok((confirmed, unconfirmed, _height)) => {
                    Response::LightBalance(LightBalanceResponse {
                        confirmed_sats: Some(confirmed),
                        unconfirmed_sats: Some(unconfirmed),
                        // An operator-side concept with no on-chain meaning.
                        // `None` says "not applicable" rather than claiming
                        // nothing is locked.
                        locked_sats: None,
                        received_at: Some(now_unix_secs() as i64),
                    })
                }
                Err(message) => Response::Error(ErrorResponse { message }),
            },
            Request::LightUtxos { min_confirmations } => {
                match l1_utxo_entries(state, 1024, min_confirmations).await {
                    Ok((utxos, total_sats)) => {
                        Response::LightUtxos(LightUtxosResponse { utxos, total_sats })
                    }
                    Err(message) => Response::Error(ErrorResponse { message }),
                }
            }
            Request::GhostLockSave {
                label,
                backup_pubkey,
                heir_pubkey,
                quorum_pubkey,
                anchor_height,
                inherit_height,
                bip86_index,
            } => {
                use wraith_wallet_core::ghost_lock_store::StoredLock;
                let lock = StoredLock::new(
                    label,
                    backup_pubkey,
                    heir_pubkey,
                    quorum_pubkey,
                    anchor_height,
                    inherit_height,
                    bip86_index.unwrap_or(0),
                );
                match ghost_lock_store_for(state) {
                    Err(e) => Response::Error(ErrorResponse {
                        message: format!("lock store: {e}"),
                    }),
                    Ok(mut store) => {
                        let created = store.get(&lock.lock_id).is_none();
                        match store.put(lock.clone()) {
                            Err(e) => Response::Error(ErrorResponse {
                                message: format!("save lock: {e}"),
                            }),
                            Ok(()) => Response::GhostLockSaved(GhostLockSavedResponse {
                                lock: lock_record(&lock),
                                created,
                            }),
                        }
                    }
                }
            }
            Request::GhostLockQuorumSign {
                lock_id,
                lane,
                psbt,
                input_index,
                coordinator_url,
            } => {
                use wraith_wallet_core::ghost_lock_account::LaneKind;
                let (account, kind, record) = match lock_lane_for(state, &lock_id, &lane).await {
                    Ok(v) => v,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }))
                    }
                };
                if kind != LaneKind::Spending {
                    return Envelope::new(
                        id,
                        Response::Error(ErrorResponse {
                            message: format!(
                                "the quorum only co-signs Spending; {} is signed another way",
                                kind.label()
                            ),
                        }),
                    );
                }
                let Some(built) = account.lanes.iter().find(|l| l.kind == kind) else {
                    return Envelope::new(
                        id,
                        Response::Error(ErrorResponse {
                            message: "Lock has no Spending lane".into(),
                        }),
                    );
                };
                let root = built.lane.spend_info.merkle_root();

                let owner_sk = match lock_owner_seckey(state, record.bip86_index).await {
                    Ok(k) => k,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }))
                    }
                };
                let owner_xonly = owner_sk
                    .x_only_public_key(&bitcoin::secp256k1::Secp256k1::new())
                    .0;
                let keys = match lane_cosigners(kind, owner_xonly, &record) {
                    Ok(k) => k,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }))
                    }
                };

                let request = ghost_lock::airgap::SigningRequest {
                    psbt: psbt.clone(),
                    input_index,
                    keys: keys.iter().map(|k| hex::encode(k.serialize())).collect(),
                    merkle_root: root.map(|r| {
                        use bitcoin::hashes::Hash as _;
                        hex::encode(r.to_byte_array())
                    }),
                };

                let (summary, message) = match ghost_lock::airgap::review(&request, state.network) {
                    Ok(v) => v,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("review: {e}"),
                            }),
                        )
                    }
                };

                // The input must be the lane's, checked here rather than trusted
                // from whoever supplied the PSBT.
                let expected = built.lane.address.to_string();
                if summary.input_address.as_deref() != Some(expected.as_str()) {
                    return Envelope::new(
                        id,
                        Response::Error(ErrorResponse {
                            message: format!(
                                "input {input_index} is not the Spending lane: it pays to {}, \
                                 the lane is {expected}",
                                summary
                                    .input_address
                                    .as_deref()
                                    .unwrap_or("an unrenderable script")
                            ),
                        }),
                    );
                }

                let mut ledger = match ghost_lock_nonce_ledger_for(state) {
                    Ok(l) => l,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("nonce ledger unavailable: {e}"),
                            }),
                        )
                    }
                };

                let (sig, view) = match wraith_wallet_core::lock_cosign_client::cosign_with_quorum(
                    &state.http,
                    &coordinator_url,
                    &lock_id,
                    &request,
                    &owner_sk,
                    &keys,
                    root,
                    &message,
                    &mut ledger,
                )
                .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("{e}"),
                            }),
                        )
                    }
                };

                let psbt_out = match attach_key_path_signature(&psbt, input_index, &sig) {
                    Ok(p) => p,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }))
                    }
                };
                // The finished transaction, when every input is signed. A
                // multi-input spend may still be waiting on somebody else, so
                // an empty string here means "signed, not yet complete" rather
                // than a failure — the PSBT above is the thing to pass on.
                let tx_hex = {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD
                        .decode(psbt_out.trim())
                        .ok()
                        .and_then(|raw| bitcoin::psbt::Psbt::deserialize(&raw).ok())
                        .and_then(|p| p.extract_tx().ok())
                        .map(|tx| bitcoin::consensus::encode::serialize_hex(&tx))
                        .unwrap_or_default()
                };

                Response::GhostLockQuorumSigned(GhostLockQuorumSignedResponse {
                    lock_id,
                    signature: hex::encode(sig.serialize()),
                    psbt: psbt_out,
                    tx_hex,
                    quorum_saw_input_sats: view.input_sats,
                    quorum_saw_fee_sats: view.fee_sats,
                })
            }

            Request::GhostLockEscapePlan { lock_id, lane } => {
                let (account, kind, _record, escape) =
                    match lock_escape_for(state, &lock_id, &lane).await {
                        Ok(v) => v,
                        Err(message) => {
                            return Envelope::new(id, Response::Error(ErrorResponse { message }))
                        }
                    };
                let Some(built) = account.lanes.iter().find(|l| l.kind == kind) else {
                    return Envelope::new(
                        id,
                        Response::Error(ErrorResponse {
                            message: format!("Lock has no {} lane", kind.label()),
                        }),
                    );
                };
                let address = built.lane.address.to_string();

                let seq = match ghost_lock::escape::escape_sequence(escape.blocks()) {
                    Ok(s) => s,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("sequence: {e}"),
                            }),
                        )
                    }
                };

                // Scanned at zero confirmations so an immature coin is listed
                // with the wait still to go, rather than being invisible until
                // it is already spendable.
                let scan = match state
                    .chain()
                    .await
                    .scan_utxos(std::slice::from_ref(&address), 0)
                    .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("scan: {e}"),
                            }),
                        )
                    }
                };
                let coins: Vec<EscapeCoin> = scan
                    .utxos
                    .iter()
                    .map(|u| EscapeCoin {
                        txid: u.txid.clone(),
                        vout: u.vout,
                        sats: u.amount_sats,
                        confirmations: u.confirmations,
                        blocks_remaining: escape.blocks().saturating_sub(u.confirmations),
                    })
                    .collect();

                Response::GhostLockEscapePlan(GhostLockEscapePlanResponse {
                    lock_id,
                    lane: kind.label().to_ascii_lowercase(),
                    escape: escape.label().to_string(),
                    delay_blocks: escape.blocks(),
                    required_sequence: seq.0,
                    lane_address: address,
                    coins,
                })
            }

            Request::GhostLockEscapeSign {
                lock_id,
                lane,
                psbt,
                input_index,
            } => {
                let (account, kind, record, escape) =
                    match lock_escape_for(state, &lock_id, &lane).await {
                        Ok(v) => v,
                        Err(message) => {
                            return Envelope::new(id, Response::Error(ErrorResponse { message }))
                        }
                    };
                let Some(built) = account.lanes.iter().find(|l| l.kind == kind) else {
                    return Envelope::new(
                        id,
                        Response::Error(ErrorResponse {
                            message: format!("Lock has no {} lane", kind.label()),
                        }),
                    );
                };

                let owner_sk = match lock_owner_seckey(state, record.bip86_index).await {
                    Ok(k) => k,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }))
                    }
                };
                let owner_xonly = owner_sk
                    .x_only_public_key(&bitcoin::secp256k1::Secp256k1::new())
                    .0;
                let leaf = match escape.leaf(&owner_xonly) {
                    Ok(l) => l,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("leaf: {e}"),
                            }),
                        )
                    }
                };

                let (mut parsed, prevouts) = match decode_psbt_with_prevouts(&psbt) {
                    Ok(v) => v,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }))
                    }
                };

                // The input must be this lane's. Otherwise the daemon would
                // sign whatever input it was pointed at, on the say-so of
                // whoever supplied the PSBT.
                let idx = input_index as usize;
                let Some(prev) = prevouts.get(idx) else {
                    return Envelope::new(
                        id,
                        Response::Error(ErrorResponse {
                            message: format!("input {idx} does not exist"),
                        }),
                    );
                };
                if prev.script_pubkey != built.lane.address.script_pubkey() {
                    return Envelope::new(
                        id,
                        Response::Error(ErrorResponse {
                            message: format!(
                                "input {idx} is not the {} lane — it pays to a different script",
                                kind.label()
                            ),
                        }),
                    );
                }

                let witness = match ghost_lock::escape::sign_escape(
                    &built.lane,
                    &leaf,
                    escape.blocks(),
                    &owner_sk,
                    &parsed.unsigned_tx,
                    idx,
                    &prevouts,
                ) {
                    Ok(w) => w,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("{e}"),
                            }),
                        )
                    }
                };

                parsed.inputs[idx].final_script_witness = Some(witness);
                let tx_hex = match parsed.clone().extract_tx() {
                    Ok(tx) => bitcoin::consensus::encode::serialize_hex(&tx),
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!(
                                    "the spend is signed but not complete ({e}); every input \
                                     needs its own witness before this can be broadcast"
                                ),
                            }),
                        )
                    }
                };
                use base64::Engine as _;
                Response::GhostLockEscapeSigned(GhostLockEscapeSignedResponse {
                    lock_id,
                    lane: kind.label().to_ascii_lowercase(),
                    escape: escape.label().to_string(),
                    psbt: base64::engine::general_purpose::STANDARD.encode(parsed.serialize()),
                    tx_hex,
                })
            }

            Request::GhostLockSignBegin {
                lock_id,
                lane,
                psbt,
                input_index,
            } => {
                let (account, kind, record) = match lock_lane_for(state, &lock_id, &lane).await {
                    Ok(v) => v,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }))
                    }
                };
                let Some(built) = account.lanes.iter().find(|l| l.kind == kind) else {
                    return Envelope::new(
                        id,
                        Response::Error(ErrorResponse {
                            message: format!("Lock has no {} lane", kind.label()),
                        }),
                    );
                };

                let root = built.lane.spend_info.merkle_root();

                let owner_sk = match lock_owner_seckey(state, record.bip86_index).await {
                    Ok(k) => k,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }))
                    }
                };
                let owner_xonly = owner_sk
                    .x_only_public_key(&bitcoin::secp256k1::Secp256k1::new())
                    .0;
                let keys = match lane_cosigners(kind, owner_xonly, &record) {
                    Ok(k) => k,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }))
                    }
                };

                let request = ghost_lock::airgap::SigningRequest {
                    psbt: psbt.clone(),
                    input_index,
                    keys: keys.iter().map(|k| hex::encode(k.serialize())).collect(),
                    merkle_root: root.map(|r| {
                        use bitcoin::hashes::Hash as _;
                        hex::encode(r.to_byte_array())
                    }),
                };

                let (summary, message) = match ghost_lock::airgap::review(&request, state.network) {
                    Ok(v) => v,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("review: {e}"),
                            }),
                        )
                    }
                };

                // The input must be the lane's. Without this the daemon would
                // happily sign an input belonging to somebody else's script,
                // on the say-so of whoever supplied the PSBT.
                let expected = built.lane.address.to_string();
                if summary.input_address.as_deref() != Some(expected.as_str()) {
                    return Envelope::new(
                        id,
                        Response::Error(ErrorResponse {
                            message: format!(
                                "input {input_index} is not the {} lane: it pays to {},                                  the lane is {expected}",
                                kind.label(),
                                summary.input_address.as_deref().unwrap_or("an unrenderable script")
                            ),
                        }),
                    );
                }

                let (session, commitment) = match ghost_lock::signing::SigningSession::begin(
                    &keys, &owner_sk, root, &message,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("round 1: {e}"),
                            }),
                        )
                    }
                };

                let session_hex = hex::encode(commitment.session.as_bytes());
                let our_nonce = commitment.public_nonce;
                state.lock_signings.write().await.insert(
                    session_hex.clone(),
                    PendingLockSign {
                        keys,
                        merkle_root: root,
                        message,
                        psbt,
                        input_index,
                        our_nonce,
                        session: Some(session),
                        nonces: Vec::new(),
                        our_partial: None,
                    },
                );

                Response::GhostLockSignBegun(GhostLockSignBegunResponse {
                    session: session_hex,
                    summary: lock_spend_summary(&summary),
                    device_request: match serde_json::to_string_pretty(&request) {
                        Ok(j) => j,
                        Err(e) => {
                            return Envelope::new(
                                id,
                                Response::Error(ErrorResponse {
                                    message: format!("device request: {e}"),
                                }),
                            )
                        }
                    },
                    our_nonce: hex::encode(our_nonce),
                })
            }

            Request::GhostLockSignNonce {
                session,
                device_nonce,
            } => {
                let device = match unhex66("device_nonce", &device_nonce) {
                    Ok(v) => v,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }))
                    }
                };

                let mut guard = state.lock_signings.write().await;
                let Some(pending) = guard.get_mut(&session) else {
                    return Envelope::new(
                        id,
                        Response::Error(ErrorResponse {
                            message: format!(
                                "no signing session '{session}' — a daemon restart drops \
                                 these, which is safe: start again with `lock sign begin`"
                            ),
                        }),
                    );
                };
                let Some(sess) = pending.session.take() else {
                    return Envelope::new(
                        id,
                        Response::Error(ErrorResponse {
                            message: "this session already has its nonce round; the next step \
                                      is `lock sign complete`"
                                .into(),
                        }),
                    );
                };

                // Nonce order must match what every party aggregates. Sorted,
                // so both sides reach the same aggregate without agreeing who
                // goes first — the same reason the keys are sorted.
                let mut nonces = vec![pending.our_nonce, device];
                nonces.sort_unstable();

                // Sign now, while both nonces are known. After this the daemon
                // holds no secret nonce, so none is sitting in memory while the
                // second payload is carried to the device.
                let mut ledger = match ghost_lock_nonce_ledger_for(state) {
                    Ok(l) => l,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("nonce ledger unavailable: {e}"),
                            }),
                        )
                    }
                };
                let partial = match sess.sign(&mut ledger, &nonces) {
                    Ok(p) => p,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("round 2: {e}"),
                            }),
                        )
                    }
                };
                pending.nonces = nonces.clone();
                pending.our_partial = Some(partial);

                let req = ghost_lock::airgap::PartialRequest {
                    session: session.clone(),
                    public_nonces: nonces.iter().map(hex::encode).collect(),
                };
                Response::GhostLockSignNonced(GhostLockSignNoncedResponse {
                    session,
                    device_request: match serde_json::to_string_pretty(&req) {
                        Ok(j) => j,
                        Err(e) => {
                            return Envelope::new(
                                id,
                                Response::Error(ErrorResponse {
                                    message: format!("device request: {e}"),
                                }),
                            )
                        }
                    },
                })
            }

            Request::GhostLockSignComplete {
                session,
                device_partial,
            } => {
                let device = match unhex32("device_partial", &device_partial) {
                    Ok(v) => v,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }))
                    }
                };

                let mut guard = state.lock_signings.write().await;
                let Some(pending) = guard.get(&session) else {
                    return Envelope::new(
                        id,
                        Response::Error(ErrorResponse {
                            message: format!("no signing session '{session}'"),
                        }),
                    );
                };
                let Some(ours) = pending.our_partial else {
                    return Envelope::new(
                        id,
                        Response::Error(ErrorResponse {
                            message: "this session has not completed its nonce round yet".into(),
                        }),
                    );
                };

                let sig = match ghost_lock::signing::combine(
                    &pending.keys,
                    pending.merkle_root,
                    &pending.nonces,
                    &[ours, device],
                    &pending.message,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("combine: {e}"),
                            }),
                        )
                    }
                };

                let psbt_out =
                    match attach_key_path_signature(&pending.psbt, pending.input_index, &sig) {
                        Ok(p) => p,
                        Err(message) => {
                            return Envelope::new(id, Response::Error(ErrorResponse { message }))
                        }
                    };
                let out = Response::GhostLockSigned(GhostLockSignedResponse {
                    session: session.clone(),
                    signature: hex::encode(sig.serialize()),
                    psbt: psbt_out,
                });
                guard.remove(&session);
                out
            }

            Request::GhostLockRoundDestination { lock_id, lane } => {
                use wraith_wallet_core::ghost_lock_account::LaneKind;

                // Name the lane, never accept an address. The whole point of
                // private entry is that the round's output IS the lane, so if
                // a caller could hand in an arbitrary address then "fund my
                // Savings privately" and "pay this stranger" would be the same
                // request with the same audit trail.
                let kind = match lane.trim().to_ascii_lowercase().as_str() {
                    "savings" => LaneKind::Savings,
                    "spending" => LaneKind::Spending,
                    "cash" => LaneKind::Cash,
                    "investments" => LaneKind::Investments,
                    other => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!(
                                "unknown lane '{other}' (try savings, spending, cash, investments)"
                            ),
                            }),
                        )
                    }
                };

                // Refused here rather than in the CLI. A rule enforced only in
                // the client is enforced only for clients that ask nicely.
                if let Err(e) = ghost_lock::check_round_destination(kind.compartment()) {
                    return Envelope::new(
                        id,
                        Response::Error(ErrorResponse {
                            message: format!("{} lane: {e}", kind.label()),
                        }),
                    );
                }

                let record = match ghost_lock_store_for(state) {
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("lock store: {e}"),
                            }),
                        )
                    }
                    Ok(store) => match store.get(&lock_id) {
                        Some(l) => l.clone(),
                        None => {
                            return Envelope::new(
                                id,
                                Response::Error(ErrorResponse {
                                    message: format!(
                                        "no remembered Lock '{lock_id}' — `wraith lock list` shows the ones this wallet knows"
                                    ),
                                }),
                            )
                        }
                    },
                };

                let account = match build_lock_account(
                    state,
                    &record.backup_pubkey,
                    &record.heir_pubkey,
                    &record.quorum_pubkey,
                    record.inherit_height,
                    record.anchor_height,
                    Some(record.bip86_index),
                )
                .await
                {
                    Ok(a) => a,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }))
                    }
                };

                match account.lanes.iter().find(|l| l.kind == kind) {
                    Some(built) => {
                        Response::GhostLockRoundDestination(GhostLockRoundDestinationResponse {
                            lock_id: record.lock_id.clone(),
                            lane: lane.trim().to_ascii_lowercase(),
                            label: kind.label().to_string(),
                            address: built.lane.address.to_string(),
                        })
                    }
                    None => Response::Error(ErrorResponse {
                        message: format!("Lock has no {} lane", kind.label()),
                    }),
                }
            }
            Request::GhostLockList => match ghost_lock_store_for(state) {
                Err(e) => Response::Error(ErrorResponse {
                    message: format!("lock store: {e}"),
                }),
                Ok(store) => Response::GhostLockList(GhostLockListResponse {
                    locks: store.list().iter().map(lock_record).collect(),
                }),
            },
            Request::GhostLockForget { lock_id } => match ghost_lock_store_for(state) {
                Err(e) => Response::Error(ErrorResponse {
                    message: format!("lock store: {e}"),
                }),
                Ok(mut store) => match store.remove(&lock_id) {
                    Err(e) => Response::Error(ErrorResponse {
                        message: format!("forget lock: {e}"),
                    }),
                    Ok(existed) => Response::GhostLockForgotten(GhostLockForgottenResponse {
                        lock_id,
                        existed,
                    }),
                },
            },
            Request::GhostLockLanes {
                backup_pubkey,
                heir_pubkey,
                quorum_pubkey,
                inherit_height,
                anchor_height,
                bip86_index,
            } => {
                use wraith_wallet_core::ghost_lock_account::balances;

                let account = match build_lock_account(
                    state,
                    &backup_pubkey,
                    &heir_pubkey,
                    &quorum_pubkey,
                    inherit_height,
                    anchor_height,
                    bip86_index,
                )
                .await
                {
                    Ok(a) => a,
                    Err(message) => {
                        return Envelope::new(id, Response::Error(ErrorResponse { message }))
                    }
                };

                let addresses: Vec<String> = account
                    .lanes
                    .iter()
                    .map(|l| l.lane.address.to_string())
                    .collect();

                // Scanned at ZERO confirmations, then split. One round trip
                // gives both figures, and the split happens here rather than
                // being two scans that could disagree with each other.
                let scan = match state.chain().await.scan_utxos(&addresses, 0).await {
                    Ok(s) => s,
                    Err(e) => {
                        return Envelope::new(
                            id,
                            Response::Error(ErrorResponse {
                                message: format!("scan: {e}"),
                            }),
                        )
                    }
                };

                // Attribute each UTXO to its lane by address.
                let mut per_lane: Vec<wraith_wallet_core::ghost_lock_account::LaneCoin> =
                    Vec::new();
                for u in &scan.utxos {
                    // A UTXO the scanner could not attribute to an address is
                    // skipped rather than guessed at. Guessing would put
                    // somebody's coins in the wrong compartment, and the
                    // compartments are the point.
                    let Some(addr) = u.address.as_deref() else {
                        continue;
                    };
                    if let Some(b) = account
                        .lanes
                        .iter()
                        .find(|l| l.lane.address.to_string() == addr)
                    {
                        per_lane.push(wraith_wallet_core::ghost_lock_account::LaneCoin {
                            kind: b.kind,
                            sats: u.amount_sats,
                            confirmations: u.confirmations,
                        });
                    }
                }

                let b = balances(&account, &per_lane);
                Response::GhostLockLanes(GhostLockLanesResponse {
                    lanes: b
                        .lanes
                        .iter()
                        .map(|l| GhostLockLane {
                            kind: format!("{:?}", l.kind).to_lowercase(),
                            label: l.label.clone(),
                            address: l.address.clone(),
                            balance_sats: l.balance_sats,
                            pending_sats: l.pending_sats,
                            quorum_can_spend_alone: l.quorum_can_spend_alone,
                            round_eligible: l.round_eligible,
                        })
                        .collect(),
                    total_sats: b.total_sats,
                    total_pending_sats: b.total_pending_sats,
                    custodial_sats: b.custodial_sats,
                    chain_height: scan.chain_height,
                })
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
            Request::DaemonEnv => {
                let network = match state.network {
                    bitcoin::Network::Bitcoin => "mainnet",
                    bitcoin::Network::Signet => "signet",
                    bitcoin::Network::Testnet => "testnet",
                    bitcoin::Network::Regtest => "regtest",
                    _ => "unknown",
                }
                .to_string();
                let ghostd = state.ghostd().await;
                Response::DaemonEnv(DaemonEnvResponse {
                    ghostd_url: ghostd.url.clone(),
                    ghostd_auth: ghostd.auth_kind().to_string(),
                    ghostd_env_override: state.ghostd_env_override,
                    pool_url: state.pool_url.read().await.clone(),
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
            Request::SetNode {
                ghostd_url,
                cookie_path,
                user,
                pass,
                pool_url,
            } => match state
                .set_node(
                    GhostdSettings {
                        url: ghostd_url,
                        cookie_path: cookie_path.map(PathBuf::from),
                        user,
                        pass,
                    },
                    pool_url,
                )
                .await
            {
                Ok(applied) => Response::NodeSet(applied),
                Err(message) => Response::Error(ErrorResponse { message }),
            },
            Request::CheckForUpdate { manifest_url } => {
                match check_for_update(state, manifest_url).await {
                    Ok(r) => Response::CheckForUpdate(r),
                    Err(message) => Response::Error(ErrorResponse { message }),
                }
            }
            Request::LightDetected => match detection_store_for(state).await {
                Err(e) => Response::Error(ErrorResponse {
                    message: format!("detections: {e}"),
                }),
                Ok(store) => Response::LightDetected(LightDetectedResponse {
                    detections: store
                        .list()
                        .into_iter()
                        .map(|d| DetectedPaymentEntry {
                            txid: d.txid,
                            vout: d.vout,
                            amount_sats: d.amount_sats,
                            block_height: d.block_height,
                            k: d.k,
                            received_at: d.received_at,
                        })
                        .collect(),
                }),
            },
            Request::LightHistory { limit, offset } => {
                return Envelope::new(id, l1_history(state, limit, offset).await)
            }
            Request::L1Send {
                recipient_address,
                amount_sats,
                fee_rate_sats_per_vb,
                change_index,
                bip86_scan_max,
                selected_outpoints,
                memo,
                shroud_max_ms,
            } => match l1_send(
                state,
                L1SendParams {
                    recipient_address,
                    amount_sats,
                    fee_rate_sats_per_vb,
                    change_index,
                    bip86_scan_max,
                    selected_outpoints,
                    memo,
                    shroud_override_ms: shroud_max_ms,
                },
            )
            .await
            {
                Ok(r) => Response::L1Sent(r),
                Err(message) => Response::Error(ErrorResponse { message }),
            },
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
                                    // A wallet cannot have been paid before it
                                    // existed, so the tip is its birth height
                                    // and the scanner need never look further
                                    // back than this.
                                    let tip = current_tip(state).await;
                                    record_birth_height(state, &name, tip).await;
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
                birth_height,
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
                                    // Whatever the owner said, and nothing if
                                    // they said nothing. Defaulting to the tip
                                    // here would look like a birth height and
                                    // silently mean "no history before now".
                                    record_birth_height(state, &name, birth_height).await;
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
                // A verified election, or no answer. "No answer" is not a
                // failure here: the caller falls back to a coordinator URL the
                // user supplied, which is a worse answer than a verified
                // election and a better one than obeying an unverifiable claim
                // about who is in charge.
                let (endpoint, epoch) = match verified_election(state).await {
                    Some(election) => {
                        crate::coordinator_resolve::resolve_from_election(&election, &tier_id)
                    }
                    None => (None, None),
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
                match psbt_broadcast_handler(state, &psbt_or_tx_hex, "send", None).await {
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

        /// Minimal `ChainClient` stub. The handlers exercised here refuse
        /// before any I/O, so a status-only error stub is all the
        /// `DaemonState` field needs.
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

        /// A distinct taproot-shaped script, so "ours" and "theirs" can be
        /// told apart without needing real keys.
        fn spk(tag: u8) -> bitcoin::ScriptBuf {
            let mut v = vec![0x51, 0x20];
            v.extend_from_slice(&[tag; 32]);
            bitcoin::ScriptBuf::from_bytes(v)
        }

        /// A PSBT spending `inputs` into `outputs`, each entry a value and the
        /// script tag paying it.
        fn test_psbt(inputs: &[(u64, u8)], outputs: &[(u64, u8)]) -> bitcoin::psbt::Psbt {
            use bitcoin::hashes::Hash;
            use bitcoin::{absolute::LockTime, transaction::Version, Amount, Transaction, TxOut};
            let tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: (0..inputs.len())
                    .map(|i| bitcoin::TxIn {
                        previous_output: bitcoin::OutPoint {
                            txid: bitcoin::Txid::from_byte_array([i as u8; 32]),
                            vout: 0,
                        },
                        ..Default::default()
                    })
                    .collect(),
                output: outputs
                    .iter()
                    .map(|(v, tag)| TxOut {
                        value: Amount::from_sat(*v),
                        script_pubkey: spk(*tag),
                    })
                    .collect(),
            };
            let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx).unwrap();
            for (i, (v, tag)) in inputs.iter().enumerate() {
                psbt.inputs[i].witness_utxo = Some(TxOut {
                    value: Amount::from_sat(*v),
                    script_pubkey: spk(*tag),
                });
            }
            psbt
        }

        /// The net is what the balance will actually move by — the payment
        /// *and* the fee, with change netted back out. A history that showed
        /// only the payment would never reconcile against the balance.
        #[test]
        fn the_net_change_counts_the_fee_and_nets_out_change() {
            let ours: std::collections::HashSet<Vec<u8>> =
                [spk(0xaa).to_bytes()].into_iter().collect();
            // 100,000 of ours in; 50,000 to a stranger, 49,500 back as change.
            let psbt = test_psbt(&[(100_000, 0xaa)], &[(50_000, 0xbb), (49_500, 0xaa)]);
            let (net, fee) = psbt_ledger_effect(&psbt, &ours);
            assert_eq!(fee, Some(500));
            assert_eq!(
                net,
                Some(-50_500),
                "the balance drops by the payment plus the fee, not the payment alone"
            );
        }

        /// A consolidation pays only the miner. It is not a zero-value event.
        #[test]
        fn a_self_send_nets_the_fee_only() {
            let ours: std::collections::HashSet<Vec<u8>> =
                [spk(0xaa).to_bytes()].into_iter().collect();
            let psbt = test_psbt(&[(10_000, 0xaa), (10_000, 0xaa)], &[(19_800, 0xaa)]);
            let (net, fee) = psbt_ledger_effect(&psbt, &ours);
            assert_eq!(fee, Some(200));
            assert_eq!(net, Some(-200));
        }

        /// One input of unknown value makes both figures unknowable. A fee
        /// computed from only the inputs that happened to be present is not a
        /// smaller fee — it is a wrong one, and it would read as authoritative.
        #[test]
        fn a_missing_input_value_yields_no_figures_rather_than_partial_ones() {
            let ours: std::collections::HashSet<Vec<u8>> =
                [spk(0xaa).to_bytes()].into_iter().collect();
            let mut psbt = test_psbt(&[(100_000, 0xaa), (100_000, 0xaa)], &[(199_000, 0xbb)]);
            psbt.inputs[1].witness_utxo = None;
            let (net, fee) = psbt_ledger_effect(&psbt, &ours);
            assert_eq!(fee, None, "a partial fee is a wrong fee");
            assert_eq!(net, None);
        }

        /// A chain stub that answers with a fixed tip, so confirmation
        /// arithmetic can be tested without a node.
        struct TipChain(u64);

        #[async_trait::async_trait]
        impl ChainClient for TipChain {
            async fn status(
                &self,
            ) -> Result<wraith_wallet_core::chain::ChainStatus, wraith_wallet_core::chain::ChainError>
            {
                Ok(wraith_wallet_core::chain::ChainStatus {
                    backend_version: "stub".into(),
                    network: "regtest".into(),
                    chain_height: Some(self.0),
                    chain_headers: Some(self.0),
                    chain_verification_progress: None,
                    chain_initial_block_download: Some(false),
                })
            }
        }

        /// Confirmations count the block the transaction landed in.
        ///
        /// An entry mined in the tip block has one confirmation, not zero.
        /// That off-by-one is the difference between a coin reading as
        /// spendable and reading as not there yet.
        #[tokio::test]
        async fn confirmations_are_inclusive_of_the_mining_block() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_with_wallet(dir.path().to_path_buf()).await;
            state.clients.write().await.chain = Arc::new(TipChain(900_010));

            let mut store = history_store_for(&state).await.unwrap();
            for (txid, height) in [("tip", 900_010u32), ("ten_deep", 900_001)] {
                store
                    .record(wraith_wallet_core::history_store::HistoryEntry {
                        txid: txid.into(),
                        at: 1,
                        block_height: Some(height),
                        amount_sats: Some(1_000),
                        fee_sats: None,
                        kind: "receive".into(),
                        memo: None,
                    })
                    .unwrap();
            }

            match l1_history(&state, 10, 0).await {
                Response::LightHistory(h) => {
                    let by: std::collections::HashMap<_, _> = h
                        .transactions
                        .into_iter()
                        .map(|t| (t.txid.clone(), t))
                        .collect();
                    assert_eq!(by["tip"].confirmations, Some(1), "the tip block counts");
                    assert_eq!(by["ten_deep"].confirmations, Some(10));
                    assert_eq!(by["tip"].block_height, Some(900_010));
                }
                other => panic!("expected history, got {other:?}"),
            }
        }

        /// An entry the scanner has not seen mined must not borrow the tip and
        /// claim a depth. It is unconfirmed, and the honest count is unknown
        /// until the node is asked about it directly.
        #[tokio::test]
        async fn an_unmined_entry_does_not_infer_confirmations_from_the_tip() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_with_wallet(dir.path().to_path_buf()).await;
            state.clients.write().await.chain = Arc::new(TipChain(900_010));

            let mut store = history_store_for(&state).await.unwrap();
            store
                .record(wraith_wallet_core::history_store::HistoryEntry {
                    txid: "pending".into(),
                    at: 1,
                    block_height: None,
                    amount_sats: Some(-1_000),
                    fee_sats: None,
                    kind: "send".into(),
                    memo: None,
                })
                .unwrap();

            match l1_history(&state, 10, 0).await {
                Response::LightHistory(h) => {
                    assert_eq!(h.transactions[0].confirmations, None);
                    assert_eq!(h.transactions[0].block_height, None);
                }
                other => panic!("expected history, got {other:?}"),
            }
        }

        /// One wallet's history must not appear in another's.
        ///
        /// The stores used to sit beside `node.json`, shared by every wallet.
        /// That is wrong twice over: payments show up under the wrong wallet,
        /// and the shared scan bookmark tells the scanner those blocks are
        /// already read — so a wallet switched to would never build a history
        /// at all.
        #[tokio::test]
        async fn two_wallets_do_not_share_a_history() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_in(dir.path().to_path_buf());

            *state.active.write().await = Some("alice".to_string());
            history_store_for(&state)
                .await
                .unwrap()
                .record(wraith_wallet_core::history_store::HistoryEntry {
                    txid: "alice-tx".into(),
                    at: 1,
                    block_height: Some(900_000),
                    amount_sats: Some(1_000),
                    fee_sats: None,
                    kind: "receive".into(),
                    memo: None,
                })
                .unwrap();

            *state.active.write().await = Some("bob".to_string());
            let bob = history_store_for(&state).await.unwrap();
            assert!(
                bob.is_empty(),
                "bob must not see alice's payment, got {:?}",
                bob.list()
            );

            *state.active.write().await = Some("alice".to_string());
            assert_eq!(
                history_store_for(&state).await.unwrap().len(),
                1,
                "and alice must still have her own"
            );
        }

        /// A store keyed on the active wallet has nothing to open when there
        /// is no active wallet, and says so rather than falling back to a
        /// shared file.
        #[tokio::test]
        async fn a_store_without_an_active_wallet_refuses() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_in(dir.path().to_path_buf());
            let err = history_store_for(&state).await.expect_err("must refuse");
            assert!(err.contains("no active wallet"), "got: {err}");
        }

        /// The birth height is what a restore reads forward from. Recording
        /// one and reading it back is the whole contract the scanner relies
        /// on, so it is pinned end to end rather than trusted.
        #[tokio::test]
        async fn a_recorded_birth_height_is_read_back() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_with_wallet(dir.path().to_path_buf()).await;

            assert_eq!(
                wallet_meta_for(&state).await.unwrap().birth_height,
                None,
                "a wallet with no recorded height must not invent one"
            );

            record_birth_height(&state, "harness", Some(880_000)).await;
            assert_eq!(
                wallet_meta_for(&state).await.unwrap().birth_height,
                Some(880_000)
            );
        }

        /// A locked wallet cannot tell its own outputs from a stranger's, so
        /// it records no amount. Recording a `0` would tell the user the
        /// transaction moved nothing, which is the one reading that is
        /// certainly wrong.
        #[tokio::test]
        async fn a_broadcast_without_keys_records_no_amount_rather_than_zero() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_with_wallet(dir.path().to_path_buf()).await;
            let psbt = test_psbt(&[(10_000, 0xaa)], &[(9_500, 0xbb)]);
            record_broadcast(&state, "deadbeef", Some(&psbt), "send", None)
                .await
                .expect("recording must succeed even with no wallet unlocked");
            let store = history_store_for(&state).await.unwrap();
            let rows = store.list();
            assert_eq!(rows.len(), 1);
            assert_eq!(
                rows[0].amount_sats, None,
                "no keys means no amount, not a zero amount"
            );
            assert_eq!(
                rows[0].fee_sats,
                Some(500),
                "the fee needs no keys — it is inputs minus outputs"
            );
        }

        /// A backend that cannot answer must not have its silence rendered as
        /// "unconfirmed" — that would show every settled payment as pending.
        #[tokio::test]
        async fn history_reports_unknown_confirmations_as_unknown() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_with_wallet(dir.path().to_path_buf()).await;
            record_broadcast(&state, "aa11", None, "send", None)
                .await
                .unwrap();
            match l1_history(&state, 10, 0).await {
                Response::LightHistory(h) => {
                    assert_eq!(h.total_count, 1);
                    assert_eq!(
                        h.transactions[0].confirmations, None,
                        "the stub chain cannot say, so the history must not claim zero"
                    );
                }
                other => panic!("expected history, got {other:?}"),
            }
        }

        /// `total_count` is the whole history, not the size of the page — a
        /// pager that reports the page length can never advance past page one.
        #[tokio::test]
        async fn paging_reports_the_full_total_not_the_page_size() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_with_wallet(dir.path().to_path_buf()).await;
            for i in 0..5u32 {
                record_broadcast(&state, &format!("tx{i}"), None, "send", None)
                    .await
                    .unwrap();
            }
            match l1_history(&state, 2, 0).await {
                Response::LightHistory(h) => {
                    assert_eq!(h.transactions.len(), 2, "the page is two");
                    assert_eq!(h.total_count, 5, "the total is five");
                }
                other => panic!("expected history, got {other:?}"),
            }
        }

        /// A session-less `DaemonState` sufficient to exercise
        /// `light_send`'s mode gate. Everything past the gate needs a
        /// live GSP session, which the IPC integration tests cover; here
        /// we only care that the gate accepts/rejects the right modes.
        fn test_state() -> Arc<DaemonState> {
            test_state_in(std::env::temp_dir())
        }

        /// A state whose per-wallet stores resolve, without unlocking a real
        /// keystore. The stores key on the ACTIVE wallet's name; a harness
        /// without one exercises the "no active wallet" path instead of the
        /// behaviour under test.
        async fn test_state_with_wallet(wallets_dir: std::path::PathBuf) -> Arc<DaemonState> {
            let state = test_state_in(wallets_dir);
            *state.active.write().await = Some("harness".to_string());
            state
        }

        fn test_state_in(wallets_dir: std::path::PathBuf) -> Arc<DaemonState> {
            let node_config_path = wallets_dir.join("node.json");
            Arc::new(DaemonState {
                started: Instant::now(),
                clients: RwLock::new(NodeClients {
                    chain: Arc::new(RejectChain),
                }),
                node_config_path,
                tor_proxy: None,
                wraith_coordinator_url: None,
                kiosk_mode: false,
                wallets_dir,
                wallets: RwLock::new(HashMap::new()),
                active: RwLock::new(None),
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
                lock_signings: RwLock::new(HashMap::new()),
                ghostd: RwLock::new(GhostdSettings::default()),
                ghostd_env_override: false,
                pool_url: RwLock::new(None),
                election_cache: RwLock::new(None),
            })
        }

        /// Cash is refused an escape, and told why rather than just "no".
        ///
        /// Every other lane has a leaf that lets the owner leave alone. Cash
        /// does not need one — it already spends with the owner's key on the
        /// key path — and a caller who asks should learn that rather than
        /// conclude the lane is stuck.
        #[tokio::test]
        async fn cash_has_no_escape_and_says_so() {
            let state = test_state();
            let line = serde_json::to_string(&Envelope::new(
                1,
                Request::GhostLockEscapePlan {
                    lock_id: "no-such-lock".into(),
                    lane: "cash".into(),
                },
            ))
            .unwrap();
            let resp = super::dispatch(&line, &state).await;
            let Response::Error(e) = resp.payload else {
                panic!("Cash must not resolve to an escape plan");
            };
            assert!(
                e.message.contains("nothing to wait for"),
                "the refusal must explain, not just decline: {}",
                e.message
            );
            // The lock_id is nonsense on purpose: if the error were about the
            // Lock, the lane check would be running too late to be useful.
            assert!(
                !e.message.contains("no remembered Lock"),
                "Cash must be refused before the Lock lookup: {}",
                e.message
            );
        }

        /// Each lane's key path has different co-signers, and two lanes have
        /// no owner-signable key path at all.
        ///
        /// Getting this wrong does not fail loudly: signing under the wrong
        /// pair produces a well-formed signature that simply does not verify
        /// against the address, discovered at broadcast.
        #[test]
        fn each_lane_names_its_own_cosigners() {
            use std::str::FromStr;
            use wraith_wallet_core::ghost_lock_account::LaneKind;

            let k = |b: u8| {
                let sk = bitcoin::secp256k1::SecretKey::from_slice(&[b; 32]).unwrap();
                sk.x_only_public_key(&bitcoin::secp256k1::Secp256k1::new())
                    .0
            };
            let owner = k(1);
            let backup = k(2);
            let quorum = k(3);
            let record = wraith_wallet_core::ghost_lock_store::StoredLock {
                lock_id: "l".into(),
                label: None,
                backup_pubkey: hex::encode(backup.serialize()),
                heir_pubkey: hex::encode(k(4).serialize()),
                quorum_pubkey: hex::encode(quorum.serialize()),
                anchor_height: 1,
                inherit_height: 2,
                bip86_index: 0,
            };

            // Savings co-signs with the backup device.
            let savings = super::lane_cosigners(LaneKind::Savings, owner, &record).unwrap();
            assert_eq!(savings, vec![owner, backup]);

            // Spending co-signs with the quorum — a DIFFERENT pair.
            let spending = super::lane_cosigners(LaneKind::Spending, owner, &record).unwrap();
            assert_eq!(spending, vec![owner, quorum]);
            assert_ne!(
                savings, spending,
                "the two co-signed lanes must not share a key set"
            );

            // Cash is single-sig; a ceremony here would be theatre.
            let err = super::lane_cosigners(LaneKind::Cash, owner, &record)
                .expect_err("Cash has no MuSig2 key path");
            assert!(err.contains("your key alone"), "{err}");

            // Investments is the quorum's alone — the owner cannot co-sign it.
            let err = super::lane_cosigners(LaneKind::Investments, owner, &record)
                .expect_err("Investments has no owner key path");
            assert!(
                err.contains("recall leaf"),
                "the refusal must name the way out: {err}"
            );

            let _ = bitcoin::XOnlyPublicKey::from_str(&record.backup_pubkey).unwrap();
        }

        /// Private entry must refuse the Cash lane, and refuse it at the gate
        /// — before the Lock is even looked up.
        ///
        /// Tested through `dispatch` rather than a helper because the point of
        /// putting the rule in the daemon is that it holds for anything that
        /// speaks the wire, not just for the CLI that asks nicely.
        #[tokio::test]
        async fn a_round_may_not_be_pointed_at_the_cash_lane() {
            let state = test_state();
            let line = serde_json::to_string(&Envelope::new(
                1,
                Request::GhostLockRoundDestination {
                    lock_id: "no-such-lock".into(),
                    lane: "cash".into(),
                },
            ))
            .unwrap();
            let resp = super::dispatch(&line, &state).await;
            let Response::Error(e) = resp.payload else {
                panic!("Cash must be refused, never resolved to an address");
            };
            assert!(
                e.message.contains("Cash"),
                "the refusal must name the lane: {}",
                e.message
            );
            // The lock_id is deliberately nonsense. If the error is about the
            // Lock not being found, the compartment rule ran too late — a real
            // lock_id would then have sailed past it.
            assert!(
                !e.message.contains("no remembered Lock"),
                "Cash must be refused BEFORE the Lock lookup; got: {}",
                e.message
            );
        }

        /// The three private lanes get past the compartment gate. They stop at
        /// the Lock lookup instead, which is what proves the gate let them
        /// through rather than the request failing for some earlier reason.
        #[tokio::test]
        async fn the_private_lanes_get_past_the_compartment_gate() {
            let state = test_state();
            for lane in ["savings", "spending", "investments"] {
                let line = serde_json::to_string(&Envelope::new(
                    1,
                    Request::GhostLockRoundDestination {
                        lock_id: "no-such-lock".into(),
                        lane: lane.into(),
                    },
                ))
                .unwrap();
                let resp = super::dispatch(&line, &state).await;
                let Response::Error(e) = resp.payload else {
                    panic!("{lane}: a nonexistent Lock cannot resolve to an address");
                };
                assert!(
                    !e.message.contains("cannot pay out into Cash"),
                    "{lane} is a private lane and must not hit the Cash rule: {}",
                    e.message
                );
            }
        }

        /// An unknown lane name is refused, not silently coerced to a default.
        #[tokio::test]
        async fn an_unknown_lane_is_refused() {
            let state = test_state();
            let line = serde_json::to_string(&Envelope::new(
                1,
                Request::GhostLockRoundDestination {
                    lock_id: "no-such-lock".into(),
                    lane: "chequing".into(),
                },
            ))
            .unwrap();
            let resp = super::dispatch(&line, &state).await;
            let Response::Error(e) = resp.payload else {
                panic!("an unknown lane must not resolve to an address");
            };
            assert!(e.message.contains("unknown lane"), "got: {}", e.message);
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
            // With the RejectChain stub standing in for an unreachable node,
            // ConnectionStatus must still return a structured snapshot — NOT
            // a Response::Error. That is what lets the header render a clear
            // "unreachable" state instead of a perpetual "connecting…"
            // spinner on a laptop with nothing running locally.
            let state = test_state();
            let req = serde_json::to_string(&Envelope::new(1, Request::ConnectionStatus)).unwrap();
            let resp = super::dispatch(&req, &state).await;
            match resp.payload {
                Response::ConnectionStatus(s) => {
                    assert_eq!(
                        s.network, "regtest",
                        "network is read from config, not the backend"
                    );
                    assert!(!s.node_reachable, "the stub must read as unreachable");
                    assert!(
                        !s.node_configured,
                        "this harness has no node set, and that is a different \
                         state from one that is set and not answering"
                    );
                    assert!(
                        s.node_error.is_none(),
                        "with no node configured there is nothing to have failed — \
                         reporting a probe error would send the user hunting for a \
                         fault instead of a setting"
                    );
                    assert!(s.node_version.is_none());
                    assert!(!s.chain_synced, "cannot be synced with no node");
                    assert!(s.chain_height.is_none());
                }
                other => panic!("expected ConnectionStatus, got {other:?}"),
            }
        }

        /// `SetNode` must apply at runtime, persist to node.json, and be
        /// reflected by `DaemonEnv` — all without a restart.
        #[tokio::test]
        async fn set_node_applies_persists_and_surfaces() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_in(dir.path().to_path_buf());

            let req = serde_json::to_string(&Envelope::new(
                1,
                Request::SetNode {
                    ghostd_url: Some("https://node.example.com:8332".into()),
                    cookie_path: Some("/home/test/.ghost/.cookie".into()),
                    user: None,
                    pass: None,
                    pool_url: None,
                },
            ))
            .unwrap();
            match super::dispatch(&req, &state).await.payload {
                Response::NodeSet(r) => {
                    assert_eq!(
                        r.ghostd_url.as_deref(),
                        Some("https://node.example.com:8332")
                    );
                    assert_eq!(r.auth, "cookie");
                    assert!(!r.env_pinned);
                }
                other => panic!("expected NodeSet, got {other:?}"),
            }

            let persisted =
                super::load_node_config(&state.node_config_path).expect("node.json written");
            assert_eq!(
                persisted.ghostd.url.as_deref(),
                Some("https://node.example.com:8332")
            );

            let env = serde_json::to_string(&Envelope::new(2, Request::DaemonEnv)).unwrap();
            match super::dispatch(&env, &state).await.payload {
                Response::DaemonEnv(e) => {
                    assert_eq!(
                        e.ghostd_url.as_deref(),
                        Some("https://node.example.com:8332")
                    );
                    assert_eq!(e.ghostd_auth, "cookie");
                    assert!(!e.ghostd_env_override);
                }
                other => panic!("expected DaemonEnv, got {other:?}"),
            }
        }

        /// The pool is optional, and its absence is silence rather than an
        /// error: mixing still works with a coordinator URL supplied per
        /// round, it just never rotates.
        #[tokio::test]
        async fn no_pool_configured_means_no_election_and_no_network_call() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_in(dir.path().to_path_buf());
            assert!(state.pool_url.read().await.is_none());
            // Returns without touching the chain stub, which would error.
            assert!(verified_election(&state).await.is_none());
        }

        /// The pool URL is persisted and reported back, so a settings screen
        /// can show what is in force after a restart.
        #[tokio::test]
        async fn a_pool_url_is_persisted_and_surfaced() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_in(dir.path().to_path_buf());
            let req = serde_json::to_string(&Envelope::new(
                1,
                Request::SetNode {
                    ghostd_url: Some("http://127.0.0.1:8332".into()),
                    cookie_path: None,
                    user: None,
                    pass: None,
                    pool_url: Some("https://pool.example:8443".into()),
                },
            ))
            .unwrap();
            match super::dispatch(&req, &state).await.payload {
                Response::NodeSet(r) => {
                    assert_eq!(r.pool_url.as_deref(), Some("https://pool.example:8443"))
                }
                other => panic!("expected NodeSet, got {other:?}"),
            }
            let persisted = super::load_node_config(&state.node_config_path).unwrap();
            assert_eq!(
                persisted.pool_url.as_deref(),
                Some("https://pool.example:8443")
            );

            let env = serde_json::to_string(&Envelope::new(2, Request::DaemonEnv)).unwrap();
            match super::dispatch(&env, &state).await.payload {
                Response::DaemonEnv(e) => {
                    assert_eq!(e.pool_url.as_deref(), Some("https://pool.example:8443"))
                }
                other => panic!("expected DaemonEnv, got {other:?}"),
            }
        }

        /// Changing the pool must drop what the last one said.
        ///
        /// The election is cached for a whole epoch — about a day — so a stale
        /// entry would keep sending rounds to the previous pool's seat long
        /// after the user pointed the wallet somewhere else.
        #[tokio::test]
        async fn changing_the_pool_invalidates_the_cached_election() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_in(dir.path().to_path_buf());
            *state.election_cache.write().await = Some((7, serde_json::json!({ "enabled": true })));

            state
                .set_node(
                    GhostdSettings {
                        url: Some("http://127.0.0.1:8332".into()),
                        ..Default::default()
                    },
                    Some("https://other.example:8443".into()),
                )
                .await
                .expect("set node");

            assert!(
                state.election_cache.read().await.is_none(),
                "a cached election must not outlive the pool that served it"
            );
        }

        /// A malformed pool URL is refused, and nothing is persisted — the
        /// same rule the node URL follows.
        #[tokio::test]
        async fn a_pool_url_with_the_wrong_scheme_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_in(dir.path().to_path_buf());
            let err = state
                .set_node(GhostdSettings::default(), Some("ws://pool.example".into()))
                .await
                .expect_err("must refuse");
            assert!(err.contains("pool URL"), "got: {err}");
            assert!(
                !state.node_config_path.exists(),
                "a rejected change must not write node.json"
            );
        }

        /// The RPC password must never come back out over the IPC.
        ///
        /// A settings screen needs to know *how* the wallet authenticates, and
        /// nothing more. Echoing the secret back would put it in every log,
        /// screenshot and bug report that captured an IPC trace.
        #[tokio::test]
        async fn the_node_password_never_crosses_the_ipc() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_in(dir.path().to_path_buf());
            let req = serde_json::to_string(&Envelope::new(
                1,
                Request::SetNode {
                    ghostd_url: Some("http://127.0.0.1:8332".into()),
                    cookie_path: None,
                    user: Some("ghost".into()),
                    pass: Some("hunter2-the-secret".into()),
                    pool_url: None,
                },
            ))
            .unwrap();
            let reply = super::dispatch(&req, &state).await;
            let wire = serde_json::to_string(&reply).unwrap();
            assert!(
                !wire.contains("hunter2-the-secret"),
                "the password must not appear in the reply: {wire}"
            );
            let env = serde_json::to_string(&Envelope::new(2, Request::DaemonEnv)).unwrap();
            let wire = serde_json::to_string(&super::dispatch(&env, &state).await).unwrap();
            assert!(
                !wire.contains("hunter2-the-secret"),
                "the password must not appear in DaemonEnv either: {wire}"
            );
        }

        /// A wrong-scheme URL is rejected, and nothing is persisted — a typo
        /// must never silently point the wallet at nothing.
        #[tokio::test]
        async fn set_node_rejects_bad_scheme() {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state_in(dir.path().to_path_buf());
            let req = serde_json::to_string(&Envelope::new(
                1,
                Request::SetNode {
                    // ws:// where http(s):// is required for an RPC endpoint.
                    ghostd_url: Some("ws://node.example.com:8332".into()),
                    cookie_path: None,
                    user: None,
                    pass: None,
                    pool_url: None,
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

        /// While the environment pins the node, `SetNode` is refused — env
        /// vars keep power-user precedence.
        #[tokio::test]
        async fn set_node_refused_under_env_override() {
            let dir = tempfile::tempdir().unwrap();
            let mut state = test_state_in(dir.path().to_path_buf());
            Arc::get_mut(&mut state).unwrap().ghostd_env_override = true;
            let err = state
                .set_node(GhostdSettings::default(), None)
                .await
                .expect_err("must refuse while env override is active");
            assert!(
                err.contains("environment"),
                "error should point at the env-var override; got: {err}"
            );
        }
    }
}
