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
//| FILE: bins/wraith-coordinator/src/main.rs                                                                            |
//|======================================================================================================================|

//! Wraith Lite v1 single-round CoinJoin coordinator — binary entry.
//!
//! Most of the implementation lives in the lib target alongside this
//! file (`src/lib.rs`). This `main` is a thin shell: parse env-driven
//! CLI args, init logging, wire the configured backends into a
//! `CoordinatorState`, build the router, bind a TCP listener, run.
//!
//! ## Backend wiring
//!
//! The coordinator depends on three pluggable backends:
//!   - `UtxoSource` — reads the UTXO set so registration can verify an
//!     input rather than believe it. Bound by `--ghostd-url`; without
//!     one, `/inputs` refuses every submission (#699).
//!   - `Broadcaster` — pushes the merged tx to the bitcoin network.
//!     Also bound by `--ghostd-url`, over the same RPC connection.
//!   - `coordinator_fee_address` — destination for the per-Mix-round
//!     service-fee output. Operator-supplied.
//!
//! `--mock-broadcaster` swaps in `StubBroadcaster` and is refused on
//! mainnet: it means no actual broadcast, which would be a security
//! disaster in production. It composes with `--ghostd-url`, which is how
//! a dev stack verifies inputs against a real node while keeping its
//! practice rounds off the network.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, warn};

use wraith_coordinator::broadcaster::{Broadcaster, GhostdBroadcaster, StubBroadcaster};
use wraith_coordinator::rpc::RpcClient;
use wraith_coordinator::utxo_source::{GhostdUtxoSource, UtxoSource};
use wraith_coordinator::{build_router, CoordinatorState};

/// CLI surface. Configuration that varies between dev, signet, and
/// mainnet ships via env vars (`WRAITH_COORDINATOR_*`) just like
/// every other node binary in this workspace.
#[derive(Parser, Debug)]
#[command(
    name = "wraith-coordinator",
    about = "Wraith Lite v1 single-round CoinJoin coordinator",
    version
)]
struct Cli {
    /// Listen address. Defaults to `WRAITH_COORDINATOR_LISTEN` env var if
    /// set, falling back to `127.0.0.1:9100`. Production deployments bind
    /// to a public address and front it with a TLS-terminating proxy.
    #[arg(
        long,
        env = "WRAITH_COORDINATOR_LISTEN",
        default_value = "127.0.0.1:9100"
    )]
    listen: SocketAddr,

    /// Bitcoin network (`mainnet` / `signet` / `testnet` / `regtest`).
    /// Defaults to signet so dev installs don't accidentally announce a
    /// mainnet coordinator. Mainnet operators set this explicitly via
    /// `WRAITH_COORDINATOR_NETWORK=mainnet`.
    #[arg(long, env = "WRAITH_COORDINATOR_NETWORK", default_value = "signet")]
    network: String,

    /// Coordinator fee-collection address. Mix rounds need this for
    /// the service-fee output; Jump rounds don't. If absent the
    /// binary still boots (Mix `/inputs` returns 503
    /// `fee_address_not_configured`); supply it for any non-trivial
    /// dev setup.
    #[arg(long, env = "WRAITH_COORDINATOR_FEE_ADDRESS")]
    fee_address: Option<String>,

    /// Override the per-session fill window in seconds. Defaults to
    /// `LITE_FILL_WINDOW_SECS` (300s), the production-tuned value
    /// from DESIGN_LITE §11. Regtest demos drop this to ~2s so the
    /// session locks immediately after `min_participants` is
    /// reached instead of waiting the full 5-minute window.
    /// Refused on mainnet — production never wants a sub-300s
    /// window because it shrinks the anonymity set per round.
    #[arg(long, env = "WRAITH_COORDINATOR_FILL_WINDOW_SECS")]
    fill_window_secs: Option<u64>,

    /// The ghost-pay node's `node_id` (64-hex Ed25519 pubkey) to pin its

    /// Use an in-memory StubBroadcaster instead of a real backend.
    /// Refused on mainnet — a stub broadcaster doesn't actually push
    /// transactions to the network. Use only in dev / signet /
    /// regtest. Mutually exclusive with --ghostd-url.
    #[arg(long, env = "WRAITH_COORDINATOR_MOCK_BROADCASTER")]
    mock_broadcaster: bool,

    /// Production bitcoind RPC endpoint (e.g.
    /// `http://127.0.0.1:8332/`). The coordinator will POST a
    /// `sendrawtransaction` call here on the round-completing
    /// `/witness` submission. Auth comes from either
    /// --ghostd-cookie or --ghostd-user/--ghostd-pass.
    #[arg(long, env = "WRAITH_COORDINATOR_GHOSTD_URL")]
    ghostd_url: Option<String>,

    /// Path to bitcoind's `.cookie` file. Mutually exclusive with
    /// --ghostd-user / --ghostd-pass.
    #[arg(long, env = "WRAITH_COORDINATOR_GHOSTD_COOKIE")]
    ghostd_cookie: Option<std::path::PathBuf>,

    /// bitcoind RPC username (from `bitcoin.conf` `rpcuser=`).
    #[arg(long, env = "WRAITH_COORDINATOR_GHOSTD_USER")]
    ghostd_user: Option<String>,

    /// bitcoind RPC password (from `bitcoin.conf` `rpcpassword=`).
    #[arg(long, env = "WRAITH_COORDINATOR_GHOSTD_PASS")]
    ghostd_pass: Option<String>,

    /// Comma-separated base URLs of every other coordinator in the
    /// pool. Each session-state change on this Active is POSTed to
    /// `<peer>/api/v1/internal/gossip` so Standbys mirror the
    /// in-flight session set. Empty (the default) runs as a
    /// solo coordinator with no replication.
    #[arg(long, env = "WRAITH_COORDINATOR_PEERS", value_delimiter = ',')]
    peers: Vec<String>,

    /// File holding the BIP39 seed this coordinator derives per-Lock quorum
    /// keys from. Ghost Lock co-signing is off until this is set.
    ///
    /// The same seed on every coordinator in the pool, so any of them can take
    /// over — which one actually co-signs is decided by `--lock-cosign-role`,
    /// not by who holds the seed. A file rather than an env var: an env var is
    /// readable from `/proc` and lands in process listings and crash dumps.
    #[arg(long, env = "WRAITH_COORDINATOR_LOCK_SEED_FILE")]
    lock_seed_file: Option<std::path::PathBuf>,

    /// File holding the BIP39 passphrase for the quorum seed, if used.
    #[arg(long, env = "WRAITH_COORDINATOR_LOCK_SEED_PASSPHRASE_FILE")]
    lock_seed_passphrase_file: Option<std::path::PathBuf>,

    /// Whether this coordinator co-signs Locks: `active` or `standby`.
    ///
    /// Only one may be active. Every coordinator with the seed derives the
    /// same key, but each keeps its own once-per-coin ledger, so two serving
    /// at once can be asked to co-sign two different spends of one coin — and
    /// both would agree, which is a double-sign proof against the quorum.
    /// Defaults to `standby`: co-signing is something an operator turns on
    /// deliberately, on exactly one host.
    #[arg(long, env = "WRAITH_COORDINATOR_LOCK_ROLE", default_value = "standby")]
    lock_cosign_role: String,

    /// Largest single Lock spend to co-sign, in satoshis.
    ///
    /// Unset means no ceiling, which makes the quorum a rubber stamp against
    /// a stolen owner key.
    #[arg(long, env = "WRAITH_COORDINATOR_LOCK_MAX_SPEND_SATS")]
    lock_max_spend_sats: Option<u64>,

    /// Most to co-sign across a rolling window, in satoshis.
    ///
    /// **A ceiling without this bounds nothing**: a thief spends the ceiling
    /// ten times rather than ten times the ceiling. Set both.
    #[arg(long, env = "WRAITH_COORDINATOR_LOCK_WINDOW_SATS")]
    lock_window_sats: Option<u64>,

    /// How long that window is, in seconds. Default 24 hours.
    #[arg(
        long,
        env = "WRAITH_COORDINATOR_LOCK_WINDOW_SECS",
        default_value_t = 86_400
    )]
    lock_window_secs: u64,

    /// Directory for the co-signing ledgers. Defaults to the working
    /// directory.
    #[arg(long, env = "WRAITH_COORDINATOR_LOCK_LEDGER_DIR")]
    lock_ledger_dir: Option<std::path::PathBuf>,

    /// Shared HMAC key for the inter-coordinator gossip route. When
    /// set, every outbound gossip POST carries `X-Ghost-Signature` +
    /// `X-Ghost-Timestamp` headers and the receive route verifies
    /// them. Same secret on every coordinator in the pool. When
    /// unset, the route accepts unsigned requests — operators must
    /// firewall `/api/v1/internal/` to the pool's address range.
    /// Refused on mainnet without a value (see startup checks).
    #[arg(long, env = "WRAITH_COORDINATOR_PEER_SECRET")]
    peer_secret: Option<String>,
}

/// Read a secret from a file, refusing one others can read.
///
/// A file rather than an env var throughout: an env var is readable from
/// `/proc`, shows up in process listings, and lands in crash dumps.
fn read_secret_file(path: &std::path::Path) -> Result<zeroize::Zeroizing<String>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| format!("cannot stat {path:?}: {e}"))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{path:?} is readable by others (mode {:o}); run `chmod 600` on it",
                meta.permissions().mode() & 0o777
            ));
        }
    }
    let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path:?}: {e}"))?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        return Err(format!("{path:?} is empty"));
    }
    Ok(zeroize::Zeroizing::new(trimmed))
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let cli = Cli::parse();
    let network =
        parse_network(&cli.network).with_context(|| format!("invalid network: {}", cli.network))?;

    // Fail closed if the OS random source cannot be read. This is the
    // whole of the RNG health check the spec permits (§6A E-5) — every
    // blind-signature nonce and per-round signing key comes from it, and a
    // host that cannot produce randomness must refuse to serve rather than
    // discover the problem at the first signature.
    wraith_protocol::ensure_os_rng_available()
        .map_err(|e| anyhow::anyhow!("refusing to start: {e}"))?;

    // Mainnet refuses a mock backend — refusing at boot beats surfacing
    // a vulnerability later.
    if matches!(network, bitcoin::Network::Bitcoin) && cli.mock_broadcaster {
        anyhow::bail!(
            "MAINNET REFUSAL: --mock-broadcaster does not actually push \
             transactions; point --ghostd-url at a real node instead."
        );
    }

    // One node connection, two jobs: `sendrawtransaction` for the
    // broadcaster and `gettxout` for input verification (#699). Built
    // once and shared, so an operator who can broadcast can also verify
    // inputs with no second set of credentials to get wrong.
    let rpc = match cli.ghostd_url.as_deref() {
        None => None,
        Some(url) => Some(
            match (
                cli.ghostd_cookie.as_ref(),
                cli.ghostd_user.as_deref(),
                cli.ghostd_pass.as_deref(),
            ) {
                (Some(cookie), None, None) => RpcClient::from_cookie(url, cookie)
                    .map_err(|e| anyhow::anyhow!("bitcoind RPC: {e}"))?,
                (None, Some(u), Some(p)) => RpcClient::new(url, u, p),
                (None, None, None) => anyhow::bail!(
                    "--ghostd-url requires either --ghostd-cookie or \
                     --ghostd-user + --ghostd-pass for authentication"
                ),
                _ => anyhow::bail!(
                    "--ghostd-cookie is mutually exclusive with \
                     --ghostd-user / --ghostd-pass"
                ),
            },
        ),
    };

    // The UTXO source is not optional in effect: without it `/inputs`
    // refuses every submission, because registration must never fall
    // back to believing a wallet's account of its own input.
    let utxo_source: Option<Arc<dyn UtxoSource>> = match rpc.as_ref() {
        Some(rpc) => Some(Arc::new(GhostdUtxoSource::new(rpc.clone()))),
        None => {
            warn!(
                "no --ghostd-url: /inputs will refuse every submission with \
                 utxo_source_not_configured, because input UTXOs cannot be verified"
            );
            None
        }
    };

    // Broadcaster: mock OR bitcoind. Both absent → /witness returns 503
    // broadcaster_not_configured on the round-completing submission.
    //
    // `--mock-broadcaster` alongside `--ghostd-url` is allowed and
    // useful: a dev stack wants inputs verified against a real node
    // without putting its practice rounds on the network.
    let broadcaster: Option<Arc<dyn Broadcaster>> = if cli.mock_broadcaster {
        warn!("using StubBroadcaster — round transactions are NOT actually broadcast");
        Some(Arc::new(StubBroadcaster::new()))
    } else {
        rpc.map(|rpc| {
            info!(endpoint = %rpc.endpoint(), "using GhostdBroadcaster");
            Arc::new(GhostdBroadcaster::from_rpc(rpc)) as Arc<dyn Broadcaster>
        })
    };

    // Mainnet refusal: if the operator configured peers without a
    // shared secret, the gossip route would accept unsigned writes
    // from any host that can reach `/api/v1/internal/`. That's only
    // OK if the operator firewalls the prefix; on mainnet we refuse
    // to start so misconfiguration can't silently expose it.
    if matches!(network, bitcoin::Network::Bitcoin)
        && !cli.peers.is_empty()
        && cli.peer_secret.is_none()
    {
        anyhow::bail!(
            "MAINNET REFUSAL: --peers without --peer-secret leaves \
             /api/v1/internal/gossip unauthenticated. Set \
             WRAITH_COORDINATOR_PEER_SECRET to the same value on \
             every coordinator in the pool."
        );
    }

    // Mainnet refuses a sub-default fill window — production
    // anonymity sets need the full 300s window for participants to
    // discover and join. Regtest / signet operators may shorten it
    // for demos and tests.
    if matches!(network, bitcoin::Network::Bitcoin) && cli.fill_window_secs.is_some() {
        anyhow::bail!(
            "MAINNET REFUSAL: --fill-window-secs is dev-only — \
             production must use the LITE_FILL_WINDOW_SECS default \
             so each round has the full 5-minute window for \
             participants to discover and join."
        );
    }

    let mut state = CoordinatorState::with_components(
        network,
        Arc::new(wraith_protocol::SystemClock),
        Arc::new(wraith_protocol::RandomSessionIdGenerator),
        cli.fee_address.clone(),
        broadcaster,
    );
    state.utxo_source = utxo_source;

    // Ghost Lock co-signing. Off unless a seed is configured: a coordinator
    // with no seed must refuse rather than derive quorum keys from nothing.
    state.lock_cosign = match &cli.lock_seed_file {
        None => {
            info!("no --lock-seed-file: this coordinator does not co-sign Ghost Locks");
            None
        }
        Some(path) => {
            let role = match cli.lock_cosign_role.trim().to_ascii_lowercase().as_str() {
                "active" => wraith_protocol::lock_cosign::Role::Active,
                "standby" => wraith_protocol::lock_cosign::Role::Standby,
                other => {
                    anyhow::bail!("--lock-cosign-role must be `active` or `standby`, got `{other}`")
                }
            };
            let phrase =
                read_secret_file(path).map_err(|e| anyhow::anyhow!("--lock-seed-file: {e}"))?;
            let passphrase = match &cli.lock_seed_passphrase_file {
                Some(p) => read_secret_file(p)
                    .map_err(|e| anyhow::anyhow!("--lock-seed-passphrase-file: {e}"))?,
                None => zeroize::Zeroizing::new(String::new()),
            };

            let window =
                cli.lock_window_sats
                    .map(|max_sats| wraith_protocol::lock_cosign::VelocityLimit {
                        max_sats,
                        window_secs: cli.lock_window_secs,
                    });
            let policy = wraith_protocol::lock_cosign::CosignPolicy {
                max_spend_sats: cli.lock_max_spend_sats,
                window,
            };

            // Say what the policy actually is, loudly where it is weak. A
            // ceiling with no window bounds one transaction and not a theft,
            // and an operator who set only one should learn that at startup
            // rather than afterwards.
            match (policy.max_spend_sats, policy.window) {
                (None, None) => warn!(
                    "Lock co-signing has NO ceiling and NO window: this quorum will \
                     co-sign anything asked of it, which adds nothing against a stolen \
                     owner key"
                ),
                (Some(c), None) => warn!(
                    ceiling_sats = c,
                    "Lock co-signing has a ceiling but no window: a thief spends the \
                     ceiling repeatedly, so this bounds one transaction and not a theft. \
                     Set --lock-window-sats."
                ),
                (None, Some(w)) => info!(
                    window_sats = w.max_sats,
                    window_secs = w.window_secs,
                    "Lock co-signing bounded by a rolling window only"
                ),
                (Some(c), Some(w)) => info!(
                    ceiling_sats = c,
                    window_sats = w.max_sats,
                    window_secs = w.window_secs,
                    "Lock co-signing policy"
                ),
            }

            let defaulted = cli.lock_ledger_dir.is_none();
            let dir = cli
                .lock_ledger_dir
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            // Always report where the ledgers actually landed, resolved.
            //
            // These hold the once-per-coin record for Lock co-signing, and
            // that module is explicit that a forgetful ledger is worse than
            // none: it reports a guarantee it has stopped providing. Defaulting
            // to the working directory means a coordinator relaunched from
            // somewhere else silently starts with an empty one and will
            // co-sign a coin it has already co-signed. Saying the absolute
            // path out loud is the difference between that being visible and
            // being discovered later.
            let resolved = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
            if defaulted {
                warn!(
                    dir = %resolved.display(),
                    "no --lock-ledger-dir: Lock co-signing ledgers go in the WORKING \
                     DIRECTORY. Starting this coordinator from elsewhere gives it an empty \
                     double-signing ledger. Pass --lock-ledger-dir to pin them."
                );
            } else {
                info!(dir = %resolved.display(), "Lock co-signing ledgers");
            }
            let cosign =
                wraith_coordinator::LockCosignState::open(&dir, phrase, passphrase, policy, role)
                    .map_err(|e| anyhow::anyhow!("Lock co-sign ledgers in {dir:?}: {e}"))?;

            match role {
                wraith_protocol::lock_cosign::Role::Active => {
                    info!(dir = ?dir, "Lock co-signing ACTIVE on this coordinator")
                }
                wraith_protocol::lock_cosign::Role::Standby => info!(
                    "Lock co-signing configured but on STANDBY: this coordinator will \
                     refuse until it is made active"
                ),
            }
            Some(cosign)
        }
    };

    state.gossip_peer_secret = cli.peer_secret.clone();
    if let Some(secs) = cli.fill_window_secs {
        state.fill_window_secs = secs;
        warn!(
            secs,
            "fill-window override active — non-default tier behaviour"
        );
    }

    // Active/Standby state replication. When the operator supplies
    // peers, every session mutation publishes to all of them; the
    // peers' `/api/v1/internal/gossip` route applies the events.
    if !cli.peers.is_empty() {
        let runtime_handle = tokio::runtime::Handle::current();
        let sink = wraith_coordinator::gossip_http::HttpGossipSink::spawn(
            cli.peers.clone(),
            cli.peer_secret.clone(),
            &runtime_handle,
        );
        state.sessions.set_gossip_sink(Box::new(sink));
        info!(
            peers = ?cli.peers,
            authenticated = cli.peer_secret.is_some(),
            "gossip enabled — session state replicates to peer coordinators"
        );
    }

    let state = Arc::new(state);

    info!(
        listen = %cli.listen,
        network = ?network,
        broadcaster = if cli.mock_broadcaster {
            "stub"
        } else if cli.ghostd_url.is_some() {
            "bitcoind"
        } else {
            "none"
        },
        fee_address = ?cli.fee_address,
        "wraith-coordinator starting"
    );

    // Background tick: sweeps no-sign-deadline-expired sessions and
    // runs time-driven Filling-→-Locked / Filling-→-Failed transitions
    // even when no wallet is polling /status. Detached — terminates
    // when the runtime tears down.
    let _tick_handle = wraith_coordinator::tick::spawn_background_tick(state.clone());

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .with_context(|| format!("failed to bind {}", cli.listen))?;
    axum::serve(listener, app)
        .await
        .context("axum serve loop terminated unexpectedly")?;
    Ok(())
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn parse_network(s: &str) -> Result<bitcoin::Network> {
    Ok(match s.trim().to_ascii_lowercase().as_str() {
        "mainnet" | "bitcoin" => bitcoin::Network::Bitcoin,
        "signet" => bitcoin::Network::Signet,
        "testnet" => bitcoin::Network::Testnet,
        "regtest" => bitcoin::Network::Regtest,
        other => anyhow::bail!("unknown network '{other}'"),
    })
}
