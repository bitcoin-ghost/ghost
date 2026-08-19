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

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let cli = Cli::parse();
    let network =
        parse_network(&cli.network).with_context(|| format!("invalid network: {}", cli.network))?;

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
