#![allow(rustdoc::all)] // imported SV2 crate: relax strict rustdoc policy (SRI upstream doc style)
use crate::{
    mining_device::Secp256k1PublicKey as MiningDeviceSecp256k1PublicKey, sniffer::*,
    sv1_minerd::MinerdProcess, template_provider::*,
};
/// The Ghost agent extension, which a translator in front of the node pool always negotiates.
pub use ghost_common::slot_class_sensing::{AGENT_TLV_EXTENSION_TYPE, PAYEE_TLV_FIELD_TYPE};
use interceptor::InterceptAction;
use once_cell::sync::OnceCell;
use pool_sv2::PoolSv2;
use std::{
    convert::TryFrom,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use stratum_apps::{
    config_helpers::CoinbaseRewardScript,
    key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
    tp_type::TemplateProviderType,
};
use tracing::Level;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use translator_sv2::TranslatorSv2;
use utils::{get_available_address, release_reservation};

pub mod interceptor;
pub mod message_aggregator;
pub mod mining_device;
pub mod mock_roles;
pub mod prometheus_metrics_assertions;
pub mod sniffer;
pub mod sniffer_error;
pub mod sv1_minerd;
pub mod sv1_sniffer;
pub mod template_provider;
pub mod types;
pub mod utils;

/// Concurrently shuts down multiple services.
///
/// Expands to `tokio::join!` over each handle's `.shutdown()` future,
/// so all shutdowns run in parallel rather than sequentially.
#[macro_export]
macro_rules! shutdown_all {
    ($($handle:expr),+ $(,)?) => {
        tokio::join!($($handle.shutdown()),+)
    };
}

const SHARES_PER_MINUTE: f32 = 120.0;

pub const POOL_COINBASE_REWARD_ADDRESS: &str = "tb1qa0sm0hxzj0x25rh8gw5xlzwlsfvvyz8u96w3p8";
const POOL_COINBASE_REWARD_DESCRIPTOR: &str = "addr(tb1qa0sm0hxzj0x25rh8gw5xlzwlsfvvyz8u96w3p8)";

static LOGGER: OnceCell<()> = OnceCell::new();

/// Helper to create Sv2Tp config for the Pool with default public key.
pub fn sv2_tp_config(address: SocketAddr) -> TemplateProviderType {
    TemplateProviderType::Sv2Tp {
        address: address.to_string(),
        public_key: None,
    }
}

/// Helper to create BitcoinCoreIpc config with default thresholds.
pub fn ipc_config(
    data_dir: std::path::PathBuf,
    is_signet: bool,
    min_interval: Option<u8>,
) -> TemplateProviderType {
    use stratum_apps::tp_type::BitcoinNetwork;

    let network = if is_signet {
        BitcoinNetwork::Signet
    } else {
        BitcoinNetwork::Regtest
    };

    TemplateProviderType::BitcoinCoreIpc {
        network,
        data_dir: Some(data_dir),
        fee_threshold: 0,
        min_interval: min_interval.unwrap_or(5),
    }
}

/// Each test function should call `start_tracing()` to enable logging.
pub fn start_tracing() {
    LOGGER.get_or_init(|| {
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(Level::INFO.to_string()));

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer())
            .init();
    });
}

pub fn start_sniffer(
    identifier: &str,
    upstream: SocketAddr,
    check_on_drop: bool,
    action: Vec<InterceptAction>,
    timeout: Option<u64>,
) -> (Sniffer<'_>, SocketAddr) {
    let listening_address = get_available_address();
    let sniffer = Sniffer::new(
        identifier,
        listening_address,
        upstream,
        check_on_drop,
        action,
        timeout,
    );
    sniffer.start();
    (sniffer, listening_address)
}

/// A regtest P2WPKH address for the node pool's fee (finder) output.
const NODE_POOL_FEE_ADDRESS_REGTEST: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// The share-chain genesis anchor the harness configures on signet, which has no default:
/// `sha256("GhostNodePool/genesis/sv2-integration-tests")`. Any non-zero hash is a valid
/// configured genesis there; regtest uses its default anchor (`UNSET`).
const NODE_POOL_SIGNET_GENESIS: &str =
    "e4f2461a2514aa2b08e1bcf372c67b2d91f6cffe3d414e61e2a396215cf3fea6";

/// Tier 0 on regtest: regtest's proof-of-work limit, the installer's regtest default
/// (`np_network_defaults`). The default, the difficulty-1 target, puts pool_sv2's channel floor
/// (tier 10) at about 2^42 hashes a share, which a CPU miner never reaches: every test that
/// waits for a share would time out.
const NODE_POOL_TIER_BASE_REGTEST: &str =
    "7fffff0000000000000000000000000000000000000000000000000000000000";

/// Tier 0 on the harness's signet: 2^17 x signet's proof-of-work limit, as the node pool's
/// regtest harness (`scripts/regtest-node-pool/harness.py`) runs its signet. For the same reason.
const NODE_POOL_TIER_BASE_SIGNET: &str =
    "06ef5c0000000000000000000000000000000000000000000000000000000000";

/// The `[node_pool]` section pool_sv2 requires: the node pool is its only mode, and it refuses
/// to start without one.
///
/// What the harness stands in for, and why:
/// - the co-located ghost-mining, whose health endpoint gives the node its identity, is a stub
///   serving one fixed `node_id` ([`spawn_node_identity_stub`]);
/// - the relay reads share headers and settles blocks over the RPC of the same Bitcoin node the
///   template provider runs on, on that node's network (regtest, or signet for the higher
///   difficulty levels), with its own store in a fresh directory;
/// - the relay accepts no peers and dials none: every test is a single node.
///
/// Nothing here relaxes a check: the config is one pool_sv2 accepts as it would on a real node.
async fn node_pool_config(
    bitcoin_core: &BitcoinCore,
    pool_listen: SocketAddr,
) -> pool_sv2::config::NodePoolConfig {
    let rpc = bitcoin_core.rpc_info();
    let cookie = rpc
        .get_cookie_values()
        .expect("read the Bitcoin node's RPC cookie")
        .expect("parse the Bitcoin node's RPC cookie");
    let (network, genesis_anchor, fee_address, tier_base) = if bitcoin_core.is_signet() {
        (
            "signet",
            NODE_POOL_SIGNET_GENESIS,
            POOL_COINBASE_REWARD_ADDRESS,
            NODE_POOL_TIER_BASE_SIGNET,
        )
    } else {
        (
            "regtest",
            pool_sv2::node_pool_relay::GENESIS_UNSET,
            NODE_POOL_FEE_ADDRESS_REGTEST,
            NODE_POOL_TIER_BASE_REGTEST,
        )
    };
    let dir = std::env::temp_dir()
        .join("sv2-integration-tests")
        .join(format!("node-pool-{}", pool_listen.port()));
    // A store left by an earlier run on the same port is another share chain's.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the node pool store directory");
    // One identity per pool, so two pools in one test are two nodes.
    let mut node_id = [0u8; 32];
    node_id[0] = 0x9e;
    node_id[30..].copy_from_slice(&pool_listen.port().to_be_bytes());
    let health = spawn_node_identity_stub(node_id).await;
    pool_sv2::config::NodePoolConfig {
        node_id: Some(hex::encode(node_id)),
        ghost_pool_health_url: Some(format!("http://{health}/health")),
        fee_address: fee_address.to_string(),
        sensing_min_shares: None,
        relay: Some(pool_sv2::node_pool_relay::NodePoolRelayConfig {
            network: Some(network.to_string()),
            listen: None,
            advertise_port: None,
            advertise_sv1_port: None,
            advertise_sv2_port: None,
            peers: vec![],
            db_path: dir.join("node-pool.db"),
            genesis_anchor: genesis_anchor.to_string(),
            genesis_btc_height: 0,
            genesis_table_digest: None,
            genesis_tier: None,
            tier_base: Some(tier_base.to_string()),
            rpc_host: rpc.rpc_socket.ip().to_string(),
            rpc_port: rpc.rpc_socket.port(),
            rpc_user: cookie.user,
            rpc_password: cookie.password,
            checkpoint_depth: None,
            prune: false,
        }),
    }
}

/// Stands in for the co-located ghost-mining's health endpoint, which pool_sv2 asks for this
/// node's identity at startup and checks a pinned `node_id` against. Answers every request with
/// `node_id`, for as long as the test process runs.
async fn spawn_node_identity_stub(node_id: [u8; 32]) -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let addr = get_available_address();
    let listener = utils::bind_listener(addr).await;
    let body = format!(r#"{{"response":{{"node_id":"{}"}}}}"#, hex::encode(node_id));
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                continue;
            };
            let body = body.clone();
            tokio::spawn(async move {
                // The request is read up to its end of headers and otherwise ignored.
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    addr
}

/// The running start of a pool: what `PoolSv2::start` returned, once it has.
type PoolStart = tokio::task::JoinHandle<Result<(), pool_sv2::error::PoolErrorKind>>;

/// Starts a pool on `template_provider_config`, as a node pool node over `bitcoin_core`, and
/// returns once it is accepting connections. A pool that fails to start panics here with its
/// error, rather than leaving the test to time out against a port nobody is listening on.
pub async fn start_pool(
    template_provider_config: TemplateProviderType,
    bitcoin_core: &BitcoinCore,
    supported_extensions: Vec<u16>,
    required_extensions: Vec<u16>,
    enable_monitoring: bool,
) -> (PoolSv2, SocketAddr, Option<SocketAddr>) {
    let (pool, listening_address, monitoring_address, started) = spawn_pool(
        template_provider_config,
        bitcoin_core,
        supported_extensions,
        required_extensions,
        enable_monitoring,
    )
    .await;
    // Wait for the listener, not for a fixed time: startup opens the relay's store and waits for
    // the template provider's first template before it binds. A start that returns before then
    // has failed; its error is the test's failure.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if started.is_finished() {
            match started.await {
                Ok(Ok(())) => panic!("pool_sv2 exited before it listened on {listening_address}"),
                Ok(Err(e)) => panic!("pool_sv2 refused to start: {e:?}"),
                Err(e) => panic!("pool_sv2 start task failed: {e}"),
            }
        }
        if tokio::net::TcpStream::connect(listening_address)
            .await
            .is_ok()
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "pool_sv2 did not listen on {listening_address} within 60s"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    (pool, listening_address, monitoring_address)
}

/// [`start_pool`] for a test that keeps the template provider's templates from the pool: such a
/// pool never listens, since it serves no miner before it has a template, so this returns as
/// soon as the pool is spawned. A start that fails is logged as an error.
pub async fn start_pool_without_templates(
    template_provider_config: TemplateProviderType,
    bitcoin_core: &BitcoinCore,
) -> PoolSv2 {
    let (pool, _, _, started) = spawn_pool(
        template_provider_config,
        bitcoin_core,
        vec![],
        vec![],
        false,
    )
    .await;
    tokio::spawn(async move {
        match started.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!("pool_sv2 refused to start: {e:?}"),
            Err(e) => tracing::error!("pool_sv2 start task failed: {e}"),
        }
    });
    pool
}

async fn spawn_pool(
    template_provider_config: TemplateProviderType,
    bitcoin_core: &BitcoinCore,
    supported_extensions: Vec<u16>,
    required_extensions: Vec<u16>,
    enable_monitoring: bool,
) -> (PoolSv2, SocketAddr, Option<SocketAddr>, PoolStart) {
    use pool_sv2::config::PoolConfig;
    let listening_address = get_available_address();
    let authority_public_key = Secp256k1PublicKey::try_from(
        "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72".to_string(),
    )
    .expect("failed");
    let authority_secret_key = Secp256k1SecretKey::try_from(
        "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n".to_string(),
    )
    .expect("failed");
    let cert_validity_sec = 3600;
    let coinbase_reward_script =
        CoinbaseRewardScript::from_descriptor(POOL_COINBASE_REWARD_DESCRIPTOR).unwrap();
    let pool_signature = "Stratum V2 SRI Pool".to_string();
    let connection_config = pool_sv2::config::ConnectionConfig::new(
        listening_address,
        cert_validity_sec,
        pool_signature,
    );
    let authority_config =
        pool_sv2::config::AuthorityConfig::new(authority_public_key, authority_secret_key);
    let share_batch_size = 1;
    let monitoring_address = if enable_monitoring {
        Some(get_available_address())
    } else {
        None
    };
    let monitoring_cache_refresh_secs = if enable_monitoring { Some(1) } else { None };
    let mut config = PoolConfig::new(
        connection_config,
        template_provider_config,
        authority_config,
        coinbase_reward_script,
        SHARES_PER_MINUTE,
        share_batch_size,
        1,
        supported_extensions,
        required_extensions,
        monitoring_address,
        monitoring_cache_refresh_secs,
    );
    config.set_node_pool(node_pool_config(bitcoin_core, listening_address).await);
    // `get_available_address` keeps the port BOUND so nothing can steal it between choice and
    // use (#408, #612). `PoolSv2` binds the address itself, so that reservation has to be handed
    // back first or the pool's own bind fails with `AddrInUse` — which is exactly what was
    // happening: the harness was holding the port against the component it had chosen it for.
    release_reservation(listening_address);
    if let Some(addr) = monitoring_address {
        release_reservation(addr);
    }

    let pool = PoolSv2::new(config);
    let pool_clone = pool.clone();
    let started = tokio::spawn(async move { pool_clone.start().await });
    (pool, listening_address, monitoring_address, started)
}

pub fn start_template_provider(
    sv2_interval: Option<u32>,
    difficulty_level: DifficultyLevel,
) -> (TemplateProvider, SocketAddr) {
    let address = get_available_address();
    let sv2_interval = sv2_interval.unwrap_or(20);
    let template_provider = TemplateProvider::start(address.port(), sv2_interval, difficulty_level);
    template_provider.generate_blocks(1);
    (template_provider, address)
}

pub fn start_bitcoin_core(difficulty_level: DifficultyLevel) -> BitcoinCore {
    let address = get_available_address();
    let bitcoin_core = BitcoinCore::start(address.port(), difficulty_level);
    bitcoin_core.generate_blocks(1);
    bitcoin_core
}

pub async fn start_sv2_translator(
    upstreams: &[SocketAddr],
    aggregate_channels: bool,
    supported_extensions: Vec<u16>,
    required_extensions: Vec<u16>,
    job_keepalive_interval_secs: Option<u16>,
    enable_monitoring: bool,
) -> (TranslatorSv2, SocketAddr, Option<SocketAddr>) {
    let job_keepalive_interval_secs = job_keepalive_interval_secs.unwrap_or(60);
    let upstreams = upstreams
        .iter()
        .map(|upstream| {
            let upstream_address = upstream.ip().to_string();
            let upstream_port = upstream.port();
            let upstream_authority_pubkey = Secp256k1PublicKey::try_from(
                "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72".to_string(),
            )
            .expect("failed");

            translator_sv2::config::Upstream::new(
                upstream_address,
                upstream_port,
                upstream_authority_pubkey,
            )
        })
        .collect();

    let listening_address = get_available_address();
    let listening_port = listening_address.port();

    let minerd_process = MinerdProcess::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), false)
        .await
        .unwrap();
    let min_individual_miner_hashrate = minerd_process.measure_hashrate().await.unwrap() as f32;

    let downstream_difficulty_config = translator_sv2::config::DownstreamDifficultyConfig::new(
        min_individual_miner_hashrate,
        SHARES_PER_MINUTE,
        true,
        job_keepalive_interval_secs,
    );

    let downstream_extranonce2_size = 4;

    let monitoring_address = if enable_monitoring {
        Some(get_available_address())
    } else {
        None
    };
    let monitoring_cache_refresh_secs = if enable_monitoring { Some(1) } else { None };
    let mut config = translator_sv2::config::TranslatorConfig::new(
        upstreams,
        listening_address.ip().to_string(),
        listening_port,
        downstream_difficulty_config,
        2,
        2,
        downstream_extranonce2_size,
        // As the installer writes it: the default username prefix is a payout address, so a
        // miner authorising with a bare worker name still names a payee the node pool accepts.
        POOL_COINBASE_REWARD_ADDRESS.to_string(),
        aggregate_channels,
        supported_extensions,
        required_extensions,
        monitoring_address,
        monitoring_cache_refresh_secs,
    );
    // ⛔ Match PRODUCTION. Every node runs `open_channel_on_subscribe = true`; the compiled
    // default is `false`, so a harness that never sets it tests a configuration the fleet does
    // not run — and specifically the one configuration in which the harness's own miner cannot
    // submit a single valid share.
    //
    // minerd is a SERIALISING SV1 client: it waits for the subscribe RESPONSE before it will
    // authorise. With the channel opening on authorize, that deadlocks, so the translator breaks
    // it by answering subscribe with an 8-byte all-zero placeholder extranonce. `config.rs` spells
    // out the consequence: the real prefix is 12 bytes, the coinbase reserves exactly 20, "so a
    // client that builds on the placeholder is 4 bytes short: malformed coinbase, wrong merkle
    // root, every share invalid. `set_extranonce` cannot rescue it — that is an OPTIONAL extension
    // and these clients never send `mining.extranonce.subscribe`."
    //
    // Measured 2026-09-06: minerd submitted 154 shares and every one was rejected `share below
    // target`, so `SubmitSharesExtended` never reached the pool and five targets failed as a
    // 60s sniffer timeout — which reads like a broken SV2 path rather than a stale test config.
    config.open_channel_on_subscribe = true;
    // Also as production runs it. A channel opened on subscribe carries the provisional identity,
    // which pool_sv2 accepts only from a client that negotiated the Ghost agent extension: that
    // extension's `UpdateChannel` binds the miner's payee once it authorises. Without it the node
    // pool refuses the channel (`node-pool-no-payee`) and minerd, a serialising client, never
    // gets a job.
    if !config
        .required_extensions
        .contains(&AGENT_TLV_EXTENSION_TYPE)
    {
        config.required_extensions.push(AGENT_TLV_EXTENSION_TYPE);
    }
    // ⚠ NOT as production: `quantise_to_tiers` stays off. The translator has no tier base of its
    // own, so it floors SV1 difficulty at 2^10 difficulty-1 units (about 2^42 hashes a share),
    // and a CPU miner's channel asks for an easier target than that and is refused
    // `max-target-out-of-range`. The node pool's regtest harness runs it off for the same reason.
    // The reservation from `get_available_address` keeps the port BOUND (#408, #612). A real
    // component binds the address itself, so the reservation must be handed back first or its
    // bind fails with `AddrInUse` — the harness holding the port against the component it chose
    // it for. That was the root cause behind 14 of the 18 targets (#617).
    release_reservation(listening_address);
    if let Some(addr) = monitoring_address {
        release_reservation(addr);
    }

    let translator_v2 = translator_sv2::TranslatorSv2::new(config);
    let clone_translator_v2 = translator_v2.clone();
    tokio::spawn(async move {
        clone_translator_v2.start().await;
    });
    (translator_v2, listening_address, monitoring_address)
}

pub async fn start_minerd(
    upstream_addr: SocketAddr,
    username: Option<String>,
    password: Option<String>,
    single_submit: bool,
) -> (sv1_minerd::MinerdProcess, SocketAddr) {
    let (process, local_addr) =
        sv1_minerd::start_minerd(upstream_addr, username, password, single_submit)
            .await
            .expect("Failed to start minerd process");
    (process, local_addr)
}

pub fn start_mining_device_sv2(
    upstream: SocketAddr,
    pub_key: Option<MiningDeviceSecp256k1PublicKey>,
    device_id: Option<String>,
    user_id: Option<String>,
    handicap: u32,
    nominal_hashrate_multiplier: Option<f32>,
    single_submit: bool,
) {
    // The node pool opens a channel only for an identity it can pay: a bare or empty one is
    // refused `node-pool-no-payee`. A device given no identity mines to the harness address.
    let user_id = user_id.or_else(|| Some(POOL_COINBASE_REWARD_ADDRESS.to_string()));
    tokio::spawn(async move {
        crate::mining_device::connect(
            upstream.to_string(),
            pub_key,
            device_id,
            user_id,
            handicap,
            nominal_hashrate_multiplier,
            single_submit,
        )
        .await;
    });
}

pub fn start_sv1_sniffer(upstream_address: SocketAddr) -> (sv1_sniffer::SnifferSV1, SocketAddr) {
    let listening_address = get_available_address();
    let sniffer_sv1 = sv1_sniffer::SnifferSV1::new(listening_address, upstream_address);
    sniffer_sv1.start();
    (sniffer_sv1, listening_address)
}
