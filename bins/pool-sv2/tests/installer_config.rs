//! The installer's pool_sv2 config, loaded by pool_sv2 itself (W2.12).
//!
//! `scripts/install-node.sh` renders `/etc/ghost/pool-config.toml` with `np_render_pool_config`
//! and checks fee addresses with `np_fee_address_check`, both inside its `NODE_POOL_FUNCTIONS`
//! block. This test runs that block out of the installer, unchanged, and holds pool_sv2 to it:
//! - the rendered file parses as a [`PoolConfig`] the way `args.rs` loads one, and carries the
//!   `[node_pool]` and `[node_pool.relay]` sections startup requires;
//! - on regtest, whose genesis the installer defines, [`NodePool::resolve`] accepts it and the
//!   relay starts on it and publishes the genesis anchor;
//! - on mainnet, whose start is compiled into pool_sv2 (set at the flag day), the `UNSET`
//!   placeholder runs on the compiled start, and any other genesis passed to the installer is
//!   refused (W2.8);
//! - the shell's fee address check agrees with [`NodePool::fee_script`] plus the network on every
//!   address class, so the installer neither writes an address pool_sv2 refuses nor refuses one
//!   it accepts.

use std::{path::PathBuf, process::Command};

use ext_config::{Config, File, FileFormat};
use pool_sv2::{
    config::PoolConfig,
    node_pool::NodePool,
    node_pool_relay::{self, GENESIS_UNSET},
};
use stratum_apps::stratum_core::bitcoin::{address::NetworkUnchecked, Address, Network, ScriptBuf};

const PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const SEC: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";
const MAINNET_FEE: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const REGTEST_FEE: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

fn installer() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/install-node.sh")
}

/// The installer's `NODE_POOL_FUNCTIONS` block, as bash source.
fn functions() -> String {
    let src = std::fs::read_to_string(installer()).expect("read the installer");
    let start = src
        .find("# >>> NODE_POOL_FUNCTIONS\n")
        .expect("the NODE_POOL_FUNCTIONS block");
    let end = src[start..]
        .find("# <<< NODE_POOL_FUNCTIONS\n")
        .expect("its end marker")
        + start;
    src[start..end].to_string()
}

/// Run `script` after the installer's functions, in bash, and return its stdout and status.
fn bash(script: &str) -> (String, bool) {
    let out = Command::new("bash")
        .arg("-c")
        .arg(format!("set -euo pipefail\n{}\n{script}", functions()))
        .output()
        .expect("run bash");
    (
        String::from_utf8(out.stdout).expect("utf-8"),
        out.status.success(),
    )
}

/// The installer's pool_sv2 config for `network`, rendered as an install would render it.
fn render(network: &str, fee: &str, peers: &str, genesis: Option<(&str, u32)>) -> String {
    let genesis = match genesis {
        Some((a, h)) => format!("GENESIS_ANCHOR={a} GENESIS_HEIGHT={h}"),
        None => "GENESIS_ANCHOR=$NP_GENESIS_ANCHOR GENESIS_HEIGHT=$NP_GENESIS_HEIGHT".into(),
    };
    let (out, ok) = bash(&format!(
        "np_network_defaults {network}\n\
         SV2_AUTH_PUB={PUB} SV2_AUTH_SEC={SEC} TDP_PUBKEY={PUB} APISECRET={} RPC_USER=u RPCPW=p \
         NETWORK={network} FEE_ADDRESS={fee} RELAY_PORT=8566 RELAY_PEERS='{peers}' {genesis}\n\
         np_render_pool_config",
        "ab".repeat(32)
    ));
    assert!(ok, "render failed for {network}");
    out
}

/// Load a config exactly as `args.rs` does.
fn load(toml: &str) -> PoolConfig {
    Config::builder()
        .add_source(File::from_str(toml, FileFormat::Toml))
        .build()
        .and_then(|c| c.try_deserialize::<PoolConfig>())
        .unwrap_or_else(|e| panic!("pool_sv2 refuses the installer's config: {e}\n{toml}"))
}

/// A stand-in ghost-mining `/health` that reports `node_id`, for `NodePool::resolve`.
async fn health_server(node_id: [u8; 32]) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = format!(r#"{{"response":{{"node_id":"{}"}}}}"#, hex::encode(node_id));
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes()).await;
        }
    });
    format!("http://{addr}/health")
}

#[tokio::test]
async fn regtest_config_is_accepted_by_resolve_and_starts_the_relay() {
    let toml = render(
        "regtest",
        REGTEST_FEE,
        "127.0.0.1:1 peer.invalid:8566",
        None,
    );
    let config = load(&toml);
    let mut np_cfg = config
        .node_pool()
        .expect("[node_pool] is required at startup")
        .clone();
    assert_eq!(np_cfg.fee_address, REGTEST_FEE);
    let mut relay = np_cfg.relay.clone().expect("[node_pool.relay] is required");
    assert_eq!(relay.listen, Some("0.0.0.0:8566".parse().unwrap()));
    assert_eq!(relay.peers, vec!["127.0.0.1:1", "peer.invalid:8566"]);
    // The mining advert open listing probes (W2.10): the translator's SV1 port, and pool_sv2's
    // own SV2 port and key.
    assert_eq!(relay.advertise_sv1_port, Some(3333));
    assert_eq!(relay.advertise_sv2_port, None);
    let advert = relay
        .advert(Some(config.listen_address().port()), PUB)
        .expect("the installer advertises its stratum ports");
    assert_eq!((advert.sv1_port, advert.sv2_port), (3333, 34255));
    assert_eq!(advert.sv2_authority_key, PUB);
    assert_eq!(
        relay.db_path,
        PathBuf::from("/var/lib/ghost/node-pool.db"),
        "the store path the installer writes"
    );
    assert_eq!(relay.genesis_btc_height, 0);
    assert!(relay.tier_base.is_some(), "regtest needs an easier tier 0");
    assert_eq!(relay.network.as_deref(), Some("regtest"));
    let genesis = relay.genesis_hash().expect("regtest's genesis is defined");
    let start = relay
        .network_start()
        .expect("regtest starts on its genesis");
    assert_eq!(start.genesis_anchor, genesis);
    assert_eq!(
        genesis,
        ghost_common::node_pool_network::regtest_default_genesis(),
        "the installer writes regtest's default"
    );

    let node_id = [0x5C; 32];
    np_cfg.ghost_pool_health_url = Some(health_server(node_id).await);
    let np = NodePool::resolve(&np_cfg, config.shares_per_minute())
        .await
        .expect("NodePool::resolve accepts the installer's [node_pool]");
    assert_eq!(
        np.finder_script(),
        NodePool::fee_script(REGTEST_FEE).unwrap().as_slice()
    );

    // The relay, on its own store and an ephemeral port, as the installed node would run it.
    let dir = std::env::temp_dir().join(format!("np-installer-config-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    relay.db_path = dir.join("node-pool.db");
    relay.listen = Some("127.0.0.1:0".parse().unwrap());
    let handle = node_pool_relay::start(&relay, &np)
        .await
        .expect("the relay starts on the installer's [node_pool.relay]");
    let mut rx = np.subscribe();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rx.wait_for(|u| u.is_some()),
    )
    .await
    .expect("the relay publishes its tip")
    .unwrap();
    assert_eq!(np.anchor_driver().current().unwrap().parent_anchor, genesis);
    handle.task.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mainnet_config_parses_and_runs_on_the_compiled_start() {
    let toml = render("mainnet", MAINNET_FEE, "", None);
    assert!(toml.contains("PLACEHOLDER"), "the placeholder is marked");
    let config = load(&toml);
    let np_cfg = config.node_pool().expect("[node_pool]");
    NodePool::fee_script(&np_cfg.fee_address).expect("the fee address is a payee class");
    let relay = np_cfg.relay.as_ref().expect("[node_pool.relay]");
    assert_eq!(relay.genesis_anchor, GENESIS_UNSET);
    assert!(relay.peers.is_empty());
    assert!(relay.tier_base.is_none(), "mainnet tier 0 is difficulty 1");
    assert_eq!(relay.network.as_deref(), Some("mainnet"));
    // Mainnet's start is compiled in: the installer's UNSET runs on it.
    let compiled = ghost_common::node_pool_network::MAINNET_START.expect("set at the flag day");
    let start = relay
        .network_start()
        .expect("UNSET takes the compiled start");
    assert_eq!(
        (
            start.genesis_anchor,
            start.genesis_btc_height,
            start.pinned_table_digest
        ),
        (
            compiled.genesis_anchor,
            compiled.genesis_btc_height,
            compiled.genesis_table_digest
        )
    );

    // A genesis passed on mainnet is written, and refused: it is not the compiled start.
    let given = "cd".repeat(32);
    let config = load(&render("mainnet", MAINNET_FEE, "", Some((&given, 975_000))));
    let relay = config.node_pool().unwrap().relay.clone().unwrap();
    assert_eq!(relay.genesis_hash().unwrap(), [0xcd; 32]);
    assert_eq!(relay.genesis_btc_height, 975_000);
    let e = relay.network_start().unwrap_err();
    assert!(e.contains("is not mainnet's compiled start"), "{e}");
}

#[test]
fn signet_config_parses() {
    let fee = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
    let config = load(&render("signet", fee, "a.example:8566", None));
    let np_cfg = config.node_pool().unwrap();
    assert_eq!(np_cfg.fee_address, fee);
    NodePool::fee_script(fee).unwrap();
    let relay = np_cfg.relay.as_ref().unwrap();
    assert_eq!(relay.network.as_deref(), Some("signet"));
    assert!(relay.genesis_hash().is_err());
    assert!(relay.network_start().is_err());
}

/// One address of each class, for a network.
fn addresses(network: Network) -> Vec<(&'static str, String)> {
    let script = |b: &[u8]| ScriptBuf::from_bytes(b.to_vec());
    let mut out = Vec::new();
    for (class, bytes) in [
        (
            "p2pkh",
            [&[0x76, 0xa9, 0x14][..], &[0x11; 20], &[0x88, 0xac]].concat(),
        ),
        ("p2sh", [&[0xa9, 0x14][..], &[0x22; 20], &[0x87]].concat()),
        ("p2wpkh", [&[0x00, 0x14][..], &[0x33; 20]].concat()),
        ("p2wsh", [&[0x00, 0x20][..], &[0x44; 32]].concat()),
        ("p2tr", [&[0x51, 0x20][..], &[0x55; 32]].concat()),
    ] {
        let a = Address::from_script(&script(&bytes), network).expect("address");
        out.push((class, a.to_string()));
    }
    out
}

#[test]
fn the_shell_fee_address_check_agrees_with_pool_sv2() {
    let nets = [
        ("mainnet", Network::Bitcoin),
        ("signet", Network::Signet),
        ("regtest", Network::Regtest),
    ];
    let mut cases = Vec::new();
    for (_, n) in nets {
        for (class, a) in addresses(n) {
            cases.push((class, a.clone()));
            // One character changed: the checksum must catch it.
            let mut broken: Vec<char> = a.chars().collect();
            let i = broken.len() - 3;
            broken[i] = if broken[i] == 'q' || broken[i] == '2' {
                'p'
            } else {
                'q'
            };
            cases.push(("broken", broken.into_iter().collect()));
        }
    }
    let mut checked = 0;
    for (net, network) in nets {
        let list: Vec<String> = cases.iter().map(|(_, a)| a.clone()).collect();
        let (out, ok) = bash(&format!(
            "for a in {}; do if np_fee_address_check \"$a\" {net} >/dev/null; then echo ok; else echo no; fi; done",
            list.join(" ")
        ));
        assert!(ok);
        let verdicts: Vec<&str> = out.lines().collect();
        assert_eq!(verdicts.len(), cases.len());
        for ((class, a), shell) in cases.iter().zip(verdicts) {
            let parsed = a.parse::<Address<NetworkUnchecked>>();
            let rust = NodePool::fee_script(a).is_ok()
                && parsed.is_ok_and(|p| p.is_valid_for_network(network));
            assert_eq!(
                shell == "ok",
                rust,
                "{class} {a} on {net}: installer says {shell}, pool_sv2 + network says {rust}"
            );
            if *class == "p2pkh" || *class == "broken" {
                assert_eq!(shell, "no", "{class} {a} must be refused on {net}");
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 90);
}
