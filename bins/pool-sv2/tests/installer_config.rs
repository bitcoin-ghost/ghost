//! The installer's pool_sv2 config, loaded by pool_sv2 itself.
//!
//! `scripts/install-node.sh` renders `/etc/ghost/pool-config.toml` with `np_render_pool_config`
//! and checks payout addresses with `np_payout_address_check`, both inside its
//! `NODE_POOL_FUNCTIONS` block. This test runs that block out of the installer, unchanged, and
//! holds pool_sv2 to it:
//! - the rendered file parses as a [`PoolConfig`] the way `args.rs` loads one, on every network,
//!   with the `[solo]` keys pool_sv2 reads (network, state directory, found-block targets and
//!   their credentials file, SV1 ports) and no `[node_pool]` section;
//! - the shell's address check agrees with the payout classes pool_sv2 accepts from a miner
//!   ([`Solo::payee_for_identity`]) plus the network, on every address class.
//!
//! `a_solo_section_is_read` does not use the installer: it pins the `[solo]` keys the installer
//! must write (`docs/SOLO.md`).

use std::{path::PathBuf, process::Command};

use ext_config::{Config, File, FileFormat};
use pool_sv2::{config::PoolConfig, solo::Solo};
use stratum_apps::stratum_core::bitcoin::{address::NetworkUnchecked, Address, Network, ScriptBuf};

const PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const SEC: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";
const REGTEST_ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

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

/// The installer's pool_sv2 config for `network`, rendered as an install would render it:
/// `submit_nodes` are the found-block targets (space-separated URLs), `auth_ready` whether the
/// credentials file was written.
fn render(network: &str, submit_nodes: &str, auth_ready: bool) -> String {
    let (out, ok) = bash(&format!(
        "np_network_defaults {network}\n\
         SV2_AUTH_PUB={PUB} SV2_AUTH_SEC={SEC} TDP_PUBKEY={PUB} APISECRET={} \
         NETWORK={network} SUBMIT_NODES='{submit_nodes}' SUBMIT_AUTH_READY={auth_ready}\n\
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

#[test]
fn every_networks_config_parses_and_starts_solo() {
    for network in ["regtest", "mainnet", "signet"] {
        let config = load(&render(network, "", false));
        assert!(
            !config.has_legacy_node_pool_section(),
            "{network}: the installer writes no [node_pool] section"
        );
        let solo = config.solo();
        assert_eq!(
            solo.network.as_deref(),
            Some(network),
            "the installer writes the network it installs"
        );
        assert_eq!(solo.network().unwrap().as_str(), network);
        assert_eq!(
            solo.state_dir.as_deref(),
            Some(std::path::Path::new("/var/lib/ghost/solo"))
        );
        assert!(
            solo.submit_rpc.is_empty(),
            "{network}: one node, no targets"
        );
        assert!(
            solo.submit_rpc_auth_file.is_none(),
            "{network}: no credentials file is named when none was written"
        );
        assert_eq!(solo.sv1_ports, vec![3333, 4444]);
        assert_eq!(config.listen_address().port(), 34255);
        assert_eq!(
            config.coinbase_reward_script().script_pubkey().as_bytes(),
            &ghost_common::solo::TREASURY_SCRIPT[..],
            "the group channel's script is the treasury's"
        );
    }
}

#[test]
fn a_two_node_config_names_the_other_node_and_its_credentials() {
    let config = load(&render(
        "mainnet",
        "http://10.0.0.2:8332 https://b.example:8443",
        true,
    ));
    let solo = config.solo();
    assert_eq!(
        solo.submit_rpc,
        vec![
            "http://10.0.0.2:8332".to_string(),
            "https://b.example:8443".to_string()
        ]
    );
    assert_eq!(
        solo.submit_rpc_auth_file.as_deref(),
        Some(std::path::Path::new("/etc/ghost/solo-submit-rpc.auth"))
    );
    // Targets without credentials: still written, the file not named (pool_sv2 refuses to start
    // on a credentials file it cannot read).
    let solo = load(&render("signet", "http://10.0.0.2:8332", false)).solo();
    assert_eq!(solo.submit_rpc, vec!["http://10.0.0.2:8332".to_string()]);
    assert!(solo.submit_rpc_auth_file.is_none());
}

#[test]
fn a_solo_section_is_read() {
    let toml = format!(
        "authority_public_key = \"{PUB}\"\nauthority_secret_key = \"{SEC}\"\n\
         cert_validity_sec = 3600\nlisten_address = \"0.0.0.0:34255\"\n\
         coinbase_reward_script = \"addr({REGTEST_ADDR})\"\npool_signature = \"- G H O S T -\"\n\
         shares_per_minute = 6.0\nshare_batch_size = 1\n\
         [template_provider_type.Sv2Tp]\naddress = \"127.0.0.1:8442\"\n\
         [solo]\nnetwork = \"regtest\"\nstate_dir = \"/var/lib/ghost/solo\"\n\
         submit_rpc = [\"http://10.0.0.2:8332\"]\n\
         submit_rpc_auth_file = \"/etc/ghost/solo-submit-rpc.auth\"\nsv1_ports = [3333]\n"
    );
    let config = load(&toml);
    let solo = config.solo();
    assert_eq!(
        solo.network().unwrap(),
        ghost_common::solo::SoloNetwork::Regtest
    );
    assert_eq!(
        solo.state_dir.as_deref(),
        Some(std::path::Path::new("/var/lib/ghost/solo"))
    );
    assert_eq!(solo.submit_rpc, vec!["http://10.0.0.2:8332".to_string()]);
    assert_eq!(
        solo.submit_rpc_auth_file.as_deref(),
        Some(std::path::Path::new("/etc/ghost/solo-submit-rpc.auth"))
    );
    assert_eq!(solo.sv1_ports, vec![3333]);
    assert!(!config.has_legacy_node_pool_section());
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
fn the_shell_address_check_agrees_with_pool_sv2() {
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
            "for a in {}; do if np_payout_address_check \"$a\" {net} >/dev/null; then echo ok; else echo no; fi; done",
            list.join(" ")
        ));
        assert!(ok);
        let verdicts: Vec<&str> = out.lines().collect();
        assert_eq!(verdicts.len(), cases.len());
        for ((class, a), shell) in cases.iter().zip(verdicts) {
            let parsed = a.parse::<Address<NetworkUnchecked>>();
            let rust = Solo::payee_for_identity(a).is_ok()
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
