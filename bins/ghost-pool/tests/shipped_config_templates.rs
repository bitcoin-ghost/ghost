//! Every `config/*.toml` we ship must parse, and must declare what its mode requires.
//!
//! Nothing validated the shipped templates before this file existed, and it showed: all three of
//! them set `public_mining`, a key that was removed from the config struct. There is no
//! `#[serde(deny_unknown_fields)]`, so it was read, ignored, and never complained about — while
//! `mainnet-solo.toml` annotated it `# Not discoverable via DNS`, which is exactly what an
//! operator would trust and exactly what it no longer did.
//!
//! A template is documentation that people paste into production. A wrong one is worse than a
//! missing one, because it is believed.

use std::path::{Path, PathBuf};

/// Repo-root `config/` directory, resolved from this crate rather than the cwd so the test works
/// under `cargo test` from anywhere in the workspace.
fn config_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("config")
}

fn templates() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(config_dir())
        .expect("config/ must exist")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    v.sort();
    assert!(!v.is_empty(), "no shipped templates found in config/");
    v
}

/// Keys that were removed from the config and must never reappear in a template.
///
/// Unknown keys are silently ignored, so a stale one produces no error anywhere — it just quietly
/// tells the reader something untrue. Add to this list whenever a config field is deleted.
const REMOVED_KEYS: &[(&str, &str)] = &[
    ("public_mining", "removed — every node is a node pool node"),
    ("wraith_enabled", "removed with Wraith"),
    ("wraith_election_enabled", "removed with Wraith"),
    (
        "coordinator_port",
        "removed with the in-process Wraith coordinator",
    ),
    (
        "coordinator_role_enabled",
        "removed with the in-process Wraith coordinator",
    ),
    (
        "coordinator_fee_address",
        "removed with the in-process Wraith coordinator",
    ),
    ("virtual_block_secs", "removed with Ghost Pay"),
    ("epoch_blocks", "removed with Ghost Pay"),
    ("genesis_password", "removed with the MPC ceremony"),
    ("mining_mode", "removed with solo and private modes"),
    (
        "private_mining_password",
        "removed with solo and private modes",
    ),
    ("solo_payout_address", "removed with solo and private modes"),
    (
        "treasury_address",
        "removed — the treasury is the node pool's compiled-in address",
    ),
    ("min_payout_sats", "removed with the old payout ledger"),
    (
        "payout_interval_blocks",
        "removed with the old payout ledger",
    ),
    ("share_shard", "removed with the share shard"),
    ("shard_arm_genesis", "removed with the share shard"),
    ("shard_coinbase", "removed with the share shard"),
    ("node_payout_address", "removed with node rewards"),
    ("noise_enabled", "removed with the old mesh"),
    ("seed_nodes", "removed with the old mesh"),
    (
        "share_propagation",
        "removed with the old mesh's `[network.p2p]` ports",
    ),
    (
        "block_announcement",
        "removed with the old mesh's `[network.p2p]` ports",
    ),
    (
        "consensus_voting",
        "removed with the old mesh's `[network.p2p]` ports",
    ),
    (
        "health_monitoring",
        "removed with the old mesh's `[network.p2p]` ports",
    ),
    (
        "elder_management",
        "removed with the old mesh's `[network.p2p]` ports",
    ),
    (
        "payout_proposal",
        "removed with the old mesh's `[network.p2p]` ports",
    ),
    (
        "payout_transaction",
        "removed with the old mesh's `[network.p2p]` ports",
    ),
];

/// Sections that were removed whole. Installed configs may still carry them and load (they are
/// read and ignored), but a template must not offer them.
const REMOVED_SECTIONS: &[(&str, &str)] = &[
    ("ghost_pay", "removed with Ghost Pay"),
    ("coordinator", "removed with the coordinator capability"),
];

#[test]
fn no_template_has_a_removed_section() {
    for p in templates() {
        let raw = std::fs::read_to_string(&p).expect("readable");
        let doc: toml::Table = raw.parse().expect("valid TOML");
        for (section, why) in REMOVED_SECTIONS {
            assert!(
                !doc.contains_key(*section),
                "{} has a `[{section}]` section, which was {why}",
                p.display()
            );
        }
    }
}

#[test]
fn every_shipped_template_parses_as_toml() {
    for p in templates() {
        let raw = std::fs::read_to_string(&p).expect("readable");
        if let Err(e) = raw.parse::<toml::Table>() {
            panic!("{} is not valid TOML: {e}", p.display());
        }
    }
}

#[test]
fn no_template_sets_a_removed_key() {
    for p in templates() {
        let raw = std::fs::read_to_string(&p).expect("readable");
        for (line_no, line) in raw.lines().enumerate() {
            let code = line.split('#').next().unwrap_or("").trim();
            if code.is_empty() {
                continue; // a comment mentioning the key is how we warn people off it
            }
            for (key, why) in REMOVED_KEYS {
                let is_assignment = code.split('=').next().is_some_and(|lhs| lhs.trim() == *key);
                assert!(
                    !is_assignment,
                    "{}:{} sets `{key}`, which is {why}. A template that sets a dead key tells \
                     the reader it does something. It does not.",
                    p.display(),
                    line_no + 1
                );
            }
        }
    }
}

/// ⛔ Syntactically-valid TOML that the BINARY REJECTS.
///
/// `every_shipped_template_parses_as_toml` reads green on a file `ghost-mining` will not start with,
/// because "parses" there means TOML grammar and nothing more. Measured 2026-08-23: BOTH
/// `mainnet-solo.toml` and `mainnet-private-pool.toml` were valid TOML and failed to deserialize —
/// their `[ghost_pay]` sections omitted `virtual_block_secs`, `epoch_blocks` and `wraith_enabled`,
/// none of which carry a serde default. An operator pasting either into production got a node that
/// would not start, and the suite said the templates were fine.
///
/// This asserts the thing that matters: the shipped struct accepts the shipped file.
#[test]
fn every_shipped_template_deserializes_as_a_node_config() {
    let mut checked = 0usize;
    for path in templates() {
        let raw = std::fs::read_to_string(&path).expect("read template");
        let parsed: Result<ghost_common::config::NodeConfig, _> = toml::from_str(&raw);
        assert!(
            parsed.is_ok(),
            "{} is valid TOML but does NOT deserialize as NodeConfig — an operator pasting this \
             into production gets a node that will not start.\n  {}",
            path.display(),
            parsed.err().map(|e| e.to_string()).unwrap_or_default()
        );
        checked += 1;
    }
    // A loop that inspected nothing must fail rather than pass silently.
    assert!(
        checked > 0,
        "no templates were checked — the glob found nothing"
    );
}

/// Keys the operator wrote that the struct SILENTLY IGNORED.
///
/// There is no `#[serde(deny_unknown_fields)]`, so a removed key or a typo is read, discarded and
/// never mentioned. `public_mining` outlived its own struct field in every shipped template that
/// way, annotated with behaviour it no longer had — and a template is documentation people paste
/// into production, so a wrong one is worse than a missing one because it is believed.
#[test]
fn no_shipped_template_contains_a_key_the_struct_ignores() {
    let mut checked = 0usize;
    for path in templates() {
        let raw = std::fs::read_to_string(&path).expect("read template");
        let ignored = ghost_common::config::ignored_config_keys(&raw)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(
            ignored.is_empty(),
            "{} sets key(s) the config struct ignores: {}\n  An ignored key is a setting the \
             operator believes is in force and which does nothing at all.",
            path.display(),
            ignored.join(", ")
        );
        checked += 1;
    }
    assert!(
        checked > 0,
        "no templates were checked — the glob found nothing"
    );
}

/// The `[alerts]` block `install-node.sh` writes must deserialize — in BOTH shapes.
///
/// `AlertsConfig` carries `#[serde(deny_unknown_fields)]`, so a single renamed key makes the
/// generated `pool.toml` unparseable and the node refuses to start. The installer is fetched
/// standalone and has no repo to read, so nothing otherwise connects its heredoc to the struct —
/// the same gap that let all three shipped templates carry a removed `public_mining` key.
///
/// Both shapes matter. #985 was that the installer wrote NO `[alerts]` section at all, so
/// `enabled` defaulted false and all fourteen detectors fired into nothing on a fresh node. The
/// fix emits a real section either way: configured when `--alert-webhook` is given, and an honest
/// `enabled = false` plus a commented template when it is not. A block claiming `enabled = true`
/// with nowhere to deliver would be worse than either, because it reads as configured.
///
/// Extracted from the script rather than restated here, so the two cannot drift.
#[test]
fn the_installers_alerts_block_parses_in_both_shapes() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("scripts/install-node.sh");
    let raw = std::fs::read_to_string(&script).expect("install-node.sh must be readable");

    // Every `[alerts]` section the script writes, read line by line from the heredoc bodies.
    //
    // ⚠ A line that is EXACTLY `[alerts]` starts one. Matching the bare string also hit this
    // file's own prose and the installer's comments, which is how the first two versions of this
    // test failed on text that was never config.
    let mut blocks: Vec<String> = Vec::new();
    let lines: Vec<&str> = raw.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        if lines[i].trim() != "[alerts]" {
            i += 1;
            continue;
        }
        let mut body = vec!["[alerts]".to_string()];
        i += 1;
        while i < lines.len() {
            let l = lines[i];
            // The heredoc terminator, or the start of the shell logic after it, ends the block.
            if l.trim() == "ALERTS" || l.trim_start().starts_with("if [[") || l.trim() == ")" {
                break;
            }
            // Commented-out template lines are part of the shape being offered.
            let stripped = l.trim_start().trim_start_matches('#').trim_start();
            body.push(stripped.to_string());
            i += 1;
        }
        blocks.push(
            body.join("\n")
                .replace("${ALERT_WEBHOOK}", "https://ntfy.sh")
                .replace("${ALERT_TOPIC}", "ghost-node"),
        );
    }

    assert!(
        !blocks.is_empty(),
        "no `[alerts]` block found in install-node.sh — #985 was that it wrote none at all, so \
         its absence is the regression this test exists to catch"
    );

    let mut saw_enabled_true = false;
    for (i, body) in blocks.iter().enumerate() {
        // The block is a NodeConfig FRAGMENT rooted at `[alerts]`, so parse it the way the node
        // would see it rather than as a bare AlertsConfig.
        #[derive(serde::Deserialize)]
        struct Fragment {
            alerts: ghost_common::config::AlertsConfig,
        }
        let cfg = toml::from_str::<Fragment>(body)
            .map(|f| f.alerts)
            .unwrap_or_else(|e| {
                panic!(
                    "install-node.sh `[alerts]` block #{i} does not deserialize: {e}\n\
                 AlertsConfig is deny_unknown_fields, so a renamed key here makes the generated \
                 pool.toml unparseable and the node refuses to start.\n--- block ---\n{body}"
                )
            });
        if cfg.enabled {
            saw_enabled_true = true;
            // An enabled block must be able to deliver, or it is a lie that reads as configured.
            let ch = &cfg.channels;
            assert!(
                (ch.push.enabled && ch.push.webhook_url.is_some())
                    || ch.email.enabled
                    || ch.telegram.enabled,
                "install-node.sh writes `[alerts] enabled = true` with no deliverable channel — \
                 every alert would be computed and dropped, while reading as configured"
            );
        }
    }

    assert!(
        saw_enabled_true,
        "no `[alerts]` shape in install-node.sh ever sets `enabled = true` — the --alert-webhook \
         path must produce a genuinely enabled block, or #985 is not fixed"
    );
}

/// A config installed before the removals must still load, and must not write the dead keys back.
///
/// Installed `pool.toml` files carry a `[ghost_pay]` section (every installer wrote one), `[pool]
/// genesis_password` on nodes that guarded the MPC genesis, a `[coordinator]` section on nodes that
/// opted into the coordinator capability, and the old ledger's keys: `[network] mining_mode`, the
/// private and solo settings, `[pool] treasury_address`, `min_payout_sats`,
/// `payout_interval_blocks`, `node_payout_address` and the share-shard flags, and the old mesh's
/// `[network] noise_enabled`, `seed_nodes` and `[network.p2p]` ports. The structs reject
/// unknown keys, so each retired key and section is accepted explicitly and ignored. If this test
/// fails, upgrading a node would leave it unable to start.
///
/// zk and MPC never had `pool.toml` keys of their own (they were configured through the
/// `ZK_*` / `MPC_PARAMS_PATH` environment), and no `[l2]` section ever existed, so there is
/// nothing else to tolerate.
#[test]
fn a_config_with_retired_keys_still_loads() {
    let mut raw = std::fs::read_to_string(config_dir().join("mainnet.toml")).expect("read");
    for section in ["[ghost_pay]", "[coordinator]"] {
        assert!(
            !raw.contains(section),
            "the template still has a {section} section"
        );
    }
    raw = raw.replacen(
        "[pool]\n",
        "[pool]\n\
         genesis_password = \"retired\"\n\
         treasury_address = \"bc1qexample\"\n\
         min_payout_sats = 100000\n\
         payout_interval_blocks = 100\n\
         node_payout_address = \"bc1qexample\"\n\
         share_shard = true\n\
         shard_arm_genesis = true\n\
         shard_coinbase = false\n",
        1,
    );
    assert!(
        raw.contains("genesis_password = \"retired\""),
        "the template has no [pool] section"
    );
    raw = raw.replacen(
        "[network]\n",
        "[network]\n\
         mining_mode = \"private_solo\"\n\
         private_mining_password = \"retired-password\"\n\
         solo_payout_address = \"bc1qexample\"\n\
         noise_enabled = true\n\
         seed_nodes = [\"203.0.113.7:8559\"]\n",
        1,
    );
    assert!(
        raw.contains("mining_mode = \"private_solo\""),
        "the template has no [network] section"
    );
    raw.push_str(
        "\n[ghost_pay]\n\
         enabled = true\n\
         virtual_block_secs = 10\n\
         epoch_blocks = 2160\n\
         payout_address = \"bc1qexample\"\n\
         wraith_enabled = true\n\
         transfer_fee_bps = 10\n\
         \n[coordinator]\n\
         wraith_election_enabled = true\n\
         coordinator_enabled = true\n\
         advertised_endpoint = \"203.0.113.7:9100\"\n\
         coordinator_port = 9100\n\
         coordinator_role_enabled = true\n\
         coordinator_fee_address = \"bc1qexample\"\n\
         \n[network.p2p]\n\
         share_propagation = 8555\n\
         block_announcement = 8556\n\
         consensus_voting = 8557\n\
         health_monitoring = 8558\n\
         discovery = 8559\n\
         elder_management = 8560\n\
         payout_proposal = 8561\n\
         payout_transaction = 8562\n",
    );

    let cfg: ghost_common::config::NodeConfig = toml::from_str(&raw)
        .unwrap_or_else(|e| panic!("a config with the retired keys must load: {e}"));

    // Written back, the retired keys are gone and the rest survives.
    let written = toml::to_string(&cfg).expect("serialize");
    for key in [
        "ghost_pay",
        "virtual_block_secs",
        "epoch_blocks",
        "genesis_password",
        "wraith_enabled",
        "coordinator",
        "advertised_endpoint",
        "mining_mode",
        "private_mining_password",
        "solo_payout_address",
        "treasury_address",
        "min_payout_sats",
        "payout_interval_blocks",
        "node_payout_address",
        "share_shard",
        "shard_arm_genesis",
        "shard_coinbase",
        "noise_enabled",
        "seed_nodes",
        "[network.p2p]",
        "share_propagation",
        "payout_transaction",
    ] {
        assert!(
            !written.contains(key),
            "retired key `{key}` was written back"
        );
    }
    assert!(written.contains("[pool]"));
    assert!(written.contains("internal_api_secret"));

    // A real typo is still refused, in a retired-key-bearing section and beside them.
    for (from, to) in [
        ("shard_coinbase = false", "shard_coinbsae = false"),
        (
            "mining_mode = \"private_solo\"",
            "mining_mdoe = \"private_solo\"",
        ),
        ("max_miners = 10000", "max_minres = 10000"),
        ("noise_enabled = true", "noise_enabeld = true"),
    ] {
        assert!(raw.contains(from), "fixture lost `{from}`");
        let typo = raw.replacen(from, to, 1);
        assert!(
            toml::from_str::<ghost_common::config::NodeConfig>(&typo).is_err(),
            "an unknown key that was never a config field must still be rejected: `{to}`"
        );
    }
}
