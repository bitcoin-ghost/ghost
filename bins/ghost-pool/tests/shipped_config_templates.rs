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

use std::collections::BTreeSet;
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
const REMOVED_KEYS: &[(&str, &str)] = &[(
    "public_mining",
    "removed — `mining_mode` is the single source of truth for discoverability",
)];

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

/// Each mode's required keys, mirroring what config validation enforces at load.
///
/// If this drifts from the real validation the templates stop being runnable, which is the whole
/// failure this file exists to prevent — so it is asserted against every shipped template rather
/// than against a hand-written fixture.
#[test]
fn every_template_declares_what_its_mode_requires() {
    for p in templates() {
        let raw = std::fs::read_to_string(&p).expect("readable");
        let doc: toml::Table = raw.parse().expect("valid TOML");
        let Some(network) = doc.get("network").and_then(|v| v.as_table()) else {
            continue; // not a node config (no [network] section)
        };
        let Some(mode) = network.get("mining_mode").and_then(|v| v.as_str()) else {
            continue;
        };

        let keys: BTreeSet<&str> = network.keys().map(|k| k.as_str()).collect();
        // Mirrors `NodeConfig::validate_mining_mode` in ghost-common — the validation that
        // actually runs at load against the TOML.
        //
        // ⚠ Do NOT take these from `TemplateConfig::validate` in template.rs. That validates a
        // struct built in code, not the config file: `pool_payout_address` is a TemplateConfig
        // field populated from `config.pool.treasury_address` at main.rs:3074 and is not a TOML
        // key at all. Asserting it here would demand a key that does nothing — the same defect as
        // the `public_mining` line this file exists to keep out.
        let required: &[&str] = match mode {
            // Needs `signing_key` for DNS registration; no payout key in [network].
            "public_pool" => &["signing_key"],
            // Password-gated. Miners are paid from the aggregated ledger, not a [network] key.
            "private_pool" => &["private_mining_password"],
            // Password-gated, and names the single address the coinbase pays.
            "private_solo" => &["private_mining_password", "solo_payout_address"],
            other => panic!("{} declares unknown mining_mode `{other}`", p.display()),
        };

        for k in required {
            assert!(
                keys.contains(k),
                "{} is mining_mode = \"{mode}\" but does not set `{k}`, which that mode requires \
                 — following this template would fail config validation at startup",
                p.display()
            );
        }
    }
}

/// There must be a template for every mode, or a mode is undeployable in practice.
///
/// `private_pool` had none until 2026-08-19: the mode existed, was reachable from the API's
/// "disable public mining" toggle, and there was nothing to copy.
#[test]
fn every_mining_mode_has_a_template() {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for p in templates() {
        let raw = std::fs::read_to_string(&p).expect("readable");
        let doc: toml::Table = raw.parse().expect("valid TOML");
        if let Some(m) = doc
            .get("network")
            .and_then(|v| v.as_table())
            .and_then(|n| n.get("mining_mode"))
            .and_then(|v| v.as_str())
        {
            seen.insert(m.to_string());
        }
    }
    for mode in ["public_pool", "private_pool", "private_solo"] {
        assert!(
            seen.contains(mode),
            "no shipped template declares mining_mode = \"{mode}\" — an operator has nothing to \
             copy, and has to discover its required keys from validation errors"
        );
    }
}

/// ⛔ Syntactically-valid TOML that the BINARY REJECTS.
///
/// `every_shipped_template_parses_as_toml` reads green on a file `ghost-pool` will not start with,
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
