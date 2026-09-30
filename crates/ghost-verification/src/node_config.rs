//! Operator-signed changes to a node's own `pool.toml` (#403).
//!
//! ## What may be changed, and why the list is so short
//!
//! An ALLOWLIST of scalar keys that cannot affect consensus, money, or identity. Everything else is
//! refused by name. A denylist would silently grant every key added later, which is how
//! `update version` came to exist as a 501 rather than a decision.
//!
//! ⛔ **Capability claims are deliberately absent** — `archive_mode`, `ghost_pay`, `reaper` and the
//! rest. They feed `NodeCapabilities::total_shares`, so flipping one changes how the node-reward
//! pool is divided. The decision (2026-09-29) is that a capability is earned by passing its
//! verification challenges, not granted by setting a flag: if an operator turns a feature on, the
//! pool should verify it properly and then award the reward, and nothing else. Making the flag
//! remotely settable would add a second, unverified route to the same money.
//!
//! ⚠ `archive_mode` already demonstrates the principle — `should_claim_archive` refuses to
//! advertise Archive on a hazed or pruned node whatever the config says. `ghost_pay` and `reaper`
//! have no such evidence gate today, which is the argument for keeping all of them off this list
//! rather than picking the safe-looking ones.
//!
//! ## Why it never restarts
//!
//! Nothing in `pool.toml` is re-read while the node runs, so a change here takes effect at the next
//! restart. That is deliberate: every node is in the mining DNS, so every restart sheds that node's
//! miners, and CLAUDE.md's rule is to batch config and binary changes into ONE restart per node.
//! This writes the file and says so; the change rides the next binary roll.
//!
//! ## Why it edits one line instead of reserialising
//!
//! `pool.toml` carries `internal_api_secret` and `signing_key`, and it is heavily commented. Parsing
//! it into a value tree and writing it back would drop every comment and put the secrets through a
//! serialiser for no reason. So a change rewrites exactly the one line it is changing and leaves
//! every other byte alone — and the result is parsed before it replaces the original, so a malformed
//! edit cannot land.

use std::fmt;

/// What a settable key holds. Rejecting the wrong type here means a bad value cannot reach the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    Bool,
    /// A positive integer. Zero is refused: every integer on this list is a limit, and zero would
    /// silently mean "accept nothing" rather than "no limit".
    PositiveInt,
    /// A short, printable, single-line string.
    ShortText,
}

/// `(toml section, key, kind)`. The section is written exactly as it appears in the file.
///
/// Sub-tables are their own sections: `[alerts.events]` is not reachable by writing into
/// `[alerts]`, and treating it as if it were would put the key in the wrong table.
pub const SETTABLE: &[(&str, &str, ValueKind)] = &[
    ("alerts", "enabled", ValueKind::Bool),
    ("alerts.events", "low_disk", ValueKind::Bool),
    ("alerts.events", "node_offline", ValueKind::Bool),
    ("alerts.events", "service_restart_loop", ValueKind::Bool),
    ("alerts.events", "behind_tip", ValueKind::Bool),
    ("alerts.events", "restart_needed", ValueKind::Bool),
    ("alerts.events", "peer_count_drop", ValueKind::Bool),
    ("alerts.events", "capability_drift", ValueKind::Bool),
    ("alerts.events", "block_found", ValueKind::Bool),
    ("alerts.events", "update_available", ValueKind::Bool),
    ("alerts.events", "mempool_congestion", ValueKind::Bool),
    ("alerts.events", "fee_spike", ValueKind::Bool),
    ("alerts.events", "failed_login", ValueKind::Bool),
    ("alerts.events", "reorg_detected", ValueKind::Bool),
    ("pool", "max_miners", ValueKind::PositiveInt),
    ("identity", "display_name", ValueKind::ShortText),
];

/// Longest a `display_name` may be. Long enough to be useful, short enough that it cannot be used
/// to smuggle bulk data into a file the operator reads by eye.
const MAX_TEXT: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The key is not on the allowlist. Carries the key so the refusal names it.
    NotSettable(String),
    /// Right key, wrong type of value.
    WrongType { key: String, want: ValueKind },
    /// The value is the right type but not acceptable (empty, too long, zero, multi-line).
    BadValue { key: String, why: String },
    /// The section exists nowhere in the file, so there is no correct place to put the key.
    NoSuchSection(String),
    /// The edited file no longer parses. The original is left untouched.
    WouldNotParse(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSettable(k) => write!(
                f,
                "'{k}' is not remotely settable. Only alert toggles, pool.max_miners and \
                 identity.display_name are. Capability claims are deliberately excluded: a \
                 capability is earned by passing its verification challenges, not by setting a flag"
            ),
            Self::WrongType { key, want } => write!(f, "'{key}' expects {want:?}"),
            Self::BadValue { key, why } => write!(f, "'{key}': {why}"),
            Self::NoSuchSection(s) => write!(f, "no [{s}] section in this node's pool.toml"),
            Self::WouldNotParse(e) => write!(f, "the edited config would not parse: {e}"),
        }
    }
}

/// The allowlist entry for a dotted key like `alerts.events.low_disk`, or `None`.
///
/// Splits on the LAST dot, because sections themselves contain dots (`alerts.events`).
pub fn lookup(dotted: &str) -> Option<(&'static str, &'static str, ValueKind)> {
    let (section, key) = dotted.rsplit_once('.')?;
    SETTABLE
        .iter()
        .find(|(s, k, _)| *s == section && *k == key)
        .map(|(s, k, v)| (*s, *k, *v))
}

/// Render a JSON value as TOML, refusing anything that is not the expected kind.
fn render(dotted: &str, kind: ValueKind, v: &serde_json::Value) -> Result<String, ConfigError> {
    match kind {
        ValueKind::Bool => {
            v.as_bool()
                .map(|b| b.to_string())
                .ok_or_else(|| ConfigError::WrongType {
                    key: dotted.into(),
                    want: kind,
                })
        }
        ValueKind::PositiveInt => {
            let n = v.as_u64().ok_or_else(|| ConfigError::WrongType {
                key: dotted.into(),
                want: kind,
            })?;
            if n == 0 {
                return Err(ConfigError::BadValue {
                    key: dotted.into(),
                    why: "zero would mean 'accept nothing' rather than 'no limit'".into(),
                });
            }
            Ok(n.to_string())
        }
        ValueKind::ShortText => {
            let s = v.as_str().ok_or_else(|| ConfigError::WrongType {
                key: dotted.into(),
                want: kind,
            })?;
            let t = s.trim();
            if t.is_empty() {
                return Err(ConfigError::BadValue {
                    key: dotted.into(),
                    why: "must not be empty".into(),
                });
            }
            if t.len() > MAX_TEXT {
                return Err(ConfigError::BadValue {
                    key: dotted.into(),
                    why: format!("longer than {MAX_TEXT} characters"),
                });
            }
            // ⛔ A newline or a quote would let one value write a second key, or break the file.
            if t.chars().any(|c| c.is_control() || c == '"' || c == '\\') {
                return Err(ConfigError::BadValue {
                    key: dotted.into(),
                    why: "must be one line, with no quotes or backslashes".into(),
                });
            }
            Ok(format!("\"{t}\""))
        }
    }
}

/// Apply one allowlisted change to `original`, returning the new file contents.
///
/// Pure: it takes and returns text, so the whole of it is testable without a config file, a node, or
/// a signature. The caller does the signature check and the atomic write.
///
/// Rewrites exactly the one line that sets the key, inside the right section, and leaves every other
/// byte — comments, ordering, spacing — untouched. If the section exists but the key does not, the
/// key is appended immediately after the section header.
pub fn apply(
    original: &str,
    dotted: &str,
    value: &serde_json::Value,
) -> Result<String, ConfigError> {
    let (section, key, kind) =
        lookup(dotted).ok_or_else(|| ConfigError::NotSettable(dotted.to_string()))?;
    let rendered = render(dotted, kind, value)?;

    let header = format!("[{section}]");
    let mut out: Vec<String> = Vec::new();
    let mut in_section = false;
    let mut wrote = false;
    let mut saw_section = false;

    for line in original.lines() {
        let t = line.trim();
        if t.starts_with('[') && t.ends_with(']') {
            // Leaving the section without having found the key: put it at the end of that section.
            if in_section && !wrote {
                out.push(format!("{key} = {rendered}"));
                wrote = true;
            }
            in_section = t == header;
            saw_section |= in_section;
            out.push(line.to_string());
            continue;
        }
        // `key =` at the start of the line, so a commented-out `# key = ...` is not matched and a
        // longer key that merely starts with this one (`max_miners_extra`) is not either.
        let is_target = in_section
            && !wrote
            && t.strip_prefix(key)
                .is_some_and(|r| r.trim_start().starts_with('='))
            && !t.starts_with('#');
        if is_target {
            out.push(format!("{key} = {rendered}"));
            wrote = true;
        } else {
            out.push(line.to_string());
        }
    }
    if in_section && !wrote {
        out.push(format!("{key} = {rendered}"));
        wrote = true;
    }
    if !saw_section {
        return Err(ConfigError::NoSuchSection(section.to_string()));
    }
    debug_assert!(wrote, "section was seen, so the key must have been written");

    let mut text = out.join("\n");
    if original.ends_with('\n') {
        text.push('\n');
    }

    // ⛔ Parse the RESULT, not the input. A surgical edit that produced something unparseable must
    // never replace a working config — the node would not come back from its next restart.
    toml::from_str::<toml::Value>(&text).map_err(|e| ConfigError::WouldNotParse(e.to_string()))?;
    Ok(text)
}

/// Read `path`, apply one allowlisted change, and replace the file atomically.
///
/// ⛔ Temp-file-then-rename, never a truncate-and-write. `pool.toml` is the file the node needs to
/// start: a partial write would leave a node that does not come back from its next restart, and the
/// deploy gate's config check would only notice on the next deploy. The rename is atomic, so the
/// file is either wholly the old one or wholly the new one.
///
/// The temp file is created 0600 before anything is written to it, because it briefly holds the
/// same secrets the original does.
pub fn write_change(
    path: &std::path::Path,
    dotted: &str,
    value: &serde_json::Value,
) -> Result<(), ConfigError> {
    use std::io::Write;
    let original = std::fs::read_to_string(path).map_err(|e| ConfigError::BadValue {
        key: dotted.into(),
        why: format!("cannot read config: {e}"),
    })?;
    let updated = apply(&original, dotted, value)?;

    let tmp = path.with_extension("toml.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).map_err(|e| ConfigError::BadValue {
        key: dotted.into(),
        why: format!("cannot open temp file: {e}"),
    })?;
    let wrote = f
        .write_all(updated.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| ConfigError::BadValue {
            key: dotted.into(),
            why: format!("cannot write temp file: {e}"),
        });
    if let Err(e) = wrote {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        ConfigError::BadValue {
            key: dotted.into(),
            why: format!("cannot replace config: {e}"),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(super) const SAMPLE: &str = r#"# Ghost pool configuration
[identity]
node_id = "abc"
display_name = "vm5"

[pool]
# how many miners this node accepts
max_miners = 500
internal_api_secret = "SECRET-MUST-SURVIVE"

[storage]
archive_mode = false

[alerts]
enabled = true

[alerts.events]
low_disk = true
block_found = false
"#;

    #[test]
    fn it_changes_only_the_one_line() {
        let out = apply(SAMPLE, "pool.max_miners", &json!(900)).unwrap();
        assert!(out.contains("max_miners = 900"));
        assert!(!out.contains("max_miners = 500"));
        // Everything else, byte for byte.
        assert!(out.contains("# how many miners this node accepts"));
        assert!(out.contains("internal_api_secret = \"SECRET-MUST-SURVIVE\""));
        assert!(out.contains("# Ghost pool configuration"));
        assert_eq!(SAMPLE.lines().count(), out.lines().count());
    }

    /// Every field of `NodeCapabilities`, and the config path an operator would have to set to
    /// claim it. `None` means the claim is not operator-settable by construction.
    ///
    /// ⛔ Mirrors the `NodeCapabilities { .. }` initialiser in `bins/ghost-pool/src/main.rs`,
    /// which is in a crate this one does not depend on — so the mapping cannot be read off a type
    /// and has to be declared. What CAN be derived is its completeness, and
    /// `scripts/check-capability-claims-are-not-settable.sh` does that in CI: every field of
    /// `NodeCapabilities` must appear here, and nothing else may.
    ///
    /// It is derived-checked because the hand-written version had already drifted (#963). It named
    /// `pool.public_mining` — not a field of any settings struct, removed when `mining_mode`
    /// replaced it, and cited BY NAME in `config.rs` as the key that sat in live configs for
    /// months meaning nothing — while omitting `network.mining_mode` and
    /// `coordinator.coordinator_enabled`, the two paths that actually drive a claim.
    pub(super) const CAPABILITY_CONFIG_PATHS: &[(&str, Option<&str>)] = &[
        ("archive_mode", Some("storage.archive_mode")),
        // Claimed via `config.ghost_pay_enabled()`, which reads `[ghost_pay] enabled`.
        ("ghost_pay", Some("ghost_pay.enabled")),
        // ⚠ NOT `pool.public_mining`. The claim is `matches!(mining_mode, MiningMode::PublicPool)`.
        ("public_mining", Some("network.mining_mode")),
        ("reaper", Some("reaper.enabled")),
        // Registration order — the first 101 nodes. No config path exists to set it.
        ("elder_status", None),
        // Earns the Wraith mixing fee rather than 5-4-3-2-1 shares, but it is still a role an
        // operator must not be able to switch on over HTTP.
        ("coordinator", Some("coordinator.coordinator_enabled")),
    ];

    /// ⛔ The decision this module exists to enforce: a capability is earned by passing its
    /// verification challenges, never by setting a flag.
    #[test]
    fn capability_claims_are_refused() {
        let mut checked = 0;
        for (field, path) in CAPABILITY_CONFIG_PATHS {
            let Some(k) = path else { continue };
            let e = apply(SAMPLE, k, &json!(true)).unwrap_err();
            assert!(
                matches!(e, ConfigError::NotSettable(ref got) if got == k),
                "{field}: '{k}' must be refused, got {e:?}"
            );
            assert!(
                e.to_string()
                    .contains("earned by passing its verification challenges"),
                "the refusal must say WHY: {e}"
            );
            checked += 1;
        }
        // A table that lost its entries would pass every assertion above by running none of them.
        assert!(
            checked >= 5,
            "only {checked} capability path(s) exercised — the table is too short to be the \
             whole set"
        );
        // And the file is untouched, because apply() returned Err before building anything.
        assert!(SAMPLE.contains("archive_mode = false"));
    }

    /// The allowlist is what does the refusing; the test above only samples it. Nothing in
    /// `SETTABLE` may be a path that drives a capability claim.
    #[test]
    fn no_capability_path_is_on_the_allowlist() {
        for (field, path) in CAPABILITY_CONFIG_PATHS {
            let Some(k) = path else { continue };
            let (section, key) = k.rsplit_once('.').expect("a dotted path");
            assert!(
                !SETTABLE
                    .iter()
                    .any(|(s, kk, _)| *s == section && *kk == key),
                "{field}: '{k}' drives a capability claim and must never be in SETTABLE"
            );
        }
    }

    #[test]
    fn a_sub_table_key_lands_in_its_own_section() {
        let out = apply(SAMPLE, "alerts.events.block_found", &json!(true)).unwrap();
        let ev = out.split("[alerts.events]").nth(1).unwrap();
        assert!(ev.contains("block_found = true"));
        // `[alerts]`'s own `enabled` must not have moved or changed.
        let alerts = out.split("[alerts]").nth(1).unwrap();
        assert!(alerts.starts_with("\nenabled = true"));
    }

    #[test]
    fn wrong_types_are_refused() {
        assert!(matches!(
            apply(SAMPLE, "alerts.enabled", &json!("yes")).unwrap_err(),
            ConfigError::WrongType { .. }
        ));
        assert!(matches!(
            apply(SAMPLE, "pool.max_miners", &json!("many")).unwrap_err(),
            ConfigError::WrongType { .. }
        ));
        assert!(matches!(
            apply(SAMPLE, "pool.max_miners", &json!(0)).unwrap_err(),
            ConfigError::BadValue { .. }
        ));
    }

    /// A value must not be able to write a second key or break the file.
    #[test]
    fn text_cannot_smuggle_a_second_key() {
        for bad in [
            "a\nmax_miners = 1",
            "has\"quote",
            "back\\slash",
            "   ",
            &"x".repeat(65),
        ] {
            assert!(
                apply(SAMPLE, "identity.display_name", &json!(bad)).is_err(),
                "{bad:?} must be refused"
            );
        }
        let ok = apply(SAMPLE, "identity.display_name", &json!("vm5-canary")).unwrap();
        assert!(ok.contains("display_name = \"vm5-canary\""));
    }

    #[test]
    fn a_missing_section_is_an_error_not_a_new_section() {
        let stripped = SAMPLE.replace("[alerts.events]", "[something.else]");
        assert!(matches!(
            apply(&stripped, "alerts.events.low_disk", &json!(false)).unwrap_err(),
            ConfigError::NoSuchSection(_)
        ));
    }

    /// A key absent from a section that DOES exist is appended there, not silently dropped.
    #[test]
    fn a_missing_key_in_a_real_section_is_appended() {
        let without = SAMPLE.replace("block_found = false\n", "");
        let out = apply(&without, "alerts.events.block_found", &json!(true)).unwrap();
        let ev = out.split("[alerts.events]").nth(1).unwrap();
        assert!(ev.contains("block_found = true"));
    }

    /// A commented-out line must not be mistaken for the setting.
    #[test]
    fn a_commented_key_is_not_the_target() {
        let c = SAMPLE.replace("max_miners = 500", "# max_miners = 500\nmax_miners = 500");
        let out = apply(&c, "pool.max_miners", &json!(7)).unwrap();
        assert!(
            out.contains("# max_miners = 500"),
            "the comment must survive"
        );
        assert!(out.contains("max_miners = 7"));
        assert!(!out.contains("\nmax_miners = 500"));
    }

    #[test]
    fn the_result_is_always_valid_toml() {
        let out = apply(SAMPLE, "alerts.enabled", &json!(false)).unwrap();
        let v: toml::Value = toml::from_str(&out).expect("must parse");
        assert_eq!(v["alerts"]["enabled"].as_bool(), Some(false));
        assert_eq!(
            v["pool"]["internal_api_secret"].as_str(),
            Some("SECRET-MUST-SURVIVE")
        );
    }
}

#[cfg(test)]
mod disk_tests {
    use super::*;
    use serde_json::json;

    /// The file must be replaced wholly, keep its secrets, and never be left half-written.
    #[test]
    fn write_change_replaces_atomically_and_keeps_everything_else() {
        let dir = std::env::temp_dir().join(format!("ghost-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("pool.toml");
        std::fs::write(&p, super::tests::SAMPLE).unwrap();

        write_change(&p, "pool.max_miners", &json!(1234)).unwrap();
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(after.contains("max_miners = 1234"));
        assert!(after.contains("internal_api_secret = \"SECRET-MUST-SURVIVE\""));
        assert!(after.contains("# how many miners this node accepts"));
        // No temp file left behind.
        assert!(!p.with_extension("toml.tmp").exists());

        // A refused key must not touch the file at all.
        let before = after.clone();
        assert!(write_change(&p, "storage.archive_mode", &json!(true)).is_err());
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            before,
            "a refusal must not write"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "the replaced config must stay 0600, got {mode:o}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
