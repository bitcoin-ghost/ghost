//! Operator-signed changes to a node's own `pool.toml` (#403).
//!
//! ## What may be changed, and why the list is so short
//!
//! An ALLOWLIST of scalar keys that cannot affect consensus, money, or identity. Everything else is
//! refused. A denylist would silently grant every key added later, which is how `update version`
//! came to exist as a 501 rather than a decision. The refusal NAMES a category where one applies
//! ([`refusal_category`]) — but the category is only the explanation. What refuses is absence from
//! [`SETTABLE`], so a key nobody has categorised yet is refused all the same.
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
//! ## How the file is edited, and how a bad edit is stopped
//!
//! `pool.toml` carries `internal_api_secret` and `signing_key`, and it is heavily commented.
//! Reserialising it through `NodeConfig` would drop every comment and push the secrets through a
//! serialiser for no reason, so the edit goes through `toml_edit`, which changes the one value and
//! keeps every other byte — comments, ordering, spacing, a trailing `# comment` on the edited line.
//!
//! The result is then checked three ways before it may replace the original:
//!
//! 1. it must deserialize as the node's real [`NodeConfig`] — the exact call the node makes at
//!    startup. Parsing it as generic TOML is NOT enough: the first version of this module did that,
//!    and its `pool.max_miners` entry named a key `PoolConfig` does not have (`deny_unknown_fields`),
//!    so every accepted change produced a valid-TOML file the node would refuse at its next start;
//! 2. the node must actually READ the key ([`ghost_common::config::ignored_config_keys`]), so a
//!    write cannot report success for a setting that does nothing;
//! 3. every OTHER setting must be unchanged, compared as parsed values, so no edit can move or
//!    rewrite anything it was not asked to.

use std::fmt;

use ghost_common::config::NodeConfig;
use toml_edit::{Document, Item, Table, Value};

/// What a settable key holds. Rejecting the wrong type here means a bad value cannot reach the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    Bool,
    /// A positive integer that fits the `u32` the struct declares. Zero is refused: every integer on
    /// this list is a limit, and zero would silently mean "accept nothing" rather than "no limit".
    PositiveU32,
    /// A short, printable, single-line string.
    ShortText,
}

/// `(toml section, key, kind)`. The section is the dotted table path, exactly as in the file.
///
/// Every entry must be a real field of [`NodeConfig`] at that path — `every_settable_key_is_read_by_
/// the_node` proves it against the struct, so a wrong path fails the build rather than a node.
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
    // ⚠ `network`, not `pool`: `NetworkConfig::max_miners: u32`. `[pool]` has no such key.
    ("network", "max_miners", ValueKind::PositiveU32),
    ("identity", "display_name", ValueKind::ShortText),
];

/// Longest a `display_name` may be. Long enough to be useful, short enough that it cannot be used
/// to smuggle bulk data into a file the operator reads by eye.
const MAX_TEXT: usize = 64;

/// Why a key off the allowlist is refused. Only the explanation — refusal itself is decided by
/// absence from [`SETTABLE`], never by this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCategory {
    /// Secrets and key material.
    Credential,
    /// Where money is paid.
    MoneyDestination,
    /// Decides whether payouts go through BFT; `deploy-node.sh` gates on it.
    MiningMode,
    /// Network, epoch and shard geometry every node must agree on.
    ConsensusGeometry,
    /// A capability claim or role — it changes the node-reward split.
    CapabilityClaim,
    /// A path or URL that could redirect data or shares.
    DataRedirection,
    /// Not on the allowlist, and not in any named category. Includes keys that do not exist yet.
    NotOnAllowlist,
}

impl RefusalCategory {
    /// Stable wire name, used in the HTTP response.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::MoneyDestination => "money_destination",
            Self::MiningMode => "mining_mode",
            Self::ConsensusGeometry => "consensus_geometry",
            Self::CapabilityClaim => "capability_claim",
            Self::DataRedirection => "data_redirection",
            Self::NotOnAllowlist => "not_on_allowlist",
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::Credential => {
                "it is a credential, and credentials are never set over the network"
            }
            Self::MoneyDestination => "it is a money destination; changing it redirects payouts",
            Self::MiningMode => {
                "mining_mode decides whether payouts go through BFT, and deploy-node.sh gates on it"
            }
            Self::ConsensusGeometry => {
                "it is consensus geometry, which every node must agree on; a change on one node \
                 forks it from the rest"
            }
            Self::CapabilityClaim => {
                "it is a capability claim, which changes the node-reward split. A capability is \
                 earned by passing its verification challenges, not by setting a flag"
            }
            Self::DataRedirection => "it is a path or URL that could redirect data or shares",
            Self::NotOnAllowlist => {
                "only the alert toggles, network.max_miners and identity.display_name are remotely \
                 settable; anything not on that list is refused, including keys added later"
            }
        }
    }
}

/// The named reason a dotted path is refused.
///
/// Checks run most-specific-harm first, because one path can match several — a coordinator's fee
/// ADDRESS is a money destination before it is a coordinator setting, and `ghost_pay.epoch_blocks`
/// is consensus geometry before it is Ghost Pay.
pub fn refusal_category(dotted: &str) -> RefusalCategory {
    let lower = dotted.to_ascii_lowercase();
    let segs: Vec<&str> = lower.split('.').collect();
    let leaf = segs.last().copied().unwrap_or("");
    let any = |f: &dyn Fn(&str) -> bool| segs.iter().any(|s| f(s));

    if any(&|s| {
        matches!(
            s,
            "internal_api_secret"
                | "signing_key"
                | "key_path"
                | "rpc_user"
                | "rpc_password"
                | "signer"
                | "bot_token"
                | "genesis_password"
                | "cert_path"
        ) || s.contains("secret")
            || s.contains("password")
            || s.contains("token")
            || s.contains("private_key")
    }) {
        return RefusalCategory::Credential;
    }
    if any(&|s| {
        matches!(
            s,
            "node_payout_address" | "treasury_address" | "coordinator_fee_address"
        ) || s.contains("payout_address")
            || s.contains("treasury")
            || s.ends_with("fee_address")
    }) {
        return RefusalCategory::MoneyDestination;
    }
    if any(&|s| matches!(s, "mining_mode" | "public_mining")) {
        return RefusalCategory::MiningMode;
    }
    // `network` is consensus geometry only as a LEAF (`bitcoin.network`). As a section it holds
    // ports and limits, including the settable `max_miners`.
    if leaf == "network" || any(&|s| s == "epoch_blocks" || s.contains("shard")) {
        return RefusalCategory::ConsensusGeometry;
    }
    if any(&|s| {
        matches!(
            s,
            "archive_mode"
                | "ghost_pay"
                | "reaper"
                | "coordinator"
                | "tor_mode"
                | "ghost_mode"
                | "haze_mode"
        ) || s.starts_with("coordinator_")
            || s.starts_with("wraith_")
    }) {
        return RefusalCategory::CapabilityClaim;
    }
    if any(&|s| {
        matches!(s, "db_path" | "target_dir" | "webhook_url")
            || s.ends_with("_path")
            || s.ends_with("_dir")
            || s.ends_with("_url")
    }) {
        return RefusalCategory::DataRedirection;
    }
    RefusalCategory::NotOnAllowlist
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The key is not on the allowlist. Carries the key and why, so the refusal names both.
    NotSettable {
        key: String,
        category: RefusalCategory,
    },
    /// Right key, wrong type of value.
    WrongType { key: String, want: ValueKind },
    /// The value is the right type but not acceptable (empty, too long, zero, multi-line).
    BadValue { key: String, why: String },
    /// The existing file is not shaped so the key can be placed (e.g. `alerts = 5`), or is not TOML.
    Unplaceable { key: String, why: String },
    /// The edited file would not load as this node's config. The original is left untouched.
    WouldNotParse(String),
    /// Reading, writing or replacing the file failed. The original is left untouched.
    Io(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSettable { key, category } => {
                write!(f, "'{key}' is not remotely settable: {}", category.reason())
            }
            Self::WrongType { key, want } => write!(f, "'{key}' expects {want:?}"),
            Self::BadValue { key, why } => write!(f, "'{key}': {why}"),
            Self::Unplaceable { key, why } => write!(f, "cannot place '{key}': {why}"),
            Self::WouldNotParse(e) => write!(
                f,
                "the edited config would not load at this node's next start: {e}"
            ),
            Self::Io(e) => write!(f, "{e}"),
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

/// Turn a JSON value into a TOML value, refusing anything that is not the expected kind.
fn render(dotted: &str, kind: ValueKind, v: &serde_json::Value) -> Result<Value, ConfigError> {
    let wrong = || ConfigError::WrongType {
        key: dotted.into(),
        want: kind,
    };
    match kind {
        ValueKind::Bool => v.as_bool().map(Value::from).ok_or_else(wrong),
        ValueKind::PositiveU32 => {
            let n = v.as_u64().ok_or_else(wrong)?;
            if n == 0 {
                return Err(ConfigError::BadValue {
                    key: dotted.into(),
                    why: "zero would mean 'accept nothing' rather than 'no limit'".into(),
                });
            }
            // ⛔ The struct field is u32. A larger number is valid TOML and valid JSON, and would
            // stop the node loading its config at the next start.
            let n = u32::try_from(n).map_err(|_| ConfigError::BadValue {
                key: dotted.into(),
                why: format!("must be at most {}", u32::MAX),
            })?;
            Ok(Value::from(i64::from(n)))
        }
        ValueKind::ShortText => {
            let s = v.as_str().ok_or_else(wrong)?;
            let t = s.trim();
            if t.is_empty() {
                return Err(ConfigError::BadValue {
                    key: dotted.into(),
                    why: "must not be empty".into(),
                });
            }
            if t.chars().count() > MAX_TEXT {
                return Err(ConfigError::BadValue {
                    key: dotted.into(),
                    why: format!("longer than {MAX_TEXT} characters"),
                });
            }
            // toml_edit escapes whatever it is given, so this is not what keeps the file valid.
            // It keeps the value one readable line in a file the operator reads by eye.
            if t.chars().any(|c| c.is_control() || c == '"' || c == '\\') {
                return Err(ConfigError::BadValue {
                    key: dotted.into(),
                    why: "must be one line, with no quotes or backslashes".into(),
                });
            }
            Ok(Value::from(t))
        }
    }
}

/// Set `section.key = new` in the document, creating `section` if it is absent.
///
/// An existing value keeps its decoration, so `max_miners = 500  # comment` becomes
/// `max_miners = 900  # comment`, and the key keeps its own spacing because the item is replaced in
/// place rather than re-inserted.
fn place(
    doc: &mut Document,
    dotted: &str,
    section: &str,
    key: &str,
    mut new: Value,
) -> Result<(), ConfigError> {
    let unplaceable = |why: String| ConfigError::Unplaceable {
        key: dotted.into(),
        why,
    };
    let mut cur: &mut dyn toml_edit::TableLike = doc.as_table_mut();
    for seg in section.split('.') {
        if cur.get(seg).is_none() {
            // Implicit, so creating `[alerts.events]` in a file with no `[alerts]` writes ONE header,
            // not an empty `[alerts]` above it. The final load decides whether the struct accepts it.
            let mut t = Table::new();
            t.set_implicit(true);
            cur.insert(seg, Item::Table(t));
        }
        cur = cur
            .get_mut(seg)
            .and_then(Item::as_table_like_mut)
            .ok_or_else(|| {
                unplaceable(format!("'{seg}' in this node's pool.toml is not a table"))
            })?;
    }
    match cur.get_mut(key) {
        Some(item) => {
            let old = item
                .as_value()
                .ok_or_else(|| unplaceable(format!("'{key}' is a table, not a value")))?;
            *new.decor_mut() = old.decor().clone();
            *item = Item::Value(new);
        }
        None => {
            cur.insert(key, Item::Value(new));
        }
    }
    Ok(())
}

/// Remove a dotted path from a parsed value, then drop any table the removal left empty.
fn remove_path(v: &mut toml::Value, path: &[&str]) {
    let Some((first, rest)) = path.split_first() else {
        return;
    };
    let Some(t) = v.as_table_mut() else { return };
    if rest.is_empty() {
        t.remove(*first);
        return;
    }
    if let Some(child) = t.get_mut(*first) {
        remove_path(child, rest);
        if child.as_table().is_some_and(|c| c.is_empty()) {
            t.remove(*first);
        }
    }
}

/// The checks every edited file must pass before it may replace the original. See the module docs.
///
/// Error text is the parser's MESSAGE only, never its source snippet: a snippet quotes lines of the
/// file, and this file holds secrets.
fn validate_result(original: &str, edited: &str, dotted: &str) -> Result<(), ConfigError> {
    // 1. Load exactly as the node does at startup.
    toml::from_str::<NodeConfig>(edited)
        .map_err(|e| ConfigError::WouldNotParse(e.message().to_string()))?;

    // 2. The node must actually read the key, or "written" would describe a setting that does nothing.
    let ignored = ghost_common::config::ignored_config_keys(edited).map_err(|_| {
        ConfigError::WouldNotParse("could not determine which keys the node reads".into())
    })?;
    if ignored.iter().any(|k| k == dotted) {
        return Err(ConfigError::WouldNotParse(format!(
            "this node's config struct does not read '{dotted}'"
        )));
    }

    // 3. Nothing but the target may differ.
    let mut before: toml::Value =
        toml::from_str(original).map_err(|e| ConfigError::Unplaceable {
            key: dotted.into(),
            why: format!("the current pool.toml is not valid TOML: {}", e.message()),
        })?;
    let mut after: toml::Value =
        toml::from_str(edited).map_err(|e| ConfigError::WouldNotParse(e.message().to_string()))?;
    let path: Vec<&str> = dotted.split('.').collect();
    remove_path(&mut before, &path);
    remove_path(&mut after, &path);
    if before != after {
        return Err(ConfigError::WouldNotParse(format!(
            "setting '{dotted}' would also have changed other settings; refusing"
        )));
    }
    Ok(())
}

/// Apply one allowlisted change to `original`, returning the new file contents.
///
/// Pure: it takes and returns text, so the whole of it is testable without a config file, a node, or
/// a signature. The caller does the signature check and the atomic write.
pub fn apply(
    original: &str,
    dotted: &str,
    value: &serde_json::Value,
) -> Result<String, ConfigError> {
    // ⛔ The allowlist is consulted FIRST and alone decides refusal. The category is only the reason.
    let Some((section, key, kind)) = lookup(dotted) else {
        return Err(ConfigError::NotSettable {
            key: dotted.to_string(),
            category: refusal_category(dotted),
        });
    };
    let rendered = render(dotted, kind, value)?;

    let mut doc: Document = original.parse().map_err(|_| ConfigError::Unplaceable {
        key: dotted.into(),
        why: "the current pool.toml is not valid TOML".into(),
    })?;
    place(&mut doc, dotted, section, key, rendered)?;
    let text = doc.to_string();

    validate_result(original, &text, dotted)?;
    Ok(text)
}

/// Serialises read-modify-write. Two concurrent changes would otherwise each read the same original
/// and the second rename would silently discard the first.
static WRITE_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
thread_local! {
    /// Test-only fault injection: fail after the temp file is complete, immediately before rename.
    static FAIL_BEFORE_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Read `path`, apply one allowlisted change, and replace the file atomically.
///
/// ⛔ Temp-file-then-rename, never a truncate-and-write. `pool.toml` is the file the node needs to
/// start: a partial write would leave a node that does not come back from its next restart. The
/// rename is atomic, so the file is either wholly the old one or wholly the new one.
///
/// The temp file is created 0600 with a random name (`create_new`, so it cannot follow a planted
/// file), then given the ORIGINAL's owner and mode before the rename. If the owner cannot be
/// preserved the change is refused rather than written — a root-owned config quietly becoming
/// owned by the node's user would widen who can rewrite it.
///
/// A symlinked `pool.toml` is resolved first, so the real file is replaced and the link survives.
pub fn write_change(
    path: &std::path::Path,
    dotted: &str,
    value: &serde_json::Value,
) -> Result<(), ConfigError> {
    use std::io::Write;

    // Refuse before touching the disk at all.
    if lookup(dotted).is_none() {
        return Err(ConfigError::NotSettable {
            key: dotted.to_string(),
            category: refusal_category(dotted),
        });
    }

    let _guard = WRITE_LOCK.lock();
    let io = |what: &str, e: std::io::Error| ConfigError::Io(format!("{what}: {e}"));

    let real = std::fs::canonicalize(path).map_err(|e| io("cannot resolve config path", e))?;
    let meta = std::fs::metadata(&real).map_err(|e| io("cannot stat config", e))?;
    let original = std::fs::read_to_string(&real).map_err(|e| io("cannot read config", e))?;
    let updated = apply(&original, dotted, value)?;

    let dir = real
        .parent()
        .ok_or_else(|| ConfigError::Io("config path has no parent directory".into()))?;
    let name = real
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "pool.toml".into());
    let mut rnd = [0u8; 8];
    getrandom::getrandom(&mut rnd)
        .map_err(|e| ConfigError::Io(format!("cannot generate temp name: {e}")))?;
    let tmp = dir.join(format!(".{name}.{}.tmp", hex::encode(rnd)));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .map_err(|e| io("cannot create temp file", e))?;

    let finish = (|| -> Result<(), ConfigError> {
        f.write_all(updated.as_bytes())
            .map_err(|e| io("cannot write temp file", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            std::os::unix::fs::fchown(&f, Some(meta.uid()), Some(meta.gid()))
                .map_err(|e| io("cannot give the new file the original's owner; refusing", e))?;
            f.set_permissions(std::fs::Permissions::from_mode(meta.mode() & 0o7777))
                .map_err(|e| io("cannot give the new file the original's mode", e))?;
        }
        #[cfg(not(unix))]
        let _ = &meta;
        f.sync_all().map_err(|e| io("cannot sync temp file", e))?;
        #[cfg(test)]
        if FAIL_BEFORE_RENAME.with(|f| f.get()) {
            return Err(ConfigError::Io("injected failure before rename".into()));
        }
        std::fs::rename(&tmp, &real).map_err(|e| io("cannot replace config", e))
    })();
    drop(f);
    if let Err(e) = finish {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // Make the rename itself durable. The file is already whole either way, so this is best-effort.
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A real, shipped, heavily-commented `pool.toml` that the node loads. Testing against a
    /// hand-written fragment is how `pool.max_miners` shipped: the fragment had a `[pool]
    /// max_miners` line, so it looked right, and no real config does.
    pub(super) const REAL: &str = include_str!("../../../config/mainnet.toml");

    #[test]
    fn the_fixture_is_a_config_the_node_loads() {
        toml::from_str::<NodeConfig>(REAL).expect("config/mainnet.toml must load as NodeConfig");
    }

    /// Every allowlisted key must be a real field the node reads, at that exact path. This is the
    /// test that would have stopped `pool.max_miners`.
    #[test]
    fn every_settable_key_is_read_by_the_node() {
        for (section, key, kind) in SETTABLE {
            let dotted = format!("{section}.{key}");
            let v = match kind {
                ValueKind::Bool => json!(false),
                ValueKind::PositiveU32 => json!(7),
                ValueKind::ShortText => json!("probe"),
            };
            let out = apply(REAL, &dotted, &v).unwrap_or_else(|e| panic!("{dotted}: {e}"));
            let cfg: toml::Value = toml::from_str(&out).unwrap();
            let mut cur = &cfg;
            for seg in dotted.split('.') {
                cur = cur
                    .get(seg)
                    .unwrap_or_else(|| panic!("{dotted} missing after write"));
            }
            assert_eq!(
                cur.to_string(),
                toml::Value::try_from(&v).unwrap().to_string(),
                "{dotted}"
            );
        }
    }

    #[test]
    fn max_miners_lands_in_network_and_the_node_loads_it() {
        let out = apply(REAL, "network.max_miners", &json!(900)).unwrap();
        let cfg: NodeConfig = toml::from_str(&out).unwrap();
        assert_eq!(cfg.network.max_miners, 900);
    }

    /// The exact shipped defect: `[pool] max_miners`. It must now be REFUSED, not written.
    #[test]
    fn pool_max_miners_is_refused_because_it_does_not_exist() {
        let e = apply(REAL, "pool.max_miners", &json!(900)).unwrap_err();
        assert!(matches!(
            e,
            ConfigError::NotSettable {
                category: RefusalCategory::NotOnAllowlist,
                ..
            }
        ));
    }

    /// The validator must use the node's real loader. This is the edit the first version of this
    /// module produced for `pool.max_miners` — valid TOML, fatal to the node.
    #[test]
    fn the_validator_refuses_a_valid_toml_file_the_node_cannot_load() {
        let mut doc: Document = REAL.parse().unwrap();
        doc["pool"]["max_miners"] = toml_edit::value(900);
        let edited = doc.to_string();
        toml::from_str::<toml::Value>(&edited).expect("it IS valid TOML — that is the trap");
        let e = validate_result(REAL, &edited, "pool.max_miners").unwrap_err();
        assert!(matches!(e, ConfigError::WouldNotParse(_)), "{e:?}");
    }

    /// An edit that changes anything besides its target must be refused, even if it loads.
    #[test]
    fn the_validator_refuses_collateral_changes() {
        let edited = REAL
            .replacen("max_miners = 10000", "max_miners = 9", 1)
            .replacen(
                "display_name = \"Ghost Pool Mainnet\"",
                "display_name = \"x\"",
                1,
            );
        assert_ne!(edited, REAL);
        let e = validate_result(REAL, &edited, "network.max_miners").unwrap_err();
        assert!(e.to_string().contains("other settings"), "{e}");
    }

    #[test]
    fn it_changes_only_the_one_value_and_keeps_every_comment() {
        let out = apply(REAL, "network.max_miners", &json!(900)).unwrap();
        assert!(out.contains("max_miners = 900"));
        assert!(!out.contains("max_miners = 10000"));
        // Byte-for-byte everywhere else: the diff is exactly one line.
        let a: Vec<&str> = REAL.lines().collect();
        let b: Vec<&str> = out.lines().collect();
        assert_eq!(a.len(), b.len());
        let diffs: Vec<_> = a.iter().zip(&b).filter(|(x, y)| x != y).collect();
        assert_eq!(diffs.len(), 1, "{diffs:?}");
        assert_eq!(REAL.ends_with('\n'), out.ends_with('\n'));
    }

    #[test]
    fn a_trailing_comment_on_the_edited_line_survives() {
        let c = REAL.replacen("max_miners = 10000", "max_miners = 10000   # cap", 1);
        let out = apply(&c, "network.max_miners", &json!(5)).unwrap();
        assert!(out.contains("max_miners = 5   # cap"), "comment lost");
    }

    /// The line-based editor this replaced could not see a header with a trailing comment.
    #[test]
    fn a_header_with_a_trailing_comment_is_still_a_header() {
        let c = format!("{REAL}\n[alerts] # operator alerts\nenabled = true\n");
        let out = apply(&c, "alerts.enabled", &json!(false)).unwrap();
        let cfg: NodeConfig = toml::from_str(&out).unwrap();
        assert!(!cfg.alerts.enabled);
        assert!(out.contains("[alerts] # operator alerts"));
    }

    /// A commented-out line must not be mistaken for the setting.
    #[test]
    fn a_commented_key_is_not_the_target() {
        let c = REAL.replacen(
            "max_miners = 10000",
            "# max_miners = 500\nmax_miners = 10000",
            1,
        );
        let out = apply(&c, "network.max_miners", &json!(7)).unwrap();
        assert!(
            out.contains("# max_miners = 500"),
            "the comment must survive"
        );
        assert!(out.contains("\nmax_miners = 7"));
    }

    /// A section the file lacks but the struct defaults (`[alerts]`) is created, once, and loads.
    #[test]
    fn a_missing_defaulted_section_is_created() {
        assert!(!REAL.contains("[alerts"), "fixture assumption");
        let out = apply(REAL, "alerts.events.block_found", &json!(false)).unwrap();
        assert_eq!(out.matches("[alerts.events]").count(), 1);
        assert!(!out.contains("[alerts]\n"), "no empty parent header");
        let cfg: NodeConfig = toml::from_str(&out).unwrap();
        assert!(!cfg.alerts.events.block_found);
        assert!(cfg.alerts.events.low_disk, "siblings keep their defaults");
    }

    #[test]
    fn a_sub_table_key_lands_in_its_own_section() {
        let c = format!("{REAL}\n[alerts]\nenabled = true\n\n[alerts.events]\nlow_disk = true\n");
        let out = apply(&c, "alerts.events.block_found", &json!(false)).unwrap();
        let cfg: NodeConfig = toml::from_str(&out).unwrap();
        assert!(cfg.alerts.enabled);
        assert!(!cfg.alerts.events.block_found);
    }

    #[test]
    fn wrong_types_and_bounds_are_refused() {
        for (k, v) in [
            ("alerts.enabled", json!("yes")),
            ("alerts.enabled", json!(1)),
            ("network.max_miners", json!("many")),
            ("network.max_miners", json!(-5)),
            ("network.max_miners", json!(1.5)),
            ("identity.display_name", json!(5)),
        ] {
            assert!(
                matches!(apply(REAL, k, &v), Err(ConfigError::WrongType { .. })),
                "{k} = {v}"
            );
        }
        for v in [json!(0), json!(u64::from(u32::MAX) + 1), json!(u64::MAX)] {
            assert!(
                matches!(
                    apply(REAL, "network.max_miners", &v),
                    Err(ConfigError::BadValue { .. })
                ),
                "max_miners = {v}"
            );
        }
        let out = apply(REAL, "network.max_miners", &json!(u32::MAX)).unwrap();
        let cfg: NodeConfig = toml::from_str(&out).unwrap();
        assert_eq!(cfg.network.max_miners, u32::MAX);
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
                apply(REAL, "identity.display_name", &json!(bad)).is_err(),
                "{bad:?} must be refused"
            );
        }
        let ok = apply(REAL, "identity.display_name", &json!("vm5-canary")).unwrap();
        let cfg: NodeConfig = toml::from_str(&ok).unwrap();
        assert_eq!(cfg.identity.display_name.as_deref(), Some("vm5-canary"));
    }

    /// The shapes the brief names, each refused with its NAMED reason.
    #[test]
    fn each_refused_category_is_named() {
        use RefusalCategory::*;
        for (k, want) in [
            ("network.internal_api_secret", Credential),
            ("network.signing_key", Credential),
            ("identity.key_path", Credential),
            ("bitcoin.rpc_user", Credential),
            ("bitcoin.rpc_password", Credential),
            ("alerts.channels.telegram.bot_token", Credential),
            ("pool.node_payout_address", MoneyDestination),
            ("pool.treasury_address", MoneyDestination),
            ("coordinator.coordinator_fee_address", MoneyDestination),
            ("network.mining_mode", MiningMode),
            ("bitcoin.network", ConsensusGeometry),
            ("ghost_pay.epoch_blocks", ConsensusGeometry),
            ("pool.shard_arm_genesis", ConsensusGeometry),
            ("pool.shard_coinbase", ConsensusGeometry),
            ("pool.share_shard", ConsensusGeometry),
            ("storage.archive_mode", CapabilityClaim),
            ("ghost_pay.enabled", CapabilityClaim),
            ("reaper.enabled", CapabilityClaim),
            ("coordinator.coordinator_enabled", CapabilityClaim),
            ("coordinator.wraith_election_enabled", CapabilityClaim),
            ("node_launch.tor_mode", CapabilityClaim),
            ("storage.ghost_mode", CapabilityClaim),
            ("storage.haze_mode", CapabilityClaim),
            ("storage.db_path", DataRedirection),
            ("backup.target_dir", DataRedirection),
            ("alerts.channels.email.webhook_url", DataRedirection),
            // Keys that do not exist yet, and real keys nobody categorised: refused all the same.
            ("alerts.events.some_future_toggle", NotOnAllowlist),
            ("network.sv2_port", NotOnAllowlist),
            ("pool.max_miners", NotOnAllowlist),
            ("max_miners", NotOnAllowlist),
            ("", NotOnAllowlist),
        ] {
            let e = apply(REAL, k, &json!(true)).unwrap_err();
            match &e {
                ConfigError::NotSettable { key, category } => {
                    assert_eq!(key, k);
                    assert_eq!(*category, want, "{k}");
                }
                other => panic!("{k}: expected a refusal, got {other:?}"),
            }
            assert!(e.to_string().contains(want.reason()), "{k}: {e}");
        }
    }

    /// ⛔ The allowlist must never contain anything a named category covers. If someone adds, say,
    /// `coordinator.coordinator_enabled` to SETTABLE, this fails — the categories are the
    /// second line of defence against an allowlist that grew the wrong way.
    #[test]
    fn nothing_on_the_allowlist_falls_in_a_named_refusal_category() {
        for (s, k, _) in SETTABLE {
            let dotted = format!("{s}.{k}");
            assert_eq!(
                refusal_category(&dotted),
                RefusalCategory::NotOnAllowlist,
                "'{dotted}' is allowlisted but looks like a refused category"
            );
        }
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
            let e = apply(REAL, k, &json!(true)).unwrap_err();
            assert!(
                matches!(
                    e,
                    ConfigError::NotSettable { ref key, category }
                        if key == k && matches!(
                            category,
                            RefusalCategory::CapabilityClaim | RefusalCategory::MiningMode
                        )
                ),
                "{field}: '{k}' must be refused as a capability claim, got {e:?}"
            );
            checked += 1;
        }
        // A table that lost its entries would pass every assertion above by running none of them.
        assert!(
            checked >= 5,
            "only {checked} capability path(s) exercised — the table is too short to be the \
             whole set"
        );
    }

    /// The allowlist is what does the refusing; the test above only samples it. Nothing in
    /// `SETTABLE` may be a path that drives a capability claim.
    #[test]
    fn no_capability_path_is_on_the_allowlist() {
        for (field, path) in CAPABILITY_CONFIG_PATHS {
            let Some(k) = path else { continue };
            assert!(
                lookup(k).is_none(),
                "{field}: '{k}' drives a capability claim and must never be in SETTABLE"
            );
        }
    }

    #[test]
    fn a_non_table_in_the_way_is_refused_not_overwritten() {
        let c = format!("alerts = 5\n{REAL}");
        let e = apply(&c, "alerts.enabled", &json!(true)).unwrap_err();
        assert!(matches!(e, ConfigError::Unplaceable { .. }), "{e:?}");
    }

    /// Error text must never quote the file: a parser snippet would print secrets.
    #[test]
    fn errors_never_quote_the_file() {
        let secret = "SECRET-MUST-NOT-LEAK";
        let c = REAL.replace("${INTERNAL_API_SECRET}", secret);
        let mut doc: Document = c.parse().unwrap();
        doc["network"]["bogus_key"] = toml_edit::value(1);
        let edited = doc.to_string();
        let e = validate_result(&c, &edited, "network.max_miners").unwrap_err();
        assert!(!e.to_string().contains(secret), "{e}");
    }
}

#[cfg(test)]
mod disk_tests {
    use super::*;
    use serde_json::json;

    fn tmp_config() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pool.toml");
        std::fs::write(&p, super::tests::REAL).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        (dir, p)
    }

    fn leftovers(dir: &std::path::Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "pool.toml")
            .collect()
    }

    /// The file must be replaced wholly, keep its comments and mode, and leave nothing behind.
    #[test]
    fn write_change_replaces_atomically_and_keeps_everything_else() {
        let (dir, p) = tmp_config();
        write_change(&p, "network.max_miners", &json!(1234)).unwrap();
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(after.contains("max_miners = 1234"));
        assert_eq!(after.lines().count(), super::tests::REAL.lines().count());
        assert!(
            leftovers(dir.path()).is_empty(),
            "{:?}",
            leftovers(dir.path())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o640,
                "the original's mode must be kept, got {mode:o}"
            );
        }
    }

    /// Neither a refusal nor an invalid value may touch the file.
    #[test]
    fn a_refused_or_invalid_change_does_not_write() {
        let (dir, p) = tmp_config();
        let before = std::fs::read(&p).unwrap();
        assert!(write_change(&p, "storage.archive_mode", &json!(true)).is_err());
        assert!(write_change(&p, "network.max_miners", &json!(0)).is_err());
        assert!(write_change(&p, "pool.max_miners", &json!(5)).is_err());
        assert_eq!(
            std::fs::read(&p).unwrap(),
            before,
            "a refusal must not write"
        );
        assert!(leftovers(dir.path()).is_empty());
    }

    /// A write that fails AFTER the temp file holds the new contents — the last moment before the
    /// rename — must leave the original byte-identical and remove the temp file.
    #[test]
    fn a_failure_after_the_temp_file_leaves_the_original_whole() {
        let (dir, p) = tmp_config();
        let before = std::fs::read(&p).unwrap();
        FAIL_BEFORE_RENAME.with(|f| f.set(true));
        let r = write_change(&p, "network.max_miners", &json!(5));
        FAIL_BEFORE_RENAME.with(|f| f.set(false));
        assert!(matches!(r, Err(ConfigError::Io(_))), "{r:?}");
        assert_eq!(std::fs::read(&p).unwrap(), before);
        assert!(
            leftovers(dir.path()).is_empty(),
            "{:?}",
            leftovers(dir.path())
        );
    }

    /// A config the node cannot currently load cannot be edited into one it can — and is untouched.
    #[test]
    fn an_already_broken_config_is_not_touched() {
        let (dir, p) = tmp_config();
        let mut doc: Document = super::tests::REAL.parse().unwrap();
        doc["pool"]["not_a_field"] = toml_edit::value(1);
        std::fs::write(&p, doc.to_string()).unwrap();
        let before = std::fs::read(&p).unwrap();
        assert!(write_change(&p, "network.max_miners", &json!(5)).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), before);
        assert!(leftovers(dir.path()).is_empty());
    }

    /// A symlinked config: the TARGET is replaced and the link survives as a link.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_config_keeps_its_link() {
        let (dir, real) = tmp_config();
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        write_change(&link, "network.max_miners", &json!(77)).unwrap();
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(std::fs::read_to_string(&real)
            .unwrap()
            .contains("max_miners = 77"));
    }

    /// Concurrent changes to different keys must BOTH land; without the lock the second rename
    /// discards the first.
    #[test]
    fn concurrent_changes_do_not_lose_each_other() {
        let (_dir, p) = tmp_config();
        let keys: Vec<&str> = SETTABLE
            .iter()
            .filter(|(s, _, kind)| *s == "alerts.events" && *kind == ValueKind::Bool)
            .map(|(_, k, _)| *k)
            .collect();
        std::thread::scope(|s| {
            for k in &keys {
                let p = &p;
                s.spawn(move || {
                    write_change(p, &format!("alerts.events.{k}"), &json!(false)).unwrap();
                });
            }
        });
        let cfg: NodeConfig = toml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        let ev = toml::Value::try_from(&cfg.alerts.events).unwrap();
        for k in &keys {
            assert_eq!(ev[*k].as_bool(), Some(false), "{k} was lost");
        }
    }
}
