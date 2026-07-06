//! Node setup and configuration wizard backends.
//!
//! Provides `apply_*` functions that modify `NodeConfig` based on wizard field values.
//! Used by both the TUI wizard dispatch and the headless `ghost-setup` CLI.

use crate::config::{GhostPayConfig, HazeMode, NodeConfig, PolicyProfile};
use crate::identity::NodeIdentity;
use crate::types::TreasuryAddress;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Field values stored per field key (shared between wizard UI and setup backends)
#[derive(Debug, Clone)]
pub enum FieldValue {
    Text(String),
    Bool(bool),
    Selected(usize),
}

impl FieldValue {
    pub fn as_text(&self) -> &str {
        match self {
            FieldValue::Text(s) => s,
            _ => "",
        }
    }

    pub fn as_bool(&self) -> bool {
        match self {
            FieldValue::Bool(b) => *b,
            _ => false,
        }
    }

    pub fn as_selected(&self) -> usize {
        match self {
            FieldValue::Selected(i) => *i,
            _ => 0,
        }
    }
}

/// Result of initial setup
pub struct SetupResult {
    pub config_path: PathBuf,
    pub node_id_hex: String,
}

/// Load existing config, apply wizard changes, save atomically.
/// Used by all config-modifying wizards (change_setup, reaper, pool_setup, etc.)
fn load_and_modify(
    config_path: &Path,
    modify: impl FnOnce(&mut NodeConfig),
) -> Result<String, String> {
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Load config {}: {e}", config_path.display()))?;
    let mut config: NodeConfig =
        toml::from_str(&content).map_err(|e| format!("Parse config: {e}"))?;
    modify(&mut config);
    config
        .save_atomic(config_path)
        .map_err(|e| format!("Save config: {e}"))?;
    Ok(format!("Config updated: {}", config_path.display()))
}

/// Initial setup — creates new config from scratch (first-run wizard)
pub fn apply_initial_setup(
    fields: &HashMap<String, FieldValue>,
    config_dir: &Path,
    data_dir: &Path,
) -> Result<SetupResult, String> {
    let nickname = fields
        .get("nickname")
        .map(|v| v.as_text().to_string())
        .unwrap_or_default();
    // The wizard's "public_mining" toggle maps to mining_mode = PublicPool.
    // Disabled → keeps the default mining_mode (PublicPool unless overridden
    // elsewhere). Operators choosing private modes use a different setup flow.
    let public_mining_intent = fields
        .get("public_mining")
        .map(|v| v.as_bool())
        .unwrap_or(false);
    let payout_address = fields
        .get("payout_address")
        .map(|v| v.as_text().to_string())
        .unwrap_or_default();
    let archive_mode = fields
        .get("archive_mode")
        .map(|v| v.as_bool())
        .unwrap_or(true);
    let ghost_pay_enabled = fields.get("ghost_pay").map(|v| v.as_bool()).unwrap_or(true);
    let reaper_enabled = fields.get("reaper").map(|v| v.as_bool()).unwrap_or(true);
    let mempool_idx = fields
        .get("mempool_profile")
        .map(|v| v.as_selected())
        .unwrap_or(0);

    std::fs::create_dir_all(data_dir)
        .map_err(|e| format!("Failed to create {}: {}", data_dir.display(), e))?;
    std::fs::create_dir_all(config_dir)
        .map_err(|e| format!("Failed to create {}: {}", config_dir.display(), e))?;

    let config_path = config_dir.join("pool.toml");
    if config_path.exists() {
        return Err(format!("Config already exists: {}", config_path.display()));
    }

    // Generate or load Ed25519 identity (with PoW)
    let key_path = data_dir.join("node.key");
    let identity = if key_path.exists() {
        NodeIdentity::load(&key_path).map_err(|e| format!("Load key: {e}"))?
    } else {
        let id = NodeIdentity::generate();
        id.save(&key_path).map_err(|e| format!("Save key: {e}"))?;
        id
    };
    let node_id_hex = hex::encode(identity.node_id());

    // Generate API secret
    let mut secret_bytes = [0u8; 32];
    getrandom::getrandom(&mut secret_bytes).map_err(|e| format!("RNG: {e}"))?;
    let api_secret = hex::encode(secret_bytes);

    let profile = match mempool_idx {
        1 => PolicyProfile::BitcoinPure,
        2 => PolicyProfile::FullOpen,
        _ => PolicyProfile::Permissive,
    };

    let mut config = NodeConfig::default();
    config.identity.key_path = key_path;
    if !nickname.is_empty() {
        config.identity.display_name = Some(nickname);
    }
    config.network.mining_mode = if public_mining_intent {
        crate::config::MiningMode::PublicPool
    } else {
        crate::config::MiningMode::PrivatePool
    };
    config.network.noise_enabled = true;
    config.network.internal_api_secret = Some(api_secret);
    config.storage.archive_mode = archive_mode;
    config.policy.profile = profile;
    if !payout_address.is_empty() {
        config.pool.treasury_address = TreasuryAddress::from(payout_address);
    }
    if ghost_pay_enabled {
        config.ghost_pay = Some(GhostPayConfig::default());
    }
    config.reaper.enabled = reaper_enabled;

    config
        .save_atomic(&config_path)
        .map_err(|e| format!("Write config: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod: {e}"))?;
    }

    Ok(SetupResult {
        config_path,
        node_id_hex,
    })
}

/// Change setup — modify existing config fields
pub fn apply_change_setup(
    fields: &HashMap<String, FieldValue>,
    config_path: &Path,
) -> Result<String, String> {
    load_and_modify(config_path, |config| {
        if let Some(v) = fields.get("nickname") {
            let name = v.as_text().to_string();
            if !name.is_empty() {
                config.identity.display_name = Some(name);
            }
        }
        if let Some(v) = fields.get("public_mining") {
            config.network.mining_mode = if v.as_bool() {
                crate::config::MiningMode::PublicPool
            } else {
                crate::config::MiningMode::PrivatePool
            };
        }
        if let Some(v) = fields.get("payout_address") {
            let addr = v.as_text().to_string();
            if !addr.is_empty() {
                config.pool.treasury_address = TreasuryAddress::from(addr);
            }
        }
        if let Some(v) = fields.get("archive_mode") {
            config.storage.archive_mode = v.as_bool();
        }
        if let Some(v) = fields.get("ghost_pay") {
            if v.as_bool() {
                config.ghost_pay.get_or_insert(GhostPayConfig::default());
            } else {
                config.ghost_pay = None;
            }
        }
        if let Some(v) = fields.get("reaper") {
            config.reaper.enabled = v.as_bool();
        }
        if let Some(v) = fields.get("ghost_mode") {
            config.network.ghost_mode = v.as_bool();
        }
        if let Some(v) = fields.get("mempool_profile") {
            config.policy.profile = match v.as_selected() {
                1 => PolicyProfile::BitcoinPure,
                2 => PolicyProfile::FullOpen,
                _ => PolicyProfile::Permissive,
            };
        }
    })
}

/// Reaper — master switch plus per-vector detector selection.
///
/// Only the keys actually present in `fields` are applied, so partial updates
/// (e.g. a single detector toggled from the dashboard) leave the rest intact.
/// Field keys match the canonical `[reaper]` config keys; `"reaper"` is kept as
/// the master-switch key for the existing setup contract.
pub fn apply_reaper(
    fields: &HashMap<String, FieldValue>,
    config_path: &Path,
) -> Result<String, String> {
    load_and_modify(config_path, |config| {
        let r = &mut config.reaper;
        if let Some(v) = fields.get("reaper") {
            r.enabled = v.as_bool();
        }
        // Per-vector detector toggles.
        for (key, slot) in [
            ("reject_inscription", &mut r.reject_inscription),
            ("reject_dropstuffing", &mut r.reject_dropstuffing),
            ("reject_fakepubkey", &mut r.reject_fakepubkey),
            ("reject_annex", &mut r.reject_annex),
            ("reject_opreturn", &mut r.reject_opreturn),
            ("reject_runestone", &mut r.reject_runestone),
            ("reject_unreachable_code", &mut r.reject_unreachable_code),
            ("reject_excess_witness", &mut r.reject_excess_witness),
            (
                "reject_legacy_data_stuffing",
                &mut r.reject_legacy_data_stuffing,
            ),
            (
                "validate_pubkey_curve_point",
                &mut r.validate_pubkey_curve_point,
            ),
        ] {
            if let Some(v) = fields.get(key) {
                *slot = v.as_bool();
            }
        }
        // Thresholds.
        for (key, slot) in [
            ("max_op_return_bytes", &mut r.max_op_return_bytes),
            ("min_drop_size", &mut r.min_drop_size),
            ("min_excess_witness_bytes", &mut r.min_excess_witness_bytes),
            ("legacy_max_push_bytes", &mut r.legacy_max_push_bytes),
        ] {
            if let Some(v) = fields.get(key) {
                if let Ok(n) = v.as_text().parse::<usize>() {
                    *slot = n;
                }
            }
        }
    })
}

/// True when `tok` is a ghostd flag that this codebase manages via the drop-in,
/// so it must be stripped from the inherited `ExecStart` before the current set
/// is re-appended (keeps regeneration idempotent).
fn is_managed_ghostd_flag(tok: &str) -> bool {
    tok.starts_with("-ghostreaper") || tok.starts_with("-tormode")
}

/// Render a systemd drop-in for ghostd that applies the per-vector reaper
/// settings AND the node launch flags (e.g. Tor mode) to the daemon.
///
/// `exec_argv` is the daemon's resolved command line (e.g. the `argv[]` from
/// `systemctl show ghostd -p ExecStart --value`). Any existing managed flags
/// (`-ghostreaper*`, `-tormode`) are stripped and the current set is appended,
/// wrapped in a drop-in that resets and replaces `ExecStart` (the systemd
/// override idiom: an empty `ExecStart=` clears the inherited value before the
/// new one is set). A single drop-in carries every ghost-managed flag so the
/// separate toggles never fight over `ExecStart`.
pub fn ghostd_managed_dropin(
    exec_argv: &str,
    reaper: &crate::config::ReaperSettings,
    launch: &crate::config::NodeLaunchConfig,
) -> String {
    let base: Vec<&str> = exec_argv
        .split_whitespace()
        .filter(|tok| !is_managed_ghostd_flag(tok))
        .collect();
    let mut flags = reaper.ghostd_flags();
    flags.extend(launch.ghostd_flags());
    format!(
        "# Managed by `ghost-setup apply-reaper` — Ghost Reaper + node launch flags.\n\
         # Do not edit by hand; regenerate from pool.toml [reaper]/[node_launch].\n\
         [Service]\n\
         ExecStart=\n\
         ExecStart={} {}\n",
        base.join(" "),
        flags.join(" ")
    )
}

/// Pool setup — configure mining pool settings
pub fn apply_pool_setup(
    fields: &HashMap<String, FieldValue>,
    config_path: &Path,
) -> Result<String, String> {
    load_and_modify(config_path, |config| {
        if let Some(v) = fields.get("public_mining") {
            config.network.mining_mode = if v.as_bool() {
                crate::config::MiningMode::PublicPool
            } else {
                crate::config::MiningMode::PrivatePool
            };
        }
        if let Some(v) = fields.get("payout_address") {
            let addr = v.as_text().to_string();
            if !addr.is_empty() {
                config.pool.treasury_address = TreasuryAddress::from(addr);
            }
        }
    })
}

/// Ghost Mode — toggle privacy-enhanced relay
pub fn apply_ghost_mode(
    fields: &HashMap<String, FieldValue>,
    config_path: &Path,
) -> Result<String, String> {
    load_and_modify(config_path, |config| {
        if let Some(v) = fields.get("ghost_mode") {
            config.network.ghost_mode = v.as_bool();
        }
    })
}

/// Ghost Shroud — toggle relay delay privacy
pub fn apply_shroud(
    fields: &HashMap<String, FieldValue>,
    config_path: &Path,
) -> Result<String, String> {
    load_and_modify(config_path, |config| {
        if let Some(v) = fields.get("enabled") {
            config.network.shroud_enabled = v.as_bool();
        }
    })
}

/// Ghost Haze — configure block storage mode
pub fn apply_haze(
    fields: &HashMap<String, FieldValue>,
    config_path: &Path,
) -> Result<String, String> {
    load_and_modify(config_path, |config| {
        if let Some(v) = fields.get("haze_mode") {
            config.storage.haze_mode = match v.as_selected() {
                1 => HazeMode::Hazed,
                2 => HazeMode::FullArchive,
                _ => HazeMode::Standard,
            };
        }
    })
}

/// Mempool policy — select mempool acceptance profile
pub fn apply_mempool_policy(
    fields: &HashMap<String, FieldValue>,
    config_path: &Path,
) -> Result<String, String> {
    load_and_modify(config_path, |config| {
        if let Some(v) = fields.get("mempool_profile") {
            config.policy.profile = match v.as_selected() {
                1 => PolicyProfile::BitcoinPure,
                2 => PolicyProfile::FullOpen,
                _ => PolicyProfile::Permissive,
            };
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NodeLaunchConfig, ReaperSettings};

    #[test]
    fn test_ghostd_managed_dropin_strips_and_appends() {
        let exec = "/opt/ghost/bin/ghostd -signet -datadir=/var/lib/bitcoin -ghostreaper=enabled -port=38333";
        let s = ReaperSettings {
            reject_annex: false,
            ..Default::default()
        };
        let launch = NodeLaunchConfig::default();
        let dropin = ghostd_managed_dropin(exec, &s, &launch);

        // resets ExecStart then re-emits the base (minus any managed flags)
        assert!(dropin.contains("[Service]\nExecStart=\nExecStart="));
        assert!(dropin.contains("/opt/ghost/bin/ghostd"));
        assert!(dropin.contains("-signet"));
        assert!(dropin.contains("-port=38333"));
        // the old hardcoded master flag is stripped, replaced by the managed set
        assert_eq!(dropin.matches("-ghostreaper=").count(), 1);
        assert!(dropin.contains("-ghostreaper=enabled"));
        assert!(dropin.contains("-ghostreaper-rejectannex=0"));
        assert!(dropin.contains("-ghostreaper-rejectinscription=1"));
        assert!(dropin.contains("-ghostreaper-rejectdustflood=1"));
        assert!(dropin.contains("-ghostreaper-dustfloodthreshold=330"));
        // Tor off by default → no -tormode flag emitted.
        assert!(!dropin.contains("-tormode"));
    }

    #[test]
    fn test_ghostd_managed_dropin_tor_toggle_is_idempotent() {
        // Simulate a re-apply where the previous drop-in already added -tormode=1:
        // it must be stripped and re-added exactly once when still enabled, and
        // dropped entirely when disabled.
        let exec = "/opt/ghost/bin/ghostd -signet -tormode=1 -ghostreaper=enabled";
        let reaper = ReaperSettings::default();

        let on = ghostd_managed_dropin(
            exec,
            &reaper,
            &NodeLaunchConfig { tor_mode: true },
        );
        assert_eq!(on.matches("-tormode=1").count(), 1);

        let off = ghostd_managed_dropin(
            exec,
            &reaper,
            &NodeLaunchConfig { tor_mode: false },
        );
        assert!(!off.contains("-tormode"));
    }
}
