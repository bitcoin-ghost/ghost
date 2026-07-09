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
        if let Some(v) = fields.get("ghost_mode_local_egress") {
            config.network.ghost_mode_local_egress = v.as_bool();
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

/// Every ghostd flag prefix this codebase owns via the drop-in. A token matching
/// any of these is stripped from the inherited `ExecStart` before the current set
/// is re-appended, which is what keeps regeneration idempotent: re-applying with
/// the same config yields the same `ExecStart`, and toggling a setting off drops
/// its flag entirely rather than leaving a stale copy behind. All are emitted by
/// `ReaperSettings::ghostd_flags` / `NodeLaunchConfig::ghostd_flags`.
const MANAGED_GHOSTD_FLAG_PREFIXES: &[&str] = &[
    // Reaper (per-vector) + Tor.
    "-ghostreaper",
    // BUDS tier/policy mempool-acceptance gate (allowed-tier set, content
    // toggles, custom per-field limits). ghostd already accepts these flags;
    // Phase 2 emits them from PolicyConfig::ghostd_flags through this drop-in.
    "-ghostpolicy",
    "-tormode",
    // Daemon / node launch settings (NodeLaunchConfig).
    "-maxmempool",
    "-mempoolexpiry",
    "-mempoolfullrbf",
    "-maxconnections",
    "-maxuploadtarget",
    "-dbcache",
    "-blockfilterindex",
    "-peerblockfilters",
    "-onlynet",
    "-i2psam",
    "-i2pacceptincoming",
    // Storage mode (StorageConfig): archive un-prune + Ghost Haze. `-reindex`
    // and `-exorcist` are ONE-SHOTs — listing their prefixes here guarantees a
    // stale copy is stripped on every regeneration, so a one-shot flag can only
    // ever be present while its `*_pending` marker is set.
    "-prune",
    "-reindex",
    "-hazemode",
    "-exorcist",
];

/// True when `tok` is a ghostd flag that this codebase manages via the drop-in,
/// so it must be stripped from the inherited `ExecStart` before the current set
/// is re-appended (keeps regeneration idempotent).
fn is_managed_ghostd_flag(tok: &str) -> bool {
    MANAGED_GHOSTD_FLAG_PREFIXES
        .iter()
        .any(|p| tok.starts_with(p))
}

/// Render a systemd drop-in for ghostd that applies the per-vector reaper
/// settings AND the node launch flags (e.g. Tor mode) to the daemon.
///
/// `exec_argv` is the daemon's resolved command line (e.g. the `argv[]` from
/// `systemctl show ghostd -p ExecStart --value`). Any existing managed flags
/// (`-ghostreaper*`, `-tormode`, the daemon flags, and the storage-mode flags in
/// `MANAGED_GHOSTD_FLAG_PREFIXES`) are stripped and the current set is appended,
/// wrapped in a drop-in that resets and replaces `ExecStart` (the systemd
/// override idiom: an empty `ExecStart=` clears the inherited value before the
/// new one is set). A single drop-in carries every ghost-managed flag so the
/// separate toggles never fight over `ExecStart`.
pub fn ghostd_managed_dropin(
    exec_argv: &str,
    reaper: &crate::config::ReaperSettings,
    launch: &crate::config::NodeLaunchConfig,
    storage: &crate::config::StorageConfig,
) -> String {
    let base: Vec<&str> = exec_argv
        .split_whitespace()
        .filter(|tok| !is_managed_ghostd_flag(tok))
        .collect();
    let mut flags = reaper.ghostd_flags();
    flags.extend(launch.ghostd_flags());
    flags.extend(storage.ghostd_flags());
    format!(
        "# Managed by `ghost-setup apply-reaper` — Ghost Reaper + node launch + storage flags.\n\
         # Do not edit by hand; regenerate from pool.toml [reaper]/[node_launch]/[storage].\n\
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
        if let Some(v) = fields.get("ghost_mode_local_egress") {
            config.network.ghost_mode_local_egress = v.as_bool();
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
    use crate::config::{HazeMode, NodeLaunchConfig, ReaperSettings, StorageConfig};

    #[test]
    fn test_ghostd_managed_dropin_strips_and_appends() {
        let exec = "/opt/ghost/bin/ghostd -signet -datadir=/var/lib/bitcoin -ghostreaper=enabled -port=38333";
        let s = ReaperSettings {
            reject_annex: false,
            ..Default::default()
        };
        let launch = NodeLaunchConfig::default();
        let storage = StorageConfig::default();
        let dropin = ghostd_managed_dropin(exec, &s, &launch, &storage);

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
        // Default storage (standard, non-archive) → no storage flags emitted.
        assert!(!dropin.contains("-prune"));
        assert!(!dropin.contains("-reindex"));
        assert!(!dropin.contains("-hazemode"));
        assert!(!dropin.contains("-exorcist"));
    }

    #[test]
    fn test_ghostd_managed_dropin_tor_toggle_is_idempotent() {
        // Simulate a re-apply where the previous drop-in already added -tormode=1:
        // it must be stripped and re-added exactly once when still enabled, and
        // dropped entirely when disabled.
        let exec = "/opt/ghost/bin/ghostd -signet -tormode=1 -ghostreaper=enabled";
        let reaper = ReaperSettings::default();

        let storage = StorageConfig::default();
        let on = ghostd_managed_dropin(
            exec,
            &reaper,
            &NodeLaunchConfig { tor_mode: true, ..Default::default() },
            &storage,
        );
        assert_eq!(on.matches("-tormode=1").count(), 1);

        let off = ghostd_managed_dropin(
            exec,
            &reaper,
            &NodeLaunchConfig { tor_mode: false, ..Default::default() },
            &storage,
        );
        assert!(!off.contains("-tormode"));
    }

    #[test]
    fn test_ghostd_managed_dropin_daemon_flags_coexist_and_idempotent() {
        // A prior drop-in already carried Tor + reaper + a stale daemon flag set;
        // re-applying with a new daemon config must strip the stale copies and
        // emit each managed flag exactly once, alongside the reaper + tor flags.
        let exec = "/opt/ghost/bin/ghostd -signet -datadir=/var/lib/bitcoin \
                    -tormode=1 -ghostreaper=enabled -maxmempool=100 -dbcache=300 \
                    -onlynet=ipv4 -port=38333";
        let reaper = ReaperSettings::default();
        let launch = NodeLaunchConfig {
            tor_mode: true,
            max_mempool_mb: Some(600),
            mempool_expiry_hours: Some(48),
            full_rbf: Some(false),
            max_connections: Some(50),
            max_upload_target_mb: Some("2G".to_string()),
            dbcache_mb: Some(2048),
            block_filter_index: Some(true),
            peer_block_filters: Some(true),
            onlynet: vec!["onion".to_string(), "i2p".to_string()],
            i2p_sam: Some("127.0.0.1:7656".to_string()),
            i2p_accept_incoming: Some(true),
        };

        let storage = StorageConfig::default();
        let dropin = ghostd_managed_dropin(exec, &reaper, &launch, &storage);

        // Base non-managed args survive.
        assert!(dropin.contains("/opt/ghost/bin/ghostd"));
        assert!(dropin.contains("-signet"));
        assert!(dropin.contains("-datadir=/var/lib/bitcoin"));
        assert!(dropin.contains("-port=38333"));

        // Each managed daemon flag appears exactly once (stale values stripped).
        assert_eq!(dropin.matches("-maxmempool=").count(), 1);
        assert!(dropin.contains("-maxmempool=600"));
        assert_eq!(dropin.matches("-dbcache=").count(), 1);
        assert!(dropin.contains("-dbcache=2048"));
        assert!(dropin.contains("-mempoolexpiry=48"));
        assert_eq!(dropin.matches("-mempoolfullrbf=").count(), 1);
        assert!(dropin.contains("-mempoolfullrbf=0"));
        assert!(dropin.contains("-maxconnections=50"));
        assert!(dropin.contains("-maxuploadtarget=2G"));
        assert!(dropin.contains("-blockfilterindex=1"));
        assert!(dropin.contains("-peerblockfilters=1"));
        assert!(dropin.contains("-i2psam=127.0.0.1:7656"));
        assert!(dropin.contains("-i2pacceptincoming=1"));

        // onlynet re-emitted per network, and the stale ipv4 is gone.
        assert!(dropin.contains("-onlynet=onion"));
        assert!(dropin.contains("-onlynet=i2p"));
        assert!(!dropin.contains("-onlynet=ipv4"));
        assert_eq!(dropin.matches("-onlynet=").count(), 2);

        // Coexists with Tor + reaper, each once.
        assert_eq!(dropin.matches("-tormode=1").count(), 1);
        assert_eq!(dropin.matches("-ghostreaper=").count(), 1);

        // Idempotence: feeding the generated ExecStart back in yields the same
        // managed flag set.
        let regen_exec = dropin
            .lines()
            .rev()
            .find(|l| l.starts_with("ExecStart=/"))
            .unwrap()
            .trim_start_matches("ExecStart=");
        let dropin2 = ghostd_managed_dropin(regen_exec, &reaper, &launch, &storage);
        assert_eq!(dropin2.matches("-maxmempool=").count(), 1);
        assert_eq!(dropin2.matches("-onlynet=").count(), 2);
        assert_eq!(dropin2.matches("-tormode=1").count(), 1);
    }

    #[test]
    fn test_ghostd_managed_dropin_archive_emits_prune_zero() {
        // Archive mode ON → -prune=0 emitted so ghostd stops pruning. Archive
        // OFF emits nothing (leaves ghostd's own configured prune behaviour).
        let exec = "/opt/ghost/bin/ghostd -signet -datadir=/var/lib/bitcoin";
        let reaper = ReaperSettings::default();
        let launch = NodeLaunchConfig::default();

        let on = ghostd_managed_dropin(
            exec,
            &reaper,
            &launch,
            &StorageConfig { archive_mode: true, ..Default::default() },
        );
        assert!(on.contains("-prune=0"));
        // No reindex unless explicitly armed.
        assert!(!on.contains("-reindex"));

        let off = ghostd_managed_dropin(exec, &reaper, &launch, &StorageConfig::default());
        assert!(!off.contains("-prune"));
    }

    #[test]
    fn test_ghostd_managed_dropin_reindex_oneshot_strips_stale() {
        // A prior drop-in armed the one-shot -reindex + -prune=0. Regenerating
        // once the marker has been cleared must strip the stale -reindex, leaving
        // -prune=0 (archive still on) with no reindex.
        let exec = "/opt/ghost/bin/ghostd -signet -prune=0 -reindex";
        let reaper = ReaperSettings::default();
        let launch = NodeLaunchConfig::default();

        let armed = ghostd_managed_dropin(
            exec,
            &reaper,
            &launch,
            &StorageConfig { archive_mode: true, reindex_pending: true, ..Default::default() },
        );
        assert_eq!(armed.matches("-reindex").count(), 1);
        assert_eq!(armed.matches("-prune=0").count(), 1);

        // Marker cleared: -reindex must be gone; -prune=0 retained.
        let cleared = ghostd_managed_dropin(
            exec,
            &reaper,
            &launch,
            &StorageConfig { archive_mode: true, reindex_pending: false, ..Default::default() },
        );
        assert!(!cleared.contains("-reindex"));
        assert_eq!(cleared.matches("-prune=0").count(), 1);
    }

    #[test]
    fn test_ghostd_managed_dropin_haze_hazed_and_exorcist_oneshot() {
        // While a retroactive conversion is pending, emit -exorcist and SUPPRESS
        // -hazemode=hazed (selecting hazed with blk*.dat present is fatal in
        // ghostd until the conversion runs). Once the marker clears, emit the
        // persistent -hazemode=hazed and drop -exorcist.
        let exec = "/opt/ghost/bin/ghostd -signet -hazemode=hazed -exorcist";
        let reaper = ReaperSettings::default();
        let launch = NodeLaunchConfig::default();

        let converting = ghostd_managed_dropin(
            exec,
            &reaper,
            &launch,
            &StorageConfig { haze_mode: HazeMode::Hazed, exorcist_pending: true, ..Default::default() },
        );
        assert_eq!(converting.matches("-exorcist").count(), 1);
        assert!(!converting.contains("-hazemode=hazed"));

        let converted = ghostd_managed_dropin(
            exec,
            &reaper,
            &launch,
            &StorageConfig { haze_mode: HazeMode::Hazed, exorcist_pending: false, ..Default::default() },
        );
        assert!(!converted.contains("-exorcist"));
        assert_eq!(converted.matches("-hazemode=hazed").count(), 1);
    }
}
