//! Capability self-check.
//!
//! For each capability the operator claims, run a prerequisite probe so the
//! dashboard can surface drift between intent and reality. Probes are
//! diagnostic only — they do not demote claims at runtime, because:
//!   1. The verification mesh already catches false claims at the consensus
//!      layer (peers issue real challenges).
//!   2. Stratum / Ghost Pay daemons may briefly be down at boot or during
//!      operator-initiated restarts; auto-demotion would oscillate.
//!
//! Operators read `/health/self_check` (or the dashboard Capability Status
//! page) to see which prerequisites are passing.

use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use ghost_common::config::{MiningMode, NodeConfig};

/// Run all four checks every 30s. Cheap (sub-second total) and covers most
/// operator drift scenarios without flooding logs.
const TICK_INTERVAL: Duration = Duration::from_secs(30);
/// Minimum free disk space for a meaningful Archive claim (700 GB).
const ARCHIVE_MIN_FREE_BYTES: u64 = 700 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize)]
pub struct CapabilityCheck {
    /// True iff the config asks for this capability.
    pub claimed: bool,
    /// True iff the prerequisite probe passes right now.
    pub passed: bool,
    /// Human-readable reason for failure (None when `passed`).
    pub reason: Option<String>,
    /// Unix timestamp of the most recent probe.
    pub last_checked_unix: i64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SelfCheckState {
    pub public_mining: CapabilityCheck,
    pub archive: CapabilityCheck,
    pub ghost_pay: CapabilityCheck,
    pub reaper: CapabilityCheck,
}

/// Self-check coordinator. Cheap to clone — wraps an `Arc<RwLock<...>>`.
#[derive(Clone)]
pub struct SelfCheck {
    state: Arc<parking_lot::RwLock<SelfCheckState>>,
}

impl Default for SelfCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl SelfCheck {
    pub fn new() -> Self {
        Self {
            state: Arc::new(parking_lot::RwLock::new(SelfCheckState::default())),
        }
    }

    /// Snapshot of the current self-check state.
    pub fn snapshot(&self) -> SelfCheckState {
        self.state.read().clone()
    }

    /// Run all probes once and update internal state. Logs at INFO when a
    /// capability transitions between passed/failed; doesn't spam on
    /// stable state.
    pub async fn run_once(&self, config: &NodeConfig) {
        let public_mining = check_public_mining(config).await;
        let archive = check_archive(config);
        let ghost_pay = check_ghost_pay(config).await;
        let reaper = check_reaper(config);

        let next = SelfCheckState {
            public_mining,
            archive,
            ghost_pay,
            reaper,
        };

        let prev = self.snapshot();
        log_transitions(&prev, &next);
        *self.state.write() = next;
    }

    /// Spawn a background task that re-runs all probes every TICK_INTERVAL.
    /// The handle is detached — caller doesn't await it.
    pub fn spawn_loop(self, config: Arc<NodeConfig>) {
        tokio::spawn(async move {
            // Run once immediately so the dashboard has something to show.
            self.run_once(&config).await;
            let mut interval = tokio::time::interval(TICK_INTERVAL);
            interval.tick().await; // consume the immediate tick
            loop {
                interval.tick().await;
                self.run_once(&config).await;
            }
        });
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn log_transitions(prev: &SelfCheckState, next: &SelfCheckState) {
    log_one("public_mining", &prev.public_mining, &next.public_mining);
    log_one("archive", &prev.archive, &next.archive);
    log_one("ghost_pay", &prev.ghost_pay, &next.ghost_pay);
    log_one("reaper", &prev.reaper, &next.reaper);
}

fn log_one(name: &str, prev: &CapabilityCheck, next: &CapabilityCheck) {
    if prev.passed == next.passed && prev.claimed == next.claimed {
        return;
    }
    if next.claimed && !next.passed {
        tracing::warn!(
            capability = name,
            reason = %next.reason.as_deref().unwrap_or("unknown"),
            "Self-check FAILED — claimed in config but prerequisite missing"
        );
    } else if next.claimed && next.passed {
        info!(capability = name, "Self-check PASSED");
    } else if !next.claimed {
        debug!(capability = name, "Capability not claimed in config");
    }
}

// ─── per-capability probes ─────────────────────────────────────────────────

async fn check_public_mining(config: &NodeConfig) -> CapabilityCheck {
    let claimed = matches!(config.network.mining_mode, MiningMode::PublicPool);
    let last_checked_unix = now_unix();
    if !claimed {
        return CapabilityCheck {
            claimed: false,
            passed: false,
            reason: None,
            last_checked_unix,
        };
    }

    // Prerequisite: SRI translator on sv1_port AND SRI pool on sv2_port are
    // listening locally. We read /proc/net/tcp instead of TCP-connecting so
    // the translator's log doesn't show a phantom downstream every 30s.
    // External reachability is what verification challenges are for.
    let sv1_ok = port_listening(config.network.sv1_port);
    let sv2_ok = port_listening(config.network.sv2_port);

    let mut missing = Vec::new();
    if !sv1_ok {
        missing.push(format!(
            "SV1 stratum (port {}) not listening — start sri-translator",
            config.network.sv1_port
        ));
    }
    if !sv2_ok {
        missing.push(format!(
            "SV2 stratum (port {}) not listening — start sri-pool",
            config.network.sv2_port
        ));
    }
    if config.network.public_address.is_none() {
        missing.push("public_address unset in pool.toml".to_string());
    }
    if config.network.signing_key.is_none() {
        missing
            .push("signing_key unset in pool.toml — generate with --generate-identity".to_string());
    }

    let passed = missing.is_empty();
    CapabilityCheck {
        claimed: true,
        passed,
        reason: (!passed).then(|| missing.join("; ")),
        last_checked_unix,
    }
}

fn check_archive(config: &NodeConfig) -> CapabilityCheck {
    let claimed = config.storage.archive_mode;
    let last_checked_unix = now_unix();
    if !claimed {
        return CapabilityCheck {
            claimed: false,
            passed: false,
            reason: None,
            last_checked_unix,
        };
    }

    // db_path may point at a not-yet-created directory (or a file); statvfs
    // wants something that exists. Fall back to its parent so we still report
    // disk-free of the partition that will hold the archive.
    let configured = config.storage.db_path.as_path();
    let probe_path = if configured.exists() {
        configured.to_path_buf()
    } else {
        configured
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("/"))
    };
    let free = free_bytes(&probe_path);
    let passed = match free {
        Some(b) if b >= ARCHIVE_MIN_FREE_BYTES => true,
        _ => false,
    };
    let reason = match free {
        None => Some(format!(
            "could not stat data_dir {} (probed {})",
            configured.display(),
            probe_path.display()
        )),
        Some(b) if b < ARCHIVE_MIN_FREE_BYTES => Some(format!(
            "only {} GiB free at {} — Archive claim needs ≥{} GiB",
            b / (1024 * 1024 * 1024),
            probe_path.display(),
            ARCHIVE_MIN_FREE_BYTES / (1024 * 1024 * 1024)
        )),
        _ => None,
    };

    CapabilityCheck {
        claimed: true,
        passed,
        reason,
        last_checked_unix,
    }
}

async fn check_ghost_pay(config: &NodeConfig) -> CapabilityCheck {
    // Match the capability advertisement: claim GhostPay only when enabled, not
    // on mere presence of a (possibly disabled) `[ghost_pay]` block.
    let claimed = config.ghost_pay_enabled();
    let last_checked_unix = now_unix();
    if !claimed {
        return CapabilityCheck {
            claimed: false,
            passed: false,
            reason: None,
            last_checked_unix,
        };
    }

    // Default Ghost Pay API port is 8800 (per CLAUDE.md). The actual port
    // can be overridden in the ghost-pay binary's args; the self-check uses
    // the conventional default since pool.toml doesn't store it directly.
    const GHOST_PAY_PORT: u16 = 8800;
    if port_listening(GHOST_PAY_PORT) {
        CapabilityCheck {
            claimed: true,
            passed: true,
            reason: None,
            last_checked_unix,
        }
    } else {
        CapabilityCheck {
            claimed: true,
            passed: false,
            reason: Some(format!(
                "ghost-pay daemon not listening on 127.0.0.1:{} — check `systemctl status ghost-pay`",
                GHOST_PAY_PORT
            )),
            last_checked_unix,
        }
    }
}

fn check_reaper(config: &NodeConfig) -> CapabilityCheck {
    let claimed = config.reaper.enabled;
    CapabilityCheck {
        claimed,
        passed: claimed, // ReaperConfig is loaded by serde; no runtime probe needed
        reason: None,
        last_checked_unix: now_unix(),
    }
}

// ─── helpers ───────────────────────────────────────────────────────────────

/// Return true iff a TCP listener is bound to `port` on any local interface.
/// Reads `/proc/net/tcp{,6}` directly instead of opening a TCP connection,
/// which keeps probes invisible to the listening daemon (no spurious
/// "downstream connected → disconnected" log entries every tick).
#[cfg(target_os = "linux")]
fn port_listening(port: u16) -> bool {
    fn scan(path: &str, port: u16) -> bool {
        // /proc/net/tcp format (whitespace-separated):
        //   sl  local_address  rem_address  st  ...
        // local_address is "ADDR:PORT" in big-endian hex; state 0A = LISTEN.
        let Ok(content) = std::fs::read_to_string(path) else {
            return false;
        };
        let port_hex = format!("{:04X}", port);
        for line in content.lines().skip(1) {
            let mut fields = line.split_whitespace();
            let _sl = fields.next();
            let Some(local) = fields.next() else { continue };
            let _rem = fields.next();
            let Some(state) = fields.next() else { continue };
            if state != "0A" {
                continue;
            }
            if local.rsplit_once(':').map(|(_, p)| p) == Some(port_hex.as_str()) {
                return true;
            }
        }
        false
    }
    scan("/proc/net/tcp", port) || scan("/proc/net/tcp6", port)
}

/// Non-Linux fallback for dev environments. Falls back to a short-lived TCP
/// connect since /proc/net/tcp is Linux-specific.
#[cfg(not(target_os = "linux"))]
fn port_listening(port: u16) -> bool {
    use std::net::TcpStream;
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(500),
    )
    .is_ok()
}

#[cfg(unix)]
fn free_bytes(path: &std::path::Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path_cstr = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(path_cstr.as_ptr(), &mut stat) };
    if rc != 0 {
        return None;
    }
    Some(stat.f_bavail as u64 * stat.f_frsize as u64)
}

#[cfg(not(unix))]
fn free_bytes(_path: &std::path::Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::config::{GhostPayConfig, MiningMode};

    #[test]
    fn reaper_check_mirrors_config() {
        let mut cfg = NodeConfig::default();
        cfg.reaper.enabled = true;
        let r = check_reaper(&cfg);
        assert!(r.claimed && r.passed);

        cfg.reaper.enabled = false;
        let r = check_reaper(&cfg);
        assert!(!r.claimed && !r.passed);
    }

    #[test]
    fn archive_check_with_existing_data_dir() {
        let mut cfg = NodeConfig::default();
        cfg.storage.archive_mode = true;
        cfg.storage.db_path = "/tmp".into();
        let r = check_archive(&cfg);
        assert!(r.claimed);
        // Pass/fail depends on host disk; just verify the probe returns
        // a coherent state (not panicked, reason set iff failed)
        assert_eq!(r.passed, r.reason.is_none());
    }

    #[test]
    fn archive_check_falls_back_to_parent_when_db_path_missing() {
        // Config points at a directory that doesn't exist; the probe should
        // walk up to the parent (which does exist) so it can still stat the
        // partition for free bytes.
        let mut cfg = NodeConfig::default();
        cfg.storage.archive_mode = true;
        cfg.storage.db_path = "/tmp/this-path-does-not-exist-xyz123/data".into();
        let r = check_archive(&cfg);
        assert!(r.claimed);
        // /tmp exists on every unix host so free_bytes should succeed.
        // We don't assert pass/fail (depends on host disk free) — but the
        // reason text must reference the parent we actually probed.
        if let Some(reason) = &r.reason {
            assert!(
                reason.contains("/tmp"),
                "reason should reference the parent we fell back to: {}",
                reason
            );
        }
    }

    #[test]
    fn archive_check_unclaimed_short_circuits() {
        let mut cfg = NodeConfig::default();
        cfg.storage.archive_mode = false;
        let r = check_archive(&cfg);
        assert!(!r.claimed && !r.passed && r.reason.is_none());
    }

    #[tokio::test]
    async fn public_mining_check_unclaimed_short_circuits() {
        let mut cfg = NodeConfig::default();
        cfg.network.mining_mode = MiningMode::PrivatePool;
        let r = check_public_mining(&cfg).await;
        assert!(!r.claimed && !r.passed && r.reason.is_none());
    }

    #[tokio::test]
    async fn public_mining_check_reports_missing_address_and_signing_key() {
        let mut cfg = NodeConfig::default();
        cfg.network.mining_mode = MiningMode::PublicPool;
        cfg.network.public_address = None;
        cfg.network.signing_key = None;
        // sv1_port / sv2_port likely not listening in the test env either,
        // so the probe will also report them as missing.
        let r = check_public_mining(&cfg).await;
        assert!(r.claimed);
        assert!(!r.passed);
        let reason = r.reason.unwrap_or_default();
        assert!(reason.contains("public_address"));
        assert!(reason.contains("signing_key"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn port_listening_finds_a_real_listener() {
        // Bind to an ephemeral port and confirm port_listening() sees it.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(
            port_listening(port),
            "expected /proc/net/tcp scan to find listener on {port}"
        );
        drop(listener);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn port_listening_returns_false_for_unbound_port() {
        // Bind+drop to learn a port that's now free, then assert nothing's
        // listening on it. (Race window is microseconds and harmless — a
        // false positive would just mean someone else grabbed it instantly.)
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        assert!(!port_listening(port), "port {port} should be free");
    }

    #[tokio::test]
    async fn ghost_pay_check_unclaimed_short_circuits() {
        let mut cfg = NodeConfig::default();
        cfg.ghost_pay = None;
        let r = check_ghost_pay(&cfg).await;
        assert!(!r.claimed && !r.passed && r.reason.is_none());
    }

    #[tokio::test]
    async fn ghost_pay_check_failure_carries_remediation_hint() {
        let mut cfg = NodeConfig::default();
        // ghost-pay ENABLED (claimed) but not running — the remediation scenario.
        cfg.ghost_pay = Some(GhostPayConfig {
            enabled: true,
            ..Default::default()
        });
        // 127.0.0.1:8800 almost certainly not bound in test env
        let r = check_ghost_pay(&cfg).await;
        assert!(r.claimed);
        if !r.passed {
            assert!(r.reason.as_ref().unwrap().contains("ghost-pay"));
        }
    }

    #[tokio::test]
    async fn ghost_pay_check_disabled_block_is_unclaimed() {
        // v1.10.20: a present-but-disabled `[ghost_pay]` block must NOT claim the
        // capability (gate on `enabled`, not mere block presence) — otherwise
        // pool-only nodes advertise GhostPay and peers waste probes on port 8800.
        let mut cfg = NodeConfig::default();
        cfg.ghost_pay = Some(GhostPayConfig::default()); // default enabled = false
        let r = check_ghost_pay(&cfg).await;
        assert!(!r.claimed && !r.passed && r.reason.is_none());
    }
}
