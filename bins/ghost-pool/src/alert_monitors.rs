//! Periodic operator-alert monitors.
//!
//! Two small background tasks that feed the existing operator-alert pipeline
//! (`ghost_verification::alerts`) for conditions that have no natural
//! event-driven trigger site:
//!
//! * **Behind-tip** — the node has fallen behind the network: either its local
//!   height lags the best connected peer by more than [`BEHIND_TIP_LAG_BLOCKS`],
//!   or no new block has arrived for [`BEHIND_TIP_MAX_AGE_SECS`] while a peer is
//!   ahead. Edge-triggered: one alert on entering the behind state, re-armed on
//!   recovery.
//! * **Update-available** — a newer node release than the one installed is
//!   published. The installed/latest versions come from the same files the
//!   dashboard auto-update view reads (`/etc/ghost/version` and the updater
//!   status file). Rate-limited to at most once per day.
//!
//! Both dispatch off the hot path (their own spawned tasks) and both honour the
//! operator's per-event enable flag + master switch inside the dispatcher.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ghost_verification::alerts::{AlertDispatcher, AlertEvent};
use tokio::sync::broadcast;
use tracing::{debug, info};

/// How far the local height may lag the best peer before the node is "behind".
/// `best_peer - local > K` (strictly greater) trips the alert.
pub const BEHIND_TIP_LAG_BLOCKS: u64 = 3;

/// How long the tip may stall (no new block) — while a peer is ahead — before
/// the node is considered behind. ~30 minutes: comfortably longer than the
/// ~10-minute target block interval, so ordinary variance never trips it.
pub const BEHIND_TIP_MAX_AGE_SECS: u64 = 30 * 60;

/// Cadence of the behind-tip check.
pub const BEHIND_TIP_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Cadence of the update-available check. The alert itself is separately
/// rate-limited to [`UPDATE_ALERT_MIN_INTERVAL`], so this only bounds freshness.
pub const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(6 * 3600);

/// Minimum interval between update-available alerts — at most once per day while
/// an update remains available.
pub const UPDATE_ALERT_MIN_INTERVAL: Duration = Duration::from_secs(24 * 3600);

/// Default path to the installed-version marker (matches the dashboard route).
const DEFAULT_VERSION_FILE: &str = "/etc/ghost/version";
/// Default path to the updater status file carrying `latest_version`.
const DEFAULT_STATUS_FILE: &str = "/var/lib/ghost/auto-update.status";

/// Decide whether the node is behind the network tip, returning an
/// operator-facing detail string when it is (and `None` when it is caught up).
/// Pure — no I/O or clock access — so the threshold logic is unit-testable.
///
/// * `best_peer_height == 0` is treated as "no peer height reported" and never
///   trips the alert (an isolated or just-started node must not false-positive).
/// * lagging: `best_peer - local > lag_blocks_k`.
/// * stalled: `tip_age_secs > max_tip_age_secs` AND a peer is strictly ahead.
pub fn evaluate_behind_tip(
    local_height: u64,
    best_peer_height: u64,
    tip_age_secs: u64,
    lag_blocks_k: u64,
    max_tip_age_secs: u64,
) -> Option<String> {
    if best_peer_height == 0 {
        return None;
    }
    let lag = best_peer_height.saturating_sub(local_height);
    if lag > lag_blocks_k {
        return Some(format!(
            "Node is {lag} blocks behind the network: local height {local_height}, \
             best peer height {best_peer_height}."
        ));
    }
    if tip_age_secs > max_tip_age_secs && best_peer_height > local_height {
        return Some(format!(
            "No new block for {} min while a peer is ahead: local height {local_height}, \
             best peer height {best_peer_height}.",
            tip_age_secs / 60
        ));
    }
    None
}

/// Parse a dotted version ("1.10.20", "v1.2", "1.2.3-rc1") into its numeric
/// components, ignoring any `-prerelease`/`+build` metadata and any non-digit
/// suffix on a segment. Missing components compare as 0.
fn parse_version(v: &str) -> Vec<u64> {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let core = v.split(['-', '+']).next().unwrap_or(v);
    core.split('.')
        .map(|seg| {
            let digits: String = seg.chars().take_while(char::is_ascii_digit).collect();
            digits.parse::<u64>().unwrap_or(0)
        })
        .collect()
}

/// Whether `latest` is a strictly newer version than `installed`. Pure, so the
/// comparison is unit-testable independent of the file reads.
pub fn version_is_newer(latest: &str, installed: &str) -> bool {
    let a = parse_version(latest);
    let b = parse_version(installed);
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}

/// Read the installed version (from the version-marker file, falling back to the
/// running binary's version) and the latest version (from the updater status
/// file's `latest_version` field). Returns `None` when no latest version is
/// available, so the caller simply skips this cycle. Paths are overridable via
/// `GHOST_VERSION_FILE` / `GHOST_AUTOUPDATE_STATUS` (matching the dashboard).
async fn read_versions(installed_fallback: &str) -> Option<(String, String)> {
    let version_path =
        std::env::var("GHOST_VERSION_FILE").unwrap_or_else(|_| DEFAULT_VERSION_FILE.to_string());
    let status_path = std::env::var("GHOST_AUTOUPDATE_STATUS")
        .unwrap_or_else(|_| DEFAULT_STATUS_FILE.to_string());

    let installed = tokio::fs::read_to_string(&version_path)
        .await
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| installed_fallback.to_string());

    let latest = tokio::fs::read_to_string(&status_path)
        .await
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| {
            v.get("latest_version")
                .and_then(|x| x.as_str())
                .map(str::to_string)
        })
        .filter(|s| !s.is_empty())?;

    Some((installed, latest))
}

/// Spawn the behind-tip monitor. `local_height` reads this node's current L1
/// height; `best_peer_height` reads the highest L1 height reported by a
/// connected mesh peer (0 when none is known). Runs until `shutdown` fires.
pub fn spawn_behind_tip_monitor<L, P>(
    alerts: Arc<AlertDispatcher>,
    local_height: L,
    best_peer_height: P,
    mut shutdown: broadcast::Receiver<()>,
) where
    L: Fn() -> u64 + Send + 'static,
    P: Fn() -> u64 + Send + 'static,
{
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(BEHIND_TIP_CHECK_INTERVAL);
        // Track when the local height last advanced, to derive tip age without a
        // block-timestamp source.
        let mut last_height = local_height();
        let mut last_change = Instant::now();
        info!("Behind-tip monitor started");
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let local = local_height();
                    if local > last_height {
                        last_height = local;
                        last_change = Instant::now();
                    }
                    let best_peer = best_peer_height();
                    let tip_age = last_change.elapsed().as_secs();
                    let detail = evaluate_behind_tip(
                        local,
                        best_peer,
                        tip_age,
                        BEHIND_TIP_LAG_BLOCKS,
                        BEHIND_TIP_MAX_AGE_SECS,
                    );
                    let active = detail.is_some();
                    if active {
                        debug!(local, best_peer, tip_age, "Node appears behind the tip");
                    }
                    alerts
                        .fire_edge(
                            AlertEvent::BehindTip,
                            "tip",
                            active,
                            detail.as_deref().unwrap_or(""),
                        )
                        .await;
                }
                _ = shutdown.recv() => break,
            }
        }
    });
}

/// Spawn the update-available monitor. `installed_fallback` is the running
/// binary's version, used when the version-marker file is absent. Runs until
/// `shutdown` fires.
pub fn spawn_update_available_monitor(
    alerts: Arc<AlertDispatcher>,
    installed_fallback: String,
    mut shutdown: broadcast::Receiver<()>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(UPDATE_CHECK_INTERVAL);
        info!("Update-available monitor started");
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Some((installed, latest)) = read_versions(&installed_fallback).await {
                        if version_is_newer(&latest, &installed) {
                            let detail = format!(
                                "A newer node release is available: installed {installed}, \
                                 latest {latest}. See the dashboard to update."
                            );
                            alerts
                                .fire_rate_limited(
                                    AlertEvent::UpdateAvailable,
                                    UPDATE_ALERT_MIN_INTERVAL,
                                    &detail,
                                )
                                .await;
                        }
                    }
                }
                _ = shutdown.recv() => break,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behind_tip_none_when_no_peer_height() {
        // best_peer == 0 means "unknown" — never alert.
        assert!(evaluate_behind_tip(0, 0, 999_999, BEHIND_TIP_LAG_BLOCKS, BEHIND_TIP_MAX_AGE_SECS)
            .is_none());
        assert!(evaluate_behind_tip(
            100,
            0,
            999_999,
            BEHIND_TIP_LAG_BLOCKS,
            BEHIND_TIP_MAX_AGE_SECS
        )
        .is_none());
    }

    #[test]
    fn behind_tip_fires_when_lagging_by_more_than_k() {
        // local 100, peer 104 → lag 4 > K(3) → behind.
        let d = evaluate_behind_tip(100, 104, 5, 3, BEHIND_TIP_MAX_AGE_SECS);
        assert!(d.is_some());
        assert!(d.unwrap().contains("4 blocks behind"));
    }

    #[test]
    fn behind_tip_silent_when_lag_within_k() {
        // lag exactly K is not "more than K"; recent tip → not stalled.
        assert!(evaluate_behind_tip(100, 103, 5, 3, BEHIND_TIP_MAX_AGE_SECS).is_none());
        // caught up / ahead.
        assert!(evaluate_behind_tip(100, 100, 5, 3, BEHIND_TIP_MAX_AGE_SECS).is_none());
        assert!(evaluate_behind_tip(105, 100, 5, 3, BEHIND_TIP_MAX_AGE_SECS).is_none());
    }

    #[test]
    fn behind_tip_fires_on_stalled_tip_while_peer_ahead() {
        // Only 1 block behind (within K) but the tip has been stale > max age
        // and a peer is ahead → stalled alert.
        let d = evaluate_behind_tip(100, 101, BEHIND_TIP_MAX_AGE_SECS + 1, 3, BEHIND_TIP_MAX_AGE_SECS);
        assert!(d.is_some());
        assert!(d.unwrap().contains("No new block"));
    }

    #[test]
    fn behind_tip_no_stall_alert_when_caught_up_even_if_old() {
        // Tip old but peer not ahead (we are at/above best peer) → healthy.
        assert!(evaluate_behind_tip(
            101,
            101,
            BEHIND_TIP_MAX_AGE_SECS + 100,
            3,
            BEHIND_TIP_MAX_AGE_SECS
        )
        .is_none());
    }

    #[test]
    fn version_newer_basic() {
        assert!(version_is_newer("1.10.20", "1.10.6"));
        assert!(version_is_newer("1.11.0", "1.10.20"));
        assert!(version_is_newer("2.0.0", "1.99.99"));
        assert!(!version_is_newer("1.10.6", "1.10.20"));
        assert!(!version_is_newer("1.10.20", "1.10.20"));
        assert!(!version_is_newer("1.10.20", "1.10.21"));
    }

    #[test]
    fn version_newer_tolerates_prefixes_and_suffixes() {
        assert!(version_is_newer("v1.10.20", "1.10.6"));
        assert!(version_is_newer("1.10.20", "v1.10.6"));
        assert!(version_is_newer("1.11.0-rc1", "1.10.20"));
        // Same numeric core, one prerelease: numeric core equal → not "newer".
        assert!(!version_is_newer("1.10.20-rc1", "1.10.20"));
    }

    #[test]
    fn version_newer_handles_missing_components() {
        assert!(version_is_newer("1.11", "1.10.20"));
        assert!(!version_is_newer("1.10", "1.10.0"));
        assert!(version_is_newer("1.10.1", "1.10"));
    }
}
