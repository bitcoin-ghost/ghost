//! Periodic operator-alert monitors.
//!
//! Small background tasks that feed the existing operator-alert pipeline
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
//! * **Mempool-congestion** — ghostd's mempool `usage` is near its `maxmempool`
//!   ceiling (from `getmempoolinfo`). Edge-triggered with hysteresis: fires when
//!   usage crosses [`MEMPOOL_CONGESTION_HIGH_PCT`], re-arms once it falls back
//!   below [`MEMPOOL_CONGESTION_REARM_PCT`].
//! * **Fee-spike** — the next-block fee rate (from `estimatesmartfee`) crosses
//!   [`FEE_SPIKE_ABS_SAT_VB`] or jumps to [`FEE_SPIKE_JUMP_FACTOR`]× a rolling
//!   baseline. Rate-limited to [`FEE_SPIKE_ALERT_MIN_INTERVAL`] so sustained
//!   high fees don't spam.
//!
//! All dispatch off the hot path (their own spawned tasks) and honour the
//! operator's per-event enable flag + master switch inside the dispatcher.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ghost_common::rpc::BitcoinRpc;
use ghost_verification::alerts::{AlertDispatcher, AlertEvent};
use ghost_verification::chain_health::{derive_tip_status, ChainHealth};
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
///
/// On each tick it also records a derived tip-status snapshot into the shared
/// [`ChainHealth`] holder (same inputs it evaluates for the alert), so the Sync
/// page's Chain Health view can display the live tip-lag status — not just be
/// paged when the node falls behind.
pub fn spawn_behind_tip_monitor<L, P>(
    alerts: Arc<AlertDispatcher>,
    chain_health: Arc<ChainHealth>,
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
                    // Record the derived tip status for the Chain Health view,
                    // using the same thresholds the alert below evaluates so the
                    // displayed status and the fired alert always agree.
                    chain_health.set_tip(derive_tip_status(
                        local,
                        best_peer,
                        tip_age,
                        BEHIND_TIP_LAG_BLOCKS,
                        BEHIND_TIP_MAX_AGE_SECS,
                    ));
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

// ============================================================================
// Mempool-congestion monitor
// ============================================================================

/// Usage (as a % of `maxmempool`) at which the mempool-congestion alert trips.
pub const MEMPOOL_CONGESTION_HIGH_PCT: f64 = 90.0;

/// Usage % the mempool must fall back below before the alert re-arms. The gap to
/// [`MEMPOOL_CONGESTION_HIGH_PCT`] is hysteresis: it stops a mempool hovering
/// right at the threshold from flapping the alert on every check.
pub const MEMPOOL_CONGESTION_REARM_PCT: f64 = 80.0;

/// Cadence of the mempool-congestion check.
pub const MEMPOOL_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Mempool `usage` as a percentage of `maxmempool`. Returns 0 when `maxmempool`
/// is 0 (unknown / not reported) so a missing bound never trips the alert. Pure.
pub fn mempool_usage_pct(usage_bytes: u64, maxmempool_bytes: u64) -> f64 {
    if maxmempool_bytes == 0 {
        return 0.0;
    }
    (usage_bytes as f64 / maxmempool_bytes as f64) * 100.0
}

/// Decide whether the mempool is congested at or above `high_pct` of its
/// capacity, returning an operator-facing detail string when it is. Pure — no
/// I/O — so the threshold logic is unit-testable independent of the RPC read.
/// `maxmempool_bytes == 0` (unknown) never trips.
pub fn evaluate_mempool_congestion(
    usage_bytes: u64,
    maxmempool_bytes: u64,
    high_pct: f64,
) -> Option<String> {
    if maxmempool_bytes == 0 {
        return None;
    }
    let pct = mempool_usage_pct(usage_bytes, maxmempool_bytes);
    if pct >= high_pct {
        const MIB: f64 = 1024.0 * 1024.0;
        return Some(format!(
            "Mempool is {pct:.0}% full: {:.0} MiB of {:.0} MiB in use (usage vs maxmempool).",
            usage_bytes as f64 / MIB,
            maxmempool_bytes as f64 / MIB,
        ));
    }
    None
}

/// Spawn the mempool-congestion monitor. Reads ghostd `getmempoolinfo` via the
/// pool's shared RPC client and fires an edge-triggered [`AlertEvent::MempoolCongestion`]
/// when `usage` crosses [`MEMPOOL_CONGESTION_HIGH_PCT`] of `maxmempool`, re-arming
/// once it falls back below [`MEMPOOL_CONGESTION_REARM_PCT`] (hysteresis).
/// Delivery + the enable flag are handled inside the dispatcher. Runs until
/// `shutdown` fires.
pub fn spawn_mempool_congestion_monitor(
    alerts: Arc<AlertDispatcher>,
    rpc: Arc<BitcoinRpc>,
    mut shutdown: broadcast::Receiver<()>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(MEMPOOL_CHECK_INTERVAL);
        // Latched congestion state, for hysteresis across ticks.
        let mut congested = false;
        info!("Mempool-congestion monitor started");
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match rpc.get_mempool_info().await {
                        Ok(info) => {
                            let pct = mempool_usage_pct(info.usage, info.maxmempool);
                            // Enter congested at HIGH; once congested, stay until
                            // usage falls below REARM.
                            let now_congested = if congested {
                                info.maxmempool > 0 && pct >= MEMPOOL_CONGESTION_REARM_PCT
                            } else {
                                info.maxmempool > 0 && pct >= MEMPOOL_CONGESTION_HIGH_PCT
                            };
                            // Detail is only consumed on the rising edge; build it there.
                            let detail = if now_congested && !congested {
                                debug!(
                                    pct,
                                    usage = info.usage,
                                    maxmempool = info.maxmempool,
                                    "Mempool near capacity"
                                );
                                evaluate_mempool_congestion(
                                    info.usage,
                                    info.maxmempool,
                                    MEMPOOL_CONGESTION_HIGH_PCT,
                                )
                                .unwrap_or_default()
                            } else {
                                String::new()
                            };
                            congested = now_congested;
                            alerts
                                .fire_edge(
                                    AlertEvent::MempoolCongestion,
                                    "mempool",
                                    now_congested,
                                    &detail,
                                )
                                .await;
                        }
                        Err(e) => {
                            debug!(error = %e, "getmempoolinfo failed; skipping congestion check");
                        }
                    }
                }
                _ = shutdown.recv() => break,
            }
        }
    });
}

// ============================================================================
// Fee-spike monitor
// ============================================================================

/// Absolute next-block fee rate (sat/vB) at or above which a fee spike is
/// reported regardless of the recent baseline — the fee environment is simply
/// expensive.
pub const FEE_SPIKE_ABS_SAT_VB: f64 = 100.0;

/// A fee rate this many times the rolling baseline is a relative spike.
pub const FEE_SPIKE_JUMP_FACTOR: f64 = 3.0;

/// A relative (baseline-multiple) spike is only reported when the current rate
/// is at least this high, so ordinary churn around a tiny baseline
/// (e.g. 1 → 4 sat/vB) never pages the operator.
pub const FEE_SPIKE_JUMP_FLOOR_SAT_VB: f64 = 20.0;

/// EMA smoothing factor for the rolling fee baseline (weight of the newest
/// sample). Small, so the baseline tracks the recent-normal slowly and a sudden
/// jump still reads as a spike before it is absorbed.
pub const FEE_SPIKE_BASELINE_ALPHA: f64 = 0.2;

/// `estimatesmartfee` confirmation target used for the fee signal: the fee rate
/// to get into the next block.
pub const FEE_SPIKE_CONF_TARGET: u32 = 1;

/// Cadence of the fee-spike check.
pub const FEE_SPIKE_CHECK_INTERVAL: Duration = Duration::from_secs(120);

/// Minimum interval between fee-spike alerts, so a sustained high-fee period
/// pages once rather than every check.
pub const FEE_SPIKE_ALERT_MIN_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Convert a Bitcoin Core fee rate (BTC per 1000 vBytes, as `estimatesmartfee`
/// reports) to sat/vB. 1 BTC/kvB = 1e8 sat / 1000 vB = 1e5 sat/vB. Pure.
pub fn feerate_btc_kvb_to_sat_vb(feerate_btc_kvb: f64) -> f64 {
    feerate_btc_kvb * 100_000.0
}

/// Decide whether the fee environment has spiked, returning an operator-facing
/// detail string when it has. Pure — no I/O or clock access — so the threshold
/// logic is unit-testable like [`evaluate_behind_tip`].
///
/// * absolute: `current >= abs_threshold` → spike (fees are simply high).
/// * relative: a known `baseline > 0`, `current >= jump_floor`, and
///   `current >= baseline * jump_factor` → spike (a sharp jump vs recent normal).
/// * `current <= 0` never trips (no usable signal).
pub fn evaluate_fee_spike(
    current_sat_vb: f64,
    baseline_sat_vb: Option<f64>,
    abs_threshold_sat_vb: f64,
    jump_factor: f64,
    jump_floor_sat_vb: f64,
) -> Option<String> {
    if current_sat_vb <= 0.0 {
        return None;
    }
    if current_sat_vb >= abs_threshold_sat_vb {
        return Some(format!(
            "Next-block fee rate is {current_sat_vb:.1} sat/vB, at or above the \
             {abs_threshold_sat_vb:.0} sat/vB alert threshold."
        ));
    }
    if let Some(base) = baseline_sat_vb {
        if base > 0.0 && current_sat_vb >= jump_floor_sat_vb && current_sat_vb >= base * jump_factor
        {
            return Some(format!(
                "Next-block fee rate jumped to {current_sat_vb:.1} sat/vB, {:.1}x the \
                 recent baseline of {base:.1} sat/vB.",
                current_sat_vb / base
            ));
        }
    }
    None
}

/// Update the rolling fee baseline (EMA) with a new sample. Pure. The first
/// sample seeds the baseline; later samples blend in at [`FEE_SPIKE_BASELINE_ALPHA`].
pub fn update_fee_baseline(baseline: Option<f64>, sample_sat_vb: f64) -> f64 {
    match baseline {
        Some(b) => b * (1.0 - FEE_SPIKE_BASELINE_ALPHA) + sample_sat_vb * FEE_SPIKE_BASELINE_ALPHA,
        None => sample_sat_vb,
    }
}

/// Spawn the fee-spike monitor. Reads ghostd `estimatesmartfee` (next-block
/// target) via the pool's shared RPC client, maintains a rolling baseline, and
/// fires a rate-limited [`AlertEvent::FeeSpike`] when the rate crosses
/// [`FEE_SPIKE_ABS_SAT_VB`] or jumps to [`FEE_SPIKE_JUMP_FACTOR`]× the baseline.
/// Delivery + the enable flag are handled inside the dispatcher. Runs until
/// `shutdown` fires.
pub fn spawn_fee_spike_monitor(
    alerts: Arc<AlertDispatcher>,
    rpc: Arc<BitcoinRpc>,
    mut shutdown: broadcast::Receiver<()>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(FEE_SPIKE_CHECK_INTERVAL);
        let mut baseline: Option<f64> = None;
        info!("Fee-spike monitor started");
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match rpc.estimate_smart_fee(FEE_SPIKE_CONF_TARGET).await {
                        Ok(est) => {
                            let Some(btc_kvb) = est.feerate else {
                                debug!("estimatesmartfee returned no feerate; skipping fee-spike check");
                                continue;
                            };
                            let sat_vb = feerate_btc_kvb_to_sat_vb(btc_kvb);
                            if sat_vb <= 0.0 {
                                continue;
                            }
                            if let Some(detail) = evaluate_fee_spike(
                                sat_vb,
                                baseline,
                                FEE_SPIKE_ABS_SAT_VB,
                                FEE_SPIKE_JUMP_FACTOR,
                                FEE_SPIKE_JUMP_FLOOR_SAT_VB,
                            ) {
                                debug!(sat_vb, ?baseline, "Fee environment spiked");
                                alerts
                                    .fire_rate_limited(
                                        AlertEvent::FeeSpike,
                                        FEE_SPIKE_ALERT_MIN_INTERVAL,
                                        &detail,
                                    )
                                    .await;
                            }
                            // Fold the sample into the rolling baseline AFTER
                            // evaluating, so a spike is measured against the
                            // pre-spike normal.
                            baseline = Some(update_fee_baseline(baseline, sat_vb));
                        }
                        Err(e) => {
                            debug!(error = %e, "estimatesmartfee failed; skipping fee-spike check");
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
        assert!(evaluate_behind_tip(
            0,
            0,
            999_999,
            BEHIND_TIP_LAG_BLOCKS,
            BEHIND_TIP_MAX_AGE_SECS
        )
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
        let d = evaluate_behind_tip(
            100,
            101,
            BEHIND_TIP_MAX_AGE_SECS + 1,
            3,
            BEHIND_TIP_MAX_AGE_SECS,
        );
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

    // ---- Mempool congestion ------------------------------------------------

    #[test]
    fn mempool_pct_is_zero_when_max_unknown() {
        assert_eq!(mempool_usage_pct(100, 0), 0.0);
        assert!((mempool_usage_pct(45, 100) - 45.0).abs() < 1e-9);
    }

    #[test]
    fn congestion_none_when_below_threshold() {
        // 80% full, threshold 90% → not congested.
        assert!(evaluate_mempool_congestion(80, 100, MEMPOOL_CONGESTION_HIGH_PCT).is_none());
    }

    #[test]
    fn congestion_fires_at_or_above_threshold() {
        // Exactly at the threshold trips (>=).
        let d = evaluate_mempool_congestion(90, 100, MEMPOOL_CONGESTION_HIGH_PCT);
        assert!(d.is_some());
        assert!(d.unwrap().contains("90% full"));
        // Well over the threshold trips too.
        assert!(evaluate_mempool_congestion(99, 100, MEMPOOL_CONGESTION_HIGH_PCT).is_some());
    }

    #[test]
    fn congestion_never_fires_when_max_unknown() {
        // maxmempool == 0 (not reported) must never trip, even with huge usage.
        assert!(evaluate_mempool_congestion(u64::MAX, 0, MEMPOOL_CONGESTION_HIGH_PCT).is_none());
    }

    #[test]
    fn congestion_rearm_is_below_high() {
        // Sanity: hysteresis band is non-empty and ordered.
        assert!(MEMPOOL_CONGESTION_REARM_PCT < MEMPOOL_CONGESTION_HIGH_PCT);
    }

    // ---- Fee spike ---------------------------------------------------------

    #[test]
    fn feerate_conversion_btc_kvb_to_sat_vb() {
        // Min-relay 0.00001 BTC/kvB == 1 sat/vB.
        assert!((feerate_btc_kvb_to_sat_vb(0.00001) - 1.0).abs() < 1e-6);
        // 0.001 BTC/kvB == 100 sat/vB.
        assert!((feerate_btc_kvb_to_sat_vb(0.001) - 100.0).abs() < 1e-6);
    }

    #[test]
    fn fee_spike_fires_on_absolute_threshold() {
        // At/above the absolute threshold fires regardless of baseline.
        let d = evaluate_fee_spike(
            120.0,
            Some(110.0),
            FEE_SPIKE_ABS_SAT_VB,
            FEE_SPIKE_JUMP_FACTOR,
            FEE_SPIKE_JUMP_FLOOR_SAT_VB,
        );
        assert!(d.is_some());
        assert!(d.unwrap().contains("120.0 sat/vB"));
    }

    #[test]
    fn fee_spike_fires_on_relative_jump() {
        // 30 sat/vB vs a 5 sat/vB baseline = 6x (>= 3x) and above the floor → spike.
        let d = evaluate_fee_spike(
            30.0,
            Some(5.0),
            FEE_SPIKE_ABS_SAT_VB,
            FEE_SPIKE_JUMP_FACTOR,
            FEE_SPIKE_JUMP_FLOOR_SAT_VB,
        );
        assert!(d.is_some());
        assert!(d.unwrap().contains("baseline"));
    }

    #[test]
    fn fee_spike_silent_below_jump_floor() {
        // 5x jump but the current rate (10) is below the 20 sat/vB floor → silent,
        // so ordinary churn around a tiny baseline never pages.
        assert!(evaluate_fee_spike(
            10.0,
            Some(2.0),
            FEE_SPIKE_ABS_SAT_VB,
            FEE_SPIKE_JUMP_FACTOR,
            FEE_SPIKE_JUMP_FLOOR_SAT_VB,
        )
        .is_none());
    }

    #[test]
    fn fee_spike_silent_when_no_baseline_and_below_abs() {
        // First reading (no baseline) below the absolute threshold → no alert.
        assert!(evaluate_fee_spike(
            25.0,
            None,
            FEE_SPIKE_ABS_SAT_VB,
            FEE_SPIKE_JUMP_FACTOR,
            FEE_SPIKE_JUMP_FLOOR_SAT_VB,
        )
        .is_none());
    }

    #[test]
    fn fee_spike_silent_within_normal_variation() {
        // 25 vs 20 baseline = 1.25x (< 3x) and below abs → not a spike.
        assert!(evaluate_fee_spike(
            25.0,
            Some(20.0),
            FEE_SPIKE_ABS_SAT_VB,
            FEE_SPIKE_JUMP_FACTOR,
            FEE_SPIKE_JUMP_FLOOR_SAT_VB,
        )
        .is_none());
    }

    #[test]
    fn fee_spike_ignores_nonpositive_rate() {
        assert!(evaluate_fee_spike(
            0.0,
            Some(5.0),
            FEE_SPIKE_ABS_SAT_VB,
            FEE_SPIKE_JUMP_FACTOR,
            FEE_SPIKE_JUMP_FLOOR_SAT_VB,
        )
        .is_none());
    }

    #[test]
    fn fee_baseline_seeds_then_smooths() {
        // First sample seeds the baseline exactly.
        let b0 = update_fee_baseline(None, 10.0);
        assert!((b0 - 10.0).abs() < 1e-9);
        // Next sample blends toward the new value but stays between old and new.
        let b1 = update_fee_baseline(Some(10.0), 30.0);
        assert!(b1 > 10.0 && b1 < 30.0);
        // Explicit EMA value: 10*0.8 + 30*0.2 = 14.
        assert!((b1 - 14.0).abs() < 1e-9);
    }
}
