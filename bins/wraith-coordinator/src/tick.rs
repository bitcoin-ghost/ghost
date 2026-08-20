//! Background ticker for time-driven session transitions.
//!
//! `/witness` triggers the no-sign deadline sweep when SOMEONE pings
//! the coordinator past the deadline. That's enough in normal flow
//! (at least one wallet always shows up to ask for status), but a
//! pathological round where every wallet drops would otherwise sit
//! in Signing forever and never fail, so the coins that killed it would
//! never go into cooldown. This module plugs that hole: a tokio task
//! scans every `SCAN_INTERVAL` for
//! sessions whose deadline has expired and runs the same sweep
//! `/witness` would have run.
//!
//! Also calls `LiteSessionRegistry::tick(now)` so Filling →
//! Locked / Filling → Failed time-driven transitions happen even
//! when no wallet is polling /status. /status used to be the only
//! tick caller.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{debug, warn};

use wraith_protocol::LiteSessionState;

use crate::no_sign_sweep::execute_no_sign_sweep;
use crate::state::CoordinatorState;

/// How often to scan. Trades wakeup overhead against worst-case
/// latency for round transitions: a session whose fill-window
/// expires right after a tick waits up to one full interval before
/// flipping to Locked. 5 seconds is a reasonable middle.
pub const SCAN_INTERVAL: Duration = Duration::from_secs(5);

/// Spawn the background ticker. Returns the JoinHandle so
/// production callers can hold it for graceful shutdown; tests
/// drop it and the task aborts when the runtime tears down.
pub fn spawn_background_tick(state: Arc<CoordinatorState>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SCAN_INTERVAL);
        // Skip the immediate-on-start tick — let the binary settle
        // before doing any state mutations.
        interval.tick().await;
        loop {
            interval.tick().await;
            run_one_pass(&state);
        }
    })
}

/// One sweep pass — exposed so tests can drive a deterministic
/// single tick instead of waiting on the real interval.
pub fn run_one_pass(state: &CoordinatorState) {
    let now = state.now();

    // 1. Time-driven Filling → Locked / Filling → Failed transitions.
    let changed = state.sessions.tick(now);
    if !changed.is_empty() {
        debug!(count = changed.len(), "tick advanced sessions");
    }

    // 2. No-sign deadline sweep on Signing-state sessions whose
    //    deadline has expired. Snapshot the deadline map first so we
    //    don't hold the lock while running per-session sweeps.
    let expired: Vec<String> = {
        let deadlines = state.signing_deadlines.lock().expect("poisoned");
        deadlines
            .iter()
            .filter(|(_, d)| now >= **d)
            .map(|(id, _)| id.clone())
            .collect()
    };
    for sid in expired {
        // Recheck state — a session that broadcasted between
        // deadline insertion and this tick is in Complete, not
        // Signing, and its deadline entry is stale. Don't sweep it.
        let still_signing = match state.sessions.get(&sid) {
            Some(s) => matches!(s.state, LiteSessionState::Signing),
            None => false,
        };
        if !still_signing {
            // Drop the stale deadline so we don't keep checking it.
            state
                .signing_deadlines
                .lock()
                .expect("poisoned")
                .remove(&sid);
            continue;
        }
        let summary = execute_no_sign_sweep(state, &sid);
        if summary.unbannable > 0 {
            warn!(
                session_id = %sid,
                unbannable = summary.unbannable,
                "swept session had non-signers whose outpoint could not be parsed",
            );
        }
    }

    // 3. Drop expired disruption cooldowns. Purely to bound memory:
    //    `banned_until` already judges expiry itself, so a tick that
    //    never runs cannot leave a coin banned past its time (#699).
    state.bans.sweep_expired(now);
}
