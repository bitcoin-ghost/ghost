//! In-process ring buffer of recent `tracing` log events.
//!
//! ghost-pool installs a `tracing` layer (`ghost_pool::log_ring::LogRingLayer`)
//! that mirrors every emitted event into this bounded buffer; the dashboard
//! `GET /api/v1/logs` endpoint reads back the most recent entries.
//!
//! Keeping the log tail in-process — rather than shelling out to `journalctl` —
//! means each entry carries the real structured message, target and level of the
//! originating `tracing` event, and the endpoint needs no host log daemon or
//! extra privileges. The previous journalctl-backed implementation returned
//! entries whose `message` field was frequently empty (the ANSI-coloured
//! formatted line was stored by journald as a byte array, so the JSON string
//! decode yielded nothing), which is the bug this module fixes.

use std::collections::VecDeque;
use std::sync::LazyLock;

use parking_lot::RwLock;

/// Maximum number of log records retained. Oldest records are evicted FIFO.
const CAPACITY: usize = 4000;

/// A single captured log event.
#[derive(Debug, Clone)]
pub struct LogRecord {
    /// Unix time in milliseconds when the event was captured.
    pub timestamp_ms: u64,
    /// Lowercase severity: `error` | `warn` | `info` | `debug` | `trace`.
    pub level: &'static str,
    /// The event's `tracing` target (module path / span target).
    pub target: String,
    /// The formatted event message plus any structured key/value fields.
    pub message: String,
}

static RING: LazyLock<RwLock<VecDeque<LogRecord>>> =
    LazyLock::new(|| RwLock::new(VecDeque::with_capacity(CAPACITY)));

/// Severity rank used for level filtering. Lower rank = higher severity, which
/// matches the dashboard's "show this level and everything more severe" filter.
fn level_rank(level: &str) -> u8 {
    match level {
        "error" => 0,
        "warn" => 1,
        "info" => 2,
        "debug" => 3,
        _ => 4, // trace / unknown
    }
}

/// Append a captured event to the ring, evicting the oldest entry when full.
pub fn push(timestamp_ms: u64, level: &'static str, target: String, message: String) {
    let mut ring = RING.write();
    if ring.len() >= CAPACITY {
        ring.pop_front();
    }
    ring.push_back(LogRecord {
        timestamp_ms,
        level,
        target,
        message,
    });
}

/// Return up to `limit` of the most recent records, oldest-first, optionally
/// filtered to a minimum severity.
///
/// `min_level = None` (or `Some("all")`) returns every level; otherwise only
/// records at or above the given severity are included (e.g. `"warn"` yields
/// `error` and `warn`). Each record is rendered as the JSON object the dashboard
/// `/logs` page expects: `{ timestamp, level, target, message }` with `timestamp`
/// in Unix milliseconds.
pub fn recent(limit: usize, min_level: Option<&str>) -> Vec<serde_json::Value> {
    let min_rank = match min_level {
        None | Some("all") => u8::MAX,
        Some(l) => level_rank(l),
    };
    let ring = RING.read();
    // Walk newest→oldest, keep the freshest `limit` that pass the filter, then
    // reverse back to chronological (oldest-first) order for display.
    let mut selected: Vec<&LogRecord> = ring
        .iter()
        .rev()
        .filter(|r| level_rank(r.level) <= min_rank)
        .take(limit)
        .collect();
    selected.reverse();
    selected
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "timestamp": r.timestamp_ms,
                "level": r.level,
                "target": r.target,
                "message": r.message,
            })
        })
        .collect()
}

/// Clear the ring. Test-only helper so unit tests start from a known state.
#[cfg(test)]
pub fn clear() {
    RING.write().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_message_target_and_level_and_filters() {
        clear();
        push(1_000, "info", "ghost-pool".into(), "started up".into());
        push(
            2_000,
            "warn",
            "ghost-pool::mesh".into(),
            "peer dropped".into(),
        );
        push(
            3_000,
            "error",
            "ghost-pool::rpc".into(),
            "rpc timeout".into(),
        );

        // No filter returns all three, oldest-first, each with a real message.
        let all = recent(100, None);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0]["message"], "started up");
        assert_eq!(all[0]["level"], "info");
        assert_eq!(all[0]["target"], "ghost-pool");
        assert_eq!(all[0]["timestamp"], 1_000);
        // Crucially, no entry has an empty message (the #246 regression).
        assert!(all
            .iter()
            .all(|e| !e["message"].as_str().unwrap().is_empty()));

        // "warn" filter yields warn + error (more severe), not info.
        let warn = recent(100, Some("warn"));
        assert_eq!(warn.len(), 2);
        assert_eq!(warn[0]["message"], "peer dropped");
        assert_eq!(warn[1]["message"], "rpc timeout");

        // limit keeps the freshest N.
        let one = recent(1, None);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0]["message"], "rpc timeout");
    }
}
