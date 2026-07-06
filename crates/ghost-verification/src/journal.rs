//! Multi-binary log source backed by `journalctl`.
//!
//! The dashboard Logs console reads ghost-pool's own output from the in-process
//! ring buffer (`crate::log_buffer`). This module extends that console to the
//! *other* node binaries — ghostd, ghost-pay, the dashboard and the SV2 stack —
//! whose logs live in the systemd journal rather than in ghost-pool's address
//! space.
//!
//! ## Security model (STRICT allowlist + argv, zero injection)
//!
//! The dashboard sends a *logical* unit key (e.g. `ghostd`), never a systemd
//! unit string. [`resolve_unit`] looks that key up in a fixed, compile-time
//! [`ALLOWLIST`]; an unknown key is rejected before anything is executed. The
//! resolved unit string is a hard-coded constant from this table — a client
//! string is never interpolated into it.
//!
//! `journalctl` is invoked with an explicit `argv` (`Command::new("journalctl")
//! .args([...])`), never through a shell, so there is no word-splitting, glob or
//! metacharacter surface even in principle. The only non-constant arguments are
//! (a) the allowlisted unit constant and (b) integers we format ourselves
//! (`limit`, priority range) — neither is attacker-controlled.

use std::collections::HashMap;

use tokio::process::Command;

/// A binary whose logs the dashboard may read.
#[derive(Debug, Clone, Copy)]
pub struct LogUnit {
    /// Stable logical key the dashboard sends (`?unit=<key>`).
    pub key: &'static str,
    /// The real systemd unit string. Hard-coded — never built from input.
    pub unit: &'static str,
    /// Human label for the selector.
    pub label: &'static str,
    /// One-line description of what this binary is.
    pub description: &'static str,
    /// `true` for ghost-pool, which is served from the in-process ring buffer
    /// rather than journald.
    pub ring_buffer: bool,
}

/// The complete, fixed set of readable log sources. Seeded from the real unit
/// names present on the production nodes (`systemctl list-units 'ghost*' 'sri*'`
/// on ghost-vm1). Adding a binary here is the ONLY way to make it readable.
pub const ALLOWLIST: &[LogUnit] = &[
    LogUnit {
        key: "ghost-pool",
        unit: "ghost-pool.service",
        label: "Ghost Pool",
        description: "Mining pool node (this process) — in-memory ring buffer",
        ring_buffer: true,
    },
    LogUnit {
        key: "ghostd",
        unit: "ghostd.service",
        label: "Ghost Core",
        description: "ghostd — Bitcoin Ghost Core daemon",
        ring_buffer: false,
    },
    LogUnit {
        key: "ghost-pay",
        unit: "ghost-pay.service",
        label: "Ghost Pay",
        description: "L2 instant-payment service",
        ring_buffer: false,
    },
    LogUnit {
        key: "dashboard",
        unit: "ghost-dashboard.service",
        label: "Dashboard",
        description: "Node dashboard web server",
        ring_buffer: false,
    },
    LogUnit {
        key: "sri-pool",
        unit: "sri-pool.service",
        label: "SV2 Pool",
        description: "Stratum V2 pool (pool_sv2)",
        ring_buffer: false,
    },
    LogUnit {
        key: "sri-translator",
        unit: "sri-translator.service",
        label: "SV2 Translator",
        description: "Stratum V1→V2 translator (translator_sv2)",
        ring_buffer: false,
    },
];

/// The default unit key (ghost-pool ring buffer), used when `?unit=` is absent.
pub const DEFAULT_UNIT: &str = "ghost-pool";

/// Resolve a logical key from the allowlist. Returns `None` for any key not in
/// [`ALLOWLIST`] — the caller MUST reject (HTTP 400) without executing anything.
pub fn resolve_unit(key: &str) -> Option<&'static LogUnit> {
    ALLOWLIST.iter().find(|u| u.key == key)
}

/// Structured failure from reading a journald unit. Rendered to an honest error
/// state in the UI — never converted into fake log lines.
#[derive(Debug)]
pub enum JournalError {
    /// `journalctl` is not installed / not on `PATH`.
    Unavailable,
    /// The journal could not be read (typically the service user is not in the
    /// `systemd-journal` group).
    PermissionDenied,
    /// Any other non-zero exit, carrying journalctl's stderr for the operator.
    Command(String),
}

impl JournalError {
    /// Operator-facing message shown in the Logs console.
    pub fn message(&self) -> String {
        match self {
            JournalError::Unavailable => {
                "journalctl is not available on this host, so logs for this binary cannot be read."
                    .to_string()
            }
            JournalError::PermissionDenied => {
                "Permission denied reading this binary's journal. The ghost-pool service needs to \
                 be in the systemd-journal group (SupplementaryGroups=systemd-journal); this takes \
                 effect on the next ghost-pool restart."
                    .to_string()
            }
            JournalError::Command(stderr) => {
                let trimmed = stderr.trim();
                if trimmed.is_empty() {
                    "journalctl exited with an error while reading this binary's log.".to_string()
                } else {
                    format!("journalctl error: {trimmed}")
                }
            }
        }
    }
}

/// Syslog priority filter passed to journalctl's `--priority a..b` for a minimum
/// display level. `None` means "no filter" (show every level).
fn priority_range(min_level: Option<&str>) -> Option<&'static str> {
    match min_level {
        None | Some("all") | Some("trace") | Some("debug") => None,
        // journald has no dedicated trace level; 7 (debug) is the finest.
        Some("info") => Some("0..6"),  // emerg..info
        Some("warn") => Some("0..4"),  // emerg..warning
        Some("error") => Some("0..3"), // emerg..err
        Some(_) => None,
    }
}

/// Map a syslog PRIORITY (0..7) to the dashboard's lowercase level string,
/// matching the ring-buffer vocabulary (`error`/`warn`/`info`/`debug`/`trace`).
fn priority_to_level(priority: Option<&str>) -> &'static str {
    match priority.and_then(|p| p.trim().parse::<u8>().ok()) {
        Some(0..=3) => "error",      // emerg, alert, crit, err
        Some(4) => "warn",           // warning
        Some(5) | Some(6) => "info", // notice, info
        Some(7) => "debug",          // debug
        _ => "info",                 // absent/unknown → info
    }
}

/// Strip ANSI/VT escape sequences (colour, cursor moves) from a log message.
///
/// ghost-pay and some other binaries colour their `tracing` output, and journald
/// stores those raw bytes. We render plain text, so drop every CSI/OSC/escape
/// sequence. Implemented as a tiny state machine (no regex dependency).
pub fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // ESC seen. Inspect the next byte to decide the sequence kind.
        match chars.next() {
            // CSI: ESC [ ... final-byte in 0x40..=0x7e
            Some('[') => {
                for f in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&f) {
                        break;
                    }
                }
            }
            // OSC: ESC ] ... terminated by BEL or ESC \
            Some(']') => {
                while let Some(f) = chars.next() {
                    if f == '\u{07}' {
                        break;
                    }
                    if f == '\u{1b}' {
                        if matches!(chars.peek(), Some('\\')) {
                            chars.next();
                        }
                        break;
                    }
                }
            }
            // Any other two-char escape (e.g. ESC c) — drop the escape + next.
            Some(_) | None => {}
        }
    }
    out
}

/// A journald MESSAGE (or any field) may arrive as a JSON string OR, when it
/// contains non-UTF-8 or control bytes, as a JSON array of byte integers.
/// Decode both shapes to a `String`.
fn field_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(arr) => {
            let bytes: Vec<u8> = arr
                .iter()
                .filter_map(|v| v.as_u64())
                .map(|n| n as u8)
                .collect();
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => None,
    }
}

/// Parse a single line of `journalctl -o json` output into the same
/// `{ timestamp, level, target, message }` object the ring buffer emits.
/// Returns `None` for blank lines or lines missing a MESSAGE.
pub fn parse_journal_line(line: &str) -> Option<serde_json::Value> {
    let obj: HashMap<String, serde_json::Value> = serde_json::from_str(line).ok()?;

    // __REALTIME_TIMESTAMP is microseconds since the epoch, as a string.
    let timestamp_ms = obj
        .get("__REALTIME_TIMESTAMP")
        .and_then(field_to_string)
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|us| us / 1000)
        .unwrap_or(0);

    let level = priority_to_level(obj.get("PRIORITY").and_then(field_to_string).as_deref());

    // Prefer SYSLOG_IDENTIFIER, else the systemd unit, as the "target" column.
    let target = obj
        .get("SYSLOG_IDENTIFIER")
        .and_then(field_to_string)
        .or_else(|| obj.get("_SYSTEMD_UNIT").and_then(field_to_string))
        .unwrap_or_default();

    let message = strip_ansi(&obj.get("MESSAGE").and_then(field_to_string)?);

    Some(serde_json::json!({
        "timestamp": timestamp_ms,
        "level": level,
        "target": target,
        "message": message,
    }))
}

/// Read up to `limit` recent journal records for an allowlisted `unit`,
/// optionally filtered to a minimum severity, and return them oldest-first as
/// the dashboard's log-line JSON objects.
///
/// `unit` MUST be the hard-coded unit string from an [`ALLOWLIST`] entry — never
/// a raw client value. `journalctl` is executed with an explicit argv.
pub async fn read_journal(
    unit: &str,
    limit: usize,
    min_level: Option<&str>,
) -> Result<Vec<serde_json::Value>, JournalError> {
    let limit = limit.clamp(1, 5000);
    let mut cmd = Command::new("journalctl");
    cmd.args([
        "--no-pager",
        "-o",
        "json",
        "-u",
        unit,
        "-n",
        &limit.to_string(),
    ]);
    if let Some(range) = priority_range(min_level) {
        cmd.args(["--priority", range]);
    }

    let output = match cmd.output().await {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(JournalError::Unavailable);
        }
        Err(e) => return Err(JournalError::Command(e.to_string())),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
        if stderr.contains("permission")
            || stderr.contains("not allowed")
            || stderr.contains("access denied")
        {
            return Err(JournalError::PermissionDenied);
        }
        return Err(JournalError::Command(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let entries: Vec<serde_json::Value> = stdout.lines().filter_map(parse_journal_line).collect();
    Ok(entries)
}

/// Check whether a systemd unit is loaded on this host, so the dashboard only
/// offers selectors for binaries that actually exist here. ghost-pool (ring
/// buffer) is always available. Errors/absence are reported as `false`, never
/// as a hard failure of the units listing.
pub async fn unit_is_present(u: &LogUnit) -> bool {
    if u.ring_buffer {
        return true;
    }
    match Command::new("systemctl")
        .args(["show", u.unit, "--property=LoadState", "--value"])
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            let state = String::from_utf8_lossy(&out.stdout);
            state.trim() == "loaded"
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_rejects_unknown_units_without_exec() {
        // Unknown / injection-shaped keys resolve to None → caller returns 400
        // and NEVER reaches the journalctl exec path.
        assert!(resolve_unit("ghostd").is_some());
        assert!(resolve_unit("ghost-pool").is_some());
        assert!(resolve_unit("does-not-exist").is_none());
        assert!(resolve_unit("ghostd.service").is_none()); // must send the KEY
        assert!(resolve_unit("ghostd; rm -rf /").is_none());
        assert!(resolve_unit("$(reboot)").is_none());
        assert!(resolve_unit("../../etc/passwd").is_none());
        assert!(resolve_unit("").is_none());
    }

    #[test]
    fn resolved_unit_string_is_a_fixed_constant() {
        // The resolved unit is the hard-coded table value, not the input.
        let u = resolve_unit("ghostd").unwrap();
        assert_eq!(u.unit, "ghostd.service");
        assert!(!u.ring_buffer);
        let pool = resolve_unit("ghost-pool").unwrap();
        assert!(pool.ring_buffer);
    }

    #[test]
    fn strip_ansi_removes_colour_and_keeps_text() {
        // SGR colour codes (ghost-pay style) are removed, text preserved.
        assert_eq!(strip_ansi("\u{1b}[32mINFO\u{1b}[0m started"), "INFO started");
        assert_eq!(strip_ansi("\u{1b}[1;31merror!\u{1b}[0m"), "error!");
        // Plain text is untouched.
        assert_eq!(strip_ansi("no escapes here"), "no escapes here");
        // OSC sequence (ESC ] ... BEL) is removed.
        assert_eq!(strip_ansi("a\u{1b}]0;title\u{07}b"), "ab");
        // Bare ESC + following byte dropped without panicking.
        assert_eq!(strip_ansi("x\u{1b}cy"), "xy");
    }

    #[test]
    fn priority_maps_to_level() {
        assert_eq!(priority_to_level(Some("0")), "error");
        assert_eq!(priority_to_level(Some("3")), "error");
        assert_eq!(priority_to_level(Some("4")), "warn");
        assert_eq!(priority_to_level(Some("6")), "info");
        assert_eq!(priority_to_level(Some("7")), "debug");
        assert_eq!(priority_to_level(None), "info");
        assert_eq!(priority_to_level(Some("garbage")), "info");
    }

    #[test]
    fn priority_range_filter() {
        assert_eq!(priority_range(None), None);
        assert_eq!(priority_range(Some("all")), None);
        assert_eq!(priority_range(Some("trace")), None);
        assert_eq!(priority_range(Some("debug")), None);
        assert_eq!(priority_range(Some("info")), Some("0..6"));
        assert_eq!(priority_range(Some("warn")), Some("0..4"));
        assert_eq!(priority_range(Some("error")), Some("0..3"));
    }

    #[test]
    fn parses_journal_json_string_message() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"6","SYSLOG_IDENTIFIER":"ghostd","MESSAGE":"UpdateTip: new best block"}"#;
        let v = parse_journal_line(line).unwrap();
        assert_eq!(v["timestamp"], 1_700_000_000_000u64); // us → ms
        assert_eq!(v["level"], "info");
        assert_eq!(v["target"], "ghostd");
        assert_eq!(v["message"], "UpdateTip: new best block");
    }

    #[test]
    fn parses_journal_json_array_message_and_strips_ansi() {
        // MESSAGE as a byte array carrying an ANSI colour sequence: bytes for
        // ESC [ 3 2 m O K ESC [ 0 m
        let line = r#"{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"4","_SYSTEMD_UNIT":"ghost-pay.service","MESSAGE":[27,91,51,50,109,79,75,27,91,48,109]}"#;
        let v = parse_journal_line(line).unwrap();
        assert_eq!(v["level"], "warn");
        assert_eq!(v["target"], "ghost-pay.service"); // fell back to unit
        assert_eq!(v["message"], "OK"); // ANSI stripped from the byte array
    }

    #[test]
    fn skips_lines_without_message_or_blank() {
        assert!(parse_journal_line("").is_none());
        assert!(parse_journal_line("not json").is_none());
        assert!(parse_journal_line(r#"{"PRIORITY":"6"}"#).is_none());
    }
}
