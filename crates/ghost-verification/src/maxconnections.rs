//! Reading and changing ghostd's `maxconnections` (#499).
//!
//! This is not a cosmetic setting. Core reserves the outbound slots out of `maxconnections`, so
//! a node configured at 50 has roughly 40 inbound to give. A settled node sits at ~39 of them,
//! is therefore **full**, and Core then refuses new peers — including crawlers, which record it
//! unreachable and drop it from public listings. The whole fleet vanished from node listings
//! that way while every node was healthy and externally reachable (#497, #498).
//!
//! Nothing surfaced that. An operator saw a healthy node with no indication it was turning peers
//! away, and no way to change it without SSH.

use std::path::PathBuf;

/// Outbound slots Core holds back from `maxconnections`: 8 full-relay + 2 block-relay-only
/// + 1 feeler.
///
/// These are Core's documented defaults (`MAX_OUTBOUND_FULL_RELAY_CONNECTIONS`,
/// `MAX_BLOCK_RELAY_ONLY_CONNECTIONS`) plus the single feeler slot, which Core includes in the
/// outbound reserve even though an individual feeler connection is short-lived.
///
/// This was 10 — the feeler was omitted — which overstated inbound capacity by one. The live
/// fleet settles it: on 2026-07-30 vm4 reported `connections_out=11` while vm1-vm3 reported 10,
/// the difference being whether a feeler happened to be open at that instant. The reserve is 11.
///
/// The inbound capacity an operator actually has is `maxconnections` MINUS this, which is the
/// number that matters and the one nothing was showing.
pub const RESERVED_OUTBOUND: u32 = 11;

/// Fraction of inbound capacity at which a node is close enough to full to warn about.
///
/// Being full is silent — it does not degrade, it just stops accepting, and the node disappears
/// from other people's view of the network while looking perfectly healthy from the inside.
pub const NEAR_CEILING_FRACTION: f64 = 0.85;

/// Memory allowance per peer used to bound the recommended maximum, in MB.
///
/// Core's per-peer ceilings are `maxreceivebuffer` (5 MB) plus `maxsendbuffer` (1 MB); steady
/// state is far below that, often under 1 MB. 4 MB sits between typical and worst case
/// deliberately: sizing for the typical figure is what lets a node get killed under load, and
/// sizing for the ceiling gives a bound so low it is useless.
///
/// It is a judgement, not a measurement, so the API returns it alongside the number it produced
/// rather than presenting the bound as fact.
pub const PER_PEER_MB: u64 = 4;

/// Memory left for everything that is not peer connections, in MB.
pub const HEADROOM_MB: u64 = 512;

/// Core's own default when `maxconnections` is absent from the config.
pub const CORE_DEFAULT: u32 = 125;

/// Refuse anything above this regardless of available memory — past here the file-descriptor
/// limit and Core's own behaviour matter more than RAM, and we are no longer the right judge.
pub const HARD_MAX: u32 = 500;

/// Path to ghostd's config file. `GHOST_BITCOIN_CONF` overrides it, which is also how tests
/// point at a temporary file instead of the real one.
pub fn conf_path() -> PathBuf {
    std::env::var("GHOST_BITCOIN_CONF")
        .unwrap_or_else(|_| "/etc/bitcoin/bitcoin.conf".to_string())
        .into()
}

/// What the config file says, and whether it says it more than once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configured {
    /// The effective value, or `None` when the file does not set it (Core then uses its default).
    pub value: Option<u32>,
    /// Every value found, in file order. More than one entry means the file is ambiguous.
    pub all_values: Vec<u32>,
}

impl Configured {
    /// A file that sets `maxconnections` more than once is ambiguous, and we will not write to it.
    ///
    /// Which occurrence Core honours is a detail of its settings layer, not something worth
    /// guessing at from here — and a writer that guesses could silently move a value the operator
    /// believes is set to something else entirely.
    pub fn is_ambiguous(&self) -> bool {
        self.all_values.len() > 1
    }

    /// The value in force: what the file sets, else Core's default.
    pub fn effective(&self) -> u32 {
        self.value.unwrap_or(CORE_DEFAULT)
    }
}

/// Parse `maxconnections` out of a config file's text.
///
/// Comments and `[section]` headers are ignored, as is leading whitespace. Core does not accept
/// trailing comments on a value line, so neither do we.
pub fn parse(contents: &str) -> Configured {
    let mut all_values = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "maxconnections" {
            continue;
        }
        if let Ok(n) = value.trim().parse::<u32>() {
            all_values.push(n);
        }
    }
    Configured {
        value: all_values.last().copied(),
        all_values,
    }
}

/// Read the configured value from disk. A missing file reads as "not set", not an error — a node
/// can legitimately run on Core's defaults.
pub fn read_configured() -> std::io::Result<Configured> {
    match std::fs::read_to_string(conf_path()) {
        Ok(contents) => Ok(parse(&contents)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Configured {
            value: None,
            all_values: Vec::new(),
        }),
        Err(e) => Err(e),
    }
}

/// Inbound slots available at a given `maxconnections`.
pub fn inbound_capacity(maxconnections: u32) -> u32 {
    maxconnections.saturating_sub(RESERVED_OUTBOUND)
}

/// MemAvailable in MB, or `None` when `/proc/meminfo` cannot be read or lacks the field.
///
/// MemAvailable, not MemTotal: what matters is what this node can still allocate alongside
/// everything already resident. vm6 has ~1376 MB available against a ghostd RSS of ~1441 MB —
/// sizing that node off MemTotal would recommend a number it cannot survive (#417, #418).
pub fn mem_available_mb() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

/// The largest `maxconnections` this node's available memory supports.
///
/// `None` when memory cannot be determined — the caller must then decline to recommend rather
/// than substitute a guess, because a fabricated ceiling is worse than an absent one.
pub fn recommended_max(mem_available_mb: Option<u64>) -> Option<u32> {
    let available = mem_available_mb?;
    let for_peers = available.saturating_sub(HEADROOM_MB);
    let peers = (for_peers / PER_PEER_MB) as u32;
    // Never recommend below Core's own reserve — a value under that leaves no inbound capacity
    // at all and is not a meaningful setting.
    Some(peers.clamp(RESERVED_OUTBOUND + 1, HARD_MAX))
}

/// Rewrite `maxconnections` in a config file's text, returning the new text.
///
/// Replaces the existing setting in place, preserving everything around it, or appends it when
/// absent. Refuses an ambiguous file rather than picking an occurrence to edit.
pub fn rewrite(contents: &str, new_value: u32) -> Result<String, String> {
    let configured = parse(contents);
    if configured.is_ambiguous() {
        return Err(format!(
            "config sets maxconnections {} times ({:?}); refusing to guess which one is in force \
             — remove the duplicates first",
            configured.all_values.len(),
            configured.all_values
        ));
    }

    if configured.value.is_none() {
        // Append, keeping exactly one trailing newline.
        let mut out = contents.trim_end().to_string();
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!("maxconnections={new_value}\n"));
        return Ok(out);
    }

    let mut out = String::with_capacity(contents.len() + 16);
    // Preserve whether the original ended with a newline; rewriting a line must not silently
    // add or remove one.
    let ends_with_newline = contents.ends_with('\n');
    let mut lines = contents.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        let is_setting = !trimmed.starts_with('#')
            && !trimmed.starts_with('[')
            && trimmed.split_once('=').is_some_and(|(k, v)| {
                k.trim() == "maxconnections" && v.trim().parse::<u32>().is_ok()
            });
        if is_setting {
            out.push_str(&format!("maxconnections={new_value}"));
        } else {
            out.push_str(line);
        }
        if lines.peek().is_some() || ends_with_newline {
            out.push('\n');
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_plain_setting() {
        let c = parse("server=1\nmaxconnections=125\ntxindex=1\n");
        assert_eq!(c.value, Some(125));
        assert!(!c.is_ambiguous());
        assert_eq!(c.effective(), 125);
    }

    #[test]
    fn an_absent_setting_reads_as_cores_default_not_as_zero() {
        let c = parse("server=1\ntxindex=1\n");
        assert_eq!(c.value, None);
        assert_eq!(
            c.effective(),
            CORE_DEFAULT,
            "a node with no setting runs on Core's default, not on nothing"
        );
    }

    #[test]
    fn comments_and_sections_are_not_settings() {
        let c = parse("# maxconnections=999\n[main]\nmaxconnections=50\n");
        assert_eq!(
            c.all_values,
            vec![50],
            "a commented-out value is not in force"
        );
    }

    /// A file that sets it twice is ambiguous, and we refuse to write rather than pick.
    #[test]
    fn a_duplicated_setting_is_refused_not_guessed() {
        let text = "maxconnections=50\nserver=1\nmaxconnections=125\n";
        let c = parse(text);
        assert!(c.is_ambiguous());
        let err = rewrite(text, 200).unwrap_err();
        assert!(err.contains("refusing to guess"), "got: {err}");
    }

    #[test]
    fn rewriting_preserves_every_other_line_and_its_position() {
        let before = "# ghostd config\nserver=1\nmaxconnections=50\nrpcuser=x\n";
        let after = rewrite(before, 125).unwrap();
        assert_eq!(
            after,
            "# ghostd config\nserver=1\nmaxconnections=125\nrpcuser=x\n"
        );
    }

    #[test]
    fn appends_when_the_setting_is_absent() {
        let after = rewrite("server=1\ntxindex=1\n", 125).unwrap();
        assert_eq!(after, "server=1\ntxindex=1\nmaxconnections=125\n");
        assert_eq!(parse(&after).value, Some(125));
    }

    /// A file with no trailing newline must not gain one silently, and vice versa.
    #[test]
    fn rewriting_preserves_the_trailing_newline_exactly() {
        assert_eq!(
            rewrite("maxconnections=50", 125).unwrap(),
            "maxconnections=125"
        );
        assert_eq!(
            rewrite("maxconnections=50\n", 125).unwrap(),
            "maxconnections=125\n"
        );
    }

    /// The number that actually matters: inbound capacity, not the headline setting.
    #[test]
    fn inbound_capacity_is_the_setting_minus_cores_outbound_reserve() {
        // The exact case from #497: 50 configured looks generous but leaves only 39 inbound,
        // which a settled node fills — and a full node silently stops accepting peers.
        assert_eq!(inbound_capacity(50), 39);
        // 125 is the current fleet setting. vm1/vm2/vm3 sat at 114 inbound on 2026-07-30,
        // i.e. exactly full against this capacity (#572).
        assert_eq!(inbound_capacity(125), 114);
        // Never negative, even below the reserve.
        assert_eq!(inbound_capacity(5), 0);
        assert_eq!(inbound_capacity(RESERVED_OUTBOUND), 0);
    }

    #[test]
    fn the_recommendation_is_bounded_by_available_memory() {
        // 4 GB available: (4096 - 512) / 4 = 896, clamped to the hard max.
        assert_eq!(recommended_max(Some(4096)), Some(HARD_MAX));
        // 1376 MB — vm6's real figure: (1376 - 512) / 4 = 216.
        assert_eq!(recommended_max(Some(1376)), Some(216));
        // A tight node gets a correspondingly small number: (600 - 512) / 4 = 22.
        assert_eq!(recommended_max(Some(600)), Some(22));
        // And once headroom eats nearly everything, the floor holds rather than
        // recommending a value with no inbound capacity at all: (520 - 512) / 4 = 2 -> 11.
        assert_eq!(recommended_max(Some(520)), Some(RESERVED_OUTBOUND + 1));
        // Below the headroom reserve entirely, the floor still holds.
        assert_eq!(recommended_max(Some(100)), Some(RESERVED_OUTBOUND + 1));
    }

    /// Unknown memory must produce no recommendation at all. A fabricated ceiling is worse
    /// than an absent one, because it looks like it was measured.
    #[test]
    fn no_memory_reading_means_no_recommendation() {
        assert_eq!(recommended_max(None), None);
    }
}
