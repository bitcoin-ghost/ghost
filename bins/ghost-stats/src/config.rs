//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: bins/ghost-stats/src/config.rs                                                                                 |

//! Configuration for the stats aggregator.
//!
//! Every refresh cadence is configurable because the underlying queries differ in cost by three
//! orders of magnitude. Measured through the public path on 2026-08-19, cache bypassed:
//!
//! ```text
//! mining/status                    0.16 s
//! pool/next_payout                 0.15 s
//! pool/records?window=day          0.06 s
//! pool/records?window=week         0.43 s
//! pool/records?window=month     7-20 s      (504s at the nginx proxy)
//! pool/leaderboard?window=day      6.65 s
//! pool/leaderboard?window=week  >10   s      (504)
//! pool/leaderboard?window=month >10   s      (504)
//! pool/leaderboard?window=lifetime 0.16 s
//! ```
//!
//! Ranking by rarity means `reverse_hex(share_hash)` over every row in the window, which is a
//! function of the column, so no index can serve the `ORDER BY`. These are not queries that get
//! cheap; they get run less often. A "best in window" record can only IMPROVE until it ages out,
//! so a stale answer is a conservative one rather than a wrong one -- which is what makes a long
//! cadence honest here rather than merely convenient.

use serde::Deserialize;
use std::time::Duration;

/// A pool node the aggregator fans out to.
///
/// `url` is the node's API base reached DIRECTLY, not through the public nginx proxy. That matters:
/// the proxy caps `proxy_read_timeout` at 10s, which is below the cost of several of these queries,
/// so going through it would make the slow windows permanently unfetchable.
#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    pub id: String,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Bound to loopback by default; nginx is the only intended caller.
    #[serde(default = "default_listen")]
    pub listen: String,
}

fn default_listen() -> String {
    "127.0.0.1:8790".to_string()
}

/// Per-task refresh cadences, in seconds.
#[derive(Debug, Clone, Deserialize)]
pub struct RefreshConfig {
    #[serde(default = "d_30")]
    pub status_secs: u64,
    #[serde(default = "d_30")]
    pub payout_secs: u64,
    #[serde(default = "d_60")]
    pub records_block_secs: u64,
    #[serde(default = "d_60")]
    pub records_day_secs: u64,
    #[serde(default = "d_300")]
    pub records_week_secs: u64,
    #[serde(default = "d_600")]
    pub records_month_secs: u64,
    #[serde(default = "d_60")]
    pub leaderboard_shares_secs: u64,
    #[serde(default = "d_120")]
    pub leaderboard_best_day_secs: u64,
    #[serde(default = "d_300")]
    pub leaderboard_best_week_secs: u64,
    #[serde(default = "d_600")]
    pub leaderboard_best_month_secs: u64,
    /// Per-node HTTP timeout. Generously above the slowest measured query (~20s) because a
    /// background refresh has nobody waiting on it -- unlike a browser, it can afford to wait.
    #[serde(default = "d_30")]
    pub node_timeout_secs: u64,
}

fn d_30() -> u64 { 30 }
fn d_60() -> u64 { 60 }
fn d_120() -> u64 { 120 }
fn d_300() -> u64 { 300 }
fn d_600() -> u64 { 600 }

impl Default for RefreshConfig {
    fn default() -> Self {
        toml::from_str("").expect("all RefreshConfig fields have serde defaults")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_server")]
    pub server: ServerConfig,
    pub nodes: Vec<NodeConfig>,
    #[serde(default)]
    pub refresh: RefreshConfig,
    /// Where the last good snapshot is mirrored to disk.
    ///
    /// Without this a service restart serves an empty page until the first cycle completes, which
    /// is precisely the "showing nothing while it loads" behaviour this service exists to remove.
    #[serde(default = "default_cache_path")]
    pub snapshot_path: String,
}

fn default_server() -> ServerConfig {
    ServerConfig { listen: default_listen() }
}

fn default_cache_path() -> String {
    "/var/lib/ghost-stats/snapshot.json".to_string()
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {path}: {e}"))?;
        let cfg: Config = toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("parsing config {path}: {e}"))?;
        if cfg.nodes.is_empty() {
            anyhow::bail!("config {path} lists no [[nodes]] -- nothing to aggregate");
        }
        Ok(cfg)
    }

    pub fn node_timeout(&self) -> Duration {
        Duration::from_secs(self.refresh.node_timeout_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_defaults_apply_when_section_absent() {
        let cfg: Config = toml::from_str(
            r#"
            [[nodes]]
            id = "vm1"
            url = "http://10.0.0.1:8080"
            "#,
        )
        .expect("minimal config parses");
        // The whole [refresh] table is optional; a bare node list must still yield working cadences.
        assert_eq!(cfg.refresh.status_secs, 30);
        assert_eq!(cfg.refresh.records_month_secs, 600);
        assert_eq!(cfg.server.listen, "127.0.0.1:8790");
    }

    #[test]
    fn partial_refresh_section_keeps_other_defaults() {
        let cfg: Config = toml::from_str(
            r#"
            [[nodes]]
            id = "vm1"
            url = "http://10.0.0.1:8080"

            [refresh]
            records_month_secs = 1800
            "#,
        )
        .expect("partial refresh config parses");
        assert_eq!(cfg.refresh.records_month_secs, 1800);
        assert_eq!(cfg.refresh.status_secs, 30, "untouched fields keep their default");
    }
}
