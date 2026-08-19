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
//| FILE: bins/ghost-stats/src/refresh.rs                                                                                |

//! Background refresh: the only thing in the system that talks to the nodes.
//!
//! One task per logical query, each on its own cadence, because the queries differ in cost by three
//! orders of magnitude and a single shared cycle would be paced by its slowest member. A 20s
//! `records?window=month` scan inside a 60s cycle would eat a third of it and stall the cheap tiles
//! behind it -- which is the shape of the original problem, just moved.
//!
//! Tasks are independent by construction: each owns one section of the snapshot and never reads
//! another's. A task that fails leaves its section untouched, so a slow or dead node degrades one
//! panel's freshness instead of blanking the page.

use crate::config::Config;
use crate::merge::{self, LeaderboardMerged, StatusSummary};
use crate::snapshot::{now_secs, Section, SharedSnapshot};
use std::sync::Arc;
use std::time::Duration;

const LEADERBOARD_LIMIT: usize = 10;

pub struct Fetcher {
    client: reqwest::Client,
    cfg: Arc<Config>,
}

impl Fetcher {
    pub fn new(cfg: Arc<Config>) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(cfg.node_timeout())
            // Keep-alive matters here: the same eight hosts are polled forever, and a fresh TLS/TCP
            // handshake per request was a large share of the latency previously attributed to the
            // handlers themselves.
            .pool_idle_timeout(Duration::from_secs(120))
            .user_agent(concat!("ghost-stats/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { client, cfg })
    }

    /// Ask every node the same question, concurrently. A node that fails contributes `None`.
    async fn fan_out(&self, path: &str) -> Vec<(String, Option<serde_json::Value>)> {
        let futures = self.cfg.nodes.iter().map(|node| {
            let client = self.client.clone();
            let url = format!("{}/{}", node.url.trim_end_matches('/'), path.trim_start_matches('/'));
            let id = node.id.clone();
            async move {
                let started = std::time::Instant::now();
                let result = client.get(&url).send().await;
                let value = match result {
                    Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
                        Ok(v) => Some(v),
                        Err(e) => {
                            tracing::warn!(node = %id, path, error = %e, "malformed JSON");
                            None
                        }
                    },
                    Ok(resp) => {
                        tracing::warn!(node = %id, path, status = %resp.status(), "node returned an error status");
                        None
                    }
                    Err(e) => {
                        tracing::warn!(node = %id, path, elapsed_ms = started.elapsed().as_millis(), error = %e, "fetch failed");
                        None
                    }
                };
                (id, value)
            }
        });
        futures::future::join_all(futures).await
    }
}

/// Run `task` immediately, then every `period`, forever.
///
/// `offset` staggers the first run so ten tasks do not hit all eight nodes in the same instant at
/// boot -- which on 4 GB nodes with a 4.5 GB database is enough to make every one of them slow and
/// produce a first snapshot far worse than steady state.
fn spawn_cycle<F, Fut>(name: &'static str, period: Duration, offset: Duration, task: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    tokio::spawn(async move {
        tokio::time::sleep(offset).await;
        let mut ticker = tokio::time::interval(period);
        // If a cycle overruns its period (a 20s query on a 60s cadence that goes badly), skip the
        // missed ticks rather than queueing them -- otherwise a slow patch produces a burst of
        // back-to-back fan-outs the moment it recovers.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let started = std::time::Instant::now();
            task().await;
            tracing::debug!(task = name, elapsed_ms = started.elapsed().as_millis(), "cycle complete");
        }
    });
}

pub fn spawn_all(cfg: Arc<Config>, snap: SharedSnapshot, fetcher: Arc<Fetcher>) {
    let r = &cfg.refresh;

    // ── status ──
    {
        let (f, s) = (fetcher.clone(), snap.clone());
        spawn_cycle("status", Duration::from_secs(r.status_secs), Duration::ZERO, move || {
            let (f, s) = (f.clone(), s.clone());
            async move {
                let responses = f.fan_out("api/v1/mining/status").await;
                let merged: StatusSummary = merge::merge_status(&responses);
                if merged.ok_nodes == 0 {
                    tracing::warn!("status: every node failed — keeping the previous snapshot");
                    return;
                }
                s.update(|snap| {
                    snap.status = Some(Section {
                        updated_at: now_secs(),
                        ok_nodes: merged.ok_nodes,
                        total_nodes: merged.total_nodes,
                        data: merged,
                    });
                })
                .await;
            }
        });
    }

    // ── next payout ──
    {
        let (f, s) = (fetcher.clone(), snap.clone());
        spawn_cycle("payout", Duration::from_secs(r.payout_secs), Duration::from_secs(2), move || {
            let (f, s) = (f.clone(), s.clone());
            async move {
                let responses = f.fan_out("api/v1/pool/next_payout").await;
                // `None` means every node failed, which is NOT the same as "nobody is owed
                // anything" — keep the previous view rather than painting an empty table.
                let Some(merged) = merge::merge_payout(&responses) else {
                    tracing::warn!("payout: every node failed — keeping the previous snapshot");
                    return;
                };
                s.update(|snap| {
                    snap.payout = Some(Section {
                        updated_at: now_secs(),
                        ok_nodes: merged.ok_nodes,
                        total_nodes: merged.total_nodes,
                        data: merged,
                    });
                })
                .await;
            }
        });
    }

    // ── records, one task per window ──
    for (window, secs, offset) in [
        ("block", r.records_block_secs, 4u64),
        ("day", r.records_day_secs, 6),
        ("week", r.records_week_secs, 8),
        ("month", r.records_month_secs, 10),
    ] {
        let (f, s) = (fetcher.clone(), snap.clone());
        spawn_cycle(
            "records",
            Duration::from_secs(secs),
            Duration::from_secs(offset),
            move || {
                let (f, s) = (f.clone(), s.clone());
                async move {
                    let responses = f.fan_out(&format!("api/v1/pool/records?window={window}")).await;
                    let any_ok = responses.iter().any(|(_, v)| v.as_ref().is_some_and(merge::usable));
                    let fresh = merge::merge_records(&responses);
                    s.update(|snap| {
                        let cached = snap.records.get(window).cloned().flatten();
                        // The latch decides; a failed cycle simply cannot beat a valid record.
                        let latched = merge::latch_record(window, cached.as_ref(), fresh, now_secs());
                        snap.records.insert(window.to_string(), latched);
                        if any_ok {
                            snap.records_updated.insert(window.to_string(), now_secs());
                        }
                        // A wider window can never be worse than a narrower one.
                        merge::enforce_monotonicity(&mut snap.records);
                    })
                    .await;
                }
            },
        );
    }

    // ── leaderboards, one task per category+window the UI can request ──
    for (key, query, secs, offset) in [
        ("shares:lifetime", "lifetime", r.leaderboard_shares_secs, 12u64),
        ("best_hash:day", "day", r.leaderboard_best_day_secs, 14),
        ("best_hash:week", "week", r.leaderboard_best_week_secs, 16),
        ("best_hash:month", "month", r.leaderboard_best_month_secs, 18),
    ] {
        let (f, s) = (fetcher.clone(), snap.clone());
        spawn_cycle(
            "leaderboard",
            Duration::from_secs(secs),
            Duration::from_secs(offset),
            move || {
                let (f, s) = (f.clone(), s.clone());
                async move {
                    let path = format!("api/v1/pool/leaderboard?window={query}&limit={LEADERBOARD_LIMIT}");
                    let responses = f.fan_out(&path).await;
                    let merged: LeaderboardMerged = merge::merge_leaderboard(&responses, LEADERBOARD_LIMIT);
                    if merged.ok_nodes == 0 {
                        tracing::warn!(key, "leaderboard: every node failed — keeping the previous snapshot");
                        return;
                    }
                    s.update(|snap| {
                        snap.leaderboards.insert(
                            key.to_string(),
                            Section {
                                updated_at: now_secs(),
                                ok_nodes: merged.ok_nodes,
                                total_nodes: merged.total_nodes,
                                data: merged,
                            },
                        );
                    })
                    .await;
                }
            },
        );
    }

    tracing::info!(nodes = cfg.nodes.len(), "refresh tasks started");
}
