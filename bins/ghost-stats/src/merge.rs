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
//| FILE: bins/ghost-stats/src/merge.rs                                                                                  |

//! Pure cross-node merge functions.
//!
//! These are a faithful port of the merge logic that used to run in `pool.html`, kept pure and
//! unit-tested so the move from browser to server is provably behaviour-preserving rather than
//! merely plausible. Where the original had a subtlety, the subtlety is reproduced and the reason
//! is recorded here, because most of them were bug fixes:
//!
//! - **Hashrate is a MAX of the mesh figure, never a SUM.** Every node reports the same mesh-wide
//!   total, so summing multiplies it by the number of responders. Summing `local_hashrate_th` is
//!   the pre-PR#27 fallback only, for nodes that report no mesh figure.
//! - **Rarity compares `share_hash` lexicographically, lowest wins.** The API returns DISPLAY
//!   order (zeros at the FRONT), so a plain string compare is the correct rarity order. This is
//!   the one place the internal/display distinction matters and gets it wrong silently.
//! - **A 200 response carrying an `error` field is a FAILURE, not empty data.** The node returns
//!   `{"error": "Database not available"}` with status 200. Treating that as a valid empty
//!   leaderboard would blank the panel every time a node's database hiccuped.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Rarity order: lowest display-order hash wins.
fn rarer(a: &str, b: &str) -> bool {
    a < b
}

/// A node response is only usable if it is an object WITHOUT an `error` key.
///
/// The pool API answers `{"error": "..."}` with HTTP 200 for an unavailable database or a bad
/// window, so status code alone does not separate success from failure.
pub fn usable(v: &serde_json::Value) -> bool {
    v.is_object() && v.get("error").is_none()
}

fn f64_of(v: &serde_json::Value, key: &str) -> Option<f64> {
    v.get(key).and_then(|x| x.as_f64())
}

fn u64_of(v: &serde_json::Value, key: &str) -> Option<u64> {
    v.get(key).and_then(|x| x.as_u64())
}

fn str_of<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

// ───────────────────────── mining/status ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct StatusSummary {
    /// Mesh-wide hashrate in TH/s.
    pub hashrate_th: f64,
    pub miners: u64,
    pub blocks_found: u64,
    pub block_height: u64,
    pub last_block_time: Option<u64>,
    pub connected_miners: u64,
    /// Per-node detail, for the node health cards.
    pub nodes: Vec<serde_json::Value>,
    pub ok_nodes: usize,
    pub total_nodes: usize,
}

pub fn merge_status(responses: &[(String, Option<serde_json::Value>)]) -> StatusSummary {
    let mut out = StatusSummary {
        total_nodes: responses.len(),
        ..Default::default()
    };

    let mut mesh_hashrate: Option<f64> = None;
    let mut sum_local = 0.0f64;
    let mut mesh_miners: Option<u64> = None;
    let mut max_active = 0u64;

    for (id, resp) in responses {
        let Some(v) = resp.as_ref().filter(|v| usable(v)) else {
            continue;
        };
        out.ok_nodes += 1;

        // Mesh totals: every node reports the same figure, so take the max. Summing would
        // multiply the pool's hashrate by the number of responding nodes.
        if let Some(t) = f64_of(v, "total_hashrate") {
            mesh_hashrate = Some(mesh_hashrate.map_or(t, |m: f64| m.max(t)));
        }
        if let Some(l) = f64_of(v, "local_hashrate_th") {
            sum_local += l;
        }
        if let Some(m) = u64_of(v, "mesh_active_miners") {
            mesh_miners = Some(mesh_miners.map_or(m, |x: u64| x.max(m)));
        }
        max_active = max_active.max(u64_of(v, "active_miners").unwrap_or(0));

        // Blocks found IS a genuine per-node counter, so it sums.
        out.blocks_found += u64_of(v, "blocks_found").unwrap_or(0);
        out.connected_miners += u64_of(v, "connected_miners").unwrap_or(0);
        out.block_height = out.block_height.max(u64_of(v, "block_height").unwrap_or(0));
        if let Some(t) = u64_of(v, "last_block_time") {
            out.last_block_time = Some(out.last_block_time.map_or(t, |x| x.max(t)));
        }

        let mut node = v.clone();
        if let Some(obj) = node.as_object_mut() {
            obj.insert("node_id".into(), serde_json::Value::String(id.clone()));
        }
        out.nodes.push(node);
    }

    out.hashrate_th = mesh_hashrate.unwrap_or(sum_local);
    out.miners = mesh_miners.unwrap_or(max_active);
    out
}

// ───────────────────────── pool/records ─────────────────────────

/// Seconds each record window covers, used to age out a latched record.
pub fn window_secs(window: &str) -> u64 {
    match window {
        "block" => 600,
        "day" => 86_400,
        "week" => 604_800,
        "month" => 2_592_000,
        _ => 2_592_000,
    }
}

/// Rarest `best` across the nodes that answered, or `None` if nobody had one.
pub fn merge_records(
    responses: &[(String, Option<serde_json::Value>)],
) -> Option<serde_json::Value> {
    let mut best: Option<serde_json::Value> = None;
    for (_, resp) in responses {
        let Some(v) = resp.as_ref().filter(|v| usable(v)) else {
            continue;
        };
        if v.get("found").and_then(|f| f.as_bool()) != Some(true) {
            continue;
        }
        let Some(candidate) = v.get("best").filter(|b| b.is_object()) else {
            continue;
        };
        let Some(hash) = str_of(candidate, "share_hash") else {
            continue;
        };
        let replace = match best
            .as_ref()
            .and_then(|b| str_of(b, "share_hash").map(|s| s.to_string()))
        {
            None => true,
            Some(prev) => rarer(hash, &prev),
        };
        if replace {
            best = Some(candidate.clone());
        }
    }
    best
}

/// Temporal latch: a "best in window" record can only IMPROVE until it ages out.
///
/// Each node holds only its own miners' shares, so a given record lives on ONE node. When that node
/// is slow or down in a cycle, the fan-out returns a worse value which must NOT clobber a record
/// that is still valid. Keep the cached best unless the fresh one is genuinely rarer, or the cached
/// one has aged out of its window (at which point fresh data legitimately replaces it).
pub fn latch_record(
    window: &str,
    cached: Option<&serde_json::Value>,
    fresh: Option<serde_json::Value>,
    now_secs: u64,
) -> Option<serde_json::Value> {
    let Some(cached) = cached else { return fresh };
    let Some(cached_ts) = u64_of(cached, "timestamp") else {
        return fresh;
    };
    if now_secs.saturating_sub(cached_ts) >= window_secs(window) {
        return fresh; // aged out of its window
    }
    let cached_hash = str_of(cached, "share_hash").unwrap_or("");
    match fresh.as_ref().and_then(|f| str_of(f, "share_hash")) {
        // Fresh missing or worse: keep the still-valid cached record.
        None => Some(cached.clone()),
        Some(fresh_hash) if rarer(cached_hash, fresh_hash) => Some(cached.clone()),
        Some(_) => fresh,
    }
}

/// Enforce window monotonicity across `block < day < week < month`.
///
/// Wider windows are supersets of narrower ones, so a wider window's best can never be worse than a
/// narrower one's. Without this, a stale month alongside a fresh week shows the user "last week was
/// better than last month", which is arithmetically impossible and reads as a bug.
pub fn enforce_monotonicity(records: &mut BTreeMap<String, Option<serde_json::Value>>) {
    const ORDER: [&str; 4] = ["block", "day", "week", "month"];
    for i in 1..ORDER.len() {
        let narrower = records.get(ORDER[i - 1]).cloned().flatten();
        let Some(narrow) = narrower else { continue };
        let Some(narrow_hash) = str_of(&narrow, "share_hash").map(|s| s.to_string()) else {
            continue;
        };
        let wider = records.get(ORDER[i]).cloned().flatten();
        let replace = match wider
            .as_ref()
            .and_then(|w| str_of(w, "share_hash").map(|s| s.to_string()))
        {
            None => true,
            Some(wide_hash) => rarer(&narrow_hash, &wide_hash),
        };
        if replace {
            records.insert(ORDER[i].to_string(), Some(narrow));
        }
    }
}

// ───────────────────────── pool/leaderboard ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct LeaderboardMerged {
    pub best_hash: Vec<serde_json::Value>,
    pub shares: Vec<serde_json::Value>,
    pub ok_nodes: usize,
    pub total_nodes: usize,
}

pub fn merge_leaderboard(
    responses: &[(String, Option<serde_json::Value>)],
    limit: usize,
) -> LeaderboardMerged {
    let mut out = LeaderboardMerged {
        total_nodes: responses.len(),
        ..Default::default()
    };
    // BTreeMap keyed by redacted miner id keeps the merge deterministic across cycles; the
    // original used a JS Map, whose iteration order is insertion order and therefore depended on
    // which node happened to answer first.
    let mut best_by_miner: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut shares_by_miner: BTreeMap<String, serde_json::Value> = BTreeMap::new();

    for (_, resp) in responses {
        let Some(v) = resp.as_ref().filter(|v| usable(v)) else {
            continue;
        };
        out.ok_nodes += 1;

        for row in v
            .get("best_hash")
            .and_then(|a| a.as_array())
            .into_iter()
            .flatten()
        {
            let (Some(miner), Some(hash)) =
                (str_of(row, "miner_id_redacted"), str_of(row, "share_hash"))
            else {
                continue;
            };
            let replace = match best_by_miner
                .get(miner)
                .and_then(|p| str_of(p, "share_hash").map(|s| s.to_string()))
            {
                None => true,
                Some(prev) => rarer(hash, &prev),
            };
            if replace {
                best_by_miner.insert(miner.to_string(), row.clone());
            }
        }

        for row in v
            .get("shares")
            .and_then(|a| a.as_array())
            .into_iter()
            .flatten()
        {
            let Some(miner) = str_of(row, "miner_id_redacted") else {
                continue;
            };
            match shares_by_miner.get_mut(miner) {
                None => {
                    shares_by_miner.insert(miner.to_string(), row.clone());
                }
                Some(prev) => {
                    // A miner active on several nodes has a ledger row on each; the pool-wide
                    // figure is the sum.
                    let add_count = u64_of(row, "share_count").unwrap_or(0);
                    let add_work = f64_of(row, "total_work").unwrap_or(0.0);
                    let new_count = u64_of(prev, "share_count").unwrap_or(0) + add_count;
                    let new_work = f64_of(prev, "total_work").unwrap_or(0.0) + add_work;
                    if let Some(o) = prev.as_object_mut() {
                        o.insert("share_count".into(), serde_json::json!(new_count));
                        o.insert("total_work".into(), serde_json::json!(new_work));
                    }
                }
            }
        }
    }

    let mut best: Vec<_> = best_by_miner.into_values().collect();
    best.sort_by(|a, b| {
        str_of(a, "share_hash")
            .unwrap_or("")
            .cmp(str_of(b, "share_hash").unwrap_or(""))
    });
    best.truncate(limit);

    let mut shares: Vec<_> = shares_by_miner.into_values().collect();
    shares.sort_by(|a, b| {
        f64_of(b, "total_work")
            .unwrap_or(0.0)
            .partial_cmp(&f64_of(a, "total_work").unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    shares.truncate(limit);

    out.best_hash = best;
    out.shares = shares;
    out
}

// ───────────────────────── pool/next_payout ─────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct PayoutMerged {
    /// Consensus-wide split values, taken from the first node that answered.
    pub base: serde_json::Value,
    /// Dust-filtered, merged, re-ranked miner list.
    pub miners: Vec<serde_json::Value>,
    pub total_work: f64,
    /// Every unpaid ledger entry across nodes (a miner on N nodes counts N times).
    pub total_on_ledger: u64,
    /// Distinct miners carrying unpaid shares, counted BEFORE the dust filter.
    ///
    /// This is the "on the ledger" figure, and it is deliberately not `total_on_ledger`: a miner
    /// active on three nodes is three ledger rows but one miner. The page contrasts it with the
    /// dust-filtered count to show how many miners actually make it into the next coinbase.
    pub unique_miners: usize,
    pub ok_nodes: usize,
    pub total_nodes: usize,
}

pub fn merge_payout(responses: &[(String, Option<serde_json::Value>)]) -> Option<PayoutMerged> {
    let mut out = PayoutMerged {
        total_nodes: responses.len(),
        ..Default::default()
    };
    let mut base: Option<serde_json::Value> = None;
    let mut by_miner: BTreeMap<String, f64> = BTreeMap::new();

    for (_, resp) in responses {
        let Some(v) = resp.as_ref().filter(|v| usable(v)) else {
            continue;
        };
        out.ok_nodes += 1;
        if base.is_none() {
            base = Some(v.clone());
        }
        out.total_on_ledger += u64_of(v, "total_unpaid_miners").unwrap_or(0);
        for row in v
            .get("miners")
            .and_then(|a| a.as_array())
            .into_iter()
            .flatten()
        {
            let Some(miner) = str_of(row, "miner_id_redacted") else {
                continue;
            };
            *by_miner.entry(miner.to_string()).or_insert(0.0) +=
                f64_of(row, "unpaid_work").unwrap_or(0.0);
        }
    }

    // Every fetch failed this cycle — signal that, so the caller keeps what it already had rather
    // than painting an empty payout table.
    let base = base?;

    let miner_pool = f64_of(&base, "miner_pool_sats").unwrap_or(0.0);
    let dust = f64_of(&base, "dust_threshold_sats").unwrap_or(546.0);
    let cap = u64_of(&base, "ledger_cap").unwrap_or(1000) as usize;

    out.unique_miners = by_miner.len();
    let mut miners: Vec<(String, f64)> = by_miner.into_iter().collect();
    miners.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Re-filter against the MERGED totals. Each node already dust-filtered against its own total,
    // but merging changes the denominator, so a miner can cross the dust line either way. Iterate,
    // because removing a duster raises everyone else's share and can pull the next one over.
    for _ in 0..10 {
        let total: f64 = miners.iter().map(|(_, w)| *w).sum();
        if total <= 0.0 {
            break;
        }
        let before = miners.len();
        miners.retain(|(_, w)| (miner_pool * w / total).floor() >= dust);
        if miners.len() == before {
            break;
        }
    }
    miners.truncate(cap);

    out.total_work = miners.iter().map(|(_, w)| *w).sum();
    let total = out.total_work;
    out.miners = miners
        .into_iter()
        .enumerate()
        .map(|(i, (miner, work))| {
            let pct = if total > 0.0 { work / total * 100.0 } else { 0.0 };
            serde_json::json!({
                "rank": i + 1,
                "miner_id_redacted": miner,
                "unpaid_work": work,
                "share_pct": pct,
                "projected_sats": if total > 0.0 { (miner_pool * work / total).floor() } else { 0.0 },
            })
        })
        .collect();
    out.base = base;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok(id: &str, v: serde_json::Value) -> (String, Option<serde_json::Value>) {
        (id.to_string(), Some(v))
    }
    fn down(id: &str) -> (String, Option<serde_json::Value>) {
        (id.to_string(), None)
    }

    // ── status ──

    #[test]
    fn mesh_hashrate_is_max_not_sum() {
        // Every node reports the same mesh-wide figure. Summing was the "sometimes 8x" bug.
        let r = merge_status(&[
            ok(
                "vm1",
                json!({"total_hashrate": 115.9, "mesh_active_miners": 4}),
            ),
            ok(
                "vm2",
                json!({"total_hashrate": 115.9, "mesh_active_miners": 4}),
            ),
            ok(
                "vm3",
                json!({"total_hashrate": 115.9, "mesh_active_miners": 4}),
            ),
        ]);
        assert_eq!(
            r.hashrate_th, 115.9,
            "mesh hashrate must not be multiplied by responder count"
        );
        assert_eq!(r.miners, 4, "mesh miner count is a max, not a sum");
        assert_eq!(r.ok_nodes, 3);
    }

    #[test]
    fn falls_back_to_summed_local_hashrate_when_no_mesh_figure() {
        let r = merge_status(&[
            ok("vm1", json!({"local_hashrate_th": 2.0})),
            ok("vm2", json!({"local_hashrate_th": 3.0})),
        ]);
        assert_eq!(
            r.hashrate_th, 5.0,
            "pre-PR#27 fallback sums the per-node figure"
        );
    }

    #[test]
    fn blocks_found_sums_but_height_maxes() {
        let r = merge_status(&[
            ok("vm1", json!({"blocks_found": 1, "block_height": 963155})),
            ok("vm2", json!({"blocks_found": 2, "block_height": 963158})),
        ]);
        assert_eq!(
            r.blocks_found, 3,
            "blocks_found is a genuine per-node counter"
        );
        assert_eq!(
            r.block_height, 963158,
            "height is a max — nodes lag each other"
        );
    }

    #[test]
    fn a_down_node_does_not_drag_the_totals_down() {
        let r = merge_status(&[ok("vm1", json!({"total_hashrate": 115.9})), down("vm2")]);
        assert_eq!(r.hashrate_th, 115.9);
        assert_eq!(r.ok_nodes, 1);
        assert_eq!(
            r.total_nodes, 2,
            "the caller can see it was a partial answer"
        );
    }

    #[test]
    fn a_200_carrying_an_error_field_is_not_a_usable_response() {
        // The pool API answers `{"error": "Database not available"}` with HTTP 200.
        assert!(!usable(&json!({"error": "Database not available"})));
        assert!(usable(&json!({"shares": []})));
        let r = merge_status(&[ok("vm1", json!({"error": "Database not available"}))]);
        assert_eq!(
            r.ok_nodes, 0,
            "an error body must not count as a healthy node"
        );
    }

    // ── records ──

    #[test]
    fn rarest_record_wins_across_nodes() {
        let best = merge_records(&[
            ok("vm1", json!({"found": true, "best": {"share_hash": "0000000000000005aa", "timestamp": 1}})),
            ok("vm2", json!({"found": true, "best": {"share_hash": "0000000000000001bb", "timestamp": 2}})),
            ok("vm3", json!({"found": false})),
        ])
        .expect("some node had a record");
        assert_eq!(
            best["share_hash"], "0000000000000001bb",
            "lowest display-order hash is rarest"
        );
    }

    #[test]
    fn latch_keeps_a_still_valid_record_when_the_fresh_one_is_worse() {
        // The node holding the record was slow this cycle; the fan-out returned a worse value.
        let cached = json!({"share_hash": "0000000000000001bb", "timestamp": 1_000_000});
        let fresh = Some(json!({"share_hash": "0000000000000009ff", "timestamp": 1_000_500}));
        let out = latch_record("day", Some(&cached), fresh, 1_000_600).expect("latched");
        assert_eq!(
            out["share_hash"], "0000000000000001bb",
            "a worse fresh value must not clobber a valid record"
        );
    }

    #[test]
    fn latch_keeps_the_record_when_the_fresh_fetch_failed_entirely() {
        let cached = json!({"share_hash": "0000000000000001bb", "timestamp": 1_000_000});
        let out = latch_record("day", Some(&cached), None, 1_000_600).expect("latched");
        assert_eq!(out["share_hash"], "0000000000000001bb");
    }

    #[test]
    fn latch_releases_once_the_cached_record_ages_out_of_its_window() {
        let cached = json!({"share_hash": "0000000000000001bb", "timestamp": 1_000_000});
        let fresh = Some(json!({"share_hash": "0000000000000009ff", "timestamp": 1_086_000}));
        // day window is 86_400s; the cached record is now older than that.
        let out = latch_record("day", Some(&cached), fresh, 1_000_000 + 86_401).expect("fresh");
        assert_eq!(
            out["share_hash"], "0000000000000009ff",
            "an aged-out record must yield to fresh data"
        );
    }

    #[test]
    fn a_better_fresh_record_replaces_the_cached_one() {
        let cached = json!({"share_hash": "0000000000000009ff", "timestamp": 1_000_000});
        let fresh = Some(json!({"share_hash": "0000000000000001bb", "timestamp": 1_000_500}));
        let out = latch_record("day", Some(&cached), fresh, 1_000_600).expect("fresh");
        assert_eq!(out["share_hash"], "0000000000000001bb");
    }

    #[test]
    fn monotonicity_propagates_a_narrow_record_outward() {
        // "last week better than last month" is arithmetically impossible; it reads as a bug.
        let mut recs: BTreeMap<String, Option<serde_json::Value>> = BTreeMap::new();
        recs.insert("block".into(), None);
        recs.insert("day".into(), None);
        recs.insert(
            "week".into(),
            Some(json!({"share_hash": "0000000000000001bb"})),
        );
        recs.insert(
            "month".into(),
            Some(json!({"share_hash": "0000000000000009ff"})),
        );
        enforce_monotonicity(&mut recs);
        assert_eq!(
            recs["month"].as_ref().unwrap()["share_hash"],
            "0000000000000001bb",
            "month must inherit week's better record"
        );
    }

    #[test]
    fn monotonicity_fills_an_empty_wider_window() {
        let mut recs: BTreeMap<String, Option<serde_json::Value>> = BTreeMap::new();
        recs.insert("block".into(), None);
        recs.insert(
            "day".into(),
            Some(json!({"share_hash": "0000000000000003cc"})),
        );
        recs.insert("week".into(), None);
        recs.insert("month".into(), None);
        enforce_monotonicity(&mut recs);
        assert_eq!(
            recs["week"].as_ref().unwrap()["share_hash"],
            "0000000000000003cc"
        );
        assert_eq!(
            recs["month"].as_ref().unwrap()["share_hash"],
            "0000000000000003cc",
            "propagation carries through successive windows in one pass"
        );
    }

    #[test]
    fn monotonicity_leaves_an_already_better_wider_window_alone() {
        let mut recs: BTreeMap<String, Option<serde_json::Value>> = BTreeMap::new();
        recs.insert("block".into(), None);
        recs.insert(
            "day".into(),
            Some(json!({"share_hash": "0000000000000009ff"})),
        );
        recs.insert(
            "week".into(),
            Some(json!({"share_hash": "0000000000000001bb"})),
        );
        recs.insert(
            "month".into(),
            Some(json!({"share_hash": "0000000000000001bb"})),
        );
        enforce_monotonicity(&mut recs);
        assert_eq!(
            recs["week"].as_ref().unwrap()["share_hash"],
            "0000000000000001bb"
        );
    }

    // ── leaderboard ──

    #[test]
    fn leaderboard_sums_shares_per_miner_across_nodes() {
        let r = merge_leaderboard(
            &[
                ok(
                    "vm1",
                    json!({"best_hash": [], "shares": [{"miner_id_redacted": "bc1q7z…y492", "share_count": 10, "total_work": 100.0}]}),
                ),
                ok(
                    "vm2",
                    json!({"best_hash": [], "shares": [{"miner_id_redacted": "bc1q7z…y492", "share_count": 5, "total_work": 50.0}]}),
                ),
            ],
            10,
        );
        assert_eq!(r.shares.len(), 1, "the same miner on two nodes is one row");
        assert_eq!(r.shares[0]["share_count"], 15);
        assert_eq!(r.shares[0]["total_work"], 150.0);
    }

    #[test]
    fn leaderboard_keeps_only_the_rarest_hash_per_miner_and_sorts_by_rarity() {
        let r = merge_leaderboard(
            &[
                ok(
                    "vm1",
                    json!({"best_hash": [{"miner_id_redacted": "a", "share_hash": "0000ff"}], "shares": []}),
                ),
                ok(
                    "vm2",
                    json!({"best_hash": [{"miner_id_redacted": "a", "share_hash": "000011"}], "shares": []}),
                ),
                ok(
                    "vm3",
                    json!({"best_hash": [{"miner_id_redacted": "b", "share_hash": "000005"}], "shares": []}),
                ),
            ],
            10,
        );
        assert_eq!(r.best_hash.len(), 2, "one row per miner");
        assert_eq!(r.best_hash[0]["miner_id_redacted"], "b", "rarest first");
        assert_eq!(
            r.best_hash[1]["share_hash"], "000011",
            "miner a keeps its rarer hash"
        );
    }

    #[test]
    fn leaderboard_shares_sort_by_work_descending_and_respect_the_limit() {
        let r = merge_leaderboard(
            &[ok(
                "vm1",
                json!({"best_hash": [], "shares": [
                    {"miner_id_redacted": "small", "share_count": 1, "total_work": 1.0},
                    {"miner_id_redacted": "big", "share_count": 1, "total_work": 900.0},
                    {"miner_id_redacted": "mid", "share_count": 1, "total_work": 50.0}
                ]}),
            )],
            2,
        );
        assert_eq!(r.shares.len(), 2);
        assert_eq!(r.shares[0]["miner_id_redacted"], "big");
        assert_eq!(r.shares[1]["miner_id_redacted"], "mid");
    }

    // ── payout ──

    #[test]
    fn payout_merges_unpaid_work_and_reranks() {
        let base = json!({
            "miner_pool_sats": 309_375_000, "dust_threshold_sats": 546, "ledger_cap": 1000,
            "total_unpaid_miners": 2
        });
        let mut a = base.clone();
        a["miners"] = json!([{"miner_id_redacted": "x", "unpaid_work": 100.0}]);
        let mut b = base.clone();
        b["miners"] = json!([{"miner_id_redacted": "x", "unpaid_work": 50.0}, {"miner_id_redacted": "y", "unpaid_work": 900.0}]);

        let r = merge_payout(&[ok("vm1", a), ok("vm2", b)]).expect("a node answered");
        assert_eq!(r.miners.len(), 2);
        assert_eq!(
            r.miners[0]["miner_id_redacted"], "y",
            "ranked by merged work"
        );
        assert_eq!(
            r.miners[1]["unpaid_work"], 150.0,
            "x's work summed across both nodes"
        );
        assert_eq!(r.miners[0]["rank"], 1);
        assert_eq!(r.total_work, 1050.0);
        assert_eq!(r.total_on_ledger, 4, "ledger entries sum across nodes");
        assert_eq!(
            r.unique_miners, 2,
            "x appears on both nodes but is one miner"
        );
    }

    #[test]
    fn payout_dust_filter_removes_miners_below_the_threshold() {
        // duster's share of the pool floors below 546 sats, so it cannot appear in the coinbase.
        let v = json!({
            "miner_pool_sats": 1_000_000, "dust_threshold_sats": 546, "ledger_cap": 1000,
            "total_unpaid_miners": 2,
            "miners": [
                {"miner_id_redacted": "whale", "unpaid_work": 1_000_000.0},
                {"miner_id_redacted": "duster", "unpaid_work": 1.0}
            ]
        });
        let r = merge_payout(&[ok("vm1", v)]).expect("answered");
        let ids: Vec<_> = r
            .miners
            .iter()
            .map(|m| m["miner_id_redacted"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            vec!["whale"],
            "the dust entry is filtered against the merged total"
        );
        assert_eq!(
            r.unique_miners, 2,
            "the ledger count is taken before dust filtering"
        );
    }

    #[test]
    fn payout_returns_none_when_every_node_failed() {
        // The caller must be able to tell "everything failed" from "nobody is owed anything",
        // so it can keep the previous view instead of painting an empty table.
        assert!(merge_payout(&[down("vm1"), down("vm2")]).is_none());
    }

    #[test]
    fn payout_share_pct_sums_to_one_hundred() {
        let v = json!({
            "miner_pool_sats": 1_000_000_000u64, "dust_threshold_sats": 546, "ledger_cap": 1000,
            "miners": [
                {"miner_id_redacted": "a", "unpaid_work": 300.0},
                {"miner_id_redacted": "b", "unpaid_work": 100.0}
            ]
        });
        let r = merge_payout(&[ok("vm1", v)]).expect("answered");
        let total: f64 = r
            .miners
            .iter()
            .map(|m| m["share_pct"].as_f64().unwrap())
            .sum();
        assert!(
            (total - 100.0).abs() < 1e-9,
            "percentages are of the merged total, got {total}"
        );
    }
}
