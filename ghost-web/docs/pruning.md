# Pruning

*Time-based data retention. The node trims old share rows, expired L2 reservations, and stale snapshot state on a rolling window so a Ghost node doesn't grow unbounded over years of uptime, while keeping enough history for verification, dispute resolution, and audit.*

## The problem

A Ghost node accumulates several kinds of historical data:

- **Share submissions** from every miner who pointed at the pool. Even moderate hashrate produces tens of thousands per day.
- **Verification challenge results** from the capability scoring system that probes peers every five minutes.
- **Round summaries** — one per block found, plus the per-miner share distribution.
- **L2 state** — Ghost Pay's snapshots, valid roots, and pending reservations.

If a node retained all of this in full detail forever, even a quiet operator would burn through a 1 TB SSD inside a year. If a node retained nothing past today, dispute resolution, capability scoring, and auditability would all fail. The right answer is bounded retention: keep the data while it's actionable, drop it once it isn't.

## The retention model

Ghost-pool's retention is **time-based, not block-based**. The pruning entry points take a number of seconds (or a count of items to keep) and remove anything older. There is no "3-window" or "blocks-since-tip" framing in the code — the storage layer doesn't even know the current chain height.

The two numbers that matter:

- **Share retention window** — passed to `delete_old_shares(retention_secs)` in seconds, with a hard 1-hour minimum guard. The default the operator binary uses is set in `pool.toml`.
- **Verification lookback** — the qualification provider scores capabilities over a **trailing 7-day window** (`lookback_days * SECONDS_PER_DAY`, ≈ 604 800 s).

Everything else is either bounded by item count (snapshots, valid roots) or by an absolute expiry timestamp (L2 reservations).

## Share pruning

`Database::delete_old_shares(retention_secs)` runs in two passes:

1. **Paid shares.** Any row in `shares` with `paid_in_proposal_hash IS NOT NULL` and `timestamp < now - retention_secs` is deleted. Once a share has been paid out, the row is just an audit tail; one retention window is enough.
2. **Unpaid shares from inactive miners.** Rows where `paid_in_proposal_hash IS NULL` are normally kept indefinitely so an active miner never loses unpaid work. The exception: if the miner's `last_seen` in the `miners` table is older than 7 days, their unpaid shares are dropped (they're picked up via the disappearance pool so they don't sit on the ledger forever). **Unpaid shares from active miners are never deleted by this pass**, regardless of age.

The 1-hour minimum on `retention_secs` is a safety guard — passing `0` would otherwise wipe the recent share log on the next prune tick. The retention is enforced via the `idx_shares_timestamp` index for an O(log n) range delete.

## Verification challenge pass-rate window

Capability qualification reads from the `archive_challenges`, `policy_challenges`, `stratum_challenges`, and `ghostpay_challenges` tables. The qualification provider computes:

```rust
fn lookback_timestamp(&self) -> i64 {
    chrono::Utc::now().timestamp()
        - (self.config.lookback_days as i64 * SECONDS_PER_DAY)
}
```

with `lookback_days = 7` by default. A node qualifies for a capability if, over those 7 days, it has at least the minimum number of challenges (typically 10) from the minimum number of unique challengers and meets the per-capability pass-rate threshold (95 % most capabilities, 90 % for GhostPay).

Seven days is the window because:

- It's long enough that 7 × ~50 challenges/day = ~350 samples, statistically meaningful.
- It's short enough that a node which has been clean for the last week qualifies, even if it had outages months ago.
- The uptime gatekeeper (`check_uptime_gatekeeper`) uses the same 7-day lookback for the 95 % uptime requirement, so both checks share a consistent window.

Old rows past the 7-day window are not currently deleted by a dedicated job; they accumulate but the qualification query filters on `timestamp >= lookback_timestamp` so they don't affect scoring. Operators who want to bound disk growth should run a manual `DELETE FROM <capability>_challenges WHERE timestamp < ?` periodically — there's no `delete_old_challenges` helper in the storage crate.

## L2 (Ghost Pay) pruning

Ghost Pay-running nodes have their own pruning helpers, all in `crates/ghost-storage/src/queries.rs`:

| Function | What it prunes | Retention bound |
|---|---|---|
| `prune_l2_snapshots(keep_count)` | Old L2 state snapshots | Keeps the most recent `keep_count` snapshots; older rows deleted |
| `prune_expired_reservations(now_millis)` | Pending L2 reservations whose absolute expiry has passed | Anything with `expires_at < now` |
| `prune_l2_valid_roots(keep_count)` | Historical valid-root entries | Keeps the most recent `keep_count` roots |

These are bounded by item count or absolute expiry, not by a duration sliding window — the policy that governs *when* and *with what arguments* they're called is set by the binary, not by the storage crate.

## Vacuum

There's no scheduled `VACUUM` cadence in the code. SQLite's standard incremental-vacuum behaviour (when enabled in the database) reclaims pages as rows are deleted; manual `VACUUM` is up to the operator during a maintenance window.

## What pruning isn't

- **It isn't Bitcoin Core's `-prune`.** Bitcoin Core's prune deletes old `blk*.dat` files entirely; a pruned node can't serve any old block. Ghost-pool pruning operates on its own SQLite tables — share data, verification challenges, L2 state. Block data lives separately and is governed by the haze_mode / archive settings (see [Haze](#haze) and [Exorcism](#exorcism)).
- **It isn't reversible.** Pruned share rows are gone. Export and archive externally if you need long-term forensics.
- **It isn't a guarantee of disk usage.** Storage growth depends on activity — share submissions, blocks found, challenges issued. The defaults keep a typical operator at single-digit GBs; a busy pool with verbose challenge history could be 10× that.
- **It isn't a privacy tool.** Pruning is operational, not adversarial. It reduces the amount of historical data on disk, but it doesn't actively scrub anything that was already extracted.
- **It isn't synchronised across the mesh.** Each node prunes its own database according to its own clock and config. Two nodes in the same mesh might keep different amounts of history. The consensus layer doesn't depend on uniform retention; nodes only need their own local view to be correct.

## Where pruning sits

| Layer | What it manages | Doc |
|---|---|---|
| Block-level data | `blk*.dat` / `gsb*.dat`, full archive vs hazed | [Haze](#haze), [Exorcism](#exorcism) |
| **Operational logs** | **Shares, verification challenges, L2 snapshots/reservations** | **this doc** |
| Mesh peer state | Recent peer messages, vote history | Held in RAM, expired on a much shorter window |

Block data and operational data are pruned by different rules because they have different value: blocks are network duty, operational logs are local accounting. Confusing the two leads either to losing data the operator needs or hoarding data nobody benefits from.

## Source

| File | Purpose |
|---|---|
| `crates/ghost-storage/src/migrations.rs` | Table definitions: `shares`, `rounds`, `payouts`, `archive_challenges`, `policy_challenges`, `stratum_challenges`, `ghostpay_challenges`, `verifications` |
| `crates/ghost-storage/src/queries.rs` | `delete_old_shares` (1-hour minimum guard), `prune_l2_snapshots`, `prune_expired_reservations`, `prune_l2_valid_roots` |
| `crates/ghost-verification/src/qualification.rs` | 7-day verification lookback window, capability pass-rate calculation |
