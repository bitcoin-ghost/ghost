# ghost-stats — public pool-stats aggregator

Serves one merged snapshot of pool statistics to `pool.html`, replacing a per-viewer fan-out to all
eight nodes.

## Why

The public pool page was its own aggregator. Every browser asked all eight nodes for status,
records, leaderboard and payout and merged the results itself — **56 requests on a single page load,
~145 per minute thereafter, per viewer**. Cost scaled with the number of people watching rather than
with the data, and several of the underlying queries take seconds:

| Endpoint | Measured (2026-08-19, cache bypassed) |
|---|---|
| `mining/status` | 0.16 s |
| `pool/next_payout` | 0.15 s |
| `pool/records?window=day` | 0.06 s |
| `pool/records?window=week` | 0.43 s |
| `pool/records?window=month` | **7–20 s** (504s at the proxy) |
| `pool/leaderboard?window=lifetime` | 0.16 s |
| `pool/leaderboard?window=day` | **6.65 s** |
| `pool/leaderboard?window=week` / `month` | **>10 s** (504) |

Ranking by rarity means `reverse_hex(share_hash)` over every row in the window — a function of the
column, so no index can serve the `ORDER BY`. These queries do not get cheap; they get run less
often.

After: **1 request per viewer per minute**, answered from memory in ~2 ms.

## The three rules it enforces

1. **Never serve nothing.** A section is replaced only by a *successful* refresh. A failed cycle
   leaves the previous answer standing, and the snapshot is mirrored to disk so a restart serves a
   warm page. Verified: 400 ms after a cold restart it served a fully populated snapshot in 2.4 ms.
2. **Pace each query to its own cost.** One task per query, each on its own cadence, so a 20 s
   monthly scan cannot delay a 60 ms one.
3. **Say how old it is.** Every section reports `age_secs` and `ok_nodes`/`total_nodes`.

## Deploying

`cargo` is not installed on the web host, so the binary is cross-built locally and shipped. Building
on Ubuntu 22.04 (glibc 2.35) for the host's 24.04 (glibc 2.39) is fine — glibc is backward
compatible.

```bash
# 1. Build
cargo build --release -p ghost-stats -j2          # -j2: WSL2 OOM-kills cc1plus above that

# 2. Ship the binary, atomically
scp target/release/ghost-stats ghost@83.136.255.218:/tmp/ghost-stats.new
ssh ghost@83.136.255.218 'sudo mv /tmp/ghost-stats.new /opt/ghost/bin/ghost-stats \
  && sudo chown ghost:ghost /opt/ghost/bin/ghost-stats && sudo chmod 755 /opt/ghost/bin/ghost-stats'

# 3. Config and unit
scp config/ghost-stats/stats.toml ghost@83.136.255.218:/tmp/
scp config/ghost-stats/ghost-stats.service ghost@83.136.255.218:/tmp/
ssh ghost@83.136.255.218 'sudo mv /tmp/stats.toml /etc/ghost/stats.toml \
  && sudo mv /tmp/ghost-stats.service /etc/systemd/system/ \
  && sudo systemctl daemon-reload && sudo systemctl enable --now ghost-stats'

# 4. Confirm it is warm BEFORE exposing it
ssh ghost@83.136.255.218 'curl -s localhost:8790/health'      # expect ready:true
```

Then add `nginx-pool-summary.conf`'s location block to the `server { }` block in
`/etc/nginx/sites-enabled/bitcoinghost`, `sudo nginx -t`, `sudo systemctl reload nginx`, and deploy
`ghost-web/pool.html`.

**Order matters:** the page must not be deployed before the endpoint answers, or it will show its
loading state to everyone. Check `/health` reports `ready: true` first.

## Verifying

```bash
curl -s https://bitcoinghost.org/api/pool/summary | jq '{ready, generated_at,
  status: .status.age_secs, records: (.records | keys), lbs: (.leaderboards | keys)}'
```

⚠ `/health` returns 200 even when `ready` is false. That is deliberate: a health check failing
during warm-up would make systemd restart-loop the service and turn a slow start into an outage.
Read the `ready` field, not the status code.
