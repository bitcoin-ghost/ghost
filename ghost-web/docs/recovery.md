# Recovery

*What to do when a Ghost node breaks. Each scenario is detection, impact, and the specific commands that get the node back. No vague "investigate further" — concrete steps.*

## How to read this page

Each section is a runbook for one failure mode. Sections start with **Impact**: what happens to the network if you do nothing. Then **Detect**: how to confirm you're in this scenario. Then **Recover**: the commands.

The mesh is BFT-tolerant: it survives one node going down without operator intervention. Most of these procedures are about specific harder cases — multi-node loss, database corruption, MPC parameter loss.

## 1. Single elder offline

**Impact:** Minimal. BFT consensus needs 67% (so 3 of 4 in the standard cluster). Payouts, voting, and L2 checkpoints continue.

**Detect:**

```bash
sqlite3 /home/ghost/.ghost/ghost.db \
  "SELECT peer_id, last_seen, datetime(last_seen,'unixepoch') AS last_seen_utc
   FROM nodes ORDER BY last_seen DESC"
```

A peer with `last_seen` more than 60 seconds old isn't pinging the mesh. More than an hour old, the elder is offline.

**Recover (VM is recoverable):**

```bash
sudo systemctl restart ghost-pool
sudo systemctl restart ghost-pay
journalctl -u ghost-pool -f --since "1 min ago" | grep -i "peer\|connect"
```

Watch for "connected to peer" lines. If they appear, the node has rejoined the mesh.

**If the elder is offline >24 hours:** investigate hardware/network. If permanent loss, see scenario 2 (replacement).

## 2. Two elders offline simultaneously

**Impact:** BFT halts. 2/4 = 50% < 67%. Payouts pause. L2 checkpoints pause. Mining continues but shares accumulate without payout. Network is **safe** — no conflicting decisions can land — but stalled.

**Detect:**

- Repeated `VotingSession timed out` in `ghost-pool` logs.
- `get_connected_peers(60)` returns < 3.

**Immediate steps:**

1. Identify which VMs are offline: `systemctl status ghost-pool` on each.
2. Check VM-to-VM connectivity: `ping <other-vm-ip>`, `traceroute`.
3. Check the hosting provider's status page.

**Recover (VMs recoverable):**

```bash
# On each offline VM:
sudo systemctl restart ghost-pool
sudo systemctl restart ghost-pay

# Verify quorum restored:
journalctl -u ghost-pool -f | grep -i "voting\|quorum\|payout"
```

Within ~30 seconds you should see voting sessions completing. Pending payouts will fire on the next confirmed block.

**Recover (VMs unrecoverable, hardware loss):**

```bash
# 1. Provision replacement VM (same OS, same specs)
# 2. Install ghost-pool + ghost-pay binaries (see /docs/#deployment)

# 3. Restore database from backup
sudo systemctl stop ghost-pool ghost-pay
cp /var/backups/ghost/db/ghost-latest.db /home/ghost/.ghost/ghost.db
cp /var/backups/ghost/db/ghost-pay-latest.db \
   /home/ghost/.ghost/ghost-pay/ghost-pay.db

# 4. Restore MPC params
cp -a /var/backups/ghost/mpc/latest/mpc_params/ /home/ghost/.ghost/mpc_params/

# 5. Verify VK files present (these are versioned with the binary, but
#    the chain of contributions only exists on disk)
ls /home/ghost/.ghost/mpc_params/note_spend_vk.bin
ls /home/ghost/.ghost/mpc_params/payout_vk.bin
ls /home/ghost/.ghost/mpc_params/unshield_vk.bin

# 6. Update /etc/ghost/pool.toml: confirm node_id key matches the
#    one in the restored DB. The seed_nodes list should still be valid.

# 7. Start services
sudo systemctl start ghost-pool ghost-pay
journalctl -u ghost-pool -f | grep -i "peer\|connect\|elder"
```

The replacement node uses the same node_id as the lost one, so its Elder slot is preserved. The mesh discovery protocol reconnects it within ~60 seconds.

## 3. Genesis node permanent loss

**Impact:** None ongoing. The genesis node has no special role after the MPC ceremony completed. All elders are equal peers thereafter.

**Recover:** follow scenario 2's hardware-loss procedure.

**Critical:** do **NOT** use the `--genesis` flag on the replacement node. Genesis flag is one-time, used only for the original ceremony bootstrap. A second genesis would create a second MPC chain that diverges from the rest of the mesh.

If no DB backup exists, the replacement can be rebuilt from scratch but it'll need MPC params from a peer (which the peer will share via the mesh sync protocol once the replacement's identity is added to the seed-node list of at least one operating peer).

## 4. Database corruption

The most common recovery scenario. SQLite + WAL mode is robust, but ungraceful shutdowns (power loss, OOM kill) sometimes leave corrupted state.

**Detect:**

```bash
sudo systemctl stop ghost-pool
sqlite3 /home/ghost/.ghost/ghost.db "PRAGMA integrity_check"
```

Healthy output: `ok`. Anything else is corruption.

**Recover (most common — WAL is intact):**

```bash
# Snapshot the DB triple (main, WAL, SHM)
cp /home/ghost/.ghost/ghost.db     /tmp/ghost-recovery.db
cp /home/ghost/.ghost/ghost.db-wal /tmp/ghost-recovery.db-wal
cp /home/ghost/.ghost/ghost.db-shm /tmp/ghost-recovery.db-shm

# Force WAL checkpoint into main DB
sqlite3 /tmp/ghost-recovery.db "PRAGMA wal_checkpoint(TRUNCATE)"

# Re-verify
sqlite3 /tmp/ghost-recovery.db "PRAGMA integrity_check"

# If integrity passes, swap in the recovered DB
sudo systemctl stop ghost-pool
cp /tmp/ghost-recovery.db /home/ghost/.ghost/ghost.db
rm -f /home/ghost/.ghost/ghost.db-wal /home/ghost/.ghost/ghost.db-shm
sudo systemctl start ghost-pool
```

In the WAL-recovery flow, no data is lost — the WAL just hadn't been checkpointed when the corruption surfaced.

**Recover (WAL also corrupt):**

```bash
sudo systemctl stop ghost-pool ghost-pay
cp /var/backups/ghost/db/ghost-YYYYMMDDHHMM.db /home/ghost/.ghost/ghost.db
rm -f /home/ghost/.ghost/ghost.db-wal /home/ghost/.ghost/ghost.db-shm
sudo systemctl start ghost-pool
```

**State re-sync after backup restore:**

| Table | Re-syncs from | Notes |
|---|---|---|
| `nodes` | Mesh health pings | Automatic, ~10 s per peer |
| `mpc_params/` | Local backup or peer | The directory must be intact |
| `l2_notes` | L2 checkpoint broadcasts | Re-syncs from peers' L2 state |
| `shares` | — | Shares between backup and corruption are **lost**; payouts for that period unrecoverable |

The same procedure applies to `ghost-pay.db`, just with substituted paths.

## 5. MPC parameter loss across all nodes

**Impact:** **Critical.** Every ZK verification fails. Existing L2 notes become unspendable. Forces a full ceremony reset.

**This is a last-resort scenario.** Try every backup before this — local, off-box, peer-shared.

**Reset procedure (every node):**

```bash
sudo systemctl stop ghost-pool ghost-pay

sqlite3 /home/ghost/.ghost/ghost.db "DELETE FROM mpc_contributions"
rm -rf /home/ghost/.ghost/mpc_params/

# L2 notes become unspendable on the new params; clear them
sqlite3 /home/ghost/.ghost/ghost.db "DELETE FROM l2_notes"
sqlite3 /home/ghost/.ghost/ghost.db "DELETE FROM pending_nullifiers"
sqlite3 /home/ghost/.ghost/ghost.db "PRAGMA wal_checkpoint(TRUNCATE)"
```

**Re-bootstrap (one node only — pick the genesis):**

```bash
ghost-pool --genesis
```

**Re-bootstrap (every other node, no `--genesis`):**

```bash
ghost-pool
```

The other nodes discover the new genesis via `seed_nodes` and begin contributing to a fresh ceremony chain. After 101 contributions (or whatever cap is set), the new params ossify.

**Post-recovery:**

- Verify all three VK files present on every node:
  ```bash
  for f in note_spend_vk.bin payout_vk.bin unshield_vk.bin; do
    ls -la /home/ghost/.ghost/mpc_params/$f
  done
  ```
- Run `backup-mpc-params.sh` on every node **immediately**.
- L2 users must re-shield funds — old notes are permanently lost. This is unavoidable when MPC params change.

The blast radius of this scenario is the reason MPC backups should be the most paranoid thing in the operator's backup posture. Multiple geographical copies, off-box, encrypted.

## 6. Network partition

**Impact:** Both sides of the partition see voting timeouts. BFT ensures **safety** — neither side can finalise a payout without the other's votes — but liveness is impaired. Mining continues; shares accumulate; payouts pause until partition heals.

**Detect:**

```bash
# Count voting timeouts in the last 30 min
journalctl -u ghost-pool --since "30 min ago" | grep -c "VotingSession timed out"

# Check connected peer count (should be 3 in a 4-node cluster)
journalctl -u ghost-pool --since "1 min ago" | grep "connected_peers"
```

**Recover (short partition <1 h):**

No action. Discovery protocol auto-reconnects peers when network heals. Voting resumes automatically.

**Recover (persistent partition):**

1. Confirm connectivity: `ping`, `traceroute` between VMs.
2. Confirm firewall: P2P ports (8555-8563) open inbound on each VM.
3. Confirm hosting-provider network status.
4. If one side has 3+ nodes, that side continues normal operation; the isolated minority accumulates shares but cannot participate in payouts.

**Verify post-heal:**

```bash
sqlite3 /home/ghost/.ghost/ghost.db \
  "SELECT peer_id, datetime(last_seen,'unixepoch') AS last_seen_utc
   FROM nodes WHERE last_seen > unixepoch() - 60"
```

All peers should appear with `last_seen` in the last minute.

## 7. Stuck Wraith session

**Impact:** Session participants' funds are locked in the mixing output. Privacy story is preserved; recovery is the operator's job.

**Detect:**

- ghost-pay logs: session started but no completion after the configured timeout.
- User reports: "my Wraith deposit is stuck".

**Diagnose:**

```bash
sqlite3 /home/ghost/.ghost/ghost-pay/ghost-pay.db \
  "SELECT session_id, status, created_at, participant_count
   FROM wraith_sessions
   WHERE status NOT IN ('completed', 'failed')
   ORDER BY created_at DESC"
```

**Recover:**

1. Identify the funding UTXO:

   ```bash
   sqlite3 /home/ghost/.ghost/ghost-pay/ghost-pay.db \
     "SELECT funding_txid, funding_vout, amount_sats
      FROM wraith_session_inputs
      WHERE session_id = '<SESSION_ID>'"
   ```

2. Check if it's still unspent on chain:

   ```bash
   ghost-cli gettxout <TXID> <VOUT>
   ```

3. If unspent, the session coordinator constructs a recovery transaction spending the funding UTXO back to participants using the known session keys. The ghost-pay binary exposes a `wraith recover --session-id <ID>` subcommand that builds and broadcasts the refund transaction; run it on the coordinator node (or any elder with read access to the same `ghost-pay.db`).

4. If the coordinator was on the crashed node, any other elder with access to the session DB can take over recovery.

5. Mark the session failed:

   ```bash
   sqlite3 /home/ghost/.ghost/ghost-pay/ghost-pay.db \
     "UPDATE wraith_sessions SET status='failed' WHERE session_id='<SESSION_ID>'"
   ```

**Prevention:**

- ghost-pay's graceful shutdown now includes `db.checkpoint()` to flush WAL.
- Session timeout auto-fails sessions that don't complete within the configured window.

## Backup posture (do this before you need it)

| What | Script | Schedule | Retention |
|---|---|---|---|
| `ghost.db` + `ghost-pay.db` | `backup-databases.sh` | Daily 03:00 UTC | 7 days local + offsite |
| MPC params + VK files | `backup-mpc-params.sh` | After ceremony, on demand | 3 copies, geographically separated |
| Node identity (`node.key`) | manual | Once at creation | Multiple secure locations |
| Noise keypair (`noise.key`) | manual | Once at creation | Same as node.key |

The MPC backup is the one that matters most. Lose every node's MPC params at once and you've gone from "hardware failure" to "ceremony reset" — the worst recovery scenario in this runbook.

## Quick reference

```bash
# Health snapshot
sqlite3 /home/ghost/.ghost/ghost.db \
  "SELECT peer_id,last_seen FROM nodes ORDER BY last_seen DESC"

# DB integrity
sqlite3 /home/ghost/.ghost/ghost.db "PRAGMA integrity_check"

# Force WAL checkpoint
sqlite3 /home/ghost/.ghost/ghost.db "PRAGMA wal_checkpoint(TRUNCATE)"

# Recent logs
journalctl -u ghost-pool -f --since "5 min ago"
journalctl -u ghost-pay  -f --since "5 min ago"

# Service control
sudo systemctl restart ghost-pool
sudo systemctl restart ghost-pay

# Manual backup
sudo -u ghost /opt/ghost/scripts/backup-databases.sh
```

## What this runbook isn't

- **It isn't an SRE incident-management process.** No paging policies, no escalation tiers, no incident-channel templates. Operators run those at their own organisational level.
- **It isn't exhaustive.** New failure modes the network actually hits get folded into operator-facing notes as they occur.
- **It doesn't replace prevention.** Most of the bad scenarios above are caused by skipping backup discipline. The recovery procedures exist; relying on them is more painful than running the backups.
- **It isn't a disaster-recovery plan.** A truly catastrophic event — geo-correlated outage, jurisdiction-level seizure — is outside this scope. Operators have to plan that themselves; the protocol is robust to single-VM and single-region failures, not to coordinated hostile action against the entire mesh.

## Source

| File | Purpose |
|---|---|
| `bins/ghost-pool/src/main.rs` | Service lifecycle, restart-safe shutdown |
| `crates/ghost-storage/src/migrations.rs` | Schema migrations on startup |
| `crates/ghost-mpc/src/manager.rs` | MPC contribution + recovery flows |
| `scripts/backup-databases.sh` | Database backup helper |
| `scripts/backup-mpc-params.sh` | MPC params backup helper |
