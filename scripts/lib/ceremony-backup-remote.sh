#!/usr/bin/env bash
#
# Node-side half of `scripts/shard-ceremony-backup.sh`. Piped to `bash -s` over ssh; reads its
# parameters from the environment (GHOST_LABEL, GHOST_STAMP, GHOST_KEEP_RAW) so nothing is
# interpolated into a remote command string.
#
# Runs against a live pool. Prints one line per step and exits non-zero on any failure, having
# removed a copy it could not verify — an unverified file in the backup directory is worse than an
# absent one, because it will be trusted.

set -uo pipefail

DB="/home/ghost/.ghost/ghost.db"
DEST_DIR="/var/backups/ghost/ceremony"
LABEL="${GHOST_LABEL:-ceremony}"
STAMP="${GHOST_STAMP:-manual}"
KEEP_RAW="${GHOST_KEEP_RAW:-0}"

fail() { echo "  FAIL: $*"; exit 2; }

[[ -f "$DB" ]] || fail "no database at $DB"
command -v sqlite3 >/dev/null || fail "sqlite3 is not installed"

sudo mkdir -p "$DEST_DIR" || fail "cannot create $DEST_DIR"

DEST="${DEST_DIR}/ghost-${LABEL}-${STAMP}.db"
[[ -e "$DEST" || -e "${DEST}.gz" ]] && fail "$DEST already exists — refusing to overwrite a backup"

# The copy is written HERE first (ghost-owned, so sqlite3 runs as the user that owns the live
# database) and only then moved into the root-owned backup directory.
STAGE="/home/ghost/.ghost/.ceremony-backup-${STAMP}.db"
cleanup_stage() { sudo rm -f "$STAGE" "${STAGE}-wal" "${STAGE}-shm"; }

# --- headroom -------------------------------------------------------------------------------
# Checked on the filesystem the copy is actually WRITTEN to, not the one it ends up on. Those can
# differ — /var/backups and /home/ghost are separate mounts on some layouts — and measuring the
# wrong one proves nothing about whether a multi-GB copy fits. vm1 runs at 90% of root, where
# exhaustion corrupts settings.json, so this is the check that matters.
#
# If they ARE different mounts the `mv` becomes a cross-device copy, so both must hold it at once;
# that case is detected and both are required to have room.
db_kb=$(sudo du -k "$DB" | cut -f1) || fail "cannot size the database"
stage_avail_kb=$(df -Pk "$(dirname "$STAGE")" | awk 'NR==2 {print $4}')
dest_avail_kb=$(df -Pk "$DEST_DIR" | awk 'NR==2 {print $4}')

# `set -u` does not catch a command that succeeded with empty output, and $(( )) reads empty as 0 —
# which would make `need_kb` zero and pass the gate silently, in exactly the degraded conditions it
# exists to catch.
for v in db_kb stage_avail_kb dest_avail_kb; do
  [[ "${!v}" =~ ^[0-9]+$ ]] || fail "could not measure ${v} (got '${!v}') — refusing to guess"
done

need_kb=$(( db_kb * 12 / 10 ))
stage_dev=$(df -Pk "$(dirname "$STAGE")" | awk 'NR==2 {print $1}')
dest_dev=$(df -Pk "$DEST_DIR" | awk 'NR==2 {print $1}')
echo "  db=$(( db_kb / 1024 ))M stage_avail=$(( stage_avail_kb / 1024 ))M dest_avail=$(( dest_avail_kb / 1024 ))M need=$(( need_kb / 1024 ))M"
[[ "$stage_avail_kb" -ge "$need_kb" ]] \
  || fail "insufficient space where the copy is written: need $(( need_kb / 1024 ))M, have $(( stage_avail_kb / 1024 ))M"
if [[ "$stage_dev" != "$dest_dev" ]]; then
  echo "  note: stage and destination are different mounts — the move is a copy, both must hold it"
  [[ "$dest_avail_kb" -ge "$need_kb" ]] \
    || fail "insufficient space at the destination: need $(( need_kb / 1024 ))M, have $(( dest_avail_kb / 1024 ))M"
fi

# --- source facts, read before the copy so they can be compared against it --------------------
src_uv=$(sudo -u ghost sqlite3 "file:${DB}?mode=ro" "PRAGMA user_version;") || fail "cannot read source user_version"
src_cp=$(sudo -u ghost sqlite3 "file:${DB}?mode=ro" "select count(*) from payout_ledger_checkpoints;") || fail "cannot count checkpoints"
src_sh=$(sudo -u ghost sqlite3 "file:${DB}?mode=ro" "select count(*) from shares;") || fail "cannot count shares"
echo "  source: user_version=${src_uv} checkpoints=${src_cp} shares=${src_sh}"

# --- copy -------------------------------------------------------------------------------------
# `.backup` is the online backup API: consistent against a running writer, and it copies the whole
# file including `user_version` (unlike `sqlcipher_export`, which silently does not).
#
# Staged inside ghost's own directory rather than written straight into the root-owned backup dir,
# so the copy runs as the SAME user that owns the live database. Running sqlite3 as root against a
# database a service has open risks it creating a `-wal`/`-shm` the service user can then no longer
# write — trading a missing backup for a stopped pool.
# `busy_timeout` before the copy: the sqlite3 CLI installs no busy handler, so against a
# continuously-written multi-GB pool database `.backup` can abort with "database is locked" — and
# the parent then marks the node failed and refuses the whole cutover over a transient lock.
echo "  copying..."
# `.timeout` rather than `PRAGMA busy_timeout` — same effect, but the pragma echoes its value
# to stdout and this output is read by an operator.
if ! sudo -u ghost sqlite3 "$DB" ".timeout 60000" ".backup '${STAGE}'"; then
  cleanup_stage
  fail "sqlite3 .backup failed"
fi
sudo mv "$STAGE" "$DEST" || { cleanup_stage; fail "cannot move copy into place"; }
# From here on any failure must remove $DEST: an unverified file in the backup directory is worse
# than an absent one, because it will be trusted.
sudo chown root:root "$DEST" || { sudo rm -f "$DEST"; fail "cannot take ownership of the copy"; }

# --- verify the COPY, not the source ----------------------------------------------------------
dst_uv=$(sudo sqlite3 "file:${DEST}?mode=ro" "PRAGMA user_version;") || fail "cannot read copy user_version"
if [[ "$dst_uv" != "$src_uv" ]]; then
  sudo rm -f "$DEST"
  fail "copy has user_version=${dst_uv}, source has ${src_uv} — a restore would skip migrations"
fi

qc=$(sudo sqlite3 "file:${DEST}?mode=ro" "PRAGMA quick_check;") || { sudo rm -f "$DEST"; fail "quick_check could not run"; }
if [[ "$qc" != "ok" ]]; then
  sudo rm -f "$DEST"
  fail "quick_check on the copy: ${qc}"
fi

dst_cp=$(sudo sqlite3 "file:${DEST}?mode=ro" "select count(*) from payout_ledger_checkpoints;") || { sudo rm -f "$DEST"; fail "cannot count checkpoints in copy"; }
# The pool keeps writing during the copy, so counts may exceed the pre-read snapshot. They must
# never be LOWER, and the ceremony tables must not be empty.
if [[ "$dst_cp" -lt "$src_cp" ]]; then
  sudo rm -f "$DEST"
  fail "copy has ${dst_cp} checkpoints, source had ${src_cp} — the copy is short"
fi
[[ "$dst_cp" -gt 0 ]] || { sudo rm -f "$DEST"; fail "copy holds no payout checkpoints"; }

# `shares` is the shard's evidence table and the gap-fold's input, so it is one of the tables the
# ceremony depends on — it was being read and printed but never actually checked.
dst_sh=$(sudo sqlite3 "file:${DEST}?mode=ro" "select count(*) from shares;") \
  || { sudo rm -f "$DEST"; fail "cannot count shares in copy"; }
if [[ "$dst_sh" -lt "$src_sh" ]]; then
  sudo rm -f "$DEST"
  fail "copy has ${dst_sh} shares, source had ${src_sh} — the copy is short"
fi
echo "  verified: user_version=${dst_uv} quick_check=ok checkpoints=${dst_cp} shares=${dst_sh}"

# --- compress ---------------------------------------------------------------------------------
# Opening the copy read-only still creates `-wal`/`-shm` beside it (WAL mode does this even for a
# read-only connection). Left behind, they outlive the `.db` that gzip removes — and a restore that
# gunzips the database next to a stale WAL is asking sqlite to reconcile two unrelated states.
sudo rm -f "${DEST}-wal" "${DEST}-shm"

raw_sha=$(sudo sha256sum "$DEST" | cut -d' ' -f1)
if [[ "$KEEP_RAW" != "1" ]]; then
  echo "  compressing..."
  # A failed gzip can leave both the original and a partial .gz. Both go: neither has been
  # verified in the state it is now in.
  if ! sudo gzip -6 "$DEST"; then
    sudo rm -f "$DEST" "${DEST}.gz"
    fail "gzip failed"
  fi
  FINAL="${DEST}.gz"
else
  FINAL="$DEST"
fi

sudo chmod 0400 "$FINAL"
final_sha=$(sudo sha256sum "$FINAL" | cut -d' ' -f1)
final_sz=$(sudo du -m "$FINAL" | cut -f1)
# The uncompressed digest is what a restore must reproduce; recorded alongside so the check does
# not require decompressing to know what was taken.
printf 'file=%s\nsize_mb=%s\nsha256=%s\nplain_sha256=%s\nuser_version=%s\ncheckpoints=%s\nstamp=%s\n' \
  "$FINAL" "$final_sz" "$final_sha" "$raw_sha" "$dst_uv" "$dst_cp" "$STAMP" \
  | sudo tee "${FINAL}.manifest" >/dev/null

echo "  OK ${FINAL} (${final_sz}M) sha256=${final_sha:0:16}…"
echo "  free after: $(df -Pk "$DEST_DIR" | awk 'NR==2 {print int($4/1024)}')M"
