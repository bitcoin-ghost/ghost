#!/usr/bin/env bash
#
# Share Shard — ceremony backup (SHARE_SHARD_BUILD.md Stage 0, and Stage 5 step 3).
#
# Takes a verified, compressed, prune-immune copy of every node's `ghost.db`. This is the rollback
# substrate for the whole cutover: migrations run irreversibly at process startup with no
# pre-migration backup, so once a v53/v54 binary has started there is no way back except from here.
#
# Why not `backup-databases.sh`: that one is the rolling daily backup and **prunes at 7 days**. A
# cutover whose rollback position silently expires mid-flight is worse than no backup, because you
# would believe you had one. These land in a separate `ceremony/` directory that nothing prunes.
#
# What it verifies, on the COPY rather than on the source:
#
#   * `PRAGMA user_version` matches the source. `.backup` uses the online backup API and copies the
#     file whole, so it should carry — but `sqlcipher_export` famously does NOT, and "should carry"
#     is how a restore discovers at 3am that the migration runner will skip straight past v53.
#   * `PRAGMA quick_check` passes. (`integrity_check` walks every page and takes minutes on 4 GB;
#     quick_check catches the structural damage a bad copy actually looks like.)
#   * Row counts for the tables the ceremony depends on are present and non-zero.
#
# A copy that fails any of these is DELETED rather than left on disk looking like a backup.
#
# The pool keeps running throughout: `.backup` is the online backup API, not a file copy, so it is
# consistent against concurrent writes. No VACUUM is involved, so the 2x-free-space rule that took
# vm6 down on 2026-08-03 does not apply — one copy plus slack is enough.
#
# Usage:
#   scripts/shard-ceremony-backup.sh [--nodes "..."] [--label cutover] [--keep-uncompressed]
#
# Exit codes: 0 every node backed up and verified, 1 usage/precondition, 2 one or more nodes failed.

set -uo pipefail

NODES="ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4 ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8"
LABEL="ceremony"
KEEP_UNCOMPRESSED=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --nodes) NODES="${2:?--nodes needs a list}"; shift 2 ;;
    --label) LABEL="${2:?--label needs a name}"; shift 2 ;;
    --keep-uncompressed) KEEP_UNCOMPRESSED=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

[[ "$LABEL" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "--label must be alphanumeric, dot, underscore or dash" >&2; exit 1; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REMOTE_SCRIPT="$(dirname "$0")/lib/ceremony-backup-remote.sh"
[[ -r "$REMOTE_SCRIPT" ]] || { echo "missing $REMOTE_SCRIPT" >&2; exit 1; }

echo "== ceremony backup ${LABEL} @ ${STAMP} =="
failed=()
for node in $NODES; do
  echo
  echo "--- ${node} ---"
  if timeout 3600 ssh -o BatchMode=yes -o ConnectTimeout=10 "$node" \
       "GHOST_LABEL='${LABEL}' GHOST_STAMP='${STAMP}' GHOST_KEEP_RAW='${KEEP_UNCOMPRESSED}' bash -s" \
       < "$REMOTE_SCRIPT"; then
    :
  else
    echo "  !! ${node} FAILED"
    failed+=("$node")
  fi
done

echo
if [[ ${#failed[@]} -gt 0 ]]; then
  echo "REFUSE: backup failed on ${#failed[@]} node(s): ${failed[*]}" >&2
  echo "Do not proceed with the cutover — this is the only rollback position." >&2
  exit 2
fi
echo "All nodes backed up and verified. Label: ${LABEL}, stamp: ${STAMP}"
