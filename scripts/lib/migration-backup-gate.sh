#!/usr/bin/env bash
#
# The decision half of deploy-node.sh's pre-migration backup gate (#996).
#
# ## Why this is a separate file
#
# The gate's value is entirely in its REFUSALS, and the refusals are pure logic over three numbers
# read off a node. Reaching this point inside `deploy-node.sh` means first satisfying every earlier
# precondition — clean tree, commit on origin/main, soak record, config gate, ops convergence, smoke
# — so a self-test that drove the whole script could not practically exercise the bad cases.
#
# So the decision lives here, is sourced by `deploy-node.sh`, and is driven directly by
# `scripts/test-migration-backup-gate.sh` against both real and deliberately-broken probe output.
# One implementation, two callers: nothing to drift.
#
# ## Why it exists at all
#
# `deploy-node.sh` backs up the BINARY and auto-rolls-back on a failed smoke test. That does nothing
# for a schema change: restoring the old binary does not restore the old schema, and a migration that
# deleted rows has already deleted them.
#
# MEASURED 2026-10-04: every node at `user_version = 59`, `ghost-backup.timer` `not-found` on all
# eight, `/var/backups/ghost/db` absent, and the fleet's entire backup inventory two ceremony
# snapshots from 2026-08-13 and 2026-08-18. The next roll carries v60, which DELETEs rows.

# Decide what the pre-migration backup gate should do.
#
# Usage: migration_backup_verdict <want_schema> <probe_text>
#
# `probe_text` is the remote probe's output: `NODB`, or one line each of `VER <n>`, `DBKB <n>`,
# `AVKB <n>`. Prints exactly one verdict line and returns 0 for a verdict the deploy may act on,
# 1 for a refusal:
#
#   NODB                                    fresh node, migrates from empty    (0)
#   NOMIGRATE <live>                         already at or past the target      (0)
#   BACKUP <live> <need_kb> <avail_kb>       take the backup, then migrate      (0)
#   REFUSE_SPACE <need_kb> <avail_kb>        not enough room for a copy         (1)
#   REFUSE_PARSE <field> <value>             the probe did not answer           (1)
migration_backup_verdict() {
    local want="${1:-}" probe="${2:-}"

    case "$want" in
        ''|*[!0-9]*) echo "REFUSE_PARSE want_schema ${want}"; return 1 ;;
    esac

    if printf '%s\n' "$probe" | /usr/bin/grep -qx 'NODB'; then
        echo "NODB"
        return 0
    fi

    local live db_kb avail_kb
    live="$(printf '%s\n' "$probe" | sed -nE 's/^VER ([0-9]+)$/\1/p' | head -1)"
    db_kb="$(printf '%s\n' "$probe" | sed -nE 's/^DBKB ([0-9]+)$/\1/p' | head -1)"
    avail_kb="$(printf '%s\n' "$probe" | sed -nE 's/^AVKB ([0-9]+)$/\1/p' | head -1)"

    # ⛔ Each field SEPARATELY. The obvious version of this is wrong and the self-test caught it:
    # testing `"$live$db_kb$avail_kb"` against `*[!0-9]*` CONCATENATES them, so an empty field is
    # invisible as long as the others are numeric. Both "sqlite printed nothing" (VER empty) and
    # "the df header leaked through" (AVKB non-numeric, so empty after the sed) passed that check,
    # then hit `[: : integer expression expected` and carried on to deploy a migration with no
    # backup — a refusal that reported nothing, because nothing failed.
    local field
    for field in "live_schema:${live}" "db_kb:${db_kb}" "avail_kb:${avail_kb}"; do
        case "${field#*:}" in
            ''|*[!0-9]*) echo "REFUSE_PARSE ${field%%:*} ${field#*:}"; return 1 ;;
        esac
    done

    if [ "$live" -ge "$want" ]; then
        echo "NOMIGRATE $live"
        return 0
    fi

    # Twice the database: `VACUUM INTO` writes a full second copy.
    local need_kb=$((db_kb * 2))
    if [ "$avail_kb" -lt "$need_kb" ]; then
        echo "REFUSE_SPACE $need_kb $avail_kb"
        return 1
    fi

    echo "BACKUP $live $need_kb $avail_kb"
    return 0
}
