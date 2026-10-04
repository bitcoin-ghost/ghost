#!/usr/bin/env bash
#
# Fail if `PRAGMA incremental_vacuum` is issued through a rusqlite call that does not step it.
#
# ## Why this exists
#
# `PRAGMA incremental_vacuum(N)` is not a one-shot statement. SQLite implements it as a statement
# that frees exactly ONE page per `sqlite3_step()`, returning a row each time until the free list
# is empty or N pages have been released. Every rusqlite convenience that "just runs some SQL"
# steps a statement once:
#
#     conn.execute_batch("PRAGMA incremental_vacuum(32768);")   -> frees 1 page, returns Ok(())
#     conn.execute("PRAGMA incremental_vacuum(32768)", [])      -> frees 1 page
#     conn.pragma_update(None, "incremental_vacuum", 32768)     -> frees 1 page
#
# MEASURED on a free list of 2,250 pages: all three forms left 2,249. Ten `execute_batch` calls in
# a row left 2,240 — one page each. Draining it as a query left 0.
#
# ⛔ The failure is completely silent. There is no error, no warning, and the return value is
# `Ok`. An hourly maintenance task built on `execute_batch` logs success for ever while handing
# back 4 KiB an hour against a database growing by hundreds of megabytes — which reads, from every
# log line and every metric, as maintenance that is working.
#
# The correct shape is to drain it (see `Database::incremental_vacuum`):
#
#     let mut stmt = conn.prepare("PRAGMA incremental_vacuum(N)")?;
#     let mut rows = stmt.query([])?;
#     while rows.next()?.is_some() {}
#
# ## What it checks
#
# Every Rust line mentioning `incremental_vacuum` that also names a non-stepping rusqlite call.
# Shell callers are NOT checked: the `sqlite3` CLI drains statements to completion, so
# `sqlite3 db 'PRAGMA incremental_vacuum;'` is correct.
#
# Exit 0 = every Rust call site steps it, 1 = one does not, 2 = INCONCLUSIVE.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

FILES="$(git ls-files 'bins/*.rs' 'crates/*.rs' 2>/dev/null)"
if [ -z "$FILES" ]; then
    echo "check-incremental-vacuum-is-stepped: INCONCLUSIVE — no Rust sources found under bins/ crates/."
    echo "  Either the layout changed or this is not a git checkout; nothing was examined."
    exit 2
fi

# Sanity floor. The pragma has exactly one production call site today; if the tree has NONE then
# either it was removed (in which case the reclaim path is gone and that is a separate problem) or
# this matcher has rotted. Reporting success on an empty scan is how a guard becomes decoration.
MENTIONS="$(/usr/bin/grep -lE 'incremental_vacuum' $FILES 2>/dev/null | wc -l | tr -d ' ')"
if [ "${MENTIONS:-0}" -lt 1 ]; then
    echo "check-incremental-vacuum-is-stepped: INCONCLUSIVE — no Rust file mentions"
    echo "  \`incremental_vacuum\` at all. Nothing reclaims freed pages, or the matcher has rotted."
    echo "  Expected at least crates/ghost-storage/src/database.rs."
    exit 2
fi

# A line that both names the pragma and uses a call form that steps once is the defect. Checked
# per line because that is how every one of these is written — the SQL string and the call that
# runs it are the same expression.
BAD="$(/usr/bin/grep -nE 'incremental_vacuum' $FILES 2>/dev/null \
       | /usr/bin/grep -E 'execute_batch|\.execute\(|pragma_update|execute_named|pragma_u?pdate' \
       || true)"

if [ -n "$BAD" ]; then
    echo "$BAD" | while IFS= read -r line; do
        echo "  *** ${line}"
    done
    echo
    echo "check-incremental-vacuum-is-stepped: a non-stepping call runs \`PRAGMA incremental_vacuum\`."
    echo
    echo "  execute_batch/execute/pragma_update step a statement ONCE, so each of these frees"
    echo "  exactly ONE page and returns Ok. Prepare it and drain the rows instead — see"
    echo "  Database::incremental_vacuum in crates/ghost-storage/src/database.rs."
    exit 1
fi

# Positive assertion: the stepped form must actually be present. Without this the check passes on
# a tree where the reclaim call was deleted outright, which is the same outcome it exists to stop.
if ! /usr/bin/grep -qE 'prepare\(&?format!\("PRAGMA incremental_vacuum|prepare\("PRAGMA incremental_vacuum' $FILES 2>/dev/null; then
    echo "check-incremental-vacuum-is-stepped: INCONCLUSIVE — found no prepared"
    echo "  \`PRAGMA incremental_vacuum\` statement. Nothing in the Rust tree reclaims freed pages"
    echo "  by stepping the pragma, so there is nothing for this guard to protect."
    exit 2
fi

echo "check-incremental-vacuum-is-stepped: PRAGMA incremental_vacuum is prepared and drained"
echo "  (${MENTIONS} file(s) mention it; no execute_batch/execute/pragma_update call site)"
exit 0
