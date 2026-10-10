#!/usr/bin/env bash
#
# End-to-end self-test for scripts/backup-databases.sh.
#
# `scripts/test-backup-retention.sh` drives the arithmetic. This drives the SCRIPT: real SQLite
# databases in WAL mode, a real gzip, a real prune, and each refusal path taken for real.
#
# ⛔ Why a `sqlite3` shim. The script needs the sqlite3 CLI, which the nodes have at /usr/bin/sqlite3
# and a dev box often does not — so without a shim this file would skip silently on the machine where
# the script is edited, which is the worst place for a test to be absent. The shim is Python's
# `sqlite3` module behind the three invocations the script makes, and it is used ONLY when no real
# CLI is on PATH; `SHIM` in the output says which ran.
#
# Exit 0 = the script behaves, 1 = it does not, 2 = INCONCLUSIVE.
set -uo pipefail

SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SRC_ROOT/scripts/backup-databases.sh"
[ -r "$SCRIPT" ] || { echo "test-backup-databases: INCONCLUSIVE — cannot read $SCRIPT"; exit 2; }
command -v python3 >/dev/null || { echo "test-backup-databases: INCONCLUSIVE — no python3 to build fixtures"; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"

if command -v sqlite3 >/dev/null; then
    echo "using the real sqlite3 CLI at $(command -v sqlite3)"
else
    echo "no sqlite3 CLI present — using the Python SHIM"
    cat > "$TMP/bin/sqlite3" <<'SHIM'
#!/usr/bin/env python3
# Stands in for the three sqlite3 CLI invocations backup-databases.sh makes:
#   sqlite3 <src> "VACUUM INTO '<dest>'"
#   sqlite3 "file:<path>?mode=ro" 'PRAGMA user_version;'
#   sqlite3 "file:<path>?mode=ro" 'PRAGMA quick_check;'
import sqlite3, sys
db, stmt = sys.argv[1], sys.argv[2]
try:
    uri = db.startswith("file:")
    # isolation_level=None: VACUUM cannot run inside the transaction the module would open.
    con = sqlite3.connect(db, uri=uri, isolation_level=None)
    rows = con.execute(stmt.rstrip(";")).fetchall()
    for r in rows:
        print(r[0])
    con.close()
except Exception as e:
    print(str(e), file=sys.stderr)
    sys.exit(1)
SHIM
    chmod +x "$TMP/bin/sqlite3"
    PATH="$TMP/bin:$PATH"
    export PATH
fi

pass=0
fail=0
ok()   { echo "  ok   $1"; pass=$((pass + 1)); }
bad()  { echo "  FAIL $1"; shift; printf '         %s\n' "$@"; fail=$((fail + 1)); }

# A case runs the script against its own BACKUP_DIR. The dir is patched rather than parameterised
# because the real one is /var/backups and this test must never touch it.
make_case() {
    local dir="$1"
    rm -rf "$dir"
    mkdir -p "$dir/.ghost/ghost-pay" "$dir/backups"
    python3 - "$dir" <<'PY'
import sqlite3, sys
root = sys.argv[1]
for p in (f"{root}/.ghost/ghost.db", f"{root}/.ghost/ghost-pay/ghost-pay.db"):
    c = sqlite3.connect(p)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA user_version=59")
    c.execute("CREATE TABLE t(x BLOB)")
    c.executemany("INSERT INTO t VALUES (?)", [(b"A" * 4096,) for _ in range(300)])
    c.commit(); c.close()
PY
    sed "s|^BACKUP_DIR=.*|BACKUP_DIR=\"$dir/backups\"|" "$SCRIPT" > "$dir/bk.sh"
    chmod +x "$dir/bk.sh"
    # ⛔ The copy resolves its library relative to ITSELF, so the library has to come too. Without
    # it every case died at the `source` line — and one of them still reported "ok", because "a
    # truncated copy is rejected" only asserts a non-zero exit and no .gz, which a script that never
    # ran satisfies perfectly. That false pass is why each case below also asserts something
    # POSITIVE about what the run did.
    mkdir -p "$dir/lib"
    cp "$SRC_ROOT/scripts/lib/backup-retention.sh" "$dir/lib/backup-retention.sh"
}

run_case() { ( cd "$1" && bash "$1/bk.sh" "$1/.ghost" 2>&1 ); }

# ---------------------------------------------------------------- 1. happy path
C="$TMP/happy"; make_case "$C"
out="$(run_case "$C")"; rc=$?
if [ "$rc" -ne 0 ]; then
    bad "happy path exits 0" "exit $rc" "$out"
else
    gz_ghost=$(find "$C/backups" -name 'ghost-*.db.gz' | wc -l)
    gz_pay=$(find "$C/backups" -name 'ghost-pay-*.db.gz' | wc -l)
    plain=$(find "$C/backups" -name '*.db' | wc -l)
    # ⛔ `ghost-*.db.gz` also matches `ghost-pay-*.db.gz`, so the ghost count is 2 here, not 1.
    # Asserted as it really globs rather than as it reads, because the script's own prune loop uses
    # the same patterns and a test that pretended otherwise would hide a real over-match.
    if [ "$gz_ghost" -eq 2 ] && [ "$gz_pay" -eq 1 ] && [ "$plain" -eq 0 ]; then
        ok "happy path: both databases backed up, gzipped, no uncompressed copy left behind"
    else
        bad "happy path produces 2 gz files and no plain .db" \
            "ghost-*.db.gz=$gz_ghost (expect 2, the glob also matches ghost-pay)" \
            "ghost-pay-*.db.gz=$gz_pay (expect 1)" "plain .db=$plain (expect 0)"
    fi
    case "$out" in
        *"user_version=59"*"quick_check=ok"*) ok "happy path verifies the copy before compressing" ;;
        *) bad "happy path reports user_version and quick_check" "$out" ;;
    esac
    # #1009: every run used to leave `<copy>.db-shm` and `<copy>.db-wal` behind, which retention
    # never matches. And a copy of a 0600 database must not be world-readable.
    stray=$(find "$C/backups" -type f ! -name '*.db.gz' | wc -l)
    modes=$(find "$C/backups" -name '*.db.gz' -exec stat -c '%a' {} + | sort -u | tr '\n' ' ')
    if [ "$stray" -eq 0 ] && [ "$modes" = "600 " ]; then
        ok "happy path leaves only .gz files, owner-only (mode 600)"
    else
        bad "happy path leaves only owner-only .gz files" "non-.gz files: $stray" "modes: '$modes' (expect '600 ')" \
            "$(find "$C/backups" -type f | sed 's|.*/||')"
    fi
    case "$out" in
        *"backup file(s) in"*) ok "happy path reports a positive file count" ;;
        *) bad "happy path reports a count, not silence" "$out" ;;
    esac
fi

# ---------------------------------------------------------------- 2. no room: must REFUSE
C="$TMP/nospace"; make_case "$C"
out="$(BACKUP_HEADROOM_KB=999999999999 run_case "$C")"; rc=$?
left=$(find "$C/backups" -type f | wc -l)
if [ "$rc" -ne 0 ] && [ "$left" -eq 0 ]; then
    case "$out" in
        *REFUSE_SPACE*) ok "no room: refuses, writes nothing, and names REFUSE_SPACE" ;;
        *) bad "no room refusal says why" "$out" ;;
    esac
else
    bad "no room must refuse and write nothing" "exit $rc" "files left: $left" "$out"
fi

# ---------------------------------------------------------------- 3. a truncated copy is caught
# The shim/CLI is replaced by one that writes a plausible non-database, which is exactly what a
# partial write leaves behind. The script must notice BEFORE gzipping.
C="$TMP/truncated"; make_case "$C"
mkdir -p "$C/bin"
cat > "$C/bin/sqlite3" <<'LIAR'
#!/usr/bin/env bash
# The copy "succeeds" and leaves 100 bytes of nonsense; the pragma reads then fail.
case "$2" in
    "VACUUM INTO"*) dest="$(printf '%s' "$2" | sed -nE "s/^VACUUM INTO '(.+)'$/\1/p")"
              [ -n "$dest" ] || { echo "liar shim could not parse: $2" >&2; exit 97; }
              head -c 100 /dev/urandom > "$dest"; exit 0 ;;
    *) echo "file is not a database" >&2; exit 1 ;;
esac
LIAR
chmod +x "$C/bin/sqlite3"
out="$(PATH="$C/bin:$PATH" run_case "$C")"; rc=$?
gz=$(find "$C/backups" -name '*.gz' | wc -l)
# ⛔ The positive half: the run must have got as far as ATTEMPTING the backup. Asserting only
# "non-zero exit, no .gz" is satisfied by a script that died on line 1, and that is exactly how an
# earlier version of this case passed while the library was missing.
case "$out" in
    *"backing up to"*) attempted=1 ;;
    *) attempted=0 ;;
esac
# #1009: the rejected copy must also be REMOVED. It is the full size of the database, and a failed
# run that leaves it is how a backup fills the disk it was written to protect. `removed the
# incomplete copy` is the positive half — it proves the file existed and the script deleted it,
# where "no files left" alone is also true of a run that never wrote one.
left=$(find "$C/backups" -type f | wc -l)
case "$out" in
    *"removed the incomplete copy"*) removed=1 ;;
    *) removed=0 ;;
esac
if [ "$rc" -ne 0 ] && [ "$gz" -eq 0 ] && [ "$attempted" -eq 1 ] && [ "$left" -eq 0 ] && [ "$removed" -eq 1 ]; then
    ok "a truncated copy is rejected before it is compressed, and removed"
else
    bad "a truncated copy must fail the run after attempting it, not be gzipped, and not be left behind" \
        "exit $rc" "gz files: $gz" "reached the backup: $attempted" "files left: $left" \
        "said it removed the copy: $removed" "$out"
fi

# ---------------------------------------------------------------- 3b. a run that is STOPPED cleans up
# `systemctl stop` and the unit's start timeout both arrive as SIGTERM to the whole control group.
# The copy here never finishes: the shim writes a destination and then blocks, which is what the
# vm8 run looked like from outside. Stopping it must leave nothing in the backup directory.
C="$TMP/stopped"; make_case "$C"
mkdir -p "$C/bin"
cat > "$C/bin/sqlite3" <<'STUCK'
#!/usr/bin/env bash
case "$2" in
    "VACUUM INTO"*) dest="$(printf '%s' "$2" | sed -nE "s/^VACUUM INTO '(.+)'$/\1/p")"
              [ -n "$dest" ] || exit 97
              head -c 4096 /dev/zero > "$dest"; : > "$dest-journal"
              exec sleep 300 ;;
    *) exit 1 ;;
esac
STUCK
chmod +x "$C/bin/sqlite3"
( cd "$C" && PATH="$C/bin:$PATH" exec setsid bash "$C/bk.sh" "$C/.ghost" ) > "$C/out.txt" 2>&1 &
stuck_pid=$!
appeared=0
for _ in $(seq 1 100); do
    if [ -n "$(find "$C/backups" -name '*.db' 2>/dev/null)" ]; then appeared=1; break; fi
    sleep 0.1
done
# The whole process group, as systemd signals the whole control group.
kill -TERM -- "-$stuck_pid" 2>/dev/null
wait "$stuck_pid" 2>/dev/null; rc=$?
left=$(find "$C/backups" -type f | wc -l)
if [ "$appeared" -eq 1 ] && [ "$rc" -ne 0 ] && [ "$left" -eq 0 ]; then
    ok "a stopped run removes its partial copy and its journal"
else
    bad "a run stopped mid-copy must leave nothing behind" "copy appeared before the stop: $appeared" \
        "exit $rc" "files left: $left ($(find "$C/backups" -type f | sed 's|.*/||' | tr '\n' ' '))" "$(cat "$C/out.txt")"
fi

# ---------------------------------------------------------------- 3c. the copy cannot be restarted
# The online backup API restarts whenever another connection commits, so against a busy pool
# database it may never finish (#1009). Asserted on the script's text because the failure is a
# race against a writer and a timing test of one would be a flaky test of the test machine.
if /usr/bin/grep -qE "sqlite3 .*VACUUM INTO" "$SCRIPT" \
   && ! /usr/bin/grep -vE '^[[:space:]]*#' "$SCRIPT" | /usr/bin/grep -qF '.backup'; then
    ok "the copy is VACUUM INTO, and no .backup command remains"
else
    bad "the live database must be copied with VACUUM INTO, never .backup" \
        "$(/usr/bin/grep -nF '.backup' "$SCRIPT" | /usr/bin/grep -vE '^[0-9]+:[[:space:]]*#')"
fi

# ---------------------------------------------------------------- 4. running as root is refused
# Asserted by driving the guard directly rather than by becoming root, which a test must not do.
if /usr/bin/grep -qF 'refusing to run as root' "$SCRIPT" \
   && /usr/bin/grep -qE '\[ "\$\(id -u\)" -eq 0 \]' "$SCRIPT"; then
    # And the guard must come BEFORE any backup work, or it refuses after writing.
    guard_line=$(/usr/bin/grep -nE '\[ "\$\(id -u\)" -eq 0 \]' "$SCRIPT" | head -1 | cut -d: -f1)
    work_line=$(/usr/bin/grep -nF 'backup_one "ghost.db"' "$SCRIPT" | head -1 | cut -d: -f1)
    if [ "$guard_line" -lt "$work_line" ]; then
        ok "the root guard exists and precedes any backup work (line $guard_line before $work_line)"
    else
        bad "the root guard must precede the backup work" "guard at $guard_line, work at $work_line"
    fi
else
    bad "the script must refuse to run as root" "no id -u guard found in $SCRIPT"
fi

# ---------------------------------------------------------------- 5. prune keeps the newest
# Nine old copies plus whatever this run makes. Both rules condemn the old ones; the newest must live.
C="$TMP/prune"; make_case "$C"
for i in $(seq 1 9); do
    printf 'x' > "$C/backups/ghost-20250101000$i.db.gz"
    touch -d "@$(( $(date +%s) - (100 + i) * 86400 ))" "$C/backups/ghost-20250101000$i.db.gz"
done
out="$(run_case "$C")"; rc=$?
remaining=$(find "$C/backups" -name 'ghost-*.db.gz' ! -name 'ghost-pay-*' | wc -l)
newest_present=$(find "$C/backups" -name 'ghost-20*.db.gz' ! -name 'ghost-pay-*' -newermt '-1 hour' | wc -l)
if [ "$rc" -eq 0 ] && [ "$remaining" -le 7 ] && [ "$newest_present" -ge 1 ]; then
    ok "prune caps the set at the keep count and the newest copy survives ($remaining left)"
else
    bad "prune must cap at 7 and keep the newest" "exit $rc" "remaining=$remaining" \
        "newest present=$newest_present" "$out"
fi

echo
if [ "$fail" -gt 0 ]; then
    echo "test-backup-databases: $fail of $((pass + fail)) check(s) FAILED"
    exit 1
fi
echo "test-backup-databases: all $pass check(s) pass — backs up and verifies before compressing,"
echo "  refuses rather than filling the disk, rejects and removes a truncated or stopped copy,"
echo "  refuses root, keeps the newest"
exit 0
