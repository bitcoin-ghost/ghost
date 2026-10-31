#!/usr/bin/env bash
#
# Self-test for the OPTIONAL off-node backup copy (#1016): scripts/ghost-backup-offsite.sh and the
# block in scripts/backup-databases.sh that calls it.
#
# Hermetic: throwaway directories, real SQLite databases, the real backup script with its
# BACKUP_DIR patched, and two stand-ins —
#
#   * `stat`, which reports a different DEVICE for paths under $FAKE_MOUNT. A test cannot mount a
#     drive, and every temp directory shares one filesystem, so this is the only way to have a
#     destination that is "off-disk". The same-filesystem refusal is tested against the REAL stat.
#   * `sftp`, a fake server that applies the batch to a local directory, or refuses the connection.
#
# What has to hold:
#   1. no /etc/ghost/backup.conf  => the run is what it was before: no off-node attempt at all
#   2. local destination          => this run's copies land, the prune keeps `keep`, nothing else
#                                    in the directory is touched
#   3. same filesystem            => refused, by `set` and by the nightly run
#   4. no room                    => refused rather than filling the destination
#   5. unreachable server         => the LOCAL backup still succeeds (exit 0) and the status file
#                                    records the error
#   6. ssh destination            => copies + prunes over SFTP; nightly requires the pinned host
#                                    key (StrictHostKeyChecking=yes), test pins it (accept-new)
#   7. malicious input            => `set` refuses every one and writes nothing
#   8. `show` is valid JSON in every state, and sudoers pins exact argv
#
# Exit 0 = all pass, 1 = a check failed, 2 = INCONCLUSIVE.
set -uo pipefail

SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP="$SRC_ROOT/scripts/backup-databases.sh"
HELPER="$SRC_ROOT/scripts/ghost-backup-offsite.sh"
SUDOERS="$SRC_ROOT/scripts/ghost-backup-offsite.sudoers"
for f in "$BACKUP" "$HELPER" "$SUDOERS" "$SRC_ROOT/scripts/lib/backup-retention.sh"; do
    [ -r "$f" ] || { echo "test-backup-offsite: INCONCLUSIVE — cannot read $f"; exit 2; }
done
for c in python3 ssh-keygen; do
    command -v "$c" >/dev/null || { echo "test-backup-offsite: INCONCLUSIVE — no $c"; exit 2; }
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
REAL_STAT="$(command -v stat)"
ME="$(id -un)"
mkdir -p "$TMP/bin"

# ---------------------------------------------------------------- stand-ins
if ! command -v sqlite3 >/dev/null; then
    echo "no sqlite3 CLI present — using the Python SHIM"
    cat > "$TMP/bin/sqlite3" <<'SHIM'
#!/usr/bin/env python3
import sqlite3, sys
db, stmt = sys.argv[1], sys.argv[2]
try:
    con = sqlite3.connect(db, uri=db.startswith("file:"), isolation_level=None)
    for r in con.execute(stmt.rstrip(";")).fetchall():
        print(r[0])
    con.close()
except Exception as e:
    print(str(e), file=sys.stderr); sys.exit(1)
SHIM
    chmod +x "$TMP/bin/sqlite3"
fi

cat > "$TMP/bin/stat" <<STAT
#!/usr/bin/env bash
# A different device for anything under \$FAKE_MOUNT, as if a drive were mounted there.
if [ "\${1:-} \${2:-} \${3:-} \${4:-}" = "-L -c %d --" ] && [ -n "\${FAKE_MOUNT:-}" ]; then
    case "\${5:-}" in "\$FAKE_MOUNT"|"\$FAKE_MOUNT"/*) echo 4242; exit 0 ;; esac
fi
exec "$REAL_STAT" "\$@"
STAT
chmod +x "$TMP/bin/stat"

cat > "$TMP/bin/sftp" <<'SFTP'
#!/usr/bin/env bash
# A fake SFTP server. Remote paths are mapped under $FAKE_REMOTE. Every argv is logged.
printf '%s\n' "$*" >> "$SFTP_LOG"
batch=""
while [ $# -gt 0 ]; do
    case "$1" in
        -b) batch="$2"; shift 2 ;;
        -P|-i|-o|-F) shift 2 ;;
        *) shift ;;
    esac
done
if [ "${SFTP_MODE:-ok}" = refuse ]; then
    echo "ssh: connect to host nas.example.org port 22: Connection refused" >&2
    echo "Connection closed" >&2
    exit 255
fi
while IFS= read -r line; do
    echo "sftp> $line"
    ign=0
    case "$line" in -*) ign=1; line="${line#-}" ;; esac
    # shellcheck disable=SC2086
    set -- $line
    case "$1" in
        put)    cp -- "$2" "$FAKE_REMOTE$3" 2>/dev/null || { [ "$ign" = 1 ] || { echo "dest open \"$3\": No such file" >&2; exit 1; }; } ;;
        rm)     rm -- "$FAKE_REMOTE$2" 2>/dev/null || { [ "$ign" = 1 ] || { echo "Couldn't delete file: $2" >&2; exit 1; }; } ;;
        rename) [ ! -e "$FAKE_REMOTE$3" ] || { echo "Couldn't rename: exists" >&2; exit 1; }
                mv -- "$FAKE_REMOTE$2" "$FAKE_REMOTE$3" || exit 1 ;;
        ls)     for f in "$FAKE_REMOTE$3"/*; do [ -e "$f" ] && echo "$3/${f##*/}"; done ;;
    esac
done < "$batch"
exit 0
SFTP
chmod +x "$TMP/bin/sftp"

PATH="$TMP/bin:$PATH"
export PATH
export SFTP_LOG="$TMP/sftp.log"
: > "$SFTP_LOG"

pass=0
fail=0
ok()  { echo "  ok   $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL $1"; shift; printf '         %s\n' "$@"; fail=$((fail + 1)); }

# ---------------------------------------------------------------- fixtures
# A case directory: two databases, the backup script with BACKUP_DIR patched, its library and the
# helper beside it (where the nightly job looks for it), and the helper's environment.
make_case() {
    local dir="$1"
    rm -rf "$dir"
    mkdir -p "$dir/.ghost/ghost-pay" "$dir/backups" "$dir/lib"
    python3 - "$dir" <<'PY'
import sqlite3, sys
root = sys.argv[1]
for p in (f"{root}/.ghost/ghost.db", f"{root}/.ghost/ghost-pay/ghost-pay.db"):
    c = sqlite3.connect(p)
    c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA user_version=59")
    c.execute("CREATE TABLE t(x BLOB)")
    c.executemany("INSERT INTO t VALUES (?)", [(b"A" * 4096,) for _ in range(50)])
    c.commit(); c.close()
PY
    sed "s|^BACKUP_DIR=.*|BACKUP_DIR=\"$dir/backups\"|" "$BACKUP" > "$dir/bk.sh"
    cp "$SRC_ROOT/scripts/lib/backup-retention.sh" "$dir/lib/"
    cp "$HELPER" "$dir/ghost-backup-offsite.sh"
    chmod +x "$dir/bk.sh" "$dir/ghost-backup-offsite.sh"
}

# The environment both the backup run and a direct helper call see for case $1.
case_env() {
    local dir="$1"
    echo "BACKUP_OFFSITE_CONF=$dir/backup.conf"
    echo "GHOST_BACKUP_CONF=$dir/backup.conf"
    echo "GHOST_BACKUP_STATE_DIR=$dir/state"
    echo "GHOST_BACKUP_DIR=$dir/backups"
    echo "GHOST_BACKUP_GHOST_DIR=$dir/.ghost"
    echo "GHOST_BACKUP_USER=$ME"
    echo "GHOST_SYSTEMCTL=false"
}

run_backup() {
    local dir="$1"; shift
    # shellcheck disable=SC2046
    ( cd "$dir" && env $(case_env "$dir") "$@" bash "$dir/bk.sh" "$dir/.ghost" 2>&1 )
}

helper() {
    local dir="$1"; shift
    # shellcheck disable=SC2046
    env $(case_env "$dir") "$dir/ghost-backup-offsite.sh" "$@"
}

status_field() { sed -n "s/^$2=//p" "$1/state/offsite.status" 2>/dev/null | head -n1; }

json_ok() { python3 -c 'import json,sys; json.loads(sys.stdin.read())' 2>/dev/null; }

# ================================================================ 1. no configuration
C="$TMP/noconf"; make_case "$C"
cat > "$TMP/sentinel-helper" <<EOF
#!/usr/bin/env bash
touch "$C/HELPER-WAS-CALLED"
EOF
chmod +x "$TMP/sentinel-helper"
out="$(run_backup "$C" BACKUP_OFFSITE_HELPER="$TMP/sentinel-helper")"; rc=$?
gz=$(find "$C/backups" -name '*.db.gz' | wc -l)
if [ "$rc" -eq 0 ] && [ "$gz" -eq 2 ] && [ ! -e "$C/HELPER-WAS-CALLED" ] && [ ! -e "$C/state" ] \
   && ! printf '%s' "$out" | /usr/bin/grep -qi 'off-node'; then
    ok "no backup.conf: local backup as before (exit 0, 2 files), helper never invoked, no off-node output, no state dir"
else
    bad "no backup.conf must mean no off-node attempt at all" "exit $rc" "gz=$gz (expect 2)" \
        "helper called: $([ -e "$C/HELPER-WAS-CALLED" ] && echo yes || echo no)" \
        "state dir: $([ -e "$C/state" ] && echo created || echo absent)" "$out"
fi

# ================================================================ 2. local destination, copy + prune
C="$TMP/local"; make_case "$C"
export FAKE_MOUNT="$TMP/mnt"
DEST="$FAKE_MOUNT/usb/ghost"
mkdir -p "$DEST"
for i in 1 2 3; do printf 'old' > "$DEST/ghost-20250101000$i.db.gz"; done
printf 'old' > "$DEST/ghost-pay-202501010001.db.gz"
printf 'mine' > "$DEST/notes.txt"
printf 'mine' > "$DEST/ghost-pre-v60-202501010000.db"
out="$(printf 'kind=local\ntarget=%s\nkeep=2\n' "$DEST" | helper "$C" set)"; rc=$?
if [ "$rc" -eq 0 ] && /usr/bin/grep -qx "OFFSITE_TARGET=$DEST" "$C/backup.conf" 2>/dev/null; then
    ok "set accepts a local directory on another filesystem (positive control for the rejections)"
else
    bad "set must accept a valid local destination" "exit $rc" "$out"
fi
out="$(run_backup "$C")"; rc=$?
new_ghost=$(find "$DEST" -name 'ghost-2*.db.gz' -newer "$DEST/notes.txt" | wc -l)
all_ghost=$(find "$DEST" -name 'ghost-[0-9]*.db.gz' | wc -l)
all_pay=$(find "$DEST" -name 'ghost-pay-*.db.gz' | wc -l)
oldest_gone=$([ -e "$DEST/ghost-202501010001.db.gz" ] && echo no || echo yes)
partials=$(find "$DEST" -name '*.partial' | wc -l)
same=1
for f in "$C"/backups/*.db.gz; do cmp -s "$f" "$DEST/${f##*/}" || same=0; done
if [ "$rc" -eq 0 ] && [ "$new_ghost" -ge 1 ] && [ "$all_ghost" -eq 2 ] && [ "$all_pay" -eq 2 ] \
   && [ "$oldest_gone" = yes ] && [ "$partials" -eq 0 ] && [ "$same" -eq 1 ] \
   && [ "$(status_field "$C" last_offsite_result)" = ok ]; then
    ok "local destination: this run's 2 copies land byte-identical, pruned to keep=2 per database, status ok"
else
    bad "local destination must copy, prune to keep and record ok" "exit $rc" \
        "new ghost copies: $new_ghost" "ghost-* at dest: $all_ghost (expect 2)" "ghost-pay-* at dest: $all_pay (expect 2)" \
        "oldest pruned: $oldest_gone" "partials: $partials" "byte-identical: $same" \
        "status: $(status_field "$C" last_offsite_result) $(status_field "$C" last_offsite_error)" "$out"
fi
if [ -e "$DEST/notes.txt" ] && [ -e "$DEST/ghost-pre-v60-202501010000.db" ]; then
    ok "the prune touches only names the job writes — the operator's other files survive"
else
    bad "the prune deleted a file it did not write" "$(ls -A "$DEST")"
fi
out="$(helper "$C" test)"; rc=$?
if [ "$rc" -eq 0 ] && [ -z "$(find "$DEST" -name '.ghost-backup-probe*')" ] && printf '%s' "$out" | json_ok; then
    ok "test on a local destination writes and removes its probe, answers JSON"
else
    bad "test on a local destination" "exit $rc" "$out"
fi

# ================================================================ 3. same filesystem is refused
C="$TMP/samefs"; make_case "$C"
mkdir -p "$TMP/samefs-dest"
out="$(printf 'kind=local\ntarget=%s\n' "$TMP/samefs-dest" | helper "$C" set)"; rc=$?
if [ "$rc" -eq 1 ] && [ ! -e "$C/backup.conf" ] && printf '%s' "$out" | /usr/bin/grep -q 'same filesystem'; then
    ok "set refuses a destination on the same filesystem as the local backups, and writes no config"
else
    bad "set must refuse a same-filesystem destination" "exit $rc" "conf: $([ -e "$C/backup.conf" ] && echo written || echo absent)" "$out"
fi
# The drive that was unmounted after it was configured: the config exists, the copy must refuse.
printf 'OFFSITE_KIND=local\nOFFSITE_TARGET=%s\nOFFSITE_KEEP=7\n' "$TMP/samefs-dest" > "$C/backup.conf"
mkdir -p "$C/state"
out="$(run_backup "$C")"; rc=$?
landed=$(find "$TMP/samefs-dest" -type f | wc -l)
local_gz=$(find "$C/backups" -name '*.db.gz' | wc -l)
if [ "$rc" -eq 0 ] && [ "$landed" -eq 0 ] && [ "$local_gz" -eq 2 ] \
   && [ "$(status_field "$C" last_offsite_result)" = failed ] \
   && status_field "$C" last_offsite_error | /usr/bin/grep -q 'same filesystem'; then
    ok "nightly: a same-filesystem (e.g. unmounted) destination gets nothing; local backup exit 0; status says why"
else
    bad "nightly must refuse a same-filesystem destination without failing the local backup" "exit $rc" \
        "files at dest: $landed" "local gz: $local_gz" \
        "status: $(status_field "$C" last_offsite_result) / $(status_field "$C" last_offsite_error)" "$out"
fi

# ================================================================ 4. refuse rather than fill
C="$TMP/full"; make_case "$C"
DEST="$FAKE_MOUNT/full"; mkdir -p "$DEST"
printf 'kind=local\ntarget=%s\n' "$DEST" | helper "$C" set >/dev/null
out="$(run_backup "$C" GHOST_BACKUP_OFFSITE_HEADROOM_KB=999999999999)"; rc=$?
if [ "$rc" -eq 0 ] && [ -z "$(ls -A "$DEST")" ] \
   && status_field "$C" last_offsite_error | /usr/bin/grep -q 'refusing to fill'; then
    ok "no room at the destination: nothing written, refusal recorded, local backup exit 0"
else
    bad "a destination without room must be refused, not filled" "exit $rc" "dest: $(ls -A "$DEST")" \
        "status: $(status_field "$C" last_offsite_error)" "$out"
fi
unset FAKE_MOUNT

# ================================================================ 5. unreachable server
C="$TMP/unreach"; make_case "$C"
printf 'kind=ssh\ntarget=bk@nas.example.org:/srv/ghost\n' | helper "$C" set >/dev/null
# Pin a host key as a successful test would have.
echo "nas.example.org $(cut -d' ' -f1,2 "$C/state/id_ed25519.pub")" > "$C/state/known_hosts"
out="$(run_backup "$C" SFTP_MODE=refuse)"; rc=$?
local_gz=$(find "$C/backups" -name '*.db.gz' | wc -l)
err="$(status_field "$C" last_offsite_error)"
if [ "$rc" -eq 0 ] && [ "$local_gz" -eq 2 ] && [ "$(status_field "$C" last_offsite_result)" = failed ] \
   && printf '%s' "$err" | /usr/bin/grep -q 'Connection refused' \
   && printf '%s' "$out" | /usr/bin/grep -q 'local backup above is complete and unaffected'; then
    ok "unreachable server: local backup exit 0 with both files; status records the error verbatim"
else
    bad "an unreachable destination must not fail the local backup, and must be recorded" "exit $rc" \
        "local gz: $local_gz" "status: $(status_field "$C" last_offsite_result) / $err" "$out"
fi
json="$(helper "$C" show)"
if printf '%s' "$json" | python3 -c '
import json,sys; d=json.load(sys.stdin)
assert d["enabled"] is True and d["kind"]=="ssh" and d["port"]==22 and d["keep"]==7
assert d["last_result"]["result"]=="failed" and "Connection refused" in d["last_result"]["error"]
assert d["public_key"].startswith("ssh-ed25519 ") and d["host_key_pinned"] is True
assert d["local"]["count"]==1 and d["local"]["newest"].startswith("ghost-")
' 2>/dev/null; then
    ok "show: valid JSON carrying kind, port, keep, public key, pin state, last error and the local backup"
else
    bad "show must report the state as JSON" "$json"
fi
# The private key's body, line by line: none of it may appear in what the dashboard is given.
leaked=0
while IFS= read -r kline; do
    case "$kline" in -----*|'') continue ;; esac
    case "$json" in *"$kline"*) leaked=1 ;; esac
done < "$C/state/id_ed25519"
if [ "$leaked" -eq 0 ] && ! /usr/bin/grep -q 'PRIVATE KEY' <<< "$json" && [ -s "$C/state/id_ed25519" ]; then
    ok "show never contains any line of the private key"
else
    bad "show leaked the private key"
fi

# ================================================================ 6. ssh destination, copy + prune
C="$TMP/ssh"; make_case "$C"
export FAKE_REMOTE="$TMP/remote"
mkdir -p "$FAKE_REMOTE/srv/ghost"
for i in 1 2 3; do printf 'old' > "$FAKE_REMOTE/srv/ghost/ghost-20250101000$i.db.gz"; done
printf 'theirs' > "$FAKE_REMOTE/srv/ghost/README"
printf 'kind=ssh\ntarget=bk@nas.example.org:/srv/ghost\nport=2222\nkeep=2\n' | helper "$C" set >/dev/null
: > "$SFTP_LOG"
out="$(run_backup "$C")"; rc=$?
if [ "$rc" -eq 0 ] && [ "$(status_field "$C" last_offsite_result)" = failed ] \
   && status_field "$C" last_offsite_error | /usr/bin/grep -q 'not pinned' && [ ! -s "$SFTP_LOG" ]; then
    ok "ssh before any Test: nightly refuses an unpinned host without connecting; local backup exit 0"
else
    bad "an unpinned host must be refused before connecting" "exit $rc" \
        "status: $(status_field "$C" last_offsite_error)" "sftp calls: $(wc -l < "$SFTP_LOG")" "$out"
fi
: > "$SFTP_LOG"
out="$(helper "$C" test)"; rc=$?
if [ "$rc" -eq 0 ] && /usr/bin/grep -q 'StrictHostKeyChecking=accept-new' "$SFTP_LOG" \
   && [ -z "$(find "$FAKE_REMOTE/srv/ghost" -name '.ghost-backup-probe*')" ]; then
    ok "test pins on first contact (accept-new) and removes its probe"
else
    bad "test must use accept-new and clean up" "exit $rc" "$out" "$(cat "$SFTP_LOG")"
fi
# The fake server cannot write known_hosts; do what ssh would have on that first contact.
echo "[nas.example.org]:2222 $(cut -d' ' -f1,2 "$C/state/id_ed25519.pub")" > "$C/state/known_hosts"
# ⛔ The earlier run's local copies go, so the comparison below is against THIS run only. When the
# two runs straddle a minute they have different names, and the first run's was never sent.
rm -f "$C"/backups/*.db.gz
: > "$SFTP_LOG"
out="$(run_backup "$C")"; rc=$?
remote_ghost=$(find "$FAKE_REMOTE/srv/ghost" -name 'ghost-[0-9]*.db.gz' | wc -l)
remote_pay=$(find "$FAKE_REMOTE/srv/ghost" -name 'ghost-pay-*.db.gz' | wc -l)
same=1
for f in "$C"/backups/*.db.gz; do cmp -s "$f" "$FAKE_REMOTE/srv/ghost/${f##*/}" || same=0; done
if [ "$rc" -eq 0 ] && [ "$remote_ghost" -eq 2 ] && [ "$remote_pay" -eq 1 ] && [ "$same" -eq 1 ] \
   && [ -e "$FAKE_REMOTE/srv/ghost/README" ] && [ "$(status_field "$C" last_offsite_result)" = ok ]; then
    ok "ssh destination: copies land byte-identical, pruned to keep=2, other files untouched, status ok"
else
    bad "ssh destination must copy and prune" "exit $rc" "ghost-* remote: $remote_ghost (expect 2)" \
        "ghost-pay-* remote: $remote_pay (expect 1)" "identical: $same" \
        "status: $(status_field "$C" last_offsite_result) $(status_field "$C" last_offsite_error)" "$out"
fi
if /usr/bin/grep -q 'StrictHostKeyChecking=yes' "$SFTP_LOG" \
   && ! /usr/bin/grep -qE 'StrictHostKeyChecking=(no|accept-new)' "$SFTP_LOG" \
   && /usr/bin/grep -q 'BatchMode=yes' "$SFTP_LOG" && /usr/bin/grep -q -- '-P 2222' "$SFTP_LOG"; then
    ok "nightly sftp requires the pinned host key (StrictHostKeyChecking=yes), batch mode, configured port"
else
    bad "nightly sftp options" "$(cat "$SFTP_LOG")"
fi
unset FAKE_REMOTE

# ================================================================ 7. malicious input
C="$TMP/evil"; make_case "$C"
evil_inputs=(
    $'kind=local\ntarget=/tmp/x;rm -rf /'
    $'kind=local\ntarget=/tmp/$(id)'
    $'kind=local\ntarget=/tmp/`id`'
    $'kind=local\ntarget=/tmp/a b'
    $'kind=local\ntarget=/tmp/a\nb'
    $'kind=local\ntarget=/tmp/../etc'
    $'kind=local\ntarget=relative/path'
    $'kind=local\ntarget=/tmp/x|id'
    $'kind=local\ntarget=/tmp/x&id'
    $'kind=local\ntarget=/tmp/x\'y'
    $'kind=ssh\ntarget=bk@nas:/srv;id'
    $'kind=ssh\ntarget=bk@nas$(id):/srv'
    $'kind=ssh\ntarget=bk@-oProxyCommand=id:/srv'
    $'kind=ssh\ntarget=-oProxyCommand=id@nas:/srv'
    $'kind=ssh\ntarget=bk@nas:/srv/a b'
    $'kind=ssh\ntarget=bk@nas:/srv\nport=22;id'
    $'kind=ssh\ntarget=bk@nas:/srv\nport=99999'
    $'kind=ssh\ntarget=bk@nas:/srv\nkeep=7;id'
    $'kind=ssh\ntarget=bk@nas:/srv\nkeep=0'
    $'kind=ssh;id\ntarget=bk@nas:/srv'
    $'kind=ssh\ntarget=bk@nas:/srv\nevil=1'
    $'kind=ssh\ntarget=bk@nas:/srv\ntarget=bk@other:/srv'
    $'kind=local\ntarget=/tmp/x\rid'
)
rejected=0
for input in "${evil_inputs[@]}"; do
    out="$(printf '%s\n' "$input" | helper "$C" set)"; rc=$?
    # Refused by VALIDATION. "does not exist" would be a refusal for the wrong reason: the same
    # string naming a directory that does exist would then be accepted.
    if [ "$rc" -eq 1 ] && [ ! -e "$C/backup.conf" ] && printf '%s' "$out" | json_ok \
       && printf '%s' "$out" | /usr/bin/grep -q '"ok":false' \
       && ! printf '%s' "$out" | /usr/bin/grep -q 'does not exist'; then
        rejected=$((rejected + 1))
    else
        bad "set must reject: $(printf '%q' "$input")" "exit $rc" "$out"
        rm -f "$C/backup.conf"
    fi
done
[ "$rejected" -eq "${#evil_inputs[@]}" ] \
    && ok "set rejects all $rejected malicious inputs (; \$( \` space newline CR .. | & ' -o…, bad port/keep/kind, unknown or repeated key) with JSON and writes nothing"
# A hand-edited config with the same kind of value: nothing is copied, the local run is unaffected.
printf 'OFFSITE_KIND=local\nOFFSITE_TARGET=/tmp/x;touch %s/PWNED\n' "$C" > "$C/backup.conf"
mkdir -p "$C/state"
out="$(run_backup "$C")"; rc=$?
show="$(helper "$C" show)"
if [ "$rc" -eq 0 ] && [ ! -e "$C/PWNED" ] && [ "$(status_field "$C" last_offsite_result)" = failed ] \
   && printf '%s' "$show" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["enabled"] is False and "invalid" in d["conf_error"]' 2>/dev/null; then
    ok "a hand-edited config with an injected target is refused: nothing runs, show reports conf_error"
else
    bad "an invalid config must be refused, not executed" "exit $rc" "pwned: $([ -e "$C/PWNED" ] && echo YES || echo no)" "$show" "$out"
fi
out="$(helper "$C" push "$C/backups/../../../etc/passwd")"; rc=$?
if [ "$rc" -ne 0 ]; then
    ok "push refuses to copy a file that is not one of the job's backups"
else
    bad "push must refuse arbitrary files" "$out"
fi

# ================================================================ 8. show + disable + sudoers
C="$TMP/fresh"; make_case "$C"
json="$(helper "$C" show)"
if printf '%s' "$json" | python3 -c '
import json,sys; d=json.load(sys.stdin)
assert d["enabled"] is False and d["kind"] is None and d["public_key"] is None and d["last_result"] is None
assert d["local"]["timer"]=="not-found"' 2>/dev/null; then
    ok "show on a node that never configured it: disabled, no key, no result"
else
    bad "show on a fresh node" "$json"
fi
printf 'kind=ssh\ntarget=bk@nas.example.org:/srv/ghost\n' | helper "$C" set >/dev/null
k1="$(helper "$C" keygen)"
helper "$C" disable >/dev/null
k2="$(helper "$C" keygen)"
if [ ! -e "$C/backup.conf" ] && [ "$k1" = "$k2" ] && printf '%s' "$k1" | json_ok \
   && ! /usr/bin/grep -q 'PRIVATE' <<< "$k1"; then
    ok "disable removes the config and keeps the key pair (the same public key comes back)"
else
    bad "disable / keygen" "conf: $([ -e "$C/backup.conf" ] && echo present || echo absent)" "$k1" "$k2"
fi
for sub in "" bogus "show extra" "push"; do
    # shellcheck disable=SC2086
    helper "$C" $sub >/dev/null 2>&1; rc=$?
    [ "$rc" -eq 2 ] || bad "'$sub' must be a usage error (exit 2)" "exit $rc"
done
ok "unknown subcommands, extra arguments and a bare push are usage errors"

rules="$(/usr/bin/grep -vE '^[[:space:]]*(#|$|Defaults)' "$SUDOERS")"
n_cmds=$(printf '%s' "$rules" | tr ',' '\n' | /usr/bin/grep -c '/opt/ghost/bin/ghost-backup-offsite' || true)
if [ "$n_cmds" -eq 5 ] && ! printf '%s' "$rules" | /usr/bin/grep -qF '*' \
   && ! printf '%s' "$rules" | /usr/bin/grep -qE 'offsite (push|_sftp)'; then
    ok "sudoers pins exactly 5 argvs (show set disable keygen test), no wildcard, no push"
else
    bad "sudoers must pin exact argvs" "$rules"
fi

echo
if [ "$fail" -gt 0 ]; then
    echo "test-backup-offsite: $fail of $((pass + fail)) check(s) FAILED"
    exit 1
fi
echo "test-backup-offsite: all $pass check(s) pass — off by default, copies and prunes, refuses"
echo "  same-disk and full destinations, never fails the local backup, rejects injected input"
exit 0
