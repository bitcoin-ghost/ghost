#!/usr/bin/env bash
#
# ghost-backup-offsite — OPTIONAL off-node copy of the nightly database backups (#1016).
#
# The nightly job (backup-databases.sh) writes gzipped copies to /var/backups/ghost/db, on the same
# disk as the database. That covers a bad migration; it does not cover losing the disk or the VM.
# This helper lets a node runner point those copies at a second place they control. The fleet pays
# for no storage: it is OFF by default, never mandatory, and a node with no /etc/ghost/backup.conf
# behaves exactly as it did before this file existed.
#
# Two kinds of destination, and only two:
#
#   local  an absolute directory on a DIFFERENT filesystem — a mounted USB drive or NFS share.
#          ⛔ A destination on the same filesystem as the local backups is refused: it would not be
#          off-disk. That is also what makes an UNMOUNTED drive safe: its empty mountpoint sits on
#          the root filesystem, so the copy is refused instead of quietly filling the root disk.
#   ssh    user@host:/path over SFTP, with a dedicated ed25519 key this node generates. The private
#          key never leaves the state directory and is never printed. The host key is pinned on the
#          first successful `test` (accept-new) and the nightly copy then requires that exact key
#          (StrictHostKeyChecking=yes). Host key checking is never turned off.
#
# Subcommands. Every one prints ONE JSON object on stdout. Exit 0 = done, 1 = refused/failed (the
# JSON says why, verbatim), 2 = usage.
#
#   show      the whole state: enabled, kind, target, port, keep, public key, pinned host key,
#             the last off-node result, and the newest local backup.
#   set       read the new settings from STDIN, one `key=value` per line (kind, target, keep,
#             port), validate every one, and write /etc/ghost/backup.conf.
#   disable   remove /etc/ghost/backup.conf. The key pair stays, so turning it back on does not
#             mean re-adding a key at the destination.
#   keygen    create the key pair if there is none; print the PUBLIC key.
#   test      write and remove a small probe file at the configured destination, as the backup
#             user, and report the error verbatim if that fails.
#   push [--deadline SECONDS] FILE...
#             (backup-databases.sh only, as the backup user — NOT in sudoers) copy the given
#             backups to the destination, prune the destination to `keep`, record the outcome.
#
# Why settings arrive on STDIN and not argv: the sudoers rule can then pin every subcommand to its
# EXACT argv (`… set`, no wildcard), so nothing the dashboard sends can reach sudo's command line.
# The values are data: they are parsed line by line, matched against fixed character sets, and
# never evaluated, sourced or interpolated into a shell. Under sudo the GHOST_* overrides below are
# stripped by env_reset; they exist for the self-test.
#
# Installed root-owned 0755 at /opt/ghost/bin/ghost-backup-offsite. Canonical source:
# scripts/ghost-backup-offsite.sh (install-node.sh embeds a byte-identical copy;
# scripts/check-inlined-copies.sh holds them together).
#
set -euo pipefail
umask 077

CONF="${GHOST_BACKUP_CONF:-/etc/ghost/backup.conf}"
STATE_DIR="${GHOST_BACKUP_STATE_DIR:-/var/lib/ghost-backup}"
LOCAL_DIR="${GHOST_BACKUP_DIR:-/var/backups/ghost/db}"
GHOST_DIR="${GHOST_BACKUP_GHOST_DIR:-/home/ghost/.ghost}"
BACKUP_USER="${GHOST_BACKUP_USER:-ghost}"
SYSTEMCTL="${GHOST_SYSTEMCTL:-systemctl}"
# Room to leave on a local destination beyond the files themselves.
HEADROOM_KB="${GHOST_BACKUP_OFFSITE_HEADROOM_KB:-262144}"

KEY="$STATE_DIR/id_ed25519"
KNOWN_HOSTS="$STATE_DIR/known_hosts"
STATUS="$STATE_DIR/offsite.status"
KEY_COMMENT="ghost-node-backup"
DEFAULT_KEEP=7

# The names this helper creates and the ONLY names it will ever delete at a destination. Anything
# else in the directory — the operator's own files — is invisible to the prune.
BACKUP_NAME_RE='^ghost(-pay)?-[0-9]{12}\.db\.gz$'

# ------------------------------------------------------------------------------------------ output

# A JSON string literal. Errors can carry any byte (they are a remote server's words), so they are
# reduced to printable ASCII by `clean` before they get here.
json_str() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/ }"
    s="$(printf '%s' "$s" | LC_ALL=C tr -cd '\40-\176')"
    printf '"%s"' "$s"
}

# Printable ASCII, newlines folded to " | ", at most 600 characters.
clean() {
    printf '%s' "$1" | LC_ALL=C tr '\n\t' '\036 ' | LC_ALL=C tr -cd '\36\40-\176' \
        | sed 's/\x1e/ | /g; s/^ | //; s/ | $//' | cut -c1-600
}

fail() {
    printf '{"ok":false,"error":%s}\n' "$(json_str "$(clean "$1")")"
    exit 1
}

usage() {
    echo "usage: ghost-backup-offsite show|set|disable|keygen|test|push [--deadline S] FILE..." >&2
    exit 2
}

# ------------------------------------------------------------------------------------- validation
#
# Each check is a whitelist. A value that fails one is refused, never repaired: stripping the bad
# characters out of `a;rm -rf /` leaves a different path that the operator never asked for.

valid_path() {
    local p="$1"
    [[ "$p" =~ ^/[A-Za-z0-9._/-]{1,254}$ ]] || return 1
    [[ "$p" != *//* ]] || return 1
    [[ "$p/" != */./* && "$p/" != */../* ]] || return 1
    [ "$p" != "/" ] || return 1
    return 0
}

valid_user() { [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9._-]{0,31}$ ]]; }

# A DNS name or IPv4 address. Every label starts and ends alphanumeric, so nothing that reaches ssh
# can begin with `-` and be read as an option.
valid_host() {
    local h="$1"
    [ "${#h}" -le 253 ] || return 1
    [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]
}

valid_port() {
    [[ "$1" =~ ^[0-9]{1,5}$ ]] || return 1
    [ "$((10#$1))" -ge 1 ] && [ "$((10#$1))" -le 65535 ]
}

valid_keep() {
    [[ "$1" =~ ^[0-9]{1,3}$ ]] || return 1
    [ "$((10#$1))" -ge 1 ] && [ "$((10#$1))" -le 365 ]
}

# Splits an ssh target into SSH_USER / SSH_HOST / SSH_PATH, or returns 1.
split_ssh_target() {
    local t="$1"
    [[ "$t" =~ ^([^@:/]+)@([^@:/]+):(/.*)$ ]] || return 1
    SSH_USER="${BASH_REMATCH[1]}"
    SSH_HOST="${BASH_REMATCH[2]}"
    SSH_PATH="${BASH_REMATCH[3]}"
    valid_user "$SSH_USER" && valid_host "$SSH_HOST" && valid_path "$SSH_PATH"
}

# Validates a complete setting. Prints the reason and returns 1 on the first problem.
validate_setting() {
    local kind="$1" target="$2" keep="$3" port="$4"
    case "$kind" in
        local)
            valid_path "$target" || { echo "local target must be an absolute path of letters, digits and . _ - / only (no spaces, no '..')"; return 1; }
            [ -z "$port" ] || { echo "a port applies to an ssh destination only"; return 1; }
            ;;
        ssh)
            split_ssh_target "$target" || { echo "ssh target must be user@host:/absolute/path — user and host of letters, digits and . _ -, path of letters, digits and . _ - /"; return 1; }
            valid_port "${port:-22}" || { echo "port must be a number from 1 to 65535"; return 1; }
            ;;
        *) echo "kind must be 'local' or 'ssh'"; return 1 ;;
    esac
    valid_keep "$keep" || { echo "keep must be a number from 1 to 365"; return 1; }
    return 0
}

# ---------------------------------------------------------------------------------------- config
#
# /etc/ghost/backup.conf is NOT sourced. Each line is a comment, blank, or one of four exact keys;
# anything else makes the whole file invalid, and an invalid file copies nothing.

C_KIND="" C_TARGET="" C_KEEP="" C_PORT="" C_ERROR=""
load_conf() {
    C_KIND="" C_TARGET="" C_KEEP="" C_PORT="" C_ERROR=""
    [ -e "$CONF" ] || return 1
    local line n=0 key val
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        case "$line" in ''|'#'*) continue ;; esac
        key="${line%%=*}"
        val="${line#*=}"
        [ "$key" != "$line" ] || { C_ERROR="$CONF line $n is not KEY=VALUE"; return 1; }
        case "$key" in
            OFFSITE_KIND)   C_KIND="$val" ;;
            OFFSITE_TARGET) C_TARGET="$val" ;;
            OFFSITE_KEEP)   C_KEEP="$val" ;;
            OFFSITE_PORT)   C_PORT="$val" ;;
            *) C_ERROR="$CONF line $n: unknown key"; return 1 ;;
        esac
    done < "$CONF" || { C_ERROR="cannot read $CONF"; return 1; }
    [ -n "$C_KEEP" ] || C_KEEP="$DEFAULT_KEEP"
    local why
    if ! why="$(validate_setting "$C_KIND" "$C_TARGET" "$C_KEEP" "$C_PORT")"; then
        C_ERROR="$CONF is invalid: $why"
        return 1
    fi
    if [ "$C_KIND" = ssh ]; then
        split_ssh_target "$C_TARGET"
        C_PORT="$((10#${C_PORT:-22}))"
    fi
    C_KEEP="$((10#$C_KEEP))"
    return 0
}

write_conf() {
    local kind="$1" target="$2" keep="$3" port="$4" tmp
    mkdir -p "$(dirname "$CONF")"
    tmp="$(mktemp "${CONF}.XXXXXX")"
    {
        echo "# Bitcoin Ghost — optional off-node copy of the nightly database backups (#1016)."
        echo "# Managed by ghost-backup-offsite (the node dashboard). Not sourced: every line is"
        echo "# parsed and validated, and an invalid file copies nothing. Delete it to turn it off."
        echo "OFFSITE_KIND=$kind"
        echo "OFFSITE_TARGET=$target"
        [ "$kind" != ssh ] || echo "OFFSITE_PORT=$port"
        echo "OFFSITE_KEEP=$keep"
    } > "$tmp"
    chmod 644 "$tmp"
    mv -f "$tmp" "$CONF"
}

# ------------------------------------------------------------------------------- the backup user

i_am_backup_user() { [ "$(id -un)" = "$BACKUP_USER" ]; }

# Runs a command as the backup user — the user the nightly job runs as — so a test proves what the
# nightly copy will be able to do, and the key and pinned host key stay owned by that user.
as_backup_user() {
    if i_am_backup_user; then
        "$@"
    elif [ "$(id -u)" -eq 0 ]; then
        (cd / && runuser -u "$BACKUP_USER" -- "$@")
    else
        echo "must run as root or as $BACKUP_USER" >&2
        return 1
    fi
}

ensure_state_dir() {
    if [ ! -d "$STATE_DIR" ]; then
        mkdir -p "$STATE_DIR"
    fi
    chmod 700 "$STATE_DIR"
    if [ "$(id -u)" -eq 0 ] && ! i_am_backup_user; then
        chown "$BACKUP_USER:" "$STATE_DIR"
    fi
}

public_key() {
    [ -r "$KEY.pub" ] || return 1
    local pk
    pk="$(head -n1 "$KEY.pub")"
    [[ "$pk" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+(\ .*)?$ ]] || return 1
    printf '%s' "${pk%% *} $(printf '%s' "$pk" | awk '{print $2}') $KEY_COMMENT"
}

# The host as ssh writes it into known_hosts: bare on port 22, bracketed with the port otherwise.
known_hosts_name() {
    if [ "$2" = 22 ]; then printf '%s' "$1"; else printf '[%s]:%s' "$1" "$2"; fi
}

host_key_pinned() {
    [ -s "$KNOWN_HOSTS" ] || return 1
    ssh-keygen -F "$(known_hosts_name "$1" "$2")" -f "$KNOWN_HOSTS" >/dev/null 2>&1
}

# ------------------------------------------------------------------------------- filesystem checks

# The device a path lives on. For a path that does not exist yet, its nearest existing ancestor.
fs_id() {
    local p="$1"
    while [ ! -e "$p" ] && [ "$p" != / ]; do p="$(dirname "$p")"; done
    stat -L -c %d -- "$p"
}

# Is a local directory usable as an off-disk destination? Prints the reason and returns 1 if not.
check_local_dest() {
    local dir="$1" dev
    [ -e "$dir" ] || { echo "local destination $dir does not exist (is the drive mounted?)"; return 1; }
    [ -d "$dir" ] || { echo "local destination $dir is not a directory"; return 1; }
    as_backup_user test -w "$dir" -a -x "$dir" 2>/dev/null \
        || { echo "local destination $dir is not writable by the backup user '$BACKUP_USER'"; return 1; }
    dev="$(fs_id "$dir")" || { echo "cannot stat $dir"; return 1; }
    if [ "$dev" = "$(fs_id "$LOCAL_DIR")" ]; then
        echo "refusing $dir: it is on the same filesystem as the local backups in $LOCAL_DIR, so a copy there is not off-disk (if it should be a mounted drive, it is not mounted)"
        return 1
    fi
    if [ "$dev" = "$(fs_id "$GHOST_DIR")" ]; then
        echo "refusing $dir: it is on the same filesystem as the database in $GHOST_DIR, so a copy there is not off-disk"
        return 1
    fi
    return 0
}

# ------------------------------------------------------------------------------------- transports

# Remaining seconds before the deadline; empty when there is none.
DEADLINE_AT=""
remaining() {
    [ -n "$DEADLINE_AT" ] || { echo 86400; return 0; }
    local left=$((DEADLINE_AT - $(date +%s)))
    [ "$left" -gt 0 ] || return 1
    echo "$left"
}

# Runs one SFTP batch against the configured server. $1 = StrictHostKeyChecking value, $2 = the
# batch file. The private key is passed by path and never read here.
SFTP_OUT=""
run_sftp() {
    local strict="$1" batch="$2" left
    left="$(remaining)" || { SFTP_OUT="deadline reached before the copy could start"; return 1; }
    SFTP_OUT="$(timeout "$left" sftp -q -b "$batch" -F /dev/null -P "$C_PORT" \
        -i "$KEY" \
        -o IdentitiesOnly=yes \
        -o BatchMode=yes \
        -o PasswordAuthentication=no \
        -o StrictHostKeyChecking="$strict" \
        -o UserKnownHostsFile="$KNOWN_HOSTS" \
        -o GlobalKnownHostsFile=/dev/null \
        -o ConnectTimeout=20 \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=4 \
        -- "$SSH_USER@$SSH_HOST" 2>&1)"
    local rc=$?
    [ "$rc" -ne 124 ] || SFTP_OUT="timed out after ${left}s. $SFTP_OUT"
    return "$rc"
}

# What sftp said, minus its echo of the batch commands.
sftp_error() {
    printf '%s\n' "$SFTP_OUT" | /usr/bin/grep -v '^sftp> ' || true
}

# ------------------------------------------------------------------------------------- subcommands

cmd_show() {
    local enabled=false kind="" target="" keep="$DEFAULT_KEEP" port="" conf_error=""
    local pk="" pinned=false
    if load_conf; then
        enabled=true kind="$C_KIND" target="$C_TARGET" keep="$C_KEEP" port="$C_PORT"
        if [ "$kind" = ssh ] && host_key_pinned "$SSH_HOST" "$C_PORT"; then pinned=true; fi
    elif [ -e "$CONF" ]; then
        conf_error="$C_ERROR"
    fi
    pk="$(public_key)" || pk=""

    # The last off-node outcome, as the nightly run recorded it.
    local last="null"
    if [ -r "$STATUS" ]; then
        local r t e f
        r="$(sed -n 's/^last_offsite_result=//p' "$STATUS" | head -n1)"
        t="$(sed -n 's/^last_offsite_time=//p' "$STATUS" | head -n1)"
        e="$(sed -n 's/^last_offsite_error=//p' "$STATUS" | head -n1)"
        f="$(sed -n 's/^last_offsite_files=//p' "$STATUS" | head -n1)"
        last="{\"result\":$(json_str "$r"),\"time\":$(json_str "$t"),\"error\":$(json_str "$e"),\"files\":$(json_str "$f")}"
    fi

    # The newest LOCAL backup of ghost.db, and how many there are.
    local newest="" newest_time="" count=0 name
    if [ -d "$LOCAL_DIR" ]; then
        for f in "$LOCAL_DIR"/ghost-*.db.gz; do
            [ -e "$f" ] || continue
            name="${f##*/}"
            [[ "$name" =~ $BACKUP_NAME_RE ]] || continue
            [[ "$name" == ghost-pay-* ]] && continue
            count=$((count + 1))
            if [ -z "$newest" ] || [[ "$name" > "$newest" ]]; then newest="$name"; fi
        done
        [ -z "$newest" ] || newest_time="$(date -u -d "@$(stat -c %Y -- "$LOCAL_DIR/$newest")" +%Y-%m-%dT%H:%M:%SZ)"
    fi
    local timer
    timer="$("$SYSTEMCTL" is-enabled ghost-backup.timer 2>/dev/null | head -n1 | LC_ALL=C tr -cd 'a-z-')" || true
    [ -n "$timer" ] || timer="not-found"

    printf '{"ok":true,"enabled":%s,"kind":%s,"target":%s,"port":%s,"keep":%s,"conf_error":%s,' \
        "$enabled" "$( [ -n "$kind" ] && json_str "$kind" || echo null)" \
        "$( [ -n "$target" ] && json_str "$target" || echo null)" \
        "${port:-null}" "$keep" \
        "$( [ -n "$conf_error" ] && json_str "$(clean "$conf_error")" || echo null)"
    printf '"public_key":%s,"host_key_pinned":%s,"last_result":%s,' \
        "$( [ -n "$pk" ] && json_str "$pk" || echo null)" "$pinned" "$last"
    printf '"local":{"dir":%s,"count":%s,"newest":%s,"newest_time":%s,"timer":%s}}\n' \
        "$(json_str "$LOCAL_DIR")" "$count" \
        "$( [ -n "$newest" ] && json_str "$newest" || echo null)" \
        "$( [ -n "$newest_time" ] && json_str "$newest_time" || echo null)" \
        "$(json_str "$timer")"
}

do_keygen() {
    ensure_state_dir
    if [ ! -s "$KEY" ] || [ ! -s "$KEY.pub" ]; then
        rm -f -- "$KEY" "$KEY.pub"
        as_backup_user ssh-keygen -q -t ed25519 -N '' -C "$KEY_COMMENT" -f "$KEY" >/dev/null 2>&1 \
            || return 1
    fi
    public_key >/dev/null
}

cmd_keygen() {
    do_keygen || fail "could not create the backup key pair in $STATE_DIR"
    printf '{"ok":true,"public_key":%s}\n' "$(json_str "$(public_key)")"
}

cmd_set() {
    local line n=0 key val kind="" target="" keep="" port="" seen=" "
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        [ "$n" -le 8 ] || fail "too many input lines"
        [ -n "$line" ] || continue
        key="${line%%=*}"
        val="${line#*=}"
        case "$key" in
            kind|target|keep|port) ;;
            *) fail "unrecognised input on line $n (expected kind=, target=, keep= or port=)" ;;
        esac
        [ "$key" != "$line" ] || fail "input line $n is not key=value"
        case "$seen" in *" $key "*) fail "'$key' given twice" ;; esac
        seen="$seen$key "
        case "$key" in
            kind) kind="$val" ;;
            target) target="$val" ;;
            keep) keep="$val" ;;
            port) port="$val" ;;
        esac
    done
    [ -n "$keep" ] || keep="$DEFAULT_KEEP"
    local why
    why="$(validate_setting "$kind" "$target" "$keep" "$port")" || fail "$why"
    keep="$((10#$keep))"
    # The nightly run records its outcome here, as the backup user, whatever the kind.
    ensure_state_dir

    if [ "$kind" = local ]; then
        why="$(check_local_dest "$target")" || fail "$why"
    else
        split_ssh_target "$target"
        port="$((10#${port:-22}))"
        do_keygen || fail "could not create the backup key pair in $STATE_DIR"
        # A different server forgets the old pin; the next `test` pins the new one. The same
        # server keeps its pin, so a changed key there is still caught.
        local old_host="" old_port=""
        if load_conf && [ "$C_KIND" = ssh ]; then old_host="$SSH_HOST" old_port="$C_PORT"; fi
        split_ssh_target "$target"
        if [ "$old_host" != "$SSH_HOST" ] || [ "$old_port" != "$port" ]; then
            rm -f -- "$KNOWN_HOSTS" "$KNOWN_HOSTS.old"
        fi
    fi
    write_conf "$kind" "$target" "$keep" "$port"
    printf '{"ok":true,"message":%s}\n' "$(json_str "off-node backups set to $kind $target (keep $keep)")"
}

cmd_disable() {
    rm -f -- "$CONF"
    printf '{"ok":true,"message":"off-node backups disabled; nightly backups stay on this node only"}\n'
}

cmd_test() {
    load_conf || fail "${C_ERROR:-off-node backups are not configured}"
    if [ "$C_KIND" = local ]; then
        local why probe
        why="$(check_local_dest "$C_TARGET")" || fail "$why"
        probe="$(as_backup_user mktemp "$C_TARGET/.ghost-backup-probe.XXXXXX" 2>&1)" \
            || fail "could not write a probe file in $C_TARGET: $probe"
        as_backup_user rm -f -- "$probe" 2>&1 || fail "wrote $probe but could not remove it"
        printf '{"ok":true,"message":%s}\n' "$(json_str "wrote and removed a probe file in $C_TARGET")"
        return 0
    fi

    [ -s "$KEY" ] || fail "no backup key yet: generate one first"
    ensure_state_dir
    local probe batch name
    probe="$(as_backup_user mktemp "$STATE_DIR/probe.XXXXXX")" || fail "cannot create a probe file in $STATE_DIR"
    name=".ghost-backup-probe-$(date +%s)-$$"
    batch="$(as_backup_user mktemp "$STATE_DIR/batch.XXXXXX")" || { rm -f -- "$probe"; fail "cannot create a batch file"; }
    printf 'put %s %s/%s\nrm %s/%s\n' "$probe" "$SSH_PATH" "$name" "$SSH_PATH" "$name" > "$batch"
    # accept-new: the FIRST successful contact pins the host key; a changed key is still refused.
    if run_sftp_as_backup_user accept-new "$batch"; then
        rm -f -- "$probe" "$batch"
        printf '{"ok":true,"message":%s}\n' \
            "$(json_str "wrote and removed a probe file at $C_TARGET; host key pinned")"
        return 0
    fi
    rm -f -- "$probe" "$batch"
    fail "$(sftp_error)"
}

# run_sftp, as the backup user when the helper is root (the dashboard's `test`).
run_sftp_as_backup_user() {
    if i_am_backup_user || [ "$(id -u)" -ne 0 ]; then
        run_sftp "$@"
        return $?
    fi
    local strict="$1" batch="$2"
    SFTP_OUT="$(cd / && runuser -u "$BACKUP_USER" -- env \
        GHOST_BACKUP_CONF="$CONF" GHOST_BACKUP_STATE_DIR="$STATE_DIR" \
        "$0" _sftp "$strict" "$batch" 2>&1)"
}

# Internal: re-entered as the backup user by run_sftp_as_backup_user.
cmd__sftp() {
    load_conf || { echo "${C_ERROR:-not configured}"; exit 1; }
    run_sftp "$1" "$2" || { sftp_error; exit 1; }
}

record_status() {
    local result="$1" err="$2" files="$3" tmp
    [ -d "$STATE_DIR" ] && [ -w "$STATE_DIR" ] || { echo "WARN: cannot record status in $STATE_DIR" >&2; return 0; }
    tmp="$(mktemp "$STATUS.XXXXXX")" || return 0
    {
        echo "last_offsite_result=$result"
        echo "last_offsite_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "last_offsite_error=$(clean "$err")"
        echo "last_offsite_files=$(clean "$files")"
        echo "last_offsite_kind=$C_KIND"
        echo "last_offsite_target=$C_TARGET"
    } > "$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$STATUS"
}

push_failed() {
    record_status failed "$1" "$PUSH_NAMES"
    fail "$1"
}

# The names to delete so that only the newest `keep` of each database remain. Never the names this
# run just copied.
prune_victims() {
    local keep="$1" listing="$2" prefix_re
    for prefix_re in '^ghost-[0-9]{12}\.db\.gz$' '^ghost-pay-[0-9]{12}\.db\.gz$'; do
        printf '%s\n' "$listing" | /usr/bin/grep -E "$prefix_re" | sort -r | awk -v keep="$keep" 'NR > keep' || true
    done | while IFS= read -r v; do
        case " $PUSH_NAMES " in *" $v "*) continue ;; esac
        if [ -n "$v" ]; then printf '%s\n' "$v"; fi
    done
    return 0
}

PUSH_NAMES=""
cmd_push() {
    [ "$(id -u)" -ne 0 ] || fail "push refuses to run as root; it runs as the backup user from backup-databases.sh"
    if [ "${1:-}" = "--deadline" ]; then
        [[ "${2:-}" =~ ^[0-9]{1,6}$ ]] || usage
        DEADLINE_AT=$(( $(date +%s) + 10#$2 ))
        shift 2
    fi
    [ "$#" -ge 1 ] || usage
    if [ ! -e "$CONF" ]; then
        printf '{"ok":true,"message":"off-node backups are not configured; nothing to do"}\n'
        return 0
    fi
    load_conf || { record_status failed "$C_ERROR" ""; fail "$C_ERROR"; }

    local f name total_kb=0
    for f in "$@"; do
        name="${f##*/}"
        [[ "$name" =~ $BACKUP_NAME_RE ]] || push_failed "refusing to copy '$name': not a backup this job writes"
        [ -f "$f" ] || push_failed "no such backup: $f"
        PUSH_NAMES="${PUSH_NAMES:+$PUSH_NAMES }$name"
        total_kb=$((total_kb + $(du -k -- "$f" | cut -f1)))
    done

    local victims="" v
    if [ "$C_KIND" = local ]; then
        local why avail left dest
        why="$(check_local_dest "$C_TARGET")" || push_failed "$why"
        # ⛔ Refuse rather than fill, as the local backup does.
        avail="$(df -Pk -- "$C_TARGET" | awk 'NR==2{print $4}')"
        [[ "$avail" =~ ^[0-9]+$ ]] || push_failed "cannot read free space on $C_TARGET"
        if [ "$avail" -lt $((total_kb + HEADROOM_KB)) ]; then
            push_failed "refusing to fill $C_TARGET: need $((total_kb + HEADROOM_KB))KB free (the copies plus ${HEADROOM_KB}KB), have ${avail}KB"
        fi
        for f in "$@"; do
            name="${f##*/}"
            dest="$C_TARGET/.$name.partial"
            left="$(remaining)" || push_failed "deadline reached while copying"
            if ! timeout "$left" cp -- "$f" "$dest" 2>/dev/null; then
                rm -f -- "$dest"
                push_failed "copying $name to $C_TARGET failed"
            fi
            if [ "$(stat -c %s -- "$dest")" != "$(stat -c %s -- "$f")" ]; then
                rm -f -- "$dest"
                push_failed "the copy of $name at $C_TARGET is not the same size as the original"
            fi
            mv -f -- "$dest" "$C_TARGET/$name"
        done
        victims="$(prune_victims "$C_KEEP" "$(ls -1A -- "$C_TARGET")")"
        while IFS= read -r v; do
            [ -n "$v" ] || continue
            rm -f -- "$C_TARGET/$v"
        done <<< "$victims"
    else
        [ -s "$KEY" ] || push_failed "no backup key: generate one and add it to the server"
        host_key_pinned "$SSH_HOST" "$C_PORT" \
            || push_failed "the host key for $SSH_HOST is not pinned yet: run Test once to pin it"
        local batch
        batch="$(mktemp "$STATE_DIR/batch.XXXXXX")"
        : > "$batch"
        for f in "$@"; do
            name="${f##*/}"
            {
                echo "put $f $SSH_PATH/.$name.partial"
                echo "-rm $SSH_PATH/$name"
                echo "rename $SSH_PATH/.$name.partial $SSH_PATH/$name"
            } >> "$batch"
        done
        run_sftp yes "$batch" || { rm -f -- "$batch"; push_failed "$(sftp_error)"; }
        echo "ls -1 $SSH_PATH" > "$batch"
        run_sftp yes "$batch" || { rm -f -- "$batch"; push_failed "copied, but listing $SSH_PATH for the prune failed: $(sftp_error)"; }
        local listing
        listing="$(printf '%s\n' "$SFTP_OUT" | /usr/bin/grep -v '^sftp> ' | sed 's|.*/||' || true)"
        victims="$(prune_victims "$C_KEEP" "$listing")"
        if [ -n "$victims" ]; then
            : > "$batch"
            while IFS= read -r v; do
                if [ -n "$v" ]; then echo "rm $SSH_PATH/$v" >> "$batch"; fi
            done <<< "$victims"
            run_sftp yes "$batch" || { rm -f -- "$batch"; push_failed "copied, but pruning $SSH_PATH failed: $(sftp_error)"; }
        fi
        rm -f -- "$batch"
    fi

    local pruned
    pruned="$(printf '%s' "$victims" | /usr/bin/grep -c . || true)"
    record_status ok "" "$PUSH_NAMES"
    printf '{"ok":true,"message":%s}\n' \
        "$(json_str "copied $PUSH_NAMES to $C_KIND $C_TARGET; pruned $pruned old copy(ies), keeping $C_KEEP")"
}

case "${1:-}" in
    show)    [ "$#" -eq 1 ] || usage; cmd_show ;;
    set)     [ "$#" -eq 1 ] || usage; cmd_set ;;
    disable) [ "$#" -eq 1 ] || usage; cmd_disable ;;
    keygen)  [ "$#" -eq 1 ] || usage; cmd_keygen ;;
    test)    [ "$#" -eq 1 ] || usage; cmd_test ;;
    push)    shift; cmd_push "$@" ;;
    _sftp)   [ "$#" -eq 3 ] || usage; cmd__sftp "$2" "$3" ;;
    *) usage ;;
esac
