#!/usr/bin/env bash
#
# Rename a node's `ghost-pool` unit and binary to `ghost-mining`, in place (#1018).
#
# Runs ON the node, as root. deploy-node.sh pipes it over ssh in place of its usual
# `systemctl restart`, so a node takes the rename and a new binary in ONE restart:
#
#   ssh <node> 'sudo -n bash -s' < scripts/ops/rename-node-unit.sh
#
# What it leaves behind:
#
#   /etc/systemd/system/ghost-mining.service        the unit (ExecStart and Description rewritten)
#   /etc/systemd/system/ghost-mining.service.d/     the drop-ins, moved WHOLE
#   /etc/systemd/system/ghost-pool.service       -> ghost-mining.service   (alias)
#   /opt/ghost/bin/ghost-pool                    -> ghost-mining            (alias)
#   /etc/systemd/system/ghost-mining-gate.service   the boot gate, renamed and re-enabled
#
# and `ghost-mining` wherever another unit or the sudoers file named `ghost-pool`.
#
# Why aliases rather than a clean break. Things outside this script still say `ghost-pool`: a
# dashboard build that has not been redeployed, an operator's fingers, a binary restored by a
# rollback (it restarts itself by the old name). With the old unit name symlinked to the new unit
# systemd loads ONE unit under both names, so `restart ghost-pool`, `Wants=ghost-pool.service`
# and `is-active ghost-pool` all keep meaning this unit.
#
# ⛔ The alias does NOT cover the journal. `journalctl -u ghost-pool` returns only what the unit
# logged BEFORE the rename; everything after is under `ghost-mining`. Anything that reads logs by
# unit name has to change with this, which is why the watchdog and the ops scripts moved in the
# same PR.
#
# ⛔ The drop-in directory is moved whole and never rebuilt from a list. The fleet's drop-ins are
# not uniform (measured 2026-10-11: five files on vm1, four on vm2-vm4, two on vm5-vm7, one on
# vm8), and one of them carries the genesis anchor.
#
# The unit switch is undone if the renamed unit does not come up: the old unit file, drop-ins
# and binary are put back and the old unit is started. A node is never left with neither.
#
# Usage:
#   rename-node-unit.sh              # apply; safe to re-run
#   rename-node-unit.sh --check      # report only
#   rename-node-unit.sh --root DIR   # treat DIR as / (for the self-test)
#
# Exit: 0 = renamed (or already was), 1 = not fully renamed (--check) or the apply failed and
#       was undone, 2 = INCONCLUSIVE: no node unit under either name, or both at once.
#
# The last line of stdout is machine-read by deploy-node.sh, and says which of three things
# happened — they need different handling and share an exit code:
#   RENAME_OK      flipped=<yes|no> active=<state>   renamed; `flipped=yes` means it restarted
#   RENAME_PARTIAL flipped=<yes|no> active=<state>   unit switched and serving, tidy-up incomplete
#   RENAME_UNDONE  active=<state>                    switch failed and was put back

set -uo pipefail

# One brace group around everything, closed on the last line. This script arrives on a pipe
# (`bash -s`), and bash executes a piped script as it reads it — so any child that touched stdin
# would be eating the lines still to come. Inside a group, bash has parsed the whole script
# before it runs the first command.
{

OLD=ghost-pool
NEW=ghost-mining

CHECK=false
ROOT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --check) CHECK=true; shift ;;
        --root)  ROOT="${2:?--root needs a directory}"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done

# Overridable so scripts/test-rename-node-unit.sh can drive every branch, the undo included,
# without a systemd to break. `SYSTEMCTL` is word-split on purpose: the self-test also runs this
# against a real `systemctl --user`.
SYSTEMCTL="${GHOST_RENAME_SYSTEMCTL:-systemctl}"
VISUDO="${GHOST_RENAME_VISUDO:-visudo}"
UNIT_DIR="${GHOST_RENAME_UNIT_DIR:-$ROOT/etc/systemd/system}"
BIN_DIR="$ROOT/opt/ghost/bin"
SUDOERS="$ROOT/etc/sudoers.d/ghost-services"
SETTLE="${GHOST_RENAME_SETTLE_SECS:-3}"

sc() { $SYSTEMCTL "$@"; }
is_file() { [ -f "$1" ] && [ ! -L "$1" ]; }

if [ -z "$ROOT" ] && [ -z "${GHOST_RENAME_UNIT_DIR:-}" ] && [ "$(id -u)" -ne 0 ]; then
    echo "rename-node-unit: must run as root" >&2
    exit 64
fi

# ---------------------------------------------------------------- where is this node?

if is_file "$UNIT_DIR/$NEW.service"; then
    if is_file "$UNIT_DIR/$OLD.service"; then
        echo "rename-node-unit: INCONCLUSIVE — $OLD.service and $NEW.service are BOTH real unit files."
        echo "  Two units would fight for the same ports. Not touching either; resolve it by hand."
        exit 2
    fi
    STATE=renamed
elif is_file "$UNIT_DIR/$OLD.service"; then
    STATE=legacy
else
    echo "rename-node-unit: INCONCLUSIVE — no node unit under either name in $UNIT_DIR."
    echo "  That is not the same as a renamed node. Nothing was examined."
    exit 2
fi

# Everything that still says the old name. Printed by --check, fixed by apply.
dependents_naming_old() {
    local f
    for f in "$UNIT_DIR"/*.service; do
        is_file "$f" || continue
        case "$(basename "$f")" in "$OLD.service"|"$NEW.service") continue ;; esac
        /usr/bin/grep -lE "^(After|Wants|Requires|BindsTo|PartOf)=(.* )?$OLD\.service( |\$)" "$f" 2>/dev/null
    done
    return 0
}

# One line per rule the file lacks, as a complete rule of its own. A line starting `UNPARSED ` is
# a line that names the node unit in a form this cannot extend.
#
# Rules are found wherever they sit in a line, not only at its end: vm1 writes one rule per line,
# vm2-vm4 write every rule on ONE comma-separated line. Anchoring on the line end matched vm1
# alone, so on the other three this added nothing, said nothing, and `--check` called the node
# clean (#1021).
#
# `$OLD` must be followed by a comma or the line end, so `ghost-pool-gate` is not the node unit.
sudoers_lines_missing() {
    [ -f "$SUDOERS" ] || return 0
    local line prefix cmd twin end='[[:space:]]*(,|$)'
    /usr/bin/grep -E "systemctl (start|stop|restart) $OLD$end" "$SUDOERS" 2>/dev/null \
        | /usr/bin/grep -v '^[[:space:]]*#' | while IFS= read -r line; do
        # Everything up to the tag is the "who, where, as whom" the twin has to repeat.
        prefix="$(printf '%s\n' "$line" | sed -nE 's/^([^=]+=[[:space:]]*(\([^)]*\))?[[:space:]]*NOPASSWD:).*/\1/p')"
        case "$line" in *\\) prefix="" ;; esac
        if [ -z "$prefix" ]; then printf 'UNPARSED %s\n' "$line"; continue; fi
        printf '%s\n' "$line" | /usr/bin/grep -oE "[^[:space:],:]*systemctl (start|stop|restart) $OLD$end" \
            | sed -E 's/[[:space:]]*,?$//' | while IFS= read -r cmd; do
            twin="${cmd%"$OLD"}$NEW"
            /usr/bin/grep -v '^[[:space:]]*#' "$SUDOERS" | /usr/bin/grep -qE "(^|[[:space:],:])$twin$end" \
                || printf '%s %s\n' "$prefix" "$twin"
        done
    done
    return 0
}

residue() {
    # Read off the disk each time, never from $STATE: that was decided before the switch ran.
    if is_file "$UNIT_DIR/$OLD.service"; then echo "unit: $OLD.service is still the real unit"; fi
    if is_file "$BIN_DIR/$OLD"; then echo "binary: $BIN_DIR/$OLD is still a real file"; fi
    if [ -d "$UNIT_DIR/$OLD.service.d" ]; then echo "drop-ins: $OLD.service.d still exists"; fi
    if is_file "$UNIT_DIR/$OLD-gate.service"; then echo "gate: $OLD-gate.service not renamed"; fi
    local f
    for f in $(dependents_naming_old); do echo "dependent: $(basename "$f") still orders on $OLD.service"; done
    [ -z "$(sudoers_lines_missing)" ] || echo "sudoers: $(sudoers_lines_missing | /usr/bin/grep -c .) rule(s) lack a $NEW twin"
    return 0
}

if $CHECK; then
    left="$(residue)"
    if [ -z "$left" ]; then
        echo "rename-node-unit: renamed — nothing left under the old name"
        exit 0
    fi
    echo "rename-node-unit: NOT fully renamed:"
    printf '%s\n' "$left" | sed 's/^/  - /'
    exit 1
fi

# ---------------------------------------------------------------- the unit switch
#
# Only this part needs the unit down. It is everything between `stop` and `start`, and nothing
# else: the gate, the dependents and sudoers below are converged with the node already serving.

FLIPPING=""
WAS_ACTIVE=""
BIN_MODE=""
FLIPPED=no

undo() {
    [ -n "$FLIPPING" ] || return 0
    FLIPPING=""
    echo "rename-node-unit: UNDOING the unit switch" >&2
    sc stop "$NEW.service" >/dev/null 2>&1 || true
    [ -L "$UNIT_DIR/$OLD.service" ] && rm -f "$UNIT_DIR/$OLD.service"
    [ -f "$UNIT_DIR/$OLD.service.pre-rename" ] && mv "$UNIT_DIR/$OLD.service.pre-rename" "$UNIT_DIR/$OLD.service"
    if [ -d "$UNIT_DIR/$OLD.service.d.pre-rename" ]; then
        rm -rf "$UNIT_DIR/$NEW.service.d"
        mv "$UNIT_DIR/$OLD.service.d.pre-rename" "$UNIT_DIR/$OLD.service.d"
    fi
    rm -f "$UNIT_DIR/$NEW.service" "$UNIT_DIR/$NEW.service.tmp"
    [ -L "$BIN_DIR/$OLD" ] && rm -f "$BIN_DIR/$OLD"
    case "$BIN_MODE" in
        staged) [ -f "$BIN_DIR/$OLD.pre-rename" ] && mv "$BIN_DIR/$OLD.pre-rename" "$BIN_DIR/$OLD" ;;
        moved)  is_file "$BIN_DIR/$NEW" && [ ! -e "$BIN_DIR/$OLD" ] && mv "$BIN_DIR/$NEW" "$BIN_DIR/$OLD" ;;
    esac
    sc daemon-reload >/dev/null 2>&1 || true
    if [ "$WAS_ACTIVE" = active ]; then
        sc start "$OLD.service" >/dev/null 2>&1 || true
        echo "rename-node-unit: $OLD.service is $(sc is-active "$OLD.service" 2>/dev/null) after the undo" >&2
    fi
}
trap undo EXIT

fail() {
    echo "rename-node-unit: FAILED — $*" >&2
    undo
    echo "RENAME_UNDONE active=$(sc is-active "$OLD.service" 2>/dev/null || true)"
    exit 1
}

if [ "$STATE" = legacy ]; then
    [ ! -e "$UNIT_DIR/$NEW.service" ] && [ ! -e "$UNIT_DIR/$NEW.service.d" ] \
        || { echo "rename-node-unit: INCONCLUSIVE — $NEW.service or its drop-in directory exists beside a real $OLD.service" >&2; exit 2; }

    # Two ways the binary can be here. deploy-node.sh installs the incoming build as `ghost-mining`
    # BEFORE calling this, leaving the outgoing one in place for the still-running process — so
    # both are real files. Run by hand, there is only the old name, and it is moved.
    if is_file "$BIN_DIR/$NEW" && is_file "$BIN_DIR/$OLD"; then BIN_MODE=staged
    elif is_file "$BIN_DIR/$OLD" && [ ! -e "$BIN_DIR/$NEW" ]; then BIN_MODE=moved
    else
        echo "rename-node-unit: INCONCLUSIVE — expected a real $BIN_DIR/$OLD (and optionally a staged $NEW)" >&2
        exit 2
    fi

    WAS_ACTIVE="$(sc is-active "$OLD.service" 2>/dev/null || true)"
    echo "rename-node-unit: switching $OLD.service -> $NEW.service (unit is ${WAS_ACTIVE:-unknown}, binary $BIN_MODE)"

    FLIPPING=1
    if [ "$WAS_ACTIVE" = active ]; then
        sc stop "$OLD.service" || fail "could not stop $OLD.service"
    fi

    sed -e "s|^ExecStart=$BIN_DIR/$OLD |ExecStart=$BIN_DIR/$NEW |" \
        -e 's|^Description=Ghost Pool node$|Description=Ghost Mining node|' \
        "$UNIT_DIR/$OLD.service" > "$UNIT_DIR/$NEW.service.tmp" || fail "could not write the new unit"
    # A substitution that matches nothing still exits 0. A unit that kept the old ExecStart would
    # start and run — through the alias — and look renamed while not being.
    n="$(/usr/bin/grep -c "^ExecStart=$BIN_DIR/$NEW " "$UNIT_DIR/$NEW.service.tmp" || true)"
    [ "$n" = 1 ] || fail "expected exactly one ExecStart=$BIN_DIR/$NEW in the new unit, found $n"
    chmod 644 "$UNIT_DIR/$NEW.service.tmp"
    mv "$UNIT_DIR/$OLD.service" "$UNIT_DIR/$OLD.service.pre-rename" || fail "could not set the old unit aside"
    mv "$UNIT_DIR/$NEW.service.tmp" "$UNIT_DIR/$NEW.service" || fail "could not place the new unit"

    if [ -d "$UNIT_DIR/$OLD.service.d" ]; then
        # Copy, then set the original aside: the undo needs it byte-for-byte, and the copy has its
        # Description rewritten (the installer-parity drop-in on vm1-vm4 sets one).
        cp -a "$UNIT_DIR/$OLD.service.d" "$UNIT_DIR/$NEW.service.d" || fail "could not copy the drop-ins"
        mv "$UNIT_DIR/$OLD.service.d" "$UNIT_DIR/$OLD.service.d.pre-rename" || fail "could not set the old drop-ins aside"
        for c in "$UNIT_DIR/$NEW.service.d"/*.conf; do
            [ -f "$c" ] || continue
            sed -i 's|^Description=Ghost Pool node$|Description=Ghost Mining node|' "$c" || fail "could not rewrite $c"
        done
        want_n="$(find "$UNIT_DIR/$OLD.service.d.pre-rename" -maxdepth 1 -type f | /usr/bin/grep -c . || true)"
        have_n="$(find "$UNIT_DIR/$NEW.service.d" -maxdepth 1 -type f | /usr/bin/grep -c . || true)"
        [ "$want_n" = "$have_n" ] || fail "drop-ins: $want_n before, $have_n after"
    fi
    ln -s "$NEW.service" "$UNIT_DIR/$OLD.service" || fail "could not alias the old unit name"

    case "$BIN_MODE" in
        staged) mv "$BIN_DIR/$OLD" "$BIN_DIR/$OLD.pre-rename" || fail "could not set the old binary aside" ;;
        moved)  mv "$BIN_DIR/$OLD" "$BIN_DIR/$NEW" || fail "could not move the binary" ;;
    esac
    ln -s "$NEW" "$BIN_DIR/$OLD" || fail "could not alias the old binary name"

    sc daemon-reload || fail "daemon-reload failed"

    if [ "$WAS_ACTIVE" = active ]; then
        sc start "$NEW.service" || fail "$NEW.service did not start"
        # `Type=simple` reports active the instant the process is forked. One that exits on its
        # first config read is `active` for that instant too.
        sleep "$SETTLE"
        now="$(sc is-active "$NEW.service" 2>/dev/null || true)"
        [ "$now" = active ] || fail "$NEW.service is '$now' ${SETTLE}s after starting"
    fi

    # One unit, two names — asked of systemd, not inferred from the symlink.
    names="$(sc show "$NEW.service" -p Names --value 2>/dev/null || true)"
    case " $names " in
        *" $OLD.service "*) ;;
        *) fail "systemd does not list $OLD.service as a name of $NEW.service (Names='$names')" ;;
    esac

    FLIPPING=""
    FLIPPED=yes
    rm -rf "$UNIT_DIR/$OLD.service.pre-rename" "$UNIT_DIR/$OLD.service.d.pre-rename" "$BIN_DIR/$OLD.pre-rename"
    echo "rename-node-unit: $NEW.service is up; $OLD.service is now an alias for it"
fi
trap - EXIT

# ---------------------------------------------------------------- everything else, node serving
#
# None of this restarts anything. A failure here is reported and exits non-zero, but it does NOT
# undo the unit switch: the node is serving under the new name, and putting it back down to tidy
# a boot gate would be the wrong trade.

tail_rc=0
reload=no

# The boot gate. ghost-mining is deliberately NOT enabled at boot — the gate starts it once
# ghostd has left initial block download. ⛔ The renamed gate is enabled but not STARTED: its
# script also starts ghost-pay where a unit file for it exists, and running it now would do that
# on a node where the service is retired. It runs at the next boot, which is its job.
if is_file "$UNIT_DIR/$OLD-gate.service" && [ ! -e "$UNIT_DIR/$NEW-gate.service" ]; then
    gate_enabled="$(sc is-enabled "$OLD-gate.service" 2>/dev/null || true)"
    if sed -e "s|Ghost Pool sync gate (starts $OLD once|Ghost Mining sync gate (starts $NEW once|" \
           "$UNIT_DIR/$OLD-gate.service" > "$UNIT_DIR/$NEW-gate.service.tmp" \
       && chmod 644 "$UNIT_DIR/$NEW-gate.service.tmp"; then
        sc disable "$OLD-gate.service" >/dev/null 2>&1 || true
        sc stop "$OLD-gate.service" >/dev/null 2>&1 || true
        mv "$UNIT_DIR/$NEW-gate.service.tmp" "$UNIT_DIR/$NEW-gate.service" && rm -f "$UNIT_DIR/$OLD-gate.service"
        sc daemon-reload || tail_rc=1
        if [ "$gate_enabled" = enabled ]; then
            sc enable "$NEW-gate.service" >/dev/null 2>&1 || true
            got="$(sc is-enabled "$NEW-gate.service" 2>/dev/null || true)"
            if [ "$got" = enabled ]; then
                echo "rename-node-unit: gate renamed and enabled"
            else
                # The one outcome here that costs something later: the node would not start
                # mining after its next reboot, and nothing would say so until then.
                echo "rename-node-unit: FAILED — $NEW-gate.service is '$got', not enabled. THIS NODE WILL NOT START $NEW AT BOOT." >&2
                tail_rc=1
            fi
        else
            echo "rename-node-unit: gate renamed (it was '$gate_enabled' before, left that way)"
        fi
    else
        rm -f "$UNIT_DIR/$NEW-gate.service.tmp"
        echo "rename-node-unit: FAILED — could not write $NEW-gate.service" >&2
        tail_rc=1
    fi
fi

# Units that order on, or want, the node unit. The alias already makes the old name work; this is
# so the files say what is true and match the repo's copies.
for f in $(dependents_naming_old); do
    if sed -E -i "/^(After|Wants|Requires|BindsTo|PartOf)=/ s/(=| )$OLD\.service( |\$)/\1$NEW.service\2/g" "$f"; then
        echo "rename-node-unit: $(basename "$f") now names $NEW.service"
        reload=yes
    else
        echo "rename-node-unit: FAILED — could not rewrite $f" >&2
        tail_rc=1
    fi
done
[ -z "$(dependents_naming_old)" ] || { echo "rename-node-unit: FAILED — a dependent still names $OLD.service" >&2; tail_rc=1; }
if [ "$reload" = yes ]; then sc daemon-reload || tail_rc=1; fi

# sudoers. The binary restarts itself with `sudo systemctl restart ghost-mining`, and sudoers
# matches the argument literally — so without a twin rule the dashboard's restart button is
# refused on exactly the nodes where it works today. The old rules stay: a rolled-back binary
# still asks by the old name.
#
# ⛔ Validated with visudo BEFORE it replaces anything. A sudoers file that does not parse locks
# sudo for everyone, and on vm1-vm4 sudo is how the next deploy gets in.
missing="$(sudoers_lines_missing)"
unparsed="$(printf '%s\n' "$missing" | /usr/bin/grep '^UNPARSED ' || true)"
if [ -n "$unparsed" ]; then
    # Nothing is appended at all: a file extended for some rules and not others would read as done.
    echo "rename-node-unit: FAILED — cannot extend this sudoers line, add its $NEW rule by hand:" >&2
    printf '%s\n' "$unparsed" | sed 's/^UNPARSED /    /' >&2
    tail_rc=1
elif [ -n "$missing" ]; then
    tmp="$SUDOERS.rename.$$"
    if { cat "$SUDOERS"; printf '%s\n' "$missing"; } > "$tmp" && chmod 0440 "$tmp" \
       && $VISUDO -cf "$tmp" >/dev/null 2>&1; then
        if [ -z "$ROOT" ]; then chown root:root "$tmp" 2>/dev/null || true; fi
        mv "$tmp" "$SUDOERS"
        echo "rename-node-unit: sudoers gained $(printf '%s\n' "$missing" | /usr/bin/grep -c .) $NEW rule(s)"
    else
        rm -f "$tmp"
        echo "rename-node-unit: FAILED — the extended sudoers file did not validate; left untouched" >&2
        tail_rc=1
    fi
fi

left="$(residue)"
if [ -n "$left" ]; then
    echo "rename-node-unit: still under the old name:" >&2
    printf '%s\n' "$left" | sed 's/^/  - /' >&2
    tail_rc=1
fi

if [ "$tail_rc" -ne 0 ]; then
    echo "RENAME_PARTIAL flipped=$FLIPPED active=$(sc is-active "$NEW.service" 2>/dev/null || true)"
    exit 1
fi
echo "RENAME_OK flipped=$FLIPPED active=$(sc is-active "$NEW.service" 2>/dev/null || true)"
exit 0

}
