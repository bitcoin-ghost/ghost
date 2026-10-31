#!/usr/bin/env bash
#
# Self-test for the installer's nightly-backup option (#1016).
#
# A fresh install used to get no database backups at all: the timer was only ever installed by
# hand with scripts/install-backup-timer.sh. The installer now installs the job on every node and
# enables it unless told not to. Asserted here, against the installer's OWN text:
#   1. the default is on, and --backups / --no-backups set it;
#   2. the enable step enables the timer when on and disables it when off;
#   3. the job and its units are installed whatever the option says (so it can be enabled later),
#      and the timer is never enabled before they are written.
#
# Hermetic: the installer is never run; its pieces are extracted and run against stubs.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${INSTALLER:-$REPO_ROOT/scripts/install-node.sh}"
G=/usr/bin/grep
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
is() { if [ "$2" = "$3" ]; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
       else printf "  [BAD] %s\n        wanted: %s\n        got:    %s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }

echo "1. the option"
is "default is on" 1 "$($G -cx 'BACKUPS="true"' "$INSTALLER" || true)"
# The two case arms, run through a minimal parse loop.
arms="$($G -E '^[[:space:]]+--(no-)?backups\)' "$INSTALLER")"
is "both flags are parsed" 2 "$(printf '%s\n' "$arms" | $G -c . || true)"
parse() {
    ( BACKUPS="true"; CONFIG_FLAGS=0
      eval "while [ \$# -gt 0 ]; do case \"\$1\" in
$arms
        *) shift;;
      esac; done"
      echo "$BACKUPS" )
}
is "--no-backups turns it off"            false "$(parse --no-backups)"
is "--backups turns it on"                true  "$(parse --no-backups --backups)"
is "no flag leaves the default"           true  "$(parse --nickname x)"
is "the wizard asks, defaulting to yes"   1 \
   "$($G -cE 'BACKUPS="\$\(prompt_yes_no ".*" Y\)"' "$INSTALLER" || true)"

echo "2. the enable step"
# The if/else that enables or disables the timer.
step="$(awk '/^if \[\[ "\$BACKUPS" == "true" \]\]; then$/{on=1} on{print} on&&/^fi$/{exit}' "$INSTALLER")"
is "the enable step is present" yes "$([ -n "$step" ] && echo yes)"
run_step() {
    ( BACKUPS="$1"
      systemctl() { echo "$*" >> "$TMP/calls"; }
      log() { :; }
      : > "$TMP/calls"
      eval "$step"
      tr '\n' ';' < "$TMP/calls" )
}
is "on: timer enabled and started"   "enable --now ghost-backup.timer;"  "$(run_step true)"
is "off: timer disabled and stopped" "disable --now ghost-backup.timer;" "$(run_step false)"

echo "3. installed either way, and before it is enabled"
line_of() { $G -nF "$1" "$INSTALLER" | head -1 | cut -d: -f1; }
enable_line="$(line_of 'if [[ "$BACKUPS" == "true" ]]; then')"
for piece in "cat > /opt/ghost/scripts/backup-databases.sh" \
             "cat > /opt/ghost/scripts/lib/backup-retention.sh" \
             "cat > /etc/systemd/system/ghost-backup.service" \
             "cat > /etc/systemd/system/ghost-backup.timer"; do
    l="$(line_of "$piece")"
    is "${piece#cat > } is written before the enable step" yes \
       "$([ -n "$l" ] && [ -n "$enable_line" ] && [ "$l" -lt "$enable_line" ] && echo yes)"
done
# None of the four writes may sit inside a BACKUPS conditional.
is "no backup piece is conditional on the option" 0 \
   "$(awk '/BACKUPS/ && /if /{inif=1} inif&&/cat > .*(backup|ghost-backup)/{n++} /^fi$/{inif=0} END{print n+0}' "$INSTALLER")"

echo
echo "test-installer-backups: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
