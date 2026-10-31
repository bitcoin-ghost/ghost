#!/usr/bin/env bash
#
# Self-test for the auto-updater's swap: what it replaces, in what order, and what a rollback
# restores (#1044).
#
# The updater used to swap ghostd and ghost-mining and leave pool_sv2 and translator_sv2 alone,
# so an auto-updated node ran a new ghost-mining against the old SV2 binaries — the split the
# fleet's roll order exists to prevent, because share-batch signing lives in pool_sv2 (#742).
#
# Runs the REAL scripts/ghost-auto-update.sh end to end: a release tarball signed with a
# throwaway GPG key, served over file://, stub binaries that print their version, and a fake
# systemctl that records every call. Asserted:
#   A. a full node swaps all four binaries, stops translator -> pool -> pay -> mining -> ghostd,
#      and starts ghostd -> mining -> pool -> translator; a masked ghost-pay is not started;
#   B. a failed health check restores all four, the SV2 pair included;
#   C. a release missing an SV2 binary the node runs is refused before anything is stopped;
#   D. a node without the SV2 stack is updated without having it installed.
#
# UPDATER=<path> runs the same cases against another copy (e.g. the pre-#1044 one, to see A and
# B fail). Hermetic: nothing here touches systemd or a node.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPDATER="${UPDATER:-$REPO_ROOT/scripts/ghost-auto-update.sh}"
G=/usr/bin/grep
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
is() { if [ "$2" = "$3" ]; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
       else printf "  [BAD] %s\n        wanted: %s\n        got:    %s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }

# --- a signed release, v1.0.1 ----------------------------------------------------------------
export GNUPGHOME="$TMP/signer"; mkdir -m700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' --quick-gen-key 'ghost test <test@invalid>' ed25519 sign never 2>/dev/null
FP="$(gpg --batch --with-colons --list-keys 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')"
gpg --batch --quiet --armor --export "$FP" > "$TMP/key.asc"

stub() { printf '#!/bin/sh\necho %s\n' "$2" > "$1"; chmod +x "$1"; }

# make_release DIR BIN... — the tarball carries exactly the named binaries.
make_release() {
    local dir="$1"; shift
    local stage="$dir/stage/bitcoin-ghost-v1.0.1"
    mkdir -p "$stage"
    local b; for b in "$@"; do stub "$stage/$b" "new-$b"; done
    local tarball="bitcoin-ghost-v1.0.1-x86_64-unknown-linux-gnu.tar.gz"
    tar -czf "$dir/$tarball" -C "$dir/stage" bitcoin-ghost-v1.0.1
    ( cd "$dir" && sha256sum "$tarball" > SHA256SUMS.txt )
    gpg --batch --quiet --yes --armor --local-user "$FP" --detach-sign -o "$dir/SHA256SUMS.txt.asc" "$dir/SHA256SUMS.txt"
}
FULL="$TMP/rel-full";  mkdir -p "$FULL";  make_release "$FULL"  ghostd ghost-mining pool_sv2 translator_sv2
NOSV2="$TMP/rel-nosv2"; mkdir -p "$NOSV2"; make_release "$NOSV2" ghostd ghost-mining translator_sv2
printf '{"tag_name": "v1.0.1"}\n' > "$TMP/latest.json"
unset GNUPGHOME

# --- a fake systemctl --------------------------------------------------------------------------
# Units the node has are listed in $NODE/units, masked ones in $NODE/masked. Active state is a
# file per unit. Every call is appended to $NODE/calls.
cat > "$TMP/systemctl" <<'S'
#!/usr/bin/env bash
N="$FAKE_NODE"; echo "$*" >> "$N/calls"
case "$1" in
  # Real systemd refuses a masked unit ("Unit ... is masked.", exit 1).
  start)          grep -qx "$2" "$N/masked" 2>/dev/null && exit 1
                  mkdir -p "$N/active"; touch "$N/active/$2" ;;
  stop)           rm -f "$N/active/$2" ;;
  is-active)      [ -e "$N/active/$2" ] && { echo active; exit 0; } || { echo inactive; exit 3; } ;;
  is-enabled)     grep -qx "$2" "$N/masked" 2>/dev/null && echo masked || echo enabled ;;
  # Real systemd exits 1 when no unit matches (measured: systemd 255 on the fleet).
  list-unit-files) grep -qx "$2" "$N/units"; exit $? ;;
esac
exit 0
S
chmod +x "$TMP/systemctl"

# run_case NAME RELEASE_DIR HEALTH UNITS... — a fresh node, one updater run.
run_case() {
    local name="$1" rel="$2" health="$3"; shift 3
    NODE="$TMP/node-$name"; mkdir -p "$NODE/bin"
    printf '%s\n' "$@" > "$NODE/units"
    echo ghost-pay.service > "$NODE/masked"
    stub "$NODE/bin/ghostd" old-ghostd
    stub "$NODE/bin/ghost-mining" old-ghost-mining
    case " $* " in *" sri-pool.service "*)       stub "$NODE/bin/pool_sv2" old-pool_sv2 ;; esac
    case " $* " in *" sri-translator.service "*) stub "$NODE/bin/translator_sv2" old-translator_sv2 ;; esac
    echo v1.0.0 > "$NODE/version"
    echo AUTO_UPDATE=true > "$NODE/auto-update.conf"
    FAKE_NODE="$NODE" \
    GHOST_GPG_KEY_FP="$FP" \
    GHOST_RELEASE_KEY_URL="file://$TMP/key.asc" \
    GHOST_RELEASES_API_URL="file://$TMP/latest.json" \
    GHOST_RELEASE_BASE="file://$rel" \
    GHOST_AUTOUPDATE_CONF="$NODE/auto-update.conf" \
    GHOST_VERSION_FILE="$NODE/version" \
    GHOST_AUTOUPDATE_STATUS="$NODE/status.json" \
    GHOST_BIN_DIR="$NODE/bin" \
    GHOST_SYSTEMCTL="$TMP/systemctl" \
    GHOST_HEALTHCHECK_OVERRIDE="$health" \
        bash "$UPDATER" > "$NODE/out" 2>&1
    echo $? > "$NODE/rc"
}
ver()    { [ -x "$NODE/bin/$1" ] && "$NODE/bin/$1" || echo absent; }
result() { sed -n 's/.*"result": "\([^"]*\)".*/\1/p' "$NODE/status.json"; }
# The order of one verb's calls, as unit names without .service.
order()  { [ -e "$NODE/calls" ] || return 0; awk -v v="$1" '$1==v{sub(/\.service$/,"",$2); print $2}' "$NODE/calls" | paste -sd' '; }
FULL_UNITS="ghostd.service ghost-mining.service ghost-pay.service sri-pool.service sri-translator.service"

echo "A. a full node takes the whole set"
# shellcheck disable=SC2086
run_case a "$FULL" "exit 0" $FULL_UNITS
is "exits 0"                       0                 "$(cat "$NODE/rc")"
is "status"                        updated           "$(result)"
is "ghostd swapped"                new-ghostd        "$(ver ghostd)"
is "ghost-mining swapped"          new-ghost-mining  "$(ver ghost-mining)"
is "pool_sv2 swapped"              new-pool_sv2      "$(ver pool_sv2)"
is "translator_sv2 swapped"        new-translator_sv2 "$(ver translator_sv2)"
is "stop order"  "sri-translator sri-pool ghost-pay ghost-mining ghostd" "$(order stop)"
is "start order (masked ghost-pay not started)" "ghostd ghost-mining sri-pool sri-translator" "$(order start)"
is "version file"                  v1.0.1            "$(cat "$NODE/version")"

echo "B. a failed health check restores the whole set"
# shellcheck disable=SC2086
run_case b "$FULL" "exit 1" $FULL_UNITS
is "exits 1"                       1                 "$(cat "$NODE/rc")"
is "status"                        rolled-back       "$(result)"
is "ghostd restored"               old-ghostd        "$(ver ghostd)"
is "ghost-mining restored"         old-ghost-mining  "$(ver ghost-mining)"
is "pool_sv2 restored"             old-pool_sv2      "$(ver pool_sv2)"
is "translator_sv2 restored"       old-translator_sv2 "$(ver translator_sv2)"
is "the stack is running again"    "ghostd ghost-mining sri-pool sri-translator" \
   "$(ls "$NODE/active" 2>/dev/null | sed 's/\.service$//' | sort | paste -sd' ' | tr ' ' '\n' | awk 'BEGIN{o["ghostd"]=1;o["ghost-mining"]=2;o["sri-pool"]=3;o["sri-translator"]=4} {print o[$0], $0}' | sort -n | cut -d' ' -f2 | paste -sd' ')"
is "version file unchanged"        v1.0.0            "$(cat "$NODE/version")"

echo "C. a release missing an SV2 binary the node runs is refused"
# shellcheck disable=SC2086
run_case c "$NOSV2" "exit 0" $FULL_UNITS
is "exits 1"                       1                 "$(cat "$NODE/rc")"
is "status"                        error             "$(result)"
is "says which binary"             1                 "$($G -c 'does not contain pool_sv2' "$NODE/out" || true)"
is "nothing was stopped"           ""                "$(order stop)"
is "ghost-mining untouched"        old-ghost-mining  "$(ver ghost-mining)"
is "pool_sv2 untouched"            old-pool_sv2      "$(ver pool_sv2)"

echo "D. a node without the SV2 stack does not get one"
run_case d "$FULL" "exit 0" ghostd.service ghost-mining.service
is "exits 0"                       0                 "$(cat "$NODE/rc")"
is "ghost-mining swapped"          new-ghost-mining  "$(ver ghost-mining)"
is "pool_sv2 not installed"        absent            "$(ver pool_sv2)"
is "translator_sv2 not installed"  absent            "$(ver translator_sv2)"
is "start order"                   "ghostd ghost-mining" "$(order start)"

echo
echo "test-auto-update-swap: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
