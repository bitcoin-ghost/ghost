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
#   A. a full node swaps all four binaries, stops translator -> pool -> mining -> ghostd,
#      and starts ghostd -> mining -> pool -> translator; a retired ghost-pay unit (enabled, its
#      binary installed and in the release) is never stopped, swapped or started;
#   B. a failed health check restores all four, the SV2 pair included;
#   C. a release missing an SV2 binary the node runs is refused before anything is stopped;
#   D. a node without the SV2 stack is updated without having it installed.
#   F. on a node pool node the dashboard moves with the release, is put back alone if it does not
#      answer, is left alone by a release without one, stops the update if its checksum fails,
#      and is never touched on an old-network node.
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
has() { if printf '%s\n' "$3" | $G -qF -- "$2"; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
        else printf "  [BAD] %s\n        wanted a line with: %s\n        in: %s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }

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
FULL="$TMP/rel-full";  mkdir -p "$FULL";  make_release "$FULL"  ghostd ghost-mining ghost-pay pool_sv2 translator_sv2
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
    : > "$NODE/masked"
    stub "$NODE/bin/ghostd" old-ghostd
    case " $* " in *" ghost-pay.service "*)      stub "$NODE/bin/ghost-pay" old-ghost-pay ;; esac
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
is "stop order"  "sri-translator sri-pool ghost-mining ghostd" "$(order stop)"
is "start order" "ghostd ghost-mining sri-pool sri-translator" "$(order start)"
is "retired ghost-pay: no systemctl call names it" 0 "$($G -c 'ghost-pay' "$NODE/calls" || true)"
is "retired ghost-pay: its binary is not swapped" old-ghost-pay "$(ver ghost-pay)"
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

echo "E. the relay-peer health check: a node pool node may have no peers"
# read_peer_count and health_ghost_pool, run against a stand-in for ghost-mining's /health.
fns="$(awk '/^read_peer_count\(\) \{$/,/^\}$/{print} /^health_ghost_pool\(\) \{$/,/^\}$/{print}' "$UPDATER")"
is "both functions are present" 2 "$(printf '%s\n' "$fns" | $G -cE '^(read_peer_count|health_ghost_pool)\(\) \{$' || true)"
# shellcheck disable=SC2034  # PEERS_BEFORE is read by the eval'd health_ghost_pool
peers_health() {   # BEFORE AFTER_JSON: health_ghost_pool's verdict
    ( log() { :; }; err() { echo "ERR $*"; }; sleep() { :; }; seq() { echo 1; echo 2; }
      curl() { [ -n "$HEALTH" ] && printf '%s' "$HEALTH"; }
      eval "$fns"; PEERS_BEFORE="$1" HEALTH="$2"
      if health_ghost_pool; then echo ok; fi ) 2>&1 | tail -1
}
is "no peers before, none after: healthy"              ok "$(peers_health 0 '{"response":{"peer_count":0}}')"
is "peers before and after: healthy"                   ok "$(peers_health 2 '{"response":{"peer_count":1}}')"
has "peers before, none after: rolls back"             "it had 2 before the update" "$(peers_health 2 '{"response":{"peer_count":0}}')"
has "no count at all (pool_sv2 down): rolls back"      "reports no peer count" "$(peers_health 0 '{"response":{"peer_count":null}}')"
has "ghost-mining not answering: rolls back"           "reports no peer count" "$(peers_health 0 '')"
is "unknown before (ghost-mining was down): a count is enough" ok "$(peers_health '' '{"response":{"peer_count":0}}')"
is "the count is read before anything is stopped" yes \
   "$(awk '/^  PEERS_BEFORE="\$\(read_peer_count\)"$/{p=NR} /^  stop_all \|\| \{/{if(!s)s=NR} END{print (p && s && p<s)?"yes":"no"}' "$UPDATER")"

echo "F. the node dashboard moves with a node pool release"
# make_np_release DIR DASH(yes|no|badsum) — np-v1.0.1 with the full stack, and the dashboard.
make_np_release() {
    local dir="$1" dash="$2" tag=np-v1.0.1
    local stage="$dir/stage/bitcoin-ghost-$tag"; mkdir -p "$stage" "$dir/dstage/ghost-dashboard"
    local b; for b in ghostd ghost-mining pool_sv2 translator_sv2; do stub "$stage/$b" "new-$b"; done
    tar -czf "$dir/bitcoin-ghost-$tag-x86_64-unknown-linux-gnu.tar.gz" -C "$dir/stage" "bitcoin-ghost-$tag"
    echo "new-dashboard" > "$dir/dstage/ghost-dashboard/server.js"
    ( cd "$dir" && sha256sum "bitcoin-ghost-$tag-x86_64-unknown-linux-gnu.tar.gz" > SHA256SUMS.txt )
    if [ "$dash" != no ]; then
        tar -czf "$dir/bitcoin-ghost-$tag-dashboard.tar.gz" -C "$dir/dstage" ghost-dashboard
        if [ "$dash" = badsum ]; then
            printf '%064d  bitcoin-ghost-%s-dashboard.tar.gz\n' 0 "$tag" >> "$dir/SHA256SUMS.txt"
        else
            ( cd "$dir" && sha256sum "bitcoin-ghost-$tag-dashboard.tar.gz" >> SHA256SUMS.txt )
        fi
    fi
    GNUPGHOME="$TMP/signer" gpg --batch --quiet --yes --armor --local-user "$FP" --detach-sign -o "$dir/SHA256SUMS.txt.asc" "$dir/SHA256SUMS.txt"
}
printf '[{"tag_name": "np-v1.0.1", "draft": false, "prerelease": true}]\n' > "$TMP/np-releases.json"
for k in yes no badsum; do mkdir -p "$TMP/np-$k"; make_np_release "$TMP/np-$k" "$k"; done
# run_np NAME RELEASE DASH_HEALTH [CHANNEL] — a node pool node with a dashboard, one updater run.
run_np() {
    local name="$1" rel="$2" dhealth="$3" channel="${4:-node-pool}"
    NODE="$TMP/node-$name"; mkdir -p "$NODE/bin" "$NODE/dashboard"
    printf '%s\n' ghostd.service ghost-mining.service sri-pool.service sri-translator.service ghost-dashboard.service > "$NODE/units"
    : > "$NODE/masked"
    for b in ghostd ghost-mining pool_sv2 translator_sv2; do stub "$NODE/bin/$b" "old-$b"; done
    echo "old-dashboard" > "$NODE/dashboard/server.js"
    if [ "$channel" = node-pool ]; then echo node-pool > "$NODE/release-channel"; echo np-v1.0.0 > "$NODE/version"
    else echo v1.0.0 > "$NODE/version"; fi
    echo AUTO_UPDATE=true > "$NODE/auto-update.conf"
    FAKE_NODE="$NODE" GHOST_GPG_KEY_FP="$FP" GHOST_RELEASE_KEY_URL="file://$TMP/key.asc" \
    GHOST_NP_RELEASES_API_URL="file://$TMP/np-releases.json" GHOST_RELEASES_API_URL="file://$TMP/latest.json" \
    GHOST_RELEASE_CHANNEL_FILE="$NODE/release-channel" GHOST_RELEASE_BASE="file://$rel" \
    GHOST_AUTOUPDATE_CONF="$NODE/auto-update.conf" GHOST_VERSION_FILE="$NODE/version" \
    GHOST_AUTOUPDATE_STATUS="$NODE/status.json" GHOST_BIN_DIR="$NODE/bin" GHOST_SYSTEMCTL="$TMP/systemctl" \
    GHOST_HEALTHCHECK_OVERRIDE="exit 0" GHOST_DASHBOARD_DIR="$NODE/dashboard" \
    GHOST_DASHBOARD_HEALTH_OVERRIDE="$dhealth" \
        bash "$UPDATER" > "$NODE/out" 2>&1
    echo $? > "$NODE/rc"
}
dash() { cat "$NODE/dashboard/server.js" 2>/dev/null || echo absent; }
msg()  { sed -n 's/.*"message": "\([^"]*\)".*/\1/p' "$NODE/status.json"; }
run_np f1 "$TMP/np-yes" "exit 0"
is "F1 exits 0"                         0              "$(cat "$NODE/rc")"
is "the binaries moved"                 new-ghost-mining "$(ver ghost-mining)"
is "the dashboard moved with them"      new-dashboard  "$(dash)"
has "the status says so"                "dashboard updated" "$(msg)"
is "the previous tree is kept once"     old-dashboard  "$(cat "$NODE"/dashboard.bak.*/server.js 2>/dev/null)"
is "the dashboard was restarted"        yes            "$($G -q '^start ghost-dashboard.service$' "$NODE/calls" && echo yes)"
run_np f2 "$TMP/np-yes" "exit 1"
is "F2 a dashboard that does not answer is put back" old-dashboard "$(dash)"
is "... without rolling the node back"  new-ghost-mining "$(ver ghost-mining)"
is "... and the update still counts"    updated        "$(result)"
has "... saying so"                     "dashboard rolled back" "$(msg)"
run_np f3 "$TMP/np-no" "exit 0"
is "F3 a release without a dashboard updates the node" new-ghost-mining "$(ver ghost-mining)"
is "... and leaves the dashboard as it is" old-dashboard "$(dash)"
has "... with a warning"                "ships no dashboard" "$(cat "$NODE/out")"
run_np f4 "$TMP/np-badsum" "exit 0"
is "F4 a dashboard that fails the signed checksum stops the update" verify-failed "$(result)"
is "... before any binary is touched"   old-ghost-mining "$(ver ghost-mining)"
is "... or the dashboard"               old-dashboard  "$(dash)"
is "... or anything stopped"            ""             "$(order stop)"
run_np f5 "$FULL" "exit 0" old-network
is "F5 an old-network node's dashboard is never touched" old-dashboard "$(dash)"
is "... while its binaries update as before" new-ghost-mining "$(ver ghost-mining)"

echo
echo "test-auto-update-swap: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
