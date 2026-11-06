#!/usr/bin/env bash
#
# Self-test for the installer's open-listing lister (--lister, W2.10). Asserted against the
# installer's OWN text:
#   1. it is off by default; --lister / --no-lister / the pin flags set it;
#   2. np_lister_blocker refuses a configuration the lister cannot run on, and the env file
#      carries what the unit needs (and nothing commented in that is missing);
#   3. the enable step enables it only with --lister and a runnable configuration, keeps an
#      enabled lister on a re-run with no flag, and disables it otherwise;
#   4. the env file is written root-only before the enable step; the unit, the binary and the
#      user are installed whatever the option says; uninstall knows the unit and its data.
#
# Hermetic: the installer is never run; its pieces are extracted and run against stubs.
# shellcheck disable=SC2034,SC2329
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${INSTALLER:-$REPO_ROOT/scripts/install-node.sh}"
G=/usr/bin/grep
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
is() { if [ "$2" = "$3" ]; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
       else printf "  [BAD] %s\n        wanted: %s\n        got:    %s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }
has() { if printf '%s\n' "$3" | $G -qF -- "$2"; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
        else printf "  [BAD] %s\n        wanted a line with: %s\n        in:\n%s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }
hasnt() { if printf '%s\n' "$3" | $G -qF -- "$2"; then printf "  [BAD] %s\n        unwanted: %s\n" "$1" "$2"; fail=$((fail+1));
          else printf "  [ok ] %s\n" "$1"; pass=$((pass+1)); fi; }

echo "1. the option"
is "default is empty (off, or as the last install left it)" 1 "$($G -cx 'LISTER=""' "$INSTALLER" || true)"
arms="$($G -E '^[[:space:]]+--(no-)?lister(-table-digest|-genesis-export|-export-digest)?\)' "$INSTALLER")"
is "the five flags are parsed" 5 "$(printf '%s\n' "$arms" | $G -c . || true)"
parse() {
    ( LISTER=""; LISTER_TABLE_DIGEST=""; CONFIG_FLAGS=0
      eval "while [ \$# -gt 0 ]; do case \"\$1\" in
$arms
        *) shift;;
      esac; done"
      echo "${LISTER:-unset}|${LISTER_TABLE_DIGEST}" )
}
is "--lister turns it on"             "true|"    "$(parse --lister)"
is "--no-lister turns it off"         "false|"   "$(parse --lister --no-lister)"
is "no flag leaves it unset"          "unset|"   "$(parse --nickname x)"
is "--lister-table-digest is taken"   "true|ab"  "$(parse --lister --lister-table-digest ab)"
has "it is documented in --help" "--lister " "$(sed -n '/^usage() {/,/^}/p' "$INSTALLER")"

echo "2. the functions"
sed -n '/^# >>> NP_LISTER$/,/^# <<< NP_LISTER$/p' "$INSTALLER" > "$TMP/l.sh"
is "the NP_LISTER block is present" yes "$([ "$(wc -l < "$TMP/l.sh")" -gt 30 ] && echo yes)"
# shellcheck source=/dev/null
source "$TMP/l.sh"
H64="$(printf 'ab%.0s' $(seq 32))"
blocker() {
    ( NETWORK="$1"; GENESIS_ANCHOR="$2"; LISTER_TABLE_DIGEST="$3"; LISTER_EXPORT_DIGEST="$4"
      LISTER_EXPORT_PRESENT="$5"; np_lister_blocker )
}
has "an UNSET genesis blocks it"        "no share-chain genesis" "$(blocker signet UNSET "$H64" "$H64" true)"
is  "regtest runs on its genesis alone" ""                       "$(blocker regtest "$H64" "" "" false)"
has "signet needs the table digest"     "--lister-table-digest"  "$(blocker signet "$H64" "" "$H64" true)"
has "mainnet needs the table digest"    "--lister-table-digest"  "$(blocker mainnet "$H64" "" "" false)"
has "... and the ledger export"         "--lister-genesis-export" "$(blocker signet "$H64" "$H64" "$H64" false)"
has "... and the export digest"         "--lister-export-digest" "$(blocker signet "$H64" "$H64" "" true)"
is  "signet with all three runs"        ""                       "$(blocker signet "$H64" "$H64" "$H64" true)"

env_of() {
    ( RPC_USER=ghostrpc_signet RPCPW=p4ss NETWORK=signet GENESIS_ANCHOR="$H64" GENESIS_HEIGHT=250000
      RELAY_PORT=8566 RELAY_PEERS="203.0.113.5:8566 203.0.113.6:8566" FEE_ADDRESS=tb1qfee
      LISTER_TABLE_DIGEST="$1" LISTER_EXPORT_DIGEST="$2" LISTER_EXPORT_PRESENT="$3"
      np_lister_env_render )
}
e="$(env_of "$H64" "$H64" true)"
has "the RPC user"      "GHOST_AUDIT_RPC_USER=ghostrpc_signet" "$e"
has "the RPC password"  "GHOST_AUDIT_RPC_PASSWORD=p4ss" "$e"
has "the lister's flags: network, genesis, this relay, the peers, the probe address" \
    "GHOST_LISTER_ARGS=--network signet --genesis-anchor ${H64} --genesis-height 250000 --relay-peer 127.0.0.1:8566 --relay-peer 203.0.113.5:8566 --relay-peer 203.0.113.6:8566 --address tb1qfee" "$e"
has "the table digest"  "GHOST_AUDIT_GENESIS_TABLE_DIGEST=${H64}" "$e"
has "the export"        "GHOST_AUDIT_GENESIS_EXPORT=/var/lib/ghost-audit/genesis-export" "$e"
has "its digest"        "GHOST_AUDIT_EXPORT_DIGEST=${H64}" "$e"
e="$(env_of "" "" false)"
has "a missing digest is a comment, not an empty value" "# GHOST_AUDIT_GENESIS_TABLE_DIGEST=" "$e"
is "... never set empty" 0 "$(printf '%s\n' "$e" | $G -cE '^GHOST_AUDIT_[A-Z_]+=$' || true)"
has "a missing export is a comment"                     "# GHOST_AUDIT_GENESIS_EXPORT=" "$e"
printf 'GHOST_AUDIT_GENESIS_TABLE_DIGEST=%s\nOTHER=1\n' "$H64" > "$TMP/old.env"
is "a re-run reads the last pin back" "$H64" "$(np_lister_old GHOST_AUDIT_GENESIS_TABLE_DIGEST "$TMP/old.env")"
is "... and nothing from a missing file" "" "$(np_lister_old GHOST_AUDIT_GENESIS_TABLE_DIGEST "$TMP/none.env")"

echo "3. the enable step"
step="$(sed -n '/^# >>> NP_LISTER_ENABLE$/,/^# <<< NP_LISTER_ENABLE$/p' "$INSTALLER")"
is "the enable step is present" yes "$([ -n "$step" ] && echo yes)"
touch "$TMP/ghost-audit"; chmod 755 "$TMP/ghost-audit"
run_step() {
    # $1 LISTER, $2 what the blocker says, $3 whether the unit is enabled now, $4 the binary.
    ( LISTER="$1"; WHY="$2"; ENABLED="$3"; NP_AUDIT_BIN="$4"; PUBIP=203.0.113.9
      systemctl() {
          if [ "$1" = is-enabled ]; then [ "$ENABLED" = yes ]; return; fi
          echo "$*" >> "$TMP/calls"
      }
      log() { echo "LOG $*" >> "$TMP/calls"; }
      np_lister_blocker() { [ -n "$WHY" ] && echo "$WHY"; return 0; }
      : > "$TMP/calls"
      eval "$step"
      $G -v '^LOG ' "$TMP/calls" | tr '\n' ';'
      echo "|$LISTER_STATUS" )
}
r="$(run_step true "" no "$TMP/ghost-audit")"
is  "--lister and runnable: enabled and started" "enable ghost-lister.service;restart ghost-lister.service;" "${r%%|*}"
has "... and the summary says where it is served" "http://203.0.113.9:8080/api/v1/node-pool/node-list" "$r"
r="$(run_step true "no genesis table digest" no "$TMP/ghost-audit")"
is  "--lister but blocked: left off" "disable --now ghost-lister.service;" "${r%%|*}"
has "... saying why" "NOT started: no genesis table digest" "$r"
r="$(run_step true "" no "$TMP/no-such-binary")"
is  "--lister with no ghost-audit binary: left off" "disable --now ghost-lister.service;" "${r%%|*}"
has "... saying why" "ships no ghost-audit" "$r"
is  "--no-lister: disabled and stopped" "disable --now ghost-lister.service;" "$(r="$(run_step false "" yes "$TMP/ghost-audit")"; echo "${r%%|*}")"
is  "no flag, enabled before: kept on" "enable ghost-lister.service;restart ghost-lister.service;" \
    "$(r="$(run_step "" "" yes "$TMP/ghost-audit")"; echo "${r%%|*}")"
is  "no flag, not enabled before: stays off" "disable --now ghost-lister.service;" \
    "$(r="$(run_step "" "" no "$TMP/ghost-audit")"; echo "${r%%|*}")"

echo "4. what is installed, and in what order"
line_of() { $G -nF -- "$1" "$INSTALLER" | head -1 | cut -d: -f1; }
enable_line="$(line_of '# >>> NP_LISTER_ENABLE')"
for piece in 'useradd -r -M -d "$NP_LISTER_DIR" -s /usr/sbin/nologin ghost-audit' \
             '( umask 077; np_lister_env_render > "${NP_LISTER_ENV}.tmp" )' \
             'chmod 600 "${NP_LISTER_ENV}.tmp"' \
             "cat > /etc/systemd/system/ghost-lister.service <<'GHOST_LISTER_SERVICE_EOF'" \
             'install -m755 -o root -g root "$audit_bin" /opt/ghost/bin/ghost-audit'; do
    l="$(line_of "$piece")"
    is "${piece:0:60} comes before the enable step" yes \
       "$([ -n "$l" ] && [ -n "$enable_line" ] && [ "$l" -lt "$enable_line" ] && echo yes)"
done
is "nothing is installed only when the lister is on" 0 \
   "$(awk '/LISTER" == "true"/ && /if /{inif=1} inif&&/(cat >|install -m|useradd)/{n++} /^fi$/{inif=0} END{print n+0}' "$INSTALLER")"
unit="$(cat "$REPO_ROOT/scripts/systemd/ghost-lister.service")"
has "the unit reads the root-only env file"   "EnvironmentFile=/etc/ghost/lister.env" "$unit"
has "the unit runs as ghost-audit"            "User=ghost-audit" "$unit"
has "the unit writes where ghost-mining reads" "--out-json /var/lib/ghost-audit/node-list.json" "$unit"
has "the unit splits the flags it is given"   ' $GHOST_LISTER_ARGS' "$unit"
has "the state directory is world-readable"   "StateDirectoryMode=0755" "$unit"
srv="$($G -n 'DEFAULT_NODE_LIST_PATH: &str' "$REPO_ROOT/crates/ghost-verification/src/server.rs" || true)"
has "ghost-mining serves the same path" '"/var/lib/ghost-audit/node-list.json"' "$srv"
uninst="$(sed -n '/^# >>> NP_UNINSTALL$/,/^# <<< NP_UNINSTALL$/p' "$INSTALLER")"
has "uninstall removes the unit"       "ghost-lister.service)" "$uninst"
has "uninstall knows the lister's data" "/var/lib/ghost-audit)" "$uninst"
has "purge removes its user"           "userdel ghost-audit" "$uninst"

echo
echo "test-installer-lister: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
