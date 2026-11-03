#!/usr/bin/env bash
#
# Self-test for the node pool release channel: np- tags, `np-latest`, the channel marker, the
# updater's choice of channel and the dashboard toggle.
#
# The old network and the node pool publish releases in the same GitHub repository. The old
# network's nodes update from `releases/latest`; node pool releases are tagged `np-v*` and are
# published as pre-releases so they can never be `latest`. Asserted here:
#   1. np_latest_tag picks the highest published final np- tag and nothing else: not an old tag
#      (even a higher one), not a draft, not an -rc tag; it refuses a list it cannot read;
#   2. the channel block is identical in the updater, the installer and the installer's embedded
#      copy of the updater;
#   3. the installer resolves GHOST_VERSION: np-latest, an exact np- tag, and refuses old tags;
#   4. the updater, run end to end against a signed fixture (file:// URLs, throwaway GPG key,
#      fake systemctl): a node pool node follows np- only; a node without the marker is updated
#      EXACTLY as the updater before the channel existed updates it; a node pool build without
#      the marker, a bad marker and a `latest` that is an np- tag are all refused untouched;
#   5. the dashboard toggle never touches the marker and refuses `on` under a bad one.
#
# Hermetic: no network, no systemd, no node. Usage: scripts/test-release-channel.sh
# Variables below are read by sourced or extracted code that shellcheck cannot see.
# shellcheck disable=SC2034
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPDATER="$REPO_ROOT/scripts/ghost-auto-update.sh"
INSTALLER="$REPO_ROOT/scripts/install-node.sh"
TOGGLE="$REPO_ROOT/scripts/ghost-autoupdate-toggle.sh"
# The updater as it was before the channel existed, for the "old install unchanged" comparison.
BASELINE_REF="${BASELINE_REF:-ab480563b}"
G=/usr/bin/grep
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
is() { if [ "$2" = "$3" ]; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
       else printf "  [BAD] %s\n        wanted: %s\n        got:    %s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }

# --------------------------------------------------------------------------- 1. np_latest_tag
echo "1. np-latest picks the newest published np- release"
sed -n '/^# >>> NP_RELEASE_CHANNEL$/,/^# <<< NP_RELEASE_CHANNEL$/p' "$UPDATER" > "$TMP/chan.sh"
# shellcheck source=/dev/null
source "$TMP/chan.sh"

# rel TAG DRAFT PRERELEASE [BODY] — one release object as GitHub prints it (keys in its order,
# with nested author/assets objects that must not confuse the parser).
rel() {
    cat <<EOF
  {
    "url": "https://api.github.com/repos/bitcoin-ghost/ghost/releases/1",
    "id": 1,
    "author": { "login": "defenwycke", "id": 7, "type": "User", "site_admin": false },
    "node_id": "RE_x",
    "tag_name": "$1",
    "target_commitish": "main",
    "name": "$1",
    "draft": $2,
    "immutable": false,
    "prerelease": $3,
    "created_at": "2026-11-02T00:00:00Z",
    "assets": [ { "name": "SHA256SUMS.txt", "state": "uploaded", "uploader": { "login": "x", "site_admin": false } } ],
    "body": "${4:-notes}"
  }
EOF
}
list() { local first=1; echo "["; while [ $# -gt 0 ]; do [ $first = 1 ] || echo ","; first=0; rel "$1" "$2" "$3" "${4:-}"; shift 4; done; echo "]"; }
latest_of() { local out rc; out="$(np_latest_tag)"; rc=$?; echo "$rc:$out"; }

mixed="$(list v1.11.99 false false '' np-v1.2.0 false true '' np-v1.10.0 false true '' \
              np-v1.11.0 true true '' np-v1.10.1-rc1 false true '' v2.0.0 false false '' \
              np-v1.9.9 false true '')"
is "the highest final np- tag, by version not by order" "0:np-v1.10.0" "$(latest_of <<<"$mixed")"
is "the same list minified onto one line"              "0:np-v1.10.0" "$(tr -d '\n' <<<"$mixed" | latest_of)"
is "a draft np- release is never picked"  "0:np-v1.2.0" "$(list np-v1.3.0 true true '' np-v1.2.0 false true '' | latest_of)"
is "an -rc tag is never picked"           "0:np-v1.2.0" "$(list np-v1.3.0-rc1 false true '' np-v1.2.0 false true '' | latest_of)"
is "old-network tags are never picked"    "1:"          "$(list v1.11.46 false false '' v1.11.45 false false '' | latest_of)"
is "np- tags of any other shape are not picked" "1:"    "$(list np-1.2.0 false true '' np-v1.2 false true '' xnp-v1.2.0 false true '' | latest_of)"
is "an empty list has none"               "1:"          "$(echo '[]' | latest_of)"
is "an error body has none"               "1:"          "$(echo '{"message": "API rate limit exceeded"}' | latest_of)"
is "a tag_name in release notes is not a release" "0:np-v1.0.0" \
   "$(list np-v1.0.0 false true 'see \"tag_name\": \"np-v9.0.0\", \"draft\": false' | latest_of)"
is "a release without a draft field fails closed" "2:" \
   "$(printf '[{"tag_name": "np-v1.0.0"}, {"tag_name": "np-v1.1.0", "draft": false}]' | latest_of)"
is "a trailing half release fails closed" "2:" \
   "$(printf '[{"tag_name": "np-v1.0.0", "draft": false}, {"tag_name": "np-v1.1.0"}]' | latest_of)"
is "exact tags: final" yes "$(np_tag_ok np-v1.2.3 && echo yes)"
is "exact tags: with a suffix" yes "$(np_tag_ok np-v1.2.3-rc1 && echo yes)"
is "exact tags: an old-network tag is not one" no "$(np_tag_ok v1.2.3 && echo yes || echo no)"
is "exact tags: no path tricks" no "$(np_tag_ok 'np-v1.2.3/../x' && echo yes || echo no)"

# --------------------------------------------------------------------------- 2. copies in sync
echo "2. one channel block, three copies"
python3 - "$UPDATER" "$INSTALLER" > "$TMP/copies" <<'PY'
import re, sys
pat = re.compile(r"# >>> NP_RELEASE_CHANNEL\n.*?# <<< NP_RELEASE_CHANNEL\n", re.S)
u = pat.findall(open(sys.argv[1]).read())
i = pat.findall(open(sys.argv[2]).read())
print(len(u), len(i), "same" if len(set(u + i)) == 1 else "DIFFERENT")
PY
is "updater 1, installer 2 (its own + the embedded updater), all identical" "1 2 same" "$(cat "$TMP/copies")"

# --------------------------------------------------------------------------- 3. installer
echo "3. the installer resolves GHOST_VERSION on the np- channel only"
sed -n '/^# >>> NODE_POOL_FUNCTIONS$/,/^# <<< NODE_POOL_FUNCTIONS$/p' "$INSTALLER" > "$TMP/np.sh"
list np-v1.0.0 false true '' np-v1.1.0 false true '' v1.11.46 false false '' > "$TMP/list.json"
list v1.11.46 false false '' np-v2.0.0 true true '' > "$TMP/list-none.json"
resolve() { ( GHOST_NP_RELEASES_API_URL="$2"; source "$TMP/np.sh"; np_resolve_release "$1" ) 2>&1 | tr '\n' ' ' | sed 's/ $//'; }
is "np-latest resolves to the newest np- release"  "np-v1.1.0" "$(resolve np-latest "file://$TMP/list.json")"
is "an exact np- tag is taken as given"            "np-v1.0.0" "$(resolve np-v1.0.0 "file://$TMP/list.json")"
is "an exact np- rc tag is taken as given"         "np-v1.2.0-rc1" "$(resolve np-v1.2.0-rc1 "file://$TMP/list.json")"
case "$(resolve np-latest "file://$TMP/list-none.json")" in *"no node pool release"*) r=refused;; *) r=accepted;; esac
is "np-latest with only old releases and drafts is refused" refused "$r"
case "$(resolve np-latest "file://$TMP/missing.json")" in *"could not fetch"*) r=refused;; *) r=accepted;; esac
is "np-latest with no list is refused" refused "$r"
for t in v1.11.46 1.11.46 latest np-v1.11 np-latest-ish ''; do
    case "$(resolve "$t" "file://$TMP/list.json")" in np-v*) r=accepted;; *) r=refused;; esac
    is "GHOST_VERSION='$t' is refused" refused "$r"
done
is "the installer's node pool code never asks for releases/latest" 0 \
   "$(sed -n '/^# >>> NODE_POOL_FUNCTIONS$/,/^# <<< NODE_POOL_FUNCTIONS$/p' "$INSTALLER" | $G -v '^[[:space:]]*#' | $G -c 'releases/latest' || true)"

# --------------------------------------------------------------------------- 4. the updater
echo "4. the updater follows the channel the marker names"
export GNUPGHOME="$TMP/signer"; mkdir -m700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' --quick-gen-key 'ghost test <test@invalid>' ed25519 sign never 2>/dev/null
FP="$(gpg --batch --with-colons --list-keys 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')"
gpg --batch --quiet --armor --export "$FP" > "$TMP/key.asc"
stub() { printf '#!/bin/sh\necho %s\n' "$2" > "$1"; chmod +x "$1"; }
# One release directory carrying both channels' tarballs, as the GitHub download URLs would.
REL="$TMP/rel"; mkdir -p "$REL"
for tag in v1.0.1 np-v1.0.1; do
    stage="$REL/stage-$tag/bitcoin-ghost-$tag"; mkdir -p "$stage"
    for b in ghostd ghost-mining pool_sv2 translator_sv2; do stub "$stage/$b" "$tag-$b"; done
    tar -czf "$REL/bitcoin-ghost-$tag-x86_64-unknown-linux-gnu.tar.gz" -C "$REL/stage-$tag" "bitcoin-ghost-$tag"
done
( cd "$REL" && sha256sum ./*.tar.gz | sed 's# \./# #' > SHA256SUMS.txt )
gpg --batch --quiet --yes --armor --local-user "$FP" --detach-sign -o "$REL/SHA256SUMS.txt.asc" "$REL/SHA256SUMS.txt"
unset GNUPGHOME
printf '{"tag_name": "v1.0.1"}\n' > "$TMP/latest-old.json"
printf '{"tag_name": "np-v1.0.1"}\n' > "$TMP/latest-np.json"
list np-v1.0.1 false true '' np-v1.0.0 false true '' np-v9.0.0 true true '' v1.0.1 false false '' > "$TMP/np-list.json"

cat > "$TMP/systemctl" <<'S'
#!/usr/bin/env bash
N="$FAKE_NODE"; echo "$*" >> "$N/calls"
case "$1" in
  start)          mkdir -p "$N/active"; touch "$N/active/$2" ;;
  stop)           rm -f "$N/active/$2" ;;
  is-active)      [ -e "$N/active/$2" ] && { echo active; exit 0; } || { echo inactive; exit 3; } ;;
  is-enabled)     echo enabled ;;
  list-unit-files) grep -qx "$2" "$N/units"; exit $? ;;
esac
exit 0
S
chmod +x "$TMP/systemctl"

# run_node NAME UPDATER INSTALLED MARKER LATEST_JSON — a fresh node with the full stack, one run.
# MARKER: "-" for none, else the file's content.
run_node() {
    local name="$1" updater="$2" installed="$3" marker="$4" latest="$5"
    NODE="$TMP/node-$name"; mkdir -p "$NODE/bin"
    printf '%s\n' ghostd.service ghost-mining.service sri-pool.service sri-translator.service > "$NODE/units"
    for b in ghostd ghost-mining pool_sv2 translator_sv2; do stub "$NODE/bin/$b" "old-$b"; done
    echo "$installed" > "$NODE/version"
    echo AUTO_UPDATE=true > "$NODE/auto-update.conf"
    [ "$marker" = "-" ] || printf '%s\n' "$marker" > "$NODE/release-channel"
    FAKE_NODE="$NODE" \
    GHOST_GPG_KEY_FP="$FP" \
    GHOST_RELEASE_KEY_URL="file://$TMP/key.asc" \
    GHOST_RELEASES_API_URL="file://$latest" \
    GHOST_NP_RELEASES_API_URL="file://$TMP/np-list.json" \
    GHOST_RELEASE_CHANNEL_FILE="$NODE/release-channel" \
    GHOST_RELEASE_BASE="${RUN_BASE-file://$REL}" \
    GHOST_RELEASE_DOWNLOAD_URL="${RUN_DOWNLOAD_URL:-https://invalid.example/download}" \
    GHOST_AUTOUPDATE_CONF="$NODE/auto-update.conf" \
    GHOST_VERSION_FILE="$NODE/version" \
    GHOST_AUTOUPDATE_STATUS="$NODE/status.json" \
    GHOST_BIN_DIR="$NODE/bin" \
    GHOST_SYSTEMCTL="$TMP/systemctl" \
    GHOST_HEALTHCHECK_OVERRIDE="exit 0" \
        bash "$updater" > "$NODE/out" 2>&1
    echo $? > "$NODE/rc"
}
field()  { sed -n "s/.*\"$1\": \"\\([^\"]*\\)\".*/\\1/p" "$NODE/status.json"; }
bins()   { local b o=""; for b in ghostd ghost-mining pool_sv2 translator_sv2; do o="$o $("$NODE/bin/$b")"; done; echo "${o# }"; }
OLD_BINS="old-ghostd old-ghost-mining old-pool_sv2 old-translator_sv2"

echo " a. a node pool node follows np- and never the old network's latest"
run_node a "$UPDATER" np-v1.0.0 node-pool "$TMP/latest-old.json"
is "exits 0"                    0 "$(cat "$NODE/rc")"
is "updated to the newest published np- release (not the np-v9 draft, not v1.0.1)" np-v1.0.1 "$(cat "$NODE/version")"
is "the whole set is the np- build" "np-v1.0.1-ghostd np-v1.0.1-ghost-mining np-v1.0.1-pool_sv2 np-v1.0.1-translator_sv2" "$(bins)"
is "status names the channel"   node-pool "$(field channel)"
is "status latest"              np-v1.0.1 "$(field latest_version)"

echo " b. ... and is up to date when it runs the newest np- release"
run_node b "$UPDATER" np-v1.0.1 node-pool "$TMP/latest-old.json"
is "exits 0"   0          "$(cat "$NODE/rc")"
is "status"    up-to-date "$(field result)"
is "untouched" "$OLD_BINS" "$(bins)"

echo " b2. without GHOST_RELEASE_BASE, assets are fetched from <download URL>/<tag>/ (GitHub's layout)"
DL="$TMP/dl"; mkdir -p "$DL/np-v1.0.1"
cp "$REL"/*.tar.gz "$REL"/SHA256SUMS.txt "$REL"/SHA256SUMS.txt.asc "$DL/np-v1.0.1/"
RUN_BASE="" RUN_DOWNLOAD_URL="file://$DL" run_node b2 "$UPDATER" np-v1.0.0 node-pool "$TMP/latest-old.json"
is "exits 0"                  0 "$(cat "$NODE/rc")"
is "updated from the tag's directory" np-v1.0.1 "$(cat "$NODE/version")"
is "the whole set is the np- build" "np-v1.0.1-ghostd np-v1.0.1-ghost-mining np-v1.0.1-pool_sv2 np-v1.0.1-translator_sv2" "$(bins)"
is "a key other than the release key is warned about, once" 1 "$($G -c 'TEST RELEASE MIRROR' "$NODE/out" || true)"

echo " c. an install without the marker is updated exactly as before the channel existed"
if git -C "$REPO_ROOT" show "$BASELINE_REF:scripts/ghost-auto-update.sh" > "$TMP/updater-before.sh" 2>/dev/null; then
    run_node c-before "$TMP/updater-before.sh" v1.0.0 - "$TMP/latest-old.json"
    before="rc=$(cat "$NODE/rc") ver=$(cat "$NODE/version") bins=$(bins) result=$(field result) calls=$(paste -sd' ' "$NODE/calls")"
    run_node c "$UPDATER" v1.0.0 - "$TMP/latest-old.json"
    after="rc=$(cat "$NODE/rc") ver=$(cat "$NODE/version") bins=$(bins) result=$(field result) calls=$(paste -sd' ' "$NODE/calls")"
    is "same exit, version, binaries, status and systemctl calls as the updater at $BASELINE_REF" "$before" "$after"
else
    echo "  [BAD] $BASELINE_REF is not in this clone; cannot compare against the updater before the channel"
    fail=$((fail+1))
    run_node c "$UPDATER" v1.0.0 - "$TMP/latest-old.json"
fi
is "it took the old network's latest"   v1.0.1 "$(cat "$NODE/version")"
is "status names the channel"           old-network "$(field channel)"
is "the np- list was never consulted"   0 "$($G -c 'np-' "$NODE/out" || true)"

echo " d. a node pool build without the marker is refused, untouched"
run_node d "$UPDATER" np-v1.0.0 - "$TMP/latest-old.json"
is "exits 1"         1     "$(cat "$NODE/rc")"
is "status"          error "$(field result)"
is "binaries"        "$OLD_BINS" "$(bins)"
is "nothing stopped" 0     "$(cat "$NODE/calls" 2>/dev/null | $G -c '^stop' || true)"
is "version file"    np-v1.0.0 "$(cat "$NODE/version")"

echo " e. a marker that says anything else is refused, untouched"
run_node e "$UPDATER" np-v1.0.0 "old-network" "$TMP/latest-old.json"
is "exits 1"   1     "$(cat "$NODE/rc")"
is "says why"  1     "$($G -c "expected 'node-pool'" "$NODE/out" || true)"
is "binaries"  "$OLD_BINS" "$(bins)"

echo " f. an old-network node whose latest is an np- release is refused, untouched"
run_node f "$UPDATER" v1.0.0 - "$TMP/latest-np.json"
is "exits 1"   1     "$(cat "$NODE/rc")"
is "says why"  1     "$($G -c 'is a node pool release' "$NODE/out" || true)"
is "binaries"  "$OLD_BINS" "$(bins)"
is "version"   v1.0.0 "$(cat "$NODE/version")"

echo " g. a node pool node with no np- release published is refused, untouched"
list v1.0.1 false false '' np-v1.0.1 true true '' > "$TMP/np-list.json"
run_node g "$UPDATER" np-v1.0.0 node-pool "$TMP/latest-old.json"
is "exits 1"   1     "$(cat "$NODE/rc")"
is "says why"  1     "$($G -c 'no published node pool release' "$NODE/out" || true)"
is "binaries"  "$OLD_BINS" "$(bins)"

echo " h. a marker with comments, as the installer writes it, is read"
printf '# Bitcoin Ghost release channel.\n# node-pool: follow np-.\nnode-pool\n' > "$TMP/marker"
is "channel" node-pool "$( ( NP_CHANNEL_FILE="$TMP/marker"; np_channel ) )"
is "no marker is the old network" old-network "$( ( NP_CHANNEL_FILE="$TMP/absent"; np_channel ) )"
is "the installer writes that marker" node-pool \
   "$(awk '/^cat > \/etc\/ghost\/release-channel <</{on=1;next} on&&/^GHOST_RELEASE_CHANNEL_EOF$/{exit} on' "$INSTALLER" > "$TMP/written"; ( NP_CHANNEL_FILE="$TMP/written"; np_channel ) )"

# --------------------------------------------------------------------------- 5. the toggle
echo "5. the dashboard toggle follows the marker and never writes it"
toggle() {   # DIR MARKER ARG
    mkdir -p "$1"; rm -f "$1/release-channel" "$1/auto-update.conf"
    echo AUTO_UPDATE=false > "$1/auto-update.conf"
    [ "$2" = "-" ] || printf '%s\n' "$2" > "$1/release-channel"
    GHOST_AUTOUPDATE_CONF="$1/auto-update.conf" GHOST_RELEASE_CHANNEL_FILE="$1/release-channel" \
        GHOST_SYSTEMCTL=true bash "$TOGGLE" "$3" 2>&1; echo "rc=$?"
}
out="$(toggle "$TMP/t1" node-pool on)"
is "on, node pool node"      "auto-update set to true (release channel: node-pool) rc=0" "$(echo $out)"
is "... marker untouched"    node-pool "$(cat "$TMP/t1/release-channel")"
out="$(toggle "$TMP/t2" - on)"
is "on, old-network node"    "auto-update set to true (release channel: old-network) rc=0" "$(echo $out)"
is "... no marker created"   no "$([ -e "$TMP/t2/release-channel" ] && echo yes || echo no)"
out="$(toggle "$TMP/t3" bogus on)"
is "on under a bad marker is refused" "rc=1" "$(echo "$out" | tail -1)"
is "... and the opt-in is unchanged"  AUTO_UPDATE=false "$(cat "$TMP/t3/auto-update.conf")"
out="$(toggle "$TMP/t4" bogus off)"
is "off is always allowed"   "rc=0" "$(echo "$out" | tail -1)"

echo
echo "test-release-channel: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
