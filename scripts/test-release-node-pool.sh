#!/usr/bin/env bash
#
# Self-test for `release.sh --node-pool`: the node pool release channel's orchestration.
#
# A node pool release is tagged np-v<version>, published as a PRE-release with make_latest=false,
# and must leave GitHub's `releases/latest` where it was: every old-network node updates from it.
# Asserted:
#   1. the phases are check, gates, build, tag — no roll phase, and none can be asked for;
#   2. `check` records the node pool branch's SHA and refuses a version the branch does not carry;
#   3. `tag` publishes as a pre-release with make_latest=false, reads the outcome back, and refuses
#      when the pre-release flag did not stick, when `latest` moved, or when `latest` already was
#      a node pool release; a positive control publishes;
#   4. the no-workflow fallback's draft is a pre-release from birth;
#   5. the old channel's mode is untouched (scripts/test-release-orchestrator.sh runs it).
#
# Nothing here touches a node or the real GitHub: `gh` is stubbed and the repos are throwaways.
# Usage: scripts/test-release-node-pool.sh
set -uo pipefail

SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
G=/usr/bin/grep

pass=0; fail=0
is() { if [ "$2" = "$3" ]; then printf "  [ok ] %s\n" "$1"; pass=$((pass+1));
       else printf "  [BAD] %s\n        wanted: %s\n        got:    %s\n" "$1" "$2" "$3"; fail=$((fail+1)); fi; }
yes_if() { if eval "$2"; then is "$1" yes yes; else is "$1" yes no; fi; }

mkdir -p "$TMP/bin" "$TMP/state"

# A node pool branch on a throwaway origin, at version 9.9.9.
git init -q --bare "$TMP/origin.git"
REPO="$TMP/repo"
mkdir -p "$REPO/scripts"
cp "$SRC_ROOT/scripts/release.sh" "$REPO/scripts/release.sh"
( cd "$REPO"
  git init -q . && git config user.email t@t && git config user.name t
  git checkout -q -b feat/node-pool
  printf '[workspace.package]\nversion = "9.9.9"\n' > Cargo.toml
  git add -A && git commit -qm init
  git remote add origin "$TMP/origin.git"
  git push -q origin feat/node-pool ) >/dev/null 2>&1
SHA="$(cd "$REPO" && git rev-parse HEAD)"

rs() { ( cd "$REPO" && PATH="$TMP/bin:$PATH" GHOST_RELEASE_STATE="$TMP/state" ./scripts/release.sh "$@" 2>&1 ); }

echo "1. the node pool channel has no roll phase"
echo "$SHA" > "$TMP/state/np-v9.9.9.sha"   # a dry run of `check` records nothing; later phases need one
out="$(rs --node-pool 9.9.9 --dry-run)"
is "phases run: check, gates, build, tag" \
   "=== node pool release np-v9.9.9 from feat/node-pool ===|=== gates on the merged SHA ===|=== build every shipped binary at 9.9.9 ===|=== tag and publish np-v9.9.9 ===" \
   "$(printf '%s\n' "$out" | $G '^===' | $G -v released | paste -sd'|')"
is "the node pool artefact set is what it builds" 1 \
   "$(printf '%s\n' "$out" | $G -c 'would build: pool_sv2 ghost-mining translator_sv2 ghost-admin ghost-audit$' || true)"
is "no old-fleet node is named" 0 "$(printf '%s\n' "$out" | $G -c 'ghost-vm' || true)"
is "the tag is np-v" 1 "$(printf '%s\n' "$out" | $G -c 'would tag np-v9.9.9' || true)"
for p in canary soak production node bump pr; do
    out="$(rs --node-pool 9.9.9 --from "$p" --dry-run)"
    is "--from $p is refused" 1 "$(printf '%s\n' "$out" | $G -c "unknown phase '$p'" || true)"
done
yes_if "roll_node and roll_ghostd refuse on the node pool channel" \
  '[ "$($G -A1 -E "^roll_(node|ghostd)\(\) \{" "$SRC_ROOT/scripts/release.sh" | $G -c refuse_roll_on_node_pool)" = 2 ]'

echo "2. check records the node pool branch and its version"
rm -f "$TMP/state/np-v9.9.9.sha"
out="$(rs --node-pool 9.9.9 --from check)"; rc=$?
# Only `check` is under test: gates would need record-tests.sh. It is expected to stop there.
is "the SHA recorded is the node pool branch's" "$SHA" "$(cat "$TMP/state/np-v9.9.9.sha" 2>/dev/null)"
out="$(rs --node-pool 9.9.8 --from check)"; rc=$?
is "a version the branch does not carry is refused" "1:1" "$rc:$(printf '%s\n' "$out" | $G -c 'is at version 9.9.9, not 9.9.8' || true)"
is "... and records nothing" no "$([ -e "$TMP/state/np-v9.9.8.sha" ] && echo yes || echo no)"

echo "3. tag publishes a pre-release and leaves latest alone"
( cd "$REPO" && git tag -a np-v9.9.9 -m np-v9.9.9 )
echo "$SHA" > "$TMP/state/np-v9.9.9.sha"
cat > "$TMP/bin/gh" <<'GH_STUB'
#!/usr/bin/env bash
S="$GH_STATE"
get() { $G_ -E "^$1=" "$S" | tail -1 | cut -d= -f2; }
G_=/usr/bin/grep
case "$*" in
  *"-X PATCH"*)
      echo "PATCH $*" >> "$GH_CALLS"
      case "$*" in *"tag_name=np-v9.9.9"*) : ;; *) echo "tagname=DETACHED" >> "$S" ;; esac
      [ "${GH_PUBLISH_WORKS:-1}" = 1 ] && echo "draft=false" >> "$S"
      case "$*" in *"prerelease=true"*) [ "${GH_PRERELEASE_STICKS:-1}" = 1 ] && echo "prerelease=true" >> "$S" ;; esac
      [ "${GH_LATEST_MOVES:-0}" = 1 ] && echo "latest=np-v9.9.9" >> "$S"
      exit 0 ;;
  *"releases/latest"*) get latest; exit 0 ;;
  *"actions/runs?per_page"*) printf '%s' "${GH_RUN_STATE-}"; [ -n "${GH_RUN_STATE-}" ] && echo; exit 0 ;;
  *releases\?per_page*) [ "${GH_NO_RELEASE:-0}" = 1 ] || echo 4242; exit 0 ;;
  *".assets|length"*) echo 5; exit 0 ;;
  *".assets[].name"*) printf '%s\n' bitcoin-ghost-np-v9.9.9-x86_64-unknown-linux-gnu.tar.gz \
        bitcoin-ghost-np-v9.9.9-x86_64-apple-darwin.tar.gz bitcoin-ghost-np-v9.9.9-aarch64-apple-darwin.tar.gz \
        SHA256SUMS.txt SHA256SUMS.txt.asc; exit 0 ;;
  *releases/4242*jq*draft*)      get draft; exit 0 ;;
  *releases/4242*jq*prerelease*) get prerelease; exit 0 ;;
  *releases/4242*jq*tag_name*)   get tagname; exit 0 ;;
  "release create"*) echo "CREATE $*" >> "$GH_CALLS"; exit 0 ;;
esac
exit 0
GH_STUB
chmod +x "$TMP/bin/gh"

tag_phase() {   # env: the GH_* knobs
    printf 'draft=true\nprerelease=%s\ntagname=np-v9.9.9\nlatest=%s\n' "${PRE0:-true}" "${LATEST0:-v1.11.46}" > "$TMP/gh_state"
    : > "$TMP/gh_calls"
    ( cd "$REPO" && PATH="$TMP/bin:$PATH" GH_STATE="$TMP/gh_state" GH_CALLS="$TMP/gh_calls" \
        GHOST_RELEASE_STATE="$TMP/state" TAG_RELEASE_WAIT_SECS=2 TAG_RELEASE_MAX_SECS=3 TAG_RELEASE_POLL_SECS=1 \
        ./scripts/release.sh --node-pool 9.9.9 --from tag 2>&1 )
}

out="$(tag_phase)"; rc=$?
is "positive control: publishes" 0 "$rc"
patch="$(cat "$TMP/gh_calls")"
for want in "tag_name=np-v9.9.9" "draft=false" "prerelease=true" "make_latest=false" "name=Node pool np-v9.9.9"; do
    is "the publish PATCH sends $want" 1 "$(printf '%s\n' "$patch" | $G -cF -- "$want" || true)"
done
is "make_latest is the API's string, not a boolean (-f, not -F)" 1 "$(printf '%s\n' "$patch" | $G -cF -- '-f make_latest=false' || true)"
is "never make_latest=true" 0 "$(printf '%s\n' "$patch" | $G -c 'make_latest=true' || true)"
is "says latest stayed put" 1 "$(printf '%s\n' "$out" | $G -c 'releases/latest still v1.11.46' || true)"

out="$(PRE0=false GH_PRERELEASE_STICKS=0 tag_phase)"; rc=$?
is "a pre-release flag that did not stick is refused" "1:1" "$rc:$(printf '%s\n' "$out" | $G -c 'NOT a pre-release' || true)"

out="$(GH_LATEST_MOVES=1 tag_phase)"; rc=$?
is "latest moving to the node pool release is refused" "1:1" "$rc:$(printf '%s\n' "$out" | $G -c 'releases/latest became np-v9.9.9' || true)"

out="$(LATEST0=np-v9.9.8 tag_phase)"; rc=$?
is "latest already a node pool release is refused" "1:1" "$rc:$(printf '%s\n' "$out" | $G -c 'already a node pool release' || true)"
is "... before anything is published" 0 "$($G -c PATCH "$TMP/gh_calls" || true)"

out="$(PRE0=false tag_phase)"; rc=$?
is "a published release that lost its pre-release flag is put back" "0:1" "$rc:$($G -c 'prerelease=true' "$TMP/gh_calls" || true)"

echo "4. the no-workflow fallback makes a pre-release draft"
out="$(GH_NO_RELEASE=1 GH_RUN_STATE= tag_phase)"; rc=$?
is "it refuses (a human decides)" 1 "$rc"
is "its draft is a pre-release" 1 "$($G -c 'CREATE release create np-v9.9.9 .*--draft --prerelease' "$TMP/gh_calls" || true)"

echo
echo "test-release-node-pool: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
