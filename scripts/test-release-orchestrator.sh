#!/usr/bin/env bash
#
# Self-test for release.sh's ORDERING and its PUBLISH step.
#
# Both cases here are regressions that actually shipped, in the same release (v1.11.38):
#
#   * `phase_tag` printed "published v1.11.38" and exited 0 while the release was still a DRAFT.
#     `gh release view` succeeds for a draft, so "a release exists" was treated as "it is
#     published" and the publish was never attempted. Its outcome check compared
#     `gh release list | awk '{print $1}'` to the tag — which MATCHED, because the draft row is
#     the newest row. It read the right row and the wrong field. Net effect: the fleet ran
#     1.11.38 while the newest published release still described 1.11.37, which is precisely the
#     mismatch `phase_tag` exists to prevent (#857).
#
#   * `PRODUCTION_NODES` listed ghost-vm1 FIRST. vm1 is genesis and must be last — CLAUDE.md says
#     so, and the ghostd loop in the same file said so in a comment and did it correctly, so the
#     file disagreed with itself. Worse, `deploy-node.sh` makes the FIRST production node the lone
#     canary for ghost-pay/ghost-gsp, so genesis carried an unsoaked binary by itself for 62
#     minutes (#856).
#
# Nothing here touches a node or the real GitHub: `gh` is stubbed and the repo is a throwaway.
#
# Usage: scripts/test-release-orchestrator.sh
set -uo pipefail

SRC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok()   { printf '[ok ] %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '[FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }

# Built up front, not beside the case that first needs them: every phase calls `require_sha`, so
# a state dir created later makes the ordering case fail on a missing SHA rather than on the
# ordering, and a missing stub dir makes the publish case fail on `gh release create` rather than
# on the publish. Both happened while writing this — each read as a real result.
mkdir -p "$TMP/bin" "$TMP/state"

# ---------------------------------------------------------------- ordering
#
# Driven through `--dry-run`, which prints the roll order it WOULD use, rather than by grepping
# the constant. The bug was that two orderings existed in one file and drifted apart, so the
# assertion has to be on what the phase would actually do.

# The REAL origin/main sha: every roll phase calls `assert_sha_still_current` first, so a bogus
# one dies on the SHA gate and the ordering assertion never runs.
( cd "$SRC_ROOT" && git rev-parse origin/main ) > "$TMP/state/v9.9.9.sha" 2>/dev/null
order_out="$( cd "$SRC_ROOT" && GHOST_RELEASE_STATE="$TMP/state" \
              ./scripts/release.sh 9.9.9 --from production --dry-run 2>&1 )"
prod_line="$(printf '%s\n' "$order_out" | grep -m1 'would roll .* to ghost-vm' || true)"

if [ -z "$prod_line" ]; then
    bad "production dry-run printed no roll order (got: $(printf '%s' "$order_out" | tail -1))"
else
    nodes="$(printf '%s\n' "$prod_line" | grep -oE 'ghost-vm[0-9]' | awk '!seen[$0]++' | tr '\n' ' ')"
    first="${nodes%% *}"
    last="$(printf '%s\n' "$nodes" | awk '{print $NF}')"
    [ "$last" = "ghost-vm1" ] \
        && ok "production roll ends with genesis (order: $nodes)" \
        || bad "production roll must END with ghost-vm1, got order: $nodes"
    [ "$first" != "ghost-vm1" ] \
        && ok "genesis is not the first production node, so it is not the lone ghost-pay canary" \
        || bad "ghost-vm1 is FIRST, so genesis soaks ghost-pay/ghost-gsp alone (#856)"
fi

# One ordering, not two. The drift is the root cause: a second hardcoded node list is how the
# ghostd loop stayed right while PRODUCTION_NODES went wrong.
stray="$(grep -nE '^[^#]*ghost-vm[0-9].*ghost-vm[0-9]' "$SRC_ROOT/scripts/release.sh" \
         | grep -vE '^[0-9]+:(CANARY_NODES|PRODUCTION_NODES)=' || true)"
[ -z "$stray" ] \
    && ok "no second hardcoded node list — order is derived from the two constants" \
    || bad "a second hardcoded node list can drift from the constants:"$'\n'"$stray"

# ---------------------------------------------------------------- publish
#
# A hermetic repo with the tag already present, so phase_tag goes straight to publishing and
# never pushes anything.

REPO="$TMP/repo"
mkdir -p "$REPO/scripts"
cp "$SRC_ROOT/scripts/release.sh" "$REPO/scripts/release.sh"
( cd "$REPO"
  git init -q .
  git config user.email t@t; git config user.name t
  git add -A >/dev/null; git commit -qm init
  git tag -a v9.9.9 -m v9.9.9 ) >/dev/null 2>&1

SHA="$( cd "$REPO" && git rev-parse HEAD )"
printf '%s\n' "$SHA" > "$TMP/state/v9.9.9.sha"

# `gh` stub. Backed by a state file so a PATCH can actually change what a later read returns —
# the point of the test is that the script READS THE OUTCOME BACK, so a stub that always claims
# success would make the assertion meaningless.
cat > "$TMP/bin/gh" <<'GH_STUB'
#!/usr/bin/env bash
S="$GH_STATE"
case "$*" in
  *"-X PATCH"*)
      echo "PATCH $*" >> "$GH_CALLS"
      # Honour tag_name so the detach case is representable.
      case "$*" in *"tag_name=v9.9.9"*) : ;; *) echo "tagname=DETACHED" >> "$S" ;; esac
      # GH_PUBLISH_WORKS=0 models the real trap: the call SUCCEEDS and changes nothing.
      [ "${GH_PUBLISH_WORKS:-1}" = "1" ] && echo "draft=false" >> "$S"
      exit 0 ;;
  *releases\?per_page*)  echo 4242; exit 0 ;;
  *releases/4242*jq*draft*)     grep -E '^draft=' "$S"    | tail -1 | cut -d= -f2; exit 0 ;;
  *releases/4242*jq*tag_name*)  grep -E '^tagname=' "$S"  | tail -1 | cut -d= -f2; exit 0 ;;
  "release view"*)   exit 0 ;;
  "release list"*)   echo "v9.9.9	Draft	v9.9.9	2026-01-01"; exit 0 ;;
  "release create"*) exit 0 ;;
esac
exit 0
GH_STUB
chmod +x "$TMP/bin/gh"

run_tag_phase() {   # $1 = GH_PUBLISH_WORKS
    printf 'draft=true\ntagname=v9.9.9\n' > "$TMP/gh_state"
    : > "$TMP/gh_calls"
    ( cd "$REPO" && PATH="$TMP/bin:$PATH" \
        GH_STATE="$TMP/gh_state" GH_CALLS="$TMP/gh_calls" GH_PUBLISH_WORKS="$1" \
        GHOST_RELEASE_STATE="$TMP/state" \
        ./scripts/release.sh 9.9.9 --from tag 2>&1 )
}

out="$(run_tag_phase 1)"; rc=$?
if grep -q 'PATCH' "$TMP/gh_calls" 2>/dev/null; then
    ok "a DRAFT release is actually published (the PATCH is issued)"
else
    bad "no publish attempted — a draft was treated as already published (#857)"
fi
grep -q 'tag_name=v9.9.9' "$TMP/gh_calls" 2>/dev/null \
    && ok "the publish PATCH carries tag_name, so the release cannot detach from its tag" \
    || bad "publish PATCH omitted tag_name — this detaches the release from its tag"
[ $rc -eq 0 ] \
    && ok "a successful publish exits 0" \
    || bad "publish that worked still failed the phase (rc=$rc): $(printf '%s' "$out" | tail -1)"

# The regression guard: the publish call succeeds and changes nothing, exactly as
# `gh release edit --draft=false` does. The phase MUST NOT report success.
out="$(run_tag_phase 0)"; rc=$?
if [ $rc -ne 0 ] && ! printf '%s' "$out" | grep -qE '^  published'; then
    ok "a publish that silently did nothing FAILS the phase instead of reporting success"
else
    bad "phase reported success while the release was still a DRAFT (rc=$rc) — #857 regression"
fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "All release-orchestrator checks passed: production ends at genesis, one ordering not two, and the publish is verified by reading the draft state back rather than trusting an exit code."
