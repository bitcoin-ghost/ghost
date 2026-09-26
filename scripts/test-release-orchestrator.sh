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
#
# ⚠ That gate RE-FETCHES and compares against live `origin/main` (`release.sh:175-180`), while
# this records the sha once. If anything touching `bins/` or `crates/` merges in between, the gate
# refuses — correctly — and the dry-run prints a refusal instead of a roll order.
#
# That made main red for a merge that was fine (#930): the failure read "printed no roll order",
# which points at the ordering logic, when the real cause was `origin/main` moving mid-run. The
# gate was doing its job; the TEST was measuring a moving target.
#
# So: retry on exactly that refusal, re-recording the sha each time. This keeps the ordering
# assertion intact — the alternative of accepting a refusal as a pass would make the test green
# while checking nothing, which is the failure mode this file exists to avoid. A refusal that
# persists across attempts is still a failure, and is reported as the SHA race rather than as
# missing output.
SHA_RACE_MARKER='no longer matches origin/main'
order_out=""
prod_line=""
for attempt in 1 2 3; do
    ( cd "$SRC_ROOT" && git rev-parse origin/main ) > "$TMP/state/v9.9.9.sha" 2>/dev/null
    order_out="$( cd "$SRC_ROOT" && GHOST_RELEASE_STATE="$TMP/state" \
                  ./scripts/release.sh 9.9.9 --from production --dry-run 2>&1 )"
    prod_line="$(printf '%s\n' "$order_out" | grep -m1 'would roll .* to ghost-vm' || true)"
    [ -n "$prod_line" ] && break
    if printf '%s\n' "$order_out" | grep -qF "$SHA_RACE_MARKER"; then
        echo "  .. attempt $attempt: origin/main moved mid-run, re-reading the sha and retrying"
        ( cd "$SRC_ROOT" && git fetch -q origin 2>/dev/null ) || true
        continue
    fi
    break   # a refusal for any OTHER reason is a real failure; stop and report it
done

if [ -z "$prod_line" ]; then
    if printf '%s\n' "$order_out" | grep -qF "$SHA_RACE_MARKER"; then
        bad "origin/main kept moving across 3 attempts, so the ordering assertion never ran \
(this is the #931 race, not an ordering fault)"
    else
        bad "production dry-run printed no roll order (got: $(printf '%s' "$order_out" | tail -1))"
    fi
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
  *"actions/runs?per_page"*)
      # Model the release.yml RUN for this tag. Empty output = no run exists at all, which is
      # the genuinely-no-workflow case. Otherwise "status:conclusion", e.g. "in_progress:" or
      # "completed:failure".
      printf '%s' "${GH_RUN_STATE-}"; [ -n "${GH_RUN_STATE-}" ] && echo
      exit 0 ;;
  *releases\?per_page*)
      # Model release.yml: the tag push creates the release ASYNCHRONOUSLY, so the first
      # $GH_RELEASE_APPEARS_AFTER lookups find nothing. A release we minted ourselves is
      # visible immediately.
      n=$(( $(cat "$GH_LOOKUPS" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$GH_LOOKUPS"
      if [ -f "$GH_CREATED" ] || [ "$n" -gt "${GH_RELEASE_APPEARS_AFTER:-0}" ]; then echo 4242; fi
      exit 0 ;;
  # ⚠ `|` and `[]` are glob metacharacters in a case pattern — quoted so they match literally.
  *".assets|length"*)
      # A release WE minted carries no artefacts — the count must agree with the name list
      # below, or a mutation can hide behind the two disagreeing.
      [ -f "$GH_CREATED" ] && { echo 0; exit 0; }
      echo "${GH_ASSETS:-5}"; exit 0 ;;
  *".assets[].name"*)
      # A release we minted ourselves has NO assets, whatever GH_ASSETS says.
      [ -f "$GH_CREATED" ] && exit 0
      i=0; while [ "$i" -lt "${GH_ASSETS:-5}" ]; do
          case $i in
            0) echo "bitcoin-ghost-v9.9.9-x86_64-unknown-linux-gnu.tar.gz" ;;
            1) echo "bitcoin-ghost-v9.9.9-x86_64-apple-darwin.tar.gz" ;;
            2) echo "bitcoin-ghost-v9.9.9-aarch64-apple-darwin.tar.gz" ;;
            3) echo "SHA256SUMS.txt" ;;
            4) [ "${GH_SIGNED:-1}" = "1" ] && echo "SHA256SUMS.txt.asc" || echo "extra.txt" ;;
            *) echo "extra$i.txt" ;;
          esac; i=$((i+1)); done
      exit 0 ;;
  *releases/4242*jq*draft*)     grep -E '^draft=' "$S"    | tail -1 | cut -d= -f2; exit 0 ;;
  *releases/4242*jq*tag_name*)  grep -E '^tagname=' "$S"  | tail -1 | cut -d= -f2; exit 0 ;;
  "release view"*)   exit 0 ;;
  "release list"*)   echo "v9.9.9	Draft	v9.9.9	2026-01-01"; exit 0 ;;
  "release create"*) echo "CREATE $*" >> "$GH_CALLS"; echo created > "$GH_CREATED"; exit 0 ;;
esac
exit 0
GH_STUB
chmod +x "$TMP/bin/gh"

run_tag_phase() {   # $1 = GH_PUBLISH_WORKS
    printf 'draft=true\ntagname=v9.9.9\n' > "$TMP/gh_state"
    : > "$TMP/gh_calls"
    : > "$TMP/gh_lookups"
    rm -f "$TMP/gh_created"
    ( cd "$REPO" && PATH="$TMP/bin:$PATH" \
        GH_STATE="$TMP/gh_state" GH_CALLS="$TMP/gh_calls" GH_PUBLISH_WORKS="$1" \
        GH_LOOKUPS="$TMP/gh_lookups" GH_CREATED="$TMP/gh_created" \
        GH_RELEASE_APPEARS_AFTER="${GH_RELEASE_APPEARS_AFTER:-0}" \
        GH_RUN_STATE="${GH_RUN_STATE-}" GH_ASSETS="${GH_ASSETS:-5}" GH_SIGNED="${GH_SIGNED:-1}" \
        TAG_RELEASE_MAX_SECS="${TAG_RELEASE_MAX_SECS:-4}" \
        GHOST_RELEASE_STATE="$TMP/state" \
        TAG_RELEASE_WAIT_SECS="${TAG_RELEASE_WAIT_SECS:-5}" TAG_RELEASE_POLL_SECS=1 \
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

# ---------------------------------------------------------------- the release.yml race
#
# The tag push TRIGGERS release.yml, and that workflow creates the release. Looking exactly once
# therefore refuses a release that is merely still being made: v1.11.42 died on a three-second
# miss, after all eight nodes were already running it. It had only ever worked because the tag
# had been pushed by an earlier aborted run, so the release already existed.

out="$(GH_RELEASE_APPEARS_AFTER=3 run_tag_phase 1)"; rc=$?
if [ $rc -eq 0 ] && grep -q 'PATCH' "$TMP/gh_calls" 2>/dev/null; then
    ok "a release release.yml is still creating is waited for, then published"
else
    bad "refused a release the workflow was still creating (rc=$rc): $(printf '%s' "$out" | tail -1)"
fi

# ⚠ The assertion above is NOT enough on its own, and a mutation proved it: with the wait removed
# the phase still exits 0, because it falls through and mints its OWN release. That is not a pass
# — it is how you end up publishing a release with no tarballs and no signed SHA256SUMS while the
# workflow quietly finishes building the real one. So pin that we waited rather than raced.
if [ -f "$TMP/gh_created" ]; then
    bad "minted a rival release while release.yml was still creating one — the published \
release would carry no assets"
else
    ok "the workflow's release is waited for, not replaced by one of ours (assets survive)"
fi

# ⛔ BEHAVIOUR CHANGED (#909). This case used to assert that when no release appears the phase
# "stops waiting and creates it" — and PUBLISHES it. That is precisely the bug: on 2026-09-20 the
# 600s timer expired against a ~19-minute workflow and published an EMPTY v1.11.43 as Latest.
# A release with no artefacts must never be published, so the no-workflow path now creates a
# DRAFT and refuses, leaving a human to decide.
out="$(GH_RELEASE_APPEARS_AFTER=9999 GH_RUN_STATE= run_tag_phase 1)"; rc=$?
# ⚠ Assert NO PUBLISH WAS ATTEMPTED. Checking only rc!=0 is not enough: a later guard (the
# signature check) also refuses here, so the case would pass even if this path went back to
# publishing. The discriminating fact is that no PATCH was ever issued.
if [ $rc -ne 0 ] && grep -q 'CREATE.*--draft' "$TMP/gh_calls" 2>/dev/null && ! grep -q 'PATCH' "$TMP/gh_calls" 2>/dev/null; then
    ok "no release workflow at all: a DRAFT is created and the phase REFUSES, never publishing it"
else
    bad "no-workflow path attempted a publish or did not refuse (rc=$rc, patched=$(grep -qc 'PATCH' "$TMP/gh_calls" 2>/dev/null || echo 0)): $(printf '%s' "$out" | tail -1)"
fi

# ---------------------------------------------------------------- #909: the empty release
#
# The failure this file exists to prevent now has its own cases. Each one is a state in which the
# OLD code exited 0 having published something wrong.

# 1. The workflow is still building and the backstop timer has long expired. The phase must keep
#    waiting on the RUN, not fall through to minting a rival release.
out="$(GH_RELEASE_APPEARS_AFTER=9999 GH_RUN_STATE=in_progress: TAG_RELEASE_WAIT_SECS=2 TAG_RELEASE_MAX_SECS=4 run_tag_phase 1)"; rc=$?
if [ ! -f "$TMP/gh_created" ] && [ $rc -ne 0 ]; then
    ok "a still-building release.yml is waited for even past the backstop timer — no rival release"
else
    bad "minted a release while release.yml was still building (#909): rc=$rc created=$([ -f "$TMP/gh_created" ] && echo yes || echo no)"
fi

# 2. The workflow FAILED. Publishing anything here hides a broken build behind a green release.
out="$(GH_RELEASE_APPEARS_AFTER=9999 GH_RUN_STATE=completed:failure run_tag_phase 1)"; rc=$?
if [ $rc -ne 0 ] && ! [ -f "$TMP/gh_created" ]; then
    ok "a FAILED release.yml refuses the phase and mints no substitute release"
else
    bad "a failed build did not stop the release (rc=$rc)"
fi

# 3. The release exists but carries NO assets — the exact end state of the #909 incident.
# ⚠ Assert the ASSET-COUNT reason by name. A bare "it refused" passes even with the count check
# deleted, because the signature check refuses this input too — a mutation proved exactly that.
out="$(GH_ASSETS=0 run_tag_phase 1)"; rc=$?
if [ $rc -ne 0 ] && printf '%s' "$out" | grep -q 'assets, want >=' && ! grep -q 'PATCH' "$TMP/gh_calls" 2>/dev/null; then
    ok "a release with zero assets is REFUSED by the asset-count check, before any publish (#909)"
else
    bad "zero-asset release not refused by the count check (rc=$rc) — #909 regression: $(printf '%s' "$out" | tail -1)"
fi

# 4. Assets present but UNSIGNED. The signature is the point of the release; its absence must not
#    be inferable only from a count.
out="$(GH_ASSETS=5 GH_SIGNED=0 run_tag_phase 1)"; rc=$?
if [ $rc -ne 0 ] && printf '%s' "$out" | grep -q 'SHA256SUMS.txt.asc'; then
    ok "a release without SHA256SUMS.txt.asc is REFUSED as unsigned"
else
    bad "published an unsigned release (rc=$rc)"
fi

# 5. POSITIVE CONTROL. Every case above asserts a refusal, and a phase that refused everything
#    would pass all of them. A correct, signed, fully-built release must still publish.
out="$(GH_ASSETS=5 GH_SIGNED=1 GH_RUN_STATE=completed:success run_tag_phase 1)"; rc=$?
if [ $rc -eq 0 ] && printf '%s' "$out" | grep -qE '^  published .* assets=5'; then
    ok "a correct signed release with all 5 assets still publishes (positive control)"
else
    bad "refused a perfectly good release (rc=$rc): $(printf '%s' "$out" | tail -1)"
fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "All release-orchestrator checks passed: production ends at genesis, one ordering not two, and the publish is verified by reading the draft state back rather than trusting an exit code."
