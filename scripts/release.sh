#!/usr/bin/env bash
#
# Release orchestrator: version bump -> PR -> merge -> gates -> build -> roll -> tag.
#
# `deploy-node.sh` already owns everything that happens TO A NODE, and owns it well: clean-tree
# and tested-marker preconditions, the config gate, ops-script convergence, readiness-by-port,
# an 11-case smoke suite, auto-rollback and the canary soak. Nothing here duplicates that — each
# roll phase below just calls it in the right order and stops when it says no.
#
# What was never automated is the ORCHESTRATION, and that is where releases actually went wrong.
# Every guard below exists because the manual process failed at that exact step:
#
#   * v1.11.35 was built, soaked and rolled to all eight nodes and then never tagged, so the
#     newest published release described a binary the network had already moved past. The tag was
#     a step someone had to remember.                                    -> `phase_tag`, mandatory
#
#   * v1.11.36 reached the canaries, soaked clean, and was REFUSED by production because two
#     unrelated PRs merged while it rolled. `deploy-node.sh` requires the release SHA to still
#     match origin/main for `bins/<binary>` + `crates`, so the whole canary phase and its 60
#     minutes were spent before the refusal landed.        -> `assert_sha_still_current`, checked
#                                                             BEFORE each phase, not just at the end
#
#   * `cargo build -p ghost-gsp` exits 0 and builds the LIBRARY crate; the binary lives in
#     `ghost-gsp-bin`. A "successful" build produced no binary and would have failed at deploy.
#                                                          -> every build verifies the ARTEFACT
#
#   * `--features ghost-pool/zk-production` is invalid when the selected packages do not include
#     ghost-pool, and ghost-pay carries its OWN `zk-production`. Getting this wrong ships the
#     random trusted setup.                                -> per-binary features in ONE table
#
# Usage:
#   scripts/release.sh <version> [--from <phase>] [--dry-run]
#   scripts/release.sh --status
#
#   <version>   e.g. 1.11.38 (no leading v)
#   --from      resume at a phase: bump|pr|gates|build|canary|soak|production|tag
#               A release takes 2h+, mostly soak. Resuming must not redo the roll.
#   --dry-run   print what each phase would do; touch nothing
#
# Phases are idempotent and each verifies its OUTCOME rather than its exit code.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

# ---------------------------------------------------------------- the binary table
#
# ONE place that knows what ships and how it is built. Split by where it can be soaked:
# the canaries carry the mining stack only, so ghost-pay and ghost-gsp have no canary and
# `deploy-node.sh` soaks them on the first PRODUCTION node instead (PRODUCTION_ONLY_BINARIES).
#
# `pool_sv2` leads `ghost-pool` because of the #742 webhook hazard: the SENDER of the share
# signature must be current before the VERIFIER is. Wrong order is not "shares are delayed",
# it is a 401 per batch and the batch is DISCARDED.
FLEET_BINARIES="pool_sv2 ghost-pool translator_sv2"
PRODUCTION_ONLY="ghost-pay ghost-gsp"

# cargo package name, where it differs from the binary name. `ghost-gsp` is a LIBRARY crate;
# building it succeeds and produces no binary at all.
pkg_for() {
    case "$1" in
        ghost-gsp) echo "ghost-gsp-bin" ;;
        *)         echo "$1" ;;
    esac
}

# Cargo feature required for a mainnet build of this binary, if any.
# ⛔ Without these ghost-pool refuses to start on mainnet, and ghost-pay silently ships the
# random trusted setup (GHOST-08). A feature named for a package that is not in the selected
# set is a hard cargo error, so these are grouped by build invocation, never concatenated.
features_for() {
    case "$1" in
        ghost-pool|pool_sv2|translator_sv2) echo "ghost-pool/zk-production" ;;
        ghost-pay)                          echo "ghost-pay/zk-production" ;;
        *)                                  echo "" ;;
    esac
}

CANARY_NODES="ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8"
PRODUCTION_NODES="ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4"
SOAK_MINUTES="${SOAK_MINUTES:-62}"

STATE_DIR="${GHOST_RELEASE_STATE:-$HOME/.ghost-deploy/release}"
mkdir -p "$STATE_DIR"

DRY_RUN=false
VERSION=""
FROM="bump"

die()  { echo "REFUSED: $*" >&2; exit 1; }
info() { echo "  $*"; }
step() { echo; echo "=== $* ==="; }
run()  { if $DRY_RUN; then echo "  [dry-run] $*"; else eval "$@"; fi; }

# ---------------------------------------------------------------- argument parsing
while [ $# -gt 0 ]; do
    case "$1" in
        --status)  shift; MODE=status ;;
        --from)    FROM="${2:-}"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        -*)        die "unknown flag: $1" ;;
        *)         VERSION="$1"; shift ;;
    esac
done
MODE="${MODE:-release}"

if [ "$MODE" = "status" ]; then
    echo "workspace version: $(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
    echo "main:              $(git rev-parse --short origin/main 2>/dev/null)"
    echo "newest tag:        $(git tag -l 'v*' --sort=-v:refname | head -1)"
    echo "newest release:    $(gh release list --limit 1 2>/dev/null | awk '{print $1}')"
    echo "state:             $STATE_DIR"
    ls -1 "$STATE_DIR" 2>/dev/null | sed 's/^/  /'
    exit 0
fi

[ -n "$VERSION" ] || die "usage: $0 <version> [--from <phase>] [--dry-run]"
echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' || die "version must look like 1.11.38, got '$VERSION'"
TAG="v$VERSION"
SHA_FILE="$STATE_DIR/$TAG.sha"
WORKTREE="${GHOST_RELEASE_WORKTREE:-/tmp/ghost-release-$VERSION}"

# ---------------------------------------------------------------- shared guards
#
# The check `deploy-node.sh` makes per binary, made ONCE and EARLY. Discovering that main has
# moved at the start of the production phase means the canary phase and its soak are already
# sunk — which is exactly how v1.11.36 was lost.
assert_sha_still_current() {
    local sha="$1" bad=""
    git fetch -q origin || die "cannot reach origin"
    for b in $FLEET_BINARIES $PRODUCTION_ONLY; do
        local dir="bins/${b//_/-}"
        [ -d "$dir" ] || dir="bins/$b"
        git diff --quiet "$sha" origin/main -- "$dir" crates 2>/dev/null || bad="$bad $b"
    done
    if [ -n "$bad" ]; then
        echo "REFUSED: $sha no longer matches origin/main for:$bad" >&2
        echo "         Something merged into crates/ or bins/ while this release was rolling." >&2
        echo "         deploy-node.sh will refuse every one of those. Cut a new release from" >&2
        echo "         current main — do NOT bypass the guard." >&2
        echo >&2
        echo "         The rule: between cutting a release and finishing its roll, land nothing" >&2
        echo "         that touches bins/ or crates/. Changes confined to .github/, scripts/," >&2
        echo "         docs/ or tests/ are safe." >&2
        exit 1
    fi
    info "release SHA still matches main for all shipped binaries"
}

# A build "succeeding" is not the same as a binary existing at the version you asked for.
# Both halves have been wrong in the same session.
assert_binary() {
    local wt="$1" bin="$2" want="$3"
    local path="$wt/target/release/$bin"
    [ -x "$path" ] || die "$bin: build reported success but $path does not exist (wrong -p? \
$bin's cargo package is '$(pkg_for "$bin")')"
    local got
    got="$("$path" --version 2>/dev/null | head -1 | awk '{print $2}')"
    [ "$got" = "$want" ] || die "$bin: built binary self-reports '$got', expected '$want'"
    info "$bin $got"
}

# ---------------------------------------------------------------- phases
phase_bump() {
    step "bump to $VERSION"
    git rev-parse --abbrev-ref HEAD | grep -qx main || die "not on main"
    [ -z "$(git status --porcelain)" ] || die "working tree is dirty"
    run "git pull -q --ff-only"

    local cur
    cur="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
    [ "$cur" = "$VERSION" ] && { info "already at $VERSION"; return 0; }

    run "git checkout -q -b release/$TAG"
    run "sed -i '0,/^version = \"$cur\"/s//version = \"$VERSION\"/' Cargo.toml"
    run "cargo update -w --offline >/dev/null 2>&1"
    run "(cd fuzz && cargo update -w --offline >/dev/null 2>&1)"

    $DRY_RUN && return 0
    # BOTH lockfiles, verified by counting. fuzz/Cargo.lock is a separate workspace and has
    # been left behind before; CI then fails on a lockfile diff after everything else is green.
    local a b
    a=$(grep -c -F "version = \"$VERSION\"" Cargo.lock)
    b=$(grep -c -F "version = \"$VERSION\"" fuzz/Cargo.lock)
    [ "$a" -gt 0 ] && [ "$b" -gt 0 ] || die "lockfiles not synced (Cargo.lock=$a fuzz=$b)"
    grep -q -F "version = \"$cur\"" Cargo.lock && die "Cargo.lock still carries $cur"
    info "lockfiles synced ($a workspace, $b fuzz)"
}

phase_pr() {
    step "release PR"
    $DRY_RUN && { info "[dry-run] would commit, push and open a PR"; return 0; }
    if git diff --quiet HEAD 2>/dev/null && git rev-parse --verify -q "release/$TAG" >/dev/null; then
        info "release branch already committed"
    else
        git add -A
        git commit -q -m "chore(release): $TAG" || true
    fi
    git push -q -u origin "release/$TAG" 2>/dev/null || true
    local pr
    pr=$(gh pr list --head "release/$TAG" --json number --jq '.[0].number' 2>/dev/null)
    if [ -z "$pr" ]; then
        gh pr create --base main --head "release/$TAG" \
            --title "chore(release): $TAG" --body "Cuts \`$TAG\`." >/dev/null || die "gh pr create failed"
        pr=$(gh pr list --head "release/$TAG" --json number --jq '.[0].number')
    fi
    info "PR #$pr"
    wait_for_ci_and_merge "$pr"
    git checkout -q main && git pull -q --ff-only
    git rev-parse HEAD > "$SHA_FILE"
    info "release SHA $(cut -c1-9 < "$SHA_FILE")"
}

# ⚠ `gh pr checks --json` does NOT exist in the gh build used here — a watcher written against
# it counts zero checks for ever and never merges, while looking healthy. Parse the TEXT output:
# tab-separated name / status / duration / url, where status is pass|fail|pending|skipping.
wait_for_ci_and_merge() {
    local pr="$1" i out pass fail pend
    for i in $(seq 1 90); do
        out=$(gh pr checks "$pr" 2>/dev/null)
        pass=$(printf '%s\n' "$out" | awk -F'\t' 'NF>1 && $2=="pass"'    | wc -l)
        fail=$(printf '%s\n' "$out" | awk -F'\t' 'NF>1 && $2=="fail"'    | wc -l)
        pend=$(printf '%s\n' "$out" | awk -F'\t' 'NF>1 && $2=="pending"' | wc -l)
        echo "  $(date -u +%H:%M:%SZ) pass=$pass fail=$fail pending=$pend"
        [ "$fail" -gt 0 ] && { printf '%s\n' "$out" >&2; die "CI failed on #$pr"; }
        if [ "$pend" -eq 0 ] && [ "$pass" -ge 10 ]; then
            gh pr merge "$pr" --squash >/dev/null 2>&1 || die "merge of #$pr failed"
            # Verify the OUTCOME. A merge command that exits 0 is not a merged PR.
            [ "$(gh pr view "$pr" --json state --jq .state)" = "MERGED" ] || die "#$pr did not merge"
            info "merged #$pr"
            return 0
        fi
        sleep 60
    done
    die "timed out waiting for CI on #$pr"
}

phase_gates() {
    step "gates on the merged SHA"
    local sha; sha="$(cat "$SHA_FILE")"
    assert_sha_still_current "$sha"
    $DRY_RUN && { info "[dry-run] would run record-tests.sh in $WORKTREE"; return 0; }
    [ -d "$WORKTREE" ] || git worktree add -q --detach "$WORKTREE" "$sha" || die "worktree failed"
    # The marker is keyed to the full SHA, so it cannot be inherited from a previous release.
    if ls "$HOME/.ghost-deploy/tested-$sha" >/dev/null 2>&1; then
        info "already recorded as tested"
    else
        (cd "$WORKTREE" && ./scripts/record-tests.sh) || die "gates failed"
        ls "$HOME/.ghost-deploy/tested-$sha" >/dev/null 2>&1 \
            || die "record-tests.sh exited 0 but wrote no marker for $sha"
    fi
    info "tested marker present"
}

phase_build() {
    step "build every shipped binary at $VERSION"
    $DRY_RUN && { info "[dry-run] would build: $FLEET_BINARIES $PRODUCTION_ONLY"; return 0; }
    # Grouped by feature set: a feature naming a package outside the selected set is a hard error.
    (cd "$WORKTREE" && cargo build --release --jobs "${BUILD_JOBS:-2}" \
        --features ghost-pool/zk-production -p ghost-pool -p pool_sv2 -p translator_sv2) \
        || die "mining-stack build failed"
    (cd "$WORKTREE" && cargo build --release --jobs "${BUILD_JOBS:-2}" \
        --features ghost-pay/zk-production -p ghost-pay) || die "ghost-pay build failed"
    (cd "$WORKTREE" && cargo build --release --jobs "${BUILD_JOBS:-2}" \
        -p "$(pkg_for ghost-gsp)") || die "ghost-gsp build failed"

    for b in $FLEET_BINARIES $PRODUCTION_ONLY; do assert_binary "$WORKTREE" "$b" "$VERSION"; done

    # zk-production, checked so it can FAIL in both directions. Absence of the insecure marker
    # alone proves nothing — the symbol may simply have been optimised away.
    local prod insecure
    prod=$(grep -ac 'disabled in production builds' "$WORKTREE/target/release/ghost-pool")
    insecure=$(grep -ac 'Using random trusted setup' "$WORKTREE/target/release/ghost-pool")
    [ "$prod" -ge 1 ] && [ "$insecure" -eq 0 ] \
        || die "ghost-pool zk-production check inconclusive (prod=$prod insecure=$insecure)"
    info "zk-production confirmed in ghost-pool (prod=$prod insecure=$insecure)"
}

roll_node() {
    local node="$1" canary="$2" bins="$3" b rc
    echo "  ---- $node ----"
    for b in $bins; do
        # A caller looping over binaries MUST stop on any non-zero exit. These three talk to
        # each other and are not independently deployable; carrying on leaves a node running a
        # combination nobody chose, and a mid-roll smoke failure then reads identically to a
        # genuinely broken binary.
        (cd "$WORKTREE" && ./scripts/deploy-node.sh "$node" "$b" $canary)
        rc=$?
        [ $rc -ne 0 ] && { echo "STOPPED at $node/$b (exit $rc)" >&2; return $rc; }
    done
    return 0
}

phase_canary() {
    step "canary roll"
    assert_sha_still_current "$(cat "$SHA_FILE")"
    $DRY_RUN && { info "[dry-run] would roll $FLEET_BINARIES to $CANARY_NODES"; return 0; }
    for n in $CANARY_NODES; do
        roll_node "$n" "--canary" "$FLEET_BINARIES" || die "canary roll stopped at $n"
    done
    date +%s > "$STATE_DIR/$TAG.soak-start"
    info "canaries done; soak clock started"
}

phase_soak() {
    step "soak ${SOAK_MINUTES}m, then verify"
    $DRY_RUN && { info "[dry-run] would soak then health-check"; return 0; }
    local start end
    start=$(cat "$STATE_DIR/$TAG.soak-start" 2>/dev/null || date +%s)
    end=$(( start + SOAK_MINUTES * 60 ))
    while [ "$(date +%s)" -lt "$end" ]; do sleep 60; done

    # The soak exists to be OBSERVED. Waiting without looking is just a delay.
    local bad=0 out
    for n in $CANARY_NODES; do
        out=$(timeout 60 ssh -o BatchMode=yes "$n" '
            A=0; for s in ghost-pool sri-pool sri-translator ghostd; do
              systemctl is-active $s >/dev/null 2>&1 && A=$((A+1)); done
            printf "services=%s/4 restarts=%s ver=%s" "$A" \
              "$(systemctl show sri-pool -p NRestarts --value)" \
              "$(/opt/ghost/bin/ghost-pool --version 2>/dev/null | head -1 | awk "{print \$2}")"' 2>/dev/null)
        echo "  $n  $out"
        echo "$out" | grep -q "services=4/4"   || bad=1
        echo "$out" | grep -q "ver=$VERSION"   || bad=1
    done
    [ $bad -ne 0 ] && die "a canary is unhealthy after the soak — not rolling production"
    info "canaries healthy"
}

phase_production() {
    step "production roll"
    assert_sha_still_current "$(cat "$SHA_FILE")"
    $DRY_RUN && { info "[dry-run] would roll $FLEET_BINARIES $PRODUCTION_ONLY to $PRODUCTION_NODES"; return 0; }
    for n in $PRODUCTION_NODES; do
        roll_node "$n" "" "$FLEET_BINARIES $PRODUCTION_ONLY" || die "production roll stopped at $n"
    done
    info "production done"
}

# The step that was simply forgotten for v1.11.35, which is why the newest published release
# described a binary the network had already moved past. It is a phase now, not a good intention.
phase_tag() {
    step "tag and publish $TAG"
    local sha; sha="$(cat "$SHA_FILE")"
    $DRY_RUN && { info "[dry-run] would tag $TAG at ${sha:0:9} and publish"; return 0; }

    if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
        info "tag $TAG already exists"
    else
        git tag -a "$TAG" "$sha" -m "$TAG" || die "tag failed"
        git push -q origin "$TAG" || die "tag push failed"
    fi
    if gh release view "$TAG" >/dev/null 2>&1; then
        info "release $TAG already published"
    else
        gh release create "$TAG" --title "$TAG" --generate-notes >/dev/null \
            || die "gh release create failed"
    fi
    # Verify the OUTCOME: a published release that is not `latest` is the failure this had before.
    local latest
    latest=$(gh release list --limit 1 2>/dev/null | awk '{print $1}')
    [ "$latest" = "$TAG" ] || echo "  WARN: newest release is '$latest', not $TAG" >&2
    info "published $TAG"
}

# ---------------------------------------------------------------- driver
PHASES="bump pr gates build canary soak production tag"
echo "$PHASES" | tr ' ' '\n' | grep -qx "$FROM" || die "unknown phase '$FROM' (want one of: $PHASES)"

started=false
for p in $PHASES; do
    [ "$p" = "$FROM" ] && started=true
    $started || { echo "  (skipping $p)"; continue; }
    "phase_$p" || exit 1
done

echo
echo "=== $TAG released ==="
