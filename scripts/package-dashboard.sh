#!/usr/bin/env bash
#
# package-dashboard.sh OUT.tar.gz [LABEL] — build the node dashboard and pack its standalone bundle.
#
# The bundle a node pool release ships as `bitcoin-ghost-<tag>-dashboard.tar.gz`, which
# install-node.sh installs at /opt/ghost/dashboard and ghost-auto-update.sh replaces on update.
# Both look for `ghost-dashboard/server.js` in it, so the archive holds one top-level directory,
# `ghost-dashboard/`, laid out as dashboard/Dockerfile assembles the standalone build:
#   the standalone tree (minimal node_modules, package.json, .next server chunks),
#   .next/static and public/ beside it (standalone omits them),
#   the custom auth-relay server.js over the generated one (`node server.js` is the entrypoint),
#   RUN.md, and BUILDINFO.txt.
#
# Runs `npm ci` and `npm run build` in dashboard/ first unless SKIP_BUILD=1 (a build already
# there is then packed as it is). Used by .github/workflows/release-node-pool.yml, and by hand to
# lay out a test release. LABEL (default: the dashboard's package.json version) goes in BUILDINFO.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:?usage: package-dashboard.sh OUT.tar.gz [LABEL]}"
LABEL="${2:-}"
case "$OUT" in /*) ;; *) OUT="$PWD/$OUT" ;; esac
DASH="$REPO_ROOT/dashboard"

if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
  ( cd "$DASH" && npm ci && npm run build )
fi

# output: 'standalone' (next.config.ts) is what this bundle is; fail loudly without it.
[[ -f "$DASH/.next/standalone/server.js" ]] \
  || { echo "package-dashboard: $DASH/.next/standalone/server.js missing — is output:'standalone' set?" >&2; exit 1; }
[[ -d "$DASH/.next/static" ]] || { echo "package-dashboard: $DASH/.next/static missing" >&2; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
STAGING="$WORK/ghost-dashboard"
mkdir -p "$STAGING/.next"
cp -r "$DASH/.next/standalone/." "$STAGING/"
cp -r "$DASH/.next/static" "$STAGING/.next/static"
cp -r "$DASH/public" "$STAGING/public"
cp "$DASH/server.js" "$STAGING/server.js"
cp "$DASH/RUN.md" "$STAGING/RUN.md"
# A build cache must never ship: it is large and specific to the machine that built it.
rm -rf "$STAGING/.next/cache"

grep -q "Custom Next.js server for the Ghost Node Dashboard" "$STAGING/server.js" \
  || { echo "package-dashboard: staged server.js is not the custom auth-relay server" >&2; exit 1; }
[[ -f "$STAGING/package.json" ]] || { echo "package-dashboard: package.json missing from the bundle" >&2; exit 1; }
[[ -d "$STAGING/node_modules/next" ]] || { echo "package-dashboard: node_modules/next missing from the standalone tree" >&2; exit 1; }

{
  echo "product:     Bitcoin Ghost node dashboard"
  echo "version:     ${LABEL:-$(node -p "require('$DASH/package.json').version")}"
  echo "built:       $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo "commit:      $(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "node:        $(node --version)"
  echo "entrypoint:  node server.js"
} > "$STAGING/BUILDINFO.txt"

mkdir -p "$(dirname "$OUT")"
tar -czf "$OUT" -C "$WORK" ghost-dashboard
echo "package-dashboard: $OUT ($(du -h "$OUT" | cut -f1))"
