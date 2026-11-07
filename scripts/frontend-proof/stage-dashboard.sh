#!/usr/bin/env bash
# stage-dashboard.sh OUT_DIR: lay out the dashboard's standalone build in OUT_DIR as the release
# bundle has it (scripts/package-dashboard.sh): the standalone tree, .next/static, public/ and the
# custom server.js. Run `npm run build` in dashboard/ first.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dash="$here/../../dashboard"
out="${1:?usage: stage-dashboard.sh OUT_DIR}"
[[ -f "$dash/.next/standalone/server.js" ]] || { echo "stage-dashboard: build the dashboard first" >&2; exit 1; }
rm -rf "$out"
mkdir -p "$out/.next"
cp -r "$dash/.next/standalone/." "$out/"
cp -r "$dash/.next/static" "$out/.next/static"
cp -r "$dash/public" "$out/public"
cp "$dash/server.js" "$out/server.js"
rm -rf "$out/.next/cache"
