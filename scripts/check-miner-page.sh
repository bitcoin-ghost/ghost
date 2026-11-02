#!/usr/bin/env bash
#
# Check the website's scripts parse and the miner page renders.
#
# ## Why this exists
#
# The miner page (ghost-web/miner.html, ghost-web/miner.js) is what miners judge the pool by,
# and it is plain JavaScript with no build step: a syntax error ships as a blank page, and a
# renamed API field as "NaN" or a made-up zero. This runs `node --check` on every script the
# site serves (vendored libraries excepted) and renders the page under node from sample API
# answers and from failed ones (scripts/web-tests/miner-page.test.js): every section must show
# its data, or say "unavailable", and never print NaN, undefined or a number it was not given.
#
# Needs node (any version from 16). No packages.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v node >/dev/null 2>&1; then
  echo "check-miner-page: node is not installed" >&2
  exit 1
fi

status=0
while IFS= read -r -d '' f; do
  if ! node --check "$f"; then
    echo "check-miner-page: $f does not parse" >&2
    status=1
  fi
done < <(find ghost-web -name '*.js' -not -path 'ghost-web/vendor/*' -print0)

node scripts/web-tests/miner-page.test.js || status=1
exit "$status"
