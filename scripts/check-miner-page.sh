#!/usr/bin/env bash
#
# Check the website's scripts parse, the pages render and their links resolve.
#
# ## Why this exists
#
# The Ghost Pool site (ghost-web/) is plain JavaScript with no build step: a syntax error ships
# as a blank page, and a renamed API field as "NaN" or a made-up zero. This runs `node --check`
# on every script the site serves and renders, under node, from sample API answers shaped as
# pool_sv2 serves them and from failed ones:
#   scripts/web-tests/pool-site.test.js   the connect box, the payout rule, the live pool status
#                                         merged from every node, and every page's local links
#   scripts/web-tests/miner-page.test.js  the miner lookup page
# Every section must show its data, or say "unavailable", and never print NaN, undefined or a
# number it was not given.
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
done < <(find ghost-web -name '*.js' -print0)

node scripts/web-tests/miner-page.test.js || status=1
node scripts/web-tests/pool-site.test.js || status=1
exit "$status"
