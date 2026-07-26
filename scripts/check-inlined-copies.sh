#!/usr/bin/env bash
#
# Catch drift between a file and the copy of it inlined in install-node.sh.
#
# install-node.sh is fetched standalone over curl and has no repo to read from, so
# scripts and units it installs are embedded as heredocs. Each embedded copy names a
# "canonical source" in the repo — and nothing has ever checked that the two still
# agree.
#
# That is not hypothetical. The vardiff floor was corrected in
# config/sri/translator-config.toml and not in the installer heredoc, so a fresh node
# would have been provisioned with the old value and re-broken the thing the change
# fixed (#431). The same shape of bug is available for every inlined script.
#
# This compares each pair byte-for-byte and fails on any difference. It cannot remove
# the duplication — the delivery model forces it — but it makes divergence loud
# instead of silent.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

python3 - <<'PY'
import re, sys, os

INSTALLER = "scripts/install-node.sh"

# heredoc marker -> canonical source in the repo
PAIRS = {
    "GHOST_RESTART_WATCH_SH_EOF":      "scripts/ghost-restart-watch.sh",
    "GHOST_RESTART_WATCH_SERVICE_EOF": "scripts/systemd/ghost-restart-watch.service",
    "GHOST_RESTART_WATCH_TIMER_EOF":   "scripts/systemd/ghost-restart-watch.timer",
}

src = open(INSTALLER).read()
bad = []

for marker, path in PAIRS.items():
    m = re.search(r"<<'" + re.escape(marker) + r"'\n(.*?)" + re.escape(marker) + r"\n", src, re.S)
    if not m:
        bad.append((path, f"heredoc {marker} not found in {INSTALLER}"))
        continue
    if not os.path.exists(path):
        bad.append((path, "canonical source missing"))
        continue
    inlined, canonical = m.group(1), open(path).read()
    if inlined != canonical:
        # Show the first differing line rather than a wall of diff.
        il, cl = inlined.splitlines(), canonical.splitlines()
        detail = f"{len(il)} inlined lines vs {len(cl)} canonical"
        for i, (a, b) in enumerate(zip(il, cl), 1):
            if a != b:
                detail = f"first difference at line {i}:\n      installer: {a.strip()[:90]}\n      canonical: {b.strip()[:90]}"
                break
        bad.append((path, detail))

if bad:
    print(f"Inlined copies in {INSTALLER} have drifted from their canonical sources:\n", file=sys.stderr)
    for path, detail in bad:
        print(f"  {path}", file=sys.stderr)
        print(f"    {detail}", file=sys.stderr)
    print("\nUpdate both, or the next fresh node is provisioned from the stale copy.", file=sys.stderr)
    sys.exit(1)

print(f"check-inlined-copies: {len(PAIRS)} inlined copies match their sources")
PY
