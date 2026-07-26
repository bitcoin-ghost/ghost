#!/usr/bin/env bash
#
# Catch shell line-continuations that YAML has silently eaten.
#
# A `run:` written as a plain (unquoted, non-block) scalar is folded onto a single
# line, joined with a space. YAML does not treat `\` specially, so a trailing
# backslash survives the fold and the shell then reads `\ ` as an escaped space —
# the next word arrives as one token with a leading space instead of as a flag.
#
# This broke the Coverage job on main for six consecutive commits (#428):
#
#     run: cargo llvm-cov $EXCLUDES --exclude integration_tests_sv2 \
#         --lib --bins --lcov --output-path lcov.info
#
#   => cargo llvm-cov ... integration_tests_sv2 \ --lib --bins ...
#   => error: unrecognized subcommand  --lib      (note the doubled space)
#
# Written as a block scalar (`run: |`) the newline is preserved and the backslash
# does its normal shell job. That is the fix; this script is the guard.
#
# We detect it after parsing rather than by grepping the source, because the
# post-fold string is unambiguous: backslash-then-space is always wrong, and
# backslash-then-newline is always fine.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

python3 - "$REPO_ROOT" <<'PY'
import sys, os, re, glob

try:
    import yaml
except ImportError:
    print("check-workflow-scalars: PyYAML not available, skipping", file=sys.stderr)
    sys.exit(0)

root = sys.argv[1]
bad = []

# A backslash followed by a space/tab (not a newline) in a shell command is the
# signature of a continuation that YAML folded away.
FOLDED = re.compile(r"\\[ \t]")

def walk(node, path, wf):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "run" and isinstance(v, str):
                if FOLDED.search(v):
                    snippet = next(
                        (ln.strip() for ln in v.splitlines() if FOLDED.search(ln)), v.strip()
                    )
                    bad.append((wf, path, snippet[:120]))
            else:
                walk(v, f"{path}.{k}", wf)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk(v, f"{path}[{i}]", wf)

files = sorted(glob.glob(os.path.join(root, ".github/workflows/*.yml")) +
               glob.glob(os.path.join(root, ".github/workflows/*.yaml")))
for f in files:
    with open(f) as fh:
        try:
            doc = yaml.safe_load(fh)
        except yaml.YAMLError as e:
            print(f"check-workflow-scalars: {os.path.relpath(f, root)} does not parse: {e}", file=sys.stderr)
            sys.exit(1)
    walk(doc, "", os.path.relpath(f, root))

if bad:
    print("Line continuation eaten by YAML folding — use a block scalar (`run: |`):\n", file=sys.stderr)
    for wf, path, snippet in bad:
        print(f"  {wf}{path}", file=sys.stderr)
        print(f"    {snippet}", file=sys.stderr)
    print("\nA plain `run:` scalar folds onto one line and keeps the backslash, so the", file=sys.stderr)
    print("shell sees an escaped space and the next flag becomes part of that token.", file=sys.stderr)
    sys.exit(1)

print(f"check-workflow-scalars: {len(files)} workflow(s) clean")
PY
