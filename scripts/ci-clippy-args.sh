#!/usr/bin/env bash
#
# Print the EXACT clippy arguments the CI lint job runs, extracted from the workflow.
#
# `scripts/record-tests.sh` writes the `tested-` marker that `deploy-node.sh` requires, so a
# green local gate is treated as "this commit is deployable". It used to run its own, weaker
# clippy invocation (#626):
#
#     record-tests.sh   cargo clippy --workspace $EXCLUDES --all-targets
#     ci.yml            cargo clippy $WORKSPACE_EXCLUDES --all-targets --all-features \
#                         -- -D warnings -A clippy::derivable_impls ... (six allows)
#
# Two consequences. Without `--all-features`, feature-gated code — `zk-consensus`,
# `mpc-ceremony`, `zk-production`, and there is a lot of it — was never linted locally.
# Without `-D warnings`, clippy exits 0 on warnings, so the gate recorded success on a commit
# CI would then reject. A commit could pass the deploy gate and turn main red.
#
# ## Why this parses the workflow instead of copying the flags
#
# Copying them creates two lists that must be kept in step by hand, and the whole defect in
# #626 is that they drifted. Deriving the local gate FROM the workflow makes drift impossible
# rather than merely detectable: change `ci.yml` and the local gate changes with it.
#
# The workflow is parsed with a real YAML loader, not grep. A `run:` written as a plain scalar
# is folded onto one line and grep-based extraction of a multi-line command silently returns a
# fragment — the same class of bug as the eaten line-continuations in
# `check-workflow-scalars.sh` (#428).
#
# ## Failure is loud, never silent
#
# If the clippy step cannot be found, this exits non-zero and prints nothing. The caller MUST
# treat that as a gate failure. Falling back to a hardcoded default is exactly how the local
# gate came to disagree with CI in the first place: a silent fallback is indistinguishable from
# agreement.
#
# Usage:
#   scripts/ci-clippy-args.sh            # prints the argument string, exit 0
#   eval "cargo clippy $(scripts/ci-clippy-args.sh)"

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

python3 - "$REPO_ROOT" <<'PY'
import sys, os, glob

try:
    import yaml
except ImportError:
    sys.stderr.write("ci-clippy-args: PyYAML not installed — cannot verify the local gate "
                     "matches CI. Install it rather than guessing the flags.\n")
    sys.exit(2)

root = sys.argv[1]

# The env block carries WORKSPACE_EXCLUDES; the clippy command references it. Resolve the
# reference rather than assuming its value, so an exclusion added in CI reaches the local gate.
def expand(cmd, env):
    for k, v in env.items():
        cmd = cmd.replace("$" + k, str(v)).replace("${" + k + "}", str(v))
    return cmd

found = []
for path in sorted(glob.glob(os.path.join(root, ".github/workflows/*.yml")) +
                   glob.glob(os.path.join(root, ".github/workflows/*.yaml"))):
    try:
        with open(path) as fh:
            doc = yaml.safe_load(fh)
    except (yaml.YAMLError, OSError) as e:
        sys.stderr.write(f"ci-clippy-args: cannot parse {path}: {e}\n")
        sys.exit(2)
    if not isinstance(doc, dict):
        continue
    top_env = doc.get("env") or {}
    for _job_name, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        env = {**top_env, **(job.get("env") or {})}
        for step in (job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            run = step.get("run")
            if not isinstance(run, str):
                continue
            step_env = {**env, **(step.get("env") or {})}
            for line in run.splitlines():
                s = line.strip()
                # Only a real clippy invocation, not a comment mentioning one.
                if s.startswith("cargo clippy ") or s == "cargo clippy":
                    found.append((path, expand(s, step_env)))

if not found:
    sys.stderr.write("ci-clippy-args: no `cargo clippy` step found in .github/workflows. "
                     "The local gate cannot be derived from CI — refusing to guess.\n")
    sys.exit(1)

# More than one would mean the local gate has to choose, and choosing wrongly is the bug this
# exists to prevent. Make the ambiguity visible instead.
if len({cmd for _p, cmd in found}) > 1:
    sys.stderr.write("ci-clippy-args: multiple DIFFERENT clippy invocations in CI:\n")
    for p, cmd in found:
        sys.stderr.write(f"  {os.path.relpath(p, root)}: {cmd}\n")
    sys.stderr.write("Resolve which one gates a deploy, or teach this script to pick.\n")
    sys.exit(1)

cmd = found[0][1]
args = cmd[len("cargo clippy"):].strip()
if not args:
    sys.stderr.write("ci-clippy-args: clippy step has no arguments — refusing to proceed.\n")
    sys.exit(1)
print(args)
PY
