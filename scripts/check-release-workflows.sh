#!/usr/bin/env bash
#
# The two release channels stay apart (static check of the workflow files).
#
# The old network releases from release.yml on `v*` tags and its nodes update from GitHub's
# `releases/latest`. The node pool releases from release-node-pool.yml on `np-v*` tags, as
# pre-releases that can never be latest. A trigger filter that matched both, or a node pool release
# that GitHub could make latest, would move every old-network node onto a node pool build. Checked:
#   1. which workflows a push of each kind of tag starts: an np- tag only release-node-pool.yml,
#      a v-tag only release.yml (GitHub tag filters are globs anchored at both ends);
#   2. each release job publishes only for its own prefix;
#   3. the node pool release is created as a pre-release with make_latest "false";
#   4. the two `build` jobs are the same apart from `needs`, so both channels ship the same
#      artefact set built the same way;
#   5. release.yml refuses a `v*` tag whose commit is not on main's history (its guard job, which
#      the build waits for), so a v-tag pushed by hand on node pool code cannot publish an
#      old-channel latest release.
# Usage: scripts/check-release-workflows.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

python3 - <<'PY'
import glob, os, re, sys
import yaml

OLD = ".github/workflows/release.yml"
NP = ".github/workflows/release-node-pool.yml"
bad = []

def load(path):
    d = yaml.safe_load(open(path))
    # PyYAML reads the bare key `on` as the boolean True.
    d["on"] = d.get("on", d.get(True))
    return d

def glob_re(pat):
    # GitHub filter patterns: `*` any characters but `/`, `**` any characters, `?` zero or one
    # of the preceding character, `+` one or more of it, `[...]` a class. Anchored at both ends.
    out, i = "", 0
    while i < len(pat):
        c = pat[i]
        if pat.startswith("**", i):
            out += ".*"; i += 2; continue
        if c == "*":
            out += "[^/]*"
        elif c in "?+":
            out += c
        elif c == "[":
            j = pat.index("]", i)
            out += pat[i:j + 1]; i = j + 1; continue
        else:
            out += re.escape(c)
        i += 1
    return re.compile("^" + out + "$")

def fires_on_tag(wf, tag):
    on = wf["on"]
    if isinstance(on, str):
        on = {on: None}
    elif isinstance(on, list):
        on = {k: None for k in on}
    if "push" not in on:
        return False
    push = on["push"] or {}
    tags, ignore = push.get("tags"), push.get("tags-ignore")
    if tags is None and ignore is None:
        # A push filtered on branches only does not run for tags; an unfiltered push does.
        return not ("branches" in push or "branches-ignore" in push or "paths" in push)
    if tags is not None:
        ok = False
        for p in tags:
            neg = p.startswith("!")
            if glob_re(p[1:] if neg else p).match(tag):
                ok = not neg
        return ok
    return not any(glob_re(p).match(tag) for p in ignore)

workflows = {os.path.basename(p): load(p) for p in sorted(glob.glob(".github/workflows/*.y*ml"))}
cases = {
    "np-v1.0.0": {"release-node-pool.yml"},
    "np-v1.11.46-rc1": {"release-node-pool.yml"},
    "v1.11.46": {"release.yml"},
    "v1.11.47-rc1": {"release.yml"},
    "agathion-v1.0.0": {"release-agathion.yml"},
}
for tag, want in cases.items():
    got = {n for n, wf in workflows.items() if fires_on_tag(wf, tag)}
    if got != want:
        bad.append(f"pushing tag {tag} starts {sorted(got) or 'nothing'}, want {sorted(want)}")

old, np = workflows["release.yml"], workflows["release-node-pool.yml"]

def release_if(wf):
    return str(wf["jobs"]["release"].get("if", ""))
if "refs/tags/v'" not in release_if(old):
    bad.append(f"release.yml's release job is not gated on refs/tags/v: {release_if(old)!r}")
if "refs/tags/np-v'" not in release_if(np):
    bad.append(f"release-node-pool.yml's release job is not gated on refs/tags/np-v: {release_if(np)!r}")

create = [s for s in np["jobs"]["release"]["steps"] if str(s.get("uses", "")).startswith("softprops/action-gh-release")]
if len(create) != 1:
    bad.append(f"release-node-pool.yml should create exactly one release, found {len(create)}")
else:
    w = create[0].get("with", {})
    if w.get("prerelease") is not True:
        bad.append("the node pool release is not created as a pre-release (prerelease: true)")
    if str(w.get("make_latest")) != "false":
        bad.append(f"the node pool release must set make_latest: \"false\", has {w.get('make_latest')!r}")
    if w.get("draft") is not True:
        bad.append("the node pool release must be created as a draft (release.sh --node-pool publishes it)")
    if "Node pool" not in str(w.get("name", "")):
        bad.append("the node pool release is not named as one")

def build(wf):
    b = dict(wf["jobs"]["build"]); b.pop("needs", None); return b
if build(old) != build(np):
    keys = sorted(set(build(old)) | set(build(np)))
    diff = [k for k in keys if build(old).get(k) != build(np).get(k)]
    bad.append(f"the build jobs of release.yml and release-node-pool.yml differ in: {diff}")
if np["jobs"]["build"].get("needs") != "guard":
    bad.append("release-node-pool.yml's build must wait for the tag guard (needs: guard)")

if old["jobs"]["build"].get("needs") != "guard":
    bad.append("release.yml's build must wait for the main-history guard (needs: guard)")
guard = old["jobs"].get("guard") or {}
checkout = [s for s in guard.get("steps", []) if str(s.get("uses", "")).startswith("actions/checkout")]
script = "\n".join(str(s.get("run", "")) for s in guard.get("steps", []))
if not checkout or (checkout[0].get("with") or {}).get("fetch-depth") != 0:
    bad.append("release.yml's guard must check out full history (fetch-depth: 0) to test ancestry")
if not re.search(r"merge-base --is-ancestor \"\$GITHUB_SHA\" origin/main", script):
    bad.append("release.yml's guard must refuse a tag whose commit is not an ancestor of origin/main")
if "fetch --no-tags origin main" not in script or "exit 1" not in script:
    bad.append("release.yml's guard must fetch main and fail the run on a tag off main")

if bad:
    print("Release channels are not kept apart:\n", file=sys.stderr)
    for b in bad:
        print(f"  {b}", file=sys.stderr)
    sys.exit(1)
print(f"check-release-workflows: {len(cases)} tag pushes route to their own workflow; the node pool "
      "release is a pre-release that cannot be latest; both channels build the same set; a v-tag "
      "off main's history is refused")
PY
