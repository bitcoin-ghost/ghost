#!/usr/bin/env bash
#
# Fail if a mesh message type has no dispatch arm anywhere.
#
# ## Why this exists
#
# Four times in one session (2026-08-16) a piece of `ghost-consensus` was found complete, fully
# unit-tested, and connected to NOTHING:
#
#   * the shard mesh handler — written, tested, and never registered, so two nodes folded correctly
#     for four hours and never converged because there was no path between them;
#   * `with_private_peers_allowed` — the fix for a documented "hard blocker" existed for two months
#     while the README still said the cluster could never mesh;
#   * `ShardTableSync` — the ONLY path that can repair a missed shard column, with zero references
#     in `bins/`, while vm1-4 sat permanently short of a column and could not heal;
#   * `select_sample_indices` / `build_sample_request` / `verify_sample_response` — §6 sampling,
#     the precondition for admitting foreign operators.
#
# Every one of them had a green test suite the entire time, because the layer being tested and the
# layer being wired are different layers. Unit tests prove a function is correct; nothing proved it
# was reachable. This does.
#
# ## What it checks
#
# Every `MessageType` variant must appear in a dispatch position somewhere in `bins/` or `crates/`:
# a match arm (`MessageType::X =>`) or an equality test (`== MessageType::X`). A variant that
# appears only in its own enum, in the size validator, and in the wire encoding is a message the
# fleet can send and no node will ever act on.
#
# This is deliberately narrow. A broader "public function with no caller" sweep drowns in false
# positives — library APIs are legitimately called by other crates, by tests, or not yet at all.
# Message types are different: a type that nothing dispatches is dead by definition, and all four
# failures above were reachable through exactly this check.
#
# Usage: scripts/check-wiring.sh
# Exit: 0 all dispatched, 1 an undispatched variant (or a stale allowlist entry).

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

python3 - <<'PY'
import re, subprocess, pathlib, sys

# Variants that are deliberately NOT dispatched. Each needs a reason, and the reason is checked:
# if an allowlisted variant gains a dispatch arm, this script fails too, so the list cannot rot
# into a place where real gaps hide.
ALLOWLIST: dict[str, str] = {
    # (empty) Every Shard message type is currently dispatched. An entry here needs the reason it
    # is deliberately ignored, and the check fails if an allowlisted type gains a dispatch arm, so
    # the list cannot quietly rot into a hiding place.
}

src = pathlib.Path("crates/ghost-consensus/src/message.rs").read_text()
m = re.search(r"pub enum MessageType\s*\{(.*?)\n\}", src, re.S)
if not m:
    print("check-wiring: could not find `pub enum MessageType` — the check cannot run, which is")
    print("              a failure, not a pass.")
    sys.exit(1)

all_variants = re.findall(r"^\s{4}([A-Z][A-Za-z0-9]*)\s*(?:=\s*\d+\s*)?,", m.group(1), re.M)

# Scoped to the Shard family — for now.
#
# This is where all four unwired-core failures happened, and it is the set whose dispatch state I
# have actually verified. Running it across all 46 variants today flags eight more (BlockFound,
# ElderUpdate, the Zk and ElderList families): those are candidates, not verdicts — several are
# likely routed through callbacks rather than a `MessageHandler`, and asserting they are dead
# without checking would be exactly the over-broad check this file argues against.
#
# ⚠ Widen this when someone has triaged the rest. An honest narrow check that fails for real
# reasons beats a broad one whose failures get muted.
variants = [v for v in all_variants if v.startswith("Shard")]
if not variants:
    print("check-wiring: parsed ZERO variants — refusing to report success on an empty set.")
    sys.exit(1)

# Scan ONLY the files that actually implement `MessageHandler`, plus the handler modules in
# `bins/`. That is where a message is acted on.
#
# ⚠ Everything else that matches `MessageType::X =>` is a TABLE, not a dispatch: the size limits in
# `message_validator.rs`, and the port/encryption routing in `mesh.rs`, both carry an arm for every
# variant. Counting those made this check unfalsifiable — it passed happily with the shard handler
# reverted to dropping everything but summaries, because the tables still had the arms. Caught by
# mutating the handler and finding the check still green; a check that cannot fail is worse than no
# check, because it is believed.
impls = subprocess.run(
    ["grep", "-rl", "--include=*.rs", "impl MessageHandler for", "bins/", "crates/"],
    capture_output=True, text=True).stdout.split()
impls += subprocess.run(
    ["grep", "-rl", "--include=*.rs", "impl ghost_consensus::mesh::MessageHandler for",
     "bins/", "crates/"], capture_output=True, text=True).stdout.split()
files = sorted(set(f for f in impls if "/tests/" not in f))
if not files:
    print("check-wiring: found NO MessageHandler implementations — the scan target is empty, which")
    print("              would make every variant look undispatched. Refusing to guess.")
    sys.exit(1)
out = subprocess.run(
    ["grep", "-hoE", r"(MessageType::[A-Za-z0-9]+ *=>|[=!]= *MessageType::[A-Za-z0-9]+)", *files],
    capture_output=True, text=True).stdout
dispatched = set(re.findall(r"MessageType::([A-Za-z0-9]+)", out))

undispatched = [v for v in variants if v not in dispatched and v not in ALLOWLIST]
stale = [v for v in ALLOWLIST if v in dispatched]

print(f"  {len(variants)} Shard message types of {len(all_variants)} total; "
      f"{len(dispatched & set(variants))} dispatched, {len(ALLOWLIST)} allowlisted")

failed = False
for v in undispatched:
    print(f"  ✗ MessageType::{v} has NO dispatch arm — the fleet can send it and no node acts on it")
    failed = True
for v in stale:
    print(f"  ✗ MessageType::{v} is allowlisted but IS dispatched — remove it from ALLOWLIST")
    failed = True

if failed:
    print()
    print("  A message type with no dispatch arm is wiring that does not exist. Either route it,")
    print("  or add it to ALLOWLIST with the reason it is deliberately ignored.")
    sys.exit(1)

print("  OK: every message type is either dispatched or allowlisted with a reason")
PY
