#!/usr/bin/env bash
#
# Fail if the SV2 accept loop takes its connection slot after spawning the per-connection task,
# or releases it by hand (#994).
#
# ## Why this exists
#
# Two properties of the connection limiter are invisible in a unit test, because both are about
# WHERE the code sits rather than what the limiter computes.
#
# **1. The slot must be acquired before the spawn.** Taken inside the spawned task, the task, its
# socket and its descriptor already exist by the time the cap is consulted — which is most of what a
# cap on a world-open port is for. The limiter's own tests pass either way.
#
# **2. The slot must be released by `Drop`, never by hand.** ⛔⛔ This is exactly how the TDP client
# slot counter failed: it decremented explicitly, leaked a slot on **six** early-return paths, and at
# ten leaked slots refused every `pool_sv2` connection for ever until ghost-pool was restarted. A
# leak does not weaken the cap, it becomes the outage the cap was added to prevent. The accept task
# has four early `return`s plus a normal end, so any explicit release is a path that can be
# forgotten — and a fifth return added tomorrow would forget it.
#
# ## What it checks
#
# In `bins/pool-sv2/src/lib/channel_manager/mod.rs`:
#
#   * `try_acquire(` appears, and its line number is BEFORE the `task_manager_clone.spawn(` that
#     follows the accept arm;
#   * the slot is bound and held in the task (`let _slot =`);
#   * no `release(` / `.release_slot(` style call appears anywhere in the file.
#
# Exit 0 = the ordering holds, 1 = it does not, 2 = INCONCLUSIVE.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

SRC="bins/pool-sv2/src/lib/channel_manager/mod.rs"
[ -r "$SRC" ] || {
    echo "check-connection-slot-is-taken-before-spawn: INCONCLUSIVE — cannot read $SRC."
    echo "  It moved or was renamed; this check now covers nothing."
    exit 2
}

ACQ_LINE="$(/usr/bin/grep -n 'try_acquire(' "$SRC" | head -1 | cut -d: -f1)"
if [ -z "$ACQ_LINE" ]; then
    echo "check-connection-slot-is-taken-before-spawn: INCONCLUSIVE — no \`try_acquire(\` in $SRC."
    echo "  The SV2 accept path has NO connection limiter, so there is no ordering to protect."
    echo "  That is the pre-#994 state, not a clean tree."
    exit 2
fi

# The spawn that creates the per-connection task. Located INDEPENDENTLY of the acquire, not
# "at or after it" — searching relative to the acquire makes an inverted ordering look like a
# missing spawn. A self-test caught that: moving the acquire inside the task produced INCONCLUSIVE
# ("the accept arm was restructured") instead of naming the inversion, which is the wrong answer to
# give about the one defect this check exists to find.
SPAWN_LINE="$(/usr/bin/grep -n 'task_manager_clone.spawn(' "$SRC" | head -1 | cut -d: -f1)"
if [ -z "$SPAWN_LINE" ]; then
    echo "check-connection-slot-is-taken-before-spawn: INCONCLUSIVE — no \`task_manager_clone.spawn(\`"
    echo "  in $SRC. The accept arm was restructured and this check can no longer establish the"
    echo "  ordering."
    exit 2
fi

problems=0

if [ "$ACQ_LINE" -ge "$SPAWN_LINE" ]; then
    echo "  *** $SRC: try_acquire is at line $ACQ_LINE, the per-connection spawn at $SPAWN_LINE."
    echo "      The slot is taken INSIDE the spawned task, so a flood still costs a task, a socket"
    echo "      and a descriptor each before the cap is consulted."
    problems=$((problems + 1))
fi

if ! /usr/bin/grep -q 'let _slot = ' "$SRC"; then
    echo "  *** $SRC: no \`let _slot = \` binding — the slot is not held for the life of the task,"
    echo "      so it is released the moment the acquire expression ends and the cap counts nothing."
    problems=$((problems + 1))
fi

# An explicit release anywhere in this file means a path can forget it. `release(` in the limiter
# module itself is the Drop impl's own helper and is not in scope here.
HAND_RELEASE="$(/usr/bin/grep -nE '\.release(_slot)?\(' "$SRC" || true)"
if [ -n "$HAND_RELEASE" ]; then
    echo "  *** $SRC: the slot is released BY HAND:"
    printf '%s\n' "$HAND_RELEASE" | sed 's/^/        /'
    echo "      Release belongs in \`ConnectionSlot::drop\` alone. The TDP slot counter decremented"
    echo "      by hand and leaked on six early-return paths; this accept task has four."
    problems=$((problems + 1))
fi

if [ "$problems" -gt 0 ]; then
    echo
    echo "check-connection-slot-is-taken-before-spawn: $problems problem(s)."
    exit 1
fi

echo "check-connection-slot-is-taken-before-spawn: the slot is acquired at line $ACQ_LINE, before"
echo "  the per-connection spawn at line $SPAWN_LINE, held for the task's life, and released only"
echo "  by Drop"
exit 0
