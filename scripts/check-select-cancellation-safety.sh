#!/usr/bin/env bash
#
# Fail if a `tokio::select!` branch future is a handler that consumes from a channel.
#
# ## Why this exists
#
# `async_channel::recv()` is cancellation-safe: drop the future and nothing is lost. A handler
# that calls `recv()` and THEN does its work is not, because by the time it is doing that work the
# message is already OFF the queue. When a sibling branch completes first, `select!` drops the
# partially-run future and the message goes with it — no error, no retry, nothing logged.
#
# It has appeared FIVE times in this repo:
#
#   * `ChannelManager` — both directions (#854, fixed in #927)
#   * `Sv1Server`      — both directions (#926)
#   * `Downstream`     — both directions (#926)
#
# The shape is always the same and always invisible: each loop is correct in isolation, each
# handler is correct in isolation, and the defect only exists in the composition.
#
# ## What it checks
#
# No `select!` branch future under `bins/` may be a `handle_*` method call. The fix is always the
# same: put the `recv()` in the branch and the handling in the branch BODY, which runs to
# completion and cannot be cancelled by a sibling becoming ready.
#
# Deliberately narrow — it matches the `handle_*` naming this codebase already uses for the
# offending pattern, rather than trying to decide in shell which futures are cancellation-safe.
# A branch calling `.recv()`, `.accept()`, `.cancelled()` or a timer is fine and is not matched.
#
# Exit 0 = clean, 1 = an unsafe branch exists, 2 = INCONCLUSIVE (no `select!` found at all, so
# this examined nothing and must not report success).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Existing instances are baselined in scripts/select-cancellation-baseline.txt, keyed by
# "path handler_name" so the list survives edits above it. This is a RATCHET: anything NOT in the
# baseline fails, so the debt cannot grow while it is being paid down. 21 instances across
# jd-client-sv2, jd-server-sv2 and pool-sv2 were present when this was written (#926) — pool-sv2
# runs on the production fleet.
BASELINE="$REPO_ROOT/scripts/select-cancellation-baseline.txt"
[ -r "$BASELINE" ] || { echo "check-select-cancellation-safety: baseline missing at $BASELINE"; exit 2; }

# Sanity: the check must be looking at something.
if [ "$(grep -rl "tokio::select!" --include=*.rs bins/ 2>/dev/null | wc -l)" -eq 0 ]; then
    echo "check-select-cancellation-safety: INCONCLUSIVE — no \`tokio::select!\` found under bins/."
    echo "  This examined nothing, so it must not report success."
    exit 2
fi

FOUND="$(grep -rnE '^[[:space:]]*[a-z_]+ = [^=]*\.handle_[a-z_]+\(' --include=*.rs bins/ 2>/dev/null \
         | grep -F '=>' || true)"

NEW=""
while IFS= read -r line; do
    [ -n "$line" ] || continue
    key="$(printf '%s' "$line" | sed -E 's|^([^:]+):[0-9]+:.*\.(handle_[a-z_]+)\(.*|\1 \2|')"
    grep -qxF "$key" "$BASELINE" || NEW="$NEW$line"$'\n'
done <<< "$FOUND"

if [ -n "$NEW" ]; then
    echo "check-select-cancellation-safety: a NEW select! branch consumes a message it can lose."
    echo
    printf '%s' "$NEW" | sed 's/^/  *** /'
    echo
    echo "  A handler that recv()s and then works is NOT cancellation-safe: when a sibling"
    echo "  branch completes first, select! drops it along with the message it already took"
    echo "  off the queue — silently, with nothing to retry."
    echo
    echo "  Put the recv() in the select! branch and the handling in the branch BODY:"
    echo
    echo "      msg = self.<...>_receiver.recv() => {"
    echo "          let res = match msg {"
    echo "              Ok(m) => self.process_<...>(m).await,"
    echo "              Err(e) => Err(TproxyError::shutdown(e)),"
    echo "          };"
    echo "      }"
    echo
    echo "  See #854 and #926. Existing debt is listed in scripts/select-cancellation-baseline.txt;"
    echo "  that list may shrink, never grow."
    exit 1
fi

echo "check-select-cancellation-safety: no select! branch consumes a message it can lose"
exit 0
