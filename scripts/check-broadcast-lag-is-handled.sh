#!/usr/bin/env bash
#
# Fail if a `tokio::sync::broadcast` receiver loop treats `Lagged` as terminal.
#
# ## Why this exists
#
# `broadcast::Receiver::recv()` returns `Err(RecvError::Lagged(n))` to say "you missed n events" —
# a RECOVERABLE condition — and `Err(RecvError::Closed)` to say "every sender is gone", which is
# the only terminal one.
#
# `while let Ok(x) = rx.recv().await` cannot tell them apart. It exits on both. For an mpsc or
# async_channel receiver that is correct, because their only error IS closure. For a broadcast
# receiver it means a momentary overflow permanently ends the consumer, with no log on either side.
#
# ⛔ FOUR instances shipped (#984), all in live paths:
#
#   main.rs  round events        the task that CREATES THE PAYOUT PROPOSAL for a found block.
#                                `ShareSubmitted` rides the same 1000-slot channel at ~6.6/sec
#                                measured, so ~150s of stall overflows it — and the heaviest work
#                                in that loop is the BlockFound arm, making the FIRST block the
#                                pool ever wins the moment of peak risk.
#   main.rs  ZMQ blocks          the node stops reacting to new blocks at all.
#   main.rs  template events     template handling stops.
#   websocket.rs  dashboard      a slow client's event stream silently ends.
#
# `reorg.rs` and `template_provider.rs` had it right the whole time, so this was never house style
# — which is also why nobody noticed the four that did not.
#
# ## What it checks
#
# Every `while let Ok(..) = <v>.recv().await` whose receiver `<v>` is bound from something this
# script can tie to `broadcast` — a `subscribe*()` call or an explicit `broadcast::` type/channel.
#
# ⚠ Deliberately conservative. A receiver whose origin cannot be established is NOT flagged:
# `async_channel::unbounded()` and `mpsc` receivers are correct with `while let Ok`, and flagging
# them would train people to ignore this check. False negatives are survivable here; false
# positives are not.
#
# Exit 0 = no broadcast loop discards `Lagged`, 1 = one does, 2 = INCONCLUSIVE.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

# Production Rust only: tests and fixtures may legitimately take shortcuts.
FILES="$(git ls-files 'bins/*.rs' 'crates/*.rs' 2>/dev/null | grep -vE '/tests?/|_test\.rs$')"
if [ -z "$FILES" ]; then
    echo "check-broadcast-lag-is-handled: INCONCLUSIVE — no Rust sources found under bins/ crates/."
    echo "  Either the layout changed or this is not a git checkout; nothing was examined."
    exit 2
fi

# Sanity floor: if the pattern cannot be found at all, the regex has rotted rather than the tree
# having become clean. A check that examined nothing must not report success.
TOTAL_RECV="$(grep -hcE '\.recv\(\)\.await' $FILES 2>/dev/null | paste -sd+ | bc 2>/dev/null || echo 0)"
if [ "${TOTAL_RECV:-0}" -lt 5 ]; then
    echo "check-broadcast-lag-is-handled: INCONCLUSIVE — found only ${TOTAL_RECV:-0} \`.recv().await\`"
    echo "  call sites across bins/ and crates/. Expected dozens; the matcher has probably rotted."
    exit 2
fi

bad=0
checked=0

while IFS= read -r f; do
    [ -n "$f" ] || continue
    # Each `while let Ok(<binding>) = <recv_var>.recv().await`
    while IFS=: read -r ln rest; do
        [ -n "${ln:-}" ] || continue
        var="$(printf '%s' "$rest" | sed -nE 's/.*while let Ok\([^)]*\) = ([A-Za-z0-9_]+)\.recv\(\)\.await.*/\1/p')"
        [ -n "$var" ] || continue

        # Establish the receiver's origin from its binding site ANYWHERE in the file. Only a
        # subscribe*() call or an explicit broadcast:: mention counts as evidence.
        origin="$(grep -nE "(let +(mut +)?${var}\b|${var} *=)" "$f" \
                  | grep -E "subscribe[A-Za-z_]*\(|broadcast::" | head -1)"
        [ -n "$origin" ] || continue        # origin unknown -> not ours to judge

        checked=$((checked + 1))
        echo "  *** $f:$ln — \`while let Ok(..) = $var.recv().await\` on a broadcast receiver"
        echo "      bound at: $(printf '%s' "$origin" | cut -c1-100)"
        bad=$((bad + 1))
    done < <(grep -nE 'while let Ok\([^)]*\) = [A-Za-z0-9_]+\.recv\(\)\.await' "$f" 2>/dev/null)
done <<< "$FILES"

if [ "$bad" -gt 0 ]; then
    echo
    echo "check-broadcast-lag-is-handled: $bad broadcast receiver loop(s) treat \`Lagged\` as terminal."
    echo
    echo "  \`Lagged\` means \"you missed n events\" and is RECOVERABLE. \`while let Ok\` exits on it,"
    echo "  permanently, with no log. Match on the error instead and \`continue\` on \`Lagged\`,"
    echo "  breaking only on \`Closed\` — see bins/ghost-pool/src/reorg.rs for the shape."
    exit 1
fi

echo "check-broadcast-lag-is-handled: no broadcast receiver loop discards Lagged"
echo "  (${TOTAL_RECV} recv() sites scanned; receivers whose origin is not provably broadcast are"
echo "   deliberately not judged — mpsc/async_channel are correct with \`while let Ok\`)"
exit 0
