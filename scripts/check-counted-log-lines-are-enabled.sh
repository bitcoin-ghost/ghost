#!/usr/bin/env bash
#
# Fail if `deploy-node.sh` counts a log line the fleet's RUST_LOG filters out.
#
# ## Why this exists
#
# The deploy gate judges a swap partly on `batches delivered`, counted by grepping sri-pool's
# journal for `Share batch sent successfully`. That line is `debug!` in `pool_sv2::share_webhook`,
# and every node runs
#
#     RUST_LOG=info,pool_sv2::channel_manager::mining_message_handler=debug
#
# — global `info`, debug for ONE module, and not that one. So the count was **structurally zero on
# every node, for ever**, while the script's own comment told the reader that zero meant "no batch
# was accepted" — the #742 signature, the thing that destroys shares. Alarming and meaningless at
# once (#947). Measured on vm5: 0 successes in 2h, with `batch_size = 1` and ~74 shares/5min.
#
# Nobody wrote a bug. A log level was narrowed in one file and a metric quietly died in another,
# and nothing connected them.
#
# ## What it checks
#
# For every literal `deploy-node.sh` counts out of sri-pool's journal: find where pool_sv2 logs
# it, read the macro level, derive the module path from the file path, and require the canonical
# RUST_LOG to enable that module at that level.
#
# The RUST_LOG value is read from the canonical drop-in, not repeated here.
#
# Exit 0 = every counted line is observable, 1 = one is filtered out, 2 = INCONCLUSIVE (a source
# this depends on could not be read or parsed).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

DEPLOY="scripts/deploy-node.sh"
DROPIN="config/sri/sri-pool.service.d/debug.conf"
SRCDIR="bins/pool-sv2/src"

for f in "$DEPLOY" "$DROPIN"; do
    [ -r "$f" ] || { echo "check-counted-log-lines-are-enabled: INCONCLUSIVE — cannot read $f"; exit 2; }
done

RUST_LOG_VALUE="$(grep -oE '^Environment=RUST_LOG=.*' "$DROPIN" | head -1 | sed 's/^Environment=RUST_LOG=//')"
[ -n "$RUST_LOG_VALUE" ] || {
    echo "check-counted-log-lines-are-enabled: INCONCLUSIVE — no Environment=RUST_LOG= in $DROPIN"
    exit 2
}

# The literals counted from sri-pool's journal: `grep -c 'LITERAL'` inside webhook_activity_since.
LITERALS="$(awk '/^webhook_activity_since\(\)/,/^}/' "$DEPLOY" \
            | grep -oE "grep -c '[^']+'" | sed -E "s/grep -c '(.*)'/\1/" | grep -vE '^\.$')"

if [ -z "$LITERALS" ]; then
    echo "check-counted-log-lines-are-enabled: INCONCLUSIVE — found no counted literals in"
    echo "  webhook_activity_since() in $DEPLOY. It was renamed or reshaped; this examined nothing."
    exit 2
fi

# Rank by verbosity so "is LEVEL enabled by DIRECTIVE" is a comparison.
level_rank() {
    case "$1" in
        error) echo 1 ;; warn) echo 2 ;; info) echo 3 ;; debug) echo 4 ;; trace) echo 5 ;;
        *) echo 0 ;;
    esac
}

# Does RUST_LOG enable `module` at `level`? Longest matching module directive wins, as env_logger
# and tracing-subscriber both resolve it; otherwise the bare global level applies.
enabled() {
    local module="$1" level="$2" best_len=-1 best_level="" d dmod dlev
    local want; want="$(level_rank "$level")"
    IFS=',' read -ra DIRS <<< "$RUST_LOG_VALUE"
    for d in "${DIRS[@]}"; do
        if [[ "$d" == *=* ]]; then
            dmod="${d%%=*}"; dlev="${d##*=}"
            # `a::b` directive covers `a::b::c`
            if [ "$module" = "$dmod" ] || [[ "$module" == "$dmod"::* ]]; then
                if [ "${#dmod}" -gt "$best_len" ]; then best_len="${#dmod}"; best_level="$dlev"; fi
            fi
        else
            if [ "$best_len" -lt 0 ]; then best_level="$d"; fi
        fi
    done
    [ -n "$best_level" ] || return 1
    [ "$(level_rank "$best_level")" -ge "$want" ]
}

bad=0
while IFS= read -r lit; do
    [ -n "$lit" ] || continue
    # Where pool_sv2 emits it, and with which macro.
    hit="$(grep -rn --include=*.rs -F "$lit" "$SRCDIR" 2>/dev/null \
           | grep -E '(error|warn|info|debug|trace)!' | head -1)"
    if [ -z "$hit" ]; then
        echo "  ?  '$lit' — not found as a log call under $SRCDIR"
        echo "     Either it moved, or the deploy gate counts something pool_sv2 never logs."
        bad=$((bad + 1))
        continue
    fi
    file="${hit%%:*}"
    macro="$(grep -oE '(error|warn|info|debug|trace)!' <<<"$hit" | head -1 | tr -d '!')"
    # bins/pool-sv2/src/lib/share_webhook.rs -> pool_sv2::share_webhook
    rel="${file#"$SRCDIR"/}"; rel="${rel%.rs}"; rel="${rel#lib/}"
    module="pool_sv2::$(printf '%s' "$rel" | tr '/' ':' | sed 's/::*/::/g')"
    module="${module%::mod}"
    if enabled "$module" "$macro"; then
        echo "  ✓  '$lit' — ${macro}! in ${module} (enabled)"
    else
        echo "  *** '$lit' — ${macro}! in ${module} is FILTERED OUT by RUST_LOG"
        echo "      $RUST_LOG_VALUE"
        bad=$((bad + 1))
    fi
done <<< "$LITERALS"

if [ "$bad" -gt 0 ]; then
    echo
    echo "check-counted-log-lines-are-enabled: $bad counted line(s) are not observable."
    echo
    echo "  A count that cannot exceed zero is worse than no metric: the deploy gate prints it"
    echo "  next to numbers that DO work, and its comment tells the reader what zero means (#947)."
    echo "  Either enable the module in $DROPIN (and the other three copies of that value), or"
    echo "  stop counting the line."
    exit 1
fi

echo "check-counted-log-lines-are-enabled: all counted line(s) are enabled by the fleet RUST_LOG"
exit 0
