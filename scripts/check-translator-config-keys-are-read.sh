#!/usr/bin/env bash
#
# Fail if the shipped translator config sets a key no Rust struct reads.
#
# ## Why this exists
#
# `TranslatorConfig` has **no** `#[serde(deny_unknown_fields)]`, so a key that no field matches is
# read, discarded, and never complained about — while reading, to anyone opening the file, exactly
# like a setting that is in force.
#
# `idle_timeout_secs = 600` sat in BOTH `config/sri/translator-config.toml` and the heredoc in
# `install-node.sh`, commented "disconnect miners with no shares". Nothing read it. There is no
# idle-miner reaper at all: the only one is `CHANNELLESS_REAP_TIMEOUT` (120s) in `sv1_server.rs`,
# which catches scanners that never open a channel. So every operator who read that file believed
# idle miners were disconnected after ten minutes, and none ever were.
#
# ⛔ This is the SAME defect `bins/ghost-pool/tests/shipped_config_templates.rs` exists for — all
# three shipped `config/*.toml` once carried a `public_mining` key the struct had removed. That
# test covers `NodeConfig` templates only; nothing covered the translator's.
#
# ⚠ Why a script rather than extending that test: the translator config is consumed by a separate
# binary whose config type is `pub(crate)`, so a test in another crate cannot deserialize it. And
# the fix CANNOT be to add `deny_unknown_fields` — the live fleet's deployed configs still carry
# the removed key, and the translator would refuse to start fleet-wide on the next roll.
#
# Exit 0 = every shipped key is read by a field, 1 = a key is ignored, 2 = INCONCLUSIVE.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

CFG="config/sri/translator-config.toml"
SRC_DIR="bins/translator-sv2/src"

[ -r "$CFG" ] || { echo "check-translator-config-keys-are-read: INCONCLUSIVE — cannot read $CFG"; exit 2; }
[ -d "$SRC_DIR" ] || { echo "check-translator-config-keys-are-read: INCONCLUSIVE — no $SRC_DIR"; exit 2; }

# Keys the shipped config SETS. Commented lines are documentation, not settings.
KEYS="$(grep -vE '^\s*#' "$CFG" | grep -oE '^\s*[a-z_][a-z0-9_]*\s*=' \
        | tr -d ' =' | sort -u)"

if [ -z "$KEYS" ] || [ "$(grep -c . <<<"$KEYS")" -lt 5 ]; then
    echo "check-translator-config-keys-are-read: INCONCLUSIVE — found only"
    echo "  $(grep -c . <<<"$KEYS" 2>/dev/null || echo 0) key(s) in $CFG. Expected ~20; the parser"
    echo "  no longer fits the file, so this examined almost nothing."
    exit 2
fi

# Every identifier the translator's own sources mention. Deliberately broad: a key may be read via
# a nested struct, a builder argument, or a `get`-style lookup, and a false ACCUSATION here is
# worse than a miss — it would train people to ignore the check.
MENTIONED="$(grep -rhoE '[a-z_][a-z0-9_]*' "$SRC_DIR" --include='*.rs' | sort -u)"

if [ -z "$MENTIONED" ]; then
    echo "check-translator-config-keys-are-read: INCONCLUSIVE — read no identifiers from $SRC_DIR"
    exit 2
fi

dead=0
checked=0
while IFS= read -r k; do
    [ -n "$k" ] || continue
    checked=$((checked + 1))
    if ! grep -qxF "$k" <<<"$MENTIONED"; then
        echo "  *** '$k' is set in $CFG but appears NOWHERE in $SRC_DIR"
        dead=$((dead + 1))
    fi
done <<< "$KEYS"

if [ "$dead" -gt 0 ]; then
    echo
    echo "check-translator-config-keys-are-read: $dead shipped key(s) are read by nothing."
    echo
    echo "  TranslatorConfig has no deny_unknown_fields, so such a key parses, is discarded, and"
    echo "  reads to an operator exactly like a setting in force. Either implement it or remove it"
    echo "  and say in the file that the behaviour does not exist."
    echo
    echo "  ⛔ Do NOT 'fix' this by adding deny_unknown_fields: deployed configs on the live fleet"
    echo "     still carry removed keys, and the translator would refuse to start fleet-wide."
    exit 1
fi

echo "check-translator-config-keys-are-read: all $checked shipped key(s) are read somewhere in $SRC_DIR"
exit 0
