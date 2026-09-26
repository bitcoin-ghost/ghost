#!/usr/bin/env bash
#
# Fail if a key-material path draws from anything but the OS CSPRNG.
#
# ## Why this exists
#
# E-1 forbids key material from a non-OS generator. `rand::thread_rng()` is a ChaCha12 CSPRNG
# seeded from the OS — sound in practice, and NOT the point. The point is that it has been
# substituted for `OsRng` three separate times in this repo, each time silently:
#
#   * `Keystore::create` drew the wallet seed from it (`4d52543f0`, #705)
#   * `Secp256k1SecretKey::generate` minted the SV2 AUTHORITY keypair from it, while its own doc
#     comment said "from the operating-system CSPRNG" (#705)
#   * `SignatureService::sign` drew the signing randomness from it (#705)
#
# That last pair is the shape of the Coldcard failure: a seed from a generator nobody audited,
# with documentation asserting otherwise. ~1,816 BTC swept from 5,200+ addresses. E-5 correctly
# forbids statistical output tests, which would not have caught it either — Yasmarang's output is
# well distributed, and only the seed SPACE was small. So the only defence is reading the source,
# which is what this does.
#
# ## What it checks
#
# The paths below generate or sign with key material. None may CALL `thread_rng()`, `SmallRng`,
# `StdRng::seed_from_u64` or `rand::random()`. Doc comments mentioning them are fine — and
# necessary, since the fixes explain themselves.
#
# Deliberately a path allowlist rather than a repo-wide sweep. Shuffling a peer list or jittering
# a retry from `thread_rng()` is fine, and a check that flagged those would be noise people learn
# to skip. Add a path here when it starts handling key material.
#
# Exit 0 = clean, 1 = a key-material path uses a non-OS generator, 2 = INCONCLUSIVE (a listed
# path is missing, so the check examined less than it claims).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PATHS=(
    "crates/stratum-apps/src/key_utils"
    "crates/ghost-common/src/signer.rs"
    "crates/ghost-keys/src"
    "crates/ghost-lock/src"
    "apps/wraith-wallet/core/src/keystore.rs"
)

BANNED='thread_rng\(|SmallRng|StdRng::seed_from_u64|rand::random\('

missing=0
for p in "${PATHS[@]}"; do
    [ -e "$p" ] || { echo "  MISSING: $p"; missing=$((missing + 1)); }
done
if [ "$missing" -gt 0 ]; then
    echo "check-key-material-rng: INCONCLUSIVE — $missing listed path(s) do not exist."
    echo "  Either they moved or the list is stale. Either way this examined less than it claims,"
    echo "  so it must not report success. Update the list."
    exit 2
fi

# Strip comment lines first: a doc comment naming the banned API is how the fixes document
# themselves, and flagging those would make the check impossible to satisfy honestly.
HITS=""
for p in "${PATHS[@]}"; do
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        code="${line#*:*:}"
        trimmed="$(printf '%s' "$code" | sed 's/^[[:space:]]*//')"
        case "$trimmed" in
            '//'*|'///'*|'//!'*|'*'*) continue ;;
        esac
        HITS="$HITS$line"$'\n'
    done < <(grep -rHnE "$BANNED" --include=*.rs "$p" 2>/dev/null \
             | grep -viE "#\[cfg\(test\)\]|/tests?/" || true)
done

if [ -n "$HITS" ]; then
    echo "check-key-material-rng: a key-material path draws from a non-OS generator."
    echo
    printf '%s' "$HITS" | sed 's/^/  *** /'
    echo
    echo "  Use \`rand::rngs::OsRng\`. E-1 forbids key material from a generator other than the"
    echo "  operating system's, and this exact substitution has been made three times here — once"
    echo "  while the doc comment claimed OsRng (#705)."
    exit 1
fi

echo "check-key-material-rng: all ${#PATHS[@]} key-material path(s) use the OS CSPRNG"
exit 0
