#!/usr/bin/env bash
# Rotate one node's SV2 Noise authority keypair.
#
# vm1-4 shipped with the keypair checked into config/sri/pool-config.toml, which is also the
# SRI project's test fixture — so the secret half is public in two repos. Anyone holding it
# can present as this pool to an SV2 miner or translator. Deleting it from the repo fixes
# nothing (git history, upstream); rotation is the fix.
#
# The translator PINS the pool's public key, so both files must change together and the pool
# must be LISTENING on the new key before the translator dials it. If they disagree the Noise
# handshake fails and the node stops accepting work — which is why this is one script rather
# than a sequence of remembered steps.
#
# TIMING, learned by rehearsing on vm6: pool_sv2 does not bind :34255 when systemd reports the
# unit active. It first completes a Noise handshake with the template provider on :8442, which
# took ~60s there. Its monitoring port :9090 comes up almost immediately, so :9090 is NOT a
# readiness signal for the translator — sri-translator's own ExecStartPre polls :9090 and can
# still lose the race. Wait for :34255 itself.
#
# Usage: rotate-sv2-authority.sh   (run ON the node, as root)
set -euo pipefail

POOL_CONF=/etc/ghost/pool-config.toml
TRAN_CONF=/etc/ghost/translator-config.toml
STAMP=$(date +%Y%m%d-%H%M%S)
SV2_PORT=34255
POOL_READY_TIMEOUT=240
TRAN_READY_TIMEOUT=180

restore() {
    cp -a "${POOL_CONF}.bak.${STAMP}" "$POOL_CONF"
    cp -a "${TRAN_CONF}.bak.${STAMP}" "$TRAN_CONF"
    systemctl restart sri-pool || true
    for _ in $(seq 1 "$POOL_READY_TIMEOUT"); do
        ss -ltn 2>/dev/null | grep -q ":${SV2_PORT}" && break
        sleep 1
    done
    systemctl restart sri-translator || true
}

# REFUSE if anything outside this box is connected to the SV2 port.
#
# SV2-DIRECT miners pin the pool's authority PUBLIC key. Rotating it disconnects every one of
# them, and there is no in-band renegotiation — the miner keeps the old key until a human edits
# its config. Nothing else in this script can detect that, and nothing reports it afterwards:
# from the pool's side the connection simply drops.
#
# This is not hypothetical. The 2026-07-27 rotation took `bitaxe4` offline for ~14.5 hours. It
# was found because a public site showed 7 miners instead of 8, not because anything alerted —
# and `mesh_active_miners` dropping 8->7 during the change was dismissed as load-balancer churn.
#
# Every node normally shows exactly TWO established connections on :34255, both loopback: the
# local translator<->pool pair. Anything else is an external miner that this rotation will break.
#
# LIMITS OF THIS CHECK, stated plainly: it is a point-in-time snapshot. It catches a miner that
# is connected right now — which is the case that matters, since an actively mining SV2-direct
# peer holds a persistent connection. It CANNOT catch a miner that happens to be offline during
# the rotation and reconnects afterwards with the old key. Nothing on the node can, because the
# pinned key lives only on the miner. So this reduces the hazard; it does not remove it, and the
# runbook step of telling every SV2-direct operator still applies.
EXTERNAL=$(ss -tn state established 2>/dev/null | grep ":${SV2_PORT}" | grep -vc '127\.0\.0\.1' || true)
if [ "${EXTERNAL:-0}" -gt 0 ]; then
    echo "REFUSED: ${EXTERNAL} external connection(s) on :${SV2_PORT} — these are SV2-direct" >&2
    echo "         miners that pin this key and will be disconnected until reconfigured:" >&2
    ss -tn state established 2>/dev/null | grep ":${SV2_PORT}" | grep -v '127\.0\.0\.1' \
        | awk '{print "           " $5}' >&2
    echo "" >&2
    echo "         Rotate anyway with ROTATE_BREAK_SV2_DIRECT=1, then reconfigure each miner" >&2
    echo "         with the NEW public key this script prints." >&2
    [ "${ROTATE_BREAK_SV2_DIRECT:-0}" = "1" ] || exit 1
    echo "  WARNING: proceeding — the miners above will stay down until reconfigured." >&2
fi

for f in "$POOL_CONF" "$TRAN_CONF"; do
    [[ -r "$f" ]] || { echo "REFUSED: cannot read $f" >&2; exit 1; }
    cp -a "$f" "${f}.bak.${STAMP}"
done
echo "  backups: *.bak.${STAMP}"

KP=$(/opt/ghost/bin/pool_sv2 --generate-key 2>/dev/null)
NEW_PUB=$(sed -n 's/^authority_public_key *= *"\(.*\)"$/\1/p' <<<"$KP")
NEW_SEC=$(sed -n 's/^authority_secret_key *= *"\(.*\)"$/\1/p' <<<"$KP")
[[ -n "$NEW_PUB" && -n "$NEW_SEC" ]] || { echo "REFUSED: could not parse a new keypair" >&2; exit 1; }

OLD_PUB=$(sed -n 's/^authority_public_key *= *"\(.*\)"$/\1/p' "$POOL_CONF")
[[ "$NEW_PUB" != "$OLD_PUB" ]] || { echo "REFUSED: generated key matches the current one" >&2; exit 1; }
echo "  rotating ${OLD_PUB:0:12}... -> ${NEW_PUB:0:12}..."

# Values are base58 (no regex metacharacters), so plain substitution is safe.
sed -i "s|^authority_public_key *= *\".*\"|authority_public_key = \"${NEW_PUB}\"|" "$POOL_CONF"
sed -i "s|^authority_secret_key *= *\".*\"|authority_secret_key = \"${NEW_SEC}\"|" "$POOL_CONF"
sed -i "s|^authority_pubkey *= *\".*\"|authority_pubkey = \"${NEW_PUB}\"|" "$TRAN_CONF"

# Verify the two agree BEFORE restarting anything — a mismatch here is a dead node.
P=$(sed -n 's/^authority_public_key *= *"\(.*\)"$/\1/p' "$POOL_CONF")
T=$(sed -n 's/^authority_pubkey *= *"\(.*\)"$/\1/p' "$TRAN_CONF")
if [[ "$P" != "$T" || "$P" != "$NEW_PUB" ]]; then
    echo "REFUSED: pool/translator keys disagree after edit — restoring" >&2
    cp -a "${POOL_CONF}.bak.${STAMP}" "$POOL_CONF"
    cp -a "${TRAN_CONF}.bak.${STAMP}" "$TRAN_CONF"
    exit 1
fi

systemctl restart sri-pool

echo -n "  waiting for pool to bind :${SV2_PORT} "
ready=no
for _ in $(seq 1 "$POOL_READY_TIMEOUT"); do
    if ss -ltn 2>/dev/null | grep -q ":${SV2_PORT}"; then ready=yes; break; fi
    sleep 1
done
if [[ "$ready" != "yes" ]]; then
    echo "- TIMEOUT after ${POOL_READY_TIMEOUT}s"
    echo "ROLLING BACK: pool never bound :${SV2_PORT}" >&2
    restore
    exit 2
fi
echo "- up"

systemctl restart sri-translator

echo -n "  waiting for translator to become active "
ready=no
for _ in $(seq 1 "$TRAN_READY_TIMEOUT"); do
    [[ "$(systemctl is-active sri-translator 2>/dev/null)" == "active" ]] && { ready=yes; break; }
    sleep 1
done
if [[ "$ready" != "yes" ]]; then
    echo "- TIMEOUT after ${TRAN_READY_TIMEOUT}s"
    echo "ROLLING BACK: translator did not come up on the new key" >&2
    restore
    exit 3
fi
echo "- up"

# Prove the handshake actually succeeded rather than trusting unit state: the translator must
# hold an ESTABLISHED connection to the pool's SV2 port. `active` only means the process is
# running, and it stays active while retrying a handshake it will never complete.
#
# Use `state established` rather than grepping for ESTAB — ss prints the state in the FIRST
# column, so a pattern like ":34255.*ESTAB" can never match. That cost a rehearsal.
echo -n "  waiting for the translator->pool handshake "
ready=no
for _ in $(seq 1 60); do
    if ss -tn state established 2>/dev/null | grep -q ":${SV2_PORT}"; then ready=yes; break; fi
    sleep 1
done
if [[ "$ready" != "yes" ]]; then
    echo "- TIMEOUT"
    echo "ROLLING BACK: no established translator->pool connection on :${SV2_PORT}" >&2
    restore
    exit 4
fi
echo "- connected"

echo "  OK: rotated to ${NEW_PUB:0:12}..., translator connected"
