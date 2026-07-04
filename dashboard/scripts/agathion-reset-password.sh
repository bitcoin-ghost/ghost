#!/usr/bin/env bash
# agathion-reset-password.sh — Recover from a forgotten Agathion Node dashboard password.
#
# The dashboard authenticates with a single DASHBOARD_PASSWORD, read from a
# systemd drop-in, and binds loopback only. A forgotten password therefore
# locks the operator out with no web-based recovery — by design, because a web
# reset endpoint would be an auth bypass. The recovery credential is instead
# *node access itself*: whoever can run this script as root on the node is,
# definitionally, the operator, so it is safe to let them set a new password.
#
# This script:
#   1. Generates a strong password (or accepts one via --password).
#   2. Writes it to the dashboard's systemd drop-in
#      (/etc/systemd/system/ghost-dashboard.service.d/override.conf) as the
#      DASHBOARD_PASSWORD= line, preserving every other Environment= entry.
#   3. Drops any explicit DASHBOARD_JWT_SECRET= line so the signing secret
#      re-derives from the new password — this, plus the restart, invalidates
#      every existing ghost-session cookie (old sessions die).
#   4. Runs `systemctl daemon-reload && systemctl restart <service>`.
#   5. Prints the new password.
#
# It is idempotent (re-running simply sets a fresh password), backs up the
# drop-in before touching it, and requires root.
#
# Usage:
#   sudo scripts/agathion-reset-password.sh                 # generate a password
#   sudo scripts/agathion-reset-password.sh --password 'xy' # set a specific one
#   sudo scripts/agathion-reset-password.sh --no-restart    # write only, no restart
#   sudo scripts/agathion-reset-password.sh --service my-dashboard.service
#
set -euo pipefail

SERVICE="ghost-dashboard.service"
NEW_PASSWORD=""
DO_RESTART=1

usage() {
    cat <<'EOF'
Reset the Agathion Node dashboard password (run on the node as root).

Options:
  -p, --password <value>   Use this password instead of generating one.
      --service <name>     systemd unit to update (default: ghost-dashboard.service).
      --no-restart         Write the drop-in but do not daemon-reload/restart.
  -h, --help               Show this help.

The new password is printed on success. Store it somewhere safe.
EOF
}

die() {
    echo "error: $*" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--password)
            [[ $# -ge 2 ]] || die "$1 requires a value"
            NEW_PASSWORD="$2"
            shift 2
            ;;
        --service)
            [[ $# -ge 2 ]] || die "$1 requires a value"
            SERVICE="$2"
            shift 2
            ;;
        --no-restart)
            DO_RESTART=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1 (see --help)"
            ;;
    esac
done

# Normalise the service name so both `foo` and `foo.service` work.
[[ "$SERVICE" == *.service ]] || SERVICE="${SERVICE}.service"

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------
[[ "$(id -u)" -eq 0 ]] || die "must run as root (try: sudo $0)"

DROPIN_DIR="/etc/systemd/system/${SERVICE}.d"
OVERRIDE="${DROPIN_DIR}/override.conf"

# ---------------------------------------------------------------------------
# Resolve the new password
# ---------------------------------------------------------------------------
if [[ -z "$NEW_PASSWORD" ]]; then
    command -v openssl >/dev/null 2>&1 || die "openssl not found; pass --password instead"
    # 24 random bytes -> 32 base64 chars (~144 bits). base64's alphabet
    # (A-Za-z0-9+/=) contains no characters that need escaping in a
    # double-quoted systemd Environment= value.
    NEW_PASSWORD="$(openssl rand -base64 24)"
    GENERATED=1
else
    GENERATED=0
fi

[[ -n "$NEW_PASSWORD" ]] || die "password is empty"
# Reject characters we cannot safely place in a double-quoted Environment=
# value. This never rejects a generated password; it only guards operator
# input against silently corrupting the drop-in.
case "$NEW_PASSWORD" in
    *'"'*|*'\'*)
        die 'password must not contain a double-quote (") or backslash (\)'
        ;;
esac
if [[ "$NEW_PASSWORD" == *$'\n'* ]]; then
    die "password must not contain a newline"
fi

ENV_LINE="Environment=\"DASHBOARD_PASSWORD=${NEW_PASSWORD}\""

# ---------------------------------------------------------------------------
# Build the new drop-in contents
# ---------------------------------------------------------------------------
mkdir -p "$DROPIN_DIR"

TMP="$(mktemp "${DROPIN_DIR}/override.conf.new.XXXXXX")"
# Ensure the temp file is cleaned up on any early exit.
trap 'rm -f "$TMP"' EXIT

if [[ -f "$OVERRIDE" ]] && grep -q '^\[Service\]' "$OVERRIDE"; then
    # Existing, well-formed drop-in: back it up, then rebuild it preserving
    # every line except the managed DASHBOARD_PASSWORD / DASHBOARD_JWT_SECRET
    # entries, inserting the fresh password line right after [Service].
    BACKUP="${OVERRIDE}.bak.$(date +%Y%m%d-%H%M%S)"
    cp -p "$OVERRIDE" "$BACKUP"
    echo "backed up existing drop-in -> $BACKUP" >&2

    awk -v newline="$ENV_LINE" '
        # Drop any previously managed lines (any quoting style).
        /^[[:space:]]*Environment=.*DASHBOARD_PASSWORD=/ { next }
        /^[[:space:]]*Environment=.*DASHBOARD_JWT_SECRET=/ { next }
        { print }
        /^\[Service\]/ && inserted == 0 { print newline; inserted = 1 }
    ' "$OVERRIDE" > "$TMP"
else
    # No drop-in yet (the common lock-out case), or a malformed one without a
    # [Service] section: write a clean, minimal drop-in from scratch. Back up
    # any pre-existing (malformed) file first so nothing is lost.
    if [[ -f "$OVERRIDE" ]]; then
        BACKUP="${OVERRIDE}.bak.$(date +%Y%m%d-%H%M%S)"
        cp -p "$OVERRIDE" "$BACKUP"
        echo "backed up existing drop-in -> $BACKUP" >&2
    fi
    {
        echo "[Service]"
        echo "$ENV_LINE"
    } > "$TMP"
fi

# Lock down and move into place atomically. The drop-in holds the password in
# clear, so it must stay root-only.
chown root:root "$TMP"
chmod 600 "$TMP"
mv -f "$TMP" "$OVERRIDE"
trap - EXIT
echo "wrote $OVERRIDE" >&2

# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------
if [[ "$DO_RESTART" -eq 1 ]]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
        systemctl restart "$SERVICE"
        echo "restarted $SERVICE" >&2
    else
        echo "warning: systemctl not found; skipped reload/restart" >&2
    fi
else
    echo "skipped daemon-reload/restart (--no-restart); run:" >&2
    echo "  systemctl daemon-reload && systemctl restart $SERVICE" >&2
fi

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
echo
echo "==================================================================="
if [[ "$GENERATED" -eq 1 ]]; then
    echo " New Agathion Node dashboard password (generated):"
else
    echo " New Agathion Node dashboard password (as provided):"
fi
echo
echo "     $NEW_PASSWORD"
echo
echo " Store it in your password manager. All existing dashboard"
echo " sessions have been invalidated; log in again at /login."
echo "==================================================================="
