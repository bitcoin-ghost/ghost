#!/usr/bin/env bash
#
# ghost-autoupdate-toggle — flip the node auto-update opt-in.
#
# This is the ONLY privileged operation the node dashboard performs. The
# dashboard service user (ghost) may run it via a tightly-scoped sudoers rule
# (/etc/sudoers.d/ghost-autoupdate) that pins the exact argument to `on` or
# `off` — nothing else. The script takes NO free-form input: it writes a fixed
# AUTO_UPDATE=true|false to /etc/ghost/auto-update.conf and enables/disables the
# timer to match. There is no path by which the dashboard can run an arbitrary
# command or smuggle other state through this helper.
#
# Installed root-owned 0755 at /opt/ghost/bin/ghost-autoupdate-toggle.
#
set -euo pipefail

CONF="${GHOST_AUTOUPDATE_CONF:-/etc/ghost/auto-update.conf}"
SYSTEMCTL="${GHOST_SYSTEMCTL:-systemctl}"

case "${1:-}" in
  on)  val="true" ;;
  off) val="false" ;;
  *) echo "usage: ghost-autoupdate-toggle on|off" >&2; exit 2 ;;
esac

umask 022
mkdir -p "$(dirname "$CONF")"
tmp="$(mktemp "${CONF}.XXXXXX")"
cat > "$tmp" <<EOF
# Bitcoin Ghost node auto-update opt-in.
# Managed by the installer and the node dashboard (ghost-autoupdate-toggle).
# When AUTO_UPDATE is anything other than exactly 'true', the updater is a no-op.
AUTO_UPDATE=${val}
EOF
chmod 644 "$tmp"
mv -f "$tmp" "$CONF"

# Keep the timer state in lockstep with the opt-in. Best-effort: the conf flag
# is the authoritative gate, so a systemd hiccup here can never cause an update.
if [[ "$val" == "true" ]]; then
  "$SYSTEMCTL" enable --now ghost-auto-update.timer >/dev/null 2>&1 || true
else
  "$SYSTEMCTL" disable --now ghost-auto-update.timer >/dev/null 2>&1 || true
fi

echo "auto-update set to ${val}"
