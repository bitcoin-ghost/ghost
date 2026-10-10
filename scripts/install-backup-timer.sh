#!/usr/bin/env bash
# install-backup-timer.sh — Install systemd timer for automated database backups
# Usage: sudo ./install-backup-timer.sh [--ghost-dir /home/ghost/.ghost]

set -euo pipefail

GHOST_DIR="${1:-/home/ghost/.ghost}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKUP_SCRIPT="$SCRIPT_DIR/backup-databases.sh"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must run as root (sudo)"
    exit 1
fi

if [ ! -f "$BACKUP_SCRIPT" ]; then
    echo "ERROR: backup-databases.sh not found at $BACKUP_SCRIPT"
    exit 1
fi

# ⛔ The backup script sources this and refuses to start without it. Checked here because the failure
# otherwise appears days later as a timer that has been failing quietly since it was installed.
if [ ! -f "$SCRIPT_DIR/lib/backup-retention.sh" ]; then
    echo "ERROR: backup-databases.sh needs $SCRIPT_DIR/lib/backup-retention.sh and it is not there"
    exit 1
fi

chmod +x "$BACKUP_SCRIPT"

# Create systemd service unit
cat > /etc/systemd/system/ghost-backup.service <<EOF
[Unit]
Description=Ghost Pool Database Backup
After=network.target

[Service]
Type=oneshot
ExecStart=$BACKUP_SCRIPT $GHOST_DIR
User=ghost
Group=ghost

# ⛔ User=ghost is load-bearing, not tidiness. The databases are WAL mode with ghost-owned 0600
# sidecars and sqlite3 opens the source read-write; a root-run that has to recreate
# -wal or -shm leaves them root-owned, after which the ghost user cannot write its own database.
# backup-databases.sh also refuses to run as root, so these two agree.

# A 2.6 GB read plus gzip competes with the pool for the same disk. Deprioritised so a backup can
# never be the reason a share took too long to credit.
# A healthy run is under four minutes. Type=oneshot has NO start timeout by default, so a copy
# that cannot finish holds a CPU until someone notices — 23 minutes on vm8 before it was stopped
# by hand (#1009). The script removes its partial copy when this fires.
TimeoutStartSec=1800

Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7

[Install]
WantedBy=multi-user.target
EOF

# Create systemd timer unit (daily at 03:00 UTC)
cat > /etc/systemd/system/ghost-backup.timer <<EOF
[Unit]
Description=Daily Ghost Pool Database Backup

[Timer]
OnCalendar=*-*-* 03:00:00 UTC
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF

# Ensure backup directory exists
mkdir -p /var/backups/ghost/db
chown ghost:ghost /var/backups/ghost/db

# Enable and start timer
systemctl daemon-reload
systemctl enable ghost-backup.timer
systemctl start ghost-backup.timer

echo "Backup timer installed and started."
echo "  Schedule: daily at 03:00 UTC (+/- 5 min jitter)"
echo "  Backup dir: /var/backups/ghost/db"
echo "  Retention: older than 7 days AND beyond the newest 7 (both must agree)"
echo "  Format: gzipped — ~850MB per copy against a 2.6GB database, so ~6GB for seven"
echo "  Refuses rather than filling the disk if free space is under the database size + 1GiB"
echo ""
echo "Verify with: systemctl list-timers ghost-backup.timer"
echo "Test now with: systemctl start ghost-backup.service"
