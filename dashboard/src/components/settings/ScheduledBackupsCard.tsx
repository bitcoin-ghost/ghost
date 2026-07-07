"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Toggle } from "@/components/ui/Toggle";
import { useToast } from "@/components/ui/Toast";
import {
  useBackupSchedule,
  useSetBackupSchedule,
} from "@/hooks/queries/useBackupScheduleQueries";
import {
  BACKUP_SCHEDULE_DEFAULTS,
  type BackupScheduleResponse,
} from "@/lib/api/backupSchedule";

type IntervalKind = "daily" | "weekly" | "custom";

// Split the compact wire interval ("daily" | "weekly" | "<n>h") into the UI's
// kind + custom-hours pair.
function parseInterval(wire: string): { kind: IntervalKind; hours: number } {
  const t = (wire ?? "").trim().toLowerCase();
  if (t === "daily" || t === "24h" || t === "24") return { kind: "daily", hours: 24 };
  if (t === "weekly" || t === "168h" || t === "168") return { kind: "weekly", hours: 168 };
  const n = parseInt(t.replace(/h$/, ""), 10);
  return { kind: "custom", hours: Number.isFinite(n) && n > 0 ? n : 12 };
}

function toWire(kind: IntervalKind, hours: number): string {
  if (kind === "daily") return "daily";
  if (kind === "weekly") return "weekly";
  const h = Number.isFinite(hours) && hours > 0 ? Math.floor(hours) : 1;
  return `${h}h`;
}

function formatUnix(unix?: number | null): string {
  if (!unix) return "—";
  return new Date(unix * 1000).toLocaleString();
}

/**
 * Settings card for automatic scheduled encrypted backups. Sits alongside the
 * manual Backup & Restore surface on the System page. The schedule is persisted
 * to pool.toml `[backup]`; the node's background task reuses the same encrypted
 * backup routine the manual export uses, writes timestamped artifacts to the
 * target directory, and prunes to the retention window.
 */
export function ScheduledBackupsCard() {
  const { data, isLoading } = useBackupSchedule();
  const save = useSetBackupSchedule();
  const { success, error } = useToast();

  const [enabled, setEnabled] = useState(BACKUP_SCHEDULE_DEFAULTS.enabled);
  const [intervalKind, setIntervalKind] = useState<IntervalKind>("daily");
  const [customHours, setCustomHours] = useState(12);
  const [retention, setRetention] = useState(BACKUP_SCHEDULE_DEFAULTS.retention);
  const [targetDir, setTargetDir] = useState(BACKUP_SCHEDULE_DEFAULTS.target_dir);

  // Hydrate local form once per distinct server response (the same "adjust
  // state while rendering" pattern the alerts settings page uses).
  const [hydratedFrom, setHydratedFrom] = useState<BackupScheduleResponse | null>(null);
  if (data && hydratedFrom !== data) {
    setHydratedFrom(data);
    setEnabled(data.enabled);
    const parsed = parseInterval(data.interval);
    setIntervalKind(parsed.kind);
    setCustomHours(parsed.hours);
    setRetention(data.retention);
    setTargetDir(data.target_dir);
  }

  const status = data?.status;

  const handleSave = async () => {
    const trimmedDir = targetDir.trim();
    if (!trimmedDir.startsWith("/")) {
      error("Invalid directory", "Target directory must be an absolute path.");
      return;
    }
    try {
      const res = await save.mutateAsync({
        enabled,
        interval: toWire(intervalKind, customHours),
        retention: Math.max(1, Math.floor(retention) || 1),
        target_dir: trimmedDir,
      });
      if (res.persisted) {
        success("Backup schedule saved", res.message);
      } else {
        error("Not persisted", res.message);
      }
    } catch (err) {
      error("Save failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <Card>
      <CardHeader
        title="Scheduled Backups"
        subtitle="Automatically create encrypted backups on a schedule and keep the most recent copies."
      />

      <div className="space-y-6">
        {/* Enable */}
        <div className="flex items-center justify-between p-4 bg-[var(--surface)]/50 rounded-lg">
          <div>
            <div className="text-[color:var(--fg)] font-medium">Enable scheduled backups</div>
            <p className="text-sm text-[color:var(--dim)]">
              Off by default. When on, the node writes an encrypted backup to the target
              directory on each interval and prunes old copies automatically.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Badge variant={enabled ? "success" : "default"}>{enabled ? "On" : "Off"}</Badge>
            <Toggle label="Enable scheduled backups" enabled={enabled} onChange={setEnabled} />
          </div>
        </div>

        {/* Settings */}
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1">
            <label className="block text-sm font-medium text-[color:var(--dim)]">Interval</label>
            <select
              value={intervalKind}
              onChange={(e) => setIntervalKind(e.target.value as IntervalKind)}
              disabled={!enabled}
              className="w-full px-3 py-2 text-sm bg-[var(--surface)] border border-[color:var(--rule-strong)] rounded-lg text-[color:var(--fg)] focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <option value="daily">Daily (every 24h)</option>
              <option value="weekly">Weekly (every 7 days)</option>
              <option value="custom">Custom (hours)</option>
            </select>
            <p className="text-xs text-[color:var(--fainter)]">How often a backup is created.</p>
          </div>

          {intervalKind === "custom" && (
            <Input
              label="Custom interval (hours)"
              type="number"
              min={1}
              value={String(customHours)}
              disabled={!enabled}
              onChange={(e) => setCustomHours(parseInt(e.target.value, 10) || 1)}
              helperText="Minimum 1 hour."
            />
          )}

          <Input
            label="Retention (keep last N)"
            type="number"
            min={1}
            value={String(retention)}
            disabled={!enabled}
            onChange={(e) => setRetention(parseInt(e.target.value, 10) || 1)}
            helperText="Older backups beyond this count are deleted after each run."
          />

          <Input
            label="Target directory"
            value={targetDir}
            disabled={!enabled}
            onChange={(e) => setTargetDir(e.target.value)}
            helperText="Absolute path where encrypted backups are written."
            className="sm:col-span-2"
          />
        </div>

        {/* Last run status */}
        <div className="p-4 bg-[var(--surface)]/50 rounded-lg border border-[color:var(--rule-strong)]">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-sm font-medium text-[color:var(--dim)]">Last run</h4>
            {status?.last_success === true && <Badge variant="success">Success</Badge>}
            {status?.last_success === false && <Badge variant="error">Failed</Badge>}
            {status?.last_run_unix == null && <Badge variant="default">Never run</Badge>}
          </div>
          <div className="text-sm text-[color:var(--dim)] space-y-1">
            <div>Time: {formatUnix(status?.last_run_unix)}</div>
            {status?.last_path && (
              <div className="break-all">Path: {status.last_path}</div>
            )}
            {status?.last_error && (
              <div className="text-[color:var(--red)] break-all">Error: {status.last_error}</div>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="primary"
            onClick={handleSave}
            loading={save.isPending}
            disabled={isLoading}
          >
            Save schedule
          </Button>
          <span className="text-xs text-[color:var(--fainter)]">
            Backups inherit the database encryption; store the target directory securely.
          </span>
        </div>
      </div>
    </Card>
  );
}
