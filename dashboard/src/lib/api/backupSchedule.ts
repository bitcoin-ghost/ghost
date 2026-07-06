// Automatic scheduled encrypted backups — configuration persisted to pool.toml
// `[backup]` by ghost-pool. The scheduled task reuses the same encrypted-backup
// routine the manual backup uses. These calls route through the HMAC-signed
// proxy like the operator-alerts config.
import { fetchApi } from "./client";

// `interval` is a compact wire string: "daily", "weekly", or "<n>h" for a
// custom period in hours (e.g. "6h"). Matches the Rust `BackupInterval` form.
export type BackupInterval = string;

export interface BackupSchedule {
  enabled: boolean;
  interval: BackupInterval;
  // Keep only the most recent N artifacts; older ones are pruned after a run.
  retention: number;
  // Absolute directory the timestamped encrypted artifacts are written to.
  target_dir: string;
}

// In-memory last-run status reported by the node (resets on restart).
export interface BackupRunStatus {
  last_run_unix?: number | null;
  last_success?: boolean | null;
  last_path?: string | null;
  last_error?: string | null;
}

export interface BackupScheduleResponse extends BackupSchedule {
  status: BackupRunStatus;
  message?: string;
}

export interface BackupScheduleSaveResponse extends BackupSchedule {
  status: BackupRunStatus;
  success: boolean;
  persisted: boolean;
  message: string;
}

export const BACKUP_SCHEDULE_DEFAULTS: BackupSchedule = {
  enabled: false,
  interval: "daily",
  retention: 7,
  target_dir: "/home/ghost/.ghost/backups",
};

export async function getBackupSchedule(): Promise<BackupScheduleResponse> {
  return fetchApi<BackupScheduleResponse>("/api/v1/config/backup_schedule");
}

export async function setBackupSchedule(
  config: BackupSchedule,
): Promise<BackupScheduleSaveResponse> {
  return fetchApi<BackupScheduleSaveResponse>("/api/v1/config/backup_schedule", {
    method: "POST",
    body: JSON.stringify(config),
  });
}
