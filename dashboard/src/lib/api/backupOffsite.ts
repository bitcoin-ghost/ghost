// Off-node backup destination API client (#1016).
//
// Like auto-update, this does NOT go through the node-API proxy: the setting
// lives on the host (/etc/ghost/backup.conf) and is served by the dashboard's
// own Node route at /api/backup-offsite, which drives the sudoers-scoped helper.
import { getApiBase } from "./client";

export type OffsiteKind = "local" | "ssh";

export interface OffsiteLastResult {
  result: string;
  time: string;
  error: string;
  files: string;
}

export interface OffsiteState {
  ok: boolean;
  enabled: boolean;
  kind: OffsiteKind | null;
  target: string | null;
  port: number | null;
  keep: number;
  conf_error: string | null;
  public_key: string | null;
  host_key_pinned: boolean;
  last_result: OffsiteLastResult | null;
  local: {
    dir: string;
    count: number;
    newest: string | null;
    newest_time: string | null;
    timer: string;
  };
}

export interface OffsiteActionResult {
  ok: boolean;
  error?: string;
  message?: string;
  public_key?: string;
}

export interface OffsiteActionResponse {
  result: OffsiteActionResult;
  state: OffsiteState | null;
}

export type OffsiteAction =
  | { action: "set"; kind: OffsiteKind; target: string; keep: number; port?: number }
  | { action: "disable" }
  | { action: "keygen" }
  | { action: "test" };

export async function getBackupOffsite(): Promise<OffsiteState> {
  const res = await fetch(`${getApiBase()}/api/backup-offsite`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    const e = await res.json().catch(() => ({ error: "Unknown error" }));
    throw new Error(e.error || `Failed to read the off-node backup setting: ${res.status}`);
  }
  return res.json();
}

export async function postBackupOffsite(body: OffsiteAction): Promise<OffsiteActionResponse> {
  const res = await fetch(`${getApiBase()}/api/backup-offsite`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const e = await res.json().catch(() => ({ error: "Unknown error" }));
    throw new Error(e.error || `Off-node backup request failed: ${res.status}`);
  }
  return res.json();
}
