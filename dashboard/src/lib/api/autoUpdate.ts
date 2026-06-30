// Auto-update opt-in API client.
//
// Unlike most dashboard endpoints, this does NOT go through the node-API proxy
// (/api/proxy/...). The opt-in lives in /etc/ghost/auto-update.conf on the host,
// so it is served by the dashboard's own Node route at /api/auto-update, which
// reads the conf and flips it via the sudoers-scoped toggle helper.
import { getApiBase } from "./client";

export interface AutoUpdateStatus {
  last_run?: string;
  result?: string;
  message?: string;
  installed_version?: string;
  latest_version?: string;
}

export interface AutoUpdateState {
  enabled: boolean;
  installed_version: string | null;
  latest_version: string | null;
  last_status: AutoUpdateStatus | null;
}

export async function getAutoUpdate(): Promise<AutoUpdateState> {
  const res = await fetch(`${getApiBase()}/api/auto-update`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    const e = await res.json().catch(() => ({ error: "Unknown error" }));
    throw new Error(e.error || `Failed to read auto-update state: ${res.status}`);
  }
  return res.json();
}

export async function setAutoUpdate(enabled: boolean): Promise<AutoUpdateState> {
  const res = await fetch(`${getApiBase()}/api/auto-update`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled }),
  });
  if (!res.ok) {
    const e = await res.json().catch(() => ({ error: "Unknown error" }));
    throw new Error(e.error || `Failed to set auto-update: ${res.status}`);
  }
  return res.json();
}
