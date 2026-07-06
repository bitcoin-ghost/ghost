"use client";

import { Badge } from "@/components/ui/Badge";
import { Toggle } from "@/components/ui/Toggle";
import { useToast } from "@/components/ui/Toast";
import { useAutoUpdate, useSetAutoUpdate } from "@/hooks/queries";

function formatDate(dateStr: string): string {
  try {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  } catch {
    return dateStr;
  }
}

/**
 * Automatic-updates opt-in row (default OFF). Self-contained — reads
 * `useAutoUpdate` and drives `useSetAutoUpdate`. Shared between /system (inside
 * the Software Updates card) and /settings/system so both surfaces flip the
 * exact same setting.
 */
export function AutoUpdateSection() {
  const { data: autoUpdate } = useAutoUpdate();
  const setAutoUpdateMut = useSetAutoUpdate();
  const autoUpdateEnabled = autoUpdate?.enabled ?? false;
  const { success, error } = useToast();

  const handleAutoUpdateToggle = async (next: boolean) => {
    try {
      const result = await setAutoUpdateMut.mutateAsync(next);
      success(
        result.enabled ? "Automatic Updates On" : "Automatic Updates Off",
        result.enabled
          ? "Signed releases will be verified and applied automatically (checked every 6h)."
          : "This node will no longer update itself.",
      );
    } catch (err) {
      error(
        "Toggle Failed",
        err instanceof Error ? err.message : "Could not change the auto-update setting",
      );
    }
  };

  return (
    <div className="flex items-center justify-between">
      <div className="pr-4">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-gray-300">Automatic updates</span>
          <Badge variant={autoUpdateEnabled ? "success" : "default"}>
            {autoUpdateEnabled ? "On" : "Off"}
          </Badge>
        </div>
        <p className="text-xs text-gray-500 mt-0.5">
          When on, newer <strong>signed</strong> releases are applied automatically —
          the GPG signature and ghostd checksum are verified before any binary is
          swapped, and the node rolls back on a failed health check. Checked every 6h.
          Off by default.
        </p>
        {autoUpdate?.last_status?.result && (
          <p className="text-xs text-gray-500 mt-1">
            Last check: {autoUpdate.last_status.result}
            {autoUpdate.last_status.last_run
              ? ` · ${formatDate(autoUpdate.last_status.last_run)}`
              : ""}
            {autoUpdate.installed_version ? ` · installed ${autoUpdate.installed_version}` : ""}
            {autoUpdate.latest_version ? ` · latest ${autoUpdate.latest_version}` : ""}
          </p>
        )}
      </div>
      <Toggle
        enabled={autoUpdateEnabled}
        onChange={handleAutoUpdateToggle}
        disabled={setAutoUpdateMut.isPending}
        label="Toggle automatic updates"
      />
    </div>
  );
}
