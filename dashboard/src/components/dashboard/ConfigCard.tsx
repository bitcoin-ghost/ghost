"use client";

import { useState } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Toggle } from "@/components/ui/Toggle";
import { useConfig } from "@/hooks/useNodeData";

export function ConfigCard() {
  const { data: config, loading, error, setGhostMode, setArchiveMode } = useConfig();
  const [updating, setUpdating] = useState<string | null>(null);

  const handleGhostMode = async (enabled: boolean) => {
    setUpdating("ghost_mode");
    try {
      await setGhostMode(enabled);
    } finally {
      setUpdating(null);
    }
  };

  const handleArchiveMode = async (enabled: boolean) => {
    setUpdating("archive_mode");
    try {
      await setArchiveMode(enabled);
    } finally {
      setUpdating(null);
    }
  };

  // Show loading skeleton only on initial load (no data yet)
  if (loading && !config) {
    return (
      <Card>
        <CardHeader title="Configuration" />
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-[var(--surface)] rounded w-full"></div>
          <div className="h-6 bg-[var(--surface)] rounded w-full"></div>
        </div>
      </Card>
    );
  }

  if (!config) {
    return (
      <Card>
        <CardHeader title="Configuration" />
        <p className="text-[color:var(--dim)]">
          {error ? `Error: ${error.message}` : "Unable to load configuration"}
        </p>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader title="Configuration" subtitle="Node settings" />

      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-[color:var(--fg)] font-medium">Ghost Mode</div>
            <div className="text-sm text-[color:var(--dim)]">
              Private blocks-only peer mode
            </div>
          </div>
          <Toggle
            enabled={config.ghost_mode ?? false}
            onChange={handleGhostMode}
            label="Ghost Mode"
            disabled={updating === "ghost_mode"}
          />
        </div>

        <div className="flex items-center justify-between">
          <div>
            <div className="text-[color:var(--fg)] font-medium">Archive Mode</div>
            <div className="text-sm text-[color:var(--dim)]">
              Full chain storage, no pruning
            </div>
          </div>
          <Toggle
            enabled={config.archive_mode ?? false}
            onChange={handleArchiveMode}
            label="Archive Mode"
            disabled={updating === "archive_mode"}
          />
        </div>
      </div>
    </Card>
  );
}
