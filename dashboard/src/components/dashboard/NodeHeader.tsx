"use client";

import { useNodeInfo } from "@/hooks/useNodeData";
import { useNickname } from "@/hooks/queries/useNodeQueries";
import { Badge } from "@/components/ui/Badge";

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  if (days > 0) {
    return `${days}d ${hours}h ${minutes}m`;
  }
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  return `${minutes}m`;
}

export function NodeHeader() {
  const { data: info, loading } = useNodeInfo();
  const { data: nicknameData } = useNickname();

  if (loading) {
    return (
      <header className="mb-8">
        <div className="animate-pulse">
          <div className="h-8 bg-[var(--surface)] rounded w-64 mb-2"></div>
          <div className="h-4 bg-[var(--surface)] rounded w-48"></div>
        </div>
      </header>
    );
  }

  if (!info) {
    return (
      <header className="mb-8">
        <h1 className="text-2xl font-bold text-[color:var(--fg)]">Ghost Node</h1>
        <p className="text-[color:var(--dim)]">Unable to connect to node</p>
      </header>
    );
  }

  const nickname = nicknameData?.nickname;

  return (
    <header className="mb-8">
      <div className="flex items-center gap-4 mb-2">
        <h1 className="text-2xl font-bold text-[color:var(--fg)]">Ghost Node</h1>
        <Badge variant="success">Online</Badge>
      </div>

      <div className="flex items-center gap-6 text-sm text-[color:var(--dim)] flex-wrap">
        {nickname && (
          <div className="flex items-center gap-2">
            <span>Node Name:</span>
            <span className="text-[color:var(--dim)] font-medium">{nickname}</span>
          </div>
        )}
        <div className="flex items-center gap-2">
          <span>Node ID:</span>
          <code className="bg-[var(--surface)] px-2 py-0.5 rounded font-mono">
            {info.node_id_short}
          </code>
        </div>
        <div>
          <span>Version:</span>{" "}
          <span className="text-[color:var(--dim)]">v{info.version}</span>
        </div>
        <div>
          <span>Uptime:</span>{" "}
          <span className="text-[color:var(--dim)]">{formatUptime(info.uptime_seconds ?? info.uptime_secs ?? 0)}</span>
        </div>
      </div>
    </header>
  );
}
