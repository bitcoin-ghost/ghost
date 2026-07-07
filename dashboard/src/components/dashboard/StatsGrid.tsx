"use client";

import { useNodeStatus, useGhostPayStatus } from "@/hooks/useNodeData";

interface StatBoxProps {
  label: string;
  value: string | number;
  sublabel?: string;
  loading?: boolean;
}

function StatBox({ label, value, sublabel, loading }: StatBoxProps) {
  if (loading) {
    return (
      <div className="bg-[var(--surface)]/50 rounded-lg p-4 text-center">
        <div className="animate-pulse">
          <div className="h-8 bg-[var(--rule-strong)] rounded w-16 mx-auto mb-2"></div>
          <div className="h-4 bg-[var(--rule-strong)] rounded w-20 mx-auto"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-[var(--surface)]/50 rounded-lg p-4 text-center">
      <div className="text-2xl font-bold text-[color:var(--fg)]">{value}</div>
      <div className="text-sm text-[color:var(--dim)]">{label}</div>
      {sublabel && <div className="text-xs text-[color:var(--fainter)] mt-1">{sublabel}</div>}
    </div>
  );
}

export function StatsGrid() {
  const { data: status, loading: statusLoading } = useNodeStatus();
  const { data: ghostPay, loading: gpLoading } = useGhostPayStatus();

  const formatUptime = (seconds: number): string => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    if (days > 0) return `${days}d ${hours}h`;
    return `${hours}h`;
  };

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <StatBox
        label="Peers"
        value={status?.peer_count ?? "-"}
        sublabel="connected"
        loading={statusLoading && !status}
      />
      <StatBox
        label="L1 Height"
        value={status?.sync_height?.toLocaleString() ?? "-"}
        sublabel="Ghost Core"
        loading={statusLoading && !status}
      />
      <StatBox
        label="L2 Height"
        value={ghostPay?.l2_height?.toLocaleString() ?? "-"}
        sublabel="Ghost Pay"
        loading={gpLoading && !ghostPay}
      />
      <StatBox
        label="Uptime"
        value={status ? formatUptime(status.uptime_seconds || 0) : "-"}
        sublabel="7d trailing"
        loading={statusLoading && !status}
      />
    </div>
  );
}
