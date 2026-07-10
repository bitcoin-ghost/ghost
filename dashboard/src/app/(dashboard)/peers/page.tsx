"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { StatusDot } from "@/components/ui/StatusDot";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { DataTable, formatDuration, truncateId } from "@/components/ui/DataTable";
import { usePoolStatus, usePeers } from "@/hooks/queries";
import { useMeshStatus } from "@/hooks/queries/useMeshQueries";
import type { PeerInfo } from "@/types/api";
import type { ColumnDef } from "@tanstack/react-table";

const TOOLTIPS = {
  total_peers: "Number of Ghost nodes your node is directly connected to via the P2P mesh network.",
  avg_latency: "Average round-trip time to your connected peers. Lower is better.",
  synced_peers: "How many of your peers are fully synced with the Bitcoin blockchain.",
  mesh_channels: "Number of active mesh communication channels (share, block, voting, health, etc).",
  active_nodes: "Total number of Ghost nodes currently online in the pool network, including your own node.",
};

const peerColumns: ColumnDef<PeerInfo>[] = [
  {
    accessorKey: "node_id",
    header: "Node ID",
    cell: ({ row }) => (
      <span className="font-mono text-sm">{truncateId(row.original.node_id || "N/A", 8)}</span>
    ),
  },
  {
    accessorKey: "version",
    header: "Version",
    cell: ({ row }) => (
      <span className="font-mono text-[color:var(--dim)]">{row.original.version || "N/A"}</span>
    ),
  },
  {
    accessorKey: "latency_ms",
    header: "Latency",
    cell: ({ row }) => {
      const latency = row.original.latency_ms;
      if (latency == null) return <span className="text-[color:var(--fainter)]">--</span>;
      return (
        <Badge variant={latency < 100 ? "success" : latency < 500 ? "warning" : "error"}>
          {latency}ms
        </Badge>
      );
    },
  },
  {
    // The backend `synced` flag is a HEARTBEAT-freshness signal (peer seen in
    // the last 60s), NOT a chain-sync state. Labelling a stale-heartbeat peer
    // "Syncing" was misleading — a fully-synced mesh node whose gossip lagged
    // past 60s would read as if it were still downloading the chain. Label it
    // by what the flag actually means: Active (recent heartbeat) / Stale.
    accessorKey: "synced",
    header: "Heartbeat",
    cell: ({ row }) => (
      <StatusDot
        status={row.original.synced ? "online" : "warning"}
        label={row.original.synced ? "Active" : "Stale"}
        size="sm"
      />
    ),
  },
  {
    accessorKey: "connected_at",
    header: "Connected",
    cell: ({ row }) => {
      const connectedAt = row.original.connected_at ?? 0;
      if (!connectedAt) return <span className="text-[color:var(--fainter)]">N/A</span>;
      const connectedAgo = Math.floor(Date.now() / 1000 - connectedAt);
      if (connectedAgo < 0 || connectedAgo > 86400 * 365) return <span className="text-[color:var(--fainter)]">N/A</span>;
      return <span className="text-[color:var(--dim)]">{formatDuration(connectedAgo)}</span>;
    },
  },
];

export default function PeersPage() {
  const { data: pool, isLoading: poolLoading } = usePoolStatus();
  const { data: peersData, isLoading: peersLoading } = usePeers();
  useMeshStatus(); // pre-fetch for mesh data

  const peers = peersData?.peers ?? [];
  const syncedPeers = peers.filter((p) => p.synced).length;
  const avgLatency = peers.length > 0
    ? Math.round(peers.reduce((sum, p) => sum + (p.latency_ms ?? 0), 0) / peers.length)
    : 0;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="peers" title="Mesh connections." subtitle="Connected nodes in the Ghost mesh network" />

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Total Peers"
          value={peers.length}
          tooltip={TOOLTIPS.total_peers}
          loading={peersLoading}
        />
        <StatCard
          label="Avg Latency"
          value={avgLatency > 0 ? `${avgLatency}ms` : "--"}
          tooltip={TOOLTIPS.avg_latency}
          loading={peersLoading}
        />
        <StatCard
          label="Synced"
          value={`${syncedPeers} / ${peers.length}`}
          tooltip={TOOLTIPS.synced_peers}
          loading={peersLoading}
        />
        <StatCard
          label="Active Nodes"
          value={pool?.active_nodes ?? "--"}
          tooltip={TOOLTIPS.active_nodes}
          loading={poolLoading}
        />
      </div>

      {/* Peer Table */}
      <SectionErrorBoundary section="Peer Table">
        <Card>
          <CardHeader title="Connected Peers" subtitle={`${peers.length} peers`} />
          <DataTable
            columns={peerColumns}
            data={peers}
            loading={peersLoading}
            emptyMessage="No peers connected"
            emptyDescription="Your node will discover peers automatically"
            searchColumn="node_id"
            searchPlaceholder="Search by node ID..."
            showPagination={peers.length > 10}
          />
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}
