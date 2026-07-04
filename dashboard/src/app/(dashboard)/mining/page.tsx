"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { CopyButton } from "@/components/ui/CopyButton";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { DataTable, formatHashrate, formatDuration } from "@/components/ui/DataTable";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useMiningStatus, useMiners, useBestHash, useSetPrivateMining, useSetPublicMining } from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import { useQueryClient } from "@tanstack/react-query";
import PoolSetupWizard from "../settings/wizards/PoolSetupWizard";
import type { MinerInfo, BestHashEntry } from "@/types/api";
import type { ColumnDef } from "@tanstack/react-table";

const TOOLTIPS = {
  network_hashrate: "Estimated total hashrate of the Bitcoin network, derived from current difficulty. This is the global network, not just Ghost.",
  hashrate: "Combined hashrate of all miners connected to your node's stratum port. Updated every few seconds from share submissions.",
  connected_miners: "Number of mining devices currently connected to your stratum port and actively submitting shares.",
  shares_round: "Total accepted shares in the current mining round. The accept rate shows valid vs rejected shares.",
  blocks_found: "Total blocks your pool has found since first startup. Each block found triggers a payout distribution.",
  best_hash: "The lowest (best) hash value submitted by miners. More leading zeros means closer to finding a block. Measured by share difficulty.",
};

const minerColumns: ColumnDef<MinerInfo>[] = [
  {
    accessorKey: "worker_name",
    header: "Worker",
    cell: ({ row }) => (
      <div>
        <div className="font-medium">{row.original.worker_name || "Unknown"}</div>
        <div className="text-xs text-gray-500 font-mono">{row.original.ip_address || "N/A"}</div>
      </div>
    ),
  },
  {
    accessorKey: "hashrate_th",
    header: "Hashrate",
    cell: ({ row }) => (
      <span className="font-mono">{formatHashrate((row.original.hashrate_th ?? 0) * 1e12)}</span>
    ),
  },
  {
    id: "shares",
    header: "Shares",
    cell: ({ row }) => (
      <span>
        {(row.original.shares_accepted ?? 0).toLocaleString()} / {(row.original.shares_submitted ?? 0).toLocaleString()}
      </span>
    ),
  },
  {
    id: "accept_rate",
    header: "Accept Rate",
    cell: ({ row }) => {
      const submitted = row.original.shares_submitted ?? 0;
      const accepted = row.original.shares_accepted ?? 0;
      const rate = submitted > 0 ? (accepted / submitted) * 100 : 0;
      return (
        <Badge variant={rate >= 95 ? "success" : rate >= 80 ? "warning" : "error"}>
          {rate.toFixed(1)}%
        </Badge>
      );
    },
  },
  {
    accessorKey: "connected_at",
    header: "Uptime",
    cell: ({ row }) => {
      const connectedAt = row.original.connected_at ?? 0;
      if (!connectedAt) return <span className="text-gray-500">N/A</span>;
      const uptime = Math.floor(Date.now() / 1000 - connectedAt);
      if (uptime < 0 || uptime > 86400 * 365) return <span className="text-gray-500">N/A</span>;
      return <span className="text-gray-400">{formatDuration(uptime)}</span>;
    },
  },
];

function formatTimeAgo(timestamp: number): string {
  if (!timestamp) return "Never";
  const diff = Math.floor(Date.now() / 1000) - timestamp;
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function calculateLeadingZeros(difficulty: number): number {
  if (difficulty <= 0) return 0;
  return Math.floor(8 + Math.log2(difficulty) / 4);
}

// Human-readable difficulty with auto-scaling K/M/G/T/P/E suffixes.
// Mirrors `formatDifficulty` in ghost-web/pool.html so the dashboard and the
// public pool site render identical numbers (e.g. "1.20 T", "340.00 G").
function formatDifficulty(d: number): string {
  if (!isFinite(d) || d <= 0) return "—";
  if (d < 1e3) return d.toFixed(2);
  if (d < 1e6) return (d / 1e3).toFixed(2) + "K";
  if (d < 1e9) return (d / 1e6).toFixed(2) + "M";
  if (d < 1e12) return (d / 1e9).toFixed(2) + "G";
  if (d < 1e15) return (d / 1e12).toFixed(2) + "T";
  if (d < 1e18) return (d / 1e15).toFixed(2) + "P";
  return (d / 1e18).toFixed(2) + "E";
}

// Public pool hostname (round-robin DNS across all nodes).
const PUBLIC_POOL_HOST = "pool.bitcoinghost.org";

// SV2/Noise clients must pin the pool's authority public key to connect.
// NOTE: the node API does NOT currently expose this — it lives in pool_sv2's
// pool.toml as `authority_public_key`, identical across every node — so it is
// mirrored here as a constant. Backend enhancement: surface it on
// /api/v1/mining/status so this can be sourced dynamically.
const SV2_AUTHORITY_PUBLIC_KEY = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";

function BestHashCard({ title, entry }: { title: string; entry: BestHashEntry | undefined }) {
  const diff = entry?.difficulty ?? 0;
  const hasData = entry && diff > 0;
  return (
    <div className="p-3 bg-gray-800/50 rounded-lg">
      <div className="text-xs text-gray-400 mb-1">{title}</div>
      {hasData ? (
        <>
          <div className="text-lg font-semibold text-orange-400">{formatDifficulty(diff)}</div>
          <div className="font-mono text-xs text-gray-400 truncate">{entry.hash}</div>
          <div className="text-xs text-gray-500 mt-0.5">{calculateLeadingZeros(diff)} leading zeros</div>
          <div className="flex justify-between items-center mt-1">
            <span className="text-xs text-gray-500">Block #{entry.block_height?.toLocaleString() || "?"}</span>
            <span className="text-xs text-gray-500">{formatTimeAgo(entry.timestamp ?? 0)}</span>
          </div>
        </>
      ) : (
        <div className="text-gray-500 text-sm">No data yet</div>
      )}
    </div>
  );
}

type MiningMode = "private_solo" | "private_pool" | "pool";

function getMiningMode(privateMining?: boolean, publicMining?: boolean): MiningMode {
  if (privateMining && publicMining) return "private_pool";
  if (publicMining) return "pool";
  return "private_solo"; // default: private solo (includes both-off state)
}

const MODES: { key: MiningMode; label: string; desc: string }[] = [
  { key: "private_solo", label: "Private Solo", desc: "Your miners only. Stratum port closed to external connections. All block rewards go to you." },
  { key: "private_pool", label: "Private Pool", desc: "Your miners + accept public miners. You operate a public pool and share rewards with connected miners." },
  { key: "pool", label: "Pool", desc: "Public pool only. No private mining — your node acts as a pool server for external miners." },
];

export default function MiningPage() {
  const { data: status, isLoading: statusLoading } = useMiningStatus();
  const { data: minersData, isLoading: minersLoading } = useMiners();
  const { data: bestHashData, isLoading: bestHashLoading } = useBestHash();
  const setPrivateMining = useSetPrivateMining();
  const setPublicMining = useSetPublicMining();
  const queryClient = useQueryClient();
  const { addToast } = useToast();
  const [poolSetupOpen, setPoolSetupOpen] = useState(false);

  const miners = minersData?.miners ?? [];
  // The miners/full `total` only counts miners seen in the last 600s, so it
  // reads 0 for TCP-connected-but-idle miners. Use the authoritative
  // connected-miner counts from mining status as a floor so the header never
  // understates reality (backend `active_miners` = local miners with recent
  // shares; `local_connected_miners` = TCP-connected on this node).
  const connectedMinerCount = Math.max(
    miners.length,
    minersData?.total ?? 0,
    status?.active_miners ?? 0,
    status?.local_connected_miners ?? 0,
  );
  const nodeHost = typeof window !== "undefined" ? window.location.hostname : "localhost";
  const isPending = setPrivateMining.isPending || setPublicMining.isPending;

  const currentMode = getMiningMode(status?.private_mining, status?.public_mining);

  const handleModeChange = async (mode: MiningMode) => {
    if (mode === currentMode || isPending) return;
    try {
      // Set both flags - order doesn't matter since both must succeed
      const privateMining = mode === "private_solo" || mode === "private_pool";
      const publicMining = mode === "private_pool" || mode === "pool";

      const results = await Promise.allSettled([
        setPrivateMining.mutateAsync(privateMining),
        setPublicMining.mutateAsync(publicMining),
      ]);

      const failures = results.filter((r) => r.status === "rejected");
      if (failures.length > 0) {
        const reason = (failures[0] as PromiseRejectedResult).reason;
        throw reason instanceof Error ? reason : new Error(String(reason));
      }

      await queryClient.invalidateQueries({ queryKey: ["mining"] });
      await queryClient.invalidateQueries({ queryKey: ["config"] });
      addToast({ type: "success", title: `Mining mode: ${MODES.find(m => m.key === mode)?.label}` });
    } catch (err: unknown) {
      const message = err instanceof Error
        ? err.message
        : typeof err === "object" && err !== null && "message" in err
          ? String((err as { message: unknown }).message)
          : "Failed to update mining mode";
      addToast({ type: "error", title: message });
    }
  };

  const totalSubmitted = status?.shares_submitted ?? 0;
  const totalAccepted = status?.shares_accepted ?? 0;
  const acceptRate = totalSubmitted > 0 ? ((totalAccepted / totalSubmitted) * 100).toFixed(1) : "0";

  // Show stratum endpoints based on mode
  const showPrivateEndpoints = currentMode === "private_solo" || currentMode === "private_pool";
  const showPublicEndpoints = currentMode === "private_pool" || currentMode === "pool";

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="mining" title="Hashrate, shares, miners." subtitle="Hashrate, miners, and mining configuration" />

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard
          label="Network Hashrate"
          value={bestHashData?.network_hashrate ? formatHashrate(bestHashData.network_hashrate) : "--"}
          sublabel="global estimate"
          tooltip={TOOLTIPS.network_hashrate}
          loading={bestHashLoading}
        />
        <StatCard
          label="Pool Hashrate"
          value={status ? formatHashrate((status.hashrate_th ?? 0) * 1e12) : "--"}
          sublabel="your node"
          tooltip={TOOLTIPS.hashrate}
          loading={statusLoading}
        />
        <StatCard
          label="Connected Miners"
          value={status?.connected_miners ?? 0}
          sublabel="active workers"
          tooltip={TOOLTIPS.connected_miners}
          loading={statusLoading}
        />
        <StatCard
          label="Shares / Round"
          value={(totalAccepted).toLocaleString()}
          sublabel={`${acceptRate}% accept rate`}
          tooltip={TOOLTIPS.shares_round}
          loading={statusLoading}
        />
        <StatCard
          label="Blocks Found"
          value={status?.blocks_found ?? 0}
          sublabel="all time"
          tooltip={TOOLTIPS.blocks_found}
          loading={statusLoading}
        />
      </div>

      {/* Mining Mode */}
      <SectionErrorBoundary section="Mining Mode">
        <Card>
          <CardHeader
            title="Mining Mode"
            subtitle="Select how your node participates in mining"
            action={
              <Button variant="outline" size="sm" onClick={() => setPoolSetupOpen(true)}>
                Pool Setup Wizard
              </Button>
            }
          />

          {/* Mode selector - 3 radio-style options */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-6">
            {MODES.map(({ key, label, desc }) => {
              const isActive = currentMode === key;
              return (
                <button
                  key={key}
                  onClick={() => handleModeChange(key)}
                  disabled={isPending}
                  className={`p-4 rounded-lg border text-left transition-all ${
                    isActive
                      ? "bg-orange-900/20 border-orange-600 ring-1 ring-orange-600/50"
                      : "bg-gray-800/30 border-gray-700 hover:border-gray-600"
                  } ${isPending ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <div className={`w-3 h-3 rounded-full border-2 flex items-center justify-center ${
                      isActive ? "border-orange-500" : "border-gray-600"
                    }`}>
                      {isActive && <div className="w-1.5 h-1.5 rounded-full bg-orange-500" />}
                    </div>
                    <span className={`font-medium ${isActive ? "text-orange-400" : "text-gray-300"}`}>{label}</span>
                    {isActive && <Badge variant="success">Active</Badge>}
                  </div>
                  <div className="text-xs text-gray-500 ml-5">{desc}</div>
                </button>
              );
            })}
          </div>

          {/* Connection endpoints */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {showPrivateEndpoints && (
              <div className="p-4 bg-gray-800/30 rounded-lg border border-gray-700">
                <div className="text-sm text-gray-300 font-medium mb-3">Your Stratum Endpoints</div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between p-2 bg-gray-900/50 rounded">
                    <div>
                      <div className="text-xs text-gray-500">Stratum V1</div>
                      <code className="text-orange-400 text-sm">stratum+tcp://{nodeHost}:{status?.stratum_v1_port || 3333}</code>
                    </div>
                    <CopyButton text={`stratum+tcp://${nodeHost}:${status?.stratum_v1_port || 3333}`} />
                  </div>
                  <div className="flex items-center justify-between p-2 bg-gray-900/50 rounded">
                    <div>
                      <div className="text-xs text-gray-500">Stratum V2</div>
                      <code className="text-orange-400 text-sm">stratum+tcp://{nodeHost}:{status?.stratum_v2_port || 34255}</code>
                    </div>
                    <CopyButton text={`stratum+tcp://${nodeHost}:${status?.stratum_v2_port || 34255}`} />
                  </div>
                </div>
              </div>
            )}
            {showPublicEndpoints && (
              <div className="p-4 bg-gray-800/30 rounded-lg border border-gray-700">
                <div className="text-sm text-gray-300 font-medium mb-3">Public Pool Endpoints</div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between p-2 bg-gray-900/50 rounded">
                    <div>
                      <div className="text-xs text-gray-500">Stratum V1</div>
                      <code className="text-orange-400 text-sm">stratum+tcp://{PUBLIC_POOL_HOST}:{status?.stratum_v1_port || 3333}</code>
                    </div>
                    <CopyButton text={`stratum+tcp://${PUBLIC_POOL_HOST}:${status?.stratum_v1_port || 3333}`} />
                  </div>
                  <div className="flex items-center justify-between p-2 bg-gray-900/50 rounded">
                    <div>
                      <div className="text-xs text-gray-500">Stratum V2</div>
                      <code className="text-orange-400 text-sm">stratum+tcp://{PUBLIC_POOL_HOST}:{status?.stratum_v2_port || 34255}</code>
                    </div>
                    <CopyButton text={`stratum+tcp://${PUBLIC_POOL_HOST}:${status?.stratum_v2_port || 34255}`} />
                  </div>
                  <div className="flex items-center justify-between p-2 bg-gray-900/50 rounded">
                    <div className="min-w-0">
                      <div className="text-xs text-gray-500">SV2 authority public key</div>
                      <code className="text-orange-400 text-sm block truncate">{SV2_AUTHORITY_PUBLIC_KEY}</code>
                    </div>
                    <CopyButton text={SV2_AUTHORITY_PUBLIC_KEY} />
                  </div>
                </div>
                <div className="text-xs text-gray-500 mt-2">SV2/Noise miners must pin the authority public key to connect.</div>
              </div>
            )}
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Best Hashes */}
      <SectionErrorBoundary section="Best Hashes">
        <Card>
          <CardHeader
            title="Best Hashes"
            subtitle="Lowest hash values achieved by connected miners — more leading zeros means closer to winning a block"
          />
          {bestHashLoading ? (
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <SkeletonCard /><SkeletonCard /><SkeletonCard /><SkeletonCard />
            </div>
          ) : (
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <BestHashCard title="Current Round" entry={bestHashData?.current_round} />
              <BestHashCard title="Last Hour" entry={bestHashData?.last_hour} />
              <BestHashCard title="Last 24h" entry={bestHashData?.last_24h} />
              <BestHashCard title="All Time" entry={bestHashData?.all_time} />
            </div>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* Connected Miners Table */}
      <SectionErrorBoundary section="Connected Miners">
        <Card>
          <CardHeader
            title="Connected Miners"
            subtitle={`${connectedMinerCount} ${connectedMinerCount === 1 ? "miner" : "miners"} connected`}
          />
          <DataTable
            columns={minerColumns}
            data={miners}
            loading={minersLoading}
            emptyMessage="No miners connected"
            emptyDescription="Connect a miner using the Stratum endpoints above"
            searchColumn="worker_name"
            searchPlaceholder="Search miners..."
            showPagination={miners.length > 10}
          />
        </Card>
      </SectionErrorBoundary>

      {/* Wizard dialog */}
      <PoolSetupWizard isOpen={poolSetupOpen} onClose={() => setPoolSetupOpen(false)} />
    </div>
  );
}
