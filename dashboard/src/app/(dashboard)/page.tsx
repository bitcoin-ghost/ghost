"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { StatusDot } from "@/components/ui/StatusDot";
import { Tooltip } from "@/components/ui/Tooltip";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useNodeInfo, useNodeStatus, useNickname } from "@/hooks/queries/useNodeQueries";
import { useWatchdogStatus } from "@/hooks/queries/useWatchdogQueries";
import { useMiningStatus, useBestHash } from "@/hooks/queries/useMiningQueries";
import { useHazeStatus } from "@/hooks/queries/useHazeQueries";
import { useShroudStatus } from "@/hooks/queries/useShroudQueries";
import { formatHashrate } from "@/components/ui/DataTable";

const TOOLTIPS = {
  block_height: "The current block height of the Bitcoin blockchain your node has synced to. During Initial Block Download (IBD), this shows sync progress.",
  l1_peers: "Number of Ghost mesh peers your node is directly connected to via P2P.",
  l1_hashrate: "Combined mining hashrate of miners connected to YOUR node's stratum port only. This is just your node, not the whole Ghost pool or the Bitcoin network.",
  pool_hashrate: "Combined mining hashrate of every miner across the entire Ghost pool — all nodes in the mesh aggregated together. This is the whole Ghost pool, not just your node or the Bitcoin network.",
  network_hashrate: "Estimated total hashrate of the Bitcoin network, derived from current difficulty. This is the global network, not just Ghost.",
  health: "Overall health of the services running on your node.",
  ghost_mode: "Ghost Mode isolates your node — stops relaying transactions and messages to peers (except block propagation). Useful for privacy.",
  privacy_tor: "Tor Mode routes all P2P connections through the Tor network, hiding your node's IP address from peers.",
  privacy_haze: "Ghost Haze strips privacy-sensitive data (signatures, witness data, inscriptions) from stored blocks.",
  privacy_shroud: "Ghost Shroud adds random delays before relaying transactions, protecting against timing analysis.",
};

function InfoIcon() {
  return (
    <svg className="w-3 h-3 text-[color:var(--fainter)] inline-block align-middle mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <circle cx="12" cy="12" r="10" />
      <path d="M12 16v-4M12 8h.01" />
    </svg>
  );
}

function L1Card() {
  const { data: status, isLoading: statusLoading } = useNodeStatus();
  const { data: mining, isLoading: miningLoading } = useMiningStatus();
  const { data: bestHash, isLoading: bestHashLoading } = useBestHash();
  const isLoading = statusLoading || miningLoading;

  const syncStatus = status?.is_synced;
  const syncHeight = status?.sync_height ?? status?.block_height ?? 0;
  const blockHeight = status?.block_height ?? 0;
  const isSyncing = syncStatus === false && syncHeight > 0 && blockHeight > 0;

  return (
    <Card>
      <CardHeader
        title={<span>L1 &middot; Bitcoin</span>}
        action={
          syncStatus != null && (
            <StatusDot
              status={syncStatus ? "online" : "warning"}
              pulse={syncStatus}
              label={syncStatus ? "Synced" : "Syncing"}
            />
          )
        }
      />
      <div className="grid grid-cols-2 gap-3">
        <Tooltip content={TOOLTIPS.block_height}>
          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1 flex items-center gap-1"><InfoIcon /> Block Height</div>
            <div className="text-lg font-mono font-semibold text-[color:var(--fg)]">
              {isLoading ? "..." : isSyncing
                ? <span>{syncHeight.toLocaleString()} <span className="text-xs text-[color:var(--fainter)]">/ {blockHeight.toLocaleString()}</span></span>
                : syncHeight.toLocaleString()
              }
            </div>
            {isSyncing && (
              <div className="text-xs text-[color:var(--dim)] mt-0.5">
                IBD &middot; {blockHeight > 0 ? ((syncHeight / blockHeight) * 100).toFixed(1) : 0}%
              </div>
            )}
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.l1_peers}>
          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1 flex items-center gap-1"><InfoIcon /> Mesh Peers</div>
            <div className="text-lg font-mono font-semibold text-[color:var(--fg)]">
              {isLoading ? "..." : `${status?.peer_count ?? 0} connected`}
            </div>
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.network_hashrate}>
          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1 flex items-center gap-1"><InfoIcon /> Network Hashrate</div>
            <div className="text-lg font-mono font-semibold text-[color:var(--fg)]">
              {bestHashLoading ? "..." : bestHash?.network_hashrate ? formatHashrate(bestHash.network_hashrate) : "--"}
            </div>
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.pool_hashrate}>
          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1 flex items-center gap-1"><InfoIcon /> Ghost Pool Hashrate</div>
            <div className="text-lg font-mono font-semibold text-[color:var(--fg)]">
              {isLoading ? "..." : mining ? formatHashrate((mining.hashrate_th ?? 0) * 1e12) : "--"}
            </div>
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.l1_hashrate}>
          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1 flex items-center gap-1"><InfoIcon /> Your Hashrate</div>
            <div className="text-lg font-mono font-semibold text-[color:var(--fg)]">
              {isLoading ? "..." : mining ? formatHashrate((mining.local_hashrate_th ?? 0) * 1e12) : "--"}
            </div>
          </div>
        </Tooltip>
        <div className="p-3 bg-[var(--surface)] rounded-lg">
          <div className="text-xs text-[color:var(--fainter)] mb-1">Your Miners</div>
          <div className="text-lg font-mono font-semibold text-[color:var(--fg)]">
            {isLoading ? "..." : `${mining?.local_connected_miners ?? 0} connected`}
          </div>
        </div>
      </div>
    </Card>
  );
}

function HealthSection() {
  const { data: watchdog, isLoading } = useWatchdogStatus();

  if (isLoading) return <SkeletonCard />;
  if (!watchdog) return null;

  const overallStatus = watchdog.overall_health ?? "unknown";
  const statusColor = overallStatus === "healthy" ? "online" : overallStatus === "degraded" ? "warning" : "offline";

  return (
    <Card>
      <CardHeader
        title="Health"
        action={
          <StatusDot
            status={statusColor as 'online' | 'warning' | 'offline'}
            pulse={statusColor === 'online'}
            label={overallStatus.charAt(0).toUpperCase() + overallStatus.slice(1)}
          />
        }
      />
      <div className="flex flex-wrap gap-2 mb-3">
        {(watchdog.services ?? []).map((svc: { name: string; status: string }) => (
          <Badge
            key={svc.name}
            variant={svc.status === "running" ? "success" : svc.status === "stopped" ? "error" : "warning"}
          >
            {svc.name}
          </Badge>
        ))}
      </div>
      {/* Color legend */}
      <div className="flex gap-4 t-caption text-[color:var(--fainter)] border-t border-[var(--rule)] pt-2">
        <div className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-green-500" />
          Running
        </div>
        <div className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-yellow-500" />
          Syncing
        </div>
        <div className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-red-500" />
          Stopped
        </div>
      </div>
    </Card>
  );
}

function PrivacySection() {
  const { data: status } = useNodeStatus();
  const { data: haze } = useHazeStatus();
  const { data: shroud } = useShroudStatus();

  // Any non-standard haze storage mode (stripping "hazed" or "full_archive")
  // counts as Active; "standard" (default node) is Off. Kept as a clean binary
  // Active/Off so the tile matches its siblings (single line, no wrapping).
  const hazeActive = haze?.mode === "hazed" || haze?.mode === "full_archive";
  const hazeLabel = !haze ? "Loading..." : hazeActive ? "Active" : "Off";

  const shroudActive = shroud?.enabled ?? false;
  const shroudLabel = shroud ? (shroudActive ? "Active" : "Off") : "Loading...";

  const ghostModeActive = status?.ghost_mode ?? false;
  const torActive = status?.tor_mode ?? false;

  return (
    <Card>
      <CardHeader title="Privacy Status" />
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
        <Tooltip content={TOOLTIPS.ghost_mode}>
          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1 flex items-start gap-1 min-h-[2.25rem] leading-tight"><InfoIcon /> Ghost Mode</div>
            <div className="flex items-center gap-2">
              <StatusDot
                status={ghostModeActive ? "online" : "offline"}
                size="sm"
              />
              <span className="text-sm text-[color:var(--fg)]">{ghostModeActive ? "Active" : "Off"}</span>
            </div>
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.privacy_tor}>
          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1 flex items-start gap-1 min-h-[2.25rem] leading-tight"><InfoIcon /> Tor Mode</div>
            <div className="flex items-center gap-2">
              <StatusDot
                status={torActive ? "online" : "offline"}
                size="sm"
              />
              <span className="text-sm text-[color:var(--fg)]">{torActive ? "Active" : "Off"}</span>
            </div>
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.privacy_haze}>
          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1 flex items-start gap-1 min-h-[2.25rem] leading-tight"><InfoIcon /> Ghost Haze</div>
            <div className="flex items-center gap-2">
              <StatusDot
                status={hazeActive ? "online" : "offline"}
                size="sm"
              />
              <span className="text-sm text-[color:var(--fg)]">{hazeLabel}</span>
            </div>
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.privacy_shroud}>
          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1 flex items-start gap-1 min-h-[2.25rem] leading-tight"><InfoIcon /> Ghost Shroud</div>
            <div className="flex items-center gap-2">
              <StatusDot
                status={shroudActive ? "online" : "offline"}
                size="sm"
              />
              <span className="text-sm text-[color:var(--fg)]">{shroudLabel}</span>
            </div>
          </div>
        </Tooltip>
      </div>
    </Card>
  );
}

export default function OverviewPage() {
  const { data: info } = useNodeInfo();
  const { data: nickname } = useNickname();
  const { data: status } = useNodeStatus();

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="overview"
        title="Your node, at a glance."
        subtitle={nickname?.nickname ? `${nickname.nickname} \u00b7 v${info?.version ?? ''}` : info?.version ? `v${info.version}` : undefined}
        actions={
          status?.is_synced != null && (
            <Badge variant={status.is_synced ? "success" : "warning"}>
              {status.is_synced ? "Synced" : "Syncing..."}
            </Badge>
          )
        }
      />

      {/* L1 hero card */}
      <SectionErrorBoundary section="L1 Status">
        <L1Card />
      </SectionErrorBoundary>

      {/* Health + Privacy */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SectionErrorBoundary section="Health">
          <HealthSection />
        </SectionErrorBoundary>
        <SectionErrorBoundary section="Privacy">
          <PrivacySection />
        </SectionErrorBoundary>
      </div>
    </div>
  );
}
