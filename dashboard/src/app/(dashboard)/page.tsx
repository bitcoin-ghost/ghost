"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { StatusDot } from "@/components/ui/StatusDot";
import { Tooltip } from "@/components/ui/Tooltip";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useNodeInfo, useNodeStatus, useShares, useNickname } from "@/hooks/queries/useNodeQueries";
import { useWatchdogStatus } from "@/hooks/queries/useWatchdogQueries";
import { useMiningStatus, useBestHash } from "@/hooks/queries/useMiningQueries";
import { useGhostPayStatus } from "@/hooks/queries/useGhostPayQueries";
import { useHazeStatus } from "@/hooks/queries/useHazeQueries";
import { useShroudStatus } from "@/hooks/queries/useShroudQueries";
import { formatHashrate } from "@/components/ui/DataTable";

const TOOLTIPS = {
  block_height: "The current block height of the Bitcoin blockchain your node has synced to. During Initial Block Download (IBD), this shows sync progress.",
  l1_peers: "Number of Ghost mesh peers your node is directly connected to via P2P.",
  l1_hashrate: "Combined mining hashrate of miners connected to YOUR node's stratum port only. This is just your node, not the whole Ghost pool or the Bitcoin network.",
  pool_hashrate: "Combined mining hashrate of every miner across the entire Ghost pool — all nodes in the mesh aggregated together. This is the whole Ghost pool, not just your node or the Bitcoin network.",
  network_hashrate: "Estimated total hashrate of the Bitcoin network, derived from current difficulty. This is the global network, not just Ghost.",
  l2_height: "The current block height of the Ghost Pay L2 network. Format: era:block. During IBD, shows syncing state.",
  l2_peers: "Number of Ghost Pay L2 peers your node is connected to.",
  l2_wraith: "Wraith privacy mixing is available when Ghost Pay is running. Any L2 participant can initiate a mixing session.",
  shares: "Your node's share count determines your portion of the node reward pool. Based on the 5-4-3-2-1 system.",
  health: "Overall health of the services running on your node.",
  ghost_mode: "Ghost Mode isolates your node — stops relaying transactions and messages to peers (except block propagation). Useful for privacy.",
  privacy_tor: "Tor Mode routes all P2P connections through the Tor network, hiding your node's IP address from peers.",
  privacy_haze: "Ghost Haze strips privacy-sensitive data (signatures, witness data, inscriptions) from stored blocks.",
  privacy_shroud: "Ghost Shroud adds random delays before relaying transactions, protecting against timing analysis.",
  privacy_wraith: "Wraith Protocol enables CoinJoin mixing on the L2 network, breaking transaction linkability.",
};

const SHARE_TIERS = [
  { key: "archive_mode", name: "Archive Mode", bonus: 5 },
  { key: "ghost_pay", name: "Ghost Pay", bonus: 4 },
  { key: "public_mining", name: "Public Mining", bonus: 3 },
  { key: "reaper", name: "Reaper", bonus: 2 },
  { key: "elder", name: "Elder Status", bonus: 1 },
] as const;

function InfoIcon() {
  return (
    <svg className="w-3 h-3 text-[color:var(--fainter)] inline-block mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
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
    <Card className="border-[color:var(--accent)]">
      <CardHeader
        title={<span className="text-[color:var(--accent)]">L1 &middot; Bitcoin</span>}
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
            <div className="text-xs text-[color:var(--fainter)] mb-1"><InfoIcon /> Block Height</div>
            <div className="text-lg font-mono font-semibold text-[color:var(--fg)]">
              {isLoading ? "..." : isSyncing
                ? <span>{syncHeight.toLocaleString()} <span className="text-xs text-[color:var(--accent)]">/ {blockHeight.toLocaleString()}</span></span>
                : syncHeight.toLocaleString()
              }
            </div>
            {isSyncing && (
              <div className="text-xs text-[color:var(--accent)] mt-0.5">
                IBD &middot; {blockHeight > 0 ? ((syncHeight / blockHeight) * 100).toFixed(1) : 0}%
              </div>
            )}
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.l1_peers}>
          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1"><InfoIcon /> Mesh Peers</div>
            <div className="text-lg font-mono font-semibold text-[color:var(--fg)]">
              {isLoading ? "..." : `${status?.peer_count ?? 0} connected`}
            </div>
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.network_hashrate}>
          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1"><InfoIcon /> Network Hashrate</div>
            <div className="text-lg font-mono font-semibold text-[color:var(--fg)]">
              {bestHashLoading ? "..." : bestHash?.network_hashrate ? formatHashrate(bestHash.network_hashrate) : "--"}
            </div>
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.pool_hashrate}>
          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1"><InfoIcon /> Ghost Pool Hashrate</div>
            <div className="text-lg font-mono font-semibold text-[color:var(--fg)]">
              {isLoading ? "..." : mining ? formatHashrate((mining.hashrate_th ?? 0) * 1e12) : "0 H/s"}
            </div>
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.l1_hashrate}>
          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1"><InfoIcon /> Your Hashrate</div>
            <div className="text-lg font-mono font-semibold text-[color:var(--fg)]">
              {isLoading ? "..." : mining ? formatHashrate((mining.local_hashrate_th ?? 0) * 1e12) : "0 H/s"}
            </div>
          </div>
        </Tooltip>
        <div className="p-3 bg-[var(--surface)] rounded-lg">
          <div className="text-xs text-[color:var(--fainter)] mb-1">Miners</div>
          <div className="text-lg font-mono font-semibold text-[color:var(--fg)]">
            {isLoading ? "..." : `${mining?.connected_miners ?? 0} connected`}
          </div>
        </div>
      </div>
    </Card>
  );
}

function L2Card() {
  const { data: gp, isLoading } = useGhostPayStatus();

  const isRunning = gp && gp.sync_state !== "disabled" && gp.sync_state !== "unavailable";
  const isSyncing = isRunning && gp?.sync_state !== "synced";
  const height = gp ? `${gp.l2_era ?? 1}:${(gp.virtual_block ?? gp.block_height ?? 0).toLocaleString()}` : "--";

  // Wraith is an optional mixing feature layered on L2. Distinguish the three
  // real states so the tile never reads a bare "Inactive" (which looks like a
  // fault) when L2 itself is healthy and only mixing is simply not enabled.
  const wraithActive = !!(isRunning && gp?.wraith_enabled);
  const wraithLabel = isLoading ? "..." : wraithActive ? "Active" : isRunning ? "Not enabled" : "Offline";
  const wraithReason = wraithActive
    ? "Active sessions"
    : isRunning
    ? "Mixing not enabled on this node"
    : "Requires Ghost Pay";

  return (
    <Card className="border-purple-600/30">
      <CardHeader
        title={<span className="text-purple-400">L2 &middot; Ghost Pay</span>}
        action={
          isRunning != null && (
            <StatusDot
              status={isRunning ? "online" : "offline"}
              pulse={!!isRunning}
              label={isRunning ? (isSyncing ? "Syncing" : "Synced") : "Offline"}
            />
          )
        }
      />
      <div className="grid grid-cols-2 gap-3">
        <Tooltip content={TOOLTIPS.l2_height}>
          <div className="p-3 bg-purple-900/10 rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1"><InfoIcon /> L2 Height</div>
            <div className="text-lg font-mono font-semibold text-[color:var(--fg)]">
              {isLoading ? "..." : isSyncing ? <span className="text-purple-400">Syncing...</span> : height}
            </div>
            {isSyncing && (
              <div className="text-xs text-purple-400 mt-0.5">
                {height}
              </div>
            )}
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.l2_peers}>
          <div className="p-3 bg-purple-900/10 rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1"><InfoIcon /> L2 Peers</div>
            <div className="text-lg font-mono font-semibold text-[color:var(--fg)]">
              {isLoading ? "..." : `${gp?.peer_count ?? 0} connected`}
            </div>
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.l2_wraith}>
          <div className="p-3 bg-purple-900/10 rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1"><InfoIcon /> Wraith</div>
            <div className="flex items-center gap-2">
              <StatusDot
                status={wraithActive ? "online" : "offline"}
                size="sm"
              />
              <span className="text-sm font-mono text-[color:var(--fg)]">
                {wraithLabel}
              </span>
            </div>
            {!isLoading && (
              <div className={`text-xs mt-0.5 ${wraithActive ? "text-purple-400" : "text-[color:var(--fainter)]"}`}>
                {wraithReason}
              </div>
            )}
          </div>
        </Tooltip>
        <div className="p-3 bg-purple-900/10 rounded-lg">
          <div className="text-xs text-[color:var(--fainter)] mb-1">Status</div>
          <div className="text-lg font-mono font-semibold text-[color:var(--fg)]">
            {isLoading ? "..." : isRunning ? "Active" : "Not enabled"}
          </div>
        </div>
      </div>
    </Card>
  );
}

function SharesSection() {
  const { data: shares, isLoading } = useShares();

  if (isLoading) return <SkeletonCard />;
  if (!shares) return null;

  const percent = shares.max_shares > 0 ? (shares.total / shares.max_shares) * 100 : 0;

  return (
    <Card>
      <CardHeader
        title="Your Shares"
        subtitle="5-4-3-2-1 Reward System"
        action={
          <Tooltip content={TOOLTIPS.shares}>
            <span className="text-2xl font-bold text-[color:var(--fg)]">
              {shares.total}<span className="text-[color:var(--fainter)] text-lg"> / {shares.max_shares}</span>
              <InfoIcon />
            </span>
          </Tooltip>
        }
      />

      <ProgressBar
        value={percent}
        color={shares.uptime_qualified ? "orange" : "red"}
        size="lg"
        className="mb-4"
      />

      {/* Uptime gatekeeper */}
      {!shares.uptime_qualified && (
        <div className="mb-4 p-3 rounded-lg bg-[var(--surface)] border border-[color:var(--red)]">
          <div className="flex items-center gap-2">
            <span className="text-[color:var(--red)]">&#10007;</span>
            <span className="text-sm text-[color:var(--dim)]">Uptime below 95%</span>
            <Badge variant="error">{(shares.uptime_percent ?? 0).toFixed(1)}%</Badge>
          </div>
          <p className="text-xs text-[color:var(--red)] mt-1">All shares disabled until uptime recovers</p>
        </div>
      )}

      <div className="space-y-1.5">
        {SHARE_TIERS.map((tier) => {
          const isActive = shares[tier.key as keyof typeof shares] as boolean;
          const disabled = !shares.uptime_qualified;
          return (
            <div key={tier.key} className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-[var(--surface)]">
              <div className="flex items-center gap-2">
                <span className={isActive && !disabled ? "text-[color:var(--green)]" : "text-[color:var(--fainter)]"}>
                  {isActive ? "\u2713" : "\u2717"}
                </span>
                <span className={isActive && !disabled ? "text-[color:var(--fg)] text-sm" : "text-[color:var(--fainter)] text-sm"}>
                  {tier.name}
                </span>
              </div>
              <Badge variant={isActive && !disabled ? "success" : "default"}>+{tier.bonus}</Badge>
            </div>
          );
        })}
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
    <Card className="border-[color:var(--green)]">
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
      <div className="flex gap-4 text-[10px] text-[color:var(--fainter)] border-t border-[var(--rule)] pt-2">
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
  const { data: gp } = useGhostPayStatus();

  // Any non-standard haze storage mode (stripping "hazed" or "full_archive")
  // counts as Active; "standard" (default node) is Off. Kept as a clean binary
  // Active/Off so the tile matches its siblings (single line, no wrapping).
  const hazeActive = haze?.mode === "hazed" || haze?.mode === "full_archive";
  const hazeLabel = !haze ? "Loading..." : hazeActive ? "Active" : "Off";

  const shroudActive = shroud?.enabled ?? false;
  const shroudLabel = shroud ? (shroudActive ? "Active" : "Off") : "Loading...";

  const ghostModeActive = status?.ghost_mode ?? false;
  const torActive = status?.tor_mode ?? false;
  const gpRunning = gp && gp.sync_state !== "disabled" && gp.sync_state !== "unavailable";
  const wraithActive = gpRunning && gp?.wraith_enabled;

  return (
    <Card className="border-[color:var(--red)]">
      <CardHeader title={<span className="text-[color:var(--red)]">Privacy Status</span>} />
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <Tooltip content={TOOLTIPS.ghost_mode}>
          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1"><InfoIcon /> Ghost Mode</div>
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
            <div className="text-xs text-[color:var(--fainter)] mb-1"><InfoIcon /> Tor Mode</div>
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
            <div className="text-xs text-[color:var(--fainter)] mb-1"><InfoIcon /> Ghost Haze</div>
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
            <div className="text-xs text-[color:var(--fainter)] mb-1"><InfoIcon /> Ghost Shroud</div>
            <div className="flex items-center gap-2">
              <StatusDot
                status={shroudActive ? "online" : "offline"}
                size="sm"
              />
              <span className="text-sm text-[color:var(--fg)]">{shroudLabel}</span>
            </div>
          </div>
        </Tooltip>
        <Tooltip content={TOOLTIPS.privacy_wraith}>
          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <div className="text-xs text-[color:var(--fainter)] mb-1"><InfoIcon /> Wraith</div>
            <div className="flex items-center gap-2">
              <StatusDot
                status={wraithActive ? "online" : "offline"}
                size="sm"
              />
              <span className="text-sm text-[color:var(--fg)]">{wraithActive ? "Active" : "Off"}</span>
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

      {/* L1 + L2 hero cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SectionErrorBoundary section="L1 Status">
          <L1Card />
        </SectionErrorBoundary>
        <SectionErrorBoundary section="L2 Status">
          <L2Card />
        </SectionErrorBoundary>
      </div>

      {/* Shares */}
      <SectionErrorBoundary section="Shares">
        <SharesSection />
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
