"use client";

import { useMemo } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { DataTable, formatHashrate, formatDuration } from "@/components/ui/DataTable";
import { TimeSeriesChart, ProportionBar } from "@/components/ui/MiniChart";
import {
  useMiningStatus,
  useBestHash,
  usePoolStatus,
  useMiners,
  useRewardsCurrent,
  useNodePayoutHistory,
} from "@/hooks/queries";
import { usePoolSeries } from "@/hooks/usePoolSeries";
import type { BestHashEntry, MinerInfo, NodePayoutEntry } from "@/types/api";

const TOOLTIPS = {
  pool_hashrate: "Combined hashrate of every node in the Ghost mesh pool, aggregated across the whole network.",
  node_hashrate: "Combined hashrate of miners connected to this node's stratum port.",
  miners: "Active miners across the mesh pool (falls back to this node's connected miners when the mesh figure is unavailable).",
  blocks: "Total blocks the pool has found since first startup. Each block triggers a payout distribution.",
  difficulty: "Current Bitcoin network difficulty, derived from the chain. This is the global target every miner is racing.",
  accept_rate: "Share of submitted shares that were accepted this round. Rejected shares are stale or invalid.",
  best_share: "The lowest (best) hash a connected miner has submitted — more leading zeros means closer to solving a block.",
  network_hashrate: "Estimated total hashrate of the whole Bitcoin network, derived from current difficulty.",
};

// Mirrors `formatDifficulty` on the public pool.html so the dashboard and the
// pool website render identical numbers.
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

function calculateLeadingZeros(difficulty: number): number {
  if (difficulty <= 0) return 0;
  return Math.floor(8 + Math.log2(difficulty) / 4);
}

function formatTimeAgo(timestamp: number): string {
  if (!timestamp) return "Never";
  const diff = Math.floor(Date.now() / 1000) - timestamp;
  if (diff < 0) return "just now";
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function formatSats(satoshis: number): string {
  if (satoshis >= 100_000_000) return `${(satoshis / 100_000_000).toFixed(6)} BTC`;
  return `${satoshis.toLocaleString()} sats`;
}

function minerName(m: MinerInfo): string {
  return m.worker_name || m.miner_id || m.address || "—";
}

function BestShareCard({ title, entry }: { title: string; entry: BestHashEntry | undefined }) {
  const diff = entry?.difficulty ?? 0;
  const hasData = entry && diff > 0;
  return (
    <div
      className="rounded-lg p-3"
      style={{ background: "var(--surface)", border: "1px solid var(--rule)" }}
    >
      <div style={{ color: "var(--dim)", fontSize: "12px", marginBottom: "4px" }}>{title}</div>
      {hasData ? (
        <>
          <div style={{ color: "var(--accent)", fontSize: "18px", fontWeight: 600 }}>{formatDifficulty(diff)}</div>
          <div className="truncate" style={{ color: "var(--dim)", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
            {entry.hash}
          </div>
          <div style={{ color: "var(--fainter)", fontSize: "11px", marginTop: "2px" }}>
            {calculateLeadingZeros(diff)} leading zeros
          </div>
          <div style={{ color: "var(--fainter)", fontSize: "11px", marginTop: "2px" }}>
            {formatTimeAgo(entry.timestamp ?? 0)}
          </div>
        </>
      ) : (
        <div style={{ color: "var(--fainter)", fontSize: "13px" }}>No data yet</div>
      )}
    </div>
  );
}

// One chart panel: title + "live (session)" tag + the plot.
function ChartCard({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <Card>
      <div className="mb-3 flex items-start justify-between gap-2">
        <div>
          <h3 className="font-medium" style={{ color: "var(--fg)", fontSize: "15px" }}>
            {title}
          </h3>
          {subtitle && (
            <p style={{ color: "var(--dim)", fontSize: "12px", marginTop: "2px" }}>{subtitle}</p>
          )}
        </div>
        <Badge variant="default">live (session)</Badge>
      </div>
      {children}
    </Card>
  );
}

export default function NodePoolPage() {
  const { data: status, isLoading: statusLoading } = useMiningStatus();
  const { data: bestHash } = useBestHash();
  const { data: pool } = usePoolStatus();
  const { data: minersData } = useMiners();
  const { data: rewards } = useRewardsCurrent();
  const { data: payouts } = useNodePayoutHistory("7d");
  const series = usePoolSeries();

  const meshTh = status?.hashrate_th ?? status?.total_hashrate ?? 0;
  const nodeTh = status?.local_hashrate_th ?? 0;
  const minersNow =
    status?.mesh_active_miners ?? pool?.miner_count ?? status?.connected_miners ?? status?.active_miners ?? 0;

  const submitted = status?.shares_submitted ?? 0;
  const accepted = status?.shares_accepted ?? 0;
  const rejected = status?.shares_rejected ?? Math.max(0, submitted - accepted);
  const acceptRate = submitted > 0 ? (accepted / submitted) * 100 : 100;

  const networkDifficulty = status?.difficulty ?? bestHash?.best_difficulty ?? 0;

  // Round progress: elapsed vs estimated time to next block, when the node
  // surfaces both. Falls back to a shares-this-round readout otherwise.
  const roundElapsed = pool?.current_round_duration_secs ?? 0;
  const roundEta = pool?.estimated_time_to_block_secs ?? 0;
  const hasRoundEta = roundEta > 0;
  const roundProgress = hasRoundEta ? (roundElapsed / (roundElapsed + roundEta)) * 100 : 0;
  const sharesThisRound = status?.shares_this_round ?? accepted;

  // Leaderboard: the operator-authed miners endpoint returns a per-miner list;
  // otherwise `miners_redacted` is set and we show the aggregate instead.
  const minerList = minersData?.miners;
  const minersRedacted = minersData?.miners_redacted === true || !minerList;

  const leaderboard = useMemo(() => {
    if (!minerList) return [] as MinerInfo[];
    return [...minerList]
      .sort((a, b) => (b.hashrate_th ?? 0) - (a.hashrate_th ?? 0))
      .slice(0, 15);
  }, [minerList]);

  const minerColumns = useMemo<ColumnDef<MinerInfo>[]>(
    () => [
      {
        id: "rank",
        header: "#",
        cell: ({ row }) => <span style={{ color: "var(--fainter)" }}>{row.index + 1}</span>,
      },
      {
        id: "miner",
        header: "Miner / Worker",
        accessorFn: (m) => minerName(m),
        cell: ({ getValue }) => (
          <span className="truncate" style={{ fontFamily: "var(--font-mono)", fontSize: "12px" }}>
            {String(getValue())}
          </span>
        ),
      },
      {
        id: "hashrate",
        header: "Hashrate",
        accessorFn: (m) => m.hashrate_th ?? 0,
        cell: ({ getValue }) => formatHashrate((getValue() as number) * 1e12),
      },
      {
        id: "shares",
        header: "Shares",
        accessorFn: (m) => m.shares_accepted ?? m.valid_shares ?? m.total_shares ?? 0,
        cell: ({ getValue }) => (getValue() as number).toLocaleString(),
      },
      {
        id: "last",
        header: "Last share",
        accessorFn: (m) => m.last_share_at ?? m.last_share ?? 0,
        cell: ({ getValue }) => formatTimeAgo(getValue() as number),
      },
    ],
    [],
  );

  const payoutColumns = useMemo<ColumnDef<NodePayoutEntry>[]>(
    () => [
      {
        id: "time",
        header: "When",
        accessorFn: (p) => p.timestamp ?? p.updated_at ?? p.created_at ?? 0,
        cell: ({ getValue }) => formatTimeAgo(getValue() as number),
      },
      {
        id: "type",
        header: "Type",
        accessorFn: (p) => p.payout_type ?? "reward",
        cell: ({ getValue }) => <Badge variant="default">{String(getValue())}</Badge>,
      },
      {
        id: "block",
        header: "Block",
        accessorFn: (p) => p.block_height ?? 0,
        cell: ({ getValue }) => {
          const h = getValue() as number;
          return h > 0 ? `#${h.toLocaleString()}` : "—";
        },
      },
      {
        id: "amount",
        header: "Amount",
        accessorFn: (p) => p.amount_satoshis ?? p.balance_sats ?? 0,
        cell: ({ getValue }) => (
          <span style={{ color: "var(--accent)", fontFamily: "var(--font-mono)" }}>
            {formatSats(getValue() as number)}
          </span>
        ),
      },
    ],
    [],
  );

  const payoutRows = payouts ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="ghost pool"
        title="Node Pool"
        subtitle="Live pool stats and graphs for this node and the Ghost mesh — hashrate, miners, shares, best shares, round progress and payouts."
      />

      {/* Live-session note: the node only exposes current values, so the graphs
          are built from a rolling in-browser buffer that resets on reload. */}
      <div
        className="rounded-lg p-3 text-sm"
        style={{ background: "var(--accent-weak)", border: "1px solid var(--rule)", color: "var(--dim)" }}
      >
        Graphs are drawn from a live in-browser buffer of the polled pool values
        ({series.sampleCount} sample{series.sampleCount === 1 ? "" : "s"} this session) and reset on reload.
        The node API exposes current values only — persisting server-side roll-ups would let these charts
        survive reloads and cover longer windows.
      </div>

      {/* Headline stats */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <StatCard
          label="Pool Hashrate"
          value={status ? formatHashrate(meshTh * 1e12) : "--"}
          sublabel="all Ghost nodes"
          tooltip={TOOLTIPS.pool_hashrate}
          loading={statusLoading}
        />
        <StatCard
          label="This Node"
          value={status ? formatHashrate(nodeTh * 1e12) : "--"}
          sublabel="local hashrate"
          tooltip={TOOLTIPS.node_hashrate}
          loading={statusLoading}
        />
        <StatCard
          label="Connected Miners"
          value={minersNow}
          sublabel="active workers"
          tooltip={TOOLTIPS.miners}
          loading={statusLoading}
        />
        <StatCard
          label="Blocks Found"
          value={status?.blocks_found ?? pool?.blocks_found ?? 0}
          sublabel="all time"
          tooltip={TOOLTIPS.blocks}
          loading={statusLoading}
        />
        <StatCard
          label="Network Difficulty"
          value={formatDifficulty(networkDifficulty)}
          sublabel="global target"
          tooltip={TOOLTIPS.difficulty}
          loading={statusLoading}
        />
        <StatCard
          label="Accept Rate"
          value={`${acceptRate.toFixed(1)}%`}
          sublabel={`${accepted.toLocaleString()} accepted`}
          tooltip={TOOLTIPS.accept_rate}
          loading={statusLoading}
        />
      </div>

      {/* Hashrate + miners time-series */}
      <SectionErrorBoundary section="Pool Graphs">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <ChartCard title="Pool Hashrate" subtitle="Mesh-wide, aggregated across all nodes">
            <TimeSeriesChart
              data={series.meshHashrate}
              ariaLabel="Pool hashrate over the session"
              formatValue={(v) => formatHashrate(v, 1)}
            />
          </ChartCard>
          <ChartCard title="Connected Miners" subtitle="Active miners across the mesh pool">
            <TimeSeriesChart
              data={series.miners}
              color="var(--green)"
              ariaLabel="Connected miners over the session"
              formatValue={(v) => Math.round(v).toString()}
            />
          </ChartCard>
          <ChartCard title="This Node Hashrate" subtitle="Miners connected to this node only">
            <TimeSeriesChart
              data={series.nodeHashrate}
              ariaLabel="This node hashrate over the session"
              formatValue={(v) => formatHashrate(v, 1)}
            />
          </ChartCard>
          <ChartCard title="Share Accept Rate" subtitle="Accepted shares as a percentage of submitted">
            <TimeSeriesChart
              data={series.acceptRate}
              color="var(--green)"
              ariaLabel="Share accept rate over the session"
              formatValue={(v) => `${v.toFixed(1)}%`}
            />
          </ChartCard>
        </div>
      </SectionErrorBoundary>

      {/* Shares + round progress */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SectionErrorBoundary section="Shares">
          <Card>
            <CardHeader title="Shares" subtitle="Accepted vs rejected this round" />
            <div className="mb-4 grid grid-cols-3 gap-4">
              <div>
                <div style={{ color: "var(--dim)", fontSize: "12px" }}>Submitted</div>
                <div style={{ color: "var(--fg)", fontSize: "20px", fontWeight: 600 }}>
                  {submitted.toLocaleString()}
                </div>
              </div>
              <div>
                <div style={{ color: "var(--dim)", fontSize: "12px" }}>Accepted</div>
                <div style={{ color: "var(--green)", fontSize: "20px", fontWeight: 600 }}>
                  {accepted.toLocaleString()}
                </div>
              </div>
              <div>
                <div style={{ color: "var(--dim)", fontSize: "12px" }}>Rejected</div>
                <div style={{ color: "var(--red)", fontSize: "20px", fontWeight: 600 }}>
                  {rejected.toLocaleString()}
                </div>
              </div>
            </div>
            <ProportionBar
              segments={[
                { label: "Accepted", value: accepted, color: "var(--green)" },
                { label: "Rejected", value: rejected, color: "var(--red)" },
              ]}
            />
          </Card>
        </SectionErrorBoundary>

        <SectionErrorBoundary section="Round Progress">
          <Card>
            <CardHeader
              title="Round Progress"
              subtitle={pool?.round_id ? `Round #${pool.round_id}` : "Current mining round"}
            />
            {hasRoundEta ? (
              <ProgressBar
                value={roundProgress}
                max={100}
                label="Elapsed vs estimated time to block"
                sublabel={`${formatDuration(roundElapsed)} / ~${formatDuration(roundElapsed + roundEta)}`}
                color="orange"
                size="lg"
              />
            ) : (
              <div style={{ color: "var(--dim)", fontSize: "13px" }}>
                No block-time estimate from the node yet.
              </div>
            )}
            <div className="mt-4 grid grid-cols-2 gap-4">
              <div>
                <div style={{ color: "var(--dim)", fontSize: "12px" }}>Shares this round</div>
                <div style={{ color: "var(--fg)", fontSize: "18px", fontWeight: 600 }}>
                  {sharesThisRound.toLocaleString()}
                </div>
              </div>
              <div>
                <div style={{ color: "var(--dim)", fontSize: "12px" }}>Pending rewards</div>
                <div style={{ color: "var(--accent)", fontSize: "18px", fontWeight: 600 }}>
                  {formatSats(rewards?.pending_rewards_sats ?? 0)}
                </div>
              </div>
            </div>
          </Card>
        </SectionErrorBoundary>
      </div>

      {/* Best shares + network */}
      <SectionErrorBoundary section="Best Shares">
        <Card>
          <CardHeader
            title="Best Shares"
            subtitle="Lowest hash values achieved by connected miners — more leading zeros means closer to a block"
            action={
              bestHash?.network_hashrate ? (
                <div className="text-right">
                  <div style={{ color: "var(--dim)", fontSize: "11px" }}>Network hashrate</div>
                  <div style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 600 }}>
                    {formatHashrate(bestHash.network_hashrate, 0)}
                  </div>
                </div>
              ) : undefined
            }
          />
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <BestShareCard title="Current Round" entry={bestHash?.current_round} />
            <BestShareCard title="Last Hour" entry={bestHash?.last_hour} />
            <BestShareCard title="Last 24h" entry={bestHash?.last_24h} />
            <BestShareCard title="All Time" entry={bestHash?.all_time} />
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Leaderboard */}
      <SectionErrorBoundary section="Miner Leaderboard">
        <Card>
          <CardHeader
            title="Miner Leaderboard"
            subtitle="Top miners connected to this node, ranked by hashrate"
          />
          {minersRedacted ? (
            <div style={{ color: "var(--dim)", fontSize: "13px" }}>
              Per-miner detail is not available on this node (the miner list is redacted for unauthenticated
              access). Aggregate:{" "}
              <span style={{ color: "var(--fg)" }}>
                {minersData?.total ?? minersData?.total_miners ?? minersNow} miner
                {(minersData?.total ?? minersData?.total_miners ?? minersNow) === 1 ? "" : "s"}
              </span>
              {minersData?.total_hashrate_th != null && (
                <> · {formatHashrate(minersData.total_hashrate_th * 1e12)}</>
              )}
              .
            </div>
          ) : (
            <DataTable
              columns={minerColumns}
              data={leaderboard}
              showPagination={false}
              emptyMessage="No miners connected"
              loadingRows={5}
            />
          )}
        </Card>
      </SectionErrorBoundary>

      {/* Recent payouts */}
      <SectionErrorBoundary section="Recent Payouts">
        <Card>
          <CardHeader title="Recent Payouts" subtitle="Payments credited to this node (last 7 days)" />
          <DataTable
            columns={payoutColumns}
            data={payoutRows}
            pageSize={10}
            emptyMessage="No payouts in the last 7 days"
          />
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}
