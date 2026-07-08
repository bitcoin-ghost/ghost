"use client";

import { useMemo } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
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
  usePoolMeshLeaderboard,
} from "@/hooks/queries";
import { usePoolSeries } from "@/hooks/usePoolSeries";
import type { BestHashEntry, MinerInfo, NodePayoutEntry, MeshLeaderboardNode } from "@/types/api";

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
      <div className="t-caption" style={{ color: "var(--dim)", marginBottom: "4px" }}>{title}</div>
      {hasData ? (
        <>
          <div className="t-title" style={{ color: "var(--accent)", fontWeight: 600 }}>{formatDifficulty(diff)}</div>
          <div className="truncate t-caption" style={{ color: "var(--dim)", fontFamily: "var(--font-mono)" }}>
            {entry.hash}
          </div>
          <div className="t-caption" style={{ color: "var(--fainter)", marginTop: "2px" }}>
            {calculateLeadingZeros(diff)} leading zeros
          </div>
          <div className="t-caption" style={{ color: "var(--fainter)", marginTop: "2px" }}>
            {formatTimeAgo(entry.timestamp ?? 0)}
          </div>
        </>
      ) : (
        <div className="t-label" style={{ color: "var(--fainter)" }}>No data yet</div>
      )}
    </div>
  );
}

// One chart panel: title + source tag + the plot. The tag shows whether the
// series is backed by the server-side ring ("history") or the in-browser
// session buffer ("live (session)").
function ChartCard({
  title,
  subtitle,
  children,
  serverBacked = false,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  serverBacked?: boolean;
}) {
  return (
    <Card>
      <div className="mb-3 flex items-start justify-between gap-2">
        <div>
          <h3 className="t-title" style={{ color: "var(--fg)" }}>
            {title}
          </h3>
          {subtitle && (
            <p className="t-caption" style={{ color: "var(--dim)", marginTop: "2px" }}>{subtitle}</p>
          )}
        </div>
        <Badge variant="default">{serverBacked ? "history" : "live (session)"}</Badge>
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
  const { data: meshLeaderboard } = usePoolMeshLeaderboard();
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
          <span className="truncate t-caption" style={{ fontFamily: "var(--font-mono)" }}>
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

  // Mesh-wide leaderboard: every node in the mesh ranked by hashrate. The
  // backend returns nodes already ranked; render them as-is.
  const meshNodes = meshLeaderboard?.nodes ?? [];
  const meshRecords = meshLeaderboard?.records ?? [];

  const meshNodeColumns = useMemo<ColumnDef<MeshLeaderboardNode>[]>(
    () => [
      {
        id: "rank",
        header: "#",
        cell: ({ row }) => <span style={{ color: "var(--fainter)" }}>{row.index + 1}</span>,
      },
      {
        id: "node",
        header: "Node",
        accessorFn: (n) => n.name || n.node_id.slice(0, 10),
        cell: ({ row }) => (
          <span className="truncate t-caption" style={{ fontFamily: "var(--font-mono)" }}>
            {row.original.name || row.original.node_id.slice(0, 10)}
            {row.original.is_self && (
              <Badge variant="default" className="ml-2">
                this node
              </Badge>
            )}
          </span>
        ),
      },
      {
        id: "hashrate",
        header: "Hashrate",
        accessorFn: (n) => n.hashrate_th ?? 0,
        cell: ({ getValue }) => formatHashrate((getValue() as number) * 1e12),
      },
      {
        id: "miners",
        header: "Miners",
        accessorFn: (n) => n.miner_count ?? 0,
        cell: ({ getValue }) => (getValue() as number).toLocaleString(),
      },
      {
        id: "shares",
        header: "Shares",
        accessorFn: (n) => n.shares ?? 0,
        cell: ({ getValue }) => `${getValue() as number} / 15`,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (n) => (n.healthy ? "online" : "offline"),
        cell: ({ getValue }) => (
          <Badge variant={getValue() === "online" ? "success" : "error"}>{String(getValue())}</Badge>
        ),
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
          <ChartCard
            title="Pool Hashrate"
            subtitle="Mesh-wide, aggregated across all nodes"
            serverBacked={series.serverBacked}
          >
            <TimeSeriesChart
              data={series.meshHashrate}
              minZero
              ariaLabel="Pool hashrate over time"
              formatValue={(v) => formatHashrate(v, 1)}
            />
          </ChartCard>
          <ChartCard
            title="Pool Connected Miners"
            subtitle="Active miners across the mesh pool"
            serverBacked={series.serverBacked}
          >
            <TimeSeriesChart
              data={series.miners}
              color="var(--green)"
              minZero
              ariaLabel="Pool connected miners over time"
              formatValue={(v) => Math.round(v).toString()}
            />
          </ChartCard>
          <ChartCard
            title="This Node Hashrate"
            subtitle="Miners connected to this node only"
            serverBacked={series.serverBacked}
          >
            <TimeSeriesChart
              data={series.nodeHashrate}
              minZero
              ariaLabel="This node hashrate over time"
              formatValue={(v) => formatHashrate(v, 1)}
            />
          </ChartCard>
          <ChartCard title="This Node Connected Miners" subtitle="Miners connected to this node only">
            <TimeSeriesChart
              data={series.nodeMiners}
              color="var(--green)"
              minZero
              ariaLabel="This node connected miners over time"
              formatValue={(v) => Math.round(v).toString()}
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
                <div className="t-caption" style={{ color: "var(--dim)" }}>Submitted</div>
                <div className="t-title" style={{ color: "var(--fg)", fontWeight: 600 }}>
                  {submitted.toLocaleString()}
                </div>
              </div>
              <div>
                <div className="t-caption" style={{ color: "var(--dim)" }}>Accepted</div>
                <div className="t-title" style={{ color: "var(--green)", fontWeight: 600 }}>
                  {accepted.toLocaleString()}
                </div>
              </div>
              <div>
                <div className="t-caption" style={{ color: "var(--dim)" }}>Rejected</div>
                <div className="t-title" style={{ color: "var(--red)", fontWeight: 600 }}>
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
              title="Round"
              subtitle={pool?.round_id ? `Round #${pool.round_id}` : "Current mining round"}
            />
            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="t-caption" style={{ color: "var(--dim)" }}>Current round</div>
                <div className="t-title" style={{ color: "var(--fg)", fontWeight: 600 }}>
                  {formatDuration(roundElapsed)}
                </div>
                <div className="t-caption" style={{ color: "var(--fainter)" }}>time on the current template</div>
              </div>
              <div>
                <div className="t-caption" style={{ color: "var(--dim)" }}>Est. time to block</div>
                <div className="t-title" style={{ color: "var(--fg)", fontWeight: 600 }}>
                  {hasRoundEta ? formatDuration(roundEta) : "—"}
                </div>
                <div className="t-caption" style={{ color: "var(--fainter)" }}>at this pool&apos;s hashrate vs network difficulty</div>
              </div>
            </div>
            <div className="mt-4 grid grid-cols-2 gap-4">
              <div>
                <div className="t-caption" style={{ color: "var(--dim)" }}>Shares this round</div>
                <div className="t-title" style={{ color: "var(--fg)", fontWeight: 600 }}>
                  {sharesThisRound.toLocaleString()}
                </div>
              </div>
              <div>
                <div className="t-caption" style={{ color: "var(--dim)" }}>Pending rewards</div>
                <div className="t-title" style={{ color: "var(--accent)", fontWeight: 600 }}>
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
                  <div className="t-caption" style={{ color: "var(--dim)" }}>Network hashrate</div>
                  <div className="t-body" style={{ color: "var(--fg)", fontWeight: 600 }}>
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

      {/* Mesh leaderboard: every node in the pool ranked by hashrate, plus the
          mesh-wide best-share records per window. Aggregated by the backend
          across the whole mesh (no client fan-out). */}
      <SectionErrorBoundary section="Mesh Leaderboard">
        <Card>
          <CardHeader
            title="Mesh Leaderboard"
            subtitle="Every node in the Ghost pool, ranked by hashrate across the whole mesh"
          />
          <DataTable
            columns={meshNodeColumns}
            data={meshNodes}
            showPagination={false}
            emptyMessage="No mesh nodes reporting yet"
            loadingRows={4}
          />
          {meshRecords.length > 0 && (
            <div className="mt-5">
              <div className="t-caption" style={{ color: "var(--dim)", marginBottom: "8px" }}>
                Mesh best-share records
              </div>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                {meshRecords.map((r) => (
                  <div key={r.window}>
                    <div className="t-caption" style={{ color: "var(--dim)", textTransform: "capitalize" }}>
                      {r.window}
                    </div>
                    <div className="t-lead" style={{ color: "var(--fg)", fontWeight: 600 }}>
                      {formatDifficulty(r.difficulty)}
                    </div>
                    <div className="t-caption" style={{ color: "var(--fainter)" }}>
                      {r.leading_zero_bits} zero bits · {r.miner_id_redacted || "—"}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {meshLeaderboard?.limit_note && (
            <p className="t-caption" style={{ color: "var(--fainter)", marginTop: "12px" }}>
              {meshLeaderboard.limit_note}
            </p>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* This node's miners: the per-miner detail this node can see locally.
          A true mesh-wide per-miner leaderboard needs client fan-out to every
          node (see the mesh leaderboard note above). */}
      <SectionErrorBoundary section="This Node's Miners">
        <Card>
          <CardHeader
            title="This Node's Miners"
            subtitle="Miners connected to this node's stratum port, ranked by hashrate"
          />
          {minersRedacted ? (
            <div className="t-label" style={{ color: "var(--dim)" }}>
              Per-miner detail is not available on this node (the miner list is redacted for unauthenticated
              access). Aggregate:{" "}
              <span>
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

      {/* Chart source note: the mesh hashrate/miner charts use the node's
          server-side time-series ring when it has data, falling back to an
          in-browser session buffer on a freshly-started node. The this-node
          connected-miners chart is always a session buffer. */}
      <div
        className="rounded-lg p-3 text-sm"
        style={{ background: "var(--surface)", border: "1px solid var(--rule)", color: "var(--dim)" }}
      >
        {series.serverBacked ? (
          <>
            Mesh hashrate and miner charts are drawn from the node&apos;s server-side history
            (sampled every 30s, up to 24h) so they survive reloads. The this-node connected-miners
            chart is a live in-browser buffer ({series.sampleCount} sample
            {series.sampleCount === 1 ? "" : "s"} this session).
          </>
        ) : (
          <>
            Graphs are drawn from a live in-browser buffer of the polled pool values
            ({series.sampleCount} sample{series.sampleCount === 1 ? "" : "s"} this session) and reset on reload.
            The node&apos;s server-side history will back the mesh charts once it has accumulated a few samples.
          </>
        )}
      </div>
    </div>
  );
}
