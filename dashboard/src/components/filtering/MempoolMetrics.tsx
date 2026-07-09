"use client";

import { useQuery } from "@tanstack/react-query";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { StatCard } from "@/components/ui/StatCard";
import { TimeSeriesChart } from "@/components/ui/MiniChart";
import { useMempoolSeries } from "@/hooks/useMempoolSeries";
import { fetchApi } from "@/lib/api/client";

/**
 * Mempool tx-count tiles + over-time graph.
 *
 * Two headline tiles (current mempool tx count, current block-template tx count)
 * plus a "mempool over time" line chart. Self-contained: it runs its own
 * lightweight `/buds/mempool` poll (getmempoolinfo.size) under the shared
 * `["buds-mempool"]` query key so {@link useMempoolSeries} can accumulate a live
 * session buffer from it, and reads the node's server-side `/pool/series` ring
 * when that carries the mempool fields.
 *
 * Data comes from {@link useMempoolSeries}: the node's server-side `/pool/series`
 * ring (30s samples, ~24h, survives reloads) when it carries the mempool fields,
 * otherwise a live in-browser session buffer keyed on this component's own
 * `/buds/mempool` poll. The "Mempool" tile prefers the live `total` already
 * fetched here and only falls back to the latest series sample; the "This block"
 * tile is server-ring only (the RPC view has no block-template count) and shows
 * "—" until the ring has it.
 */

interface BudsMempoolSummary {
  total?: number; // getmempoolinfo.size
  message?: string; // present when RPC unavailable
}

async function fetchBudsMempool(): Promise<BudsMempoolSummary> {
  return fetchApi<BudsMempoolSummary>("/api/v1/buds/mempool");
}

function formatCount(n: number | undefined): string {
  return n === undefined || n === null ? "—" : n.toLocaleString();
}

export function MempoolMetrics() {
  // Own the buds/mempool poll (shared query key so useMempoolSeries can sample
  // it for the live session buffer). The full mempool page uses the same key.
  const { data: mempool } = useQuery<BudsMempoolSummary>({
    queryKey: ["buds-mempool"],
    queryFn: fetchBudsMempool,
    refetchInterval: 15_000,
  });

  const series = useMempoolSeries();

  // Live getmempoolinfo.size when we have it, else the newest series sample.
  const mempoolNow = mempool?.total ?? series.latestMempoolTxs ?? undefined;
  const blockNow = series.latestBlockTxs ?? undefined;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Mempool"
          value={formatCount(mempoolNow)}
          sublabel="transactions right now"
          tooltip="getmempoolinfo.size — transactions your node currently holds"
        />
        <StatCard
          label="This block"
          value={formatCount(blockNow)}
          sublabel="in the block template"
          tooltip="transactions in the block template your node is currently building"
        />
      </div>

      <Card>
        <div className="mb-3 flex items-start justify-between gap-2">
          <div>
            <h3 className="t-title" style={{ color: "var(--fg)" }}>
              Mempool over time
            </h3>
            <p className="t-caption" style={{ color: "var(--dim)", marginTop: "2px" }}>
              Transactions in your node&apos;s mempool, sampled over time
            </p>
          </div>
          <Badge variant="default">{series.serverBacked ? "history" : "live (session)"}</Badge>
        </div>
        <TimeSeriesChart
          data={series.mempoolTxs}
          minZero
          ariaLabel="Mempool transaction count over time"
          formatValue={(v) => Math.round(v).toLocaleString()}
        />
        <p className="t-caption" style={{ color: "var(--fainter)", marginTop: "12px" }}>
          {series.serverBacked
            ? "Drawn from this node's server-side history (sampled every 30s, up to 24h) so it survives reloads."
            : `Collecting live in-browser samples (${series.sampleCount} this session) — the node's server-side history will back this chart once it has accumulated a few. Resets on reload.`}
        </p>
      </Card>
    </div>
  );
}
