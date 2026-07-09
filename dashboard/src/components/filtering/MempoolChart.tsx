"use client";

import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { TimeSeriesChart } from "@/components/ui/MiniChart";
import { useMempoolSeries } from "@/hooks/useMempoolSeries";

/**
 * "Mempool over time" line chart.
 *
 * Draws this node's mempool transaction count over time. Data comes from
 * {@link useMempoolSeries}: the node's server-side `/pool/series` ring (30s
 * samples, ~24h, survives reloads) when it carries the mempool fields,
 * otherwise a live in-browser session buffer accumulated from the shared
 * `["buds-mempool"]` poll (owned by the filtering overview page). The
 * "history/live" badge reflects which source is backing the line.
 */
export function MempoolChart() {
  const series = useMempoolSeries();

  return (
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
  );
}
