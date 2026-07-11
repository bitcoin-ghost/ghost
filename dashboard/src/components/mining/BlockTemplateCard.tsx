"use client";

import { useEffect, useState } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { useMiningTemplate } from "@/hooks/queries/useMiningQueries";

const MAX_WEIGHT = 4_000_000; // consensus block-weight limit

function btc(sat: number): string {
  const s = (sat / 1e8).toFixed(8).replace(/0+$/, "").replace(/\.$/, "");
  return `${s === "" ? "0" : s} BTC`;
}
function truncMid(s: string, n = 10): string {
  return s.length > 2 * n ? `${s.slice(0, n)}…${s.slice(-n)}` : s;
}

function Tile({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string;
  sub?: string;
  accent?: boolean;
}) {
  return (
    <div
      style={{
        background: "var(--surface)",
        border: "1px solid var(--rule)",
        borderRadius: 8,
        padding: "12px 14px",
      }}
    >
      <div className="t-caption" style={{ color: "var(--dim)", marginBottom: 4 }}>
        {label}
      </div>
      <div
        className="t-title"
        style={{ color: accent ? "var(--accent)" : "var(--fg)", fontWeight: 600, fontVariantNumeric: "tabular-nums" }}
      >
        {value}
      </div>
      {sub && (
        <div className="t-caption" style={{ color: "var(--fainter)", marginTop: 2 }}>
          {sub}
        </div>
      )}
    </div>
  );
}

/**
 * Live view of the block template this node is currently building — reads
 * GET /api/v1/mining/template (a cheap summary of the pool's current WorkState).
 * Height, tx count, fees, subsidy, coinbase reward, block-weight fill, and a
 * live "building for Xs" age. Polls every 5s; the age ticks every second.
 */
export function BlockTemplateCard() {
  const { data, isLoading } = useMiningTemplate();
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const id = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(id);
  }, []);

  const t = data?.available ? data.template : null;

  return (
    <Card>
      <CardHeader
        title="Block template"
        subtitle="The block this node is currently building. Refreshed for fresh mempool fees between blocks; rebuilt instantly on a new tip (empty template first)."
      />
      {!t ? (
        <div className="t-label" style={{ color: "var(--dim)" }}>
          {isLoading ? "Loading template…" : "No template yet — the pool has not built a block template."}
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-baseline gap-3">
              <span
                style={{ color: "var(--fg)", fontWeight: 700, fontSize: "1.75rem", fontVariantNumeric: "tabular-nums" }}
              >
                #{t.height.toLocaleString()}
              </span>
              <span className="t-caption" style={{ color: "var(--dim)" }}>
                next block
              </span>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="default">building {Math.max(0, now - t.ntime)}s</Badge>
              <Badge variant="default">refresh {t.refresh_secs}s</Badge>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Tile label="Transactions" value={t.tx_count.toLocaleString()} sub="incl. coinbase" />
            <Tile label="Fees" value={btc(t.total_fees_sat)} sub={`${t.total_fees_sat.toLocaleString()} sat`} />
            <Tile label="Subsidy" value={btc(t.subsidy_sat)} />
            <Tile label="Coinbase reward" value={btc(t.coinbase_value_sat)} sub="subsidy + fees" accent />
          </div>

          <div>
            <div
              className="flex items-center justify-between t-caption"
              style={{ color: "var(--dim)", marginBottom: 4 }}
            >
              <span>Block weight</span>
              <span style={{ fontVariantNumeric: "tabular-nums" }}>
                {t.total_weight.toLocaleString()} / {MAX_WEIGHT.toLocaleString()} WU ·{" "}
                {((t.total_weight / MAX_WEIGHT) * 100).toFixed(1)}%
              </span>
            </div>
            <div
              style={{
                height: 8,
                borderRadius: 4,
                background: "var(--surface)",
                border: "1px solid var(--rule)",
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  height: "100%",
                  width: `${Math.min(100, (t.total_weight / MAX_WEIGHT) * 100)}%`,
                  background: "var(--accent)",
                }}
              />
            </div>
          </div>

          <div
            className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-1 t-caption"
            style={{ color: "var(--dim)" }}
          >
            <div className="flex justify-between gap-2">
              <span>Previous block</span>
              <span className="font-mono truncate" style={{ color: "var(--fainter)" }}>
                {truncMid(t.prev_hash)}
              </span>
            </div>
            <div className="flex justify-between gap-2">
              <span>Job ID</span>
              <span className="font-mono" style={{ color: "var(--fainter)" }}>
                {t.job_id}
              </span>
            </div>
            <div className="flex justify-between gap-2">
              <span>Version</span>
              <span className="font-mono" style={{ color: "var(--fainter)" }}>
                0x{(t.version >>> 0).toString(16)}
              </span>
            </div>
            <div className="flex justify-between gap-2">
              <span>nBits</span>
              <span className="font-mono" style={{ color: "var(--fainter)" }}>
                {t.nbits}
              </span>
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}
