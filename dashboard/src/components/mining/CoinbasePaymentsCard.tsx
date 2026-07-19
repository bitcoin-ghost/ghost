"use client";

import { useState } from "react";
import { ChevronRight } from "lucide-react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { useMiningCoinbase } from "@/hooks/queries/useMiningQueries";

function btc(sat: number): string {
  const s = (sat / 1e8).toFixed(8).replace(/0+$/, "").replace(/\.$/, "");
  return `${s === "" ? "0" : s} BTC`;
}
function truncMid(s: string, n = 10): string {
  return s.length > 2 * n ? `${s.slice(0, n)}…${s.slice(-n)}` : s;
}

// A proportional horizontal share bar — mirrors the block-weight bar in
// BlockTemplateCard: a track div with an accent-filled inner div.
function ShareBar({ fraction }: { fraction: number }) {
  return (
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
          width: `${Math.min(100, Math.max(0, fraction * 100))}%`,
          background: "var(--accent)",
        }}
      />
    </div>
  );
}

// One category row: label, BTC value + sat sub-label, and a proportional bar.
// Optionally expandable (chevron toggles the detail body rendered below).
function CategoryRow({
  label,
  amount,
  total,
  expandable,
  expanded,
  onToggle,
  children,
}: {
  label: string;
  amount: number;
  total: number;
  expandable?: boolean;
  expanded?: boolean;
  onToggle?: () => void;
  children?: React.ReactNode;
}) {
  const header = (
    <div className="flex items-center justify-between gap-3 mb-1">
      <div className="flex items-center gap-1.5 min-w-0">
        {expandable && (
          <ChevronRight
            size={14}
            strokeWidth={1.75}
            style={{
              color: "var(--dim)",
              transition: "transform 0.15s",
              transform: expanded ? "rotate(90deg)" : "none",
              flexShrink: 0,
            }}
          />
        )}
        <span className="t-label" style={{ color: "var(--fg)" }}>
          {label}
        </span>
      </div>
      <div className="text-right">
        <div
          className="t-label"
          style={{ color: "var(--fg)", fontWeight: 600, fontVariantNumeric: "tabular-nums" }}
        >
          {btc(amount)}
        </div>
        <div className="t-caption" style={{ color: "var(--fainter)", fontVariantNumeric: "tabular-nums" }}>
          {amount.toLocaleString()} sat
        </div>
      </div>
    </div>
  );

  return (
    <div>
      {expandable ? (
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={expanded}
          className="w-full text-left"
          style={{ background: "transparent", border: "none", padding: 0, cursor: "pointer" }}
        >
          {header}
        </button>
      ) : (
        header
      )}
      <ShareBar fraction={total > 0 ? amount / total : 0} />
      {expandable && expanded && children && <div className="mt-2">{children}</div>}
    </div>
  );
}

// One detail row in an expanded category: a mono identifier + its BTC amount.
function DetailRow({ id, amount }: { id: string; amount: number }) {
  return (
    <div
      className="flex items-center justify-between gap-3 py-1 t-caption"
      style={{ color: "var(--dim)" }}
    >
      <span className="font-mono truncate" style={{ color: "var(--fainter)" }}>
        {id}
      </span>
      <span style={{ color: "var(--dim)", fontVariantNumeric: "tabular-nums", flexShrink: 0 }}>
        {btc(amount)}
      </span>
    </div>
  );
}

/**
 * How the coinbase for the block currently being built splits across its
 * recipients — reads GET /api/v1/mining/coinbase. Four category rows (miners,
 * node rewards, treasury, finder's tx-fee share), each with a proportional
 * share bar; the miners and node-reward rows expand to their per-recipient
 * breakdown when the operator is authed. Polls every 5s.
 */
export function CoinbasePaymentsCard() {
  const { data, isLoading } = useMiningCoinbase();
  const [minersOpen, setMinersOpen] = useState(false);
  const [nodesOpen, setNodesOpen] = useState(false);

  return (
    <Card>
      <CardHeader
        title="Coinbase payments"
        subtitle="How the coinbase for the block above splits across recipients. Updates as the payout is agreed each round."
      />
      {isLoading ? (
        <div className="t-label" style={{ color: "var(--dim)" }}>
          Loading coinbase…
        </div>
      ) : !data?.available ? (
        <div className="t-label" style={{ color: "var(--dim)" }}>
          No coinbase payout agreed yet — the block currently pays subsidy only.
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-baseline gap-3">
              <span
                style={{ color: "var(--fg)", fontWeight: 700, fontSize: "1.75rem", fontVariantNumeric: "tabular-nums" }}
              >
                #{(data.height ?? 0).toLocaleString()}
              </span>
              <span className="t-caption" style={{ color: "var(--dim)" }}>
                coinbase split
              </span>
            </div>
            {data.round_id != null && <Badge variant="default">round {data.round_id}</Badge>}
          </div>

          <div className="space-y-3">
            <CategoryRow
              label="Miners"
              amount={data.miner_pool_sat ?? 0}
              total={data.total_coinbase_sat ?? 0}
              expandable
              expanded={minersOpen}
              onToggle={() => setMinersOpen((v) => !v)}
            >
              {data.addresses_redacted ? (
                <div className="space-y-1">
                  {data.miners && data.miners.length > 0 ? (
                    data.miners.map((m, i) => (
                      <DetailRow key={i} id={`miner ${i + 1}`} amount={m.amount_sat} />
                    ))
                  ) : (
                    <div className="t-caption" style={{ color: "var(--dim)" }}>
                      {(data.miner_count ?? 0).toLocaleString()} miners · {btc(data.miner_pool_sat ?? 0)}
                    </div>
                  )}
                  <div className="t-caption" style={{ color: "var(--fainter)" }}>
                    Addresses hidden — operator authentication required
                  </div>
                </div>
              ) : data.miners && data.miners.length > 0 ? (
                <div className="space-y-0.5">
                  {data.miners.map((m, i) => (
                    <DetailRow key={i} id={truncMid(m.address)} amount={m.amount_sat} />
                  ))}
                </div>
              ) : (
                <div className="t-caption" style={{ color: "var(--dim)" }}>
                  No per-miner breakdown available.
                </div>
              )}
            </CategoryRow>

            <CategoryRow
              label="Node rewards"
              amount={data.node_reward_pool_sat ?? 0}
              total={data.total_coinbase_sat ?? 0}
              expandable
              expanded={nodesOpen}
              onToggle={() => setNodesOpen((v) => !v)}
            >
              {data.nodes && data.nodes.length > 0 ? (
                <div className="space-y-0.5">
                  {data.nodes.map((n, i) => (
                    <DetailRow key={i} id={truncMid(n.node_id)} amount={n.amount_sat} />
                  ))}
                </div>
              ) : (
                <div className="t-caption" style={{ color: "var(--dim)" }}>
                  {(data.node_count ?? 0).toLocaleString()} nodes · {btc(data.node_reward_pool_sat ?? 0)}
                </div>
              )}
            </CategoryRow>

            <CategoryRow
              label="Treasury"
              amount={data.treasury_sat ?? 0}
              total={data.total_coinbase_sat ?? 0}
            />

            <CategoryRow
              label="TX fees → node"
              amount={data.tx_fees_to_finder_sat ?? 0}
              total={data.total_coinbase_sat ?? 0}
            />
          </div>

          <div
            className="flex items-center justify-between t-caption border-t pt-3"
            style={{ color: "var(--dim)", borderColor: "var(--rule)" }}
          >
            <span>Total coinbase</span>
            <span style={{ color: "var(--fg)", fontWeight: 600, fontVariantNumeric: "tabular-nums" }}>
              {btc(data.total_coinbase_sat ?? 0)}
            </span>
          </div>
        </div>
      )}
    </Card>
  );
}
