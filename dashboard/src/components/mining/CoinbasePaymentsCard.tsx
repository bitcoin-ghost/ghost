"use client";

import { Card, CardHeader } from "@/components/ui/Card";
import { useMiningCoinbase } from "@/hooks/queries/useMiningQueries";

function btc(sat: number): string {
  const s = (sat / 1e8).toFixed(8).replace(/0+$/, "").replace(/\.$/, "");
  return `${s === "" ? "0" : s} BTC`;
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

// One category row: label, BTC value + sat sub-label, a proportional bar and a note.
function CategoryRow({
  label,
  amount,
  total,
  note,
}: {
  label: string;
  amount: number | undefined;
  total: number;
  note?: string;
}) {
  const known = typeof amount === "number";
  return (
    <div>
      <div className="flex items-center justify-between gap-3 mb-1">
        <span className="t-label" style={{ color: "var(--fg)" }}>
          {label}
        </span>
        <div className="text-right">
          <div
            className="t-label"
            style={{ color: known ? "var(--fg)" : "var(--fainter)", fontWeight: 600, fontVariantNumeric: "tabular-nums" }}
          >
            {known ? btc(amount) : "unknown"}
          </div>
          {known && (
            <div className="t-caption" style={{ color: "var(--fainter)", fontVariantNumeric: "tabular-nums" }}>
              {amount.toLocaleString()} sat
            </div>
          )}
        </div>
      </div>
      <ShareBar fraction={known && total > 0 ? amount / total : 0} />
      {note && (
        <div className="t-caption mt-1" style={{ color: "var(--fainter)" }}>
          {note}
        </div>
      )}
    </div>
  );
}

/**
 * How the coinbase of the block currently being built splits: the treasury's base share
 * (S/200), the miners' share (Rm), and every transaction fee to the finder. Reads
 * GET /api/v1/mining/coinbase. Which balances Rm pays is decided per job by the finder's slot
 * class (see the Miners page); what it cannot pay goes to the treasury on top of its base.
 */
export function CoinbasePaymentsCard() {
  const { data, isLoading, error } = useMiningCoinbase();
  const total = data?.total_coinbase_sat ?? 0;

  return (
    <Card>
      <CardHeader
        title="Coinbase split"
        subtitle="How the coinbase of the block above splits between the treasury, miners' balances and the finder"
      />
      {isLoading ? (
        <div className="t-label" style={{ color: "var(--dim)" }}>
          Loading coinbase…
        </div>
      ) : error ? (
        <div className="t-label" style={{ color: "var(--red)" }}>
          Coinbase unavailable: {error instanceof Error ? error.message : String(error)}
        </div>
      ) : !data?.available ? (
        <div className="t-label" style={{ color: "var(--dim)" }}>
          No block template yet, so there is no coinbase to show.
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex items-baseline gap-3">
            <span
              style={{ color: "var(--fg)", fontWeight: 700, fontSize: "1.75rem", fontVariantNumeric: "tabular-nums" }}
            >
              #{typeof data.height === "number" ? data.height.toLocaleString() : "unknown"}
            </span>
            <span className="t-caption" style={{ color: "var(--dim)" }}>
              coinbase split
            </span>
          </div>

          <div className="space-y-3">
            <CategoryRow
              label="Miners' balances (Rm)"
              amount={data.miner_pool_sat}
              total={total}
              note="Paid to owed balances, up to the finder's slot class; what it cannot pay goes to the treasury."
            />
            <CategoryRow label="Treasury base (S/200)" amount={data.treasury_base_sat} total={total} />
            <CategoryRow label="TX fees to the finder" amount={data.tx_fees_to_finder_sat} total={total} />
          </div>

          <div
            className="flex items-center justify-between t-caption border-t pt-3"
            style={{ color: "var(--dim)", borderColor: "var(--rule)" }}
          >
            <span>Total coinbase</span>
            <span style={{ color: "var(--fg)", fontWeight: 600, fontVariantNumeric: "tabular-nums" }}>
              {typeof data.total_coinbase_sat === "number" ? btc(data.total_coinbase_sat) : "unknown"}
            </span>
          </div>
        </div>
      )}
    </Card>
  );
}
