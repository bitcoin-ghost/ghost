"use client";

import { useEffect, useState } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { useGhostPayStatus, useWraithStats, useSettlementStatus } from "@/hooks/queries";
import { getRewardsHistory } from "@/lib/api";

export function QuickStatsCard() {
  const { data: ghostPay, isLoading: gpLoading, error: gpError } = useGhostPayStatus();
  const { data: wraithStats, isLoading: wraithLoading } = useWraithStats();
  const { data: settlement, isLoading: settlementLoading } = useSettlementStatus();
  const [totalEarned, setTotalEarned] = useState<number | null>(null);

  useEffect(() => {
    getRewardsHistory()
      .then((data) => setTotalEarned(data.total_earned_btc ?? null))
      .catch(() => setTotalEarned(null));
  }, []);

  const isLoading = gpLoading || wraithLoading || settlementLoading;

  if (isLoading && !ghostPay) {
    return (
      <Card>
        <CardHeader title="Quick Stats" />
        <div className="animate-pulse space-y-3">
          <div className="h-4 bg-[var(--surface)] rounded w-3/4"></div>
          <div className="h-4 bg-[var(--surface)] rounded w-1/2"></div>
          <div className="h-4 bg-[var(--surface)] rounded w-2/3"></div>
        </div>
      </Card>
    );
  }

  // Format BTC with appropriate precision
  const formatBtc = (btc: number): string => {
    if (btc >= 1) return `${btc.toFixed(4)} BTC`;
    if (btc >= 0.001) return `${btc.toFixed(6)} BTC`;
    const sats = Math.floor(btc * 100_000_000);
    return `${sats.toLocaleString()} sats`;
  };

  return (
    <Card>
      <CardHeader title="Quick Stats" />

      <div className="space-y-4">
        {/* Total Earnings */}
        <div className="p-4 bg-[var(--accent-weak)] border border-[color:color-mix(in_srgb,var(--accent)_40%,transparent)] rounded-lg">
          <div className="text-xs text-[color:var(--accent)] uppercase tracking-wide mb-1">
            Total Earnings
          </div>
          <div className="text-2xl font-bold text-[color:var(--accent)]">
            {totalEarned !== null ? formatBtc(totalEarned) : "--"}
          </div>
          <div className="text-xs text-[color:var(--fainter)] mt-1">
            Node rewards received
          </div>
        </div>

        <div className="p-3 bg-[var(--surface)]/50 rounded-lg">
          <div className="text-xs text-[color:var(--fainter)] uppercase tracking-wide mb-1">
            Ghost Pay L2
          </div>
          <div className="flex justify-between items-center">
            <span className="text-[color:var(--dim)]">Block Height</span>
            <span className="font-mono text-[color:var(--fg)]">
              {ghostPay?.block_height?.toLocaleString() ?? 0}
            </span>
          </div>
          <div className="flex justify-between items-center mt-1">
            <span className="text-[color:var(--dim)]">Epoch</span>
            <span className="font-mono text-[color:var(--fg)]">
              {ghostPay?.epoch ?? 0}
            </span>
          </div>
          <div className="flex justify-between items-center mt-1">
            <span className="text-[color:var(--dim)]">Peers</span>
            <span className="font-mono text-[color:var(--fg)]">
              {ghostPay?.peer_count ?? 0}
            </span>
          </div>
        </div>

        <div className="p-3 bg-[var(--surface)]/50 rounded-lg">
          <div className="text-xs text-[color:var(--fainter)] uppercase tracking-wide mb-1">
            Wraith Sessions
          </div>
          <div className="flex justify-between items-center">
            <span className="text-[color:var(--dim)]">Active</span>
            <span className="font-mono text-[color:var(--fg)]">
              {wraithStats?.active_sessions ?? 0}
            </span>
          </div>
          <div className="flex justify-between items-center mt-1">
            <span className="text-[color:var(--dim)]">Completed</span>
            <span className="font-mono text-[color:var(--fg)]">
              {wraithStats?.sessions_completed ?? 0}
            </span>
          </div>
        </div>

        <div className="p-3 bg-[var(--surface)]/50 rounded-lg">
          <div className="text-xs text-[color:var(--fainter)] uppercase tracking-wide mb-1">
            Settlements
          </div>
          <div className="flex justify-between items-center">
            <span className="text-[color:var(--dim)]">Pending</span>
            <span className="font-mono text-[color:var(--fg)]">
              {settlement?.pending_count ?? 0}
            </span>
          </div>
          <div className="flex justify-between items-center mt-1">
            <span className="text-[color:var(--dim)]">Confirmed (24h)</span>
            <span className="font-mono text-[color:var(--fg)]">
              {settlement?.batches_24h ?? 0}
            </span>
          </div>
        </div>

        {gpError && (
          <p className="text-xs text-[color:var(--fainter)]">
            Ghost Pay not connected
          </p>
        )}
      </div>
    </Card>
  );
}
