"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { DataTable } from "@/components/ui/DataTable";
import { SkeletonTable } from "@/components/ui/Skeleton";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { NetworkPayoutHistoryCard, GhostPayPayoutHistoryCard } from "@/components/PayoutHistoryCard";
import { useNetworkPayoutHistory, useGhostPayPayoutHistory, useNodeBalances } from "@/hooks/queries";
import { PageLoader } from "@/components/ui/PageLoader";
import type { NodeBalanceEntry } from "@/lib/api/rewards";
import type { PayoutHistoryTimeFilter } from "@/types/api";
import type { ColumnDef } from "@tanstack/react-table";

const REWARD_SOURCES = [
  {
    name: "Node Reward Pool",
    desc: "Earned via the 5-4-3-2-1 share system. Each block reward allocates a portion to the node reward pool, distributed proportionally by verified shares.",
    color: "bg-green-500",
  },
  {
    name: "Block TX Fees",
    desc: "When your pool finds a block, transaction fees from the block are distributed to the winning node's miners and node operators.",
    color: "bg-orange-500",
  },
  {
    name: "Ghost Pay L2 Fees",
    desc: "Fees collected from L2 payment channel operations (instant payments, channel opens/closes). Earned by nodes running Ghost Pay.",
    color: "bg-purple-500",
  },
  {
    name: "Wraith Mixing Fees",
    desc: "Fees from CoinJoin mixing sessions coordinated through the Wraith protocol. Earned by nodes facilitating privacy mixing rounds.",
    color: "bg-red-500",
  },
];

function formatSats(satoshis: number): string {
  if (satoshis >= 100_000_000) {
    return `${(satoshis / 100_000_000).toFixed(4)} BTC`;
  }
  return `${satoshis.toLocaleString()} sats`;
}

function formatTimestamp(timestamp: number): string {
  if (!timestamp) return "—";
  const date = new Date(timestamp * 1000);
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

const nodeBalanceColumns: ColumnDef<NodeBalanceEntry>[] = [
  {
    id: "rank",
    header: "#",
    cell: ({ row }) => (
      <span className="text-[color:var(--fainter)] text-sm">{row.index + 1}</span>
    ),
  },
  {
    accessorKey: "node_id",
    header: "Node",
    cell: ({ row }) => (
      <div className="flex items-center gap-2">
        <span className="font-mono text-sm text-[color:var(--dim)]">
          {row.original.node_id.slice(0, 12)}...
        </span>
        {row.original.is_self && (
          <Badge variant="success">You</Badge>
        )}
      </div>
    ),
  },
  {
    accessorKey: "balance_sats",
    header: "Balance",
    cell: ({ row }) => (
      <span className="font-mono text-[color:var(--green)]">
        {formatSats(row.original.balance_sats)}
      </span>
    ),
  },
  {
    accessorKey: "total_credits_sats",
    header: "Lifetime Earned",
    cell: ({ row }) => (
      <span className="font-mono text-[color:var(--dim)]">
        {formatSats(row.original.total_credits_sats)}
      </span>
    ),
  },
  {
    accessorKey: "total_withdrawals_sats",
    header: "Withdrawn",
    cell: ({ row }) => (
      <span className="font-mono text-[color:var(--dim)]">
        {formatSats(row.original.total_withdrawals_sats)}
      </span>
    ),
  },
  {
    accessorKey: "last_credited_round",
    header: "Last Credit",
    cell: ({ row }) => (
      <span className="text-[color:var(--dim)] text-sm">
        Round #{row.original.last_credited_round}
      </span>
    ),
  },
  {
    accessorKey: "updated_at",
    header: "Updated",
    cell: ({ row }) => (
      <span className="text-[color:var(--fainter)] text-sm">
        {formatTimestamp(row.original.updated_at)}
      </span>
    ),
  },
];

export default function PayoutsPage() {
  const [networkTimeFilter, setNetworkTimeFilter] = useState<PayoutHistoryTimeFilter>("7d");
  const [gpTimeFilter, setGpTimeFilter] = useState<PayoutHistoryTimeFilter>("7d");

  const { data: payoutHistory, isLoading: payoutLoading } = useNetworkPayoutHistory(networkTimeFilter);
  const { data: gpPayoutHistory, isLoading: gpPayoutLoading } = useGhostPayPayoutHistory(gpTimeFilter);
  const { data: balancesData, isLoading: balancesLoading } = useNodeBalances();

  const summary = payoutHistory?.summary ?? {
    total_treasury_satoshis: 0,
    total_node_rewards_satoshis: 0,
    total_miner_rewards_satoshis: 0,
    blocks_in_period: 0,
  };

  const nodeBalances = balancesData?.history ?? [];
  // Sort by balance descending (highest balance first)
  const sortedBalances = [...nodeBalances].sort((a, b) => b.balance_sats - a.balance_sats);

  if (payoutLoading && !payoutHistory) {
    return (
      <div className="space-y-6">
        <PageHeader eyebrow="payouts" title="Block reward distributions." subtitle="Transparent record of all block reward distributions" />
        <PageLoader message="Loading payout data..." />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Network Payouts"
        subtitle="Transparent record of all block reward distributions"
      />

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Treasury"
          value={formatSats(summary.total_treasury_satoshis)}
          sublabel="in period"
        />
        <StatCard
          label="Node Rewards"
          value={formatSats(summary.total_node_rewards_satoshis)}
          sublabel="in period"
        />
        <StatCard
          label="Miner Rewards"
          value={formatSats(summary.total_miner_rewards_satoshis)}
          sublabel="in period"
        />
        <StatCard
          label="Blocks"
          value={summary.blocks_in_period}
          sublabel="in period"
        />
      </div>

      {/* Network Payout History */}
      <SectionErrorBoundary section="Network Payout History">
        <NetworkPayoutHistoryCard
          entries={payoutHistory?.entries ?? []}
          summary={summary}
          isLoading={payoutLoading}
          timeFilter={networkTimeFilter}
          onTimeFilterChange={setNetworkTimeFilter}
        />
      </SectionErrorBoundary>

      {/* GhostPay Fee History */}
      <SectionErrorBoundary section="GhostPay Fee History">
        <GhostPayPayoutHistoryCard
          ghostpayFees={gpPayoutHistory?.ghostpay_fees ?? []}
          wraithFees={gpPayoutHistory?.wraith_fees ?? []}
          summary={gpPayoutHistory?.summary ?? { total_ghostpay_fees_satoshis: 0, total_wraith_fees_satoshis: 0, ghostpay_sessions_count: 0, wraith_sessions_count: 0 }}
          isLoading={gpPayoutLoading}
          timeFilter={gpTimeFilter}
          onTimeFilterChange={setGpTimeFilter}
        />
      </SectionErrorBoundary>

      {/* Node Balance Accounts */}
      <SectionErrorBoundary section="Node Balance Accounts">
        <Card>
          <CardHeader
            title="Node Balance Accounts"
            subtitle={`${balancesData?.total ?? sortedBalances.length} nodes with reward balances`}
          />
          {balancesLoading ? (
            <SkeletonTable rows={5} cols={6} />
          ) : (
            <DataTable
              columns={nodeBalanceColumns}
              data={sortedBalances}
              emptyMessage="No node balances yet"
              emptyDescription="Balances accumulate as blocks are found and rewards are distributed"
              searchColumn="node_id"
              searchPlaceholder="Search by node ID..."
              showPagination={sortedBalances.length > 20}
            />
          )}
        </Card>
      </SectionErrorBoundary>

      {/* Where Rewards Come From */}
      <SectionErrorBoundary section="Reward Sources">
        <Card>
          <CardHeader title="Where Rewards Come From" subtitle="Nodes earn from multiple revenue streams" />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {REWARD_SOURCES.map((source) => (
              <div key={source.name} className="flex items-start gap-3 p-3 bg-[var(--surface)] rounded-lg">
                <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${source.color}`} />
                <div>
                  <div className="text-sm font-medium text-[color:var(--fg)]">{source.name}</div>
                  <div className="text-xs text-[color:var(--fainter)] mt-0.5">{source.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}
