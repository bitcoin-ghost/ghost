"use client";

import { useState } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { DataTable } from "@/components/ui/DataTable";
import { SkeletonTable } from "@/components/ui/Skeleton";
import type { PayoutHistoryTimeFilter, NetworkPayoutEntry, GhostPayFeeEntry, WraithFeeEntry, NodePayoutEntry } from "@/types/api";
import type { ColumnDef } from "@tanstack/react-table";

// Shared utility functions
function formatSats(satoshis: number): string {
  if (satoshis >= 100_000_000) {
    return `${(satoshis / 100_000_000).toFixed(4)} BTC`;
  }
  return `${satoshis.toLocaleString()} sats`;
}

function formatTimestamp(timestamp: number): string {
  const date = new Date(timestamp * 1000);
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function makeBlockLink(height: number, network: string = "signet"): string {
  // Use mempool.space for block explorer links
  const baseUrl = network === "mainnet" ? "https://mempool.space" : `https://mempool.space/${network}`;
  return `${baseUrl}/block/${height}`;
}

// Time filter toggle component
function TimeFilterToggle({
  value,
  onChange,
}: {
  value: PayoutHistoryTimeFilter;
  onChange: (v: PayoutHistoryTimeFilter) => void;
}) {
  return (
    <div className="flex gap-1">
      <button
        onClick={() => onChange("24h")}
        className={`px-2 py-1 text-xs rounded transition-colors ${
          value === "24h"
            ? "bg-[var(--accent)] text-white"
            : "bg-[var(--surface)] text-[color:var(--dim)] hover:bg-[var(--rule-strong)]"
        }`}
      >
        24h
      </button>
      <button
        onClick={() => onChange("7d")}
        className={`px-2 py-1 text-xs rounded transition-colors ${
          value === "7d"
            ? "bg-[var(--accent)] text-white"
            : "bg-[var(--surface)] text-[color:var(--dim)] hover:bg-[var(--rule-strong)]"
        }`}
      >
        7d
      </button>
    </div>
  );
}

// Entry type badge colors
function getEntryTypeBadge(entryType: string) {
  const colors: Record<string, "info" | "success" | "warning" | "error" | "default"> = {
    treasury_fee: "warning",
    node_reward_pool: "info",
    node_node_reward: "success",
    node_ghostpay_fee: "success",
    node_wraith_fee: "success",
    miner_reward: "default",
  };

  const labels: Record<string, string> = {
    treasury_fee: "Treasury",
    node_reward_pool: "Node Pool",
    node_node_reward: "Node Reward",
    node_ghostpay_fee: "GhostPay Fee",
    node_wraith_fee: "Wraith Fee",
    miner_reward: "Miner Pool",
  };

  return (
    <Badge variant={colors[entryType] ?? "default"}>
      {labels[entryType] ?? entryType}
    </Badge>
  );
}

function getPayoutTypeBadge(payoutType: string) {
  const colors: Record<string, "info" | "success" | "warning" | "error" | "default"> = {
    node_reward: "success",
    ghostpay_fee: "info",
    wraith_fee: "warning",
  };

  const labels: Record<string, string> = {
    node_reward: "Node Reward",
    ghostpay_fee: "GhostPay Fee",
    wraith_fee: "Wraith Fee",
  };

  return (
    <Badge variant={colors[payoutType] ?? "default"}>
      {labels[payoutType] ?? payoutType}
    </Badge>
  );
}

// Network Payout History Card (for Network page)
export function NetworkPayoutHistoryCard({
  entries,
  summary,
  isLoading,
  timeFilter,
  onTimeFilterChange,
}: {
  entries: NetworkPayoutEntry[];
  summary: { total_treasury_satoshis: number; total_node_rewards_satoshis: number; total_miner_rewards_satoshis: number; blocks_in_period: number };
  isLoading: boolean;
  timeFilter: PayoutHistoryTimeFilter;
  onTimeFilterChange: (filter: PayoutHistoryTimeFilter) => void;
}) {
  const columns: ColumnDef<NetworkPayoutEntry>[] = [
    {
      accessorKey: "timestamp",
      header: "Time",
      cell: ({ row }) => (
        <span className="text-[color:var(--dim)] text-sm">
          {formatTimestamp(row.original.timestamp ?? 0)}
        </span>
      ),
    },
    {
      accessorKey: "block_height",
      header: "Block",
      cell: ({ row }) => (
        <a
          href={makeBlockLink(row.original.block_height ?? 0)}
          target="_blank"
          rel="noopener noreferrer"
          className="font-mono text-[color:var(--accent)] hover:text-[color:var(--accent)] hover:underline"
        >
          #{row.original.block_height ?? 0}
        </a>
      ),
    },
    {
      accessorKey: "entry_type",
      header: "Type",
      cell: ({ row }) => getEntryTypeBadge(row.original.entry_type ?? "unknown"),
    },
    {
      accessorKey: "amount_satoshis",
      header: "Amount",
      cell: ({ row }) => (
        <span className="font-mono text-[color:var(--fg)]">
          {formatSats(row.original.amount_satoshis ?? 0)}
        </span>
      ),
    },
    {
      accessorKey: "recipient_node_id",
      header: "Recipient",
      cell: ({ row }) => (
        <span className="font-mono text-[color:var(--dim)] text-sm">
          {row.original.recipient_node_id
            ? row.original.recipient_node_id.slice(0, 8)
            : row.original.recipient_address
              ? `${row.original.recipient_address.slice(0, 8)}...`
              : "—"}
        </span>
      ),
    },
  ];

  return (
    <Card>
      <CardHeader
        title="Network Payout History"
        subtitle={`${summary.blocks_in_period} blocks in period`}
        action={<TimeFilterToggle value={timeFilter} onChange={onTimeFilterChange} />}
      />

      {/* Summary row */}
      <div className="grid grid-cols-3 gap-4 mb-4 p-3 bg-[var(--surface)] rounded">
        <div className="text-center">
          <div className="text-[color:var(--accent)] font-mono">{formatSats(summary.total_treasury_satoshis)}</div>
          <div className="text-xs text-[color:var(--fainter)]">Treasury</div>
        </div>
        <div className="text-center">
          <div className="text-[color:var(--green)] font-mono">{formatSats(summary.total_node_rewards_satoshis)}</div>
          <div className="text-xs text-[color:var(--fainter)]">Node Rewards</div>
        </div>
        <div className="text-center">
          <div className="text-[color:var(--dim)] font-mono">{formatSats(summary.total_miner_rewards_satoshis)}</div>
          <div className="text-xs text-[color:var(--fainter)]">Miner Rewards</div>
        </div>
      </div>

      {isLoading ? (
        <SkeletonTable rows={5} cols={5} />
      ) : (
        <DataTable
          columns={columns}
          data={entries}
          emptyMessage="No payouts in this period"
          showPagination={entries.length > 10}
        />
      )}
    </Card>
  );
}

// GhostPay Payout History Card (for Ghost-Pay page)
export function GhostPayPayoutHistoryCard({
  ghostpayFees,
  wraithFees,
  summary,
  isLoading,
  timeFilter,
  onTimeFilterChange,
}: {
  ghostpayFees: GhostPayFeeEntry[];
  wraithFees: WraithFeeEntry[];
  summary: { total_ghostpay_fees_satoshis: number; total_wraith_fees_satoshis: number; ghostpay_sessions_count: number; wraith_sessions_count: number };
  isLoading: boolean;
  timeFilter: PayoutHistoryTimeFilter;
  onTimeFilterChange: (filter: PayoutHistoryTimeFilter) => void;
}) {
  const [activeTab, setActiveTab] = useState<"ghostpay" | "wraith">("ghostpay");

  const ghostpayColumns: ColumnDef<GhostPayFeeEntry>[] = [
    {
      accessorKey: "timestamp",
      header: "Time",
      cell: ({ row }) => (
        <span className="text-[color:var(--dim)] text-sm">
          {formatTimestamp(row.original.timestamp ?? 0)}
        </span>
      ),
    },
    {
      accessorKey: "block_height",
      header: "Block",
      cell: ({ row }) => (
        <a
          href={makeBlockLink(row.original.block_height ?? 0)}
          target="_blank"
          rel="noopener noreferrer"
          className="font-mono text-[color:var(--accent)] hover:text-[color:var(--accent)] hover:underline"
        >
          #{row.original.block_height ?? 0}
        </a>
      ),
    },
    {
      accessorKey: "batch_id",
      header: "Batch ID",
      cell: ({ row }) => (
        <span className="font-mono text-[color:var(--dim)] text-sm">
          {(row.original.batch_id ?? "").slice(0, 12)}...
        </span>
      ),
    },
    {
      accessorKey: "fee_satoshis",
      header: "Fee",
      cell: ({ row }) => (
        <span className="font-mono text-[color:var(--green)]">
          {formatSats(row.original.fee_satoshis ?? 0)}
        </span>
      ),
    },
    {
      accessorKey: "recipient_node_id",
      header: "Node",
      cell: ({ row }) => (
        <span className="font-mono text-[color:var(--dim)] text-sm">
          {row.original.recipient_node_id?.slice(0, 8) ?? "—"}
        </span>
      ),
    },
  ];

  const wraithColumns: ColumnDef<WraithFeeEntry>[] = [
    {
      accessorKey: "timestamp",
      header: "Time",
      cell: ({ row }) => (
        <span className="text-[color:var(--dim)] text-sm">
          {formatTimestamp(row.original.timestamp ?? 0)}
        </span>
      ),
    },
    {
      accessorKey: "block_height",
      header: "Block",
      cell: ({ row }) => (
        <a
          href={makeBlockLink(row.original.block_height ?? 0)}
          target="_blank"
          rel="noopener noreferrer"
          className="font-mono text-[color:var(--accent)] hover:text-[color:var(--accent)] hover:underline"
        >
          #{row.original.block_height ?? 0}
        </a>
      ),
    },
    {
      accessorKey: "session_id",
      header: "Session ID",
      cell: ({ row }) => (
        <span className="font-mono text-[color:var(--dim)] text-sm">
          {(row.original.session_id ?? "").slice(0, 12)}...
        </span>
      ),
    },
    {
      accessorKey: "fee_satoshis",
      header: "Fee",
      cell: ({ row }) => (
        <span className="font-mono text-[color:var(--accent)]">
          {formatSats(row.original.fee_satoshis ?? 0)}
        </span>
      ),
    },
    {
      accessorKey: "recipient_node_id",
      header: "Node",
      cell: ({ row }) => (
        <span className="font-mono text-[color:var(--dim)] text-sm">
          {row.original.recipient_node_id?.slice(0, 8) ?? "—"}
        </span>
      ),
    },
  ];

  return (
    <Card>
      <CardHeader
        title="Fee Payout History"
        subtitle={`${summary.ghostpay_sessions_count + summary.wraith_sessions_count} sessions in period`}
        action={<TimeFilterToggle value={timeFilter} onChange={onTimeFilterChange} />}
      />

      {/* Summary row */}
      <div className="grid grid-cols-2 gap-4 mb-4 p-3 bg-[var(--surface)] rounded">
        <div className="text-center">
          <div className="text-[color:var(--green)] font-mono">{formatSats(summary.total_ghostpay_fees_satoshis)}</div>
          <div className="text-xs text-[color:var(--fainter)]">GhostPay Fees ({summary.ghostpay_sessions_count})</div>
        </div>
        <div className="text-center">
          <div className="text-[color:var(--accent)] font-mono">{formatSats(summary.total_wraith_fees_satoshis)}</div>
          <div className="text-xs text-[color:var(--fainter)]">Wraith Fees ({summary.wraith_sessions_count})</div>
        </div>
      </div>

      {/* Tab toggle */}
      <div className="flex gap-2 mb-4">
        <button
          onClick={() => setActiveTab("ghostpay")}
          className={`px-3 py-1.5 text-sm rounded transition-colors ${
            activeTab === "ghostpay"
              ? "bg-[var(--accent)] text-white"
              : "bg-[var(--surface)] text-[color:var(--dim)] hover:bg-[var(--rule-strong)]"
          }`}
        >
          L2→L1 Reconciliation ({ghostpayFees.length})
        </button>
        <button
          onClick={() => setActiveTab("wraith")}
          className={`px-3 py-1.5 text-sm rounded transition-colors ${
            activeTab === "wraith"
              ? "bg-[var(--accent)] text-white"
              : "bg-[var(--surface)] text-[color:var(--dim)] hover:bg-[var(--rule-strong)]"
          }`}
        >
          Wraith Sessions ({wraithFees.length})
        </button>
      </div>

      {isLoading ? (
        <SkeletonTable rows={5} cols={5} />
      ) : activeTab === "ghostpay" ? (
        <DataTable
          columns={ghostpayColumns}
          data={ghostpayFees}
          emptyMessage="No GhostPay fees in this period"
          showPagination={ghostpayFees.length > 10}
        />
      ) : (
        <DataTable
          columns={wraithColumns}
          data={wraithFees}
          emptyMessage="No Wraith fees in this period"
          showPagination={wraithFees.length > 10}
        />
      )}
    </Card>
  );
}

// Node Payout History Card (for Rewards page - this node only)
export function NodePayoutHistoryCard({
  entries,
  isLoading,
  timeFilter,
  onTimeFilterChange,
  payoutTypeFilter,
  onPayoutTypeFilterChange,
}: {
  entries: NodePayoutEntry[];
  isLoading: boolean;
  timeFilter: PayoutHistoryTimeFilter;
  onTimeFilterChange: (filter: PayoutHistoryTimeFilter) => void;
  payoutTypeFilter?: string;
  onPayoutTypeFilterChange?: (filter?: string) => void;
}) {
  const totalSats = entries.reduce((sum, e) => sum + (e.amount_satoshis ?? 0), 0);

  const columns: ColumnDef<NodePayoutEntry>[] = [
    {
      accessorKey: "timestamp",
      header: "Time",
      cell: ({ row }) => (
        <span className="text-[color:var(--dim)] text-sm">
          {formatTimestamp(row.original.timestamp ?? 0)}
        </span>
      ),
    },
    {
      accessorKey: "block_height",
      header: "Block",
      cell: ({ row }) => (
        <a
          href={makeBlockLink(row.original.block_height ?? 0)}
          target="_blank"
          rel="noopener noreferrer"
          className="font-mono text-[color:var(--accent)] hover:text-[color:var(--accent)] hover:underline"
        >
          #{row.original.block_height ?? 0}
        </a>
      ),
    },
    {
      accessorKey: "payout_type",
      header: "Type",
      cell: ({ row }) => getPayoutTypeBadge(row.original.payout_type ?? "unknown"),
    },
    {
      accessorKey: "amount_satoshis",
      header: "Amount",
      cell: ({ row }) => (
        <span className="font-mono text-[color:var(--green)]">
          {formatSats(row.original.amount_satoshis ?? 0)}
        </span>
      ),
    },
    {
      accessorKey: "share_percentage",
      header: "Share %",
      cell: ({ row }) => (
        <span className="font-mono text-[color:var(--dim)]">
          {row.original.share_percentage
            ? `${(row.original.share_percentage * 100).toFixed(2)}%`
            : "—"}
        </span>
      ),
    },
  ];

  return (
    <Card>
      <CardHeader
        title="Node Payout History"
        subtitle={`${entries.length} payouts (${formatSats(totalSats)} total)`}
        action={<TimeFilterToggle value={timeFilter} onChange={onTimeFilterChange} />}
      />

      {/* Type filter buttons */}
      {onPayoutTypeFilterChange && (
        <div className="flex gap-2 mb-4">
          <button
            onClick={() => onPayoutTypeFilterChange(undefined)}
            className={`px-2 py-1 text-xs rounded transition-colors ${
              !payoutTypeFilter
                ? "bg-[var(--accent)] text-white"
                : "bg-[var(--surface)] text-[color:var(--dim)] hover:bg-[var(--rule-strong)]"
            }`}
          >
            All
          </button>
          <button
            onClick={() => onPayoutTypeFilterChange("node_reward")}
            className={`px-2 py-1 text-xs rounded transition-colors ${
              payoutTypeFilter === "node_reward"
                ? "bg-[var(--accent)] text-white"
                : "bg-[var(--surface)] text-[color:var(--dim)] hover:bg-[var(--rule-strong)]"
            }`}
          >
            Node Rewards
          </button>
          <button
            onClick={() => onPayoutTypeFilterChange("ghostpay_fee")}
            className={`px-2 py-1 text-xs rounded transition-colors ${
              payoutTypeFilter === "ghostpay_fee"
                ? "bg-[var(--accent)] text-white"
                : "bg-[var(--surface)] text-[color:var(--dim)] hover:bg-[var(--rule-strong)]"
            }`}
          >
            GhostPay Fees
          </button>
          <button
            onClick={() => onPayoutTypeFilterChange("wraith_fee")}
            className={`px-2 py-1 text-xs rounded transition-colors ${
              payoutTypeFilter === "wraith_fee"
                ? "bg-[var(--accent)] text-white"
                : "bg-[var(--surface)] text-[color:var(--dim)] hover:bg-[var(--rule-strong)]"
            }`}
          >
            Wraith Fees
          </button>
        </div>
      )}

      {isLoading ? (
        <SkeletonTable rows={5} cols={5} />
      ) : (
        <DataTable
          columns={columns}
          data={entries}
          emptyMessage="No payouts received in this period"
          showPagination={entries.length > 10}
        />
      )}
    </Card>
  );
}
