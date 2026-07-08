"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { Tooltip } from "@/components/ui/Tooltip";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { NetworkPayoutHistoryCard } from "@/components/PayoutHistoryCard";
import { useTreasury, useNetworkPayoutHistory } from "@/hooks/queries";
import type { PayoutHistoryTimeFilter } from "@/types/api";

const TOOLTIPS = {
  accumulated: "Total BTC accumulated in the treasury from block rewards. Used to fund protocol development during bootstrap.",
  target: "The treasury accumulates up to 21 BTC, then begins a 5-year decay to zero.",
  progress: "How close the treasury is to reaching the 21 BTC target.",
  phase: "Bootstrap = accumulating. Decay = treasury share decreasing yearly. Ossified = treasury complete, 100% to node pool.",
};

const DECAY_SCHEDULE = [
  { year: 0, treasury: 0.5, nodePool: 0.5, label: "21 BTC" },
  { year: 1, treasury: 0.4, nodePool: 0.6, label: "Yr 1" },
  { year: 2, treasury: 0.3, nodePool: 0.7, label: "Yr 2" },
  { year: 3, treasury: 0.2, nodePool: 0.8, label: "Yr 3" },
  { year: 4, treasury: 0.1, nodePool: 0.9, label: "Yr 4" },
  { year: 5, treasury: 0.0, nodePool: 1.0, label: "Ossified" },
];

function formatBtc(btc: number): string {
  if (btc >= 1) return `${btc.toFixed(4)} BTC`;
  const sats = Math.floor(btc * 100_000_000);
  return `${sats.toLocaleString()} sats`;
}

function TreasuryDetails() {
  const { data: treasury, isLoading } = useTreasury();

  if (isLoading) return <SkeletonCard className="col-span-full" />;
  if (!treasury) return null;

  const phase = treasury.phase ?? "bootstrap";
  const phaseLabel = { bootstrap: "Bootstrap", decay: "Decay", ossified: "Ossified" }[phase] ?? "Unknown";
  const phaseColor = { bootstrap: "text-[color:var(--accent)]", decay: "text-[color:var(--accent)]", ossified: "text-[color:var(--green)]" }[phase] ?? "text-[color:var(--dim)]";

  return (
    <>
      {/* Hero progress */}
      <Card className="col-span-full">
        <CardHeader title="Treasury Progress" />
        <div className="space-y-4">
          <div className="flex justify-between text-sm mb-1">
            <span className="text-[color:var(--dim)]">Accumulated</span>
            <span className="text-[color:var(--fg)]">
              {formatBtc(treasury.accumulated_btc ?? 0)} / {(treasury.target_btc ?? 21).toFixed(1)} BTC
              <span className="text-[color:var(--fainter)] ml-2">({(treasury.progress_percent ?? 0).toFixed(1)}%)</span>
            </span>
          </div>
          <ProgressBar value={treasury.progress_percent ?? 0} color="orange" size="lg" />
        </div>
      </Card>

      {/* Phase details */}
      <Card>
        <CardHeader title="Phase Details" />
        <div className="space-y-3">
          <div className="flex justify-between">
            <span className="text-[color:var(--dim)]">Current Phase</span>
            <span className={`font-semibold ${phaseColor}`}>{phaseLabel}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-[color:var(--dim)]">Treasury Share</span>
            <span className="font-mono text-[color:var(--fg)]">{(treasury.treasury_percent ?? 50).toFixed(0)}% of block rewards</span>
          </div>
          <div className="flex justify-between">
            <span className="text-[color:var(--dim)]">Node Pool Share</span>
            <span className="font-mono text-[color:var(--fg)]">{(treasury.node_pool_percent ?? 50).toFixed(0)}% of block rewards</span>
          </div>
          {treasury.decay_started && treasury.decay_year != null && (
            <div className="flex justify-between">
              <span className="text-[color:var(--dim)]">Decay Year</span>
              <span className="font-mono text-[color:var(--fg)]">Year {treasury.decay_year}</span>
            </div>
          )}
          {treasury.blocks_until_full != null && treasury.blocks_until_full > 0 && (
            <div className="flex justify-between">
              <span className="text-[color:var(--dim)]">Blocks Until Full</span>
              <span className="font-mono text-[color:var(--fg)]">{treasury.blocks_until_full.toLocaleString()}</span>
            </div>
          )}
        </div>
      </Card>

      {/* Decay schedule timeline */}
      <Card>
        <CardHeader title="Decay Schedule" subtitle="5-year transition to full decentralization" />
        <div className="flex items-center justify-between mt-2">
          {DECAY_SCHEDULE.map((step) => {
            const decayYear = treasury.decay_year ?? 0;
            const isCurrentYear = treasury.decay_started && decayYear === step.year;
            const isPast = treasury.decay_started && treasury.decay_year != null && step.year < decayYear;
            const isOssified = treasury.phase === "ossified";

            let dotColor = "bg-[var(--surface)]";
            if (isOssified && step.year === 5) dotColor = "bg-green-500";
            else if (isCurrentYear) dotColor = "bg-orange-500 animate-pulse";
            else if (isPast) dotColor = "bg-orange-400";
            else if (!treasury.decay_started && step.year === 0) dotColor = "bg-yellow-500";

            return (
              <Tooltip key={step.year} content={`Treasury: ${(step.treasury * 100).toFixed(0)}% / Node Pool: ${(step.nodePool * 100).toFixed(0)}%`}>
                <div className="flex flex-col items-center flex-1">
                  <div className={`w-3.5 h-3.5 rounded-full ${dotColor}`} />
                  <div className="text-xs text-[color:var(--fainter)] mt-1.5">{step.label}</div>
                  <div className="t-caption text-[color:var(--fainter)] mt-0.5">
                    {(step.treasury * 100).toFixed(0)}% / {(step.nodePool * 100).toFixed(0)}%
                  </div>
                </div>
              </Tooltip>
            );
          })}
        </div>
      </Card>
    </>
  );
}

export default function TreasuryPage() {
  const [payoutTimeFilter, setPayoutTimeFilter] = useState<PayoutHistoryTimeFilter>("7d");
  const { data: treasury } = useTreasury();
  const { data: payoutHistory, isLoading: payoutLoading } = useNetworkPayoutHistory(payoutTimeFilter);

  const phase = treasury?.phase ?? "bootstrap";
  const phaseLabel = { bootstrap: "Bootstrap", decay: "Decay", ossified: "Ossified" }[phase] ?? "Unknown";

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="treasury"
        title="Pool reward distribution."
        subtitle="Decentralization timeline and block reward distribution"
        actions={
          <Badge variant={phase === "ossified" ? "success" : phase === "decay" ? "warning" : "info"}>
            {phaseLabel}
          </Badge>
        }
      />

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Accumulated"
          value={treasury ? formatBtc(treasury.accumulated_btc ?? 0) : "--"}
          tooltip={TOOLTIPS.accumulated}
        />
        <StatCard
          label="Target"
          value={`${(treasury?.target_btc ?? 21).toFixed(1)} BTC`}
          tooltip={TOOLTIPS.target}
        />
        <StatCard
          label="Progress"
          value={`${(treasury?.progress_percent ?? 0).toFixed(1)}%`}
          tooltip={TOOLTIPS.progress}
        />
        <StatCard
          label="Phase"
          value={phaseLabel}
          tooltip={TOOLTIPS.phase}
        />
      </div>

      {/* Treasury details */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SectionErrorBoundary section="Treasury">
          <TreasuryDetails />
        </SectionErrorBoundary>
      </div>

      {/* Network Payout History */}
      <SectionErrorBoundary section="Payout History">
        <NetworkPayoutHistoryCard
          entries={payoutHistory?.entries ?? []}
          summary={payoutHistory?.summary ?? { total_treasury_satoshis: 0, total_node_rewards_satoshis: 0, total_miner_rewards_satoshis: 0, blocks_in_period: 0 }}
          isLoading={payoutLoading}
          timeFilter={payoutTimeFilter}
          onTimeFilterChange={setPayoutTimeFilter}
        />
      </SectionErrorBoundary>
    </div>
  );
}
