"use client";

import { FlowDiagram } from "@/components/ui/FlowDiagram";
import { Card, CardHeader } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { StatusDot } from "@/components/ui/StatusDot";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { Toggle } from "@/components/ui/Toggle";
import { useToast } from "@/components/ui/Toast";
import { useGhostPayStatus, useWraithStats, useSetWraith } from "@/hooks/queries";

const DENOMINATION_TIERS = [
  { name: "Tiny", amount: "10,000 sats", btc: "0.0001 BTC", desc: "Micro-transactions, tipping" },
  { name: "Small", amount: "100,000 sats", btc: "0.001 BTC", desc: "Everyday purchases" },
  { name: "Medium", amount: "1,000,000 sats", btc: "0.01 BTC", desc: "Standard mixing" },
  { name: "Large", amount: "10,000,000 sats", btc: "0.1 BTC", desc: "Significant transactions" },
  { name: "Whale", amount: "100,000,000 sats", btc: "1.0 BTC", desc: "High-value mixing" },
];

export default function WraithPage() {
  const { data: ghostPayStatus, isLoading: statusLoading } = useGhostPayStatus();
  const { data: wraithStats, isLoading: wraithLoading } = useWraithStats();
  const setWraith = useSetWraith();
  const { success, error } = useToast();

  const isLoading = statusLoading || wraithLoading;
  const wraithEnabled = ghostPayStatus?.wraith_enabled ?? false;

  const handleWraithToggle = async (enabled: boolean) => {
    try {
      await setWraith.mutateAsync(enabled);
      success("Saved", `Wraith mixing ${enabled ? "enabled" : "disabled"} — restart ghost-pool to apply`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. PageHeader */}
      <PageHeader
        eyebrow="wraith"
        title="Privacy mixing sessions."
        subtitle="CoinJoin mixing for transaction privacy"
        actions={
          ghostPayStatus ? (
            <Badge variant={wraithEnabled ? "success" : "default"}>
              {wraithEnabled ? "Enabled" : "Disabled"}
            </Badge>
          ) : undefined
        }
      />

      {/* 2. StatCards row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Status"
          value={wraithEnabled ? "Active" : "Inactive"}
          loading={isLoading}
        />
        <StatCard
          label="Active Sessions"
          value={wraithStats?.active_sessions ?? 0}
          loading={isLoading}
        />
        <StatCard
          label="Completed"
          value={wraithStats?.sessions_completed ?? 0}
          loading={isLoading}
        />
        <StatCard
          label="Participants"
          value={wraithStats?.total_participants ?? 0}
          loading={isLoading}
        />
      </div>

      {/* 3. How It Works — collapsible, NOT wrapped in SectionErrorBoundary */}
      <Card collapsible defaultCollapsed>
        <CardHeader
          title="How It Works"
          subtitle="Two-phase CoinJoin mixing flow"
        />
        <div className="space-y-4">
          <p className="text-gray-300 text-sm leading-relaxed">
            Wraith is a two-phase CoinJoin mixing protocol that breaks the link between your UTXOs and
            their history. A single UTXO is split into equal-denomination outputs, mixed with other
            participants, and merged into a clean UTXO whose transaction history cannot be traced back
            to its origin.
          </p>
          <FlowDiagram
            accentColor="red"
            steps={[
              { label: "Your UTXO", sublabel: "1 input" },
              { label: "Split (1 \u2192 10)", sublabel: "Phase 1", accent: true },
              { label: "Mix Pool", sublabel: "Other participants", accent: true },
              { label: "Merge (10 \u2192 1)", sublabel: "Phase 2", accent: true },
              { label: "Clean UTXO", sublabel: "Unlinkable output" },
            ]}
          />
          <div className="p-3 bg-gray-800/50 rounded-lg border border-gray-700">
            <p className="text-xs text-gray-400 leading-relaxed">
              <span className="text-red-400 font-medium">Phase 1 (Split):</span> Your UTXO is split into 10 equal-denomination
              outputs in a single transaction. Each output matches the selected denomination tier exactly.
              <br className="my-1" />
              <span className="text-red-400 font-medium">Phase 2 (Merge):</span> Your 10 outputs are combined with outputs from
              other participants in a CoinJoin transaction. The merged output is a single clean UTXO with no traceable link to
              the original input.
            </p>
          </div>
        </div>
      </Card>

      {/* 4. Primary Content — Denomination table + Status card */}
      <SectionErrorBoundary section="Denomination Tiers">
        <Card>
          <CardHeader
            title="Denomination Tiers"
            subtitle="Available mixing amounts — all participants in a session use the same denomination"
          />
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left py-2 px-3 text-gray-400 font-medium">Tier</th>
                  <th className="text-right py-2 px-3 text-gray-400 font-medium">Amount</th>
                  <th className="text-right py-2 px-3 text-gray-400 font-medium">BTC</th>
                  <th className="text-left py-2 px-3 text-gray-400 font-medium">Use Case</th>
                </tr>
              </thead>
              <tbody>
                {DENOMINATION_TIERS.map((tier) => (
                  <tr key={tier.name} className="border-b border-gray-800/50 last:border-b-0">
                    <td className="py-2.5 px-3 text-gray-100 font-medium">{tier.name}</td>
                    <td className="py-2.5 px-3 text-right font-mono text-red-400">{tier.amount}</td>
                    <td className="py-2.5 px-3 text-right font-mono text-gray-400">{tier.btc}</td>
                    <td className="py-2.5 px-3 text-gray-500">{tier.desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </SectionErrorBoundary>

      <SectionErrorBoundary section="Wraith Status">
        {isLoading ? <SkeletonCard /> : (
          <Card>
            <CardHeader
              title="Status"
              action={
                <StatusDot
                  status={wraithEnabled ? "online" : "offline"}
                  label={wraithEnabled ? "Wraith Active" : "Wraith Inactive"}
                  pulse={wraithEnabled}
                />
              }
            />
            <div className="space-y-3">
              <div className="flex justify-between items-start py-2 border-b border-gray-800 gap-4">
                <div>
                  <span className="text-gray-400">Wraith Enabled</span>
                  <p className="text-xs text-gray-500 mt-0.5 max-w-md">
                    Mixing lets any L2 participant initiate a CoinJoin session through this node. Off means this
                    node won&apos;t participate. A ghost-pool restart applies the change.
                  </p>
                </div>
                <Toggle
                  enabled={wraithEnabled}
                  onChange={handleWraithToggle}
                  label="Toggle Wraith mixing"
                  disabled={setWraith.isPending}
                />
              </div>
              <div className="flex justify-between items-center py-2 border-b border-gray-800">
                <span className="text-gray-400">Active Sessions</span>
                <span className="font-mono text-gray-100">{wraithStats?.active_sessions ?? 0}</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-gray-800">
                <span className="text-gray-400">Total Sessions Hosted</span>
                <span className="font-mono text-gray-100">{wraithStats?.total_sessions?.toLocaleString() ?? 0}</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-gray-800">
                <span className="text-gray-400">Sessions Completed</span>
                <span className="font-mono text-gray-100">{wraithStats?.sessions_completed?.toLocaleString() ?? 0}</span>
              </div>
              <div className="flex justify-between items-center py-2">
                <span className="text-gray-400">Total Participants Served</span>
                <span className="font-mono text-gray-100">{wraithStats?.total_participants?.toLocaleString() ?? 0}</span>
              </div>
            </div>
          </Card>
        )}
      </SectionErrorBoundary>

      {/* 5. Technical Details — collapsible, NOT wrapped in SectionErrorBoundary */}
      <Card collapsible defaultCollapsed>
        <CardHeader
          title="Privacy Properties"
          subtitle="What Wraith does and does not protect against"
        />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Protects Against */}
          <div className="p-4 bg-red-900/10 rounded-lg border border-red-600/30">
            <h4 className="text-sm font-medium text-red-400 mb-3 flex items-center gap-2">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Protects Against
            </h4>
            <ul className="space-y-3">
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5 flex-shrink-0">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                </span>
                <div>
                  <span className="text-gray-200 text-sm font-medium">Chain Analysis</span>
                  <p className="text-gray-500 text-xs mt-0.5">
                    Equal-denomination outputs in CoinJoin transactions break the deterministic links that chain analysis relies on.
                  </p>
                </div>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5 flex-shrink-0">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                </span>
                <div>
                  <span className="text-gray-200 text-sm font-medium">UTXO Linking</span>
                  <p className="text-gray-500 text-xs mt-0.5">
                    After mixing, your clean UTXO cannot be linked back to the original input through on-chain analysis.
                  </p>
                </div>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-green-400 mt-0.5 flex-shrink-0">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                </span>
                <div>
                  <span className="text-gray-200 text-sm font-medium">Amount Correlation</span>
                  <p className="text-gray-500 text-xs mt-0.5">
                    Fixed denomination tiers prevent amount-based correlation between inputs and outputs.
                  </p>
                </div>
              </li>
            </ul>
          </div>

          {/* Does Not Protect Against */}
          <div className="p-4 bg-gray-800/50 rounded-lg border border-gray-700">
            <h4 className="text-sm font-medium text-gray-400 mb-3 flex items-center gap-2">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              Does Not Protect Against
            </h4>
            <ul className="space-y-3">
              <li className="flex items-start gap-2">
                <span className="text-gray-500 mt-0.5 flex-shrink-0">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </span>
                <div>
                  <span className="text-gray-300 text-sm font-medium">Timing Correlation</span>
                  <p className="text-gray-500 text-xs mt-0.5">
                    If not using Ghost Shroud, an adversary may correlate your mixing activity with relay timing.
                    Enable Shroud for full privacy.
                  </p>
                </div>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-gray-500 mt-0.5 flex-shrink-0">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </span>
                <div>
                  <span className="text-gray-300 text-sm font-medium">Endpoint Surveillance</span>
                  <p className="text-gray-500 text-xs mt-0.5">
                    If an adversary controls both the sender and receiver endpoints, mixing cannot prevent correlation.
                  </p>
                </div>
              </li>
            </ul>
          </div>
        </div>
      </Card>
    </div>
  );
}
