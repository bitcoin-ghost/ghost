"use client";

import { StatusRow } from "@/components/ui/StatusRow";
import { FlowDiagram } from "@/components/ui/FlowDiagram";
import { Card, CardHeader } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { StatusDot } from "@/components/ui/StatusDot";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useShroudStatus } from "@/hooks/queries/useShroudQueries";

const TOOLTIPS = {
  enabled: "Whether Ghost Shroud relay delay is currently active on your node.",
  ghost_core: "Connection to Ghost Core (ghostd) is required for Shroud to intercept and delay relays.",
  max_delay: "The maximum random delay applied before relaying a transaction to peers.",
  avg_delay: "The average delay currently being applied across recent transaction relays.",
  timing_analysis: "Adversaries monitor when nodes relay transactions to infer which node originated them.",
  topology_mapping: "Adversaries map the network graph by observing relay timing patterns between nodes.",
};

export default function ShroudPage() {
  const { data: status, isLoading, error } = useShroudStatus({ refetchInterval: 10_000 });

  const showSkeleton = isLoading && !status;

  return (
    <div className="space-y-6">
      {/* 1. PageHeader */}
      <PageHeader
        eyebrow="shroud"
        title="Relay-timing privacy."
        subtitle="Transaction relay privacy"
        actions={
          status ? (
            <Badge variant={status.enabled ? "success" : "default"}>
              {status.enabled ? "Enabled" : "Disabled"}
            </Badge>
          ) : undefined
        }
      />

      {/* 2. StatCards row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Status"
          value={status ? (status.enabled ? "Active" : "Inactive") : "--"}
          tooltip={TOOLTIPS.enabled}
          loading={showSkeleton}
        />
        <StatCard
          label="Ghost Core"
          value={status ? (status.ghost_core_connected ? "Connected" : "Disconnected") : "--"}
          tooltip={TOOLTIPS.ghost_core}
          loading={showSkeleton}
        />
        <StatCard
          label="Max Delay"
          value={status?.max_delay_ms != null ? `${status.max_delay_ms} ms` : "--"}
          tooltip={TOOLTIPS.max_delay}
          loading={showSkeleton}
        />
        <StatCard
          label="Avg Delay"
          value={status?.avg_delay_ms != null ? `${status.avg_delay_ms} ms` : "--"}
          tooltip={TOOLTIPS.avg_delay}
          loading={showSkeleton}
        />
      </div>

      {/* 3. How It Works — collapsible */}
      <Card collapsible defaultCollapsed>
        <CardHeader
          title="How It Works"
          subtitle="Transaction relay flow with Shroud enabled"
        />
        <p className="text-[color:var(--dim)] text-sm leading-relaxed mb-4">
          Ghost Shroud adds random delays before relaying transactions to peers, breaking
          timing-based origin detection. Your transactions enter your mempool instantly for
          mining and validation — only the outbound relay to other nodes is delayed, making it
          impossible for observers to determine whether your node originated a transaction or
          simply forwarded it.
        </p>
        <FlowDiagram
          accentColor="blue"
          steps={[
            { label: "TX received", sublabel: "From wallet or peer" },
            { label: "Mempool", sublabel: "Instant" },
            { label: "Random delay", sublabel: "0-5s", accent: true },
            { label: "Relay to peers", sublabel: "Delayed broadcast" },
          ]}
        />
        <div className="mt-4 p-3 bg-[var(--surface)] rounded-lg border border-[var(--rule-strong)]">
          <p className="text-xs text-[color:var(--dim)] leading-relaxed">
            <span className="text-[color:var(--blue)] font-medium">Note:</span> The mempool addition is
            instant — your node can mine and validate the transaction immediately. Shroud only
            affects the <span className="text-[color:var(--blue)]">outbound relay</span> timing, ensuring
            adversaries cannot correlate relay order with transaction origin.
          </p>
        </div>
      </Card>

      {/* 4. Primary Content — Status rows */}
      <SectionErrorBoundary section="Shroud Status">
        {showSkeleton ? (
          <SkeletonCard />
        ) : error ? (
          <Card>
            <CardHeader title="Status" />
            <div className="p-4 bg-[var(--surface)] border border-[color:var(--red)] rounded-lg">
              <p className="text-[color:var(--red)] text-sm">
                Unable to fetch Ghost Shroud status. Ensure Ghost Core is running and the Shroud module is enabled.
              </p>
            </div>
          </Card>
        ) : status ? (
          <Card>
            <CardHeader
              title="Status"
              subtitle="Current Shroud relay configuration"
            />
            <div className="divide-y divide-[var(--rule)]">
              <StatusRow label="Shroud Enabled" tooltip={TOOLTIPS.enabled}>
                <StatusDot
                  status={status.enabled ? "online" : "offline"}
                  label={status.enabled ? "Active" : "Inactive"}
                  pulse={status.enabled}
                />
              </StatusRow>
              <StatusRow label="Ghost Core Connection" tooltip={TOOLTIPS.ghost_core}>
                <StatusDot
                  status={status.ghost_core_connected ? "online" : "offline"}
                  label={status.ghost_core_connected ? "Connected" : "Disconnected"}
                  pulse={status.ghost_core_connected}
                />
              </StatusRow>
              <StatusRow label="Max Delay" tooltip={TOOLTIPS.max_delay}>
                <span className="text-[color:var(--fg)] font-mono text-sm">
                  {(status.max_delay_ms ?? 0).toLocaleString()} ms
                </span>
              </StatusRow>
              <StatusRow label="Avg Delay" tooltip={TOOLTIPS.avg_delay}>
                <span className="text-[color:var(--blue)] font-mono text-sm">
                  {(status.avg_delay_ms ?? 0).toLocaleString()} ms
                </span>
              </StatusRow>
            </div>
          </Card>
        ) : null}
      </SectionErrorBoundary>

      {/* 5. Technical Details — collapsible */}
      <Card collapsible defaultCollapsed>
        <CardHeader
          title="Privacy Properties"
          subtitle="What Shroud does and does not protect against"
        />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Protects Against */}
          <div className="p-4 bg-[color-mix(in_srgb,var(--blue)_10%,transparent)] rounded-lg border border-[color-mix(in_srgb,var(--blue)_30%,transparent)]">
            <h4 className="text-sm font-medium text-[color:var(--blue)] mb-3 flex items-center gap-2">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Protects Against
            </h4>
            <ul className="space-y-3">
              <li className="flex items-start gap-2">
                <span className="text-[color:var(--green)] mt-0.5 flex-shrink-0">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                </span>
                <div>
                  <span className="text-[color:var(--fg)] text-sm font-medium">Timing Analysis</span>
                  <p className="text-[color:var(--fainter)] text-xs mt-0.5">
                    Random delays make it impossible to identify the originating node by relay timing.
                  </p>
                </div>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-[color:var(--green)] mt-0.5 flex-shrink-0">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                </span>
                <div>
                  <span className="text-[color:var(--fg)] text-sm font-medium">Topology Mapping</span>
                  <p className="text-[color:var(--fainter)] text-xs mt-0.5">
                    Obscures the network graph by preventing relay order inference between peers.
                  </p>
                </div>
              </li>
            </ul>
          </div>

          {/* Does Not Protect Against */}
          <div className="p-4 bg-[var(--surface)] rounded-lg border border-[var(--rule-strong)]">
            <h4 className="text-sm font-medium text-[color:var(--dim)] mb-3 flex items-center gap-2">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              Does Not Protect Against
            </h4>
            <ul className="space-y-3">
              <li className="flex items-start gap-2">
                <span className="text-[color:var(--fainter)] mt-0.5 flex-shrink-0">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </span>
                <div>
                  <span className="text-[color:var(--dim)] text-sm font-medium">Content Encryption</span>
                  <p className="text-[color:var(--fainter)] text-xs mt-0.5">
                    Transaction contents are not encrypted. Shroud only affects relay timing, not data.
                  </p>
                </div>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-[color:var(--fainter)] mt-0.5 flex-shrink-0">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </span>
                <div>
                  <span className="text-[color:var(--dim)] text-sm font-medium">Global Observer</span>
                  <p className="text-[color:var(--fainter)] text-xs mt-0.5">
                    An adversary monitoring all network links simultaneously may still correlate transactions.
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
