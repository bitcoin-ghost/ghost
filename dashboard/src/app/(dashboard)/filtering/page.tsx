"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { fetchApi } from "@/lib/api/client";
import { useConfig, useFullConfig } from "@/hooks/queries/useConfigQueries";
import { useReaperStatus } from "@/hooks/queries";
import { useAdvancedFilteringGate } from "@/hooks/useAdvancedFilteringGate";
import type { FullNodeConfig } from "@/types/api";

type TierKey = "T0" | "T1" | "T2" | "T3";

interface BudsMempool {
  by_tier?: { T0: number; T1: number; T2: number; T3: number };
  sample_size?: number;
  message?: string;
}

// Plain-English preset name for the stored [policy].profile, normalising the
// legacy `bitcoin_pure` alias to Strict. Returns "Custom" for the custom policy.
function modeLabel(profile?: string): string {
  switch (profile) {
    case "bitcoin_pure":
    case "strict":
      return "Strict";
    case "permissive":
      return "Standard";
    case "full_open":
      return "Everything";
    case "custom":
      return "Custom";
    default:
      return profile ? profile : "—";
  }
}

// Which BUDS tiers this node's policy drops (does not mine). Presets map to a
// fixed set; a custom policy drops any tier whose allow flag is false.
function droppedTiers(
  profile: string | undefined,
  custom?: FullPolicyCustom,
): TierKey[] {
  switch (profile) {
    case "bitcoin_pure":
    case "strict":
      return ["T2", "T3"];
    case "permissive":
      return ["T3"];
    case "full_open":
      return [];
    case "custom": {
      if (!custom) return [];
      const dropped: TierKey[] = [];
      if (!custom.allow_t0) dropped.push("T0");
      if (!custom.allow_t1) dropped.push("T1");
      if (!custom.allow_t2) dropped.push("T2");
      if (!custom.allow_t3) dropped.push("T3");
      return dropped;
    }
    default:
      return [];
  }
}

type FullPolicyCustom = NonNullable<FullNodeConfig["policy"]>["custom"];

function bytes(n?: number): string {
  if (n === undefined || n === null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export default function FilteringOverviewPage() {
  const { data: config } = useConfig();
  const { data: fullConfig } = useFullConfig();
  const { data: reaperStats } = useReaperStatus();
  const { data: mempool } = useQuery({
    queryKey: ["buds-mempool"],
    queryFn: () => fetchApi<BudsMempool>("/api/v1/buds/mempool"),
    refetchInterval: 15_000,
  });

  const [advancedEnabled] = useAdvancedFilteringGate();

  const reaperOn = config?.reaper ?? false;
  const profile = fullConfig?.policy?.profile;
  const dropped = droppedTiers(profile, fullConfig?.policy?.custom);

  // % filtered — the share of the CURRENT mempool sample that sits in the tiers
  // this node's policy drops. Single-node indicator, not a cross-node comparison.
  const byTier = mempool?.by_tier ?? { T0: 0, T1: 0, T2: 0, T3: 0 };
  const sampled = mempool?.sample_size ?? (byTier.T0 + byTier.T1 + byTier.T2 + byTier.T3);
  const droppedCount = dropped.reduce((s, t) => s + (byTier[t] ?? 0), 0);
  const hasSample = !mempool?.message && sampled > 0;
  const pctFiltered = hasSample ? (droppedCount / sampled) * 100 : null;
  const droppedLabel = dropped.length ? dropped.join(" + ") : "none";

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="filtering"
        title="Filtering."
        subtitle="What your node lets in, and what it mines — at a glance. Set it up in Basic, fine-tune in Advanced."
        subtitleFullWidth
      />

      {/* Cumulative counters */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Total txs filtered"
          value={reaperStats ? reaperStats.txs_reaped.toLocaleString() : "—"}
          sublabel="cumulative, this run"
          tooltip="Transactions the reaper has dropped from the blocks this node builds, since the last ghost-pool restart."
        />
        <StatCard
          label="Dead weight cut"
          value={reaperStats ? bytes(reaperStats.dead_bytes_total) : "—"}
          sublabel="reclaimed for real txs"
          tooltip="Total bytes of dead code stripped from block templates, returned to fee-paying transactions."
        />
        <StatCard
          label="% of mempool filtered"
          value={pctFiltered === null ? "—" : `${pctFiltered.toFixed(0)}%`}
          sublabel={dropped.length ? `${droppedLabel} dropped` : "nothing dropped"}
          tooltip="Share of your current mempool sample that sits in the tiers your policy drops. A single-node indicator, not a standard-vs-reaper comparison."
        />
        <StatCard
          label="Reaper"
          value={reaperOn ? "On" : "Off"}
          sublabel={reaperOn ? "stripping junk" : "not filtering"}
          tooltip="Whether the reaper is enabled. When on, it removes dead-code transactions from your mempool and the blocks you build."
        />
      </div>

      {/* Status readout — which settings are active */}
      <SectionErrorBoundary section="Active settings">
        <Card>
          <CardHeader
            title="What's active"
            subtitle="The filtering your node is running right now."
          />
          <div className="space-y-3">
            <StatusRow
              label="Mode"
              value={modeLabel(profile)}
              desc={
                dropped.length
                  ? `Drops ${droppedLabel} — mines everything else.`
                  : profile === "full_open"
                    ? "Mines every class, including heavy data (T3)."
                    : "The tier policy this node mines under."
              }
            />
            <StatusRow
              label="Reaper"
              value={reaperOn ? "On" : "Off"}
              desc={
                reaperOn
                  ? "Stripping dead-code transactions from your mempool and blocks."
                  : "Not removing dead-code transactions."
              }
            />
            <StatusRow
              label="Advanced controls"
              value={advancedEnabled ? "Enabled" : "Disabled"}
              desc={
                advancedEnabled
                  ? "Per-vector reaper + custom policy controls are unlocked in Advanced."
                  : "Basic presets only. Unlock per-vector controls in Advanced."
              }
            />
            {pctFiltered !== null && (
              <div style={{ color: "var(--fainter)", fontSize: "12px", lineHeight: "1.5" }}>
                {droppedCount.toLocaleString()} of {sampled.toLocaleString()} sampled mempool transactions
                sit in the tiers this node drops. This is a live single-node indicator of your current
                mempool sample — not a standard-vs-reaper-vs-Knots comparison.
              </div>
            )}
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Where to go next */}
      <SectionErrorBoundary section="Configure filtering">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <NavCard
            href="/filtering/basic"
            title="Basic"
            desc="Pick how much your node filters with one simple choice — the three tier presets, plus a live view of your mempool by class."
          />
          <NavCard
            href="/filtering/advanced"
            title="Advanced"
            desc="Hand-tune the reaper's per-vector spam controls and a full custom tier policy. For confident operators only."
          />
        </div>
      </SectionErrorBoundary>
    </div>
  );
}

function StatusRow({ label, value, desc }: { label: string; value: string; desc: string }) {
  return (
    <div
      style={{
        padding: "12px 14px",
        border: "1px solid var(--rule)",
        borderRadius: "6px",
        background: "var(--bg)",
      }}
    >
      <div className="flex items-center gap-2">
        <span style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 600 }}>{label}</span>
        <span style={{ color: "var(--accent)", fontSize: "13px", fontWeight: 600 }}>{value}</span>
      </div>
      <div style={{ color: "var(--dim)", fontSize: "13px", marginTop: "2px" }}>{desc}</div>
    </div>
  );
}

function NavCard({ href, title, desc }: { href: string; title: string; desc: string }) {
  return (
    <Link href={href} className="bare">
      <Card>
        <div className="flex items-center justify-between gap-3" style={{ marginBottom: "4px" }}>
          <span style={{ color: "var(--fg)", fontSize: "15px", fontWeight: 600 }}>{title}</span>
          <span style={{ color: "var(--accent)", fontSize: "13px", whiteSpace: "nowrap" }}>Open →</span>
        </div>
        <div style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.6" }}>{desc}</div>
      </Card>
    </Link>
  );
}
