"use client";

import Link from "next/link";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useConfig, useFullConfig } from "@/hooks/queries/useConfigQueries";
import { useAdvancedFilteringGate } from "@/hooks/useAdvancedFilteringGate";
import type { FullNodeConfig } from "@/types/api";

type TierKey = "T0" | "T1" | "T2" | "T3";

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
      return "Open";
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

export default function FilteringOverviewPage() {
  const { data: config } = useConfig();
  const { data: fullConfig } = useFullConfig();
  const [advancedEnabled] = useAdvancedFilteringGate();

  const reaperOn = config?.reaper ?? false;
  const profile = fullConfig?.policy?.profile;
  const dropped = droppedTiers(profile, fullConfig?.policy?.custom);
  const droppedLabel = dropped.length ? dropped.join(" + ") : "none";

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="filtering"
        title="Filtering."
        subtitle="What your node filters. Set it in Basic, fine-tune in Advanced."
      />

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
                  ? `Rejects ${droppedLabel} — accepts everything else.`
                  : profile === "full_open"
                    ? "Accepts every class, including heavy data (T3)."
                    : "The tier policy this node accepts under."
              }
            />
            <StatusRow
              label="Reaper"
              value={reaperOn ? "On" : "Off"}
              desc={
                reaperOn
                  ? "Strips dead-code spam from your mempool relay and block templates."
                  : "Not removing dead-code spam."
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
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* How filtering works — short two-line explainer for newcomers */}
      <Card>
        <CardHeader title="How filtering works" subtitle="Two layers, in plain terms." />
        <div className="space-y-2">
          <p className="t-body" style={{ color: "var(--dim)", lineHeight: 1.6 }}>
            The Reaper rejects spam — inscription stuffing, dust floods, oversized data — at your
            mempool, so it is never relayed or mined.
          </p>
          <p className="t-body" style={{ color: "var(--dim)", lineHeight: 1.6 }}>
            The tier policy (BUDS) picks which transaction classes your node accepts — and your
            mempool is exactly the set your blocks build from.
          </p>
        </div>
      </Card>

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
        <span className="t-body" style={{ color: "var(--dim)" }}>{label}</span>
        <span className="t-body" style={{ color: "var(--fg)" }}>{value}</span>
      </div>
      <div className="t-label" style={{ color: "var(--dim)", marginTop: "2px" }}>{desc}</div>
    </div>
  );
}

function NavCard({ href, title, desc }: { href: string; title: string; desc: string }) {
  return (
    <Link href={href} className="bare">
      <Card>
        <div className="flex items-center justify-between gap-3" style={{ marginBottom: "4px" }}>
          <span className="t-title" style={{ color: "var(--fg)" }}>{title}</span>
          <span className="t-label" style={{ color: "var(--accent)", whiteSpace: "nowrap" }}>Open →</span>
        </div>
        <div className="t-label" style={{ color: "var(--dim)", lineHeight: "1.6" }}>{desc}</div>
      </Card>
    </Link>
  );
}
