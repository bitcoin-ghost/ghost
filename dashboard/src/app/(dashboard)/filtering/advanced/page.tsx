"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Toggle } from "@/components/ui/Toggle";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { ReaperControls } from "@/components/filtering/ReaperControls";
import { AdvancedPolicyPanel } from "@/components/filtering/AdvancedPolicyPanel";
import { useAdvancedFilteringGate } from "@/hooks/useAdvancedFilteringGate";

export default function AdvancedFilteringPage() {
  const [enabled, setEnabled] = useAdvancedFilteringGate();

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="filtering"
        title="Advanced."
        subtitle="Hand-tune exactly what your node relays and mines: dead-code/spam vectors (Reaper) and per-tier / size / content limits (Custom policy). Only for confident operators; the Basic presets cover most needs."
        subtitleFullWidth
      />

      {/* Enable gate — controls stay hidden until deliberately switched on */}
      <Card>
        <div className="flex items-start justify-between gap-4">
          <div>
            <div style={{ color: "var(--fg)", fontSize: "15px", fontWeight: 600 }}>Enable advanced controls</div>
            <div style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.6", marginTop: "4px" }}>
              Off by default. When on, the reaper vectors and custom mining policy below become editable.
              This switch is per-browser only — it does not change your node until you save a control below.
            </div>
          </div>
          <Toggle enabled={enabled} onChange={setEnabled} label="Enable advanced controls" />
        </div>
      </Card>

      {enabled && (
        <>
          <SectionErrorBoundary section="Reaper">
            <ReaperControls />
          </SectionErrorBoundary>

          <SectionErrorBoundary section="Custom policy">
            <Card>
              <AdvancedPolicyPanel />
            </Card>
          </SectionErrorBoundary>
        </>
      )}
    </div>
  );
}
