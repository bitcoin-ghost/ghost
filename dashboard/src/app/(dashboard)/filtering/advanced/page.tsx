"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
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
              <CardHeader
                title="Custom mining policy"
                subtitle="The full per-field counterpart to the Basic presets — every knob the block builder enforces. Includes the block fee floor (Min fee rate)."
              />
              <AdvancedPolicyPanel />
            </Card>
          </SectionErrorBoundary>

          <SectionErrorBoundary section="Replace-by-fee">
            <Card>
              <CardHeader title="Replace-by-fee (RBF)" />
              <div style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.6" }}>
                <p style={{ marginBottom: "8px" }}>
                  Full replace-by-fee is <strong>always on</strong> at this node and cannot be disabled.
                  ghostd hardcodes <code>fullrbf = true</code> — there is no <code>-mempoolfullrbf</code> or
                  <code> -replacebyfee</code> launch flag to turn it off, so exposing a toggle here would be
                  cosmetic. Any unconfirmed transaction may be replaced by a higher-fee spend of the same inputs,
                  regardless of BIP-125 signalling.
                </p>
                <p>
                  To bias which of a set of conflicting transactions actually lands in your blocks, use the fee
                  floor and content limits in <strong>Custom mining policy</strong> above rather than a
                  node-level RBF switch.
                </p>
              </div>
            </Card>
          </SectionErrorBoundary>
        </>
      )}
    </div>
  );
}
