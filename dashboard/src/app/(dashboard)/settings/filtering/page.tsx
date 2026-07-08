"use client";

import Link from "next/link";
import { Card, CardHeader } from "@/components/ui/Card";
import { Toggle } from "@/components/ui/Toggle";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { PolicyProfileSelector } from "@/components/filtering/PolicyProfileSelector";
import { BlockPrioritySelector } from "@/components/filtering/BlockPrioritySelector";
import { ReaperControls } from "@/components/filtering/ReaperControls";
import { AdvancedPolicyPanel } from "@/components/filtering/AdvancedPolicyPanel";
import { useAdvancedFilteringGate } from "@/hooks/useAdvancedFilteringGate";

/**
 * Settings › Filtering — central mirror of the tier-policy + reaper controls
 * that also live under /filtering. Reuses the exact same components and
 * mutations (PolicyProfileSelector → setPolicyProfile, ReaperControls →
 * setReaper, AdvancedPolicyPanel → setPolicyCustom) so there is one source of
 * truth. The advanced gate is the same per-browser opt-in used on /filtering.
 */
export default function FilteringSettingsPage() {
  const [advancedEnabled, setAdvancedEnabled] = useAdvancedFilteringGate();

  return (
    <div className="space-y-6">
      {/* Basic tier policy — the one-choice presets */}
      <SectionErrorBoundary section="Mining policy">
        <Card>
          <CardHeader
            title="Mining policy"
            subtitle="How strictly this node filters, by transaction class (BUDS T0–T3). Changing it restarts the node."
          />
          <PolicyProfileSelector />
          <p className="text-xs text-[color:var(--fainter)] mt-3">
            Prefer the guided view? The same choice, with a live mempool-by-class breakdown, is on{" "}
            <Link href="/filtering/basic" className="text-[color:var(--accent)] hover:text-[color:var(--accent)] underline">
              Filtering › Basic
            </Link>
            .
          </p>
        </Card>
      </SectionErrorBoundary>

      {/* Advanced gate — controls stay hidden until deliberately switched on */}
      <Card>
        <div className="flex items-start justify-between gap-4">
          <div>
            <div style={{ color: "var(--fg)", fontSize: "15px", fontWeight: 600 }}>Enable advanced controls</div>
            <div style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.6", marginTop: "4px" }}>
              Off by default. When on, the reaper vectors and custom mining policy below become editable.
              This switch is per-browser only — it does not change your node until you save a control below.
            </div>
          </div>
          <Toggle enabled={advancedEnabled} onChange={setAdvancedEnabled} label="Enable advanced controls" />
        </div>
      </Card>

      {advancedEnabled && (
        <>
          <SectionErrorBoundary section="Block priority">
            <Card>
              <CardHeader
                title="Block priority"
                subtitle="Ordering only — which admitted transactions this node seats first. Max fee maximises revenue; Payments first prioritises payments (BUDS T0/T1) over data (T2/T3), forgoing some fee income. Changing it restarts the node."
              />
              <BlockPrioritySelector />
            </Card>
          </SectionErrorBoundary>

          <SectionErrorBoundary section="Reaper">
            <ReaperControls />
          </SectionErrorBoundary>

          <SectionErrorBoundary section="Custom policy">
            <Card>
              <CardHeader
                title="Custom mining policy"
                subtitle="The full per-field counterpart to the presets above — every knob the block builder enforces, including the block fee floor (Min fee rate)."
              />
              <AdvancedPolicyPanel />
            </Card>
          </SectionErrorBoundary>
        </>
      )}
    </div>
  );
}
