"use client";

import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { NodePoolSettingsView } from "@/components/nodePool/NodePoolSettingsView";
import { useNodePoolStatus } from "@/hooks/queries/useNodePoolQueries";
import { IdentitySection } from "../IdentitySection";

export default function GeneralSettingsPage() {
  const { data, error, isLoading } = useNodePoolStatus();
  return (
    <div className="space-y-6">
      <SectionErrorBoundary section="Identity">
        <IdentitySection />
      </SectionErrorBoundary>
      <SectionErrorBoundary section="Node pool">
        <NodePoolSettingsView status={data} statusError={error ?? undefined} statusLoading={isLoading} />
      </SectionErrorBoundary>
    </div>
  );
}
