"use client";

import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { PoolSettingsView } from "@/components/pool/PoolSettingsView";
import { usePoolStatus } from "@/hooks/queries/usePoolQueries";
import { IdentitySection } from "../IdentitySection";

export default function GeneralSettingsPage() {
  const { data, error, isLoading } = usePoolStatus();
  return (
    <div className="space-y-6">
      <SectionErrorBoundary section="Identity">
        <IdentitySection />
      </SectionErrorBoundary>
      <SectionErrorBoundary section="Ghost Pool">
        <PoolSettingsView status={data} statusError={error ?? undefined} statusLoading={isLoading} />
      </SectionErrorBoundary>
    </div>
  );
}
