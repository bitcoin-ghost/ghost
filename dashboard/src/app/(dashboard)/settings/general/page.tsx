"use client";

import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { IdentitySection } from "../IdentitySection";

export default function GeneralSettingsPage() {
  return (
    <div className="space-y-6">
      <SectionErrorBoundary section="Identity">
        <IdentitySection />
      </SectionErrorBoundary>
    </div>
  );
}
