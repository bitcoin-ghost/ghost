"use client";

import { CapabilityToggles } from "@/components/settings/CapabilityToggles";
import { SettingsSection } from "../shared";

export default function CapabilitiesSettingsPage() {
  return (
    <SettingsSection
      title="Node Capabilities"
      subtitle="Earn shares in the node reward pool — 5-4-3-2-1 system"
    >
      {/*
       * The five capability rows are shared with the Onboarding wizard via
       * CapabilityToggles (single source of truth). Here Ghost Pay is read-only
       * status, and the Reaper row links out to detector-level configuration.
       */}
      <CapabilityToggles reaperConfigHref="/filtering/advanced" />
    </SettingsSection>
  );
}
