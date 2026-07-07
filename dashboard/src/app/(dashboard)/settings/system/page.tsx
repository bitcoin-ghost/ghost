"use client";

import Link from "next/link";
import { Card, CardHeader } from "@/components/ui/Card";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { AutoUpdateSection } from "@/components/settings/AutoUpdateSection";

/**
 * Settings › System — central mirror of the operator-adjustable system setting:
 * the automatic-updates opt-in. Reuses the same AutoUpdateSection component +
 * `useSetAutoUpdate` mutation as /system. Manual update install, rollback and
 * encrypted backups remain on /system (they are actions, not persisted
 * settings).
 */
export default function SystemSettingsPage() {
  return (
    <div className="space-y-6">
      <SectionErrorBoundary section="Automatic updates">
        <Card>
          <CardHeader
            title="Software Updates"
            subtitle="Keep this node current automatically, or drive updates by hand from System."
          />
          <div className="p-4 bg-[var(--surface)]/50 rounded-lg">
            <AutoUpdateSection />
          </div>
        </Card>
      </SectionErrorBoundary>

      <Card>
        <p className="text-sm text-[color:var(--dim)]">
          Check for and install updates manually, roll back to a previous version, or manage encrypted
          backups on{" "}
          <Link href="/system" className="text-[color:var(--accent)] hover:text-[color:var(--accent)] underline">
            System
          </Link>
          .
        </p>
      </Card>
    </div>
  );
}
