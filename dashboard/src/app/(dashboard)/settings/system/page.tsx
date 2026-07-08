"use client";

import Link from "next/link";
import { Card, CardHeader } from "@/components/ui/Card";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { AutoUpdateSection } from "@/components/settings/AutoUpdateSection";
import { ScheduledBackupsCard } from "@/components/settings/ScheduledBackupsCard";

/**
 * Settings › System — central home for the operator-adjustable, persisted system
 * settings: the automatic-updates opt-in and the scheduled-backups schedule.
 * Reuses the same AutoUpdateSection (`useSetAutoUpdate`) and ScheduledBackupsCard
 * (`useSetBackupSchedule`) components that /system renders, so the persisted
 * settings have a Settings home consistent with the mirror pattern. Manual
 * update install, rollback and one-off encrypted backups remain on /system
 * (they are actions, not persisted settings).
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

      <SectionErrorBoundary section="Scheduled backups">
        <ScheduledBackupsCard />
      </SectionErrorBoundary>

      <Card>
        <p className="text-sm text-[color:var(--dim)]">
          Check for and install updates manually, roll back to a previous version, or create a one-off
          encrypted backup on{" "}
          <Link href="/system" className="text-[color:var(--accent)] hover:text-[color:var(--accent)] underline">
            System
          </Link>
          .
        </p>
      </Card>
    </div>
  );
}
