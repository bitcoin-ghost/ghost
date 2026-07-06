"use client";

import Link from "next/link";
import { Card } from "@/components/ui/Card";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { StoragePruningCard } from "@/components/settings/StoragePruningCard";

/**
 * Settings › Storage — central mirror of the L1 pruning controls (Archive Mode,
 * Operator Window, BUDS prune profile) that also live on /storage. Reuses the
 * exact same StoragePruningCard component + mutations. Full L2 pruning status,
 * quick-reference tables and backups remain on /storage and /system.
 */
export default function StorageSettingsPage() {
  return (
    <div className="space-y-6">
      <SectionErrorBoundary section="L1 Pruning">
        <StoragePruningCard />
      </SectionErrorBoundary>

      <Card>
        <p className="text-sm text-gray-400">
          Looking for L2 (Ghost Pay) pruning status and the full storage breakdown? See{" "}
          <Link href="/storage" className="text-orange-400 hover:text-orange-300 underline">
            Storage
          </Link>
          . Backups and software updates live under{" "}
          <Link href="/system" className="text-orange-400 hover:text-orange-300 underline">
            System
          </Link>
          .
        </p>
      </Card>
    </div>
  );
}
