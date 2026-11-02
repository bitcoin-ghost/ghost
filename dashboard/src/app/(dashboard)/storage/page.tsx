"use client";

import { Badge } from "@/components/ui/Badge";
import { SkeletonCard } from "@/components/ui/Skeleton";
import {
  useFullConfig,
  useNodeStatus,
} from "@/hooks/queries";
import { StoragePruningCard } from "@/components/settings/StoragePruningCard";
import { PageHeader } from "@/components/ui/PageHeader";

export default function StoragePage() {
  const { isLoading: configLoading } = useFullConfig();
  const { data: status } = useNodeStatus();

  const isLoading = configLoading;
  const archiveMode = status?.archive_mode ?? false;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="storage"
        title="Storage & Pruning"
        subtitle="Block-storage pruning for this node — how much recent chain history to keep on disk."
        actions={archiveMode ? <Badge variant="success">Archive</Badge> : undefined}
      />

      {isLoading ? (
        <>
          <SkeletonCard />
          <SkeletonCard />
        </>
      ) : (
        <>
          {/* L1 Pruning - Three Window Model. Shared with /settings/storage. */}
          <StoragePruningCard />

        </>
      )}
    </div>
  );
}
