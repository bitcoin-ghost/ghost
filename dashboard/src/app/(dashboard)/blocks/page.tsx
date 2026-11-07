"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { BlocksView } from "@/components/nodePool/BlocksView";
import { useNodePoolStatus } from "@/hooks/queries/useNodePoolQueries";
import { useNow } from "@/hooks/useNow";

export default function BlocksPage() {
  const { data, error, isLoading } = useNodePoolStatus();
  const now = useNow();
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="node pool"
        title="Pool blocks."
        subtitle="Blocks the pool found, what each paid, the treasury change, and settlement"
      />
      <SectionErrorBoundary section="Pool blocks">
        <BlocksView status={data} statusError={error} statusLoading={isLoading} now={now} />
      </SectionErrorBoundary>
    </div>
  );
}
