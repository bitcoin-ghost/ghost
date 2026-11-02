"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { ShareChainView } from "@/components/nodePool/ShareChainView";
import { useNodePoolStatus } from "@/hooks/queries/useNodePoolQueries";
import { useNow } from "@/hooks/useNow";

export default function ShareChainPage() {
  const { data, error, isLoading } = useNodePoolStatus();
  const now = useNow();
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="node pool"
        title="Share chain."
        subtitle="Tip, anchors, sync, relay counters, checkpoints and pruning"
      />
      <SectionErrorBoundary section="Share chain">
        <ShareChainView status={data} statusError={error} statusLoading={isLoading} now={now} />
      </SectionErrorBoundary>
    </div>
  );
}
