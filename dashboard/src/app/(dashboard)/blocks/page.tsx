"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { BlocksView } from "@/components/pool/BlocksView";
import { usePoolStatus } from "@/hooks/queries/usePoolQueries";
import { useNow } from "@/hooks/useNow";

export default function BlocksPage() {
  const { data, error, isLoading } = usePoolStatus();
  const now = useNow();
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="ghost pool"
        title="Blocks found."
        subtitle="Every block a miner on this node found, what it paid, its coinbase check and what the other nodes said"
      />
      <SectionErrorBoundary section="Blocks found">
        <BlocksView status={data} statusError={error} statusLoading={isLoading} now={now} />
      </SectionErrorBoundary>
    </div>
  );
}
