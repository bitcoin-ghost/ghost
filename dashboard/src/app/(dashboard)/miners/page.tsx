"use client";

import { useMemo } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { MinersView, type PerAddress } from "@/components/nodePool/MinersView";
import { useNodePoolAddresses, useNodePoolStatus } from "@/hooks/queries/useNodePoolQueries";
import type { NodePoolLedger, NodePoolMiner } from "@/lib/api/nodePool";
import { groupByAddress } from "@/lib/nodePool/view";

export default function MinersPage() {
  const { data, error, isLoading } = useNodePoolStatus();
  const addresses = useMemo(
    () => (data ? groupByAddress(data.miners).map((g) => g.address) : []),
    [data],
  );
  const { ledgers, miners } = useNodePoolAddresses(addresses);
  const byAddress = <T,>(rs: { data?: T; error: unknown }[]) => {
    const out: Record<string, PerAddress<T>> = {};
    addresses.forEach((a, i) => {
      out[a] = { data: rs[i]?.data, error: rs[i]?.error ?? undefined };
    });
    return out;
  };
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="node pool"
        title="Miners."
        subtitle="Connected miners, their slot class and sensing, shares, balance, queue and expected wait"
      />
      <SectionErrorBoundary section="Miners">
        <MinersView
          status={data}
          statusError={error}
          statusLoading={isLoading}
          ledgers={byAddress<NodePoolLedger>(ledgers)}
          miners={byAddress<NodePoolMiner>(miners)}
        />
      </SectionErrorBoundary>
    </div>
  );
}
