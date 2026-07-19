"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { BlockTemplateCard } from "@/components/mining/BlockTemplateCard";
import { CoinbasePaymentsCard } from "@/components/mining/CoinbasePaymentsCard";

export default function BlockTemplatePage() {
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="ghost pool"
        title="Block Template."
        subtitle="The block this node is building and how its coinbase pays out"
      />

      {/* The block this node is currently building. */}
      <SectionErrorBoundary section="Block Template">
        <BlockTemplateCard />
      </SectionErrorBoundary>

      {/* How that block's coinbase splits across miners, nodes, treasury, fees. */}
      <SectionErrorBoundary section="Coinbase Payments">
        <CoinbasePaymentsCard />
      </SectionErrorBoundary>
    </div>
  );
}
