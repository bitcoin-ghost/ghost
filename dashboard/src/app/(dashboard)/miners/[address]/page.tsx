"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/ui/PageHeader";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { MinerDetailView } from "@/components/nodePool/MinerDetailView";
import { useNodePoolLedger, useNodePoolMiner } from "@/hooks/queries/useNodePoolQueries";
import { useNow } from "@/hooks/useNow";

export default function MinerDetailPage() {
  const params = useParams<{ address: string }>();
  const address = params?.address ? decodeURIComponent(params.address) : "";
  const ledger = useNodePoolLedger(address || null);
  const miner = useNodePoolMiner(address || null);
  const now = useNow();
  return (
    <div className="space-y-6">
      <PageHeader eyebrow="node pool · miner" title="Miner." subtitle={address ? `${address}: this node's view of one payout address` : "No address given"} />
      <Link href="/miners" className="text-sm" style={{ color: "var(--accent)" }}>
        All miners
      </Link>
      <SectionErrorBoundary section="Miner">
        <MinerDetailView
          address={address}
          ledger={ledger.data}
          ledgerError={ledger.error ?? undefined}
          miner={miner.data}
          minerError={miner.error ?? undefined}
          now={now}
        />
      </SectionErrorBoundary>
    </div>
  );
}
