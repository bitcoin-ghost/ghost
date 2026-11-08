"use client";

import { useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/ui/PageHeader";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { MinerDetailView } from "@/components/pool/MinerDetailView";
import { usePoolMiner, usePoolMinerHistory } from "@/hooks/queries/usePoolQueries";
import type { PoolHistoryWindow } from "@/lib/api/pool";
import { useNow } from "@/hooks/useNow";

const WINDOWS: PoolHistoryWindow[] = ["24h", "7d", "30d"];

export default function MinerDetailPage() {
  const params = useParams<{ address: string }>();
  const address = params?.address ? decodeURIComponent(params.address) : "";
  const [win, setWin] = useState<PoolHistoryWindow>("24h");
  const miner = usePoolMiner(address || null);
  const history = usePoolMinerHistory(address || null, win);
  const now = useNow();
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="ghost pool · miner"
        title="Miner."
        subtitle={address ? `${address}: this node's view of one payout address` : "No address given"}
      />
      <div className="flex flex-wrap items-center gap-4 text-sm">
        <Link href="/miners" style={{ color: "var(--accent)" }}>
          All miners
        </Link>
        <span style={{ color: "var(--fainter)" }}>History:</span>
        {WINDOWS.map((w) => (
          <button
            key={w}
            type="button"
            onClick={() => setWin(w)}
            className="px-2 py-0.5 rounded"
            style={{
              border: "1px solid var(--rule-strong)",
              color: w === win ? "var(--fg)" : "var(--dim)",
              background: w === win ? "var(--surface)" : "transparent",
            }}
          >
            {w}
          </button>
        ))}
      </div>
      <SectionErrorBoundary section="Miner">
        <MinerDetailView
          address={address}
          miner={miner.data}
          minerError={miner.error ?? undefined}
          history={history.data}
          historyError={history.error ?? undefined}
          now={now}
        />
      </SectionErrorBoundary>
    </div>
  );
}
