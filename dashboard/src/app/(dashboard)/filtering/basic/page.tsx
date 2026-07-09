"use client";

import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { fetchApi } from "@/lib/api/client";
import { PolicyProfileSelector } from "@/components/filtering/PolicyProfileSelector";
import { BUDS_TIER_COLORS, type BudsTierKey } from "@/lib/budsTiers";

interface TierMeta {
  key: BudsTierKey;
  name: string;
  short: string;
  color: string;
  blurb: string;
  examples: string;
}

const TIERS: TierMeta[] = [
  {
    key: "T0",
    name: "T0 · Financial",
    short: "Ordinary payments",
    color: BUDS_TIER_COLORS.T0,
    blurb: "Plain money moving between people — the transactions Bitcoin exists for.",
    examples: "single-sig sends, change, consolidations",
  },
  {
    key: "T1",
    name: "T1 · Extended",
    short: "Bigger financial",
    color: BUDS_TIER_COLORS.T1,
    blurb: "Still money, just more elaborate — multiple signers or time locks.",
    examples: "multisig, Lightning channels, timelocks",
  },
  {
    key: "T2",
    name: "T2 · Data",
    short: "Small data carriers",
    color: BUDS_TIER_COLORS.T2,
    blurb: "Transactions that also carry a little standard data. Allowed, but not payments.",
    examples: "OP_RETURN ≤ 80 bytes, commitments",
  },
  {
    key: "T3",
    name: "T3 · Abusive",
    short: "Heavy / abusive data",
    color: BUDS_TIER_COLORS.T3,
    blurb: "Transactions whose main purpose is stuffing data onto the chain.",
    examples: "inscriptions, runes, BRC-20, oversized data",
  },
];

interface BudsMempool {
  by_tier?: { T0: number; T1: number; T2: number; T3: number };
  sample_size?: number;
  message?: string;
}

export default function BasicFilteringPage() {
  const { data: mempool } = useQuery({
    queryKey: ["buds-mempool"],
    queryFn: () => fetchApi<BudsMempool>("/api/v1/buds/mempool"),
    refetchInterval: 15_000,
  });

  const byTier = mempool?.by_tier ?? { T0: 0, T1: 0, T2: 0, T3: 0 };
  const sampled = mempool?.sample_size ?? TIERS.reduce((s, t) => s + (byTier[t.key] ?? 0), 0);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="filtering"
        title="Basic."
        subtitle="Pick how much your node filters with one simple choice. Every transaction is sorted into a BUDS class (T0–T3), and your choice decides which classes your node accepts — filtered classes are rejected at your mempool, so they are never relayed or mined."
        subtitleFullWidth
      />

      {/* The four classes, explained — lead with what BUDS is */}
      <SectionErrorBoundary section="Transaction classes">
        <Card>
          <p className="t-body" style={{ color: "var(--dim)", lineHeight: "1.6", marginBottom: "16px" }}>
            BUDS — Bitcoin Universal Data Specification. We use BUDS to sort every transaction into a
            class (T0–T3), so filtering is one simple choice instead of dozens of settings.
          </p>
          <CardHeader
            title="The four classes"
            subtitle="What each BUDS class means, in plain terms."
          />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {TIERS.map((t) => (
              <div
                key={t.key}
                style={{
                  padding: "12px 14px",
                  border: "1px solid var(--rule)",
                  borderLeft: `3px solid ${t.color}`,
                  borderRadius: "6px",
                  background: "var(--bg)",
                }}
              >
                <div className="flex items-center gap-2" style={{ marginBottom: "4px" }}>
                  <span style={{ width: "10px", height: "10px", borderRadius: "2px", background: t.color, display: "inline-block" }} />
                  <span className="t-body" style={{ color: "var(--fg)" }}>{t.name}</span>
                  <span className="t-caption" style={{ color: "var(--dim)" }}>· {t.short}</span>
                </div>
                <div className="t-label" style={{ color: "var(--dim)", lineHeight: "1.5" }}>{t.blurb}</div>
                <div className="t-caption" style={{ color: "var(--fainter)", marginTop: "6px" }}>
                  e.g. {t.examples}
                </div>
              </div>
            ))}
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* The simple choice: the three tier presets — now below the classes */}
      <SectionErrorBoundary section="Mining policy">
        <Card>
          <CardHeader
            title="Mining policy"
            subtitle="How strictly this node filters, by transaction class. Changing it restarts the node."
          />
          <PolicyProfileSelector />
        </Card>
      </SectionErrorBoundary>

      {/* Live composition — what THIS node is holding right now */}
      <SectionErrorBoundary section="Your mempool by class">
        <Card>
          <CardHeader
            title="Your mempool by class"
            subtitle="The transaction classes your node accepts, relays, and mines — filtered classes never enter your mempool. From a live mempool sample."
          />
          <div className="space-y-3">
            {mempool?.message ? (
              <p className="t-label" style={{ color: "var(--dim)" }}>
                Mempool classification is unavailable — {mempool.message}
              </p>
            ) : (
              <>
                <div style={{ display: "flex", height: "14px", borderRadius: "4px", overflow: "hidden", background: "var(--bg)" }}>
                  {TIERS.map((t) => {
                    const count = byTier[t.key] ?? 0;
                    const pct = sampled ? (count / sampled) * 100 : 0;
                    if (pct === 0) return null;
                    return (
                      <div key={t.key} title={`${t.name}: ${count} (${pct.toFixed(1)}%)`} style={{ width: `${pct}%`, background: t.color }} />
                    );
                  })}
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {TIERS.map((t) => {
                    const count = byTier[t.key] ?? 0;
                    const pct = sampled ? (count / sampled) * 100 : 0;
                    return (
                      <div key={t.key} style={{ padding: "10px 12px", border: "1px solid var(--rule)", borderRadius: "4px", background: "var(--bg)" }}>
                        <div className="flex items-center gap-2" style={{ marginBottom: "4px" }}>
                          <span style={{ width: "10px", height: "10px", borderRadius: "2px", background: t.color, display: "inline-block" }} />
                          <span className="t-label" style={{ color: "var(--fg)" }}>{t.name}</span>
                        </div>
                        <div className="t-title" style={{ fontFamily: "var(--font-mono)", color: "var(--fg)" }}>{pct.toFixed(0)}%</div>
                        <div className="t-caption" style={{ color: "var(--dim)" }}>{count.toLocaleString()} sampled</div>
                      </div>
                    );
                  })}
                </div>
              </>
            )}
          </div>
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}
