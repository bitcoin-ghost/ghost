"use client";

import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { fetchApi } from "@/lib/api/client";
import { PolicyProfileSelector } from "@/components/filtering/PolicyProfileSelector";

interface TierMeta {
  key: "T0" | "T1" | "T2" | "T3";
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
    color: "#3fb950",
    blurb: "Plain money moving between people — the transactions Bitcoin exists for.",
    examples: "single-sig sends, change, consolidations",
  },
  {
    key: "T1",
    name: "T1 · Extended",
    short: "Bigger financial",
    color: "#58a6ff",
    blurb: "Still money, just more elaborate — multiple signers or time locks.",
    examples: "multisig, Lightning channels, timelocks",
  },
  {
    key: "T2",
    name: "T2 · Data",
    short: "Small data carriers",
    color: "#d29922",
    blurb: "Transactions that also carry a little standard data. Allowed, but not payments.",
    examples: "OP_RETURN ≤ 80 bytes, commitments",
  },
  {
    key: "T3",
    name: "T3 · Abusive",
    short: "Heavy / abusive data",
    color: "#f85149",
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
        subtitle="Pick how much your node filters with one simple choice. Every transaction is sorted into a BUDS class (T0–T3), and your choice decides which classes get mined."
        subtitleFullWidth
      />

      {/* The four classes, explained — lead with what BUDS is */}
      <SectionErrorBoundary section="Transaction classes">
        <Card>
          <p style={{ color: "var(--dim)", fontSize: "14px", lineHeight: "1.6", marginBottom: "16px" }}>
            <strong style={{ color: "var(--fg)" }}>BUDS — Bitcoin Universal Data Specification.</strong>{" "}
            We use BUDS to sort every transaction into a class (T0–T3), so filtering is one simple choice
            instead of dozens of settings.
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
                  <span style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 600 }}>{t.name}</span>
                  <span style={{ color: "var(--dim)", fontSize: "12px" }}>· {t.short}</span>
                </div>
                <div style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.5" }}>{t.blurb}</div>
                <div style={{ color: "var(--fainter)", fontSize: "12px", marginTop: "6px" }}>
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
            subtitle="What your node is holding right now, by share of sampled transactions."
          />
          <div className="space-y-3">
            {mempool?.message ? (
              <p style={{ color: "var(--dim)", fontSize: "13px" }}>
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
                          <span style={{ color: "var(--fg)", fontSize: "13px", fontWeight: 500 }}>{t.name}</span>
                        </div>
                        <div style={{ fontFamily: "var(--font-mono)", fontSize: "18px", color: "var(--fg)" }}>{pct.toFixed(0)}%</div>
                        <div style={{ color: "var(--dim)", fontSize: "12px" }}>{count.toLocaleString()} sampled</div>
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
