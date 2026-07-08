"use client";

import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { fetchApi } from "@/lib/api/client";
import { PolicyProfileSelector, normalizeProfile } from "@/components/filtering/PolicyProfileSelector";
import { useFullConfig } from "@/hooks/queries/useConfigQueries";
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

  // Which BUDS tiers this node's blocks actually mine, under the active policy.
  // The mempool holds every class you relay; the blockpool is that set filtered
  // through the tier policy — the difference is your filter at work.
  const { data: fullConfig } = useFullConfig();
  const profile = fullConfig?.policy?.profile;
  const custom = fullConfig?.policy?.custom;
  const mined = new Set<BudsTierKey>();
  if (profile === "custom" && custom) {
    if (custom.allow_t0) mined.add("T0");
    if (custom.allow_t1) mined.add("T1");
    if (custom.allow_t2) mined.add("T2");
    if (custom.allow_t3) mined.add("T3");
  } else {
    const norm = normalizeProfile(profile);
    if (norm === "strict") {
      mined.add("T0");
      mined.add("T1");
    } else if (norm === "permissive") {
      mined.add("T0");
      mined.add("T1");
      mined.add("T2");
    } else {
      // full_open or unknown (config not loaded) — assume all mined, never
      // show a class as "dropped" unless we're sure it is.
      (["T0", "T1", "T2", "T3"] as BudsTierKey[]).forEach((k) => mined.add(k));
    }
  }

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
            subtitle="Every valid transaction class your node holds and relays, from a live mempool sample. What you actually mine is the blockpool below."
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

      {/* Blockpool — what your blocks actually mine (the mempool after tier policy) */}
      <SectionErrorBoundary section="Your blockpool by class">
        <Card>
          <CardHeader
            title="Your blockpool by class"
            subtitle="What your blocks actually mine — the mempool above, after your tier policy. Dropped classes still sit in your mempool and get relayed; they just don't earn a place in your block."
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
                    const isMined = mined.has(t.key);
                    return (
                      <div
                        key={t.key}
                        title={isMined ? `${t.name}: mined — ${count} (${pct.toFixed(1)}%)` : `${t.name}: dropped by your tier policy`}
                        style={{ width: `${pct}%`, background: isMined ? t.color : "var(--rule-strong)", opacity: isMined ? 1 : 0.35 }}
                      />
                    );
                  })}
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {TIERS.map((t) => {
                    const count = byTier[t.key] ?? 0;
                    const pct = sampled ? (count / sampled) * 100 : 0;
                    const isMined = mined.has(t.key);
                    return (
                      <div key={t.key} style={{ padding: "10px 12px", border: "1px solid var(--rule)", borderRadius: "4px", background: "var(--bg)", opacity: isMined ? 1 : 0.55 }}>
                        <div className="flex items-center gap-2" style={{ marginBottom: "4px" }}>
                          <span style={{ width: "10px", height: "10px", borderRadius: "2px", background: isMined ? t.color : "var(--fainter)", display: "inline-block" }} />
                          <span className="t-label" style={{ color: "var(--fg)" }}>{t.name}</span>
                        </div>
                        {isMined ? (
                          <>
                            <div className="t-title" style={{ fontFamily: "var(--font-mono)", color: "var(--fg)" }}>{pct.toFixed(0)}%</div>
                            <div className="t-caption" style={{ color: "var(--dim)" }}>{count.toLocaleString()} mined</div>
                          </>
                        ) : (
                          <>
                            <div className="t-title" style={{ color: "var(--dim)" }}>Dropped</div>
                            <div className="t-caption" style={{ color: "var(--dim)" }}>not mined by you</div>
                          </>
                        )}
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
