"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { fetchApi } from "@/lib/api/client";
import { useConfig } from "@/hooks/queries/useConfigQueries";

// Plain-English names for the tier policy, so operators never see the raw
// `permissive` / `bitcoin_pure` / `full_open` keys.
function policyLabel(profile?: string): string {
  switch (profile) {
    case "bitcoin_pure":
      return "Bitcoin-only";
    case "permissive":
      return "Standard";
    case "full_open":
      return "Everything";
    default:
      return profile ? profile : "Standard";
  }
}

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

export default function BudsPage() {
  const { data: config } = useConfig();
  const { data: mempool } = useQuery({
    queryKey: ["buds-mempool"],
    queryFn: () => fetchApi<BudsMempool>("/api/v1/buds/mempool"),
    refetchInterval: 15_000,
  });

  const reaperEnabled = config?.reaper ?? false;
  const byTier = mempool?.by_tier ?? { T0: 0, T1: 0, T2: 0, T3: 0 };
  const sampled = mempool?.sample_size ?? TIERS.reduce((s, t) => s + (byTier[t.key] ?? 0), 0);
  const cleanShare = sampled ? (byTier.T0 + byTier.T1) / sampled : 0;
  const abusiveShare = sampled ? byTier.T3 / sampled : 0;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="filtering"
        title="BUDS."
        subtitle="Every transaction your node sees is sorted into one of four classes — from ordinary payments to abusive data. That class decides how it's filtered."
        subtitleFullWidth
      />

      {/* The four classes, explained */}
      <SectionErrorBoundary section="Transaction classes">
        <Card>
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
                <div style={{ color: "var(--fg)", fontSize: "13px", lineHeight: "1.6" }}>
                  Most of what your node holds right now is clean payments:{" "}
                  <strong style={{ color: "#3fb950" }}>~{Math.round(cleanShare * 100)}%</strong> of sampled
                  transactions are ordinary payments (T0 + T1).
                  {byTier.T3 > 0 && (
                    <>
                      {" "}
                      About <strong style={{ color: "var(--fg)" }}>~{Math.round(abusiveShare * 100)}%</strong>{" "}
                      carry abusive patterns (T3) — inscriptions, runes and oversized data. The reaper drops
                      the ones that hide dead code; a runestone is standard, provably-unspendable OP_RETURN
                      data — not dead code — so the reaper leaves it.
                      {reaperEnabled && (
                        <>
                          {" "}
                          Tune your reject vectors on the{" "}
                          <Link href="/reaper" className="bare" style={{ color: "var(--fg)", textDecoration: "underline" }}>
                            Reaper page
                          </Link>{" "}
                          to catch more dead-code variants.
                        </>
                      )}
                    </>
                  )}
                </div>
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
                <p style={{ color: "var(--fainter)", fontSize: "12px" }}>
                  Based on a live sample of {sampled.toLocaleString()} transactions (the node classifies up to
                  100 per poll to stay light). Proportions are representative, not exact totals.
                </p>
              </>
            )}
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Filtering settings — current policy + where to change it */}
      <SectionErrorBoundary section="Filtering settings">
        <Card>
          <CardHeader
            title="Filtering settings"
            subtitle="How strictly this node filters transactions."
          />
          <div className="space-y-3">
            <SettingRow
              label="Reaper"
              value={reaperEnabled ? "On" : "Off"}
              desc={reaperEnabled ? "Strips dead-code transactions from your mempool and blocks." : "Not removing dead-code transactions."}
              href="/reaper"
              cta="Reaper settings"
            />
            <SettingRow
              label="Mining policy"
              value={policyLabel(config?.template_profile)}
              desc="Which transaction classes this node will mine into the blocks it builds."
              href="/settings"
              cta="Change in Settings"
            />
            <SettingRow
              label="Mempool policy"
              value={policyLabel(config?.mempool_profile)}
              desc="Which transaction classes this node will keep in its mempool."
              href="/settings"
              cta="Change in Settings"
            />
          </div>
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}

function SettingRow({
  label,
  value,
  desc,
  href,
  cta,
}: {
  label: string;
  value: string;
  desc: string;
  href: string;
  cta: string;
}) {
  return (
    <div
      style={{
        padding: "12px 14px",
        border: "1px solid var(--rule)",
        borderRadius: "6px",
        background: "var(--bg)",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        gap: "12px",
        flexWrap: "wrap",
      }}
    >
      <div>
        <div className="flex items-center gap-2">
          <span style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 600 }}>{label}</span>
          <span style={{ color: "var(--accent)", fontSize: "13px", fontWeight: 600 }}>{value}</span>
        </div>
        <div style={{ color: "var(--dim)", fontSize: "13px", marginTop: "2px" }}>{desc}</div>
      </div>
      <Link href={href} className="bare" style={{ color: "var(--accent)", textDecoration: "underline", fontSize: "13px", whiteSpace: "nowrap" }}>
        {cta} →
      </Link>
    </div>
  );
}
