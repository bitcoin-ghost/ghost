"use client";

import { useState } from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { fetchApi } from "@/lib/api/client";
import { useConfig, useFullConfig } from "@/hooks/queries/useConfigQueries";
import { setPolicyProfile, type PolicyProfileType } from "@/lib/api/config";
import { useToast } from "@/components/ui/Toast";

// The three real tier-policy presets (pool.toml [policy].profile), with
// plain-English labels and descriptions true to what each actually mines.
const POLICY_PRESETS: { value: PolicyProfileType; label: string; desc: string }[] = [
  { value: "strict", label: "Strict", desc: "Payments, multisig & timelocks only (T0+T1). Drops all data — no OP_RETURN, inscriptions or runes." },
  { value: "permissive", label: "Standard", desc: "Adds small OP_RETURN / Lightning commitments (T0+T1+T2). Still drops inscriptions, runes & BRC-20 (T3)." },
  { value: "full_open", label: "Everything", desc: "All valid transactions including inscriptions, runes & BRC-20 (T0–T3). Maximum fees, no tier filtering." },
];

// Normalise the stored profile (legacy `bitcoin_pure` == `strict`).
function normalizeProfile(profile?: string): PolicyProfileType | undefined {
  if (profile === "bitcoin_pure") return "strict";
  if (profile === "strict" || profile === "permissive" || profile === "full_open") return profile;
  return undefined;
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
            subtitle="Basic — pick a tier preset below. Advanced — per-vector spam controls on the Reaper page (and custom policy, when enabled)."
          />
          <div className="space-y-3">
            <PolicyProfileSelector />
            <SettingRow
              label="Reaper"
              value={`${reaperEnabled ? "On" : "Off"} · Advanced`}
              desc={reaperEnabled ? "Advanced: per-vector dead-code / spam filtering for your mempool and blocks." : "Advanced: per-vector dead-code / spam filtering (currently off)."}
              href="/reaper"
              cta="Reaper settings"
            />
          </div>
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}

// Editable tier-policy selector — writes the real pool.toml [policy].profile via
// POST /api/v1/config/policy_profile, which persists + triggers a graceful
// restart to apply. A pending-confirm step makes the restart explicit.
function PolicyProfileSelector() {
  const { data: fullConfig } = useFullConfig();
  const { success, error } = useToast();
  const queryClient = useQueryClient();
  const current = normalizeProfile(fullConfig?.policy?.profile);
  const [pending, setPending] = useState<PolicyProfileType | null>(null);
  const [saving, setSaving] = useState(false);

  const apply = async (profile: PolicyProfileType) => {
    setSaving(true);
    try {
      await setPolicyProfile(profile);
      success("Policy updated", "The node is restarting to apply the new tier policy.");
      setPending(null);
      queryClient.invalidateQueries({ queryKey: ["config"] });
    } catch (e) {
      error("Failed to update policy", e instanceof Error ? e.message : "Unknown error");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <div className="flex items-center gap-2" style={{ marginBottom: "2px" }}>
        <span style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 600 }}>Mining policy</span>
        <span style={{ color: "var(--accent)", fontSize: "11px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em" }}>
          Basic
        </span>
      </div>
      <div style={{ color: "var(--dim)", fontSize: "13px", marginBottom: "10px" }}>
        The simple choice — how much your node filters, by transaction class. Changing it restarts the node.
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {POLICY_PRESETS.map((p) => {
          const isCurrent = current === p.value;
          return (
            <button
              key={p.value}
              onClick={() => !isCurrent && setPending(p.value)}
              disabled={isCurrent || saving}
              style={{
                textAlign: "left",
                padding: "12px 14px",
                borderRadius: "6px",
                border: `1px solid ${isCurrent ? "var(--accent)" : "var(--rule)"}`,
                background: isCurrent ? "var(--accent-weak)" : "var(--bg)",
                cursor: isCurrent ? "default" : "pointer",
              }}
            >
              <div className="flex items-center gap-2" style={{ marginBottom: "4px" }}>
                <span style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 600 }}>{p.label}</span>
                {isCurrent && (
                  <span style={{ color: "var(--accent)", fontSize: "11px", fontWeight: 600 }}>· current</span>
                )}
              </div>
              <div style={{ color: "var(--dim)", fontSize: "12px", lineHeight: "1.5" }}>{p.desc}</div>
            </button>
          );
        })}
      </div>
      {pending && (
        <div
          style={{
            marginTop: "12px",
            padding: "12px 14px",
            border: "1px solid var(--accent)",
            borderRadius: "6px",
            background: "var(--accent-weak)",
          }}
        >
          <div style={{ color: "var(--fg)", fontSize: "13px", marginBottom: "10px" }}>
            Switch mining policy to <strong>{POLICY_PRESETS.find((p) => p.value === pending)?.label}</strong>? This
            writes the config and <strong>restarts the node</strong> to apply.
          </div>
          <div className="flex items-center gap-2">
            <Button variant="primary" size="sm" onClick={() => apply(pending)} disabled={saving}>
              {saving ? "Applying…" : "Apply & restart"}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setPending(null)} disabled={saving}>
              Cancel
            </Button>
          </div>
        </div>
      )}
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
