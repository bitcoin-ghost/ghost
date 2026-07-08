"use client";

import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Toggle } from "@/components/ui/Toggle";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { ReaperControls } from "@/components/filtering/ReaperControls";
import { AdvancedPolicyPanel } from "@/components/filtering/AdvancedPolicyPanel";
import { fetchApi } from "@/lib/api/client";
import { useReaperStatus } from "@/hooks/queries";
import { useAdvancedFilteringGate } from "@/hooks/useAdvancedFilteringGate";
import { BUDS_TIER_COLORS, BUDS_TIER_KEYS } from "@/lib/budsTiers";

interface BudsMempool {
  by_tier?: { T0: number; T1: number; T2: number; T3: number };
  sample_size?: number;
  message?: string;
}

function bytes(n?: number): string {
  if (n === undefined || n === null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

// Live context strip for the controls below. These pages are otherwise
// controls-only, so an operator tuning the Reaper's per-vector rejects and
// thresholds has no readout of what's actually in the mempool or what the
// Reaper is currently stripping. This reuses the exact same sources as the
// /filtering overview: the sampled BUDS-tier histogram and the Reaper's
// per-block counters. Compact by design — it's context, not the main content.
function ReaperLiveContext() {
  const { data: mempool } = useQuery({
    queryKey: ["buds-mempool"],
    queryFn: () => fetchApi<BudsMempool>("/api/v1/buds/mempool"),
    refetchInterval: 15_000,
  });
  const { data: reaper } = useReaperStatus();

  const byTier = mempool?.by_tier ?? { T0: 0, T1: 0, T2: 0, T3: 0 };
  const sampled = mempool?.sample_size ?? (byTier.T0 + byTier.T1 + byTier.T2 + byTier.T3);
  const hasSample = !mempool?.message && sampled > 0;

  const blockBuilt = reaper?.last_block_unix != null;
  const lastReaped = reaper?.last_block_reaped ?? 0;
  const lastDeadBytes = reaper?.last_block_dead_bytes ?? 0;

  return (
    <Card>
      <div className="flex items-center justify-between gap-3" style={{ marginBottom: "10px" }}>
        <span className="t-eyebrow" style={{ color: "var(--dim)" }}>Live Reaper context</span>
        <span className="t-caption" style={{ color: "var(--fainter)" }}>
          the current picture your Reaper settings act on
        </span>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Mempool make-up right now, by BUDS class */}
        <div>
          <div className="t-label" style={{ color: "var(--fg)", marginBottom: "6px" }}>
            Mempool by class
          </div>
          {hasSample ? (
            <>
              <div style={{ display: "flex", height: "12px", borderRadius: "4px", overflow: "hidden", background: "var(--bg)" }}>
                {BUDS_TIER_KEYS.map((k) => {
                  const count = byTier[k] ?? 0;
                  const pct = sampled ? (count / sampled) * 100 : 0;
                  if (pct === 0) return null;
                  return <div key={k} title={`${k}: ${count}`} style={{ width: `${pct}%`, background: BUDS_TIER_COLORS[k] }} />;
                })}
              </div>
              <div className="flex items-center gap-3" style={{ marginTop: "6px", flexWrap: "wrap" }}>
                {BUDS_TIER_KEYS.map((k) => (
                  <span key={k} className="t-caption flex items-center gap-1" style={{ color: "var(--dim)" }}>
                    <span style={{ width: "8px", height: "8px", borderRadius: "2px", background: BUDS_TIER_COLORS[k], display: "inline-block" }} />
                    {k} {(byTier[k] ?? 0).toLocaleString()}
                  </span>
                ))}
                <span className="t-caption" style={{ color: "var(--fainter)" }}>· {sampled.toLocaleString()} sampled</span>
              </div>
            </>
          ) : (
            <div className="t-caption" style={{ color: "var(--dim)" }}>
              {mempool?.message ? `Classification unavailable — ${mempool.message}` : "Waiting for a mempool sample…"}
            </div>
          )}
        </div>

        {/* What the Reaper has been stripping */}
        <div>
          <div className="t-label" style={{ color: "var(--fg)", marginBottom: "6px" }}>
            Recently reaped
          </div>
          <div className="flex items-baseline gap-2">
            <span className="t-stat" style={{ color: "var(--fg)", fontFamily: "var(--font-mono)" }}>
              {!blockBuilt ? "—" : bytes(lastDeadBytes)}
            </span>
            <span className="t-caption" style={{ color: "var(--dim)" }}>
              {!blockBuilt ? "no block built yet" : `${lastReaped} junk tx from your last block`}
            </span>
          </div>
          {reaper && (
            <div className="t-caption" style={{ color: "var(--fainter)", marginTop: "4px" }}>
              {reaper.txs_reaped.toLocaleString()} tx · {bytes(reaper.dead_bytes_total)} stripped since restart
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}

export default function AdvancedFilteringPage() {
  const [enabled, setEnabled] = useAdvancedFilteringGate();

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="filtering"
        title="Advanced."
        subtitle="Hand-tune exactly what your node relays and mines: dead-code/spam vectors (Reaper) and per-tier / size / content limits (Custom policy). Only for confident operators; the Basic presets cover most needs."
        subtitleFullWidth
      />

      {/* Live context for the Reaper controls below — mempool make-up and what
          the Reaper is currently stripping, so the tuning below isn't blind. */}
      <SectionErrorBoundary section="Live Reaper context">
        <ReaperLiveContext />
      </SectionErrorBoundary>

      {/* Enable gate — controls stay hidden until deliberately switched on */}
      <Card>
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="t-title" style={{ color: "var(--fg)" }}>Enable advanced controls</div>
            <div className="t-label" style={{ color: "var(--dim)", lineHeight: "1.6", marginTop: "4px" }}>
              Off by default. When on, the reaper vectors and custom mining policy below become editable.
              This switch is per-browser only — it does not change your node until you save a control below.
            </div>
          </div>
          <Toggle enabled={enabled} onChange={setEnabled} label="Enable advanced controls" />
        </div>
      </Card>

      {enabled && (
        <>
          <SectionErrorBoundary section="Reaper">
            <ReaperControls />
          </SectionErrorBoundary>

          <SectionErrorBoundary section="Custom policy">
            <Card>
              <CardHeader
                title="Custom mining policy"
                subtitle="The full per-field counterpart to the Basic presets — every knob the block builder enforces. Includes the block fee floor (Min fee rate)."
              />
              <AdvancedPolicyPanel />
            </Card>
          </SectionErrorBoundary>
        </>
      )}
    </div>
  );
}
