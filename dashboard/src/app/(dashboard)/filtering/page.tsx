"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { fetchApi } from "@/lib/api/client";
import { useConfig, useFullConfig } from "@/hooks/queries/useConfigQueries";
import { useReaperStatus } from "@/hooks/queries";
import { useAdvancedFilteringGate } from "@/hooks/useAdvancedFilteringGate";
import type { FullNodeConfig } from "@/types/api";

type TierKey = "T0" | "T1" | "T2" | "T3";

interface BudsMempool {
  by_tier?: { T0: number; T1: number; T2: number; T3: number };
  sample_size?: number;
  message?: string;
}

// Plain-English preset name for the stored [policy].profile, normalising the
// legacy `bitcoin_pure` alias to Strict. Returns "Custom" for the custom policy.
function modeLabel(profile?: string): string {
  switch (profile) {
    case "bitcoin_pure":
    case "strict":
      return "Strict";
    case "permissive":
      return "Standard";
    case "full_open":
      return "Open";
    case "custom":
      return "Custom";
    default:
      return profile ? profile : "—";
  }
}

// Headline "what your node does" summary for the mode card: a short value plus a
// one-line plain-English description of what it means for the blocks you build.
// The description is driven by the tiers actually dropped, so a Custom policy
// reads correctly too.
function modeSummary(
  profile: string | undefined,
  dropped: TierKey[],
): { value: string; sublabel: string } {
  switch (profile) {
    case "full_open":
      return { value: "Open", sublabel: "Accepting every kind of transaction" };
    case "permissive":
      return { value: "Standard", sublabel: "T3 not accepted" };
    case "bitcoin_pure":
    case "strict":
      return { value: "Strict", sublabel: "T2 + T3 not accepted" };
    case "custom":
      return dropped.length
        ? { value: "Custom", sublabel: `Rejecting ${dropped.join(" + ")}` }
        : { value: "Custom", sublabel: "Accepting every tier" };
    default:
      return { value: modeLabel(profile), sublabel: "The tier policy this node accepts under" };
  }
}

// Which BUDS tiers this node's policy drops (does not mine). Presets map to a
// fixed set; a custom policy drops any tier whose allow flag is false.
function droppedTiers(
  profile: string | undefined,
  custom?: FullPolicyCustom,
): TierKey[] {
  switch (profile) {
    case "bitcoin_pure":
    case "strict":
      return ["T2", "T3"];
    case "permissive":
      return ["T3"];
    case "full_open":
      return [];
    case "custom": {
      if (!custom) return [];
      const dropped: TierKey[] = [];
      if (!custom.allow_t0) dropped.push("T0");
      if (!custom.allow_t1) dropped.push("T1");
      if (!custom.allow_t2) dropped.push("T2");
      if (!custom.allow_t3) dropped.push("T3");
      return dropped;
    }
    default:
      return [];
  }
}

type FullPolicyCustom = NonNullable<FullNodeConfig["policy"]>["custom"];

function bytes(n?: number): string {
  if (n === undefined || n === null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export default function FilteringOverviewPage() {
  const { data: config } = useConfig();
  const { data: fullConfig } = useFullConfig();
  const { data: reaperStats } = useReaperStatus();
  const { data: mempool } = useQuery({
    queryKey: ["buds-mempool"],
    queryFn: () => fetchApi<BudsMempool>("/api/v1/buds/mempool"),
    refetchInterval: 15_000,
  });

  const [advancedEnabled] = useAdvancedFilteringGate();

  const reaperOn = config?.reaper ?? false;
  const profile = fullConfig?.policy?.profile;
  const dropped = droppedTiers(profile, fullConfig?.policy?.custom);
  const mode = modeSummary(profile, dropped);

  // Live mempool composition from the sampled tier histogram. T0/T1 are ordinary
  // payments; T2/T3 carry data (OP_RETURN, inscriptions, runes). These are the
  // real, per-request counts — not a since-restart artefact.
  const byTier = mempool?.by_tier ?? { T0: 0, T1: 0, T2: 0, T3: 0 };
  const sampled = mempool?.sample_size ?? (byTier.T0 + byTier.T1 + byTier.T2 + byTier.T3);
  const hasSample = !mempool?.message && sampled > 0;
  const paymentsCount = byTier.T0 + byTier.T1;
  const dataCount = byTier.T2 + byTier.T3;
  const paymentsPct = hasSample ? Math.round((paymentsCount / sampled) * 100) : null;
  const dataPct = hasSample ? Math.round((dataCount / sampled) * 100) : null;

  // What THIS node would drop: the share of the current sample sitting in the
  // tiers its policy drops. 0% on Open mode — that's correct, not broken.
  const droppedCount = dropped.reduce((s, t) => s + (byTier[t] ?? 0), 0);
  const pctFiltered = hasSample ? Math.round((droppedCount / sampled) * 100) : null;
  const droppedLabel = dropped.length ? dropped.join(" + ") : "none";

  // Per-block reaper impact — the junk stripped from the block this node most
  // recently built. Uses the per-template snapshot (last_block_*), NOT the
  // cumulative since-restart counters, so it stays honest and current.
  const blockBuilt = reaperStats?.last_block_unix != null;
  const lastBlockDeadBytes = reaperStats?.last_block_dead_bytes ?? 0;
  const lastBlockReaped = reaperStats?.last_block_reaped ?? 0;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="filtering"
        title="Filtering."
        subtitle="Two layers keep your mempool clean — the Reaper rejects spam, and a tier policy picks which transaction classes your node accepts. Filtered transactions never enter your mempool, so they are not relayed or mined. Set it in Basic; fine-tune both in Advanced."
        subtitleFullWidth
      />

      {/* Live, comparative snapshot — what your node does, what's in the
          mempool right now, and what your policy actually removes. */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Mode"
          value={fullConfig ? mode.value : "—"}
          sublabel={fullConfig ? mode.sublabel : undefined}
          tooltip="What your node accepts, in plain English. This is the tier policy — which classes enter your mempool, and therefore the blocks you build."
        />
        <StatCard
          label="Mempool right now"
          value={paymentsPct === null ? "—" : `${paymentsPct}% payments`}
          sublabel={
            dataPct === null
              ? "waiting for a sample"
              : `${dataPct}% carry data · of ${sampled} sampled`
          }
          tooltip="Live make-up of the current mempool from a sample of up to 100 transactions. Payments are simple sends and financial scripts (T0/T1); data-carrying are OP_RETURN, inscriptions and runes (T2/T3)."
        />
        <StatCard
          label="What you'd drop"
          value={pctFiltered === null ? "—" : `${pctFiltered}%`}
          sublabel={
            dropped.length
              ? `${droppedCount} of ${sampled} in ${droppedLabel}`
              : "You accept every tier"
          }
          tooltip="Share of that same live sample sitting in the tiers your policy drops. 0% means your node currently mines everything in the mempool — that's expected on Open mode, not a fault. (This is tier policy only — the Reaper still strips dead-code spam on top of it.)"
        />
        <StatCard
          label="Kept out of your blocks"
          value={
            !reaperOn
              ? "Reaper off"
              : !blockBuilt
                ? "—"
                : lastBlockReaped === 0
                  ? "0"
                  : bytes(lastBlockDeadBytes)
          }
          sublabel={
            !reaperOn
              ? "Not stripping junk"
              : !blockBuilt
                ? "No block built yet"
                : lastBlockReaped === 0
                  ? "Nothing to strip last block"
                  : `${lastBlockReaped} junk tx from your last block`
          }
          tooltip="Dead-code and malformed data the reaper stripped from the last block template this node built. This is per-block, not a running total — it reflects your most recent block only."
        />
      </div>

      {/* How filtering works — plain-English teaching block for newcomers */}
      <Card>
        <CardHeader title="How filtering works" subtitle="Two layers, in plain terms." />
        <div className="space-y-4">
          <div>
            <div className="t-lead" style={{ color: "var(--fg)", fontWeight: 500, marginBottom: "4px" }}>
              The Reaper — your junk filter
            </div>
            <p className="t-body" style={{ color: "var(--dim)", lineHeight: 1.6 }}>
              It rejects specific spam patterns — inscription stuffing, dust floods, oversized data —
              regardless of class, at your mempool. Transactions it catches are never accepted, relayed, or
              mined. The Reaper runs all the time on a sensible default; tune its individual detectors in
              Advanced.
            </p>
          </div>
          <div>
            <div className="t-lead" style={{ color: "var(--fg)", fontWeight: 500, marginBottom: "4px" }}>
              Tier policy (BUDS) — which classes your node accepts
            </div>
            <p className="t-body" style={{ color: "var(--dim)", lineHeight: 1.6 }}>
              Legitimate transactions come in classes, from ordinary payments (T0) up to heavy data (T3).
              This is your choice of which classes your node accepts — and therefore relays and mines.
              Filtered classes are rejected at your mempool, exactly like Bitcoin Core or Knots: they never
              enter it, so they are not relayed on and never appear in the blocks you build. Set it in Basic,
              customise it in Advanced.
            </p>
          </div>
          <div style={{ borderTop: "1px solid var(--rule)", paddingTop: "12px" }}>
            <p className="t-body" style={{ color: "var(--dim)", lineHeight: 1.6 }}>
              In one line: the Reaper is the bouncer that rejects junk at the door; the tier policy is the
              menu deciding which classes your node accepts. Whatever gets in is what you relay and mine — your
              mempool is your block-building set. Basic sets the menu; Advanced tunes both.
            </p>
          </div>
        </div>
      </Card>

      {/* Status readout — which settings are active */}
      <SectionErrorBoundary section="Active settings">
        <Card>
          <CardHeader
            title="What's active"
            subtitle="The filtering your node is running right now."
          />
          <div className="space-y-3">
            <StatusRow
              label="Mode"
              value={modeLabel(profile)}
              desc={
                dropped.length
                  ? `Rejects ${droppedLabel} — accepts everything else.`
                  : profile === "full_open"
                    ? "Accepts every class, including heavy data (T3)."
                    : "The tier policy this node accepts under."
              }
            />
            <StatusRow
              label="Reaper"
              value={reaperOn ? "On" : "Off"}
              desc={
                !reaperOn
                  ? "Not removing dead-code transactions."
                  : !blockBuilt
                    ? "Strips dead-code spam from your mempool relay and block templates — no block built yet this run."
                    : lastBlockReaped === 0
                      ? "Strips dead-code spam from your mempool relay and blocks. Nothing matched in your last block."
                      : `Strips dead-code spam from your mempool relay and blocks — removed ${lastBlockReaped} junk tx (${bytes(lastBlockDeadBytes)}) from your last block.`
              }
            />
            <StatusRow
              label="Advanced controls"
              value={advancedEnabled ? "Enabled" : "Disabled"}
              desc={
                advancedEnabled
                  ? "Per-vector reaper + custom policy controls are unlocked in Advanced."
                  : "Basic presets only. Unlock per-vector controls in Advanced."
              }
            />
            {pctFiltered !== null && (
              <div className="t-caption" style={{ color: "var(--fainter)", lineHeight: "1.5" }}>
                {dropped.length
                  ? `${droppedCount.toLocaleString()} of ${sampled.toLocaleString()} sampled mempool transactions sit in the tiers this node drops (${droppedLabel}).`
                  : `All ${sampled.toLocaleString()} sampled mempool transactions fall in tiers this node mines — nothing is dropped by tier policy.`}{" "}
                A live single-node reading of your current mempool sample — not a standard-vs-reaper-vs-Knots comparison.
                {reaperOn &&
                  " The Reaper is a separate layer on top: it targets specific dead-code/spam patterns (inscription envelopes, drop-stuffing, dust-flood, oversized OP_RETURN…) in both your mempool relay and blocks — so it only removes the handful of transactions that match those patterns, never whole classes. That's why a wide-open tier policy can still show a small reaped count."}
              </div>
            )}
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Where to go next */}
      <SectionErrorBoundary section="Configure filtering">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <NavCard
            href="/filtering/basic"
            title="Basic"
            desc="Pick how much your node filters with one simple choice — the three tier presets, plus a live view of your mempool by class."
          />
          <NavCard
            href="/filtering/advanced"
            title="Advanced"
            desc="Hand-tune the reaper's per-vector spam controls and a full custom tier policy. For confident operators only."
          />
        </div>
      </SectionErrorBoundary>
    </div>
  );
}

function StatusRow({ label, value, desc }: { label: string; value: string; desc: string }) {
  return (
    <div
      style={{
        padding: "12px 14px",
        border: "1px solid var(--rule)",
        borderRadius: "6px",
        background: "var(--bg)",
      }}
    >
      <div className="flex items-center gap-2">
        <span className="t-body" style={{ color: "var(--dim)" }}>{label}</span>
        <span className="t-body" style={{ color: "var(--fg)" }}>{value}</span>
      </div>
      <div className="t-label" style={{ color: "var(--dim)", marginTop: "2px" }}>{desc}</div>
    </div>
  );
}

function NavCard({ href, title, desc }: { href: string; title: string; desc: string }) {
  return (
    <Link href={href} className="bare">
      <Card>
        <div className="flex items-center justify-between gap-3" style={{ marginBottom: "4px" }}>
          <span className="t-title" style={{ color: "var(--fg)" }}>{title}</span>
          <span className="t-label" style={{ color: "var(--accent)", whiteSpace: "nowrap" }}>Open →</span>
        </div>
        <div className="t-label" style={{ color: "var(--dim)", lineHeight: "1.6" }}>{desc}</div>
      </Card>
    </Link>
  );
}
