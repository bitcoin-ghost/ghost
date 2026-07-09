"use client";

import type { CSSProperties, ReactNode } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useConfig, useFullConfig } from "@/hooks/queries/useConfigQueries";
import { useFilteringActivity } from "@/hooks/queries/useFilteringQueries";
import { useAdvancedFilteringGate } from "@/hooks/useAdvancedFilteringGate";
import type { FullNodeConfig } from "@/types/api";

type TierKey = "T0" | "T1" | "T2" | "T3";

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

export default function FilteringOverviewPage() {
  const { data: config } = useConfig();
  const { data: fullConfig } = useFullConfig();
  const [advancedEnabled] = useAdvancedFilteringGate();

  const reaperOn = config?.reaper ?? false;
  const profile = fullConfig?.policy?.profile;
  const dropped = droppedTiers(profile, fullConfig?.policy?.custom);
  const droppedLabel = dropped.length ? dropped.join(" + ") : "none";

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="filtering"
        title="Filtering."
        subtitle="What your node filters. Set it in Basic, fine-tune in Advanced."
      />

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
                reaperOn
                  ? "Strips dead-code spam from your mempool relay and block templates."
                  : "Not removing dead-code spam."
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
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* How filtering works — short two-line explainer for newcomers */}
      <Card>
        <CardHeader title="How filtering works" subtitle="Two layers, in plain terms." />
        <div className="space-y-2">
          <p className="t-body" style={{ color: "var(--dim)", lineHeight: 1.6 }}>
            The Reaper rejects spam — inscription stuffing, dust floods, oversized data — at your
            mempool, so it is never relayed or mined.
          </p>
          <p className="t-body" style={{ color: "var(--dim)", lineHeight: 1.6 }}>
            The tier policy (BUDS) picks which transaction classes your node accepts — and your
            mempool is exactly the set your blocks build from.
          </p>
        </div>
      </Card>

      {/* What the node has actually rejected, and where */}
      <SectionErrorBoundary section="Filtering activity">
        <FilteringActivityCard />
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

// A count that renders "—" when we have no data (endpoint 404 during rollout).
const dash = "—";

// Human byte size — B / KB / MB. Bytes here are virtual bytes (vbytes).
function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

// "Filtering activity" — what this node has rejected, and where, since it
// started. Reads the cumulative per-stage counters and lays them out as
// summary tiles (the glance) → a two-stage funnel (teaches the shape) → a
// detail table (the exact numbers). Degrades to a calm "no rejections yet"
// state when the endpoint is absent (older nodes 404) or all counts are zero.
function FilteringActivityCard() {
  const { data, isLoading } = useFilteringActivity();

  // No payload: still loading, or the endpoint isn't wired on this node yet.
  const haveData = !!data;

  const s1Reaper = data?.stage1_mempool.reaper ?? { txs: 0, vbytes: 0 };
  const s1Tier = data?.stage1_mempool.tier ?? { txs: 0, vbytes: 0 };
  const s2Reaper = data?.stage2_block.reaper ?? { txs: 0, vbytes: 0 };

  const keptOut = s1Reaper.txs + s1Tier.txs;
  const stripped = s2Reaper.txs;
  const totalRejected = data?.totals.rejected_txs ?? 0;
  const totalBytes = s1Reaper.vbytes + s1Tier.vbytes + s2Reaper.vbytes;

  // Nothing to show: either no data, or the node has rejected nothing so far.
  const nothingYet = haveData && totalRejected === 0 && keptOut === 0 && stripped === 0;

  // Render a count, or "—" when we have no data to stand behind it.
  const count = (n: number) => (haveData ? n.toLocaleString() : dash);
  const bytes = (n: number) => (haveData ? formatBytes(n) : dash);

  return (
    <Card>
      <CardHeader
        title="Filtering activity"
        subtitle="What your node has rejected, and where — since it started."
      />

      {isLoading && !haveData ? (
        <p className="t-body" style={{ color: "var(--dim)" }}>Loading…</p>
      ) : (
        <div className="space-y-6">
          {/* Summary tiles — the glance */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <SummaryTile label="Kept out of your mempool" value={count(keptOut)} />
            <SummaryTile label="Stripped from your block" value={count(stripped)} />
            <SummaryTile label="Total rejected" value={count(totalRejected)} />
          </div>

          {(nothingYet || !haveData) && (
            <p className="t-label" style={{ color: "var(--dim)" }}>
              {haveData
                ? "No rejections yet — nothing junk has reached this node so far."
                : "No rejections recorded yet — this node hasn't reported filtering activity."}
            </p>
          )}

          {/* Funnel — teaches the two stages, top to bottom */}
          <div>
            <FunnelEndcap label="Transactions in" />
            <FunnelConnector />
            <StagePanel
              stage="Stage 1 · Your mempool"
              note="Not kept, relayed, or mined."
              filters={[
                { label: "Reaper rejected", value: count(s1Reaper.txs) },
                { label: "Tier policy rejected", value: count(s1Tier.txs) },
              ]}
            />
            <FunnelConnector caption="accepted" />
            <StagePanel
              stage="Stage 2 · Your block"
              note="Stripped when building the block."
              filters={[{ label: "Reaper stripped", value: count(s2Reaper.txs) }]}
            />
            <FunnelConnector />
            <FunnelEndcap label="Your block" />
          </div>

          {/* Detail table — the exact numbers. Open by default; we don't hide reference. */}
          <details open>
            <summary
              className="t-label"
              style={{ color: "var(--dim)", cursor: "pointer", marginBottom: "8px" }}
            >
              Details
            </summary>
            <div style={{ overflowX: "auto" }}>
              <table className="t-label" style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--rule)" }}>
                    <ActivityTh>Stage</ActivityTh>
                    <ActivityTh>Filter</ActivityTh>
                    <ActivityTh align="right">Rejected txs</ActivityTh>
                    <ActivityTh align="right">Bytes</ActivityTh>
                  </tr>
                </thead>
                <tbody>
                  <ActivityRow
                    stage="Stage 1 · Your mempool"
                    filter="Reaper"
                    txs={count(s1Reaper.txs)}
                    bytes={bytes(s1Reaper.vbytes)}
                  />
                  <ActivityRow
                    stage="Stage 1 · Your mempool"
                    filter="Tier policy"
                    txs={count(s1Tier.txs)}
                    bytes={bytes(s1Tier.vbytes)}
                  />
                  <ActivityRow
                    stage="Stage 2 · Your block"
                    filter="Reaper"
                    txs={count(s2Reaper.txs)}
                    bytes={bytes(s2Reaper.vbytes)}
                  />
                  <tr style={{ borderTop: "1px solid var(--rule-strong)" }}>
                    <ActivityTd style={{ color: "var(--fg)" }}>Total</ActivityTd>
                    <ActivityTd />
                    <ActivityTd align="right" style={{ color: "var(--fg)" }}>
                      {count(totalRejected)}
                    </ActivityTd>
                    <ActivityTd align="right" style={{ color: "var(--fg)" }}>
                      {bytes(totalBytes)}
                    </ActivityTd>
                  </tr>
                </tbody>
              </table>
            </div>
          </details>
        </div>
      )}
    </Card>
  );
}

function SummaryTile({ label, value }: { label: string; value: string }) {
  return (
    <div
      style={{
        padding: "12px 14px",
        border: "1px solid var(--rule)",
        borderRadius: "6px",
        background: "var(--bg)",
      }}
    >
      <div className="t-caption" style={{ color: "var(--dim)" }}>{label}</div>
      <div
        className="t-stat"
        style={{ color: "var(--fg)", marginTop: "4px", fontVariantNumeric: "tabular-nums" }}
      >
        {value}
      </div>
    </div>
  );
}

// A labelled endpoint of the funnel (top = junk in, bottom = clean block out).
function FunnelEndcap({ label }: { label: string }) {
  return (
    <div className="t-label" style={{ color: "var(--dim)", textAlign: "center" }}>
      {label}
    </div>
  );
}

// The vertical rule + arrow that connects two funnel stages, with an optional
// caption (e.g. "accepted") describing what flows through.
function FunnelConnector({ caption }: { caption?: string }) {
  return (
    <div
      className="flex flex-col items-center"
      style={{ color: "var(--dim)", padding: "6px 0" }}
    >
      <div style={{ width: "1px", height: "10px", background: "var(--rule-strong)" }} />
      <div className="t-caption" style={{ lineHeight: 1 }} aria-hidden>↓</div>
      {caption && <div className="t-caption" style={{ marginTop: "2px" }}>{caption}</div>}
    </div>
  );
}

// One stage of the funnel: a bordered panel listing its filters and counts.
function StagePanel({
  stage,
  note,
  filters,
}: {
  stage: string;
  note: string;
  filters: { label: string; value: string }[];
}) {
  return (
    <div
      style={{
        padding: "14px 16px",
        border: "1px solid var(--rule)",
        borderRadius: "6px",
        background: "var(--bg)",
      }}
    >
      <div className="t-body" style={{ color: "var(--fg)" }}>{stage}</div>
      <div className="t-caption" style={{ color: "var(--dim)", marginTop: "1px" }}>{note}</div>
      <div className="space-y-1" style={{ marginTop: "10px" }}>
        {filters.map((f) => (
          <div key={f.label} className="flex items-baseline justify-between gap-3">
            <span className="t-label" style={{ color: "var(--dim)" }}>{f.label}</span>
            <span
              className="t-body"
              style={{ color: "var(--accent)", fontVariantNumeric: "tabular-nums" }}
            >
              {f.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ActivityTh({
  children,
  align = "left",
}: {
  children?: ReactNode;
  align?: "left" | "right";
}) {
  return (
    <th
      className="t-caption"
      style={{ color: "var(--dim)", fontWeight: 400, textAlign: align, padding: "6px 8px" }}
    >
      {children}
    </th>
  );
}

function ActivityTd({
  children,
  align = "left",
  style,
}: {
  children?: ReactNode;
  align?: "left" | "right";
  style?: CSSProperties;
}) {
  return (
    <td
      style={{
        color: "var(--dim)",
        textAlign: align,
        padding: "6px 8px",
        fontVariantNumeric: "tabular-nums",
        ...style,
      }}
    >
      {children}
    </td>
  );
}

function ActivityRow({
  stage,
  filter,
  txs,
  bytes,
}: {
  stage: string;
  filter: string;
  txs: string;
  bytes: string;
}) {
  return (
    <tr style={{ borderBottom: "1px solid var(--rule)" }}>
      <ActivityTd>{stage}</ActivityTd>
      <ActivityTd style={{ color: "var(--fg)" }}>{filter}</ActivityTd>
      <ActivityTd align="right">{txs}</ActivityTd>
      <ActivityTd align="right">{bytes}</ActivityTd>
    </tr>
  );
}
