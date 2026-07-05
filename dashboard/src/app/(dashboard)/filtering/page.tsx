"use client";

import Link from "next/link";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useConfig } from "@/hooks/queries/useConfigQueries";
import { useReaperStatus } from "@/hooks/queries";

// Plain-English names for the tier policy the node mines under, so operators
// never have to see the raw `permissive` / `bitcoin_pure` / `full_open` keys.
function policyLabel(profile?: string): string {
  switch (profile) {
    case "bitcoin_pure":
      return "Bitcoin-only";
    case "permissive":
      return "Standard";
    case "full_open":
      return "Everything";
    default:
      return profile ? profile : "—";
  }
}

function bytes(n?: number): string {
  if (n === undefined || n === null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export default function FilteringOverviewPage() {
  const { data: config } = useConfig();
  const { data: reaperStats } = useReaperStatus();

  const reaperOn = config?.reaper ?? false;
  const hasBlock = !!reaperStats && reaperStats.last_block_unix != null;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="filtering"
        title="Filtering."
        subtitle="What your node lets in, and what it mines. Every transaction is sorted into a class (BUDS) and passed through two filters — one for your mempool, one for the blocks you build."
        subtitleFullWidth
      />

      {/* Status tiles */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Reaper"
          value={reaperOn ? "On" : "Off"}
          sublabel={reaperOn ? "stripping junk" : "not filtering"}
          tooltip="Whether the reaper is enabled. When on, it removes dead-code transactions from your mempool and the blocks you build."
        />
        <StatCard
          label="Mining policy"
          value={policyLabel(config?.template_profile)}
          sublabel="classes you'll mine"
          tooltip="The tier policy applied when building blocks. Standard mines T0–T2; Bitcoin-only mines T0–T1; Everything mines all classes including T3."
        />
        <StatCard
          label="Reaped this block"
          value={hasBlock ? reaperStats!.last_block_reaped.toLocaleString() : "—"}
          sublabel={hasBlock ? "junk txs dropped" : "no block yet"}
          tooltip="Transactions the reaper dropped from the block your node is currently building. Per-block, not cumulative."
        />
        <StatCard
          label="Dead weight cut"
          value={hasBlock ? bytes(reaperStats!.last_block_dead_bytes) : "—"}
          sublabel="reclaimed for real txs"
          tooltip="Bytes of dead code stripped from the current block, returned to fee-paying transactions."
        />
      </div>

      {/* Funnel explainer */}
      <SectionErrorBoundary section="How filtering works">
        <Card>
          <CardHeader
            title="How filtering works"
            subtitle="Transactions flow through two gates. Follow the funnel from top to bottom."
          />
          <Funnel reaperOn={reaperOn} />
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}

// ─── the funnel: incoming → mempool gate → your mempool → block gate → block ──

function Funnel({ reaperOn }: { reaperOn: boolean }) {
  return (
    <div className="space-y-2">
      <FunnelNode label="Incoming transactions" desc="Everything the network sends your node." tone="neutral" />
      <Arrow />
      <FunnelGate
        title="Gate 1 · What you keep"
        desc="The mempool reaper decides what your node stores and relays. Junk (inscriptions, runestones, dust) can be turned away here."
        control={{ label: "Reaper settings", href: "/reaper" }}
        active={reaperOn}
      />
      <Arrow />
      <FunnelNode
        label="Your mempool"
        desc="What's left is sorted into four BUDS classes — from ordinary payments (T0) to abusive data (T3)."
        tone="accent"
        control={{ label: "See the classes", href: "/filtering/buds" }}
      />
      <Arrow />
      <FunnelGate
        title="Gate 2 · What you mine"
        desc="When building a block, the reaper strips dead code and your policy drops whole classes you've chosen not to mine (e.g. no T3)."
        control={{ label: "Policy & classes", href: "/filtering/buds" }}
        active={reaperOn}
      />
      <Arrow />
      <FunnelNode label="The block you build" desc="Clean, fee-paying transactions — the block your node mines." tone="success" />
    </div>
  );
}

function FunnelNode({
  label,
  desc,
  tone,
  control,
}: {
  label: string;
  desc: string;
  tone: "neutral" | "accent" | "success";
  control?: { label: string; href: string };
}) {
  const border =
    tone === "success" ? "#3fb95055" : tone === "accent" ? "var(--accent)" : "var(--rule)";
  const bg = tone === "neutral" ? "var(--bg)" : "var(--surface)";
  return (
    <div
      style={{
        padding: "12px 14px",
        border: `1px solid ${border}`,
        borderRadius: "6px",
        background: bg,
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        gap: "12px",
        flexWrap: "wrap",
      }}
    >
      <div>
        <div style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 600 }}>{label}</div>
        <div style={{ color: "var(--dim)", fontSize: "13px", marginTop: "2px" }}>{desc}</div>
      </div>
      {control && (
        <Link
          href={control.href}
          className="bare"
          style={{ color: "var(--accent)", textDecoration: "underline", fontSize: "13px", whiteSpace: "nowrap" }}
        >
          {control.label} →
        </Link>
      )}
    </div>
  );
}

function FunnelGate({
  title,
  desc,
  control,
  active,
}: {
  title: string;
  desc: string;
  control: { label: string; href: string };
  active: boolean;
}) {
  return (
    <div
      style={{
        padding: "12px 14px",
        border: `1px dashed ${active ? "var(--accent)" : "var(--rule)"}`,
        borderRadius: "6px",
        background: "var(--bg)",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
        <div style={{ color: active ? "var(--accent)" : "var(--dim)", fontSize: "13px", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em" }}>
          {title}
        </div>
        <Link
          href={control.href}
          className="bare"
          style={{ color: "var(--fg)", textDecoration: "underline", fontSize: "13px", whiteSpace: "nowrap" }}
        >
          {control.label} →
        </Link>
      </div>
      <div style={{ color: "var(--dim)", fontSize: "13px", marginTop: "4px" }}>{desc}</div>
    </div>
  );
}

function Arrow() {
  return (
    <div style={{ textAlign: "center", color: "var(--fainter)", fontSize: "14px", lineHeight: "1" }}>↓</div>
  );
}
