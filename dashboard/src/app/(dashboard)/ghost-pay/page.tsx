"use client";

import { Card } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { Toggle } from "@/components/ui/Toggle";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { EmptyState } from "@/components/ui/EmptyState";
import {
  useGhostPayStatus,
  useSettlement,
  useL2TreeState,
  useL2FeeDistributionContext,
  useGhostPayPayoutHistory,
  useShares,
  useNodeStatus,
  useFullConfig,
  useSetGhostPay,
} from "@/hooks/queries";

/**
 * Ghost Pay — operator view of the L2 this node helps run.
 *
 * Ghost Pay is Ghost's L2 for fast, private payments. Sending and receiving
 * live in the wallet; this page is purely the node operator's read on the L2
 * they help run: is it alive and busy, is it settling to L1, and what is the
 * node earning for running it. Every value here is a live backend field —
 * nothing is synthesised. Sections whose data is genuinely empty say so
 * honestly rather than rendering a misleading zero.
 */

function formatL2Block(era: number, height: number): string {
  if (era <= 1) return height.toLocaleString();
  return `${era}:${height.toLocaleString()}`;
}

function formatSats(sats?: number | null): string {
  if (sats == null) return "0 sats";
  return `${sats.toLocaleString()} sats`;
}

function shortId(id?: string): string {
  if (!id) return "—";
  return id.length > 12 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id;
}

function formatWhen(ts?: number | null): string {
  if (!ts) return "—";
  // Backend timestamps are unix seconds.
  const d = new Date(ts * 1000);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

const labelStyle: React.CSSProperties = {
  color: "var(--dim)",
  fontSize: "13px",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
  letterSpacing: "0.06em",
};

const valueStyle: React.CSSProperties = {
  color: "var(--fg)",
  fontSize: "14px",
  fontFamily: "var(--font-mono)",
};

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: "16px",
        padding: "12px 0",
        borderBottom: "1px solid var(--rule)",
      }}
    >
      <span style={labelStyle}>{label}</span>
      <span style={valueStyle}>{children}</span>
    </div>
  );
}

function SectionTitle({ title, subtitle, action }: { title: string; subtitle?: string; action?: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "16px", marginBottom: "16px" }}>
      <div>
        <h2 style={{ color: "var(--fg)", fontSize: "16px", fontWeight: 500 }}>{title}</h2>
        {subtitle && <p style={{ color: "var(--dim)", fontSize: "13px", marginTop: "4px", lineHeight: 1.5 }}>{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export default function GhostPayPage() {
  const { data: status, isLoading: statusLoading, error: statusError } = useGhostPayStatus();
  const { data: tree } = useL2TreeState();
  const { data: settlement } = useSettlement();
  const { data: feeContext } = useL2FeeDistributionContext();
  const { data: payoutHistory } = useGhostPayPayoutHistory("all");
  const { data: shares } = useShares();
  const { data: nodeStatus } = useNodeStatus();
  const { data: fullConfig } = useFullConfig();
  const setGhostPay = useSetGhostPay();

  // Not reachable at all — ghost-pay service down / dashboard can't sign.
  if (!statusLoading && statusError) {
    return (
      <div className="space-y-6">
        <PageHeader
          eyebrow="ghost pay"
          title="Your node's view of the L2."
          subtitle="Ghost Pay is Ghost's L2 for fast private payments. Sending lives in the wallet — this is your node's view of the L2 it helps run."
        />
        <Card>
          <EmptyState
            icon={
              <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 18.75a60.07 60.07 0 0115.797 2.101c.727.198 1.453-.342 1.453-1.096V18.75M3.75 4.5v.75A.75.75 0 013 6h-.75m0 0v-.375c0-.621.504-1.125 1.125-1.125H20.25M2.25 6v9m18-10.5v.75c0 .414.336.75.75.75h.75m-1.5-1.5h.375c.621 0 1.125.504 1.125 1.125v9.75c0 .621-.504 1.125-1.125 1.125h-.375m1.5-1.5H21a.75.75 0 00-.75.75v.75m0 0H3.75m0 0h-.375a1.125 1.125 0 01-1.125-1.125V15m1.5 1.5v-.75A.75.75 0 003 15h-.75M15 10.5a3 3 0 11-6 0 3 3 0 016 0zm3 0h.008v.008H18V10.5zm-12 0h.008v.008H6V10.5z" />
              </svg>
            }
            title="Ghost Pay is not reachable"
            description="The ghost-pay service on this node isn't responding. Enable Ghost Pay in Settings, or check the ghost-pay daemon on port 8800."
            action={
              <a href="/settings" className="bare" style={{ color: "var(--accent)", fontSize: "14px" }}>
                Go to Settings →
              </a>
            }
          />
        </Card>
      </div>
    );
  }

  const l2Era = status?.l2_era ?? 1;
  const l2Height = status?.l2_height ?? status?.virtual_block ?? 0;
  const epoch = status?.epoch ?? 0;
  const syncState = status?.sync_state;
  const enabled = status?.enabled ?? false;
  const peerCount = status?.peer_count ?? 0;

  // Settlement (flat backend shape from /api/v1/settlement/status).
  const last = settlement?.last_settlement as
    | { batch_id?: string; total_amount_sats?: number; l1_txid?: string | null; finalized_at?: number | null }
    | null
    | undefined;
  const pendingSettlements = settlement?.pending_count ?? settlement?.pending_settlements ?? 0;
  const totalSettled = settlement?.total_settled_sats ?? 0;
  const settlementStatus = settlement?.status ?? "idle";

  // Earnings.
  const capabilityClaimed = !!nodeStatus?.ghost_pay || !!fullConfig?.ghost_pay;
  const capabilityQualified = !!shares?.ghost_pay;
  const ghostPayNodeCount = feeContext?.ghost_pay_nodes?.length ?? 0;
  const payoutCount = payoutHistory?.total ?? payoutHistory?.payouts?.length ?? 0;

  // Config.
  const ghostPayOn = !!fullConfig?.ghost_pay;

  return (
    <div className="space-y-6">
      {/* 1. Header + one-line explainer (replaces the old privacy-layer cards). */}
      <PageHeader
        eyebrow="ghost pay"
        title="Your node's view of the L2."
        subtitle="Ghost Pay is Ghost's L2 for fast private payments. Sending lives in the wallet — this is your node's view of the L2 it helps run: is it alive, settling to L1, and earning."
      />

      {/* 1b. Primary control — enable Ghost Pay, up top. Pruning of L2 state is
           mandatory and automatic, so there is no pruning knob here. */}
      <SectionErrorBoundary section="Ghost Pay">
        <Card>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "16px" }}>
            <div>
              <div style={{ color: "var(--fg)", fontSize: "15px", fontWeight: 500 }}>Ghost Pay L2</div>
              <div style={{ color: "var(--dim)", fontSize: "13px", marginTop: "2px", lineHeight: 1.5 }}>
                Run the L2 payments layer and earn the +4 capability share. L2 state pruning is mandatory and handled automatically.
              </div>
            </div>
            <Toggle
              label="Ghost Pay L2"
              enabled={ghostPayOn}
              disabled={setGhostPay.isPending}
              onChange={(v) => setGhostPay.mutate(v)}
            />
          </div>
          {setGhostPay.isError && (
            <p style={{ color: "var(--red)", fontSize: "13px", marginTop: "8px" }}>
              Failed to update Ghost Pay setting. Try again.
            </p>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* 2. Status strip — is the L2 alive and busy. */}
      <SectionErrorBoundary section="L2 status">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            label="Ghost Pay"
            value={enabled ? (syncState === "synced" ? "Synced" : syncState ?? "Running") : "Disabled"}
            sublabel={status?.network ?? undefined}
            loading={statusLoading}
          />
          <StatCard
            label="L2 Height"
            value={status ? formatL2Block(l2Era, l2Height) : "—"}
            sublabel={`epoch ${epoch}`}
            loading={statusLoading}
          />
          <StatCard
            label="L2 Notes"
            value={tree ? (tree.note_count ?? 0).toLocaleString() : "—"}
            sublabel={`tree epoch ${tree?.epoch ?? 0}`}
            tooltip="Commitment-tree note count from /api/v1/l2/tree-state — the live size of the L2 note set this node tracks."
            loading={statusLoading}
          />
          <StatCard
            label="Mesh Peers"
            value={peerCount}
            sublabel={status?.uptime_secs != null ? `${Math.floor(status.uptime_secs / 3600)}h uptime` : undefined}
            loading={statusLoading}
          />
        </div>
      </SectionErrorBoundary>

      {/* 3. Settlement to L1 — the genuinely operator-relevant reconciliation view. */}
      <SectionErrorBoundary section="Settlement to L1">
        <Card>
          <SectionTitle
            title="Settlement to L1"
            subtitle="Batched L2 → L1 reconciliation. When L2 activity accumulates, the node bundles it into a batch and settles on-chain."
            action={
              pendingSettlements > 0
                ? <Badge variant="warning">{pendingSettlements} pending</Badge>
                : settlementStatus === "processing"
                  ? <Badge variant="info">processing</Badge>
                  : <Badge variant="default">idle</Badge>
            }
          />
          <div>
            <Field label="Pending batches">{pendingSettlements}</Field>
            <Field label="Total settled">{formatSats(totalSettled)}</Field>
            <Field label="Last batch id">{last?.batch_id ? shortId(last.batch_id) : "—"}</Field>
            <Field label="Last batch amount">{last ? formatSats(last.total_amount_sats) : "—"}</Field>
            <Field label="Last L1 txid">{last?.l1_txid ? shortId(last.l1_txid) : "—"}</Field>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "16px", padding: "12px 0" }}>
              <span style={labelStyle}>Last settled at</span>
              <span style={valueStyle}>{formatWhen(last?.finalized_at)}</span>
            </div>
          </div>
          {pendingSettlements === 0 && !last && (
            <p style={{ color: "var(--fainter)", fontSize: "13px", marginTop: "4px", lineHeight: 1.5 }}>
              No settlement batches yet. Batches appear here once L2 activity is reconciled to L1.
            </p>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* 4. Your L2 earnings — fees the node earns + capability qualification. */}
      <SectionErrorBoundary section="L2 earnings">
        <Card>
          <SectionTitle
            title="Your L2 earnings"
            subtitle="Running Ghost Pay earns your node a +4 capability share and a cut of L2 fees, paid from the treasury pool once it reaches threshold."
            action={
              capabilityQualified
                ? <Badge variant="success">Ghost Pay qualified · +4</Badge>
                : capabilityClaimed
                  ? <Badge variant="warning">Claimed · not qualified</Badge>
                  : <Badge variant="default">Not claimed</Badge>
            }
          />
          <div>
            <Field label="Capability">
              {capabilityQualified ? "Qualified (+4 shares)" : capabilityClaimed ? "Claimed, awaiting challenges" : "Off"}
            </Field>
            <Field label="Nodes sharing L2 fees">{ghostPayNodeCount}</Field>
            <Field label="Your payout records">{payoutCount}</Field>
          </div>
          <p style={{ color: "var(--fainter)", fontSize: "13px", marginTop: "12px", lineHeight: 1.5 }}>
            {capabilityQualified
              ? "Your node is verified as Ghost Pay-capable and shares in L2 fee distribution. "
              : "The +4 share counts at payout only once peer challenges qualify the capability. "}
            L2 fee reference: transfers 10 sats + 0.1%, Wraith mix 1%. Fees accrue to the treasury pool and distribute to qualified nodes.{" "}
            <a href="/capabilities" className="bare" style={{ color: "var(--accent)", textDecoration: "underline", textDecorationColor: "var(--rule-strong)" }}>
              Capability detail →
            </a>
          </p>
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}
