"use client";

import { Card } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Badge } from "@/components/ui/Badge";
import { Toggle } from "@/components/ui/Toggle";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { useToast } from "@/components/ui/Toast";
import { useGhostPayStatus, useWraithStats, useSetWraith } from "@/hooks/queries";

/**
 * Wraith — operator view of the CoinJoin mixing this node helps coordinate.
 *
 * Wraith is Ghost's CoinJoin mixing on the L2. Choosing amounts and mixing
 * your own coins happens in the wallet; this page is purely the node
 * operator's read on the mixing the node facilitates: is it enabled, is it
 * hosting sessions right now, and how much mixing has it coordinated. Every
 * value here is a live backend field — nothing is synthesised. Sections with
 * genuinely empty data say so honestly rather than rendering a misleading zero.
 */

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
      <span className="t-label-mono" style={{ color: "var(--dim)" }}>{label}</span>
      <span className="t-body" style={{ color: "var(--fg)", fontFamily: "var(--font-mono)" }}>{children}</span>
    </div>
  );
}

function SectionTitle({ title, subtitle, action }: { title: string; subtitle?: string; action?: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "16px", marginBottom: "16px" }}>
      <div>
        <h2 className="t-title" style={{ color: "var(--fg)" }}>{title}</h2>
        {subtitle && <p className="t-caption" style={{ color: "var(--dim)", marginTop: "4px" }}>{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export default function WraithPage() {
  const { data: status, isLoading: statusLoading, error: statusError } = useGhostPayStatus();
  const { data: wraithStats, isLoading: wraithLoading } = useWraithStats();
  const setWraith = useSetWraith();
  const { success, error } = useToast();

  const handleWraithToggle = async (enabled: boolean) => {
    try {
      await setWraith.mutateAsync(enabled);
      success("Saved", `Wraith mixing ${enabled ? "enabled" : "disabled"} — restart ghost-pool to apply`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  // Not reachable at all — ghost-pay service down / dashboard can't reach it.
  if (!statusLoading && statusError) {
    return (
      <div className="space-y-6">
        <PageHeader
          eyebrow="wraith"
          title="Your node's view of the mixing."
          subtitle="Wraith is Ghost's CoinJoin mixing on the L2. Choosing amounts and mixing your own coins happens in the wallet — this is your node's view of the mixing it helps coordinate."
        />
        <Card>
          <EmptyState
            icon={
              <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m6-2.457a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            }
            title="Wraith status is not reachable"
            description="The ghost-pay service on this node isn't responding, so mixing status is unavailable. Enable Ghost Pay in Settings, or check the ghost-pay daemon on port 8800."
            action={
              <a href="/settings" className="bare t-body" style={{ color: "var(--accent)" }}>
                Go to Settings →
              </a>
            }
          />
        </Card>
      </div>
    );
  }

  const wraithEnabled = status?.wraith_enabled ?? false;
  const hostsMixing = status?.ghostpay_hosts_mixing ?? false;

  const activeSessions = wraithStats?.active_sessions ?? 0;
  const totalSessions = wraithStats?.total_sessions ?? 0;
  const sessionsCompleted = wraithStats?.sessions_completed ?? 0;
  const sessionsExpired = wraithStats?.sessions_expired ?? 0;
  const totalParticipants = wraithStats?.total_participants ?? 0;

  const noActivity = totalSessions === 0 && activeSessions === 0 && sessionsCompleted === 0 && totalParticipants === 0;

  return (
    <div className="space-y-6">
      {/* 1. Header + one-line explainer (replaces the old wallet-brochure cards). */}
      <PageHeader
        eyebrow="wraith"
        title="Your node's view of the mixing."
        subtitle="Wraith is Ghost's CoinJoin mixing on the L2. Choosing amounts and mixing your own coins happens in the wallet — this is your node's view of the mixing it helps coordinate."
        actions={
          status ? (
            <Badge variant={wraithEnabled ? (hostsMixing ? "success" : "warning") : "default"}>
              {wraithEnabled ? (hostsMixing ? "Hosting mixing" : "Enabled · idle") : "Disabled"}
            </Badge>
          ) : undefined
        }
      />

      {/* 1b. Primary control — enable Wraith mixing, up top (mirrors Ghost Pay).
           The enable switch is the lead card; telemetry follows below. */}
      <SectionErrorBoundary section="Wraith">
        <Card>
          {statusLoading ? (
            <SkeletonCard />
          ) : (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "16px" }}>
              <div>
                <div className="t-lead" style={{ color: "var(--fg)", fontWeight: 500 }}>Wraith mixing</div>
                <div className="t-caption" style={{ color: "var(--dim)", marginTop: "2px", maxWidth: "36rem" }}>
                  When enabled, any L2 participant can initiate a CoinJoin session through this node. Off means the node won&apos;t coordinate mixing. A ghost-pool restart applies the change.
                </div>
              </div>
              <Toggle
                label="Wraith mixing"
                enabled={wraithEnabled}
                disabled={setWraith.isPending}
                onChange={handleWraithToggle}
              />
            </div>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* 2. Status strip — is mixing enabled and busy on this node. */}
      <SectionErrorBoundary section="Wraith status">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            label="Wraith"
            value={wraithEnabled ? "Enabled" : "Disabled"}
            sublabel={wraithEnabled ? (hostsMixing ? "hosting mixing" : "idle") : undefined}
            loading={statusLoading}
          />
          <StatCard
            label="Active Sessions"
            value={activeSessions}
            sublabel="mixing now"
            loading={statusLoading || wraithLoading}
          />
          <StatCard
            label="Completed"
            value={sessionsCompleted.toLocaleString()}
            sublabel={`${totalSessions.toLocaleString()} total`}
            loading={statusLoading || wraithLoading}
          />
          <StatCard
            label="Participants Served"
            value={totalParticipants.toLocaleString()}
            loading={statusLoading || wraithLoading}
          />
        </div>
      </SectionErrorBoundary>

      {/* 3. Mixing activity — the sessions this node has coordinated. */}
      <SectionErrorBoundary section="Mixing activity">
        <Card>
          <SectionTitle
            title="Mixing activity"
            subtitle="CoinJoin sessions this node has helped coordinate. Participants register equal-denomination inputs; the node relays the round to completion."
            action={
              activeSessions > 0
                ? <Badge variant="info">{activeSessions} active</Badge>
                : <Badge variant="default">idle</Badge>
            }
          />
          <div>
            <Field label="Active sessions">{activeSessions.toLocaleString()}</Field>
            <Field label="Total sessions">{totalSessions.toLocaleString()}</Field>
            <Field label="Completed">{sessionsCompleted.toLocaleString()}</Field>
            <Field label="Expired">{sessionsExpired.toLocaleString()}</Field>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "16px", padding: "12px 0" }}>
              <span className="t-label-mono" style={{ color: "var(--dim)" }}>Participants served</span>
              <span className="t-body" style={{ color: "var(--fg)", fontFamily: "var(--font-mono)" }}>{totalParticipants.toLocaleString()}</span>
            </div>
          </div>
          {noActivity && (
            <p className="t-caption" style={{ color: "var(--fainter)", marginTop: "4px" }}>
              {wraithEnabled
                ? "No mixing sessions yet. Sessions appear here once wallet participants begin mixing through this node."
                : "Wraith mixing is disabled on this node, so it is not coordinating any sessions. Enable it above to participate."}
            </p>
          )}
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}
