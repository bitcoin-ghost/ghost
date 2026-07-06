"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useMeshNodes } from "@/hooks/queries";
import type { MeshNode } from "@/lib/api/meshNodes";

/**
 * Capacity & load-balancer view.
 *
 * Sourced from `/api/v1/pool/mesh-nodes` — the SAME live mesh-node list the
 * Swarm and Geo pages and the deduped mesh-wide active-miner total (Watchdog's
 * `mesh_active_miners`) are built from — so the table covers the WHOLE fleet,
 * not just the `public_mining` capacity reporters the load-balancer
 * `pool-nodes` path filtered to. Each node carries a `deduped_miner_count`
 * (every unique miner is owned by exactly one node, so these sum to the deduped
 * mesh total) and its hardware-derived `max_capacity`. Nodes that haven't
 * gossiped a capacity ceiling yet are shown with an "unknown" marker rather
 * than being dropped, keeping the visible node set == the deduped-total set.
 */

// Utilisation from the DEDUPED miner count (the honest per-node figure) over
// the node's capacity ceiling. Unknown capacity (0) yields 0% and renders "—".
function utilPct(n: MeshNode): number {
  const cap = n.max_capacity ?? 0;
  if (!cap) return 0;
  return Math.round((n.deduped_miner_count * 100) / cap);
}

function hasCapacity(n: MeshNode): boolean {
  return (n.max_capacity ?? 0) > 0;
}

function utilColor(pct: number): string {
  if (pct >= 95) return "var(--red)";
  if (pct >= 90) return "var(--accent)";
  if (pct >= 80) return "var(--accent)";
  return "var(--green)";
}

function UtilisationBar({ pct, label }: { pct: number; label?: string }) {
  return (
    <div style={{ width: "100%" }}>
      <div
        style={{
          height: "8px",
          background: "var(--rule)",
          borderRadius: "2px",
          overflow: "hidden",
          position: "relative",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${Math.min(100, pct)}%`,
            background: utilColor(pct),
            transition: "width 200ms",
          }}
        />
      </div>
      {label && (
        <div
          style={{
            marginTop: "4px",
            fontSize: "12px",
            fontFamily: "var(--font-mono)",
            color: "var(--dim)",
          }}
        >
          {label}
        </div>
      )}
    </div>
  );
}

export default function CapacityPage() {
  const { data, isLoading, error } = useMeshNodes();

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader
          eyebrow="capacity"
          title="Hardware utilisation."
          subtitle="Each node's miner count vs its hardware-derived capacity ceiling."
          subtitleFullWidth
        />
        <SkeletonCard />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="space-y-6">
        <PageHeader
          eyebrow="capacity"
          title="Hardware utilisation."
        />
        <Card>
          <p style={{ color: "var(--dim)" }}>
            Could not reach <code>/api/v1/pool/mesh-nodes</code>.{" "}
            {error instanceof Error ? error.message : "Unknown error"}
          </p>
        </Card>
      </div>
    );
  }

  const nodes = data.nodes ?? [];
  const me = nodes.find((n) => n.is_self);
  const myMiners = me?.deduped_miner_count ?? 0;
  const myCapacity = me?.max_capacity ?? 0;
  const myPct = myCapacity ? Math.round((myMiners * 100) / myCapacity) : 0;

  // Distinct active miners across the mesh = sum of every node's deduped share.
  // Because each unique miner is owned by exactly one node, this equals the
  // deduped `mesh_active_miners` grand total the Watchdog reports — and, being
  // computed from the SAME rows shown below, it is guaranteed to equal the
  // visible sum. No more header/table mismatch.
  const distinctMiners = nodes.reduce((sum, n) => sum + (n.deduped_miner_count ?? 0), 0);
  const capacityUnknown = nodes.filter((n) => !hasCapacity(n)).length;

  // Sort the table: self first, then by ascending utilisation (nodes with a
  // known capacity ranked by load; unknown-capacity nodes sink to the bottom).
  const sorted = nodes.slice().sort((a, b) => {
    if (a.is_self !== b.is_self) return a.is_self ? -1 : 1;
    const aKnown = hasCapacity(a);
    const bKnown = hasCapacity(b);
    if (aKnown !== bKnown) return aKnown ? -1 : 1;
    return utilPct(a) - utilPct(b);
  });

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="capacity"
        title="Hardware utilisation."
        subtitle="Each node's miner count vs its hardware-derived capacity ceiling. The translator's load balancer routes new connections to the under-utilised peer."
        subtitleFullWidth
        actions={
          <Badge
            variant={myPct >= 90 ? "error" : myPct >= 80 ? "warning" : "success"}
          >
            this node: {myPct}%
          </Badge>
        }
      />

      {/* This node summary */}
      <SectionErrorBoundary section="This node">
        <Card>
          <div style={{ marginBottom: "16px" }}>
            <h3 style={{ color: "var(--fg)", fontSize: "16px", fontWeight: 500, marginBottom: "4px" }}>
              This node
            </h3>
            <p style={{ color: "var(--dim)", fontSize: "13px" }}>
              Hardware-derived ceiling. Operator&apos;s <code>network.max_miners</code> can throttle this DOWN, never UP.
            </p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mb-6">
            <Stat label="connected miners" value={myMiners.toLocaleString()} />
            <Stat label="capacity ceiling" value={myCapacity ? myCapacity.toLocaleString() : "—"} />
            <Stat label="utilisation" value={myCapacity ? `${myPct}%` : "—"} accent={utilColor(myPct)} />
            <Stat
              label="state"
              value={
                !myCapacity
                  ? "unknown"
                  : myPct >= 95
                  ? "critical"
                  : myPct >= 90
                  ? "reject new"
                  : myPct >= 80
                  ? "warning"
                  : "normal"
              }
              accent={utilColor(myPct)}
            />
          </div>

          <UtilisationBar
            pct={myPct}
            label={myCapacity ? `${myMiners} of ${myCapacity} (${myPct}%)` : `${myMiners} miners · capacity unknown`}
          />
        </Card>
      </SectionErrorBoundary>

      {/* Peer mesh utilisation */}
      <SectionErrorBoundary section="Peers">
        <Card>
          <div style={{ marginBottom: "16px" }}>
            <h3 style={{ color: "var(--fg)", fontSize: "16px", fontWeight: 500, marginBottom: "4px" }}>
              Peer mesh
            </h3>
            <p style={{ color: "var(--dim)", fontSize: "13px" }}>
              {nodes.length} {nodes.length === 1 ? "node" : "nodes"} across the mesh ·{" "}
              <strong style={{ color: "var(--fg)" }}>{distinctMiners}</strong> distinct active{" "}
              {distinctMiners === 1 ? "miner" : "miners"} (deduplicated). Each miner is owned by
              exactly one node, so the per-node counts below sum to this total.
              {capacityUnknown > 0 && (
                <>
                  {" "}
                  {capacityUnknown} {capacityUnknown === 1 ? "node has" : "nodes have"} not gossiped a
                  capacity ceiling yet (shown as <code>—</code>).
                </>
              )}
            </p>
          </div>

          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--rule)" }}>
                  <th style={thStyle}>Node</th>
                  <th style={thStyle}>Miners</th>
                  <th style={thStyle}>Capacity</th>
                  <th style={thStyle}>Utilisation</th>
                  <th style={{ ...thStyle, width: "30%" }}>&nbsp;</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((node, idx) => (
                  <MeshRow key={node.node_id || node.address || idx} node={node} />
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </SectionErrorBoundary>

      <p style={{ color: "var(--fainter)", fontSize: "13px" }}>
        Capacity is hardware-derived (
        <code>min(ram_mb / 3, cpu_cores * 500, fd_limit / 4)</code>) at startup. Operator&apos;s{" "}
        <code>network.max_miners</code> in <code>pool.toml</code> can throttle below the calculated value but cannot exceed
        it. Translator load-balancer thresholds: 80% warn, 90% reject new, 95% critical.
      </p>
    </div>
  );
}

function MeshRow({ node }: { node: MeshNode }) {
  const known = hasCapacity(node);
  const pct = utilPct(node);
  const isSelf = node.is_self;
  // this_node carries no public_address in some deploys; label it explicitly.
  const label = isSelf ? "this node" : node.address?.split(":")[0] || "?";
  const capacity = node.max_capacity ?? 0;
  return (
    <tr
      style={{
        borderBottom: "1px solid var(--rule)",
        background: isSelf ? "var(--rule)" : undefined,
      }}
    >
      <td style={tdStyle}>
        <code style={{ color: "var(--fg)", fontSize: "13px" }}>{label}</code>
        {isSelf && (
          <Badge variant="info" className="ml-2">
            you
          </Badge>
        )}
        {!node.capabilities?.public_mining && (
          <Badge variant="warning" className="ml-2">
            non-public
          </Badge>
        )}
        {!known && (
          <Badge variant="warning" className="ml-2">
            capacity unknown
          </Badge>
        )}
      </td>
      <td style={{ ...tdStyle, fontFamily: "var(--font-mono)" }}>{node.deduped_miner_count ?? 0}</td>
      <td style={{ ...tdStyle, fontFamily: "var(--font-mono)", color: "var(--dim)" }}>
        {known ? capacity : "—"}
      </td>
      <td style={{ ...tdStyle, fontFamily: "var(--font-mono)", color: utilColor(pct) }}>
        {known ? `${pct}%` : "—"}
      </td>
      <td style={tdStyle}>
        <UtilisationBar pct={known ? pct : 0} />
      </td>
    </tr>
  );
}

function Stat({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div>
      <div
        style={{
          fontSize: "11px",
          fontFamily: "var(--font-mono)",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          color: "var(--dim)",
          marginBottom: "4px",
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: "24px",
          fontWeight: 500,
          color: accent ?? "var(--fg)",
          fontFamily: "var(--font-mono)",
        }}
      >
        {value}
      </div>
    </div>
  );
}

const thStyle: React.CSSProperties = {
  textAlign: "left",
  padding: "10px 12px",
  fontWeight: 500,
  fontSize: "12px",
  color: "var(--dim)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
  letterSpacing: "0.06em",
};

const tdStyle: React.CSSProperties = {
  padding: "12px",
  fontSize: "14px",
  verticalAlign: "middle",
};
