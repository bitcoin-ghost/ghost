"use client";

import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { fetchApi } from "@/lib/api/client";
import { useMiningStatus } from "@/hooks/queries";

/**
 * Capacity & load-balancer view.
 *
 * Pulls `/api/internal/pool-nodes` (the same endpoint the colocated
 * translator polls every 30 s) and renders this node's utilisation against
 * its hardware-derived `max_capacity`, plus every peer's utilisation so the
 * operator can see whether the mesh is balanced or skewed.
 */

interface PoolNode {
  miner_count: number;
  max_capacity: number;
  public_address?: string;
  public_mining?: boolean;
  last_seen?: number;
  // Deduplicated share of the mesh-wide active-miner total attributed to this
  // node. Unlike the raw `miner_count` (kept for the load-balancer utilisation
  // view), these DO sum to the deduped `mesh_active_miners` total because each
  // unique miner is owned by exactly one node. Absent on pre-redeploy nodes.
  deduped_miner_count?: number;
}

interface PoolNodesResponse {
  this_node: PoolNode;
  peers: PoolNode[];
}

async function fetchPoolNodes(): Promise<PoolNodesResponse> {
  // Route through the proxy (fetchApi) so the HMAC-signed internal request
  // reaches ghost-pool; a bare fetch hits the Next server and always 404s,
  // which previously left this page rendering only an error card.
  return fetchApi<PoolNodesResponse>("/api/internal/pool-nodes");
}

function utilPct(n: PoolNode): number {
  if (!n.max_capacity || n.max_capacity === 0) return 0;
  return Math.round((n.miner_count * 100) / n.max_capacity);
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
  const { data, isLoading, error } = useQuery<PoolNodesResponse>({
    queryKey: ["pool-nodes"],
    queryFn: fetchPoolNodes,
    refetchInterval: 30_000,
  });

  // Authoritative, DEDUPED mesh miner total. The per-peer `miner_count`s below
  // are a load-balancer routing view: a miner that reconnects or fails over
  // between nodes is momentarily counted on more than one peer, so summing the
  // rows over-counts (e.g. rows total 7–9 while the real distinct total is 6).
  // `mining/status` already de-duplicates across the mesh, so source the total
  // from there instead of adding up the breakdown.
  // Backend follow-up: dedupe the per-peer capacity miner_counts at the source.
  const { data: miningStatus } = useMiningStatus();
  const meshTotal = miningStatus?.mesh_active_miners ?? miningStatus?.connected_miners;

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader
          eyebrow="capacity"
          title="Hardware utilisation."
          subtitle="Each node's miner count vs its hardware-derived capacity ceiling."
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
            Could not reach <code>/api/internal/pool-nodes</code>.{" "}
            {error instanceof Error ? error.message : "Unknown error"}
          </p>
        </Card>
      </div>
    );
  }

  const me = data.this_node;
  const myPct = utilPct(me);

  // Post-redeploy nodes report a `deduped_miner_count` per node that sums to the
  // deduped mesh total. When present, the peer table shows those (labelled just
  // "Miners") and drops the "don't sum" caveat. Pre-redeploy nodes omit it, so
  // we fall back to the raw routed `miner_count` and keep the caveat.
  const dedupAvailable = me.deduped_miner_count !== undefined;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="capacity"
        title="Hardware utilisation."
        subtitle="Each node's miner count vs its hardware-derived capacity ceiling. The translator's load balancer routes new connections to the under-utilised peer."
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
            <Stat label="connected miners" value={me.miner_count.toLocaleString()} />
            <Stat label="capacity ceiling" value={me.max_capacity.toLocaleString()} />
            <Stat label="utilisation" value={`${myPct}%`} accent={utilColor(myPct)} />
            <Stat
              label="state"
              value={
                myPct >= 95
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

          <UtilisationBar pct={myPct} label={`${me.miner_count} of ${me.max_capacity} (${myPct}%)`} />
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
              {data.peers.length === 0
                ? "No peers reporting capacity yet — showing this node only."
                : `${data.peers.length} ${data.peers.length === 1 ? "peer" : "peers"} plus this node reporting capacity. New miner connections route to the lowest utilisation %.`}
            </p>
            {meshTotal !== undefined && (
              <p style={{ color: "var(--fainter)", fontSize: "12px", marginTop: "8px" }}>
                <strong style={{ color: "var(--fg)" }}>{meshTotal}</strong> distinct active{" "}
                {meshTotal === 1 ? "miner" : "miners"} across the mesh (deduplicated).{" "}
                {dedupAvailable ? (
                  <>
                    Each miner is owned by exactly one node, so the per-node counts below —{" "}
                    <em>this node included</em> — sum to this total.
                  </>
                ) : (
                  <>
                    The per-node counts below are a routing view and may overlap — a miner failing
                    over between nodes appears on more than one node, so{" "}
                    <em>don&apos;t sum the rows</em>.
                  </>
                )}
              </p>
            )}
          </div>

          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--rule)" }}>
                  <th style={thStyle}>Node</th>
                  <th style={thStyle}>{dedupAvailable ? "Miners" : "Miners (routed)"}</th>
                  <th style={thStyle}>Capacity</th>
                  <th style={thStyle}>Utilisation</th>
                  <th style={{ ...thStyle, width: "30%" }}>&nbsp;</th>
                </tr>
              </thead>
              <tbody>
                {/* This node is part of the deduplicated total, so it belongs in
                    the breakdown — otherwise the visible per-node counts under-
                    report the mesh (they'd sum to the peers' share only). */}
                <MeshRow node={me} isSelf dedupAvailable={dedupAvailable} />
                {data.peers
                  .slice()
                  .sort((a, b) => utilPct(a) - utilPct(b))
                  .map((p, idx) => (
                    <MeshRow
                      key={p.public_address ?? idx}
                      node={p}
                      isSelf={false}
                      dedupAvailable={dedupAvailable}
                    />
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

function MeshRow({
  node,
  isSelf,
  dedupAvailable,
}: {
  node: PoolNode;
  isSelf: boolean;
  dedupAvailable: boolean;
}) {
  const pct = utilPct(node);
  // this_node carries no public_address; label it explicitly.
  const label = isSelf ? "this node" : node.public_address?.split(":")[0] ?? "?";
  // Deduped view = unique miners owned by this node; routed view = raw
  // connection count (may overlap across nodes).
  const miners = dedupAvailable ? node.deduped_miner_count ?? 0 : node.miner_count;
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
        {node.public_mining === false && (
          <Badge variant="warning" className="ml-2">
            non-public
          </Badge>
        )}
      </td>
      <td style={{ ...tdStyle, fontFamily: "var(--font-mono)" }}>{miners}</td>
      <td style={{ ...tdStyle, fontFamily: "var(--font-mono)", color: "var(--dim)" }}>
        {node.max_capacity || "—"}
      </td>
      <td style={{ ...tdStyle, fontFamily: "var(--font-mono)", color: utilColor(pct) }}>
        {node.max_capacity ? `${pct}%` : "—"}
      </td>
      <td style={tdStyle}>
        <UtilisationBar pct={node.max_capacity ? pct : 0} />
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
