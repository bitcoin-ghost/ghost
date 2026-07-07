"use client";

import Link from "next/link";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useNodeStatus, useShares } from "@/hooks/queries/useNodeQueries";

/**
 * Capability Status — every share the node could earn, with two columns:
 *
 *   Claimed   — what this node advertises in its mesh health pings
 *   Qualified — what's actually earning at payout time
 *               (verified by 7d ≥95% peer challenges, ≥2 unique challengers)
 *
 * Drift between the two columns is the diagnostic. Claimed but not qualified
 * means challenges are failing — the row's `hint` line points at where to
 * look (which usually happens to be the page already linked from /settings).
 */

interface Row {
  key: string;
  label: string;
  bonus: number;
  claimed: boolean;
  qualified: boolean;
  hint?: string;
  configHref?: string;
}

function StatusCell({ ok }: { ok: boolean }) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "8px",
        color: ok ? "var(--green)" : "var(--dim)",
        fontFamily: "var(--font-mono)",
        fontSize: "13px",
      }}
    >
      <span
        aria-hidden="true"
        style={{
          width: "8px",
          height: "8px",
          borderRadius: "50%",
          background: ok ? "var(--green)" : "var(--rule-strong)",
          display: "inline-block",
        }}
      />
      {ok ? "yes" : "no"}
    </span>
  );
}

export default function CapabilitiesPage() {
  const { data: status, isLoading: statusLoading } = useNodeStatus();
  const { data: shares, isLoading: sharesLoading } = useShares();

  if (statusLoading || sharesLoading) {
    return (
      <div className="space-y-6">
        <PageHeader
          eyebrow="capabilities"
          title="What this node is earning."
          subtitle="Five capability shares — what you've claimed vs what's actually qualifying for payout."
        />
        <SkeletonCard />
      </div>
    );
  }

  // Claimed = what's set in this node's runtime config (NodeStatus top-level).
  // Qualified = what the mesh has verified via peer challenges (SharesInfo).
  // Both share the same field names but live on different endpoints.
  const q = shares;

  const rows: Row[] = [
    {
      key: "archive",
      label: "Archive",
      bonus: 5,
      claimed: !!status?.archive_mode,
      qualified: !!q?.archive_mode,
      hint: "Requires keeping full block archive. Random block-retrieval challenges from peers must succeed at ≥95% over 7 days.",
      configHref: "/settings/capabilities",
    },
    {
      key: "ghost_pay",
      label: "Ghost Pay",
      bonus: 4,
      claimed: !!status?.ghost_pay,
      qualified: !!q?.ghost_pay,
      hint: "Requires the ghost-pay daemon running on port 8800 (identity-derived TLS). L2 epoch-state challenges must succeed at ≥90%.",
      configHref: "/settings/capabilities",
    },
    {
      key: "public_mining",
      label: "Public Mining",
      bonus: 3,
      claimed: !!status?.public_mining,
      qualified: !!q?.public_mining,
      hint: "Requires SV1 (3333) and SV2 (34255) reachable from peers. Mining mode must be PublicPool with signing_key + public_address set.",
      configHref: "/settings/capabilities",
    },
    {
      key: "reaper",
      label: "Reaper",
      bonus: 2,
      claimed: !!status?.reaper,
      qualified: !!q?.reaper,
      hint: "Requires the BUDS classifier to correctly tier known transactions. Policy challenges must succeed at ≥95%.",
      configHref: "/settings/capabilities",
    },
    {
      key: "elder",
      label: "Elder",
      bonus: 1,
      // Elder status is automatic from MPC registration order — claimed and
      // qualified are the same fact (you either occupy a slot or you don't).
      claimed: !!q?.elder,
      qualified: !!q?.elder,
      hint: "Awarded automatically to the first 101 registered nodes in the MPC ceremony. Position is fixed for the life of the node.",
      configHref: "/elders",
    },
  ];

  const totalQualified = rows.reduce((sum, r) => sum + (r.qualified ? r.bonus : 0), 0);
  const driftRows = rows.filter((r) => r.claimed && !r.qualified);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="capabilities"
        title="What this node is earning."
        subtitle="Five capability shares. The Claimed column is what your node advertises; the Qualified column is what's earning at payout. Drift between them means challenges are failing."
        subtitleFullWidth
        actions={
          <Badge variant={totalQualified === 15 ? "success" : totalQualified >= 6 ? "warning" : "error"}>
            {totalQualified}/15 shares earning
          </Badge>
        }
      />

      <SectionErrorBoundary section="Capability table">
        <Card>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid var(--rule)" }}>
                  <th style={thStyle}>Capability</th>
                  <th style={thStyle}>Bonus</th>
                  <th style={thStyle}>Claimed</th>
                  <th style={thStyle}>Qualified</th>
                  <th style={thStyle}>Configure</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.key} style={{ borderBottom: "1px solid var(--rule)" }}>
                    <td style={tdStyle}>
                      <span style={{ color: "var(--fg)", fontWeight: 500 }}>{row.label}</span>
                    </td>
                    <td style={{ ...tdStyle, fontFamily: "var(--font-mono)", color: "var(--accent)" }}>
                      +{row.bonus}
                    </td>
                    <td style={tdStyle}>
                      <StatusCell ok={row.claimed} />
                    </td>
                    <td style={tdStyle}>
                      <StatusCell ok={row.qualified} />
                    </td>
                    <td style={tdStyle}>
                      {row.configHref && (
                        <Link
                          href={row.configHref}
                          className="bare"
                          style={{
                            color: "var(--dim)",
                            fontSize: "13px",
                            textDecoration: "underline",
                            textDecorationColor: "var(--rule-strong)",
                          }}
                        >
                          edit →
                        </Link>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </SectionErrorBoundary>

      {driftRows.length > 0 && (
        <SectionErrorBoundary section="Drift detail">
          <Card>
            <h3 style={{ color: "var(--fg)", fontSize: "16px", fontWeight: 500, marginBottom: "12px" }}>
              {driftRows.length === 1 ? "1 capability not qualifying" : `${driftRows.length} capabilities not qualifying`}
            </h3>
            <div className="space-y-4">
              {driftRows.map((row) => (
                <div key={row.key} style={{ paddingLeft: "12px", borderLeft: "2px solid var(--accent)" }}>
                  <div style={{ color: "var(--fg)", fontWeight: 500, marginBottom: "4px" }}>
                    {row.label} <span style={{ color: "var(--dim)", fontWeight: 400 }}>(+{row.bonus})</span>
                  </div>
                  <p style={{ color: "var(--dim)", fontSize: "14px", lineHeight: "1.5" }}>{row.hint}</p>
                </div>
              ))}
            </div>
          </Card>
        </SectionErrorBoundary>
      )}

      <p style={{ color: "var(--fainter)", fontSize: "13px" }}>
        Qualification is calculated from peer-issued verification challenges over a 7-day rolling window. A capability counts at payout when ≥10 challenges have completed at ≥95% pass rate (≥90% for Ghost Pay) from at least 2 unique peers.
      </p>
    </div>
  );
}

const thStyle: React.CSSProperties = {
  textAlign: "left",
  padding: "12px 16px",
  fontWeight: 500,
  fontSize: "13px",
  color: "var(--dim)",
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase",
  letterSpacing: "0.06em",
};

const tdStyle: React.CSSProperties = {
  padding: "14px 16px",
  fontSize: "14px",
  verticalAlign: "middle",
};
