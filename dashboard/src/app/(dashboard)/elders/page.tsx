"use client";

import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { StatusDot } from "@/components/ui/StatusDot";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { DataTable, truncateId } from "@/components/ui/DataTable";
import { useElderStatus, usePoolStatus } from "@/hooks/queries";
import { fetchApi } from "@/lib/api/client";
import type { ColumnDef } from "@tanstack/react-table";

// --- Types ---

interface MpcStatus {
  contribution_count: number;
  max_contributors: number;
  is_ossified: boolean;
  is_elder: boolean;
  elder_slot: number | null;
  phase: string;
  has_params: boolean;
  node_id: string;
}

interface MpcContributor {
  position: number;
  node_id: string;
  created_at: string;
}

interface MpcContributorsResponse {
  contributors: MpcContributor[];
  count: number;
}

// --- Tooltips ---

const TOOLTIPS = {
  activeElders:
    "Nodes that contributed to the MPC ceremony and maintain 95% uptime over a trailing 7-day window. Elder status grants +1 share in the 5-4-3-2-1 capability system.",
  spotsRemaining:
    "Open slots in the MPC ceremony. Once all 101 positions are filled, the ceremony is ossified and no new elders can join.",
  yourPosition:
    "Your node's position in the MPC ceremony. Position 1 is the genesis contributor. Elder status is permanent and non-transferable.",
  ceremonyStatus:
    "Current state of the multi-party computation ceremony. Active means new contributions are accepted. Ossified means all 101 slots are filled.",
  progressBar:
    "Each MPC contribution adds a layer of randomness to the Groth16 proving parameters. Only one contributor needs to be honest for the parameters to be secure.",
  zkProofInfo:
    "The MPC ceremony generates trusted setup parameters for Groth16 zero-knowledge proofs. These parameters are used to verify node capabilities without revealing private data.",
};

// --- Query keys & hooks ---

const mpcKeys = {
  status: ["mpc", "status"] as const,
  contributors: ["mpc", "contributors"] as const,
};

function useMpcStatus() {
  return useQuery({
    queryKey: mpcKeys.status,
    queryFn: () => fetchApi<MpcStatus>("/api/v1/mpc/status"),
    refetchInterval: 30_000,
  });
}

function useMpcContributors() {
  return useQuery({
    queryKey: mpcKeys.contributors,
    queryFn: () => fetchApi<MpcContributorsResponse>("/api/v1/mpc/contributors"),
    refetchInterval: 30_000,
  });
}

// --- Table columns ---

const contributorColumns: ColumnDef<MpcContributor>[] = [
  {
    accessorKey: "position",
    header: "#",
    cell: ({ row }) => (
      <span className="font-mono text-[color:var(--accent)] font-medium">
        {row.original.position}
      </span>
    ),
  },
  {
    accessorKey: "node_id",
    header: "Node ID",
    cell: ({ row }) => (
      <span className="font-mono text-sm">
        {truncateId(row.original.node_id, 8)}
      </span>
    ),
  },
  {
    id: "status",
    header: "Status",
    cell: () => (
      <StatusDot status="online" label="Contributed" size="sm" />
    ),
  },
  {
    accessorKey: "created_at",
    header: "Contributed",
    cell: ({ row }) => (
      <span className="text-[color:var(--dim)] text-sm">{formatContributed(row.original.created_at)}</span>
    ),
  },
];

// --- Helpers ---

// The backend stores `created_at` as Unix SECONDS (i64 as_secs). Feeding that
// straight to `new Date()` (which expects milliseconds) landed every elder on
// "21 Jan 1970". Coerce to a real timestamp — treat a numeric value below 1e12
// as seconds — and render a full date + time of when the node registered.
function formatContributed(value: string | number): string {
  const n = typeof value === "number" ? value : Number(value);
  let date: Date;
  if (Number.isFinite(n) && n > 0) {
    date = new Date(n < 1e12 ? n * 1000 : n); // seconds → ms, or already ms
  } else {
    date = new Date(value); // fall back to an ISO/date string
  }
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function getCeremonyPhase(mpc: MpcStatus | undefined): {
  label: string;
  variant: "success" | "warning" | "info" | "default";
} {
  if (!mpc) return { label: "Unknown", variant: "default" };
  // Use backend phase field if available
  switch (mpc.phase) {
    case "ossified": return { label: "Ossified", variant: "success" };
    case "contributing": return { label: "Active", variant: "info" };
    case "initializing": return { label: "Awaiting Genesis", variant: "warning" };
  }
  // Fallback
  if (mpc.is_ossified) return { label: "Ossified", variant: "success" };
  if (mpc.contribution_count > 0) return { label: "Active", variant: "info" };
  return { label: "Awaiting Genesis", variant: "warning" };
}

function getYourMpcStatus(
  mpc: MpcStatus | undefined,
  elder: { is_elder?: boolean; elder_slot?: number | null } | undefined,
): { label: string; variant: "success" | "warning" | "info" | "default" } {
  if (!mpc) return { label: "Loading...", variant: "default" };
  // Use MPC status fields directly (more authoritative than elder endpoint)
  if (mpc.is_elder) return { label: `Contributor #${mpc.elder_slot}`, variant: "success" };
  if (elder?.is_elder) return { label: `Contributor #${elder.elder_slot}`, variant: "success" };
  if (mpc.is_ossified) return { label: "Ceremony Closed", variant: "default" };
  return { label: "Not Contributed", variant: "warning" };
}

// --- Page ---

export default function EldersPage() {
  const { data: elder, isLoading: elderLoading } = useElderStatus();
  const { data: pool, isLoading: poolLoading } = usePoolStatus();
  const { data: mpc, isLoading: mpcLoading } = useMpcStatus();
  const { data: contributorsData, isLoading: contributorsLoading } = useMpcContributors();

  const contributors = contributorsData?.contributors ?? [];
  const contributionCount = mpc?.contribution_count ?? 0;
  const maxContributors = mpc?.max_contributors ?? 101;
  const spotsRemaining = maxContributors - contributionCount;
  const ceremonyPhase = getCeremonyPhase(mpc);
  const yourStatus = getYourMpcStatus(mpc, elder);
  const isElder = mpc?.is_elder || elder?.is_elder;
  const elderSlot = mpc?.elder_slot ?? elder?.elder_slot;
  const statsLoading = elderLoading || poolLoading || mpcLoading;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        eyebrow="elders & mpc"
        title="Quorum members and ceremony."
        subtitle="MPC ceremony status, elder registry, and zero-knowledge proof parameters"
        subtitleFullWidth
        actions={
          isElder && elderSlot != null ? (
            <Badge variant="success">Elder #{elderSlot}</Badge>
          ) : undefined
        }
      />

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Active Elders"
          value={elder ? `${elder.active_elders ?? 0} / 101` : "--"}
          sublabel={pool ? `of ${pool.active_nodes ?? 0} active nodes` : undefined}
          tooltip={TOOLTIPS.activeElders}
          loading={statsLoading}
        />
        <StatCard
          label="Spots Remaining"
          value={mpc ? spotsRemaining : "--"}
          sublabel={mpc?.is_ossified ? "Ceremony ossified" : "Open for contributions"}
          tooltip={TOOLTIPS.spotsRemaining}
          loading={statsLoading}
        />
        <StatCard
          label="Your Position"
          value={isElder ? `#${elderSlot}` : "None"}
          sublabel={isElder ? "MPC contributor" : "Not an elder"}
          tooltip={TOOLTIPS.yourPosition}
          loading={statsLoading}
        />
        <StatCard
          label="Ceremony Status"
          value={ceremonyPhase.label}
          sublabel={`${contributionCount} / ${maxContributors} contributions`}
          tooltip={TOOLTIPS.ceremonyStatus}
          loading={statsLoading}
        />
      </div>

      {/* MPC Ceremony Card */}
      <SectionErrorBoundary section="MPC Ceremony">
        {mpcLoading ? (
          <SkeletonCard />
        ) : (
          <Card>
            <CardHeader
              title="MPC Ceremony"
              subtitle="Multi-Party Computation for Groth16 trusted setup"
              action={
                <Badge variant={ceremonyPhase.variant}>{ceremonyPhase.label}</Badge>
              }
            />
            <div className="space-y-5">
              {/* Progress */}
              <ProgressBar
                value={contributionCount}
                max={maxContributors}
                label="Contributions"
                sublabel={`${contributionCount} / ${maxContributors}`}
                color={mpc?.is_ossified ? "green" : "orange"}
                size="lg"
              />

              {/* Details grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-3 bg-[var(--surface)] rounded-lg">
                  <div className="text-xs text-[color:var(--dim)] mb-1">Phase</div>
                  <Badge variant={ceremonyPhase.variant}>{ceremonyPhase.label}</Badge>
                </div>
                <div className="p-3 bg-[var(--surface)] rounded-lg">
                  <div className="text-xs text-[color:var(--dim)] mb-1">Your Status</div>
                  <Badge variant={yourStatus.variant}>{yourStatus.label}</Badge>
                </div>
                <div className="p-3 bg-[var(--surface)] rounded-lg">
                  <div className="text-xs text-[color:var(--dim)] mb-1">Circuit Type</div>
                  <span className="font-mono text-sm text-[color:var(--fg)]">Groth16</span>
                </div>
                <div className="p-3 bg-[var(--surface)] rounded-lg">
                  <div className="text-xs text-[color:var(--dim)] mb-1">Parameters</div>
                  <StatusDot
                    status={mpc?.has_params ? "online" : "offline"}
                    label={mpc?.has_params ? "Generated" : "Pending"}
                    size="sm"
                  />
                </div>
              </div>

              {/* Downtime warning */}
              {elder?.downtime_warning && (
                <div className="p-3 bg-[var(--surface)] border border-[color:var(--yellow)] rounded-lg">
                  <p className="text-[color:var(--yellow)] text-sm font-medium">
                    Downtime Warning
                  </p>
                  <p className="text-[color:var(--yellow)] text-sm mt-1">
                    {elder.consecutive_downtime_days} consecutive days of downtime detected.
                    Elder status requires 95% uptime over a trailing 7-day window.
                  </p>
                </div>
              )}
            </div>
          </Card>
        )}
      </SectionErrorBoundary>

      {/* Elder Registry Table */}
      <SectionErrorBoundary section="Elder Registry">
        <Card>
          <CardHeader
            title="Elder Registry"
            subtitle={`${contributorsData?.count ?? contributors.length} MPC contributors`}
            action={
              mpc?.node_id ? (
                <span className="text-xs text-[color:var(--fainter)] font-mono">
                  You: {truncateId(mpc.node_id, 6)}
                </span>
              ) : undefined
            }
          />
          <DataTable
            columns={contributorColumns}
            data={contributors}
            loading={contributorsLoading}
            emptyMessage="No MPC contributors yet"
            emptyDescription="The genesis node initiates the ceremony with the first contribution"
            searchColumn="node_id"
            searchPlaceholder="Search by node ID..."
            showPagination={contributors.length > 10}
          />
        </Card>
      </SectionErrorBoundary>

      {/* ZK Proof Info (Collapsible) */}
      <SectionErrorBoundary section="ZK Proof Info">
        <Card>
          <CardHeader
            title="Zero-Knowledge Proof Info"
            subtitle="How the MPC ceremony secures the network"
          />
          <div className="space-y-4 text-sm text-[color:var(--dim)] leading-relaxed">
            <div>
              <h4 className="t-title mb-1" style={{ color: "var(--fg)" }}>What is the MPC Ceremony?</h4>
              <p>
                The Multi-Party Computation (MPC) ceremony generates trusted setup parameters
                for Groth16 zero-knowledge proofs. Each of the 101 contributors adds a layer of
                cryptographic randomness. As long as at least one contributor is honest and
                destroys their secret, the parameters are secure.
              </p>
            </div>
            <div>
              <h4 className="t-title mb-1" style={{ color: "var(--fg)" }}>Why Groth16?</h4>
              <p>
                Groth16 produces the smallest proofs (just 3 group elements, ~128 bytes) with the
                fastest verification time of any general-purpose ZK proof system. The tradeoff is
                requiring a trusted setup, which the MPC ceremony provides.
              </p>
            </div>
            <div>
              <h4 className="t-title mb-1" style={{ color: "var(--fg)" }}>Elder Status</h4>
              <p>
                Nodes that contribute to the MPC ceremony earn permanent Elder status, granting +1
                share in the 5-4-3-2-1 capability system. The first 101 nodes to contribute claim
                permanent positions. Elder status is non-transferable -- if an elder goes offline
                permanently, their position is lost forever.
              </p>
            </div>
            <div>
              <h4 className="t-title mb-1" style={{ color: "var(--fg)" }}>Ossification</h4>
              <p>
                Once all 101 slots are filled, the ceremony is ossified. No new contributions
                can be accepted and the parameters are finalized. The ceremony cannot be restarted
                or modified after ossification.
              </p>
            </div>
            <div className="pt-2 border-t border-[var(--rule)]">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-[color:var(--fainter)]">Circuit</span>
                  <p className="text-[color:var(--fg)] font-mono">Groth16 (BN254)</p>
                </div>
                <div>
                  <span className="text-[color:var(--fainter)]">Max Contributors</span>
                  <p className="text-[color:var(--fg)] font-mono">101</p>
                </div>
                <div>
                  <span className="text-[color:var(--fainter)]">Proof Size</span>
                  <p className="text-[color:var(--fg)] font-mono">~128 bytes</p>
                </div>
                <div>
                  <span className="text-[color:var(--fainter)]">Share Bonus</span>
                  <p className="text-[color:var(--fg)] font-mono">+1 (Elder)</p>
                </div>
              </div>
            </div>
          </div>
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}
