"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { StatusDot } from "@/components/ui/StatusDot";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { OverviewView } from "@/components/pool/OverviewView";
import { useNodeInfo, useNodeStatus, useNickname } from "@/hooks/queries/useNodeQueries";
import { useWatchdogStatus } from "@/hooks/queries/useWatchdogQueries";
import { usePoolStatus } from "@/hooks/queries/usePoolQueries";

function ServicesSection() {
  const { data: watchdog, isLoading, error } = useWatchdogStatus();

  if (isLoading) return <SkeletonCard />;
  if (!watchdog) {
    return (
      <Card>
        <CardHeader title="Services" action={<Badge>Unknown</Badge>} />
        <p className="text-sm" style={{ color: "var(--dim)" }}>
          The watchdog did not answer{error instanceof Error ? `: ${error.message}` : ""}. Service
          state is unknown.
        </p>
      </Card>
    );
  }

  const overall = watchdog.overall_health ?? "unknown";
  const dot = overall === "healthy" ? "online" : overall === "degraded" ? "warning" : "offline";

  return (
    <Card>
      <CardHeader
        title="Services"
        action={
          <StatusDot
            status={dot as "online" | "warning" | "offline"}
            pulse={dot === "online"}
            label={overall.charAt(0).toUpperCase() + overall.slice(1)}
          />
        }
      />
      <div className="flex flex-wrap gap-2">
        {(watchdog.services ?? []).map((svc: { name: string; status: string }) => (
          <Badge
            key={svc.name}
            variant={svc.status === "running" ? "success" : svc.status === "stopped" ? "error" : "warning"}
          >
            {svc.name}
          </Badge>
        ))}
      </div>
    </Card>
  );
}

export default function OverviewPage() {
  const { data: info } = useNodeInfo();
  const { data: nickname } = useNickname();
  const node = useNodeStatus();
  const pool = usePoolStatus();

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="overview"
        title="Your Ghost Pool node."
        subtitle={
          nickname?.nickname
            ? `${nickname.nickname} · v${info?.version ?? ""}`
            : info?.version
              ? `v${info.version}`
              : undefined
        }
      />
      <SectionErrorBoundary section="Ghost Pool">
        <OverviewView
          status={pool.data}
          statusError={pool.error ?? undefined}
          statusLoading={pool.isLoading}
          node={node.data}
          nodeError={node.error ?? undefined}
        />
      </SectionErrorBoundary>
      <SectionErrorBoundary section="Services">
        <ServicesSection />
      </SectionErrorBoundary>
    </div>
  );
}
