"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { EmptyState } from "@/components/ui/EmptyState";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Dialog } from "@/components/ui/Dialog";
import { SkeletonTable } from "@/components/ui/Skeleton";
import { useWatchdogStatus, useWatchdogEvents, useStartService, useStopService, useRestartService, useResourceStatus } from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import { clearSystemCache } from "@/lib/api/watchdog";

type ServiceAction = "start" | "stop" | "restart";


function formatTimestamp(timestamp: number): string {
  if (!timestamp) return "—";
  // Backend timestamps are Unix seconds; guard against values already in ms.
  const ms = timestamp < 1e12 ? timestamp * 1000 : timestamp;
  return new Date(ms).toLocaleString();
}

// A component/service is "running" when it reports an active state. Anything
// else (stopped, error, unknown, not_enabled) should offer Start, not Stop.
function isRunningStatus(status: string): boolean {
  return status === "ok" || status === "running" || status === "syncing";
}

function getStatusBadge(status: string): { variant: "success" | "warning" | "error" | "info" | "default"; label: string } {
  switch (status) {
    case "ok":
    case "running":
      return { variant: "success", label: "Running" };
    case "syncing":
      return { variant: "info", label: "Syncing" };
    case "stopped":
      return { variant: "default", label: "Stopped" };
    case "not_enabled":
      return { variant: "default", label: "Not Enabled" };
    case "error":
    case "unknown":
      return { variant: "error", label: "Error" };
    default:
      return { variant: "default", label: status };
  }
}

function getEventBadge(eventType: "restart" | "failure" | "recovery" | "warning"): { variant: "success" | "warning" | "error" | "info"; label: string } {
  switch (eventType) {
    case "restart":
      return { variant: "info", label: "Restart" };
    case "failure":
      return { variant: "error", label: "Failure" };
    case "recovery":
      return { variant: "success", label: "Recovered" };
    case "warning":
      return { variant: "warning", label: "Warning" };
    default:
      return { variant: "info", label: eventType };
  }
}

function getHealthBadge(health: string): { variant: "success" | "warning" | "error"; label: string } {
  switch (health) {
    case "healthy":
      return { variant: "success", label: "Healthy" };
    case "degraded":
      return { variant: "warning", label: "Degraded" };
    case "unhealthy":
      return { variant: "error", label: "Unhealthy" };
    default:
      return { variant: "warning", label: health };
  }
}

function getResourceBadge(status: string): { variant: "success" | "warning" | "error"; label: string } {
  switch (status) {
    case "healthy":
      return { variant: "success", label: "Healthy" };
    case "warning":
      return { variant: "warning", label: "Warning" };
    case "critical":
      return { variant: "error", label: "Critical" };
    default:
      return { variant: "warning", label: status };
  }
}

function resourceColor(value: number, warnThreshold: number, critThreshold: number): "green" | "yellow" | "red" {
  if (value >= critThreshold) return "red";
  if (value >= warnThreshold) return "yellow";
  return "green";
}

export default function WatchdogPage() {
  const { data: status, isLoading: statusLoading } = useWatchdogStatus();
  const { data: eventsData, isLoading: eventsLoading } = useWatchdogEvents(50);
  const { data: resourceStatus, isLoading: resourceLoading } = useResourceStatus();
  const startService = useStartService();
  const stopService = useStopService();
  const restartService = useRestartService();
  const { success, error } = useToast();

  const [dialogOpen, setDialogOpen] = useState(false);
  const [selectedService, setSelectedService] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<ServiceAction>("restart");
  const [isClearingCache, setIsClearingCache] = useState(false);

  const components = status?.components ?? [];
  const services = status?.services ?? [];
  const events = eventsData?.events ?? [];
  const overallHealth = status?.overall_health ?? "unknown";

  const isPending = startService.isPending || stopService.isPending || restartService.isPending;

  const handleClearCache = async () => {
    if (isClearingCache) return;
    setIsClearingCache(true);
    try {
      const result = await clearSystemCache();
      if (result.success) {
        success("Cache Cleared", result.message);
      } else {
        error("Clear Cache Failed", result.message);
      }
    } catch (err) {
      error("Clear Cache Failed", err instanceof Error ? err.message : "Unknown error");
    } finally {
      setIsClearingCache(false);
    }
  };

  const handleActionClick = (service: string, action: ServiceAction) => {
    setSelectedService(service);
    setSelectedAction(action);
    setDialogOpen(true);
  };

  const handleActionConfirm = async () => {
    if (!selectedService) return;

    try {
      let result;
      switch (selectedAction) {
        case "start":
          result = await startService.mutateAsync(selectedService);
          break;
        case "stop":
          result = await stopService.mutateAsync(selectedService);
          break;
        case "restart":
          result = await restartService.mutateAsync(selectedService);
          break;
      }
      if (result.success) {
        const actionLabels = { start: "Started", stop: "Stopped", restart: "Restarted" };
        success(`Service ${actionLabels[selectedAction]}`, `${selectedService} has been ${actionLabels[selectedAction].toLowerCase()}`);
      } else {
        error(`${selectedAction.charAt(0).toUpperCase() + selectedAction.slice(1)} Failed`, result.message);
      }
    } catch (err) {
      error(`${selectedAction.charAt(0).toUpperCase() + selectedAction.slice(1)} Failed`, err instanceof Error ? err.message : "Unknown error");
    }
    setDialogOpen(false);
    setSelectedService(null);
  };

  // Only show loading skeleton on initial load, not on refetch
  const showStatusSkeleton = statusLoading && !status;
  const showEventsSkeleton = eventsLoading && !eventsData;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="watchdog"
        title="Service health & resources."
        subtitle="Live status of node services, components, and system resources."
        actions={
          status ? (
            <Badge variant={getHealthBadge(overallHealth).variant}>
              {getHealthBadge(overallHealth).label}
            </Badge>
          ) : undefined
        }
      />

      {/* Overview Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Components"
          value={components.length}
          sublabel="total monitored"
          loading={showStatusSkeleton}
        />
        <StatCard
          label="Running"
          value={components.filter((c) => c.status === "ok").length}
          sublabel="healthy components"
          loading={showStatusSkeleton}
        />
        <StatCard
          label="Services"
          value={services.length}
          sublabel="active services"
          loading={showStatusSkeleton}
        />
        <StatCard
          label="Errors"
          value={components.filter((c) => c.status === "error" || c.status === "unknown").length}
          sublabel="components with issues"
          loading={showStatusSkeleton}
        />
      </div>

      {/* Resource Monitoring */}
      <SectionErrorBoundary section="Resource Monitor">
        <Card>
          <CardHeader
            title="Resource Monitor"
            subtitle="CPU, memory, and disk usage monitoring"
            action={
              <div className="flex items-center gap-2">
                {resourceStatus && (
                  <Badge variant={getResourceBadge(resourceStatus.status).variant}>
                    {getResourceBadge(resourceStatus.status).label}
                  </Badge>
                )}
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={handleClearCache}
                  loading={isClearingCache}
                >
                  Clear Cache
                </Button>
              </div>
            }
          />
          {resourceLoading && !resourceStatus ? (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard label="CPU" value="--" loading />
              <StatCard label="Memory" value="--" loading />
              <StatCard label="Disk" value="--" loading />
              <StatCard label="Miners" value="--" loading />
            </div>
          ) : resourceStatus ? (
            <div className="space-y-4">
              {/* Resource Bars */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 bg-[var(--surface)] rounded-lg border border-[var(--rule-strong)]">
                  <ProgressBar
                    value={resourceStatus.cpu_percent}
                    label="CPU Usage"
                    sublabel={`${resourceStatus.cpu_percent.toFixed(1)}%`}
                    color={resourceColor(resourceStatus.cpu_percent, resourceStatus.warning_threshold_cpu, resourceStatus.critical_threshold_cpu)}
                    size="lg"
                  />
                  <div className="flex justify-between mt-1.5 text-xs text-[color:var(--fainter)]">
                    <span>Warning: {resourceStatus.warning_threshold_cpu}%</span>
                    <span>Critical: {resourceStatus.critical_threshold_cpu}%</span>
                  </div>
                </div>

                <div className="p-4 bg-[var(--surface)] rounded-lg border border-[var(--rule-strong)]">
                  <ProgressBar
                    value={resourceStatus.memory_percent}
                    label="Memory Usage"
                    sublabel={`${resourceStatus.memory_percent.toFixed(1)}%`}
                    color={resourceColor(resourceStatus.memory_percent, resourceStatus.warning_threshold_memory, resourceStatus.critical_threshold_memory)}
                    size="lg"
                  />
                  <div className="flex justify-between mt-1.5 text-xs text-[color:var(--fainter)]">
                    <span>{resourceStatus.memory_used_mb.toLocaleString()} / {resourceStatus.memory_total_mb.toLocaleString()} MB</span>
                  </div>
                </div>

                <div className="p-4 bg-[var(--surface)] rounded-lg border border-[var(--rule-strong)]">
                  <ProgressBar
                    value={resourceStatus.disk_percent}
                    label="Disk Usage"
                    sublabel={`${resourceStatus.disk_percent.toFixed(1)}%`}
                    color={resourceColor(resourceStatus.disk_percent, 75, 90)}
                    size="lg"
                  />
                  <div className="flex justify-between mt-1.5 text-xs text-[color:var(--fainter)]">
                    <span>{resourceStatus.disk_used_gb.toLocaleString()} / {resourceStatus.disk_total_gb.toLocaleString()} GB</span>
                  </div>
                </div>
              </div>

              {/* Stats Row */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <StatCard
                  label="Connected Miners"
                  value={resourceStatus.connected_miners.toLocaleString()}
                />
                <StatCard
                  label="Est. Capacity"
                  value={resourceStatus.estimated_capacity.toLocaleString()}
                />
                <StatCard
                  label="Miner Capacity Used"
                  value={
                    resourceStatus.estimated_capacity > 0
                      ? `${((resourceStatus.connected_miners / resourceStatus.estimated_capacity) * 100).toFixed(1)}%`
                      : "0%"
                  }
                />
                <StatCard
                  label="Last Redirect"
                  value={
                    resourceStatus.last_redirect_secs_ago !== null && resourceStatus.last_redirect_secs_ago !== undefined
                      ? `${Math.floor(resourceStatus.last_redirect_secs_ago / 60)}m ago (${resourceStatus.last_redirect_count})`
                      : "Never"
                  }
                />
              </div>

              {/* Warning/Critical Info */}
              {resourceStatus.status === "warning" && (
                <div className="p-3 bg-[var(--surface)] border border-[color:var(--accent)] rounded-lg">
                  <p className="text-[color:var(--accent)] text-sm">
                    Resource usage is elevated. If usage continues to increase, low-hashrate miners may be redirected to other nodes.
                  </p>
                </div>
              )}
              {resourceStatus.status === "critical" && (
                <div className="p-3 bg-[var(--surface)] border border-[color:var(--red)] rounded-lg">
                  <p className="text-[color:var(--red)] text-sm">
                    Resource usage is critical! Low-hashrate miners are being redirected to other nodes to reduce load.
                  </p>
                </div>
              )}
            </div>
          ) : (
            <EmptyState
              title="Resource monitoring unavailable"
              description="Unable to retrieve resource status from the node"
            />
          )}
        </Card>
      </SectionErrorBoundary>

      {/* Services Status */}
      {services.length > 0 && (
        <SectionErrorBoundary section="Service Status">
          <Card>
            <CardHeader
              title="Service Status"
              subtitle="High-level service status overview"
            />
            <div className="space-y-3">
              {services.map((service) => {
                const statusBadge = getStatusBadge(service.status);
                return (
                  <div
                    key={service.name}
                    className="p-4 bg-[var(--surface)] rounded-lg border border-[var(--rule-strong)]"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="text-[color:var(--fg)] font-medium">{service.name}</span>
                        <Badge variant={statusBadge.variant}>{statusBadge.label}</Badge>
                      </div>
                      <div className="flex gap-2">
                        {isRunningStatus(service.status) ? (
                          <Button
                            size="sm"
                            variant="danger"
                            onClick={() => handleActionClick(service.name, "stop")}
                            disabled={isPending}
                          >
                            Stop
                          </Button>
                        ) : (
                          <Button
                            size="sm"
                            variant="success"
                            onClick={() => handleActionClick(service.name, "start")}
                            disabled={isPending}
                          >
                            Start
                          </Button>
                        )}
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => handleActionClick(service.name, "restart")}
                          disabled={isPending}
                        >
                          Restart
                        </Button>
                      </div>
                    </div>
                    {service.details && Object.keys(service.details).length > 0 && (
                      <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        {Object.entries(service.details).map(([key, value]) => (
                          <div key={key}>
                            <span className="text-[color:var(--fainter)]">{key}: </span>
                            <span className="text-[color:var(--dim)]">
                              {typeof value === "number"
                                ? value.toLocaleString()
                                : String(value)}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </Card>
        </SectionErrorBoundary>
      )}

      {/* Components Health Table */}
      <SectionErrorBoundary section="Component Health">
        <Card>
          <CardHeader
            title="Component Health"
            subtitle="Real-time status of all node components"
          />
          {showStatusSkeleton ? (
            <SkeletonTable rows={7} cols={5} />
          ) : components.length === 0 ? (
            <EmptyState
              title="No components registered"
              description="Components will appear here once the node starts reporting"
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-[var(--rule)]">
                    <th className="pb-3 text-[color:var(--dim)] font-medium">Component</th>
                    <th className="pb-3 text-[color:var(--dim)] font-medium">Port</th>
                    <th className="pb-3 text-[color:var(--dim)] font-medium">Status</th>
                    <th className="pb-3 text-[color:var(--dim)] font-medium">PID</th>
                    <th className="pb-3 text-[color:var(--dim)] font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {components.map((component) => {
                    const statusBadge = getStatusBadge(component.status);
                    return (
                      <tr
                        key={component.name}
                        className="border-b border-[var(--rule)] hover:bg-[var(--surface)]"
                      >
                        <td className="py-3">
                          <div>
                            <div className="text-[color:var(--fg)] font-medium">{component.name}</div>
                            {component.process_name && (
                              <div className="text-xs text-[color:var(--fainter)]">{component.process_name}</div>
                            )}
                          </div>
                        </td>
                        <td className="py-3">
                          <code className="text-[color:var(--accent)]">{component.port}</code>
                        </td>
                        <td className="py-3">
                          <Badge variant={statusBadge.variant}>{statusBadge.label}</Badge>
                        </td>
                        <td className="py-3">
                          <code className="text-[color:var(--dim)]">{component.pid ?? "N/A"}</code>
                        </td>
                        <td className="py-3">
                          <div className="flex gap-2">
                            {isRunningStatus(component.status) ? (
                              <Button
                                size="sm"
                                variant="danger"
                                onClick={() => handleActionClick(component.name, "stop")}
                                disabled={isPending}
                              >
                                Stop
                              </Button>
                            ) : (
                              <Button
                                size="sm"
                                variant="success"
                                onClick={() => handleActionClick(component.name, "start")}
                                disabled={isPending}
                              >
                                Start
                              </Button>
                            )}
                            <Button
                              size="sm"
                              variant="secondary"
                              onClick={() => handleActionClick(component.name, "restart")}
                              disabled={isPending}
                            >
                              Restart
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* Recent Events */}
      <SectionErrorBoundary section="Recent Events">
        <Card>
          <CardHeader
            title="Recent Events"
            subtitle={`${events.length} events recorded`}
          />
          {showEventsSkeleton ? (
            <SkeletonTable rows={10} cols={4} />
          ) : events.length === 0 ? (
            <EmptyState
              title="No events recorded"
              description="Events will appear here as services report status changes"
            />
          ) : (
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {events.map((event, idx) => {
                const eventBadge = getEventBadge((event.event_type ?? "warning") as "warning" | "restart" | "failure" | "recovery");
                return (
                  <div
                    key={`${event.timestamp}-${idx}`}
                    className={`p-3 rounded-lg border ${
                      event.event_type === "failure"
                        ? "bg-[var(--surface)] border-[color:var(--red)]"
                        : event.event_type === "recovery"
                        ? "bg-[var(--surface)] border-[color:var(--green)]"
                        : event.event_type === "warning"
                        ? "bg-[var(--surface)] border-[color:var(--accent)]"
                        : "bg-[var(--surface)] border-[var(--rule-strong)]"
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <Badge variant={eventBadge.variant}>{eventBadge.label}</Badge>
                      <span className="text-[color:var(--fg)] font-medium">{event.service}</span>
                      <span className="text-[color:var(--fainter)] text-sm ml-auto">
                        {formatTimestamp(event.timestamp ?? 0)}
                      </span>
                    </div>
                    <p className="text-[color:var(--dim)] text-sm mt-1">{event.message}</p>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* Info Card */}
      <Card>
        <div className="p-4 bg-[var(--surface)] border border-[color:var(--accent)] rounded-lg">
          <h4 className="text-[color:var(--accent)] font-medium mb-2">About Watchdog</h4>
          <ul className="text-sm text-[color:var(--accent)] space-y-1 list-disc list-inside">
            <li>Watchdog monitors all Ghost node components in real-time</li>
            <li>Components are automatically restarted if they crash</li>
            <li>Use the Restart button to manually restart a component</li>
            <li>Events are recorded for auditing and troubleshooting</li>
            <li>Health checks run every 5 seconds</li>
          </ul>
        </div>
      </Card>

      {/* Service Action Confirmation Dialog */}
      <Dialog
        isOpen={dialogOpen}
        onClose={() => {
          setDialogOpen(false);
          setSelectedService(null);
        }}
        title={`${selectedAction.charAt(0).toUpperCase() + selectedAction.slice(1)} Service`}
      >
        <div className="space-y-4">
          <p className="text-[color:var(--dim)]">
            Are you sure you want to {selectedAction} <strong className="text-[color:var(--fg)]">{selectedService}</strong>?
          </p>
          <div className={`p-3 rounded border ${
            selectedAction === "stop"
              ? "bg-[var(--surface)] border-[color:var(--red)]"
              : selectedAction === "start"
              ? "bg-[var(--surface)] border-[color:var(--green)]"
              : "bg-[var(--surface)] border-[color:var(--accent)]"
          }`}>
            <p className={`text-sm ${
              selectedAction === "stop"
                ? "text-[color:var(--red)]"
                : selectedAction === "start"
                ? "text-[color:var(--green)]"
                : "text-[color:var(--accent)]"
            }`}>
              {selectedAction === "stop"
                ? "This will stop the service. It will not automatically restart until started manually."
                : selectedAction === "start"
                ? "This will start the service if it is currently stopped."
                : "This will temporarily interrupt the service. Any in-progress operations may be affected."}
            </p>
          </div>
          <div className="flex gap-3 pt-4 border-t border-[var(--rule)]">
            <Button
              variant="ghost"
              className="flex-1"
              onClick={() => {
                setDialogOpen(false);
                setSelectedService(null);
              }}
            >
              Cancel
            </Button>
            <Button
              variant={selectedAction === "stop" ? "danger" : selectedAction === "start" ? "success" : "warning"}
              className="flex-1"
              onClick={handleActionConfirm}
              loading={isPending}
            >
              {selectedAction.charAt(0).toUpperCase() + selectedAction.slice(1)}
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
