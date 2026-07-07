"use client";

import { useState, useEffect } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { EmptyState } from "@/components/ui/EmptyState";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Dialog } from "@/components/ui/Dialog";
import { SkeletonTable } from "@/components/ui/Skeleton";
import { Tooltip } from "@/components/ui/Tooltip";
import { truncateId } from "@/components/ui/DataTable";
import {
  useSwarm,
  useAddSwarmNode,
  useRemoveSwarmNode,
  useUpdateSwarmNode,
  useRefreshSwarmNode,
  useNodeInfo,
} from "@/hooks/queries";
import { setNickname } from "@/lib/api/node";
import { refreshSwarmNode, syncSwarm, restartSwarmNode, updateAllSwarmNodes } from "@/lib/api/swarm";
import { useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/components/ui/Toast";
import { swarmKeys } from "@/hooks/queries/useSwarmQueries";
import type { SwarmNode } from "@/types/api";

function formatBtc(btc: number): string {
  return btc.toFixed(4);
}

function formatUptime(percent: number): string {
  return `${percent.toFixed(1)}%`;
}

function formatHashrate(th: number): string {
  if (th >= 1000) {
    return `${(th / 1000).toFixed(1)} PH/s`;
  }
  return `${th.toFixed(0)} TH/s`;
}

// Small inline help affordance placed next to a label; the surrounding element
// is wrapped in a <Tooltip> that carries the explanatory copy.
function InfoIcon() {
  return (
    <svg className="w-3 h-3 text-[color:var(--fainter)] inline-block align-middle mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <circle cx="12" cy="12" r="10" />
      <path d="M12 16v-4M12 8h.01" />
    </svg>
  );
}

// One short, plain-language line per element. "—" copy ties to the em-dash
// placeholder above (issue #219): a value a mesh peer simply does not gossip.
const TOOLTIPS = {
  // Summary tiles
  nodes: "Total nodes tracked in this swarm.",
  online: "Nodes currently reporting healthy.",
  combinedHashrate: "Combined hashrate summed across the mesh.",
  combinedShares: "Qualified capability shares summed across the swarm (max = 15 × node count).",
  // This Node card
  nodeId: "This node's mesh identity — paste it into another node to add this one.",
  connectionAddress: "The endpoint other nodes add to reach this node.",
  // Per-node fields
  uptime: "Trailing-7-day uptime %. Capabilities only count at ≥95%. — means this peer did not gossip it.",
  peers: "Mesh peers this node is connected to. — means not gossiped.",
  l1Height: "Bitcoin (L1) chain height. — means not gossiped.",
  l2Height: "Ghost-Pay (L2) chain height. — means not gossiped.",
  shares: "Qualified capability shares, out of a maximum of 15.",
  capabilities: "Capabilities in the 5-4-3-2-1 model. Green = qualified; red = claimed but not yet verified.",
  // Status badges
  statusOnline: "Whether this node is reachable and reporting healthy.",
  mesh: "Auto-discovered gossip peer — can't be polled or removed from here.",
  stale: "The last manual refresh of this node failed.",
  you: "This is the node you're viewing the dashboard on.",
  // Actions
  viewToggle: "Switch between list and grid layouts.",
  refreshAll: "Re-poll manual nodes and sync the mesh.",
  updateAll: "Push a version update across the whole swarm.",
  addNode: "Track a remote node by its address.",
  edit: "Rename this node (and edit its address if remote).",
  restart: "Restart this node's services.",
  refresh: "Re-poll this node now.",
  remove: "Stop tracking this remote node.",
};

// Em-dash placeholder for values a mesh peer does not gossip (uptime %, mesh
// peer count, L1/L2 heights, balance). These are genuinely unknown from here,
// so we render "—" rather than a misleading 0.
const NO_VALUE = "—";

function orDash<T>(value: T | null | undefined, fmt: (v: T) => string): string {
  return value === null || value === undefined ? NO_VALUE : fmt(value);
}

// An auto-discovered consensus mesh peer: status is sourced from health-ping
// gossip, so it is authoritative and cannot be polled/removed from here.
function isMeshNode(node: SwarmNode): boolean {
  return node.source === "mesh" && !node.is_self;
}

function getAlertIcon(severity: "info" | "warning" | "error"): string {
  switch (severity) {
    case "error":
      return "!";
    case "warning":
      return "!";
    case "info":
    default:
      return "i";
  }
}

type ViewMode = "list" | "grid";

export default function SwarmPage() {
  const { data: swarmData, isLoading: swarmLoading } = useSwarm();
  const { data: nodeInfo } = useNodeInfo();
  const addNode = useAddSwarmNode();
  const removeNode = useRemoveSwarmNode();
  const updateNode = useUpdateSwarmNode();
  const refreshNode = useRefreshSwarmNode();
  const queryClient = useQueryClient();
  const { success, error } = useToast();

  const [viewMode, setViewMode] = useState<ViewMode>("list");
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [updateDialogOpen, setUpdateDialogOpen] = useState(false);
  const [selectedNode, setSelectedNode] = useState<SwarmNode | null>(null);
  const [newNodeName, setNewNodeName] = useState("");
  const [newNodeAddress, setNewNodeAddress] = useState("");
  const [editNodeName, setEditNodeName] = useState("");
  const [editNodeAddress, setEditNodeAddress] = useState("");
  const [updateVersion, setUpdateVersion] = useState("");
  const [isUpdating, setIsUpdating] = useState(false);

  const nodes = swarmData?.nodes ?? [];
  const stats = swarmData?.stats ?? null;
  const alerts = swarmData?.alerts ?? [];

  const handleAddNode = async () => {
    if (!newNodeName.trim() || !newNodeAddress.trim()) return;

    try {
      await addNode.mutateAsync({
        name: newNodeName.trim(),
        address: newNodeAddress.trim(),
      });
      success("Node Added", `${newNodeName} added to swarm`);
      setNewNodeName("");
      setNewNodeAddress("");
      setAddDialogOpen(false);
    } catch (err) {
      error("Failed to Add Node", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleRemoveNode = async (node: SwarmNode) => {
    try {
      await removeNode.mutateAsync(node.node_id);
      success("Node Removed", `${node.name} removed from swarm`);
    } catch (err) {
      error("Failed to Remove", err instanceof Error ? err.message : "Unknown error");
    }
  };

  // Refresh all nodes - calls API directly for reliability
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [restartingNode, setRestartingNode] = useState<string | null>(null);
  // Nodes whose last refresh failed — surfaced as a per-node "stale" marker so
  // best-effort refresh failures aren't silently swallowed.
  const [staleNodeIds, setStaleNodeIds] = useState<Set<string>>(new Set());

  const markNodeStale = (nodeId: string, stale: boolean) => {
    setStaleNodeIds((prev) => {
      if (prev.has(nodeId) === stale) return prev;
      const next = new Set(prev);
      if (stale) {
        next.add(nodeId);
      } else {
        next.delete(nodeId);
      }
      return next;
    });
  };

  const handleRestartNode = async (node: SwarmNode) => {
    if (restartingNode) return;
    setRestartingNode(node.node_id);

    try {
      const result = await restartSwarmNode(node.node_id);
      if (result.success) {
        success("Restart Initiated", result.message);
      } else {
        error("Restart Failed", result.message);
      }
    } catch (err) {
      error("Restart Failed", err instanceof Error ? err.message : "Unknown error");
    } finally {
      setRestartingNode(null);
    }
  };

  const handleUpdateAll = async () => {
    if (!updateVersion.trim() || isUpdating) return;

    setIsUpdating(true);
    try {
      const result = await updateAllSwarmNodes(updateVersion.trim());
      if (result.success) {
        success("Update Initiated", result.message);
      } else {
        // Show partial success/failure details
        const failedNodes = result.results.filter(r => !r.success);
        if (failedNodes.length > 0) {
          error("Update Partially Failed", `${failedNodes.length} nodes failed: ${failedNodes.map(n => n.name).join(", ")}`);
        } else {
          success("Update Initiated", result.message);
        }
      }
      setUpdateDialogOpen(false);
      setUpdateVersion("");
    } catch (err) {
      error("Update Failed", err instanceof Error ? err.message : "Unknown error");
    } finally {
      setIsUpdating(false);
    }
  };

  const handleRefreshAll = async (showToast = true) => {
    // Only manually-added remote nodes are polled via their dashboard API.
    // Mesh peers are gossip-sourced (useSwarm refetches them every 10s), so
    // there is nothing to poll — and their loopback dashboards are unreachable
    // from here anyway.
    const remoteNodes = nodes.filter(n => n.address !== "localhost" && !isMeshNode(n));

    if (isRefreshing) return;
    setIsRefreshing(true);

    try {
      // First, sync to discover new peers and announce ourselves
      let syncResult = { discovered_peers: 0, removed_stale: 0, total_peers: 0 };
      try {
        syncResult = await syncSwarm();
      } catch (err) {
        // Sync failed, continue with refresh anyway — but log it.
        console.error("Swarm sync failed; continuing with refresh", err);
      }

      // Refresh all remote nodes in parallel via direct API calls
      if (remoteNodes.length > 0) {
        await Promise.all(remoteNodes.map(async (node) => {
          try {
            await refreshSwarmNode(node.node_id);
            markNodeStale(node.node_id, false);
          } catch (err) {
            // Mark the node stale and log — don't swallow silently.
            console.error(`Swarm refresh failed for ${node.name} (${node.node_id})`, err);
            markNodeStale(node.node_id, true);
          }
        }));
      }
      // Invalidate to get fresh data for all nodes including local
      await queryClient.invalidateQueries({ queryKey: swarmKeys.all });
      if (showToast) {
        const extra = syncResult.discovered_peers > 0
          ? ` (${syncResult.discovered_peers} new peers discovered)`
          : "";
        success("Swarm Refreshed", `All ${nodes.length} nodes updated${extra}`);
      }
    } catch (err) {
      if (showToast) {
        error("Refresh Failed", err instanceof Error ? err.message : "Unknown error");
      }
    } finally {
      setIsRefreshing(false);
    }
  };

  // Individual refresh button now refreshes ALL nodes
  const handleRefreshNode = async (_node: SwarmNode) => {
    await handleRefreshAll(true);
  };

  // Auto-refresh all nodes every 30 seconds
  useEffect(() => {
    // Only poll manually-added remote nodes; mesh peers are gossip-sourced.
    const remoteNodes = nodes.filter(n => n.address !== "localhost" && !isMeshNode(n));
    if (remoteNodes.length === 0) return;

    const doRefresh = async () => {
      // Call refresh API for each remote node using the proper API function
      await Promise.all(remoteNodes.map(async (node) => {
        try {
          await refreshSwarmNode(node.node_id);
          markNodeStale(node.node_id, false);
        } catch (err) {
          console.error(`Swarm auto-refresh failed for ${node.name} (${node.node_id})`, err);
          markNodeStale(node.node_id, true);
        }
      }));
      // Refetch swarm data
      queryClient.invalidateQueries({ queryKey: swarmKeys.all });
    };

    const interval = setInterval(doRefresh, 30000);
    return () => clearInterval(interval);
  }, [nodes.length, queryClient]); // Re-setup when node count changes

  const handleEditClick = (node: SwarmNode) => {
    setSelectedNode(node);
    setEditNodeName(node.name ?? "");
    setEditNodeAddress(node.address ?? "");
    setEditDialogOpen(true);
  };

  const handleEditNode = async () => {
    if (!selectedNode || !editNodeName.trim()) return;

    // For localhost, only update the nickname
    if (selectedNode.address === "localhost") {
      try {
        await setNickname(editNodeName.trim());
        queryClient.invalidateQueries({ queryKey: swarmKeys.all });
        success("Node Updated", `Local node renamed to ${editNodeName}`);
        setEditDialogOpen(false);
        setSelectedNode(null);
      } catch (err) {
        error("Failed to Update", err instanceof Error ? err.message : "Unknown error");
      }
      return;
    }

    // For remote nodes, update via swarm API
    if (!editNodeAddress.trim()) return;

    try {
      await updateNode.mutateAsync({
        nodeId: selectedNode.node_id,
        updates: {
          name: editNodeName.trim(),
          address: editNodeAddress.trim(),
        },
      });
      success("Node Updated", `${editNodeName} updated`);
      setEditDialogOpen(false);
      setSelectedNode(null);
    } catch (err) {
      error("Failed to Update", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header with view toggle + action buttons */}
      <PageHeader
        eyebrow="swarm"
        title="Multi-node fleet."
        subtitle="Multi-node fleet management"
        actions={
          <>
            <Tooltip content={TOOLTIPS.viewToggle}>
              <div className="flex rounded-lg border border-[var(--rule-strong)] overflow-hidden">
                <button
                  onClick={() => setViewMode("list")}
                  className={`px-3 py-1.5 text-sm ${
                    viewMode === "list"
                      ? "bg-[var(--accent)] text-white"
                      : "bg-[var(--surface)] text-[color:var(--dim)] hover:text-[color:var(--fg)]"
                  }`}
                >
                  List
                </button>
                <button
                  onClick={() => setViewMode("grid")}
                  className={`px-3 py-1.5 text-sm ${
                    viewMode === "grid"
                      ? "bg-[var(--accent)] text-white"
                      : "bg-[var(--surface)] text-[color:var(--dim)] hover:text-[color:var(--fg)]"
                  }`}
                >
                  Grid
                </button>
              </div>
            </Tooltip>
            <Tooltip content={TOOLTIPS.refreshAll}>
              <Button
                variant="secondary"
                onClick={() => handleRefreshAll()}
                loading={isRefreshing}
                disabled={nodes.filter(n => n.address !== "localhost").length === 0}
              >
                Refresh All
              </Button>
            </Tooltip>
            <Tooltip content={TOOLTIPS.updateAll}>
              <Button
                variant="warning"
                onClick={() => setUpdateDialogOpen(true)}
                disabled={nodes.length === 0}
              >
                Update All
              </Button>
            </Tooltip>
            <Tooltip content={TOOLTIPS.addNode}>
              <Button variant="primary" onClick={() => setAddDialogOpen(true)}>
                + Add Node
              </Button>
            </Tooltip>
          </>
        }
      />

      {/* Aggregate Stats — 4 StatCards */}
      <SectionErrorBoundary section="Aggregate Stats">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            label="Nodes"
            value={stats?.total_nodes ?? 0}
            tooltip={TOOLTIPS.nodes}
            loading={swarmLoading}
          />
          <StatCard
            label="Online"
            value={stats?.online_nodes ?? 0}
            tooltip={TOOLTIPS.online}
            loading={swarmLoading}
          />
          <StatCard
            label="Combined Hashrate"
            value={formatHashrate(stats?.combined_hashrate_th ?? 0)}
            tooltip={TOOLTIPS.combinedHashrate}
            loading={swarmLoading}
          />
          <StatCard
            label="Combined Shares"
            value={`${stats?.combined_shares ?? 0} / ${stats?.max_combined_shares ?? 0}`}
            tooltip={TOOLTIPS.combinedShares}
            loading={swarmLoading}
          />
        </div>
      </SectionErrorBoundary>

      {/* Local Node Setup Info */}
      <SectionErrorBoundary section="This Node">
        {nodeInfo && (
          <Card className="border-[color:var(--accent)]">
            <CardHeader
              title="This Node"
              subtitle="Use these details when adding this node to another swarm"
            />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-3 bg-[var(--surface)] rounded-lg">
                <Tooltip content={TOOLTIPS.nodeId}>
                  <div className="text-xs text-[color:var(--fainter)] uppercase tracking-wide mb-1 flex items-center gap-1"><InfoIcon /> Node ID</div>
                </Tooltip>
                <div className="font-mono text-sm text-[color:var(--fg)] break-all select-all">
                  {nodeInfo.node_id}
                </div>
              </div>
              <div className="p-3 bg-[var(--surface)] rounded-lg">
                <Tooltip content={TOOLTIPS.connectionAddress}>
                  <div className="text-xs text-[color:var(--fainter)] uppercase tracking-wide mb-1 flex items-center gap-1"><InfoIcon /> Connection Address</div>
                </Tooltip>
                <div className="font-mono text-sm text-[color:var(--fg)] mb-2 select-all">
                  {swarmData?.self?.address
                    ? `http://${swarmData.self.address}`
                    : "http://<your-ip>:8080"}
                </div>
                <p className="text-xs text-[color:var(--fainter)]">
                  {swarmData?.self?.address
                    ? "Other nodes can add this address to their swarm."
                    : "Template — replace <your-ip> with your public IP or hostname, then other nodes can add this address to their swarm."}
                </p>
              </div>
            </div>
          </Card>
        )}
      </SectionErrorBoundary>

      {/* Node Cards */}
      <SectionErrorBoundary section="Node List">
        {swarmLoading ? (
          <SkeletonTable rows={3} cols={4} />
        ) : nodes.length === 0 ? (
          <EmptyState
            title="No nodes in your swarm"
            description="Add remote nodes to monitor and manage your fleet"
            action={
              <Button variant="primary" onClick={() => setAddDialogOpen(true)}>
                Add Your First Node
              </Button>
            }
          />
        ) : viewMode === "grid" ? (
          /* Grid View - Compact cards */
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {nodes.map((node) => (
              <Card key={node.node_id} className={node.address === "localhost" ? "border-[color:var(--accent)]" : ""}>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <span
                      className={`w-2.5 h-2.5 rounded-full ${node.online ? "bg-green-500" : "bg-red-500"}`}
                    />
                    <span className="font-semibold text-[color:var(--fg)]">{node.name}</span>
                    {node.is_self && (
                      <Tooltip content={TOOLTIPS.you}>
                        <Badge variant="info" className="text-xs">
                          You
                        </Badge>
                      </Tooltip>
                    )}
                  </div>
                  <div className="flex items-center gap-1">
                    <Tooltip content={TOOLTIPS.statusOnline}>
                      <Badge variant={node.online ? "success" : "error"} className="text-xs">
                        {node.online ? "Online" : "Offline"}
                      </Badge>
                    </Tooltip>
                    {isMeshNode(node) && (
                      <Tooltip content={TOOLTIPS.mesh}>
                        <Badge variant="info" className="text-xs">
                          Mesh
                        </Badge>
                      </Tooltip>
                    )}
                    {staleNodeIds.has(node.node_id) && (
                      <Tooltip content={TOOLTIPS.stale}>
                        <Badge variant="warning" className="text-xs">
                          Stale
                        </Badge>
                      </Tooltip>
                    )}
                    {node.watchdog_health && (
                      <Badge
                        variant={node.watchdog_health === "healthy" ? "success" : node.watchdog_health === "degraded" ? "warning" : "error"}
                        className="text-xs"
                      >
                        {(node.watchdog_errors ?? 0) > 0 ? `Watchdog:${node.watchdog_errors} Error${(node.watchdog_errors ?? 0) > 1 ? 's' : ''}` : "Watchdog:OK"}
                      </Badge>
                    )}
                  </div>
                </div>

                <div className="text-xs text-[color:var(--dim)] mb-3 font-mono truncate">{node.address}</div>

                <div className="grid grid-cols-2 gap-2 text-xs mb-3">
                  <Tooltip content={TOOLTIPS.l1Height}>
                    <div>
                      <span className="text-[color:var(--fainter)]"><InfoIcon /> L1:</span>{" "}
                      <span className="text-[color:var(--dim)]">{orDash(node.l1_height, (v) => v.toLocaleString())}</span>
                    </div>
                  </Tooltip>
                  <Tooltip content={TOOLTIPS.l2Height}>
                    <div>
                      <span className="text-[color:var(--fainter)]"><InfoIcon /> L2:</span>{" "}
                      <span className="text-[color:var(--dim)]">{orDash(node.l2_height, (v) => v.toLocaleString())}</span>
                    </div>
                  </Tooltip>
                  <Tooltip content={TOOLTIPS.peers}>
                    <div>
                      <span className="text-[color:var(--fainter)]"><InfoIcon /> Peers:</span>{" "}
                      <span className="text-[color:var(--dim)]">{orDash(node.peer_count, (v) => String(v))}</span>
                    </div>
                  </Tooltip>
                  <Tooltip content={TOOLTIPS.shares}>
                    <div>
                      <span className="text-[color:var(--fainter)]"><InfoIcon /> Shares:</span>{" "}
                      <span className="text-[color:var(--dim)]">{node.shares ?? 0}/{node.max_shares ?? 15}</span>
                    </div>
                  </Tooltip>
                </div>

                <Tooltip content={TOOLTIPS.capabilities}>
                  <div className="flex flex-wrap gap-1 mb-3">
                    <Badge variant={node.archive_mode ? "success" : "error"} className="text-xs px-1.5 py-0">+5</Badge>
                    <Badge variant={node.ghost_pay ? "success" : "error"} className="text-xs px-1.5 py-0">+4</Badge>
                    <Badge variant={node.public_mining ? "success" : "error"} className="text-xs px-1.5 py-0">+3</Badge>
                    <Badge variant={node.reaper ? "success" : "error"} className="text-xs px-1.5 py-0">+2</Badge>
                    <Badge variant={node.elder ? "success" : "error"} className="text-xs px-1.5 py-0">+1</Badge>
                  </div>
                </Tooltip>

                <div className="flex gap-1 pt-2 border-t border-[var(--rule)]">
                  <Tooltip content={TOOLTIPS.edit}>
                    <Button variant="ghost" size="sm" onClick={() => handleEditClick(node)} className="text-xs px-2">
                      Edit
                    </Button>
                  </Tooltip>
                  {node.address !== "localhost" && !isMeshNode(node) && (
                    <Tooltip content={TOOLTIPS.refresh}>
                      <Button variant="ghost" size="sm" onClick={() => handleRefreshNode(node)} className="text-xs px-2">
                        Refresh
                      </Button>
                    </Tooltip>
                  )}
                  {node.address !== "localhost" && !isMeshNode(node) && (
                    <Tooltip content={TOOLTIPS.remove}>
                      <Button variant="danger" size="sm" onClick={() => handleRemoveNode(node)} className="text-xs px-2">
                        Remove
                      </Button>
                    </Tooltip>
                  )}
                </div>
              </Card>
            ))}
          </div>
        ) : (
          /* List View - Full detail cards */
          <div className="space-y-4">
            {nodes.map((node) => (
              <Card key={node.node_id} className={node.address === "localhost" ? "border-[color:var(--accent)]" : ""}>
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <span
                      className={`w-3 h-3 rounded-full ${node.online ? "bg-green-500" : "bg-red-500"}`}
                    />
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-lg font-semibold text-[color:var(--fg)]">{node.name}</span>
                        <span className="text-[color:var(--fainter)] font-mono text-sm">
                          ({truncateId(node.node_id, 6)})
                        </span>
                        <Tooltip content={TOOLTIPS.statusOnline}>
                          <Badge variant={node.online ? "success" : "error"}>
                            {node.online ? "Online" : "Offline"}
                          </Badge>
                        </Tooltip>
                        {isMeshNode(node) && (
                          <Tooltip content={TOOLTIPS.mesh}>
                            <Badge variant="info">Mesh</Badge>
                          </Tooltip>
                        )}
                        {staleNodeIds.has(node.node_id) && (
                          <Tooltip content={TOOLTIPS.stale}>
                            <Badge variant="warning">Stale</Badge>
                          </Tooltip>
                        )}
                        {node.watchdog_health && (
                          <Badge
                            variant={node.watchdog_health === "healthy" ? "success" : node.watchdog_health === "degraded" ? "warning" : "error"}
                          >
                            {(node.watchdog_errors ?? 0) > 0 ? `Watchdog:${node.watchdog_errors} Error${(node.watchdog_errors ?? 0) > 1 ? 's' : ''}` : "Watchdog:OK"}
                          </Badge>
                        )}
                      </div>
                      <div className="text-sm text-[color:var(--dim)] mt-1">{node.address}</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-lg font-bold text-[color:var(--fg)]">
                      {orDash(node.balance_btc, (v) => `${formatBtc(v)} BTC`)}
                    </div>
                    <Tooltip content={TOOLTIPS.shares}>
                      <div className="text-sm text-[color:var(--dim)] inline-block">
                        <InfoIcon /> {node.shares ?? 0}/{node.max_shares ?? 15} shares
                      </div>
                    </Tooltip>
                  </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4 text-sm">
                  <Tooltip content={TOOLTIPS.uptime}>
                    <div>
                      <span className="text-[color:var(--fainter)]"><InfoIcon /> Uptime</span>
                      <div
                        className={`font-medium ${
                          node.uptime_percent === undefined || node.uptime_percent === null
                            ? "text-[color:var(--dim)]"
                            : node.uptime_percent >= 95
                              ? "text-[color:var(--green)]"
                              : node.uptime_percent >= 90
                                ? "text-[color:var(--accent)]"
                                : "text-[color:var(--red)]"
                        }`}
                      >
                        {orDash(node.uptime_percent, formatUptime)}
                      </div>
                    </div>
                  </Tooltip>
                  <Tooltip content={TOOLTIPS.peers}>
                    <div>
                      <span className="text-[color:var(--fainter)]"><InfoIcon /> Peers</span>
                      <div className="text-[color:var(--fg)]">{orDash(node.peer_count, (v) => String(v))}</div>
                    </div>
                  </Tooltip>
                  <Tooltip content={TOOLTIPS.l1Height}>
                    <div>
                      <span className="text-[color:var(--fainter)]"><InfoIcon /> L1 Height</span>
                      <div className="text-[color:var(--fg)] font-mono">{orDash(node.l1_height, (v) => v.toLocaleString())}</div>
                    </div>
                  </Tooltip>
                  <Tooltip content={TOOLTIPS.l2Height}>
                    <div>
                      <span className="text-[color:var(--fainter)]"><InfoIcon /> L2 Height</span>
                      <div className="text-[color:var(--fg)] font-mono">{orDash(node.l2_height, (v) => v.toLocaleString())}</div>
                    </div>
                  </Tooltip>
                </div>

                <Tooltip content={TOOLTIPS.capabilities}>
                  <div className="flex flex-wrap gap-2 mt-4">
                    <Badge variant={node.archive_mode ? "success" : "error"}>Archive +5</Badge>
                    <Badge variant={node.ghost_pay ? "success" : "error"}>Ghost Pay +4</Badge>
                    <Badge variant={node.public_mining ? "success" : "error"}>Public Mining +3</Badge>
                    <Badge variant={node.reaper ? "success" : "error"}>Reaper +2</Badge>
                    <Badge variant={node.elder ? "success" : "error"}>
                      Elder{node.elder && node.elder_slot != null ? ` #${node.elder_slot}` : ""} +1
                    </Badge>
                  </div>
                </Tooltip>

                <div className="flex gap-2 mt-4 pt-4 border-t border-[var(--rule)]">
                  <Tooltip content={TOOLTIPS.edit}>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => handleEditClick(node)}
                    >
                      Edit
                    </Button>
                  </Tooltip>
                  <Tooltip content={TOOLTIPS.restart}>
                    <Button
                      variant="warning"
                      size="sm"
                      onClick={() => handleRestartNode(node)}
                      loading={restartingNode === node.node_id}
                    >
                      Restart
                    </Button>
                  </Tooltip>
                  {node.address !== "localhost" && !isMeshNode(node) && (
                    <Tooltip content={TOOLTIPS.refresh}>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleRefreshNode(node)}
                        loading={refreshNode.isPending}
                      >
                        Refresh
                      </Button>
                    </Tooltip>
                  )}
                  {node.address !== "localhost" && !isMeshNode(node) && (
                    <Tooltip content={TOOLTIPS.remove}>
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => handleRemoveNode(node)}
                        loading={removeNode.isPending}
                      >
                        Remove
                      </Button>
                    </Tooltip>
                  )}
                </div>
              </Card>
            ))}
          </div>
        )}
      </SectionErrorBoundary>

      {/* Alerts */}
      <SectionErrorBoundary section="Alerts">
        {alerts.length > 0 && (
          <Card>
            <CardHeader title="Alerts" />
            <div className="space-y-2">
              {alerts.map((alert) => (
                <div
                  key={alert.id}
                  className={`p-3 rounded-lg flex items-start gap-3 ${
                    alert.severity === "error"
                      ? "bg-[var(--surface)] border border-[color:var(--red)]"
                      : alert.severity === "warning"
                        ? "bg-[var(--surface)] border border-[color:var(--accent)]"
                        : "bg-[var(--surface)] border border-[color:var(--accent)]"
                  }`}
                >
                  <span
                    className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${
                      alert.severity === "error"
                        ? "bg-red-500 text-white"
                        : alert.severity === "warning"
                          ? "bg-yellow-500 text-black"
                          : "bg-orange-500 text-white"
                    }`}
                  >
                    {getAlertIcon(alert.severity ?? "info")}
                  </span>
                  <div className="flex-1">
                    <p
                      className={`${
                        alert.severity === "error"
                          ? "text-[color:var(--red)]"
                          : alert.severity === "warning"
                            ? "text-[color:var(--accent)]"
                            : "text-[color:var(--accent)]"
                      }`}
                    >
                      {alert.message}
                    </p>
                    <p className="text-xs text-[color:var(--fainter)] mt-1">
                      {new Date((alert.timestamp ?? 0) * 1000).toLocaleString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}
      </SectionErrorBoundary>

      {/* Add Node Dialog */}
      <Dialog
        isOpen={addDialogOpen}
        onClose={() => setAddDialogOpen(false)}
        title="Add Node to Swarm"
      >
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-[color:var(--dim)] mb-1">Node Name</label>
            <Input
              value={newNodeName}
              onChange={(e) => setNewNodeName(e.target.value)}
              placeholder="e.g., US-East, Primary"
            />
          </div>

          <div>
            <label className="block text-sm text-[color:var(--dim)] mb-1">Node Address</label>
            <Input
              value={newNodeAddress}
              onChange={(e) => setNewNodeAddress(e.target.value)}
              placeholder="e.g., 192.168.1.100:8080"
            />
            <p className="text-xs text-[color:var(--fainter)] mt-1">
              The node must have API access enabled for remote connections
            </p>
          </div>

          <div className="flex gap-3 pt-4 border-t border-[var(--rule)]">
            <Button variant="ghost" className="flex-1" onClick={() => setAddDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              className="flex-1"
              onClick={handleAddNode}
              loading={addNode.isPending}
              disabled={!newNodeName.trim() || !newNodeAddress.trim()}
            >
              Add Node
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Edit Node Dialog */}
      <Dialog
        isOpen={editDialogOpen}
        onClose={() => setEditDialogOpen(false)}
        title={`Edit ${selectedNode?.name ?? "Node"}`}
      >
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-[color:var(--dim)] mb-1">Node Name</label>
            <Input
              value={editNodeName}
              onChange={(e) => setEditNodeName(e.target.value)}
              placeholder="e.g., US-East, Primary"
            />
          </div>

          {selectedNode?.address !== "localhost" && (
            <div>
              <label className="block text-sm text-[color:var(--dim)] mb-1">Node Address</label>
              <Input
                value={editNodeAddress}
                onChange={(e) => setEditNodeAddress(e.target.value)}
                placeholder="e.g., 192.168.1.100:8080"
              />
              <p className="text-xs text-[color:var(--fainter)] mt-1">
                Do not include http:// prefix
              </p>
            </div>
          )}

          <div className="flex gap-3 pt-4 border-t border-[var(--rule)]">
            <Button variant="ghost" className="flex-1" onClick={() => setEditDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              className="flex-1"
              onClick={handleEditNode}
              loading={updateNode.isPending}
              disabled={!editNodeName.trim() || (selectedNode?.address !== "localhost" && !editNodeAddress.trim())}
            >
              Save Changes
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Update All Nodes Dialog */}
      <Dialog
        isOpen={updateDialogOpen}
        onClose={() => setUpdateDialogOpen(false)}
        title="Update All Swarm Nodes"
      >
        <div className="space-y-4">
          <div className="p-4 bg-[var(--surface)] border border-[color:var(--accent)] rounded-lg">
            <p className="text-[color:var(--accent)] text-sm font-medium mb-2">Warning</p>
            <p className="text-[color:var(--accent)] text-sm">
              This will initiate updates on ALL {nodes.length} nodes in the swarm.
              Each node will download the update from GitHub and restart.
              Rollback must be done individually on each node if needed.
            </p>
          </div>

          <div>
            <label className="block text-sm text-[color:var(--dim)] mb-1">Version</label>
            <Input
              value={updateVersion}
              onChange={(e) => setUpdateVersion(e.target.value)}
              placeholder="e.g., 0.2.0 or v0.2.0"
            />
            <p className="text-xs text-[color:var(--fainter)] mt-1">
              Enter the release version from GitHub (e.g., 0.2.0)
            </p>
          </div>

          <div className="p-3 bg-[var(--surface)] rounded-lg">
            <p className="text-sm text-[color:var(--dim)] mb-2">Nodes to update:</p>
            <div className="flex flex-wrap gap-2">
              {nodes.map((node) => (
                <Badge
                  key={node.node_id}
                  variant={node.online || node.address === "localhost" ? "success" : "error"}
                >
                  {node.name} {!node.online && node.address !== "localhost" && "(offline)"}
                </Badge>
              ))}
            </div>
          </div>

          <div className="flex gap-3 pt-4 border-t border-[var(--rule)]">
            <Button
              variant="ghost"
              className="flex-1"
              onClick={() => {
                setUpdateDialogOpen(false);
                setUpdateVersion("");
              }}
            >
              Cancel
            </Button>
            <Button
              variant="warning"
              className="flex-1"
              onClick={handleUpdateAll}
              loading={isUpdating}
              disabled={!updateVersion.trim()}
            >
              Update All Nodes
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
