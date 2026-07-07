"use client";

import { useState, useEffect, useRef } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Dialog } from "@/components/ui/Dialog";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { PageHeader } from "@/components/ui/PageHeader";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import {
  // Version & Updates
  useSystemVersion,
  useCheckForUpdates,
  useUpdateStatus,
  useStartUpdate,
  useRollbackUpdate,
  // Storage & Pruning
  useFullConfig,
  useNodeStatus,
  useL2PruningStatus,
  useSetPruneProfile,
  useSetOperatorWindow,
  useSetArchiveMode,
  useGhostPayStatus,
  // Backup & Restore
  useBackupHistory,
  useCreateBackup,
  useImportBackup,
  useVerifyBackup,
  useDeleteBackup,
} from "@/hooks/queries";
import { getBackupDownloadUrl } from "@/lib/api/backup";
import { useToast } from "@/components/ui/Toast";
import { AutoUpdateSection } from "@/components/settings/AutoUpdateSection";
import { ScheduledBackupsCard } from "@/components/settings/ScheduledBackupsCard";
import type { UpdateStatus } from "@/lib/api/system";
import type { PruneProfile } from "@/types/api";
import type { VerifyBackupResponse } from "@/types/api";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function formatDate(dateStr: string): string {
  try {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  } catch {
    return dateStr;
  }
}

function formatTimestampDate(timestamp: number): string {
  return new Date(timestamp * 1000).toLocaleString();
}

function formatDuration(blocks: number): string {
  const days = Math.round(blocks / 144);
  if (days === 1) return "1 day";
  if (days < 7) return `${days} days`;
  if (days === 7) return "1 week";
  if (days < 30) return `${Math.round(days / 7)} weeks`;
  if (days < 60) return "1 month";
  return `${Math.round(days / 30)} months`;
}

function formatTimestamp(ts: number): string {
  if (!ts) return "Never";
  const date = new Date(ts * 1000);
  return date.toLocaleString();
}

function formatTimeAgo(ts: number): string {
  if (!ts) return "Never";
  const now = Math.floor(Date.now() / 1000);
  const diff = now - ts;
  if (diff < 60) return "Just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function getStatusBadge(status: UpdateStatus["status"]): {
  variant: "success" | "warning" | "error" | "info" | "default";
  label: string;
} {
  switch (status) {
    case "idle":
      return { variant: "default", label: "Ready" };
    case "checking":
      return { variant: "info", label: "Checking..." };
    case "downloading":
      return { variant: "info", label: "Downloading" };
    case "verifying":
      return { variant: "info", label: "Verifying" };
    case "installing":
      return { variant: "warning", label: "Installing" };
    case "complete":
      return { variant: "success", label: "Complete" };
    case "failed":
      return { variant: "error", label: "Failed" };
    default:
      return { variant: "default", label: status };
  }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const OW_PRESETS = [
  { blocks: 1008, label: "7 days", description: "Minimum recommended" },
  { blocks: 2016, label: "14 days", description: "Default" },
  { blocks: 4032, label: "30 days", description: "Extended retention" },
];

const PRUNE_PROFILES: { value: PruneProfile; label: string; keep: string; prune: string }[] = [
  { value: "default", label: "Default", keep: "T0, T1, T2", prune: "T3 only" },
  { value: "strict", label: "Strict", keep: "T0, T1", prune: "T2, T3" },
  { value: "clean", label: "Clean", keep: "T0, T1", prune: "T2, T3" },
  { value: "structured", label: "Structured", keep: "T0, T1, T2", prune: "T3" },
  { value: "archive", label: "Archive", keep: "All (T0-T3)", prune: "None" },
];

// ---------------------------------------------------------------------------
// Page Component
// ---------------------------------------------------------------------------

export default function SystemPage() {
  // -- Version & Update hooks --
  const { data: version, isLoading: versionLoading } = useSystemVersion();
  const {
    data: updateCheck,
    isLoading: updateCheckLoading,
    refetch: recheckUpdates,
    isFetching: isChecking,
  } = useCheckForUpdates({ enabled: true });

  const [isUpdating, setIsUpdating] = useState(false);
  const { data: statusData } = useUpdateStatus({
    refetchInterval: isUpdating ? 1000 : false,
    enabled: isUpdating,
  });

  const startUpdate = useStartUpdate();
  const rollback = useRollbackUpdate();

  const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
  const [rollbackDialogOpen, setRollbackDialogOpen] = useState(false);

  const updateStatus = statusData?.update_status;
  const updateInfo = updateCheck?.update_info;
  const hasUpdate = updateCheck?.update_available ?? false;

  // -- Storage hooks --
  const { data: fullConfig, isLoading: configLoading } = useFullConfig();
  const { data: status } = useNodeStatus();
  const { data: l2Pruning, isLoading: l2Loading } = useL2PruningStatus();
  const { data: ghostPayStatus } = useGhostPayStatus();

  const setPruneProfile = useSetPruneProfile();
  const setOperatorWindow = useSetOperatorWindow();
  const setArchiveMode = useSetArchiveMode();

  const archiveMode = status?.archive_mode ?? false;
  const ghostPayRunning = !!ghostPayStatus?.l2_height;

  // -- Backup hooks --
  const { data: historyData, isLoading: backupLoading } = useBackupHistory();
  const createBackup = useCreateBackup();
  const importBackup = useImportBackup();
  const verifyBackup = useVerifyBackup();
  const deleteBackupMutation = useDeleteBackup();

  const [exportDialogOpen, setExportDialogOpen] = useState(false);

  const [importDialogOpen, setImportDialogOpen] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerifyBackupResponse | null>(null);
  // Set after a successful import: the artifact is staged and a restart applies it.
  const [restartRequired, setRestartRequired] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const backupHistory = historyData?.backups ?? [];

  // -- Toast --
  const { success, error: toastError, warning } = useToast();

  // -------------------------------------------------------------------------
  // Update handlers
  // -------------------------------------------------------------------------

  useEffect(() => {
    if (!updateStatus) return;

    if (updateStatus.status === "complete") {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setIsUpdating(false);
      success(
        "Update Complete",
        "message" in updateStatus ? updateStatus.message : "Node updated successfully. Please restart the node.",
      );
    } else if (updateStatus.status === "failed") {
      setIsUpdating(false);
      toastError(
        "Update Failed",
        "error" in updateStatus ? updateStatus.error : "Unknown error occurred",
      );
    }
  }, [updateStatus, success, toastError]);

  const handleCheckForUpdates = async () => {
    try {
      await recheckUpdates();
      if (!updateCheck?.update_available) {
        success("Up to Date", "You are running the latest version");
      }
    } catch (err) {
      toastError("Check Failed", err instanceof Error ? err.message : "Failed to check for updates");
    }
  };

  const handleStartUpdate = async () => {
    setConfirmDialogOpen(false);
    setIsUpdating(true);
    try {
      const result = await startUpdate.mutateAsync();
      if (!result.success) {
        setIsUpdating(false);
        toastError("Update Failed", result.message);
      }
    } catch (err) {
      setIsUpdating(false);
      toastError("Update Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleRollback = async () => {
    setRollbackDialogOpen(false);
    try {
      const result = await rollback.mutateAsync();
      if (result.success) {
        success("Rollback Started", result.message);
      } else {
        toastError("Rollback Failed", result.message);
      }
    } catch (err) {
      toastError("Rollback Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  // -------------------------------------------------------------------------
  // Storage handlers
  // -------------------------------------------------------------------------

  const handlePruneProfileChange = async (profile: PruneProfile) => {
    try {
      await setPruneProfile.mutateAsync(profile);
      success("Profile Updated", `Prune profile set to "${profile}"`);
    } catch (err) {
      toastError("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleOperatorWindowChange = async (blocks: number) => {
    try {
      await setOperatorWindow.mutateAsync(blocks);
      success("Window Updated", `Operator window set to ${formatDuration(blocks)}`);
    } catch (err) {
      toastError("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleArchiveModeToggle = async () => {
    try {
      await setArchiveMode.mutateAsync(!archiveMode);
      success("Mode Changed", `Archive Mode ${!archiveMode ? "enabled" : "disabled"}`);
    } catch (err) {
      toastError("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  // -------------------------------------------------------------------------
  // Backup handlers
  // -------------------------------------------------------------------------

  const handleDownload = (filename: string) => {
    const url = getBackupDownloadUrl(filename);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleDeleteBackup = async (filename: string) => {
    if (!confirm(`Are you sure you want to delete ${filename}?`)) return;

    try {
      const result = await deleteBackupMutation.mutateAsync(filename);
      if (result.success) {
        success("Backup Deleted", `${filename} has been deleted`);
      } else {
        toastError("Delete Failed", result.error || "Delete failed");
      }
    } catch (err) {
      console.error("Delete error:", err);
      toastError("Delete Failed", err instanceof Error ? err.message : String(err));
    }
  };

  const handleExport = async () => {
    try {
      // The node produces a full encrypted snapshot server-side, then we stream
      // the bytes down through the proxy.
      const result = await createBackup.mutateAsync();

      const link = document.createElement("a");
      link.href = getBackupDownloadUrl(result.filename);
      link.download = result.filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      success("Backup Created", `Backup saved as ${result.filename}`);
      setExportDialogOpen(false);
    } catch (err) {
      toastError("Export Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setSelectedFile(file);
    setVerifyResult(null);
  };

  const handleVerify = async () => {
    if (!selectedFile) return;

    try {
      const result = await verifyBackup.mutateAsync({ file: selectedFile });
      setVerifyResult(result);

      if (result.valid) {
        success("Backup Verified", "Backup file passed the integrity and schema checks");
      } else {
        warning("Verification Failed", result.error ?? "Backup file is invalid or corrupt");
      }
    } catch (err) {
      toastError("Verification Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleImport = async () => {
    if (!selectedFile || !verifyResult?.valid) return;

    try {
      const result = await importBackup.mutateAsync({ file: selectedFile });
      setRestartRequired(Boolean(result.restart_required));
      success(
        "Restore Staged",
        result.message ??
          "Backup verified and staged. Restart ghost-pool to apply the restore.",
      );
    } catch (err) {
      toastError("Import Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="system"
        title="Process health and resources."
        subtitle="Version, updates, storage, and backups"
      />

      {/* ----------------------------------------------------------------- */}
      {/* Version                                                            */}
      {/* ----------------------------------------------------------------- */}
      <SectionErrorBoundary section="Version">
        {versionLoading ? (
          <SkeletonCard />
        ) : (
          <Card>
            <CardHeader title="Version" />
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 bg-gray-800/50 rounded-lg">
                <div className="text-sm text-gray-400 mb-1">Version</div>
                <div className="text-xl font-bold text-orange-400">
                  {version?.version ?? version?.node_version ?? "Unknown"}
                </div>
              </div>
              <div className="p-4 bg-gray-800/50 rounded-lg">
                <div className="text-sm text-gray-400 mb-1">Build Date</div>
                <div className="text-gray-100">
                  {version?.build_time ? formatDate(version.build_time) : "Unknown"}
                </div>
              </div>
              <div className="p-4 bg-gray-800/50 rounded-lg">
                <div className="text-sm text-gray-400 mb-1">Git Commit</div>
                <code className="text-gray-300 text-sm">
                  {version?.git_hash?.substring(0, 8) ?? "Unknown"}
                </code>
              </div>
            </div>
          </Card>
        )}
      </SectionErrorBoundary>

      {/* ----------------------------------------------------------------- */}
      {/* Software Updates                                                   */}
      {/* ----------------------------------------------------------------- */}
      <SectionErrorBoundary section="Updates">
        <Card collapsible>
          <CardHeader
            title="Software Updates"
            subtitle="Check and install from GitHub releases"
          />

          {updateCheckLoading ? (
            <SkeletonCard />
          ) : (
            <div className="space-y-6">
              {/* Update Progress (visible only while updating) */}
              {isUpdating && updateStatus && (
                <div className="space-y-4 p-4 bg-gray-800/50 rounded-lg">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-300">Status</span>
                    <Badge variant={getStatusBadge(updateStatus.status).variant}>
                      {getStatusBadge(updateStatus.status).label}
                    </Badge>
                  </div>

                  {"progress" in updateStatus && updateStatus.progress && (
                    <>
                      <ProgressBar
                        value={updateStatus.progress.progress_percent ?? 0}
                        label={updateStatus.progress.step}
                        sublabel={`${updateStatus.progress.progress_percent}%`}
                        color="orange"
                      />
                      <p className="text-sm text-gray-500">{updateStatus.progress.message}</p>
                    </>
                  )}

                  {updateStatus.status === "verifying" && (
                    <div className="flex items-center gap-2">
                      <div className="animate-spin w-4 h-4 border-2 border-orange-500 border-t-transparent rounded-full" />
                      <span className="text-gray-400">Verifying SHA256 checksum...</span>
                    </div>
                  )}
                </div>
              )}

              {/* Available Update */}
              {hasUpdate && updateInfo ? (
                <>
                  <div className="p-4 bg-orange-900/20 border border-orange-700 rounded-lg">
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="flex items-center gap-3 mb-2">
                          <h3 className="text-lg font-bold text-orange-300">
                            Version {updateInfo.version}
                          </h3>
                          <Badge variant="success">New</Badge>
                        </div>
                        <p className="text-sm text-gray-400">
                          Released {formatDate(updateInfo.release_date ?? "")} &middot;{" "}
                          {formatBytes(updateInfo.size_bytes ?? 0)}
                        </p>
                      </div>
                      <Button
                        onClick={() => setConfirmDialogOpen(true)}
                        disabled={isUpdating || startUpdate.isPending}
                        loading={startUpdate.isPending}
                      >
                        Install Update
                      </Button>
                    </div>
                  </div>

                  {updateInfo.changelog && (
                    <div className="p-4 bg-gray-800/50 rounded-lg">
                      <h4 className="text-sm font-medium text-gray-300 mb-3">Release Notes</h4>
                      <div className="prose prose-sm prose-invert max-w-none">
                        <pre className="text-sm text-gray-400 whitespace-pre-wrap font-sans">
                          {updateInfo.changelog}
                        </pre>
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <div className="text-center py-6">
                  <div className="text-4xl mb-3">&#10003;</div>
                  <h3 className="text-lg font-medium text-gray-100 mb-1">
                    You&apos;re up to date!
                  </h3>
                  <p className="text-gray-400 mb-4">
                    Running version {updateCheck?.current_version ?? version?.version ?? version?.node_version}
                  </p>
                </div>
              )}

              <Button
                onClick={handleCheckForUpdates}
                variant="secondary"
                className="w-full"
                loading={isChecking}
                disabled={isUpdating}
              >
                Check for Updates
              </Button>

              {/* Automatic Updates (opt-in, default OFF). Shared with /settings/system. */}
              <div className="pt-4 border-t border-gray-800">
                <AutoUpdateSection />
              </div>

              {/* Rollback */}
              <div className="pt-4 border-t border-gray-800">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm font-medium text-gray-300">Rollback</div>
                    <p className="text-xs text-gray-500 mt-0.5">
                      Revert to the previous version if an update causes issues. The node will restart.
                    </p>
                  </div>
                  <Button
                    onClick={() => setRollbackDialogOpen(true)}
                    variant="warning"
                    size="sm"
                    disabled={isUpdating || rollback.isPending}
                    loading={rollback.isPending}
                  >
                    Rollback
                  </Button>
                </div>
              </div>

              {/* About Updates */}
              <div className="p-4 bg-orange-900/20 border border-orange-800 rounded-lg">
                <h4 className="text-orange-300 font-medium mb-2">About Updates</h4>
                <ul className="text-sm text-orange-300/80 space-y-1 list-disc list-inside">
                  <li>Updates are downloaded from official GitHub releases</li>
                  <li>SHA256 checksums are verified before installation</li>
                  <li>Current binaries are backed up before updating</li>
                  <li>The node will restart automatically after update</li>
                  <li>You can rollback to the previous version if needed</li>
                </ul>
              </div>
            </div>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* ----------------------------------------------------------------- */}
      {/* Storage & Pruning                                                  */}
      {/* ----------------------------------------------------------------- */}
      <SectionErrorBoundary section="Storage">
        <Card collapsible>
          <CardHeader
            title="Storage & Pruning"
            subtitle="L1/L2 pruning, archive mode, and operator window"
            action={archiveMode ? <Badge variant="success">+5 Shares (Archive)</Badge> : undefined}
          />

          {configLoading ? (
            <SkeletonCard />
          ) : (
            <div className="space-y-6">
              {/* ---------- L1 Pruning ---------- */}
              <div className="space-y-6">
                <h4 className="text-sm font-medium text-gray-300 uppercase tracking-wider">L1 Pruning</h4>

                {/* Archive Mode Toggle */}
                <div className="p-4 bg-gray-800/50 rounded-lg">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-gray-100 font-medium">Archive Mode</span>
                        {archiveMode && <Badge variant="success">+5 Shares</Badge>}
                      </div>
                      <p className="text-sm text-gray-400 mt-1">
                        Store complete blockchain history. Disables all pruning and earns bonus shares.
                      </p>
                    </div>
                    <Button
                      variant={archiveMode ? "primary" : "secondary"}
                      onClick={handleArchiveModeToggle}
                      loading={setArchiveMode.isPending}
                    >
                      {archiveMode ? "Enabled" : "Disabled"}
                    </Button>
                  </div>
                </div>

                {/* Window Visualization */}
                <div className="grid grid-cols-3 gap-4">
                  <div className="p-4 bg-orange-900/20 border border-orange-800 rounded-lg">
                    <div className="text-orange-400 font-medium mb-2">Validator Window (VW)</div>
                    <div className="text-2xl font-bold text-gray-100">288 blocks</div>
                    <div className="text-sm text-gray-400 mt-1">~2 days</div>
                    <div className="mt-3 text-xs text-orange-300">
                      Fixed - Bitcoin Core minimum for reorg safety
                    </div>
                  </div>

                  <div className={`p-4 rounded-lg border ${archiveMode ? "bg-gray-800/30 border-gray-700" : "bg-orange-900/20 border-orange-800"}`}>
                    <div className={`font-medium mb-2 ${archiveMode ? "text-gray-500" : "text-orange-400"}`}>
                      Operator Window (OW)
                    </div>
                    <div className={`text-2xl font-bold ${archiveMode ? "text-gray-500" : "text-gray-100"}`}>
                      {fullConfig?.pruning?.ow_blocks ?? 2016} blocks
                    </div>
                    <div className="text-sm text-gray-400 mt-1">
                      ~{formatDuration(fullConfig?.pruning?.ow_blocks ?? 2016)}
                    </div>
                    <div className={`mt-3 text-xs ${archiveMode ? "text-gray-500" : "text-orange-300"}`}>
                      {archiveMode ? "Disabled (Archive Mode)" : "BUDS-based pruning applied here"}
                    </div>
                  </div>

                  <div className={`p-4 rounded-lg border ${archiveMode ? "bg-green-900/20 border-green-800" : "bg-gray-800/30 border-gray-700"}`}>
                    <div className={`font-medium mb-2 ${archiveMode ? "text-green-400" : "text-gray-500"}`}>
                      Archive Window (AW)
                    </div>
                    <div className={`text-2xl font-bold ${archiveMode ? "text-gray-100" : "text-gray-500"}`}>
                      {archiveMode ? "Infinite" : "Pruned"}
                    </div>
                    <div className="text-sm text-gray-400 mt-1">
                      {archiveMode ? "All history retained" : "Data beyond OW is deleted"}
                    </div>
                    <div className={`mt-3 text-xs ${archiveMode ? "text-green-300" : "text-gray-500"}`}>
                      {archiveMode ? "Full chain storage enabled" : "Enable Archive Mode for +5 shares"}
                    </div>
                  </div>
                </div>

                {/* Operator Window Selection */}
                {!archiveMode && (
                  <div className="space-y-3">
                    <label className="text-sm font-medium text-gray-300">Operator Window Size</label>
                    <div className="grid grid-cols-3 gap-3">
                      {OW_PRESETS.map((preset) => (
                        <button
                          key={preset.blocks}
                          onClick={() => handleOperatorWindowChange(preset.blocks)}
                          disabled={setOperatorWindow.isPending}
                          className={`p-3 rounded-lg border transition-colors text-left ${
                            fullConfig?.pruning?.ow_blocks === preset.blocks
                              ? "bg-orange-900/30 border-orange-600 text-orange-300"
                              : "bg-gray-800/50 border-gray-700 text-gray-300 hover:border-gray-500"
                          }`}
                        >
                          <div className="font-medium">{preset.label}</div>
                          <div className="text-xs text-gray-500 mt-1">{preset.blocks} blocks</div>
                          <div className="text-xs text-gray-400 mt-1">{preset.description}</div>
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Prune Profile Selection */}
                {!archiveMode && (
                  <div className="space-y-3">
                    <label className="text-sm font-medium text-gray-300">BUDS Prune Profile</label>
                    <p className="text-xs text-gray-500">
                      Controls which BUDS tiers are retained in the Operator Window
                    </p>
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                      {PRUNE_PROFILES.filter((p) => p.value !== "archive").map((profile) => (
                        <button
                          key={profile.value}
                          onClick={() => handlePruneProfileChange(profile.value)}
                          disabled={setPruneProfile.isPending}
                          className={`p-3 rounded-lg border transition-colors text-left ${
                            fullConfig?.pruning?.prune_profile === profile.value
                              ? "bg-orange-900/30 border-orange-600 text-orange-300"
                              : "bg-gray-800/50 border-gray-700 text-gray-300 hover:border-gray-500"
                          }`}
                        >
                          <div className="font-medium capitalize">{profile.label}</div>
                          <div className="text-xs text-green-400 mt-1">Keep: {profile.keep}</div>
                          <div className="text-xs text-red-400">Prune: {profile.prune}</div>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* ---------- L2 Pruning ---------- */}
              <div className="space-y-4 pt-4 border-t border-gray-800">
                <h4 className="text-sm font-medium text-gray-300 uppercase tracking-wider">L2 Pruning (Ghost Pay)</h4>

                {!ghostPayRunning ? (
                  <div className="p-4 bg-yellow-900/20 border border-yellow-800 rounded-lg">
                    <div className="flex items-center gap-2">
                      <Badge variant="warning">Ghost Pay Not Running</Badge>
                    </div>
                    <p className="text-sm text-yellow-300 mt-2">
                      Start ghost-pay-node to enable L2 functionality and see pruning status.
                    </p>
                  </div>
                ) : l2Loading ? (
                  <SkeletonCard />
                ) : l2Pruning ? (
                  <>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="p-4 bg-gray-800/50 rounded-lg">
                        <div className="text-sm text-gray-400">Retention Period</div>
                        <div className="text-xl font-bold text-gray-100 mt-1">
                          {l2Pruning.retention_days} days
                        </div>
                      </div>
                      <div className="p-4 bg-gray-800/50 rounded-lg">
                        <div className="text-sm text-gray-400">Auto Prune</div>
                        <div className="mt-1">
                          <Badge variant="success">Always On</Badge>
                        </div>
                        <div className="text-xs text-gray-500 mt-1">
                          Every {l2Pruning.prune_interval_hours}h
                        </div>
                      </div>
                      <div className="p-4 bg-gray-800/50 rounded-lg">
                        <div className="text-sm text-gray-400">Last Prune</div>
                        <div className="text-lg font-medium text-gray-100 mt-1">
                          {formatTimeAgo(l2Pruning.last_prune_timestamp ?? 0)}
                        </div>
                        <div className="text-xs text-gray-500 mt-1">
                          {formatTimestamp(l2Pruning.last_prune_timestamp ?? 0)}
                        </div>
                      </div>
                      <div className="p-4 bg-gray-800/50 rounded-lg">
                        <div className="text-sm text-gray-400">Last Run Stats</div>
                        <div className="text-sm text-gray-300 mt-2 space-y-1">
                          <div>Payments: {l2Pruning.payments_pruned}</div>
                          <div>Attestations: {l2Pruning.attestations_pruned}</div>
                          <div>Locks: {l2Pruning.locks_pruned}</div>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="p-4 bg-red-900/20 border border-red-800 rounded-lg">
                        <h4 className="text-red-300 font-medium mb-3">What Gets Pruned</h4>
                        <ul className="text-sm text-red-200/80 space-y-2">
                          <li className="flex items-start gap-2">
                            <span className="text-red-400 mt-0.5">&bull;</span>
                            <span>Payments (with ZK proofs) older than {l2Pruning.retention_days} days</span>
                          </li>
                          <li className="flex items-start gap-2">
                            <span className="text-red-400 mt-0.5">&bull;</span>
                            <span>Attestations older than {l2Pruning.retention_days} days</span>
                          </li>
                          <li className="flex items-start gap-2">
                            <span className="text-red-400 mt-0.5">&bull;</span>
                            <span>Closed locks (reconciled or jumped) older than {l2Pruning.retention_days} days</span>
                          </li>
                        </ul>
                      </div>
                      <div className="p-4 bg-green-900/20 border border-green-800 rounded-lg">
                        <h4 className="text-green-300 font-medium mb-3">What is Never Pruned</h4>
                        <ul className="text-sm text-green-200/80 space-y-2">
                          <li className="flex items-start gap-2">
                            <span className="text-green-400 mt-0.5">&bull;</span>
                            <span>Active locks (regardless of age)</span>
                          </li>
                          <li className="flex items-start gap-2">
                            <span className="text-green-400 mt-0.5">&bull;</span>
                            <span>L2 block headers (contain state_root commitments)</span>
                          </li>
                        </ul>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="p-4 bg-gray-800/50 rounded-lg text-gray-400">
                    Unable to fetch L2 pruning status. Ensure ghost-pay-node API is accessible.
                  </div>
                )}
              </div>

              {/* Quick Reference Table */}
              <div className="pt-4 border-t border-gray-800">
                <h4 className="text-sm font-medium text-gray-300 mb-3">Quick Reference</h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-gray-400 border-b border-gray-800">
                        <th className="pb-3 font-medium">Layer</th>
                        <th className="pb-3 font-medium">Window</th>
                        <th className="pb-3 font-medium">Duration</th>
                        <th className="pb-3 font-medium">Behavior</th>
                      </tr>
                    </thead>
                    <tbody className="text-gray-300">
                      <tr className="border-b border-gray-800/50">
                        <td className="py-3">L1</td>
                        <td className="py-3">Validator (VW)</td>
                        <td className="py-3">288 blocks (~2 days)</td>
                        <td className="py-3">Full retention - Bitcoin Core minimum</td>
                      </tr>
                      <tr className="border-b border-gray-800/50">
                        <td className="py-3">L1</td>
                        <td className="py-3">Operator (OW)</td>
                        <td className="py-3">
                          {fullConfig?.pruning?.ow_blocks ?? 2016} blocks (~{formatDuration(fullConfig?.pruning?.ow_blocks ?? 2016)})
                        </td>
                        <td className="py-3">
                          {archiveMode
                            ? "Archive Mode - no pruning"
                            : `BUDS pruning (${fullConfig?.pruning?.prune_profile ?? "default"})`}
                        </td>
                      </tr>
                      <tr className="border-b border-gray-800/50">
                        <td className="py-3">L1</td>
                        <td className="py-3">Archive (AW)</td>
                        <td className="py-3">{archiveMode ? "Infinite" : "N/A"}</td>
                        <td className="py-3">
                          {archiveMode ? "Full chain stored (+5 shares)" : "Data pruned beyond OW"}
                        </td>
                      </tr>
                      <tr>
                        <td className="py-3">L2</td>
                        <td className="py-3">Retention</td>
                        <td className="py-3">{l2Pruning?.retention_days ?? 90} days</td>
                        <td className="py-3">Auto-prune payments, attestations, closed locks</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* ----------------------------------------------------------------- */}
      {/* Backup & Restore                                                   */}
      {/* ----------------------------------------------------------------- */}
      <SectionErrorBoundary section="Backup">
        <Card>
          <CardHeader title="Backup & Restore" />

          <div className="space-y-6">
            {/* Export / Import buttons */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-gray-800/50 rounded-lg">
                <div className="text-gray-100 font-medium mb-1">Export Backup</div>
                <p className="text-gray-400 text-sm mb-3">
                  Create a full snapshot of this node&apos;s pool database (miners, shares,
                  rounds, payouts) and download it. The artifact is encrypted with this
                  node&apos;s own key.
                </p>
                <Button variant="primary" onClick={() => setExportDialogOpen(true)}>
                  Create Backup
                </Button>
              </div>

              <div className="p-4 bg-gray-800/50 rounded-lg">
                <div className="text-gray-100 font-medium mb-1">Import Backup</div>
                <p className="text-gray-400 text-sm mb-3">
                  Restore from a backup file. The artifact is verified, then staged and applied
                  atomically on the next ghost-pool restart (your current database is copied to a
                  safety backup first).
                </p>
                <Button variant="secondary" onClick={() => setImportDialogOpen(true)}>
                  Restore Backup
                </Button>
              </div>
            </div>

            {/* Backup History */}
            <div className="pt-4 border-t border-gray-800">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-sm font-medium text-gray-300">
                  Backup History ({backupHistory.length})
                </h4>
              </div>

              {backupLoading ? (
                <SkeletonCard />
              ) : backupHistory.length === 0 ? (
                <div className="text-center py-6">
                  <p className="text-gray-400">No backups created yet</p>
                  <p className="text-sm text-gray-500 mt-1">
                    Create your first backup to protect your node data
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {backupHistory.map((backup, idx) => (
                    <div
                      key={`${backup.filename}-${idx}`}
                      className="p-4 bg-gray-800/50 rounded-lg border border-gray-700"
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-gray-100 font-medium">{backup.filename}</span>
                            <Badge variant="info">{formatBytes(backup.size_bytes ?? 0)}</Badge>
                          </div>
                          <div className="text-sm text-gray-400 mt-1">
                            Created: {formatTimestampDate(backup.created_at ?? 0)}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant="success">Full</Badge>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDownload(backup.filename)}
                          >
                            Download
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDeleteBackup(backup.filename)}
                            disabled={deleteBackupMutation.isPending}
                          >
                            Delete
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Backup Best Practices */}
            <div className="p-4 bg-orange-900/20 border border-orange-800 rounded-lg">
              <h4 className="text-orange-300 font-medium mb-2">Backup Best Practices</h4>
              <ul className="text-sm text-orange-300/80 space-y-1 list-disc list-inside">
                <li>Create regular backups before making configuration changes</li>
                <li>Store backup files in a secure location separate from your node</li>
                <li>The artifact is encrypted with this node&apos;s key — restore it on this node</li>
                <li>Test your backups periodically by verifying them</li>
                <li>Keep multiple backup copies in different locations</li>
              </ul>
            </div>
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* ----------------------------------------------------------------- */}
      {/* Scheduled Backups                                                  */}
      {/* ----------------------------------------------------------------- */}
      <SectionErrorBoundary section="Scheduled Backups">
        <ScheduledBackupsCard />
      </SectionErrorBoundary>

      {/* ================================================================= */}
      {/* Dialogs                                                            */}
      {/* ================================================================= */}

      {/* Install Update Confirmation Dialog */}
      <Dialog
        isOpen={confirmDialogOpen}
        onClose={() => setConfirmDialogOpen(false)}
        title="Install Update"
      >
        <div className="space-y-4">
          <p className="text-gray-300">
            Are you sure you want to update to version{" "}
            <strong className="text-white">{updateInfo?.version}</strong>?
          </p>
          <div className="p-3 bg-orange-900/20 border border-orange-800 rounded">
            <p className="text-sm text-orange-400">
              The node will be stopped during the update and automatically restarted once complete.
              Your current version will be backed up in case you need to rollback.
            </p>
          </div>
          <div className="flex gap-3 pt-4 border-t border-gray-800">
            <Button
              variant="ghost"
              className="flex-1"
              onClick={() => setConfirmDialogOpen(false)}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              className="flex-1"
              onClick={handleStartUpdate}
              loading={startUpdate.isPending}
            >
              Install Update
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Rollback Confirmation Dialog */}
      <Dialog
        isOpen={rollbackDialogOpen}
        onClose={() => setRollbackDialogOpen(false)}
        title="Rollback to Previous Version"
      >
        <div className="space-y-4">
          <p className="text-gray-300">
            Are you sure you want to rollback to the previous version?
          </p>
          <div className="p-3 bg-yellow-900/20 border border-yellow-800 rounded">
            <p className="text-sm text-yellow-400">
              This will restore the backup of your previous Ghost Node version.
              The node will restart after the rollback completes.
            </p>
          </div>
          <div className="flex gap-3 pt-4 border-t border-gray-800">
            <Button
              variant="ghost"
              className="flex-1"
              onClick={() => setRollbackDialogOpen(false)}
            >
              Cancel
            </Button>
            <Button
              variant="warning"
              className="flex-1"
              onClick={handleRollback}
              loading={rollback.isPending}
            >
              Rollback
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Export Backup Dialog */}
      <Dialog
        isOpen={exportDialogOpen}
        onClose={() => setExportDialogOpen(false)}
        title="Create Backup"
      >
        <div className="space-y-4">
          <p className="text-sm text-gray-300">
            This creates a consistent, compact snapshot of this node&apos;s pool database
            (<span className="font-mono text-gray-200">VACUUM INTO</span>) — miners, shares,
            rounds and payout records — and downloads it as a timestamped
            <span className="font-mono text-gray-200"> .db</span> file.
          </p>

          <div className="p-3 bg-gray-800/50 border border-gray-700 rounded space-y-1">
            <p className="text-sm text-gray-300">
              The artifact is encrypted with this node&apos;s own key: payout addresses stay
              field-encrypted, so no separate backup password is needed.
            </p>
          </div>

          <div className="p-3 bg-yellow-900/20 border border-yellow-800 rounded">
            <p className="text-yellow-400 text-sm">
              Because it is bound to this node&apos;s key, restore this backup on this same node.
            </p>
          </div>

          <div className="flex gap-3 pt-4 border-t border-gray-800">
            <Button variant="ghost" className="flex-1" onClick={() => setExportDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              className="flex-1"
              onClick={handleExport}
              loading={createBackup.isPending}
            >
              Create Backup
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Import Backup Dialog */}
      <Dialog
        isOpen={importDialogOpen}
        onClose={() => {
          setImportDialogOpen(false);
          setSelectedFile(null);
          setVerifyResult(null);
          setRestartRequired(false);
        }}
        title="Restore Backup"
      >
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Backup File</label>
            <input
              ref={fileInputRef}
              type="file"
              accept=".db,.backup"
              onChange={handleFileSelect}
              className="hidden"
            />
            <div className="flex gap-2">
              <Button
                variant="secondary"
                onClick={() => fileInputRef.current?.click()}
                className="flex-1"
              >
                {selectedFile ? selectedFile.name : "Select File"}
              </Button>
              {selectedFile && (
                <Button
                  variant="ghost"
                  onClick={() => {
                    setSelectedFile(null);
                    setVerifyResult(null);
                  }}
                >
                  Clear
                </Button>
              )}
            </div>
          </div>

          {!restartRequired && !verifyResult && selectedFile && (
            <Button
              variant="secondary"
              onClick={handleVerify}
              loading={verifyBackup.isPending}
              className="w-full"
            >
              Verify Backup
            </Button>
          )}

          {!restartRequired && verifyResult && (
            <div
              className={`p-4 rounded-lg border ${
                verifyResult.valid
                  ? "bg-green-900/20 border-green-800"
                  : "bg-red-900/20 border-red-800"
              }`}
            >
              <div className="flex items-center gap-2 mb-2">
                <Badge variant={verifyResult.valid ? "success" : "error"}>
                  {verifyResult.valid ? "Valid" : "Invalid"}
                </Badge>
                <span className={verifyResult.valid ? "text-green-400" : "text-red-400"}>
                  {verifyResult.valid ? "Passed integrity + schema checks" : verifyResult.error}
                </span>
              </div>
              {verifyResult.valid && verifyResult.info && (
                <div className="text-sm text-gray-400 space-y-1">
                  <p>Integrity: {verifyResult.info.integrity_ok ? "ok" : "failed"}</p>
                  <p>Schema version: {verifyResult.info.schema_version ?? "?"}</p>
                  <p>Tables: {verifyResult.info.table_count ?? 0}</p>
                  <p>Miners: {verifyResult.info.miner_count ?? 0}</p>
                  <p>Size: {formatBytes(verifyResult.info.size_bytes ?? 0)}</p>
                  <div className="flex gap-2 mt-2">
                    {verifyResult.info.encrypted && <Badge variant="info">Encrypted</Badge>}
                  </div>
                </div>
              )}
            </div>
          )}

          {!restartRequired && verifyResult?.valid && (
            <div className="p-3 bg-yellow-900/20 border border-yellow-800 rounded">
              <p className="text-yellow-400 text-sm">
                Restoring stages this artifact and applies it on the next ghost-pool restart.
                Your current database is copied to a timestamped safety backup first, then
                replaced. Restart the node to complete the restore.
              </p>
            </div>
          )}

          {restartRequired && (
            <div className="p-4 rounded-lg border bg-blue-900/20 border-blue-800 space-y-2">
              <div className="flex items-center gap-2">
                <Badge variant="info">Restart required</Badge>
                <span className="text-blue-300">Restore staged</span>
              </div>
              <p className="text-sm text-gray-400">
                The backup was verified and staged. Restart ghost-pool (System &gt; Restart, or
                the node&apos;s service manager) to apply it. The current database is copied to a
                <span className="font-mono"> .pre-restore-*.db </span> safety backup automatically
                before the swap.
              </p>
            </div>
          )}

          <div className="flex gap-3 pt-4 border-t border-gray-800">
            <Button
              variant="ghost"
              className="flex-1"
              onClick={() => {
                setImportDialogOpen(false);
                setSelectedFile(null);
                setVerifyResult(null);
                setRestartRequired(false);
              }}
            >
              {restartRequired ? "Close" : "Cancel"}
            </Button>
            {!restartRequired && (
              <Button
                variant="danger"
                className="flex-1"
                onClick={handleImport}
                loading={importBackup.isPending}
                disabled={!verifyResult?.valid}
              >
                Restore Backup
              </Button>
            )}
          </div>
        </div>
      </Dialog>
    </div>
  );
}
