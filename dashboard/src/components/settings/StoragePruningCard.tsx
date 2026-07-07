"use client";

import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { SkeletonCard } from "@/components/ui/Skeleton";
import {
  useFullConfig,
  useNodeStatus,
  useSetPruneProfile,
  useSetOperatorWindow,
  useSetArchiveMode,
} from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import type { PruneProfile } from "@/types/api";

// Preset OW options (in blocks).
const OW_PRESETS = [
  { blocks: 1008, label: "7 days", description: "Minimum recommended" },
  { blocks: 2016, label: "14 days", description: "Default" },
  { blocks: 4032, label: "30 days", description: "Extended retention" },
];

// Prune profile descriptions.
const PRUNE_PROFILES: { value: PruneProfile; label: string; keep: string; prune: string }[] = [
  { value: "default", label: "Default", keep: "T0, T1, T2", prune: "T3 only" },
  { value: "strict", label: "Strict", keep: "T0, T1", prune: "T2, T3" },
  { value: "clean", label: "Clean", keep: "T0, T1", prune: "T2, T3" },
  { value: "structured", label: "Structured", keep: "T0, T1, T2", prune: "T3" },
  { value: "archive", label: "Archive", keep: "All (T0-T3)", prune: "None" },
];

function formatDuration(blocks: number): string {
  const days = Math.round(blocks / 144);
  if (days === 1) return "1 day";
  if (days < 7) return `${days} days`;
  if (days === 7) return "1 week";
  if (days < 30) return `${Math.round(days / 7)} weeks`;
  if (days < 60) return "1 month";
  return `${Math.round(days / 30)} months`;
}

/**
 * L1 pruning controls — Archive Mode, Operator Window size, and BUDS prune
 * profile — as a single self-contained card. Shared between /storage and
 * /settings/storage so both surfaces drive the SAME endpoints
 * (`useSetArchiveMode`, `useSetOperatorWindow`, `useSetPruneProfile`).
 */
export function StoragePruningCard() {
  const { data: fullConfig, isLoading: configLoading } = useFullConfig();
  const { data: status } = useNodeStatus();

  const setPruneProfile = useSetPruneProfile();
  const setOperatorWindow = useSetOperatorWindow();
  const setArchiveMode = useSetArchiveMode();

  const { success, error } = useToast();

  const archiveMode = status?.archive_mode ?? false;

  const handlePruneProfileChange = async (profile: PruneProfile) => {
    try {
      await setPruneProfile.mutateAsync(profile);
      success("Profile Updated", `Prune profile set to "${profile}"`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleOperatorWindowChange = async (blocks: number) => {
    try {
      await setOperatorWindow.mutateAsync(blocks);
      success("Window Updated", `Operator window set to ${formatDuration(blocks)}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleArchiveModeToggle = async () => {
    try {
      await setArchiveMode.mutateAsync(!archiveMode);
      success("Mode Changed", `Archive Mode ${!archiveMode ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  if (configLoading) {
    return <SkeletonCard />;
  }

  return (
    <Card>
      <CardHeader
        title="L1 Pruning"
        subtitle="Three-window model: VW (consensus safety) -> OW (configurable) -> AW (archive)"
      />
      <div className="space-y-6">
        {/* Archive Mode Toggle */}
        <div className="p-4 bg-[var(--surface)]/50 rounded-lg">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[color:var(--fg)] font-medium">Archive Mode</span>
                {archiveMode && <Badge variant="success">+5 Shares</Badge>}
              </div>
              <p className="text-sm text-[color:var(--dim)] mt-1">
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
          {/* Validator Window */}
          <div className="p-4 bg-[color-mix(in_srgb,var(--accent)_16%,transparent)] border border-[color:var(--accent)] rounded-lg">
            <div className="text-[color:var(--accent)] font-medium mb-2">Validator Window (VW)</div>
            <div className="text-2xl font-bold text-[color:var(--fg)]">288 blocks</div>
            <div className="text-sm text-[color:var(--dim)] mt-1">~2 days</div>
            <div className="mt-3 text-xs text-[color:var(--accent)]">
              Fixed - Bitcoin Core minimum for reorg safety
            </div>
          </div>

          {/* Operator Window */}
          <div className={`p-4 rounded-lg border ${archiveMode ? "bg-[var(--surface)]/30 border-[color:var(--rule-strong)]" : "bg-[color-mix(in_srgb,var(--accent)_16%,transparent)] border-[color:var(--accent)]"}`}>
            <div className={`font-medium mb-2 ${archiveMode ? "text-[color:var(--fainter)]" : "text-[color:var(--accent)]"}`}>
              Operator Window (OW)
            </div>
            <div className={`text-2xl font-bold ${archiveMode ? "text-[color:var(--fainter)]" : "text-[color:var(--fg)]"}`}>
              {fullConfig?.pruning?.ow_blocks ?? 2016} blocks
            </div>
            <div className="text-sm text-[color:var(--dim)] mt-1">
              ~{formatDuration(fullConfig?.pruning?.ow_blocks ?? 2016)}
            </div>
            <div className={`mt-3 text-xs ${archiveMode ? "text-[color:var(--fainter)]" : "text-[color:var(--accent)]"}`}>
              {archiveMode ? "Disabled (Archive Mode)" : "BUDS-based pruning applied here"}
            </div>
          </div>

          {/* Archive Window */}
          <div className={`p-4 rounded-lg border ${archiveMode ? "bg-[color-mix(in_srgb,var(--green)_16%,transparent)] border-[color:var(--green)]" : "bg-[var(--surface)]/30 border-[color:var(--rule-strong)]"}`}>
            <div className={`font-medium mb-2 ${archiveMode ? "text-[color:var(--green)]" : "text-[color:var(--fainter)]"}`}>
              Archive Window (AW)
            </div>
            <div className={`text-2xl font-bold ${archiveMode ? "text-[color:var(--fg)]" : "text-[color:var(--fainter)]"}`}>
              {archiveMode ? "Infinite" : "Pruned"}
            </div>
            <div className="text-sm text-[color:var(--dim)] mt-1">
              {archiveMode ? "All history retained" : "Data beyond OW is deleted"}
            </div>
            <div className={`mt-3 text-xs ${archiveMode ? "text-[color:var(--green)]" : "text-[color:var(--fainter)]"}`}>
              {archiveMode ? "Full chain storage enabled" : "Enable Archive Mode for +5 shares"}
            </div>
          </div>
        </div>

        {/* Operator Window Selection (only if not archive mode) */}
        {!archiveMode && (
          <div className="space-y-3">
            <label className="text-sm font-medium text-[color:var(--dim)]">Operator Window Size</label>
            <div className="grid grid-cols-3 gap-3">
              {OW_PRESETS.map((preset) => (
                <button
                  key={preset.blocks}
                  onClick={() => handleOperatorWindowChange(preset.blocks)}
                  disabled={setOperatorWindow.isPending}
                  className={`p-3 rounded-lg border transition-colors text-left ${
                    fullConfig?.pruning?.ow_blocks === preset.blocks
                      ? "bg-[color-mix(in_srgb,var(--accent)_16%,transparent)] border-[color:var(--accent)] text-[color:var(--accent)]"
                      : "bg-[var(--surface)]/50 border-[color:var(--rule-strong)] text-[color:var(--dim)] hover:border-[color:var(--rule-strong)]"
                  }`}
                >
                  <div className="font-medium">{preset.label}</div>
                  <div className="text-xs text-[color:var(--fainter)] mt-1">{preset.blocks} blocks</div>
                  <div className="text-xs text-[color:var(--dim)] mt-1">{preset.description}</div>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Prune Profile Selection (only if not archive mode) */}
        {!archiveMode && (
          <div className="space-y-3">
            <label className="text-sm font-medium text-[color:var(--dim)]">BUDS Prune Profile</label>
            <p className="text-xs text-[color:var(--fainter)]">
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
                      ? "bg-[color-mix(in_srgb,var(--accent)_16%,transparent)] border-[color:var(--accent)] text-[color:var(--accent)]"
                      : "bg-[var(--surface)]/50 border-[color:var(--rule-strong)] text-[color:var(--dim)] hover:border-[color:var(--rule-strong)]"
                  }`}
                >
                  <div className="font-medium capitalize">{profile.label}</div>
                  <div className="text-xs text-[color:var(--green)] mt-1">Keep: {profile.keep}</div>
                  <div className="text-xs text-[color:var(--red)]">Prune: {profile.prune}</div>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}
