"use client";

import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { SkeletonCard } from "@/components/ui/Skeleton";
import {
  useFullConfig,
  useNodeStatus,
  useSetOperatorWindow,
  useSetArchiveMode,
} from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";

// Preset Operator Window depths (in blocks). Each writes the real
// `storage.prune_height` (blocks to keep). The backend clamps any non-zero
// depth up to the Validator Window floor.
const OW_PRESETS = [
  { blocks: 1008, label: "7 days", description: "Minimum recommended" },
  { blocks: 2016, label: "14 days", description: "Default" },
  { blocks: 4032, label: "30 days", description: "Extended retention" },
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
 * L1 pruning controls as a single self-contained card, built on the three-window
 * model:
 *   - VW (Validator Window) — the mandatory Bitcoin Core prune floor, read-only.
 *   - OW (Operator Window)  — the one editable depth knob = `storage.prune_height`.
 *   - AW (Archive Window)   — `storage.archive_mode`; when on, pruning is disabled.
 *
 * Shared between /storage and /settings/storage so both surfaces drive the SAME
 * endpoints (`useSetArchiveMode`, `useSetOperatorWindow`). Pruning is
 * block-storage only — it is deliberately NOT entangled with BUDS tx-filtering.
 */
export function StoragePruningCard() {
  const { data: fullConfig, isLoading: configLoading } = useFullConfig();
  const { data: status } = useNodeStatus();

  const setOperatorWindow = useSetOperatorWindow();
  const setArchiveMode = useSetArchiveMode();

  const { success, error } = useToast();

  const archiveMode = status?.archive_mode ?? false;
  const vwBlocks = fullConfig?.pruning?.vw_blocks ?? 288;
  const owBlocks = fullConfig?.pruning?.ow_blocks ?? 0;

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
        {/* Archive Mode Toggle (AW) */}
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
          {/* Validator Window (VW) — read-only floor */}
          <div className="p-4 bg-[color-mix(in_srgb,var(--accent)_16%,transparent)] border border-[color:var(--accent)] rounded-lg">
            <div className="text-[color:var(--accent)] font-medium mb-2">Validator Window (VW)</div>
            <div className="text-2xl font-bold text-[color:var(--fg)]">{vwBlocks} blocks</div>
            <div className="text-sm text-[color:var(--dim)] mt-1">~{formatDuration(vwBlocks)}</div>
            <div className="mt-3 text-xs text-[color:var(--accent)]">
              Fixed - Bitcoin Core minimum for reorg safety
            </div>
          </div>

          {/* Operator Window (OW) = prune_height */}
          <div className={`p-4 rounded-lg border ${archiveMode ? "bg-[var(--surface)]/30 border-[color:var(--rule-strong)]" : "bg-[color-mix(in_srgb,var(--accent)_16%,transparent)] border-[color:var(--accent)]"}`}>
            <div className={`font-medium mb-2 ${archiveMode ? "text-[color:var(--fainter)]" : "text-[color:var(--accent)]"}`}>
              Operator Window (OW)
            </div>
            <div className={`text-2xl font-bold ${archiveMode ? "text-[color:var(--fainter)]" : "text-[color:var(--fg)]"}`}>
              {owBlocks > 0 ? `${owBlocks} blocks` : "Keep all"}
            </div>
            <div className="text-sm text-[color:var(--dim)] mt-1">
              {owBlocks > 0 ? `~${formatDuration(owBlocks)}` : "No pruning depth set"}
            </div>
            <div className={`mt-3 text-xs ${archiveMode ? "text-[color:var(--fainter)]" : "text-[color:var(--accent)]"}`}>
              {archiveMode ? "Disabled (Archive Mode)" : "Prune depth (prune_height)"}
            </div>
          </div>

          {/* Archive Window (AW) */}
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
            <p className="text-xs text-[color:var(--fainter)]">
              How many recent blocks to keep on disk (prune_height). Any non-zero depth is
              clamped up to the Validator Window floor.
            </p>
            <div className="grid grid-cols-3 gap-3">
              {OW_PRESETS.map((preset) => (
                <button
                  key={preset.blocks}
                  onClick={() => handleOperatorWindowChange(preset.blocks)}
                  disabled={setOperatorWindow.isPending}
                  className={`p-3 rounded-lg border transition-colors text-left cursor-pointer disabled:cursor-not-allowed ${
                    owBlocks === preset.blocks
                      ? "bg-[color-mix(in_srgb,var(--accent)_16%,transparent)] border-[color:var(--accent)] text-[color:var(--accent)]"
                      : "bg-[var(--surface)]/50 border-[color:var(--rule-strong)] text-[color:var(--dim)] hover:border-[color:var(--accent)] hover:text-[color:var(--fg)] hover:bg-[color-mix(in_srgb,var(--accent)_8%,transparent)]"
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
      </div>
    </Card>
  );
}
