"use client";

import { useEffect, useState } from "react";
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

// ── Operator Window conversions ───────────────────────────────────────────
// The canonical stored value is `storage.prune_height` — a BLOCK COUNT. The
// picker lets an operator think in Time, Blocks or Size, but everything is
// converted back to blocks before it is sent.
const BLOCKS_PER_DAY = 144; // exact (10-min blocks)
const MB_PER_BLOCK = 1.6; // rough average serialized block size
const GB_PER_BLOCK = MB_PER_BLOCK / 1024;

// 14 days — used when no prune depth is set yet (owBlocks === 0 / keep-all).
const DEFAULT_TARGET_BLOCKS = 2016;

type OwUnit = "time" | "blocks" | "size";

const UNIT_META: Record<
  OwUnit,
  { label: string; min: number; max: number; step: number; suffix: string }
> = {
  // ~2 days floor up toward a 3-year / near-archive ceiling.
  time: { label: "Time (days)", min: 2, max: 1095, step: 1, suffix: "days" },
  blocks: { label: "Blocks", min: 288, max: 157_680, step: 144, suffix: "blocks" },
  size: { label: "Size (GB)", min: 0.5, max: 250, step: 0.5, suffix: "GB" },
};

function blocksToUnit(blocks: number, unit: OwUnit): number {
  if (unit === "time") return blocks / BLOCKS_PER_DAY;
  if (unit === "size") return blocks * GB_PER_BLOCK;
  return blocks;
}

function unitToBlocks(value: number, unit: OwUnit): number {
  if (unit === "time") return Math.round(value * BLOCKS_PER_DAY);
  if (unit === "size") return Math.round(value / GB_PER_BLOCK);
  return Math.round(value);
}

// String value for the numeric input in the active unit.
function formatUnitValue(blocks: number, unit: OwUnit): string {
  const v = blocksToUnit(blocks, unit);
  if (unit === "size") return (Math.round(v * 10) / 10).toString();
  return Math.round(v).toString();
}

function formatDaysLabel(blocks: number): string {
  const d = Math.round(blocks / BLOCKS_PER_DAY);
  return `${d.toLocaleString()} day${d === 1 ? "" : "s"}`;
}

function formatSizeLabel(blocks: number): string {
  const gb = blocks * GB_PER_BLOCK;
  return gb < 10
    ? `~${(Math.round(gb * 10) / 10).toFixed(1)} GB`
    : `~${Math.round(gb).toLocaleString()} GB`;
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

        {/* Operator Window Size (only if not archive mode) */}
        {!archiveMode && (
          <OperatorWindowPicker
            owBlocks={owBlocks}
            vwBlocks={vwBlocks}
            isPending={setOperatorWindow.isPending}
            onSet={handleOperatorWindowChange}
          />
        )}
      </div>
    </Card>
  );
}

/**
 * Multi-unit Operator Window depth picker.
 *
 * The canonical value is `prune_height` in BLOCKS; the operator can dial it in
 * whatever unit they think in (Time / Blocks / Size). Slider + numeric input
 * stay in sync and only touch LOCAL state — the POST (which restarts the node)
 * happens on the explicit Set button. The resulting depth is clamped UP to the
 * Validator Window floor to mirror the backend.
 */
function OperatorWindowPicker({
  owBlocks,
  vwBlocks,
  isPending,
  onSet,
}: {
  owBlocks: number;
  vwBlocks: number;
  isPending: boolean;
  onSet: (blocks: number) => void;
}) {
  const initialTarget = owBlocks > 0 ? owBlocks : DEFAULT_TARGET_BLOCKS;

  const [unit, setUnit] = useState<OwUnit>("time");
  const [targetBlocks, setTargetBlocks] = useState(initialTarget);
  const [inputStr, setInputStr] = useState(() => formatUnitValue(initialTarget, "time"));

  // Re-sync local state when the stored value changes (e.g. after a successful
  // Set + config refetch). owBlocks only moves when the backend value moves, so
  // this will not clobber in-progress edits.
  useEffect(() => {
    const next = owBlocks > 0 ? owBlocks : DEFAULT_TARGET_BLOCKS;
    setTargetBlocks(next);
    setInputStr(formatUnitValue(next, unit));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [owBlocks]);

  const meta = UNIT_META[unit];

  // Mirror the backend clamp: any non-zero depth is clamped UP to the VW floor.
  const effectiveBlocks = Math.max(targetBlocks, vwBlocks);
  const clampEngaged = targetBlocks < vwBlocks;
  const isCurrent = effectiveBlocks === owBlocks;

  const sliderValue = Math.min(
    Math.max(blocksToUnit(targetBlocks, unit), meta.min),
    meta.max,
  );
  const fillPct = ((sliderValue - meta.min) / (meta.max - meta.min)) * 100;

  const switchUnit = (u: OwUnit) => {
    setUnit(u);
    setInputStr(formatUnitValue(targetBlocks, u));
  };

  const handleSlider = (raw: string) => {
    const v = parseFloat(raw);
    if (Number.isNaN(v)) return;
    const blocks = Math.max(unitToBlocks(v, unit), 0);
    setTargetBlocks(blocks);
    setInputStr(formatUnitValue(blocks, unit));
  };

  const handleInput = (raw: string) => {
    setInputStr(raw);
    const v = parseFloat(raw);
    if (!Number.isNaN(v) && v >= 0) {
      setTargetBlocks(unitToBlocks(v, unit));
    }
  };

  const applyChip = (blocks: number) => {
    setTargetBlocks(blocks);
    setInputStr(formatUnitValue(blocks, unit));
  };

  const chips = [
    { label: "7d", blocks: 1008 },
    { label: "30d", blocks: 4320 },
    { label: "90d", blocks: 12960 },
    { label: "1yr", blocks: 52560 },
  ];

  return (
    <div className="space-y-4">
      <div>
        <label className="text-sm font-medium text-[color:var(--dim)]">Operator Window Size</label>
        <p className="text-xs text-[color:var(--fainter)] mt-1">
          How much recent history to keep on disk (prune_height). Set it in whatever unit
          you think in — the value is stored as a block count.
        </p>
      </div>

      {/* Unit toggle */}
      <div className="inline-flex rounded-lg border border-[color:var(--rule-strong)] bg-[var(--surface)]/50 p-0.5">
        {(["time", "blocks", "size"] as OwUnit[]).map((u) => (
          <button
            key={u}
            onClick={() => switchUnit(u)}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer ${
              unit === u
                ? "bg-[var(--accent)] text-white"
                : "text-[color:var(--dim)] hover:text-[color:var(--fg)]"
            }`}
          >
            {UNIT_META[u].label}
          </button>
        ))}
      </div>

      {/* Slider + numeric input (kept in sync) */}
      <div className="flex items-center gap-4">
        <input
          type="range"
          className="ow-range flex-1"
          min={meta.min}
          max={meta.max}
          step={meta.step}
          value={sliderValue}
          onChange={(e) => handleSlider(e.target.value)}
          disabled={isPending}
          style={{
            background: `linear-gradient(to right, var(--accent) ${fillPct}%, var(--rule-strong) ${fillPct}%)`,
          }}
        />
        <div className="flex items-center gap-2 shrink-0">
          <input
            type="number"
            inputMode="decimal"
            min={meta.min}
            step={meta.step}
            value={inputStr}
            onChange={(e) => handleInput(e.target.value)}
            disabled={isPending}
            className="w-24 px-2 py-1.5 text-sm rounded-lg border border-[color:var(--rule-strong)] bg-[var(--surface)] text-[color:var(--fg)] focus:outline-none focus:border-[color:var(--accent)]"
          />
          <span className="w-12 text-xs text-[color:var(--dim)]">{meta.suffix}</span>
        </div>
      </div>

      {/* Quick chips */}
      <div className="flex flex-wrap gap-2">
        {chips.map((c) => (
          <button
            key={c.label}
            onClick={() => applyChip(c.blocks)}
            disabled={isPending}
            className={`px-3 py-1 text-xs rounded-full border transition-colors cursor-pointer disabled:cursor-not-allowed ${
              targetBlocks === c.blocks
                ? "bg-[color-mix(in_srgb,var(--accent)_16%,transparent)] border-[color:var(--accent)] text-[color:var(--accent)]"
                : "bg-[var(--surface)]/50 border-[color:var(--rule-strong)] text-[color:var(--dim)] hover:border-[color:var(--accent)] hover:text-[color:var(--fg)]"
            }`}
          >
            {c.label}
          </button>
        ))}
      </div>

      {/* Live conversion readout */}
      <div className="p-3 rounded-lg bg-[var(--surface)]/50 border border-[color:var(--rule-strong)] space-y-1">
        <div className="text-sm text-[color:var(--fg)]">
          ≈ {formatDaysLabel(effectiveBlocks)} · {effectiveBlocks.toLocaleString()} blocks ·{" "}
          {formatSizeLabel(effectiveBlocks)}
        </div>
        <p className="text-xs text-[color:var(--fainter)]">
          Size is an estimate — actual disk use depends on block sizes.
        </p>
        {clampEngaged && (
          <p className="text-xs text-[color:var(--yellow)]">
            Below the Validator Window floor — will be clamped up to{" "}
            {vwBlocks.toLocaleString()} blocks (~{formatDuration(vwBlocks)}).
          </p>
        )}
        <p className="text-xs text-[color:var(--fainter)]">
          Validator Window floor: {vwBlocks.toLocaleString()} blocks / ~{formatDuration(vwBlocks)}.
        </p>
      </div>

      {/* Apply */}
      <div className="flex items-center gap-3">
        <Button
          variant="primary"
          onClick={() => onSet(effectiveBlocks)}
          loading={isPending}
          disabled={isPending || isCurrent}
        >
          Set Operator Window
        </Button>
        {isCurrent ? (
          <span className="text-xs text-[color:var(--green)]">Current setting</span>
        ) : (
          <span className="text-xs text-[color:var(--fainter)]">
            Applying a new depth restarts the node.
          </span>
        )}
      </div>

      <p className="text-xs text-[color:var(--fainter)]">
        For full history, use Archive Mode (above).
      </p>
    </div>
  );
}
