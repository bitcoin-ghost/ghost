"use client";

import { useState, useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/Button";
import { useFullConfig } from "@/hooks/queries/useConfigQueries";
import { setTemplateRefresh } from "@/lib/api/config";
import { useToast } from "@/components/ui/Toast";

const MIN = 10;
const MAX = 60;

/**
 * Block-template refresh cadence slider (10–60s). Writes pool.toml
 * [pool].template_refresh_secs via POST /api/v1/config/template_refresh, applied
 * LIVE (no node restart). Controls how often the template is rebuilt from the
 * mempool for fresh fee-paying txs BETWEEN blocks — tip changes are instant
 * regardless (an empty template is pushed on the new tip). Faster = fresher fees
 * at more getblocktemplate load; the revenue upside across the range is modest.
 */
export function TemplateRefreshSlider() {
  const { data: fullConfig } = useFullConfig();
  const { success, error } = useToast();
  const queryClient = useQueryClient();
  const saved = Math.max(MIN, Math.min(MAX, fullConfig?.template_refresh_secs ?? 30));
  const [value, setValue] = useState(saved);
  const [saving, setSaving] = useState(false);

  // Track the saved value when the config loads/changes.
  useEffect(() => {
    setValue(saved);
  }, [saved]);

  const dirty = value !== saved;

  const apply = async () => {
    setSaving(true);
    try {
      const res = await setTemplateRefresh(value);
      success(
        "Refresh cadence updated",
        `Template now rebuilds every ${res.template_refresh_secs}s${res.applied_live ? " (applied live)" : ""}.`,
      );
      queryClient.invalidateQueries({ queryKey: ["config"] });
    } catch (e) {
      error("Failed to update cadence", e instanceof Error ? e.message : "Unknown error");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <div className="flex items-center gap-4">
        <input
          type="range"
          min={MIN}
          max={MAX}
          step={1}
          value={value}
          onChange={(e) => setValue(Number(e.target.value))}
          disabled={saving}
          style={{ flex: 1 }}
          aria-label="Template refresh cadence in seconds"
        />
        <span
          className="t-body"
          style={{
            color: "var(--fg)",
            fontWeight: 600,
            fontVariantNumeric: "tabular-nums",
            minWidth: "3.5rem",
            textAlign: "right",
          }}
        >
          {value}s
        </span>
        <Button variant="primary" size="sm" onClick={apply} disabled={!dirty || saving}>
          {saving ? "Applying…" : "Apply"}
        </Button>
      </div>
      <div
        className="flex justify-between t-caption"
        style={{ color: "var(--fainter)", marginTop: "4px" }}
      >
        <span>10s · freshest fees, more load</span>
        <span>60s · lighter, staler fees</span>
      </div>
      <p className="text-xs text-[color:var(--fainter)] mt-3">
        Applied live — no restart. Only affects fee freshness <strong>between</strong> blocks; a new
        block always gets instant work via an empty template regardless of this setting. The revenue
        difference across the range is modest.
      </p>
    </div>
  );
}
