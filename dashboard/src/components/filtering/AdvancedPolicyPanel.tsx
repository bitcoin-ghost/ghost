"use client";

import { useEffect, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/Button";
import { StickySaveBar } from "@/components/ui/StickySaveBar";
import { useFullConfig } from "@/hooks/queries/useConfigQueries";
import {
  setPolicyCustom,
  POLICY_CUSTOM_DEFAULTS,
  type PolicyCustomConfig,
} from "@/lib/api/config";
import { useToast } from "@/components/ui/Toast";

// Advanced, custom tier policy: the full per-field counterpart to the three
// Basic presets. Expanding it reveals every knob the block builder enforces;
// saving writes [policy].custom, sets the profile to `custom`, and restarts the
// node — same confirm as the presets.
const TIER_TOGGLES: { key: keyof PolicyCustomConfig; label: string; desc: string }[] = [
  { key: "allow_t0", label: "T0 · Financial", desc: "Ordinary payments — single-sig sends, change, consolidations." },
  { key: "allow_t1", label: "T1 · Extended", desc: "Multisig, timelocks and Lightning channel transactions." },
  { key: "allow_t2", label: "T2 · Data", desc: "Small data carriers — OP_RETURN commitments within your size limit." },
  { key: "allow_t3", label: "T3 · Heavy", desc: "Heavy/abusive data — inscriptions, runes, BRC-20, oversized transactions." },
];

const CONTENT_TOGGLES: { key: keyof PolicyCustomConfig; label: string; desc: string }[] = [
  { key: "allow_inscriptions", label: "Inscriptions", desc: "Mine Ordinals inscription transactions." },
  { key: "allow_runes", label: "Runes", desc: "Mine Runes runestone transactions." },
  { key: "allow_brc20", label: "BRC-20", desc: "Mine BRC-20 token-transfer transactions." },
];

const NUMERIC_FIELDS: { key: keyof PolicyCustomConfig; label: string; unit: string; desc: string; step?: number }[] = [
  { key: "max_op_return_size", label: "Max OP_RETURN size", unit: "bytes", desc: "Largest OP_RETURN payload to mine. 0 drops every OP_RETURN transaction." },
  { key: "max_witness_per_input", label: "Max witness / input", unit: "bytes", desc: "Largest witness per input. Low values block inscription-style witness stuffing." },
  { key: "max_tx_outputs", label: "Max tx outputs", unit: "outputs", desc: "Most outputs a transaction may have to be eligible for a block." },
  { key: "max_tx_size", label: "Max tx size", unit: "vB", desc: "Largest transaction to mine, in virtual bytes." },
  { key: "min_fee_rate", label: "Min fee rate", unit: "sat/vB", desc: "Lowest fee rate to mine. 0 means no minimum.", step: 0.1 },
];

export function AdvancedPolicyPanel() {
  const { data: fullConfig } = useFullConfig();
  const { success, error } = useToast();
  const queryClient = useQueryClient();

  const [form, setForm] = useState<PolicyCustomConfig>(POLICY_CUSTOM_DEFAULTS);
  // `baseline` is the last-saved (or loaded) state used to compute dirtiness.
  const [baseline, setBaseline] = useState<PolicyCustomConfig>(POLICY_CUSTOM_DEFAULTS);
  const [confirming, setConfirming] = useState(false);
  const [saving, setSaving] = useState(false);

  const isCustomActive = fullConfig?.policy?.profile === "custom";
  const stored = fullConfig?.policy?.custom;

  // Seed the form + baseline from the node's persisted custom values once they
  // arrive, so the panel edits the real config rather than blank defaults.
  useEffect(() => {
    if (stored) {
      const seeded: PolicyCustomConfig = {
        allow_t0: stored.allow_t0,
        allow_t1: stored.allow_t1,
        allow_t2: stored.allow_t2,
        allow_t3: stored.allow_t3,
        allow_inscriptions: stored.allow_inscriptions,
        allow_runes: stored.allow_runes,
        allow_brc20: stored.allow_brc20,
        max_op_return_size: stored.max_op_return_size,
        max_witness_per_input: stored.max_witness_per_input,
        max_tx_outputs: stored.max_tx_outputs,
        max_tx_size: stored.max_tx_size,
        min_fee_rate: stored.min_fee_rate,
      };
      setForm(seeded);
      setBaseline(seeded);
    }
  }, [stored]);

  const dirty = JSON.stringify(form) !== JSON.stringify(baseline);

  const setBool = (key: keyof PolicyCustomConfig, value: boolean) =>
    setForm((f) => ({ ...f, [key]: value }));
  const setNum = (key: keyof PolicyCustomConfig, value: number) =>
    setForm((f) => ({ ...f, [key]: value }));

  const noTiers = !form.allow_t0 && !form.allow_t1 && !form.allow_t2 && !form.allow_t3;

  const apply = async () => {
    setSaving(true);
    try {
      await setPolicyCustom(form);
      success("Custom policy saved", "The node is restarting to apply your custom tier policy.");
      setBaseline(form);
      setConfirming(false);
      queryClient.invalidateQueries({ queryKey: ["config"] });
    } catch (e) {
      error("Failed to save custom policy", e instanceof Error ? e.message : "Unknown error");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <div className="flex items-center gap-2" style={{ marginBottom: "2px" }}>
        <span className="t-body" style={{ color: "var(--fg)", fontWeight: 600 }}>Custom mining policy</span>
        {isCustomActive && (
          <span className="t-caption" style={{ color: "var(--accent)", fontWeight: 600 }}>· current</span>
        )}
      </div>
      <div className="t-label" style={{ color: "var(--dim)", marginBottom: "12px" }}>
        Per-field control over which transaction classes, content and sizes this node mines. Saving writes{" "}
        <code>[policy].custom</code>, sets the profile to <code>custom</code>, and restarts the node.
      </div>

      {/* Tiers */}
      <PanelSection title="Transaction classes to mine">
        {TIER_TOGGLES.map((t) => (
          <CheckboxRow
            key={t.key}
            label={t.label}
            desc={t.desc}
            checked={Boolean(form[t.key])}
            onChange={(v) => setBool(t.key, v)}
          />
        ))}
        {noTiers && (
          <div className="t-caption" style={{ color: "var(--warn, #d29922)", marginTop: "6px" }}>
            No classes selected — the node would mine empty blocks (coinbase only).
          </div>
        )}
      </PanelSection>

      {/* Content toggles */}
      <PanelSection title="Data content">
        {CONTENT_TOGGLES.map((t) => (
          <CheckboxRow
            key={t.key}
            label={t.label}
            desc={t.desc}
            checked={Boolean(form[t.key])}
            onChange={(v) => setBool(t.key, v)}
          />
        ))}
      </PanelSection>

      {/* Numeric limits */}
      <PanelSection title="Size & fee limits">
        {NUMERIC_FIELDS.map((f) => (
          <NumberRow
            key={f.key}
            label={f.label}
            unit={f.unit}
            desc={f.desc}
            step={f.step}
            value={Number(form[f.key])}
            onChange={(v) => setNum(f.key, v)}
          />
        ))}
      </PanelSection>

      {confirming ? (
        // Sticky confirm bar — keeps the restart confirmation reachable no
        // matter how far the operator has scrolled. Cancel/back-out is safe.
        <div
          className="animate-slide-up"
          style={{
            position: "sticky",
            bottom: 0,
            zIndex: 20,
            marginTop: "8px",
            padding: "12px 14px",
            border: "1px solid var(--accent)",
            borderRadius: "6px",
            background: "var(--accent-weak)",
            boxShadow: "0 -6px 20px -8px rgba(0, 0, 0, 0.35)",
          }}
        >
          <div className="t-label" style={{ color: "var(--fg)", marginBottom: "10px" }}>
            Apply this <strong>custom mining policy</strong>? This writes the config and{" "}
            <strong>restarts the node</strong> to apply.
          </div>
          <div className="flex items-center gap-2">
            <Button variant="primary" size="sm" onClick={apply} disabled={saving}>
              {saving ? "Applying…" : "Apply & restart"}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setConfirming(false)} disabled={saving}>
              Cancel
            </Button>
          </div>
        </div>
      ) : dirty ? (
        // Pending edits: the sticky Save bar takes over as the save affordance.
        // Save opens the restart-confirm flow above; Reset reverts to baseline.
        <StickySaveBar
          dirty={dirty}
          saving={saving}
          onSave={() => setConfirming(true)}
          onReset={() => setForm(baseline)}
          saveLabel="Save custom policy…"
        />
      ) : (
        // No pending edits: the plain trigger still lets an operator (re)apply
        // the custom profile — e.g. to switch a preset node over to custom.
        <Button variant="secondary" size="sm" onClick={() => setConfirming(true)}>
          Save custom policy…
        </Button>
      )}
    </div>
  );
}

function PanelSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div style={{ marginBottom: "14px" }}>
      <div className="t-label" style={{ color: "var(--fg)", fontWeight: 600, marginBottom: "8px" }}>{title}</div>
      <div className="space-y-2">{children}</div>
    </div>
  );
}

function CheckboxRow({
  label,
  desc,
  checked,
  onChange,
}: {
  label: string;
  desc: string;
  checked: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <label style={{ display: "flex", gap: "10px", alignItems: "flex-start", cursor: "pointer" }}>
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        style={{ marginTop: "3px" }}
      />
      <span>
        <span className="t-label" style={{ color: "var(--fg)", fontWeight: 500 }}>{label}</span>
        <div className="t-caption" style={{ color: "var(--dim)", lineHeight: "1.5" }}>{desc}</div>
      </span>
    </label>
  );
}

function NumberRow({
  label,
  unit,
  desc,
  value,
  step,
  onChange,
}: {
  label: string;
  unit: string;
  desc: string;
  value: number;
  step?: number;
  onChange: (value: number) => void;
}) {
  return (
    <div style={{ display: "flex", gap: "12px", alignItems: "flex-start", justifyContent: "space-between", flexWrap: "wrap" }}>
      <span style={{ flex: "1 1 240px" }}>
        <span className="t-label" style={{ color: "var(--fg)", fontWeight: 500 }}>{label}</span>
        <div className="t-caption" style={{ color: "var(--dim)", lineHeight: "1.5" }}>{desc}</div>
      </span>
      <span className="flex items-center gap-2" style={{ flex: "0 0 auto" }}>
        <input
          type="number"
          min={0}
          step={step ?? 1}
          value={Number.isFinite(value) ? value : 0}
          onChange={(e) => {
            const n = Number(e.target.value);
            onChange(Number.isFinite(n) && n >= 0 ? n : 0);
          }}
          className="t-label"
          style={{
            width: "110px",
            padding: "6px 8px",
            borderRadius: "4px",
            border: "1px solid var(--rule)",
            background: "var(--bg)",
            color: "var(--fg)",
            fontFamily: "var(--font-mono)",
          }}
        />
        <span className="t-caption" style={{ color: "var(--dim)", minWidth: "48px" }}>{unit}</span>
      </span>
    </div>
  );
}
