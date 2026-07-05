"use client";

import { useEffect, useState, type ReactNode } from "react";
import Link from "next/link";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { fetchApi } from "@/lib/api/client";
import { useConfig, useFullConfig } from "@/hooks/queries/useConfigQueries";
import {
  setPolicyProfile,
  setPolicyCustom,
  POLICY_CUSTOM_DEFAULTS,
  type PolicyProfileType,
  type PolicyCustomConfig,
} from "@/lib/api/config";
import { useToast } from "@/components/ui/Toast";

// The three real tier-policy presets (pool.toml [policy].profile), with
// plain-English labels and descriptions true to what each actually mines.
const POLICY_PRESETS: { value: PolicyProfileType; label: string; desc: string }[] = [
  { value: "strict", label: "Strict", desc: "Payments, multisig & timelocks only (T0+T1). Drops all data — no OP_RETURN, inscriptions or runes." },
  { value: "permissive", label: "Standard", desc: "Adds small OP_RETURN / Lightning commitments (T0+T1+T2). Still drops inscriptions, runes & BRC-20 (T3)." },
  { value: "full_open", label: "Everything", desc: "All valid transactions including inscriptions, runes & BRC-20 (T0–T3). Maximum fees, no tier filtering." },
];

// Normalise the stored profile (legacy `bitcoin_pure` == `strict`).
function normalizeProfile(profile?: string): PolicyProfileType | undefined {
  if (profile === "bitcoin_pure") return "strict";
  if (profile === "strict" || profile === "permissive" || profile === "full_open") return profile;
  return undefined;
}


interface TierMeta {
  key: "T0" | "T1" | "T2" | "T3";
  name: string;
  short: string;
  color: string;
  blurb: string;
  examples: string;
}

const TIERS: TierMeta[] = [
  {
    key: "T0",
    name: "T0 · Financial",
    short: "Ordinary payments",
    color: "#3fb950",
    blurb: "Plain money moving between people — the transactions Bitcoin exists for.",
    examples: "single-sig sends, change, consolidations",
  },
  {
    key: "T1",
    name: "T1 · Extended",
    short: "Bigger financial",
    color: "#58a6ff",
    blurb: "Still money, just more elaborate — multiple signers or time locks.",
    examples: "multisig, Lightning channels, timelocks",
  },
  {
    key: "T2",
    name: "T2 · Data",
    short: "Small data carriers",
    color: "#d29922",
    blurb: "Transactions that also carry a little standard data. Allowed, but not payments.",
    examples: "OP_RETURN ≤ 80 bytes, commitments",
  },
  {
    key: "T3",
    name: "T3 · Abusive",
    short: "Heavy / abusive data",
    color: "#f85149",
    blurb: "Transactions whose main purpose is stuffing data onto the chain.",
    examples: "inscriptions, runes, BRC-20, oversized data",
  },
];

interface BudsMempool {
  by_tier?: { T0: number; T1: number; T2: number; T3: number };
  sample_size?: number;
  message?: string;
}

export default function BudsPage() {
  const { data: config } = useConfig();
  const { data: mempool } = useQuery({
    queryKey: ["buds-mempool"],
    queryFn: () => fetchApi<BudsMempool>("/api/v1/buds/mempool"),
    refetchInterval: 15_000,
  });

  const reaperEnabled = config?.reaper ?? false;
  const byTier = mempool?.by_tier ?? { T0: 0, T1: 0, T2: 0, T3: 0 };
  const sampled = mempool?.sample_size ?? TIERS.reduce((s, t) => s + (byTier[t.key] ?? 0), 0);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="filtering"
        title="BUDS."
        subtitle="Every transaction your node sees is sorted into one of four classes — from ordinary payments to abusive data. That class decides how it's filtered."
        subtitleFullWidth
      />

      {/* The four classes, explained */}
      <SectionErrorBoundary section="Transaction classes">
        <Card>
          <CardHeader
            title="The four classes"
            subtitle="What each BUDS class means, in plain terms."
          />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {TIERS.map((t) => (
              <div
                key={t.key}
                style={{
                  padding: "12px 14px",
                  border: "1px solid var(--rule)",
                  borderLeft: `3px solid ${t.color}`,
                  borderRadius: "6px",
                  background: "var(--bg)",
                }}
              >
                <div className="flex items-center gap-2" style={{ marginBottom: "4px" }}>
                  <span style={{ width: "10px", height: "10px", borderRadius: "2px", background: t.color, display: "inline-block" }} />
                  <span style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 600 }}>{t.name}</span>
                  <span style={{ color: "var(--dim)", fontSize: "12px" }}>· {t.short}</span>
                </div>
                <div style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.5" }}>{t.blurb}</div>
                <div style={{ color: "var(--fainter)", fontSize: "12px", marginTop: "6px" }}>
                  e.g. {t.examples}
                </div>
              </div>
            ))}
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Live composition — what THIS node is holding right now */}
      <SectionErrorBoundary section="Your mempool by class">
        <Card>
          <CardHeader
            title="Your mempool by class"
            subtitle="What your node is holding right now, by share of sampled transactions."
          />
          <div className="space-y-3">
            {mempool?.message ? (
              <p style={{ color: "var(--dim)", fontSize: "13px" }}>
                Mempool classification is unavailable — {mempool.message}
              </p>
            ) : (
              <>
                <div style={{ display: "flex", height: "14px", borderRadius: "4px", overflow: "hidden", background: "var(--bg)" }}>
                  {TIERS.map((t) => {
                    const count = byTier[t.key] ?? 0;
                    const pct = sampled ? (count / sampled) * 100 : 0;
                    if (pct === 0) return null;
                    return (
                      <div key={t.key} title={`${t.name}: ${count} (${pct.toFixed(1)}%)`} style={{ width: `${pct}%`, background: t.color }} />
                    );
                  })}
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {TIERS.map((t) => {
                    const count = byTier[t.key] ?? 0;
                    const pct = sampled ? (count / sampled) * 100 : 0;
                    return (
                      <div key={t.key} style={{ padding: "10px 12px", border: "1px solid var(--rule)", borderRadius: "4px", background: "var(--bg)" }}>
                        <div className="flex items-center gap-2" style={{ marginBottom: "4px" }}>
                          <span style={{ width: "10px", height: "10px", borderRadius: "2px", background: t.color, display: "inline-block" }} />
                          <span style={{ color: "var(--fg)", fontSize: "13px", fontWeight: 500 }}>{t.name}</span>
                        </div>
                        <div style={{ fontFamily: "var(--font-mono)", fontSize: "18px", color: "var(--fg)" }}>{pct.toFixed(0)}%</div>
                        <div style={{ color: "var(--dim)", fontSize: "12px" }}>{count.toLocaleString()} sampled</div>
                      </div>
                    );
                  })}
                </div>
                <p style={{ color: "var(--fainter)", fontSize: "12px" }}>
                  Based on a live sample of {sampled.toLocaleString()} transactions (the node classifies up to
                  100 per poll to stay light). Proportions are representative, not exact totals.
                </p>
              </>
            )}
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Filtering settings — current policy + where to change it */}
      <SectionErrorBoundary section="Filtering settings">
        <Card>
          <CardHeader
            title="Filtering settings"
            subtitle="How strictly this node filters transactions."
          />
          <div className="space-y-3">
            <SettingRow
              label="Reaper"
              value={reaperEnabled ? "On" : "Off"}
              desc={reaperEnabled ? "Strips dead-code transactions from your mempool and blocks." : "Not removing dead-code transactions."}
              href="/reaper"
              cta="Reaper settings"
            />
            <PolicyProfileSelector />
            <AdvancedPolicyPanel />
          </div>
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}

// Editable tier-policy selector — writes the real pool.toml [policy].profile via
// POST /api/v1/config/policy_profile, which persists + triggers a graceful
// restart to apply. A pending-confirm step makes the restart explicit.
function PolicyProfileSelector() {
  const { data: fullConfig } = useFullConfig();
  const { success, error } = useToast();
  const queryClient = useQueryClient();
  const current = normalizeProfile(fullConfig?.policy?.profile);
  const [pending, setPending] = useState<PolicyProfileType | null>(null);
  const [saving, setSaving] = useState(false);

  const apply = async (profile: PolicyProfileType) => {
    setSaving(true);
    try {
      await setPolicyProfile(profile);
      success("Policy updated", "The node is restarting to apply the new tier policy.");
      setPending(null);
      queryClient.invalidateQueries({ queryKey: ["config"] });
    } catch (e) {
      error("Failed to update policy", e instanceof Error ? e.message : "Unknown error");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <div style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 600, marginBottom: "2px" }}>
        Mining policy
      </div>
      <div style={{ color: "var(--dim)", fontSize: "13px", marginBottom: "10px" }}>
        Which transaction classes this node mines into the blocks it builds. Changing this restarts the node.
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {POLICY_PRESETS.map((p) => {
          const isCurrent = current === p.value;
          return (
            <button
              key={p.value}
              onClick={() => !isCurrent && setPending(p.value)}
              disabled={isCurrent || saving}
              style={{
                textAlign: "left",
                padding: "12px 14px",
                borderRadius: "6px",
                border: `1px solid ${isCurrent ? "var(--accent)" : "var(--rule)"}`,
                background: isCurrent ? "var(--accent-weak)" : "var(--bg)",
                cursor: isCurrent ? "default" : "pointer",
              }}
            >
              <div className="flex items-center gap-2" style={{ marginBottom: "4px" }}>
                <span style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 600 }}>{p.label}</span>
                {isCurrent && (
                  <span style={{ color: "var(--accent)", fontSize: "11px", fontWeight: 600 }}>· current</span>
                )}
              </div>
              <div style={{ color: "var(--dim)", fontSize: "12px", lineHeight: "1.5" }}>{p.desc}</div>
            </button>
          );
        })}
      </div>
      {pending && (
        <div
          style={{
            marginTop: "12px",
            padding: "12px 14px",
            border: "1px solid var(--accent)",
            borderRadius: "6px",
            background: "var(--accent-weak)",
          }}
        >
          <div style={{ color: "var(--fg)", fontSize: "13px", marginBottom: "10px" }}>
            Switch mining policy to <strong>{POLICY_PRESETS.find((p) => p.value === pending)?.label}</strong>? This
            writes the config and <strong>restarts the node</strong> to apply.
          </div>
          <div className="flex items-center gap-2">
            <Button variant="primary" size="sm" onClick={() => apply(pending)} disabled={saving}>
              {saving ? "Applying…" : "Apply & restart"}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setPending(null)} disabled={saving}>
              Cancel
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

// Advanced, secondary panel: the full custom tier policy. Collapsed by default
// so the three presets stay the simple front door. Expanding it reveals every
// per-field knob the block builder enforces; saving writes [policy].custom, sets
// the profile to `custom`, and restarts the node — same confirm as the presets.
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

function AdvancedPolicyPanel() {
  const { data: fullConfig } = useFullConfig();
  const { success, error } = useToast();
  const queryClient = useQueryClient();

  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<PolicyCustomConfig>(POLICY_CUSTOM_DEFAULTS);
  const [confirming, setConfirming] = useState(false);
  const [saving, setSaving] = useState(false);

  const isCustomActive = fullConfig?.policy?.profile === "custom";
  const stored = fullConfig?.policy?.custom;

  // Seed the form from the node's persisted custom values once they arrive, so
  // the panel edits the real config rather than blank defaults.
  useEffect(() => {
    if (stored) {
      setForm({
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
      });
    }
  }, [stored]);

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
      setConfirming(false);
      queryClient.invalidateQueries({ queryKey: ["config"] });
    } catch (e) {
      error("Failed to save custom policy", e instanceof Error ? e.message : "Unknown error");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ marginTop: "4px", border: "1px solid var(--rule)", borderRadius: "6px", background: "var(--bg)" }}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="bare"
        style={{
          width: "100%",
          textAlign: "left",
          padding: "12px 14px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "12px",
          cursor: "pointer",
          background: "transparent",
        }}
      >
        <span>
          <span style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 600 }}>Advanced: custom policy</span>
          {isCustomActive && (
            <span style={{ color: "var(--accent)", fontSize: "11px", fontWeight: 600, marginLeft: "8px" }}>· current</span>
          )}
          <div style={{ color: "var(--dim)", fontSize: "12px", marginTop: "2px" }}>
            Set every tier, content and size rule by hand. Most operators want a preset instead.
          </div>
        </span>
        <span style={{ color: "var(--dim)", fontSize: "13px" }}>{open ? "Hide" : "Show"}</span>
      </button>

      {open && (
        <div style={{ padding: "0 14px 14px", borderTop: "1px solid var(--rule)" }}>
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
              <div style={{ color: "var(--warn, #d29922)", fontSize: "12px", marginTop: "6px" }}>
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

          {!confirming ? (
            <Button variant="secondary" size="sm" onClick={() => setConfirming(true)}>
              Save custom policy…
            </Button>
          ) : (
            <div
              style={{
                marginTop: "4px",
                padding: "12px 14px",
                border: "1px solid var(--accent)",
                borderRadius: "6px",
                background: "var(--accent-weak)",
              }}
            >
              <div style={{ color: "var(--fg)", fontSize: "13px", marginBottom: "10px" }}>
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
          )}
        </div>
      )}
    </div>
  );
}

function PanelSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div style={{ marginTop: "14px" }}>
      <div style={{ color: "var(--fg)", fontSize: "13px", fontWeight: 600, marginBottom: "8px" }}>{title}</div>
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
        <span style={{ color: "var(--fg)", fontSize: "13px", fontWeight: 500 }}>{label}</span>
        <div style={{ color: "var(--dim)", fontSize: "12px", lineHeight: "1.5" }}>{desc}</div>
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
        <span style={{ color: "var(--fg)", fontSize: "13px", fontWeight: 500 }}>{label}</span>
        <div style={{ color: "var(--dim)", fontSize: "12px", lineHeight: "1.5" }}>{desc}</div>
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
          style={{
            width: "110px",
            padding: "6px 8px",
            borderRadius: "4px",
            border: "1px solid var(--rule)",
            background: "var(--bg)",
            color: "var(--fg)",
            fontFamily: "var(--font-mono)",
            fontSize: "13px",
          }}
        />
        <span style={{ color: "var(--dim)", fontSize: "12px", minWidth: "48px" }}>{unit}</span>
      </span>
    </div>
  );
}

function SettingRow({
  label,
  value,
  desc,
  href,
  cta,
}: {
  label: string;
  value: string;
  desc: string;
  href: string;
  cta: string;
}) {
  return (
    <div
      style={{
        padding: "12px 14px",
        border: "1px solid var(--rule)",
        borderRadius: "6px",
        background: "var(--bg)",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        gap: "12px",
        flexWrap: "wrap",
      }}
    >
      <div>
        <div className="flex items-center gap-2">
          <span style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 600 }}>{label}</span>
          <span style={{ color: "var(--accent)", fontSize: "13px", fontWeight: 600 }}>{value}</span>
        </div>
        <div style={{ color: "var(--dim)", fontSize: "13px", marginTop: "2px" }}>{desc}</div>
      </div>
      <Link href={href} className="bare" style={{ color: "var(--accent)", textDecoration: "underline", fontSize: "13px", whiteSpace: "nowrap" }}>
        {cta} →
      </Link>
    </div>
  );
}
