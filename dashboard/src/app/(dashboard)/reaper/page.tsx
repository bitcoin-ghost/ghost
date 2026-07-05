"use client";

import { useState } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { Toggle } from "@/components/ui/Toggle";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { useToast } from "@/components/ui/Toast";
import { useConfig, useReaperConfig, useSetReaper } from "@/hooks/queries/useConfigQueries";
import { useReaperStatus } from "@/hooks/queries";
import { type ReaperSettings } from "@/lib/api/config";

const DETECTION_VECTORS = [
  {
    key: "inscription_envelope" as const,
    name: "Inscription Envelopes",
    desc: "Detects OP_FALSE OP_IF ... OP_ENDIF witness patterns used by Ordinal inscriptions to embed arbitrary data.",
  },
  {
    key: "drop_stuffing" as const,
    name: "Drop Stuffing",
    desc: "Identifies unreachable OP_DROP sequences that push and immediately discard data, wasting block space.",
  },
  {
    key: "unreachable_code" as const,
    name: "Unreachable Code",
    desc: "Finds dead code paths in witness scripts that can never execute but bloat transaction size.",
  },
  {
    key: "fake_pubkey" as const,
    name: "Fake Pubkeys",
    desc: "Detects invalid or non-functional public keys used as data carriers in multisig outputs.",
  },
  {
    key: "fake_pubkey_curve_point" as const,
    name: "Fake Pubkey Curve Points",
    desc: "Flags fake pubkeys that are not valid secp256k1 curve points, a tell-tale sign the value carries embedded data rather than a real key.",
  },
  {
    key: "oversized_op_return" as const,
    name: "Oversized OP_RETURN",
    desc: "Flags OP_RETURN outputs exceeding standard relay limits, used for embedding large data payloads.",
  },
  {
    key: "dust_flood" as const,
    name: "Dust-flood (UTXO spam)",
    desc: "Rejects 1-in/1-out transactions whose sole non-OP_RETURN output sits at or below the dust-flood threshold, the signature of UTXO-set flooding spam.",
  },
  {
    key: "annex_present" as const,
    name: "Annex Bloat",
    desc: "Identifies taproot annex fields carrying non-consensus data, exploiting the annex discount.",
  },
  {
    key: "excess_witness_data" as const,
    name: "Excess Witness Data",
    desc: "Catches witness items far exceeding what the script actually consumes during execution.",
  },
  {
    key: "excess_stack_items" as const,
    name: "Excess Stack Items",
    desc: "Flags witnesses that leave surplus elements on the stack after script execution, a vector for stuffing extra data into the witness.",
  },
  {
    key: "legacy_scriptsig_data" as const,
    name: "Legacy ScriptSig Data",
    desc: "Detects data-carrying patterns in legacy scriptSig fields that serve no signing purpose.",
  },
];

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatPercent(numerator: number, denominator: number): string {
  if (denominator === 0) return "—";
  const pct = (numerator / denominator) * 100;
  return pct < 0.01 ? "<0.01%" : `${pct.toFixed(2)}%`;
}

function formatRelative(unixSecs: number | null): string {
  if (!unixSecs) return "never";
  const ago = Math.floor(Date.now() / 1000) - unixSecs;
  if (ago < 60) return `${ago}s ago`;
  if (ago < 3600) return `${Math.floor(ago / 60)}m ago`;
  if (ago < 86400) return `${Math.floor(ago / 3600)}h ago`;
  return `${Math.floor(ago / 86400)}d ago`;
}

// ---------------------------------------------------------------------------
// Interactive controls
//
// Field names below MUST match ghost_common::config::ReaperSettings (serde
// deserialises the POST body straight into it); a renamed key is silently
// dropped and never reaches the node. Grouping mirrors which enforcement layer
// honours each vector — the same split the ReaperWizard uses.
// ---------------------------------------------------------------------------

type Vector = { key: keyof ReaperSettings; label: string; desc: string };

// Shared vectors feed BOTH reapers: the pool block-template reaper and the
// ghostd mempool reaper.
const SHARED_VECTORS: Vector[] = [
  { key: "reject_inscription", label: "Inscription envelopes", desc: "OP_FALSE OP_IF … OP_ENDIF ordinal/inscription wrappers" },
  { key: "reject_dropstuffing", label: "Drop stuffing", desc: "A large data push immediately followed by OP_DROP / OP_2DROP" },
  { key: "reject_fakepubkey", label: "Fake pubkeys", desc: "Bare multisig outputs with invalid pubkey prefixes" },
  { key: "reject_annex", label: "P2TR annex", desc: "Taproot inputs carrying a witness annex" },
];
// Node-only vectors feed the ghostd mempool reaper (-ghostreaper reject flags).
const NODE_VECTORS: Vector[] = [
  { key: "reject_opreturn", label: "Oversized OP_RETURN", desc: "OP_RETURN payloads larger than the max below" },
  { key: "reject_runestone", label: "Runestones", desc: "Runestone protocol outputs (OP_RETURN OP_13)" },
  { key: "reject_dustflood", label: "Dust-flood (UTXO spam)", desc: "1-in/1-out txs whose sole non-OP_RETURN output is at/below the dust-flood threshold below" },
];
// Pool-only vectors feed the block-template reaper (what this node mines).
const POOL_VECTORS: Vector[] = [
  { key: "reject_unreachable_code", label: "Unreachable code", desc: "Witness code after an OP_RETURN opcode" },
  { key: "reject_excess_witness", label: "Excess witness", desc: "Witness data beyond what execution requires" },
  { key: "reject_legacy_data_stuffing", label: "Legacy scriptSig stuffing", desc: "Non-sig/non-pubkey data pushes in legacy scriptSig" },
  { key: "validate_pubkey_curve_point", label: "Pubkey curve check", desc: "Also verify bare-multisig pubkeys are on the secp256k1 curve" },
];

function VectorGroup({
  title,
  note,
  vectors,
  data,
  onChange,
  disabled,
}: {
  title: string;
  note: string;
  vectors: Vector[];
  data: ReaperSettings;
  onChange: (patch: Partial<ReaperSettings>) => void;
  disabled: boolean;
}) {
  return (
    <div
      style={{
        padding: "14px",
        border: "1px solid var(--rule)",
        borderRadius: "4px",
        background: "var(--bg)",
      }}
    >
      <div style={{ marginBottom: "10px" }}>
        <div style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 500 }}>{title}</div>
        <div style={{ color: "var(--dim)", fontSize: "12px", marginTop: "2px" }}>{note}</div>
      </div>
      <div className="space-y-3">
        {vectors.map((v) => (
          <div key={v.key} className="flex items-start justify-between gap-4">
            <div>
              <div style={{ color: "var(--fg)", fontSize: "13px" }}>{v.label}</div>
              <div style={{ color: "var(--dim)", fontSize: "12px", lineHeight: "1.5" }}>{v.desc}</div>
            </div>
            <Toggle
              enabled={Boolean(data[v.key])}
              onChange={(val) => onChange({ [v.key]: val } as Partial<ReaperSettings>)}
              label={v.label}
              disabled={disabled}
            />
          </div>
        ))}
      </div>
    </div>
  );
}

function ReaperControls() {
  const { data: reaper, isLoading, isError } = useReaperConfig();
  const setReaper = useSetReaper();
  const toast = useToast();

  // `form` is the working copy; `baseline` is the last-saved (or loaded) state
  // used to compute dirtiness. Initialise from the loaded config exactly once so
  // a background refetch (e.g. window-focus) can't clobber in-progress edits.
  const [form, setForm] = useState<ReaperSettings | null>(null);
  const [baseline, setBaseline] = useState<ReaperSettings | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Seed the working copy + baseline from the loaded config exactly once.
  // Setting state during render (guarded so it can't loop) is React's
  // recommended alternative to an initialising effect, and it means a
  // background refetch can't clobber in-progress edits.
  if (reaper?.settings && form === null) {
    setForm(reaper.settings);
    setBaseline(reaper.settings);
  }

  if (isError) {
    return (
      <Card>
        <CardHeader title="Adjust reaper" subtitle="Per-vector controls" />
        <p style={{ color: "var(--dim)", fontSize: "14px" }}>
          Could not load the reaper configuration from ghost-pool. The controls are unavailable until
          the node responds.
        </p>
      </Card>
    );
  }

  if (isLoading || !form || !baseline) {
    return (
      <Card>
        <CardHeader title="Adjust reaper" subtitle="Per-vector controls" />
        <p style={{ color: "var(--dim)", fontSize: "14px" }}>Loading current reaper configuration…</p>
      </Card>
    );
  }

  const patch = (p: Partial<ReaperSettings>) => {
    setErrorMsg(null);
    setForm((prev) => (prev ? { ...prev, ...p } : prev));
  };

  const dirty = JSON.stringify(form) !== JSON.stringify(baseline);
  const pending = setReaper.isPending;
  const thresholdsValid = form.max_op_return_bytes >= 1 && form.min_drop_size >= 1;

  const onSave = async () => {
    if (!thresholdsValid) {
      setErrorMsg("Max OP_RETURN bytes and min drop size must be greater than zero.");
      return;
    }
    try {
      const res = await setReaper.mutateAsync(form);
      setBaseline(form);
      setErrorMsg(null);
      toast.success(
        "Reaper settings saved",
        res.persisted
          ? "Both reapers are updating automatically: the pool template reaper on the imminent ghost-pool restart, and the ghostd mempool reaper is being applied now (ghostd briefly restarts). No manual step needed."
          : "Settings received but no node config path is configured — nothing was persisted."
      );
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to save reaper settings.";
      setErrorMsg(msg);
      toast.error("Failed to save reaper settings", msg);
    }
  };

  const onReset = () => {
    setErrorMsg(null);
    setForm(baseline);
  };

  const controlsDisabled = pending;
  const vectorsDisabled = pending || !form.enabled;

  return (
    <Card>
      <CardHeader
        title="Adjust reaper"
        subtitle="Master switch, per-vector rejects and thresholds — written to pool.toml [reaper]"
        action={
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={onReset} disabled={!dirty || pending}>
              Reset
            </Button>
            <Button variant="primary" size="sm" onClick={onSave} loading={pending} disabled={!dirty || pending}>
              {dirty ? "Save changes" : "Saved"}
            </Button>
          </div>
        }
      />
      <div className="space-y-4">
        {/* Master switch */}
        <div
          style={{
            padding: "14px",
            border: "1px solid var(--rule)",
            borderRadius: "4px",
            background: "var(--bg)",
          }}
        >
          <div className="flex items-start justify-between gap-4">
            <div>
              <div style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 500 }}>Reaper master switch</div>
              <div style={{ color: "var(--dim)", fontSize: "12px", lineHeight: "1.5", marginTop: "2px" }}>
                When off, every detector is disabled on both the pool template reaper and the ghostd mempool
                reaper. When on, the per-vector choices below apply. Running Reaper earns +2 capability shares.
              </div>
            </div>
            <Toggle
              enabled={form.enabled}
              onChange={(val) => patch({ enabled: val })}
              label="Reaper master switch"
              disabled={controlsDisabled}
            />
          </div>
        </div>

        <VectorGroup
          title="Shared detectors"
          note="Apply to BOTH reapers: the pool block-template reaper and the ghostd mempool reaper."
          vectors={SHARED_VECTORS}
          data={form}
          onChange={patch}
          disabled={vectorsDisabled}
        />
        <VectorGroup
          title="Node mempool reaper only"
          note="ghostd -ghostreaper mempool rejects. Applied automatically on save (ghostd briefly restarts) — no manual step."
          vectors={NODE_VECTORS}
          data={form}
          onChange={patch}
          disabled={vectorsDisabled}
        />
        <VectorGroup
          title="Pool template reaper only"
          note="Strips dead weight from the blocks this node builds. Applied automatically when ghost-pool restarts."
          vectors={POOL_VECTORS}
          data={form}
          onChange={patch}
          disabled={vectorsDisabled}
        />

        {/* Thresholds */}
        <div
          style={{
            padding: "14px",
            border: "1px solid var(--rule)",
            borderRadius: "4px",
            background: "var(--bg)",
          }}
        >
          <div style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 500, marginBottom: "10px" }}>
            Thresholds
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Input
              label="Max OP_RETURN bytes (shared)"
              type="number"
              min={1}
              value={form.max_op_return_bytes}
              onChange={(e) => patch({ max_op_return_bytes: Number(e.target.value) })}
              disabled={vectorsDisabled}
            />
            <Input
              label="Min drop-stuffing push size (shared)"
              type="number"
              min={1}
              value={form.min_drop_size}
              onChange={(e) => patch({ min_drop_size: Number(e.target.value) })}
              disabled={vectorsDisabled}
            />
            <Input
              label="Dust-flood threshold (sats)"
              type="number"
              min={0}
              value={form.dust_flood_threshold}
              onChange={(e) => patch({ dust_flood_threshold: Number(e.target.value) })}
              disabled={vectorsDisabled}
            />
            <Input
              label="Min excess-witness bytes (pool)"
              type="number"
              min={0}
              value={form.min_excess_witness_bytes}
              onChange={(e) => patch({ min_excess_witness_bytes: Number(e.target.value) })}
              disabled={vectorsDisabled}
            />
            <Input
              label="Legacy max push bytes (pool)"
              type="number"
              min={0}
              value={form.legacy_max_push_bytes}
              onChange={(e) => patch({ legacy_max_push_bytes: Number(e.target.value) })}
              disabled={vectorsDisabled}
            />
          </div>
        </div>

        {errorMsg && (
          <p style={{ color: "var(--danger, #f87171)", fontSize: "13px" }}>{errorMsg}</p>
        )}

        <div
          style={{
            padding: "12px",
            background: "var(--accent-weak)",
            border: "1px solid var(--accent)",
            borderRadius: "4px",
          }}
        >
          <p style={{ color: "var(--fg)", fontSize: "13px", lineHeight: "1.6" }}>
            Saving writes these settings to the node config (<code>pool.toml [reaper]</code>) and applies
            them to <strong>both</strong> reapers automatically. The pool template reaper picks them up when{" "}
            <strong style={{ color: "var(--accent)" }}>ghost-pool restarts</strong>, and the ghostd{" "}
            <strong>mempool</strong> reaper is regenerated for you — the node rewrites its{" "}
            <code>-ghostreaper</code> reject flags and <strong>briefly restarts ghostd</strong>. No manual{" "}
            <code>ghost-setup apply-reaper</code> step is needed.
          </p>
        </div>
      </div>
    </Card>
  );
}

export default function ReaperPage() {
  const { data: config } = useConfig();
  const { data: stats } = useReaperStatus();

  const enabled = config?.reaper ?? false;
  const reapRate = stats ? formatPercent(stats.txs_reaped, stats.txs_evaluated) : "—";

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="reaper"
        title="Dead-code policy."
        subtitle="Live counters from your node's template builder. Cumulative since last ghost-pool restart."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Mode"
          value={enabled ? "active" : "disabled"}
          sublabel={enabled ? "filtering on" : "adjust in controls below"}
        />
        <StatCard
          label="TXs evaluated"
          value={stats?.txs_evaluated.toLocaleString() ?? "—"}
          sublabel={stats ? `${stats.txs_accepted.toLocaleString()} accepted` : "no data"}
        />
        <StatCard
          label="TXs reaped"
          value={stats?.txs_reaped.toLocaleString() ?? "—"}
          sublabel={stats ? `${reapRate} of evaluated` : "no data"}
        />
        <StatCard
          label="Dead bytes saved"
          value={stats ? formatBytes(stats.dead_bytes_total) : "—"}
          sublabel={
            stats
              ? `last reap ${formatRelative(stats.last_reaped_unix)}`
              : "no data"
          }
        />
      </div>

      <SectionErrorBoundary section="Two reapers">
        <Card collapsible>
          <CardHeader
            title="Two reapers, one switch"
            subtitle="Where these controls apply — and why 'reaper on' can still leave a node's mempool unfiltered"
          />
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div
                style={{
                  padding: "16px",
                  background: "var(--surface)",
                  border: "1px solid var(--rule)",
                  borderRadius: "4px",
                }}
              >
                <h4 style={{ color: "var(--fg)", fontWeight: 500, marginBottom: "6px" }}>
                  ghostd mempool reaper
                </h4>
                <p style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.6", marginBottom: "8px" }}>
                  The node&apos;s <code>-ghostreaper</code> reject vectors. Rejects junk from the mempool so it
                  never relays or gets mined. Driven by the <strong>shared</strong> + <strong>node-only</strong>{" "}
                  toggles below and applied <strong>automatically</strong> when you save — the node rewrites
                  its <code>-ghostreaper</code> flags and briefly restarts ghostd for you.
                </p>
                <div style={{ fontSize: "13px", color: "var(--dim)" }}>
                  Saved config:{" "}
                  <strong style={{ color: enabled ? "var(--accent)" : "var(--fainter)" }}>
                    {enabled ? "enabled" : "disabled"}
                  </strong>{" "}
                  <span style={{ color: "var(--fainter)" }}>
                    (applied to ghostd on save)
                  </span>
                </div>
              </div>
              <div
                style={{
                  padding: "16px",
                  background: "var(--accent-weak)",
                  border: "1px solid var(--accent)",
                  borderRadius: "4px",
                }}
              >
                <h4 style={{ color: "var(--accent)", fontWeight: 500, marginBottom: "6px" }}>
                  Pool block-template reaper
                </h4>
                <p style={{ color: "var(--fg)", fontSize: "13px", lineHeight: "1.6", marginBottom: "8px" }}>
                  The +2-capability reaper that strips dead weight from the blocks this node builds. Driven by
                  the <strong>shared</strong> + <strong>pool-only</strong> toggles below and applied
                  automatically when ghost-pool restarts (the save does this).
                </p>
                <div style={{ fontSize: "13px", color: "var(--dim)" }}>
                  Live:{" "}
                  <strong style={{ color: enabled ? "var(--accent)" : "var(--fainter)" }}>
                    {enabled ? "active" : "disabled"}
                  </strong>{" "}
                  {stats
                    ? `· ${stats.txs_reaped.toLocaleString()} reaped, ${formatBytes(stats.dead_bytes_total)} saved`
                    : "· no counters yet"}
                </div>
              </div>
            </div>
            <p style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.6" }}>
              <strong style={{ color: "var(--accent)" }}>Applied to both on save:</strong> the toggles below
              reflect the saved node config (<code>pool.toml [reaper]</code>), which is exactly what the pool
              template reaper runs. Saving now also regenerates the ghostd mempool reaper&apos;s{" "}
              <code>-ghostreaper</code> flags and restarts ghostd automatically, so the node&apos;s live
              filtering tracks these toggles without a manual <code>ghost-setup apply-reaper</code> step.
              Running a node deliberately as an <strong>unfiltered control</strong> (mempool reaper off) is a
              valid configuration.
            </p>
          </div>
        </Card>
      </SectionErrorBoundary>

      <ReaperControls />

      <Card collapsible defaultCollapsed>
        <CardHeader
          title="How It Works"
          subtitle="Dead code detection and mempool filtering"
        />
        <div className="space-y-4">
          <p style={{ color: "var(--dim)", fontSize: "14px", lineHeight: "1.6" }}>
            Ghost Reaper detects non-financial data embedded in transaction witnesses — inscriptions,
            drop stuffing, fake pubkeys, and other dead code patterns. When enabled, your node&apos;s template
            builder rejects transactions carrying dead weight before they enter your block, keeping your
            mining capacity focused on real monetary transactions.
          </p>
          <div
            style={{
              padding: "12px",
              background: "var(--accent-weak)",
              border: "1px solid var(--accent)",
              borderRadius: "4px",
            }}
          >
            <p style={{ color: "var(--fg)", fontSize: "14px" }}>
              Nodes running Reaper earn{" "}
              <strong style={{ color: "var(--accent)" }}>+2 capability shares</strong> in the node
              reward pool. Part of the 5-4-3-2-1 system: Archive (+5), Ghost Pay (+4), Public Mining (+3),
              <strong style={{ color: "var(--accent)" }}> Reaper (+2)</strong>, Elder (+1).
            </p>
          </div>
        </div>
      </Card>

      <SectionErrorBoundary section="Detection Vectors">
        <Card>
          <CardHeader
            title="Detection vectors"
            subtitle="Patterns Reaper identifies, with cumulative hit counts"
          />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {DETECTION_VECTORS.map((vector) => {
              const hits = stats?.by_type[vector.key] ?? 0;
              return (
                <div
                  key={vector.name}
                  style={{
                    padding: "14px",
                    border: "1px solid var(--rule)",
                    borderRadius: "4px",
                    background: "var(--bg)",
                  }}
                >
                  <div className="flex items-baseline justify-between mb-1">
                    <div style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 500 }}>
                      {vector.name}
                    </div>
                    <div
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "13px",
                        color: hits > 0 ? "var(--accent)" : "var(--fainter)",
                      }}
                    >
                      {hits.toLocaleString()}
                    </div>
                  </div>
                  <div style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.5" }}>
                    {vector.desc}
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      </SectionErrorBoundary>

      <Card collapsible defaultCollapsed>
        <CardHeader
          title="Reaper vs mempool policy"
          subtitle="Understanding the distinction"
        />
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div
              style={{
                padding: "16px",
                background: "var(--accent-weak)",
                border: "1px solid var(--accent)",
                borderRadius: "4px",
              }}
            >
              <h4 style={{ color: "var(--accent)", fontWeight: 500, marginBottom: "8px" }}>Reaper</h4>
              <ul style={{ color: "var(--fg)", fontSize: "13px", lineHeight: "1.7", paddingLeft: "20px", listStyle: "disc" }}>
                <li>Specifically targets <strong>dead code</strong> in witness scripts</li>
                <li>Detects inscriptions, drop stuffing, fake pubkeys, annex bloat</li>
                <li>Works at the witness / script level, not transaction-level policy</li>
                <li>Can run alongside any mempool policy</li>
              </ul>
            </div>
            <div
              style={{
                padding: "16px",
                background: "var(--surface)",
                border: "1px solid var(--rule)",
                borderRadius: "4px",
              }}
            >
              <h4 style={{ color: "var(--dim)", fontWeight: 500, marginBottom: "8px" }}>Mempool policy</h4>
              <ul style={{ color: "var(--fg)", fontSize: "13px", lineHeight: "1.7", paddingLeft: "20px", listStyle: "disc" }}>
                <li>Controls accept/reject by <strong>fee rates, sizes, standardness</strong></li>
                <li>Configurable profiles: standard, strict, clean, custom</li>
                <li>Operates at transaction level (size, fee, output type)</li>
                <li>Independent of Reaper — they complement each other</li>
              </ul>
            </div>
          </div>
          <p style={{ color: "var(--dim)", fontSize: "13px" }}>
            <strong style={{ color: "var(--accent)" }}>Key point:</strong> Reaper is NOT a mempool policy.
            You can run Reaper alongside any mempool policy. Mempool policies filter by economic rules;
            Reaper filters by content analysis of witness scripts.
          </p>
        </div>
      </Card>
    </div>
  );
}
