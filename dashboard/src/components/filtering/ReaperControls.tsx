"use client";

import { useState } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Toggle } from "@/components/ui/Toggle";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { useToast } from "@/components/ui/Toast";
import { StickySaveBar } from "@/components/ui/StickySaveBar";
import { useReaperConfig, useSetReaper } from "@/hooks/queries/useConfigQueries";
import { type ReaperSettings } from "@/lib/api/config";

// ---------------------------------------------------------------------------
// Interactive reaper controls — the master switch, per-vector rejects and
// thresholds. Shared between the (now redirected) /reaper page and the
// Filtering › Advanced page.
//
// Field names below MUST match ghost_common::config::ReaperSettings (serde
// deserialises the POST body straight into it); a renamed key is silently
// dropped and never reaches the node. Grouping mirrors which enforcement layer
// honours each vector.
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
        <div className="t-body" style={{ color: "var(--accent)", fontWeight: 500 }}>{title}</div>
        <div className="t-caption" style={{ color: "var(--dim)", marginTop: "2px" }}>{note}</div>
      </div>
      <div className="space-y-3">
        {vectors.map((v) => (
          <div key={v.key} className="flex items-start justify-between gap-4">
            <div>
              <div className="t-label" style={{ color: "var(--fg)" }}>{v.label}</div>
              <div className="t-caption" style={{ color: "var(--dim)", lineHeight: "1.5" }}>{v.desc}</div>
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

export function ReaperControls() {
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
        <p className="t-body" style={{ color: "var(--dim)" }}>
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
        <p className="t-body" style={{ color: "var(--dim)" }}>Loading current reaper configuration…</p>
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
              <div className="t-body" style={{ color: "var(--accent)", fontWeight: 500 }}>Reaper master switch</div>
              <div className="t-caption" style={{ color: "var(--dim)", lineHeight: "1.5", marginTop: "2px" }}>
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
          <div className="t-body" style={{ color: "var(--accent)", fontWeight: 500, marginBottom: "10px" }}>
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
          <p className="t-label" style={{ color: "var(--red)" }}>{errorMsg}</p>
        )}

        <div
          style={{
            padding: "12px",
            background: "var(--accent-weak)",
            border: "1px solid var(--accent)",
            borderRadius: "4px",
          }}
        >
          <p className="t-label" style={{ color: "var(--fg)", lineHeight: "1.6" }}>
            Saving writes these settings to the node config (<code>pool.toml [reaper]</code>) and applies
            them to <strong>both</strong> reapers automatically. The pool template reaper picks them up when{" "}
            <strong style={{ color: "var(--accent)" }}>ghost-pool restarts</strong>, and the ghostd{" "}
            <strong>mempool</strong> reaper is regenerated for you — the node rewrites its{" "}
            <code>-ghostreaper</code> reject flags and <strong>briefly restarts ghostd</strong>. No manual{" "}
            <code>ghost-setup apply-reaper</code> step is needed.
          </p>
        </div>

        {/* Sticky bottom bar — keeps Save/Reset reachable while editing the
            thresholds at the bottom, where the top header bar is off-screen. */}
        <StickySaveBar dirty={dirty} saving={pending} onSave={onSave} onReset={onReset} />
      </div>
    </Card>
  );
}
