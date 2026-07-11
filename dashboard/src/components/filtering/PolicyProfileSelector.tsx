"use client";

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/Button";
import { useFullConfig } from "@/hooks/queries/useConfigQueries";
import { setPolicyProfile, type PolicyProfileType } from "@/lib/api/config";
import { useToast } from "@/components/ui/Toast";
import { BUDS_TIER_COLORS, BUDS_TIER_KEYS, type BudsTierKey } from "@/lib/budsTiers";

// The three real tier-policy presets (pool.toml [policy].profile), with
// plain-English labels, descriptions and the BUDS classes each actually mines.
export const POLICY_PRESETS: {
  value: PolicyProfileType;
  label: string;
  desc: string;
  tiers: BudsTierKey[]; // BUDS classes this preset MINES (rest are dropped)
}[] = [
  { value: "strict", label: "Strict", tiers: ["T0", "T1"], desc: "Payments, multisig & timelocks only (T0+T1). Drops all data — no OP_RETURN, inscriptions or runes." },
  { value: "permissive", label: "Standard", tiers: ["T0", "T1", "T2"], desc: "Adds small OP_RETURN / Lightning commitments (T0+T1+T2). Still drops inscriptions, runes & BRC-20 (T3)." },
  { value: "full_open", label: "Open", tiers: ["T0", "T1", "T2", "T3"], desc: "All valid transactions including inscriptions, runes & BRC-20 (T0–T3). Maximum fees, no tier filtering." },
];

// A tight row of four BUDS-class pills. Mined classes are filled with the
// class's BUDS colour; dropped classes are dimmed/outlined so the difference
// is legible at a glance.
function TierPills({ mined }: { mined: BudsTierKey[] }) {
  return (
    <div className="flex items-center" style={{ gap: "4px", marginBottom: "6px" }}>
      {BUDS_TIER_KEYS.map((key) => {
        const isMined = mined.includes(key);
        const color = BUDS_TIER_COLORS[key];
        return (
          <span
            key={key}
            className="t-eyebrow"
            title={isMined ? `${key} mined` : `${key} dropped`}
            style={{
              fontWeight: 600,
              lineHeight: 1,
              letterSpacing: "0.02em",
              padding: "3px 6px",
              borderRadius: "4px",
              border: `1px solid ${isMined ? color : "var(--rule)"}`,
              background: isMined ? color : "transparent",
              color: isMined ? "#0b0f14" : "var(--dim)",
              opacity: isMined ? 1 : 0.55,
            }}
          >
            {key}
          </span>
        );
      })}
    </div>
  );
}

// Normalise the stored profile (legacy `bitcoin_pure` == `strict`).
export function normalizeProfile(profile?: string): PolicyProfileType | undefined {
  if (profile === "bitcoin_pure") return "strict";
  if (profile === "strict" || profile === "permissive" || profile === "full_open") return profile;
  return undefined;
}

/**
 * Editable tier-policy selector — writes the real pool.toml [policy].profile via
 * POST /api/v1/config/policy_profile, which persists + triggers a graceful
 * restart to apply. A pending-confirm step makes the restart explicit.
 *
 * Shared between /filtering/basic and /settings/filtering so both surfaces drive
 * the exact same mutation and confirm flow.
 */
export function PolicyProfileSelector() {
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
      {fullConfig?.policy?.drift && (
        <div
          role="alert"
          style={{
            marginBottom: "12px",
            padding: "10px 12px",
            borderRadius: "6px",
            border: "1px solid var(--warning, #b45309)",
            background: "var(--warning-weak, rgba(180,83,9,0.12))",
            fontSize: "13px",
            color: "var(--fg)",
          }}
        >
          <strong>Policy drift.</strong> ghostd is actually enforcing{" "}
          <code>{fullConfig.policy.enforced_profile}</code>, but this node is configured for{" "}
          <code>{current ?? fullConfig.policy.profile}</code>. Re-apply the configured profile below to sync
          ghostd (the node restarts), or pick the policy you actually want.
        </div>
      )}
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
                <span className="t-body" style={{ color: "var(--fg)", fontWeight: 600 }}>{p.label}</span>
                {isCurrent && (
                  <span className="t-caption" style={{ color: "var(--accent)", fontWeight: 600 }}>· current</span>
                )}
              </div>
              <TierPills mined={p.tiers} />
              <div className="t-caption" style={{ color: "var(--dim)", lineHeight: "1.5" }}>{p.desc}</div>
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
          <div className="t-label" style={{ color: "var(--fg)", marginBottom: "10px" }}>
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
