"use client";

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/Button";
import { useFullConfig } from "@/hooks/queries/useConfigQueries";
import { setPolicyProfile, type PolicyProfileType } from "@/lib/api/config";
import { useToast } from "@/components/ui/Toast";

// The three real tier-policy presets (pool.toml [policy].profile), with
// plain-English labels and descriptions true to what each actually mines.
export const POLICY_PRESETS: { value: PolicyProfileType; label: string; desc: string }[] = [
  { value: "strict", label: "Strict", desc: "Payments, multisig & timelocks only (T0+T1). Drops all data — no OP_RETURN, inscriptions or runes." },
  { value: "permissive", label: "Standard", desc: "Adds small OP_RETURN / Lightning commitments (T0+T1+T2). Still drops inscriptions, runes & BRC-20 (T3)." },
  { value: "full_open", label: "Everything", desc: "All valid transactions including inscriptions, runes & BRC-20 (T0–T3). Maximum fees, no tier filtering." },
];

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
