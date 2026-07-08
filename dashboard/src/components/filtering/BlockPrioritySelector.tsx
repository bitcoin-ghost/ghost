"use client";

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/Button";
import { useFullConfig } from "@/hooks/queries/useConfigQueries";
import { setBlockPriority, type BlockPriorityType } from "@/lib/api/config";
import { useToast } from "@/components/ui/Toast";

// The two block-priority modes (pool.toml [pool].block_priority), with
// plain-English labels and an honest statement of the revenue-vs-values
// tradeoff. This lever only ORDERS the block — it never drops transactions, so
// it composes with (and is strictly softer than) the tier policy above.
export const BLOCK_PRIORITY_OPTIONS: {
  value: BlockPriorityType;
  label: string;
  desc: string;
}[] = [
  {
    value: "max_fee",
    label: "Max fee",
    desc: "Order the block purely by fee rate. Maximises this node's mining revenue. This is the default.",
  },
  {
    value: "payments_first",
    label: "Payments first",
    desc: "Seat payments (BUDS T0/T1) ahead of data (T2/T3), each still fee-ordered within its group. Prioritises Bitcoin-as-money — you may earn less when data transactions are bidding high.",
  },
];

// Normalise the stored value; anything unknown falls back to the default.
export function normalizeBlockPriority(value?: string): BlockPriorityType {
  return value === "payments_first" ? "payments_first" : "max_fee";
}

/**
 * Editable block-priority selector — writes the real pool.toml
 * [pool].block_priority via POST /api/v1/config/block_priority, which persists +
 * triggers a graceful restart to apply. A pending-confirm step makes the restart
 * explicit, matching the tier-policy selector it sits beside.
 *
 * This is the softer sibling of the tier policy: the policy decides WHICH tx
 * classes are mined; this decides which of those admitted classes are seated
 * FIRST. Under a strict policy (data tiers already dropped) it is a no-op.
 */
export function BlockPrioritySelector() {
  const { data: fullConfig } = useFullConfig();
  const { success, error } = useToast();
  const queryClient = useQueryClient();
  const current = normalizeBlockPriority(fullConfig?.block_priority);
  const [pending, setPending] = useState<BlockPriorityType | null>(null);
  const [saving, setSaving] = useState(false);

  const apply = async (value: BlockPriorityType) => {
    setSaving(true);
    try {
      await setBlockPriority(value);
      success("Block priority updated", "The node is restarting to apply the new block ordering.");
      setPending(null);
      queryClient.invalidateQueries({ queryKey: ["config"] });
    } catch (e) {
      error("Failed to update block priority", e instanceof Error ? e.message : "Unknown error");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {BLOCK_PRIORITY_OPTIONS.map((opt) => {
          const isCurrent = current === opt.value;
          return (
            <button
              key={opt.value}
              onClick={() => !isCurrent && setPending(opt.value)}
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
                <span className="t-body" style={{ color: "var(--fg)", fontWeight: 600 }}>{opt.label}</span>
                {isCurrent && (
                  <span className="t-caption" style={{ color: "var(--accent)", fontWeight: 600 }}>· current</span>
                )}
              </div>
              <div className="t-caption" style={{ color: "var(--dim)", lineHeight: "1.5" }}>{opt.desc}</div>
            </button>
          );
        })}
      </div>
      <p className="text-xs text-[color:var(--fainter)] mt-3">
        Ordering only — no transaction is ever dropped by this lever. Under a strict tier policy (data
        tiers already filtered out) <strong>Payments first</strong> has nothing to reorder and is a no-op.
      </p>
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
            Switch block priority to{" "}
            <strong>{BLOCK_PRIORITY_OPTIONS.find((o) => o.value === pending)?.label}</strong>? This writes the
            config and <strong>restarts the node</strong> to apply.
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
