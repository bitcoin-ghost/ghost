"use client";

import { useEffect, useState } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Toggle } from "@/components/ui/Toggle";
import { Button } from "@/components/ui/Button";
import { ConfirmDialog } from "@/components/ui/Dialog";
import { useToast } from "@/components/ui/Toast";
import { useDaemonSettings, useSetDaemonSettings } from "@/hooks/queries/useConfigQueries";

// ---------------------------------------------------------------------------
// Full RBF control — a real, working toggle backed by the same ghostd daemon
// settings the Settings › Daemon page uses. Full RBF maps to ghostd's
// -mempoolfullrbf launch flag:
//   ON  (default) → any unconfirmed tx is replaceable by a higher-fee conflict.
//   OFF           → only BIP125-signalling txs are replaceable (-mempoolfullrbf=0).
//
// full_rbf semantics (mirrors the daemon page):
//   full_rbf === false → opted OUT (OFF).
//   null / absent      → ghostd default (ON).
// On save we send the FULL current daemon settings with ONLY full_rbf changed,
// so the sibling launch flags (maxmempool, dbcache, onlynet, …) are preserved.
// Because -mempoolfullrbf is read only at startup, applying restarts ghostd.
// ---------------------------------------------------------------------------
export function FullRbfControl() {
  const { data, isLoading } = useDaemonSettings();
  const setDaemon = useSetDaemonSettings();
  const { success, error } = useToast();

  const settings = data?.settings;
  // Full RBF is ON unless the operator explicitly opted out (full_rbf === false).
  const serverEnabled = settings?.full_rbf !== false;

  // Local desired state, seeded from the server and re-seeded when it changes.
  const [enabled, setEnabled] = useState(serverEnabled);
  const [confirmOpen, setConfirmOpen] = useState(false);

  useEffect(() => {
    setEnabled(serverEnabled);
  }, [serverEnabled]);

  const dirty = enabled !== serverEnabled;

  const handleApply = async () => {
    try {
      // Preserve every sibling launch flag — spread the current settings and
      // override only full_rbf. ON → null (emit no flag, keep ghostd default);
      // OFF → false (opt out, -mempoolfullrbf=0).
      const res = await setDaemon.mutateAsync({
        ...(settings ?? {}),
        full_rbf: enabled ? null : false,
      });
      setConfirmOpen(false);
      success("Applying", res.message ?? "ghostd is restarting to apply the Full RBF change.");
    } catch (err) {
      setConfirmOpen(false);
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <Card>
      <CardHeader title="Replace-by-fee (RBF)" />

      <div className="flex items-start justify-between gap-4">
        <div style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.6" }}>
          <p style={{ marginBottom: "8px" }}>
            <strong>Full RBF is on by default</strong> — any unconfirmed transaction can be replaced
            by a higher-fee spend of the same inputs, regardless of BIP-125 signalling.
          </p>
          <p>
            Turn it <strong>off</strong> for first-seen-safe / opt-in RBF: only transactions that
            signal BIP-125 opt-in replaceability can be replaced, and non-signalling first-seen
            transactions are protected (<code>-mempoolfullrbf=0</code>). Changing this restarts
            ghostd and briefly bounces the pool.
          </p>
        </div>
        <Toggle
          enabled={enabled}
          onChange={setEnabled}
          label="Full RBF"
          disabled={isLoading || setDaemon.isPending}
        />
      </div>

      {dirty && (
        <div className="flex items-center justify-end gap-3 mt-4">
          <span style={{ color: "var(--dim)", fontSize: "13px" }}>
            {enabled ? "Full RBF will be turned ON." : "Full RBF will be turned OFF."}
          </span>
          <Button
            variant="primary"
            loading={setDaemon.isPending}
            disabled={setDaemon.isPending}
            onClick={() => setConfirmOpen(true)}
          >
            Apply &amp; restart
          </Button>
        </div>
      )}

      <ConfirmDialog
        isOpen={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        onConfirm={handleApply}
        title="Apply Full RBF change & restart ghostd?"
        message={
          (enabled
            ? "Full RBF will be turned ON (any unconfirmed transaction becomes replaceable). "
            : "Full RBF will be turned OFF (only BIP125-signalling transactions stay replaceable). ") +
          "ghostd restarts with the new launch flag and ghost-pool bounces once it settles. Mining pauses for a few seconds. Continue?"
        }
        confirmLabel="Apply & restart"
        variant="danger"
        loading={setDaemon.isPending}
      />
    </Card>
  );
}
