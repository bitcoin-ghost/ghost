"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import {
  useNodeStatus,
  useGhostPayStatus,
  useSetGhostMode,
  useSetWraith,
} from "@/hooks/queries";
import { useHazeStatus } from "@/hooks/queries/useHazeQueries";
import { useShroudStatus } from "@/hooks/queries/useShroudQueries";
import { useToast } from "@/components/ui/Toast";
import { Card, CardHeader } from "@/components/ui/Card";
import { ToggleRow } from "../shared";
import ShroudWizard from "../wizards/ShroudWizard";
import HazeWizard from "../wizards/HazeWizard";

export default function PrivacySettingsPage() {
  const { data: status } = useNodeStatus();
  const { data: ghostPayStatus } = useGhostPayStatus();
  const { data: hazeStatus } = useHazeStatus();
  const { data: shroudStatus } = useShroudStatus();

  const setGhostMode = useSetGhostMode();
  const setWraith = useSetWraith();
  const { success, error } = useToast();

  const [shroudOpen, setShroudOpen] = useState(false);
  const [hazeOpen, setHazeOpen] = useState(false);

  const handleGhostModeToggle = async (enabled: boolean) => {
    try {
      await setGhostMode.mutateAsync(enabled);
      success("Mode Changed", `Ghost Mode ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleWraithToggle = async (enabled: boolean) => {
    try {
      await setWraith.mutateAsync(enabled);
      success(
        "Saved",
        `Wraith mixing ${enabled ? "enabled" : "disabled"} — restart ghost-pool to apply`
      );
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const hazeMode = hazeStatus?.mode ?? "unknown";
  const hazeModeLabel = hazeMode === "hazed" ? "Hazed" : hazeMode === "full_archive" ? "Full Archive" : hazeMode === "standard" ? "Standard" : "Unknown";

  const gpRunning = ghostPayStatus && ghostPayStatus.sync_state !== "disabled" && ghostPayStatus.sync_state !== "unavailable";
  const wraithEnabled = ghostPayStatus?.wraith_enabled ?? false;

  return (
    <>
      <Card className="border-[var(--red)]/30">
        <CardHeader
          title={<span className="text-[color:var(--red)]">Privacy &amp; Anonymity</span>}
          subtitle="Control your node's privacy features"
        />
        <div className="space-y-4">
          <ToggleRow
            label="Ghost Mode"
            description="Isolates your node — stops relaying transactions and messages to peers (except block propagation)"
            enabled={status?.ghost_mode ?? false}
            onChange={handleGhostModeToggle}
            disabled={setGhostMode.isPending}
            badge={
              status?.ghost_mode ? (
                <Badge variant="success">Active</Badge>
              ) : (
                <Badge variant="default">Inactive</Badge>
              )
            }
          />

          <div className="flex items-center justify-between p-3 bg-[var(--surface)]/50 rounded-lg">
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <span className="text-[color:var(--fg)] font-medium">Tor Mode</span>
                {status?.tor_mode ? (
                  <Badge variant="success">Active</Badge>
                ) : (
                  <Badge variant="default">Disabled</Badge>
                )}
              </div>
              <div className="text-sm text-[color:var(--dim)]">
                Routes all P2P connections through the Tor network, hiding your node&apos;s IP address
              </div>
              {status?.tor_mode && status?.onion_address && (
                <div className="mt-2 flex items-center gap-2">
                  <code className="text-xs text-[color:var(--accent)] bg-[var(--surface)]/50 px-2 py-1 rounded font-mono">
                    {status.onion_address}
                  </code>
                  <button
                    className="text-xs text-[color:var(--fainter)] hover:text-[color:var(--dim)] transition-colors"
                    onClick={() => {
                      navigator.clipboard.writeText(status.onion_address!);
                    }}
                  >
                    Copy
                  </button>
                </div>
              )}
              {!status?.tor_mode && (
                <div className="text-xs text-[color:var(--fainter)] mt-1">
                  Configure via Ghost Core startup flags (-proxy, -torcontrol). Set at startup, read-only here.
                </div>
              )}
            </div>
          </div>

          {/* Ghost Shroud — configurable via the same wizard as Settings › Wizards */}
          <div className="flex items-center justify-between p-3 bg-[var(--surface)]/50 rounded-lg">
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <span className="text-[color:var(--fg)] font-medium">Ghost Shroud</span>
                {shroudStatus ? (
                  <Badge variant={shroudStatus.enabled ? "success" : "default"}>
                    {shroudStatus.enabled ? "Active" : "Disabled"}
                  </Badge>
                ) : (
                  <Badge variant="default">Unknown</Badge>
                )}
              </div>
              <div className="text-sm text-[color:var(--dim)]">
                Random delays before relaying transactions — protects against timing analysis
              </div>
            </div>
            <Button variant="secondary" size="sm" onClick={() => setShroudOpen(true)}>
              Configure
            </Button>
          </div>

          {/* Ghost Haze — configurable via the same wizard as Settings › Wizards */}
          <div className="flex items-center justify-between p-3 bg-[var(--surface)]/50 rounded-lg">
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <span className="text-[color:var(--fg)] font-medium">Ghost Haze</span>
                {hazeStatus ? (
                  <Badge variant={hazeMode === "hazed" ? "success" : hazeMode === "full_archive" ? "info" : "default"}>
                    {hazeModeLabel}
                  </Badge>
                ) : (
                  <Badge variant="default">Unknown</Badge>
                )}
              </div>
              <div className="text-sm text-[color:var(--dim)]">
                Strips privacy-sensitive data (signatures, witness data, inscriptions) from stored blocks
              </div>
            </div>
            <Button variant="secondary" size="sm" onClick={() => setHazeOpen(true)}>
              Configure
            </Button>
          </div>

          {/* Wraith mixing — an editable toggle (requires ghost-pay running) */}
          {gpRunning ? (
            <ToggleRow
              label="Wraith Protocol"
              description="CoinJoin mixing on the L2 network — lets any L2 participant initiate a mixing session through this node. Restart ghost-pool to apply."
              enabled={wraithEnabled}
              onChange={handleWraithToggle}
              disabled={setWraith.isPending}
              badge={wraithEnabled ? <Badge variant="success">Active</Badge> : <Badge variant="default">Available</Badge>}
            />
          ) : (
            <div className="flex items-center justify-between p-3 bg-[var(--surface)]/50 rounded-lg">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-[color:var(--fg)] font-medium">Wraith Protocol</span>
                  <Badge variant="warning">Not Running</Badge>
                </div>
                <div className="text-sm text-[color:var(--dim)]">
                  CoinJoin mixing on the L2 network — breaks transaction linkability. Requires an active
                  ghost-pay-node.
                </div>
              </div>
            </div>
          )}
        </div>
      </Card>

      <ShroudWizard isOpen={shroudOpen} onClose={() => setShroudOpen(false)} />
      <HazeWizard isOpen={hazeOpen} onClose={() => setHazeOpen(false)} />
    </>
  );
}
