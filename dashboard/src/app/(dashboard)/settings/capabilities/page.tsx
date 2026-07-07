"use client";

import { Badge } from "@/components/ui/Badge";
import {
  useNodeStatus,
  useConfig,
  useSetArchiveMode,
  useSetReaper,
  useSetPublicMining,
  useGhostPayStatus,
  useShares,
} from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import { SettingsSection, ToggleRow, StatusRow } from "../shared";

export default function CapabilitiesSettingsPage() {
  const { data: status } = useNodeStatus();
  const { data: config } = useConfig();
  const { data: ghostPayStatus } = useGhostPayStatus();
  const { data: shares } = useShares();

  const setArchiveMode = useSetArchiveMode();
  const setReaper = useSetReaper();
  const setPublicMining = useSetPublicMining();

  const { success, error } = useToast();

  // Ghost Mode and Public Mining are mutually exclusive: a Ghost Mode node
  // builds near-empty blocks and forfeits all transaction-fee income, so it
  // must not also accept public miners. Block enabling Public Mining while
  // Ghost Mode is active (disabling it stays allowed). The backend enforces the
  // same rule and answers a conflicting enable with a 409, surfaced below.
  const ghostModeActive = status?.ghost_mode ?? false;
  const publicMiningActive = status?.public_mining ?? false;
  const publicMiningBlocked = ghostModeActive && !publicMiningActive;

  const handlePublicMiningToggle = async (enabled: boolean) => {
    try {
      await setPublicMining.mutateAsync(enabled);
      success("Mode Changed", `Public Mining ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleArchiveModeToggle = async (enabled: boolean) => {
    try {
      await setArchiveMode.mutateAsync(enabled);
      success("Mode Changed", `Archive Mode ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleReaperToggle = async (enabled: boolean) => {
    try {
      await setReaper.mutateAsync(enabled);
      success(
        "Mode Changed",
        enabled
          ? "Ghost Reaper enabled — mempool filtering active"
          : "Ghost Reaper disabled — filtering inactive"
      );
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <SettingsSection
      title="Node Capabilities"
      subtitle="Earn shares in the node reward pool — 5-4-3-2-1 system"
    >
      <ToggleRow
        label="Archive Mode"
        description="Store full blockchain history (+5 shares bonus)"
        enabled={status?.archive_mode ?? false}
        onChange={handleArchiveModeToggle}
        disabled={setArchiveMode.isPending}
        badge={
          status?.archive_mode ? (
            <Badge variant="success">+5 Shares</Badge>
          ) : null
        }
      />

      <StatusRow
        label="Ghost Pay"
        description={`L2 payment network participation — requires ghost-pay-node${ghostPayStatus?.l2_height ? ` (L2 height: ${ghostPayStatus.l2_height})` : ''}`}
        badge={
          ghostPayStatus?.l2_height ? (
            <Badge variant="success">+4 Shares</Badge>
          ) : (
            <Badge variant="warning">Not Running</Badge>
          )
        }
      />

      <ToggleRow
        label="Public Mining"
        description="Accept mining connections from public miners (+3 shares bonus)"
        enabled={publicMiningActive}
        onChange={handlePublicMiningToggle}
        disabled={setPublicMining.isPending || publicMiningBlocked}
        badge={
          publicMiningActive ? (
            <Badge variant="success">+3 Shares</Badge>
          ) : null
        }
      />

      {publicMiningBlocked && (
        <div
          className="p-3 rounded-lg"
          style={{
            background: "color-mix(in srgb, var(--yellow) 8%, transparent)",
            border: "1px solid color-mix(in srgb, var(--yellow) 40%, transparent)",
          }}
        >
          <p className="text-sm" style={{ color: "var(--fg)", lineHeight: "1.6" }}>
            <span style={{ color: "var(--yellow)", fontWeight: 600 }}>Ghost Mode is active</span>{" "}
            — disable it before enabling Public Mining. A Ghost Mode node builds empty blocks and
            forfeits all transaction-fee income, so the two can&apos;t run together.
          </p>
        </div>
      )}

      <ToggleRow
        label="Ghost Reaper"
        description="Reject transactions with dead code in witness scripts. Filters inscriptions, drop stuffing, and other non-financial data from your mempool. (+2 shares)"
        enabled={config?.reaper ?? false}
        onChange={handleReaperToggle}
        disabled={setReaper.isPending}
        badge={
          config?.reaper ? (
            <Badge variant="success">+2 Shares</Badge>
          ) : null
        }
      />

      <StatusRow
        label="Elder Status"
        description={
          shares?.elder
            ? `MPC contributor — Elder slot #${shares.elder_slot ?? '?'}`
            : "Contribute to the MPC ceremony to earn Elder status (+1 share)"
        }
        badge={
          shares?.elder ? (
            <Badge variant="success">+1 Share</Badge>
          ) : (
            <Badge variant="default">Not Elder</Badge>
          )
        }
      />
    </SettingsSection>
  );
}
