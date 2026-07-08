"use client";

import Link from "next/link";
import { Badge } from "@/components/ui/Badge";
import { useToast } from "@/components/ui/Toast";
import {
  useNodeStatus,
  useConfig,
  useGhostPayStatus,
  useShares,
  useSetArchiveMode,
  useSetPublicMining,
  useSetReaper,
  useSetGhostPay,
} from "@/hooks/queries";
import { ToggleRow, StatusRow } from "@/app/(dashboard)/settings/shared";

interface CapabilityTogglesProps {
  /**
   * How the Ghost Pay row is presented:
   * - "status" (default): read-only StatusRow — enabling requires a running
   *   ghost-pay-node, so Settings › Capabilities shows state only.
   * - "toggle": an editable ToggleRow backed by `useSetGhostPay` (Onboarding).
   */
  ghostPayControl?: "status" | "toggle";
  /**
   * Extra content rendered immediately after the Ghost Pay row — used by
   * Onboarding to slot in its Wraith mixing toggle without duplicating the
   * five canonical capability rows.
   */
  afterGhostPay?: React.ReactNode;
  /**
   * When provided, a cross-link to detector-level Reaper configuration is
   * rendered beneath the Reaper toggle (Settings › Capabilities points at
   * `/filtering/advanced`).
   */
  reaperConfigHref?: string;
}

/**
 * The five canonical node-capability rows (Archive / Ghost Pay / Public Mining /
 * Reaper / Elder) that drive the 5-4-3-2-1 share system. Extracted from the
 * duplicated markup that Settings › Capabilities and the Onboarding wizard both
 * rendered, so there is a single source of truth wired to the same mutation
 * hooks. Callers wrap this in their own Card/SettingsSection shell.
 *
 * The Public-Mining ↔ Ghost-Mode mutual-exclusion guard lives here: a Ghost Mode
 * node builds near-empty blocks and forfeits all transaction-fee income, so it
 * must not also accept public miners. Enabling Public Mining while Ghost Mode is
 * active is blocked in the UI (disabling stays allowed); the backend enforces
 * the same rule with a 409.
 */
export function CapabilityToggles({
  ghostPayControl = "status",
  afterGhostPay,
  reaperConfigHref,
}: CapabilityTogglesProps) {
  const { data: status } = useNodeStatus();
  const { data: config } = useConfig();
  const { data: ghostPayStatus } = useGhostPayStatus();
  const { data: shares } = useShares();

  const setArchiveMode = useSetArchiveMode();
  const setPublicMining = useSetPublicMining();
  const setReaper = useSetReaper();
  const setGhostPay = useSetGhostPay();

  const { success, error } = useToast();

  const ghostModeActive = status?.ghost_mode ?? false;
  const publicMiningActive = status?.public_mining ?? false;
  const publicMiningBlocked = ghostModeActive && !publicMiningActive;

  // Ghost Pay running-state comes from the explicit `sync_state` flag, NOT
  // `l2_height` — an L2 height of 0 is a perfectly valid running state (fresh
  // node), so its truthiness would mislabel a running node as "Not Running".
  const ghostPayRunning = ghostPayStatus?.sync_state === "synced";
  const ghostPayEnabled = status?.ghost_pay ?? false;

  const archiveEnabled = status?.archive_mode ?? false;
  const reaperEnabled = config?.reaper ?? false;

  const handleArchiveModeToggle = async (enabled: boolean) => {
    try {
      await setArchiveMode.mutateAsync(enabled);
      success("Saved", `Archive Mode ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleGhostPayToggle = async (enabled: boolean) => {
    try {
      await setGhostPay.mutateAsync(enabled);
      success("Saved", `Ghost Pay ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handlePublicMiningToggle = async (enabled: boolean) => {
    try {
      await setPublicMining.mutateAsync(enabled);
      success("Saved", `Public Mining ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleReaperToggle = async (enabled: boolean) => {
    try {
      await setReaper.mutateAsync(enabled);
      success(
        "Saved",
        enabled
          ? "Ghost Reaper enabled — mempool filtering active"
          : "Ghost Reaper disabled — filtering inactive"
      );
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <>
      <ToggleRow
        label="Archive Mode"
        description="Store full blockchain history (+5 shares bonus)"
        enabled={archiveEnabled}
        onChange={handleArchiveModeToggle}
        disabled={setArchiveMode.isPending}
        badge={archiveEnabled ? <Badge variant="success">+5 Shares</Badge> : null}
      />

      {ghostPayControl === "toggle" ? (
        <ToggleRow
          label="Ghost Pay"
          description={`L2 payment network participation — requires ghost-pay-node${
            ghostPayRunning ? ` (L2 height: ${ghostPayStatus?.l2_height ?? 0})` : ""
          } (+4 shares bonus)`}
          enabled={ghostPayEnabled}
          onChange={handleGhostPayToggle}
          disabled={setGhostPay.isPending}
          badge={
            ghostPayEnabled ? (
              ghostPayRunning ? (
                <Badge variant="success">+4 Shares</Badge>
              ) : (
                <Badge variant="warning">Not Running</Badge>
              )
            ) : null
          }
        />
      ) : (
        <StatusRow
          label="Ghost Pay"
          description={`L2 payment network participation — requires ghost-pay-node${
            ghostPayRunning ? ` (L2 height: ${ghostPayStatus?.l2_height ?? 0})` : ""
          }`}
          badge={
            ghostPayRunning ? (
              <Badge variant="success">+4 Shares</Badge>
            ) : (
              <Badge variant="warning">Not Running</Badge>
            )
          }
        />
      )}

      {afterGhostPay}

      <ToggleRow
        label="Public Mining"
        description="Accept mining connections from public miners (+3 shares bonus)"
        enabled={publicMiningActive}
        onChange={handlePublicMiningToggle}
        disabled={setPublicMining.isPending || publicMiningBlocked}
        badge={publicMiningActive ? <Badge variant="success">+3 Shares</Badge> : null}
      />

      {publicMiningBlocked && (
        <div
          className="p-3 rounded-lg"
          style={{
            background: "color-mix(in srgb, var(--yellow) 8%, transparent)",
            border: "1px solid color-mix(in srgb, var(--yellow) 40%, transparent)",
          }}
        >
          <p className="t-body" style={{ color: "var(--fg)" }}>
            <span style={{ color: "var(--yellow)", fontWeight: 600 }}>Ghost Mode is active</span>{" "}
            — disable it before enabling Public Mining. A Ghost Mode node builds empty blocks and
            forfeits all transaction-fee income, so the two can&apos;t run together.
          </p>
        </div>
      )}

      <ToggleRow
        label="Ghost Reaper"
        description="Reject transactions with dead code in witness scripts. Filters inscriptions, drop stuffing, and other non-financial data from your mempool. (+2 shares)"
        enabled={reaperEnabled}
        onChange={handleReaperToggle}
        disabled={setReaper.isPending}
        badge={reaperEnabled ? <Badge variant="success">+2 Shares</Badge> : null}
      />

      {reaperConfigHref && (
        <Link
          href={reaperConfigHref}
          className="block px-3 -mt-2 t-caption text-[color:var(--accent)] hover:underline"
        >
          Configure Reaper detectors and thresholds →
        </Link>
      )}

      <StatusRow
        label="Elder Status"
        description={
          shares?.elder
            ? `MPC contributor — Elder slot #${shares.elder_slot ?? "?"}`
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
    </>
  );
}
