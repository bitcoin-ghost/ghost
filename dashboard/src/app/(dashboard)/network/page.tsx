"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { CopyButton } from "@/components/ui/CopyButton";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useNodeStatus } from "@/hooks/queries/useNodeQueries";
import { useSetGhostMode, useSetTor } from "@/hooks/queries/useConfigQueries";
import { useToast } from "@/components/ui/Toast";

/**
 * /network — observability and control for this node's network exposure.
 *
 * Tor mode is a ghostd startup flag (-tormode), so toggling it persists the
 * setting and restarts ghostd (then bounces the pool) — hence the explicit
 * "Apply & restart" confirm. Ghost Mode toggles live with no restart.
 *
 * For the broader *config* surface use /settings/privacy. This page is for
 * "what's actually happening right now" plus the exposure controls.
 */

interface ToggleRowProps {
  label: string;
  description: string;
  enabled: boolean;
  onChange?: (next: boolean) => void;
  disabled?: boolean;
  readOnly?: boolean;
  badge?: string;
}

function ExposureRow({ label, description, enabled, onChange, disabled, readOnly, badge }: ToggleRowProps) {
  return (
    <div
      className="flex items-start justify-between gap-6"
      style={{
        padding: "16px 0",
        borderTop: "1px solid var(--rule)",
      }}
    >
      <div style={{ flex: 1, minWidth: 0 }}>
        <div className="flex items-center gap-2 mb-1">
          <span style={{ color: "var(--fg)", fontWeight: 500, fontSize: "15px" }}>{label}</span>
          {badge && <Badge variant={enabled ? "success" : "info"}>{badge}</Badge>}
          {readOnly && <Badge variant="info">read-only</Badge>}
        </div>
        <p style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.5", maxWidth: "60ch" }}>
          {description}
        </p>
      </div>
      {!readOnly && onChange ? (
        <button
          onClick={() => onChange(!enabled)}
          disabled={disabled}
          className="flex-shrink-0"
          style={{
            width: "44px",
            height: "24px",
            borderRadius: "12px",
            background: enabled ? "var(--accent)" : "var(--rule-strong)",
            border: "none",
            cursor: disabled ? "not-allowed" : "pointer",
            opacity: disabled ? 0.6 : 1,
            position: "relative",
            transition: "background 120ms",
          }}
          aria-pressed={enabled}
        >
          <span
            style={{
              position: "absolute",
              top: "3px",
              left: enabled ? "23px" : "3px",
              width: "18px",
              height: "18px",
              borderRadius: "50%",
              background: "white",
              transition: "left 120ms",
            }}
          />
        </button>
      ) : (
        <span
          className="flex-shrink-0"
          style={{
            color: enabled ? "var(--green)" : "var(--dim)",
            fontFamily: "var(--font-mono)",
            fontSize: "13px",
            paddingTop: "2px",
          }}
        >
          {enabled ? "active" : "inactive"}
        </span>
      )}
    </div>
  );
}

export default function NetworkPage() {
  const { data: status, isLoading } = useNodeStatus();
  const setGhostMode = useSetGhostMode();
  const setTor = useSetTor();
  const { success, error } = useToast();

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader
          eyebrow="network"
          title="How this node is exposed."
          subtitle="Live view of your node's outbound transport, onion address, and relay-suppression state."
        />
        <SkeletonCard />
      </div>
    );
  }

  const torActive = !!status?.tor_mode;
  const onion = status?.onion_address;
  const ghostMode = !!status?.ghost_mode;
  const peerCount = status?.peer_count ?? 0;
  const exposure = torActive ? (onion ? "tor" : "tor (no onion)") : "clearnet";

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="network"
        title="How this node is exposed."
        subtitle="Live view of your node's outbound transport, onion address, and relay-suppression state — with controls for Tor mode and Ghost Mode."
        actions={
          <Badge variant={torActive ? "success" : "info"}>
            {exposure}
          </Badge>
        }
      />

      <SectionErrorBoundary section="Exposure summary">
        <Card>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-6 mb-2">
            <Stat label="outbound transport" value={torActive ? "Tor" : "clearnet"} />
            <Stat label="connected peers" value={peerCount.toLocaleString()} />
            <Stat
              label="onion address"
              value={onion ? "✓ present" : "—"}
              accent={onion ? "var(--green)" : "var(--dim)"}
            />
          </div>

          {onion && (
            <div
              className="flex items-center justify-between gap-3 mt-4"
              style={{
                background: "var(--bg)",
                border: "1px solid var(--rule)",
                borderRadius: "4px",
                padding: "12px 16px",
                fontFamily: "var(--font-mono)",
                fontSize: "13px",
                overflow: "auto",
              }}
            >
              <code style={{ color: "var(--fg)", whiteSpace: "nowrap" }}>{onion}</code>
              <CopyButton text={onion} />
            </div>
          )}
        </Card>
      </SectionErrorBoundary>

      <SectionErrorBoundary section="Privacy modes">
        <Card>
          <h3 style={{ color: "var(--fg)", fontSize: "16px", fontWeight: 500, marginBottom: "4px" }}>
            Privacy modes
          </h3>
          <p style={{ color: "var(--dim)", fontSize: "13px", marginBottom: "8px" }}>
            Tor mode is a ghostd startup flag (<code>-tormode</code>): toggling it restarts ghostd, so it asks
            for confirmation. Ghost Mode is runtime-toggleable with no restart.
          </p>

          <div>
            <TorRow
              enabled={torActive}
              pending={setTor.isPending}
              onApply={async (next) => {
                try {
                  await setTor.mutateAsync(next);
                  success(
                    "Tor mode " + (next ? "enabling" : "disabling"),
                    "ghostd is restarting" + (next ? " with -tormode=1" : " on clearnet") +
                      "; live state updates once it settles."
                  );
                } catch (e) {
                  error(
                    "Failed to update Tor mode",
                    e instanceof Error ? e.message : "Unknown error"
                  );
                }
              }}
            />
            <ExposureRow
              label="Ghost Mode"
              description="When enabled, your node accepts and validates blocks but never relays unconfirmed transactions or answers getdata for them. Mempool becomes opaque to peers — useful for privacy-maximising operators. Block relay is unaffected."
              enabled={ghostMode}
              onChange={async (next) => {
                try {
                  await setGhostMode.mutateAsync(next);
                  success(
                    "Ghost Mode " + (next ? "enabled" : "disabled"),
                    next
                      ? "Outbound transaction relay suppressed"
                      : "Standard relay resumed"
                  );
                } catch (e) {
                  error(
                    "Failed to update Ghost Mode",
                    e instanceof Error ? e.message : "Unknown error"
                  );
                }
              }}
              disabled={setGhostMode.isPending}
              badge={ghostMode ? "active" : undefined}
            />
          </div>
        </Card>
      </SectionErrorBoundary>

      <p style={{ color: "var(--fainter)", fontSize: "13px" }}>
        For the underlying config (ghostd flags, bridge configuration, etc.) see{" "}
        <a
          href="/settings/privacy"
          className="bare"
          style={{
            color: "var(--dim)",
            textDecoration: "underline",
            textDecorationColor: "var(--rule-strong)",
          }}
        >
          /settings/privacy
        </a>
        . For relay timing privacy see <a href="/shroud" className="bare" style={{ color: "var(--dim)", textDecoration: "underline", textDecorationColor: "var(--rule-strong)" }}>Shroud</a>.
      </p>
    </div>
  );
}

function TorRow({
  enabled,
  pending,
  onApply,
}: {
  enabled: boolean;
  pending: boolean;
  onApply: (next: boolean) => void | Promise<void>;
}) {
  // `target` holds the pending confirmation value (true=enable, false=disable),
  // or null when not confirming. `false` is meaningful, so guard on `!== null`.
  const [target, setTarget] = useState<boolean | null>(null);

  return (
    <div style={{ padding: "16px 0", borderTop: "1px solid var(--rule)" }}>
      <div className="flex items-start justify-between gap-6">
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="flex items-center gap-2 mb-1">
            <span style={{ color: "var(--fg)", fontWeight: 500, fontSize: "15px" }}>Tor mode</span>
            {enabled && <Badge variant="success">+anonymity</Badge>}
          </div>
          <p style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.5", maxWidth: "60ch" }}>
            When enabled, ghostd routes all outbound P2P through Tor (<code>-tormode=1</code>) and publishes an
            onion service; clearnet address gossip is suppressed. This is a startup flag, so changing it
            restarts ghostd and briefly bounces the pool.
          </p>
        </div>
        <button
          onClick={() => setTarget(!enabled)}
          disabled={pending || target !== null}
          className="flex-shrink-0"
          style={{
            width: "44px",
            height: "24px",
            borderRadius: "12px",
            background: enabled ? "var(--accent)" : "var(--rule-strong)",
            border: "none",
            cursor: pending || target !== null ? "not-allowed" : "pointer",
            opacity: pending || target !== null ? 0.6 : 1,
            position: "relative",
            transition: "background 120ms",
          }}
          aria-pressed={enabled}
        >
          <span
            style={{
              position: "absolute",
              top: "3px",
              left: enabled ? "23px" : "3px",
              width: "18px",
              height: "18px",
              borderRadius: "50%",
              background: "white",
              transition: "left 120ms",
            }}
          />
        </button>
      </div>

      {target !== null && (
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
            {target ? "Enable" : "Disable"} <strong>Tor mode</strong>? This writes the config and{" "}
            <strong>restarts ghostd</strong> (then bounces the pool) to apply.
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="primary"
              size="sm"
              disabled={pending}
              onClick={async () => {
                await onApply(target);
                setTarget(null);
              }}
            >
              {pending ? "Applying…" : "Apply & restart"}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setTarget(null)} disabled={pending}>
              Cancel
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div>
      <div
        style={{
          fontSize: "11px",
          fontFamily: "var(--font-mono)",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          color: "var(--dim)",
          marginBottom: "4px",
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: "22px",
          fontWeight: 500,
          color: accent ?? "var(--fg)",
          fontFamily: "var(--font-mono)",
        }}
      >
        {value}
      </div>
    </div>
  );
}
