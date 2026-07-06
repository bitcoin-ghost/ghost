"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useNodeStatus } from "@/hooks/queries/useNodeQueries";
import { useSetGhostMode } from "@/hooks/queries/useConfigQueries";
import { useToast } from "@/components/ui/Toast";

/**
 * /ghost-mode — dedicated control + explainer for Ghost Mode.
 *
 * Ghost Mode is a ghost-core runtime flag (`m_ghost_mode` in net.cpp) that
 * suppresses the P2P transaction-relay path: no INV announcements, getdata for
 * transactions returns NOT_FOUND, and RelayTransaction() returns early. Block
 * relay is unaffected. It toggles live — the POST handler calls the ghost-core
 * RPC `set_ghost_mode` and persists to config; no node restart is required
 * (unlike Tor mode). See ghost-web/docs/ghost-mode.md.
 */

function InfoRow({ threat, protection, strong }: { threat: string; protection: string; strong: boolean }) {
  return (
    <div
      className="flex items-start justify-between gap-6"
      style={{ padding: "12px 0", borderTop: "1px solid var(--rule)" }}
    >
      <span style={{ color: "var(--fg)", fontSize: "14px", flex: 1, minWidth: 0 }}>{threat}</span>
      <span
        className="flex-shrink-0"
        style={{
          color: strong ? "var(--green)" : "var(--dim)",
          fontSize: "13px",
          fontFamily: "var(--font-mono)",
          maxWidth: "24ch",
          textAlign: "right",
        }}
      >
        {protection}
      </span>
    </div>
  );
}

export default function GhostModePage() {
  const { data: status, isLoading } = useNodeStatus();
  const setGhostMode = useSetGhostMode();
  const { success, error } = useToast();

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader
          eyebrow="ghost mode"
          title="Transaction-level silence."
          subtitle="Stop your node from relaying, announcing, or serving any unconfirmed transaction — to peers, your mempool effectively doesn't exist."
        />
        <SkeletonCard />
      </div>
    );
  }

  const ghostMode = !!status?.ghost_mode;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="ghost mode"
        title="Transaction-level silence."
        subtitle="Stop your node from relaying, announcing, or serving any unconfirmed transaction — to peers, your mempool effectively doesn't exist. Block relay is unaffected."
        actions={<Badge variant={ghostMode ? "success" : "info"}>{ghostMode ? "active" : "inactive"}</Badge>}
      />

      {/* Toggle */}
      <SectionErrorBoundary section="Ghost Mode control">
        <Card>
          <div className="flex items-start justify-between gap-6">
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="flex items-center gap-2 mb-1">
                <span style={{ color: "var(--fg)", fontWeight: 500, fontSize: "15px" }}>Ghost Mode</span>
                {ghostMode && <Badge variant="success">+privacy</Badge>}
              </div>
              <p style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.5", maxWidth: "60ch" }}>
                When enabled, your node still accepts, validates and forwards blocks, but never relays
                unconfirmed transactions, sends no <code>INV</code> announcements, and answers every
                transaction <code>getdata</code> with <code>NOT_FOUND</code>. Toggles live with no restart.
              </p>
            </div>
            <button
              onClick={async () => {
                const next = !ghostMode;
                try {
                  await setGhostMode.mutateAsync(next);
                  success(
                    "Ghost Mode " + (next ? "enabled" : "disabled"),
                    next ? "Outbound transaction relay suppressed" : "Standard relay resumed"
                  );
                } catch (e) {
                  error("Failed to update Ghost Mode", e instanceof Error ? e.message : "Unknown error");
                }
              }}
              disabled={setGhostMode.isPending}
              className="flex-shrink-0"
              style={{
                width: "44px",
                height: "24px",
                borderRadius: "12px",
                background: ghostMode ? "var(--accent)" : "var(--rule-strong)",
                border: "none",
                cursor: setGhostMode.isPending ? "not-allowed" : "pointer",
                opacity: setGhostMode.isPending ? 0.6 : 1,
                position: "relative",
                transition: "background 120ms",
              }}
              aria-pressed={ghostMode}
            >
              <span
                style={{
                  position: "absolute",
                  top: "3px",
                  left: ghostMode ? "23px" : "3px",
                  width: "18px",
                  height: "18px",
                  borderRadius: "50%",
                  background: "white",
                  transition: "left 120ms",
                }}
              />
            </button>
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* What it does */}
      <Card>
        <h3 style={{ color: "var(--fg)", fontSize: "16px", fontWeight: 500, marginBottom: "4px" }}>
          What it does
        </h3>
        <p style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.6", marginBottom: "12px", maxWidth: "68ch" }}>
          Shroud delays <em>when</em> you relay; Ghost Mode decides <em>whether</em> you relay at all. It is
          ghost-core&apos;s integrated take on Bitcoin Core&apos;s <code>-blocksonly</code>, wired into the runtime
          config with a friendly toggle. When <code>ghost_mode = true</code>:
        </p>
        <ul style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.7", paddingLeft: "18px", listStyle: "disc", maxWidth: "68ch" }}>
          <li><strong style={{ color: "var(--fg)" }}>Relay is suppressed.</strong> <code>RelayTransaction()</code> returns early — your node never pushes transactions to peers, and the Shroud delay queue is bypassed (nothing to delay).</li>
          <li><strong style={{ color: "var(--fg)" }}>getdata returns NOT_FOUND.</strong> A peer asking &quot;give me transaction X&quot; is answered <code>NOT_FOUND</code> regardless of whether X is in your mempool. Your mempool stops being a public lookup table.</li>
          <li><strong style={{ color: "var(--fg)" }}>No INV announcements.</strong> Your node doesn&apos;t tell peers about unconfirmed transactions it has seen.</li>
          <li><strong style={{ color: "var(--fg)" }}>Blocks are unaffected.</strong> You still receive, validate and forward blocks; the chain propagates through your node normally.</li>
        </ul>
        <div
          style={{
            marginTop: "14px",
            padding: "12px 14px",
            background: "var(--bg)",
            border: "1px solid var(--rule)",
            borderRadius: "6px",
          }}
        >
          <p style={{ color: "var(--fainter)", fontSize: "13px", lineHeight: "1.6" }}>
            <span style={{ color: "var(--accent)", fontWeight: 500 }}>Trade-off:</span> Ghost Mode is a
            suppression of the standard relay path, not a replacement transport. A wallet on a Ghost Mode
            node must find another route to reach miners — an out-of-band relay over Tor, a separate
            broadcasting node, or a paid broadcast service — otherwise its transactions never confirm.
          </p>
        </div>
      </Card>

      {/* Threat model */}
      <Card>
        <h3 style={{ color: "var(--fg)", fontSize: "16px", fontWeight: 500, marginBottom: "4px" }}>
          What it protects against
        </h3>
        <p style={{ color: "var(--dim)", fontSize: "13px", marginBottom: "4px", maxWidth: "68ch" }}>
          Ghost Mode is transaction-level silence at the gossip layer. It does not change consensus and
          does not make your node invisible.
        </p>
        <div>
          <InfoRow threat="Mempool query services (getrawmempool, INV-bait)" protection="Strong" strong />
          <InfoRow threat="INV-bait probes watching for announcements" protection="Strong" strong />
          <InfoRow threat="Transaction-origin triangulation by relay timing" protection="Strong" strong />
          <InfoRow threat="Determining whether your node runs a wallet" protection="Strong" strong />
          <InfoRow threat="Compelled disclosure / running-process seizure (mempool still in RAM)" protection="None" strong={false} />
          <InfoRow threat="Block-level traffic analysis (block relay is unchanged)" protection="None" strong={false} />
          <InfoRow threat="IP-level anonymity — run Tor mode in addition" protection="None" strong={false} />
        </div>
      </Card>

      {/* When to use */}
      <Card>
        <h3 style={{ color: "var(--fg)", fontSize: "16px", fontWeight: 500, marginBottom: "4px" }}>
          When to enable it
        </h3>
        <p style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.6", maxWidth: "68ch" }}>
          Ghost Mode is for privacy-maximising operators who want zero P2P-layer transaction footprint and
          already have a separate broadcast path for their own payments. Most users only need Shroud for
          basic relay-timing protection. Ghost Mode composes with Tor mode — running both gives a node
          that is behind Tor <em>and</em> silent about transactions. If you don&apos;t have an out-of-band
          broadcast route, leave it off, or your own transactions won&apos;t reach a miner.
        </p>
      </Card>

      <p style={{ color: "var(--fainter)", fontSize: "13px" }}>
        For network-exposure controls (Tor mode, onion address) see{" "}
        <a href="/network" className="bare" style={{ color: "var(--dim)", textDecoration: "underline", textDecorationColor: "var(--rule-strong)" }}>
          Network
        </a>
        . For relay-timing privacy see{" "}
        <a href="/shroud" className="bare" style={{ color: "var(--dim)", textDecoration: "underline", textDecorationColor: "var(--rule-strong)" }}>
          Shroud
        </a>
        .
      </p>
    </div>
  );
}
