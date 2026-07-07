"use client";

import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useNodeStatus } from "@/hooks/queries/useNodeQueries";
import { useSetGhostMode, useSetGhostModeLocalEgress } from "@/hooks/queries/useConfigQueries";
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
  const setLocalEgress = useSetGhostModeLocalEgress();
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
  const localEgress = !!status?.ghost_mode_local_egress;
  // The sub-toggle only has any effect while Ghost Mode is on; grey it out
  // otherwise so operators can't arm a setting that does nothing.
  const localEgressDisabled = !ghostMode || setLocalEgress.isPending;

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
              <p style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.5" }}>
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

          {/* Sub-toggle: local egress (own-tx broadcast) */}
          <div
            className="flex items-start justify-between gap-6"
            style={{
              marginTop: "16px",
              paddingTop: "16px",
              borderTop: "1px solid var(--rule)",
              opacity: ghostMode ? 1 : 0.5,
            }}
          >
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="flex items-center gap-2 mb-1">
                <span style={{ color: "var(--fg)", fontWeight: 500, fontSize: "15px" }}>
                  Allow my own wallet broadcasts
                </span>
                {ghostMode && localEgress && <Badge variant="success">on</Badge>}
              </div>
              <p style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.5" }}>
                Keep transactions your own node submits (via <code>sendrawtransaction</code> or a connected
                wallet) flowing to peers so they can reach a miner, while transactions received from other
                peers stay fully suppressed. Only your <em>own</em> still-unbroadcast transactions are
                announced and served. {!ghostMode && "Enable Ghost Mode to use this."}
              </p>
            </div>
            <button
              onClick={async () => {
                const next = !localEgress;
                try {
                  await setLocalEgress.mutateAsync(next);
                  success(
                    "Own-tx broadcast " + (next ? "enabled" : "disabled"),
                    next
                      ? "Your node will announce its own transactions to peers"
                      : "Your node is silent about all transactions again"
                  );
                } catch (e) {
                  error("Failed to update own-tx broadcast", e instanceof Error ? e.message : "Unknown error");
                }
              }}
              disabled={localEgressDisabled}
              className="flex-shrink-0"
              style={{
                width: "44px",
                height: "24px",
                borderRadius: "12px",
                background: localEgress && ghostMode ? "var(--accent)" : "var(--rule-strong)",
                border: "none",
                cursor: localEgressDisabled ? "not-allowed" : "pointer",
                opacity: setLocalEgress.isPending ? 0.6 : 1,
                position: "relative",
                transition: "background 120ms",
              }}
              aria-pressed={localEgress && ghostMode}
              aria-disabled={localEgressDisabled}
            >
              <span
                style={{
                  position: "absolute",
                  top: "3px",
                  left: localEgress && ghostMode ? "23px" : "3px",
                  width: "18px",
                  height: "18px",
                  borderRadius: "50%",
                  background: "white",
                  transition: "left 120ms",
                }}
              />
            </button>
          </div>

          {/* Privacy caution: broadcasting reveals your txs to peers */}
          {ghostMode && localEgress && (
            <div
              style={{
                marginTop: "14px",
                padding: "12px 14px",
                background: "color-mix(in srgb, var(--yellow) 8%, transparent)",
                border: "1px solid color-mix(in srgb, var(--yellow) 40%, transparent)",
                borderRadius: "6px",
              }}
            >
              <p style={{ color: "var(--fg)", fontSize: "13px", lineHeight: "1.6" }}>
                <span style={{ color: "var(--yellow)", fontWeight: 600 }}>Heads up:</span> broadcasting your
                own transactions reveals them to the peers you announce to, which can tie a transaction to
                your node&apos;s IP address. Enable{" "}
                <a
                  href="/network"
                  className="bare"
                  style={{ color: "var(--fg)", textDecoration: "underline", textDecorationColor: "var(--yellow)" }}
                >
                  Tor mode on the Network page
                </a>{" "}
                to keep your IP private while broadcasting.
              </p>
            </div>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* What it does */}
      <Card>
        <h3 style={{ color: "var(--fg)", fontSize: "16px", fontWeight: 500, marginBottom: "4px" }}>
          What it does
        </h3>
        <p style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.6", marginBottom: "12px" }}>
          Ghost Mode decides <em>whether</em> your node relays unconfirmed transactions at all — it is
          ghost-core&apos;s integrated take on Bitcoin Core&apos;s <code>-blocksonly</code>, wired into the runtime
          config with a friendly toggle. When <code>ghost_mode = true</code>:
        </p>
        <ul style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.7", paddingLeft: "18px", listStyle: "disc" }}>
          <li><strong style={{ color: "var(--fg)" }}>Relay is suppressed.</strong> <code>RelayTransaction()</code> returns early — your node never pushes unconfirmed transactions to peers.</li>
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
            suppression of the standard relay path, not a replacement transport. Without local egress, a
            wallet on a Ghost Mode node must find another route to reach miners — an out-of-band relay over
            Tor, a separate broadcasting node, or a paid broadcast service — otherwise its transactions
            never confirm. Turn on <em>Allow my own wallet broadcasts</em> above to let the node relay its
            own transactions while staying silent about everyone else&apos;s.
          </p>
        </div>
      </Card>

      {/* Rewards / capability shares */}
      <Card>
        <h3 style={{ color: "var(--fg)", fontSize: "16px", fontWeight: 500, marginBottom: "4px" }}>
          Does this affect my capability shares?
        </h3>
        <p style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.6", marginBottom: "12px" }}>
          <strong style={{ color: "var(--fg)" }}>No.</strong> Every capability is verified by an HTTP
          challenge–response to your node&apos;s API — Archive by historical-block retrieval, Ghost Pay by
          L2-block lookup, Reaper by policy classification — plus a Stratum port check for Public Mining.
          None of that rides the P2P transaction-relay path Ghost Mode suppresses, so you keep all of your
          5-4-3-2-1 shares while running silent. Ghost Mode composes cleanly with an archive / verification
          node behind Tor: a private, silent node that still earns its full share of the reward pool.
        </p>
        <div
          style={{
            padding: "12px 14px",
            background: "var(--bg)",
            border: "1px solid var(--rule)",
            borderRadius: "6px",
          }}
        >
          <p style={{ color: "var(--fainter)", fontSize: "13px", lineHeight: "1.6" }}>
            <span style={{ color: "var(--yellow)", fontWeight: 500 }}>Mining caveat:</span> Ghost Mode
            rejects transactions from peers, so your mempool never fills with anyone else&apos;s fee-paying
            transactions. Blocks your node builds are therefore near-empty — coinbase subsidy only, no
            transaction fees. The Public Mining <strong style={{ color: "var(--fg)" }}>+3</strong> share
            still verifies (the Stratum port stays open), but any block your miners find earns no fees.
            Ghost Mode suits archive / verification nodes; if you mine for fee revenue, leave it off.
          </p>
        </div>
      </Card>

      {/* Threat model */}
      <Card>
        <h3 style={{ color: "var(--fg)", fontSize: "16px", fontWeight: 500, marginBottom: "4px" }}>
          What it protects against
        </h3>
        <p style={{ color: "var(--dim)", fontSize: "13px", marginBottom: "4px" }}>
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
        <p style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.6" }}>
          Ghost Mode is for privacy-maximising operators who want zero P2P-layer transaction footprint and
          already have a separate broadcast path for their own payments (or use <em>Allow my own wallet
          broadcasts</em> above). Ghost Mode composes with Tor mode — running both gives a node
          that is behind Tor <em>and</em> silent about transactions. If you don&apos;t have an out-of-band
          broadcast route, leave it off, or your own transactions won&apos;t reach a miner.
        </p>
      </Card>

      <p style={{ color: "var(--fainter)", fontSize: "13px" }}>
        For network-exposure controls (Tor mode, onion address) see{" "}
        <a href="/network" className="bare" style={{ color: "var(--dim)", textDecoration: "underline", textDecorationColor: "var(--rule-strong)" }}>
          Network
        </a>
        .
      </p>
    </div>
  );
}
