"use client";

import { ReactNode } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { CopyButton } from "@/components/ui/CopyButton";
import { QrCode } from "@/components/ui/QrCode";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useNodeInfo, useSwarm, useBlockchainStatus } from "@/hooks/queries";

// Default JSON-RPC and P2P ports per Bitcoin-Ghost network. Sourced from the
// node's reported network (node info / blockchain status); Ghost uses the
// upstream Bitcoin port scheme.
function portsForNetwork(network?: string | null): { rpc: number; p2p: number; label: string } {
  const n = (network || "").toLowerCase();
  if (n.includes("signet")) return { rpc: 38332, p2p: 38333, label: "signet" };
  if (n.includes("regtest")) return { rpc: 18443, p2p: 18444, label: "regtest" };
  if (n.includes("test")) return { rpc: 18332, p2p: 18333, label: "testnet" };
  return { rpc: 8332, p2p: 8333, label: "mainnet" };
}

// A single labelled + copyable string with its QR and a one-line explainer.
function ConnectionEntry({
  title,
  badge,
  connString,
  qrValue,
  what,
  note,
  extra,
}: {
  title: string;
  badge?: ReactNode;
  connString: string;
  qrValue?: string;
  what: string;
  note?: string;
  extra?: ReactNode;
}) {
  return (
    <Card>
      <CardHeader title={<span className="flex items-center gap-2">{title}{badge}</span>} subtitle={what} />
      <div className="flex flex-col sm:flex-row gap-5">
        <div className="flex-1 min-w-0 space-y-3">
          <div className="p-3 rounded-lg" style={{ background: "var(--surface-2, rgba(120,120,120,0.08))", border: "1px solid var(--rule)" }}>
            <div className="text-xs uppercase tracking-wide mb-1" style={{ color: "var(--dim)" }}>
              Connection string
            </div>
            <div className="flex items-center gap-2">
              <code className="font-mono text-sm break-all select-all" style={{ color: "var(--accent)" }}>
                {connString}
              </code>
              <CopyButton text={connString} className="flex-shrink-0" />
            </div>
          </div>
          {extra}
          {note && (
            <p className="text-xs" style={{ color: "var(--fainter)" }}>
              {note}
            </p>
          )}
        </div>
        <div className="flex-shrink-0 self-start">
          <QrCode value={qrValue ?? connString} size={148} />
        </div>
      </div>
    </Card>
  );
}

export default function ConnectPage() {
  const { data: nodeInfo } = useNodeInfo();
  const { data: swarmData } = useSwarm();
  const { data: blockchain } = useBlockchainStatus();

  // Prefer the swarm self address (the node's real public <ip>:8080), falling
  // back to the browser host — which, over an SSH tunnel or localhost, is
  // whatever the operator is viewing the dashboard through.
  const selfAddr = swarmData?.self?.address;
  const host = selfAddr
    ? selfAddr.split(":")[0]
    : typeof window !== "undefined"
      ? window.location.hostname
      : "<your-ip>";
  const hostKnown = Boolean(selfAddr);

  const network = nodeInfo?.network ?? blockchain?.network ?? blockchain?.chain ?? undefined;
  const ports = portsForNetwork(network);
  const nodeId = nodeInfo?.node_id;

  const httpUrl = `http://${host}:8080`;
  const gspUrl = `ws://${host}:8900`;
  const rpcEndpoint = `http://${host}:${ports.rpc}`;
  const p2pAddr = `${host}:${ports.p2p}`;

  return (
    <div>
      <PageHeader
        eyebrow="connect wallet"
        title="Pair wallets & nodes"
        subtitle="Connection strings and QR codes to pair wallets and other nodes to this one. Scan a code or copy a string into your wallet — QR codes are generated locally in your browser, nothing leaves this page."
      />

      {!hostKnown && (
        <div
          className="mb-6 p-3 rounded-lg text-sm"
          style={{ background: "rgba(234,140,40,0.08)", border: "1px solid var(--rule)", color: "var(--dim)" }}
        >
          This node has not advertised a public address yet, so the codes below use the host you are viewing the
          dashboard through (<code className="font-mono">{host}</code>). Set the node&apos;s public IP or hostname in
          Swarm so wallets on other machines can reach it.
        </div>
      )}

      <div className="space-y-4">
        {/* Ghost node — the primary pairing surface for Ghost wallets. */}
        <SectionErrorBoundary section="Ghost Node">
          <ConnectionEntry
            title="Ghost Node"
            badge={<Badge variant="success">Available</Badge>}
            what="Your node's Ghost HTTP endpoint. Wraith and Ghost light wallets pair to their own node here; other operators can add this address to their swarm."
            connString={httpUrl}
            note={`Network: ${ports.label}. This is the node's :8080 API / swarm address.`}
            extra={
              nodeId ? (
                <div
                  className="p-3 rounded-lg"
                  style={{ background: "var(--surface-2, rgba(120,120,120,0.08))", border: "1px solid var(--rule)" }}
                >
                  {/* This is the mesh/consensus node identity. It is NOT the Ghost ID, which is
                      the node's L2 receive address from ghost-pay and lives in Settings. Labelling
                      this one "Ghost ID" made two unrelated identifiers look interchangeable. */}
                  <div className="text-xs uppercase tracking-wide mb-1" style={{ color: "var(--dim)" }}>
                    Node ID (mesh identity)
                  </div>
                  <div className="flex items-center gap-2">
                    <code className="font-mono text-xs break-all select-all" style={{ color: "var(--fg)" }}>
                      {nodeId}
                    </code>
                    <CopyButton text={nodeId} className="flex-shrink-0" />
                  </div>
                </div>
              ) : undefined
            }
          />
        </SectionErrorBoundary>

        {/* GSP — light-wallet WebSocket. */}
        <SectionErrorBoundary section="Light Wallet (GSP)">
          <ConnectionEntry
            title="Light Wallet (GSP)"
            badge={<Badge variant="success">Available</Badge>}
            what="Ghost Service Provider WebSocket. Light wallets — GhostTap mobile and the ghost-light-wallet CLI/TUI — sync against this endpoint."
            connString={gspUrl}
            note="GSP serves compact block filters and note delivery to light clients over a WebSocket on port 8900."
          />
        </SectionErrorBoundary>

        {/* P2P — add this node as a peer. */}
        <SectionErrorBoundary section="P2P">
          <ConnectionEntry
            title="P2P Peer"
            badge={<Badge variant="success">Available</Badge>}
            what="The node's peer-to-peer address. Add it to another Ghost node with addnode to connect the two directly."
            connString={p2pAddr}
            note={`Default ${ports.label} P2P port (${ports.p2p}). Reachable only if the operator has opened this port to the internet.`}
          />
        </SectionErrorBoundary>

        {/* RPC — endpoint only, never credentials. */}
        <SectionErrorBoundary section="RPC">
          <ConnectionEntry
            title="RPC Endpoint"
            badge={<Badge variant="info">Endpoint only</Badge>}
            what="The node's JSON-RPC endpoint. Full wallets that talk RPC point here."
            connString={rpcEndpoint}
            note="Credentials are deliberately NOT included in this string or QR. RPC is usually bound to localhost and firewalled — pair over an SSH tunnel and supply your rpcuser / rpcpassword (or cookie) in the wallet, never on a shared surface."
          />
        </SectionErrorBoundary>

        {/* Electrum — genuinely unavailable on a Ghost node. */}
        <SectionErrorBoundary section="Electrum">
          <Card>
            <CardHeader
              title={
                <span className="flex items-center gap-2">
                  Electrum Server
                  <Badge variant="default">Not available</Badge>
                </span>
              }
              subtitle="Electrum-protocol wallets (host:port:s) would pair here."
            />
            <p className="text-sm" style={{ color: "var(--dim)" }}>
              This node does not run an Electrum-compatible server (electrs/ElectrumX). Ghost&apos;s privacy model
              serves light wallets through the GSP endpoint above instead of an address-indexing Electrum server, so
              there is no Electrum connection string to advertise. If you run electrs alongside your node, expose it
              yourself — it is not part of the Ghost node.
            </p>
          </Card>
        </SectionErrorBoundary>
      </div>
    </div>
  );
}
