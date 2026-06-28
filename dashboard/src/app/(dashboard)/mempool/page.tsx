"use client";

import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { CopyButton } from "@/components/ui/CopyButton";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { fetchApi } from "@/lib/api/client";

/**
 * Per-node mempool view.
 *
 * The mempool stack (mempool.space + electrs) is an opt-in add-on because it
 * costs ~2 GB RAM and ~50 GB disk. Operators on tight hardware skip it and
 * use mempool.space directly; operators with headroom install it locally and
 * see THEIR node's view of the mempool — which actually differs depending on
 * Reaper policy.
 *
 * Three UI states based on `/api/v1/system/mempool`:
 *
 *   running              → iframe http://localhost:<port>/
 *   installed_not_running → status panel + start instruction
 *   not_installed         → install panel with one-line command + reqs
 */

interface MempoolStatus {
  enabled: boolean;
  status: "running" | "installed_not_running" | "not_installed";
  port: number;
  marker_path: string;
  install_command: string;
  uninstall_command: string;
  min_ram_gb: number;
  min_disk_gb: number;
}

async function fetchMempoolStatus(): Promise<MempoolStatus> {
  // Route through the proxy (fetchApi) so the HMAC-signed internal request
  // reaches ghost-pool; a bare fetch hits the Next server and always 404s,
  // which previously made every node falsely report "not installed".
  return fetchApi<MempoolStatus>("/api/v1/system/mempool");
}

export default function MempoolPage() {
  const { data, isLoading, error } = useQuery<MempoolStatus>({
    queryKey: ["mempool-status"],
    queryFn: fetchMempoolStatus,
    refetchInterval: 15_000,
  });

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader eyebrow="mempool" title="Your node's mempool view." />
        <SkeletonCard />
      </div>
    );
  }

  // Backend endpoint missing or fetch failed → assume not installed and show
  // install panel. Better than blanking out — operator gets actionable UI.
  if (error || !data) {
    return <NotInstalled fallback={true} />;
  }

  if (data.status === "running") {
    return <Running port={data.port} />;
  }

  if (data.status === "installed_not_running") {
    return <InstalledNotRunning data={data} />;
  }

  return <NotInstalled data={data} />;
}

// ─── State 1: running — iframe the live mempool.space frontend ────────────

function Running({ port }: { port: number }) {
  // Same-origin from the user's browser perspective: dashboard runs on
  // http://localhost:3000, mempool stack on http://localhost:<port>. The
  // iframe loads cleanly without mixed-content warnings.
  const url = `http://localhost:${port}/`;
  return (
    <div className="space-y-4" style={{ height: "calc(100vh - 100px)", display: "flex", flexDirection: "column" }}>
      <PageHeader
        eyebrow="mempool"
        title="Your node's mempool view."
        subtitle="Live mempool.space rendering of THIS node's view (filtered by your Reaper policy if enabled)."
        actions={
          <Badge variant="success">running on :{port}</Badge>
        }
      />
      <div
        style={{
          flex: 1,
          border: "1px solid var(--rule)",
          borderRadius: "4px",
          overflow: "hidden",
          background: "var(--surface)",
        }}
      >
        <iframe
          src={url}
          title="mempool"
          style={{ width: "100%", height: "100%", border: 0, display: "block" }}
        />
      </div>
    </div>
  );
}

// ─── State 2: installed but service not running ───────────────────────────

function InstalledNotRunning({ data }: { data: MempoolStatus }) {
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="mempool"
        title="Mempool stack is installed but not running."
        subtitle="The marker file is present but nothing is listening on the port."
        actions={<Badge variant="warning">stopped</Badge>}
      />
      <Card>
        <div className="space-y-4">
          <Row label="Marker file" value={<code>{data.marker_path}</code>} />
          <Row label="Configured port" value={<code>{data.port}</code>} />
          <div>
            <p style={{ color: "var(--dim)", fontSize: "14px", marginBottom: "12px" }}>
              Bring it back up with:
            </p>
            <CodeBlock command="sudo systemctl start ghost-mempool" />
          </div>
          <p style={{ color: "var(--dim)", fontSize: "13px" }}>
            Or run <code>{data.uninstall_command}</code> to remove the stack entirely.
          </p>
        </div>
      </Card>
    </div>
  );
}

// ─── State 3: not installed — show install panel ──────────────────────────

function NotInstalled({ data, fallback = false }: { data?: MempoolStatus; fallback?: boolean }) {
  const minRam = data?.min_ram_gb ?? 4;
  const minDisk = data?.min_disk_gb ?? 50;
  const installCmd = data?.install_command ?? "sudo /opt/ghost/bin/ghost-mempool install";

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="mempool"
        title="Run mempool.space on your own node."
        subtitle="Optional add-on. Most operators don't need it — your node already validates the mempool. Install only if you want a local mempool.space-style explorer."
        actions={<Badge variant="info">not installed</Badge>}
      />

      <Card>
        <div className="space-y-6">
          <div>
            <h3 style={{ color: "var(--fg)", fontSize: "16px", fontWeight: 500, marginBottom: "8px" }}>
              What gets installed
            </h3>
            <ul style={{ color: "var(--dim)", fontSize: "14px", lineHeight: "1.7", paddingLeft: "20px", listStyle: "disc" }}>
              <li>
                <strong style={{ color: "var(--fg)" }}>mempool-backend</strong> — the API + websocket service that powers mempool.space
              </li>
              <li>
                <strong style={{ color: "var(--fg)" }}>electrs</strong> — Bitcoin index server (this is the bulk of the disk usage)
              </li>
              <li>
                <strong style={{ color: "var(--fg)" }}>mempool-frontend</strong> — the web UI you'll be looking at
              </li>
              <li>Listens on <code>localhost:{data?.port ?? 8999}</code> only — no public exposure</li>
              <li>Reads from your local <code>ghostd</code> RPC (already running)</li>
            </ul>
          </div>

          <div>
            <h3 style={{ color: "var(--fg)", fontSize: "16px", fontWeight: 500, marginBottom: "8px" }}>
              Resource requirements
            </h3>
            <div className="grid grid-cols-2 gap-6">
              <Stat label="free RAM" value={`≥${minRam} GB`} />
              <Stat label="free disk" value={`≥${minDisk} GB`} />
            </div>
            <p style={{ color: "var(--dim)", fontSize: "13px", marginTop: "12px" }}>
              The installer pre-flights these — if your node doesn't meet them, it refuses to proceed and tells you what's missing. Won't break your existing services.
            </p>
          </div>

          <div>
            <h3 style={{ color: "var(--fg)", fontSize: "16px", fontWeight: 500, marginBottom: "8px" }}>
              One-line install
            </h3>
            <CodeBlock command={installCmd} />
            <p style={{ color: "var(--dim)", fontSize: "13px", marginTop: "12px" }}>
              Bring-up takes 5–15 minutes (electrs has to index the chain on first run). This page auto-refreshes every 15 s — once the stack is up the UI flips automatically.
            </p>
          </div>

          {fallback && (
            <p style={{ color: "var(--fainter)", fontSize: "13px", borderTop: "1px solid var(--rule)", paddingTop: "12px" }}>
              <em>Note:</em> couldn't reach <code>/api/v1/system/mempool</code> on this node. This page falls back to the install panel because that's the safe assumption (showing an iframe to a non-existent port would be worse).
            </p>
          )}
        </div>
      </Card>

      <p style={{ color: "var(--fainter)", fontSize: "13px" }}>
        If you don't want to run the stack, that's fine — your node still validates the mempool through ghost-core's RPC and{" "}
        <a href="/" className="bare" style={{ color: "var(--dim)", textDecoration: "underline", textDecorationColor: "var(--rule-strong)" }}>
          public mempool.space
        </a>{" "}
        works just as well for visualisation. This page is here purely for operators who want a node-local view (e.g. seeing the difference between filtered and unfiltered).
      </p>
    </div>
  );
}

// ─── helpers ──────────────────────────────────────────────────────────────

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline gap-4">
      <span
        style={{
          fontSize: "11px",
          fontFamily: "var(--font-mono)",
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          color: "var(--dim)",
          minWidth: "140px",
        }}
      >
        {label}
      </span>
      <span style={{ color: "var(--fg)", fontSize: "14px" }}>{value}</span>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
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
      <div style={{ fontSize: "24px", fontWeight: 500, color: "var(--fg)", fontFamily: "var(--font-mono)" }}>
        {value}
      </div>
    </div>
  );
}

function CodeBlock({ command }: { command: string }) {
  return (
    <div
      className="flex items-center justify-between gap-3"
      style={{
        background: "var(--bg)",
        border: "1px solid var(--rule)",
        borderRadius: "4px",
        padding: "12px 16px",
        fontFamily: "var(--font-mono)",
        fontSize: "13px",
      }}
    >
      <code style={{ color: "var(--fg)", overflow: "auto", whiteSpace: "nowrap" }}>$ {command}</code>
      <CopyButton text={command} />
    </div>
  );
}
