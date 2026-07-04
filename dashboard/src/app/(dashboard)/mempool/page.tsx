"use client";

import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { CopyButton } from "@/components/ui/CopyButton";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { StatCard } from "@/components/ui/StatCard";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useConfig } from "@/hooks/queries/useConfigQueries";
import { fetchApi } from "@/lib/api/client";

/**
 * Per-node mempool view — LIGHTWEIGHT by default.
 *
 * The primary content is sourced entirely from ghostd's RPC via the node API
 * (`/api/v1/buds/mempool` = getmempoolinfo + getrawmempool, and
 * `/api/v1/reaper/status` = template-builder filter counters). This needs NO
 * electrs index and NO 50 GB of disk — it mirrors the RPC-only mempool
 * comparison the public site shows, plus the Ghost-specific "what your node
 * filters" view that only a node-local vantage point can produce.
 *
 * The heavy mempool.space + electrs stack (address-searchable full explorer,
 * ≥50 GB) is demoted to an optional "Advanced" add-on at the bottom of the
 * page, driven by `/api/v1/system/mempool` (running / installed_not_running /
 * not_installed).
 */

// ─── types ────────────────────────────────────────────────────────────────

interface MempoolTx {
  txid: string;
  vsize: number;
  weight: number;
  fee: number; // BTC (fees.base from getrawmempool)
  time: number; // unix seconds
  tier: number | null;
  tier_name: string;
  classification_reason: string;
}

interface BudsMempool {
  transactions: MempoolTx[];
  total: number; // mempool tx count (getmempoolinfo.size)
  bytes?: number; // total vsize bytes
  usage?: number; // estimated memory usage
  max_mempool?: number; // maxmempool bytes
  min_fee?: number; // BTC/kvB (getmempoolinfo.mempoolminfee)
  by_tier: { T0: number; T1: number; T2: number; T3: number };
  sample_size?: number;
  message?: string; // present when RPC unavailable
}

interface ReaperStats {
  txs_evaluated: number;
  txs_reaped: number;
  txs_accepted: number;
  dead_bytes_total: number;
  last_reaped_unix: number | null;
  by_type: {
    inscription_envelope: number;
    drop_stuffing: number;
    unreachable_code: number;
    fake_pubkey: number;
    fake_pubkey_curve_point: number;
    annex_present: number;
    oversized_op_return: number;
    dust_flood?: number;
    excess_witness_data: number;
    excess_stack_items: number;
    legacy_scriptsig_data: number;
  };
}

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

// ─── fetchers ───────────────────────────────────────────────────────────────

async function fetchBudsMempool(): Promise<BudsMempool> {
  return fetchApi<BudsMempool>("/api/v1/buds/mempool");
}

async function fetchReaperStats(): Promise<ReaperStats | null> {
  try {
    const data = await fetchApi<unknown>("/api/v1/reaper/status");
    return data && typeof data === "object" && "txs_evaluated" in data
      ? (data as ReaperStats)
      : null;
  } catch {
    return null;
  }
}

async function fetchMempoolStatus(): Promise<MempoolStatus | null> {
  try {
    return await fetchApi<MempoolStatus>("/api/v1/system/mempool");
  } catch {
    return null;
  }
}

// ─── formatting helpers ─────────────────────────────────────────────────────

function formatBytes(n: number | undefined): string {
  if (n === undefined || n === null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatCount(n: number | undefined): string {
  return n === undefined || n === null ? "—" : n.toLocaleString();
}

function formatPercent(numerator: number, denominator: number): string {
  if (!denominator) return "—";
  const pct = (numerator / denominator) * 100;
  return pct < 0.01 ? "<0.01%" : `${pct.toFixed(2)}%`;
}

function formatRelative(unixSecs: number | null): string {
  if (!unixSecs) return "never";
  const ago = Math.floor(Date.now() / 1000) - unixSecs;
  if (ago < 60) return `${ago}s ago`;
  if (ago < 3600) return `${Math.floor(ago / 60)}m ago`;
  if (ago < 86400) return `${Math.floor(ago / 3600)}h ago`;
  return `${Math.floor(ago / 86400)}d ago`;
}

// min_fee from getmempoolinfo is BTC/kvB. sat/vB = BTC/kvB * 1e8 / 1000 = *1e5
function btcPerKvbToSatVb(btcPerKvb: number | undefined): number | null {
  if (btcPerKvb === undefined || btcPerKvb === null) return null;
  return btcPerKvb * 1e5;
}

// Per-tx fee-rate in sat/vB. fee is BTC (fees.base), vsize in vbytes.
function feeRateSatVb(tx: MempoolTx): number {
  if (!tx.vsize) return 0;
  return (tx.fee * 1e8) / tx.vsize;
}

function formatFeeRate(satVb: number | null): string {
  if (satVb === null) return "—";
  if (satVb < 1) return `${satVb.toFixed(2)} sat/vB`;
  return `${satVb.toFixed(1)} sat/vB`;
}

// ─── static metadata ────────────────────────────────────────────────────────

const TIERS = [
  { key: "T0" as const, name: "T0 · Financial", color: "#3fb950", desc: "Clean monetary transactions" },
  { key: "T1" as const, name: "T1 · Extended", color: "#58a6ff", desc: "Multisig / larger financial" },
  { key: "T2" as const, name: "T2 · Data", color: "#d29922", desc: "OP_RETURN data carriers" },
  { key: "T3" as const, name: "T3 · Abusive", color: "#f85149", desc: "Runes, inscriptions, stuffing" },
];

const FEE_BUCKETS = [
  { label: "0–1", min: 0, max: 1 },
  { label: "1–2", min: 1, max: 2 },
  { label: "2–5", min: 2, max: 5 },
  { label: "5–10", min: 5, max: 10 },
  { label: "10–20", min: 10, max: 20 },
  { label: "20–50", min: 20, max: 50 },
  { label: "50–100", min: 50, max: 100 },
  { label: "100+", min: 100, max: Infinity },
];

const REAPER_VECTORS: { key: keyof ReaperStats["by_type"]; name: string }[] = [
  { key: "inscription_envelope", name: "Inscription envelopes" },
  { key: "fake_pubkey_curve_point", name: "Fake pubkey curve points" },
  { key: "oversized_op_return", name: "Oversized OP_RETURN" },
  { key: "excess_witness_data", name: "Excess witness data" },
  { key: "excess_stack_items", name: "Excess stack items" },
  { key: "unreachable_code", name: "Unreachable code" },
  { key: "drop_stuffing", name: "Drop stuffing" },
  { key: "fake_pubkey", name: "Fake pubkeys" },
  { key: "annex_present", name: "Annex bloat" },
  { key: "dust_flood", name: "Dust-flood spam" },
  { key: "legacy_scriptsig_data", name: "Legacy scriptSig data" },
];

// ─── page ───────────────────────────────────────────────────────────────────

export default function MempoolPage() {
  const { data: config } = useConfig();
  const {
    data: mempool,
    isLoading,
    error: mempoolError,
  } = useQuery<BudsMempool>({
    queryKey: ["buds-mempool"],
    queryFn: fetchBudsMempool,
    refetchInterval: 15_000,
  });

  const { data: reaper } = useQuery<ReaperStats | null>({
    queryKey: ["reaper-status"],
    queryFn: fetchReaperStats,
    refetchInterval: 15_000,
  });

  const { data: stackStatus } = useQuery<MempoolStatus | null>({
    queryKey: ["mempool-status"],
    queryFn: fetchMempoolStatus,
    refetchInterval: 30_000,
  });

  const reaperEnabled = config?.reaper ?? false;

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader eyebrow="mempool" title="Your node's mempool." />
        <SectionErrorBoundary section="Node mempool explorer">
          <NodeMempoolExplorer />
        </SectionErrorBoundary>
        <SkeletonCard />
      </div>
    );
  }

  const rpcUnavailable = !!mempoolError || (!!mempool?.message && (mempool?.total ?? 0) === 0);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="mempool"
        title="Your node's mempool."
        subtitle="Live view straight from your node's RPC — no indexer, no 50 GB, nothing to install. This is THIS node's mempool, filtered by your policy, with the Ghost class breakdown a general explorer can't show."
        actions={<Badge variant="success">rpc · lightweight</Badge>}
      />

      {/* The real mempool.space UI of THIS node's own mempool, served
          same-origin through the dashboard, at the very top. The lightweight
          RPC cards and the Reaper filter breakdown follow below. */}
      <SectionErrorBoundary section="Node mempool explorer">
        <NodeMempoolExplorer />
      </SectionErrorBoundary>

      {rpcUnavailable ? (
        <Card>
          <div className="space-y-2">
            <p style={{ color: "var(--fg)", fontSize: "15px" }}>
              Couldn&apos;t read the mempool from <code>ghostd</code> RPC.
            </p>
            <p style={{ color: "var(--dim)", fontSize: "13px" }}>
              {mempool?.message ??
                "The node API returned an error for /api/v1/buds/mempool. Check that ghostd is running and RPC credentials are configured in pool.toml."}
            </p>
          </div>
        </Card>
      ) : (
        <>
          <LiveStats mempool={mempool} />
          <SectionErrorBoundary section="Ghost filter view">
            <FilterView reaper={reaper} reaperEnabled={reaperEnabled} />
          </SectionErrorBoundary>
          <SectionErrorBoundary section="Mempool composition">
            <Composition mempool={mempool} />
          </SectionErrorBoundary>
          <SectionErrorBoundary section="Fee distribution">
            <FeeDistribution mempool={mempool} />
          </SectionErrorBoundary>
          <SectionErrorBoundary section="Recent transactions">
            <RecentTxs mempool={mempool} />
          </SectionErrorBoundary>
        </>
      )}

      {/* Heavy full-explorer add-on, demoted to the bottom. */}
      <AdvancedExplorer status={stackStatus} />
    </div>
  );
}

// ─── node mempool explorer (real mempool.space UI, same-origin) ──────────────

// The dashboard serves the built mempool.space frontend at this same-origin
// subpath and proxies its API + WebSocket to the node's own Core-only mempool
// backend on 127.0.0.1:8999. Because it is same-origin (no external host, no
// certificate, no DNS) it frames without mixed-content or cross-origin issues,
// and it shows THIS node's own mempool on any node.
const NODE_MEMPOOL_APP_URL = "/mempool-app/";

/**
 * The real mempool.space explorer for this node's own mempool, embedded
 * same-origin.
 *
 * Same-origin means the usual embed hazards (a TLS cert that doesn't cover a
 * subdomain, a cross-origin `X-Frame-Options`, mixed content) simply cannot
 * arise — the frontend is served by the dashboard itself under `/mempool-app/`
 * and its traffic is proxied to the loopback backend. The only realistic
 * failure is the app not being deployed, or the backend being down, in which
 * case the iframe never fires `onLoad`; we arm a timeout on mount and degrade
 * to an explanatory card with a direct link rather than leaving a blank frame.
 */
function NodeMempoolExplorer() {
  const [state, setState] = useState<"loading" | "ok" | "blocked">("loading");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    timer.current = setTimeout(() => {
      setState((s) => (s === "loading" ? "blocked" : s));
    }, 8000);
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  const openLink = (
    <a
      href={NODE_MEMPOOL_APP_URL}
      target="_blank"
      rel="noreferrer"
      className="bare"
      style={{ color: "var(--accent)", fontSize: "13px", textDecoration: "underline" }}
    >
      open in a new tab ↗
    </a>
  );

  return (
    <Card>
      <CardHeader
        title="Your node's mempool"
        subtitle="The full mempool.space explorer for this node's own mempool, served straight from the dashboard. Same-origin — no external host, no certificate, nothing to trust off-box."
      />
      <div className="flex items-center gap-3" style={{ marginBottom: "12px" }}>
        <Badge variant="info">mempool.space · this node</Badge>
        {openLink}
      </div>

      {state === "blocked" ? (
        <div
          className="space-y-2"
          style={{
            border: "1px solid var(--rule)",
            borderRadius: "4px",
            background: "var(--surface)",
            padding: "16px 18px",
          }}
        >
          <p style={{ color: "var(--fg)", fontSize: "14px" }}>
            The embedded explorer couldn&apos;t load here.
          </p>
          <p style={{ color: "var(--dim)", fontSize: "13px" }}>
            The dashboard couldn&apos;t serve <code>/mempool-app/</code>, or the node&apos;s
            mempool backend on <code>127.0.0.1:8999</code> isn&apos;t responding. Check that the
            mempool service is running on this node, then reload. You can also open it
            directly: {openLink}.
          </p>
        </div>
      ) : (
        <div
          style={{
            border: "1px solid var(--rule)",
            borderRadius: "4px",
            overflow: "hidden",
            background: "var(--surface)",
            height: "720px",
          }}
        >
          <iframe
            src={NODE_MEMPOOL_APP_URL}
            title="Your node's mempool (mempool.space)"
            loading="lazy"
            onLoad={() => {
              if (timer.current) clearTimeout(timer.current);
              setState("ok");
            }}
            style={{ width: "100%", height: "100%", border: 0, display: "block" }}
          />
        </div>
      )}

      <p style={{ color: "var(--fainter)", fontSize: "12px", marginTop: "12px" }}>
        Served same-origin from the dashboard at <code>/mempool-app/</code>, proxied to this
        node&apos;s own mempool backend. The lightweight RPC view and the Reaper strip
        breakdown are below.
      </p>
    </Card>
  );
}

// ─── live RPC stats row ─────────────────────────────────────────────────────

function LiveStats({ mempool }: { mempool?: BudsMempool }) {
  const fillPct =
    mempool?.bytes && mempool?.max_mempool
      ? formatPercent(mempool.bytes, mempool.max_mempool)
      : "—";
  const minFee = btcPerKvbToSatVb(mempool?.min_fee);

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <StatCard
        label="Transactions"
        value={formatCount(mempool?.total)}
        sublabel="in your mempool now"
        tooltip="getmempoolinfo.size — count of transactions your node currently holds in its mempool."
      />
      <StatCard
        label="Mempool size"
        value={formatBytes(mempool?.bytes)}
        sublabel={`${fillPct} of ${formatBytes(mempool?.max_mempool)} cap`}
        tooltip="Total virtual size of all mempool transactions vs your configured maxmempool."
      />
      <StatCard
        label="Memory used"
        value={formatBytes(mempool?.usage)}
        sublabel="RAM footprint"
        tooltip="getmempoolinfo.usage — estimated memory the mempool occupies."
      />
      <StatCard
        label="Min relay fee"
        value={formatFeeRate(minFee)}
        sublabel="floor to enter mempool"
        tooltip="getmempoolinfo.mempoolminfee — the current dynamic minimum fee rate to be accepted."
      />
    </div>
  );
}

// ─── Ghost filter view (what Reaper strips) — the node-local differentiator ──

function FilterView({
  reaper,
  reaperEnabled,
}: {
  reaper?: ReaperStats | null;
  reaperEnabled: boolean;
}) {
  return (
    <Card>
      <CardHeader
        title="Filtered vs unfiltered"
        subtitle="What your node keeps out of its blocks that a stock node would carry — the reason to look at the mempool from your own vantage point."
      />
      {!reaper ? (
        <p style={{ color: "var(--dim)", fontSize: "14px" }}>
          No filter counters yet. These populate from your template builder as it evaluates
          transactions; if Reaper has never run (or ghost-pool just restarted) there&apos;s nothing to
          show. Enable Reaper in{" "}
          <a
            href="/settings/capabilities"
            className="bare"
            style={{ color: "var(--dim)", textDecoration: "underline" }}
          >
            settings
          </a>
          .
        </p>
      ) : (
        <div className="space-y-5">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard
              label="Evaluated"
              value={formatCount(reaper.txs_evaluated)}
              sublabel="unfiltered — everything seen"
            />
            <StatCard
              label="Kept"
              value={formatCount(reaper.txs_accepted)}
              sublabel="filtered — passed into blocks"
            />
            <StatCard
              label="Stripped"
              value={formatCount(reaper.txs_reaped)}
              sublabel={`${formatPercent(reaper.txs_reaped, reaper.txs_evaluated)} reaped`}
            />
            <StatCard
              label="Dead weight removed"
              value={formatBytes(reaper.dead_bytes_total)}
              sublabel={`last reap ${formatRelative(reaper.last_reaped_unix)}`}
            />
          </div>

          {!reaperEnabled && (
            <div
              style={{
                padding: "10px 12px",
                background: "var(--surface)",
                border: "1px solid var(--rule)",
                borderRadius: "4px",
                fontSize: "13px",
                color: "var(--dim)",
              }}
            >
              Reaper is currently <strong style={{ color: "var(--fg)" }}>disabled</strong> — the counters
              below are cumulative history since the last ghost-pool restart. Turn it on to actually
              strip this weight from your blocks.
            </div>
          )}

          <div>
            <div
              style={{
                fontSize: "11px",
                fontFamily: "var(--font-mono)",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                color: "var(--dim)",
                marginBottom: "10px",
              }}
            >
              What got stripped, by type
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {REAPER_VECTORS.map((v) => {
                const hits = reaper.by_type[v.key] ?? 0;
                return (
                  <div
                    key={v.key}
                    className="flex items-baseline justify-between"
                    style={{
                      padding: "8px 12px",
                      border: "1px solid var(--rule)",
                      borderRadius: "4px",
                      background: "var(--bg)",
                    }}
                  >
                    <span style={{ color: "var(--fg)", fontSize: "13px" }}>{v.name}</span>
                    <span
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "13px",
                        color: hits > 0 ? "var(--accent)" : "var(--fainter)",
                      }}
                    >
                      {hits.toLocaleString()}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          <p style={{ color: "var(--fainter)", fontSize: "12px" }}>
            Counters are cumulative since the last ghost-pool restart, sourced from your template
            builder (<code>/api/v1/reaper/status</code>). &ldquo;Evaluated&rdquo; is the unfiltered
            baseline; &ldquo;kept&rdquo; is what survives your policy.
          </p>
        </div>
      )}
    </Card>
  );
}

// ─── mempool composition by BUDS class ──────────────────────────────────────

function Composition({ mempool }: { mempool?: BudsMempool }) {
  const byTier = mempool?.by_tier ?? { T0: 0, T1: 0, T2: 0, T3: 0 };
  const sampled = mempool?.sample_size ?? TIERS.reduce((s, t) => s + (byTier[t.key] ?? 0), 0);

  return (
    <Card>
      <CardHeader
        title="Mempool composition"
        subtitle="Transaction classes flowing through your node, by BUDS tier — what an address explorer never tells you."
      />
      <div className="space-y-3">
        <div style={{ display: "flex", height: "14px", borderRadius: "4px", overflow: "hidden", background: "var(--bg)" }}>
          {TIERS.map((t) => {
            const count = byTier[t.key] ?? 0;
            const pct = sampled ? (count / sampled) * 100 : 0;
            if (pct === 0) return null;
            return (
              <div
                key={t.key}
                title={`${t.name}: ${count} (${pct.toFixed(1)}%)`}
                style={{ width: `${pct}%`, background: t.color }}
              />
            );
          })}
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {TIERS.map((t) => {
            const count = byTier[t.key] ?? 0;
            const pct = sampled ? (count / sampled) * 100 : 0;
            return (
              <div
                key={t.key}
                style={{ padding: "10px 12px", border: "1px solid var(--rule)", borderRadius: "4px", background: "var(--bg)" }}
              >
                <div className="flex items-center gap-2" style={{ marginBottom: "4px" }}>
                  <span style={{ width: "10px", height: "10px", borderRadius: "2px", background: t.color, display: "inline-block" }} />
                  <span style={{ color: "var(--fg)", fontSize: "13px", fontWeight: 500 }}>{t.name}</span>
                </div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "18px", color: "var(--fg)" }}>
                  {pct.toFixed(0)}%
                </div>
                <div style={{ color: "var(--dim)", fontSize: "12px" }}>
                  {count.toLocaleString()} · {t.desc}
                </div>
              </div>
            );
          })}
        </div>
        <p style={{ color: "var(--fainter)", fontSize: "12px" }}>
          Based on a sample of {sampled.toLocaleString()} transactions (the node classifies up to 100
          per poll to stay light). Proportions are representative, not exact totals.
        </p>
      </div>
    </Card>
  );
}

// ─── fee-rate distribution (computed client-side from the tx sample) ─────────

function FeeDistribution({ mempool }: { mempool?: BudsMempool }) {
  const txs = mempool?.transactions ?? [];
  const rates = txs.map(feeRateSatVb).filter((r) => Number.isFinite(r));
  const counts = FEE_BUCKETS.map(
    (b) => rates.filter((r) => r >= b.min && r < b.max).length,
  );
  const maxCount = Math.max(1, ...counts);

  const sorted = [...rates].sort((a, b) => a - b);
  const median = sorted.length ? sorted[Math.floor(sorted.length / 2)] : null;

  if (txs.length === 0) {
    return (
      <Card>
        <CardHeader title="Fee-rate distribution" subtitle="sat/vB across sampled transactions" />
        <p style={{ color: "var(--dim)", fontSize: "14px" }}>
          No transactions in the sample to bucket right now.
        </p>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader
        title="Fee-rate distribution"
        subtitle={`sat/vB across ${txs.length} sampled transactions · median ${formatFeeRate(median)}`}
      />
      <div className="space-y-2">
        {FEE_BUCKETS.map((b, i) => {
          const c = counts[i];
          const w = (c / maxCount) * 100;
          return (
            <div key={b.label} className="flex items-center gap-3">
              <span
                style={{
                  width: "56px",
                  textAlign: "right",
                  fontFamily: "var(--font-mono)",
                  fontSize: "12px",
                  color: "var(--dim)",
                }}
              >
                {b.label}
              </span>
              <div style={{ flex: 1, height: "16px", background: "var(--bg)", borderRadius: "3px", overflow: "hidden" }}>
                <div
                  style={{
                    width: `${w}%`,
                    height: "100%",
                    background: "var(--accent)",
                    opacity: c > 0 ? 0.85 : 0,
                    transition: "width 0.3s",
                  }}
                />
              </div>
              <span
                style={{
                  width: "44px",
                  fontFamily: "var(--font-mono)",
                  fontSize: "12px",
                  color: c > 0 ? "var(--fg)" : "var(--fainter)",
                }}
              >
                {c}
              </span>
            </div>
          );
        })}
      </div>
      <p style={{ color: "var(--fainter)", fontSize: "12px", marginTop: "12px" }}>
        Buckets are computed in your browser from the transaction sample (fee ÷ vsize). The node does
        not expose a full server-side fee histogram, so this is a representative snapshot, not the
        whole mempool.
      </p>
    </Card>
  );
}

// ─── recent transactions from the sample ────────────────────────────────────

function RecentTxs({ mempool }: { mempool?: BudsMempool }) {
  const txs = [...(mempool?.transactions ?? [])]
    .sort((a, b) => b.time - a.time)
    .slice(0, 12);

  if (txs.length === 0) return null;

  const tierColor = (name: string) =>
    TIERS.find((t) => t.key === name)?.color ?? "var(--dim)";

  return (
    <Card collapsible defaultCollapsed>
      <CardHeader title="Recent transactions" subtitle="newest entries from the sample" />
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
          <thead>
            <tr style={{ color: "var(--dim)", textAlign: "left" }}>
              <th style={{ padding: "6px 8px", fontWeight: 400 }}>txid</th>
              <th style={{ padding: "6px 8px", fontWeight: 400 }}>class</th>
              <th style={{ padding: "6px 8px", fontWeight: 400, textAlign: "right" }}>vsize</th>
              <th style={{ padding: "6px 8px", fontWeight: 400, textAlign: "right" }}>fee rate</th>
            </tr>
          </thead>
          <tbody>
            {txs.map((tx) => (
              <tr key={tx.txid} style={{ borderTop: "1px solid var(--rule)" }}>
                <td style={{ padding: "6px 8px", fontFamily: "var(--font-mono)", color: "var(--fg)" }}>
                  {tx.txid.slice(0, 10)}…{tx.txid.slice(-6)}
                </td>
                <td style={{ padding: "6px 8px" }}>
                  <span style={{ color: tierColor(tx.tier_name), fontWeight: 500 }}>
                    {tx.tier_name}
                  </span>
                  <span style={{ color: "var(--dim)" }}> · {tx.classification_reason}</span>
                </td>
                <td style={{ padding: "6px 8px", textAlign: "right", fontFamily: "var(--font-mono)", color: "var(--dim)" }}>
                  {tx.vsize.toLocaleString()}
                </td>
                <td style={{ padding: "6px 8px", textAlign: "right", fontFamily: "var(--font-mono)", color: "var(--fg)" }}>
                  {feeRateSatVb(tx).toFixed(2)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

// ─── Advanced: heavy full explorer (electrs + mempool.space) ────────────────

function AdvancedExplorer({ status }: { status?: MempoolStatus | null }) {
  const running = status?.status === "running";
  const installedNotRunning = status?.status === "installed_not_running";
  const port = status?.port ?? 8999;
  const installCmd = status?.install_command ?? "sudo /opt/ghost/bin/ghost-mempool install";
  const minRam = status?.min_ram_gb ?? 4;
  const minDisk = status?.min_disk_gb ?? 50;

  return (
    <Card collapsible defaultCollapsed={!running}>
      <CardHeader
        title="Advanced: full block explorer"
        subtitle="Optional mempool.space + electrs stack for address search and a familiar UI. Heavy — needs ≥50 GB of disk and an index. Most operators don't need this; the view above already covers day-to-day mempool watching."
      />

      {running ? (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <Badge variant="success">running on :{port}</Badge>
            <a
              href={`http://localhost:${port}/`}
              target="_blank"
              rel="noreferrer"
              className="bare"
              style={{ color: "var(--accent)", fontSize: "13px", textDecoration: "underline" }}
            >
              open full explorer in a new tab ↗
            </a>
          </div>
          <div
            style={{
              border: "1px solid var(--rule)",
              borderRadius: "4px",
              overflow: "hidden",
              background: "var(--surface)",
              height: "640px",
            }}
          >
            <iframe
              src={`http://localhost:${port}/`}
              title="mempool.space full explorer"
              style={{ width: "100%", height: "100%", border: 0, display: "block" }}
            />
          </div>
        </div>
      ) : installedNotRunning ? (
        <div className="space-y-4">
          <Badge variant="warning">installed · stopped</Badge>
          <p style={{ color: "var(--dim)", fontSize: "14px" }}>
            The stack is installed but nothing is listening on <code>:{port}</code>. Bring it back up:
          </p>
          <CodeBlock command="sudo systemctl start ghost-mempool" />
          <p style={{ color: "var(--fainter)", fontSize: "13px" }}>
            Or remove it entirely with <code>{status?.uninstall_command ?? "sudo /opt/ghost/bin/ghost-mempool uninstall"}</code>.
          </p>
        </div>
      ) : (
        <div className="space-y-5">
          <Badge variant="info">not installed</Badge>
          <div>
            <h4 style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 500, marginBottom: "6px" }}>
              What gets installed
            </h4>
            <ul
              style={{
                color: "var(--dim)",
                fontSize: "13px",
                lineHeight: "1.7",
                paddingLeft: "20px",
                listStyle: "disc",
              }}
            >
              <li><strong style={{ color: "var(--fg)" }}>electrs</strong> — Bitcoin address-index server (this is the ≥{minDisk} GB)</li>
              <li><strong style={{ color: "var(--fg)" }}>mempool-backend</strong> + <strong style={{ color: "var(--fg)" }}>frontend</strong> — the mempool.space API and UI</li>
              <li>Binds <code>localhost:{port}</code> only — no public exposure; reads your local <code>ghostd</code> RPC</li>
            </ul>
          </div>
          <div className="grid grid-cols-2 gap-6" style={{ maxWidth: "320px" }}>
            <Stat label="free RAM" value={`≥${minRam} GB`} />
            <Stat label="free disk" value={`≥${minDisk} GB`} />
          </div>
          <div>
            <h4 style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 500, marginBottom: "6px" }}>
              One-line install
            </h4>
            <CodeBlock command={installCmd} />
            <p style={{ color: "var(--fainter)", fontSize: "12px", marginTop: "8px" }}>
              First run indexes the chain (5–15 min). This page auto-refreshes — once the stack is up
              the embedded explorer appears here.
            </p>
          </div>
          {!status && (
            <p style={{ color: "var(--fainter)", fontSize: "12px", borderTop: "1px solid var(--rule)", paddingTop: "10px" }}>
              <em>Note:</em> couldn&apos;t reach <code>/api/v1/system/mempool</code>; showing the install
              panel as the safe default.
            </p>
          )}
        </div>
      )}
    </Card>
  );
}

// ─── small shared helpers ───────────────────────────────────────────────────

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
      <div style={{ fontSize: "20px", fontWeight: 500, color: "var(--fg)", fontFamily: "var(--font-mono)" }}>
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
