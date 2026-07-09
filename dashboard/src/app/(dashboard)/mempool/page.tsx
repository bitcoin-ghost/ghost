"use client";

import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { StatCard } from "@/components/ui/StatCard";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useConfig } from "@/hooks/queries/useConfigQueries";
import { useReaperStatus } from "@/hooks/queries";
import { type ReaperStats } from "@/lib/api/reaper";
import { fetchApi } from "@/lib/api/client";

/**
 * Per-node mempool view — LIGHTWEIGHT, no heavy indexer.
 *
 * Every panel is sourced from ghostd's RPC via the node API
 * (`/api/v1/buds/mempool` = getmempoolinfo + getrawmempool + live BUDS tier
 * classification). This needs NO electrs index and NO 50 GB of disk. On top of
 * the plain RPC stats it derives the Ghost-specific "clean vs abusive" view of
 * the current mempool — the node-local vantage point a stock explorer can't
 * give — plus the same-origin mempool.space embed of this node's own mempool.
 *
 * The "Reaper impact" panel is the exception: it reads the pool's cumulative
 * block-template reaper counters from `/api/v1/reaper/status` (real reaped-tx
 * and dead-byte totals), so it reports what the reaper has actually kept out of
 * this node's blocks rather than estimating from the live mempool sample.
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

// ─── fetchers ───────────────────────────────────────────────────────────────

async function fetchBudsMempool(): Promise<BudsMempool> {
  return fetchApi<BudsMempool>("/api/v1/buds/mempool");
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

  const { data: reaperStats } = useReaperStatus();

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
            <p className="t-title" style={{ color: "var(--fg)" }}>
              Couldn&apos;t read the mempool from <code>ghostd</code> RPC.
            </p>
            <p className="t-label" style={{ color: "var(--dim)" }}>
              {mempool?.message ??
                "The node API returned an error for /api/v1/buds/mempool. Check that ghostd is running and RPC credentials are configured in pool.toml."}
            </p>
          </div>
        </Card>
      ) : (
        <>
          <LiveStats mempool={mempool} reaperStats={reaperStats} reaperEnabled={reaperEnabled} />
          <SectionErrorBoundary section="Fee distribution">
            <FeeDistribution mempool={mempool} />
          </SectionErrorBoundary>
        </>
      )}
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

  // mempool.space's UI has a wide min-width and won't shrink its own content to
  // fit a narrower container, so we render it at a fixed design width and CSS
  // scale-to-fit the actual container width. A ResizeObserver keeps it dynamic
  // as the window / sidebar changes.
  const wrapRef = useRef<HTMLDivElement>(null);
  const [scale, setScale] = useState(1);
  const DESIGN_WIDTH = 1300; // lower = more zoomed-in; the blocks row may overflow (fine — the tx/goggles content below matters more)
  const VIEW_HEIGHT = 1050; // taller so the transactions / goggles / stats below the block row are visible

  useEffect(() => {
    timer.current = setTimeout(() => {
      setState((s) => (s === "loading" ? "blocked" : s));
    }, 8000);
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const update = () => {
      const w = el.clientWidth;
      if (w > 0) setScale(w / DESIGN_WIDTH);
    };
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const openLink = (
    <a
      href={NODE_MEMPOOL_APP_URL}
      target="_blank"
      rel="noreferrer"
      className="bare t-label"
      style={{ color: "var(--accent)", textDecoration: "underline" }}
    >
      open in a new tab ↗
    </a>
  );

  return (
    <Card>
      <div className="flex items-center gap-3" style={{ marginBottom: "12px" }}>
        <Badge variant="info">mempool.space · this node</Badge>
        {openLink}
      </div>

      <p className="t-label" style={{ color: "var(--dim)", marginBottom: "12px", lineHeight: 1.6 }}>
        Your node&apos;s own mempool — which now equals the set your blocks build from. Filtered classes
        never enter it, so this one view is your block builder: what you see here is exactly what your
        blocks mine.
      </p>

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
          <p className="t-title" style={{ color: "var(--fg)" }}>
            The embedded explorer couldn&apos;t load here.
          </p>
          <p className="t-label" style={{ color: "var(--dim)" }}>
            The dashboard couldn&apos;t serve <code>/mempool-app/</code>, or the node&apos;s
            mempool backend on <code>127.0.0.1:8999</code> isn&apos;t responding. Check that the
            mempool service is running on this node, then reload. You can also open it
            directly: {openLink}.
          </p>
        </div>
      ) : (
        <div
          ref={wrapRef}
          style={{
            border: "1px solid var(--rule)",
            borderRadius: "4px",
            overflow: "hidden",
            background: "var(--surface)",
            height: `${VIEW_HEIGHT}px`,
            width: "100%",
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
            style={{
              width: `${DESIGN_WIDTH}px`,
              height: `${VIEW_HEIGHT / scale}px`,
              border: 0,
              display: "block",
              transform: `scale(${scale})`,
              transformOrigin: "top left",
            }}
          />
        </div>
      )}

      <p className="t-caption" style={{ color: "var(--fainter)", marginTop: "12px" }}>
        Served same-origin from the dashboard at <code>/mempool-app/</code>, proxied to this
        node&apos;s own mempool backend. The lightweight RPC view and the Reaper strip
        breakdown are below.
      </p>
    </Card>
  );
}

// ─── live RPC stats row ─────────────────────────────────────────────────────

function LiveStats({
  mempool,
  reaperStats,
  reaperEnabled,
}: {
  mempool?: BudsMempool;
  reaperStats?: ReaperStats | null;
  reaperEnabled: boolean;
}) {
  // maxmempool caps memory USAGE, not the summed vsize (`bytes`), so the "how
  // full" ratio must be usage/maxmempool — matching mempool.space's Memory
  // Usage / 300 MB. Dividing bytes by maxmempool understated it ~4x.
  const fillPct =
    mempool?.usage && mempool?.max_mempool
      ? formatPercent(mempool.usage, mempool.max_mempool)
      : "—";
  const minFee = btcPerKvbToSatVb(mempool?.min_fee);

  // The "Reaped this block" tile only appears when this node runs the reaper
  // (opt-in +2 capability). It reports the block currently being built — the
  // most recent template snapshot — not cumulative history; lifetime totals
  // live on the Reaper page.
  const showReaped = reaperEnabled;
  const hasBlock = !!reaperStats && reaperStats.last_block_unix != null;
  // Five tiles need a wider track; four keep the original layout.
  const gridCols = showReaped
    ? "grid-cols-2 md:grid-cols-3 xl:grid-cols-5"
    : "grid-cols-2 md:grid-cols-4";

  return (
    <div className={`grid ${gridCols} gap-4`}>
      <StatCard
        label="Transactions"
        value={formatCount(mempool?.total)}
        sublabel="in your mempool now"
        tooltip="getmempoolinfo.size — count of transactions your node currently holds in its mempool."
      />
      {showReaped && (
        <StatCard
          label="Reaped this block"
          value={hasBlock ? reaperStats!.last_block_reaped.toLocaleString() : "—"}
          sublabel={
            hasBlock
              ? `${formatBytes(reaperStats!.last_block_dead_bytes)} dead weight · ${formatRelative(reaperStats!.last_block_unix)}`
              : "no block built yet"
          }
          tooltip="Transactions the pool template-builder reaper dropped from the block currently being built (dead code detected). A per-block snapshot, not cumulative — lifetime totals and per-vector detail are on the Reaper page."
        />
      )}
      <StatCard
        label="Mempool size"
        value={formatBytes(mempool?.bytes)}
        sublabel="total virtual size"
        tooltip="getmempoolinfo.bytes — the summed virtual size (vB) of every transaction in your mempool."
      />
      <StatCard
        label="Memory used"
        value={formatBytes(mempool?.usage)}
        sublabel={`${fillPct} of ${formatBytes(mempool?.max_mempool)} cap`}
        tooltip="getmempoolinfo.usage vs maxmempool — how full your mempool is by memory, the limit ghostd actually enforces (matches mempool.space's Memory Usage)."
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

// ─── reaper helpers (feed the "Reaped this block" stat tile) ─────────────────

function formatRelative(unixSecs: number | null): string {
  if (!unixSecs) return "never";
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - unixSecs);
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
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
        <p className="t-body" style={{ color: "var(--dim)" }}>
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
                className="t-caption"
                style={{
                  width: "56px",
                  textAlign: "right",
                  fontFamily: "var(--font-mono)",
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
                className="t-caption"
                style={{
                  width: "44px",
                  fontFamily: "var(--font-mono)",
                  color: c > 0 ? "var(--fg)" : "var(--fainter)",
                }}
              >
                {c}
              </span>
            </div>
          );
        })}
      </div>
      <p className="t-caption" style={{ color: "var(--fainter)", marginTop: "12px" }}>
        Buckets are computed in your browser from the transaction sample (fee ÷ vsize). The node does
        not expose a full server-side fee histogram, so this is a representative snapshot, not the
        whole mempool.
      </p>
    </Card>
  );
}

