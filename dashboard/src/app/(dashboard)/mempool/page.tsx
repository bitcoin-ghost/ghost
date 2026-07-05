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
            <FilterView mempool={mempool} reaperEnabled={reaperEnabled} />
          </SectionErrorBoundary>
          <SectionErrorBoundary section="Mempool composition">
            <Composition mempool={mempool} />
          </SectionErrorBoundary>
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
      className="bare"
      style={{ color: "var(--accent)", fontSize: "13px", textDecoration: "underline" }}
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

// ─── Ghost filter view — LIVE clean-vs-abusive from the current mempool ──────

// Byte-weight groupings for the current-mempool "dead weight" view. This panel
// deliberately reads the mempool by VIRTUAL SIZE rather than transaction count
// (which the "Mempool composition" section below already covers per tier): the
// point of a spam-aware policy is that abusive heavy-data transactions are few
// in number but eat a hugely disproportionate share of block space.
const FILTER_GROUPS = [
  { key: "financial", name: "Financial", color: "#3fb950", desc: "T0 + T1 · standard & extended payments" },
  { key: "data", name: "Data-anchoring", color: "#d29922", desc: "T2 · small OP_RETURN, Lightning, timestamps" },
  { key: "abusive", name: "Abusive heavy-data", color: "#f85149", desc: "T3 · inscriptions, runes, large witness — what your policy targets" },
] as const;

function FilterView({
  mempool,
  reaperEnabled,
}: {
  mempool?: BudsMempool;
  reaperEnabled: boolean;
}) {
  const txs = mempool?.transactions ?? [];
  const total = mempool?.total ?? 0;
  const totalBytes = mempool?.bytes ?? 0;

  // Classify the LIVE sample by BUDS tier, tracking both transaction count and
  // virtual size so we can express the abusive share two honest ways: how many
  // of the mempool's transactions carry it, and how much of its weight it eats.
  const countByTier = { T0: 0, T1: 0, T2: 0, T3: 0 };
  const bytesByTier = { T0: 0, T1: 0, T2: 0, T3: 0 };
  for (const tx of txs) {
    const key = tx.tier_name as keyof typeof countByTier;
    if (key in countByTier) {
      countByTier[key] += 1;
      bytesByTier[key] += tx.vsize;
    }
  }
  const sampleCount = txs.length;
  const sampleBytes = bytesByTier.T0 + bytesByTier.T1 + bytesByTier.T2 + bytesByTier.T3;

  if (sampleCount === 0) {
    return (
      <Card>
        <CardHeader
          title="Filtered vs unfiltered"
          subtitle="A live clean-vs-abusive read of the transactions your node is holding right now."
        />
        <p style={{ color: "var(--dim)", fontSize: "14px" }}>
          No transactions in the current sample to classify. This populates from your node&apos;s live
          mempool; if it&apos;s empty there&apos;s nothing to weigh.
        </p>
      </Card>
    );
  }

  // Sample fractions, extrapolated to the full mempool. These are estimates in
  // exactly the same sense as the composition bar below — the node classifies a
  // bounded sample per poll to stay light — so we surface them as "~" figures.
  const abusiveCountFrac = countByTier.T3 / sampleCount;
  const abusiveByteFrac = sampleBytes ? bytesByTier.T3 / sampleBytes : 0;
  const cleanCountFrac = (countByTier.T0 + countByTier.T1) / sampleCount;
  const dataCountFrac = countByTier.T2 / sampleCount;

  const estAbusiveTxs = Math.round(total * abusiveCountFrac);
  const estDeadWeight = Math.round(totalBytes * abusiveByteFrac);
  const estCleanTxs = Math.round(total * cleanCountFrac);
  const estDataTxs = Math.round(total * dataCountFrac);

  const groupBytes: Record<(typeof FILTER_GROUPS)[number]["key"], number> = {
    financial: bytesByTier.T0 + bytesByTier.T1,
    data: bytesByTier.T2,
    abusive: bytesByTier.T3,
  };

  return (
    <Card>
      <CardHeader
        title="Filtered vs unfiltered"
        subtitle="Of the transactions your node is holding right now, how many carry the abusive patterns your policy targets — read live from the current mempool by weight, not cumulative history."
      />
      <div className="space-y-5">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            label="Abusive txs"
            value={`~${formatCount(estAbusiveTxs)}`}
            sublabel={`${formatPercent(countByTier.T3, sampleCount)} of the mempool (T3)`}
            tooltip="Estimated count of T3 heavy-data transactions (inscriptions, runes, large witness) in your mempool right now, extrapolated from the live BUDS sample."
          />
          <StatCard
            label="Dead weight"
            value={`~${formatBytes(estDeadWeight)}`}
            sublabel={`${formatPercent(bytesByTier.T3, sampleBytes)} of mempool bytes`}
            tooltip="Share of your mempool's virtual size consumed by abusive T3 transactions. They are a small fraction of the transaction count but dominate the byte weight — this is the space a spam-aware block policy reclaims."
          />
          <StatCard
            label="Clean payments"
            value={`~${formatCount(estCleanTxs)}`}
            sublabel="standard & extended financial (T0 + T1)"
            tooltip="Estimated count of ordinary financial transactions (single-sig, multisig, timelocks) currently in your mempool."
          />
          <StatCard
            label="Data-anchoring"
            value={`~${formatCount(estDataTxs)}`}
            sublabel="small OP_RETURN · Lightning / timestamps (T2)"
            tooltip="Estimated count of small data-commitment transactions — legitimate carriers your policy does not target."
          />
        </div>

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
            Where your mempool&apos;s weight is going
          </div>
          <div
            style={{
              display: "flex",
              height: "14px",
              borderRadius: "4px",
              overflow: "hidden",
              background: "var(--bg)",
            }}
          >
            {FILTER_GROUPS.map((g) => {
              const b = groupBytes[g.key];
              const pct = sampleBytes ? (b / sampleBytes) * 100 : 0;
              if (pct === 0) return null;
              return (
                <div
                  key={g.key}
                  title={`${g.name}: ${pct.toFixed(1)}% of mempool weight`}
                  style={{ width: `${pct}%`, background: g.color }}
                />
              );
            })}
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2" style={{ marginTop: "10px" }}>
            {FILTER_GROUPS.map((g) => {
              const b = groupBytes[g.key];
              const pct = sampleBytes ? (b / sampleBytes) * 100 : 0;
              return (
                <div
                  key={g.key}
                  style={{
                    padding: "8px 12px",
                    border: "1px solid var(--rule)",
                    borderRadius: "4px",
                    background: "var(--bg)",
                  }}
                >
                  <div className="flex items-center gap-2" style={{ marginBottom: "4px" }}>
                    <span
                      style={{
                        width: "10px",
                        height: "10px",
                        borderRadius: "2px",
                        background: g.color,
                        display: "inline-block",
                      }}
                    />
                    <span style={{ color: "var(--fg)", fontSize: "13px", fontWeight: 500 }}>
                      {g.name}
                    </span>
                    <span
                      style={{
                        marginLeft: "auto",
                        fontFamily: "var(--font-mono)",
                        fontSize: "13px",
                        color: "var(--fg)",
                      }}
                    >
                      {pct.toFixed(0)}%
                    </span>
                  </div>
                  <div style={{ color: "var(--dim)", fontSize: "12px" }}>{g.desc}</div>
                </div>
              );
            })}
          </div>
        </div>

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
          {reaperEnabled ? (
            <>
              Reaper is <strong style={{ color: "var(--fg)" }}>enabled</strong> — this abusive weight is
              stripped from the blocks your node builds, so the space above is reclaimed for fee-paying
              transactions.
            </>
          ) : (
            <>
              Reaper is <strong style={{ color: "var(--fg)" }}>disabled</strong> — this abusive weight is
              currently eligible for the blocks your node builds. Enable it in{" "}
              <a
                href="/settings/capabilities"
                className="bare"
                style={{ color: "var(--fg)", textDecoration: "underline" }}
              >
                settings
              </a>{" "}
              to strip it.
            </>
          )}
        </div>

        {/*
          NOTE: This panel shows what is measurable RIGHT NOW — the abusive share
          already sitting in your node's mempool, classified live via BUDS. It is
          deliberately NOT a "what a stock node would additionally carry" baseline:
          that number needs ghostd's mempool-reaper reject counts (transactions its
          admission policy dropped before they ever reached the mempool), which the
          node does not expose live. Surfacing those real reject counts is a
          separate backend follow-up (a new ghostd RPC / node-API endpoint); until
          it exists we do not fabricate an unfiltered baseline here.
        */}
        <p style={{ color: "var(--fainter)", fontSize: "12px" }}>
          Estimated from a live sample of {sampleCount.toLocaleString()} transactions (the node
          classifies a bounded set per poll to stay light) extrapolated across the {formatCount(total)}{" "}
          transactions in your mempool — representative proportions, not exact totals. This is the
          abusive weight your node is holding <em>now</em>; a true &ldquo;what a stock node would also
          carry&rdquo; baseline needs ghostd&apos;s mempool-reaper reject counts, which aren&apos;t
          exposed live yet.
        </p>
      </div>
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
        subtitle="The per-tier count breakdown behind the summary above — every BUDS class flowing through your node, by share of transactions."
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

