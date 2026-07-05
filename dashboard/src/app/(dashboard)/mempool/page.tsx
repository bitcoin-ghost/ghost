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
import { type ReaperStats, type ReaperByType } from "@/lib/api/reaper";
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
          <SectionErrorBoundary section="Reaper impact">
            <ReaperImpact
              mempool={mempool}
              reaperStats={reaperStats}
              reaperEnabled={reaperEnabled}
            />
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

// ─── Reaper impact — what the pool reaper keeps out of this node's blocks ────

// Human labels for the reaper's per-DeadCodeType counters, so the "most-caught
// pattern" tile reads in plain language instead of a raw enum key.
const VECTOR_LABELS: Record<keyof ReaperByType, string> = {
  inscription_envelope: "Inscription envelopes",
  drop_stuffing: "Drop stuffing",
  unreachable_code: "Unreachable code",
  fake_pubkey: "Fake pubkeys",
  fake_pubkey_curve_point: "Fake-pubkey curve points",
  annex_present: "Annex bloat",
  oversized_op_return: "Oversized OP_RETURN",
  dust_flood: "Dust-flood spam",
  excess_witness_data: "Excess witness data",
  excess_stack_items: "Excess stack items",
  legacy_scriptsig_data: "Legacy scriptSig data",
};

function formatRelative(unixSecs: number | null): string {
  if (!unixSecs) return "never";
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - unixSecs);
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

// Largest single detection vector across the cumulative counters. The reaper
// increments one counter per matched pattern and a tx can match several, so we
// surface the single most-frequent vector as "what your reaper catches most".
function topVector(byType: ReaperByType): { label: string; count: number } | null {
  let best: { label: string; count: number } | null = null;
  for (const [key, count] of Object.entries(byType) as [keyof ReaperByType, number][]) {
    if (count > 0 && (!best || count > best.count)) {
      best = { label: VECTOR_LABELS[key], count };
    }
  }
  return best;
}

/**
 * "Reaper impact" — leads with the pool block-template reaper's real, countable
 * win (cumulative txs reaped + dead weight stripped from this node's blocks,
 * straight from `/api/v1/reaper/status`), then turns the abusive share still
 * sitting in the live mempool into an actionable policy-scope prompt rather than
 * an alarming "the reaper failed" number.
 *
 * The two reapers this distinguishes:
 *  - ghostd MEMPOOL reaper (admission-time reject vectors) keeps spam out of the
 *    mempool, but ghostd exposes NO reject counters, so its work isn't counted here.
 *  - pool TEMPLATE-BUILDER reaper (the +2 capability) strips spam from each block
 *    it assembles and DOES count — that's what these cumulative tiles report.
 */
function ReaperImpact({
  mempool,
  reaperStats,
  reaperEnabled,
}: {
  mempool?: BudsMempool;
  reaperStats?: ReaperStats | null;
  reaperEnabled: boolean;
}) {
  // Live mempool tier mix (sampled). We read composition by COUNT here, which is
  // the honest, un-extrapolated figure — the same sample the composition panel
  // below draws — rather than extrapolating sample bytes across the whole
  // mempool (which previously overstated the "dead weight" share).
  const byTier = mempool?.by_tier ?? { T0: 0, T1: 0, T2: 0, T3: 0 };
  const sampled =
    mempool?.sample_size ?? byTier.T0 + byTier.T1 + byTier.T2 + byTier.T3;
  const cleanShare = sampled ? (byTier.T0 + byTier.T1) / sampled : 0;
  const abusiveShare = sampled ? byTier.T3 / sampled : 0;

  const top = reaperStats ? topVector(reaperStats.by_type) : null;

  return (
    <Card>
      <CardHeader
        title="Reaper impact"
        subtitle="What your pool's block-template reaper has kept out of the blocks this node builds — cumulative, counted, not sampled."
      />
      <div className="space-y-5">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            label="Kept out of your blocks"
            value={reaperStats ? reaperStats.txs_reaped.toLocaleString() : "—"}
            sublabel={
              reaperStats
                ? `spam txs stripped · last ${formatRelative(reaperStats.last_reaped_unix)}`
                : "no counters yet"
            }
            tooltip="Cumulative transactions the pool template-builder reaper removed from the blocks this node assembled, since the last ghost-pool restart (/api/v1/reaper/status → txs_reaped)."
          />
          <StatCard
            label="Dead weight stripped"
            value={reaperStats ? formatBytes(reaperStats.dead_bytes_total) : "—"}
            sublabel="block space returned to fee-paying txs"
            tooltip="Cumulative virtual bytes of dead weight the reaper stripped from your block templates (/api/v1/reaper/status → dead_bytes_total). That space is reclaimed for real, fee-paying transactions."
          />
          {/*
            BACKEND FOLLOW-UP: this tile is wired for a per-block reaped count.
            template.rs builds `FilterStats.reaped` (bins/ghost-pool/src/template.rs,
            the `reaped` field ~line 1994) on every template, but that per-block
            figure is only logged — it is NOT exposed via any API. Surface it (e.g.
            add `last_block_reaped` to /api/v1/reaper/status, or a per-template
            endpoint) and swap the "—" below for that value. Until then we show no
            fabricated number.
          */}
          <StatCard
            label="Reaped this block"
            value="—"
            sublabel="per-block counter — pending node endpoint"
            tooltip="The template builder already computes a per-block reaped count (template.rs FilterStats.reaped) but does not expose it via the API yet. This tile is wired and will populate once ghost-pool surfaces the per-template figure; until then it shows no fabricated number."
          />
          <StatCard
            label="Most-caught pattern"
            value={top ? top.label : "—"}
            sublabel={top ? `${top.count.toLocaleString()} flagged` : "no counters yet"}
            tooltip="The single most-frequent dead-code pattern across the reaper's cumulative counters (/api/v1/reaper/status → by_type). A transaction can match more than one vector."
          />
        </div>

        <div
          style={{
            padding: "10px 12px",
            background: reaperEnabled ? "var(--accent-weak)" : "var(--surface)",
            border: `1px solid ${reaperEnabled ? "var(--accent)" : "var(--rule)"}`,
            borderRadius: "4px",
            fontSize: "13px",
            color: reaperEnabled ? "var(--fg)" : "var(--dim)",
          }}
        >
          {reaperEnabled ? (
            <>
              Reaper is <strong style={{ color: "var(--accent)" }}>enabled</strong> — every block this
              node builds is stripped of dead weight before it&apos;s mined, so the totals above keep
              climbing. Full per-vector detail is on the{" "}
              <a href="/reaper" className="bare" style={{ color: "var(--accent)", textDecoration: "underline" }}>
                Reaper page
              </a>
              .
            </>
          ) : (
            <>
              Reaper is <strong style={{ color: "var(--fg)" }}>disabled</strong> — this node currently
              builds blocks without stripping dead weight. Turn it on from the{" "}
              <a href="/reaper" className="bare" style={{ color: "var(--fg)", textDecoration: "underline" }}>
                Reaper page
              </a>{" "}
              to start protecting your blocks.
            </>
          )}
        </div>

        {/* Reassuring + honest read of the current mempool, and — crucially — the
            actionable reframing of "abusive txs are STILL here". They are not a
            reaper failure: the pool reaper strips its reject vectors from BLOCKS,
            while BUDS "T3 abusive" is a broader taxonomy (large witnesses,
            OP_RETURN ≤82 bytes) that the current reject RULES deliberately admit.
            So T3-still-present = "carries patterns your rules don't yet cover" —
            a policy-scope knob the operator can tighten, not a bug. */}
        <div
          style={{
            padding: "12px 14px",
            background: "var(--bg)",
            border: "1px solid var(--rule)",
            borderRadius: "4px",
          }}
        >
          <div style={{ color: "var(--fg)", fontSize: "13px", lineHeight: "1.6" }}>
            In your mempool right now, most of what your node holds is clean money:{" "}
            <strong style={{ color: "#3fb950" }}>~{Math.round(cleanShare * 100)}%</strong> of sampled
            transactions are ordinary payments (T0 + T1).
          </div>
          {byTier.T3 > 0 && (
            <div style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.6", marginTop: "8px" }}>
              About <strong style={{ color: "var(--fg)" }}>~{Math.round(abusiveShare * 100)}%</strong>{" "}
              still carry abusive patterns (T3). That is not a reaper miss — these use large witnesses or
              small OP_RETURN payloads that your current reject rules admit into the mempool. To keep them
              out of the blocks you build too, tighten your reject vectors on the{" "}
              <a href="/reaper" className="bare" style={{ color: "var(--fg)", textDecoration: "underline" }}>
                Reaper page
              </a>
              .
            </div>
          )}
        </div>

        <p style={{ color: "var(--fainter)", fontSize: "12px" }}>
          The tiles above are exact cumulative counts from the pool&apos;s block-template reaper
          (<code>/api/v1/reaper/status</code>), reset only when ghost-pool restarts. The mempool mix is
          read from a live sample of {sampled.toLocaleString()} transactions, so its percentages are
          representative, not exact totals. Note the ghostd <em>mempool</em> reaper (admission-time) keeps
          extra spam out before it ever reaches this view, but ghostd exposes no reject counters, so that
          share isn&apos;t counted here.
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
        subtitle="The per-tier breakdown behind the reaper impact above — every BUDS class your node is holding right now, by share of transactions."
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

