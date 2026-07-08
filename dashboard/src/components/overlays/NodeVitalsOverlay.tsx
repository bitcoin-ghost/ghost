/**
 * Overlay: Node Vitals — Instrument Cluster
 *
 * CONCEPT — the Home screen reimagined as a premium car instrument cluster.
 * The 5-4-3-2-1 capability ring stays at the centre as the "speedometer",
 * wrapping a mechanical rolling-digit ODOMETER of the block height. It is
 * flanked by two tachometer dials: LEFT = live mempool (blue), RIGHT = this
 * node's mining hashrate (amber → red). Below sit the car-dash extras — a bank
 * of warning-light tell-tales for the CORE / POOL / PAY watchdog services, three
 * fuel/temp gauges for CPU / memory / disk, and a chain-sync bar that runs a
 * "warm-up" sweep while the node is still syncing. A genuine new block still
 * fires the heartbeat pulse and re-beats the odometer.
 *
 * The scene keeps its ambient DEPTH: a full-bleed background canvas paints a
 * soft radial vignette focused on the ring, two drifting nebula washes and a
 * capped speck field, and a second canvas behind the ring emanates the
 * heartbeat pulses so the board always reads as alive, never frozen.
 *
 * IMPLEMENTER NOTES:
 *  - Keep the `export function NodeVitalsOverlay({ active }: OverlayProps)`
 *    signature exactly — the Home page renders it directly.
 *  - Honour `active`: run rAF loops and polling ONLY while `active === true`.
 *  - CSP-safe only: <canvas> or inline SVG / DOM+CSS. No external assets, no new
 *    deps. Theme-aware via the design-token CSS vars. Real data only — every
 *    dial and gauge rests at zero / shows dashes when its data is absent.
 */
'use client';

import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNodeStatus, useShares } from '@/hooks/queries/useNodeQueries';
import { useMiningStatus, useBestHash } from '@/hooks/queries/useMiningQueries';
import { useWatchdogStatus } from '@/hooks/queries/useWatchdogQueries';
import { useResourceStatus } from '@/hooks/queries/useResourceQueries';
import { fetchApi } from '@/lib/api/client';
import { formatHashrate, formatDuration } from '@/components/ui/DataTable';
import type { SharesInfo, WatchdogStatus } from '@/types/api';

/**
 * The scene honours `active`: it runs its rAF animation loops and lets its data
 * hooks poll ONLY while `active === true`. The Home page mounts it permanently
 * with `active` fixed on (there is no carousel), so the loops always run — the
 * prop is retained so the animation contract stays explicit and the scene could
 * be paused again if it were ever placed off-screen.
 */
interface OverlayProps {
  active: boolean;
}

// Bitcoin orange — identical in both themes (--accent), so the canvas can use
// it directly without reading it back out of the DOM every frame.
const ACCENT_RGB = '247, 147, 26';
// The rotating highlight sweep is green so it stays distinct from the orange
// capability arcs — obvious even now that the glow band is thin.
const SWEEP_RGB = '92, 199, 126';
// A cool tint blended into one nebula wash so the depth field isn't monochrome.
const COOL = { r: 70, g: 110, b: 190 };
// Fixed rgba anchors for canvas / glow use (the CSS var equivalents shift a
// little per theme, but a constant glow tint reads fine in both).
const BLUE_RGB = '90, 150, 210';
// The mining needle is a hot orange-red — distinct from both the amber arc and
// the pure-red redline, so it never reads as a full alarm-red face.
const MINING_NEEDLE_RGB = '255, 92, 48';

// The 1-2-3-4-5 capability ring. Array order is the on-ring order: starting at
// the top (12 o'clock) and going CLOCKWISE the bonus ASCENDS — Elder (+1) first,
// then Reaper (+2), Mining (+3), GhostPay (+4), Archive (+5). Both the arcs and
// the outer labels iterate this array by index, so this order drives both.
// `key` indexes SharesInfo's boolean capability flags.
const CAPS: { key: keyof SharesInfo; label: string; bonus: number }[] = [
  { key: 'elder', label: 'ELDER', bonus: 1 },
  { key: 'reaper', label: 'REAPER', bonus: 2 },
  { key: 'public_mining', label: 'MINING', bonus: 3 },
  { key: 'ghost_pay', label: 'GHOSTPAY', bonus: 4 },
  { key: 'archive_mode', label: 'ARCHIVE', bonus: 5 },
];

// Ring geometry (SVG userspace units; viewBox is 0 0 400 400).
const CENTER = 200;
const RING_R = 150;
const RING_STROKE = 13;
const SEG_SLOT = 100 / CAPS.length; // pathLength=100 → 20 units per capability
const SEG_GAP = 3; // units of gap between arcs
const SEG_VISIBLE = SEG_SLOT - SEG_GAP;
// Labels curve along invisible arcs concentric with the ring. The name rides an
// outer arc, the "+bonus" an inner arc; both radii are chosen so that even where
// a bottom-half label's glyphs extend inward (toward the ring), they still clear
// the ring's outer edge (RING_R + RING_STROKE/2 = 156.5) with comfortable margin.
const LABEL_NAME_R = RING_R + 34; // 184
const LABEL_BONUS_R = RING_R + 18; // 168

// Build an SVG arc `d` for a label baseline: a minor arc (≤180°) of radius `r`
// centred on the ring angle `thetaDeg` (clockwise from 12 o'clock), spanning
// `span` degrees. On the TOP half the arc runs clockwise (sweep=1) so text reads
// upright with glyphs pointing outward; on the BOTTOM half it runs
// counter-clockwise (sweep=0) so text stays upright (never mirrored) with glyphs
// pointing gently inward. textPath + startOffset 50% + text-anchor middle then
// centres each label exactly on its capability's 72° segment midpoint.
function labelArc(thetaDeg: number, r: number, bottom: boolean, span = 120): string {
  const pt = (a: number): [number, number] => {
    const phi = ((a - 90) * Math.PI) / 180; // 12 o'clock = 0°, clockwise positive
    return [CENTER + r * Math.cos(phi), CENTER + r * Math.sin(phi)];
  };
  const half = span / 2;
  if (bottom) {
    const [x1, y1] = pt(thetaDeg + half);
    const [x2, y2] = pt(thetaDeg - half);
    return `M ${x1} ${y1} A ${r} ${r} 0 0 0 ${x2} ${y2}`; // CCW → upright at bottom
  }
  const [x1, y1] = pt(thetaDeg - half);
  const [x2, y2] = pt(thetaDeg + half);
  return `M ${x1} ${y1} A ${r} ${r} 0 0 1 ${x2} ${y2}`; // CW → upright at top
}

interface Vitals {
  height: number; // node's synced height (the big ticking number)
  target: number; // chain tip height (== height once synced)
  isSyncing: boolean;
  syncPct: number;
  peers: number;
  miners: number;
  nodeHashrateHs: number; // this node's hashrate (miners on this node), in H/s
  uptimeSecs: number;
  bestDifficulty: number;
}

// A pulse emanating from the medallion. Real new blocks are `strong`; the
// ambient metronome fires faint ones so the board is never still.
interface Beat {
  t: number; // performance.now() timestamp of the beat
  strong: boolean;
}

// A drifting background speck (parallax depth via `z`).
interface Speck {
  x: number; // 0..1 normalised
  y: number; // 0..1 normalised
  z: number; // 0..1 depth (1 = nearest → brighter, faster)
  phase: number;
  tw: number; // twinkle speed
  warm: boolean; // a minority are accent-tinted
}

type RGB = { r: number; g: number; b: number };
const FALLBACK_BG: RGB = { r: 15, g: 16, b: 18 };
const FALLBACK_FG: RGB = { r: 230, g: 228, b: 222 };

// The lightweight node mempool payload (mirrors the Mempool page): plain
// getmempoolinfo + tier classification, no heavy indexer. `message` is present
// only when the node's RPC is unavailable → the dial rests / shows dashes.
interface BudsMempool {
  total: number; // mempool tx count (getmempoolinfo.size)
  bytes?: number; // total vsize bytes
  usage?: number; // estimated memory usage
  max_mempool?: number; // maxmempool bytes
  min_fee?: number; // BTC/kvB (getmempoolinfo.mempoolminfee)
  by_tier?: { T0: number; T1: number; T2: number; T3: number };
  message?: string;
}

function parseHex(value: string): RGB | null {
  const m = value.trim().match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (!m) return null;
  let h = m[1];
  if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
  return {
    r: parseInt(h.slice(0, 2), 16),
    g: parseInt(h.slice(2, 4), 16),
    b: parseInt(h.slice(4, 6), 16),
  };
}

function luminance(c: RGB): number {
  return (0.2126 * c.r + 0.7152 * c.g + 0.0722 * c.b) / 255;
}

function shift(c: RGB, d: number): RGB {
  return {
    r: Math.max(0, Math.min(255, c.r + d)),
    g: Math.max(0, Math.min(255, c.g + d)),
    b: Math.max(0, Math.min(255, c.b + d)),
  };
}

// Difficulty formatting — metric prefixes (…M/G/T/P/E), matching the pool
// page's formatDifficulty so a best share reads the same everywhere (e.g.
// 4.26e9 → "4.26G", not "4.26B").
function fmtCompact(n: number): string {
  if (!isFinite(n) || n <= 0) return '—';
  if (n >= 1e18) return `${(n / 1e18).toFixed(2)}E`;
  if (n >= 1e15) return `${(n / 1e15).toFixed(2)}P`;
  if (n >= 1e12) return `${(n / 1e12).toFixed(2)}T`;
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)}G`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(2)}K`;
  return Math.round(n).toLocaleString();
}

// Short SI number for tach tick labels — a compact "12T" / "3.4M" / "2k" / "50".
// Works for both mempool tx counts and hashrate (H/s) full-scale values.
function siShort(n: number): string {
  if (!isFinite(n)) return '';
  if (n === 0) return '0';
  const units: [string, number][] = [
    ['P', 1e15],
    ['T', 1e12],
    ['G', 1e9],
    ['M', 1e6],
    ['k', 1e3],
  ];
  const abs = Math.abs(n);
  for (const [s, val] of units) {
    if (abs >= val) {
      const x = n / val;
      const str = x >= 10 ? x.toFixed(0) : x.toFixed(1).replace(/\.0$/, '');
      return `${str}${s}`;
    }
  }
  return `${Math.round(n)}`;
}

// Round a raw value up to a "nice" full-scale (1 / 2 / 5 × 10^n) so tach tick
// labels land on clean numbers and the needle uses the arc well.
function niceCeil(x: number): number {
  if (x <= 0) return 1;
  const e = Math.pow(10, Math.floor(Math.log10(x)));
  const f = x / e;
  const nf = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
  return nf * e;
}

// ── Watchdog tell-tales ──────────────────────────────────────────────────────
// Each monitored service is reduced to a dashboard warning-light: green/unlit =
// healthy, amber = degraded/syncing/unknown, red = down. The real per-service
// statuses come from the watchdog endpoint — nothing here is fabricated.
type Tone = 'ok' | 'down' | 'warn';
interface Led {
  name: string;
  label: string;
  tone: Tone;
  title: string;
}

const TONE_COLOR: Record<Tone, string> = {
  ok: 'var(--green)',
  down: 'var(--red)',
  warn: 'var(--accent)', // amber/orange — degraded or unknown
};

function ledTone(status: string): Tone {
  switch (status) {
    case 'ok':
    case 'running':
    case 'syncing':
    case 'healthy':
      return 'ok';
    case 'error':
    case 'unhealthy':
      return 'down';
    default:
      // stopped, not_enabled, unknown, degraded, …
      return 'warn';
  }
}

// Trim the noisy prefixes/suffixes so labels stay legible in the compact row
// (e.g. "ghost-pool" → "pool", "sri-translator" → "translator").
function shortName(name: string): string {
  const trimmed = name
    .replace(/^ghost[-_]?/i, '')
    .replace(/^sri[-_]?/i, '')
    .replace(/[-_]?(service|node)$/i, '');
  return trimmed.length > 0 ? trimmed : name;
}

// Prefer the granular per-component health list; fall back to the higher-level
// services list if components are absent.
function deriveLeds(status: WatchdogStatus | undefined): Led[] {
  if (!status) return [];
  const src =
    status.components && status.components.length > 0
      ? status.components.map((c) => ({ name: c.name, status: String(c.status) }))
      : (status.services ?? []).map((s) => ({ name: s.name, status: String(s.status) }));
  const leds = src.map((s) => ({
    name: s.name,
    label: shortName(s.name),
    tone: ledTone(s.status),
    title: `${s.name}: ${s.status}`,
  }));
  // Preferred glance order: core (ghostd) before pool, then pay; any other
  // service keeps its original order after these (Array.sort is stable).
  const ORDER = ['core', 'pool', 'pay'];
  const rank = (l: string) => {
    const i = ORDER.indexOf(l.toLowerCase());
    return i === -1 ? ORDER.length : i;
  };
  return leds.sort((a, b) => rank(a.label) - rank(b.label));
}

// Resource usage → tone, mirroring the Watchdog page's threshold colouring.
function usageTone(value: number, warn: number, crit: number): Tone {
  if (value >= crit) return 'down';
  if (value >= warn) return 'warn';
  return 'ok';
}

// ── Tach gauge geometry (SVG userspace; viewBox 0 0 200 200). ────────────────
// Angles are measured clockwise from due-east (0° = 3 o'clock, 90° = 6 o'clock,
// 180° = 9 o'clock, 270° = 12 o'clock) so an SVG rotate() maps 1:1. The sweep
// spans 264° with a symmetric 96° gap at the bottom: start 138° (≈7 o'clock),
// end 402° (≈5 o'clock).
const GA = { cx: 100, cy: 92, r: 72, start: 138, sweep: 264 };

function polar(r: number, deg: number): [number, number] {
  const a = (deg * Math.PI) / 180;
  return [GA.cx + r * Math.cos(a), GA.cy + r * Math.sin(a)];
}

// Arc path along the sweep between two fractions t0..t1 (0 = start, 1 = end) at
// radius `r`. Sweep-flag 1 (clockwise, matching increasing screen angle).
function arcPath(r: number, t0: number, t1: number): string {
  const a0 = GA.start + t0 * GA.sweep;
  const a1 = GA.start + t1 * GA.sweep;
  const [x0, y0] = polar(r, a0);
  const [x1, y1] = polar(r, a1);
  const large = a1 - a0 > 180 ? 1 : 0;
  return `M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1}`;
}

export function NodeVitalsOverlay({ active }: OverlayProps) {
  const { data: status, isLoading: statusLoading } = useNodeStatus();
  const { data: mining } = useMiningStatus();
  const { data: shares } = useShares();
  const { data: bestHash } = useBestHash();
  const { data: watchdog } = useWatchdogStatus();
  const { data: resources } = useResourceStatus();
  // Live mempool — same lightweight RPC payload the Mempool page reads. Gated on
  // `active` so it stops polling when the scene is paused.
  const { data: mempool } = useQuery<BudsMempool>({
    queryKey: ['buds-mempool'],
    queryFn: () => fetchApi<BudsMempool>('/api/v1/buds/mempool'),
    enabled: active,
    refetchInterval: active ? 15_000 : false,
  });

  const rootRef = useRef<HTMLDivElement | null>(null);
  const bgCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);

  // Heartbeat: pulses the canvases animate. Real block increments are `strong`;
  // the rAF metronome adds faint ambient beats.
  const beatsRef = useRef<Beat[]>([]);
  const prevHeightRef = useRef<number | null>(null);

  // ── Derive a single tidy vitals object (mirrors the Overview page logic). ──
  const blockHeight = status?.block_height ?? 0;
  const syncHeight = status?.sync_height ?? status?.block_height ?? 0;
  const isSyncing = status?.is_synced === false && syncHeight > 0 && blockHeight > 0;

  const v: Vitals = {
    height: syncHeight,
    target: blockHeight,
    isSyncing,
    syncPct: isSyncing
      ? Math.min(100, (syncHeight / blockHeight) * 100)
      : status?.is_synced === false
        ? 0
        : 100,
    peers: status?.peer_count ?? 0,
    miners: mining?.local_connected_miners ?? mining?.connected_miners ?? 0,
    // This node's own hashrate — the combined hashrate of miners connected to
    // this node's stratum port (not the mesh-wide total). Never fabricated.
    nodeHashrateHs: (mining?.local_hashrate_th ?? 0) * 1e12,
    uptimeSecs: status?.uptime_seconds ?? status?.uptime_secs ?? 0,
    bestDifficulty:
      bestHash?.all_time?.difficulty ??
      bestHash?.best_difficulty ??
      bestHash?.last_24h?.difficulty ??
      0,
  };

  const uptimeQualified = shares?.uptime_qualified ?? true;
  const totalShares = shares?.total ?? 0;
  const maxShares = shares?.max_shares ?? 15;
  const hasStatus = !!status;

  // ── Watchdog tell-tales (real per-service health, or empty until it loads).
  const leds = deriveLeds(watchdog);

  // ── CPU / Memory / Disk gauges — real values, gracefully absent otherwise.
  // Individual numeric fields are guarded (not just the `resources` object): a
  // partial resources response with a missing field must render '—'/rest, never
  // crash on `.toFixed` of undefined.
  const gauges: { key: string; label: string; pct: number | null; tone: Tone; detail: string }[] =
    resources
      ? (() => {
          const num = (x: number | undefined | null): number | null =>
            typeof x === 'number' && Number.isFinite(x) ? x : null;
          const cpu = num(resources.cpu_percent);
          const mem = num(resources.memory_percent);
          const disk = num(resources.disk_percent);
          const memUsed = num(resources.memory_used_mb);
          const memTotal = num(resources.memory_total_mb);
          const diskUsed = num(resources.disk_used_gb);
          const diskTotal = num(resources.disk_total_gb);
          return [
            {
              key: 'cpu',
              label: 'CPU',
              pct: cpu,
              tone:
                cpu === null
                  ? ('ok' as Tone)
                  : usageTone(
                      cpu,
                      resources.warning_threshold_cpu ?? 70,
                      resources.critical_threshold_cpu ?? 90,
                    ),
              detail: cpu === null ? '—' : `${cpu.toFixed(0)}%`,
            },
            {
              key: 'mem',
              label: 'MEM',
              pct: mem,
              tone:
                mem === null
                  ? ('ok' as Tone)
                  : usageTone(
                      mem,
                      resources.warning_threshold_memory ?? 70,
                      resources.critical_threshold_memory ?? 90,
                    ),
              detail:
                memUsed !== null && memTotal !== null
                  ? `${(memUsed / 1024).toFixed(1)}/${(memTotal / 1024).toFixed(0)} GB`
                  : '—',
            },
            {
              key: 'disk',
              label: 'DISK',
              pct: disk,
              tone: disk === null ? ('ok' as Tone) : usageTone(disk, 75, 90),
              detail:
                diskUsed !== null && diskTotal !== null
                  ? `${diskUsed.toFixed(0)}/${diskTotal.toFixed(0)} GB`
                  : '—',
            },
          ];
        })()
      : [
          { key: 'cpu', label: 'CPU', pct: null, tone: 'ok', detail: '—' },
          { key: 'mem', label: 'MEM', pct: null, tone: 'ok', detail: '—' },
          { key: 'disk', label: 'DISK', pct: null, tone: 'ok', detail: '—' },
        ];

  // ── Mempool dial inputs. `message` present with 0 txs → RPC down → at rest.
  const mempoolRest = !mempool || (!!mempool.message && (mempool.total ?? 0) === 0);
  const mempoolTotal = mempool?.total ?? 0;
  const mempoolFull =
    mempool && mempool.usage && mempool.max_mempool
      ? Math.max(0, Math.min(1, mempool.usage / mempool.max_mempool))
      : 0;
  // min_fee is BTC/kvB → sat/vB = ×1e5 (×1e8 / 1000).
  const minFeeSatVb =
    mempool?.min_fee !== undefined && mempool.min_fee !== null ? mempool.min_fee * 1e5 : null;
  const mempoolMB = mempool?.bytes ? mempool.bytes / (1024 * 1024) : null;
  // Congestion redline: the red band widens as the mempool memory fills.
  const mempZones: Zone[] = [{ from: Math.max(0.45, 1 - mempoolFull * 0.55), to: 1, kind: 'red' }];
  const tierChips =
    mempool?.by_tier && !mempoolRest
      ? [
          { label: 'T0', value: mempool.by_tier.T0 ?? 0 },
          { label: 'T1', value: mempool.by_tier.T1 ?? 0 },
          { label: 'T2', value: mempool.by_tier.T2 ?? 0 },
          { label: 'T3', value: mempool.by_tier.T3 ?? 0 },
        ]
      : undefined;

  // ── Mining dial: green "in the zone" band while actively mining, redline top.
  const miningActive = v.nodeHashrateHs > 0;
  const miningZones: Zone[] = [
    ...(miningActive ? [{ from: 0.08, to: 0.82, kind: 'green' as const }] : []),
    { from: 0.82, to: 1, kind: 'red' as const },
  ];

  // ── Heartbeat detection: a rising synced height registers a STRONG beat. ──
  useEffect(() => {
    const h = v.height;
    if (h <= 0) return;
    const prev = prevHeightRef.current;
    prevHeightRef.current = h;
    // Only pulse on a genuine forward tick (not the first data arrival, and not
    // a backward wobble), and only while this overlay is the active one.
    if (prev !== null && h > prev && active) {
      beatsRef.current.push({ t: performance.now(), strong: true });
    }
  }, [v.height, active]);

  // ── Canvas: ambient depth field + breathing medallion + emanating pulses. ──
  useEffect(() => {
    if (!active) return;
    const root = rootRef.current;
    const bg = bgCanvasRef.current;
    const canvas = canvasRef.current;
    const wrap = wrapRef.current;
    if (!root || !bg || !canvas || !wrap) return;
    const bgCtx = bg.getContext('2d');
    const ctx = canvas.getContext('2d');
    if (!bgCtx || !ctx) return;

    let raf = 0;
    let dpr = 1;
    let bw = 1;
    let bh = 1;
    let focusX = 0.5;
    let focusY = 0.44;
    let specks: Speck[] = [];

    let bgCol = FALLBACK_BG;
    let fgCol = FALLBACK_FG;
    let dark = true;
    const readColours = () => {
      const cs = getComputedStyle(root);
      bgCol = parseHex(cs.getPropertyValue('--bg')) ?? FALLBACK_BG;
      fgCol = parseHex(cs.getPropertyValue('--fg')) ?? FALLBACK_FG;
      dark = luminance(bgCol) < 0.4;
    };
    readColours();
    let lastColourRead = -1;

    const seedSpecks = () => {
      const count = Math.round(Math.min(56, Math.max(30, (bw * bh) / 26000)));
      specks = new Array(count).fill(0).map((_, i) => ({
        x: Math.random(),
        y: Math.random(),
        z: Math.random(),
        phase: Math.random() * Math.PI * 2,
        tw: 0.3 + Math.random() * 1.3,
        warm: i % 5 === 0,
      }));
    };

    const resize = () => {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      const rr = root.getBoundingClientRect();
      bw = Math.max(1, rr.width);
      bh = Math.max(1, rr.height);
      bg.width = Math.max(1, Math.round(bw * dpr));
      bg.height = Math.max(1, Math.round(bh * dpr));

      const wr = wrap.getBoundingClientRect();
      canvas.width = Math.max(1, Math.round(wr.width * dpr));
      canvas.height = Math.max(1, Math.round(wr.height * dpr));

      focusX = wr.left - rr.left + wr.width / 2;
      focusY = wr.top - rr.top + wr.height / 2;
      seedSpecks();
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(root);

    const medallionR = () => {
      const r = wrap.getBoundingClientRect();
      return Math.min(Math.min(r.width, r.height) * 0.32, 320);
    };

    const drawBackground = (t: number) => {
      bgCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
      bgCtx.clearRect(0, 0, bw, bh);

      const core = shift(bgCol, dark ? 9 : 4);
      const edge = shift(bgCol, dark ? -6 : 0);
      const vg = bgCtx.createRadialGradient(
        focusX,
        focusY,
        0,
        focusX,
        focusY,
        Math.max(bw, bh) * 0.72,
      );
      vg.addColorStop(0, `rgb(${core.r}, ${core.g}, ${core.b})`);
      vg.addColorStop(1, `rgb(${edge.r}, ${edge.g}, ${edge.b})`);
      bgCtx.fillStyle = vg;
      bgCtx.fillRect(0, 0, bw, bh);

      bgCtx.globalCompositeOperation = dark ? 'lighter' : 'source-over';

      const washes: Array<{ cx: number; cy: number; col: RGB }> = [
        {
          cx: focusX + bw * 0.06 * Math.sin(t * 0.00005),
          cy: focusY - bh * 0.05 * Math.cos(t * 0.00004),
          col: { r: 247, g: 147, b: 26 },
        },
        {
          cx: focusX - bw * 0.08 * Math.cos(t * 0.000045),
          cy: focusY + bh * 0.06 * Math.sin(t * 0.00005),
          col: COOL,
        },
      ];
      for (const wsh of washes) {
        const rad = Math.max(bw, bh) * 0.5;
        const g = bgCtx.createRadialGradient(wsh.cx, wsh.cy, 0, wsh.cx, wsh.cy, rad);
        g.addColorStop(0, `rgba(${wsh.col.r}, ${wsh.col.g}, ${wsh.col.b}, ${dark ? 0.06 : 0.03})`);
        g.addColorStop(1, `rgba(${wsh.col.r}, ${wsh.col.g}, ${wsh.col.b}, 0)`);
        bgCtx.fillStyle = g;
        bgCtx.fillRect(0, 0, bw, bh);
      }

      for (const s of specks) {
        const drift = t * 0.000006 * (0.4 + s.z);
        const sx = (((s.x + drift) % 1) + 1) % 1;
        const sy =
          (((s.y - t * 0.0000045 * (0.3 + s.z) + Math.sin(t * 0.0002 + s.phase) * 0.006) % 1) + 1) %
          1;
        const px = sx * bw;
        const py = sy * bh;
        const tw = 0.4 + 0.6 * (0.5 + 0.5 * Math.sin(t * 0.001 * s.tw + s.phase));
        const a = (dark ? 0.42 : 0.22) * (0.25 + s.z) * tw;
        const rad = (0.4 + s.z * 1.3) * (dark ? 1 : 0.9);
        const col = s.warm ? { r: 247, g: 147, b: 26 } : fgCol;
        bgCtx.fillStyle = `rgba(${col.r}, ${col.g}, ${col.b}, ${a})`;
        bgCtx.beginPath();
        bgCtx.arc(px, py, rad, 0, Math.PI * 2);
        bgCtx.fill();
      }

      bgCtx.globalCompositeOperation = 'source-over';
    };

    let nextSoft = performance.now() + 1200;
    const SOFT_INTERVAL = 4200;

    const drawMedallion = (t: number) => {
      const w = canvas.width / dpr;
      const h = canvas.height / dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      const cx = w / 2;
      const cy = h / 2;
      const base = medallionR();
      const minWH = Math.min(w, h);

      ctx.globalCompositeOperation = dark ? 'lighter' : 'source-over';

      const disk = ctx.createRadialGradient(cx, cy, 0, cx, cy, base * 0.95);
      disk.addColorStop(0, `rgba(${ACCENT_RGB}, ${dark ? 0.05 : 0.03})`);
      disk.addColorStop(1, `rgba(${ACCENT_RGB}, 0)`);
      ctx.fillStyle = disk;
      ctx.beginPath();
      ctx.arc(cx, cy, base * 0.95, 0, Math.PI * 2);
      ctx.fill();

      const breathe = 0.5 + 0.5 * Math.sin(t / 2600);
      ctx.beginPath();
      ctx.arc(cx, cy, base + 12 + breathe * 6, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(${ACCENT_RGB}, ${0.04 + breathe * 0.05})`;
      ctx.lineWidth = 2;
      ctx.stroke();

      if (t >= nextSoft) {
        beatsRef.current.push({ t, strong: false });
        nextSoft = t + SOFT_INTERVAL;
        if (t > nextSoft) nextSoft = t + SOFT_INTERVAL;
      }

      const beats = beatsRef.current;
      for (let i = beats.length - 1; i >= 0; i--) {
        const beat = beats[i];
        const life = beat.strong ? 2000 : 2600;
        const age = t - beat.t;
        if (age > life || age < 0) {
          if (age > life) beats.splice(i, 1);
          continue;
        }
        const p = age / life;
        const ease = 1 - Math.pow(1 - p, 3);
        const reach = beat.strong ? minWH * 0.5 : minWH * 0.34;
        const r = base + ease * reach;
        const peak = beat.strong ? 0.5 : 0.16;
        const alpha = (1 - p) * peak;
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(${ACCENT_RGB}, ${alpha})`;
        ctx.lineWidth = (beat.strong ? 2.5 : 1.4) * (1 - p) + 0.4;
        ctx.stroke();
      }

      ctx.globalCompositeOperation = 'source-over';
    };

    const draw = (t: number) => {
      if (t - lastColourRead > 400) {
        readColours();
        lastColourRead = t;
      }
      drawBackground(t);
      drawMedallion(t);
      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      bgCtx.setTransform(1, 0, 0, 1, 0, 0);
      bgCtx.clearRect(0, 0, bg.width, bg.height);
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, canvas.width, canvas.height);
    };
  }, [active]);

  // ── Render ──────────────────────────────────────────────────────────────
  return (
    <div
      ref={rootRef}
      className="relative flex h-full w-full flex-col items-center justify-center select-none overflow-hidden"
      style={{ background: 'var(--bg)', color: 'var(--fg)', gap: 'clamp(4px, 1.1vh, 14px)' }}
    >
      <style>{keyframes}</style>

      {/* Full-bleed ambient depth field (behind everything). */}
      <canvas
        ref={bgCanvasRef}
        className="pointer-events-none absolute inset-0"
        style={{ width: '100%', height: '100%' }}
        aria-hidden
      />

      {/* Eyebrow / status line */}
      <div
        className="relative flex items-center gap-3"
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '12px',
          textTransform: 'uppercase',
          letterSpacing: '0.24em',
          color: 'var(--dim)',
        }}
      >
        <span
          style={{
            width: 8,
            height: 8,
            borderRadius: 9999,
            background: v.isSyncing ? 'var(--accent)' : 'var(--green)',
            boxShadow: `0 0 12px 2px rgba(${ACCENT_RGB}, ${v.isSyncing ? 0.6 : 0})`,
          }}
        />
        <span style={{ color: v.isSyncing ? 'var(--accent)' : 'var(--dim)' }}>
          {!hasStatus ? 'Acquiring signal' : v.isSyncing ? 'Syncing' : 'Synced'}
        </span>
      </div>

      {/* ── Instrument cluster: LEFT dial · CENTRE ring/odometer · RIGHT dial. */}
      <div className="nv-cockpit relative">
        {/* LEFT — Mempool tachometer (blue). */}
        <div className="nv-dial-slot nv-left">
          <TachGauge
            active={active}
            title="MEMPOOL"
            hue="blue"
            value={mempoolRest ? null : mempoolTotal}
            atRest={mempoolRest}
            minScale={50}
            hub={{ value: mempoolRest ? '—' : mempoolTotal.toLocaleString(), unit: 'TX IN MEMPOOL' }}
            tickFormat={siShort}
            zones={mempZones}
            secondaries={[
              { label: 'SIZE', value: mempoolMB !== null ? `${mempoolMB.toFixed(1)}MB` : '—' },
              {
                label: 'MIN FEE',
                value:
                  minFeeSatVb !== null
                    ? `${minFeeSatVb.toFixed(minFeeSatVb < 1 ? 2 : 1)} s/vB`
                    : '—',
              },
            ]}
            tierChips={tierChips}
          />
        </div>

        {/* CENTRE — capability speedometer ring wrapping the odometer. */}
        <div className="nv-center relative flex items-center justify-center">
          <div
            ref={wrapRef}
            className="relative flex items-center justify-center"
            style={{ width: 'min(38vh, 44vw, 360px)', aspectRatio: '1 / 1' }}
          >
            {/* Canvas heartbeat layer (behind the SVG ring), circular-masked so
                the emanating pulses stay full circles and don't clip to corners. */}
            <canvas
              ref={canvasRef}
              className="absolute inset-0"
              style={{
                width: '100%',
                height: '100%',
                WebkitMaskImage:
                  'radial-gradient(circle closest-side, #000 90%, transparent 100%)',
                maskImage: 'radial-gradient(circle closest-side, #000 90%, transparent 100%)',
              }}
              aria-hidden
            />

            {/* Slow rotating highlight sweep travelling around the ring. */}
            <div
              className="pointer-events-none absolute inset-0"
              style={{
                borderRadius: '9999px',
                background: `conic-gradient(rgba(${SWEEP_RGB}, 0) 0deg, rgba(${SWEEP_RGB}, 0) 250deg, rgba(${SWEEP_RGB}, 0.55) 322deg, rgba(${SWEEP_RGB}, 0.95) 352deg, rgba(${SWEEP_RGB}, 0) 360deg)`,
                WebkitMaskImage:
                  'radial-gradient(circle closest-side, transparent 69%, #000 72%, #000 78%, transparent 81%)',
                maskImage:
                  'radial-gradient(circle closest-side, transparent 69%, #000 72%, #000 78%, transparent 81%)',
                mixBlendMode: 'screen',
                opacity: 0.75,
                animation: active ? 'nv-sweep 15s linear infinite' : undefined,
              }}
              aria-hidden
            />

            {/* Capability ring (the "speedometer"). */}
            <svg
              viewBox="0 0 400 400"
              className="absolute inset-0"
              style={{ width: '100%', height: '100%' }}
              aria-hidden
            >
              <circle
                cx={CENTER}
                cy={CENTER}
                r={RING_R}
                fill="none"
                stroke="var(--rule)"
                strokeWidth={RING_STROKE}
                opacity={0.5}
                style={{ animation: active ? 'nv-track 6s ease-in-out infinite' : undefined }}
              />
              <g
                transform={`rotate(${-(90 + (SEG_VISIBLE / 2) * (360 / 100))} ${CENTER} ${CENTER})`}
              >
                {CAPS.map((cap, i) => {
                  const qualified = !!shares?.[cap.key] && uptimeQualified;
                  const claimed = !!shares?.[cap.key] && !uptimeQualified;
                  const color = qualified
                    ? `rgb(${ACCENT_RGB})`
                    : claimed
                      ? 'var(--red)'
                      : 'var(--rule-strong)';
                  return (
                    <circle
                      key={cap.key}
                      cx={CENTER}
                      cy={CENTER}
                      r={RING_R}
                      fill="none"
                      stroke={color}
                      strokeWidth={RING_STROKE}
                      strokeLinecap="round"
                      pathLength={100}
                      strokeDasharray={`${SEG_VISIBLE} ${100 - SEG_VISIBLE}`}
                      strokeDashoffset={-(i * SEG_SLOT)}
                      style={{
                        filter: qualified
                          ? `drop-shadow(0 0 5px rgba(${ACCENT_RGB}, 0.7))`
                          : 'none',
                        transition: 'stroke 0.4s ease',
                        animation: active
                          ? `${qualified ? 'nv-arc' : 'nv-arc-dim'} 3.6s ease-in-out infinite`
                          : undefined,
                        animationDelay: `${i * 0.24}s`,
                      }}
                    />
                  );
                })}
              </g>
            </svg>

            {/* Capability labels — curved along arcs just outside the ring. */}
            <svg
              viewBox="0 0 400 400"
              className="absolute inset-0"
              style={{ width: '100%', height: '100%', overflow: 'visible' }}
              aria-hidden
            >
              <defs>
                {CAPS.map((cap, i) => {
                  const theta = ((i * SEG_SLOT) / 100) * 360;
                  const bottom = theta > 90 && theta < 270;
                  return (
                    <g key={cap.key}>
                      <path
                        id={`nv-lbl-${cap.key}`}
                        d={labelArc(theta, LABEL_NAME_R, bottom)}
                        fill="none"
                      />
                      <path
                        id={`nv-bns-${cap.key}`}
                        d={labelArc(theta, LABEL_BONUS_R, bottom)}
                        fill="none"
                      />
                    </g>
                  );
                })}
              </defs>
              {CAPS.map((cap) => {
                const qualified = !!shares?.[cap.key] && uptimeQualified;
                return (
                  <g key={cap.key}>
                    <text
                      dominantBaseline="middle"
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 12,
                        letterSpacing: '0.12em',
                        fill: qualified ? 'var(--fg)' : 'var(--fainter)',
                      }}
                    >
                      <textPath href={`#nv-lbl-${cap.key}`} startOffset="50%" textAnchor="middle">
                        {cap.label}
                      </textPath>
                    </text>
                    <text
                      dominantBaseline="middle"
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 11,
                        fontWeight: 600,
                        fill: qualified ? `rgb(${ACCENT_RGB})` : 'var(--fainter)',
                      }}
                    >
                      <textPath href={`#nv-bns-${cap.key}`} startOffset="50%" textAnchor="middle">
                        +{cap.bonus}
                      </textPath>
                    </text>
                  </g>
                );
              })}
            </svg>

            {/* Centre readout — odometer block height + shares + peers/uptime. */}
            <div
              key={v.height}
              className="relative flex flex-col items-center justify-center text-center"
              style={{ animation: active ? 'nv-beat 1.6s ease-out' : undefined }}
            >
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'clamp(9px, 1.3vh, 12px)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.28em',
                  color: 'var(--dim)',
                  marginBottom: 6,
                }}
              >
                Block Height
              </div>
              <Odometer value={v.height} hasData={hasStatus} />
              {v.isSyncing && (
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 'clamp(10px, 1.5vh, 13px)',
                    color: 'var(--accent)',
                    marginTop: 7,
                  }}
                >
                  / {v.target.toLocaleString()} · {v.syncPct.toFixed(1)}%
                </div>
              )}
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'clamp(10px, 1.5vh, 13px)',
                  letterSpacing: '0.1em',
                  marginTop: 9,
                }}
              >
                {shares ? (
                  <>
                    <span
                      style={{
                        color: uptimeQualified ? 'var(--fg)' : 'var(--red)',
                        fontWeight: 600,
                      }}
                    >
                      {totalShares}
                    </span>
                    <span style={{ color: 'var(--fainter)' }}> / {maxShares} shares</span>
                  </>
                ) : (
                  <span style={{ color: 'var(--fainter)' }}>— / {maxShares} shares</span>
                )}
              </div>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '10px',
                  letterSpacing: '0.14em',
                  color: 'var(--fainter)',
                  marginTop: 5,
                  whiteSpace: 'nowrap',
                }}
              >
                {hasStatus ? `${v.peers} peers` : '— peers'}
                {' · '}
                {v.uptimeSecs > 0 ? formatDuration(v.uptimeSecs) : hasStatus ? '0m' : '—'}
              </div>
              {shares && !uptimeQualified && (
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '9px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.18em',
                    color: 'var(--red)',
                    marginTop: 4,
                  }}
                >
                  uptime below 95% · shares paused
                </div>
              )}
            </div>
          </div>
        </div>

        {/* RIGHT — Mining / hashrate tachometer (amber → red), THIS NODE. */}
        <div className="nv-dial-slot nv-right">
          <TachGauge
            active={active}
            title="HASHRATE"
            hue="mining"
            value={hasStatus ? v.nodeHashrateHs : null}
            atRest={!hasStatus}
            minScale={1e12}
            hub={{
              value: !hasStatus
                ? '—'
                : v.nodeHashrateHs > 0
                  ? formatHashrate(v.nodeHashrateHs)
                  : '0 H/s',
              unit: 'LOCAL · THIS NODE',
            }}
            tickFormat={siShort}
            zones={miningZones}
            secondaries={[
              { label: 'MINERS', value: hasStatus ? String(v.miners) : '—' },
              { label: 'BEST SHARE', value: fmtCompact(v.bestDifficulty) },
            ]}
          />
        </div>
      </div>

      {/* ── Warning-light tell-tales: one lamp per watchdog service. ── */}
      <TellTaleBank leds={leds} active={active} />

      {/* ── Fuel / temp gauges: CPU / memory / disk. ── */}
      <div
        className="relative flex items-stretch justify-center"
        style={{ gap: 'clamp(10px, 2vw, 26px)' }}
      >
        {gauges.map((g) => (
          <FuelGauge key={g.key} label={g.label} pct={g.pct} tone={g.tone} detail={g.detail} />
        ))}
      </div>

      {/* ── Chain-sync bar — a "warm-up" sweep while syncing. ── */}
      <div className="relative" style={{ width: 'min(620px, 82vw)' }}>
        <div
          className="flex items-center justify-between"
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '10px',
            textTransform: 'uppercase',
            letterSpacing: '0.2em',
            color: 'var(--dim)',
            marginBottom: 6,
          }}
        >
          <span>Chain Sync</span>
          <span style={{ color: v.isSyncing ? 'var(--accent)' : 'var(--green)' }}>
            {!hasStatus
              ? '—'
              : v.isSyncing
                ? `Warming up · ${v.syncPct.toFixed(1)}%`
                : 'Synced · 100%'}
          </span>
        </div>
        <div
          style={{
            position: 'relative',
            height: 5,
            width: '100%',
            borderRadius: 9999,
            background: 'var(--rule)',
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              height: '100%',
              width: `${hasStatus ? v.syncPct : 0}%`,
              borderRadius: 9999,
              background: v.isSyncing ? `rgb(${ACCENT_RGB})` : 'var(--green)',
              boxShadow: `0 0 10px 0 rgba(${ACCENT_RGB}, ${v.isSyncing ? 0.5 : 0.25})`,
              transition: 'width 0.6s ease',
            }}
          />
          {v.isSyncing && active && (
            <div
              className="pointer-events-none absolute inset-y-0"
              style={{
                width: '38%',
                left: 0,
                background: `linear-gradient(90deg, transparent, rgba(${ACCENT_RGB}, 0.55), transparent)`,
                animation: 'nv-warmup 1.8s ease-in-out infinite',
              }}
              aria-hidden
            />
          )}
        </div>
      </div>

      {/* Initial connecting state — only before any status has arrived. */}
      {statusLoading && !hasStatus && (
        <div
          className="relative"
          style={{
            position: 'absolute',
            bottom: 'clamp(16px, 4vh, 40px)',
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            letterSpacing: '0.2em',
            textTransform: 'uppercase',
            color: 'var(--fainter)',
          }}
        >
          connecting to node…
        </div>
      )}
    </div>
  );
}

// ── TachGauge ────────────────────────────────────────────────────────────────
// A parametrised premium tachometer: 264° sweep, major + minor ticks with
// numeric labels, a coloured zone band (redline / green operating band), an
// auto-scaling arc, and a spring-driven needle with a slight overshoot-settle.
interface Zone {
  from: number; // 0..1 fraction of the sweep
  to: number;
  kind: 'red' | 'green';
}
interface TachGaugeProps {
  active: boolean;
  title: string;
  hue: 'blue' | 'mining';
  value: number | null; // raw needle value (tx count / H/s); null → at rest
  atRest: boolean; // data absent → needle rests at zero, hub shows dashes
  minScale: number; // floor full-scale so tiny values still register
  hub: { value: string; unit: string };
  tickFormat: (v: number) => string;
  zones: Zone[];
  secondaries: { label: string; value: string }[];
  tierChips?: { label: string; value: number }[];
}

function TachGauge({
  active,
  title,
  hue,
  value,
  atRest,
  minScale,
  hub,
  tickFormat,
  zones,
  secondaries,
  tierChips,
}: TachGaugeProps) {
  const needleRef = useRef<SVGGElement | null>(null);
  const angleRef = useRef(GA.start); // current needle screen angle (deg)
  const velRef = useRef(0); // angular velocity (deg/s)
  const targetRef = useRef(GA.start); // spring target angle

  // ── Auto-scale: a rolling peak that rises instantly and decays slowly, so a
  // one-off spike doesn't permanently inflate the scale. The full-scale is a
  // "nice" ceiling 25% above the tracked peak, floored at `minScale`. The peak
  // is advanced with the documented "adjust state while rendering" pattern —
  // setState is called during render (not in an effect) and guarded by a
  // value-change check, so React re-renders immediately without a cascade and
  // repeat renders on unchanged data don't over-decay the scale.
  const [peak, setPeak] = useState(minScale);
  const [lastVal, setLastVal] = useState<number | null>(null);
  if (value != null && isFinite(value) && value !== lastVal) {
    setLastVal(value);
    const target = Math.max(minScale, value);
    setPeak((prev) =>
      target >= prev ? target : Math.max(target, prev * 0.9 + target * 0.1),
    );
  }
  const fullScale = niceCeil(Math.max(minScale, peak) * 1.25);

  const t =
    value == null || !isFinite(value) || atRest ? 0 : Math.max(0, Math.min(1, value / fullScale));

  useEffect(() => {
    targetRef.current = GA.start + t * GA.sweep;
  }, [t]);

  // ── Needle physics: a damped spring (ζ ≈ 0.68) so it swings to the target
  // with a subtle overshoot, then settles — mutating the SVG transform directly
  // each frame to avoid a React re-render per animation tick.
  useEffect(() => {
    const needle = needleRef.current;
    if (!needle) return;
    const apply = (a: number) =>
      needle.setAttribute('transform', `rotate(${a} ${GA.cx} ${GA.cy})`);
    if (!active) {
      angleRef.current = targetRef.current;
      velRef.current = 0;
      apply(angleRef.current);
      return;
    }
    let raf = 0;
    let last = performance.now();
    const step = (now: number) => {
      const dt = Math.min(0.04, (now - last) / 1000);
      last = now;
      const k = 90; // stiffness
      const c = 13; // damping → underdamped, ~8% overshoot
      const acc = k * (targetRef.current - angleRef.current) - c * velRef.current;
      velRef.current += acc * dt;
      angleRef.current += velRef.current * dt;
      if (Math.abs(targetRef.current - angleRef.current) < 0.03 && Math.abs(velRef.current) < 0.05) {
        angleRef.current = targetRef.current;
        velRef.current = 0;
      }
      apply(angleRef.current);
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [active]);

  const id = title.toLowerCase().replace(/[^a-z0-9]/g, '');
  const isMining = hue === 'mining';
  const fillStroke = isMining ? `url(#nvgrad-${id})` : 'var(--blue)';
  const fillGlowRgb = isMining ? ACCENT_RGB : BLUE_RGB;
  const needleRgb = isMining ? MINING_NEEDLE_RGB : BLUE_RGB;

  // Major ticks at 0/⅕/…/1 (labelled) with 5 minor subdivisions each.
  const majors = [0, 0.2, 0.4, 0.6, 0.8, 1];
  const minors: number[] = [];
  for (let i = 0; i <= 25; i++) {
    if (i % 5 !== 0) minors.push(i / 25);
  }

  return (
    <div className="relative flex flex-col items-center" style={{ width: '100%' }}>
      <div style={{ position: 'relative', width: '100%', aspectRatio: '1 / 1' }}>
        <svg viewBox="0 0 200 200" style={{ width: '100%', height: '100%' }} aria-hidden>
          <defs>
            <linearGradient
              id={`nvgrad-${id}`}
              gradientUnits="userSpaceOnUse"
              x1={26}
              y1={92}
              x2={174}
              y2={92}
            >
              <stop offset="0%" stopColor={`rgb(${ACCENT_RGB})`} />
              <stop offset="60%" stopColor="#e0662f" />
              <stop offset="100%" stopColor="var(--red)" />
            </linearGradient>
          </defs>

          {/* Base track. */}
          <path
            d={arcPath(GA.r, 0, 1)}
            fill="none"
            stroke="var(--rule)"
            strokeWidth={6}
            strokeLinecap="round"
          />

          {/* Coloured zone bands (green operating band / red redline). */}
          {zones.map((z, i) =>
            z.to > z.from ? (
              <path
                key={i}
                d={arcPath(GA.r + 9, z.from, z.to)}
                fill="none"
                stroke={z.kind === 'red' ? 'var(--red)' : 'var(--green)'}
                strokeWidth={4}
                strokeLinecap="round"
                style={{
                  filter: `drop-shadow(0 0 3px ${z.kind === 'red' ? 'var(--red)' : 'var(--green)'})`,
                  opacity: 0.9,
                }}
              />
            ) : null,
          )}

          {/* Value fill arc — auto-scaled, glides to its target via CSS. */}
          <path
            d={arcPath(GA.r, 0, 1)}
            fill="none"
            stroke={fillStroke}
            strokeWidth={6}
            strokeLinecap="round"
            pathLength={1000}
            strokeDasharray={`${Math.max(0, t * 1000)} 1000`}
            style={{
              filter: `drop-shadow(0 0 4px rgba(${fillGlowRgb}, 0.55))`,
              transition: 'stroke-dasharray 0.6s ease',
              opacity: atRest ? 0.25 : 1,
            }}
          />

          {/* Minor ticks. */}
          {minors.map((mt, i) => {
            const a = GA.start + mt * GA.sweep;
            const [x1, y1] = polar(GA.r - 4, a);
            const [x2, y2] = polar(GA.r - 9, a);
            return (
              <line
                key={`mn-${i}`}
                x1={x1}
                y1={y1}
                x2={x2}
                y2={y2}
                stroke="var(--rule-strong)"
                strokeWidth={1}
              />
            );
          })}

          {/* Major ticks + numeric labels. */}
          {majors.map((mt, i) => {
            const a = GA.start + mt * GA.sweep;
            const [x1, y1] = polar(GA.r - 4, a);
            const [x2, y2] = polar(GA.r - 13, a);
            const [lx, ly] = polar(GA.r - 23, a);
            return (
              <g key={`mj-${i}`}>
                <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="var(--dim)" strokeWidth={1.6} />
                <text
                  x={lx}
                  y={ly}
                  textAnchor="middle"
                  dominantBaseline="central"
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 8, fill: 'var(--dim)' }}
                >
                  {tickFormat(mt * fullScale)}
                </text>
              </g>
            );
          })}

          {/* Dial title (top). */}
          <text
            x={100}
            y={14}
            textAnchor="middle"
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 9,
              letterSpacing: '0.16em',
              fill: 'var(--dim)',
            }}
          >
            {title}
          </text>

          {/* Hub digital readout. */}
          <text
            x={100}
            y={124}
            textAnchor="middle"
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: hub.value.length > 8 ? 16 : 20,
              fontWeight: 300,
              fill: atRest ? 'var(--fainter)' : 'var(--fg)',
            }}
          >
            {hub.value}
          </text>
          <text
            x={100}
            y={138}
            textAnchor="middle"
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 6.5,
              letterSpacing: '0.14em',
              fill: 'var(--fainter)',
            }}
          >
            {hub.unit}
          </text>

          {/* Secondary readouts (bottom, either side of the gap). */}
          {secondaries.slice(0, 2).map((s, i) => {
            const x = secondaries.length === 1 ? 100 : i === 0 ? 60 : 140;
            return (
              <g key={`sec-${i}`}>
                <text
                  x={x}
                  y={162}
                  textAnchor="middle"
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 6.5,
                    letterSpacing: '0.1em',
                    fill: 'var(--fainter)',
                  }}
                >
                  {s.label}
                </text>
                <text
                  x={x}
                  y={174}
                  textAnchor="middle"
                  style={{ fontFamily: 'var(--font-mono)', fontSize: 9.5, fill: 'var(--fg)' }}
                >
                  {s.value}
                </text>
              </g>
            );
          })}

          {/* Needle — drawn pointing east; the rAF rotates it to the target. */}
          <g ref={needleRef} style={{ filter: `drop-shadow(0 0 3px rgba(${needleRgb}, 0.9))` }}>
            <polygon
              points={`${GA.cx + 52},${GA.cy} ${GA.cx - 12},${GA.cy - 2.6} ${GA.cx - 12},${GA.cy + 2.6}`}
              fill={`rgb(${needleRgb})`}
            />
          </g>
          <circle
            cx={GA.cx}
            cy={GA.cy}
            r={6}
            fill="var(--surface)"
            stroke={`rgb(${needleRgb})`}
            strokeWidth={1.6}
          />
          <circle cx={GA.cx} cy={GA.cy} r={2} fill={`rgb(${needleRgb})`} />
        </svg>
      </div>

      {/* Optional tier chip strip (mempool T0–T3). */}
      {tierChips && (
        <div className="flex items-center justify-center" style={{ gap: 4, marginTop: 2 }}>
          {tierChips.map((c, i) => {
            const chipColor =
              ['var(--green)', 'var(--blue)', 'var(--yellow)', 'var(--red)'][i] ?? 'var(--dim)';
            return (
              <div
                key={c.label}
                title={`${c.label}: ${c.value}`}
                className="flex items-center"
                style={{
                  gap: 3,
                  padding: '1px 6px',
                  borderRadius: 6,
                  border: `1px solid ${chipColor}`,
                  background: 'var(--surface)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 8.5,
                }}
              >
                <span style={{ color: chipColor, fontWeight: 600 }}>{c.label}</span>
                <span style={{ color: 'var(--dim)' }}>{c.value}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Odometer ─────────────────────────────────────────────────────────────────
// The block height as a mechanical rolling-digit odometer: each digit lives in a
// clipped window over a 0-9 reel translated by CSS, so a changed digit rolls on
// each new block. Separators (commas) stay static.
function Odometer({ value, hasData }: { value: number; hasData: boolean }) {
  const chars = hasData ? value.toLocaleString().split('') : ['—', '—', '—', '—', '—', '—'];
  return (
    <div
      className="flex items-center justify-center"
      style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 'clamp(26px, 5.4vh, 60px)',
        fontWeight: 300,
        lineHeight: 1,
        letterSpacing: '0.01em',
        fontVariantNumeric: 'tabular-nums',
        color: 'var(--fg)',
      }}
    >
      {chars.map((ch, i) => {
        const d = Number(ch);
        if (ch >= '0' && ch <= '9' && !Number.isNaN(d)) {
          return (
            <span
              key={i}
              style={{
                display: 'inline-block',
                height: '1em',
                width: '0.62em',
                overflow: 'hidden',
                position: 'relative',
              }}
            >
              <span
                style={{
                  display: 'block',
                  transform: `translateY(${-d * 10}%)`,
                  transition: 'transform 0.7s cubic-bezier(0.34, 1.4, 0.5, 1)',
                }}
              >
                {[0, 1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => (
                  <span key={n} style={{ display: 'block', height: '1em', textAlign: 'center' }}>
                    {n}
                  </span>
                ))}
              </span>
            </span>
          );
        }
        // Static separator / dash.
        return (
          <span
            key={i}
            style={{
              display: 'inline-block',
              textAlign: 'center',
              color: ch === '—' ? 'var(--fainter)' : 'var(--fg)',
              width: ch === ',' ? '0.34em' : '0.62em',
            }}
          >
            {ch}
          </span>
        );
      })}
    </div>
  );
}

// ── Warning-light tell-tales ─────────────────────────────────────────────────
// The watchdog services rendered as car-dash warning lamps: green/unlit when
// healthy, amber/red lit with a soft glow (and a blink when down) otherwise.
function TellTaleBank({ leds, active }: { leds: Led[]; active: boolean }) {
  if (leds.length === 0) {
    return (
      <div
        className="relative"
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '9px',
          textTransform: 'uppercase',
          letterSpacing: '0.2em',
          color: 'var(--fainter)',
        }}
      >
        watchdog · acquiring service health
      </div>
    );
  }
  return (
    <div
      className="relative flex flex-wrap items-center justify-center"
      style={{ gap: 'clamp(8px, 1.4vw, 16px)', maxWidth: '92vw' }}
    >
      {leds.map((led) => (
        <TellTale key={led.name} led={led} active={active} />
      ))}
    </div>
  );
}

function TellTale({ led, active }: { led: Led; active: boolean }) {
  const lit = led.tone !== 'ok';
  const color = TONE_COLOR[led.tone];
  const anim =
    !active || !lit
      ? undefined
      : led.tone === 'down'
        ? 'nv-lamp-blink 1.1s ease-in-out infinite'
        : 'nv-lamp-pulse 2.4s ease-in-out infinite';
  return (
    <div
      title={led.title}
      className="flex items-center"
      style={{
        gap: 7,
        padding: '5px 10px',
        borderRadius: 10,
        border: `1px solid ${lit ? color : 'var(--rule)'}`,
        background: lit ? `color-mix(in srgb, var(--surface) 82%, ${color})` : 'var(--surface)',
        boxShadow: lit ? `0 0 14px -3px ${color}, inset 0 0 10px -6px ${color}` : 'none',
        animation: anim,
      }}
    >
      <ServiceIcon name={led.label} color={color} lit={lit} />
      <span
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '9.5px',
          textTransform: 'uppercase',
          letterSpacing: '0.14em',
          color: lit ? color : 'var(--dim)',
          whiteSpace: 'nowrap',
        }}
      >
        {led.label}
      </span>
    </div>
  );
}

// A small warning-light glyph per known service, with a generic fallback lamp.
function ServiceIcon({ name, color, lit }: { name: string; color: string; lit: boolean }) {
  const n = name.toLowerCase();
  const stroke = color;
  const fill = lit ? color : 'none';
  const common = {
    width: 15,
    height: 15,
    viewBox: '0 0 24 24',
    fill: 'none',
    style: { filter: lit ? `drop-shadow(0 0 3px ${color})` : 'none', flexShrink: 0 },
    'aria-hidden': true as const,
  };
  if (n.includes('core')) {
    // Engine / CPU chip — the node core.
    return (
      <svg {...common}>
        <rect
          x={7}
          y={7}
          width={10}
          height={10}
          rx={1.5}
          stroke={stroke}
          strokeWidth={1.8}
          fill={lit ? `color-mix(in srgb, ${color} 45%, transparent)` : 'none'}
        />
        <rect x={10} y={10} width={4} height={4} fill={stroke} />
        {[9, 12, 15].map((p) => (
          <g key={p}>
            <line x1={p} y1={4} x2={p} y2={7} stroke={stroke} strokeWidth={1.6} />
            <line x1={p} y1={17} x2={p} y2={20} stroke={stroke} strokeWidth={1.6} />
            <line x1={4} y1={p} x2={7} y2={p} stroke={stroke} strokeWidth={1.6} />
            <line x1={17} y1={p} x2={20} y2={p} stroke={stroke} strokeWidth={1.6} />
          </g>
        ))}
      </svg>
    );
  }
  if (n.includes('pool')) {
    // Stacked ledger of shares — the pool.
    return (
      <svg {...common}>
        {[6, 11, 16].map((y, i) => (
          <rect
            key={y}
            x={4}
            y={y}
            width={16}
            height={3.2}
            rx={1.4}
            stroke={stroke}
            strokeWidth={1.4}
            fill={lit && i === 0 ? color : 'none'}
          />
        ))}
      </svg>
    );
  }
  if (n.includes('pay')) {
    // Lightning bolt — instant pay.
    return (
      <svg {...common}>
        <polygon
          points="13,2 4,13 11,13 10,22 20,10 13,10"
          stroke={stroke}
          strokeWidth={1.6}
          strokeLinejoin="round"
          fill={fill}
        />
      </svg>
    );
  }
  // Generic warning-triangle lamp.
  return (
    <svg {...common}>
      <polygon
        points="12,3 22,20 2,20"
        stroke={stroke}
        strokeWidth={1.8}
        strokeLinejoin="round"
        fill={lit ? `color-mix(in srgb, ${color} 30%, transparent)` : 'none'}
      />
      <line x1={12} y1={9} x2={12} y2={15} stroke={stroke} strokeWidth={1.8} />
      <circle cx={12} cy={17.6} r={1.1} fill={stroke} />
    </svg>
  );
}

// ── Fuel / temp gauge ────────────────────────────────────────────────────────
// A small half-circle fuel gauge for a host resource (CPU / Memory / Disk): a
// 180° arc with E–F markings, a needle that swings by CSS transition, coloured
// by the warn/crit tone. Rests at empty with '—' when the value is unavailable.
function FuelGauge({
  label,
  pct,
  tone,
  detail,
}: {
  label: string;
  pct: number | null;
  tone: Tone;
  detail: string;
}) {
  const has = pct !== null;
  const clamped = has ? Math.max(0, Math.min(100, pct)) : 0;
  const color = TONE_COLOR[tone];
  // Half-circle sweep: 180° (left, E) → 360° (right, F) over the top.
  const angle = 180 + (clamped / 100) * 180;
  const cx = 40;
  const cy = 42;
  const r = 30;
  const pol = (deg: number, rr: number): [number, number] => {
    const a = (deg * Math.PI) / 180;
    return [cx + rr * Math.cos(a), cy + rr * Math.sin(a)];
  };
  const half = (t0: number, t1: number, rr: number) => {
    const [x0, y0] = pol(180 + t0 * 180, rr);
    const [x1, y1] = pol(180 + t1 * 180, rr);
    const large = t1 - t0 > 0.5 ? 1 : 0;
    return `M ${x0} ${y0} A ${rr} ${rr} 0 ${large} 1 ${x1} ${y1}`;
  };
  return (
    <div className="relative flex flex-col items-center" style={{ gap: 3 }}>
      <div style={{ position: 'relative', width: 'clamp(58px, 8vw, 82px)' }}>
        <svg viewBox="0 0 80 50" style={{ width: '100%', height: '100%' }} aria-hidden>
          <path
            d={half(0, 1, r)}
            fill="none"
            stroke="var(--rule)"
            strokeWidth={5}
            strokeLinecap="round"
          />
          {has && (
            <path
              d={half(0, clamped / 100, r)}
              fill="none"
              stroke={color}
              strokeWidth={5}
              strokeLinecap="round"
              style={{ filter: `drop-shadow(0 0 3px ${color})`, transition: 'stroke 0.4s ease' }}
            />
          )}
          {/* E / F end markings. */}
          <text
            x={10}
            y={48}
            textAnchor="middle"
            style={{ fontFamily: 'var(--font-mono)', fontSize: 7, fill: 'var(--fainter)' }}
          >
            E
          </text>
          <text
            x={70}
            y={48}
            textAnchor="middle"
            style={{ fontFamily: 'var(--font-mono)', fontSize: 7, fill: 'var(--fainter)' }}
          >
            F
          </text>
          {/* Needle. */}
          <g
            style={{
              transform: `rotate(${angle}deg)`,
              transformOrigin: `${cx}px ${cy}px`,
              transition: 'transform 0.7s cubic-bezier(0.34, 1.3, 0.5, 1)',
            }}
          >
            <polygon
              points={`${cx + 24},${cy} ${cx - 5},${cy - 2} ${cx - 5},${cy + 2}`}
              fill={has ? color : 'var(--fainter)'}
            />
          </g>
          <circle
            cx={cx}
            cy={cy}
            r={3}
            fill="var(--surface)"
            stroke={has ? color : 'var(--fainter)'}
            strokeWidth={1.4}
          />
        </svg>
      </div>
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '9px',
          textTransform: 'uppercase',
          letterSpacing: '0.16em',
          color: 'var(--dim)',
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '8.5px',
          letterSpacing: '0.04em',
          color: has ? 'var(--fg)' : 'var(--fainter)',
          whiteSpace: 'nowrap',
        }}
      >
        {has ? `${Math.round(clamped)}% · ${detail}` : '—'}
      </div>
    </div>
  );
}

const keyframes = `
@keyframes nv-blink { 0%, 100% { opacity: 1 } 50% { opacity: 0.35 } }
@keyframes nv-beat {
  0% { transform: scale(1); }
  12% { transform: scale(1.035); }
  40% { transform: scale(1); }
}
@keyframes nv-arc { 0%, 100% { opacity: 1 } 50% { opacity: 0.7 } }
@keyframes nv-arc-dim { 0%, 100% { opacity: 1 } 50% { opacity: 0.82 } }
@keyframes nv-track { 0%, 100% { opacity: 0.5 } 50% { opacity: 0.34 } }
@keyframes nv-sweep { from { transform: rotate(0deg) } to { transform: rotate(360deg) } }
@keyframes nv-lamp-blink { 0%, 100% { opacity: 1 } 50% { opacity: 0.4 } }
@keyframes nv-lamp-pulse { 0%, 100% { opacity: 1 } 50% { opacity: 0.72 } }
@keyframes nv-warmup { 0% { transform: translateX(-100%) } 100% { transform: translateX(320%) } }

/* Instrument-cluster layout — LEFT dial · CENTRE ring · RIGHT dial, reflowing
   gracefully so nothing clips and the body never scrolls horizontally. */
.nv-cockpit {
  display: grid;
  width: 100%;
  max-width: 100vw;
  align-items: center;
  justify-items: center;
  gap: clamp(6px, 1.4vw, 22px);
  grid-template-columns: 1fr auto 1fr;
  grid-template-areas: "left center right";
}
.nv-cockpit .nv-center { grid-area: center; }
.nv-cockpit .nv-left { grid-area: left; }
.nv-cockpit .nv-right { grid-area: right; }
.nv-dial-slot {
  width: 100%;
  display: flex;
  justify-content: center;
}
.nv-dial-slot > * { width: min(30vh, 34vw, 300px); }

@media (max-width: 900px) {
  .nv-cockpit {
    grid-template-columns: 1fr 1fr;
    grid-template-areas:
      "center center"
      "left right";
  }
  .nv-dial-slot > * { width: min(34vh, 42vw, 260px); }
}
@media (max-width: 560px) {
  .nv-cockpit {
    grid-template-columns: 1fr;
    grid-template-areas:
      "center"
      "left"
      "right";
  }
  .nv-dial-slot > * { width: min(60vw, 240px); }
}
`;
