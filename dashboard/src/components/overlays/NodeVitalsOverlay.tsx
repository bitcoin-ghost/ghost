/**
 * Overlay: Node Vitals
 *
 * CONCEPT — a calm mission-control board for this node: block height ticking
 * up, a heartbeat pulse on each new block, current hashrate, the 5-4-3-2-1
 * capability ring, peer count, uptime, and a sync progress bar. It also carries
 * a compact row of watchdog service LEDs (one dot per monitored service) and
 * CPU / memory / disk resource gauges, so the Home screen is a full glance-able
 * health board. Big, legible, ambient — designed to be read from across a room.
 *
 * The scene is given DEPTH so the medallion never floats in a black void: a
 * full-bleed background canvas paints a soft radial vignette focused on the
 * ring, two drifting nebula washes and a capped, low-contrast speck field.
 * Because real block updates are rare (~10 min), the board keeps a quiet
 * heartbeat of its own: an ambient pulse emanates from the centre every few
 * seconds, the capability arcs breathe, and a slow highlight sweep travels
 * around the ring — so it always reads as alive, never frozen. A genuine new
 * block still fires a stronger, brighter pulse (and re-beats the number).
 *
 * IMPLEMENTER NOTES:
 *  - Keep the `export function NodeVitalsOverlay({ active }: OverlayProps)`
 *    signature exactly. Replace only the body of this file.
 *  - Honour `active`: run your rAF / animation loop and any polling ONLY while
 *    `active === true`; cancel the rAF and stop polling when it flips to false.
 *  - CSP-safe only: draw with <canvas> or inline SVG / DOM+CSS. No external
 *    assets, no new deps. Theme-aware via the design-token CSS vars.
 */
'use client';

import { useEffect, useRef } from 'react';
import { useNodeStatus, useShares } from '@/hooks/queries/useNodeQueries';
import { useMiningStatus, useBestHash } from '@/hooks/queries/useMiningQueries';
import { useWatchdogStatus } from '@/hooks/queries/useWatchdogQueries';
import { useResourceStatus } from '@/hooks/queries/useResourceQueries';
import { formatHashrate, formatDuration } from '@/components/ui/DataTable';
import type { SharesInfo, WatchdogStatus } from '@/types/api';

/**
 * The scene honours `active`: it runs its rAF animation loop and lets its data
 * hooks poll ONLY while `active === true`. The Home page mounts it permanently
 * with `active` fixed on (there is no carousel), so the loop always runs — the
 * prop is retained so the animation contract stays explicit and the scene could
 * be paused again if it were ever placed off-screen.
 */
interface OverlayProps {
  active: boolean;
}

// Bitcoin orange — identical in both themes (--accent), so the canvas can use
// it directly without reading it back out of the DOM every frame.
const ACCENT_RGB = '247, 147, 26';
// A cool tint blended into one nebula wash so the depth field isn't monochrome.
const COOL = { r: 70, g: 110, b: 190 };

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

// ── Watchdog LEDs ──────────────────────────────────────────────────────────
// Each monitored service is reduced to a coloured dot: green = healthy/running,
// red = down/errored, amber = degraded/unknown/stopped. The real per-service
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
  // Preferred glance-row order: core (ghostd) before pool, then pay; any other
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

export function NodeVitalsOverlay({ active }: OverlayProps) {
  const { data: status, isLoading: statusLoading } = useNodeStatus();
  const { data: mining } = useMiningStatus();
  const { data: shares } = useShares();
  const { data: bestHash } = useBestHash();
  const { data: watchdog } = useWatchdogStatus();
  const { data: resources } = useResourceStatus();

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
    syncPct: isSyncing ? Math.min(100, (syncHeight / blockHeight) * 100) : status?.is_synced ? 100 : 0,
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

  // ── Watchdog service LEDs (real per-service health, or empty until it loads).
  const leds = deriveLeds(watchdog);

  // ── CPU / Memory / Disk gauges — real values, gracefully absent otherwise.
  const gauges: { key: string; label: string; pct: number | null; tone: Tone; detail: string }[] =
    resources
      ? [
          {
            key: 'cpu',
            label: 'CPU',
            pct: resources.cpu_percent,
            tone: usageTone(
              resources.cpu_percent,
              resources.warning_threshold_cpu,
              resources.critical_threshold_cpu,
            ),
            detail: `${resources.cpu_percent.toFixed(0)}%`,
          },
          {
            key: 'mem',
            label: 'MEM',
            pct: resources.memory_percent,
            tone: usageTone(
              resources.memory_percent,
              resources.warning_threshold_memory,
              resources.critical_threshold_memory,
            ),
            detail: `${(resources.memory_used_mb / 1024).toFixed(1)}/${(resources.memory_total_mb / 1024).toFixed(0)} GB`,
          },
          {
            key: 'disk',
            label: 'DISK',
            pct: resources.disk_percent,
            tone: usageTone(resources.disk_percent, 75, 90),
            detail: `${resources.disk_used_gb.toFixed(0)}/${resources.disk_total_gb.toFixed(0)} GB`,
          },
        ]
      : [
          { key: 'cpu', label: 'CPU', pct: null, tone: 'ok', detail: '—' },
          { key: 'mem', label: 'MEM', pct: null, tone: 'ok', detail: '—' },
          { key: 'disk', label: 'DISK', pct: null, tone: 'ok', detail: '—' },
        ];

  // ── Heartbeat detection: a rising synced height registers a STRONG beat. ──
  useEffect(() => {
    const h = v.height;
    if (h <= 0) return;
    const prev = prevHeightRef.current;
    prevHeightRef.current = h;
    // Only pulse on a genuine forward tick (not the first data arrival, and not
    // a backward wobble), and only while this overlay is the active one. The
    // central number restarts its CSS beat purely via its `key={v.height}`
    // remount below — no state needed here.
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
    // Full-bleed background metrics + the medallion's centre within it (so the
    // vignette focuses on the ring, wherever the flex column places it).
    let bw = 1;
    let bh = 1;
    let focusX = 0.5;
    let focusY = 0.44;
    let specks: Speck[] = [];

    // Theme colours, re-read a few times a second (cheap; the rest screen is
    // static). Accent is fixed orange in both themes so it stays a constant.
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
      // Capped for a calm, room-legible field (~30–56 specks).
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

      // Medallion centre relative to the root → vignette focus.
      focusX = wr.left - rr.left + wr.width / 2;
      focusY = wr.top - rr.top + wr.height / 2;
      seedSpecks();
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(root);

    // Radius, in CSS px, of the medallion the pulses emanate from. Tracks the
    // rendered SVG ring (a fraction of the smaller side), clamped for big rooms.
    const medallionR = () => {
      const r = wrap.getBoundingClientRect();
      return Math.min(Math.min(r.width, r.height) * 0.32, 320);
    };

    // ── Full-bleed background: vignette + drifting nebula + speck field. ──
    const drawBackground = (t: number) => {
      bgCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
      bgCtx.clearRect(0, 0, bw, bh);

      // Radial vignette focused on the medallion — a gentle lift at the centre
      // fading to the theme bg, so the ring sits IN a space rather than a void.
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

      // Additive glow reads as luminous on dark; stay plain on light so nothing
      // washes out.
      bgCtx.globalCompositeOperation = dark ? 'lighter' : 'source-over';

      // Two slow nebula washes (warm accent + cool) give the field real depth.
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

      // Drifting specks — deeper (small z) drift slower and glimmer fainter.
      for (const s of specks) {
        const drift = t * 0.000006 * (0.4 + s.z);
        const sx = (((s.x + drift) % 1) + 1) % 1;
        const sy =
          (((s.y - t * 0.0000045 * (0.3 + s.z) + Math.sin(t * 0.0002 + s.phase) * 0.006) % 1) + 1) % 1;
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

    // Ambient metronome: schedule the next faint self-pulse.
    let nextSoft = performance.now() + 1200;
    const SOFT_INTERVAL = 4200;

    // ── Medallion layer: soft centre glow, breathing halo, emanating pulses. ──
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

      // A soft radial disk behind the readout lifts the number off the field.
      const disk = ctx.createRadialGradient(cx, cy, 0, cx, cy, base * 0.95);
      disk.addColorStop(0, `rgba(${ACCENT_RGB}, ${dark ? 0.05 : 0.03})`);
      disk.addColorStop(1, `rgba(${ACCENT_RGB}, 0)`);
      ctx.fillStyle = disk;
      ctx.beginPath();
      ctx.arc(cx, cy, base * 0.95, 0, Math.PI * 2);
      ctx.fill();

      // Ambient breathing halo just outside the ring — slow and quiet.
      const breathe = 0.5 + 0.5 * Math.sin(t / 2600);
      ctx.beginPath();
      ctx.arc(cx, cy, base + 12 + breathe * 6, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(${ACCENT_RGB}, ${0.04 + breathe * 0.05})`;
      ctx.lineWidth = 2;
      ctx.stroke();

      // Fire the ambient metronome (catch up gracefully after a stall).
      if (t >= nextSoft) {
        beatsRef.current.push({ t, strong: false });
        nextSoft = t + SOFT_INTERVAL;
        if (t > nextSoft) nextSoft = t + SOFT_INTERVAL;
      }

      // Emanating pulses. Strong (block) rings reach further and burn brighter;
      // soft (ambient) rings are a quiet heartbeat. Both expand and fade out.
      const beats = beatsRef.current;
      for (let i = beats.length - 1; i >= 0; i--) {
        const beat = beats[i];
        const life = beat.strong ? 2000 : 2600;
        const age = t - beat.t;
        if (age > life || age < 0) {
          if (age > life) beats.splice(i, 1);
          continue;
        }
        const p = age / life; // 0 → 1
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
      style={{ background: 'var(--bg)', color: 'var(--fg)', gap: 'clamp(6px, 1.5vh, 20px)' }}
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
            animation: active ? 'nv-blink 2.4s ease-in-out infinite' : undefined,
          }}
        />
        <span>Node Vitals</span>
        <span style={{ color: 'var(--fainter)' }}>·</span>
        <span style={{ color: v.isSyncing ? 'var(--accent)' : 'var(--dim)' }}>
          {!hasStatus ? 'Acquiring signal' : v.isSyncing ? 'Syncing' : 'Synced'}
        </span>
      </div>

      {/* Watchdog service LEDs — one dot per monitored service. */}
      <WatchdogLeds leds={leds} active={active} />

      {/* Medallion: capability ring wrapping the big ticking block height. */}
      <div
        ref={wrapRef}
        className="relative flex items-center justify-center"
        style={{ width: 'min(42vh, 72vw, 384px)', aspectRatio: '1 / 1' }}
      >
        {/* Canvas heartbeat layer (behind the SVG ring). Circular mask: the
            emanating pulses expand past the square canvas's half-width, so a
            bare square bitmap clips them into four stray arc fragments in the
            diagonal corners (outside the ring). Fading the layer to transparent
            just inside the corners keeps the pulses reading as full circles and
            removes the fragments — everything drawn (disk, breathing halo,
            pulses) stays well within the solid 90% core. */}
        <canvas
          ref={canvasRef}
          className="absolute inset-0"
          style={{
            width: '100%',
            height: '100%',
            WebkitMaskImage: 'radial-gradient(circle closest-side, #000 90%, transparent 100%)',
            maskImage: 'radial-gradient(circle closest-side, #000 90%, transparent 100%)',
          }}
          aria-hidden
        />

        {/* Slow rotating highlight sweep travelling around the ring (a comet of
            light masked to the ring band; brightens the arcs as it passes). */}
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            borderRadius: '9999px',
            background: `conic-gradient(rgba(${ACCENT_RGB}, 0) 0deg, rgba(${ACCENT_RGB}, 0) 250deg, rgba(${ACCENT_RGB}, 0.45) 322deg, rgba(${ACCENT_RGB}, 0.85) 352deg, rgba(${ACCENT_RGB}, 0) 360deg)`,
            WebkitMaskImage:
              'radial-gradient(circle closest-side, transparent 66%, #000 71%, #000 80%, transparent 85%)',
            maskImage:
              'radial-gradient(circle closest-side, transparent 66%, #000 71%, #000 80%, transparent 85%)',
            mixBlendMode: 'screen',
            opacity: 0.75,
            animation: active ? 'nv-sweep 15s linear infinite' : undefined,
          }}
          aria-hidden
        />

        {/* Capability ring. */}
        <svg
          viewBox="0 0 400 400"
          className="absolute inset-0"
          style={{ width: '100%', height: '100%' }}
          aria-hidden
        >
          {/* faint full track — softly breathing so it's never dead flat */}
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
          {/* Two composed rotations, applied as one angle:
              -90° brings the SVG circle's 3-o'clock path start to 12 o'clock,
              and a further -(SEG_VISIBLE/2 path-units → degrees) recentres each
              segment on its slot boundary. Segment i's visible dash occupies the
              path interval [i·SEG_SLOT, i·SEG_SLOT+SEG_VISIBLE]; without this
              extra turn its *centre* sits at i·72°+SEG_VISIBLE/2·3.6° (~30.6°
              clockwise of where it should). Rotating the whole group back by that
              half-arc lands each centre exactly on i·72° — Elder at the top,
              then Reaper/Mining/GhostPay/Archive clockwise — while every dash
              stays inside [i·20, i·20+17] (max 97 < 100), so none straddles the
              path's 0/100 seam and no segment splits at the top. */}
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

        {/* Capability labels — curved along arcs just outside the ring so the
            text follows the ring's curvature and never overlaps the arcs. */}
        <svg
          viewBox="0 0 400 400"
          className="absolute inset-0"
          style={{ width: '100%', height: '100%', overflow: 'visible' }}
          aria-hidden
        >
          <defs>
            {CAPS.map((cap, i) => {
              const theta = ((i * SEG_SLOT) / 100) * 360; // segment centre: i·72° clockwise from top
              const bottom = theta > 90 && theta < 270; // lower half → keep upright
              return (
                <g key={cap.key}>
                  <path id={`nv-lbl-${cap.key}`} d={labelArc(theta, LABEL_NAME_R, bottom)} fill="none" />
                  <path id={`nv-bns-${cap.key}`} d={labelArc(theta, LABEL_BONUS_R, bottom)} fill="none" />
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

        {/* Centre readout. */}
        <div
          key={v.height}
          className="relative flex flex-col items-center justify-center text-center"
          style={{ animation: active ? 'nv-beat 1.6s ease-out' : undefined }}
        >
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'clamp(10px, 1.4vh, 13px)',
              textTransform: 'uppercase',
              letterSpacing: '0.28em',
              color: 'var(--dim)',
              marginBottom: 6,
            }}
          >
            Block Height
          </div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'clamp(30px, 6.2vh, 74px)',
              fontWeight: 300,
              lineHeight: 1,
              letterSpacing: '-0.01em',
              fontVariantNumeric: 'tabular-nums',
              color: 'var(--fg)',
            }}
          >
            {hasStatus ? v.height.toLocaleString() : '—'}
          </div>
          {v.isSyncing && (
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 'clamp(11px, 1.6vh, 14px)',
                color: 'var(--accent)',
                marginTop: 8,
              }}
            >
              / {v.target.toLocaleString()} · {v.syncPct.toFixed(1)}%
            </div>
          )}
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'clamp(11px, 1.6vh, 14px)',
              letterSpacing: '0.1em',
              color: uptimeQualified ? 'var(--dim)' : 'var(--red)',
              marginTop: 10,
            }}
          >
            {shares ? (
              <>
                <span style={{ color: uptimeQualified ? 'var(--fg)' : 'var(--red)', fontWeight: 600 }}>
                  {totalShares}
                </span>
                <span style={{ color: 'var(--fainter)' }}> / {maxShares} shares</span>
              </>
            ) : (
              <span style={{ color: 'var(--fainter)' }}>— / {maxShares} shares</span>
            )}
          </div>
          {shares && !uptimeQualified && (
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '10px',
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

      {/* Vital stat tiles. */}
      <div
        className="relative flex flex-wrap items-stretch justify-center"
        style={{ gap: 'clamp(8px, 1.5vw, 20px)', maxWidth: '92vw' }}
      >
        <Stat
          label="Hashrate"
          sub="this node"
          value={
            v.nodeHashrateHs > 0
              ? formatHashrate(v.nodeHashrateHs)
              : hasStatus
                ? '0 H/s'
                : '—'
          }
        />
        <Stat label="Miners" value={hasStatus ? String(v.miners) : '—'} />
        <Stat label="Peers" value={hasStatus ? String(v.peers) : '—'} />
        <Stat label="Uptime" value={v.uptimeSecs > 0 ? formatDuration(v.uptimeSecs) : hasStatus ? '0m' : '—'} />
        <Stat label="Best Share" value={fmtCompact(v.bestDifficulty)} accent />
      </div>

      {/* Host resources — CPU / Memory / Disk mini radial gauges. */}
      <div
        className="relative flex items-stretch justify-center"
        style={{ gap: 'clamp(10px, 1.6vw, 22px)' }}
      >
        {gauges.map((g) => (
          <ResourceGauge
            key={g.key}
            label={g.label}
            pct={g.pct}
            tone={g.tone}
            detail={g.detail}
          />
        ))}
      </div>

      {/* Sync progress bar. */}
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
            {!hasStatus ? '—' : v.isSyncing ? `${v.syncPct.toFixed(1)}%` : 'Synced · 100%'}
          </span>
        </div>
        <div
          style={{
            height: 4,
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

function Stat({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string;
  sub?: string;
  accent?: boolean;
}) {
  return (
    <div
      className="relative flex flex-col items-center overflow-hidden"
      style={{
        minWidth: 'clamp(72px, 12vw, 118px)',
        padding: 'clamp(8px, 1.1vh, 13px) clamp(10px, 1.4vw, 18px)',
        borderRadius: 12,
        border: '1px solid var(--rule)',
        background: 'linear-gradient(180deg, var(--surface) 0%, var(--bg) 140%)',
        boxShadow: accent
          ? `0 0 0 1px rgba(${ACCENT_RGB}, 0.16) inset, 0 10px 26px -18px rgba(0,0,0,0.55)`
          : '0 1px 0 rgba(255,255,255,0.03) inset, 0 10px 26px -18px rgba(0,0,0,0.55)',
      }}
    >
      {/* Hairline top highlight — a subtle premium edge. */}
      <div
        className="pointer-events-none absolute inset-x-0 top-0"
        style={{
          height: 1,
          background: accent
            ? `linear-gradient(90deg, transparent, rgba(${ACCENT_RGB}, 0.5), transparent)`
            : 'linear-gradient(90deg, transparent, var(--rule-strong), transparent)',
        }}
      />
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 'clamp(15px, 2.3vh, 24px)',
          fontWeight: 300,
          lineHeight: 1.1,
          fontVariantNumeric: 'tabular-nums',
          color: accent ? `rgb(${ACCENT_RGB})` : 'var(--fg)',
          whiteSpace: 'nowrap',
        }}
      >
        {value}
      </div>
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '10px',
          textTransform: 'uppercase',
          letterSpacing: '0.18em',
          color: 'var(--dim)',
          marginTop: 6,
        }}
      >
        {label}
      </div>
      {sub && (
        <div
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '9px',
            letterSpacing: '0.14em',
            textTransform: 'uppercase',
            color: 'var(--fainter)',
            marginTop: 3,
          }}
        >
          {sub}
        </div>
      )}
    </div>
  );
}

// A compact row of watchdog service LEDs: one dot + tiny label per monitored
// service. Healthy dots share a gentle unison blink so the row reads as alive.
function WatchdogLeds({ leds, active }: { leds: Led[]; active: boolean }) {
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
      style={{ gap: 'clamp(8px, 1.2vw, 16px)', maxWidth: '92vw' }}
    >
      {leds.map((led) => (
        <div key={led.name} className="flex items-center" style={{ gap: 6 }} title={led.title}>
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: 9999,
              background: TONE_COLOR[led.tone],
              boxShadow: `0 0 8px 1px ${TONE_COLOR[led.tone]}`,
              opacity: 0.9,
              animation:
                active && led.tone === 'ok' ? 'nv-blink 3s ease-in-out infinite' : undefined,
            }}
          />
          <span
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '9.5px',
              textTransform: 'uppercase',
              letterSpacing: '0.14em',
              color: led.tone === 'down' ? 'var(--red)' : 'var(--dim)',
              whiteSpace: 'nowrap',
            }}
          >
            {led.label}
          </span>
        </div>
      ))}
    </div>
  );
}

// A small radial gauge for a host-resource percentage (CPU / Memory / Disk).
// Renders '—' with a dim track when the value is unavailable.
function ResourceGauge({
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
  return (
    <div className="relative flex flex-col items-center" style={{ gap: 4 }}>
      <div style={{ position: 'relative', width: 'clamp(50px, 6.6vh, 66px)', aspectRatio: '1 / 1' }}>
        <svg viewBox="0 0 64 64" style={{ width: '100%', height: '100%' }} aria-hidden>
          <circle cx={32} cy={32} r={24} fill="none" stroke="var(--rule)" strokeWidth={5} />
          {has && (
            <circle
              cx={32}
              cy={32}
              r={24}
              fill="none"
              stroke={color}
              strokeWidth={5}
              strokeLinecap="round"
              pathLength={100}
              strokeDasharray={`${clamped} ${100 - clamped}`}
              transform="rotate(-90 32 32)"
              style={{
                filter: `drop-shadow(0 0 4px ${color})`,
                transition: 'stroke-dasharray 0.6s ease, stroke 0.4s ease',
              }}
            />
          )}
        </svg>
        <div
          className="absolute inset-0 flex items-center justify-center"
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 'clamp(11px, 1.7vh, 15px)',
            fontWeight: 300,
            fontVariantNumeric: 'tabular-nums',
            color: has ? 'var(--fg)' : 'var(--fainter)',
          }}
        >
          {has ? `${Math.round(clamped)}%` : '—'}
        </div>
      </div>
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '9.5px',
          textTransform: 'uppercase',
          letterSpacing: '0.18em',
          color: 'var(--dim)',
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '8.5px',
          letterSpacing: '0.06em',
          color: 'var(--fainter)',
          whiteSpace: 'nowrap',
        }}
      >
        {detail}
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
`;
