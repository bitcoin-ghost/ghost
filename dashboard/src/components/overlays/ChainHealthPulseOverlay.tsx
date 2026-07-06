/**
 * Overlay: Chain Health Pulse
 *
 * CONCEPT — a calm EKG / heartbeat of the chain's stability. A continuously
 * scrolling heartbeat trace whose character reflects tip health, read from
 * `/api/v1/chain/health` via `useChainHealth`:
 *
 *   - at_tip + 0 reorgs/24h → a steady, calm GREEN heartbeat (the reassuring
 *     "healthy, single chain" state — 0 reorgs is the headline, shown as STABLE),
 *     with a small blip each time a new block lands.
 *   - behind → the line drifts/flattens (AMBER), lag scaled by behind_by / tip age.
 *   - stale → RED, faster and restless (alarm-ish, not garish).
 *   - each recent reorg → a distinct spike/notch on the trace, depth ∝ amplitude,
 *     scrolling away so recent instability stays visible.
 *
 * Rendered on a full-viewport 2D <canvas> (CSP-safe: no external assets, no new
 * deps). Theme-aware via the design-token CSS variables. The rAF loop runs ONLY
 * while `active`; it is cancelled on inactive / unmount, and polling is disabled
 * off-screen. Loading / missing-endpoint (404 in local dev) states degrade to a
 * neutral idle heartbeat with an "awaiting" readout.
 */
'use client';

import { useEffect, useRef, useState } from 'react';
import { Activity, AlertTriangle, ShieldCheck } from 'lucide-react';
import { useChainHealth } from '@/hooks/queries';
import type { ChainHealthResponse, TipStatusKind } from '@/types/api';
import type { OverlayProps } from './types';

const POLL_MS = 15_000;

// ── Small deterministic maths helpers (pure, module scope) ──────────────────

function clamp(v: number, lo: number, hi: number): number {
  return v < lo ? lo : v > hi ? hi : v;
}

/** Unit-height gaussian bump. */
function gauss(x: number, mu: number, sigma: number): number {
  const d = (x - mu) / sigma;
  return Math.exp(-0.5 * d * d);
}

/** Deterministic hash → [0,1). */
function hash1(n: number): number {
  const s = Math.sin(n * 127.1) * 43758.5453;
  return s - Math.floor(s);
}

/** Smooth value noise in [0,1] — scrolls with the trace, stays stable per sample. */
function vnoise(x: number): number {
  const i = Math.floor(x);
  const f = x - i;
  const u = f * f * (3 - 2 * f);
  const a = hash1(i);
  const b = hash1(i + 1);
  return a + (b - a) * u;
}

/** Stylised PQRST heartbeat complex over a normalised phase [0,1). */
function ekg(p: number): number {
  return (
    0.12 * gauss(p, 0.18, 0.03) - // P
    0.09 * gauss(p, 0.44, 0.012) + // Q
    1.0 * gauss(p, 0.5, 0.014) - // R
    0.2 * gauss(p, 0.56, 0.018) + // S
    0.26 * gauss(p, 0.74, 0.045) // T
  );
}

/** Sharp bidirectional reorg spike (unit amplitude), in sample units around apex. */
function reorgSpike(dk: number): number {
  return gauss(dk, 0, 1.5) - 0.5 * gauss(dk, 3.4, 2) - 0.22 * gauss(dk, -2.8, 1.7);
}

/** Gentle "new block" blip. */
function blockBlip(dk: number): number {
  return 0.32 * gauss(dk, 0, 2.2);
}

// ── Colour tokens read from the live theme ──────────────────────────────────

interface Colors {
  bg: string;
  fg: string;
  dim: string;
  rule: string;
  green: string;
  amber: string;
  red: string;
}

function readVar(el: Element, name: string, fallback: string): string {
  const v = getComputedStyle(el).getPropertyValue(name).trim();
  return v || fallback;
}

function readColors(): Colors {
  const el = document.documentElement;
  return {
    bg: readVar(el, '--bg', '#0f1012'),
    fg: readVar(el, '--fg', '#e6e4de'),
    dim: readVar(el, '--dim', '#8b8a84'),
    rule: readVar(el, '--rule', '#222528'),
    green: readVar(el, '--green', '#5cc77e'),
    amber: readVar(el, '--accent', '#f7931a'),
    red: readVar(el, '--red', '#d8746a'),
  };
}

function hexToRgba(hex: string, alpha: number): string {
  let h = hex.replace('#', '').trim();
  if (h.length === 3) {
    h = h
      .split('')
      .map((c) => c + c)
      .join('');
  }
  const n = parseInt(h, 16);
  if (h.length !== 6 || Number.isNaN(n)) return `rgba(120,120,120,${alpha})`;
  const r = (n >> 16) & 255;
  const g = (n >> 8) & 255;
  const b = n & 255;
  return `rgba(${r},${g},${b},${alpha})`;
}

// ── Per-status trace character derived from live data ───────────────────────

type PulseStatus = TipStatusKind | 'none';

interface PulseParams {
  status: PulseStatus;
  period: number; // samples per heartbeat
  amp: number; // heartbeat amplitude (R = 1)
  speed: number; // scroll px/s
  noise: number; // baseline restlessness
  sag: number; // slow baseline drift (lag)
}

function deriveParams(data: ChainHealthResponse | undefined): PulseParams {
  const tip = data?.tip;
  if (!tip) {
    return { status: 'none', period: 70, amp: 0.55, speed: 42, noise: 0.015, sag: 0.02 };
  }
  if (tip.status === 'stale') {
    // Restless, low, red — reads alarm-ish without thrashing.
    return { status: 'stale', period: 42, amp: 0.4, speed: 38, noise: 0.06, sag: 0.06 };
  }
  if (tip.status === 'behind') {
    const sev = clamp(Math.max(tip.behind_by / 12, tip.tip_age_secs / 900), 0, 1);
    return {
      status: 'behind',
      period: 70 + sev * 46, // slower cadence the further behind
      amp: 1 - 0.55 * sev, // flatter the further behind
      speed: 64 - 24 * sev,
      noise: 0.02,
      sag: 0.12 + 0.5 * sev, // baseline drifts with lag
    };
  }
  // at_tip: calm, steady, green. A whisper of restlessness only if reorgs seen.
  const count = data?.reorg_count_24h ?? 0;
  return {
    status: 'at_tip',
    period: 62,
    amp: 1,
    speed: 72,
    noise: count > 0 ? clamp(0.008 + count * 0.01, 0.008, 0.05) : 0.008,
    sag: 0,
  };
}

function colorFor(status: PulseStatus, c: Colors): string {
  switch (status) {
    case 'at_tip':
      return c.green;
    case 'behind':
      return c.amber;
    case 'stale':
      return c.red;
    default:
      return c.dim;
  }
}

// ── Scrolling trace events (reorg notches + block blips) ────────────────────

interface TraceEvent {
  k: number; // absolute sample index of the apex
  kind: 'reorg' | 'block';
  amp: number; // reorg amplitude (depth-scaled); unused for block
}

interface SimState {
  sBase: number; // leftmost sample index currently on screen (float → smooth scroll)
  last: number; // last frame timestamp
  emitAccum: number; // px scrolled since last reorg emission
  cycle: number; // reorg round-robin cursor
  frame: number;
  cssW: number;
  cssH: number;
  colors: Colors;
  events: TraceEvent[];
  prevHeight: number | null;
}

// ── Readout text helpers ────────────────────────────────────────────────────

function formatRel(unixSec: number, nowMs: number): string {
  const s = Math.max(0, Math.floor(nowMs / 1000 - unixSec));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86_400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86_400)}d ago`;
}

function truncHash(h: string): string {
  if (!h || h.length <= 14) return h || '—';
  return `${h.slice(0, 6)}…${h.slice(-6)}`;
}

export function ChainHealthPulseOverlay({ active }: OverlayProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Live query. Reuse the shared hook; disable polling while off-screen so an
  // inactive-but-mounted overlay does no work (contract). TanStack Query treats
  // a false refetchInterval as "no polling"; the hook only types it as number.
  const query = useChainHealth({
    refetchInterval: (active ? POLL_MS : false) as unknown as number,
  });
  const { data, isLoading, isError } = query;

  // The animation loop reads the freshest data through a ref (no loop restart).
  const dataRef = useRef<ChainHealthResponse | undefined>(undefined);

  const simRef = useRef<SimState>({
    sBase: 0,
    last: 0,
    emitAccum: 0,
    cycle: 0,
    frame: 0,
    cssW: 0,
    cssH: 0,
    colors: {
      bg: '#0f1012',
      fg: '#e6e4de',
      dim: '#8b8a84',
      rule: '#222528',
      green: '#5cc77e',
      amber: '#f7931a',
      red: '#d8746a',
    },
    events: [],
    prevHeight: null,
  });

  // 1s ticker so "last reorg X ago" stays live between polls (active only).
  const [now, setNow] = useState<number>(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [active]);

  // Sync latest data into the loop's ref and emit a "new block" blip on height++.
  useEffect(() => {
    dataRef.current = data;
    const sim = simRef.current;
    const h = data?.tip?.local_height;
    if (typeof h === 'number') {
      if (sim.prevHeight !== null && h > sim.prevHeight) {
        // Enter from the right edge and scroll left with the trace.
        sim.events.push({ k: sim.sBase + sim.cssW + 2, kind: 'block', amp: 0 });
      }
      sim.prevHeight = h;
    }
  }, [data]);

  // The animation loop — runs ONLY while active; cancelled on inactive/unmount.
  useEffect(() => {
    if (!active) return;
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const sim = simRef.current;
    let raf = 0;

    const resize = () => {
      const rect = container.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      sim.cssW = Math.max(1, rect.width);
      sim.cssH = Math.max(1, rect.height);
      canvas.width = Math.round(sim.cssW * dpr);
      canvas.height = Math.round(sim.cssH * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(container);

    sim.last = 0;

    const frame = (ts: number) => {
      const dt = sim.last === 0 ? 0 : clamp((ts - sim.last) / 1000, 0, 0.05);
      sim.last = ts;

      // Refresh theme colours periodically (cheap; catches light/dark toggles).
      if (sim.frame % 20 === 0) sim.colors = readColors();
      sim.frame++;

      const { cssW: W, cssH: H, colors } = sim;
      const p = deriveParams(dataRef.current);
      const color = colorFor(p.status, colors);

      // Advance the scroll position.
      const prevBase = sim.sBase;
      sim.sBase += p.speed * dt;
      const scrolled = sim.sBase - prevBase;

      // Emit recent reorgs as a continuous stream of depth-scaled spikes so the
      // whole recent list keeps flowing across the trace. More reorgs → denser.
      const reorgs = dataRef.current?.reorgs ?? [];
      if (reorgs.length > 0) {
        const spacing = clamp(W / (reorgs.length + 1), 150, 360);
        sim.emitAccum += scrolled;
        let guard = 0;
        while (sim.emitAccum >= spacing && guard < 8) {
          sim.emitAccum -= spacing;
          guard++;
          const ev = reorgs[sim.cycle % reorgs.length];
          sim.cycle++;
          const depth = Math.max(1, ev.depth || 1);
          sim.events.push({
            k: sim.sBase + W + 2,
            kind: 'reorg',
            amp: 0.6 + 0.14 * Math.min(depth, 6),
          });
        }
      } else {
        sim.emitAccum = 0;
      }

      // Prune events that have scrolled off the left edge.
      if (sim.events.length > 0) {
        sim.events = sim.events.filter((e) => e.k - sim.sBase > -10);
      }

      const unit = Math.min(H * 0.24, 170);
      const midY = H * 0.5;
      const period = Math.max(20, p.period);
      const events = sim.events;

      const value = (k: number): number => {
        const ph = (((k % period) + period) % period) / period;
        let v = p.amp * ekg(ph);
        if (p.sag !== 0) v += p.sag * Math.sin(k * 0.012);
        if (p.noise !== 0) v += p.noise * (vnoise(k * 0.35) - 0.5) * 2;
        for (let i = 0; i < events.length; i++) {
          const ev = events[i];
          const dk = k - ev.k;
          if (dk < -8 || dk > 16) continue;
          v += ev.kind === 'reorg' ? reorgSpike(dk) * ev.amp : blockBlip(dk);
        }
        return v;
      };

      const yAt = (k: number) => midY - value(k) * unit;

      // ── Paint ──
      ctx.clearRect(0, 0, W, H);
      ctx.fillStyle = colors.bg;
      ctx.fillRect(0, 0, W, H);

      // Faint centre baseline.
      ctx.strokeStyle = hexToRgba(colors.rule, 0.9);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, midY);
      ctx.lineTo(W, midY);
      ctx.stroke();

      const step = W > 1400 ? 2 : 1;

      // Soft area fill under the trace.
      ctx.save();
      ctx.beginPath();
      let started = false;
      for (let x = 0; x <= W; x += step) {
        const y = yAt(sim.sBase + x);
        if (!started) {
          ctx.moveTo(x, y);
          started = true;
        } else {
          ctx.lineTo(x, y);
        }
      }
      ctx.lineTo(W, midY);
      ctx.lineTo(0, midY);
      ctx.closePath();
      const fill = ctx.createLinearGradient(0, midY - unit, 0, midY + unit);
      fill.addColorStop(0, hexToRgba(color, 0.14));
      fill.addColorStop(0.5, hexToRgba(color, 0.05));
      fill.addColorStop(1, hexToRgba(color, 0.14));
      ctx.fillStyle = fill;
      ctx.fill();
      ctx.restore();

      // The trace line, with a soft glow.
      ctx.save();
      ctx.beginPath();
      started = false;
      for (let x = 0; x <= W; x += step) {
        const y = yAt(sim.sBase + x);
        if (!started) {
          ctx.moveTo(x, y);
          started = true;
        } else {
          ctx.lineTo(x, y);
        }
      }
      ctx.lineJoin = 'round';
      ctx.lineCap = 'round';
      ctx.shadowColor = hexToRgba(color, 0.55);
      ctx.shadowBlur = 14;
      ctx.strokeStyle = color;
      ctx.lineWidth = 2.4;
      ctx.stroke();
      ctx.restore();

      // Reorg markers: a distinct glowing notch dot + tick at each spike apex.
      for (let i = 0; i < events.length; i++) {
        const ev = events[i];
        if (ev.kind !== 'reorg') continue;
        const x = ev.k - sim.sBase;
        if (x < -4 || x > W + 4) continue;
        const y = yAt(ev.k);
        const r = 2.6 + Math.min(ev.amp * 3.4, 6);
        ctx.save();
        ctx.strokeStyle = hexToRgba(colors.red, 0.35);
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(x, midY);
        ctx.lineTo(x, y);
        ctx.stroke();
        ctx.shadowColor = hexToRgba(colors.red, 0.7);
        ctx.shadowBlur = 12;
        ctx.fillStyle = colors.red;
        ctx.beginPath();
        ctx.arc(x, y, r, 0, Math.PI * 2);
        ctx.fill();
        ctx.restore();
      }

      // Fade the scrolled-out left edge (and soften the right entry).
      const lgrad = ctx.createLinearGradient(0, 0, W * 0.16, 0);
      lgrad.addColorStop(0, colors.bg);
      lgrad.addColorStop(1, hexToRgba(colors.bg, 0));
      ctx.fillStyle = lgrad;
      ctx.fillRect(0, 0, W * 0.16, H);

      const rgrad = ctx.createLinearGradient(W * 0.94, 0, W, 0);
      rgrad.addColorStop(0, hexToRgba(colors.bg, 0));
      rgrad.addColorStop(1, colors.bg);
      ctx.fillStyle = rgrad;
      ctx.fillRect(W * 0.94, 0, W * 0.06, H);

      // Leading cursor: the "live" apex at the right edge.
      const cx = W - 2;
      const cy = yAt(sim.sBase + W - 2);
      ctx.save();
      ctx.shadowColor = hexToRgba(color, 0.85);
      ctx.shadowBlur = 16;
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(cx, cy, 3.4, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();

      raf = requestAnimationFrame(frame);
    };

    raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, [active]);

  // ── Readout overlay (HTML for crisp, theme-aware text) ──
  const tip = data?.tip ?? null;
  const count24h = data?.reorg_count_24h ?? 0;
  const lastReorg = (data?.reorgs ?? [])[0];

  let statusWord: string;
  let statusColorVar: string;
  let StatusIcon = Activity;
  let detail: string;

  if (!tip) {
    statusWord = 'AWAITING';
    statusColorVar = 'var(--dim)';
    detail = isError
      ? 'chain-health endpoint unavailable'
      : isLoading
        ? 'reading chain health…'
        : 'awaiting first check';
  } else if (tip.status === 'at_tip') {
    statusWord = 'AT TIP';
    statusColorVar = 'var(--green)';
    StatusIcon = ShieldCheck;
    detail = `synced · height ${tip.local_height.toLocaleString()}`;
  } else if (tip.status === 'behind') {
    statusWord = 'BEHIND';
    statusColorVar = 'var(--accent)';
    StatusIcon = AlertTriangle;
    detail = `behind by ${tip.behind_by.toLocaleString()} block${tip.behind_by === 1 ? '' : 's'} · height ${tip.local_height.toLocaleString()}`;
  } else {
    statusWord = 'STALE';
    statusColorVar = 'var(--red)';
    StatusIcon = AlertTriangle;
    detail = `no block in ${Math.max(0, Math.floor(tip.tip_age_secs / 60))} min`;
  }

  const stable = count24h === 0;

  return (
    <div
      ref={containerRef}
      className="relative h-full w-full select-none overflow-hidden"
      style={{ background: 'var(--bg)', color: 'var(--fg)' }}
    >
      <canvas ref={canvasRef} className="absolute inset-0 h-full w-full" />

      {/* Readouts float above the trace; never intercept the carousel chrome. */}
      <div
        className="pointer-events-none absolute inset-0 flex flex-col justify-between"
        style={{ padding: 'clamp(20px, 4vw, 52px)' }}
      >
        {/* Top: tip status + reorg headline */}
        <div className="flex flex-wrap items-start justify-between gap-6">
          {/* Tip status */}
          <div>
            <div
              className="flex items-center gap-2"
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                letterSpacing: '0.22em',
                textTransform: 'uppercase',
                color: 'var(--fainter)',
              }}
            >
              <StatusIcon size={13} strokeWidth={2} style={{ color: statusColorVar }} />
              Chain tip
            </div>
            <div
              style={{
                fontFamily: 'var(--font-sans)',
                fontWeight: 300,
                fontSize: 'clamp(30px, 5.5vw, 60px)',
                letterSpacing: '0.01em',
                lineHeight: 1.05,
                marginTop: 6,
                color: statusColorVar,
              }}
            >
              {statusWord}
            </div>
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                letterSpacing: '0.04em',
                color: 'var(--dim)',
                marginTop: 4,
              }}
            >
              {detail}
            </div>
          </div>

          {/* Reorg headline — 0 reorgs is the good, reassuring state. */}
          <div style={{ textAlign: 'right' }}>
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                letterSpacing: '0.22em',
                textTransform: 'uppercase',
                color: 'var(--fainter)',
              }}
            >
              Reorgs · 24h
            </div>
            <div
              style={{
                fontFamily: 'var(--font-sans)',
                fontWeight: 300,
                fontSize: 'clamp(30px, 5.5vw, 60px)',
                lineHeight: 1.05,
                marginTop: 6,
                color: stable ? 'var(--green)' : 'var(--red)',
              }}
            >
              {stable ? 'STABLE' : count24h.toLocaleString()}
            </div>
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                letterSpacing: '0.04em',
                color: 'var(--dim)',
                marginTop: 4,
              }}
            >
              {stable
                ? 'single chain · healthy'
                : `${count24h} reorg${count24h === 1 ? '' : 's'} in last 24h`}
            </div>
          </div>
        </div>

        {/* Bottom: last-reorg line (kept clear of the carousel chrome below it). */}
        <div style={{ marginBottom: 'clamp(56px, 9vh, 96px)' }}>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              letterSpacing: '0.22em',
              textTransform: 'uppercase',
              color: 'var(--fainter)',
            }}
          >
            Last reorg
          </div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'clamp(13px, 1.6vw, 15px)',
              letterSpacing: '0.02em',
              color: lastReorg ? 'var(--fg)' : 'var(--dim)',
              marginTop: 5,
            }}
          >
            {lastReorg
              ? `depth ${lastReorg.depth} · ${formatRel(lastReorg.unix_time, now)} · ${truncHash(lastReorg.old_tip_hash)}${
                  typeof lastReorg.new_tip_height === 'number'
                    ? ` → height ${lastReorg.new_tip_height.toLocaleString()}`
                    : ''
                }`
              : 'none recently'}
          </div>
        </div>
      </div>
    </div>
  );
}
