/**
 * Overlay: Node Vitals
 *
 * CONCEPT — a calm mission-control board for this node: block height ticking
 * up, a heartbeat pulse on each new block, current hashrate, the 5-4-3-2-1
 * capability ring, peer count, uptime, and a sync progress bar. Big, legible,
 * ambient — designed to be glanced at from across a room.
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
import type { OverlayProps } from './types';
import { useNodeStatus, useShares } from '@/hooks/queries/useNodeQueries';
import { useMiningStatus, useBestHash } from '@/hooks/queries/useMiningQueries';
import { formatHashrate, formatDuration } from '@/components/ui/DataTable';
import type { SharesInfo } from '@/types/api';

// Bitcoin orange — identical in both themes (--accent), so the canvas can use
// it directly without reading it back out of the DOM every frame.
const ACCENT_RGB = '247, 147, 26';
// A cool tint blended into one nebula wash so the depth field isn't monochrome.
const COOL = { r: 70, g: 110, b: 190 };

// The 5-4-3-2-1 capability ring, first arc (Archive, +5) to last (Elder, +1).
// `key` indexes SharesInfo's boolean capability flags.
const CAPS: { key: keyof SharesInfo; label: string; bonus: number }[] = [
  { key: 'archive_mode', label: 'ARCHIVE', bonus: 5 },
  { key: 'ghost_pay', label: 'GHOSTPAY', bonus: 4 },
  { key: 'public_mining', label: 'MINING', bonus: 3 },
  { key: 'reaper', label: 'REAPER', bonus: 2 },
  { key: 'elder', label: 'ELDER', bonus: 1 },
];

// Ring geometry (SVG userspace units; viewBox is 0 0 400 400).
const CENTER = 200;
const RING_R = 150;
const RING_STROKE = 13;
const SEG_SLOT = 100 / CAPS.length; // pathLength=100 → 20 units per capability
const SEG_GAP = 3; // units of gap between arcs
const SEG_VISIBLE = SEG_SLOT - SEG_GAP;
const LABEL_R = RING_R + 30;

interface Vitals {
  height: number; // node's synced height (the big ticking number)
  target: number; // chain tip height (== height once synced)
  isSyncing: boolean;
  syncPct: number;
  peers: number;
  miners: number;
  poolHashrateHs: number; // mesh/pool-wide hashrate, in H/s
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

function fmtCompact(n: number): string {
  if (!isFinite(n) || n <= 0) return '—';
  if (n >= 1e12) return `${(n / 1e12).toFixed(2)}T`;
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(2)}K`;
  return Math.round(n).toLocaleString();
}

export function NodeVitalsOverlay({ active }: OverlayProps) {
  const { data: status, isLoading: statusLoading } = useNodeStatus();
  const { data: mining } = useMiningStatus();
  const { data: shares } = useShares();
  const { data: bestHash } = useBestHash();

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
    miners: mining?.connected_miners ?? mining?.local_connected_miners ?? 0,
    // Mesh/pool-wide hashrate — this is a pool node with ~0 self-hashrate, so
    // the local figure reads as dead. Show the whole pool's work instead (same
    // source the Pool page labels "Ghost Pool Hashrate"). Never fabricated.
    poolHashrateHs: (mining?.hashrate_th ?? mining?.total_hashrate ?? 0) * 1e12,
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
      style={{ background: 'var(--bg)', color: 'var(--fg)', gap: 'clamp(20px, 4vh, 56px)' }}
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

      {/* Medallion: capability ring wrapping the big ticking block height. */}
      <div
        ref={wrapRef}
        className="relative flex items-center justify-center"
        style={{ width: 'min(74vh, 92vw, 620px)', aspectRatio: '1 / 1' }}
      >
        {/* Canvas heartbeat layer (behind the SVG ring). */}
        <canvas
          ref={canvasRef}
          className="absolute inset-0"
          style={{ width: '100%', height: '100%' }}
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
          <g transform={`rotate(-90 ${CENTER} ${CENTER})`}>
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

        {/* Capability labels around the ring. */}
        <svg
          viewBox="0 0 400 400"
          className="absolute inset-0"
          style={{ width: '100%', height: '100%', overflow: 'visible' }}
          aria-hidden
        >
          {CAPS.map((cap, i) => {
            const frac = (i * SEG_SLOT + SEG_VISIBLE / 2) / 100;
            const ang = (-90 + frac * 360) * (Math.PI / 180);
            const x = CENTER + LABEL_R * Math.cos(ang);
            const y = CENTER + LABEL_R * Math.sin(ang);
            const qualified = !!shares?.[cap.key] && uptimeQualified;
            return (
              <g key={cap.key} transform={`translate(${x} ${y})`}>
                <text
                  textAnchor="middle"
                  dominantBaseline="middle"
                  y={-6}
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 12,
                    letterSpacing: '0.12em',
                    fill: qualified ? 'var(--fg)' : 'var(--fainter)',
                  }}
                >
                  {cap.label}
                </text>
                <text
                  textAnchor="middle"
                  dominantBaseline="middle"
                  y={9}
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 11,
                    fontWeight: 600,
                    fill: qualified ? `rgb(${ACCENT_RGB})` : 'var(--fainter)',
                  }}
                >
                  +{cap.bonus}
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
              fontSize: 'clamp(40px, 9vh, 108px)',
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
              marginTop: 14,
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
        style={{ gap: 'clamp(10px, 2vw, 28px)', maxWidth: '92vw' }}
      >
        <Stat
          label="Pool Hashrate"
          sub="all nodes"
          value={
            v.poolHashrateHs > 0
              ? formatHashrate(v.poolHashrateHs)
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
        minWidth: 'clamp(88px, 15vw, 150px)',
        padding: 'clamp(10px, 1.5vh, 18px) clamp(12px, 1.7vw, 24px)',
        borderRadius: 14,
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
          fontSize: 'clamp(18px, 3vh, 30px)',
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
          marginTop: 8,
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
