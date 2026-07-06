/**
 * Overlay: Mempool River
 *
 * CONCEPT — live transaction particles flowing left→right like a river,
 * coloured by their BUDS class (T0 green → T3 red, via `@/lib/budsTiers`). The
 * spawn mix tracks the live tier composition (more green when the mempool is
 * mostly payments) and overall density tracks mempool load. Mid-stream a reaper
 * "blade" visibly cuts the T3 (junk) particles out of the current — scattering
 * and dissolving them — but ONLY while the node's reaper is actually reaping
 * that junk. When the reaper is idle, the red junk flows straight through.
 *
 * Data:
 *  - `/api/v1/buds/mempool` — sampled tier histogram (by_tier T0..T3 + sample_size).
 *  - `useReaperStatus()`     — cumulative reaper counters (drives the blade).
 *
 * Honours the overlay `active` contract: the rAF loop runs only while active,
 * and is cancelled on inactive / unmount. Poll intervals are gated with
 * `enabled: active`. CSP-safe (canvas 2D, no external assets, no new deps).
 * Theme-aware: background/foreground read live from CSS vars, class colours from
 * the shared BUDS palette.
 */
'use client';

import { useEffect, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import type { OverlayProps } from './types';
import { fetchApi } from '@/lib/api/client';
import { useReaperStatus } from '@/hooks/queries';
import { BUDS_TIER_COLORS, BUDS_TIER_KEYS, type BudsTierKey } from '@/lib/budsTiers';

// Live mempool composition — same shape the Filtering pages read from this
// endpoint: a sampled per-class histogram plus the sample size. `message` is
// present when the node has no sample to offer yet.
interface BudsMempoolSample {
  by_tier?: { T0: number; T1: number; T2: number; T3: number };
  sample_size?: number;
  message?: string;
}

interface Particle {
  x: number;
  y0: number; // baseline y (drift oscillates around it)
  vx: number; // px/sec
  r: number;
  tier: BudsTierKey;
  phase: number;
  driftFreq: number;
  driftAmp: number;
  alpha: number;
  cut: boolean; // has entered the reaper blade
  cutT: number; // 0..1 dissolve progress
}

interface Spark {
  x: number;
  y: number;
  vx: number;
  vy: number;
  life: number; // seconds remaining
  maxLife: number;
  tier: BudsTierKey;
}

const MAX_PARTICLES = 260;

// Weighted tier pick from live fractions. Falls back to a payment-heavy mix when
// there's no sample so the river never looks empty or wrong.
function pickTier(fractions: Record<BudsTierKey, number>, total: number): BudsTierKey {
  if (total <= 0) {
    const fallback = Math.random();
    if (fallback < 0.5) return 'T0';
    if (fallback < 0.8) return 'T1';
    if (fallback < 0.92) return 'T2';
    return 'T3';
  }
  let r = Math.random();
  for (const k of BUDS_TIER_KEYS) {
    r -= fractions[k];
    if (r <= 0) return k;
  }
  return 'T3';
}

// Parse a `#rrggbb` (or `#rgb`) hex colour to an `r,g,b` string for rgba().
function hexToRgb(hex: string): string {
  const h = hex.trim().replace('#', '');
  if (h.length === 3) {
    const r = parseInt(h[0] + h[0], 16);
    const g = parseInt(h[1] + h[1], 16);
    const b = parseInt(h[2] + h[2], 16);
    return `${r},${g},${b}`;
  }
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return `${r},${g},${b}`;
}

export function MempoolRiverOverlay({ active }: OverlayProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  // Live data — polled only while this overlay is on screen.
  const { data: mempool } = useQuery({
    queryKey: ['buds-mempool'],
    queryFn: () => fetchApi<BudsMempoolSample>('/api/v1/buds/mempool'),
    refetchInterval: 15_000,
    enabled: active,
  });
  const { data: reaperStats } = useReaperStatus(active ? undefined : { refetchInterval: 0 });

  // Latest data mirrored into refs so the animation loop reads fresh values
  // without restarting on every poll.
  const dataRef = useRef({
    fractions: { T0: 0, T1: 0, T2: 0, T3: 0 } as Record<BudsTierKey, number>,
    total: 0,
    load: 0, // 0..1 spawn-density driver
    empty: true,
    reaperCutting: false,
  });

  useEffect(() => {
    const byTier = mempool?.by_tier ?? { T0: 0, T1: 0, T2: 0, T3: 0 };
    const total = mempool?.sample_size ?? byTier.T0 + byTier.T1 + byTier.T2 + byTier.T3;
    const hasSample = !mempool?.message && total > 0;
    const fractions: Record<BudsTierKey, number> = hasSample
      ? { T0: byTier.T0 / total, T1: byTier.T1 / total, T2: byTier.T2 / total, T3: byTier.T3 / total }
      : { T0: 0, T1: 0, T2: 0, T3: 0 };

    // Reaper is actively cutting when its counters show it has reaped junk.
    // When the endpoint isn't wired (null) the blade stays dormant and the junk
    // flows straight through — an honest "reaper off" reading.
    const reaperCutting =
      !!reaperStats &&
      (reaperStats.txs_reaped > 0 ||
        reaperStats.dead_bytes_total > 0 ||
        reaperStats.last_reaped_unix != null);

    dataRef.current = {
      fractions,
      total,
      load: hasSample ? Math.min(1, total / 80) : 0,
      empty: !hasSample,
      reaperCutting,
    };
  }, [mempool, reaperStats]);

  // Animation loop — created once and gated on `active`.
  useEffect(() => {
    if (!active) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let raf = 0;
    let running = true;
    const particles: Particle[] = [];
    const sparks: Spark[] = [];
    let spawnAcc = 0;
    let last = performance.now();

    // Logical (CSS-pixel) canvas size.
    let cssW = 0;
    let cssH = 0;

    // Theme colours resolved from CSS vars; refreshed on resize + theme change.
    const theme = { bgRgb: '15,16,18', dim: '#8b8a84', fainter: '#55544f' };
    function readTheme() {
      const root = getComputedStyle(document.documentElement);
      const bg = root.getPropertyValue('--bg').trim() || '#0f1012';
      theme.bgRgb = hexToRgb(bg);
      theme.dim = root.getPropertyValue('--dim').trim() || '#8b8a84';
      theme.fainter = root.getPropertyValue('--fainter').trim() || '#55544f';
    }

    function resize() {
      const rect = canvas!.getBoundingClientRect();
      cssW = Math.max(1, rect.width);
      cssH = Math.max(1, rect.height);
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      canvas!.width = Math.round(cssW * dpr);
      canvas!.height = Math.round(cssH * dpr);
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    readTheme();
    resize();

    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    const mo = new MutationObserver(readTheme);
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    function spawn() {
      if (particles.length >= MAX_PARTICLES) return;
      const { fractions, total } = dataRef.current;
      const tier = pickTier(fractions, total);
      const centerY = cssH * 0.5;
      const bandHalf = cssH * 0.34;
      particles.push({
        x: -20,
        y0: centerY + (Math.random() * 2 - 1) * bandHalf,
        vx: cssW / (6 + Math.random() * 6), // cross in ~6–12s
        r: 2.4 + Math.random() * 3.6,
        tier,
        phase: Math.random() * Math.PI * 2,
        driftFreq: 0.3 + Math.random() * 0.5,
        driftAmp: cssH * (0.015 + Math.random() * 0.03),
        alpha: 0.75 + Math.random() * 0.25,
        cut: false,
        cutT: 0,
      });
    }

    function frame(now: number) {
      if (!running) return;
      const dt = Math.min(0.05, (now - last) / 1000); // clamp big gaps
      last = now;
      const t = now / 1000;
      const { load, empty, reaperCutting } = dataRef.current;
      const bladeX = cssW * 0.6;

      // Spawn — density tracks mempool load (a gentle baseline keeps it alive).
      const spawnRate = 3 + load * 34; // particles/sec
      spawnAcc += dt * spawnRate;
      while (spawnAcc >= 1) {
        spawn();
        spawnAcc -= 1;
      }

      // Motion-blur trail: paint the background at low alpha so particles leave
      // flowing streaks instead of hard dots.
      ctx!.globalCompositeOperation = 'source-over';
      ctx!.fillStyle = `rgba(${theme.bgRgb},0.20)`;
      ctx!.fillRect(0, 0, cssW, cssH);

      // Dormant blade marker — a faint vertical rule so the cut point reads even
      // when the reaper is idle.
      ctx!.strokeStyle = `rgba(${hexToRgb(theme.fainter)},0.5)`;
      ctx!.lineWidth = 1;
      ctx!.beginPath();
      ctx!.moveTo(bladeX, cssH * 0.12);
      ctx!.lineTo(bladeX, cssH * 0.88);
      ctx!.stroke();

      // Active reaper blade — a shimmering red band that pulses while cutting.
      if (reaperCutting) {
        const junkRgb = hexToRgb(BUDS_TIER_COLORS.T3);
        const shimmer = 0.5 + 0.5 * Math.sin(t * 3);
        const grad = ctx!.createLinearGradient(bladeX - 10, 0, bladeX + 10, 0);
        grad.addColorStop(0, `rgba(${junkRgb},0)`);
        grad.addColorStop(0.5, `rgba(${junkRgb},${0.18 + shimmer * 0.18})`);
        grad.addColorStop(1, `rgba(${junkRgb},0)`);
        ctx!.fillStyle = grad;
        ctx!.fillRect(bladeX - 10, cssH * 0.1, 20, cssH * 0.8);
        // A brighter travelling highlight along the blade.
        const hy = cssH * (0.1 + ((t * 0.25) % 1) * 0.8);
        ctx!.fillStyle = `rgba(${junkRgb},0.7)`;
        ctx!.fillRect(bladeX - 1.5, hy - 14, 3, 28);
      }

      // Particles.
      ctx!.globalCompositeOperation = 'lighter';
      for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i];
        p.x += p.vx * dt;
        const y = p.y0 + Math.sin(t * p.driftFreq + p.phase) * p.driftAmp;

        // Reaper cut: a T3 particle reaching the blade dissolves + scatters.
        if (!p.cut && reaperCutting && p.tier === 'T3' && p.x >= bladeX) {
          p.cut = true;
          for (let s = 0; s < 6; s++) {
            sparks.push({
              x: bladeX,
              y,
              vx: (Math.random() - 0.3) * 90,
              vy: (Math.random() - 0.5) * 160,
              life: 0.5 + Math.random() * 0.4,
              maxLife: 0.9,
              tier: 'T3',
            });
          }
        }

        let drawAlpha = p.alpha;
        let drawR = p.r;
        let drawY = y;
        if (p.cut) {
          p.cutT += dt * 2.6;
          drawAlpha = p.alpha * Math.max(0, 1 - p.cutT);
          drawR = p.r * (1 + p.cutT * 0.6);
          drawY = y + p.cutT * (p.phase - Math.PI) * 6; // slight scatter
          if (p.cutT >= 1) {
            particles.splice(i, 1);
            continue;
          }
        }

        if (p.x - drawR > cssW) {
          particles.splice(i, 1);
          continue;
        }

        const rgb = hexToRgb(BUDS_TIER_COLORS[p.tier]);
        // Soft glow.
        ctx!.fillStyle = `rgba(${rgb},${drawAlpha * 0.22})`;
        ctx!.beginPath();
        ctx!.arc(p.x, drawY, drawR * 2.6, 0, Math.PI * 2);
        ctx!.fill();
        // Core.
        ctx!.fillStyle = `rgba(${rgb},${drawAlpha})`;
        ctx!.beginPath();
        ctx!.arc(p.x, drawY, drawR, 0, Math.PI * 2);
        ctx!.fill();
      }

      // Sparks from cut junk.
      for (let i = sparks.length - 1; i >= 0; i--) {
        const s = sparks[i];
        s.life -= dt;
        if (s.life <= 0) {
          sparks.splice(i, 1);
          continue;
        }
        s.x += s.vx * dt;
        s.y += s.vy * dt;
        s.vy += 40 * dt; // gentle settle
        const a = (s.life / s.maxLife) * 0.8;
        const rgb = hexToRgb(BUDS_TIER_COLORS[s.tier]);
        ctx!.fillStyle = `rgba(${rgb},${a})`;
        ctx!.beginPath();
        ctx!.arc(s.x, s.y, 1.6, 0, Math.PI * 2);
        ctx!.fill();
      }

      // Legend + status chrome (crisp; drawn over the trail each frame).
      ctx!.globalCompositeOperation = 'source-over';
      ctx!.font = '11px var(--font-mono), monospace';
      ctx!.textBaseline = 'middle';
      const labels: Record<BudsTierKey, string> = {
        T0: 'Payments',
        T1: 'Extended',
        T2: 'Data',
        T3: 'Junk',
      };
      let lx = 28;
      const ly = cssH - 40;
      for (const k of BUDS_TIER_KEYS) {
        ctx!.fillStyle = BUDS_TIER_COLORS[k];
        ctx!.beginPath();
        ctx!.arc(lx, ly, 4, 0, Math.PI * 2);
        ctx!.fill();
        ctx!.fillStyle = theme.dim;
        ctx!.fillText(labels[k], lx + 10, ly + 1);
        lx += 20 + ctx!.measureText(labels[k]).width + 18;
      }
      ctx!.fillStyle = reaperCutting ? BUDS_TIER_COLORS.T3 : theme.fainter;
      ctx!.fillText(
        reaperCutting ? 'reaper cutting junk' : 'reaper idle',
        28,
        cssH - 22,
      );

      // Empty / degraded state — a faint centred note; the river still drifts.
      if (empty) {
        ctx!.fillStyle = theme.fainter;
        ctx!.font = '13px var(--font-mono), monospace';
        ctx!.textAlign = 'center';
        ctx!.fillText('waiting for a mempool sample…', cssW / 2, cssH / 2);
        ctx!.textAlign = 'left';
      }

      raf = requestAnimationFrame(frame);
    }

    raf = requestAnimationFrame(frame);

    return () => {
      running = false;
      cancelAnimationFrame(raf);
      ro.disconnect();
      mo.disconnect();
    };
  }, [active]);

  return (
    <canvas
      ref={canvasRef}
      className="block h-full w-full"
      style={{ background: 'var(--bg)' }}
    />
  );
}
