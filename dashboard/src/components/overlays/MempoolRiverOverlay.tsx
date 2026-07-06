/**
 * Overlay: Mempool River
 *
 * CONCEPT — the live mempool rendered as a calm, legible RIVER of transactions.
 * Tokens flow left→right along a handful of gently-undulating streamlines
 * (lanes), each token a crisp comet — a bright jewel core with a short trail
 * pointing downstream — coloured by its BUDS class (T0 green → T3 red, via
 * `@/lib/budsTiers`). The spawn mix tracks the live tier composition and the
 * river's density tracks mempool load, but tokens are spaced along their lane so
 * the current always reads as a flowing line rather than a blurry swarm. Faint
 * channel guides trace each streamline so the river reads even when sparse.
 *
 * Two-thirds downstream sits the reaper's blade. While the node's reaper is
 * actually reaping junk, T3 tokens that reach the blade are dramatically cut —
 * they flash, dissolve and scatter into sparks, and the blade pulses. When the
 * reaper is idle the junk simply flows straight through.
 *
 * Data:
 *  - `/api/v1/buds/mempool` — sampled tier histogram (by_tier T0..T3 + sample_size).
 *  - `useReaperStatus()`     — cumulative reaper counters (drives the blade).
 *
 * Honours the overlay `active` contract: the rAF loop runs only while active and
 * is cancelled on inactive / unmount; polling is gated with `enabled: active`.
 * CSP-safe (canvas 2D, no external assets, no new deps). Theme-aware: the
 * background reads live from CSS vars, class colours from the shared BUDS palette.
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

// A streamline the tokens ride. All tokens in a lane share its speed so their
// spacing is preserved downstream — that coherence is what reads as "current".
interface Lane {
  baseY: number; // rest height of the lane
  amp: number; // vertical amplitude of the undulation
  k: number; // spatial frequency of the undulation
  drift: number; // how fast the wave crest travels
  phase: number; // per-lane phase so lanes desync
  speed: number; // px/sec — shared by every token in the lane
  thickness: number; // half-height of the lane band (token jitter)
  gap: number; // px covered since the last spawn (spacing gate)
}

interface Particle {
  x: number; // head position along the flow
  lane: number; // index into `lanes`
  offset: number; // fixed vertical offset within the lane band
  r: number; // core radius
  tier: BudsTierKey;
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

const MAX_PARTICLES = 130;
const BLADE_FRAC = 0.66; // where the reaper blade crosses the river

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
    const c = canvas.getContext('2d');
    if (!c) return;

    let raf = 0;
    let running = true;
    const particles: Particle[] = [];
    const sparks: Spark[] = [];
    const lanes: Lane[] = [];
    let bladeFlash = 0; // spikes on each cut, decays — drives the blade pulse
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

    // Build the streamlines for the current canvas size. The river occupies a
    // central band; lane count scales gently with height so it never crowds.
    function buildLanes() {
      lanes.length = 0;
      const bandTop = cssH * 0.17;
      const bandBot = cssH * 0.83;
      const n = Math.max(4, Math.min(8, Math.round(cssH / 82)));
      const speedBase = Math.max(90, cssW / 9); // cross in ~9s
      const laneH = (bandBot - bandTop) / n;
      for (let i = 0; i < n; i++) {
        const baseY = bandTop + laneH * (i + 0.5);
        lanes.push({
          baseY,
          amp: laneH * (0.28 + Math.random() * 0.22),
          k: (Math.PI * 2) / (cssW * (0.75 + Math.random() * 0.6)),
          drift: 0.18 + Math.random() * 0.22,
          phase: Math.random() * Math.PI * 2,
          // Slight per-lane speed spread gives the river subtle depth/parallax.
          speed: speedBase * (0.82 + (i % 3) * 0.08 + Math.random() * 0.1),
          thickness: laneH * 0.3,
          gap: Infinity, // ready to spawn immediately
        });
      }
      // Existing particles may reference a now-missing lane after a shrink.
      for (const p of particles) if (p.lane >= lanes.length) p.lane = lanes.length - 1;
    }

    function laneY(lane: Lane, x: number, t: number): number {
      return lane.baseY + Math.sin(x * lane.k + t * lane.drift + lane.phase) * lane.amp;
    }

    function resize() {
      const rect = canvas!.getBoundingClientRect();
      cssW = Math.max(1, rect.width);
      cssH = Math.max(1, rect.height);
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      canvas!.width = Math.round(cssW * dpr);
      canvas!.height = Math.round(cssH * dpr);
      c!.setTransform(dpr, 0, 0, dpr, 0, 0);
      buildLanes();
    }

    readTheme();
    resize();

    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    const mo = new MutationObserver(readTheme);
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    function spawnInLane(lane: Lane, li: number) {
      const { fractions, total } = dataRef.current;
      const tier = pickTier(fractions, total);
      particles.push({
        x: -18,
        lane: li,
        offset: (Math.random() * 2 - 1) * lane.thickness,
        r: 2.1 + Math.random() * 1.3,
        tier,
        alpha: 0.82 + Math.random() * 0.18,
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
      const bladeX = cssW * BLADE_FRAC;
      bladeFlash = Math.max(0, bladeFlash - dt * 3);

      // Spacing gate: at low load tokens sit far apart; at high load they pack
      // tighter — but never touch, so the current stays legible. Per-lane, a
      // token is emitted only once the lane has advanced a full gap downstream.
      const minGap = 132 - load * 78; // px between tokens in a lane
      for (let li = 0; li < lanes.length; li++) {
        const lane = lanes[li];
        lane.gap += lane.speed * dt;
        if (!empty && lane.gap >= minGap && particles.length < MAX_PARTICLES) {
          spawnInLane(lane, li);
          lane.gap = -Math.random() * minGap * 0.28; // jitter so it isn't a metronome
        }
      }

      // Opaque clear each frame — crisp tokens, no smeary motion-blur build-up.
      c!.globalCompositeOperation = 'source-over';
      c!.fillStyle = `rgb(${theme.bgRgb})`;
      c!.fillRect(0, 0, cssW, cssH);

      // Channel guides — faint undulating streamlines so the river reads as a
      // flowing bed even between tokens.
      c!.lineWidth = 1;
      c!.strokeStyle = `rgba(${hexToRgb(theme.fainter)},0.16)`;
      for (const lane of lanes) {
        c!.beginPath();
        for (let x = 0; x <= cssW; x += 18) {
          const y = laneY(lane, x, t);
          if (x === 0) c!.moveTo(x, y);
          else c!.lineTo(x, y);
        }
        c!.stroke();
      }

      // Blade marker. Idle: a faint dashed rule. Active: a glowing red blade
      // with a travelling highlight, brightened by recent cuts.
      const junkRgb = hexToRgb(BUDS_TIER_COLORS.T3);
      const bTop = cssH * 0.14;
      const bBot = cssH * 0.86;
      if (reaperCutting) {
        const shimmer = 0.5 + 0.5 * Math.sin(t * 3);
        const glow = 0.16 + shimmer * 0.16 + bladeFlash * 0.4;
        const grad = c!.createLinearGradient(bladeX - 14, 0, bladeX + 14, 0);
        grad.addColorStop(0, `rgba(${junkRgb},0)`);
        grad.addColorStop(0.5, `rgba(${junkRgb},${glow})`);
        grad.addColorStop(1, `rgba(${junkRgb},0)`);
        c!.fillStyle = grad;
        c!.fillRect(bladeX - 14, bTop, 28, bBot - bTop);
        // Bright core line + a travelling highlight sliding down the blade.
        c!.strokeStyle = `rgba(${junkRgb},${0.5 + bladeFlash * 0.5})`;
        c!.lineWidth = 1.5;
        c!.beginPath();
        c!.moveTo(bladeX, bTop);
        c!.lineTo(bladeX, bBot);
        c!.stroke();
        const hy = bTop + ((t * 0.3) % 1) * (bBot - bTop);
        c!.fillStyle = 'rgba(255,255,255,0.7)';
        c!.fillRect(bladeX - 1.5, hy - 12, 3, 24);
      } else {
        c!.strokeStyle = `rgba(${hexToRgb(theme.fainter)},0.4)`;
        c!.lineWidth = 1;
        c!.setLineDash([4, 6]);
        c!.beginPath();
        c!.moveTo(bladeX, bTop);
        c!.lineTo(bladeX, bBot);
        c!.stroke();
        c!.setLineDash([]);
      }

      // Tokens — comets riding their lane, drawn head-first with a downstream
      // trail. source-over (no additive 'lighter') keeps overlaps crisp.
      for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i];
        const lane = lanes[p.lane];
        p.x += lane.speed * dt;
        const yh = laneY(lane, p.x, t) + p.offset;

        // Reaper cut: a T3 token reaching the blade flashes, dissolves + scatters.
        if (!p.cut && reaperCutting && p.tier === 'T3' && p.x >= bladeX) {
          p.cut = true;
          bladeFlash = 1;
          for (let s = 0; s < 8; s++) {
            sparks.push({
              x: bladeX,
              y: yh,
              vx: (Math.random() - 0.2) * 110,
              vy: (Math.random() - 0.5) * 190,
              life: 0.45 + Math.random() * 0.45,
              maxLife: 0.9,
              tier: 'T3',
            });
          }
        }

        let a = p.alpha;
        let drawR = p.r;
        if (p.cut) {
          p.cutT += dt * 3.2;
          a = p.alpha * Math.max(0, 1 - p.cutT);
          drawR = p.r * (1 + p.cutT * 0.5);
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
        const trailLen = lane.speed * 0.11;
        const xt = p.x - trailLen;
        const yt = laneY(lane, xt, t) + p.offset;

        // Downstream trail (tapered, transparent → colour toward the head).
        const g = c!.createLinearGradient(xt, yt, p.x, yh);
        g.addColorStop(0, `rgba(${rgb},0)`);
        g.addColorStop(1, `rgba(${rgb},${a * 0.5})`);
        c!.strokeStyle = g;
        c!.lineWidth = drawR * 1.4;
        c!.lineCap = 'round';
        c!.beginPath();
        c!.moveTo(xt, yt);
        c!.lineTo(p.x, yh);
        c!.stroke();

        // Tight glow — enough to make the token pop without a fuzzy halo.
        c!.fillStyle = `rgba(${rgb},${a * 0.14})`;
        c!.beginPath();
        c!.arc(p.x, yh, drawR * 2.3, 0, Math.PI * 2);
        c!.fill();
        // Jewel core + a bright highlight so it reads as a distinct tx.
        c!.fillStyle = `rgba(${rgb},${a})`;
        c!.beginPath();
        c!.arc(p.x, yh, drawR, 0, Math.PI * 2);
        c!.fill();
        c!.fillStyle = `rgba(255,255,255,${a * 0.55})`;
        c!.beginPath();
        c!.arc(p.x - drawR * 0.25, yh - drawR * 0.25, drawR * 0.42, 0, Math.PI * 2);
        c!.fill();
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
        s.vy += 42 * dt; // gentle settle
        const a = (s.life / s.maxLife) * 0.85;
        const rgb = hexToRgb(BUDS_TIER_COLORS[s.tier]);
        c!.fillStyle = `rgba(${rgb},${a})`;
        c!.beginPath();
        c!.arc(s.x, s.y, 1.5, 0, Math.PI * 2);
        c!.fill();
      }

      // Legend + status chrome (crisp; drawn over the scene each frame).
      c!.globalCompositeOperation = 'source-over';
      c!.font = '11px var(--font-mono), monospace';
      c!.textBaseline = 'middle';
      const labels: Record<BudsTierKey, string> = {
        T0: 'Payments',
        T1: 'Extended',
        T2: 'Data',
        T3: 'Junk',
      };
      let lx = 28;
      const ly = cssH - 40;
      for (const k of BUDS_TIER_KEYS) {
        c!.fillStyle = BUDS_TIER_COLORS[k];
        c!.beginPath();
        c!.arc(lx, ly, 4, 0, Math.PI * 2);
        c!.fill();
        c!.fillStyle = theme.dim;
        c!.fillText(labels[k], lx + 10, ly + 1);
        lx += 20 + c!.measureText(labels[k]).width + 18;
      }
      c!.fillStyle = reaperCutting ? BUDS_TIER_COLORS.T3 : theme.fainter;
      c!.fillText(reaperCutting ? 'reaper cutting junk' : 'reaper idle', 28, cssH - 22);

      // Empty / degraded state — the channel guides keep drifting beneath a
      // faint centred note.
      if (empty) {
        c!.fillStyle = theme.fainter;
        c!.font = '13px var(--font-mono), monospace';
        c!.textAlign = 'center';
        c!.fillText('waiting for a mempool sample…', cssW / 2, cssH / 2);
        c!.textAlign = 'left';
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
