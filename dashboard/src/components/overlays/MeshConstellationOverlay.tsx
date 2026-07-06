/**
 * Overlay: Mesh Constellation
 *
 * CONCEPT — the live mesh rendered as a slowly-turning galaxy. `is_self` is the
 * luminous heart at the centre; every peer is a glowing body placed in a loose
 * 3D shell around it (by geographic longitude/latitude when we can resolve it,
 * an even golden-angle spread otherwise) and the whole cloud is projected to 2D
 * with a gentle camera drift, so nearer nodes swell and brighten while far ones
 * recede into fog. The mesh is (near) fully-connected, so we draw a LATTICE of
 * faint light-threads between all the healthy nodes and stream packets of light
 * along them — the gossip flow that gives the scene its life. Elders burn warm
 * and wear a corona; a healthy peer glows cool green; a stale node cools to a
 * dim red ember. Miners (`deduped_miner_count`) orbit their node as tiny sparks,
 * nodes breathe, edges shimmer, and every so often a node emits a ping ripple.
 * Behind it all drifts a parallax starfield and a faint nebula so even eight
 * nodes read as a living galaxy rather than an empty ring.
 *
 * Data: `useMeshNodes` (`/api/v1/pool/mesh-nodes`) for the swarm, and the
 * offline geo lib (`useGeoDb` + `extractHost`) purely to PLACE peers by
 * lon/lat. It degrades gracefully to a deterministic golden-angle sphere when
 * geo is unavailable, and to loading / offline notices when there is no data.
 *
 * Contract:
 *  - Fills its container (the shell gives it 100dvh).
 *  - Honours `active`: the rAF loop and polling run ONLY while active===true and
 *    are cancelled on active===false and on unmount.
 *  - CSP-safe: canvas 2D only, no external assets, no new deps. Theme-aware via
 *    the design-token CSS vars read off the container (deep-space on dark, and a
 *    softer but faithful rendering on light).
 */
'use client';

import { useEffect, useMemo, useRef } from 'react';
import { useMeshNodes, useGeoDb } from '@/hooks/queries';
import { extractHost } from '@/lib/geo/geoip';
import type { MeshNode } from '@/lib/api/meshNodes';
import type { OverlayProps } from './types';

type RGB = { r: number; g: number; b: number };

/** A node lifted into the 3D cloud plus the derived state the renderer needs. */
interface Body {
  node: MeshNode;
  /** World-space position on the peer shell (self sits at the origin). */
  wx: number;
  wy: number;
  wz: number;
  /** 0..1 hashrate weight → orb size. */
  weight: number;
  /** Stable per-node phase so pulses/orbits desync. */
  phase: number;
  isSelf: boolean;
}

interface Layout {
  bodies: Body[];
  /** Index pairs of healthy↔healthy nodes forming the gossip lattice. */
  edges: Array<[number, number]>;
}

interface Star {
  x: number; // 0..1 normalised
  y: number; // 0..1 normalised
  z: number; // 0..1 depth (1 = nearest layer → brighter, faster drift)
  phase: number;
  twinkle: number;
}

interface Ripple {
  body: number; // index into bodies
  t0: number; // spawn time (s)
}

const FALLBACK: Record<string, RGB> = {
  bg: { r: 15, g: 16, b: 18 },
  fg: { r: 230, g: 228, b: 222 },
  accent: { r: 247, g: 147, b: 26 },
  green: { r: 92, g: 199, b: 126 },
  red: { r: 216, g: 116, b: 106 },
  dim: { r: 139, g: 138, b: 132 },
};

// A fixed cool tint for the far nebula/space wash; blended with the theme so it
// never fights the palette.
const COOL: RGB = { r: 70, g: 110, b: 190 };
// A warm highlight elders are tinted toward.
const WARM: RGB = { r: 255, g: 210, b: 140 };

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

function rgba({ r, g, b }: RGB, a: number): string {
  return `rgba(${r}, ${g}, ${b}, ${a})`;
}

function mix(a: RGB, b: RGB, t: number): RGB {
  return {
    r: Math.round(a.r + (b.r - a.r) * t),
    g: Math.round(a.g + (b.g - a.g) * t),
    b: Math.round(a.b + (b.b - a.b) * t),
  };
}

function lighten(c: RGB, amount: number): RGB {
  return {
    r: Math.min(255, Math.round(c.r + (255 - c.r) * amount)),
    g: Math.min(255, Math.round(c.g + (255 - c.g) * amount)),
    b: Math.min(255, Math.round(c.b + (255 - c.b) * amount)),
  };
}

function luminance(c: RGB): number {
  return (0.2126 * c.r + 0.7152 * c.g + 0.0722 * c.b) / 255;
}

/** Deterministic 0..1 from a string, so placement/phase are stable per node. */
function hash01(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) % 100000) / 100000;
}

export function MeshConstellationOverlay({ active }: OverlayProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  // Poll briskly while on-screen; back right off when the carousel moves on.
  const { data, isLoading, isError } = useMeshNodes({
    refetchInterval: active ? 15_000 : 60_000,
  });
  // Geo DB is a one-shot static asset; used only to place peers by lon/lat.
  const { data: geoDb } = useGeoDb();

  const nodes = useMemo(() => data?.nodes ?? [], [data]);

  // Lay the swarm out into the 3D cloud whenever the nodes or geo resolution
  // change. The rAF loop reads this via a ref so it never restarts on updates.
  const layout = useMemo<Layout>(() => {
    const self = nodes.find((n) => n.is_self) ?? null;
    const peers = nodes.filter((n) => n !== self);

    const maxHash = Math.max(1e-9, ...nodes.map((n) => n.hashrate_th));
    const weightOf = (n: MeshNode) => Math.sqrt(Math.max(0, n.hashrate_th) / maxHash);

    // Stable order so golden-angle indices don't jump between polls.
    const ordered = [...peers].sort(
      (a, b) => hash01(a.node_id || a.address) - hash01(b.node_id || b.address),
    );
    const n = Math.max(1, ordered.length);

    const bodies: Body[] = [];
    if (self) {
      bodies.push({
        node: self,
        wx: 0,
        wy: 0,
        wz: 0,
        weight: weightOf(self),
        phase: 0,
        isSelf: true,
      });
    }

    ordered.forEach((node, i) => {
      // Golden-angle point on a unit sphere — an even spread for every node.
      const y = 1 - ((i + 0.5) / n) * 2; // 1 → -1
      const rad = Math.sqrt(Math.max(0, 1 - y * y));
      const theta = i * 2.399963229728653; // golden angle
      let ux = Math.cos(theta) * rad;
      let uy = y;
      let uz = Math.sin(theta) * rad;

      // Override the direction with true geography where we can resolve it, so
      // the layout reads like a globe: lon → azimuth, lat → elevation.
      if (geoDb) {
        try {
          const geo = geoDb.resolve(extractHost(node.address));
          if (geo.plottable && typeof geo.lat === 'number' && typeof geo.lon === 'number') {
            const phi = (geo.lat * Math.PI) / 180;
            const lam = (geo.lon * Math.PI) / 180;
            ux = Math.cos(phi) * Math.sin(lam);
            uy = Math.sin(phi);
            uz = Math.cos(phi) * Math.cos(lam);
          }
        } catch {
          /* keep the golden-angle fallback */
        }
      }

      // A little radial jitter gives the shell real depth instead of a hoop.
      const rr = 0.8 + 0.32 * hash01((node.node_id || node.address) + 'r');
      bodies.push({
        node,
        wx: ux * rr,
        wy: uy * rr,
        wz: uz * rr,
        weight: weightOf(node),
        phase: hash01((node.node_id || node.address) + 'p') * Math.PI * 2,
        isSelf: false,
      });
    });

    // Full lattice between every pair of healthy nodes (near fully-connected).
    const edges: Array<[number, number]> = [];
    for (let i = 0; i < bodies.length; i++) {
      if (!bodies[i].node.healthy) continue;
      for (let j = i + 1; j < bodies.length; j++) {
        if (!bodies[j].node.healthy) continue;
        edges.push([i, j]);
      }
    }

    return { bodies, edges };
  }, [nodes, geoDb]);

  const layoutRef = useRef(layout);
  const stateRef = useRef({ isLoading, isError, count: nodes.length });
  useEffect(() => {
    layoutRef.current = layout;
    stateRef.current = { isLoading, isError, count: nodes.length };
  }, [layout, isLoading, isError, nodes.length]);

  useEffect(() => {
    if (!active) return;
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let raf = 0;
    let width = 0;
    let height = 0;
    let dpr = 1;

    let colours = FALLBACK;
    let dark = true;
    let lastColourRead = -1;
    const readColours = () => {
      const cs = getComputedStyle(container);
      const pick = (name: string, key: keyof typeof FALLBACK): RGB =>
        parseHex(cs.getPropertyValue(name)) ?? FALLBACK[key];
      colours = {
        bg: pick('--bg', 'bg'),
        fg: pick('--fg', 'fg'),
        accent: pick('--accent', 'accent'),
        green: pick('--green', 'green'),
        red: pick('--red', 'red'),
        dim: pick('--dim', 'dim'),
      };
      dark = luminance(colours.bg) < 0.4;
    };

    // Parallax starfield — regenerated to keep density roughly constant on
    // resize. Three implicit depth layers via `z`.
    let stars: Star[] = [];
    const seedStars = () => {
      const count = Math.round(Math.min(320, Math.max(120, (width * height) / 8500)));
      stars = new Array(count).fill(0).map(() => ({
        x: Math.random(),
        y: Math.random(),
        z: Math.random(),
        phase: Math.random() * Math.PI * 2,
        twinkle: 0.4 + Math.random() * 1.6,
      }));
    };

    const resize = () => {
      const rect = container.getBoundingClientRect();
      width = Math.max(1, rect.width);
      height = Math.max(1, rect.height);
      dpr = Math.min(2, window.devicePixelRatio || 1);
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      seedStars();
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(container);

    // Camera / projection constants (world units; peer shell radius ≈ 1).
    const CAM_Z = 2.7;
    const FOCAL = 2.7;

    const ripples: Ripple[] = [];
    let lastRipple = 0;

    // Additive glow reads as luminous on the dark rest screen; on a light theme
    // we fall back to plain compositing so nothing washes out.
    const glowOn = () => {
      ctx.globalCompositeOperation = dark ? 'lighter' : 'source-over';
    };
    const glowOff = () => {
      ctx.globalCompositeOperation = 'source-over';
    };

    const drawSpace = (t: number) => {
      // Deepened radial wash off the theme bg → a sense of depth behind it all.
      const b = colours.bg;
      const deep = dark
        ? { r: Math.max(0, b.r - 4), g: Math.max(0, b.g - 4), b: Math.max(0, b.b - 3) }
        : b;
      const halo = { r: b.r + (dark ? 10 : 2), g: b.g + (dark ? 10 : 2), b: b.b + (dark ? 14 : 3) };
      const bgGrad = ctx.createRadialGradient(
        width * 0.5,
        height * 0.46,
        0,
        width * 0.5,
        height * 0.5,
        Math.max(width, height) * 0.75,
      );
      bgGrad.addColorStop(0, rgba(halo, 1));
      bgGrad.addColorStop(1, rgba(deep, 1));
      ctx.fillStyle = bgGrad;
      ctx.fillRect(0, 0, width, height);

      // Faint drifting nebula — two large, very soft blobs (warm + cool).
      glowOn();
      const blobs: Array<{ cx: number; cy: number; col: RGB }> = [
        {
          cx: width * (0.32 + 0.03 * Math.sin(t * 0.05)),
          cy: height * (0.38 + 0.02 * Math.cos(t * 0.04)),
          col: mix(colours.accent, colours.bg, 0.35),
        },
        {
          cx: width * (0.7 + 0.03 * Math.cos(t * 0.045)),
          cy: height * (0.62 + 0.02 * Math.sin(t * 0.05)),
          col: mix(COOL, colours.bg, 0.4),
        },
      ];
      for (const nb of blobs) {
        const rr = Math.max(width, height) * 0.55;
        const g = ctx.createRadialGradient(nb.cx, nb.cy, 0, nb.cx, nb.cy, rr);
        g.addColorStop(0, rgba(nb.col, dark ? 0.1 : 0.05));
        g.addColorStop(1, rgba(nb.col, 0));
        ctx.fillStyle = g;
        ctx.fillRect(0, 0, width, height);
      }

      // Parallax stars — deeper layers drift slower and glimmer fainter.
      for (const s of stars) {
        const drift = t * (0.004 + s.z * 0.01);
        const sx = (((s.x + drift) % 1) + 1) % 1;
        const px = sx * width;
        const py = ((s.y + Math.sin(t * 0.02 + s.phase) * 0.004) % 1) * height;
        const tw = 0.35 + 0.65 * (0.5 + 0.5 * Math.sin(t * s.twinkle + s.phase));
        const a = (dark ? 0.5 : 0.28) * (0.25 + s.z) * tw;
        const rad = (0.4 + s.z * 1.3) * (dark ? 1 : 0.9);
        ctx.fillStyle = rgba(colours.fg, a);
        ctx.beginPath();
        ctx.arc(px, py, rad, 0, Math.PI * 2);
        ctx.fill();
      }
      glowOff();
    };

    // Layered radial-gradient bloom + hot core → a luminous body.
    const drawOrb = (x: number, y: number, r: number, colour: RGB, intensity: number) => {
      const glowR = r * 5.2;
      const g = ctx.createRadialGradient(x, y, 0, x, y, glowR);
      g.addColorStop(0, rgba(colour, 0.9 * intensity));
      g.addColorStop(0.12, rgba(colour, 0.55 * intensity));
      g.addColorStop(0.32, rgba(colour, 0.2 * intensity));
      g.addColorStop(1, rgba(colour, 0));
      ctx.fillStyle = g;
      ctx.beginPath();
      ctx.arc(x, y, glowR, 0, Math.PI * 2);
      ctx.fill();
      // Bright body + white-hot centre.
      ctx.fillStyle = rgba(lighten(colour, 0.35), Math.min(1, 0.85 + 0.15 * intensity));
      ctx.beginPath();
      ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = rgba(lighten(colour, 0.85), 0.9 * intensity);
      ctx.beginPath();
      ctx.arc(x, y, r * 0.42, 0, Math.PI * 2);
      ctx.fill();
    };

    // Elder corona — a soft ring plus slowly-turning rays (a crown).
    const drawCorona = (
      x: number,
      y: number,
      r: number,
      colour: RGB,
      t: number,
      breath: number,
    ) => {
      ctx.strokeStyle = rgba(colour, 0.35 + 0.3 * breath);
      ctx.lineWidth = Math.max(1, r * 0.12);
      ctx.beginPath();
      ctx.arc(x, y, r * 1.9, 0, Math.PI * 2);
      ctx.stroke();
      const rays = 8;
      for (let k = 0; k < rays; k++) {
        const a = t * 0.25 + (k / rays) * Math.PI * 2;
        const r0 = r * 2.1;
        const r1 = r * (2.7 + 0.4 * Math.sin(t * 1.5 + k));
        ctx.strokeStyle = rgba(colour, 0.18 + 0.14 * breath);
        ctx.lineWidth = Math.max(1, r * 0.09);
        ctx.beginPath();
        ctx.moveTo(x + Math.cos(a) * r0, y + Math.sin(a) * r0);
        ctx.lineTo(x + Math.cos(a) * r1, y + Math.sin(a) * r1);
        ctx.stroke();
      }
    };

    const centreText = (text: string, sub: string) => {
      glowOff();
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      const scale = Math.min(width, height);
      ctx.fillStyle = rgba(colours.fg, 0.85);
      ctx.font = `300 ${Math.round(scale * 0.045)}px var(--font-sans), system-ui, sans-serif`;
      ctx.fillText(text, width / 2, height / 2 - scale * 0.02);
      ctx.fillStyle = rgba(colours.dim, 0.8);
      ctx.font = `400 ${Math.round(scale * 0.016)}px var(--font-mono), monospace`;
      ctx.fillText(sub, width / 2, height / 2 + scale * 0.03);
    };

    const render = (nowMs: number) => {
      const t = nowMs / 1000;
      if (nowMs - lastColourRead > 400) {
        readColours();
        lastColourRead = nowMs;
      }

      drawSpace(t);

      ctx.save();
      ctx.scale(dpr, dpr);

      const { bodies, edges } = layoutRef.current;
      const { isLoading: loading, isError: err, count } = stateRef.current;

      if (err || (!loading && count === 0)) {
        // A lone dim red ember at the heart while the mesh is dark.
        glowOn();
        drawOrb(width / 2, height / 2, 5, colours.red, 0.4 * (0.6 + 0.4 * Math.sin(t)));
        glowOff();
        centreText('Mesh offline', 'no peers reachable');
        ctx.restore();
        raf = requestAnimationFrame(render);
        return;
      }
      if (loading && count === 0) {
        glowOn();
        drawOrb(width / 2, height / 2, 6, colours.accent, 0.6 + 0.4 * Math.sin(t * 0.9));
        glowOff();
        centreText('Mapping the mesh…', 'reading gossip');
        ctx.restore();
        raf = requestAnimationFrame(render);
        return;
      }

      const cx = width / 2;
      const cy = height / 2;
      const scale = Math.min(width, height);
      const viewScale = scale * 0.27;
      const sizeScale = Math.min(2.3, Math.max(0.72, scale / 680));

      // Slow camera drift: continuous yaw + a gently breathing tilt.
      const yaw = t * 0.05;
      const pitch = 0.34 + 0.05 * Math.sin(t * 0.07);
      const cyaw = Math.cos(yaw);
      const syaw = Math.sin(yaw);
      const cpit = Math.cos(pitch);
      const spit = Math.sin(pitch);

      // Project every body once (painter order by depth).
      const proj = bodies.map((body) => {
        // Yaw about Y, then pitch about X.
        const x1 = body.wx * cyaw + body.wz * syaw;
        const z1 = -body.wx * syaw + body.wz * cyaw;
        const y2 = body.wy * cpit - z1 * spit;
        const z2 = body.wy * spit + z1 * cpit;
        const depth = CAM_Z - z2;
        const sc = FOCAL / depth;
        const dz = Math.min(1, Math.max(0, (z2 + 1) / 2)); // 0 far … 1 near
        return {
          body,
          x: cx + x1 * sc * viewScale,
          y: cy - y2 * sc * viewScale,
          sc,
          dz,
        };
      });

      const breath = 0.5 + 0.5 * Math.sin(t * 0.6);

      // 1) Gossip lattice — faint light-threads with packets streaming along.
      glowOn();
      for (let e = 0; e < edges.length; e++) {
        const [i, j] = edges[e];
        const a = proj[i];
        const bp = proj[j];
        const nearness = (a.dz + bp.dz) / 2;
        const shimmer = 0.5 + 0.5 * Math.sin(t * 0.9 + e * 1.3);
        const threadA = (0.05 + 0.09 * nearness) * (0.6 + 0.4 * shimmer);
        ctx.strokeStyle = rgba(colours.accent, threadA);
        ctx.lineWidth = 0.6 + 0.7 * nearness;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(bp.x, bp.y);
        ctx.stroke();

        // Packets of light — analytic positions, no per-frame allocation.
        const dir = e % 2 === 0 ? 1 : -1;
        const packets = 2;
        for (let k = 0; k < packets; k++) {
          let frac = (((t * 0.22 * dir + k / packets + e * 0.137) % 1) + 1) % 1;
          if (dir < 0) frac = 1 - frac;
          const px = a.x + (bp.x - a.x) * frac;
          const py = a.y + (bp.y - a.y) * frac;
          const fade = Math.sin(frac * Math.PI); // fade in/out at the ends
          const pr = (1.2 + 1.1 * nearness) * sizeScale;
          ctx.fillStyle = rgba(lighten(colours.accent, 0.4), 0.85 * fade * (0.5 + 0.5 * nearness));
          ctx.beginPath();
          ctx.arc(px, py, pr, 0, Math.PI * 2);
          ctx.fill();
        }
      }
      glowOff();

      // 2) Ping ripples — occasionally a node pulses a ring outward.
      if (t - lastRipple > 2.1 && proj.length > 0) {
        lastRipple = t;
        const healthyIdx: number[] = [];
        for (let idx = 0; idx < proj.length; idx++) {
          if (proj[idx].body.node.healthy) healthyIdx.push(idx);
        }
        if (healthyIdx.length > 0) {
          ripples.push({
            body: healthyIdx[Math.floor(Math.random() * healthyIdx.length)],
            t0: t,
          });
          if (ripples.length > 6) ripples.shift();
        }
      }
      glowOn();
      const RIPPLE_DUR = 2.4;
      for (let i = ripples.length - 1; i >= 0; i--) {
        const age = t - ripples[i].t0;
        if (age > RIPPLE_DUR) {
          ripples.splice(i, 1);
          continue;
        }
        const p = proj[ripples[i].body];
        if (!p) continue;
        const k = age / RIPPLE_DUR;
        const rr = (8 + k * 70) * sizeScale * (0.6 + 0.6 * p.dz);
        const col = p.body.isSelf || p.body.node.elder ? colours.accent : colours.green;
        ctx.strokeStyle = rgba(col, 0.4 * (1 - k) * p.dz);
        ctx.lineWidth = 1.4 * sizeScale;
        ctx.beginPath();
        ctx.arc(p.x, p.y, rr, 0, Math.PI * 2);
        ctx.stroke();
      }
      glowOff();

      // 3) Bodies, painted far → near so nearer nodes sit on top.
      const order = proj.map((_, i) => i).sort((u, v) => proj[u].dz - proj[v].dz);
      glowOn();
      for (const idx of order) {
        const p = proj[idx];
        const b = p.body;
        const online = b.node.healthy;
        const elder = b.node.elder;

        // Colour: self & elders warm accent, healthy peers cool green, stale red.
        let colour: RGB;
        let baseIntensity: number;
        if (!online) {
          colour = colours.red;
          baseIntensity = 0.32;
        } else if (b.isSelf) {
          colour = colours.accent;
          baseIntensity = 1;
        } else if (elder) {
          colour = mix(colours.accent, WARM, 0.25);
          baseIntensity = 0.95;
        } else {
          colour = colours.green;
          baseIntensity = 0.82;
        }

        const pulse = 0.86 + 0.14 * Math.sin(t * 1.1 + b.phase);
        const depthFade = 0.5 + 0.5 * p.dz;
        const intensity = baseIntensity * depthFade * pulse;

        const selfBoost = b.isSelf ? 1.35 : 1;
        const r = (3.5 + 11 * b.weight) * sizeScale * p.sc * selfBoost;

        // Orbiting miner sparks — one per (capped) deduped miner.
        if (online && b.node.deduped_miner_count > 0) {
          const m = Math.min(6, Math.max(1, b.node.deduped_miner_count));
          const orbitR = r * 2.3 + 6 * sizeScale;
          for (let k = 0; k < m; k++) {
            const a = t * (0.6 + 0.15 * (b.phase % 1)) + (k / m) * Math.PI * 2 + b.phase;
            const sxk = p.x + Math.cos(a) * orbitR;
            const syk = p.y + Math.sin(a) * orbitR * 0.9;
            ctx.fillStyle = rgba(lighten(colour, 0.5), 0.55 * p.dz);
            ctx.beginPath();
            ctx.arc(sxk, syk, 1.1 * sizeScale, 0, Math.PI * 2);
            ctx.fill();
          }
        }

        // Extra breathing halo for "you" so the heart reads instantly.
        if (b.isSelf) {
          const haloR = r * (4.6 + 0.8 * breath);
          const halo = ctx.createRadialGradient(p.x, p.y, r, p.x, p.y, haloR);
          halo.addColorStop(0, rgba(colour, 0.22 * depthFade));
          halo.addColorStop(1, rgba(colour, 0));
          ctx.fillStyle = halo;
          ctx.beginPath();
          ctx.arc(p.x, p.y, haloR, 0, Math.PI * 2);
          ctx.fill();
        }

        drawOrb(p.x, p.y, r, colour, intensity);
        if (online && (elder || b.isSelf)) {
          drawCorona(p.x, p.y, r, colour, t, breath * depthFade);
        }
      }
      glowOff();

      ctx.restore();
      raf = requestAnimationFrame(render);
    };

    raf = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, [active]);

  return (
    <div
      ref={containerRef}
      className="relative h-full w-full overflow-hidden select-none"
      style={{ background: 'var(--bg)' }}
    >
      <canvas ref={canvasRef} className="absolute inset-0 block h-full w-full" />
    </div>
  );
}
