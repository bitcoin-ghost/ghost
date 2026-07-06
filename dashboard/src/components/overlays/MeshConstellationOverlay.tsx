/**
 * Overlay: Mesh Constellation
 *
 * CONCEPT — the 8-node swarm rendered as a living star map: glowing orbs
 * (elders brighter / crowned, sized by hashrate, `is_self` at the centre in the
 * accent colour), connection lines from this node to its peers that softly
 * pulse as gossip flows, and particles drifting along those edges. A slow
 * rotation and breathing keep it alive on a dark rest screen.
 *
 * Data: `useMeshNodes` (`/api/v1/pool/mesh-nodes`) for the swarm, and the
 * offline geo lib (`useGeoDb` + `extractHost`/`resolve`) purely to ORDER peers
 * around the ring by longitude (west → left, east → right) so the layout reads
 * like a map. It degrades gracefully to a deterministic ordering when geo is
 * unavailable.
 *
 * Contract:
 *  - Fills its container (the shell gives it 100dvh).
 *  - Honours `active`: the rAF loop and polling run ONLY while active===true and
 *    are cancelled on active===false and on unmount.
 *  - CSP-safe: canvas 2D only, no external assets, no new deps. Theme-aware via
 *    the design-token CSS vars read off the container.
 */
'use client';

import { useEffect, useMemo, useRef } from 'react';
import { useMeshNodes, useGeoDb } from '@/hooks/queries';
import { extractHost } from '@/lib/geo/geoip';
import type { MeshNode } from '@/lib/api/meshNodes';
import type { OverlayProps } from './types';

/** A node plus the small amount of derived state the renderer needs. */
interface PlacedNode {
  node: MeshNode;
  /** Fixed angle (radians) on the ring; peers only. Self sits at the centre. */
  angle: number;
  /** 0..1 hashrate weight used for orb size. */
  weight: number;
}

type RGB = { r: number; g: number; b: number };

const FALLBACK: Record<string, RGB> = {
  bg: { r: 15, g: 16, b: 18 },
  fg: { r: 230, g: 228, b: 222 },
  accent: { r: 247, g: 147, b: 26 },
  green: { r: 92, g: 199, b: 126 },
  red: { r: 216, g: 116, b: 106 },
  dim: { r: 139, g: 138, b: 132 },
};

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

/** Deterministic 0..1 from a string, so ordering is stable without geo. */
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

  // Poll briskly while on-screen and back off to a slow trickle when this
  // overlay is off-screen, so it does not drive fast refetches in the carousel.
  const { data, isLoading, isError } = useMeshNodes({
    refetchInterval: active ? 15_000 : 60_000,
  });
  // Geo DB is a one-shot static asset; used only to order peers by longitude.
  const { data: geoDb } = useGeoDb();

  const nodes = useMemo(() => data?.nodes ?? [], [data]);

  // Precompute placement whenever the swarm or geo resolution changes. The rAF
  // loop reads this via a ref so it never restarts on data updates.
  const placed = useMemo(() => {
    const self = nodes.find((n) => n.is_self) ?? null;
    const peers = nodes.filter((n) => n !== self);

    const maxHash = Math.max(1e-9, ...peers.map((p) => p.hashrate_th), self?.hashrate_th ?? 0);
    const weightOf = (n: MeshNode) => Math.sqrt(Math.max(0, n.hashrate_th) / maxHash);

    // Order peers by resolved longitude (west→east). Fall back to a stable
    // per-node hash so the ring is still evenly, deterministically arranged.
    const keyed = peers.map((n) => {
      let key = hash01(n.node_id || n.address);
      if (geoDb) {
        try {
          const geo = geoDb.resolve(extractHost(n.address));
          if (typeof geo.lon === 'number') key = (geo.lon + 180) / 360;
        } catch {
          /* keep hash fallback */
        }
      }
      return { n, key };
    });
    keyed.sort((a, b) => a.key - b.key || hash01(a.n.node_id) - hash01(b.n.node_id));

    const count = keyed.length || 1;
    const peerNodes: PlacedNode[] = keyed.map(({ n }, i) => ({
      node: n,
      // -PI/2 puts the first node at the top; spread evenly around the circle.
      angle: -Math.PI / 2 + (i / count) * Math.PI * 2,
      weight: weightOf(n),
    }));

    const selfNode: PlacedNode | null = self
      ? { node: self, angle: 0, weight: weightOf(self) }
      : null;

    return { selfNode, peers: peerNodes };
  }, [nodes, geoDb]);

  // The rAF loop reads live data through refs so it never has to restart when
  // the swarm/geo/loading state changes. Sync them outside render.
  const placedRef = useRef(placed);
  const stateRef = useRef({ isLoading, isError, count: nodes.length });
  useEffect(() => {
    placedRef.current = placed;
    stateRef.current = { isLoading, isError, count: nodes.length };
  }, [placed, isLoading, isError, nodes.length]);

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

    // Theme colours, re-read cheaply (throttled) so a light/dark toggle while
    // the overlay is up is picked up without per-frame layout thrash.
    let colours = FALLBACK;
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
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(container);

    const drawOrb = (
      x: number,
      y: number,
      radius: number,
      colour: RGB,
      intensity: number,
      breath: number,
    ) => {
      const glow = radius * (3.4 + 0.7 * breath);
      const g = ctx.createRadialGradient(x, y, 0, x, y, glow);
      g.addColorStop(0, rgba(colour, 0.95 * intensity));
      g.addColorStop(0.18, rgba(colour, 0.6 * intensity));
      g.addColorStop(0.5, rgba(colour, 0.16 * intensity));
      g.addColorStop(1, rgba(colour, 0));
      ctx.fillStyle = g;
      ctx.beginPath();
      ctx.arc(x, y, glow, 0, Math.PI * 2);
      ctx.fill();
      // Solid core.
      ctx.fillStyle = rgba(
        { r: Math.min(255, colour.r + 60), g: Math.min(255, colour.g + 60), b: Math.min(255, colour.b + 60) },
        Math.min(1, 0.85 + 0.15 * intensity),
      );
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, Math.PI * 2);
      ctx.fill();
    };

    const drawCrown = (x: number, y: number, radius: number, colour: RGB, breath: number) => {
      ctx.strokeStyle = rgba(colour, 0.5 + 0.35 * breath);
      ctx.lineWidth = Math.max(1, radius * 0.14);
      ctx.beginPath();
      ctx.arc(x, y, radius * 1.9, 0, Math.PI * 2);
      ctx.stroke();
    };

    const centreText = (text: string, sub: string) => {
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

    const render = (now: number) => {
      const t = now / 1000;
      if (now - lastColourRead > 400) {
        readColours();
        lastColourRead = now;
      }

      // Background — a soft radial vignette on the theme bg.
      const bgGrad = ctx.createRadialGradient(
        width / 2,
        height / 2,
        0,
        width / 2,
        height / 2,
        Math.max(width, height) * 0.7,
      );
      const b = colours.bg;
      bgGrad.addColorStop(0, rgba({ r: b.r + 6, g: b.g + 6, b: b.b + 8 }, 1));
      bgGrad.addColorStop(1, rgba(b, 1));
      ctx.fillStyle = bgGrad;
      ctx.fillRect(0, 0, width, height);

      ctx.save();
      ctx.scale(dpr, dpr);

      const { selfNode, peers } = placedRef.current;
      const { isLoading: loading, isError: err, count } = stateRef.current;

      if (err || (!loading && count === 0)) {
        centreText('Mesh offline', 'no peers reachable');
        ctx.restore();
        raf = requestAnimationFrame(render);
        return;
      }
      if (loading && count === 0) {
        // A lone breathing core while the first payload lands.
        const breath = 0.5 + 0.5 * Math.sin(t * 0.9);
        drawOrb(width / 2, height / 2, 6, colours.accent, 0.7, breath);
        centreText('Mapping the mesh…', 'reading gossip');
        ctx.restore();
        raf = requestAnimationFrame(render);
        return;
      }

      const cx = width / 2;
      const cy = height / 2;
      const scale = Math.min(width, height);
      const ringR = scale * 0.34;
      const rotation = t * 0.03;
      const breath = 0.5 + 0.5 * Math.sin(t * 0.6);
      const sizeScale = Math.min(2.4, Math.max(0.7, scale / 680));
      const orbR = (w: number) => (5 + 12 * w) * sizeScale;

      // Position peers on the (slowly rotating) ring.
      const peerPos = peers.map((p) => ({
        p,
        x: cx + Math.cos(p.angle + rotation) * ringR,
        y: cy + Math.sin(p.angle + rotation) * ringR,
      }));

      // 1) Edges from this node (centre) to each peer, drawn first so orbs sit
      //    on top. Healthy edges pulse and carry gossip particles.
      peerPos.forEach(({ p, x, y }, i) => {
        const healthy = p.node.healthy && (selfNode ? selfNode.node.healthy : true);
        const phase = i * 1.7;
        if (healthy) {
          const pulse = 0.12 + 0.16 * (0.5 + 0.5 * Math.sin(t * 1.6 + phase));
          ctx.strokeStyle = rgba(colours.accent, pulse);
          ctx.lineWidth = 1;
          ctx.setLineDash([]);
          ctx.beginPath();
          ctx.moveTo(cx, cy);
          ctx.lineTo(x, y);
          ctx.stroke();

          // Particles drifting outward along the edge (gossip).
          const particles = 3;
          for (let k = 0; k < particles; k++) {
            const frac = ((t * 0.28 + k / particles + i * 0.13) % 1 + 1) % 1;
            const px = cx + (x - cx) * frac;
            const py = cy + (y - cy) * frac;
            const fade = Math.sin(frac * Math.PI); // fade in/out at the ends
            ctx.fillStyle = rgba(colours.accent, 0.7 * fade);
            ctx.beginPath();
            ctx.arc(px, py, 1.6 * sizeScale, 0, Math.PI * 2);
            ctx.fill();
          }
        } else {
          // Offline peer — faint, static, dashed red tether.
          ctx.strokeStyle = rgba(colours.red, 0.14);
          ctx.lineWidth = 1;
          ctx.setLineDash([4, 6]);
          ctx.beginPath();
          ctx.moveTo(cx, cy);
          ctx.lineTo(x, y);
          ctx.stroke();
          ctx.setLineDash([]);
        }
      });

      // 2) Peer orbs.
      peerPos.forEach(({ p, x, y }) => {
        const online = p.node.healthy;
        const colour = !online ? colours.red : p.node.elder ? colours.accent : colours.green;
        const intensity = online ? (p.node.elder ? 1 : 0.82) : 0.4;
        const r = orbR(p.weight);
        drawOrb(x, y, r, colour, intensity, breath);
        if (p.node.elder && online) drawCrown(x, y, r, colours.accent, breath);
      });

      // 3) This node at the centre, highlighted in the accent colour.
      if (selfNode) {
        const online = selfNode.node.healthy;
        const r = orbR(Math.max(0.5, selfNode.weight)) * 1.15;
        const colour = online ? colours.accent : colours.red;
        // Extra pulsing halo so "you" reads instantly.
        const haloR = r * (4.5 + 0.8 * breath);
        const halo = ctx.createRadialGradient(cx, cy, r, cx, cy, haloR);
        halo.addColorStop(0, rgba(colour, 0.22));
        halo.addColorStop(1, rgba(colour, 0));
        ctx.fillStyle = halo;
        ctx.beginPath();
        ctx.arc(cx, cy, haloR, 0, Math.PI * 2);
        ctx.fill();
        drawOrb(cx, cy, r, colour, 1, breath);
        if (selfNode.node.elder) drawCrown(cx, cy, r, colours.accent, breath);
      } else {
        // No self in the payload — a faint focal core stands in as "the mesh".
        drawOrb(cx, cy, 4 * sizeScale, colours.dim, 0.5, breath);
      }

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
